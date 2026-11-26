//! The arena's buffer pools: per-buffer records, a free stack per pool, and exclusive buffer handles.
//!
//! Invariants:
//!
//! - Pools are carved from the backing in [`PoolKind::ALL`] order, each span starting at a multiple of its power-of-two buffer length.
//!   Every buffer lies inside one backing page and its pool's span, and overlaps no other buffer; padding and tail hold none.
//!   Buffer `i` of a pool starts `i * buffer_len` bytes into the pool's span.
//! - Each buffer carries an obligation set: empty when free, `{APPLICATION}` behind a live [`Buffer`] handle, `{STORAGE}` inside a command table record, `{STORAGE, DETACHED}` once its command was cancelled, `{RECEIVE}` while posted to a device for receive, `{NIC}` once its handle dropped while a device still reads it, and `{RETIRED}` once its incarnations ran out.
//!   Every transition is O(1) and writes the buffer's record, plus the free stack and `free_low` on an acquire or post, the free stack on a free, and the retired count on a retirement; every transition but a posting run's end panics in every build when the custody core makes it illegal, so a second release panics before it pushes a buffer on the free stack twice and an acquire of a retired buffer panics before it reuses an exhausted incarnation. [`Pool::unpost_run`] reaches only buffers carrying the by-index mark and checks legality with a debug assertion.
//!   Each record keeps its buffer's set, which a returning device reference reads to learn whether the handle already dropped; a report counts the records.
//! - Per pool, `free + application + storage + quarantined + posted + nic_held + retired = count` after every call; a handle with device references counts once, as application.
//! - Each buffer has a device reference count and an incarnation number. A [`NicHold`] names the buffer and incarnation it holds, which stays current while the hold lives, so dropping it returns its reference; a raw return through [`BufferArena::nic_return`](super::BufferArena::nic_return) decrements only a matching incarnation, and a mismatched one is counted and changes nothing. A buffer whose count is positive never reaches the free stack: its handle's drop leaves it `{NIC}` until the last reference returns. Each return to the free stack starts a new incarnation; a buffer whose incarnation would wrap retires instead.
//! - A buffer posted for receive has no CPU byte view until the device finished writing it and [`RxPosted::complete`] hands it over as a handle.
//!   A posting by index, through [`Pool::post_run`] for the device mempool serving the kind, has no [`RxPosted`]; its record marks it until [`Pool::unpost_run`] ends it or [`Pool::take_posted`] turns it into an [`RxPosted`].
//! - A buffer enters `STORAGE` only when a driver accepted its command, or when the driver's submit call unwound, and leaves it only through the command table: back to a handle at its terminal event, or, when detached, straight to the free stack through a path distinct from handle drop.
//! - Acquire pops the most recently freed buffer of a kind (LIFO) and dropping the handle pushes it back.
//!   Acquire, drop and every custody transition are O(1), touch only this pool's records, stack and counts, and use only storage allocated once, at initialization.
//! - A buffer index is on its pool's free stack exactly when it is not retired and no handle, record, posting or device reference names it, so at most one handle reaches any buffer.

use std::cell::Cell;
use std::fmt;
use std::marker::PhantomData;
use std::mem::ManuallyDrop;
use std::ops::Range;
use std::ptr::{self, NonNull};

use super::area::DmaArea;
use super::config::{PoolKind, PoolSpec, SECTOR, ValidatedBufferConfig};
use super::disk::DmaRange;

pub(super) use super::custody::APPLICATION;
use super::custody::{self, Event, Next};
use super::custody::{DETACHED, NIC, RECEIVE, RETIRED, STORAGE};

struct Record {
    /// The buffer's obligation set in the low byte, its device references
    /// to the current incarnation in the 16 bits above, and [`BY_INDEX`] in
    /// bit 24, with the bits above it clear: one word, so a transition's
    /// legality check reads them with one load.
    state: Cell<u32>,
    /// LIFO reuse can put a pool's increments on one buffer. A 32-bit count
    /// wraps after about 72 minutes at one million increments per second;
    /// 64 bits last about 584 years at one increment per nanosecond.
    incarnation: Cell<u64>,
}

impl Record {
    fn free() -> Self {
        Self {
            state: Cell::new(0),
            incarnation: Cell::new(0),
        }
    }

    #[inline]
    fn set(&self) -> u8 {
        set_of(self.state.get())
    }

    /// Device references to the buffer's current incarnation.
    #[inline]
    fn nic(&self) -> u16 {
        nic_of(self.state.get())
    }
}

/// The [`Record`] state word of obligation set `set` with `nic` device references.
#[inline(always)]
const fn state(set: u8, nic: u16) -> u32 {
    set as u32 | (nic as u32) << 8
}

#[inline(always)]
const fn set_of(word: u32) -> u8 {
    word as u8
}

#[inline(always)]
const fn nic_of(word: u32) -> u16 {
    (word >> 8) as u16
}

/// The state word's change for one device reference. The count sits above the set's byte, so adding this to a count below `u16::MAX`, or subtracting it from a positive count, moves the count alone.
const ONE_REFERENCE: u32 = state(0, 1);

/// The state word's mark of a buffer [`Pool::post_run`] posted by index; [`Pool::unpost_run`] and [`Pool::take_posted`] require and clear it.
/// A marked word holds obligation set `{RECEIVE}` and no device references; [`set_of`] and [`nic_of`] read only the bits below the mark.
const BY_INDEX: u32 = 1 << 24;

/// One kind's buffers. `addr` is the span's first byte; `start` its offset from the backing base.
pub(crate) struct Pool {
    spec: PoolSpec,
    addr: NonNull<u8>,
    start: usize,
    records: Vec<Record>,
    /// The free indices at `0..free`, the top acquired next.
    stack: Vec<Cell<u32>>,
    free: Cell<u32>,
    retired: Cell<u32>,
    /// Device reference returns that named no live reference of the buffer's current incarnation.
    mismatched: Cell<u64>,
    /// Returns that took a buffer's device reference count to zero, wrapping; every end of a device's reads of a buffer increments it.
    holds_ended: Cell<u64>,
    /// The fewest free buffers seen; `count - free_low` is the most buffers off the free stack at once, retired included.
    free_low: Cell<u32>,
    /// A packet pool view holds this kind, so its data cap counts every lease.
    viewed: Cell<bool>,
    /// A device mempool serves this kind's buffers.
    served: Cell<bool>,
}

/// Every kind's pool, indexed by [`PoolKind::index`]; an absent kind's pool has no buffers.
pub(crate) struct Pools {
    pools: [Pool; PoolKind::ALL.len()],
}

/// Every buffer of the requested kind is held, or the arena has no pool of that kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolExhausted {
    pub kind: PoolKind,
}

/// Why a buffer prefix was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanError {
    ZeroLength,
    /// The length is not a multiple of [`SECTOR`].
    Misaligned {
        len: u32,
    },
    TooLong {
        len: u32,
        capacity: usize,
    },
}

/// Why a device reference was refused; nothing changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldError {
    /// The buffer already carries the most references its count holds.
    Cap,
}

/// One pool's counts; `free + application + storage + quarantined + posted + nic_held + retired = count`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferPoolReport {
    pub kind: PoolKind,
    pub count: u32,
    pub buffer_len: u32,
    pub free: u32,
    pub application: u32,
    pub storage: u32,
    pub quarantined: u32,
    /// Posted to a device for receive.
    pub posted: u32,
    /// Handle dropped while a device still reads the buffer.
    pub nic_held: u32,
    /// Out of incarnations; never reused.
    pub retired: u32,
    /// Device reference returns that matched no live reference.
    pub mismatched: u64,
    /// Bytes of every buffer not free and not retired.
    pub held_bytes: u64,
    /// The most buffers off the free stack at once, retired included.
    pub held_high_water: u32,
}

/// Exclusive access to one buffer, returned to its pool's free stack on drop
/// once no device reference remains.
pub struct Buffer<'a> {
    pool: &'a Pool,
    index: usize,
}

/// One buffer posted to a device for receive: exclusive device-write custody,
/// with no CPU byte view until [`complete`](Self::complete) hands it back.
/// [`unpost`](Self::unpost) returns it to the free stack once the device
/// stopped writing it; dropping it leaves the buffer posted for good, so an
/// unwind between publishing its address and completion never frees memory
/// a device may still write, and the arena stays unreleasable.
///
/// A posted buffer has no byte view:
///
/// ```compile_fail,E0599
/// fn read(posted: &kestrike::storage::RxPosted<'_>) -> u8 {
///     posted.bytes()[0]
/// }
/// ```
pub struct RxPosted<'a> {
    pool: &'a Pool,
    index: usize,
}

/// A validated range of a held buffer that a transmit device may read. It
/// borrows the handle that made it for `'s`, so the buffer keeps its current
/// incarnation while the range exists, and the arena for `'a`, the lifetime
/// of any [`NicHold`] it grants.
#[derive(Clone, Copy)]
pub struct SourceRange<'s, 'a> {
    pool: &'a Pool,
    index: u32,
    offset: u32,
    len: u32,
    handle: PhantomData<&'s ()>,
}

/// One device reference to a buffer incarnation's range, from
/// [`SourceRange::hold`]. While any reference lives the buffer never returns
/// to the free stack; dropping the hold returns the reference.
pub struct NicHold<'a> {
    pool: &'a Pool,
    index: u32,
    incarnation: u64,
    offset: u32,
    len: u32,
}

impl Pools {
    /// Bytes [`with_capacity`](Self::with_capacity) allocates for `config`: per buffer, one record and one free-stack entry.
    pub(crate) fn metadata_bytes(config: &ValidatedBufferConfig) -> usize {
        Self::buffer_count(config) * (size_of::<Record>() + size_of::<Cell<u32>>())
    }

    fn buffer_count(config: &ValidatedBufferConfig) -> usize {
        PoolKind::ALL
            .iter()
            .map(|kind| config.pool(*kind).count as usize)
            .sum()
    }

    /// Allocates every record and stack slot up front, empty, so carving and every later transition allocate nothing.
    pub(crate) fn with_capacity(config: &ValidatedBufferConfig) -> Self {
        let pools = PoolKind::ALL.map(|kind| {
            let spec = config.pool(kind);
            Pool {
                spec,
                addr: NonNull::dangling(),
                start: config.start(kind),
                records: Vec::with_capacity(spec.count as usize),
                stack: Vec::with_capacity(spec.count as usize),
                free: Cell::new(0),
                retired: Cell::new(0),
                mismatched: Cell::new(0),
                holds_ended: Cell::new(0),
                free_low: Cell::new(spec.count),
                viewed: Cell::new(false),
                served: Cell::new(false),
            }
        });
        Self { pools }
    }

    /// Carves `area`, the whole backing, into each present pool at its validated start, every buffer free.
    ///
    /// # Safety
    ///
    /// `area` is the entire backing of the configuration these pools were
    /// built from, and stays live and exclusive to the pools for as long as
    /// any [`Buffer`] they hand out lives.
    pub(crate) unsafe fn carve(&mut self, area: DmaArea<'_>) {
        debug_assert_eq!(area.offset(), 0);
        let mut rest = Some(area);
        for pool in &mut self.pools {
            debug_assert!(pool.records.is_empty());
            if pool.spec.count == 0 {
                continue;
            }
            let buffer_len = pool.spec.buffer_len as usize;
            let span_len = pool.spec.count as usize * buffer_len;
            let Some(mut area) = rest.take() else {
                unreachable!("validation sized the backing to hold every pool")
            };
            let padding = pool.start - area.offset();
            if padding > 0 {
                let (_, after) = area.split_at(padding).unwrap_or_else(|_| {
                    unreachable!("alignment padding is a unit multiple inside the backing")
                });
                area = after;
            }
            let span = if span_len == area.len() {
                area
            } else {
                let (span, tail) = area.split_at(span_len).unwrap_or_else(|_| {
                    unreachable!("a pool span is a positive unit multiple inside the backing")
                });
                rest = Some(tail);
                span
            };
            debug_assert_eq!(span.offset(), pool.start);
            pool.addr = span.addr();
            let mut parts = span.parts(buffer_len).unwrap_or_else(|_| {
                unreachable!("a buffer length is a positive unit multiple no longer than its span")
            });
            for part in parts.by_ref() {
                debug_assert_eq!(part.offset(), pool.start + pool.records.len() * buffer_len);
                pool.records.push(Record::free());
            }
            debug_assert!(parts.remainder().is_none());
            for index in (0..pool.spec.count).rev() {
                pool.stack.push(Cell::new(index));
            }
            pool.free.set(pool.spec.count);
        }
    }

    #[inline]
    pub(crate) fn pool(&self, kind: PoolKind) -> &Pool {
        &self.pools[kind.index()]
    }

    /// Whether `pool` is one of these pools: its address lies inside the pools array.
    /// An address below the array wraps to an offset past the array's size, so one comparison decides.
    #[inline]
    fn holds(&self, pool: &Pool) -> bool {
        let offset = ptr::from_ref(pool)
            .addr()
            .wrapping_sub(self.pools.as_ptr().addr());
        offset < size_of_val(&self.pools)
    }

    /// Pops a free buffer of `kind`, the most recently freed first.
    ///
    /// # Errors
    ///
    /// `PoolExhausted` when every buffer of `kind` is held or the arena has none.
    #[inline]
    pub(crate) fn acquire(&self, kind: PoolKind) -> Result<Buffer<'_>, PoolExhausted> {
        self.pool(kind).acquire()
    }

    /// Pops a free buffer of `kind` and posts it to a device for receive.
    ///
    /// # Errors
    ///
    /// `PoolExhausted` when every buffer of `kind` is held or the arena has none.
    pub(crate) fn post(&self, kind: PoolKind) -> Result<RxPosted<'_>, PoolExhausted> {
        self.pool(kind).post()
    }

    /// Returns one device reference to buffer `index` of `kind`'s incarnation
    /// `incarnation`; a return that names no live reference is counted and
    /// changes nothing. Returns whether it matched.
    ///
    /// # Safety
    ///
    /// As for [`BufferArena::nic_return`](super::BufferArena::nic_return).
    #[inline]
    pub(crate) unsafe fn nic_return(&self, kind: PoolKind, index: u32, incarnation: u64) -> bool {
        // SAFETY: the caller's contract.
        unsafe { self.pool(kind).nic_return(index, incarnation) }
    }

    /// Counts the returns that took a buffer's device reference count to zero in `kind`'s pool, wrapping; each such return increments it, so a value equal to an earlier call's shows that none happened in between, short of 2^64 returns.
    pub(crate) fn holds_ended(&self, kind: PoolKind) -> u64 {
        self.pool(kind).holds_ended.get()
    }

    /// Whether a packet pool view holds `kind`.
    pub(crate) fn viewed(&self, kind: PoolKind) -> bool {
        self.pool(kind).viewed.get()
    }

    /// Whether a device mempool serves `kind`.
    #[inline]
    pub(crate) fn served(&self, kind: PoolKind) -> bool {
        self.pool(kind).served()
    }

    pub(crate) fn report(&self, kind: PoolKind) -> BufferPoolReport {
        self.pool(kind).report()
    }

    /// Buffers neither free nor retired, per kind in [`PoolKind::ALL`] order.
    pub(crate) fn held(&self) -> [(PoolKind, u32); PoolKind::ALL.len()] {
        self.pools
            .each_ref()
            .map(|pool| (pool.spec.kind, pool.held()))
    }

    /// Whether a device mempool serves each kind, in [`PoolKind::ALL`] order.
    pub(crate) fn served_kinds(&self) -> [(PoolKind, bool); PoolKind::ALL.len()] {
        self.pools
            .each_ref()
            .map(|pool| (pool.spec.kind, pool.served()))
    }

    /// The obligation set of the buffer of `kind` at `offset`, or `None` when no buffer starts there.
    #[cfg(test)]
    pub(crate) fn obligations(&self, kind: PoolKind, offset: usize) -> Option<u8> {
        let pool = self.pool(kind);
        let buffer_len = pool.spec.buffer_len as usize;
        let span_offset = offset.checked_sub(pool.start)?;
        if !span_offset.is_multiple_of(buffer_len) {
            return None;
        }
        pool.records
            .get(span_offset / buffer_len)
            .map(|record| record.set())
    }

    /// An independent count of `kind`'s buffers by obligation set: free,
    /// application, storage, quarantined, posted, NIC-held and retired.
    #[cfg(test)]
    pub(crate) fn census(&self, kind: PoolKind) -> [u32; 7] {
        let mut counts = [0; 7];
        for record in &self.pool(kind).records {
            counts[census_class(record.set())] += 1;
        }
        counts
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self, kind: PoolKind) -> Vec<(usize, u64)> {
        self.pool(kind)
            .records
            .iter()
            .map(|record| (census_class(record.set()), record.incarnation.get()))
            .collect()
    }

    /// Each buffer's device-reference count for `kind`, in index order,
    /// copied into `out` beside the class and incarnation [`snapshot`](Self::snapshot) reports.
    #[cfg(test)]
    pub(crate) fn device_counts_into(&self, kind: PoolKind, out: &mut Vec<u16>) {
        out.clear();
        out.extend(self.pool(kind).records.iter().map(|record| record.nic()));
    }

    /// The indices on `kind`'s free stack, bottom first.
    #[cfg(test)]
    pub(crate) fn free_stack(&self, kind: PoolKind) -> Vec<u32> {
        let pool = self.pool(kind);
        pool.stack[..pool.free.get() as usize]
            .iter()
            .map(Cell::get)
            .collect()
    }

    /// Starts buffer `index` of `kind` at incarnation `incarnation`, so a test can reach exhaustion.
    #[cfg(test)]
    pub(crate) fn set_incarnation(&self, kind: PoolKind, index: usize, incarnation: u64) {
        self.pool(kind).records[index].incarnation.set(incarnation);
    }

    /// Ends the handle of buffer `index` of `kind` as dropping it does, so a test can release a buffer whose handle it forgot, or release one twice.
    #[cfg(test)]
    pub(crate) fn release_index(&self, kind: PoolKind, index: usize) {
        self.pool(kind).release(index);
    }

    /// Pushes buffer `index` on `kind`'s free stack whatever its obligation set, so a test can offer a retired buffer to acquire.
    ///
    /// # Panics
    ///
    /// If the free stack already holds `count` entries.
    #[cfg(test)]
    pub(crate) fn push_free(&self, kind: PoolKind, index: u32) {
        let pool = self.pool(kind);
        let free = pool.free.get();
        pool.stack[free as usize].set(index);
        pool.free.set(free + 1);
    }
}

/// The index [`Pools::census`] counts an obligation set under: free,
/// application, storage, quarantined, posted, NIC-held, retired. Panics on
/// any other set.
#[cfg(test)]
fn census_class(set: u8) -> usize {
    match set {
        0 => 0,
        APPLICATION => 1,
        STORAGE => 2,
        set if set == STORAGE | DETACHED => 3,
        RECEIVE => 4,
        NIC => 5,
        RETIRED => 6,
        set => panic!("an illegal obligation set {set:#b}"),
    }
}

impl Pool {
    /// `acquire` returns this pool's most recently freed buffer as an exclusive handle.
    ///
    /// # Errors
    ///
    /// `acquire` returns `PoolExhausted` when the free stack is empty.
    #[inline]
    pub(crate) fn acquire(&self) -> Result<Buffer<'_>, PoolExhausted> {
        let index = self.pop().ok_or(PoolExhausted {
            kind: self.spec.kind,
        })?;
        self.event(index, Event::Acquire);
        Ok(Buffer { pool: self, index })
    }

    /// `post` posts this pool's most recently freed buffer to a device for receive.
    ///
    /// # Errors
    ///
    /// `post` returns `PoolExhausted` when the free stack is empty.
    #[inline]
    pub(crate) fn post(&self) -> Result<RxPosted<'_>, PoolExhausted> {
        let index = self.pop().ok_or(PoolExhausted {
            kind: self.spec.kind,
        })?;
        self.event(index, Event::Post);
        Ok(RxPosted { pool: self, index })
    }

    /// `claim_view` claims this pool for one packet pool view and returns `true` when the pool was unclaimed.
    /// The claim lasts until [`end_view`](Self::end_view).
    pub(crate) fn claim_view(&self) -> bool {
        !self.viewed.replace(true)
    }

    /// `end_view` ends the packet pool view's claim on this pool.
    pub(crate) fn end_view(&self) {
        self.viewed.set(false);
    }

    /// The kind of buffers this pool holds.
    #[inline]
    pub(crate) fn kind(&self) -> PoolKind {
        self.spec.kind
    }

    /// The address of the pool's first buffer, its provenance exposed for a device mempool that names buffers by address, and its spec.
    pub(crate) fn span(&self) -> (usize, PoolSpec) {
        (self.addr.as_ptr().expose_provenance(), self.spec)
    }

    /// Claims the pool for one device mempool while every buffer is free; false otherwise.
    /// The claim lasts until [`end_served`](Self::end_served).
    pub(crate) fn claim_served(&self) -> bool {
        self.free.get() == self.spec.count && !self.served.replace(true)
    }

    /// Whether a device mempool serves this pool's buffers.
    #[inline]
    pub(crate) fn served(&self) -> bool {
        self.served.get()
    }

    /// Ends the device mempool's claim on this pool.
    pub(crate) fn end_served(&self) {
        self.served.set(false);
    }

    /// Free buffers.
    #[inline]
    pub(crate) fn free_count(&self) -> u32 {
        self.free.get()
    }

    #[inline]
    pub(crate) fn held(&self) -> u32 {
        self.spec.count - self.free.get() - self.retired.get()
    }

    /// Buffers that are not free: held by the application, the storage or a device, quarantined, or retired.
    #[inline]
    pub(crate) fn not_free(&self) -> u32 {
        self.spec.count - self.free.get()
    }

    /// Posts `n` free buffers to a device for receive, the most recently
    /// freed first, and hands each index to `each`, for a device that names
    /// buffers by index; each record carries the by-index mark that
    /// [`unpost_run`](Self::unpost_run) and [`take_posted`](Self::take_posted) require. Returns false with nothing
    /// changed while fewer than `n` are free. The free count and its low
    /// mark change once, after the last call to `each`.
    ///
    /// # Safety
    ///
    /// `each` returns normally and reaches no buffer pool.
    #[inline(always)]
    pub(crate) unsafe fn post_run(&self, n: u32, mut each: impl FnMut(u32)) -> bool {
        let free = self.free.get();
        let Some(rest) = free.checked_sub(n) else {
            return false;
        };
        for slot in (rest..free).rev() {
            // SAFETY: `slot < free <= count`, the stack's length.
            let index = unsafe { self.stack.get_unchecked(slot as usize) }.get();
            let record = self.record(index as usize);
            self.step_marked(
                record,
                index as usize,
                record.state.get(),
                Event::Post,
                BY_INDEX,
            );
            each(index);
        }
        self.free.set(rest);
        if rest < self.free_low.get() {
            self.free_low.set(rest);
        }
        true
    }

    /// Ends the posting of each buffer whose index `indices` yields while it
    /// carries the by-index mark of [`post_run`](Self::post_run), returning
    /// the buffer to the free stack with the effect of [`RxPosted::unpost`],
    /// and returns how many ended. The loop recycles each buffer directly and
    /// checks the core's `Unpost` decision only in debug assertions. `None`,
    /// an index past the pool and a buffer without the mark, including one
    /// [`take_posted`](Self::take_posted) took, change nothing, so a repeated
    /// index ends its posting once.
    /// The free count changes once, after the last item.
    ///
    /// # Safety
    ///
    /// The device stopped writing each marked buffer `indices` yields, and
    /// iterating `indices` reaches no buffer pool.
    #[inline(always)]
    pub(crate) unsafe fn unpost_run(&self, indices: impl IntoIterator<Item = Option<u32>>) -> u32 {
        let (records, stack) = (&self.records[..], &self.stack[..]);
        let mut free = self.free.get();
        let mut ended = 0;
        for index in indices {
            let Some((index, record)) =
                index.and_then(|index| Some((index, records.get(index as usize)?)))
            else {
                continue;
            };
            let word = record.state.get();
            if word & BY_INDEX == 0 {
                continue;
            }
            let (set, nic) = (set_of(word), nic_of(word));
            debug_assert!(
                custody::legal(set, nic, Event::Unpost),
                "illegal obligation transition"
            );
            debug_assert_eq!(custody::after(set, nic, Event::Unpost), Next::Free);
            // SAFETY: the marked buffer is held, its record and this pool's stack are the ones passed, and `free` is the stack's depth.
            let to = unsafe { recycle(record, stack, index, &mut free) };
            // A posting holds no device reference, so the new word holds the set alone and drops the mark.
            record.state.set(state(to, 0));
            ended += 1;
            if to == RETIRED {
                self.retired.set(self.retired.get() + 1);
            }
        }
        self.free.set(free);
        ended
    }

    /// Takes the posting of buffer `index` that [`post_run`](Self::post_run)
    /// marked: clears the mark and returns the posting as an [`RxPosted`],
    /// whose [`complete`](RxPosted::complete) or [`unpost`](RxPosted::unpost)
    /// ends it. Returns `None` for an index past the pool or a buffer
    /// without the mark, so each posting is taken once.
    ///
    /// # Safety
    ///
    /// The device stopped writing the buffer.
    #[inline]
    pub(crate) unsafe fn take_posted(&self, index: u32) -> Option<RxPosted<'_>> {
        let record = self.records.get(index as usize)?;
        let word = record.state.get();
        if word & BY_INDEX == 0 {
            return None;
        }
        record.state.set(word & !BY_INDEX);
        debug_assert_eq!(
            set_of(word),
            RECEIVE,
            "a by-index mark names a posted buffer"
        );
        Some(RxPosted {
            pool: self,
            index: index as usize,
        })
    }

    /// Rebuilds the handle a caller relinquished with [`RxPosted::into_index`].
    ///
    /// # Safety
    ///
    /// No other [`RxPosted`] for the buffer exists: the one its post returned
    /// was relinquished with [`RxPosted::into_index`] and nothing rebuilt it since.
    #[inline]
    pub(crate) unsafe fn posting(&self, index: u32) -> Option<RxPosted<'_>> {
        let record = self.records.get(index as usize)?;
        (record.set() == RECEIVE).then_some(RxPosted {
            pool: self,
            index: index as usize,
        })
    }

    /// Buffers whose incarnations ran out; they never return to the free stack.
    #[inline]
    pub(crate) fn retired(&self) -> u32 {
        self.retired.get()
    }

    /// `report` returns this pool's counts by obligation set, counted over its records, with `free` and `retired` from the pool's counts, plus its mismatched returns, held bytes and high water.
    pub(crate) fn report(&self) -> BufferPoolReport {
        let (free, retired) = (self.free.get(), self.retired.get());
        let (mut storage, mut quarantined, mut posted, mut nic_held) = (0, 0, 0, 0);
        for record in &self.records {
            match record.set() {
                STORAGE => storage += 1,
                set if set == STORAGE | DETACHED => quarantined += 1,
                RECEIVE => posted += 1,
                NIC => nic_held += 1,
                _ => {}
            }
        }
        let count = self.spec.count;
        BufferPoolReport {
            kind: self.spec.kind,
            count,
            buffer_len: self.spec.buffer_len,
            free,
            application: count - free - storage - quarantined - posted - nic_held - retired,
            storage,
            quarantined,
            posted,
            nic_held,
            retired,
            mismatched: self.mismatched.get(),
            held_bytes: u64::from(count - free - retired) * u64::from(self.spec.buffer_len),
            held_high_water: count - self.free_low.get(),
        }
    }

    #[inline]
    fn offset(&self, index: usize) -> usize {
        self.start + index * self.spec.buffer_len as usize
    }

    #[inline]
    fn record(&self, index: usize) -> &Record {
        // SAFETY: every index the pool hands out came off its free stack, so it is below `count`, the records' length.
        unsafe { self.records.get_unchecked(index) }
    }

    /// Pops the top of the free stack and records a new free-count minimum when this pop sets one.
    #[inline]
    fn pop(&self) -> Option<usize> {
        let free = self.free.get().checked_sub(1)?;
        // SAFETY: `free < count`, the stack's length.
        let index = unsafe { self.stack.get_unchecked(free as usize) }.get() as usize;
        self.free.set(free);
        if free < self.free_low.get() {
            self.free_low.set(free);
        }
        Some(index)
    }

    /// Moves buffer `index`'s obligation set by `event` as the custody core decides, freeing the buffer once every obligation ended.
    ///
    /// # Panics
    ///
    /// If the custody core makes `event` illegal for the buffer's set and device reference count, in every build.
    /// The pool's invariants exclude this; an acquire of a retired buffer panics before it reuses an exhausted incarnation.
    #[inline(always)]
    fn event(&self, index: usize, event: Event) {
        let record = self.record(index);
        self.step(record, index, record.state.get(), event);
    }

    /// `word` is `record.state`'s value or the state word the caller computed for this transition before storing it.
    /// Both outcomes overwrite `record.state`, so a stored word older than `word` never survives the step.
    ///
    /// # Panics
    ///
    /// If the custody core makes `event` illegal for `word`'s set and device reference count, in every build.
    #[inline(always)]
    fn step(&self, record: &Record, index: usize, word: u32, event: Event) {
        self.step_marked(record, index, word, event, 0);
    }

    /// [`step`](Self::step) that ORs `mark` into the stored word when the buffer keeps a set; a freed buffer's word carries no mark.
    ///
    /// # Panics
    ///
    /// If the custody core makes `event` illegal for `word`'s set and device reference count, in every build.
    #[inline(always)]
    fn step_marked(&self, record: &Record, index: usize, word: u32, event: Event, mark: u32) {
        let (set, nic) = (set_of(word), nic_of(word));
        assert!(
            custody::legal(set, nic, event),
            "illegal obligation transition"
        );
        match custody::after(set, nic, event) {
            Next::Set(to) => record.state.set(state(to, nic) | mark),
            Next::Free => self.free(index),
        }
    }

    /// Ends the buffer's incarnation and pushes it on the free stack, or retires it when its incarnations ran out.
    /// Every obligation of the buffer ended, so no device reference remains.
    #[inline(always)]
    fn free(&self, index: usize) {
        let record = self.record(index);
        let mut free = self.free.get();
        // SAFETY: the caller frees a held buffer, its record and this pool's stack are the ones passed, and `free` is the stack's depth.
        let to = unsafe { recycle(record, &self.stack, index as u32, &mut free) };
        self.free.set(free);
        record.state.set(state(to, 0));
        if to == RETIRED {
            self.retired.set(self.retired.get() + 1);
        }
    }

    /// The end of a handle: free, or `{NIC}` while device references remain.
    /// For a word of exactly `{APPLICATION}` and a device reference count of zero, a live handle's usual state, the drop takes the free path, which pushes or retires the buffer. Every other word undergoes the legality check.
    ///
    /// # Panics
    ///
    /// If the buffer's obligation set differs from `{APPLICATION}`, in every build: a second release of one handle panics before it pushes the buffer on the free stack twice.
    #[inline]
    fn release(&self, index: usize) {
        let record = self.record(index);
        let word = record.state.get();
        let (set, nic) = (set_of(word), nic_of(word));
        let next = if word == state(APPLICATION, 0) {
            custody::after(APPLICATION, 0, Event::Drop)
        } else {
            assert!(
                custody::legal(set, nic, Event::Drop),
                "illegal obligation transition"
            );
            custody::after(set, nic, Event::Drop)
        };
        match next {
            Next::Set(to) => record.state.set(state(to, nic)),
            Next::Free => self.free(index),
        }
    }

    /// Takes one device reference to buffer `index`, which a live handle
    /// names, and returns the buffer's incarnation, which stays current while
    /// the handle or any reference lives.
    #[inline]
    fn hold(&self, index: usize) -> Result<u64, HoldError> {
        let record = self.record(index);
        let word = record.state.get();
        custody::holds(nic_of(word)).ok_or(HoldError::Cap)?;
        record.state.set(word + ONE_REFERENCE);
        Ok(record.incarnation.get())
    }

    /// Returns one live [`NicHold`]'s reference. A buffer with references
    /// never reaches the free stack, so the hold's incarnation is the
    /// buffer's current one and its count is positive.
    #[inline]
    fn unhold(&self, index: usize) {
        let record = self.record(index);
        let word = record.state.get();
        debug_assert!(nic_of(word) > 0, "a live hold counts one reference");
        self.end_reference(record, index, word);
    }

    /// Ends one device reference to buffer `index`, whose record `record` holds state `word` with a positive count.
    /// The last reference counts in `holds_ended` and passes [`Event::LastReturn`], which frees a `{NIC}` buffer and leaves a handle's buffer `{APPLICATION}`.
    ///
    /// # Panics
    ///
    /// If the last reference ends while the buffer's set is other than `{NIC}` or `{APPLICATION}`, in every build.
    #[inline(always)]
    fn end_reference(&self, record: &Record, index: usize, word: u32) {
        let rest = word - ONE_REFERENCE;
        if nic_of(rest) > 0 {
            record.state.set(rest);
            return;
        }
        self.holds_ended.set(self.holds_ended.get().wrapping_add(1));
        self.step(record, index, rest, Event::LastReturn);
    }

    /// Returns one device reference to buffer `index`'s incarnation
    /// `incarnation`; a return that names no live reference is counted and
    /// changes nothing. Returns whether it matched.
    ///
    /// # Safety
    ///
    /// As for [`BufferArena::nic_return`](super::BufferArena::nic_return).
    #[inline(always)]
    pub(crate) unsafe fn nic_return(&self, index: u32, incarnation: u64) -> bool {
        let Some(record) = self.records.get(index as usize) else {
            self.mismatched.set(self.mismatched.get() + 1);
            return false;
        };
        let word = record.state.get();
        if !custody::returns(record.incarnation.get(), incarnation, nic_of(word)) {
            self.mismatched.set(self.mismatched.get() + 1);
            return false;
        }
        self.end_reference(record, index as usize, word);
        true
    }
}

/// Ends held buffer `index`'s incarnation, pushes the index on `stack` at
/// depth `free`, advances `free` and returns the empty set; when the
/// incarnation would wrap, it pushes nothing and returns `RETIRED`. The
/// caller moves `record`'s obligation set to the returned set, counts a
/// retirement and stores `free` back.
///
/// # Safety
///
/// `record` is held buffer `index`'s record in the pool whose free stack is
/// `stack`, and `*free` is that stack's depth.
#[inline(always)]
unsafe fn recycle(record: &Record, stack: &[Cell<u32>], index: u32, free: &mut u32) -> u8 {
    let Some(next) = custody::next_incarnation(record.incarnation.get()) else {
        return RETIRED;
    };
    record.incarnation.set(next);
    // SAFETY: each push returns one index a pop or a posting run took, and this buffer is still held, so `*free < count`, the stack's length.
    unsafe { stack.get_unchecked(*free as usize) }.set(index);
    *free += 1;
    0
}

impl fmt::Debug for Pool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pool")
            .field("spec", &self.spec)
            .field("start", &self.start)
            .field("free", &self.free.get())
            .field("retired", &self.retired.get())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for Pools {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pools")
            .field("pools", &self.pools)
            .finish_non_exhaustive()
    }
}

impl Buffer<'_> {
    #[inline]
    pub fn kind(&self) -> PoolKind {
        self.pool.spec.kind
    }

    /// Byte offset of the buffer from the arena backing's base, a multiple of [`IO_UNIT`](super::config::IO_UNIT).
    #[inline]
    pub fn offset(&self) -> usize {
        self.pool.offset(self.index)
    }

    /// The buffer's index in its pool, below the pool's count.
    #[inline]
    pub(crate) fn index(&self) -> usize {
        self.index
    }

    /// The buffer's size in bytes: its pool's `buffer_len`, never zero.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.pool.spec.buffer_len as usize
    }

    /// Address of the buffer's first byte, with the mapping's provenance.
    #[inline]
    fn addr(&self) -> NonNull<u8> {
        // SAFETY: the index came off the free stack, so `index < count` and `index * buffer_len` lies inside the pool's `count * buffer_len`-byte span of the live backing.
        unsafe { self.pool.addr.add(self.index * self.capacity()) }
    }

    /// The first `len` bytes of the buffer, described for a driver.
    /// The range is inert data: nothing reaches the bytes through it except a driver inside an accepted command, which only an `unsafe` submit starts.
    ///
    /// # Errors
    ///
    /// In this order: `ZeroLength`, `Misaligned`, then `TooLong`.
    #[inline]
    pub fn range(&self, len: u32) -> Result<DmaRange, SpanError> {
        if len == 0 {
            return Err(SpanError::ZeroLength);
        }
        if !(len as usize).is_multiple_of(SECTOR) {
            return Err(SpanError::Misaligned { len });
        }
        if len as usize > self.capacity() {
            return Err(SpanError::TooLong {
                len,
                capacity: self.capacity(),
            });
        }
        Ok(DmaRange::new(self.addr(), self.offset(), len))
    }

    #[inline]
    pub fn bytes(&self) -> &[u8] {
        // SAFETY: the handle holds the only access to `capacity` live, initialized bytes at `addr`; a command over this buffer starts only through an `unsafe` `Disk` submit, whose caller forms no reference to the bytes until the command ends; and `&self` rules out a mutable view.
        unsafe { std::slice::from_raw_parts(self.addr().as_ptr(), self.capacity()) }
    }

    /// # Panics
    ///
    /// While a device holds a reference to the buffer.
    #[inline]
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        assert!(
            !self.device_held(),
            "a buffer a device reads has no mutable view"
        );
        // SAFETY: as for `bytes`; no device reference reads the buffer, checked above, and `&mut self` makes the slice the only access.
        unsafe { std::slice::from_raw_parts_mut(self.addr().as_ptr(), self.capacity()) }
    }
}

impl fmt::Debug for Buffer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Buffer")
            .field("kind", &self.kind())
            .field("offset", &self.offset())
            .field("capacity", &self.capacity())
            .finish()
    }
}

impl Drop for Buffer<'_> {
    #[inline]
    fn drop(&mut self) {
        self.pool.release(self.index);
    }
}

impl<'a> Buffer<'a> {
    /// Hands this buffer to a device: takes one device reference to its current incarnation and ends the handle,
    /// as [`SourceRange::hold`], [`NicHold::into_raw`] and dropping the handle would, so the buffer stays `{NIC}`
    /// off the free stack until that reference returns through
    /// [`BufferArena::nic_return`](super::BufferArena::nic_return). Returns the reference's identity.
    ///
    /// # Errors
    ///
    /// The handle, unchanged, and [`HoldError::Cap`] when the buffer's count is full.
    ///
    /// # Panics
    ///
    /// If the custody core makes the handle's end illegal, in every build, before any write: the record keeps its
    /// state and the handle never releases, so the buffer stays off the free stack.
    #[inline]
    pub(crate) fn into_device(self) -> Result<(PoolKind, u32, u64), (Self, HoldError)> {
        let (pool, index) = (self.pool, self.index);
        let record = pool.record(index);
        let word = record.state.get();
        let Some(nic) = custody::holds(nic_of(word)) else {
            return Err((self, HoldError::Cap));
        };
        // The handle ends here; its record write below is the end its drop would make.
        let _ended = ManuallyDrop::new(self);
        let set = set_of(word);
        assert!(
            custody::legal(set, nic, Event::Drop),
            "illegal obligation transition"
        );
        match custody::after(set, nic, Event::Drop) {
            Next::Set(to) => record.state.set(state(to, nic)),
            // A positive count keeps every set the drop can reach, so this arm is unreachable.
            Next::Free => unreachable!("a held buffer survives its handle's end"),
        }
        Ok((pool.spec.kind, index as u32, record.incarnation.get()))
    }

    /// The validated range `range` of this buffer, for a transmit device to
    /// read, or `None` when `range` is inverted or ends past the buffer. The
    /// range borrows this handle, so [`bytes_mut`](Self::bytes_mut) cannot run
    /// while it lives, and `bytes_mut` panics while a [`NicHold`] from it
    /// lives, so the bytes a device reads stay unchanged.
    #[inline]
    pub(crate) fn source(&self, range: Range<usize>) -> Option<SourceRange<'_, 'a>> {
        (range.start <= range.end && range.end <= self.capacity()).then(|| SourceRange {
            pool: self.pool,
            index: self.index as u32,
            offset: range.start as u32,
            len: (range.end - range.start) as u32,
            handle: PhantomData,
        })
    }
}

impl<'a> RxPosted<'a> {
    /// Relinquishes the handle while the buffer stays posted, for a device
    /// that identifies buffers by index; [`Pool::posting`] rebuilds it once
    /// the device returns the buffer.
    #[inline]
    pub(crate) fn into_index(self) -> u32 {
        let posted = ManuallyDrop::new(self);
        posted.index as u32
    }

    /// `is_of` reports whether this posting's buffer belongs to `pool`, by address identity.
    #[inline]
    pub(crate) fn is_of(&self, pool: &Pool) -> bool {
        ptr::eq(self.pool, pool)
    }

    /// The device-facing start of the buffer, which only the device writes while posted.
    pub fn device_addr(&self) -> NonNull<u8> {
        // SAFETY: the index came off the free stack, so the offset lies inside the pool's span of the live backing.
        unsafe {
            self.pool
                .addr
                .add(self.index * self.pool.spec.buffer_len as usize)
        }
    }

    /// Hands the received buffer to the CPU as an exclusive handle.
    ///
    /// # Safety
    ///
    /// The device finished writing the buffer and its writes are visible to
    /// this thread, so nothing else reaches its bytes.
    #[inline]
    pub unsafe fn complete(self) -> Buffer<'a> {
        let posted = ManuallyDrop::new(self);
        posted.pool.event(posted.index, Event::Complete);
        Buffer {
            pool: posted.pool,
            index: posted.index,
        }
    }
}

impl RxPosted<'_> {
    /// Returns the buffer to the free stack without a CPU view.
    ///
    /// # Safety
    ///
    /// The device stopped writing the buffer: it never received the address, or it is proven stopped.
    pub unsafe fn unpost(self) {
        let posted = ManuallyDrop::new(self);
        posted.pool.event(posted.index, Event::Unpost);
    }
}

impl fmt::Debug for RxPosted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RxPosted")
            .field("offset", &self.pool.offset(self.index))
            .finish()
    }
}

impl<'s, 'a> SourceRange<'s, 'a> {
    /// The range's bytes, live and unchanged while the handle the range borrows lives.
    #[inline]
    pub fn bytes(&self) -> &'s [u8] {
        let start = self.index as usize * self.pool.spec.buffer_len as usize + self.offset as usize;
        // SAFETY: `source` checked the range lies inside the buffer, and the
        // range borrows the buffer's handle for `'s`, which keeps the buffer
        // off the free stack for `'s`.
        unsafe { std::slice::from_raw_parts(self.pool.addr.add(start).as_ptr(), self.len as usize) }
    }

    /// `is_of` reports whether the range's buffer belongs to `pool`, by address identity.
    #[inline]
    pub(crate) fn is_of(&self, pool: &Pool) -> bool {
        ptr::eq(self.pool, pool)
    }

    /// Takes one device reference to the range's buffer incarnation.
    ///
    /// # Errors
    ///
    /// `Cap` when the buffer's count is full; nothing changes.
    #[inline]
    pub fn hold(&self) -> Result<NicHold<'a>, HoldError> {
        let incarnation = self.pool.hold(self.index as usize)?;
        Ok(NicHold {
            pool: self.pool,
            index: self.index,
            incarnation,
            offset: self.offset,
            len: self.len,
        })
    }
}

impl fmt::Debug for SourceRange<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SourceRange")
            .field("kind", &self.pool.spec.kind)
            .field("index", &self.index)
            .field("offset", &self.offset)
            .field("len", &self.len)
            .finish()
    }
}

impl NicHold<'_> {
    /// The held bytes, as the device reads them.
    #[inline]
    pub fn bytes(&self) -> &[u8] {
        // SAFETY: `device_addr` lies inside the buffer with `len` bytes after
        // that address, and the reference keeps the incarnation off the free
        // stack.
        unsafe { std::slice::from_raw_parts(self.device_addr().as_ptr(), self.len as usize) }
    }

    /// The device-facing address of the held bytes, for a device to read them in place.
    #[inline]
    pub fn device_addr(&self) -> NonNull<u8> {
        let start = self.index as usize * self.pool.spec.buffer_len as usize + self.offset as usize;
        // SAFETY: `source` checked the range lies inside the buffer, so the offset stays inside the pool's span of the live backing.
        unsafe { self.pool.addr.add(start) }
    }

    /// The pool kind, buffer index and incarnation the reference names.
    pub fn identity(&self) -> (PoolKind, u32, u64) {
        (self.pool.spec.kind, self.index, self.incarnation)
    }

    /// Detaches the reference from this value without returning it, for a
    /// device whose own descriptor return later calls [`BufferArena::nic_return`](super::BufferArena::nic_return)
    /// with the same identity.
    pub fn into_raw(self) -> (PoolKind, u32, u64) {
        let hold = ManuallyDrop::new(self);
        hold.identity()
    }
}

impl Drop for NicHold<'_> {
    #[inline]
    fn drop(&mut self) {
        self.pool.unhold(self.index as usize);
    }
}

impl fmt::Debug for NicHold<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NicHold")
            .field("kind", &self.pool.spec.kind)
            .field("index", &self.index)
            .field("incarnation", &self.incarnation)
            .finish()
    }
}

/// A buffer inside a command table record: its pool and index alone, so no byte access and no drop glue.
/// It leaves only through [`into_buffer`](Self::into_buffer), at its command's terminal event or a proven stop, or through [`free`](Self::free) once detached.
/// Callers pass the `pools` whose [`Buffer`] became this custody. `into_buffer` and `free` assert that `pools` holds the buffer's pool, because a revived handle addresses bytes from that pool's span and a freed index joins its stack; `detach` moves the buffer's obligation set, so its pool's report counts one more buffer quarantined, and its caller passes the table's `pools`, which admitted the buffer through `belongs_to`.
pub(crate) struct Held<'a> {
    pool: &'a Pool,
    index: usize,
}

impl<'a> Buffer<'a> {
    /// Whether a device holds a reference to the buffer's current incarnation.
    #[inline]
    pub(crate) fn device_held(&self) -> bool {
        self.pool.record(self.index).nic() > 0
    }

    /// Whether this buffer belongs to `pools`.
    #[inline]
    pub(crate) fn belongs_to(&self, pools: &Pools) -> bool {
        pools.holds(self.pool)
    }

    /// Moves the buffer into storage custody: `{APPLICATION}` becomes `{STORAGE}` and the handle's drop no longer runs.
    #[inline]
    pub(crate) fn into_storage(self) -> Held<'a> {
        assert!(
            !self.device_held(),
            "a buffer a device reads takes no device write"
        );
        let buffer = ManuallyDrop::new(self);
        buffer.pool.event(buffer.index, Event::IntoStorage);
        Held {
            pool: buffer.pool,
            index: buffer.index,
        }
    }
}

impl<'a> Held<'a> {
    /// Ends storage custody: `{STORAGE}` becomes `{APPLICATION}` and the handle is live again.
    ///
    /// # Panics
    ///
    /// If `pools` does not hold this buffer's pool.
    #[inline]
    pub(crate) fn into_buffer(self, pools: &'a Pools) -> Buffer<'a> {
        assert!(
            pools.holds(self.pool),
            "a held buffer returns to the pools it came from"
        );
        self.pool.event(self.index, Event::IntoBuffer);
        Buffer {
            pool: self.pool,
            index: self.index,
        }
    }

    /// Marks the command cancelled: `{STORAGE}` becomes `{STORAGE, DETACHED}` and the buffer counts as quarantined.
    #[inline]
    pub(crate) fn detach(&self, pools: &Pools) {
        debug_assert!(
            pools.holds(self.pool),
            "a held buffer is detached by the pools it came from"
        );
        self.pool.event(self.index, Event::Detach);
    }

    /// Frees a detached buffer at its command's terminal event or a proven stop, without ever reviving its handle.
    ///
    /// # Panics
    ///
    /// If `pools` does not hold this buffer's pool.
    #[inline]
    pub(crate) fn free(self, pools: &Pools) {
        assert!(
            pools.holds(self.pool),
            "a held buffer returns to the pools it came from"
        );
        self.pool.event(self.index, Event::FreeDetached);
    }
}

#[cfg(test)]
impl RxPosted<'_> {
    /// Byte offset of the buffer from the arena backing's base.
    pub(crate) fn offset(&self) -> usize {
        self.pool.offset(self.index)
    }
}

#[cfg(test)]
impl Buffer<'_> {
    /// The buffer's index in its pool and its incarnation.
    pub(crate) fn identity(&self) -> (u32, u64) {
        (
            self.index as u32,
            self.pool.record(self.index).incarnation.get(),
        )
    }
}

#[cfg(test)]
impl Held<'_> {
    /// `offset` returns the buffer's displacement in bytes from the arena backing's base.
    pub(crate) fn offset(&self) -> usize {
        self.pool.offset(self.index)
    }

    /// The buffer's pool, index and current incarnation.
    #[cfg(test)]
    pub(crate) fn identity(&self) -> (PoolKind, usize, u64) {
        (
            self.pool.kind(),
            self.index,
            self.pool.record(self.index).incarnation.get(),
        )
    }
}

impl fmt::Debug for Held<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Held")
            .field(&self.pool.offset(self.index))
            .finish()
    }
}
