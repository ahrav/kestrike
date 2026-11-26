//! Packet buffers leased from the arena's packet pools, and the exclusive
//! owner-thread leases that hold them.
//!
//! Invariants owned by this module:
//!
//! - BOUNDED: a [`PacketPool`] is a view over one packet kind of a
//!   [`BufferArena`](crate::storage::BufferArena), whose backing, records and
//!   device reference counts the arena allocated and charged once. Acquire,
//!   release and conversion reuse that storage and allocate nothing.
//! - A [`PacketLease`] holds one arena buffer exclusively and exposes only
//!   its frame data room, as laid out by [`PacketLayout`]. It returns its
//!   buffer to the arena pool it came from when it drops, whatever the
//!   endpoint did since, so a lease outlives polling and close; a forgotten
//!   lease keeps its buffer out of the pool for good.
//! - One view at a time holds a packet kind, so its data count covers every
//!   data lease of the kind.
//! - [`PacketPool::data_cap`] is `count - control_reserve - retired`,
//!   saturating at zero: every retired buffer comes out of data capacity,
//!   and pool count and control reserve stay as configured. Acquiring a
//!   data lease and converting a control lease to data both refuse while
//!   data leases hold `data_cap` or more buffers. While data stays within
//!   the cap and at most `count - control_reserve` buffers have retired,
//!   `control_reserve` buffers stay available to control use whenever no
//!   control lease or receive posting holds them.
//! - A retirement leaves every live data lease, its bytes and its buffer's
//!   identity in place, so data leases may exceed a shrunk cap until they
//!   drain. Meanwhile the control reserve is short by
//!   `data - data_cap`, the [`PacketPoolReport::reserve_shortfall`], which
//!   reaches zero once data drains to the cap; data admission and
//!   conversion resume once data drops below the cap. Retired buffers never
//!   return, so a view whose `data_cap` reaches zero admits no data again,
//!   which [`PacketPoolReport::data_capacity_lost`] reports; each later
//!   retirement takes a control reserve buffer.
//! - A buffer a device receives into is posted with no CPU view until the
//!   device finished writing it; [`PacketPool::received`] then turns it into
//!   a control lease.
//! - Leases borrow the pool and the arena, which are not `Sync`, so neither a
//!   lease nor a borrow leaves its thread, and no lease outlives its pool.

use std::cell::Cell;

use crate::storage::{Buffer, BufferArena, PacketLayout, Platform, PoolKind, RxPosted};

/// Why a pool view was not built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketPoolError {
    /// `kind` is not a packet kind, or the arena holds no pool of it.
    Kind,
    /// The stride holds no data room after the native object layout.
    Layout,
    /// `control_reserve` is not below the pool's count.
    Reserve,
    /// Another view holds the kind, whose data cap would then miss its leases.
    InUse,
}

/// What a lease's buffer holds, which decides the cap it counts against.
///
/// Word-sized, so every scalar in a [`PacketLease`] is one aligned word and
/// each word load of a moved lease covers exactly one earlier word store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum PacketUse {
    /// Control frames and receive scratch; may use every free buffer.
    Control,
    /// Data the application or a retransmission holds; capped at [`PacketPool::data_cap`].
    Data,
}

/// No buffer was free for the requested use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketExhausted {
    pub wanted: PacketUse,
}

/// A pool's counters; `free + data + control` covers every buffer neither posted nor retired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketPoolReport {
    pub count: u32,
    pub free: u32,
    pub data: u32,
    pub control: u32,
    /// Bytes of frame data room per buffer.
    pub data_room: u32,
    /// [`PacketPool::data_cap`] when the report was taken.
    pub data_cap: u32,
}

impl PacketPoolReport {
    /// Buffers the control reserve lacks while data leases drain above the cap after a retirement: `data - data_cap`, or zero. Once [`data_capacity_lost`](Self::data_capacity_lost) holds, each further retirement also takes a reserve buffer; this count omits those, and the arena pool's retired count shows them.
    pub fn reserve_shortfall(&self) -> u32 {
        self.data.saturating_sub(self.data_cap)
    }

    /// Whether retirement took the last of the view's data capacity, so the view admits no data lease or conversion again.
    pub fn data_capacity_lost(&self) -> bool {
        self.data_cap == 0
    }
}

/// One packet kind of an arena, as an endpoint leases it.
///
/// A lease cannot leave its thread:
///
/// ```compile_fail,E0277
/// # fn check(pool: &kestrike::net::PacketPool<'_>) {
/// use kestrike::net::PacketUse;
///
/// fn requires_send<T: Send>(_: T) {}
///
/// let lease = pool.acquire(PacketUse::Data).unwrap();
/// requires_send(lease);
/// # }
/// ```
///
/// nor outlive its pool:
///
/// ```compile_fail,E0597
/// # fn check<P: kestrike::storage::Platform>(arena: &kestrike::storage::BufferArena<P>) {
/// use kestrike::net::{PacketPool, PacketUse};
/// use kestrike::storage::PoolKind;
///
/// let lease;
/// {
///     let pool = PacketPool::new(arena, PoolKind::PacketReceive, 1).unwrap();
///     lease = pool.acquire(PacketUse::Data).unwrap();
/// }
/// drop(lease);
/// # }
/// ```
pub struct PacketPool<'a> {
    // `new` claims `pool` through `claim_view`; `Drop` ends the claim.
    pool: &'a crate::storage::device::Pool,
    layout: PacketLayout,
    count: u32,
    data: Cell<u32>,
    data_cap: u32,
}

/// An exclusive hold on one packet buffer of a [`PacketPool`], with the length of the frame bytes it holds.
///
/// The lease is neither `Clone` nor `Send`; dropping it returns the buffer to its pool.
pub struct PacketLease<'p> {
    buffer: Buffer<'p>,
    pool: &'p PacketPool<'p>,
    len: usize,
    used: PacketUse,
    /// Bytes of the data room before the lease's first byte, a word like every other field so a receive's field-by-field build is read back whole.
    start: usize,
}

impl<'a> PacketPool<'a> {
    /// A view over `arena`'s pool of packet `kind`, keeping `control_reserve` buffers from data use.
    ///
    /// # Errors
    ///
    /// `Kind`, `Layout`, `Reserve`, then `InUse` while another view of `kind` lives.
    pub fn new<P: Platform>(
        arena: &'a BufferArena<P>,
        kind: PoolKind,
        control_reserve: u32,
    ) -> Result<Self, PacketPoolError> {
        let spec = arena.config().pool(kind);
        if !PoolKind::PACKET.contains(&kind) || spec.count == 0 {
            return Err(PacketPoolError::Kind);
        }
        let layout = PacketLayout::of(spec.buffer_len as usize).ok_or(PacketPoolError::Layout)?;
        if control_reserve >= spec.count {
            return Err(PacketPoolError::Reserve);
        }
        let pool = arena.pools().pool(kind);
        if !pool.claim_view() {
            return Err(PacketPoolError::InUse);
        }
        Ok(Self {
            pool,
            layout,
            count: spec.count,
            data: Cell::new(0),
            data_cap: spec.count - control_reserve,
        })
    }

    /// Leases a free buffer for `used`, its length zero.
    ///
    /// # Errors
    ///
    /// `PacketExhausted` when no buffer is free, for data use when data leases already hold [`data_cap`](Self::data_cap) or more buffers, or while a device mempool serves the kind and alone hands out its buffers.
    #[inline]
    pub fn acquire(&self, used: PacketUse) -> Result<PacketLease<'_>, PacketExhausted> {
        if (used == PacketUse::Data && self.data.get() >= self.data_cap()) || self.pool.served() {
            return Err(PacketExhausted { wanted: used });
        }
        let buffer = self
            .pool
            .acquire()
            .map_err(|_| PacketExhausted { wanted: used })?;
        if used == PacketUse::Data {
            self.data.set(self.data.get() + 1);
        }
        Ok(PacketLease {
            buffer,
            pool: self,
            len: 0,
            used,
            start: 0,
        })
    }

    /// Posts a free buffer to a device for receive.
    ///
    /// # Errors
    ///
    /// `PacketExhausted` for control use when no buffer is free, or while a device mempool serves the kind and alone posts its buffers.
    #[inline]
    pub fn post(&self) -> Result<RxPosted<'a>, PacketExhausted> {
        if self.pool.served() {
            return Err(PacketExhausted {
                wanted: PacketUse::Control,
            });
        }
        self.pool.post().map_err(|_| PacketExhausted {
            wanted: PacketUse::Control,
        })
    }

    /// Turns a posted buffer the device wrote `len` frame bytes into, at the
    /// layout's data offset, into a control lease.
    ///
    /// # Safety
    ///
    /// The device finished writing `posted`, its writes visible to this thread.
    ///
    /// # Panics
    ///
    /// When `posted` is not of this view's arena and kind.
    #[inline]
    pub unsafe fn received(&self, posted: RxPosted<'a>, len: usize) -> PacketLease<'_> {
        assert!(
            posted.is_of(self.pool),
            "a posting completes through its own view"
        );
        // SAFETY: the caller's contract.
        let buffer = unsafe { posted.complete() };
        let mut lease = PacketLease {
            buffer,
            pool: self,
            len: 0,
            used: PacketUse::Control,
            start: 0,
        };
        lease.set_len(len);
        lease
    }

    /// Whether `posted` is a posting of this view's pool.
    pub fn holds(&self, posted: &RxPosted<'a>) -> bool {
        posted.is_of(self.pool)
    }

    /// The arena pool the view holds.
    #[inline]
    pub(crate) fn served(&self) -> &'a crate::storage::device::Pool {
        self.pool
    }

    /// The data room's place in each buffer.
    #[inline]
    pub fn layout(&self) -> PacketLayout {
        self.layout
    }

    /// The data-lease count below which data admission and conversion succeed:
    /// the count less the control reserve and every retired buffer, saturating
    /// at zero. Subtracting retired buffers, which never return, keeps a
    /// retirement out of the reserve while the cap is positive. Data leases
    /// live at a retirement may exceed the cap until they drain.
    #[inline]
    pub fn data_cap(&self) -> u32 {
        self.data_cap.saturating_sub(self.pool.retired())
    }

    /// The buffers the view keeps from data use, as configured at
    /// [`new`](Self::new); a retirement leaves it unchanged.
    #[inline]
    pub(crate) fn control_reserve(&self) -> u32 {
        self.count - self.data_cap
    }

    /// Buffers off the free stack: leased, posted to or still read by a device, or retired. Reads the pool's
    /// free count in O(1).
    #[inline]
    pub fn not_free(&self) -> u32 {
        self.pool.not_free()
    }

    pub fn report(&self) -> PacketPoolReport {
        let pool = self.pool.report();
        let data = self.data.get();
        PacketPoolReport {
            count: self.count,
            free: pool.free,
            data,
            control: pool.application - data,
            data_room: self.layout.data_room as u32,
            data_cap: self.data_cap(),
        }
    }
}

impl PacketLease<'_> {
    #[inline]
    pub fn buffer_mut(&mut self) -> &mut [u8] {
        let layout = self.pool.layout;
        let start = layout.data_offset + self.start;
        &mut self.buffer.bytes_mut()[start..layout.data_offset + layout.data_room]
    }

    /// The `len` bytes the buffer holds.
    #[inline]
    pub fn bytes(&self) -> &[u8] {
        let start = self.pool.layout.data_offset + self.start;
        &self.buffer.bytes()[start..start + self.len]
    }

    /// Bytes of data room from the lease's first byte.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.pool.layout.data_room - self.start
    }

    /// Narrows the lease to `range` of the bytes it holds, such as a frame's payload after its headers.
    ///
    /// # Panics
    ///
    /// When `range` is inverted or reaches past the bytes held.
    #[inline]
    pub fn keep(&mut self, range: std::ops::Range<usize>) {
        assert!(
            range.start <= range.end && range.end <= self.len,
            "a kept range lies inside the bytes held"
        );
        self.start += range.start;
        self.len = range.len();
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Records that the buffer holds `len` bytes, at most its capacity.
    #[inline]
    pub fn set_len(&mut self, len: usize) {
        debug_assert!(len <= self.capacity());
        self.len = len.min(self.capacity());
    }

    /// Moves a control lease under the data cap, so its bytes may be held as data.
    ///
    /// # Errors
    ///
    /// `PacketExhausted` when data leases already hold [`PacketPool::data_cap`] or more buffers; the lease stays control.
    #[inline]
    pub fn retain_as_data(&mut self) -> Result<(), PacketExhausted> {
        if self.used == PacketUse::Data {
            return Ok(());
        }
        let pool = self.pool;
        if pool.data.get() >= pool.data_cap() {
            return Err(PacketExhausted {
                wanted: PacketUse::Data,
            });
        }
        pool.data.set(pool.data.get() + 1);
        self.used = PacketUse::Data;
        Ok(())
    }

    /// Whether this lease came from `pool`.
    #[inline]
    pub fn belongs_to(&self, pool: &PacketPool<'_>) -> bool {
        std::ptr::eq(
            std::ptr::from_ref(self.pool).cast::<()>(),
            std::ptr::from_ref(pool).cast::<()>(),
        )
    }
}

#[cfg(test)]
impl PacketLease<'_> {
    /// The leased buffer's index in its pool and its incarnation.
    pub(crate) fn identity(&self) -> (u32, u64) {
        self.buffer.identity()
    }
}

impl Drop for PacketPool<'_> {
    fn drop(&mut self) {
        self.pool.end_view();
    }
}

impl Drop for PacketLease<'_> {
    #[inline]
    fn drop(&mut self) {
        if self.used == PacketUse::Data {
            self.pool.data.set(self.pool.data.get() - 1);
        }
    }
}

impl std::fmt::Debug for PacketLease<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketLease")
            .field("len", &self.len)
            .field("used", &self.used)
            .finish()
    }
}

/// A heap-backed arena of `count` packet buffers of `stride` bytes and eight
/// header buffers, for tests that keep it in their own scope.
#[cfg(test)]
pub(crate) fn test_arena(
    count: u32,
    stride: u32,
) -> BufferArena<crate::storage::test_platform::TestPlatform> {
    use crate::storage::test_platform::TestPlatform;
    use crate::storage::{BufferConfig, EngineBudget, HugepageSize, NodeMask, PoolSpec};

    let pools = [
        PoolSpec {
            kind: PoolKind::PacketReceive,
            count,
            buffer_len: stride,
        },
        PoolSpec {
            kind: PoolKind::PacketHeader,
            count: 8,
            buffer_len: 4096,
        },
    ];
    let config = BufferConfig {
        hugepage: HugepageSize::TwoMiB,
        nodes: NodeMask::from_nodes(&[0]).expect("node 0"),
        pools: &pools,
    };
    let validated = config.validate().expect("a valid packet arena");
    BufferArena::initialize(
        &validated,
        TestPlatform::heap(4096),
        &mut EngineBudget::new(usize::MAX),
    )
    .expect("a heap arena")
}

/// A pool view over a leaked [`test_arena`], for tests whose pools outlive
/// any scope.
#[cfg(test)]
pub(crate) fn test_pool_with(
    count: u32,
    control_reserve: u32,
    stride: u32,
) -> Result<PacketPool<'static>, PacketPoolError> {
    PacketPool::new(
        Box::leak(Box::new(test_arena(count, stride))),
        PoolKind::PacketReceive,
        control_reserve,
    )
}

/// [`test_pool_with`] of 16 KiB buffers, whose data room holds a whole frame.
#[cfg(test)]
pub(crate) fn test_pool(
    count: u32,
    control_reserve: u32,
) -> Result<PacketPool<'static>, PacketPoolError> {
    test_pool_with(count, control_reserve, 16384)
}
