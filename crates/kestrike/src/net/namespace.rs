//! Shared request admission and wire routing for one endpoint's operations.
//!
//! A wire identity combines a peer, a 16-bit wire slot and a 48-bit generation.
//! Admission returns a separate table handle. Wire slots bind these two identity
//! spaces; per-request work uses the table handle.
//!
//! Invariants owned by this module:
//!
//! - Each wire slot keeps its session's highest admitted or settled
//!   generation, a generation refused while a request held the binding, the
//!   table handle of the request bound to it, and a retained outcome row. Admission
//!   binds a request. `unbind` clears the binding and marks the record unbound;
//!   release clears the binding or the mark. An unbound draining record keeps
//!   its table slot and peer share until release.
//! - Generations below the watermark route as older. The watermark routes to
//!   the bound request and row. Higher generations, or an unset watermark, route
//!   as fresh; admission requires a free binding, a generation above every
//!   settled one and below [`GENERATION_LIMIT`], and room in the peer's share
//!   and table, and builds the request record only after all three checks pass.
//! - An operation that answers a fresh identity without admitting it settles
//!   the identity through [`Namespace::settle`]: on a free binding the answer
//!   the operation keeps becomes the retained row and the generation the
//!   watermark, so a retransmission routes to the answer, or to `Same` with
//!   no row when the operation keeps none; while a request holds the binding
//!   the generation is recorded as refused, admission refuses it as busy, and
//!   the binding's unbind or release raises the watermark to it, after which
//!   admission refuses it as stale. Each wire identity is admitted at most
//!   once per session.
//! - At the watermark, a live record or retained row of another operation yields
//!   [`Route::WrongOperation`]; [`Namespace::route`] increments its counter, and
//!   [`Namespace::lookup`] leaves it unchanged. Every other field stays
//!   unchanged. Rows keep their operation through expiry.
//! - Release preserves the watermark and row of a slot with no refused
//!   generation; with one, unbind or release sets the watermark to it and
//!   drops the row. Admission advances the watermark
//!   and clears the row. Session retirement clears both. The operation checks
//!   row epoch and expiry when answering a frame.
//! - A bound wire slot names a live record of the slot's peer: admission
//!   binds the handle it just admitted for that peer, and `release` clears
//!   that binding when it drops the record unless `unbind` cleared it
//!   earlier.
//! - Session retirement preserves live bindings and their census charges. Each
//!   operation ends its requests and keeps custody until drain completes.
//!   Release checks the exact table handle and peer before clearing a binding,
//!   preserving any successor's binding.
//! - The creator charges the table; construction charges and allocates the wire
//!   slots and a one-bit-per-table-slot unbound mark. Subsequent namespace calls
//!   use that fixed storage.

use crate::storage::{EngineBudget, EngineBudgetExceeded};

use super::datagram::PeerId;
use super::requests::{GENERATION_LIMIT, RequestCensus, RequestId, RequestPressure, RequestTable};

/// The operation a request, a retained row or a frame belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Get,
    Put,
}

/// Operation identity used to check records and retained rows during routing.
/// Implementations keep this identity fixed for each admitted request and its row.
pub trait Operated {
    fn operation(&self) -> Operation;
}

/// Replay evidence whose session and expiry the consuming operation checks.
/// Routing uses `outcome`'s operation even after `expires_us` passes.
#[derive(Debug, Clone, Copy)]
pub struct Cached<T> {
    pub epoch: u64,
    pub expires_us: u64,
    pub outcome: T,
}

impl<T: Copy> Cached<T> {
    pub(super) fn current(self, epoch: u64, now_us: u64) -> Option<T> {
        (self.epoch == epoch && self.expires_us > now_us).then_some(self.outcome)
    }
}

/// One wire slot of one peer as [`Namespace::slot`] decodes it.
#[derive(Debug, Clone, Copy)]
pub struct WireSlot<T> {
    /// The highest generation admitted or settled on the slot this session.
    pub watermark: Option<u64>,
    /// The slot's table handle.
    pub active: Option<RequestId>,
    /// The retained outcome of the slot's last ended or settled request.
    pub cached: Option<Cached<T>>,
    /// The highest generation answered while a request held the binding;
    /// the binding's unbind or release raises the watermark to it.
    pub refused: Option<u64>,
}

impl<T> Default for WireSlot<T> {
    fn default() -> Self {
        Self {
            watermark: None,
            active: None,
            cached: None,
            refused: None,
        }
    }
}

/// The bit of [`Mark::seen`] that marks a request bound in [`Mark::active`].
const BOUND: u64 = 1 << 63;
/// The bit of [`Mark::seen`] that marks the bound request as a PUT.
const BOUND_PUT: u64 = 1 << 59;
/// The bit of [`Mark::seen`] that marks a retained row in [`Kept::cached`].
const ROW: u64 = 1 << 62;
/// The bit of [`Mark::seen`] that marks the retained row as a PUT's.
const ROW_PUT: u64 = 1 << 61;
/// The bit of [`Mark::seen`] that marks a refused generation in [`Kept::refused`].
const REFUSED: u64 = 1 << 60;
/// The bits of [`Mark::seen`] that hold the stored watermark.
const WATERMARK: u64 = (1 << 49) - 1;

/// The routing state of one wire slot, which every frame on the slot reads.
/// Generations are stored one higher, so zero stands for none; a stored
/// generation is at most `GENERATION_LIMIT + 1` and fits [`WATERMARK`].
#[derive(Clone, Copy)]
struct Mark {
    /// One more than the highest generation admitted or settled on the slot
    /// this session, under the [`BOUND`], [`BOUND_PUT`], [`ROW`], [`ROW_PUT`]
    /// and [`REFUSED`] bits.
    seen: u64,
    /// The bound request's table handle in wire form, read only under [`BOUND`].
    active: u64,
}

impl Mark {
    const EMPTY: Self = Self { seen: 0, active: 0 };

    fn bound(self) -> Option<RequestId> {
        (self.seen & BOUND != 0).then(|| RequestId::from_wire(self.active))
    }

    fn binds(self, id: RequestId) -> bool {
        self.seen & BOUND != 0 && self.active == id.wire()
    }
}

/// The parts of one wire slot that only replay and refusal read, aligned so
/// each entry fills whole cache lines.
#[derive(Clone, Copy)]
#[repr(align(64))]
struct Kept<T> {
    /// One more than the highest generation answered while a request held
    /// the binding, read only under [`REFUSED`]; the binding's unbind or
    /// release raises the watermark to it.
    refused: u64,
    /// The retained outcome of the slot's last ended or settled request,
    /// read only under [`ROW`].
    cached: Option<Cached<T>>,
}

/// The [`Mark::seen`] bits naming a retained row of `cached`'s operation.
fn row_bits<T: Operated>(cached: &Cached<T>) -> u64 {
    match cached.outcome.operation() {
        Operation::Get => ROW,
        Operation::Put => ROW | ROW_PUT,
    }
}

/// Where a frame naming a wire identity lands.
#[derive(Debug, Clone, Copy)]
pub enum Route<T> {
    /// The wire slot lies at or past the namespace's width, or the peer outside it.
    Outside,
    /// The generation is below the slot's watermark.
    Older,
    /// The generation is the slot's watermark: its live request and retained row, both of the frame's operation where present.
    Same {
        active: Option<RequestId>,
        cached: Option<Cached<T>>,
    },
    Fresh,
    /// The generation is the watermark and its live request or retained row belongs to another operation; [`Namespace::route`] counts it.
    WrongOperation,
}

/// Why admission refused a fresh request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Peer or wire slot exceeds the configured namespace.
    Outside,
    /// The wire slot binds a request: an active one, or a draining one still bound.
    Busy,
    /// The generation is at or below the slot's watermark.
    Stale,
    /// The request's generation is the last a wire identity carries.
    Exhausted,
    /// The peer's share or the table is full.
    Pressure(RequestPressure),
}

/// Shared table and wire bindings whose active and draining records consume
/// one per-peer share across operations.
#[cfg_attr(test, derive(Clone))]
pub struct Namespace<R, T> {
    table: RequestTable<R>,
    unbound: Box<[u64]>,
    /// The routing state of `width` wire slots per peer, peer `p`'s at `p * width`.
    marks: Box<[Mark]>,
    /// The rows and refusals of the wire slots, indexed as `marks`.
    kept: Box<[Kept<T>]>,
    width: u32,
    wrong_operation: u64,
}

impl<R: Operated, T: Operated + Copy> Namespace<R, T> {
    /// Bytes charged beyond the table, or `None` on `usize` overflow.
    pub fn charge(width: u32, peers: u16, table_slots: u32) -> Option<usize> {
        (width as usize)
            .checked_mul(usize::from(peers))?
            .checked_mul(size_of::<Mark>() + size_of::<Kept<T>>())?
            .checked_add(
                (table_slots as usize)
                    .div_ceil(64)
                    .checked_mul(size_of::<u64>())?,
            )
    }

    /// Creates `width` wire slots per peer around an empty, already-charged `table`.
    /// Charges [`charge`](Self::charge) bytes for the wire slots and the unbound mark.
    ///
    /// # Errors
    ///
    /// Returns `EngineBudgetExceeded` if the charge exceeds the remaining budget;
    /// `budget` stays unchanged.
    pub fn new(
        table: RequestTable<R>,
        width: u32,
        budget: &mut EngineBudget,
    ) -> Result<Self, EngineBudgetExceeded> {
        let peers = table.peers();
        debug_assert_eq!(table.census().live(), 0);
        budget.charge(Self::charge(width, peers, table.slots()).unwrap_or(usize::MAX))?;
        Ok(Self {
            unbound: vec![0; (table.slots() as usize).div_ceil(64)].into_boxed_slice(),
            table,
            marks: vec![Mark::EMPTY; width as usize * usize::from(peers)].into_boxed_slice(),
            kept: vec![
                Kept {
                    refused: 0,
                    cached: None,
                };
                width as usize * usize::from(peers)
            ]
            .into_boxed_slice(),
            width,
            wrong_operation: 0,
        })
    }

    pub fn table(&self) -> &RequestTable<R> {
        &self.table
    }

    /// See [`RequestTable::start_slot_at`].
    #[cfg(test)]
    pub(super) fn start_slot_at(&mut self, slot: u16, generation: u64) {
        self.table.start_slot_at(slot, generation);
    }

    /// Unbinding preserves the table record until release.
    /// `id`, when the slot binds it, must name a draining record.
    #[inline(always)]
    pub(super) fn unbind(&mut self, peer: PeerId, slot: u16, id: RequestId) {
        if let Some(at) = self.at(peer, slot)
            && self.marks[at].binds(id)
        {
            debug_assert_eq!(
                self.table.peer(id),
                Some(peer),
                "a bound handle is live for its slot's peer"
            );
            debug_assert!(self.table.draining(id), "unbinding names a draining record");
            self.free(at);
            let slot = usize::from(id.slot());
            self.unbound[slot / 64] |= 1 << (slot % 64);
        }
    }

    /// Clears every record's unbound mark, so the namespace refuses the
    /// release of each record its sent terminal unbound.
    #[cfg(test)]
    pub(super) fn forget_unbound(&mut self) {
        self.unbound.fill(0);
    }

    #[inline]
    pub(super) fn record_mut(&mut self, id: RequestId) -> Option<&mut R> {
        self.table.get_mut(id)
    }

    #[inline]
    pub(super) fn live_mut(&mut self, slot: u32) -> Option<(RequestId, &mut R)> {
        self.table.live_mut(slot)
    }

    #[inline]
    pub(super) fn begin_drain(&mut self, id: RequestId) -> bool {
        self.table.begin_drain(id)
    }

    pub fn census(&self) -> RequestCensus {
        self.table.census()
    }

    /// Frames that named another operation's request or row.
    pub fn wrong_operation(&self) -> u64 {
        self.wrong_operation
    }

    #[inline]
    fn at(&self, peer: PeerId, slot: u16) -> Option<usize> {
        let at = (u32::from(slot) < self.width)
            .then(|| usize::from(peer.0) * self.width as usize + usize::from(slot))?;
        (at < self.marks.len()).then_some(at)
    }

    /// Whether `generation` is at or below a generation this session already
    /// admitted, settled or refused on wire slot `at`.
    #[inline]
    fn settled(&self, at: usize, generation: u64) -> bool {
        let seen = self.marks[at].seen;
        let refused = if seen & REFUSED != 0 {
            self.kept[at].refused
        } else {
            0
        };
        generation < (seen & WATERMARK).max(refused)
    }

    /// Frees wire slot `at`'s binding. With a refused generation recorded, it
    /// sets the watermark to that generation and drops the retained row.
    #[inline]
    fn free(&mut self, at: usize) {
        let mark = &mut self.marks[at];
        mark.seen &= !(BOUND | BOUND_PUT);
        if mark.seen & REFUSED != 0 {
            mark.seen = self.kept[at].refused;
        }
    }

    /// `peer`'s wire slot `slot`, or `None` outside the namespace.
    pub fn slot(&self, peer: PeerId, slot: u16) -> Option<WireSlot<T>> {
        self.at(peer, slot).map(|at| self.view(at))
    }

    fn view(&self, at: usize) -> WireSlot<T> {
        let (mark, kept) = (self.marks[at], &self.kept[at]);
        WireSlot {
            watermark: (mark.seen & WATERMARK).checked_sub(1),
            active: mark.bound(),
            cached: if mark.seen & ROW != 0 {
                kept.cached
            } else {
                None
            },
            refused: if mark.seen & REFUSED != 0 {
                kept.refused.checked_sub(1)
            } else {
                None
            },
        }
    }

    /// Routes an admitted session's wire identity by generation and operation.
    /// At the watermark, an operation mismatch increments [`wrong_operation`](Self::wrong_operation)
    /// and preserves the table and wire slots. The caller checks the returned
    /// row's epoch and expiry before using its evidence.
    #[inline]
    pub fn route(&mut self, peer: PeerId, wire: RequestId, operation: Operation) -> Route<T> {
        let route = self.lookup(peer, wire, operation);
        if matches!(route, Route::WrongOperation) {
            self.wrong_operation += 1;
        }
        route
    }

    /// Callers use `lookup` to read request evidence before passing the frame to [`route`](Self::route), which counts operation mismatches.
    #[inline]
    pub fn lookup(&self, peer: PeerId, wire: RequestId, operation: Operation) -> Route<T> {
        let Some(at) = self.at(peer, wire.slot()) else {
            return Route::Outside;
        };
        let mark = self.marks[at];
        let next = wire.generation() + 1;
        let seen = mark.seen & WATERMARK;
        if next < seen {
            return Route::Older;
        }
        if next > seen {
            return Route::Fresh;
        }
        let active_other =
            mark.seen & BOUND != 0 && (mark.seen & BOUND_PUT != 0) != (operation == Operation::Put);
        let cached_other =
            mark.seen & ROW != 0 && (mark.seen & ROW_PUT != 0) != (operation == Operation::Put);
        if active_other || cached_other {
            return Route::WrongOperation;
        }
        Route::Same {
            active: mark.bound(),
            cached: if mark.seen & ROW != 0 {
                self.kept[at].cached
            } else {
                None
            },
        }
    }

    fn binding(&self, at: usize, wire: RequestId) -> Result<(), Refusal> {
        if self.marks[at].seen & BOUND != 0 {
            return Err(Refusal::Busy);
        }
        if self.settled(at, wire.generation()) {
            return Err(Refusal::Stale);
        }
        if wire.generation() == GENERATION_LIMIT {
            return Err(Refusal::Exhausted);
        }
        Ok(())
    }

    pub fn admissible(&self, peer: PeerId, wire: RequestId) -> Result<(), Refusal> {
        let at = self.at(peer, wire.slot()).ok_or(Refusal::Outside)?;
        self.binding(at, wire)?;
        self.table.room(peer).map_err(Refusal::Pressure)
    }

    /// Admits a fresh wire identity and returns its table handle for per-request work.
    /// Success raises the wire watermark, binds the handle and clears the retained row.
    ///
    /// # Errors
    ///
    /// Checked in order:
    /// - `Outside`: the peer or wire slot lies outside the namespace.
    /// - `Busy`: a request holds the binding.
    /// - `Stale`: the generation is at or below the watermark.
    /// - `Exhausted`: the generation equals [`GENERATION_LIMIT`].
    /// - `Pressure`: the peer's share or the table is full.
    ///
    /// Every check runs before `build`: a refusal leaves `build` uncalled and
    /// namespace state unchanged, and success calls `build` exactly once.
    #[inline]
    pub fn admit(
        &mut self,
        peer: PeerId,
        wire: RequestId,
        build: impl FnOnce() -> R,
    ) -> Result<RequestId, Refusal> {
        let at = self.at(peer, wire.slot()).ok_or(Refusal::Outside)?;
        self.binding(at, wire)?;
        self.table.room(peer).map_err(Refusal::Pressure)?;
        // `admit` holds exclusive access to `self` while `build` runs, preserving the room `room` confirmed.
        let record = build();
        let put = match record.operation() {
            Operation::Get => 0,
            Operation::Put => BOUND_PUT,
        };
        let Ok(id) = self.table.admit(peer, record) else {
            unreachable!("the table has room for the peer")
        };
        self.marks[at] = Mark {
            seen: (wire.generation() + 1) | BOUND | put,
            active: id.wire(),
        };
        Ok(id)
    }

    /// Replaces the retained row when `peer`'s wire `slot` still binds table handle `id`
    /// and that record belongs to `peer`. A mismatched binding preserves the row.
    /// The caller supplies the request's operation, session epoch and expiry.
    #[inline]
    pub fn retain(&mut self, peer: PeerId, slot: u16, id: RequestId, cached: Cached<T>) {
        if let Some(at) = self.at(peer, slot)
            && self.marks[at].binds(id)
        {
            debug_assert_eq!(
                self.table.peer(id),
                Some(peer),
                "a bound handle is live for its slot's peer"
            );
            self.kept[at].cached = Some(cached);
            let mark = &mut self.marks[at];
            mark.seen = (mark.seen & !(ROW | ROW_PUT)) | row_bits(&cached);
        }
    }

    /// Settles the fresh identity `wire` of `peer` that an operation answered
    /// from outside the table. On a free binding the generation becomes the
    /// watermark and `cached` the slot's retained row, which `None` leaves
    /// empty. While a request holds the binding, the generation is recorded
    /// as refused. A stale generation, [`GENERATION_LIMIT`], or a slot
    /// outside the namespace leaves the namespace unchanged.
    #[inline]
    pub fn settle(&mut self, peer: PeerId, wire: RequestId, cached: Option<Cached<T>>) {
        let Some(at) = self.at(peer, wire.slot()) else {
            return;
        };
        let generation = wire.generation();
        if self.settled(at, generation) || generation == GENERATION_LIMIT {
            return;
        }
        let seen = self.marks[at].seen;
        if seen & BOUND != 0 {
            self.kept[at].refused = generation + 1;
            self.marks[at].seen = seen | REFUSED;
            return;
        }
        let row = cached.as_ref().map_or(0, row_bits);
        self.kept[at].cached = cached;
        self.marks[at].seen = (generation + 1) | (seen & REFUSED) | row;
    }

    /// Drops the record and frees its slot and peer share after its operation drains custody.
    /// Success clears the binding when wire slot `slot` still binds `id`, clears the unbound mark, raises the watermark to a generation refused while the binding was held, and otherwise preserves the watermark, the retained row and any successor's binding.
    /// Returns `false` with state unchanged when the wire slot lies outside the namespace, `id` is not live for `peer`, or `id` is neither bound to `slot` nor marked unbound.
    #[inline]
    pub fn release(&mut self, id: RequestId, peer: PeerId, slot: u16) -> bool {
        let Some(at) = self.at(peer, slot) else {
            return false;
        };
        let table_slot = usize::from(id.slot());
        let (word, bit) = (table_slot / 64, 1 << (table_slot % 64));
        let bound = self.marks[at].binds(id);
        if self.table.peer(id) != Some(peer) || (!bound && self.unbound[word] & bit == 0) {
            return false;
        }
        if self.table.discard(id).is_none() {
            return false;
        }
        self.unbound[word] &= !bit;
        if bound {
            self.free(at);
        }
        true
    }

    /// Clears `peer`'s watermarks and retained rows while preserving live bindings and census.
    /// Each operation ends the peer's requests before this call, then releases them
    /// once its custody drains. A draining binding keeps fresh admission busy.
    pub fn retire(&mut self, peer: PeerId) {
        let width = self.width as usize;
        let Some(marks) = self
            .marks
            .get_mut(usize::from(peer.0) * width..(usize::from(peer.0) + 1) * width)
        else {
            return;
        };
        for mark in marks {
            mark.seen &= BOUND | BOUND_PUT;
        }
    }
}

/// Formats each wire slot as its decoded [`WireSlot`], so two namespaces in
/// the same state format alike whatever their unread fields hold.
#[cfg(test)]
impl<R: Operated + std::fmt::Debug, T: Operated + Copy + std::fmt::Debug> std::fmt::Debug
    for Namespace<R, T>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let slots: Vec<WireSlot<T>> = (0..self.marks.len()).map(|at| self.view(at)).collect();
        f.debug_struct("Namespace")
            .field("table", &self.table)
            .field("unbound", &self.unbound)
            .field("slots", &slots)
            .field("width", &self.width)
            .field("wrong_operation", &self.wrong_operation)
            .finish()
    }
}
