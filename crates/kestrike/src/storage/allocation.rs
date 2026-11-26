//! The unique owner of one reserved extent.
//!
//! An [`ExtentReservation`] borrows the [`Storage`] it came from and names
//! one slot, its incarnation, its extent and its record layout. The fill
//! that owns it writes the record to the device through the volume, so the
//! payload lives on the device alone. The owner is unique:
//! only this crate constructs it, it has no `Clone`, freeing takes the owner
//! itself, and its completion, which publication performs with the
//! publication's portable pair, consumes it as the completion proof.
//!
//! Dropping the owner is abandonment, not return. It makes one nonblocking
//! gate attempt; with the gate it moves the ledger from `Filling` to
//! `Retired` and sets the slot's pre-reserved flag, without it the flag and
//! the volume's pending counter record the obligation and the ledger catches up
//! when maintenance services the flag. Nothing is freed, nothing waits,
//! nothing scans, nothing unmaps. [`cancel`](ExtentReservation::cancel)
//! returns storage immediately when no write of the extent was ever
//! submitted, its slot counts no right and the gate is free. Once a write
//! was submitted, or its submit unwound with the right installed, the extent
//! returns through service, after it observes the slot's count at zero; the
//! volume's write right keeps that count positive until the fill's last
//! outstanding write reaches its terminal or, for a submit whose driver call
//! unwound, the proven stop.
//!
//! ```compile_fail,E0599
//! # use kestrike::storage::*;
//! # fn f(storage: &Storage<LinuxPlatform>, budget: &mut WorkBudget) {
//! let reservation = storage.reserve(Some(1), Some(1), budget).unwrap();
//! let copy = reservation.clone();
//! # }
//! ```
//!
//! ```compile_fail,E0599
//! # use kestrike::storage::*;
//! # fn f(storage: &Storage<LinuxPlatform>, budget: &mut WorkBudget) {
//! let reservation = storage.reserve(Some(1), Some(1), budget).unwrap();
//! let id = reservation.id();
//! storage.free(id);
//! # }
//! ```
//!
//! ```compile_fail,E0451
//! # use kestrike::storage::*;
//! # fn f(storage: &Storage<LinuxPlatform>, real: ExtentReservation<'_, LinuxPlatform>) {
//! let forged = ExtentReservation { storage, ..real };
//! # }
//! ```
//!
//! Stable rustdoc does not check the error codes above; they record the
//! intended cause (E0599 missing method, E0451 private field) for a reader,
//! and a signature change that made a snippet fail for another reason would
//! need these rewritten.

use std::sync::atomic::Ordering;

use super::budget::{WorkBudget, WorkKind};
use super::capture::PoisonOnUnwind;
use super::completed::{CompleteError, Completed};
use super::extent::{ExtentLocator, HeldPhase};
use super::layout::AllocationLayout;
use super::os::Platform;
use super::owner::{Pool, Storage};
use super::pending::unmark_parked_slot;
use super::portable::PortableExpiry;
use super::probe::{self, Event};
use super::recovery::{NO_RECORD, PARKED_EPOCH};
use super::release::{ReturnTransfer, park_marked};
use super::reserve::return_extent;
use super::slot::deadline_seconds;
use super::tables::{Naming, SlotIndex, SlotState, Tables};
use super::word::{self, ABANDONED, LINKED, RETIRED};
use crate::index::Key;

/// Opaque identity of one allocation: the slot and the incarnation the slot
/// had when it was issued. Equality is identity equality only; it proves
/// nothing about liveness and grants no access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AllocationId {
    slot: SlotIndex,
    incarnation: u32,
}

impl AllocationId {
    pub(crate) fn new(slot: SlotIndex, incarnation: u32) -> Self {
        Self { slot, incarnation }
    }

    /// Slot position, for reports. An index alone confers no access.
    pub fn slot_index(&self) -> usize {
        self.slot.0
    }

    pub(crate) fn slot(&self) -> SlotIndex {
        self.slot
    }

    pub(crate) fn incarnation(&self) -> u32 {
        self.incarnation
    }

    /// The value a record header stores for this allocation.
    pub(crate) fn record_tag(&self) -> u64 {
        (self.slot.0 as u64) << 32 | u64::from(self.incarnation)
    }

    /// The allocation `tag`, a [`record_tag`](Self::record_tag), names.
    pub(crate) fn of_record_tag(tag: u64) -> Self {
        Self::new(SlotIndex((tag >> 32) as usize), tag as u32)
    }
}

/// Unique owner of one reserved extent. See the module documentation.
pub struct ExtentReservation<'s, P: Platform> {
    pub(crate) lineage: u32,
    storage: &'s Storage<P>,
    id: AllocationId,
    locator: ExtentLocator,
    layout: AllocationLayout,
    /// Set once the first write of the extent was submitted. From then on
    /// `cancel` refuses and drop abandons the extent to service, which waits
    /// for the slot's count.
    written: bool,
}

impl<P: Platform> std::fmt::Debug for ExtentReservation<'_, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtentReservation")
            .field("id", &self.id)
            .field("locator", &self.locator)
            .field("written", &self.written)
            .finish_non_exhaustive()
    }
}

impl<'s, P: Platform> ExtentReservation<'s, P> {
    pub(crate) fn new(
        storage: &'s Storage<P>,
        id: AllocationId,
        locator: ExtentLocator,
        layout: AllocationLayout,
        lineage: u32,
    ) -> Self {
        Self {
            storage,
            id,
            locator,
            layout,
            written: false,
            lineage,
        }
    }

    /// The slot's word still describes this owner: same incarnation, still
    /// filling. Checked under the gate before any table is changed on this
    /// owner's behalf.
    fn owns(&self, pool: &Pool) -> bool {
        describes(pool, SlotState::Filling, self.id)
    }

    pub fn id(&self) -> AllocationId {
        self.id
    }

    /// The extent this owner holds, in units of the volume, or its sequence's
    /// handle for an object of several extents.
    pub fn locator(&self) -> ExtentLocator {
        self.locator
    }

    /// The record layout the extent was reserved for.
    pub(super) fn layout(&self) -> AllocationLayout {
        self.layout
    }

    /// Whether a write of the extent was ever submitted.
    #[cfg(test)]
    pub(crate) fn written(&self) -> bool {
        self.written
    }

    /// Records that a write of the extent was submitted, so `cancel`
    /// refuses from now on and drop abandons the extent to service.
    pub(super) fn mark_written(&mut self) {
        self.written = true;
    }

    /// Ends this owner's access and hands the allocator the eligibility
    /// transfer for exactly this incarnation. With the unique owner consumed
    /// no accessor remains, which is the whole reuse predicate for a
    /// reservation nothing wrote. Nothing is freed here: the transfer is
    /// consumed by [`Storage::return_allocation`] or serviced later. An owner
    /// that reaches the return holds the slot's only claim and a zero count:
    /// no write was submitted, or its last write's terminal released the
    /// right.
    pub fn release(self) -> ReturnTransfer<'s, P> {
        let transfer = ReturnTransfer::new(self.storage, self.id);
        std::mem::forget(self);
        transfer
    }

    /// Immediate rollback of a reservation no write was submitted for.
    /// Succeeds only when nothing was written, the slot counts no right and
    /// the gate is free; otherwise the owner is dropped and abandonment
    /// applies.
    ///
    /// # Errors
    ///
    /// `Retained` when a write was submitted, the slot's word counts a right,
    /// the storage is torn down, the gate is busy or poisoned, or the slot's
    /// word names a different state or incarnation; the owner is then
    /// dropped, which abandons the reservation.
    pub fn cancel(self) -> Result<(), Retained> {
        self.rollback()?;
        std::mem::forget(self);
        Ok(())
    }

    /// Disposes of the reservation for an owner that holds a record beside
    /// it: [`cancel`](Self::cancel), or the abandonment its drop performs
    /// when the extent is retained. Returns false when that abandonment's
    /// park found the slot word malformed or naming another incarnation, as [`abandon_in_place`](Self::abandon_in_place)
    /// reports, so the caller keeps its record occupied. A rollback that
    /// panics unwinds through the owner, whose drop parks the abandonment.
    pub(super) fn dispose(self) -> bool {
        if self.rollback().is_ok() {
            std::mem::forget(self);
            return true;
        }
        self.abandon()
    }

    /// The abandonment the drop performs, consuming the owner, with
    /// [`abandon_in_place`](Self::abandon_in_place)'s result.
    pub(super) fn abandon(self) -> bool {
        std::mem::ManuallyDrop::new(self).abandon_in_place()
    }

    /// The rollback of [`cancel`](Self::cancel) on a borrowed owner. On `Ok`
    /// the extent has returned and the owner must be forgotten, never dropped,
    /// or abandonment would charge the returned extent again; on `Err` nothing
    /// changed and dropping the owner abandons as usual.
    // Forced inline, so an owner that holds this reservation in place
    // disposes of it without reading it out by value or calling out.
    #[inline(always)]
    pub(super) fn rollback(&self) -> Result<(), Retained> {
        if self.written {
            return Err(Retained);
        }
        let Some(pool) = self.storage.live_pool() else {
            return Err(Retained);
        };
        pool.prefetch_slot(self.id.slot.0);
        let Ok(access) = pool.try_lock_quiet() else {
            return Err(Retained);
        };
        // Both outcomes end the hold through `release`, so its drop is a
        // panic of the owner check on a malformed slot word or of the return,
        // and that drop poisons the gate also in a rollback made by a thread
        // that was already unwinding.
        let mut access = access.poison_on_unwind();
        // A write submit installs the slot's right before its driver call,
        // and a call that unwinds leaves the right counted with nothing
        // marked written; the right returns only at the write's terminal
        // or the proven stop, so the extent stays abandoned until then.
        let returns = self.owns(pool)
            && word::refs(pool.records()[self.id.slot.0].ident.load(Ordering::Acquire)) == 0;
        if returns {
            // A rollback holds no budget: it returns uncharged, its visits
            // bounded by what the slot holds (`Pool::held_work`), one extent's
            // bound for a direct extent and every extent's for a sequence.
            return_extent(
                &mut access.tables(),
                pool,
                self.id.slot.0,
                HeldPhase::Reserved,
            );
        }
        access.release();
        if returns { Ok(()) } else { Err(Retained) }
    }

    /// The abandonment the drop performs, on a borrowed owner; any caller but
    /// the drop must forget the owner afterwards, or abandonment would charge
    /// the extent twice.
    ///
    /// Returns false when the gate recorded nothing and the park found the
    /// slot word malformed or naming another incarnation, as
    /// [`park`](super::release::park) reports: nothing records
    /// the abandonment and nothing will service the slot, so an owner that
    /// holds a record beside the reservation keeps it occupied. True after
    /// teardown.
    #[inline(always)]
    pub(super) fn abandon_in_place(&self) -> bool {
        let Some(pool) = self.storage.live_pool() else {
            return true;
        };
        abandon(pool, self.id, Owned::Filling, 0, false, None).1
    }

    /// Binds the slot's record for `key` and `expires_at_ticks` with the
    /// absent portable pair and the fixture session as the record's
    /// generation, moving the slot from filling to resident; the
    /// test build's completion outside publication. Consuming the owner is
    /// the completion proof. The record's bytes are whatever the owner's fill wrote to the
    /// device; publication requires every write of it to have succeeded
    /// before it calls this.
    ///
    /// Order: one coordination attempt pays for the gate try and one update
    /// for the transition. Under the gate the slot's word must still
    /// describe this owner, else `Rejected` with both steps debited and
    /// nothing bound; then the key's fingerprint and the deadline's whole
    /// seconds are stored, the state moves to resident, and the ledger
    /// moves the payload bytes from reserved to resident and one slot from
    /// filling to resident.
    ///
    /// # Errors
    ///
    /// The owner comes back with a [`CompleteError`]. The issued incarnation
    /// stays consumed either way; only dropping, cancelling or releasing the
    /// returned owner frees the slot.
    // Forced inline, with `bind` below: the owner arrives by value and the
    // result carries either the completed owner or the owner back, so an
    // out-of-line call copies both through memory, and those copies stall on
    // store forwarding behind the field-wise stores that built them. Inlined,
    // the fields are read where `reserve` left them and the completed owner
    // is written where the caller keeps it.
    #[cfg(test)]
    #[inline(always)]
    pub fn complete(
        self,
        key: Key,
        expires_at_ticks: u64,
        budget: &mut WorkBudget,
    ) -> Result<Completed<'s, P>, (Self, CompleteError)> {
        self.complete_under(
            key,
            expires_at_ticks,
            Naming {
                session: super::volume_fixture::SESSION,
                version: 0,
            },
            budget,
        )
    }

    /// [`complete`](Self::complete) with `naming` as the record's session and cache version: the ones a fixture wrote the record's header under.
    #[cfg(test)]
    pub(crate) fn complete_under(
        self,
        key: Key,
        expires_at_ticks: u64,
        naming: Naming,
        budget: &mut WorkBudget,
    ) -> Result<Completed<'s, P>, (Self, CompleteError)> {
        // The key's hash word, the removal route of expiry and eviction; a
        // storage without an index routes nothing and stores zero.
        let fingerprint = self.storage.index().map_or(0, |index| {
            index
                .hasher
                .route_unpaid(&key, &index.geometry, crate::index::Prefetch::NONE)
                .map_or(0, |route| route.fingerprint())
        });
        self.complete_routed(
            key,
            fingerprint,
            expires_at_ticks,
            PortableExpiry::ABSENT,
            naming,
            budget,
        )
    }

    /// `fingerprint` is the storage hasher's word for `key`, or zero for a
    /// storage that routes nothing: one with no index or no enabled shard.
    /// The bind stores the full key and `expiry`, the publication's portable
    /// pair, beside the slot's record for the volume's capture; a test build
    /// also keeps the key on the completed owner so test-only publication
    /// can route by it.
    /// `naming` holds the writer session and the cache version of the record's header.
    #[inline(always)]
    pub(crate) fn complete_routed(
        self,
        key: Key,
        fingerprint: u64,
        expires_at_ticks: u64,
        expiry: PortableExpiry,
        naming: Naming,
        budget: &mut WorkBudget,
    ) -> Result<Completed<'s, P>, (Self, CompleteError)> {
        match self.bind(key, fingerprint, expires_at_ticks, expiry, naming, budget) {
            Ok(()) => {
                #[cfg(not(test))]
                let completed = Completed::new(self.storage, self.id);
                #[cfg(test)]
                let completed = Completed::new(self.storage, self.id, key);
                std::mem::forget(self);
                Ok(completed)
            }
            Err(error) => Err((self, error)),
        }
    }

    /// The fallible part of [`complete_routed`](Self::complete_routed): on success the
    /// record is bound and the ledger says resident. Borrowed so
    /// a refusal leaves the owner in the caller's hands.
    #[inline(always)]
    fn bind(
        &self,
        key: Key,
        fingerprint: u64,
        expires_at_ticks: u64,
        expiry: PortableExpiry,
        naming: Naming,
        budget: &mut WorkBudget,
    ) -> Result<(), CompleteError> {
        let pool = self.storage.live_pool().ok_or(CompleteError::TornDown)?;
        budget.debit(WorkKind::CoordinationAttempt)?;
        // The binding and each refusal end the hold through `release`, so
        // its drop is a panic under it, and that drop poisons the gate also
        // in a completion made by a thread that was already unwinding.
        let mut access = pool
            .try_lock()
            .map_err(CompleteError::Gate)?
            .poison_on_unwind();
        if let Err(exhausted) = budget.debit(WorkKind::Update) {
            access.release();
            return Err(exhausted.into());
        }
        if !self.owns(pool) {
            access.release();
            return Err(CompleteError::Rejected);
        }
        let mut tables = access.tables();
        let slot = self.id.slot.0;
        let record = &pool.records()[slot];
        record.set_fingerprint(fingerprint);
        let expires_at_s = deadline_seconds(expires_at_ticks);
        record.set_expires_at_s(expires_at_s);
        // Membership starts in the hold that sets Resident, inside the one
        // update debited above; the word carries no visited bit, since the
        // return cleared the previous occupant's and a retain needs the
        // count this object's publication installs.
        let ident = &record.ident;
        let bind =
            |linked| word::move_state(ident, SlotState::Filling, SlotState::Resident, linked);
        tables.queue().link_with(slot, bind);
        tables.bind_naming(slot, key, expiry, naming);
        if tables.state.note_deadline(expires_at_s) {
            pool.publish_deadline_bound(tables.state.earliest_deadline);
        }
        // The whole object's payload, which the slot's extents hold together.
        tables.publish_payload(self.layout.payload());
        tables.state.ledger.filling -= 1;
        tables.state.ledger.resident += 1;
        access.release();
        Ok(())
    }
}

/// The owned state a record must still hold for the owner asking about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Owned {
    Filling,
    Resident,
}

impl Owned {
    fn slot_state(self) -> SlotState {
        match self {
            Self::Filling => SlotState::Filling,
            Self::Resident => SlotState::Resident,
        }
    }
}

/// Whether slot `id`'s word still names the owner `id` in state `state`.
/// Owner methods and `abandon` check this under the gate before changing
/// any table; the gate orders the word's load against the claim and every
/// state move, and a malformed word panics under the gate. The slot's
/// extent is fixed from its claim to its return, so the incarnation names
/// the extent too.
#[inline(always)]
pub(super) fn describes(pool: &Pool, state: SlotState, id: AllocationId) -> bool {
    pool.gate_state(id.slot.0) == (state, id.incarnation)
}

/// How an abandonment or retirement was recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetireOutcome {
    /// The ledger moved the slot to retired under the gate; the slot is
    /// flagged for the deferred return.
    Recorded,
    /// The gate was busy or poisoned, or the record no longer named its owner.
    /// The park records the abandonment only while the word names the
    /// owner's incarnation, and a later service pass resolves that slot.
    /// A poisoned gate makes service fail with `GateError::Poisoned`, so the
    /// slot stays charged.
    Parked,
}

/// Records that the owner of `id`, in state `from`, was dropped or retired
/// without returning. One nonblocking gate attempt: with the gate, the slot
/// and its payload bytes move from `from` to `Retired` in the ledger and the
/// word's flags record that it did; without it, or when the record no longer
/// names the owner, the counter and the flags a park sets on the word are
/// the pre-reserved record that service finds later. Either way nothing
/// waits, scans, frees or unmaps. The slot's record, which holds the word
/// and the policy's `prev` link, and its policy `next` link are warmed first
/// so their misses are taken before the hold. `marks` are flag bits
/// the caller has this one read-modify-write carry beside the abandonment's
/// own: a retirement passes `ANCHORED`, whose stamp it stored before the
/// call, so the release read-modify-write that publishes the abandonment
/// publishes the stamp with it; an owner's drop passes none. With
/// `evicted`, a hold that records the retirement of a resident also applies
/// the eviction mark to it.
///
/// Returns the outcome with whether the abandonment is recorded: false when
/// the gate attempt recorded nothing and the park found the slot word
/// malformed or naming another incarnation, as [`park_marked`] reports, so neither the ledger nor the word
/// holds the abandonment and nothing will service the slot.
///
/// # Panics
///
/// If the retirement of a capture member panics in its entry copy, on tables the copy cannot trust. The pool gate and the capture mutex are both poisoned when the panic leaves, also on a thread that was already unwinding when the call began.
// Forced inline: this is the whole body of two `Drop` impls, and the owner's
// fields arrive in registers.
#[inline(always)]
pub(crate) fn abandon(
    pool: &Pool,
    id: AllocationId,
    from: Owned,
    marks: u64,
    evicted: bool,
    counted: Option<u64>,
) -> (RetireOutcome, bool) {
    pool.prefetch_slot(id.slot.0);
    if let Ok(access) = pool.try_lock_quiet() {
        // Either answer of the retirement ends the hold through `release`, so its drop is a panic in the retirement, on a malformed slot word or on tables it cannot trust, and that drop poisons the gate also when a thread that was already unwinding took it.
        let mut access = access.poison_on_unwind();
        let retired = retire_held(
            pool,
            &mut access.tables(),
            id,
            from,
            marks,
            evicted,
            counted,
        );
        access.release();
        if retired {
            return (RetireOutcome::Recorded, true);
        }
    }
    if let Some(epoch) = counted {
        // Stored before the park's release exchange, which service's acquire load of the word reads, so a servicer that sees the park sees the epoch; a retirement counted here is resident and anchored, so no gate holder writes this word until the park converts.
        let marker = &pool.positions()[id.slot.0];
        debug_assert_eq!(
            marker.load(Ordering::Relaxed),
            NO_RECORD,
            "an anchored resident retires once, so no other record names its slot"
        );
        marker.store(PARKED_EPOCH[epoch as usize], Ordering::Relaxed);
    }
    let parked = park_marked(pool, id.slot.0, id.incarnation, marks);
    (RetireOutcome::Parked, parked)
}

/// Service also runs this gated body of [`abandon`] on its first gate-held sighting of a parked resident slot. If the slot's word matches `id` and state `from`, the function transfers the slot and payload bytes to `Retired` in the ledger, sets the retired flags, bit, and units, absorbs this incarnation's park, and returns true. The slot's position becomes `NO_RECORD`, or for a resident the suffix position of the newest recorded removal once one exists, and the coverage registration named by `counted` ends, so a parked slot's caller passes its marker's epoch; the extent returns once the epoch release admits it and the position is durable. A mismatched word leaves the slot unchanged and returns false.
///
/// Capture contention leaves ownership with the caller for a later service pass.
/// A poisoned capture is abandoned while retirement drains the slot; its mutex remains poisoned.
///
/// # Panics
///
/// If the entry copy of a capture member panics on tables it cannot trust. The capture mutex is poisoned before the panic leaves; the caller holds the pool gate under a hold whose drop poisons the gate as the panic passes.
#[inline(always)]
pub(crate) fn retire_held(
    pool: &Pool,
    tables: &mut Tables<'_>,
    id: AllocationId,
    from: Owned,
    marks: u64,
    evicted: bool,
    counted: Option<u64>,
) -> bool {
    let slot = id.slot.0;
    let from_state = from.slot_state();
    if !describes(pool, from_state, id) {
        return false;
    }
    if tables.step(slot) != 0 {
        let Ok(mut capture) = pool.capture_membership_lock() else {
            return false;
        };
        // A panic in the entry copy found the member's tables malformed, and the walk's unwind poisons the capture.
        let walk = PoisonOnUnwind(&mut capture);
        // A restored binding retired before its publication is no logical removal, so nothing records it.
        pool.capture_remove(tables, walk.0, slot, false);
        walk.returned();
    }
    let (payload, units) = pool.held_charge(tables, slot);
    // The retired record is itself the proof service needs. The
    // flags stay set for the deferred return; a park of this
    // incarnation that landed earlier is absorbed, so the counter
    // keeps exactly one entry per parked slot and none for a
    // retired one.
    let retired = SlotState::Retired.bits() & !from_state.bits();
    let set = ABANDONED | RETIRED | marks | retired;
    let ident = &pool.records()[slot].ident;
    // Only the pool gate's holder writes the policy bits, so every
    // retry of the exchange flips the same `departure` bits, and a
    // park, retain or release that moves the word between the load
    // and the exchange costs one retry and keeps its own bits.
    let retire = |departure: u64| {
        let (Ok(previous) | Err(previous)) =
            ident.try_update(Ordering::AcqRel, Ordering::Relaxed, |current| {
                Some((current | set) ^ departure)
            });
        (previous, departure)
    };
    let (previous, departure) = match from {
        Owned::Filling => retire(0),
        Owned::Resident => {
            // This hold records the current incarnation's retirement,
            // so it is the first observer: a member leaves the domain.
            debug_assert_ne!(
                ident.load(Ordering::Relaxed) & word::POLICY,
                0,
                "a resident slot that did not enter through bind"
            );
            if evicted {
                tables.queue().mark_evicted_with(slot, units, retire)
            } else {
                tables.queue().detach_with(slot, retire)
            }
        }
    };
    tables.mark_retired(slot);
    tables.domain.retired_units += u64::from(units);
    match from {
        Owned::Filling => {
            // Reserved bytes reach retired through resident, in this
            // one hold, so no reader sees the intermediate ledger.
            tables.publish_payload(payload);
            tables.state.ledger.filling -= 1;
        }
        Owned::Resident => {
            if departure & LINKED != 0 {
                probe::event(Event::Detached { slot });
            }
            tables.state.ledger.resident -= 1;
        }
    }
    tables.retire_payload(payload);
    tables.state.ledger.retired += 1;
    // The capture's removal hook covers the removed entry. A resident waits for the suffix block of the newest
    // recorded removal, at or after its own removal's block: the raise happens before this retirement, on the
    // recording thread or through the park's release exchange that service acquires, so coherence gives this load
    // that value or a later one.
    let held = (from == Owned::Resident)
        .then(|| pool.suffix_tail.load(Ordering::Acquire).checked_sub(1))
        .flatten();
    tables.journal().retire(slot, held, counted);
    if word::checked(previous) & ABANDONED != 0 {
        pool.telemetry()
            .pending_marks
            .fetch_sub(1, Ordering::Relaxed);
        // The retired bit now stands for the absorbed park.
        unmark_parked_slot(pool.parked_slots(), slot);
    }
    true
}

/// The allocation could not be rolled back and stays charged as pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retained;

impl<P: Platform> Drop for ExtentReservation<'_, P> {
    #[inline]
    fn drop(&mut self) {
        let _ = self.abandon_in_place();
    }
}
