//! The reservation step every lease acquisition shares, and the test-only
//! acquisition of further leases under the resident authority.
//!
//! [`LeaseCounters`] is the crate's one way to take and give back the credit
//! and right a lease holds: the engine's credit controls and one slot's
//! lifetime word, resolved once by a caller that has validated the slot, or,
//! in tests, by `reserve_lease` and `refund_lease` from an identity.
//! Reservation is one engine credit through the shared bounded loop, then
//! one object right on the word, whose first attempt runs inline and whose
//! retries go through the same loop, expecting the word the
//! caller loaded and adding one reference with the visited bit set,
//! which distinguishes `RetainLimit` (rights already at `C`) from
//! `Contended` (every paid try failed) and refuses a count at zero, a moved
//! incarnation and a malformed word; a refused right returns the credit
//! first. The refund runs
//! in reverse, right then credit, exactly once. Neither step reads the
//! deadline or the admission cutoff; each caller wraps them in its own checks
//! and its own protection, and resolving the counters is `unsafe` because it
//! indexes the slot's count by the caller's slot index.
//!
//! The test-only `Resident::acquire` is the caller whose protection is the `&Resident`
//! borrow: the authority holds the anchor, so the slot's incarnation, key
//! row, bytes, locator and deadline stay fixed and the slot stays bound for
//! as long as the borrow lasts, while the word's count and visited bit move
//! as leases take rights. A candidate with a wrong domain, a stale
//! incarnation, an out-of-range slot or a foreign identity has no value of this type to
//! borrow. Its order: the caller's deadline first, because it is immutable
//! and a refusal costs no reservation; then the reservation; then the
//! open-admission witness, read after the reservations so a success carries
//! it. A close that happens before that read refunds; a close racing it may
//! admit one more lease, exactly as a reservation racing `close` may. The
//! registered lookup wraps the same step in its snapshot and final bracket.
//! Nothing here takes the pool gate, waits, or holds capacity beyond the
//! reservations it returns.
//!
//! Deadlines compare the whole seconds of one live sample on the engine's
//! monotonic nanosecond timeline with the record's deadline seconds: a
//! sample below them admits, one at or past them is expired, a deadline
//! below one second is expired for every sample, and a caller whose clock
//! is unavailable or whose conversion overflowed passes `None` and is
//! refused. A lease acquired
//! before the deadline stays valid after it.

use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(test)]
use super::allocation::AllocationId;
use super::budget::{WorkBudget, WorkKind};
use super::image::RootDescriptor;
use super::lease::{
    Credit, CreditError, Exchanged, IncrementError, reserve_credit, return_credit, update_after,
};
#[cfg(test)]
use super::lease::{ExtentLease, Resident};
use super::os::Platform;
use super::owner::{Pool, Storage};
use super::probe::{self, Primitive};
use super::readiness::State as Readiness;
#[cfg(test)]
use super::slot::expired;
use super::tables::RetainCounters;
use super::word;

/// Why no lease was acquired. Every reservation the attempt made was
/// returned; the visited bit a successful retain set on the object's word
/// stays set.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquireError {
    /// The sample is at or past the deadline, or the deadline is zero.
    Expired,
    /// The caller had no sample: clock unavailable or conversion failed.
    ClockUnavailable,
    /// Every one of the `L` credits is reserved.
    LeaseLimit,
    /// The object already holds `C` external rights.
    RetainLimit,
    /// Every attempt the budget paid for failed its compare-exchange.
    Contended,
    /// The budget could not pay for a reservation's first attempt: either
    /// nothing was tried, or the credit's attempts spent it and the credit
    /// was refunded.
    BudgetExhausted,
    /// Admission was closed before the final witness.
    Closed,
    /// The retain found the object's count at zero, its word naming another
    /// incarnation, or a reserved bit set: no right can be taken on the
    /// object the caller validated.
    Retired,
}

/// Why [`reserve_lease`] reserved nothing. Every reservation the attempt
/// made was returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LeaseRefusal {
    /// Every one of the `L` credits is reserved.
    LeaseLimit,
    /// The object already holds `C` external rights.
    RetainLimit,
    /// Every attempt the budget paid for failed its compare-exchange.
    Contended,
    /// The budget could not pay for a reservation's first attempt: either
    /// nothing was tried, or the credit's attempts spent it and the credit
    /// was refunded.
    BudgetExhausted,
    /// The object's count read zero, so its anchor and every right were
    /// released, or its word carries a different incarnation or is malformed.
    Retired,
    /// The slot carries the recovered-origin marker and the readiness word
    /// differs from `Live`, so READ-READY refuses the grant.
    NotLive,
}

impl From<CreditError> for LeaseRefusal {
    fn from(error: CreditError) -> Self {
        match error {
            CreditError::LeaseLimit => Self::LeaseLimit,
            CreditError::Contended => Self::Contended,
            CreditError::BudgetExhausted => Self::BudgetExhausted,
        }
    }
}

#[cfg(test)]
impl From<LeaseRefusal> for AcquireError {
    fn from(refusal: LeaseRefusal) -> Self {
        match refusal {
            LeaseRefusal::LeaseLimit => Self::LeaseLimit,
            LeaseRefusal::RetainLimit => Self::RetainLimit,
            LeaseRefusal::Contended => Self::Contended,
            LeaseRefusal::BudgetExhausted => Self::BudgetExhausted,
            LeaseRefusal::Retired => Self::Retired,
            LeaseRefusal::NotLive => Self::Contended,
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Runs once after both reservations and before the admission witness on
    /// this thread, so a test can close admission at the last moment.
    pub(crate) static INTERPOSE_BEFORE_ADMISSION_WITNESS: std::cell::Cell<Option<fn(&std::sync::atomic::AtomicBool)>> =
        const { std::cell::Cell::new(None) };
}

/// When the policy hit of a retain reaches the object's word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Hit {
    /// The retain's exchange sets the visited bit with the right.
    WithRight,
    /// The exchange leaves the bit as found. The holder calls
    /// [`LeaseCounters::visit`] once the verdict that follows its right
    /// grants the lease, so a right returned on a refusal leaves no hit.
    OnGrant,
}

/// Adds one external right to `slot_word`, expecting `current`, the word
/// the caller loaded, and for [`Hit::WithRight`] sets the visited bit in the
/// same exchange. While
/// the anchor is live the count holds it, so the rights are `refs - 1`. The
/// exchange admits only a well-formed word on `incarnation` with a nonzero
/// count, so a retain racing a reuse of the slot fails.
///
/// The first attempt runs inline and returns when its exchange succeeds. A
/// failed first exchange, lost to another writer or spurious, hands the
/// value it found to `update_after` with that failure counted, so charging,
/// refusals, failure counts and the `Contended` or `BudgetExhausted`
/// outcome match `bounded_update`.
#[inline(always)]
pub(super) fn retain_right(
    slot_word: &AtomicU64,
    current: u64,
    incarnation: u32,
    retains: &RetainCounters,
    limit: usize,
    hit: Hit,
    budget: &mut WorkBudget,
) -> Result<(), LeaseRefusal> {
    // The word's own refusal first, so a moved incarnation, a reserved bit
    // or a zero count is named `Retired` whatever the count; then the
    // limit. The count holds at most `C + 1`, so a count above `C` has
    // every right taken, and refusing it keeps the exchange from carrying
    // the count past the word's width.
    let next = match hit {
        Hit::WithRight => word::retained,
        Hit::OnGrant => word::counted,
    };
    let admit = |current| match next(current, incarnation) {
        None => Err(LeaseRefusal::Retired),
        Some(_) if word::refs(current) > limit => Err(LeaseRefusal::RetainLimit),
        Some(next) => Ok(next),
    };
    budget
        .debit(WorkKind::CoordinationAttempt)
        .map_err(|_| LeaseRefusal::BudgetExhausted)?;
    let next = admit(current)?;
    #[cfg(test)]
    slot_word.interpose();
    probe::note(Primitive::Cas);
    let Err(seen) = slot_word.exchange_weak(current, next) else {
        return Ok(());
    };
    let failures = if seen == current { (0, 1) } else { (1, 0) };
    update_after(
        slot_word,
        seen,
        failures,
        (&retains.lost, &retains.stalled),
        budget,
        admit,
    )
    .map(|_| ())
    .map_err(|error| match error {
        IncrementError::Refused(refused) => refused,
        IncrementError::Contended => LeaseRefusal::Contended,
        IncrementError::BudgetExhausted => LeaseRefusal::BudgetExhausted,
    })
}

/// The two counters one lease moves, resolved once: the engine's credit
/// controls, reached through the storage so a credit parked in a reader's
/// record can be taken and given back, and the object's lifetime word. A
/// caller that validated the slot holds this instead of deriving the pool and
/// its tables again for the reservation, the refund and the lease.
pub(super) struct LeaseCounters<'a, P: Platform> {
    storage: &'a Storage<P>,
    slot_word: &'a AtomicU64,
}

// Two shared references, so the counters are `Copy` for every
// `P: Platform`.
impl<P: Platform> Clone for LeaseCounters<'_, P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P: Platform> Copy for LeaseCounters<'_, P> {}

impl<'a, P: Platform> LeaseCounters<'a, P> {
    /// The counters of `slot` in `pool`, a live pool of `storage`.
    ///
    /// # Safety
    ///
    /// `slot` is below `pool`'s slot count, the count its tables were sized
    /// from. [`reserve`](Self::reserve) validates the word itself; the right
    /// [`refund`](Self::refund) returns is the caller's to hold.
    #[inline(always)]
    pub(super) unsafe fn new(storage: &'a Storage<P>, pool: &'a Pool, slot: usize) -> Self {
        Self {
            storage,
            // SAFETY: the caller's `slot < O`.
            slot_word: unsafe { pool.slot_word(slot) },
        }
    }

    /// Reserves one engine credit within `root.lease_limit`, from `credit`,
    /// then one right on `incarnation` of the object within
    /// `root.object_rights`, the retain expecting `current`, the word the
    /// caller loaded, through the bounded loops, with the retain's failed
    /// exchanges counted in `retains` and its hit landing as `hit` says. On
    /// any refusal every reservation this call made is back before the error.
    #[inline(always)]
    #[expect(clippy::too_many_arguments)]
    pub(super) fn reserve(
        self,
        root: &RootDescriptor,
        credit: Credit,
        retains: &RetainCounters,
        incarnation: u32,
        current: u64,
        hit: Hit,
        budget: &mut WorkBudget,
    ) -> Result<(), LeaseRefusal> {
        // READ-READY requires `Live` readiness before granting access to a slot carrying the recovered-origin marker.
        if current & word::MARKER != 0 && self.storage.readiness.state() != Readiness::Live {
            return Err(LeaseRefusal::NotLive);
        }
        reserve_credit(self.storage, root.lease_limit, credit, budget)?;
        let retained = retain_right(
            self.slot_word,
            current,
            incarnation,
            retains,
            root.object_rights,
            hit,
            budget,
        );
        if let Err(error) = retained {
            return_credit(self.storage, credit);
            return Err(error);
        }
        Ok(())
    }

    /// Sets the visited bit of the object a [`Hit::OnGrant`] reservation
    /// counted. The caller holds that right, so the word's incarnation is
    /// the object's own and no reuse of the slot can receive the bit.
    #[inline(always)]
    pub(super) fn visit(self) {
        probe::note(Primitive::Rmw);
        word::visit(self.slot_word);
    }

    /// Gives back what [`reserve`](Self::reserve) took, in reverse order:
    /// the right, then the credit to `credit`, each once. The caller holds
    /// that right, so the count is positive and the word's incarnation is the
    /// object's own; its permission to access the slot ends with this call.
    /// Release mirrors a
    /// lease's drop; any read-modify-write keeps the release sequence
    /// intact, since the refunding thread read nothing that a later return
    /// must observe.
    #[inline(always)]
    pub(super) fn refund(self, credit: Credit) {
        probe::note(Primitive::Rmw);
        let previous = self.slot_word.fetch_sub(word::REF, Ordering::Release);
        debug_assert!(
            word::refs(previous) >= 2,
            "right refunded without a reservation"
        );
        return_credit(self.storage, credit);
    }
}

/// Reserves one engine credit from `credit`'s source, within
/// `root.lease_limit` for a `Shared` credit and none for `Read`, then one
/// right on `incarnation` of the object in `slot` within `root.object_rights`,
/// the retain expecting the word as loaded now, for a fill's follower. The
/// retain admits only a word on `incarnation` with a positive count, so a
/// slot returned or reused since the caller learned the incarnation refuses
/// `Retired` and gains no right. On any refusal every reservation this call
/// made is back before the error. The retain sets no visited bit; the
/// follower sets it through the returned counters once its cutoff read
/// grants the lease.
///
/// # Safety
///
/// `slot` is below `pool`'s slot count, the count its tables were sized
/// from.
#[inline]
pub(super) unsafe fn reserve_incarnation<'a, P: Platform>(
    storage: &'a Storage<P>,
    pool: &'a Pool,
    slot: usize,
    root: &RootDescriptor,
    incarnation: u32,
    credit: Credit,
    budget: &mut WorkBudget,
) -> Result<LeaseCounters<'a, P>, LeaseRefusal> {
    // SAFETY: the caller's `slot < O`; the retain below validates the
    // incarnation and a positive count itself, so it needs no protection
    // beyond the slot index.
    let counters = unsafe { LeaseCounters::new(storage, pool, slot) };
    let current = counters.slot_word.load(Ordering::Relaxed);
    counters.reserve(
        root,
        credit,
        &pool.telemetry().retains,
        incarnation,
        current,
        Hit::OnGrant,
        budget,
    )?;
    Ok(counters)
}

/// Reserves one engine credit within `L`, then one right on `id`'s object
/// within `C`, through the bounded loops, for a holder under no
/// registration. On any refusal every reservation this call made is back
/// before the error.
///
/// # Safety
///
/// `id.slot()` is below the slot count of the live pool `id.pool()` names,
/// as it is for a resident authority's issued identity. The caller also
/// keeps the object's count positive for the whole call, through the
/// resident borrow, which keeps the anchor counted, or through a right it
/// holds, so the counter is the object's own.
#[cfg(test)]
#[inline(always)]
pub(super) unsafe fn reserve_lease<P: Platform>(
    storage: &Storage<P>,
    id: AllocationId,
    budget: &mut WorkBudget,
) -> Result<(), LeaseRefusal> {
    let (pool, root) = storage
        .live()
        .expect("the caller's protection keeps the storage live");
    // SAFETY: forwarded from the caller.
    let counters = unsafe { LeaseCounters::new(storage, pool, id.slot().0) };
    let current = counters.slot_word.load(Ordering::Relaxed);
    counters.reserve(
        root,
        Credit::Shared,
        &pool.telemetry().retains,
        id.incarnation(),
        current,
        Hit::WithRight,
        budget,
    )
}

/// Gives back what [`reserve_lease`] took, in reverse order: the right, then
/// the credit, each once.
///
/// # Safety
///
/// As for [`reserve_lease`], for the same `id`, whose reservation this call
/// returns.
#[cfg(test)]
#[inline(always)]
pub(super) unsafe fn refund_lease<P: Platform>(storage: &Storage<P>, id: AllocationId) {
    let pool = storage
        .live_pool()
        .expect("the caller's protection keeps the storage live");
    // SAFETY: forwarded from the caller.
    unsafe { LeaseCounters::new(storage, pool, id.slot().0) }.refund(Credit::Shared);
}

#[cfg(test)]
impl<'s, P: Platform> Resident<'s, P> {
    /// Acquires one more lease on this object for a caller whose monotonic
    /// sample is `now_ticks`, or `None` when no sample could be taken. See
    /// the module documentation for the order of checks and refunds.
    ///
    /// # Errors
    ///
    /// [`AcquireError`]; every reservation the attempt made is returned
    /// before the error.
    pub fn acquire(
        &self,
        now_ticks: Option<u64>,
        budget: &mut WorkBudget,
    ) -> Result<ExtentLease<'s, P>, AcquireError> {
        let now = now_ticks.ok_or(AcquireError::ClockUnavailable)?;
        if expired(now, self.expires_at_s()) {
            return Err(AcquireError::Expired);
        }
        let storage = self.storage();
        let id = self.id();
        // SAFETY: `id` was issued for its pool, so its slot index is below
        // `O`, and this authority holds the object's anchor.
        unsafe { reserve_lease(storage, id, budget) }?;
        #[cfg(test)]
        if let Ok(Some(interpose)) = INTERPOSE_BEFORE_ADMISSION_WITNESS.try_with(|hook| hook.take())
        {
            interpose(storage.closed());
        }
        // The borrow keeps the storage live, so the flag is read directly,
        // with the `SeqCst` load every admission path uses on the cutoff.
        if storage.closed().load(Ordering::SeqCst) {
            // SAFETY: as for the reservation above.
            unsafe { refund_lease(storage, id) };
            return Err(AcquireError::Closed);
        }
        Ok(ExtentLease::new(storage, id, *self.key(), Credit::Shared))
    }
}

#[cfg(test)]
mod tests {
    //! Recorded exemptions: wrong domain, stale incarnation, out-of-range
    //! coordinates and a foreign capability have no value of type `Resident`
    //! to borrow, so the acquisition path cannot be reached with them; the
    //! compile-fail snippets on `lease` are the witnesses, and no
    //! address-reuse fixture is built because no address is ever accepted.
    //! This crate's protection is the borrow; lookup and index visibility are
    //! out of scope, so every refusal and rollback below is proved against
    //! the borrow only. Removal and expiry of a candidate during an attempt
    //! have no path: the borrow blocks removal, the deadline is immutable and
    //! the sample is the caller's. A `Retired` refusal needs a zero counter
    //! under a live authority, which only test tampering can produce, and a
    //! caller-side conversion overflow arrives as `None`.

    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

    use super::super::budget::WorkBudget;
    use super::super::config::StorageConfig;
    use super::super::lease::{ExtentLease, Resident};
    use super::super::lease::{INTERPOSE_BEFORE_CAS, INTERPOSE_BEFORE_RETAIN};
    use super::super::owner::Storage;
    use super::super::placement::PlacementConfig;
    use super::super::tables::{SlotIndex, SlotState};
    use super::super::test_platform::TestPlatform;
    use super::{AcquireError, INTERPOSE_BEFORE_ADMISSION_WITNESS};

    const PAGE: usize = 4096;
    const SLOTS: usize = 8;
    const KEY: [u8; 32] = [0x3C; 32];
    const DEADLINE: u64 = 1_000 * 1_000_000_000;

    fn storage_with(
        slot_count: usize,
        lease_limit: usize,
        object_rights: usize,
    ) -> Storage<TestPlatform> {
        let config = StorageConfig {
            page_size: PAGE,
            engine_budget: 1 << 24,
            body_cap: 200,
            metadata_cap: Some(16),
            lease_limit,
            object_rights,
            reader_limit: 4,
            volume: crate::storage::test_volume(slot_count * crate::storage::IO_UNIT, slot_count),
        };
        let placement = PlacementConfig { control_home: 0 };

        Storage::initialize(
            &config.validate().unwrap(),
            &placement,
            TestPlatform::heap(PAGE),
        )
        .unwrap()
    }

    /// Room for a Miri run, where a weak compare-exchange fails spuriously
    /// most of the time; on hardware one attempt is the norm.
    fn budget() -> WorkBudget {
        WorkBudget::new(1 << 10)
    }

    /// An anchored object with producer-held bytes and its first lease.
    fn anchored<'s>(
        storage: &'s Storage<TestPlatform>,
        body: &[u8],
        deadline: u64,
    ) -> (Resident<'s, TestPlatform>, ExtentLease<'s, TestPlatform>) {
        let mut allocation = storage
            .reserve(Some(4), Some(body.len()), &mut budget())
            .unwrap();
        allocation.mark_written();
        let completed = allocation
            .complete(KEY, deadline, &mut budget())
            .ok()
            .unwrap();
        completed.handoff(&mut budget()).ok().unwrap()
    }

    fn refs(storage: &Storage<TestPlatform>, slot: usize) -> usize {
        storage.live_pool().unwrap().refs(slot)
    }

    /// Sets `slot`'s count to `refs`, as only test tampering can.
    fn set_refs(storage: &Storage<TestPlatform>, slot: usize, refs: usize) {
        storage.live_pool().unwrap().set_refs(slot, refs);
    }

    fn reserved(storage: &Storage<TestPlatform>) -> usize {
        storage.lease_report().unwrap().reserved
    }

    fn retain_counters(storage: &Storage<TestPlatform>) -> (usize, usize) {
        let report = storage.pool_report().unwrap();
        (report.retain_cas_failed, report.retain_cas_spurious)
    }

    /// Ten responses on one object: ten credits and rights, one record,
    /// slot and payload charge; independent ledgers agree at every prefix
    /// and the anchor stays one throughout.
    #[test]
    fn ten_leases_on_one_object_charge_ten_rights_and_one_payload() {
        let storage = storage_with(SLOTS, 16, 16);
        let body: Vec<u8> = (0..60u8).collect();
        let (resident, first) = anchored(&storage, &body, DEADLINE);
        let slot = resident.id().slot_index();
        let ledger_before = storage.pool_report().unwrap();
        let mut leases = Vec::with_capacity(10);
        leases.push(first);
        let allocations = crate::instrument::allocations();
        for n in 1..10 {
            let spurious_before =
                storage.lease_report().unwrap().cas_spurious + retain_counters(&storage).1;
            let mut spent = budget();
            let lease = resident.acquire(Some(DEADLINE - 1), &mut spent).unwrap();
            // One credit attempt and one right attempt, plus one per spurious
            // weak failure, which Miri injects and a single thread cannot
            // otherwise provoke.
            let spurious =
                storage.lease_report().unwrap().cas_spurious + retain_counters(&storage).1;
            assert_eq!(
                spent.counters().coordination_attempts,
                2 + spurious - spurious_before,
                "{n}"
            );
            if !cfg!(miri) {
                assert_eq!(spurious, 0);
            }
            leases.push(lease);
            // Model at every prefix: rights = leases, credits = leases, the
            // anchor is the one count that is not a lease, and the pool ledger
            // charges the object once.
            assert_eq!(refs(&storage, slot), leases.len() + 1);
            assert_eq!(refs(&storage, slot) - leases.len(), 1);
            assert_eq!(reserved(&storage), leases.len());
            let ledger = storage.pool_report().unwrap();
            assert_eq!(ledger.ledger, ledger_before.ledger);
        }
        assert_eq!(crate::instrument::allocations() - allocations, 0);
        assert_eq!(ledger_before.ledger.unwrap().raw.resident, 64);
        assert_eq!(
            storage.slot_state(SlotIndex(slot)),
            Some((SlotState::Resident, 1))
        );
        // Release in an arbitrary order, checking the model at every prefix.
        for expected in (1..10).rev() {
            let index = (expected * 7) % leases.len();
            drop(leases.swap_remove(index));
            assert_eq!(refs(&storage, slot), expected + 1);
            assert_eq!(reserved(&storage), expected);
        }
        drop(leases);
        assert_eq!(refs(&storage, slot), 1);
        assert_eq!(reserved(&storage), 0);
        drop(resident);
    }

    /// `C - 1`/`C` and `L - 1`/`L`: the boundary acquisition is refused with
    /// exactly one refund and the acquisition below it succeeds.
    #[test]
    fn right_and_credit_limits_refuse_at_the_boundary_with_one_refund() {
        // C = 3 rights per object, L = 5 credits.
        let storage = storage_with(SLOTS, 5, 3);
        let (a, _a1) = anchored(&storage, &[7; 20], DEADLINE);
        let a_slot = a.id().slot_index();
        let _a2 = a.acquire(Some(1), &mut budget()).unwrap();
        assert_eq!(refs(&storage, a_slot), 3);
        // C - 1 = 2 rights held: the third succeeds; C = 3: refused.
        let a3 = a.acquire(Some(1), &mut budget()).unwrap();
        assert_eq!(refs(&storage, a_slot), 4);
        assert_eq!(reserved(&storage), 3);
        let mut spent = budget();
        assert_eq!(
            a.acquire(Some(1), &mut spent).err(),
            Some(AcquireError::RetainLimit)
        );
        // The credit attempt and the right attempt were both paid and the
        // credit refunded exactly once.
        if !cfg!(miri) {
            assert_eq!(spent.counters().coordination_attempts, 2);
        }
        assert_eq!(reserved(&storage), 3);
        assert_eq!(refs(&storage, a_slot), 4);

        // Another object takes the fourth and fifth credits; L = 5 refuses
        // the sixth with nothing reserved and no right touched.
        let (b, _b1) = anchored(&storage, &[8; 20], DEADLINE);
        let b_slot = b.id().slot_index();
        let _b2 = b.acquire(Some(1), &mut budget()).unwrap();
        assert_eq!(reserved(&storage), 5);
        assert_eq!(refs(&storage, b_slot), 3);
        let mut spent = budget();
        assert_eq!(
            b.acquire(Some(1), &mut spent).err(),
            Some(AcquireError::LeaseLimit)
        );
        assert_eq!(spent.counters().coordination_attempts, 1);
        assert_eq!(reserved(&storage), 5);
        assert_eq!(refs(&storage, b_slot), 3);
        // Releasing one credit anywhere re-admits, within `C` of the object.
        drop(a3);
        assert_eq!(reserved(&storage), 4);
        let _b3 = b.acquire(Some(1), &mut budget()).unwrap();
        assert_eq!(refs(&storage, b_slot), 4);
    }

    /// Deterministic ticks: only a sample strictly before the deadline yields
    /// a lease; equality, a zero lifetime, the clock horizon and a missing
    /// sample refuse without any reservation; an existing lease keeps reading
    /// after expiry and the deadline never restarts.
    #[test]
    fn only_a_sample_strictly_before_the_deadline_acquires() {
        let storage = storage_with(SLOTS, 8, 8);
        let (resident, early) = anchored(&storage, &[5; 30], DEADLINE);
        let slot = resident.id().slot_index();
        let allocations = crate::instrument::allocations();
        let refusals: [(Option<u64>, AcquireError); 4] = [
            (Some(DEADLINE), AcquireError::Expired),
            (Some(DEADLINE + 1), AcquireError::Expired),
            (Some(u64::MAX), AcquireError::Expired),
            (None, AcquireError::ClockUnavailable),
        ];
        for (sample, expected) in refusals {
            let mut spent = WorkBudget::new(8);
            assert_eq!(resident.acquire(sample, &mut spent).err(), Some(expected));
            assert_eq!(spent.counters().coordination_attempts, 0);
            assert_eq!(reserved(&storage), 1);
            assert_eq!(refs(&storage, slot), 2);
        }
        assert_eq!(crate::instrument::allocations(), allocations);
        let before = resident.acquire(Some(DEADLINE - 1), &mut budget()).unwrap();
        let at_zero = resident.acquire(Some(0), &mut budget()).unwrap();
        assert_eq!(refs(&storage, slot), 4);
        // Past the deadline the existing leases still read their bytes and
        // the record's deadline is unchanged.
        assert_eq!(
            resident.expires_at_s(),
            super::super::slot::deadline_seconds(DEADLINE)
        );
        assert_eq!(
            resident.acquire(Some(DEADLINE), &mut budget()).err(),
            Some(AcquireError::Expired)
        );
        drop((before, at_zero, early));

        // A zero lifetime is expired for every sample, including zero.
        let (never, _first) = anchored(&storage, &[6; 30], 0);
        assert_eq!(
            never.acquire(Some(0), &mut budget()).err(),
            Some(AcquireError::Expired)
        );
    }

    /// Close on either side of acquisition: a pre-close success carries the
    /// witness, a post-close attempt is refused with both reservations
    /// refunded, a close landing between the reservations and the witness is
    /// caught by the witness, and existing leases read and release normally.
    #[test]
    fn close_refuses_new_acquisition_and_leaves_existing_leases_valid() {
        fn close(flag: &AtomicBool) {
            flag.store(true, Ordering::SeqCst);
        }
        let storage = storage_with(SLOTS, 8, 8);
        let (resident, first) = anchored(&storage, &[9; 30], DEADLINE);
        let slot = resident.id().slot_index();
        let witnessed = resident.acquire(Some(1), &mut budget()).unwrap();
        assert!(!storage.is_closed());
        assert_eq!(refs(&storage, slot), 3);

        // The close lands after both reservations and before the witness.
        INTERPOSE_BEFORE_ADMISSION_WITNESS.with(|hook| hook.set(Some(close)));
        let allocations = crate::instrument::allocations();
        assert_eq!(
            resident.acquire(Some(1), &mut budget()).err(),
            Some(AcquireError::Closed)
        );
        assert_eq!(crate::instrument::allocations(), allocations);
        assert!(storage.is_closed());
        assert_eq!(refs(&storage, slot), 3);
        assert_eq!(reserved(&storage), 2);
        assert!(INTERPOSE_BEFORE_ADMISSION_WITNESS.with(|hook| hook.get().is_none()));

        // Post-close: refused with exact refunds, existing leases unaffected.
        assert_eq!(
            resident.acquire(Some(1), &mut budget()).err(),
            Some(AcquireError::Closed)
        );
        assert_eq!(refs(&storage, slot), 3);
        assert_eq!(reserved(&storage), 2);
        drop(witnessed);
        assert_eq!(refs(&storage, slot), 2);
        assert_eq!(reserved(&storage), 1);
        drop(first);
        assert_eq!(reserved(&storage), 0);
        drop(resident);
    }

    /// Work accounting: zero budget makes no attempt; one step pays the
    /// credit and cannot pay the right, refunding the credit; a lost right
    /// compare-exchange is counted and charged, refuses `Contended` when the
    /// budget ends and succeeds on the retry; a zero counter is never
    /// incremented.
    #[test]
    fn every_attempt_is_charged_and_every_partial_reservation_refunded() {
        fn steal(refs: &AtomicUsize) {
            refs.fetch_add(1, Ordering::Relaxed);
        }
        fn steal_right(slot_word: &AtomicU64) {
            slot_word.fetch_add(super::super::word::REF, Ordering::Relaxed);
        }
        let storage = storage_with(SLOTS, 8, 8);
        let (resident, first) = anchored(&storage, &[2; 30], DEADLINE);
        let slot = resident.id().slot_index();
        let allocations = crate::instrument::allocations();

        let counters_before = (storage.lease_report().unwrap(), retain_counters(&storage));
        let mut zero = WorkBudget::new(0);
        assert_eq!(
            resident.acquire(Some(1), &mut zero).err(),
            Some(AcquireError::BudgetExhausted)
        );
        assert_eq!(zero.counters().coordination_attempts, 0);
        assert_eq!(
            (storage.lease_report().unwrap(), retain_counters(&storage)),
            counters_before
        );
        assert_eq!((reserved(&storage), refs(&storage, slot)), (1, 2));

        // One step: the credit attempt is paid and succeeds, the right
        // attempt cannot be paid, the credit comes back.
        let mut one = WorkBudget::new(1);
        let outcome = resident.acquire(Some(1), &mut one).err();
        if cfg!(miri) {
            assert!(matches!(
                outcome,
                Some(AcquireError::BudgetExhausted | AcquireError::Contended)
            ));
        } else {
            assert_eq!(outcome, Some(AcquireError::BudgetExhausted));
            assert_eq!(one.counters().coordination_attempts, 1);
        }
        assert_eq!((reserved(&storage), refs(&storage, slot)), (1, 2));

        if !cfg!(miri) {
            // A lost credit attempt with no budget for a retry: paid, counted,
            // nothing reserved.
            INTERPOSE_BEFORE_CAS.with(|hook| hook.set(Some(steal)));
            let mut one = WorkBudget::new(1);
            assert_eq!(
                resident.acquire(Some(1), &mut one).err(),
                Some(AcquireError::Contended)
            );
            assert_eq!(one.counters().coordination_attempts, 1);
            assert_eq!(storage.lease_report().unwrap().cas_failed, 1);
            assert_eq!(reserved(&storage), 2);
            assert_eq!(refs(&storage, slot), 2);
            storage.leases().reserved.fetch_sub(1, Ordering::Relaxed);

            // A lost right attempt (the second compare-exchange) with no
            // budget for a retry: the credit comes back and the lost attempt
            // is counted.
            INTERPOSE_BEFORE_RETAIN.with(|hook| hook.set(Some(steal_right)));
            let mut two = WorkBudget::new(2);
            assert_eq!(
                resident.acquire(Some(1), &mut two).err(),
                Some(AcquireError::Contended)
            );
            assert_eq!(two.counters().coordination_attempts, 2);
            assert_eq!(retain_counters(&storage), (1, 0));
            assert_eq!(reserved(&storage), 1);
            // The stolen right is still there and the hook ran once; undo it.
            assert!(INTERPOSE_BEFORE_RETAIN.with(|hook| hook.get().is_none()));
            assert_eq!(refs(&storage, slot), 3);
            set_refs(&storage, slot, 2);

            // The same loss with room for a retry succeeds.
            INTERPOSE_BEFORE_RETAIN.with(|hook| hook.set(Some(steal_right)));
            let mut three = WorkBudget::new(3);
            let lease = resident.acquire(Some(1), &mut three).unwrap();
            assert_eq!(three.counters().coordination_attempts, 3);
            assert_eq!(retain_counters(&storage), (2, 0));
            assert_eq!(refs(&storage, slot), 4);
            drop(lease);
            set_refs(&storage, slot, 2);
        }
        assert_eq!((reserved(&storage), refs(&storage, slot)), (1, 2));
        assert_eq!(crate::instrument::allocations(), allocations);

        // Terminal zero is never incremented, even under a live authority:
        // the credit and the right attempt are paid, the credit refunded.
        set_refs(&storage, slot, 0);
        let mut spent = budget();
        assert_eq!(
            resident.acquire(Some(1), &mut spent).err(),
            Some(AcquireError::Retired)
        );
        if !cfg!(miri) {
            assert_eq!(spent.counters().coordination_attempts, 2);
        }
        assert_eq!((reserved(&storage), refs(&storage, slot)), (1, 0));
        set_refs(&storage, slot, 2);
        drop(first);
        drop(resident);
    }

    /// The count holds the anchor and all `C = 2^18 - 2` rights, the word's
    /// full 18-bit count, and refuses one more right as `RetainLimit` with
    /// the incarnation and flags intact, or as `Retired` once the
    /// incarnation moved; releasing every right leaves the anchor alone.
    #[test]
    fn the_count_fills_its_eighteen_bits_and_refuses_one_more() {
        if cfg!(miri) {
            return;
        }
        let rights = super::super::word::REFS_MAX - 1;
        let storage = storage_with(SLOTS, rights + 1, rights);
        let (resident, first) = anchored(&storage, &[5; 30], DEADLINE);
        let slot = resident.id().slot_index();
        let pool = storage.live_pool().unwrap();
        let leases: Vec<_> = (1..rights)
            .map(|_| resident.acquire(Some(1), &mut budget()).unwrap())
            .collect();
        assert_eq!(refs(&storage, slot), super::super::word::REFS_MAX);
        let full = pool.word(slot);
        assert_eq!(
            resident.acquire(Some(1), &mut budget()).err(),
            Some(AcquireError::RetainLimit)
        );
        assert_eq!(pool.word(slot), full);
        assert_eq!(pool.incarnation(slot), resident.id().incarnation());
        assert_eq!(pool.flags(slot), 0);
        // A moved incarnation at the full count names the move, not the
        // limit.
        pool.set_incarnation(slot, resident.id().incarnation().wrapping_add(1));
        assert_eq!(
            resident.acquire(Some(1), &mut budget()).err(),
            Some(AcquireError::Retired)
        );
        pool.set_incarnation(slot, resident.id().incarnation());
        drop((leases, first));
        assert_eq!(refs(&storage, slot), 1);
        drop(resident);
    }

    /// A retain exchanges only a word that still carries the incarnation it
    /// validated: a reuse between the load and the exchange, a word already
    /// naming another incarnation, and a reserved bit each refuse `Retired`
    /// with the credit refunded and no right, flag or visited bit written.
    #[test]
    fn a_retain_meeting_a_moved_incarnation_or_a_reserved_bit_takes_no_right() {
        fn move_incarnation(slot_word: &AtomicU64) {
            slot_word.fetch_add(1, Ordering::Relaxed);
        }
        let storage = storage_with(SLOTS, 8, 8);
        let (resident, first) = anchored(&storage, &[4; 30], DEADLINE);
        let slot = resident.id().slot_index();
        let pool = storage.live_pool().unwrap();
        let before = pool.word(slot);
        let incarnation = resident.id().incarnation();
        let refused = |budget: &mut WorkBudget| {
            assert_eq!(
                resident.acquire(Some(1), budget).err(),
                Some(AcquireError::Retired)
            );
            assert_eq!(reserved(&storage), 1);
        };

        if !cfg!(miri) {
            // The slot moves on between the retain's load and its exchange.
            INTERPOSE_BEFORE_RETAIN.with(|hook| hook.set(Some(move_incarnation)));
            let mut paid = WorkBudget::new(4);
            refused(&mut paid);
            assert_eq!(paid.counters().coordination_attempts, 3);
            assert_eq!(pool.word(slot), before + 1);
            pool.set_incarnation(slot, incarnation);
        }

        // A forged word naming the next incarnation before the load.
        pool.set_incarnation(slot, incarnation.wrapping_add(1));
        refused(&mut budget());
        assert_eq!(refs(&storage, slot), 2);
        pool.set_incarnation(slot, incarnation);

        // A reserved bit fails closed.
        for bit in 43..46 {
            pool.edit_word(slot, |current| current | 1 << bit);
            refused(&mut budget());
            pool.edit_word(slot, |current| current & !(1 << bit));
        }
        assert_eq!(pool.word(slot), before);
        drop(first);
        drop(resident);
    }

    /// Concurrent acquisition against release on one object: every attempt
    /// ends in a lease, a limit refusal or a counted lost or spurious
    /// compare-exchange; the anchor stays one throughout and the counters
    /// return to the anchor and zero credits.
    #[test]
    fn concurrent_retain_against_release_conserves_rights_and_credits() {
        let storage = storage_with(SLOTS, 6, 4);
        let (resident, first) = anchored(&storage, &[3; 30], DEADLINE);
        let slot = resident.id().slot_index();
        drop(first);
        let credit_before = storage.lease_report().unwrap();
        let retain_before = retain_counters(&storage);
        let attempts = AtomicUsize::new(0);
        let successes = AtomicUsize::new(0);
        let lease_limits = AtomicUsize::new(0);
        let retain_limits = AtomicUsize::new(0);
        let contended = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let resident = &resident;
                let storage = &storage;
                let (attempts, successes, lease_limits, retain_limits, contended) = (
                    &attempts,
                    &successes,
                    &lease_limits,
                    &retain_limits,
                    &contended,
                );
                scope.spawn(move || {
                    for _ in 0..60 {
                        let mut spent = WorkBudget::new(4);
                        let outcome = resident.acquire(Some(1), &mut spent);
                        attempts
                            .fetch_add(spent.counters().coordination_attempts, Ordering::Relaxed);
                        match outcome {
                            Ok(lease) => {
                                successes.fetch_add(1, Ordering::Relaxed);
                                let count = refs(storage, slot);
                                assert!((2..=5).contains(&count), "{count}");
                                drop(lease);
                            }
                            Err(AcquireError::LeaseLimit) => {
                                lease_limits.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(AcquireError::RetainLimit) => {
                                retain_limits.fetch_add(1, Ordering::Relaxed);
                            }
                            // Contended: every paid right attempt failed.
                            // Budget exhausted: lost credit attempts spent
                            // the budget before the right could be paid for.
                            // Either way the credit's one successful attempt
                            // is the paid step no term below names.
                            Err(AcquireError::Contended | AcquireError::BudgetExhausted) => {
                                contended.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(error) => panic!("{error:?}"),
                        }
                    }
                });
            }
        });
        assert_eq!(refs(&storage, slot), 1);
        assert_eq!(reserved(&storage), 0);
        let successes = successes.load(Ordering::Relaxed);
        assert!(successes >= 4, "{successes}");
        // Each success paid one credit and one right attempt, a lease-limit
        // refusal one, a retain-limit refusal two, and each failed
        // compare-exchange one more; a contended or budget-exhausted outcome
        // whose credit succeeded paid one attempt no other term names.
        let (retain_failed, retain_spurious) = retain_counters(&storage);
        let report = storage.lease_report().unwrap();
        let failures = (retain_failed - retain_before.0)
            + (retain_spurious - retain_before.1)
            + (report.cas_failed - credit_before.cas_failed)
            + (report.cas_spurious - credit_before.cas_spurious);
        let paid = attempts.load(Ordering::Relaxed);
        let explained = 2 * successes
            + lease_limits.load(Ordering::Relaxed)
            + 2 * retain_limits.load(Ordering::Relaxed)
            + failures;
        assert!(paid >= explained, "{paid} {explained}");
        assert!(
            paid <= explained + contended.load(Ordering::Relaxed),
            "{paid} {explained}"
        );
        drop(resident);
    }
}
