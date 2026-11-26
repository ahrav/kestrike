//! The unique owner of one completed, record-bound object before any lease
//! exists.
//!
//! A [`Completed`] owner is produced only by consuming an
//! [`ExtentReservation`](super::ExtentReservation) through its completion,
//! which [`WritableFill::publish`](super::WritableFill::publish) performs with
//! the publication's portable pair, so a completed object has exactly one
//! owner. It borrows the [`Storage`] like
//! the reservation did, which keeps the control tables alive
//! for as long as the owner exists and forbids finalization meanwhile. It is
//! not `Clone`, has no public constructor, and offers no method that frees
//! by identity or asserts anything about completion. It holds the storage
//! borrow and the object's identity, its slot and incarnation; the object's
//! record is on the device, read through the volume.
//!
//! Dropping the owner is abandonment, exactly as for a reservation: the slot
//! moves from resident to retired, or the obligation is parked, and the
//! deferred return frees the extent. [`Completed::release`] hands
//! the return eligibility over instead, for an immediate return.
//!
//! ```compile_fail,E0599
//! # use kestrike::storage::*;
//! # fn f(completed: Completed<'_, LinuxPlatform>) {
//! let copy = completed.clone();
//! # }
//! ```
//!
//! ```compile_fail,E0599
//! # use kestrike::storage::*;
//! # fn f(completed: Completed<'_, LinuxPlatform>, budget: &mut WorkBudget) {
//! let again = completed.complete([0; 32], 1, budget);
//! # }
//! ```
//!
//! Stable rustdoc does not check the error codes above; they record the
//! intended cause (E0599 missing method) for a reader, and
//! `cargo +nightly test --doc` verifies them.

use super::allocation::{AllocationId, Owned, abandon};
use super::budget::BudgetExhausted;
use super::extent::ExtentLocator;
use super::gate::GateError;
use super::os::Platform;
use super::owner::Storage;
use super::release::ReturnTransfer;

/// Why a reservation was not completed. The owner is handed back unchanged
/// alongside the error; its identity and charges are untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompleteError {
    /// The storage is drained.
    TornDown,
    /// The budget ran out before the try or before the update.
    BudgetExhausted,
    /// The gate was busy or poisoned; the failed try is counted.
    Gate(GateError),
    /// The slot's word no longer describes this owner.
    Rejected,
}

impl From<BudgetExhausted> for CompleteError {
    fn from(_: BudgetExhausted) -> Self {
        Self::BudgetExhausted
    }
}

/// Unique owner of one completed, record-bound object. See the module
/// documentation.
pub struct Completed<'s, P: Platform> {
    storage: &'s Storage<P>,
    id: AllocationId,
    /// The key the object was completed under. Test-only publication routes
    /// by it, and `handoff` gives it to the resident authority and its
    /// leases.
    #[cfg(test)]
    pub(super) key: crate::index::Key,
}

impl<P: Platform> std::fmt::Debug for Completed<'_, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Completed")
            .field("id", &self.id)
            .field("locator", &self.locator())
            .finish_non_exhaustive()
    }
}

impl<'s, P: Platform> Completed<'s, P> {
    pub(crate) fn new(
        storage: &'s Storage<P>,
        id: AllocationId,
        #[cfg(test)] key: crate::index::Key,
    ) -> Self {
        Self {
            storage,
            id,
            #[cfg(test)]
            key,
        }
    }

    pub fn id(&self) -> AllocationId {
        self.id
    }

    /// The storage borrow and identity.
    #[cfg(test)]
    pub(crate) fn parts(&self) -> (&'s Storage<P>, AllocationId) {
        (self.storage, self.id)
    }

    /// Ends this owner without abandonment and hands its parts to the
    /// authority that takes over the slot; only a handoff that has already
    /// anchored the object may call it. The lease publication ends its owner
    /// in place instead, under the `ManuallyDrop` that suppressed it.
    #[cfg(test)]
    pub(crate) fn into_parts(self) -> (&'s Storage<P>, AllocationId) {
        let parts = self.parts();
        std::mem::forget(self);
        parts
    }

    /// The deadline's whole seconds `bind` stored.
    pub(crate) fn expires_at_s(&self) -> u32 {
        self.storage.pool().records()[self.id.slot().0].expires_at_s()
    }

    /// The extent the object's record fills, in units of the volume.
    pub fn locator(&self) -> ExtentLocator {
        self.storage.pool().records()[self.id.slot().0].locator()
    }

    /// Ends this owner's access and hands the allocator the eligibility
    /// transfer for exactly this incarnation. With the unique owner consumed
    /// no accessor remains. Nothing is freed here: the transfer is consumed
    /// by [`Storage::return_allocation`] or serviced later.
    pub fn release(self) -> ReturnTransfer<'s, P> {
        let transfer = ReturnTransfer::new(self.storage, self.id);
        std::mem::forget(self);
        transfer
    }
}

impl<P: Platform> Completed<'_, P> {
    /// The abandonment the drop performs, on a borrowed owner; any caller
    /// but the drop must never drop the owner afterwards, or the abandonment
    /// would run twice. Returns false when the gate recorded nothing and the
    /// park found the slot word malformed or naming another incarnation, so
    /// nothing records the abandonment and
    /// a caller that holds a record beside the owner keeps it occupied. True
    /// after teardown.
    pub(super) fn abandon_in_place(&self) -> bool {
        let Some(pool) = self.storage.live_pool() else {
            return true;
        };
        abandon(pool, self.id, Owned::Resident, 0, false, None).1
    }
}

impl<P: Platform> Drop for Completed<'_, P> {
    fn drop(&mut self) {
        let _ = self.abandon_in_place();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::super::budget::{WorkBudget, WorkCounters};
    use super::super::claim_exit_tests::{FREE, PARKED_RESIDENT, RETIRED, conserved_at};
    use super::super::config::StorageConfig;
    use super::super::extent::RawPartition;
    use super::super::finalize::Finalization;
    use super::super::gate::GateError;
    use super::super::layout::IO_UNIT;
    use super::super::ledger::SlotPartition;
    use super::super::owner::Storage;
    use super::super::placement::PlacementConfig;
    use super::super::release::ReturnOutcome;
    use super::super::tables::{SlotIndex, SlotState};
    use super::super::test_platform::{TestPlatform, finalize};
    use super::super::word::ABANDONED;
    use super::{CompleteError, Completed};

    const PAGE: usize = 4096;
    const SLOTS: usize = 4;
    const KEY: [u8; 32] = [0xA5; 32];

    fn storage(slot_count: usize) -> Storage<TestPlatform> {
        let config = StorageConfig {
            page_size: PAGE,
            engine_budget: 1 << 24,
            body_cap: 200,
            metadata_cap: Some(16),
            lease_limit: 1024,
            object_rights: 64,
            reader_limit: 4,
            volume: crate::storage::test_volume(slot_count * IO_UNIT, slot_count),
        };
        let placement = PlacementConfig { control_home: 0 };
        Storage::initialize(
            &config.validate().unwrap(),
            &placement,
            TestPlatform::heap(PAGE),
        )
        .unwrap()
    }

    fn budget() -> WorkBudget {
        WorkBudget::new(1 << 10)
    }

    /// Enough for one whole service pass over the pool: the call controls
    /// and one prepaid bundle per slot.
    fn maintenance() -> WorkBudget {
        WorkBudget::new(1 << 10)
    }

    fn partition(storage: &Storage<TestPlatform>) -> (RawPartition, SlotPartition) {
        let report = storage.pool_report().unwrap();
        let ledger = report.ledger.unwrap();
        (ledger.raw, ledger.slots)
    }

    /// An 8-byte metadata, 60-byte body owner in one unit with producer-held
    /// bytes written through it.
    fn filled<'s>(
        storage: &'s Storage<TestPlatform>,
        metadata: &[u8],
        body: &[u8],
    ) -> super::super::ExtentReservation<'s, TestPlatform> {
        storage
            .reserve(Some(metadata.len()), Some(body.len()), &mut budget())
            .unwrap()
    }

    fn complete<'s>(
        allocation: super::super::ExtentReservation<'s, TestPlatform>,
        key: [u8; 32],
        ticks: u64,
        budget: &mut WorkBudget,
    ) -> Completed<'s, TestPlatform> {
        match allocation.complete(key, ticks, budget) {
            Ok(completed) => completed,
            Err((_, error)) => panic!("{error:?}"),
        }
    }

    #[test]
    fn completion_binds_the_record_and_moves_the_ledger() {
        let storage = storage(SLOTS);
        let metadata = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let body: Vec<u8> = (0..60u8).map(|b| b.wrapping_mul(3)).collect();
        let allocation = filled(&storage, &metadata, &body);
        let id = allocation.id();
        let address = allocation.locator();
        // The locator ends at the record's last 512-byte sector: header, metadata and body.
        let record_len = allocation.layout().record().record_len();
        assert_eq!(address.record_end(), record_len.next_multiple_of(512));
        let before = partition(&storage);
        let allocations = crate::instrument::allocations();

        let mut spent = budget();
        let completed = complete(allocation, KEY, 1_000, &mut spent);
        assert_eq!(
            spent.counters(),
            WorkCounters {
                coordination_attempts: 1,
                updates: 1,
                ..WorkCounters::default()
            }
        );
        assert_eq!(completed.id(), id);
        assert_eq!(completed.locator(), address);
        assert_eq!(crate::instrument::allocations(), allocations);
        // A deadline below one second keeps zero whole seconds.
        assert_eq!(completed.expires_at_s(), 0);
        // The first extent starts at the volume's first unit.
        assert_eq!(
            (
                completed.locator().start_unit(),
                completed.locator().len_units()
            ),
            (0, 1)
        );

        let (payload, slots) = partition(&storage);
        assert_eq!(
            payload,
            RawPartition {
                reserved: 0,
                resident: 68,
                ..before.0
            }
        );
        assert_eq!(
            slots,
            SlotPartition {
                filling: 0,
                resident: 1,
                ..before.1
            }
        );
        assert_eq!(
            storage.slot_state(SlotIndex(id.slot_index())),
            Some((SlotState::Resident, 1))
        );
        assert!(storage.identity_is_current(id));

        // Release is an ordinary return from Resident; the same extent is
        // reissued at the same address.
        assert_eq!(
            storage.return_allocation(completed.release(), &mut budget()),
            Ok(ReturnOutcome::Returned)
        );
        assert_eq!(partition(&storage), before_free(&before));
        // The claim cursor moved past the returned slot; pointed back at it,
        // the next claim takes it again.
        storage.live_pool().unwrap().claim_next(id.slot_index());
        let again = filled(&storage, &metadata, &body);
        assert_eq!(again.locator(), address);
        assert_eq!(again.id().slot_index(), id.slot_index());
    }

    fn before_free(before: &(RawPartition, SlotPartition)) -> (RawPartition, SlotPartition) {
        (
            RawPartition {
                free: before.0.free + before.0.reserved + before.0.waste,
                reserved: 0,
                waste: 0,
                ..before.0
            },
            SlotPartition {
                free: before.1.free + 1,
                filling: 0,
                ..before.1
            },
        )
    }

    /// Empty metadata and body: one positive charge of one unit, all waste.
    #[test]
    fn the_empty_object_completes_with_one_positive_charge() {
        let storage = storage(SLOTS);
        let allocation = storage.reserve(Some(0), Some(0), &mut budget()).unwrap();
        let completed = complete(allocation, KEY, 1, &mut budget());
        assert_eq!(partition(&storage).0.resident, 0);
        assert_eq!(partition(&storage).0.waste, IO_UNIT);
        assert_eq!(partition(&storage).1.resident, 1);
        // The first extent starts at the mapping base and spans one unit.
        assert_eq!(
            (
                completed.locator().start_unit(),
                completed.locator().len_units()
            ),
            (0, 1)
        );
    }

    /// Each refusal hands the owner back with identity, bytes, address and
    /// charges unchanged; a retained incumbent is untouched throughout, and
    /// both slots and extents stay charged until the old return.
    #[test]
    fn refusals_return_the_owner_unchanged_and_preserve_the_incumbent() {
        let storage = storage(SLOTS);
        let live = storage.live_pool().unwrap();
        let incumbent_body: Vec<u8> = (0..60u8).collect();
        let incumbent = complete(
            filled(&storage, &[9; 8], &incumbent_body),
            [1; 32],
            5,
            &mut budget(),
        );
        let incumbent_address = incumbent.locator();
        let incumbent_id = incumbent.id();

        let replacement = filled(&storage, &[7; 8], &[7; 60]);
        let replacement_id = replacement.id();
        let replacement_address = replacement.locator();
        let before = partition(&storage);
        assert_eq!((before.0.resident, before.0.reserved), (68, 68));
        let tries = live.telemetry().failed_tries.load(Ordering::Relaxed);

        // Zero budget: no try, no change.
        let (replacement, error) = replacement
            .complete(KEY, 1, &mut WorkBudget::new(0))
            .err()
            .unwrap();
        assert_eq!(error, CompleteError::BudgetExhausted);
        assert_eq!(live.telemetry().failed_tries.load(Ordering::Relaxed), tries);

        // One step: the try is paid, the update is not; the gate is released.
        let mut one = WorkBudget::new(1);
        let (replacement, error) = replacement.complete(KEY, 1, &mut one).err().unwrap();
        assert_eq!(error, CompleteError::BudgetExhausted);
        assert_eq!(one.counters().coordination_attempts, 1);
        assert!(live.try_lock_quiet().is_ok());

        // Contended: the failed try is counted.
        let held = live.lock().unwrap();
        let (replacement, error) = replacement.complete(KEY, 1, &mut budget()).err().unwrap();
        assert_eq!(error, CompleteError::Gate(GateError::Contended));
        assert_eq!(
            live.telemetry().failed_tries.load(Ordering::Relaxed),
            tries + 1
        );
        drop(held);

        // A word that no longer names the owner in its state or its
        // incarnation is rejected before any record write: the sentinels
        // written beforehand survive every rejected attempt.
        let slot = replacement_id.slot_index();
        let record = &live.records()[slot];
        record.set_fingerprint(77);
        record.set_expires_at_s(77);
        let mut replacement = replacement;
        for perturb in 0..2 {
            {
                let _held = live.lock().unwrap();
                match perturb {
                    0 => live.set_state(slot, SlotState::Resident),
                    _ => live.set_incarnation(slot, live.incarnation(slot) + 1),
                }
            }
            let mut spent = budget();
            let allocations = crate::instrument::allocations();
            let (returned, error) = replacement.complete(KEY, 1, &mut spent).err().unwrap();
            assert_eq!(crate::instrument::allocations(), allocations);
            assert_eq!(error, CompleteError::Rejected, "{perturb}");
            assert_eq!(spent.counters().coordination_attempts, 1);
            assert_eq!(spent.counters().updates, 1);
            replacement = returned;
            {
                let _held = live.lock().unwrap();
                match perturb {
                    0 => live.set_state(slot, SlotState::Filling),
                    _ => live.set_incarnation(slot, live.incarnation(slot) - 1),
                }
            }
            assert_eq!(record.fingerprint(), 77);
            assert_eq!(record.expires_at_s(), 77);
        }

        assert_eq!(replacement.id(), replacement_id);
        assert_eq!(replacement.locator(), replacement_address);
        assert_eq!(partition(&storage), before);
        assert_eq!(
            storage.slot_state(SlotIndex(slot)),
            Some((SlotState::Filling, 1))
        );
        assert_eq!(incumbent.id(), incumbent_id);
        assert_eq!(incumbent.locator(), incumbent_address);

        // The same owner completes afterwards, after close (close changes
        // admission only); both are resident until the old one returns, and
        // the incumbent's record stays bound across the other slot's
        // completion, return and service.
        storage.close();
        let allocations = crate::instrument::allocations();
        let replacement = complete(replacement, KEY, 1, &mut budget());
        assert_eq!(crate::instrument::allocations(), allocations);
        assert_eq!(partition(&storage).0.resident, 136);
        assert_eq!(partition(&storage).1.resident, 2);
        assert_eq!(
            storage.return_allocation(replacement.release(), &mut budget()),
            Ok(ReturnOutcome::Returned)
        );
        assert_eq!(crate::instrument::allocations(), allocations);
        storage.service(&mut maintenance()).unwrap();
        assert_eq!(incumbent.locator(), incumbent_address);
        assert_eq!(incumbent.expires_at_s(), 0);
        assert_eq!(partition(&storage).0.resident, 68);
        assert_eq!(
            storage.return_allocation(incumbent.release(), &mut budget()),
            Ok(ReturnOutcome::Returned)
        );
        assert_eq!(partition(&storage).0.resident, 0);
    }

    /// Dropping a resident owner is abandonment: resident to retired under a
    /// free gate, parked under a busy one; service returns the extent, the
    /// cell is reused by the next incarnation, and the incarnation advances.
    /// The tables pass the conservation judge after each drop and after the
    /// service pass that returns its extent.
    #[test]
    fn dropped_resident_is_retired_then_returned_and_the_cell_is_reused() {
        let storage = storage(SLOTS);
        let live = storage.live_pool().unwrap();
        let body: Vec<u8> = (0..60u8).collect();
        let first = complete(filled(&storage, &[1; 8], &body), [1; 32], 1, &mut budget());
        let slot = first.id().slot_index();
        let address = first.locator();
        let allocations = crate::instrument::allocations();
        drop(first);
        assert_eq!(crate::instrument::allocations(), allocations);
        conserved_at(&storage, slot, RETIRED);
        let (payload, slots) = partition(&storage);
        assert_eq!((payload.resident, payload.retired), (0, 68));
        assert_eq!((slots.resident, slots.retired), (0, 1));
        assert_eq!(
            storage.slot_state(SlotIndex(slot)),
            Some((SlotState::Retired, 1))
        );
        assert_eq!(storage.service(&mut maintenance()).unwrap().serviced, 1);
        conserved_at(&storage, slot, FREE);
        assert_eq!(
            storage.slot_state(SlotIndex(slot)),
            Some((SlotState::Free, 1))
        );

        // The next incarnation writes and reads the same cell with new
        // contents at the same address, once the claim cursor points at the
        // slot again.
        live.claim_next(slot);
        let second = complete(
            filled(&storage, &[2; 8], &[2; 60]),
            [2; 32],
            2,
            &mut budget(),
        );
        assert_eq!(second.id().slot_index(), slot);
        assert_eq!(second.locator(), address);
        assert_eq!(
            storage.slot_state(SlotIndex(slot)),
            Some((SlotState::Resident, 2))
        );

        // Under a held gate the drop parks: flag and counter carry the
        // obligation, the ledger still says resident, nothing waited.
        let held = live.lock().unwrap();
        drop(second);
        assert_eq!(live.flags(slot), ABANDONED);
        assert_eq!(live.telemetry().pending_marks.load(Ordering::Acquire), 1);
        drop(held);
        conserved_at(&storage, slot, PARKED_RESIDENT);
        assert_eq!(partition(&storage).0.resident, 68);
        assert_eq!(storage.service(&mut maintenance()).unwrap().serviced, 1);
        conserved_at(&storage, slot, FREE);
        assert_eq!(partition(&storage).0.resident, 0);
        assert_eq!(live.telemetry().pending_marks.load(Ordering::Acquire), 0);
        assert!(storage.outstanding().is_clear());
    }

    /// Repeated refused completion consumes incarnations until the counter is
    /// exhausted; the slot quarantines and is never reissued, not on an empty
    /// pool, not after close, not after slab reassignment.
    #[test]
    fn exhausted_incarnation_through_refused_completion_quarantines_the_slot() {
        let storage = storage(SLOTS);
        let live = storage.live_pool().unwrap();
        {
            let _held = live.lock().unwrap();
            live.set_incarnation(0, u32::MAX - 2);
        }
        for expected in [u32::MAX - 1, u32::MAX] {
            let owner = filled(&storage, &[0; 8], &[0; 60]);
            assert_eq!(owner.id().slot_index(), 0);
            let (owner, error) = if expected == u32::MAX {
                owner
                    .complete(KEY, 1, &mut WorkBudget::new(0))
                    .err()
                    .unwrap()
            } else {
                let held = live.lock().unwrap();
                let refused = owner.complete(KEY, 1, &mut budget()).err().unwrap();
                drop(held);
                refused
            };
            assert!(matches!(
                error,
                CompleteError::Gate(GateError::Contended) | CompleteError::BudgetExhausted
            ));
            assert_eq!(
                storage.slot_state(SlotIndex(0)),
                Some((SlotState::Filling, expected))
            );
            drop(owner);
            assert_eq!(storage.service(&mut maintenance()).unwrap().serviced, 1);
            assert_eq!(
                storage.slot_state(SlotIndex(0)),
                Some((SlotState::Free, expected))
            );
            // The claim cursor moved past slot 0; point it back so the next
            // claim takes slot 0 again.
            live.claim_next(0);
        }
        let next = filled(&storage, &[0; 8], &[0; 60]);
        assert_eq!(next.id().slot_index(), 1);
        let quarantined = Some((SlotState::Quarantined, u32::MAX));
        assert_eq!(storage.slot_state(SlotIndex(0)), quarantined);
        let slots = partition(&storage).1;
        assert_eq!(
            slots,
            SlotPartition {
                free: SLOTS - 2,
                filling: 1,
                quarantined: 1,
                ..SlotPartition::default()
            }
        );
        assert_eq!(slots.total(), Ok(SLOTS));
        drop(next);
        storage.service(&mut maintenance()).unwrap();
        storage.close();
        assert_eq!(storage.slot_state(SlotIndex(0)), quarantined);
        assert_eq!(partition(&storage).1.quarantined, 1);
    }

    /// The record and tail charge: `O` records of 32 bytes on a line
    /// boundary, then `O` tails of 2 bytes, then the free-slot set's words,
    /// inside the control mapping, charged once at initialization and
    /// unchanged by completion, refusal or return. The tails follow the
    /// records directly.
    #[test]
    fn records_and_tails_are_charged_once_at_initialization() {
        let storage = storage(SLOTS);
        let inventory = storage.table_inventory().unwrap();
        assert_eq!(inventory.records.1, SLOTS);
        assert_eq!(inventory.records.0 % 64, 0);
        assert_eq!(inventory.tails, (inventory.records.0 + 32 * SLOTS, SLOTS));
        assert_eq!(
            inventory.free_slots,
            (
                (inventory.tails.0 + 2 * SLOTS).next_multiple_of(8),
                super::super::free::words(SLOTS)
            )
        );
        assert_eq!(
            inventory.telemetry.0,
            inventory.free_slots.0 + 8 * inventory.free_slots.1
        );
        let report = storage.pool_report().unwrap();
        assert!(inventory.tails.0 + 2 * SLOTS <= report.control_extent);
        let used = storage.engine_used();

        let owner = filled(&storage, &[1; 8], &[1; 60]);
        let (owner, _) = owner
            .complete(KEY, 1, &mut WorkBudget::new(0))
            .err()
            .unwrap();
        let completed = complete(owner, KEY, 1, &mut budget());
        assert_eq!(storage.engine_used(), used);
        assert_eq!(storage.table_inventory(), Some(inventory));
        assert_eq!(
            storage.return_allocation(completed.release(), &mut budget()),
            Ok(ReturnOutcome::Returned)
        );
        assert_eq!(storage.engine_used(), used);
        assert_eq!(
            storage.pool_report().unwrap().control_extent,
            report.control_extent
        );
    }

    /// Completion moves ownership to another thread and the final drop or
    /// return happens there; teardown waits for the borrow to end.
    #[test]
    fn a_completed_owner_moves_across_threads_and_returns_there() {
        let mut storage = storage(SLOTS);
        let body: Vec<u8> = (0..60u8).rev().collect();
        let shared = &storage;
        std::thread::scope(|scope| {
            let completed = complete(filled(shared, &[3; 8], &body), KEY, 3, &mut budget());
            let locator = completed.locator();
            scope.spawn(move || {
                assert_eq!(completed.locator(), locator);
                assert_eq!(
                    shared.return_allocation(completed.release(), &mut budget()),
                    Ok(ReturnOutcome::Returned)
                );
            });
        });
        assert!(storage.outstanding().is_clear());
        assert_eq!(finalize(&mut storage), Ok(Finalization::Drained));
    }
}
