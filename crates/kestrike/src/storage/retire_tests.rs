//! Retirement, anchor release, eligible return and finalization across the
//! whole owner lifecycle: allocation, completion, handoff, further leases,
//! retirement and service, on the heap-backed platform.
//!
//! The conjuncts of reuse in this crate are the ones its types express: no
//! owner of the allocation or the completed object, no anchor, no read
//! right, a retirement recorded or parked for service, and grace certified
//! above the slot's retirement era. Acquisition intervals are `&Resident`
//! borrows and end before the authority can be consumed. `ServiceReport::held`
//! and `Outstanding::anchored` are the blocked-by-readers signals. The kernels
//! below run real schedules on threads. Registered readers and their pins are
//! exercised in the `register` and `grace` modules.

use std::sync::atomic::Ordering;

use super::budget::WorkBudget;
use super::config::StorageConfig;
use super::gate::GateError;
use super::ledger::SlotPartition;
use super::owner::Storage;
use super::placement::PlacementConfig;
use super::release::{
    Outstanding, ReturnError, ReturnTransfer, SERVICE_CONTROLS, SERVICE_MINIMUM, ServiceError, park,
};
use super::tables::{SlotIndex, SlotState};
use super::test_platform::TestPlatform;
use super::test_platform::{blocked, finalize};
use super::word::{ABANDONED, ANCHORED};
use super::{
    CompleteError, Completed, ExtentLease, HandoffError, ReserveError, Resident, RetireOutcome,
};
use super::{Finalization, FinalizeError};

const PAGE: usize = 4096;
const KEY: [u8; 32] = [0x77; 32];

fn storage(slot_count: usize, lease_limit: usize) -> Storage<TestPlatform> {
    let config = StorageConfig {
        page_size: PAGE,
        engine_budget: 1 << 24,
        body_cap: 200,
        metadata_cap: Some(16),
        lease_limit,
        object_rights: 8,
        reader_limit: 4,
        volume: crate::storage::test_volume((slot_count + 1) * crate::storage::IO_UNIT, slot_count),
    };
    let placement = PlacementConfig { control_home: 0 };

    Storage::initialize(
        &config.validate().unwrap(),
        &placement,
        TestPlatform::heap(PAGE),
    )
    .unwrap()
}

/// Room for a Miri run, where a weak compare-exchange fails spuriously most
/// of the time.
fn budget() -> WorkBudget {
    WorkBudget::new(1 << 10)
}

fn completed<'s>(
    storage: &'s Storage<TestPlatform>,
    metadata: &[u8],
    body: &[u8],
) -> Completed<'s, TestPlatform> {
    let mut allocation = storage
        .reserve(Some(metadata.len()), Some(body.len()), &mut budget())
        .unwrap();
    allocation.mark_written();
    allocation
        .complete(KEY, u64::MAX, &mut budget())
        .ok()
        .unwrap()
}

fn handoff<'s>(
    storage: &'s Storage<TestPlatform>,
    metadata: &[u8],
    body: &[u8],
) -> (Resident<'s, TestPlatform>, ExtentLease<'s, TestPlatform>) {
    completed(storage, metadata, body)
        .handoff(&mut budget())
        .ok()
        .unwrap()
}

fn refs(storage: &Storage<TestPlatform>, slot: usize) -> usize {
    let pool = storage.live_pool().unwrap();
    pool.refs(slot)
}

fn partition(storage: &Storage<TestPlatform>) -> (super::RawPartition, SlotPartition) {
    let ledger = storage.pool_report().unwrap().ledger.unwrap();
    (ledger.raw, ledger.slots)
}

fn state(storage: &Storage<TestPlatform>, slot: usize) -> SlotState {
    storage.slot_state(SlotIndex(slot)).unwrap().0
}

/// One full service pass with a generous budget.
fn service(storage: &Storage<TestPlatform>) -> super::release::ServiceReport {
    storage.service(&mut WorkBudget::new(1 << 12)).unwrap()
}

/// One complete certification pass with a generous budget; with no reader
/// pinned it certifies the current era.
fn certify(storage: &Storage<TestPlatform>) -> u64 {
    storage
        .certify(&mut WorkBudget::new(400))
        .unwrap()
        .certified
        .unwrap()
}

fn transient_reserve(error: ReserveError) -> Result<(), ReserveError> {
    matches!(
        error,
        ReserveError::Gate(GateError::Contended)
            | ReserveError::CleanReserve
            | ReserveError::ObjectSlotsFull
            | ReserveError::PayloadFull
    )
    .then_some(())
    .ok_or(error)
}

/// `Err(Ok(()))` denotes a transient refusal another thread must clear.
/// `Err(Err(error))` is a genuine failure. The bound turns a livelock into
/// a failure instead of a hang.
fn retrying<T, E: std::fmt::Debug>(mut attempt: impl FnMut() -> Result<T, Result<(), E>>) -> T {
    for _ in 0..1_000_000 {
        match attempt() {
            Ok(value) => return value,
            Err(Ok(())) => std::thread::yield_now(),
            Err(Err(error)) => panic!("{error:?}"),
        }
    }
    panic!("a transient refusal never cleared");
}

/// Withholding each conjunct of reuse eligibility independently keeps the
/// block, its bytes and its address in place; releasing all of them yields
/// exactly one return and useful same-class reuse, for an empty and a
/// non-empty object, and again after the pool saturates.
#[test]
fn withholding_each_conjunct_prevents_return_and_releasing_all_reuses_the_block() {
    let slot_count = 8;
    let storage = storage(slot_count, 16);
    let live = storage.live_pool().unwrap();
    let body: Vec<u8> = (0..60u8).collect();
    let engine_used = storage.engine_used();

    // A mutable owner: not flagged, not returned, however often service runs.
    let filling = storage.reserve(Some(8), Some(60), &mut budget()).unwrap();
    let filling_address = filling.locator();
    assert_eq!(service(&storage).serviced, 0);
    assert_eq!(
        state(&storage, filling.id().slot_index()),
        SlotState::Filling
    );
    assert_eq!(filling.locator(), filling_address);
    drop(filling);
    assert_eq!(service(&storage).serviced, 1);

    // An immutable owner without an anchor: resident, unflagged, kept. A
    // park for another incarnation of its slot changes no bit: nothing to
    // clear, the owner untouched.
    let owner = completed(&storage, &[1; 8], &body);
    let slot = owner.id().slot_index();
    let incarnation = owner.id().incarnation();
    let address = owner.locator();
    assert_eq!(service(&storage).serviced, 0);
    assert_eq!(state(&storage, slot), SlotState::Resident);
    park(live, slot, incarnation.wrapping_sub(1));
    let pass = service(&storage);
    assert_eq!(pass.serviced, 0);
    assert_eq!(state(&storage, slot), SlotState::Resident);
    assert_eq!(live.telemetry().pending_marks.load(Ordering::Acquire), 0);

    // The anchor alone: the authority lives, every lease is gone. The slot
    // is unflagged, since the flag and the anchor release are one consumption
    // of the authority, so service never examines it.
    let (resident, lease) = owner.handoff(&mut budget()).ok().unwrap();
    let second = resident.acquire(Some(1), &mut budget()).unwrap();
    drop(lease);
    drop(second);
    assert_eq!(refs(&storage, slot), 1);
    assert_eq!(service(&storage).serviced, 0);
    assert_eq!(state(&storage, slot), SlotState::Resident);

    // Grace alone: retired with two leases, the anchor stays counted and
    // service holds the slot until a completed pass certifies past the
    // retirement era; then exactly one anchor is released.
    let first = resident.acquire(Some(1), &mut budget()).unwrap();
    let second = resident.acquire(Some(1), &mut budget()).unwrap();
    let era_before = storage.era_report().unwrap().era;
    assert_eq!(resident.retire(), RetireOutcome::Recorded);
    assert_eq!(refs(&storage, slot), 3);
    assert_eq!(state(&storage, slot), SlotState::Retired);
    assert_eq!(live.retire_era(slot), era_before);
    assert_eq!(storage.era_report().unwrap().era, era_before + 1);
    let pass = service(&storage);
    assert_eq!((pass.serviced, pass.held, pass.released), (0, 1, 0));
    assert_eq!(refs(&storage, slot), 3);
    assert_eq!(certify(&storage), era_before + 1);
    // Rights alone: the anchor is released on the next visit, two leases
    // keep the block.
    let pass = service(&storage);
    assert_eq!((pass.serviced, pass.held, pass.released), (0, 1, 1));
    assert_eq!(refs(&storage, slot), 2);
    drop(first);
    let pass = service(&storage);
    assert_eq!((pass.serviced, pass.held), (0, 1));
    let (payload, slots) = partition(&storage);
    assert_eq!((payload.retired, slots.retired), (68, 1));

    // Every conjunct released: exactly one return, then same-class reuse at
    // the same address with a newer incarnation, and a stale transfer for
    // the old incarnation changes nothing.
    drop(second);
    assert_eq!(refs(&storage, slot), 0);
    assert_eq!(storage.outstanding().pending, 1);
    let pass = service(&storage);
    assert_eq!((pass.serviced, pass.held), (1, 0));
    assert_eq!(service(&storage).serviced, 0);
    assert_eq!(state(&storage, slot), SlotState::Free);
    assert!(storage.outstanding().is_clear());
    // The claim cursor moved past the slot; pointed back at it, the slot is
    // the next claim.
    live.claim_next(slot);
    let again = completed(&storage, &[2; 8], &[2; 60]);
    assert_eq!(again.id().slot_index(), slot);
    assert_eq!(again.locator(), address);
    assert_eq!(again.id().incarnation(), incarnation + 1);
    // Same slot, only the incarnation is old.
    let stale = ReturnTransfer::new(
        &storage,
        super::AllocationId::new(SlotIndex(slot), incarnation),
    );
    let before = (partition(&storage), storage.lease_report().unwrap());
    assert_eq!(
        storage.return_allocation(stale, &mut budget()),
        Err(ReturnError::Rejected)
    );
    assert_eq!(
        (partition(&storage), storage.lease_report().unwrap()),
        before
    );
    drop(again);
    service(&storage);

    // The empty object goes through the same cycle.
    let (resident, lease) = handoff(&storage, &[], &[]);
    let empty_slot = resident.id().slot_index();
    drop(resident);
    certify(&storage);
    assert_eq!(service(&storage).held, 1);
    drop(lease);
    assert_eq!(service(&storage).serviced, 1);
    live.claim_next(empty_slot);
    let (resident, lease) = handoff(&storage, &[], &[]);
    assert_eq!(resident.id().slot_index(), empty_slot);
    drop((lease, resident));
    certify(&storage);
    service(&storage);

    // Saturation: every slot anchored, then everything released.
    let mut residents = Vec::new();
    for n in 0..8u8 {
        let (resident, lease) = handoff(&storage, &[n; 8], &[n; 60]);
        drop(lease);
        residents.push(resident);
    }
    assert!(storage.reserve(Some(1), Some(1), &mut budget()).is_err());
    for resident in residents {
        assert_eq!(resident.retire(), RetireOutcome::Recorded);
    }
    assert_eq!(partition(&storage).1.retired, 8);
    assert_eq!(service(&storage).held, 8);
    certify(&storage);
    let pass = service(&storage);
    assert_eq!((pass.serviced, pass.released), (8, 8));
    assert!(storage.outstanding().is_clear());
    let (payload, slots) = partition(&storage);
    assert_eq!((payload.retired, payload.resident, slots.free), (0, 0, 8));
    let (resident, lease) = handoff(&storage, &[9; 8], &[9; 60]);
    drop((lease, resident));
    // Block returns restore usable capacity, never the engine charge.
    assert_eq!(storage.engine_used(), engine_used);
}

/// Retirement before and after the last lease, and the last release before
/// and after retirement, each leave exactly the anchor counted, and one
/// certified pass then one service converge to one return; parking under a
/// busy gate converges the same way.
#[test]
fn every_order_of_last_release_and_retirement_converges_to_one_return() {
    let slot_count = 8;
    let storage = storage(slot_count, 16);
    let live = storage.live_pool().unwrap();
    for order in 0..4 {
        let (resident, first) = handoff(&storage, &[order; 8], &[order; 60]);
        let second = resident.acquire(Some(1), &mut budget()).unwrap();
        let slot = resident.id().slot_index();
        let before = partition(&storage);
        match order {
            0 => {
                drop(first);
                drop(second);
                assert_eq!(refs(&storage, slot), 1);
                let allocations = crate::instrument::allocations();
                assert_eq!(resident.retire(), RetireOutcome::Recorded);
                assert_eq!(crate::instrument::allocations(), allocations);
            }
            1 => {
                assert_eq!(resident.retire(), RetireOutcome::Recorded);
                assert_eq!(refs(&storage, slot), 3);
                drop(first);
                let allocations = crate::instrument::allocations();
                drop(second);
                assert_eq!(crate::instrument::allocations(), allocations);
            }
            2 => {
                drop(first);
                drop(resident);
                assert_eq!(refs(&storage, slot), 2);
                drop(second);
            }
            _ => {
                // Retirement under a busy gate parks; the era is stamped all
                // the same and the ledger catches up in service.
                let held = live.lock().unwrap();
                assert_eq!(resident.retire(), RetireOutcome::Parked);
                assert_eq!(live.flags(slot), ABANDONED | ANCHORED);
                drop(held);
                assert_eq!(partition(&storage), before);
                assert_eq!(state(&storage, slot), SlotState::Resident);
                drop(second);
                drop(first);
            }
        }
        // Only the anchor remains, and service without certification holds.
        assert_eq!(refs(&storage, slot), 1);
        let pass = service(&storage);
        assert_eq!((pass.serviced, pass.held, pass.released), (0, 1, 0));
        let allocations = crate::instrument::allocations();
        certify(&storage);
        let pass = service(&storage);
        assert_eq!(
            (pass.serviced, pass.held, pass.released),
            (1, 0, 1),
            "{order}"
        );
        assert_eq!(service(&storage).serviced, 0);
        assert_eq!(crate::instrument::allocations(), allocations);
        assert_eq!(state(&storage, slot), SlotState::Free);
        assert_eq!(live.flags(slot), 0);
        assert_eq!(storage.lease_report().unwrap().reserved, 0);
        assert!(storage.outstanding().is_clear());
    }
}

/// Retirements and dropped owners on one thread race certification and
/// service on another: whenever service holds the pool gate, the retirement
/// or the drop parks, setting its slot's flag and then its parked bit while
/// service may be clearing a stale bit or returning a slot in the same
/// bitmap word. Once both threads stop, resumed service finds every parked
/// slot from the bitmaps and returns it, so no park's bit was lost: no mark
/// stays pending, no slot stays retired, and every block is free again.
#[test]
fn parks_racing_service_on_another_thread_all_return() {
    use std::sync::atomic::AtomicBool;

    let slot_count = 64;
    let storage = storage(slot_count, 16);
    let stop = AtomicBool::new(false);
    let mut parked = 0usize;
    std::thread::scope(|scope| {
        let server = scope.spawn(|| {
            while !stop.load(Ordering::Acquire) {
                let _ = storage.certify(&mut budget());
                let _ = storage.service(&mut budget());
            }
        });
        let mut residents = Vec::new();
        // A retirement parks only while service holds the pool gate, so
        // whether a round parks depends on how the scheduler interleaves
        // the threads.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        for round in 0u32.. {
            if round >= 20_000 && (parked > 0 || std::time::Instant::now() >= deadline) {
                break;
            }
            let Ok(mut allocation) = storage.reserve(Some(4), Some(20), &mut budget()) else {
                std::thread::yield_now();
                continue;
            };
            allocation.mark_written();
            // Every third round's object is dropped as a completed owner,
            // which abandons it; the rest are handed off and retired later.
            let Ok(completed) = allocation.complete(KEY, u64::MAX, &mut budget()) else {
                continue;
            };
            if round % 3 == 0 {
                drop(completed);
                continue;
            }
            let Ok((resident, lease)) = completed.handoff(&mut budget()) else {
                continue;
            };
            drop(lease);
            residents.push(resident);
            if residents.len() >= 8 {
                for resident in residents.drain(..) {
                    parked += usize::from(resident.retire() == RetireOutcome::Parked);
                }
            }
        }
        for resident in residents {
            parked += usize::from(resident.retire() == RetireOutcome::Parked);
        }
        stop.store(true, Ordering::Release);
        server.join().unwrap();
    });
    assert!(parked > 0, "no retirement met a busy gate");
    // Two certifications cover every retirement era; each service pass
    // covers the table.
    for _ in 0..2 {
        certify(&storage);
        service(&storage);
    }
    let live = storage.live_pool().unwrap();
    assert_eq!(live.telemetry().pending_marks.load(Ordering::Acquire), 0);
    let (raw, slots) = partition(&storage);
    assert_eq!(slots.retired, 0);
    assert_eq!(slots.free, slot_count);
    assert_eq!(
        raw,
        super::RawPartition::new(
            crate::storage::TEST_METADATA_UNITS as usize * crate::storage::IO_UNIT,
            (slot_count + 1) * crate::storage::IO_UNIT
        )
    );
    assert!(storage.outstanding().is_clear());
}

/// Every cleanup record occupied and service stopped: final leases dropped
/// on other threads while the pool gate is busy lose no obligation, write no
/// slot state after zero, and resumed service returns every block with no
/// notification of any kind.
#[test]
fn saturated_pending_records_survive_a_busy_pool_and_cross_thread_drops() {
    let slot_count = 8;
    let storage = storage(slot_count, 16);
    let live = storage.live_pool().unwrap();
    let mut leases = Vec::new();
    let mut residents = Vec::new();
    let mut incarnations = Vec::new();
    for n in 0..8u8 {
        let (resident, lease) = handoff(&storage, &[n; 8], &[n; 60]);
        incarnations.push(resident.id().incarnation());
        residents.push(resident);
        leases.push(lease);
    }
    let calls = storage.platform.log().all().len();
    let held = live.lock().unwrap();
    // Every retirement parks: eight flags, eight marks, ledger untouched.
    for resident in residents {
        assert_eq!(resident.retire(), RetireOutcome::Parked);
    }
    assert_eq!(live.telemetry().pending_marks.load(Ordering::Acquire), 8);
    let flags: Vec<u64> = (0..8).map(|slot| live.flags(slot)).collect();
    assert!(flags.iter().all(|flag| *flag == ABANDONED | ANCHORED));
    // Final drops on other threads while the gate stays busy.
    std::thread::scope(|scope| {
        for lease in leases.drain(..) {
            scope.spawn(move || drop(lease));
        }
    });
    for (slot, incarnation) in incarnations.iter().enumerate() {
        assert_eq!(refs(&storage, slot), 1);
        assert_eq!(live.flags(slot), ABANDONED | ANCHORED);
        assert_eq!(live.incarnation(slot), *incarnation);
    }
    assert_eq!(storage.lease_report().unwrap().reserved, 0);
    assert_eq!(live.telemetry().pending_marks.load(Ordering::Acquire), 8);
    // No kernel call, unmap or platform work of any kind happened.
    assert_eq!(storage.platform.log().all().len(), calls);
    drop(held);
    // The ledger still says resident: the drops wrote nothing but counts.
    assert_eq!(partition(&storage).1.resident, 8);
    assert_eq!(
        storage.outstanding(),
        Outstanding {
            pending: 8,
            anchored: 8,
            ..Outstanding::default()
        }
    );
    // Every anchor waits for grace; one certified pass releases all eight.
    let pass = service(&storage);
    assert_eq!((pass.serviced, pass.held, pass.released), (0, 8, 0));
    certify(&storage);
    let pass = service(&storage);
    assert_eq!((pass.serviced, pass.held), (8, 0));
    assert_eq!(pass.released, 8);
    assert_eq!(live.telemetry().pending_marks.load(Ordering::Acquire), 0);
    assert!(storage.outstanding().is_clear());
    assert_eq!(partition(&storage).1.free, 8);
}

/// Work accounting per kind for zero, one and generous budgets: held
/// records are counted separately from returns, an eligible target
/// behind held records is reached and returned across wraps, and the cursor
/// stops in front of a transition it cannot pay for.
#[test]
fn service_counts_held_and_returns_separately_and_revisits_fairly() {
    let slot_count = 4;
    let storage = storage(slot_count, 16);
    let live = storage.live_pool().unwrap();
    // Slots 0 and 1: retired with a live lease each. Slot 2: retired and
    // eligible. Slot 3: free and unflagged.
    let (a, a_lease) = handoff(&storage, &[0; 8], &[0; 60]);
    let (b, b_lease) = handoff(&storage, &[1; 8], &[1; 60]);
    let (c, c_lease) = handoff(&storage, &[2; 8], &[2; 60]);
    drop(a);
    drop(b);
    drop(c);
    drop(c_lease);
    // Certified past every retirement, so each anchor is released on its
    // first visit and only the live rights hold slots 0 and 1.
    certify(&storage);

    // Below `SERVICE_MINIMUM` the call is refused before the try, so the
    // budget is untouched and the cursor does not move.
    for short in 0..SERVICE_MINIMUM {
        let mut budget = WorkBudget::new(short);
        assert_eq!(
            storage.service(&mut budget),
            Err(ServiceError::BudgetExhausted)
        );
        assert_eq!(budget.remaining(), short);
    }

    // A funded call: the retired pass probes summary word 0 and bitmap word
    // 0 once, then visits slots 0 (held), 1 (held) and 2 (serviced) from the
    // word it read, each prepaying its bundle whether or not its updates
    // run; the word holds nothing past slot 2, so the pass covers every
    // position and wraps. Free slot 3 is never read.
    let mut spent = WorkBudget::new(1 << 10);
    super::reserve::take_return_visits();
    let report = storage.service(&mut spent).unwrap();
    let counted = super::reserve::take_return_visits();
    assert_eq!(
        (report.probes, report.visited, report.held, report.serviced),
        (2, 3, 2, 1)
    );
    assert_eq!(report.released, 3);
    assert_eq!((refs(&storage, 0), refs(&storage, 1)), (1, 1));
    assert_eq!(spent.counters().visits, 2 + 3 + counted);
    assert_eq!(spent.counters().comparisons, 3 * 3);
    assert_eq!(spent.counters().updates, SERVICE_CONTROLS - 1 + 2 * 3);
    assert_eq!(report.covered, slot_count);
    assert!(!report.budget_exhausted);
    assert_eq!(live.telemetry().pending_marks.load(Ordering::Acquire), 0);
    assert_eq!(state(&storage, 3), SlotState::Free);

    // The held slots are revisited on every wrap and return once released.
    let report = service(&storage);
    assert_eq!((report.held, report.serviced), (2, 0));
    drop(b_lease);
    let report = service(&storage);
    assert_eq!((report.held, report.serviced), (1, 1));
    drop(a_lease);
    let report = service(&storage);
    assert_eq!((report.held, report.serviced), (0, 1));
    assert!(storage.outstanding().is_clear());
}

/// `Drained` needs every lease released, every anchor gone and every pending
/// obligation serviced, on the thread that owns the storage; a forgotten
/// lease keeps its charges and blocks drain without a deadline, a poisoned
/// gate blocks it too, and repeated close and teardown change nothing.
#[test]
fn drained_needs_every_lease_anchor_and_obligation_ended() {
    let slot_count = 8;
    let mut storage = storage(slot_count, 16);
    let body: Vec<u8> = (0..60u8).collect();
    let (resident, lease) = handoff(&storage, &[4; 8], &body);
    let slot = resident.id().slot_index();
    let second = resident.acquire(Some(1), &mut budget()).unwrap();
    assert_eq!(
        storage.outstanding(),
        Outstanding {
            live: 1,
            leases: 2,
            anchored: 1,
            ..Outstanding::default()
        }
    );
    storage.close();
    storage.close();
    assert!(storage.is_closed());
    // Released one at a time from another thread while service keeps
    // running here; the ledger becomes clear only after the last one.
    let (ready, resume) = (std::sync::Barrier::new(2), std::sync::Barrier::new(2));
    std::thread::scope(|scope| {
        let (ready, resume) = (&ready, &resume);
        let shared = &storage;
        scope.spawn(move || {
            drop(lease);
            ready.wait();
            resume.wait();
            drop(resident);
            ready.wait();
            resume.wait();
            drop(second);
            ready.wait();
        });
        ready.wait();
        assert_eq!(shared.outstanding().leases, 1);
        assert_eq!(service(shared).serviced, 0);
        resume.wait();
        ready.wait();
        assert_eq!(state(shared, slot), SlotState::Retired);
        assert_eq!(service(shared).held, 1);
        assert_eq!(shared.outstanding().anchored, 1);
        resume.wait();
        ready.wait();
    });
    assert_eq!(
        storage.outstanding(),
        Outstanding {
            pending: 1,
            anchored: 1,
            ..Outstanding::default()
        }
    );
    assert!(!blocked(&mut storage).is_clear());
    assert_eq!(service(&storage).held, 1);
    certify(&storage);
    assert_eq!(service(&storage).serviced, 1);
    assert!(storage.outstanding().is_clear());

    assert_eq!(finalize(&mut storage), Ok(Finalization::Drained));
    assert_eq!(finalize(&mut storage), Err(FinalizeError::Drained));

    // A forgotten lease keeps its credit and right charged for good.
    let mut forgotten = self::storage(8, 16);
    let (resident, lease) = handoff(&forgotten, &[5; 8], &body);
    let forgotten_slot = resident.id().slot_index();
    std::mem::forget(lease);
    drop(resident);
    certify(&forgotten);
    assert_eq!(service(&forgotten).released, 1);
    let used = forgotten.engine_used();
    assert_eq!(
        forgotten.outstanding(),
        Outstanding {
            pending: 1,
            leases: 1,
            anchored: 1,
            ..Outstanding::default()
        }
    );
    assert_eq!(state(&forgotten, forgotten_slot), SlotState::Retired);
    assert_eq!(partition(&forgotten).0.retired, 68);
    let blockers = blocked(&mut forgotten);
    assert_eq!(blockers.leases, 1);
    assert!(blockers.pending >= 1, "{blockers:?}");
    assert_eq!(forgotten.engine_used(), used);
    assert_eq!(partition(&forgotten).1.retired, 1);

    // A poisoned gate keeps the whole pool unverifiable.
    let mut poisoned = self::storage(8, 16);
    std::thread::scope(|scope| {
        let handle = scope.spawn(|| {
            let _held = poisoned.live_pool().unwrap().lock().unwrap();
            panic!("poison the gate");
        });
        assert!(handle.join().is_err());
    });
    assert!(poisoned.outstanding().unverifiable);
    assert_eq!(finalize(&mut poisoned), Err(FinalizeError::Poisoned));
}

/// A return attempted while a right or the anchor is still counted fails
/// closed: the gate is poisoned, the slot keeps its state and bytes, and the
/// pool becomes unverifiable, so no reader can ever alias a reused block.
#[test]
fn a_return_against_an_outstanding_count_fails_closed() {
    let slot_count = 4;
    let mut storage = storage(slot_count, 16);
    let live = storage.live_pool().unwrap();
    let (resident, lease) = handoff(&storage, &[3; 8], &[3; 60]);
    let slot = resident.id().slot_index();
    let incarnation = resident.id().incarnation();
    let forged = ReturnTransfer::new(&storage, resident.id());
    let shared = &storage;
    std::thread::scope(|scope| {
        let handle = scope.spawn(move || shared.return_allocation(forged, &mut budget()));
        assert!(handle.join().is_err());
    });
    assert_eq!(refs(&storage, slot), 2);
    assert!(storage.outstanding().unverifiable);
    drop(lease);
    assert_eq!(resident.retire(), RetireOutcome::Parked);
    assert_eq!(refs(&storage, slot), 1);
    assert_eq!(live.flags(slot), ABANDONED | ANCHORED);
    assert_eq!(live.incarnation(slot), incarnation);
    assert_eq!(live.telemetry().pending_marks.load(Ordering::Acquire), 1);
    // Certification completes without this pool's gate; the release needs
    // this pool's service, which the poisoned gate refuses.
    let retired_at = live.retire_era(slot);
    assert_eq!(
        storage
            .certify(&mut WorkBudget::new(400))
            .unwrap()
            .certified,
        Some(retired_at + 1)
    );
    assert_eq!(
        storage.service(&mut WorkBudget::new(400)),
        Err(ServiceError::Gate(GateError::Poisoned))
    );
    assert_eq!(refs(&storage, slot), 1);
    assert_eq!(live.flags(slot), ABANDONED | ANCHORED);
    assert_eq!(finalize(&mut storage), Err(FinalizeError::Poisoned));
}

/// A slot whose incarnation counter is exhausted through full retire and
/// return cycles quarantines: its extent came back to the free set while the
/// slot is charged, unavailable and reported.
#[test]
fn exhausted_incarnation_through_full_cycles_quarantines_the_slot() {
    let slot_count = 4;
    let storage = storage(slot_count, 16);
    let live = storage.live_pool().unwrap();
    {
        let _held = live.lock().unwrap();
        live.set_incarnation(0, u32::MAX - 2);
    }
    for expected in [u32::MAX - 1, u32::MAX] {
        let (resident, lease) = handoff(&storage, &[1; 8], &[1; 60]);
        assert_eq!(resident.id().slot_index(), 0);
        assert_eq!(resident.id().incarnation(), expected);
        drop(lease);
        assert_eq!(resident.retire(), RetireOutcome::Recorded);
        certify(&storage);
        assert_eq!(service(&storage).serviced, 1);
        assert_eq!(
            storage.slot_state(SlotIndex(0)),
            Some((SlotState::Free, expected))
        );
        // The cursor is pointed back at slot 0, so the cycle reuses it.
        live.claim_next(0);
    }
    let next = completed(&storage, &[1; 8], &[1; 60]);
    assert_eq!(next.id().slot_index(), 1);
    assert_eq!(
        storage.slot_state(SlotIndex(0)),
        Some((SlotState::Quarantined, u32::MAX))
    );
    let slots = partition(&storage).1;
    assert_eq!((slots.quarantined, slots.resident, slots.free), (1, 1, 2));
    assert_eq!(slots.total(), Ok(4));
    // The extent the quarantined slot last held is back in the free set.
    drop(next);
    service(&storage);
    storage.close();
    assert_eq!(
        storage.slot_state(SlotIndex(0)),
        Some((SlotState::Quarantined, u32::MAX))
    );
    assert_eq!(partition(&storage).1.quarantined, 1);
    assert!(storage.outstanding().is_clear());
}

#[test]
fn the_lifecycle_workers_wait_out_the_refusal_of_an_exhausted_volume() {
    let slot_count = 64;
    let storage = storage(slot_count, 64);
    let mut held: Vec<_> = (0..slot_count)
        .map(|_| storage.reserve(Some(1), Some(1), &mut budget()).unwrap())
        .collect();
    let refusal = storage
        .reserve(Some(1), Some(1), &mut budget())
        .err()
        .unwrap();
    assert_eq!(transient_reserve(refusal), Ok(()), "{refusal:?}");
    assert_eq!(held.pop().unwrap().cancel(), Ok(()));
    assert!(storage.reserve(Some(1), Some(1), &mut budget()).is_ok());
}

/// Real-schedule kernels: full lifecycles on several threads with service
/// running concurrently, retirement racing lease release, and the finalizer
/// waiting for the last accessor.
#[test]
fn concurrent_lifecycles_conserve_the_ledger_and_drain() {
    let slot_count = 64;
    let mut storage = storage(slot_count, 64);
    let engine_used = storage.engine_used();
    let stop = std::sync::atomic::AtomicBool::new(false);
    let cycles = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        let stop = &stop;
        let cycles = &cycles;
        let storage = &storage;
        let workers: Vec<_> = (0..4u8)
            .map(|worker| {
                scope.spawn(move || {
                    for round in 0..30u8 {
                        let mut allocation = retrying(|| {
                            storage
                                .reserve(Some(1), Some(1), &mut budget())
                                .map_err(transient_reserve)
                        });
                        allocation.mark_written();
                        let mut pending = Some(allocation);
                        let owner = retrying(|| {
                            let allocation = pending.take().expect("returned on refusal");
                            allocation
                                .complete([worker; 32], u64::MAX, &mut budget())
                                .map_err(|(allocation, error)| {
                                    pending = Some(allocation);
                                    matches!(error, CompleteError::Gate(GateError::Contended))
                                        .then_some(())
                                        .ok_or(error)
                                })
                        });
                        let mut pending = Some(owner);
                        let (resident, lease) = retrying(|| {
                            let owner = pending.take().expect("returned on refusal");
                            owner.handoff(&mut budget()).map_err(|(owner, error)| {
                                pending = Some(owner);
                                matches!(error, HandoffError::Contended)
                                    .then_some(())
                                    .ok_or(error)
                            })
                        });
                        let extra = resident.acquire(Some(1), &mut budget()).ok();
                        cycles.fetch_add(1, Ordering::Relaxed);
                        match round % 3 {
                            0 => {
                                drop(lease);
                                drop(extra);
                                drop(resident);
                            }
                            1 => {
                                drop(resident);
                                drop(lease);
                                drop(extra);
                            }
                            _ => {
                                // Retirement races the final releases on
                                // two other threads.
                                std::thread::scope(|inner| {
                                    inner.spawn(move || drop(resident));
                                    inner.spawn(move || {
                                        drop(lease);
                                        drop(extra);
                                    });
                                });
                            }
                        }
                    }
                })
            })
            .collect();
        let servicer = scope.spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let _ = storage.certify(&mut WorkBudget::new(100));
                let _ = storage.service(&mut WorkBudget::new(storage.service_minimum()));
                std::thread::yield_now();
            }
        });
        // The servicer stops and joins before a worker's panic resumes, so
        // the scope finishes unwinding.
        let joined: Vec<_> = workers.into_iter().map(|worker| worker.join()).collect();
        stop.store(true, Ordering::Relaxed);
        servicer.join().unwrap();
        for result in joined {
            if let Err(panic) = result {
                std::panic::resume_unwind(panic);
            }
        }
    });
    let mut rounds = 0;
    // Each flagged run also funds its return's extent work bound, so a round
    // funds the whole pass and every pending return.
    while !storage.outstanding().is_clear() {
        certify(&storage);
        storage.service(&mut WorkBudget::new(1 << 14)).unwrap();
        rounds += 1;
        assert!(rounds < 20, "service did not converge");
    }
    assert_eq!(cycles.load(Ordering::Relaxed), 4 * 30);
    let (payload, slots) = partition(&storage);
    assert_eq!(
        payload,
        super::RawPartition::new(
            crate::storage::TEST_METADATA_UNITS as usize * crate::storage::IO_UNIT,
            (slot_count + 1) * crate::storage::IO_UNIT
        )
    );
    assert_eq!(slots.free, 64);
    assert_eq!(storage.lease_report().unwrap().reserved, 0);
    assert_eq!(storage.engine_used(), engine_used);
    // Finalizer against the last accessor: the last lease lives on another
    // thread and teardown can only run once it is gone.
    {
        let shared = &storage;
        std::thread::scope(|scope| {
            let (resident, lease) = handoff(shared, &[7; 8], &[7; 60]);
            scope.spawn(move || {
                drop(resident);
                drop(lease);
            });
        });
    }
    certify(&storage);
    assert_eq!(service(&storage).serviced, 1);
    assert_eq!(finalize(&mut storage), Ok(Finalization::Drained));
}
