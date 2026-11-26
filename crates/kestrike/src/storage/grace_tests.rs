//! Grace certification against live storage: pinned readers versus
//! retirement, resumable passes, the terminal era and the allocation-free
//! paths, on the heap-backed platform.
//!
//! Every expected era, pin and count below is written down by the test from
//! its own log of events, never read back from a production helper and
//! echoed. The reader threads run real schedules.

use std::sync::Barrier;
use std::sync::atomic::Ordering;

use super::Finalization;
use super::budget::WorkBudget;
use super::config::StorageConfig;
use super::grace::{ERA_FIRST, ERA_TERMINAL, PassCursor};
use super::owner::Storage;
use super::placement::PlacementConfig;
use super::register::PinError;
use super::release::{CERTIFY_CONTROLS, CertifyReport, Outstanding, ServiceError, certify_minimum};
use super::tables::SlotState;
use super::test_platform::TestPlatform;
use super::test_platform::{blocked, finalize};
use super::word::{ABANDONED, ANCHORED, RETIRED};
use super::{ExtentLease, RegisterError, RegistrationIndex, ReserveError, Resident, RetireOutcome};

pub(super) const PAGE: usize = 4096;
pub(super) const SLOTS: usize = 4;

/// A storage whose registration records have all been claimed once, so a
/// certification pass covers all `reader_limit` of them, as it does once
/// every reader has registered.
pub(super) fn storage(slot_count: usize, reader_limit: usize) -> Storage<TestPlatform> {
    let storage = unclaimed_storage(slot_count, reader_limit);
    let readers: Vec<_> = (0..reader_limit)
        .map(|_| storage.register().unwrap())
        .collect();
    drop(readers);
    storage
}

/// A storage no reader has registered with: the claimed bound is zero.
pub(super) fn unclaimed_storage(slot_count: usize, reader_limit: usize) -> Storage<TestPlatform> {
    let config = StorageConfig {
        page_size: PAGE,
        engine_budget: 1 << 24,
        body_cap: 200,
        metadata_cap: Some(16),
        lease_limit: 16,
        object_rights: 8,
        reader_limit,
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
pub(super) fn budget() -> WorkBudget {
    WorkBudget::new(1 << 10)
}

pub(super) fn handoff<'s>(
    storage: &'s Storage<TestPlatform>,
    body: &[u8],
) -> (Resident<'s, TestPlatform>, ExtentLease<'s, TestPlatform>) {
    let mut allocation = storage
        .reserve(Some(4), Some(body.len()), &mut budget())
        .unwrap();
    allocation.mark_written();
    allocation
        .complete([0x42; 32], u64::MAX, &mut budget())
        .ok()
        .unwrap()
        .handoff(&mut budget())
        .ok()
        .unwrap()
}

pub(super) fn refs(storage: &Storage<TestPlatform>, slot: usize) -> usize {
    storage.live_pool().unwrap().refs(slot)
}

pub(super) fn retire_era(storage: &Storage<TestPlatform>, slot: usize) -> u64 {
    storage.live_pool().unwrap().retire_era(slot)
}

pub(super) fn era(storage: &Storage<TestPlatform>) -> u64 {
    storage.era_report().unwrap().era
}

pub(super) fn certified(storage: &Storage<TestPlatform>) -> u64 {
    storage.era_report().unwrap().certified
}

pub(super) fn pinned(storage: &Storage<TestPlatform>, index: RegistrationIndex) -> Option<u64> {
    storage.registration_report(index).unwrap().pinned_era
}

/// One certification call funded to complete any pass it begins.
pub(super) fn certify(storage: &Storage<TestPlatform>) -> CertifyReport {
    storage.certify(&mut WorkBudget::new(400)).unwrap()
}

pub(super) fn service(storage: &Storage<TestPlatform>) -> super::release::ServiceReport {
    storage.service(&mut WorkBudget::new(400)).unwrap()
}

/// The grace cursor as the last certification call left it.
pub(super) fn cursor(storage: &Storage<TestPlatform>) -> PassCursor {
    storage.grace_cursor().load()
}

/// A reader pinned before the retirement of an object it could have observed
/// blocks that object's anchor through any number of passes: the slot is
/// held, its count unchanged, the reader named by its record; once the
/// reader unpins, one complete pass certifies and the next service releases
/// exactly one anchor and returns the block. The log written here is the
/// witness: `retire_era < certified` first holds after the pin cleared.
#[test]
fn a_reader_pinned_before_retirement_blocks_release_until_it_unpins() {
    let storage = storage(SLOTS, 2);
    let (resident, lease) = handoff(&storage, &[7; 20]);
    let slot = resident.id().slot_index();
    drop(lease);
    let pinned_at = Barrier::new(2);
    let resume = Barrier::new(2);
    let index = std::sync::atomic::AtomicUsize::new(usize::MAX);
    // (event, era, pin, refs, certified)
    let mut log: Vec<(&str, u64, Option<u64>, usize, u64)> = Vec::new();
    std::thread::scope(|scope| {
        let shared = &storage;
        let (pinned_at, resume, index) = (&pinned_at, &resume, &index);
        scope.spawn(move || {
            let mut registration = shared.register().unwrap();
            index.store(registration.index().0, Ordering::Release);
            let protected = registration.enter().unwrap();
            assert_eq!(protected.era(), ERA_FIRST);
            pinned_at.wait();
            resume.wait();
            protected.exit();
            pinned_at.wait();
        });
        pinned_at.wait();
        let index = RegistrationIndex(index.load(Ordering::Acquire));
        let mut record = |event: &'static str| {
            log.push((
                event,
                era(shared),
                pinned(shared, index),
                refs(shared, slot),
                certified(shared),
            ));
        };
        record("pinned");
        assert_eq!(resident.retire(), RetireOutcome::Recorded);
        record("retired");
        assert_eq!(retire_era(shared, slot), ERA_FIRST);
        for pass in 0..3 {
            let report = certify(shared);
            assert_eq!(report.certified, Some(ERA_FIRST), "{pass}");
            let pass_report = service(shared);
            assert_eq!(
                (pass_report.held, pass_report.released, pass_report.serviced),
                (1, 0, 0),
                "{pass}"
            );
            record("pass while pinned");
        }
        assert_eq!(
            shared.outstanding(),
            Outstanding {
                pending: 1,
                anchored: 1,
                registrations: 1,
                ..Outstanding::default()
            }
        );
        assert_eq!(
            shared.slot_state(super::SlotIndex(slot)).unwrap().0,
            SlotState::Retired
        );
        resume.wait();
        pinned_at.wait();
        record("unpinned");
        let report = certify(shared);
        assert_eq!(report.certified, Some(ERA_FIRST + 1));
        record("pass after unpin");
        let pass_report = service(shared);
        assert_eq!(
            (pass_report.held, pass_report.released, pass_report.serviced),
            (0, 1, 1)
        );
        record("serviced");
    });
    // Independent witness: one bump for the one retirement, the pin equal
    // to the era before it until the reader unpins, `retire_era < certified`
    // only after the pin cleared, and `refs` falling only at the final
    // service.
    let retired_at = ERA_FIRST;
    let expected: [(&str, u64, Option<u64>, usize, u64); 8] = [
        ("pinned", ERA_FIRST, Some(ERA_FIRST), 1, 0),
        ("retired", ERA_FIRST + 1, Some(ERA_FIRST), 1, 0),
        (
            "pass while pinned",
            ERA_FIRST + 1,
            Some(ERA_FIRST),
            1,
            ERA_FIRST,
        ),
        (
            "pass while pinned",
            ERA_FIRST + 1,
            Some(ERA_FIRST),
            1,
            ERA_FIRST,
        ),
        (
            "pass while pinned",
            ERA_FIRST + 1,
            Some(ERA_FIRST),
            1,
            ERA_FIRST,
        ),
        ("unpinned", ERA_FIRST + 1, None, 1, ERA_FIRST),
        ("pass after unpin", ERA_FIRST + 1, None, 1, ERA_FIRST + 1),
        ("serviced", ERA_FIRST + 1, None, 0, ERA_FIRST + 1),
    ];
    assert_eq!(log, expected);
    for (event, _, _, _, certified) in &log {
        assert_eq!(
            retired_at < *certified,
            matches!(*event, "pass after unpin" | "serviced"),
            "{event}"
        );
    }
    assert_eq!(log.last().unwrap().3, 0);
    assert_eq!(
        storage.slot_state(super::SlotIndex(slot)).unwrap().0,
        SlotState::Free
    );
    assert!(storage.outstanding().is_clear());
}

/// A leaked pin stalls reclamation in its domain for good while memory stays
/// bounded: admission still refuses at capacity, the engine charge does not
/// move, and teardown refuses naming the registration.
#[test]
fn a_leaked_pin_stalls_reclamation_and_teardown_names_the_reader() {
    let mut storage = storage(SLOTS, 1);
    let used = storage.engine_used();
    let (resident, lease) = handoff(&storage, &[3; 20]);
    let slot = resident.id().slot_index();
    drop(lease);
    let mut registration = storage.register().unwrap();
    let index = registration.index();
    let protected = registration.enter().unwrap();
    let pin = protected.era();
    std::mem::forget(protected);
    std::mem::forget(registration);
    assert_eq!(resident.retire(), RetireOutcome::Recorded);
    assert_eq!(retire_era(&storage, slot), pin);
    for _ in 0..2 {
        assert_eq!(certify(&storage).certified, Some(pin));
        assert_eq!(service(&storage).held, 1);
    }
    assert_eq!(refs(&storage, slot), 1);
    // Bounded: the remaining slots fill and the next reservation refuses.
    // The fixture's volume has one unit per slot plus the clean reserve, so
    // the reserve check, which runs first, refuses once every slot is held.
    let mut owners = Vec::with_capacity(SLOTS);
    while let Ok(owner) = storage.reserve(Some(1), Some(1), &mut budget()) {
        owners.push(owner);
    }
    assert_eq!(owners.len(), SLOTS - 1);
    assert_eq!(
        storage.reserve(Some(1), Some(1), &mut budget()).err(),
        Some(ReserveError::CleanReserve)
    );
    for owner in owners {
        owner.cancel().unwrap();
    }
    assert_eq!(storage.engine_used(), used);
    assert_eq!(pinned(&storage, index), Some(pin));
    let blockers = blocked(&mut storage);
    assert_eq!(
        (blockers.registrations, blockers.leases),
        (1, 0),
        "{blockers:?}"
    );
    assert!(blockers.pending >= 1, "{blockers:?}");
}

/// A reader pinned after a retirement, or after a pass loaded its start era,
/// never blocks that retirement's certification; one pinned before it does.
/// Both cases are witnessed by the anchors released in the next service, and
/// every expected era comes from the test's own count of retirements.
#[test]
fn only_readers_pinned_before_a_retirement_block_its_certification() {
    let storage = storage(SLOTS, 2);
    let mut reader = storage.register().unwrap();
    let mut other = storage.register().unwrap();
    // One bump per retirement, counted here.
    let mut retirements = 0u64;
    let now = |retirements: u64| ERA_FIRST + retirements;

    // Pinned before: the pin equals the retirement era, so the bound stays
    // at it and the anchor is held.
    let (before, before_lease) = handoff(&storage, &[1; 20]);
    let before_slot = before.id().slot_index();
    drop(before_lease);
    let protected = reader.enter().unwrap();
    assert_eq!(protected.era(), now(retirements));
    assert_eq!(before.retire(), RetireOutcome::Recorded);
    let before_stamp = now(retirements);
    retirements += 1;
    assert_eq!(retire_era(&storage, before_slot), before_stamp);
    assert_eq!(era(&storage), now(retirements));
    assert_eq!(certify(&storage).certified, Some(before_stamp));
    assert_eq!(
        (service(&storage).held, refs(&storage, before_slot)),
        (1, 1)
    );
    protected.exit();

    // Pinned after: the retirement happened first, so the pin exceeds the
    // stamp and the anchor is released while the reader stays pinned.
    let (after, after_lease) = handoff(&storage, &[2; 20]);
    let after_slot = after.id().slot_index();
    drop(after_lease);
    assert_eq!(after.retire(), RetireOutcome::Recorded);
    let after_stamp = now(retirements);
    retirements += 1;
    assert_eq!(retire_era(&storage, after_slot), after_stamp);
    let protected = reader.enter().unwrap();
    assert_eq!(protected.era(), now(retirements));
    assert_eq!(certify(&storage).certified, Some(now(retirements)));
    let pass = service(&storage);
    // Both anchors release: the earlier reader has unpinned by now.
    assert_eq!((pass.released, pass.serviced, pass.held), (2, 2, 0));
    protected.exit();

    // Pinned on an unvisited record after the pass loaded its start era but
    // before it completed: the resumed pass still certifies the retirement
    // that preceded its start.
    let (late, late_lease) = handoff(&storage, &[3; 20]);
    let late_slot = late.id().slot_index();
    drop(late_lease);
    assert_eq!(late.retire(), RetireOutcome::Recorded);
    let late_stamp = now(retirements);
    retirements += 1;
    // The controls plus the visit of record 0 only.
    let partial = storage
        .certify(&mut WorkBudget::new(CERTIFY_CONTROLS + 1))
        .unwrap();
    assert_eq!((partial.visited, partial.certified), (1, None));
    assert!(partial.budget_exhausted);
    let protected = other.enter().unwrap();
    assert_eq!(protected.era(), now(retirements));
    let resumed = certify(&storage);
    assert_eq!(
        (resumed.visited, resumed.certified),
        (1, Some(now(retirements)))
    );
    assert!(late_stamp < now(retirements));
    let pass = service(&storage);
    assert_eq!((pass.released, pass.serviced), (1, 1));
    protected.exit();
    assert_eq!(refs(&storage, late_slot), 0);

    // A retirement that lands after the pass began, on a record already
    // visited while unpinned, is bounded by the start era whatever the
    // reader does afterwards: the slot stays held until a fresh pass.
    let (racing, racing_lease) = handoff(&storage, &[4; 20]);
    let racing_slot = racing.id().slot_index();
    drop(racing_lease);
    // The era is certified, and a pass from a certified era is not begun, so
    // an earlier retirement moves it; that slot is released by the resumed
    // pass below.
    let (spare, spare_lease) = handoff(&storage, &[6; 20]);
    drop(spare_lease);
    assert_eq!(spare.retire(), RetireOutcome::Recorded);
    retirements += 1;
    let start = now(retirements);
    let partial = storage
        .certify(&mut WorkBudget::new(CERTIFY_CONTROLS + 1))
        .unwrap();
    assert_eq!((partial.visited, partial.certified), (1, None));
    let protected = reader.enter().unwrap();
    assert_eq!(protected.era(), start);
    assert_eq!(racing.retire(), RetireOutcome::Recorded);
    assert_eq!(retire_era(&storage, racing_slot), start);
    retirements += 1;
    protected.exit();
    let resumed = certify(&storage);
    assert_eq!(resumed.certified, Some(start));
    let pass = service(&storage);
    assert_eq!((pass.serviced, pass.held), (1, 1));
    assert_eq!(certify(&storage).certified, Some(now(retirements)));
    assert_eq!(service(&storage).serviced, 1);
}

/// A pin seen on a record before the pass is interrupted stays in the bound
/// the resumed pass certifies, so an anchor retired before that pin is held
/// even though the reader unpinned before the resume; a resume that forgot
/// the minimum would release it.
#[test]
fn an_interrupted_pass_keeps_the_minimum_pin_it_saw() {
    let storage = storage(SLOTS, 2);
    let mut early = storage.register().unwrap();
    let (resident, lease) = handoff(&storage, &[5; 20]);
    let slot = resident.id().slot_index();
    drop(lease);
    // Pinned at the era the object will retire at.
    let protected = early.enter().unwrap();
    let pinned = protected.era();
    assert_eq!(resident.retire(), RetireOutcome::Recorded);
    assert_eq!(retire_era(&storage, slot), pinned);
    // The controls plus the visit of record 0, which is the pinned one.
    let partial = storage
        .certify(&mut WorkBudget::new(CERTIFY_CONTROLS + 1))
        .unwrap();
    assert_eq!((partial.visited, partial.certified), (1, None));
    let interrupted = cursor(&storage);
    assert_eq!(
        (
            interrupted.start_era,
            interrupted.min_pin(),
            interrupted.next
        ),
        (pinned + 1, pinned, 1)
    );
    // The reader unpins before the pass resumes; the record now reads
    // inactive, and only the carried minimum can hold the anchor.
    protected.exit();
    let resumed = certify(&storage);
    assert_eq!((resumed.visited, resumed.certified), (1, Some(pinned)));
    let pass = service(&storage);
    assert_eq!((pass.held, pass.released), (1, 0));
    assert_eq!(refs(&storage, slot), 1);
    assert_eq!(certify(&storage).certified, Some(pinned + 1));
    assert_eq!(service(&storage).serviced, 1);
}

/// With no registration records the pass completes on its first call, so
/// every retirement is certified by the next pass and teardown drains.
#[test]
fn zero_records_certify_on_the_first_call_and_drain() {
    let mut storage = storage(SLOTS, 0);
    let (resident, lease) = handoff(&storage, &[6; 20]);
    drop(lease);
    assert_eq!(resident.retire(), RetireOutcome::Recorded);
    // With no record the minimum is the controls alone; one step fewer is
    // refused with nothing debited.
    assert_eq!(certify_minimum(0), CERTIFY_CONTROLS);
    let mut short = WorkBudget::new(CERTIFY_CONTROLS - 1);
    assert_eq!(
        storage.certify(&mut short),
        Err(ServiceError::BudgetExhausted)
    );
    assert_eq!(short.remaining(), CERTIFY_CONTROLS - 1);
    let mut spent = WorkBudget::new(CERTIFY_CONTROLS);
    assert_eq!(
        storage.certify(&mut spent),
        Ok(CertifyReport {
            visited: 0,
            certified: Some(ERA_FIRST + 1),
            budget_exhausted: false,
        })
    );
    assert_eq!(spent.counters().visits, 0);
    assert_eq!(spent.remaining(), 0);
    assert_eq!(spent.counters().coordination_attempts, 1);
    let pass = service(&storage);
    assert_eq!((pass.released, pass.serviced), (1, 1));
    assert_eq!(finalize(&mut storage), Ok(Finalization::Drained));
}

/// A pass interrupted at every record boundary resumes from its cursor with
/// the start era it loaded first, charges exactly one visit per record per
/// pass, certifies only on completion, and a zero budget visits nothing.
#[test]
fn an_interrupted_pass_resumes_from_its_cursor_and_certifies_only_on_completion() {
    const R: usize = 4;
    let storage = storage(SLOTS, R);
    let live = storage.live_pool().unwrap();
    let tries = live.telemetry().failed_tries.load(Ordering::Relaxed);

    // Below the minimum, the controls plus one visit, nothing is tried
    // either; the minimum begins the pass, loading its start era, and visits
    // record 0.
    for short in 1..certify_minimum(R) {
        let mut spent = WorkBudget::new(short);
        assert_eq!(
            storage.certify(&mut spent),
            Err(ServiceError::BudgetExhausted)
        );
        assert_eq!(spent.remaining(), short);
    }
    assert_eq!(cursor(&storage), PassCursor::IDLE);
    assert_eq!(live.telemetry().failed_tries.load(Ordering::Relaxed), tries);
    let start = era(&storage);
    let mut minimum = WorkBudget::new(certify_minimum(R));
    let report = storage.certify(&mut minimum).unwrap();
    assert_eq!(
        report,
        CertifyReport {
            visited: 1,
            certified: None,
            budget_exhausted: true,
        }
    );
    assert_eq!(minimum.remaining(), 0);
    assert_eq!(
        (
            minimum.counters().coordination_attempts,
            minimum.counters().updates,
            minimum.counters().visits
        ),
        (1, CERTIFY_CONTROLS - 1, 1)
    );
    let begun = cursor(&storage);
    assert_eq!((begun.start_era, begun.next), (start, 1));
    assert!(begun.in_progress());

    // A retirement between calls moves the era; the resumed pass keeps the
    // start era it loaded, so the retired object is not certified by it.
    let (resident, lease) = handoff(&storage, &[5; 20]);
    let slot = resident.id().slot_index();
    drop(lease);
    assert_eq!(resident.retire(), RetireOutcome::Recorded);
    assert_eq!(retire_era(&storage, slot), start);

    let mut visits = 1;
    for record in 1..R {
        let mut two = WorkBudget::new(CERTIFY_CONTROLS + 1);
        let report = storage.certify(&mut two).unwrap();
        visits += two.counters().visits;
        assert_eq!(report.visited, 1, "{record}");
        assert_eq!(two.counters().coordination_attempts, 1);
        if record + 1 < R {
            assert_eq!(report.certified, None, "{record}");
            assert!(report.budget_exhausted);
            let resumed = cursor(&storage);
            assert_eq!((resumed.start_era, resumed.next), (start, record + 1));
            assert_eq!(certified(&storage), 0);
        } else {
            assert_eq!(report.certified, Some(start));
            assert!(!report.budget_exhausted);
            assert_eq!(cursor(&storage), PassCursor::IDLE);
        }
    }
    assert_eq!(visits, R);
    assert_eq!(certified(&storage), start);
    assert_eq!(service(&storage).held, 1);

    // A fresh pass loads the moved era and certifies past the retirement.
    let mut spent = WorkBudget::new(CERTIFY_CONTROLS + R);
    let report = storage.certify(&mut spent).unwrap();
    assert_eq!(report.certified, Some(start + 1));
    assert_eq!(spent.counters().visits, R);
    assert_eq!(spent.remaining(), 0);
    assert_eq!(service(&storage).serviced, 1);
    assert_eq!(live.telemetry().failed_tries.load(Ordering::Relaxed), tries);

    // A contended maintenance gate refuses a pass in progress without moving
    // its cursor, charging the one attempt and nothing else, and so does an
    // exhausted budget; a held pool gate refuses nothing. The era is
    // certified, so a retirement moves it for the pass to begin.
    let (resident, lease) = handoff(&storage, &[7; 20]);
    drop(lease);
    assert_eq!(resident.retire(), RetireOutcome::Recorded);
    let partial = storage
        .certify(&mut WorkBudget::new(CERTIFY_CONTROLS + 2))
        .unwrap();
    assert_eq!((partial.visited, partial.certified), (2, None));
    let in_progress = cursor(&storage);
    assert_eq!(in_progress.next, 2);
    let held = storage.maintenance_gate().try_lock().unwrap();
    let mut busy = WorkBudget::new(CERTIFY_CONTROLS + 8);
    assert_eq!(
        storage.certify(&mut busy),
        Err(ServiceError::Gate(super::GateError::Contended))
    );
    assert_eq!(busy.remaining(), CERTIFY_CONTROLS + 8 - 1);
    assert_eq!(busy.counters().coordination_attempts, 1);
    drop(held);
    assert_eq!(cursor(&storage), in_progress);
    assert_eq!(
        storage.certify(&mut WorkBudget::new(0)),
        Err(ServiceError::BudgetExhausted)
    );
    assert_eq!(cursor(&storage), in_progress);
    let pool_held = live.lock().unwrap();
    assert_eq!(certify(&storage).visited, R - 2);
    drop(pool_held);
    assert_eq!(cursor(&storage), PassCursor::IDLE);
    assert_eq!(live.telemetry().failed_tries.load(Ordering::Relaxed), tries);
}

/// The bump that reaches the terminal era poisons admission; pins are then
/// refused with `Contended`, existing pins and leases survive, retirement
/// and certification still run, and nothing wraps.
#[test]
fn the_terminal_era_poisons_admission_and_keeps_existing_pins_and_leases() {
    let storage = storage(SLOTS, 2);
    let mut reader = storage.register().unwrap();
    let mut late = storage.register().unwrap();
    let (first, first_lease) = handoff(&storage, &[8; 20]);
    let first_slot = first.id().slot_index();
    let (second, second_lease) = handoff(&storage, &[9; 20]);
    let second_slot = second.id().slot_index();
    storage.eras().era.store(ERA_TERMINAL - 1, Ordering::SeqCst);
    let protected = reader.enter().unwrap();
    assert_eq!(protected.era(), ERA_TERMINAL - 1);
    assert!(!storage.is_closed());

    assert_eq!(first.retire(), RetireOutcome::Recorded);
    assert_eq!(retire_era(&storage, first_slot), ERA_TERMINAL - 1);
    assert_eq!(era(&storage), ERA_TERMINAL);
    assert!(storage.era_report().unwrap().terminal);
    assert!(storage.is_closed());
    assert_eq!(late.enter().err(), Some(PinError::Contended));
    assert_eq!(storage.register().err(), Some(RegisterError::Closed));
    assert_eq!(
        storage.reserve(Some(1), Some(1), &mut budget()).err(),
        Some(ReserveError::Closed)
    );
    // Existing pin and leases survive.
    assert_eq!(protected.era(), ERA_TERMINAL - 1);
    // The pinned reader still holds the retirement it could have observed.
    assert_eq!(certify(&storage).certified, Some(ERA_TERMINAL - 1));
    drop(first_lease);
    assert_eq!(service(&storage).held, 1);
    // Retirement in the terminal band still stamps and never reports the
    // crossing again; the counter keeps counting up, not around.
    assert_eq!(second.retire(), RetireOutcome::Recorded);
    assert_eq!(retire_era(&storage, second_slot), ERA_TERMINAL);
    assert_eq!(era(&storage), ERA_TERMINAL + 1);
    protected.exit();
    assert_eq!(certify(&storage).certified, Some(ERA_TERMINAL + 1));
    drop(second_lease);
    let pass = service(&storage);
    assert_eq!((pass.released, pass.serviced), (2, 2));
    assert_eq!(refs(&storage, first_slot) + refs(&storage, second_slot), 0);
}

/// Register, pin, unpin, retire, one certification visit and one service
/// visit allocate nothing after initialization; registration and pins take
/// no gate at all, so they succeed while the pool gate is held elsewhere and
/// count no failed try; the flags record the anchor's wait for grace.
#[test]
fn registration_pins_retirement_and_maintenance_visits_allocate_nothing() {
    let storage = storage(SLOTS, 1);
    let live = storage.live_pool().unwrap();
    let (resident, lease) = handoff(&storage, &[6; 20]);
    let slot = resident.id().slot_index();
    drop(lease);
    let allocations = crate::instrument::allocations();
    let tries = live.telemetry().failed_tries.load(Ordering::Relaxed);
    {
        let held = live.lock().unwrap();
        let mut registration = storage.register().unwrap();
        let index = registration.index();
        let protected = registration.enter().unwrap();
        assert_eq!(pinned(&storage, index), Some(protected.era()));
        protected.exit();
        assert_eq!(pinned(&storage, index), None);
        drop(registration);
        assert!(!storage.registration_report(index).unwrap().claimed);
        drop(held);
    }
    assert_eq!(live.telemetry().failed_tries.load(Ordering::Relaxed), tries);
    let mut registration = storage.register().unwrap();
    let protected = registration.enter().unwrap();
    protected.exit();
    drop(registration);
    assert_eq!(resident.retire(), RetireOutcome::Recorded);
    assert_eq!(live.flags(slot), ABANDONED | RETIRED | ANCHORED);
    let report = storage
        .certify(&mut WorkBudget::new(certify_minimum(1)))
        .unwrap();
    assert_eq!(report.visited, 1);
    assert_eq!(report.certified, Some(ERA_FIRST + 1));
    let pass = storage
        .service(&mut WorkBudget::new(storage.service_minimum()))
        .unwrap();
    assert_eq!((pass.released, pass.serviced), (1, 1));
    assert_eq!(live.flags(slot), 0);
    assert_eq!(crate::instrument::allocations(), allocations);
}

/// A guard leaked without ending keeps its pin: the registration refuses
/// further intervals rather than raise the pin, the leaked pin holds every
/// later retirement, and dropping the registration clears the record so a
/// fresh one pins again.
#[test]
fn a_leaked_guard_keeps_its_pin_and_refuses_the_next_interval() {
    let storage = storage(SLOTS, 1);
    let mut registration = storage.register().unwrap();
    let index = registration.index();
    let leaked = registration.enter().unwrap();
    let pin = leaked.era();
    std::mem::forget(leaked);
    assert_eq!(registration.enter().err(), Some(PinError::Leaked));
    assert_eq!(pinned(&storage, index), Some(pin));
    let (resident, lease) = handoff(&storage, &[7; 20]);
    let slot = resident.id().slot_index();
    drop(lease);
    assert_eq!(resident.retire(), RetireOutcome::Recorded);
    assert_eq!(certify(&storage).certified, Some(pin));
    assert_eq!(service(&storage).held, 1);
    drop(registration);
    assert_eq!(pinned(&storage, index), None);
    let mut again = storage.register().unwrap();
    assert_eq!(again.enter().unwrap().era(), pin + 1);
    assert_eq!(certify(&storage).certified, Some(pin + 1));
    assert_eq!(service(&storage).serviced, 1);
    assert_eq!(refs(&storage, slot), 0);
}

/// Runs service over one retired, anchored record whose grace has passed and
/// whose word is edited to carry the state `encoding`, with `leases` rights
/// beside the anchor, and returns the word before the call, the word after
/// it and the panic's message, or `None` when service returned.
fn service_of_a_retired_state(encoding: u64, leases: usize) -> (u64, u64, Option<String>) {
    let storage = storage(SLOTS, 1);
    let live = storage.live_pool().unwrap();
    let (resident, lease) = handoff(&storage, &[6; 20]);
    let slot = resident.id().slot_index();
    let kept = (leases == 1).then_some(lease);
    assert_eq!(resident.retire(), RetireOutcome::Recorded);
    assert_eq!(live.flags(slot), ABANDONED | RETIRED | ANCHORED);
    assert_eq!(certify(&storage).certified, Some(ERA_FIRST + 1));
    live.edit_word(slot, |word| word & !super::word::STATE | encoding << 36);
    let before = live.word(slot);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        storage
            .service(&mut WorkBudget::new(storage.service_minimum()))
            .unwrap()
    }));
    let after = live.word(slot);
    let message = outcome.err().map(|payload| {
        payload
            .downcast_ref::<&str>()
            .map(|message| (*message).to_owned())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap()
    });
    if message.is_some() {
        assert!(matches!(
            live.try_lock_quiet().err(),
            Some(super::gate::GateError::Poisoned)
        ));
    }
    std::mem::forget(kept);
    (before, after, message)
}

/// Service's sighting of a retired, anchored member whose word carries a
/// state encoding past `Quarantined` panics and poisons the gate before
/// any step runs on the word: the word is as the sighting found it.
#[test]
fn an_unknown_state_on_a_retired_anchor_poisons_service_with_the_word_untouched() {
    let retired = SlotState::Retired.bits() >> 36;
    let mut changed = Vec::new();
    for leases in [0, 1] {
        let (before, after, message) = service_of_a_retired_state(retired, leases);
        assert_eq!(message, None, "{leases}");
        assert_ne!(before, after, "the sibling releases its anchor");
        for encoding in [5, 6, 7] {
            let (before, after, message) = service_of_a_retired_state(encoding, leases);
            let message = message.expect("service returned over an unknown state");
            assert!(message.contains("unknown state"), "{message}");
            if before != after {
                changed.push((encoding, leases, before, after));
            }
        }
    }
    assert_eq!(
        changed,
        [],
        "a step ran on a word with an unknown state: (encoding, leases, word before, word after)"
    );
}
