//! Certification, terminal retirement, the in-gate allocation recheck and
//! the prepaid maintenance bundles against live storage, with the
//! test-only primitive observer as the independent ledger.
//!
//! Every expected era, pin, count and step below comes from the test's own
//! record of what it did and from the observer's log; the state-preservation
//! cases also compare production reports before and after the refused
//! operation.

use std::sync::atomic::{AtomicBool, Ordering};

use super::budget::{WorkBudget, WorkCounters};
use super::config::StorageConfig;
use super::gate::GateError;
use super::grace::{ERA_FIRST, ERA_TERMINAL, INACTIVE, PassCursor};
use super::grace_tests::{
    SLOTS, certified, certify, cursor, era, handoff, refs, retire_era, service, storage,
};
use super::lease::INTERPOSE_BEFORE_TERMINAL_CLOSE;
use super::probe::{self, Event};
use super::release::{
    CERTIFY_CONTROLS, CertifyReport, PARKED_PROBE, RETIRED_PROBE, SERVICE_CONTROLS,
    SERVICE_MINIMUM, SERVICE_PER_SLOT, ServiceError, ServiceReport, certify_minimum,
};
use super::reserve::INTERPOSE_AFTER_OPEN_READ;
use super::word::{ABANDONED, ANCHORED, RETIRED};
use super::{RegisterError, ReserveError, RetireOutcome};

/// Runs `call` with the observer armed on this thread and returns its
/// events with the primitive counts it recorded.
fn observed<R>(call: impl FnOnce() -> R) -> (R, Vec<Event>, probe::Counts) {
    probe::arm();
    let result = call();
    probe::disarm();
    let log = probe::events();
    assert!(!log.overflowed, "the event log overflowed");
    (result, log.events, probe::counts())
}

/// What one pass log must show: the start sampled once before visit 0, one
/// visit per index in order, and the publication equal to
/// `max(previous, min(start, minimum nonzero pin))`.
fn check_pass_log(events: &[Event], records: usize, previous: u64) -> u64 {
    let mut visits = Vec::new();
    let mut start = None;
    let mut published = None;
    for event in events {
        match *event {
            Event::CertifyStart { era } => {
                assert!(start.is_none(), "start sampled twice: {events:?}");
                assert!(visits.is_empty(), "start after a visit: {events:?}");
                start = Some(era);
            }
            Event::CertifyVisit { index, pin } => {
                assert!(start.is_some(), "visit before start: {events:?}");
                visits.push((index, pin));
            }
            Event::CertifyPublish { bound, certified } => {
                assert!(published.is_none(), "published twice: {events:?}");
                published = Some((bound, certified));
            }
            Event::AnchorRelease { .. }
            | Event::Return { .. }
            | Event::ExtentReturn { .. }
            | Event::Inhibit { .. }
            | Event::Cutoff { .. }
            | Event::Sampled { .. }
            | Event::Cleared { .. }
            | Event::Revoked { .. }
            | Event::Committed { .. }
            | Event::Parked { .. }
            | Event::Detached { .. }
            | Event::Sighted { .. }
            | Event::Absent { .. }
            | Event::StaleMark { .. } => {}
        }
    }
    let start = start.expect("a start");
    assert_eq!(
        visits.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
        (0..records).collect::<Vec<_>>(),
        "{events:?}"
    );
    let minimum = visits
        .iter()
        .map(|(_, pin)| *pin)
        .filter(|pin| *pin != INACTIVE)
        .min()
        .unwrap_or(u64::MAX);
    let expected = start.min(minimum);
    let (bound, certified) = published.expect("a publication");
    assert_eq!(bound, expected, "{events:?}");
    assert_eq!(certified, previous.max(expected), "{events:?}");
    certified
}

/// An independent pass log for every split of the pass at every cursor
/// position, with the second half run by another collector thread: the
/// start is sampled once before visit 0, every index 0..R-1 is visited
/// once in order, the publication is `max(old, min(start, minimum nonzero
/// pin))`, an incomplete pass publishes nothing, and the certificate never
/// decreases. A pin taken between the halves on a record already visited
/// does not lower the bound; one taken on a record still to visit does.
/// A registration dropped and reclaimed between the halves reuses its
/// record without disturbing the pass.
#[test]
fn every_split_of_a_pass_logs_one_start_every_record_and_the_exact_bound() {
    const R: usize = 4;
    let storage = storage(SLOTS, R);
    let mut reader_zero = storage.register().unwrap();
    let mut reader_one = storage.register().unwrap();
    let reader_two = storage.register().unwrap();
    let mut reader_three = storage.register().unwrap();
    assert_eq!(reader_zero.index().0, 0);
    let mut previous = 0;
    // The minimum funds one visit, so the smallest first half is one record;
    // the largest leaves one record for the second collector.
    for split in 1..R {
        // Pin record 3 strictly below the round's start, then move the era
        // with a retirement so the pass samples a higher start; the low pin
        // is the bound the pass must carry, and record 3 is always in the
        // second collector's half.
        let pin_three = reader_three.enter().unwrap();
        let pinned_three = pin_three.era();
        let (resident, lease) = handoff(&storage, &[split as u8; 20]);
        drop(lease);
        assert_eq!(resident.retire(), RetireOutcome::Recorded);
        let start = era(&storage);
        assert!(pinned_three < start);
        let pin_one = reader_one.enter().unwrap();
        let pinned_one = pin_one.era();
        assert_eq!(pinned_one, start);

        let (first, first_events, _) = observed(|| {
            storage
                .certify(&mut WorkBudget::new(CERTIFY_CONTROLS + split))
                .unwrap()
        });
        assert_eq!(first.visited, split);
        assert_eq!(first.certified, None);
        assert!(first.budget_exhausted);
        assert!(
            !first_events
                .iter()
                .any(|event| matches!(event, Event::CertifyPublish { .. })),
            "an incomplete pass published: {first_events:?}"
        );
        assert_eq!(certified(&storage), previous);

        // Between the halves: record 0, already visited, is dropped,
        // reclaimed and pinned again; the second half must not count that
        // pin, and record 3's low pin is still ahead of the cursor.
        drop(reader_zero);
        reader_zero = storage.register().unwrap();
        assert_eq!(reader_zero.index().0, 0);
        let pin_zero = reader_zero.enter().unwrap();
        assert_eq!(pin_zero.era(), start);

        let second_events = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let (second, events, _) = observed(|| certify(&storage));
                    assert_eq!(second.visited, R - split);
                    assert!(!second.budget_exhausted);
                    events
                })
                .join()
                .unwrap()
        });
        let mut events = first_events;
        events.extend(second_events);
        let published = check_pass_log(&events, R, previous);
        assert_eq!(published, certified(&storage));
        assert!(published >= previous);
        // The bound the test computes on its own from what it pinned: the
        // low pin on record 3, carried across the collector handoff.
        let expected = pinned_three.min(pinned_one).min(start);
        assert_eq!(expected, pinned_three);
        assert_eq!(published, previous.max(expected));
        previous = published;
        drop(pin_zero);
        drop(pin_one);
        drop(pin_three);
        assert_eq!(cursor(&storage), PassCursor::IDLE);
    }
    // A full-budget call visits every record and publishes; a pin taken
    // after that cannot lower a bound already published.
    let (resident, lease) = handoff(&storage, &[0xAA; 20]);
    drop(lease);
    assert_eq!(resident.retire(), RetireOutcome::Recorded);
    let start = era(&storage);
    let (first, first_events, _) = observed(|| {
        storage
            .certify(&mut WorkBudget::new(CERTIFY_CONTROLS + R))
            .unwrap()
    });
    assert_eq!(first.visited, R);
    // Every record visited: the pass is complete and published on its own.
    let published = check_pass_log(&first_events, R, previous);
    assert_eq!(first.certified, Some(published));
    assert_eq!(published, start);
    previous = published;
    let late = reader_three.enter().unwrap();
    assert_eq!(late.era(), start);
    drop(late);
    drop((reader_zero, reader_one, reader_two, reader_three));
    // With every pin gone a complete pass certifies the start era. The last
    // pass certified the era and a pass from a certified era is not begun,
    // so the era is moved first, as a retirement's bump would move it.
    let moved = storage.eras().era.fetch_add(1, Ordering::SeqCst) + 1;
    let (report, events, _) = observed(|| certify(&storage));
    assert_eq!(report.certified, Some(check_pass_log(&events, R, previous)));
    assert_eq!(report.certified, Some(moved));
}

/// Zero records: the pass completes on its first funded call with one start
/// and no visit, and a busy or poisoned gate publishes nothing. The
/// poisoned maintenance gate closes admission; it is not the pool gate, so
/// the volume still serves and a storage with nothing outstanding still
/// tears down.
#[test]
fn zero_records_busy_and_poisoned_gates_publish_only_from_a_complete_pass() {
    let mut storage = storage(SLOTS, 0);
    let (report, events, counts) = observed(|| {
        storage
            .certify(&mut WorkBudget::new(certify_minimum(0)))
            .unwrap()
    });
    assert_eq!(report.visited, 0);
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], Event::CertifyStart { era: ERA_FIRST }));
    assert!(matches!(
        events[1],
        Event::CertifyPublish {
            bound: ERA_FIRST,
            certified: ERA_FIRST
        }
    ));
    assert_eq!(counts.gate_taken, 1);
    assert_eq!(counts.gate_attempts(), 1);

    // Busy: the attempt is charged and observed, nothing else happens.
    let held = storage.maintenance_gate().try_lock().unwrap();
    let (busy, events, counts) = observed(|| {
        let mut spent = WorkBudget::new(64);
        let outcome = storage.certify(&mut spent);
        (outcome, spent)
    });
    assert_eq!(busy.0, Err(ServiceError::Gate(GateError::Contended)));
    assert_eq!(busy.1.counters().coordination_attempts, 1);
    assert_eq!(busy.1.remaining(), 63);
    assert!(events.is_empty());
    assert_eq!((counts.gate_busy, counts.gate_attempts()), (1, 1));
    assert!(!storage.is_closed());
    drop(held);

    // Poisoned: the attempt is charged and observed, admission closes and
    // no repair runs; the volume's own gate is untouched.
    std::thread::scope(|scope| {
        let handle = scope.spawn(|| {
            let _held = storage.maintenance_gate().try_lock().unwrap();
            panic!("poison the maintenance gate");
        });
        assert!(handle.join().is_err());
    });
    let (poisoned, events, counts) = observed(|| {
        let mut spent = WorkBudget::new(64);
        let outcome = storage.certify(&mut spent);
        (outcome, spent)
    });
    assert_eq!(poisoned.0, Err(ServiceError::Gate(GateError::Poisoned)));
    assert_eq!(poisoned.1.counters().coordination_attempts, 1);
    assert!(events.is_empty());
    assert_eq!((counts.gate_poisoned, counts.gate_attempts()), (1, 1));
    assert!(storage.is_closed());
    assert_eq!(storage.register().err(), Some(RegisterError::Closed));
    assert!(storage.service(&mut WorkBudget::new(64)).is_ok());
    assert!(!storage.outstanding().unverifiable);
    assert_eq!(
        super::test_platform::finalize(&mut storage),
        Ok(super::finalize::Finalization::Drained)
    );
}

/// A poisoned pool gate refuses service with the attempt charged and leaves
/// admission open: the volume is reported unverifiable and blocks teardown,
/// but only the maintenance gate's poison, found by certification, closes
/// the cache.
#[test]
fn a_poisoned_pool_gate_refuses_service_without_closing_admission() {
    let config = StorageConfig {
        page_size: 4096,
        engine_budget: 1 << 24,
        body_cap: 200,
        metadata_cap: Some(16),
        lease_limit: 16,
        object_rights: 8,
        reader_limit: 1,
        volume: crate::storage::test_volume(5 * crate::storage::IO_UNIT, 4),
    };
    let placement = super::PlacementConfig { control_home: 0 };
    let mut storage = super::Storage::initialize(
        &config.validate().unwrap(),
        &placement,
        super::test_platform::TestPlatform::heap(4096),
    )
    .unwrap();
    std::thread::scope(|scope| {
        let handle = scope.spawn(|| {
            let _held = storage.live_pool().unwrap().lock().unwrap();
            panic!("poison the volume's gate");
        });
        assert!(handle.join().is_err());
    });
    let (outcome, events, counts) = observed(|| {
        let mut spent = WorkBudget::new(64);
        (storage.service(&mut spent), spent)
    });
    assert_eq!(outcome.0, Err(ServiceError::Gate(GateError::Poisoned)));
    assert_eq!(outcome.1.counters().coordination_attempts, 1);
    assert_eq!(outcome.1.remaining(), 63);
    assert!(events.is_empty());
    assert_eq!((counts.gate_poisoned, counts.gate_attempts()), (1, 1));
    assert!(!storage.is_closed());
    // Certification still runs; the poisoned volume keeps teardown refused.
    assert!(certify(&storage).certified.is_some());
    assert!(!storage.is_closed());
    assert!(storage.outstanding().unverifiable);
    assert!(matches!(
        super::test_platform::finalize(&mut storage),
        Err(super::FinalizeError::Poisoned)
    ));
}

/// Certify at budgets 0, 1, minimum-1, minimum and a large one: below the
/// minimum nothing is tried, visited or moved and nothing is debited; the
/// minimum advances exactly one record; observed steps by kind never exceed
/// the charged allowance, and a busy gate is charged one attempt.
#[test]
fn certify_budget_edges_and_observed_steps_stay_within_the_charge() {
    const R: usize = 3;
    let storage = storage(SLOTS, R);
    let minimum = certify_minimum(R);
    for short in [0, 1, minimum - 1] {
        let (outcome, events, counts) = observed(|| {
            let mut spent = WorkBudget::new(short);
            (storage.certify(&mut spent), spent)
        });
        assert_eq!(outcome.0, Err(ServiceError::BudgetExhausted), "{short}");
        assert_eq!(outcome.1.remaining(), short);
        assert_eq!(outcome.1.counters(), WorkCounters::default());
        assert!(events.is_empty());
        assert_eq!(counts, probe::Counts::default(), "{short}");
        assert_eq!(cursor(&storage), PassCursor::IDLE);
    }
    let (outcome, events, counts) = observed(|| {
        let mut spent = WorkBudget::new(minimum);
        (storage.certify(&mut spent), spent)
    });
    let report = outcome.0.unwrap();
    assert_eq!(report.visited, 1);
    assert!(report.budget_exhausted);
    assert_eq!(outcome.1.remaining(), 0);
    assert_eq!(cursor(&storage).next, 1);
    // One start load and one visit load against the four controls and one
    // visit charged; one gate attempt against one charged.
    assert_eq!(events.len(), 2);
    let charged = outcome.1.counters();
    assert_eq!(counts.loads, 2);
    assert!(counts.loads <= charged.updates + charged.visits);
    assert_eq!(counts.gate_attempts(), charged.coordination_attempts);
    assert_eq!((counts.rmws, counts.stores), (0, 0));

    let (outcome, events, counts) = observed(|| {
        let mut spent = WorkBudget::new(1 << 10);
        (storage.certify(&mut spent), spent)
    });
    let report = outcome.0.unwrap();
    assert_eq!(report.visited, R - 1);
    assert!(report.certified.is_some());
    let charged = outcome.1.counters();
    assert_eq!(events.len(), R - 1 + 1);
    // One load per resumed visit, one publication read-modify-write.
    assert_eq!((counts.loads, counts.rmws), (R - 1, 1));
    assert!(counts.loads <= charged.updates + charged.visits);
    assert!(counts.rmws <= charged.updates);
    assert_eq!(counts.gate_attempts(), charged.coordination_attempts);
    assert_eq!(charged.coordination_attempts, 1);
    assert_eq!(charged.updates, CERTIFY_CONTROLS - 1);
    assert_eq!(charged.visits, R - 1);

    // The largest allowance behaves like the large one: the pass completes
    // in one call and only its own steps are debited. The era is certified
    // now, so a retirement moves it first; otherwise no pass would begin.
    let (resident, lease) = handoff(&storage, &[7; 20]);
    drop(lease);
    assert_eq!(resident.retire(), RetireOutcome::Recorded);
    let (outcome, _, counts) = observed(|| {
        let mut spent = WorkBudget::new(usize::MAX);
        (storage.certify(&mut spent), spent)
    });
    assert_eq!(outcome.0.unwrap().visited, R);
    assert_eq!(outcome.1.remaining(), usize::MAX - CERTIFY_CONTROLS - R);
    assert_eq!((counts.loads, counts.rmws), (R + 1, 1));

    let held = storage.maintenance_gate().try_lock().unwrap();
    let (outcome, _, counts) = observed(|| {
        let mut spent = WorkBudget::new(1 << 10);
        (storage.certify(&mut spent), spent)
    });
    assert_eq!(outcome.0, Err(ServiceError::Gate(GateError::Contended)));
    assert_eq!(outcome.1.counters().coordination_attempts, 1);
    assert_eq!(outcome.1.counters().updates, 0);
    assert_eq!(counts.gate_busy, 1);
    drop(held);
}

/// A pass covers only the records below the claimed bound: with no record
/// ever claimed it completes on its first call with no visit and certifies
/// its start era, releasing an anchor retired before it; a registration
/// raises the bound for the record it claims, dropping it does not lower
/// the bound, and a pin on a claimed record bounds the next pass again.
#[test]
fn a_pass_visits_only_records_ever_claimed() {
    const R: usize = 4;
    let storage = super::grace_tests::unclaimed_storage(SLOTS, R);
    let (resident, lease) = handoff(&storage, &[5; 20]);
    let slot = resident.id().slot_index();
    drop(lease);
    assert_eq!(resident.retire(), RetireOutcome::Recorded);
    let stamp = retire_era(&storage, slot);
    let mut spent = WorkBudget::new(certify_minimum(R));
    let (report, events, _) = observed(|| storage.certify(&mut spent).unwrap());
    assert_eq!(
        report,
        CertifyReport {
            visited: 0,
            certified: Some(stamp + 1),
            budget_exhausted: false,
        }
    );
    assert_eq!(spent.counters().visits, 0);
    assert_eq!(check_pass_log(&events, 0, 0), stamp + 1);
    let pass = service(&storage);
    assert_eq!((pass.released, pass.serviced), (1, 1));

    // Two registrations raise the bound to two; dropping the second leaves
    // it there, so the next pass visits both records and no more.
    let mut first = storage.register().unwrap();
    let second = storage.register().unwrap();
    assert_eq!((first.index().0, second.index().0), (0, 1));
    drop(second);
    let pin = first.enter().unwrap();
    let pinned = pin.era();
    let (resident, lease) = handoff(&storage, &[6; 20]);
    let slot = resident.id().slot_index();
    drop(lease);
    assert_eq!(resident.retire(), RetireOutcome::Recorded);
    assert_eq!(retire_era(&storage, slot), pinned);
    let (report, events, _) = observed(|| certify(&storage));
    assert_eq!(report.visited, 2);
    assert_eq!(check_pass_log(&events, 2, stamp + 1), pinned);
    assert_eq!(service(&storage).held, 1);
    pin.exit();
    let (report, events, _) = observed(|| certify(&storage));
    assert_eq!(report.visited, 2);
    assert_eq!(check_pass_log(&events, 2, pinned), pinned + 1);
    assert_eq!(service(&storage).serviced, 1);
    drop(first);
}

/// A pass from an era already certified is not begun: the call takes the
/// gate, loads the start era and the certificate, visits no record, logs no
/// pass, debits only its controls and leaves the cursor idle, and reports
/// the certificate. Once a retirement moves the era, the next call begins
/// and completes a pass that certifies past it and releases the anchor.
#[test]
fn a_pass_from_a_certified_era_is_not_begun() {
    const R: usize = 3;
    let storage = storage(SLOTS, R);
    let first = certify(&storage);
    assert_eq!((first.visited, first.certified), (R, Some(ERA_FIRST)));
    assert_eq!(era(&storage), ERA_FIRST);
    for _ in 0..2 {
        let (outcome, events, counts) = observed(|| {
            let mut spent = WorkBudget::new(1 << 10);
            (storage.certify(&mut spent), spent)
        });
        assert_eq!(
            outcome.0,
            Ok(CertifyReport {
                visited: 0,
                certified: Some(ERA_FIRST),
                budget_exhausted: false,
            })
        );
        let charged = outcome.1.counters();
        assert_eq!(
            (
                charged.coordination_attempts,
                charged.updates,
                charged.visits
            ),
            (1, CERTIFY_CONTROLS - 1, 0)
        );
        assert!(events.is_empty());
        assert_eq!((counts.loads, counts.rmws, counts.stores), (1, 0, 0));
        assert_eq!(counts.gate_attempts(), 1);
        assert_eq!(cursor(&storage), PassCursor::IDLE);
        assert_eq!(certified(&storage), ERA_FIRST);
    }
    let (resident, lease) = handoff(&storage, &[3; 20]);
    let slot = resident.id().slot_index();
    drop(lease);
    assert_eq!(resident.retire(), RetireOutcome::Recorded);
    assert_eq!(retire_era(&storage, slot), ERA_FIRST);
    let (report, events, _) = observed(|| certify(&storage));
    assert_eq!(report.visited, R);
    assert_eq!(report.certified, Some(ERA_FIRST + 1));
    assert_eq!(check_pass_log(&events, R, ERA_FIRST), ERA_FIRST + 1);
    let pass = service(&storage);
    assert_eq!((pass.released, pass.serviced), (1, 1));
    assert_eq!(refs(&storage, slot), 0);
}

/// Service at budgets 0, 1, minimum-1, minimum and a large one over a volume
/// with one retired slot: below the minimum nothing is tried, visited or
/// moved; the minimum decides one whole slot; observed steps by kind stay
/// within the prepaid bundles; the anchor release is observed exactly once
/// and never retried.
#[test]
fn service_budget_edges_and_observed_steps_stay_within_the_charge() {
    let storage = storage(SLOTS, 1);
    let (resident, lease) = handoff(&storage, &[9; 20]);
    let slot = resident.id().slot_index();
    drop(lease);
    assert_eq!(resident.retire(), RetireOutcome::Recorded);
    assert!(certify(&storage).certified.is_some());
    let live = storage.live_pool().unwrap();
    let cursor_slot = || {
        let mut access = live.lock().unwrap();
        access.tables().state.cursor_slot
    };
    for short in [0, 1, SERVICE_MINIMUM - 1] {
        let (outcome, events, counts) = observed(|| {
            let mut spent = WorkBudget::new(short);
            (storage.service(&mut spent), spent)
        });
        assert_eq!(outcome.0, Err(ServiceError::BudgetExhausted), "{short}");
        assert_eq!(outcome.1.remaining(), short);
        assert_eq!(outcome.1.counters(), WorkCounters::default());
        assert!(events.is_empty());
        assert_eq!(counts, probe::Counts::default());
        assert_eq!(cursor_slot(), 0);
    }
    // The minimum decides slot 0: retired, eligible, released and returned.
    // With no park counted the retired pass spends the whole allowance:
    // two probes reach slot 0, and after the return the words they read
    // hold no later member, so the pass covers every position and the cursor
    // wraps back to 0. The return debits the visits it counted from the
    // bound it funded.
    super::reserve::take_return_visits();
    let (outcome, events, counts) = observed(|| {
        let mut spent = WorkBudget::new(storage.service_minimum());
        (storage.service(&mut spent), spent)
    });
    let report = outcome.0.unwrap();
    let counted = super::reserve::take_return_visits();
    assert_eq!(
        (
            report.probes,
            report.visited,
            report.released,
            report.serviced,
            report.covered
        ),
        (2, 1, 1, 1, SLOTS)
    );
    assert!(!report.budget_exhausted);
    assert_eq!(
        outcome.1.remaining(),
        storage.service_minimum()
            - SERVICE_CONTROLS
            - 2 * RETIRED_PROBE
            - SERVICE_PER_SLOT
            - counted
    );
    assert_eq!(outcome.1.counters().visits, 2 + 1 + counted);
    assert_eq!(cursor_slot(), 0);
    assert_eq!(
        events,
        [
            Event::AnchorRelease { slot, previous: 1 },
            Event::Return { slot }
        ]
    );
    let charged = outcome.1.counters();
    // Two probes; the anchored and eligibility validations and the count
    // check; the anchor's release exchange and the return's word update.
    assert_eq!((counts.loads, counts.rmws, counts.stores), (2 + 3, 2, 0));
    assert!(counts.loads <= charged.visits + charged.comparisons);
    assert!(counts.rmws + counts.stores <= charged.updates);
    assert_eq!(counts.gate_attempts(), charged.coordination_attempts);
    assert_eq!(refs(&storage, slot), 0);

    // A large budget over a volume with nothing pending: the call pays its
    // controls alone, reads no slot and no summary, and moves no cursor; the
    // anchor is not released again.
    let (outcome, events, counts) = observed(|| {
        let mut spent = WorkBudget::new(1 << 10);
        (storage.service(&mut spent), spent)
    });
    let report = outcome.0.unwrap();
    assert_eq!(
        (
            report.probes,
            report.visited,
            report.released,
            report.serviced
        ),
        (0, 0, 0, 0)
    );
    assert_eq!((report.covered, report.park_covered), (SLOTS, SLOTS));
    assert!(!report.pending && !report.budget_exhausted);
    assert!(events.is_empty());
    let charged = outcome.1.counters();
    assert_eq!((charged.visits, charged.comparisons), (0, 0));
    assert_eq!(charged.updates, SERVICE_CONTROLS - 1);
    assert_eq!((counts.loads, counts.rmws, counts.stores), (0, 0, 0));
    assert_eq!(cursor_slot(), 0);

    // The largest allowance: the same controls, and the remainder is
    // exactly the allowance less them.
    let (outcome, _, counts) = observed(|| {
        let mut spent = WorkBudget::new(usize::MAX);
        (storage.service(&mut spent), spent)
    });
    assert_eq!(outcome.0.unwrap().visited, 0);
    assert_eq!(outcome.1.remaining(), usize::MAX - SERVICE_CONTROLS);
    assert_eq!(counts.loads, 0);
}

/// Last lease before grace and grace before last lease: in both orders the
/// lease reads its bytes until it is dropped, the anchor decrement is
/// observed exactly once, exactly one return follows, and the slot's next
/// reservation carries a fresh incarnation. Without certification service
/// leaves the anchor counted; after it a live lease still holds the slot
/// even though its anchor is released.
#[test]
fn both_release_orders_release_the_anchor_once_and_reuse_with_a_fresh_incarnation() {
    let storage = storage(SLOTS, 1);
    let lease_first = handoff(&storage, &[0x11; 20]);
    let grace_first = handoff(&storage, &[0x22; 20]);
    let (lease_first, lease_first_lease) = lease_first;
    let (grace_first, grace_first_lease) = grace_first;
    let slot_a = lease_first.id().slot_index();
    let slot_b = grace_first.id().slot_index();
    let incarnation_a = lease_first.id().incarnation();
    let incarnation_b = grace_first.id().incarnation();
    assert_eq!(lease_first.retire(), RetireOutcome::Recorded);
    assert_eq!(grace_first.retire(), RetireOutcome::Recorded);

    // Order A: the last lease ends first; the anchor waits for grace, so
    // service holds both slots and releases nothing.
    drop(lease_first_lease);
    let (pass, events, _) = observed(|| service(&storage));
    assert_eq!((pass.held, pass.released, pass.serviced), (2, 0, 0));
    assert!(events.is_empty());
    assert_eq!((refs(&storage, slot_a), refs(&storage, slot_b)), (1, 2));

    // Grace completes: slot A releases and returns in one visit; slot B,
    // whose lease is still live, releases its anchor and is held on the
    // right, its bytes readable throughout.
    assert!(certify(&storage).certified.is_some());
    let (pass, events, _) = observed(|| service(&storage));
    assert_eq!((pass.held, pass.released, pass.serviced), (1, 2, 1));
    let releases: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            Event::AnchorRelease { slot, previous } => Some((*slot, *previous)),
            _ => None,
        })
        .collect();
    assert_eq!(releases.len(), 2);
    assert!(releases.contains(&(slot_a, 1)));
    assert!(releases.contains(&(slot_b, 2)));
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, Event::Return { slot } if *slot == slot_a))
            .count(),
        1
    );
    assert_eq!(refs(&storage, slot_b), 1);

    // Order B: the last lease ends after grace; the next service returns the
    // slot with no further anchor decrement.
    drop(grace_first_lease);
    let (pass, events, _) = observed(|| service(&storage));
    assert_eq!((pass.held, pass.released, pass.serviced), (0, 0, 1));
    assert_eq!(events, [Event::Return { slot: slot_b }]);
    assert_eq!((refs(&storage, slot_a), refs(&storage, slot_b)), (0, 0));

    // Both slots come back with fresh incarnations and are usable once the
    // claim cursor reaches them.
    let live = storage.live_pool().unwrap();
    live.claim_next(slot_a.min(slot_b));
    let mut reused = Vec::new();
    for _ in 0..2 {
        let (resident, lease) = handoff(&storage, &[0x33; 20]);
        reused.push((resident.id().slot_index(), resident.id().incarnation()));
        drop(lease);
        drop(resident);
    }
    reused.sort_unstable();
    let mut expected = vec![(slot_a, incarnation_a + 1), (slot_b, incarnation_b + 1)];
    expected.sort_unstable();
    assert_eq!(reused, expected);
}

/// Every terminal-band retirement closes admission before its mark, not
/// only the crossing one. A crossing thread paused between its bump and its
/// close still holds its slot: a later terminal retirement closes admission
/// first, a reservation attempted then is refused, and when the paused
/// thread resumes its slot's incarnation and the era are what the test
/// recorded; the era never wraps and the certificate still advances.
#[test]
fn every_terminal_band_retirement_closes_admission_before_its_mark() {
    // The main thread waits for `PAUSED` and the paused thread waits for
    // `RELEASE`, so a panic on either side before its store would leave the
    // other spinning: `PAUSED` is stored before the stamp is judged, and the
    // main thread's in-scope outcomes are judged only after `RELEASE`.
    fn hold(stamp: u64) {
        PAUSED.store(true, Ordering::SeqCst);
        assert_eq!(stamp, ERA_TERMINAL - 1);
        while !RELEASE.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }
    }
    static PAUSED: AtomicBool = AtomicBool::new(false);
    static RELEASE: AtomicBool = AtomicBool::new(false);

    let storage = storage(SLOTS, 1);
    let (crossing, crossing_lease) = handoff(&storage, &[1; 20]);
    let (later, later_lease) = handoff(&storage, &[2; 20]);
    let crossing_slot = crossing.id().slot_index();
    let later_slot = later.id().slot_index();
    let crossing_incarnation = crossing.id().incarnation();
    drop((crossing_lease, later_lease));
    storage.eras().era.store(ERA_TERMINAL - 1, Ordering::SeqCst);

    std::thread::scope(|scope| {
        let paused = scope.spawn(|| {
            INTERPOSE_BEFORE_TERMINAL_CLOSE.with(|hook| hook.set(Some(hold)));
            crossing.retire()
        });
        while !PAUSED.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }
        // The crossing thread is paused after its bump and before its close:
        // admission is open, its obligation is unrecorded, its slot is held.
        // Assertions here are collected, not made: a panic while the
        // crossing thread waits would deadlock the scope.
        let paused_era = era(&storage);
        let paused_closed = storage.is_closed();
        let paused_refs = refs(&storage, crossing_slot);
        let paused_flag = storage.live_pool().unwrap().flags(crossing_slot);
        let later_outcome = later.retire();
        let later_closed = storage.is_closed();
        let later_era = era(&storage);
        let later_stamp = retire_era(&storage, later_slot);
        let refused = storage
            .reserve(Some(4), Some(20), &mut WorkBudget::new(64))
            .err();
        RELEASE.store(true, Ordering::SeqCst);
        let resumed = paused.join().unwrap();
        // The crossing thread was paused after its bump and before its close:
        // admission was open, its obligation was not yet recorded, so its
        // flag was still clear, and its anchor held the slot.
        assert_eq!(paused_era, ERA_TERMINAL);
        assert!(!paused_closed);
        assert_eq!(paused_refs, 1);
        assert_eq!(paused_flag, 0);
        assert!(later_closed, "a later terminal retirement closes");
        assert_eq!(later_outcome, RetireOutcome::Recorded);
        assert_eq!(later_era, ERA_TERMINAL + 1);
        assert_eq!(later_stamp, ERA_TERMINAL);
        assert_eq!(refused, Some(ReserveError::Closed));
        assert_eq!(resumed, RetireOutcome::Recorded);
    });
    assert_eq!(retire_era(&storage, crossing_slot), ERA_TERMINAL - 1);
    assert_eq!(
        storage.live_pool().unwrap().flags(crossing_slot),
        ABANDONED | RETIRED | ANCHORED
    );
    assert_eq!(
        storage.slot_state(super::SlotIndex(crossing_slot)),
        Some((super::SlotState::Retired, crossing_incarnation))
    );
    assert_eq!(era(&storage), ERA_TERMINAL + 1);
    assert!(storage.era_report().unwrap().terminal);
    // Certification and service still run after the close; both anchors
    // release once the pass certifies past them, and the era never wrapped.
    let (report, events, _) = observed(|| certify(&storage));
    assert_eq!(report.certified, Some(ERA_TERMINAL + 1));
    assert_eq!(check_pass_log(&events, 1, 0), ERA_TERMINAL + 1);
    let (pass, events, _) = observed(|| service(&storage));
    assert_eq!((pass.released, pass.serviced), (2, 2));
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, Event::AnchorRelease { .. }))
            .count(),
        2
    );
    assert_eq!(era(&storage), ERA_TERMINAL + 1);
}

/// A reservation that read the cutoff open is refused by the recheck under
/// the pool gate when a close lands in between: no slot is claimed, no
/// incarnation advances, the partition is unchanged, and the gate attempt
/// is the only step charged.
#[test]
fn a_reservation_paused_after_its_open_read_is_refused_under_the_gate() {
    fn close(flag: &AtomicBool) {
        flag.store(true, Ordering::SeqCst);
    }
    let storage = storage(SLOTS, 1);
    let before = storage.pool_report().unwrap().ledger;
    let incarnations: Vec<_> = (0..SLOTS)
        .map(|slot| storage.slot_state(super::SlotIndex(slot)))
        .collect();
    INTERPOSE_AFTER_OPEN_READ.with(|hook| hook.set(Some(close)));
    let (outcome, _, counts) = observed(|| {
        let mut spent = WorkBudget::new(64);
        (storage.reserve(Some(4), Some(20), &mut spent).err(), spent)
    });
    assert!(INTERPOSE_AFTER_OPEN_READ.with(|hook| hook.get().is_none()));
    assert_eq!(outcome.0, Some(ReserveError::Closed));
    assert!(storage.is_closed());
    assert_eq!(outcome.1.counters().coordination_attempts, 1);
    assert_eq!(outcome.1.counters().updates, 0);
    assert_eq!(counts.gate_taken, 1);
    assert_eq!(storage.pool_report().unwrap().ledger, before);
    assert_eq!(
        (0..SLOTS)
            .map(|slot| storage.slot_state(super::SlotIndex(slot)))
            .collect::<Vec<_>>(),
        incarnations
    );
}

/// A pass interrupted with the minimum and resumed with the minimum makes
/// one record's progress per call and reports its shape faithfully; the
/// report's `certified` matches the observer's publication.
#[test]
fn minimum_certify_calls_advance_one_record_each_until_the_pass_completes() {
    const R: usize = 3;
    let storage = storage(SLOTS, R);
    let _reader_zero = storage.register().unwrap();
    let _reader_one = storage.register().unwrap();
    let mut reader_two = storage.register().unwrap();
    let pinned = reader_two.enter().unwrap();
    let pin = pinned.era();
    let (resident, lease) = handoff(&storage, &[3; 20]);
    drop(lease);
    assert_eq!(resident.retire(), RetireOutcome::Recorded);
    let mut events = Vec::new();
    for call in 0..R {
        let (report, mut logged, _) = observed(|| {
            storage
                .certify(&mut WorkBudget::new(certify_minimum(R)))
                .unwrap()
        });
        events.append(&mut logged);
        if call + 1 < R {
            assert_eq!(
                report,
                CertifyReport {
                    visited: 1,
                    certified: None,
                    budget_exhausted: true,
                }
            );
        } else {
            assert_eq!(
                report,
                CertifyReport {
                    visited: 1,
                    certified: Some(pin),
                    budget_exhausted: false,
                }
            );
        }
    }
    assert_eq!(check_pass_log(&events, R, 0), pin);
    drop(pinned);
}

/// A counted mark with no parked bit leaves the retired pass's decisions
/// unchanged: two storages driven identically, one with a pending mark
/// counted and no flag set, report the same retired-pass coverage, visits,
/// returns and releases under an allowance that funds both passes whole.
/// The counted one adds only the park pass's one summary probe over its
/// empty parked set and that probe's charge.
#[test]
fn a_counted_mark_without_a_parked_bit_adds_only_the_park_passs_probe() {
    let (bitmap, flags) = (storage(SLOTS, 1), storage(SLOTS, 1));
    let mut kept = Vec::new();
    for storage in [&bitmap, &flags] {
        for slot in 0..SLOTS {
            let (resident, lease) = handoff(storage, &[slot as u8; 20]);
            drop(lease);
            if slot % 2 == 1 {
                assert_eq!(resident.retire(), RetireOutcome::Recorded);
            } else {
                kept.push(resident);
            }
        }
        assert!(certify(storage).certified.is_some());
    }
    let marks = &flags.live_pool().unwrap().telemetry().pending_marks;
    marks.fetch_add(1, Ordering::Relaxed);
    assert_eq!(bitmap.service_minimum(), flags.service_minimum());
    let run = |storage: &super::Storage<super::test_platform::TestPlatform>| {
        let mut spent = WorkBudget::new(1 << 10);
        (storage.service(&mut spent).unwrap(), spent.counters())
    };
    let ((by_bitmap, bitmap_spent), (by_flags, flags_spent)) = (run(&bitmap), run(&flags));
    assert_eq!(
        ServiceReport {
            probes: by_bitmap.probes + 1,
            ..by_bitmap
        },
        by_flags
    );
    assert_eq!(
        (by_bitmap.serviced, by_bitmap.released),
        (SLOTS / 2, SLOTS / 2)
    );
    assert_eq!(flags_spent.visits, bitmap_spent.visits + 1);
    assert_eq!(flags_spent.updates, bitmap_spent.updates + PARKED_PROBE - 1);
    assert_eq!(flags_spent.comparisons, bitmap_spent.comparisons);
    marks.fetch_sub(1, Ordering::Relaxed);
    drop(kept);
}

/// A resumed pass covers the records the claimed bound gained since it
/// began: begun with two records claimed and funded for one visit, it
/// visits the other two after a third registration, and its log shows one
/// start and every record once.
#[test]
fn a_resumed_pass_visits_records_claimed_after_it_began() {
    const R: usize = 3;
    let storage = super::grace_tests::unclaimed_storage(SLOTS, R);
    let first = storage.register().unwrap();
    let second = storage.register().unwrap();
    let (resident, lease) = handoff(&storage, &[8; 20]);
    drop(lease);
    assert_eq!(resident.retire(), RetireOutcome::Recorded);
    let start = era(&storage);
    let (partial, mut events, _) = observed(|| {
        storage
            .certify(&mut WorkBudget::new(certify_minimum(R)))
            .unwrap()
    });
    assert_eq!(
        (partial.visited, partial.certified, partial.budget_exhausted),
        (1, None, true)
    );
    let third = storage.register().unwrap();
    assert_eq!(third.index().0, 2);
    let (resumed, rest, _) = observed(|| certify(&storage));
    assert_eq!((resumed.visited, resumed.certified), (2, Some(start)));
    events.extend(rest);
    assert_eq!(check_pass_log(&events, R, 0), start);
    drop((first, second, third));
}

/// A certification that panics under the grace maintenance gate poisons it,
/// so the next certification closes admission (`maintain` module doc: a
/// panic "under the grace maintenance gate poisons it, so the next
/// certification closes admission"), on a thread that is not unwinding and
/// from a destructor that catches the panic while its thread unwinds from
/// another. The stored pass cursor names a record past the claimed bound,
/// so the pass's record range panics under the gate.
#[test]
fn a_certification_panic_poisons_the_maintenance_gate_even_during_unwinding() {
    type Live = super::Storage<super::test_platform::TestPlatform>;
    struct CertifiesOnDrop<'a> {
        storage: &'a Live,
        panicked: &'a std::cell::Cell<bool>,
    }
    impl Drop for CertifiesOnDrop<'_> {
        fn drop(&mut self) {
            let storage = self.storage;
            let certified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                storage.certify(&mut WorkBudget::new(400)).is_ok()
            }));
            self.panicked.set(certified.is_err());
        }
    }
    const READERS: usize = 3;
    for unwinding in [false, true] {
        let storage = storage(SLOTS, READERS);
        let held = storage.maintenance_gate().try_lock().unwrap();
        storage.grace_cursor().store(PassCursor {
            start_era: ERA_FIRST + 1,
            min_key: u64::MAX,
            next: READERS + 1,
        });
        held.release();
        let panicked = std::cell::Cell::new(false);
        if unwinding {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _certifier = CertifiesOnDrop {
                    storage: &storage,
                    panicked: &panicked,
                };
                panic!("an unrelated panic with a live certifier");
            }));
            assert!(outcome.is_err());
        } else {
            drop(CertifiesOnDrop {
                storage: &storage,
                panicked: &panicked,
            });
        }
        assert!(
            panicked.get(),
            "premise: the certification panicked, unwinding={unwinding}"
        );
        assert!(
            matches!(
                storage.maintenance_gate().try_lock(),
                Err(GateError::Poisoned)
            ),
            "the certification's panic poisons the maintenance gate, unwinding={unwinding}"
        );
        assert_eq!(
            storage.certify(&mut WorkBudget::new(400)),
            Err(ServiceError::Gate(GateError::Poisoned)),
            "unwinding={unwinding}"
        );
        assert!(storage.is_closed(), "unwinding={unwinding}");
    }
}
