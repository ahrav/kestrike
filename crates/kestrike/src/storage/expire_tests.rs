//! The expiry sweep: removal never precedes the per-call sample, a missing
//! sample skips the stage, validity stays lookup's, a replacement attempt
//! survives the removal of its expired incumbent, and the persistent cursor
//! resumes and wraps.

use super::admission::Decision;
use super::budget::WorkBudget;
use super::config::StorageConfig;
use super::evict::{Commit, SELECT_CONTROLS, SELECT_MIN, SELECT_PER_VISIT};
use super::evict_tests::{drain, generous, hold_pool_gate_during_commit, ready, release_holder};
use super::expire::{ExpiryReport, sweep};
use super::lookup::LookupError;
use super::lookup_tests::{body, hit_key, key, lookup};
use super::owner::Storage;
use super::publish_tests::{PAGE, RETRIES, TRIES, index_config, storage_config, storage_from};
use super::tables::{SlotIndex, SlotState};
use super::test_platform::TestPlatform;
use super::volume_fixture;
use super::{ExtentLease, FillPublishError};
use crate::index::{IndexConfig, Ratio};

/// One second on the engine's nanosecond timeline: the deadlines and samples
/// here count whole seconds.
const SECOND: u64 = 1_000_000_000;

/// Publishes `n` with a deadline of `deadline` seconds.
fn publish(storage: &Storage<TestPlatform>, n: u8, deadline: u64) -> usize {
    super::lookup_tests::publish(storage, key(n), deadline * SECOND, &body(n)).slot_index()
}

/// As `ready`, with the index at a quarter load, so a table full of
/// residents does not meet `IndexFull` under an unlucky hash key.
fn roomy(slots: usize) -> Storage<TestPlatform> {
    let slot_count = slots;
    let limits = [slots];
    let fills = [2usize];
    let index = IndexConfig {
        fills: &fills,
        load: Ratio {
            numerator: 1,
            denominator: 4,
        },
        ..index_config(&limits, (1, 1), 1)
    };
    let config = StorageConfig {
        lease_limit: 64,
        ..storage_config(slot_count)
    };
    let storage = storage_from(&config, &index, TestPlatform::heap(PAGE));
    ticks(&storage, &[Some(1)]);
    storage
}

fn expire(storage: &Storage<TestPlatform>) -> super::expire::ExpiryReport {
    storage.expire_step(&mut generous()).unwrap()
}

fn removed(report: &super::expire::ExpiryReport) -> Option<usize> {
    match report.commit {
        Some(Commit::Evicted { victim, .. }) => Some(victim.slot_index()),
        _ => None,
    }
}

/// Queues `samples`, each in seconds.
fn ticks(storage: &Storage<TestPlatform>, samples: &[Option<u64>]) {
    let scaled: Vec<Option<u64>> = samples
        .iter()
        .map(|sample| sample.map(|s| s * SECOND))
        .collect();
    storage.platform.ticks(&scaled);
}

/// The domain's in-flight count and the volume's expiry cursor.
fn in_flight_and_cursor(storage: &Storage<TestPlatform>) -> (u32, usize) {
    let live = storage.live_pool().unwrap();
    let mut access = live.lock().unwrap();
    let tables = access.tables();
    (tables.domain.in_flight, tables.state.cursor_expiry)
}

/// The pool's deadline bound.
fn earliest_deadline(storage: &Storage<TestPlatform>) -> u32 {
    let live = storage.live_pool().unwrap();
    let mut access = live.lock().unwrap();
    let bound = access.tables().state.earliest_deadline;
    assert_eq!(
        live.deadline_bound
            .load(std::sync::atomic::Ordering::Relaxed),
        bound,
        "the published bound is the gate-held bound"
    );
    bound
}

/// Deadline 10 with samples 9, 10 and 11: nothing is removed at 9 and the
/// object is removed at 10 (equality is expired) and at 11. A deadline one
/// past the sample stays. Each call takes exactly one sample however many
/// slots it examines.
#[test]
fn removal_never_precedes_the_sample_and_equality_is_expired() {
    for (sample, expected) in [(9, false), (10, true), (11, true)] {
        let storage = ready(8);
        for n in 1..=4 {
            publish(&storage, n, 100);
        }
        let slot = publish(&storage, 5, 10);
        let late = publish(&storage, 6, 11);
        ticks(&storage, &[Some(sample)]);
        let taken = storage.platform.samples_taken();
        let report = expire(&storage);
        assert_eq!(
            storage.platform.samples_taken(),
            taken + 1,
            "one sample per call"
        );
        assert_eq!(
            removed(&report),
            expected.then_some(slot),
            "sample {sample}"
        );
        let report = expire(&storage);
        assert_eq!(storage.platform.samples_taken(), taken + 2);
        if sample == 11 {
            assert_eq!(removed(&report), Some(late));
        } else {
            assert_eq!(removed(&report), None, "deadline 11 at sample {sample}");
        }
    }
}

/// A missing sample skips the stage: nothing removed, nothing debited, the
/// cursor unmoved, `clock_unavailable` set. An allowance below the minimum
/// refuses before the sample. A busy pool gate refuses after the sample,
/// which is taken before any gate, with the cursor unmoved.
#[test]
fn a_missing_sample_skips_the_stage() {
    let storage = ready(8);
    publish(&storage, 1, 10);
    publish(&storage, 2, 10);
    ticks(&storage, &[Some(10)]);
    let minimum = SELECT_MIN + storage.commit_bundle();
    let taken = storage.platform.samples_taken();
    assert_eq!(
        storage.expire_step(&mut WorkBudget::new(minimum - 1)),
        Err(super::evict::EvictError::BudgetExhausted)
    );
    assert_eq!(
        storage.platform.samples_taken(),
        taken,
        "refused before the sample"
    );
    // One funded visit moves the cursor off zero, removing the expired slot
    // it examined.
    storage.expire_step(&mut WorkBudget::new(minimum)).unwrap();
    let before = in_flight_and_cursor(&storage);
    assert_eq!(before, (1, 1));
    {
        let live = storage.live_pool().unwrap();
        let _gate = live.lock().unwrap();
        let taken = storage.platform.samples_taken();
        assert!(matches!(
            storage.expire_step(&mut generous()),
            Err(super::evict::EvictError::Gate(_))
        ));
        assert_eq!(
            storage.platform.samples_taken(),
            taken + 1,
            "sampled before the gate"
        );
    }
    assert_eq!(in_flight_and_cursor(&storage), before);
    ticks(&storage, &[None]);
    let mut spent = generous();
    let report = storage.expire_step(&mut spent).unwrap();
    assert!(report.clock_unavailable);
    assert_eq!((report.commit, report.visited), (None, 0));
    assert_eq!(spent.counters(), WorkBudget::new(0).counters());
    assert_eq!(in_flight_and_cursor(&storage), before);
}

/// The pending mark's slot and incarnation, read without taking it.
fn pending_identity(storage: &Storage<TestPlatform>) -> (u64, u32) {
    use std::sync::atomic::Ordering::Relaxed;
    let mark = storage.live_pool().unwrap().pending_mark();
    (mark.slot.load(Relaxed), mark.incarnation.load(Relaxed))
}

/// A step that finds no clock reports the pending mark's actual state: with
/// no mark pending it reports none, and with a mark that an eviction parked behind
/// a busy pool gate it reports the mark pending, with no commit and no
/// visits, and the cursor, the mark's identity and the work counters
/// unchanged; a sample below every deadline reports it pending too. Once the clock returns at a deadline, a funded step applies the
/// mark.
#[test]
fn a_missing_clock_reports_the_pending_mark() {
    let storage: &'static Storage<TestPlatform> = Box::leak(Box::new(ready(8)));
    publish(storage, 1, 100);
    publish(storage, 2, 100);
    ticks(storage, &[None]);
    let report = expire(storage);
    assert_eq!(
        (report.clock_unavailable, report.mark_pending),
        (true, false)
    );
    let holder = hold_pool_gate_during_commit(storage);
    let evicted = storage.evict_step(&mut generous(), |_, _| true).unwrap();
    release_holder(holder);
    assert!(evicted.mark_pending, "the busy gate parked the mark");
    let before = (in_flight_and_cursor(storage), pending_identity(storage));
    ticks(storage, &[None]);
    let mut spent = generous();
    let report = storage.expire_step(&mut spent).unwrap();
    assert_eq!(
        (report.clock_unavailable, report.mark_pending),
        (true, true)
    );
    assert_eq!((report.commit, report.visited), (None, 0));
    assert_eq!(spent.counters(), WorkBudget::new(0).counters());
    assert_eq!(
        (in_flight_and_cursor(storage), pending_identity(storage)),
        before
    );
    ticks(storage, &[Some(1)]);
    let report = expire(storage);
    assert_eq!(
        (report.clock_unavailable, report.mark_pending),
        (false, true)
    );
    assert_eq!(
        (in_flight_and_cursor(storage), pending_identity(storage)),
        before,
        "a sample below every deadline leaves the mark"
    );
    ticks(storage, &[Some(100)]);
    let report = expire(storage);
    assert!(!report.clock_unavailable);
    assert!(!report.mark_pending, "the funded step applied the mark");
    assert!(!storage.live_pool().unwrap().pending_mark().is_pending());
    drain(storage);
}

/// The sweep never decides validity: an expired resident the sweep has not
/// reached is refused `Expired` by lookup, and an expired object a reader
/// holds is retained, its bytes readable, until the lease is released; the
/// sweep then removes it, and its block returns only after grace and
/// service.
#[test]
fn an_expired_object_stays_readable_through_a_held_lease() {
    let storage = ready(8);
    let slot = publish(&storage, 1, 10);
    let mut reader = storage.register().unwrap();
    ticks(&storage, &[Some(5)]);
    let lease = lookup(&mut reader, &key(1), RETRIES).unwrap();
    ticks(&storage, &[Some(20)]);
    assert_eq!(
        lookup(&mut reader, &key(1), RETRIES).err(),
        Some(LookupError::Expired),
        "unswept and expired"
    );
    let report = expire(&storage);
    assert_eq!((report.commit, report.held), (None, 1));
    assert_eq!(hit_key(&lease), key(1));
    drop(lease);
    let report = expire(&storage);
    assert_eq!(removed(&report), Some(slot));
    assert_eq!(in_flight_and_cursor(&storage).0, 1, "marked and in flight");
    assert_eq!(
        storage.slot_state(SlotIndex(slot)).unwrap().0,
        SlotState::Retired
    );
    drain(&storage);
    assert_eq!(
        storage.slot_state(SlotIndex(slot)).unwrap().0,
        SlotState::Free
    );
    assert_eq!(in_flight_and_cursor(&storage).0, 0);
}

thread_local! {
    static STORAGE: std::cell::Cell<Option<&'static Storage<TestPlatform>>> =
        const { std::cell::Cell::new(None) };
    static LEASE: std::cell::RefCell<Option<ExtentLease<'static, TestPlatform>>> =
        const { std::cell::RefCell::new(None) };
}

/// A lease taken after the sweep chose its candidate does not stop the
/// removal: the object loses visibility, the reader keeps its bytes, and the
/// block returns only after the release, grace and service.
#[test]
fn a_lease_taken_after_the_choice_keeps_its_bytes_until_release() {
    let storage: &'static Storage<TestPlatform> = Box::leak(Box::new(ready(8)));
    let slot = publish(storage, 1, 10);
    STORAGE.with(|cell| cell.set(Some(storage)));
    super::evict::INTERPOSE_BEFORE_COMMIT.with(|hook| {
        hook.set(Some(|| {
            let storage = STORAGE.with(std::cell::Cell::get).unwrap();
            ticks(storage, &[Some(5)]);
            let lease = lookup(&mut storage.register().unwrap(), &key(1), RETRIES).unwrap();
            LEASE.with(|cell| *cell.borrow_mut() = Some(lease));
        }))
    });
    ticks(storage, &[Some(20)]);
    assert_eq!(removed(&expire(storage)), Some(slot));
    assert_eq!(in_flight_and_cursor(storage).0, 1);
    let lease = LEASE.with(|cell| cell.borrow_mut().take()).unwrap();
    drain(storage);
    assert_eq!(hit_key(&lease), key(1));
    assert_eq!(
        storage.slot_state(SlotIndex(slot)).unwrap().0,
        SlotState::Retired,
        "a right still holds the block"
    );
    drop(lease);
    drain(storage);
    assert_eq!(
        storage.slot_state(SlotIndex(slot)).unwrap().0,
        SlotState::Free
    );
}

/// An expired incumbent whose key has a current replacement attempt is
/// removed with the attempt intact and not revoked; the attempt's later
/// publication is a vacant insert.
#[test]
fn an_expired_incumbent_is_removed_with_its_replacement_attempt_intact() {
    let storage = ready(8);
    let slot = publish(&storage, 1, 10);
    let attempt = super::attempt_tests::begin(&storage, &key(1)).unwrap();
    let serial = attempt.serial();
    ticks(&storage, &[Some(20)]);
    assert_eq!(removed(&expire(&storage)), Some(slot));
    assert!(
        super::attempt_tests::records(&storage).contains(&super::attempt_tests::live(serial)),
        "the attempt is current and not revoked"
    );
    let Decision::Admit(admitted) = storage.decide_admission(Some(4), Some(20)) else {
        panic!("admission refused");
    };
    let buffers = volume_fixture::arena();
    let (mut volume, control) = volume_fixture::attach(&storage, &buffers);
    let mut fill = attempt
        .reserve_storage(admitted, Some(4), Some(20), TRIES, &mut generous())
        .unwrap();
    let payload: Vec<u8> = key(1)[..4].iter().copied().chain([3; 20]).collect();
    volume_fixture::receive_all(&mut fill, &mut volume, &control, &payload, 64);
    volume_fixture::settle(&mut volume, &control);
    ticks(&storage, &[Some(21)]);
    let published: Result<_, FillPublishError> =
        fill.publish(&mut volume, 100 * SECOND, TRIES, &mut generous());
    let lease = published.unwrap();
    assert_eq!(
        volume_fixture::read_back(&mut volume, &control, &lease).bytes,
        payload
    );
    drop(lease);
    let mut reader = storage.register().unwrap();
    let lease = lookup(&mut reader, &key(1), RETRIES).unwrap();
    assert_eq!(
        volume_fixture::read_back(&mut volume, &control, &lease).bytes,
        payload
    );
}

/// A run debits one visit bundle per slot it passes: with the one expired
/// resident held by a lease, a funded run passes the whole table, and an
/// allowance for three visits passes three and stops on its budget; each
/// pays the selection controls and its bundles, nothing more. The sample
/// sits at the deadline so the pool's bound does not skip the run.
#[test]
fn a_run_debits_one_visit_bundle_per_slot_passed() {
    let storage = ready(8);
    publish(&storage, 1, 100);
    let mut reader = storage.register().unwrap();
    ticks(&storage, &[Some(1)]);
    let _held = lookup(&mut reader, &key(1), RETRIES).unwrap();
    ticks(&storage, &[Some(100)]);
    let minimum = SELECT_MIN + storage.commit_bundle();
    for (allowance, visits) in [(1 << 16, 8), (minimum + 2 * SELECT_PER_VISIT, 3)] {
        let mut spent = WorkBudget::new(allowance);
        let report = storage.expire_step(&mut spent).unwrap();
        assert_eq!((report.commit, report.visited), (None, visits));
        assert_eq!(report.budget_exhausted, visits < 8);
        assert_eq!(
            allowance - spent.remaining(),
            SELECT_CONTROLS + visits * SELECT_PER_VISIT
        );
        assert_eq!(
            (spent.counters().visits, spent.counters().comparisons),
            (visits, 3 * visits)
        );
    }
}

/// A run that starts near the end of the table passes the end, wraps and
/// continues in the same call up to the slots its allowance funds, then
/// stops on its budget with the cursor past the last slot passed; a
/// candidate on the last funded slot ends the run without a budget stop.
#[test]
fn a_run_wraps_within_one_call_and_stops_at_its_funded_limit() {
    let storage = ready(8);
    let slots: Vec<usize> = [(1, 100), (2, 10), (3, 100)]
        .into_iter()
        .map(|(n, deadline)| publish(&storage, n, deadline))
        .collect();
    assert_eq!(slots, [0, 1, 2], "the fixture's slots");
    ticks(&storage, &[Some(50), Some(50)]);
    let set_cursor = |at: usize| {
        let live = storage.live_pool().unwrap();
        let mut access = live.lock().unwrap();
        access.tables().state.cursor_expiry = at;
    };
    let four = SELECT_MIN + storage.commit_bundle() + 3 * SELECT_PER_VISIT;
    // From slot 5: slots 5, 6, 7 and 0 are funded; slot 1's expired
    // object lies past the limit.
    set_cursor(5);
    let mut budget = WorkBudget::new(four);
    let report = storage.expire_step(&mut budget).unwrap();
    assert_eq!((report.commit, report.visited), (None, 4));
    assert!(report.wrapped && report.budget_exhausted);
    assert_eq!(in_flight_and_cursor(&storage).1, 1);
    assert_eq!(
        four - budget.remaining(),
        SELECT_CONTROLS + 4 * SELECT_PER_VISIT
    );
    // From slot 6: slots 6, 7, 0 and 1 are funded, and the last is the
    // candidate.
    set_cursor(6);
    let mut budget = WorkBudget::new(four);
    let report = storage.expire_step(&mut budget).unwrap();
    assert_eq!((removed(&report), report.visited), (Some(1), 4));
    assert!(report.wrapped && !report.budget_exhausted);
    assert_eq!(in_flight_and_cursor(&storage), (1, 2));
    drain(&storage);
}

/// The sweep walks four slots per step and the remainder one at a time: an
/// expired resident at any position of a run, in any lane of a step or in
/// the remainder, is the candidate, the run's visits end on it and the
/// cursor rests past it, wrapping when it is the table's last slot.
#[test]
fn the_candidate_ends_the_run_at_every_position_of_steps_and_remainder() {
    for expired in 1..16 {
        let storage = ready(16);
        for n in 0..16u8 {
            let deadline = if usize::from(n) == expired { 10 } else { 100 };
            assert_eq!(publish(&storage, n + 1, deadline), usize::from(n));
        }
        ticks(&storage, &[Some(50)]);
        // From slot 1 the run to the table's end is fifteen slots: three
        // whole steps and three more.
        {
            let live = storage.live_pool().unwrap();
            live.lock().unwrap().tables().state.cursor_expiry = 1;
        }
        let report = expire(&storage);
        assert_eq!(removed(&report), Some(expired), "expired slot {expired}");
        assert_eq!(report.visited, expired, "expired slot {expired}");
        // A candidate on the last slot passes the table's end.
        assert_eq!(report.wrapped, expired == 15, "expired slot {expired}");
        assert!(!report.budget_exhausted);
        assert_eq!(in_flight_and_cursor(&storage), (1, (expired + 1) % 16));
        drain(&storage);
    }
}

/// The cursor persists: a sweep stopped by its allowance resumes where it
/// stopped, and a funded loop wraps and removes every expired slot, each
/// marked and counted in flight. The revisit of a slot behind the cursor
/// after the wrap is shown by the held-lease test.
#[test]
fn a_stopped_sweep_resumes_and_a_funded_loop_removes_every_expired_slot() {
    let storage = ready(16);
    let expired: Vec<usize> = (1..=6).map(|n| publish(&storage, n, 10)).collect();
    for n in 7..=10 {
        publish(&storage, n, 100);
    }
    ticks(&storage, &[Some(50)]);
    let minimum = SELECT_MIN + storage.commit_bundle();
    // One visit's allowance: the sweep examines one slot and stops there.
    let mut short = WorkBudget::new(minimum);
    let first = storage.expire_step(&mut short).unwrap();
    assert_eq!(first.visited, 1);
    let (_, cursor) = in_flight_and_cursor(&storage);
    assert_eq!(cursor, 1, "the cursor rests past the slot examined");
    let mut gone: Vec<usize> = removed(&first).into_iter().collect();
    let mut wrapped = false;
    for _ in 0..40 {
        let mut budget = WorkBudget::new(minimum + 3 * SELECT_PER_VISIT);
        let report = storage.expire_step(&mut budget).unwrap();
        wrapped |= report.wrapped;
        gone.extend(removed(&report));
    }
    gone.sort_unstable();
    let mut want = expired.clone();
    want.sort_unstable();
    assert_eq!(gone, want);
    assert!(wrapped, "the cursor wrapped");
    assert_eq!(in_flight_and_cursor(&storage).0, 6);
    drain(&storage);
    assert_eq!(in_flight_and_cursor(&storage).0, 0);
    let live = storage.live_pool().unwrap();
    assert!(!live.pending_mark().is_pending());
}

/// A sample below every resident's deadline visits nothing: the cursor
/// stays, nothing is removed and the stage is done. The bound starts as the
/// least deadline bound; the pass in which the earliest object went
/// republishes its deadline at the wrap, the next full pass raises the
/// bound to the next deadline, and a later bind with an earlier deadline
/// lowers it.
#[test]
fn a_sample_below_every_deadline_visits_nothing_and_the_bound_follows_the_residents() {
    let storage = ready(8);
    let early = publish(&storage, 1, 10);
    let late = publish(&storage, 2, 100);
    assert_eq!(earliest_deadline(&storage), 10);
    ticks(&storage, &[Some(9)]);
    let report = expire(&storage);
    assert_eq!((report.visited, report.budget_exhausted), (0, false));
    assert_eq!(removed(&report), None);
    assert_eq!(in_flight_and_cursor(&storage), (0, 0));
    ticks(&storage, &[Some(10)]);
    assert_eq!(removed(&expire(&storage)), Some(early));
    // The pass that folded the removed deadline republishes it at its wrap;
    // the next full pass sees only the late object.
    assert!(expire(&storage).wrapped);
    assert_eq!(earliest_deadline(&storage), 10);
    let report = expire(&storage);
    assert_eq!((report.visited, report.wrapped), (8, true));
    assert_eq!(earliest_deadline(&storage), 100);
    assert_eq!(expire(&storage).visited, 0, "skipped at sample 10");
    ticks(&storage, &[Some(99)]);
    assert_eq!(expire(&storage).visited, 0, "skipped below the bound");
    publish(&storage, 4, 200);
    assert_eq!(earliest_deadline(&storage), 100, "a later deadline");
    let middle = publish(&storage, 3, 50);
    assert_eq!(earliest_deadline(&storage), 50);
    ticks(&storage, &[Some(50)]);
    assert_eq!(removed(&expire(&storage)), Some(middle));
    ticks(&storage, &[Some(100)]);
    let mut gone = Vec::new();
    for _ in 0..4 {
        gone.extend(removed(&expire(&storage)));
    }
    assert_eq!(gone, [late]);
    drain(&storage);
}

/// A retirement parked behind a held gate on a leased resident is detached
/// by the first sweep that sights it and never again: the walk meets it on
/// every pass, and later sightings count and emit nothing. The sweeps
/// sample at the deadline, so they visit; the held lease was taken before.
#[test]
fn a_parked_retirement_is_detached_once_by_the_sweep() {
    let storage = ready(4);
    publish(&storage, 1, 100);
    ticks(&storage, &[Some(1)]);
    let mut reader = storage.register().unwrap();
    let lease = lookup(&mut reader, &key(1), RETRIES).unwrap();
    ticks(&storage, &[Some(100)]);
    {
        let live = storage.live_pool().unwrap();
        let _gate = live.lock().unwrap();
        super::attempt_tests::invalidate(&storage, &key(1)).unwrap();
    }
    super::probe::arm();
    let first = expire(&storage);
    let second = expire(&storage);
    let events = super::probe::events().events;
    super::probe::disarm();
    assert_eq!((first.detached_seen, second.detached_seen), (1, 0));
    let detached = events
        .iter()
        .filter(|event| matches!(event, super::probe::Event::Detached { .. }))
        .count();
    assert_eq!(detached, 1);
    let live = storage.live_pool().unwrap();
    assert_eq!(live.lock().unwrap().tables().domain.detached, 1);
    drop(lease);
    drain(&storage);
}

/// The walk stops exactly at the one resident it cannot pass wherever that
/// falls, on a full table, which it tests slot by slot, and on one with a
/// free slot, which it tests a block at a time: a lone expired resident at
/// every position of a table long enough for a first slot, whole blocks and
/// a tail is removed with the visits counted up to it, and a lone leased
/// expired one at every position is counted held while the pass visits
/// every slot; its deadline is the sample the pool's bound lets through.
#[test]
fn the_walk_stops_at_a_lone_expired_or_leased_resident_at_every_position() {
    const SLOTS: usize = 27;
    for residents in [SLOTS as u8, SLOTS as u8 - 1] {
        for at in 0..residents {
            let storage = roomy(SLOTS);
            let slots: Vec<usize> = (0..residents)
                .map(|n| publish(&storage, n, if n == at { 10 } else { 100 }))
                .collect();
            ticks(&storage, &[Some(50)]);
            let report = expire(&storage);
            let slot = slots[usize::from(at)];
            assert_eq!(
                removed(&report),
                Some(slot),
                "expired at {at} of {residents}"
            );
            assert_eq!(report.visited, slot + 1, "expired at {at} of {residents}");

            let storage = roomy(SLOTS);
            for n in 0..residents {
                publish(&storage, n, if n == at { 50 } else { 100 });
            }
            let mut reader = storage.register().unwrap();
            ticks(&storage, &[Some(1)]);
            let lease = lookup(&mut reader, &key(at), RETRIES).unwrap();
            ticks(&storage, &[Some(50)]);
            let report = expire(&storage);
            let counted = (report.commit, report.held, report.visited);
            assert_eq!(counted, (None, 1, SLOTS), "leased at {at} of {residents}");
            drop(lease);
        }
    }
}

/// A run that chooses a candidate names the fingerprint of the slot its
/// cursor then rests on when that slot holds an expired resident, and the
/// step hints that fingerprint's bucket for the next removal; a slot whose
/// resident is unexpired yields `None`. The second run, from the cursor the
/// first left, chooses the named resident by its own test.
#[test]
fn a_chosen_candidate_names_the_next_expired_resident() {
    let storage = ready(16);
    let first = publish(&storage, 1, 10);
    let second = publish(&storage, 2, 10);
    let unexpired = publish(&storage, 3, 100);
    assert_eq!((second, unexpired), (first + 1, first + 2));
    let live = storage.live_pool().unwrap();
    let mut access = live.lock().unwrap();
    let mut tables = access.tables();
    let sample = 50 * SECOND;
    let run = |tables: &mut _| {
        let mut report = ExpiryReport::default();
        let mut next = None;
        let chosen = sweep(tables, live, sample, 16, &mut report, &mut next);
        (chosen.map(|victim| victim.id.slot_index()), next)
    };
    let fingerprint = |slot: usize| live.records()[slot].fingerprint();
    assert_eq!(run(&mut tables), (Some(first), Some(fingerprint(second))));
    assert_eq!(run(&mut tables), (Some(second), None));
}

/// How the test plants a bind that skips part of its running-minimum update.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Omit {
    /// The bind as the pool makes it.
    Nothing,
    /// The pass's least and the published bound, with its atomic copy, go back to their values before the bind.
    Both,
    /// Only the pass's least goes back, so the published bound stays lowered.
    PassMinimum,
}

/// A bind behind the expiry cursor mid-pass, the cursor at slot 14 before
/// the pass wraps, with the earliest deadline: once the sample reaches it,
/// the resident is the sweep's candidate within `ceil(count / visits) + 1`
/// calls, `visits` the visits each call's allowance funds and `count` the
/// slot count. A run continues past the wrap within its call, so the walk
/// from the cursor through the wrap to the slot spans at most `count`
/// visits, `slot < cursor`, and `ceil(count / visits)` calls reach it; the
/// extra call covers the step's one error, a bind that lowers the bound
/// after the step's unlocked read. The bind folds its deadline into the
/// pass's running least as well as into the published bound, so the wrap on
/// the way publishes a bound at or below the bind's deadline.
///
/// The sample is the bind's deadline, between it and every other resident's.
/// `omit` undoes part of the bind's update under the pool gate. With
/// `Omit::Both` the step reads a bound above the sample, visits nothing, and
/// the resident is never reached; a sample at or past the other deadlines
/// would run the sweep regardless and mask the fault. With
/// `Omit::PassMinimum` the step runs, and the wrap publishes the pass's
/// least, above the bind's deadline.
fn bind_behind_the_cursor(omit: Omit) {
    const BIND: u64 = 20;
    const LATER: u64 = 100;
    const SAMPLE: u64 = BIND;
    let storage = ready(16);
    let count = storage.live_pool().unwrap().records().len();
    for n in 0..12u8 {
        assert_eq!(publish(&storage, n + 1, LATER), usize::from(n));
    }
    let cursor = 14;
    let before = {
        let live = storage.live_pool().unwrap();
        let mut access = live.lock().unwrap();
        let tables = access.tables();
        tables.state.cursor_expiry = cursor;
        (tables.state.pass_earliest, tables.state.earliest_deadline)
    };
    let slot = publish(&storage, 13, BIND);
    assert_eq!(slot, 12, "the bind lands behind the cursor");
    assert_eq!(earliest_deadline(&storage), BIND as u32);
    {
        let live = storage.live_pool().unwrap();
        let mut access = live.lock().unwrap();
        let tables = access.tables();
        match omit {
            Omit::Nothing => {}
            Omit::Both => {
                (tables.state.pass_earliest, tables.state.earliest_deadline) = before;
                live.publish_deadline_bound(before.1);
            }
            Omit::PassMinimum => tables.state.pass_earliest = before.0,
        }
    }
    let minimum = SELECT_MIN + storage.commit_bundle();
    let visits = 3;
    let allowance = minimum + (visits - 1) * SELECT_PER_VISIT;
    let calls = count.div_ceil(visits) + 1;
    ticks(&storage, &vec![Some(SAMPLE); calls]);
    let mut wrapped = false;
    for call in 1..=calls {
        let report = storage
            .expire_step(&mut WorkBudget::new(allowance))
            .unwrap();
        if report.wrapped {
            wrapped = true;
            assert!(
                earliest_deadline(&storage) <= BIND as u32,
                "call {call}: the wrap published a bound above the bind's deadline"
            );
        }
        if removed(&report) == Some(slot) {
            assert!(wrapped, "the slot behind the cursor follows the wrap");
            drain(&storage);
            return;
        }
        assert_eq!(removed(&report), None, "call {call}: {report:?}");
        if omit != Omit::Both {
            assert_eq!(report.visited, visits, "call {call} visits what it funds");
        }
    }
    panic!("the bound resident behind the cursor was not the candidate within {calls} calls");
}

#[test]
fn an_earlier_deadline_bound_behind_the_cursor_expires_within_one_revisit() {
    bind_behind_the_cursor(Omit::Nothing);
}

#[test]
#[should_panic(expected = "was not the candidate within 7 calls")]
fn negative_control_an_omitted_running_minimum_keeps_the_bind_behind_the_cursor() {
    bind_behind_the_cursor(Omit::Both);
}

#[test]
#[should_panic(expected = "call 1: the wrap published a bound above the bind's deadline")]
fn negative_control_an_omitted_pass_minimum_raises_the_bound_at_the_wrap() {
    bind_behind_the_cursor(Omit::PassMinimum);
}
