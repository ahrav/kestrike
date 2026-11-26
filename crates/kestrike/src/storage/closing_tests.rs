//! The bounded close service and exclusive finalization, end to end: a
//! closed engine with a live registration and lease is swept, serviced and
//! certified through repeated calls whose reports add up to an independent
//! visit count, every blocker is named alone, budgets stop at stage
//! boundaries, and finalization drains only after every owner has ended.

use std::sync::{Arc, Barrier};

use super::budget::WorkBudget;
use super::closing::{CloseError, CloseStage, ClosingReport};
use super::finalize::{Finalization, FinalizeError, Phase, Progress};
use super::lookup_tests::hit_key;
use super::lookup_tests::{body, key, lookup, publish, ready, reserved, ticks};
use super::owner::Storage;
use super::probe;
use super::publish_tests::{PAGE, RETRIES, index_config, storage, storage_with};
use super::release::{PARKED_PROBE, RETIRED_PROBE, SERVICE_CONTROLS, SERVICE_PER_SLOT};
use super::test_platform::{Op, TestPlatform, blocked, finalize};
use crate::index::{BucketView, CONTROL_MASK, PAIRS, ShardIndex, is_occupied};

/// A control bit outside every lane, which no store ever sets.
const RESERVED_BIT: u64 = 1 << 60;
const _: () = assert!(RESERVED_BIT & CONTROL_MASK == 0);

/// A deadline 100 seconds into the engine's nanosecond timeline.
const DEADLINE: u64 = 100 * 1_000_000_000;

/// Positions of the `ready` index: `B + A` physical buckets of three pairs.
fn positions(storage: &Storage<TestPlatform>) -> usize {
    let shard = storage.index_geometry().unwrap().shards()[0];
    (shard.base + shard.overflow) * PAIRS
}

/// Runs funded close-service calls until one reports the pass complete,
/// at most 1024 of them, so a sweep that stops advancing fails the test.
fn service_all(storage: &Storage<TestPlatform>) -> Vec<ClosingReport> {
    let mut reports = Vec::new();
    for _ in 0..1024 {
        let report = storage.close_service(&mut WorkBudget::new(4096)).unwrap();
        let done = report.complete;
        reports.push(report);
        if done {
            return reports;
        }
    }
    panic!("close service made no progress");
}

/// A closed engine with a live registration and a live lease: repeated
/// funded calls remove every remaining mapping, the leased bytes stay
/// readable throughout, the reports' visit counts add up to the index's
/// positions exactly once, the blockers name the registration, the lease and
/// the held slot, and once both end, further calls return the blocks and
/// finalization drains with every extent released once.
#[test]
fn close_service_sweeps_around_a_live_registration_and_lease_then_finalization_drains() {
    let slot_count = 16;
    let limits = [8usize];
    let platform = TestPlatform::heap(PAGE);
    let log = platform.log();
    let mut storage = storage_with(slot_count, &index_config(&limits, (1, 1), 1), platform);
    let mapped = log.ranges(Op::Map);
    ticks(&storage, &[Some(1)]);
    let keys: Vec<_> = (0x10u8..0x16).map(key).collect();
    for k in &keys {
        publish(&storage, *k, DEADLINE, &body(k[0]));
    }
    let mut reader = storage.register().unwrap();
    let lease = lookup(&mut reader, &keys[2], RETRIES).unwrap();
    assert_eq!(
        storage.close_service(&mut WorkBudget::new(64)),
        Err(CloseError::Open)
    );
    storage.close();

    let reports = service_all(&storage);
    assert_eq!(reports[0].started_in, CloseStage::Index);
    let visited: usize = reports.iter().map(|r| r.positions_visited).sum();
    let removed: usize = reports.iter().map(|r| r.removed).sum();
    assert_eq!(visited, positions(&storage));
    assert_eq!(removed, keys.len());
    let last = reports.last().unwrap();
    assert!(last.complete);
    assert_eq!(last.blockers.registrations, 1);
    assert_eq!(last.blockers.leases, 1);
    assert!(last.blockers.held_slots >= 1, "{last:?}");
    assert_eq!(last.blockers.poisoned_gates, 0);
    // The lease reads through every pass, and no mapping was released.
    assert_eq!(hit_key(&lease), key(keys[2][0]));
    assert!(log.calls(Op::Unmap).is_empty());
    // A second pass finds nothing left in the index and the same blockers.
    let again = service_all(&storage);
    assert_eq!(again.iter().map(|r| r.removed).sum::<usize>(), 0);
    assert_eq!(again.last().unwrap().blockers.leases, 1);
    assert_eq!(hit_key(&lease), key(keys[2][0]));

    drop(lease);
    drop(reader);
    assert_eq!(reserved(&storage), 0);
    // With the owners gone, passes certify and return until nothing is held
    // or pending; the report never claims more than it saw.
    for _ in 0..4 {
        service_all(&storage);
    }
    let clear = service_all(&storage);
    let last = clear.last().unwrap();
    assert_eq!(last.blockers.registrations, 0);
    assert_eq!(last.blockers.leases, 0);
    assert_eq!(last.blockers.held_slots, 0);
    assert_eq!(last.blockers.pending_marks, 0);
    assert!(storage.outstanding().is_clear());

    assert_eq!(storage.phase(), Phase::Live);
    assert_eq!(finalize(&mut storage), Ok(Finalization::Drained));
    assert_eq!(storage.phase(), Phase::Drained);
    let mut expected = mapped;
    expected.reverse();
    assert_eq!(log.ranges(Op::Unmap), expected);
    assert_eq!(
        storage.close_service(&mut WorkBudget::new(64)),
        Err(CloseError::NotLive)
    );
}

/// Blockers taken one at a time are each named: a busy pool gate returns
/// without blocking, is counted, and leaves the pool's own cursor for the
/// next call while the stages after it run; a poisoned pool gate is counted;
/// an unfunded suffix stops at the stage boundary with the cursor resuming
/// there; a forgotten registration and a pending mark block finalization
/// without releasing an extent.
#[test]
fn each_blocker_alone_is_named_and_the_cursor_resumes() {
    // A busy gate: the call returns while another thread holds the pool.
    let storage = ready(8);
    ticks(&storage, &[Some(1)]);
    publish(&storage, key(0x21), DEADLINE, &body(0x21));
    storage.close();
    let held = Arc::new(Barrier::new(2));
    let released = Arc::new(Barrier::new(2));
    let report = std::thread::scope(|scope| {
        let (held_by, released_by) = (Arc::clone(&held), Arc::clone(&released));
        let storage = &storage;
        scope.spawn(move || {
            let access = storage.live_pool().unwrap().lock().unwrap();
            held_by.wait();
            released_by.wait();
            access.release();
        });
        held.wait();
        let report = storage.close_service(&mut WorkBudget::new(4096)).unwrap();
        released.wait();
        report
    });
    // The busy pool is counted, the stages after it still run, and the
    // call reports incomplete; the pool's own cursor waits for the next
    // call, which services it.
    assert!(!report.complete);
    assert_eq!(report.removed, 1);
    // Service found the one pool's gate busy; certification takes the
    // root's maintenance gate, which nothing held.
    assert_eq!(report.gates_busy, 1);
    assert_eq!(report.service_calls, 0);
    assert_eq!(report.records_visited, storage.registrations().len());
    let next = storage.close_service(&mut WorkBudget::new(4096)).unwrap();
    assert_eq!(next.started_in, CloseStage::Index);
    assert!(next.complete);
    assert!(next.service_calls >= 1);

    // A poisoned gate is counted and named, and the call still completes
    // the stages after it.
    let storage = ready(8);
    storage.close();
    std::thread::scope(|scope| {
        let handle = scope.spawn(|| {
            let _held = storage.live_pool().unwrap().lock().unwrap();
            panic!("poison the gate");
        });
        assert!(handle.join().is_err());
    });
    let report = storage.close_service(&mut WorkBudget::new(4096)).unwrap();
    // Service tries the one pool's gate once; certification's maintenance
    // gate is untouched; the status stage still runs, and the call is
    // incomplete.
    assert_eq!(report.blockers.poisoned_gates, 1);
    assert_eq!(report.service_calls, 0);
    assert_eq!(report.records_visited, storage.registrations().len());
    assert!(!report.complete);

    // An unfunded suffix: enough for the index stage's first positions only,
    // the cursor stays on the next position and the next call resumes there.
    let storage = ready(8);
    ticks(&storage, &[Some(1)]);
    publish(&storage, key(0x22), DEADLINE, &body(0x22));
    storage.close();
    // The cursor gate, then one run's gate attempt and three visits, or
    // fewer decided positions when the published key's removal falls inside
    // them and cannot be paid.
    let mut short = WorkBudget::new(1 + 1 + 3);
    let report = storage.close_service(&mut short).unwrap();
    assert!(report.budget_exhausted);
    assert!(!report.complete);
    assert!(report.positions_visited <= 3, "{report:?}");
    let rest = service_all(&storage);
    assert_eq!(rest[0].started_in, CloseStage::Index);
    // The rest decides each undecided position once, and the one mapping is
    // removed exactly once between the two.
    assert_eq!(
        rest.iter().map(|r| r.positions_visited).sum::<usize>(),
        positions(&storage) - report.positions_visited
    );
    assert_eq!(
        report.removed + rest.iter().map(|r| r.removed).sum::<usize>(),
        1
    );

    // A forgotten registration blocks finalization and touches no mapping.
    let slot_count = 8;
    let limits = [8usize];
    let platform = TestPlatform::heap(PAGE);
    let log = platform.log();
    let mut storage = storage_with(slot_count, &index_config(&limits, (1, 1), 1), platform);
    let forgotten = storage.register().unwrap();
    let index = forgotten.index();
    std::mem::forget(forgotten);
    let blockers = blocked(&mut storage);
    assert_eq!(blockers.registrations, 1);
    assert!(log.calls(Op::Unmap).is_empty());
    assert_eq!(storage.phase(), Phase::Live);
    // The blocked call closed admission; once the claim ends, it drains.
    assert!(storage.is_closed());
    storage.registrations()[index.0]
        .claimed
        .store(false, std::sync::atomic::Ordering::Release);
    assert_eq!(finalize(&mut storage), Ok(Finalization::Drained));

    // A pending mark blocks it too, until service discharges the mark.
    let platform = TestPlatform::heap(PAGE);
    let log = platform.log();
    let mut storage = storage_with(slot_count, &index_config(&limits, (1, 1), 1), platform);
    ticks(&storage, &[Some(1)]);
    let id = publish(&storage, key(0x23), DEADLINE, &body(0x23));
    storage.close();
    service_all(&storage);
    let _ = id;
    let blockers = blocked(&mut storage);
    assert!(blockers.pending >= 1, "{blockers:?}");
    assert!(log.calls(Op::Unmap).is_empty());
    for _ in 0..4 {
        service_all(&storage);
    }
    assert_eq!(finalize(&mut storage), Ok(Finalization::Drained));
}

/// Budgets of zero and of the first stage boundaries: zero visits nothing and
/// moves no cursor; a run of positions costs one gate attempt and one visit
/// per position; the observer counts no more primitives than the call
/// charged.
#[test]
fn close_service_budget_edges_stop_at_indivisible_actions() {
    let storage = ready(8);
    ticks(&storage, &[Some(1)]);
    publish(&storage, key(0x31), DEADLINE, &body(0x31));
    storage.close();
    let mut zero = WorkBudget::new(0);
    assert_eq!(
        storage.close_service(&mut zero),
        Err(CloseError::BudgetExhausted)
    );
    // One unit pays the cursor gate's attempt and nothing after it.
    let one = {
        let mut one = WorkBudget::new(1);
        let report = storage.close_service(&mut one).unwrap();
        assert!(report.budget_exhausted);
        assert_eq!(report.positions_visited, 0);
        assert_eq!(one.remaining(), 0);
        report
    };
    assert_eq!(one.started_in, CloseStage::Index);
    // Three units: the cursor gate, then one run's gate attempt and first
    // visit; the position is decided unless it holds the mapping, whose
    // removal the rest cannot pay.
    let mut three = WorkBudget::new(3);
    let report = storage.close_service(&mut three).unwrap();
    assert!(report.positions_visited <= 1, "{report:?}");
    assert_eq!(three.remaining(), 0);
    let decided = report.positions_visited;
    // A funded call from here: primitives within the charge in total.
    let mut spent = WorkBudget::new(4096);
    probe::arm();
    let report = storage.close_service(&mut spent).unwrap();
    probe::disarm();
    let counts = probe::counts();
    let charged = spent.counters();
    let total_charged = charged.comparisons
        + charged.coordination_attempts
        + charged.visits
        + charged.updates
        + charged.hashes;
    let total_observed =
        counts.loads + counts.stores + counts.cas + counts.rmws + counts.gate_attempts();
    assert!(
        total_observed <= total_charged,
        "{counts:?} over {charged:?}"
    );
    assert!(report.complete, "{report:?}");
    assert_eq!(report.positions_visited, positions(&storage) - decided);
    assert_eq!(report.removed, 1);
}

/// An empty shard is swept in one run: the cursor gate, one shard gate
/// attempt and one visit per position decide every position, and the call
/// stops at the pool stage with nothing left to pay.
#[test]
fn an_empty_shard_is_decided_under_one_gate_attempt() {
    let storage = ready(8);
    storage.close();
    let all = positions(&storage);
    let mut exact = WorkBudget::new(1 + 1 + all);
    let report = storage.close_service(&mut exact).unwrap();
    assert_eq!(report.positions_visited, all);
    assert!(report.budget_exhausted);
    assert_eq!(report.service_calls, 0);
    assert_eq!(exact.remaining(), 0);
    assert_eq!(exact.counters().coordination_attempts, 2);
    assert_eq!(exact.counters().visits, all);
    // The next call starts at the pool stage.
    let next = storage.close_service(&mut WorkBudget::new(4096)).unwrap();
    assert_eq!(next.started_in, CloseStage::Volume);
    assert_eq!(next.positions_visited, 0);
}

/// A closed engine whose every slot holds an eligible retired record, with
/// its index stage done, so its next close-service call runs the volume
/// stage.
fn retired_volume(slots: usize) -> Storage<TestPlatform> {
    let storage = ready(slots);
    for _ in 0..slots {
        drop(
            storage
                .reserve(Some(1), Some(1), &mut WorkBudget::new(1 << 10))
                .unwrap(),
        );
    }
    let ledger = storage.pool_report().unwrap().ledger.unwrap();
    assert_eq!(ledger.slots.retired, slots);
    storage.close();
    let all = positions(&storage);
    storage
        .close_service(&mut WorkBudget::new(1 + 1 + all))
        .unwrap();
    storage
}

/// The steps one unbounded service call spends on `storage`, measured by
/// running it: a twin built the same way spends the same in its volume
/// stage, since every probe, bundle and return visit follows from the
/// identical history.
fn service_spend(storage: &Storage<TestPlatform>) -> usize {
    let mut spent = WorkBudget::new(1 << 20);
    let report = storage.service(&mut spent).unwrap();
    assert!(!report.budget_exhausted, "{report:?}");
    (1 << 20) - spent.remaining()
}

/// Calls funded at the service minimum cover 24 retired slots in several
/// calls, each resuming both pass cursors where the last left them, and
/// together visit every retired slot exactly once before the stage ends.
#[test]
fn a_pool_pass_spread_over_calls_still_ends_the_pool_stage() {
    let storage = retired_volume(24);
    let per_call = 1 + storage.service_minimum() + 1;
    let (mut visited, mut calls) = (0, 0);
    loop {
        let report = storage
            .close_service(&mut WorkBudget::new(per_call))
            .unwrap();
        assert_eq!(report.started_in, CloseStage::Volume, "{report:?}");
        calls += 1;
        visited += report.slots_visited;
        if !report.budget_exhausted {
            break;
        }
        assert!(calls < 24, "the volume stage made no progress");
    }
    assert!(calls > 1, "{calls}");
    assert_eq!(visited, 24);
    let ledger = storage.pool_report().unwrap().ledger.unwrap();
    assert_eq!(ledger.slots.free, 24);
}

/// A removal runs under the hold that found its pair: when the allowance
/// pays the visit that finds it but not the removal's hash passes, the pair
/// stays undecided and the hold is released, so the next call finds the gate
/// open and stops at the same pair, and a funded call removes it.
#[test]
fn an_unpaid_removal_releases_the_hold_and_leaves_the_pair_undecided() {
    let storage = ready(8);
    ticks(&storage, &[Some(1)]);
    publish(&storage, key(0x41), DEADLINE, &body(0x41));
    storage.close();
    let all = positions(&storage);
    // The cursor gate, one run's attempt and one visit per call: each call
    // decides one empty position, until the one that stops at the pair.
    let mut decided = 0;
    let stopped = loop {
        let report = storage.close_service(&mut WorkBudget::new(3)).unwrap();
        assert!(report.budget_exhausted, "{report:?}");
        assert_eq!(report.shards_busy, 0);
        assert_eq!(report.removed, 0);
        if report.positions_visited == 0 {
            break report;
        }
        decided += report.positions_visited;
        assert!(decided < all, "the pair was never reached");
    };
    assert_eq!(stopped.started_in, CloseStage::Index);
    // Again: the gate is open, and the same pair stops the call.
    let again = storage.close_service(&mut WorkBudget::new(3)).unwrap();
    assert_eq!((again.shards_busy, again.positions_visited), (0, 0));
    // Funded: the pair is removed and every other position decided once.
    let rest = service_all(&storage);
    assert_eq!(rest.iter().map(|r| r.removed).sum::<usize>(), 1);
    assert_eq!(
        decided + rest.iter().map(|r| r.positions_visited).sum::<usize>(),
        all
    );
}

/// One caller at a time: a second call while the cursor is held is refused
/// without moving anything.
#[test]
fn a_concurrent_close_service_call_is_refused() {
    let storage = ready(8);
    storage.close();
    let guard = storage.close.gate.try_lock().unwrap();
    assert_eq!(
        storage.close_service(&mut WorkBudget::new(64)),
        Err(CloseError::Contended)
    );
    guard.release();
    assert!(
        storage
            .close_service(&mut WorkBudget::new(4096))
            .unwrap()
            .complete
    );
}

/// A rejected unmap in the middle of the order leaves that extent retained
/// and the later ones released once, reports closing, and a later call
/// retries nothing.
#[test]
fn a_rejected_unmap_is_retained_once_and_later_extents_still_release() {
    let slot_count = 8;
    let limits = [8usize];
    let platform = TestPlatform::heap(PAGE);
    let log = platform.log();
    platform.fail_at(super::test_platform::Fail {
        op: Op::Unmap,
        ordinal: 2,
        code: super::os::OsCode(16),
        region: None,
    });
    let mut storage = storage_with(slot_count, &index_config(&limits, (1, 1), 1), platform);
    let mapped = log.ranges(Op::Map);
    assert_eq!(mapped.len(), 3);
    assert_eq!(
        finalize(&mut storage),
        Ok(Finalization::Closing(Progress {
            released: 2,
            retained: 1,
            remaining: 0
        }))
    );
    let retained: Vec<_> = storage.retained().collect();
    assert_eq!(retained.len(), 1);
    assert_eq!((retained[0].base, retained[0].len), mapped[1]);
    let mut expected = mapped;
    expected.reverse();
    assert_eq!(log.ranges(Op::Unmap), expected);
    let calls = log.all().len();
    assert!(matches!(
        finalize(&mut storage),
        Ok(Finalization::Closing(_))
    ));
    assert_eq!(log.all().len(), calls);
    assert_eq!(storage.phase(), Phase::Finalizing);
    assert_eq!(
        storage.finalize(&mut WorkBudget::new(0)),
        Ok(Finalization::Closing(Progress {
            released: 2,
            retained: 1,
            remaining: 0
        }))
    );
    drop(storage);
    assert_eq!(log.all().len(), calls);
}

/// A malformed control found by the sweep poisons the shard's gate and is
/// counted as a blocker: a reserved bit in a bucket's control word. The sweep
/// never advances past it, so the call is incomplete and finalization
/// refuses the poison rather than draining over corrupt tables.
#[test]
fn a_malformed_control_poisons_the_shard_during_the_sweep() {
    let slot_count = 8;
    let limits = [8usize];
    let config = index_config(&limits, (1, 1), 1);
    let storage = storage(slot_count, &config);
    ticks(&storage, &[Some(1)]);
    publish(&storage, key(0x31), DEADLINE, &body(0x31));
    let index = storage.index.as_ref().unwrap();
    let shard = index.image.shard(ShardIndex(0)).unwrap();
    // SAFETY: the index mapping is live and nothing else holds the gate.
    let base = &unsafe { shard.tables(&index.mapping) }.buckets[0];
    base.corrupt(base.control() | RESERVED_BIT, base.next());
    storage.close();
    let report = storage.close_service(&mut WorkBudget::new(4096)).unwrap();
    assert_eq!(report.blockers.poisoned_gates, 1, "{config:?}");
    assert!(!report.complete, "{config:?}");
    assert_eq!(report.removed, 0, "{config:?}");
    // The malformed position was read and decided: it is counted.
    assert_eq!(report.positions_visited, 1, "{config:?}");
    // SAFETY: as above.
    assert!(unsafe { shard.gate(&index.mapping) }.try_lock().is_err());
    // The next call finds the shard poisoned and counts it again.
    let next = storage.close_service(&mut WorkBudget::new(4096)).unwrap();
    assert_eq!(next.blockers.poisoned_gates, 1, "{config:?}");
}

/// An occupied pair that names no anchored slot is corruption, as it is to
/// the gate holders comparing keys: the sweep poisons the shard, counts the
/// blocker and decides nothing past it.
#[test]
fn an_occupied_pair_without_an_anchor_poisons_the_shard_during_the_sweep() {
    let slot_count = 8;
    let limits = [8usize];
    let config = index_config(&limits, (1, 1), 1);
    let storage = storage(slot_count, &config);
    ticks(&storage, &[Some(1)]);
    let id = publish(&storage, key(0x32), DEADLINE, &body(0x32));
    // The test plants a pair whose anchor is gone.
    storage.live_pool().unwrap().set_refs(id.slot_index(), 0);
    storage.close();
    let report = storage.close_service(&mut WorkBudget::new(4096)).unwrap();
    assert_eq!(report.blockers.poisoned_gates, 1, "{config:?}");
    assert_eq!(report.removed, 0, "{config:?}");
    assert!(!report.complete, "{config:?}");
    let index = storage.index.as_ref().unwrap();
    let shard = index.image.shard(ShardIndex(0)).unwrap();
    // SAFETY: the index mapping is live.
    assert!(unsafe { shard.gate(&index.mapping) }.try_lock().is_err());
}

/// The pool stage ends only after one contiguous traversal by the close
/// service itself. An ordinary service call between two budget-split close
/// calls moves the pool's shared cursor past a slot; the close service
/// notices the cursor did not resume where its own pass left it and starts
/// its count over, so the held slot the other call passed is still counted.
#[test]
fn an_interleaved_service_call_does_not_complete_the_close_pass_for_it() {
    let storage = ready(8);
    ticks(&storage, &[Some(1)]);
    let ids: Vec<_> = (0x41u8..0x45)
        .map(|n| publish(&storage, key(n), DEADLINE, &body(n)))
        .collect();
    // The lease holds slot 3 through every pass below.
    let leased = ids.iter().position(|id| id.slot_index() == 3).unwrap();
    let mut reader = storage.register().unwrap();
    let lease = lookup(&mut reader, &key(0x41 + leased as u8), RETRIES).unwrap();
    storage.close();
    // Pass one removes every mapping and certifies; the pool cursor returns
    // to slot 0.
    let first = service_all(&storage);
    assert!(first.last().unwrap().complete);
    // Pass two: the index stage exactly, then the pool stage in calls that
    // fund the cursor gate and the service minimum. The retired pass reads
    // summary word 0 and bitmap word 0, then decides slots from that word
    // while its allowance covers a bundle and the extent work bound: the
    // first call returns slots 0, 1 and 2 and stops in front of flagged
    // slot 3, whose decision it cannot fund.
    let all = positions(&storage);
    let report = storage
        .close_service(&mut WorkBudget::new(1 + 1 + all))
        .unwrap();
    assert!(report.budget_exhausted, "{report:?}");
    let call = 1 + storage.service_minimum();
    let report = storage.close_service(&mut WorkBudget::new(call)).unwrap();
    assert_eq!(report.started_in, CloseStage::Volume, "{report:?}");
    assert_eq!((report.slots_visited, report.blockers.held_slots), (3, 0));
    // Another caller's call starts at slot 3 and finds it held; the return
    // bound it funded and did not spend carries it past further slots.
    let outside = storage
        .service(&mut WorkBudget::new(storage.service_minimum()))
        .unwrap();
    assert_eq!((outside.first, outside.held), (3, 1), "{outside:?}");
    // The close service finishes its own pass over every slot.
    let mut held = 0;
    let mut visited = 3;
    loop {
        let report = storage.close_service(&mut WorkBudget::new(call)).unwrap();
        if report.started_in != CloseStage::Volume {
            break;
        }
        held += report.blockers.held_slots;
        visited += report.slots_visited;
        assert!(visited <= 12, "{report:?}");
    }
    assert_eq!(held, 1);
    drop(lease);
    drop(reader);
}

/// An occupied pair the routed walk cannot find again is corruption: the
/// sweep read it under the hold the removal runs under, so nothing removed
/// it in between. A pair whose stored tag disagrees with its key's is such
/// a pair; the sweep poisons the shard rather than leave the pair
/// and its anchor behind.
#[test]
fn an_occupied_pair_the_walk_cannot_find_poisons_the_shard_during_the_sweep() {
    let slot_count = 8;
    let limits = [8usize];
    let config = index_config(&limits, (1, 1), 1);
    let storage = storage(slot_count, &config);
    ticks(&storage, &[Some(1)]);
    let id = publish(&storage, key(0x33), DEADLINE, &body(0x33));
    let route = storage.route(&key(0x33)).unwrap();
    let index = storage.index.as_ref().unwrap();
    let shard = index.image.shard(ShardIndex(0)).unwrap();
    // SAFETY: the index mapping is live and nothing else holds the gate.
    let bucket = &unsafe { shard.tables(&index.mapping) }.buckets[route.bucket()];
    let pair = (0..PAIRS)
        .find(|pair| is_occupied(bucket.control(), *pair))
        .unwrap();
    bucket.publish_pair(pair, bucket.control(), route.tag() ^ 1, id);
    storage.close();
    let report = storage.close_service(&mut WorkBudget::new(4096)).unwrap();
    assert_eq!(report.blockers.poisoned_gates, 1, "{config:?}");
    assert_eq!(report.removed, 0, "{config:?}");
    assert!(!report.complete, "{config:?}");
    // SAFETY: the index mapping is live.
    assert!(unsafe { shard.gate(&index.mapping) }.try_lock().is_err());
}

/// A pair under the key's own tag whose incarnation differs from the slot's
/// current one is found by the routed walk and refused by the sweep's own
/// resolve: the sweep poisons the shard, removes nothing, and the object's
/// anchor stays counted.
#[test]
fn a_found_pair_naming_another_incarnation_poisons_the_shard_during_the_sweep() {
    let slot_count = 8;
    let limits = [8usize];
    let config = index_config(&limits, (1, 1), 1);
    let storage = storage(slot_count, &config);
    ticks(&storage, &[Some(1)]);
    let id = publish(&storage, key(0x34), DEADLINE, &body(0x34));
    let route = storage.route(&key(0x34)).unwrap();
    let index = storage.index.as_ref().unwrap();
    let shard = index.image.shard(ShardIndex(0)).unwrap();
    // SAFETY: the index mapping is live and nothing else holds the gate.
    let bucket = &unsafe { shard.tables(&index.mapping) }.buckets[route.bucket()];
    let pair = (0..PAIRS)
        .find(|pair| is_occupied(bucket.control(), *pair))
        .unwrap();
    let other = super::AllocationId::new(id.slot(), id.incarnation() + 1);
    bucket.publish_pair(pair, bucket.control(), route.tag(), other);
    storage.close();
    let report = storage.close_service(&mut WorkBudget::new(4096)).unwrap();
    assert_eq!(report.blockers.poisoned_gates, 1, "{config:?}");
    assert_eq!(report.removed, 0, "{config:?}");
    assert!(!report.complete, "{config:?}");
    // SAFETY: the index mapping is live.
    assert!(unsafe { shard.gate(&index.mapping) }.try_lock().is_err());
    assert_eq!(storage.live_pool().unwrap().refs(id.slot_index()), 1);
}

/// The groups of a table whose extent work bound equals `groups - 1`, the
/// probes a retired pass makes after visiting held slots of bitmap word 0:
/// summary word 0 marks no other word, so one summary word per later group.
/// The bound grows with the slot count, so the count is found by
/// iteration.
fn held_volume_groups() -> usize {
    let mut groups = 100;
    for _ in 0..8 {
        let bound = held_volume_storage(groups)
            .pool_report()
            .unwrap()
            .extent_bound;
        if bound == groups - 1 {
            return groups;
        }
        groups = bound + 1;
    }
    panic!("no group count matches its extent work bound");
}

fn held_volume_storage(groups: usize) -> Storage<TestPlatform> {
    let config = super::config::StorageConfig {
        engine_budget: 1 << 27,
        lease_limit: 64,
        ..super::publish_tests::storage_config(groups * super::pending::GROUP_SLOTS)
    };
    super::publish_tests::storage_from(
        &config,
        &index_config(&[64], (1, 1), 1),
        TestPlatform::heap(PAGE),
    )
}

/// One volume-stage call on a closed engine whose retired pass, from slot
/// 0, reads summary word 0 and bitmap word 0, visits held retired slots of
/// that word and then reads summary words to the end of its lap, with the
/// cursor gate, the service spend and `extra` steps: the report, the steps
/// left and the next call's report. The held slots' leases keep each visit
/// a bundle with no return, and their count lifts the spend to the service
/// minimum; after the last visit the bound it checked pays exactly the
/// remaining probes.
fn held_volume_stage(groups: usize, extra: usize) -> (ClosingReport, usize, ClosingReport) {
    let storage = held_volume_storage(groups);
    let bound = storage.pool_report().unwrap().extent_bound;
    let held =
        (storage.service_minimum() - SERVICE_CONTROLS - 2 - bound).div_ceil(SERVICE_PER_SLOT);
    assert!((1..=64).contains(&held), "{held}");
    let mut leases = Vec::new();
    for n in 0..held {
        let completed = super::publish_tests::completed(&storage, key(n as u8 + 1));
        let (resident, lease) = completed
            .handoff(&mut WorkBudget::new(1 << 10))
            .ok()
            .unwrap();
        assert!(resident.id().slot_index() < 64);
        drop(resident);
        leases.push(lease);
    }
    storage.close();
    let all = positions(&storage);
    storage
        .close_service(&mut WorkBudget::new(1 + 1 + all))
        .unwrap();
    let spend = SERVICE_CONTROLS + 2 + held * SERVICE_PER_SLOT + bound;
    assert!(spend >= storage.service_minimum());
    let mut allowance = WorkBudget::new(1 + spend + extra);
    let report = storage.close_service(&mut allowance).unwrap();
    let next = storage.close_service(&mut WorkBudget::new(4096)).unwrap();
    drop(leases);
    (report, allowance.remaining(), next)
}

/// A pool pass ends with one observation of the pool's pending marks, and
/// that observation is a paid step: an allowance that pays the cursor gate
/// and the service call's whole spend covers every position and stops
/// short of the read, which the next call makes; one step more completes
/// the stage in one call.
#[test]
fn a_pool_pass_pays_for_its_blocker_observation() {
    let groups = held_volume_groups();
    let (short, left, next) = held_volume_stage(groups, 0);
    assert_eq!(short.started_in, CloseStage::Volume, "{short:?}");
    assert!(short.budget_exhausted && !short.complete, "{short:?}");
    assert!(short.blockers.held_slots > 0, "{short:?}");
    assert_eq!(left, 0);
    assert_eq!(next.started_in, CloseStage::Volume, "{next:?}");
    assert_eq!(next.slots_visited, 0, "{next:?}");
    let (exact, left, next) = held_volume_stage(groups, 1);
    assert_eq!(exact.started_in, CloseStage::Volume, "{exact:?}");
    assert_eq!(left, 0);
    assert_eq!(next.started_in, CloseStage::Certify, "{next:?}");
}

/// One funded call completes a pool pass over eight retired slots: both
/// service passes cover every position, every slot is visited and returned
/// once, the pass ends with its one blocker observation, and the next call
/// starts at the following stage.
#[test]
fn one_funded_call_completes_a_pool_pass_over_retired_slots() {
    let storage = retired_volume(8);
    let report = storage
        .close_service(&mut WorkBudget::new(1 << 20))
        .unwrap();
    assert_eq!(report.started_in, CloseStage::Volume, "{report:?}");
    assert_eq!(
        (report.slots_visited, report.serviced),
        (8, 8),
        "{report:?}"
    );
    assert_eq!(report.blockers.pending_marks, 0, "{report:?}");
    assert!(report.complete, "{report:?}");
}

/// A pool pass split over calls credits each call's coverage to both pass
/// counts: a call funded at the service minimum covers a prefix and leaves
/// the stage on the pool, a resumed funded call visits exactly the slots
/// the first left, and the call after it starts at certification.
#[test]
fn a_split_pool_pass_resumes_both_passes_and_ends_the_stage() {
    let storage = retired_volume(24);
    let first = storage
        .close_service(&mut WorkBudget::new(1 + storage.service_minimum()))
        .unwrap();
    assert_eq!(first.started_in, CloseStage::Volume, "{first:?}");
    assert!(
        first.budget_exhausted && first.slots_visited < 24,
        "{first:?}"
    );
    let funded =
        1 + service_spend(&{
            let twin = retired_volume(24);
            twin.close_service(&mut WorkBudget::new(1 + twin.service_minimum()))
                .unwrap();
            twin
        }) + storage.service_minimum();
    let mut allowance = WorkBudget::new(funded);
    let second = storage.close_service(&mut allowance).unwrap();
    assert_eq!(
        (
            second.started_in,
            first.slots_visited + second.slots_visited
        ),
        (CloseStage::Volume, 24)
    );
    // The volume stage ended in the second call: the call after it starts
    // at certification, or the second call completed the close pass too.
    let next = storage.close_service(&mut WorkBudget::new(4096)).unwrap();
    assert!(
        second.complete || next.started_in == CloseStage::Certify,
        "{second:?} then {next:?}"
    );
}

/// The first volume-stage call completes the retired pass. Later calls
/// finish the park pass; each held retired slot is visited once per stage.
#[test]
fn a_completed_retired_pass_is_not_walked_again_while_the_park_pass_finishes() {
    const HELD: usize = 4;
    const PARKED: usize = 8;
    let storage = held_volume_storage(1);
    let bound = storage.pool_report().unwrap().extent_bound;
    // Leases hold these retired slots through every visit.
    let leases: Vec<_> = (0..HELD)
        .map(|n| {
            let completed = super::publish_tests::completed(&storage, key(n as u8 + 1));
            let (resident, lease) = completed
                .handoff(&mut WorkBudget::new(1 << 10))
                .ok()
                .unwrap();
            drop(resident);
            lease
        })
        .collect();
    // A filling owner dropped under a held pool gate parks its obligation.
    for _ in 0..PARKED {
        let owner = storage
            .reserve(Some(1), Some(1), &mut WorkBudget::new(1 << 10))
            .unwrap();
        let held = storage.live_pool().unwrap().lock().unwrap();
        drop(owner);
        drop(held);
    }
    storage.close();
    let all = positions(&storage);
    storage
        .close_service(&mut WorkBudget::new(1 + 1 + all))
        .unwrap();
    let per_call = 1
        + SERVICE_CONTROLS
        + 2 * RETIRED_PROBE
        + HELD * SERVICE_PER_SLOT
        + bound
        + 2 * PARKED_PROBE
        + SERVICE_PER_SLOT
        + bound;
    assert!(per_call > storage.service_minimum());
    let (mut calls, mut visited, mut held, mut serviced) = (0, 0, 0, 0);
    loop {
        let report = storage
            .close_service(&mut WorkBudget::new(per_call))
            .unwrap();
        if report.started_in != CloseStage::Volume {
            break;
        }
        calls += 1;
        visited += report.slots_visited;
        held += report.blockers.held_slots;
        serviced += report.serviced;
        assert!(calls <= 2 * PARKED, "the volume stage made no progress");
    }
    assert!(calls > 1, "{calls}");
    assert_eq!((visited, held, serviced), (HELD + PARKED, HELD, PARKED));
    drop(leases);
}

/// The inspection's lease count is one paid step for one load: the idle
/// credits it subtracts were read with each record's visit, so the step
/// count bounds the loads whatever the reader limit.
#[test]
fn the_lease_count_step_reads_one_word() {
    let mut storage = ready(8);
    let records = storage.registrations().len();
    let mut spent = WorkBudget::new(records + 1);
    probe::arm();
    let outcome = storage.finalize(&mut spent);
    probe::disarm();
    let counts = probe::counts();
    assert_eq!(outcome, Err(FinalizeError::BudgetExhausted));
    assert_eq!(spent.remaining(), 0);
    assert!(
        counts.loads <= spent.counters().comparisons,
        "{counts:?} over {:?}",
        spent.counters()
    );
}

/// Finalization refuses a poisoned gate explicitly and never drains over it.
#[test]
fn a_poisoned_gate_fails_finalization_explicitly() {
    let mut storage = ready(8);
    std::thread::scope(|scope| {
        let handle = scope.spawn(|| {
            let _held = storage.live_pool().unwrap().lock().unwrap();
            panic!("poison the gate");
        });
        assert!(handle.join().is_err());
    });
    assert_eq!(finalize(&mut storage), Err(FinalizeError::Poisoned));
    assert_eq!(storage.phase(), Phase::Live);
}

/// Every shared accessor refuses or returns nothing once finalization has
/// begun: with one extent released and the rest owned, each report is
/// `None`, the outstanding sample is empty, each maintenance call refuses,
/// and no mapping is read.
#[test]
fn every_shared_accessor_refuses_while_finalizing() {
    use super::release::ServiceError;
    use super::tables::SlotIndex;
    let slot_count = 8;
    let limits = [8usize];
    let platform = TestPlatform::heap(PAGE);
    let log = platform.log();
    let mut storage = storage_with(slot_count, &index_config(&limits, (1, 1), 1), platform);
    ticks(&storage, &[Some(1)]);
    let id = publish(&storage, key(0x41), DEADLINE, &body(0x41));
    storage.close();
    for _ in 0..6 {
        service_all(&storage);
    }
    // The inspection, then exactly one release: the index.
    let inspection = storage.registrations().len() + 1 + 1 + 8;
    assert!(matches!(
        storage.finalize(&mut WorkBudget::new(inspection + 1)),
        Ok(Finalization::Closing(Progress { released: 1, .. }))
    ));
    assert_eq!(storage.phase(), Phase::Finalizing);
    assert_eq!(log.ranges(Op::Unmap).len(), 1);
    let calls = log.all().len();

    assert!(storage.root_descriptor().is_none());
    assert!(storage.pool_report().is_none());
    assert!(storage.root_placement().is_none());
    assert!(storage.slot_state(SlotIndex(0)).is_none());
    assert!(storage.table_inventory().is_none());
    assert!(storage.index_extent().is_none());
    assert!(storage.index_geometry().is_none());
    assert!(storage.route(&key(0x41)).is_none());
    assert!(storage.shard_report(crate::index::ShardIndex(0)).is_none());
    assert!(storage.lease_report().is_none());
    assert!(storage.era_report().is_none());
    assert!(
        storage
            .registration_report(super::RegistrationIndex(0))
            .is_none()
    );
    assert!(!storage.is_closed());
    assert!(!storage.is_issued());
    assert!(!storage.identity_is_current(id));
    assert!(storage.outstanding().is_clear());
    assert!(storage.register().is_err());
    assert!(storage.issue_cache().is_err());
    assert_eq!(
        storage.service(&mut WorkBudget::new(64)),
        Err(ServiceError::TornDown)
    );
    assert!(storage.certify(&mut WorkBudget::new(64)).is_err());
    assert!(
        storage
            .invalidate(&key(0x41), 1, &mut WorkBudget::new(64))
            .is_err()
    );
    assert!(
        storage
            .remove(&key(0x41), id, 1, &mut WorkBudget::new(64))
            .is_err()
    );
    assert!(
        storage
            .reserve(Some(4), Some(20), &mut WorkBudget::new(64))
            .is_err()
    );
    assert_eq!(
        storage.close_service(&mut WorkBudget::new(64)),
        Err(CloseError::NotLive)
    );
    assert_eq!(log.all().len(), calls);
    assert_eq!(finalize(&mut storage), Ok(Finalization::Drained));
}

/// A busy shard gate during the index stage: the position is not decided,
/// the shard and position cursor stay for the next call, the stages after
/// the index still run, and the next call decides the position once.
#[test]
fn a_busy_shard_gate_leaves_the_position_for_the_next_call() {
    let storage = ready(8);
    ticks(&storage, &[Some(1)]);
    publish(&storage, key(0x51), DEADLINE, &body(0x51));
    storage.close();
    let held = Arc::new(Barrier::new(2));
    let released = Arc::new(Barrier::new(2));
    let report = std::thread::scope(|scope| {
        let (held_by, released_by) = (Arc::clone(&held), Arc::clone(&released));
        let storage = &storage;
        scope.spawn(move || {
            let index = storage.index().unwrap();
            let shard = index.image.shard(crate::index::ShardIndex(0)).unwrap();
            // SAFETY: the index mapping is owned while the storage is live,
            // which the shared borrow this thread holds guarantees.
            let gate = unsafe { shard.gate(&index.mapping) };
            let guard = gate.try_lock().unwrap();
            held_by.wait();
            released_by.wait();
            guard.release();
        });
        held.wait();
        let report = storage.close_service(&mut WorkBudget::new(4096)).unwrap();
        released.wait();
        report
    });
    assert!(!report.complete);
    assert_eq!(report.shards_busy, 1);
    assert_eq!(report.positions_visited, 0);
    assert_eq!(report.removed, 0);
    assert!(report.service_calls >= 1);
    assert_eq!(report.records_visited, storage.registrations().len());
    let rest = service_all(&storage);
    assert_eq!(
        rest.iter().map(|r| r.positions_visited).sum::<usize>(),
        positions(&storage)
    );
    assert_eq!(rest.iter().map(|r| r.removed).sum::<usize>(), 1);
}

/// A refused release with extents still remaining: the call reports closing
/// with the remainder, the retained extent is never retried, and the later
/// extents release exactly once across the calls that follow.
#[test]
fn a_retained_extent_with_extents_remaining_resumes_past_it() {
    let slot_count = 8;
    let limits = [8usize];
    let platform = TestPlatform::heap(PAGE);
    let log = platform.log();
    platform.fail_at(super::test_platform::Fail {
        op: Op::Unmap,
        ordinal: 1,
        code: super::os::OsCode(16),
        region: None,
    });
    let mut storage = storage_with(slot_count, &index_config(&limits, (1, 1), 1), platform);
    let mapped = log.ranges(Op::Map);
    let inspection = storage.registrations().len() + 1 + 1 + 8;
    assert_eq!(
        storage.finalize(&mut WorkBudget::new(inspection + 1)),
        Ok(Finalization::Closing(Progress {
            released: 0,
            retained: 1,
            remaining: 2
        }))
    );
    assert_eq!(storage.phase(), Phase::Finalizing);
    assert_eq!(log.ranges(Op::Unmap), vec![mapped[2]]);
    assert_eq!(
        storage.finalize(&mut WorkBudget::new(0)),
        Err(FinalizeError::BudgetExhausted)
    );
    assert_eq!(
        storage.finalize(&mut WorkBudget::new(1)),
        Ok(Finalization::Closing(Progress {
            released: 1,
            retained: 1,
            remaining: 1
        }))
    );
    assert_eq!(
        storage.finalize(&mut WorkBudget::new(1)),
        Ok(Finalization::Closing(Progress {
            released: 2,
            retained: 1,
            remaining: 0
        }))
    );
    let mut expected = mapped;
    expected.reverse();
    assert_eq!(log.ranges(Op::Unmap), expected);
    assert_eq!(storage.retained().count(), 1);
    drop(storage);
}

/// "A gate a panicking call poisoned refuses `Poisoned` from then on": a
/// close-service call whose volume stage panics on a malformed parked word
/// leaves the cursor's gate poisoned, and the next call is refused
/// `Poisoned`, charged its one attempt, with no cursor moved. The call is
/// made on a plain thread, and from a destructor that catches the panic on
/// a thread already unwinding from an unrelated one.
#[test]
fn a_call_that_panics_poisons_the_cursor_gate_also_during_unwinding() {
    use std::sync::atomic::Ordering;

    use super::gate::GateError;
    use super::word::{ABANDONED, ANCHORED, REF};

    fn call(storage: &Storage<TestPlatform>) {
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = storage.close_service(&mut WorkBudget::new(1 << 20));
        }));
        assert!(panicked.is_err(), "the volume stage panics");
    }
    struct CallOnDrop<'a>(&'a Storage<TestPlatform>);
    impl Drop for CallOnDrop<'_> {
        fn drop(&mut self) {
            assert!(std::thread::panicking());
            call(self.0);
        }
    }

    for unwinding in [false, true] {
        let storage = ready(8);
        let id = publish(&storage, key(0x68), DEADLINE, &body(0x68));
        let live = storage.live_pool().unwrap();
        let slot = id.slot_index();
        live.records()[slot].stamp_era(u64::MAX);
        live.telemetry()
            .pending_marks
            .fetch_add(1, Ordering::Relaxed);
        live.edit_word(slot, |word| (word | ABANDONED | ANCHORED) - REF);
        live.mark_parked_slot(slot);
        storage.close();

        if unwinding {
            let outer = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _call = CallOnDrop(&storage);
                panic!("an unrelated panic");
            }));
            assert!(outer.is_err());
        } else {
            call(&storage);
        }

        let words = storage.close.words();
        assert_eq!(
            storage.close.gate.try_lock().map(|hold| hold.release()),
            Err(GateError::Poisoned),
            "unwinding {unwinding}: the cursor's gate after the call's panic"
        );
        let mut refused = WorkBudget::new(4096);
        assert_eq!(
            storage.close_service(&mut refused),
            Err(CloseError::Poisoned),
            "unwinding {unwinding}"
        );
        assert_eq!(refused.remaining(), 4095);
        assert_eq!(storage.close.words(), words);
    }
}
