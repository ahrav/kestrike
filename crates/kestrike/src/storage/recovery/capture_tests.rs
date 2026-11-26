//! Capture passes on a live storage: snapshot membership at `t0` across publications and removals, the side list, the load guard over the drained entries, and the policy's triggers.

use super::super::extent::ExtentLocator;
use super::super::owner::Storage;
use super::super::publish_tests::{TRIES, budget, completed, index_config, key, storage};
use super::super::test_platform::TestPlatform;
use super::capture_trace::{CaptureOracle, CaptureTrace, TraceEvent};
use super::*;

pub(crate) fn entry(slot: usize, incarnation: u32, start: u64) -> CaptureEntry {
    let mut key = [0; 32];
    key[..8].copy_from_slice(&(slot as u64).to_le_bytes());
    CaptureEntry {
        key,
        allocation: (slot as u64) << 32 | u64::from(incarnation),
        session: 2,
        version: 1,
        deadline_ns: 0,
        lifetime_ms: 0,
        tail: 0,
        extents: vec![ExtentLocator::new(start, 1).unwrap().bits()],
    }
}
pub(crate) fn observed_completed(
    s: &Storage<TestPlatform>,
    key: [u8; 32],
) -> (super::super::Completed<'_, TestPlatform>, CaptureEntry) {
    let mut allocation = s.reserve(Some(4), Some(20), &mut budget()).unwrap();
    let expected = CaptureEntry {
        key,
        allocation: allocation.id().record_tag(),
        session: super::super::volume_fixture::SESSION,
        version: 0,
        deadline_ns: 0,
        lifetime_ms: 0,
        tail: (allocation.layout().record().record_len() % super::super::IO_UNIT as u64) as u16,
        extents: vec![allocation.locator().bits()],
    };
    allocation.mark_written();
    let bound = allocation
        .complete(key, u64::MAX, &mut budget())
        .ok()
        .unwrap();
    (bound, expected)
}
fn side(entries: usize) -> SideCap {
    SideCap {
        entries,
        words: usize::MAX,
    }
}
pub(crate) fn limits() -> LoadLimits {
    LoadLimits {
        payload_start: 0,
        payload_end: 100,
        reserve_units: 1,
        slot_count: 8,
        n_max: 8,
        record_chunk_len: 8192,
    }
}
pub(crate) fn drain(s: &Storage<TestPlatform>) -> Vec<CaptureEntry> {
    let counter = s.pool().capture_lock().unwrap().counter();
    let mut entries = Vec::new();
    for _ in 0..s.pool().records().len() {
        if let Some(e) = s.capture_next(counter).unwrap() {
            entries.push(e);
        }
    }
    entries.extend(s.capture_saved(counter).unwrap());
    entries
}
/// When a snapshot member is removed before the cursor reaches it, the checkpoint preserves its pre-removal ownership and disjoint member extents across unit reuse and reload.
#[test]
fn removed_entry_unit_reuse_crash() {
    let source_records = "EX-SA-8, EX-RR-3 to EX-RR-7, EX-IV-3";
    let s = storage(4, &index_config(&[4], (1, 1), 2));
    let (bound, kept) = observed_completed(&s, key(3));
    bound.publish(TRIES, &mut budget()).unwrap();
    let (bound, before) = observed_completed(&s, key(1));
    let a = bound.publish(TRIES, &mut budget()).unwrap();
    s.start_capture(4, true, 4).unwrap();
    s.remove(&key(1), a, TRIES, &mut budget()).unwrap();
    let _ = s.certify(&mut budget()).unwrap();
    for _ in 0..4 {
        s.service(&mut budget()).unwrap();
    }
    let (bound, after) = observed_completed(&s, key(2));
    bound.publish(TRIES, &mut budget()).unwrap();
    assert_eq!(
        before.extents, after.extents,
        "{source_records}: unit reuse"
    );
    let mut captured = drain(&s);
    captured.sort_by_key(CaptureEntry::slot);
    let mut expected = vec![before, kept];
    expected.sort_by_key(CaptureEntry::slot);
    assert_eq!(captured, expected, "{source_records}");
    assert_ne!(captured[0].extents, captured[1].extents);
    let encoded = serde_json::to_vec(&captured).unwrap();
    let recovered: Vec<CaptureEntry> = serde_json::from_slice(&encoded).unwrap();
    let GuardedLoad::Warm(loaded) = guarded_load(recovered, limits(), &engine()) else {
        panic!("{source_records}: a consistent checkpoint loads warm");
    };
    assert_eq!(loaded, captured, "{source_records}");
}
#[test]
fn load_guard_refuses_at_the_slot_count_and_below_the_payload_start() {
    let lim = limits();
    let last = entry(lim.slot_count - 1, 1, 0);
    assert_eq!(load_guard(&[last], lim, &engine()), Ok(()));
    let past = entry(lim.slot_count, 1, 0);
    assert_eq!(load_guard(&[past], lim, &engine()), Err(LoadRefusal::Slot));
    let mut shifted = lim;
    shifted.payload_start = 1;
    assert_eq!(load_guard(&[entry(0, 1, 1)], shifted, &engine()), Ok(()));
    assert_eq!(
        load_guard(&[entry(0, 1, 0)], shifted, &engine()),
        Err(LoadRefusal::Bounds)
    );
    let full: Vec<_> = (0..lim.n_max)
        .map(|slot| entry(slot, 1, slot as u64))
        .collect();
    assert_eq!(load_guard(&full, lim, &engine()), Ok(()));
}
#[test]
fn bind_capture_publish_scan_excludes_post_start_insert() {
    let s = storage(4, &index_config(&[4], (1, 1), 2));
    let bound = completed(&s, key(1));
    s.start_capture(4, true, 4).unwrap();
    bound.publish(TRIES, &mut budget()).unwrap();
    assert!(drain(&s).is_empty());
    finish(&s, 1).unwrap();
    s.start_capture(4, true, 4).unwrap();
    assert_eq!(drain(&s).len(), 1);
}
#[test]
fn production_bind_capture_publish_scan_excludes_unfinished_fill() {
    use super::super::publication::AFTER_BIND;
    use super::super::publication_tests::{DEADLINE, filled, ready_with};
    use super::super::volume_fixture::{Device, arena};
    use std::sync::Arc;
    let s = Arc::new(ready_with(2, 16, 8));
    let buffers = arena();
    let mut device = Device::new(&s, &buffers);
    let fill = filled(&s, &mut device, &key(1), &[7; 20]);
    let captured = Arc::clone(&s);
    AFTER_BIND.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            captured.start_capture(8, true, 8).unwrap();
        }))
    });
    let lease = fill
        .publish(&mut device.volume, DEADLINE, TRIES, &mut budget())
        .unwrap();
    assert!(drain(&s).is_empty());
    finish(&s, 1).unwrap();
    s.start_capture(8, true, 8).unwrap();
    let checkpoint = drain(&s);
    assert_eq!(checkpoint.len(), 1);
    assert_eq!(checkpoint[0].allocation, lease.id().record_tag());
}

std::thread_local! {
    static RELEASE_CAPTURE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[test]
fn production_fill_publishes_past_a_capture_hold_during_preparation() {
    use super::super::publication::INTERPOSE_BEFORE_INHIBITION;
    use super::super::publication_tests::{DEADLINE, filled, ready_with};
    use super::super::volume_fixture::{Device, arena};
    use std::sync::mpsc::channel;
    // The interposition waits for the holder thread to release the capture mutex before publication resumes.
    fn release(_: &std::sync::atomic::AtomicBool) {
        RELEASE_CAPTURE.with(|hook| hook.borrow_mut().take().unwrap()());
    }
    let s = ready_with(2, 16, 8);
    let buffers = arena();
    let mut device = Device::new(&s, &buffers);
    let fill = filled(&s, &mut device, &key(1), &[7; 20]);
    let (held_tx, held_rx) = channel();
    let (release_tx, release_rx) = channel::<()>();
    let (released_tx, released_rx) = channel();
    let holder = &s;
    std::thread::scope(|scope| {
        scope.spawn(move || {
            let hold = holder.pool().capture_lock().unwrap();
            held_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            drop(hold);
            released_tx.send(()).unwrap();
        });
        held_rx.recv().unwrap();
        RELEASE_CAPTURE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                release_tx.send(()).unwrap();
                released_rx.recv().unwrap();
            }));
        });
        INTERPOSE_BEFORE_INHIBITION.with(|hook| hook.set(Some(release)));
        let published = fill.publish(&mut device.volume, DEADLINE, TRIES, &mut budget());
        INTERPOSE_BEFORE_INHIBITION.with(|hook| hook.set(None));
        let pending = RELEASE_CAPTURE.with(|hook| hook.borrow_mut().take());
        let interposed = pending.is_none();
        if let Some(release) = pending {
            release();
        }
        let lease = published.unwrap();
        assert!(interposed);
        s.start_capture(8, true, 8).unwrap();
        let checkpoint = drain(&s);
        assert_eq!(checkpoint.len(), 1);
        assert_eq!(checkpoint[0].allocation, lease.id().record_tag());
    });
}

/// A fill whose publication finds the capture mutex held makes `tries` attempts on it, each debited as one coordination attempt beside the shard gate's, before refusing `Contended`.
/// The refusal retires the fill's slot with `ABANDONED`, the tables pass the conservation judge, and one service pass frees the slot.
#[test]
fn production_fill_spends_its_tries_on_a_held_capture_mutex() {
    use super::super::claim_exit_tests::{FREE, RETIRED, conserved_after_service, conserved_at};
    use super::super::publication::FillPublishError;
    use super::super::publication_tests::{DEADLINE, filled, ready_with};
    use super::super::volume_fixture::{Device, arena};
    let s = ready_with(2, 16, 8);
    let buffers = arena();
    let mut device = Device::new(&s, &buffers);
    let held = s.pool().capture_lock().unwrap();
    let mut attempts = |key, tries| {
        let fill = filled(&s, &mut device, &key, &[7; 20]);
        let slot = fill.id().slot_index();
        let mut work = budget();
        assert_eq!(
            fill.publish(&mut device.volume, DEADLINE, tries, &mut work)
                .err(),
            Some(FillPublishError::Contended)
        );
        conserved_at(&s, slot, RETIRED);
        conserved_after_service(&s, slot, FREE);
        work.counters().coordination_attempts
    };
    let one = attempts(key(1), 1);
    let three = attempts(key(2), 3);
    assert_eq!(
        (one, three),
        (3, 5),
        "premise: one bind and one shard gate attempt beside the mutex's tries"
    );
    drop(held);
}

#[test]
fn production_capture_preserves_nonzero_publication_metadata() {
    use super::super::portable::scripted::ScriptedClock;
    use super::super::publication_tests::{payload, ready_with};
    use super::super::volume_fixture::{Device, arena_with};
    use super::super::{CacheVersion, IO_UNIT, TEST_CLOCK};

    let s = ready_with(2, 16, 8);
    assert_eq!(s.clock, TEST_CLOCK);
    let second = 1_000_000_000u64;
    s.platform.ticks(&[Some(5 * second)]);
    let buffers = arena_with(4, 5);
    let (clock, script) = ScriptedClock::with_script();
    let earliest = 1_700_000_000_000_000_000;
    script.trusted(earliest, earliest + 2_000_000);
    let session = crate::storage::upcoming_session();
    assert_ne!(session, 0);
    let mut device = Device::clocked(&s, &buffers, clock);
    assert_eq!(device.volume.session(), session);
    let k = key(1);
    let version = CacheVersion(7);
    let mut fill = super::super::writable_tests::reserve_at(&s, &k, version, 4, 20).unwrap();
    let id = fill.id();
    let expected = CaptureEntry {
        key: k,
        allocation: id.record_tag(),
        session,
        version: version.0,
        deadline_ns: earliest + 10 * second,
        lifetime_ms: 10_000,
        tail: (fill.layout().record().record_len() % IO_UNIT as u64) as u16,
        extents: vec![s.pool().records()[id.slot_index()].locator().bits()],
    };
    device.fill(&mut fill, &payload(&k, &[7; 20]));
    let lease = fill
        .publish(&mut device.volume, 15 * second, TRIES, &mut budget())
        .unwrap();
    assert_eq!(lease.id(), id);
    s.start_capture(8, true, 8).unwrap();
    let captured = drain(&s);
    assert_eq!(captured, vec![expected.clone()]);
    let recovered: Vec<CaptureEntry> =
        serde_json::from_slice(&serde_json::to_vec(&captured).unwrap()).unwrap();
    assert_eq!(recovered, vec![expected]);
}

#[test]
fn post_start_membership_changes_on_another_thread_keep_the_t0_snapshot() {
    use std::sync::Barrier;
    let s = storage(8, &index_config(&[8], (1, 1), 2));
    let prior = completed(&s, key(1)).publish(TRIES, &mut budget()).unwrap();
    let barrier = Barrier::new(2);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let bound = completed(&s, key(2));
            barrier.wait();
            barrier.wait();
            bound.publish(TRIES, &mut budget()).unwrap();
            s.remove(&key(1), prior, TRIES, &mut budget()).unwrap();
            barrier.wait();
        });
        barrier.wait();
        s.start_capture(8, true, 8).unwrap();
        barrier.wait();
        barrier.wait();
        let captured = drain(&s);
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].allocation, prior.record_tag());
    });
}
#[test]
fn membership_contention_refuses_without_changing_cursor_or_index() {
    let s = storage(4, &index_config(&[4], (1, 1), 2));
    let a = completed(&s, key(1)).publish(TRIES, &mut budget()).unwrap();
    s.start_capture(4, true, 4).unwrap();
    let access = s.pool().try_lock().unwrap();
    assert_eq!(s.capture_next(1), Err(CaptureError::Unavailable));
    assert_eq!(
        s.remove(&key(1), a, TRIES, &mut budget()),
        Err(super::super::remove::RemoveError::Contended)
    );
    s.platform.ticks(&[Some(1)]);
    let mut reader = s.register().unwrap();
    let observed = reader.lookup(&key(1), TRIES, &mut budget()).unwrap();
    assert_eq!(observed.id(), a);
    drop(observed);
    drop(reader);
    access.release();
    assert_eq!(drain(&s).len(), 1);
}
#[test]
fn parked_candidate_keeps_units_until_capture_hook_runs() {
    let s = storage(4, &index_config(&[4], (1, 1), 2));
    let bound = completed(&s, key(1));
    let id = bound.id();
    let (resident, lease) = bound.handoff(&mut budget()).ok().unwrap();
    drop(lease);
    {
        let capture = s.pool().capture_lock().unwrap();
        s.pool().capture_insert(&capture, id.slot_index());
    }
    s.start_capture(4, true, 4).unwrap();
    let hold = s.pool().capture_lock().unwrap();
    assert_eq!(resident.retire(), super::super::RetireOutcome::Parked);
    let before = s.pool_report().unwrap().ledger.unwrap().raw.free;
    let _ = s.certify(&mut budget()).unwrap();
    s.service(&mut budget()).unwrap();
    assert_eq!(s.pool_report().unwrap().ledger.unwrap().raw.free, before);
    drop(hold);
    for _ in 0..4 {
        s.service(&mut budget()).unwrap();
    }
    assert!(s.pool_report().unwrap().ledger.unwrap().raw.free > before);
    let captured = drain(&s);
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].allocation, id.record_tag());
}

#[test]
fn overflow_prevents_the_next_real_submission() {
    use std::cell::Cell;
    let s = storage(4, &index_config(&[4], (1, 1), 2));
    let ids: Vec<_> = (0..3)
        .map(|n| completed(&s, key(n)).publish(TRIES, &mut budget()).unwrap())
        .collect();
    s.start_capture(4, true, 1).unwrap();
    assert!(s.capture_next(1).unwrap().is_some());
    let submissions = Cell::new(0);
    s.submit_capture_unit(1, || submissions.set(submissions.get() + 1))
        .unwrap();
    for (n, &id) in ids.iter().enumerate().skip(1) {
        s.remove(&key(n as u8), id, TRIES, &mut budget()).unwrap();
    }
    assert_eq!(
        s.submit_capture_unit(1, || submissions.set(submissions.get() + 1)),
        Err(CaptureError::Abandoned)
    );
    assert_eq!(submissions.get(), 1);
}

#[test]
fn side_list_overflow_abandons() {
    let mut c = Capture::default();
    c.start((3, CaptureEpoch::default()), 4, 3, 4, true, side(1))
        .unwrap();
    assert!(c.visit(0, Some((1, entry(0, 1, 0)))).unwrap().is_some());
    c.removed(2, entry(1, 1, 1));
    assert_eq!(c.side_len(), Ok(1));
    assert_eq!(c.submission_allowed(), Ok(()));
    c.removed(3, entry(2, 1, 2));
    assert_eq!(c.visit(1, None), Err(CaptureError::Abandoned));
    assert_eq!(c.take_saved(), Err(CaptureError::Abandoned));
    assert_eq!(c.submission_allowed(), Err(CaptureError::Abandoned));
    assert_eq!(c.finish(), vec![entry(1, 1, 1)]);
    assert_eq!(c.submission_allowed(), Err(CaptureError::Idle));
}
/// A saved removal whose extent words would exceed `extent_words` abandons the pass while the entry count is still under `q_cap`.
#[test]
fn a_removal_past_the_side_list_word_capacity_abandons_the_pass() {
    use super::super::publish_tests::{PAGE, storage_config, storage_from};
    let mut cfg = storage_config(4);
    cfg.volume = crate::storage::test_volume(512 * super::super::IO_UNIT, 4);
    cfg.volume.block_roots = 1;
    cfg.body_cap = 200_000;
    let s = storage_from(
        &cfg,
        &index_config(&[4], (1, 1), 2),
        super::super::test_platform::TestPlatform::heap(PAGE),
    );
    let long = completed(&s, key(1)).publish(TRIES, &mut budget()).unwrap();
    super::super::sequence_tests::published_sequence(&s, long, 3);
    let mut capture = config();
    capture.n_max = 2;
    capture.slot_bound = 4;
    capture.q_cap = 2;
    capture.extent_words = 2;
    let mut policy = CapturePolicy::new(capture, 0, &mut engine()).unwrap();
    policy.changed_bytes(capture.byte_trigger);
    let started = s
        .try_start_capture(&mut policy, 0, false, false, true)
        .unwrap()
        .unwrap();
    s.remove(&key(1), long, TRIES, &mut budget()).unwrap();
    assert_eq!(
        s.capture_visit(started.counter, 4, |_| {}),
        Err(CaptureError::Abandoned)
    );
    assert_eq!(
        s.capture_saved(started.counter),
        Err(CaptureError::Abandoned)
    );
}
#[test]
fn checkpoint_counter_refuses_at_limit() {
    let source_record = "EX-RD-4";
    let mut c = super::capture::Capture::at_counter((1 << 32) - 3);
    assert_eq!(
        c.start((0, CaptureEpoch::default()), 4, 0, 4, true, side(1)),
        Ok(u32::MAX - 1),
        "{source_record}"
    );
    drop(c.finish());
    assert_eq!(
        c.start((0, CaptureEpoch::default()), 4, 0, 4, true, side(1)),
        Ok(u32::MAX),
        "{source_record}"
    );
    drop(c.finish());
    assert_eq!(
        c.start((0, CaptureEpoch::default()), 4, 0, 4, true, side(1)),
        Err(CaptureError::CounterExhausted),
        "{source_record}"
    );
    assert_eq!(c.submission_allowed(), Err(CaptureError::Idle));
    assert_eq!(c.counter(), u32::MAX);
    assert_eq!(
        Capture::default().start((0, CaptureEpoch::default()), 4, 0, 4, false, side(1)),
        Err(CaptureError::NoFreeCheckpointSlot)
    );
    assert_eq!(
        Capture::default().start((0, CaptureEpoch::default()), 4, 5, 4, true, side(1)),
        Err(CaptureError::TooManyEntries)
    );
}
fn engine() -> super::super::ledger::EngineBudget {
    super::super::ledger::EngineBudget::unlimited()
}
pub(crate) fn finish(s: &Storage<TestPlatform>, counter: u32) -> Result<(), CaptureError> {
    let mut policy = CapturePolicy::new(config(), 0, &mut engine()).unwrap();
    policy.started(0).unwrap();
    s.finish_capture(&mut policy, counter)
}
fn config() -> CaptureConfig {
    CaptureConfig {
        n_max: 65536,
        slot_bound: 65536,
        byte_trigger: 100,
        time_ceiling_ns: 1000,
        paced_unit_ns: 31_269_544,
        fast_unit_ns: 625_391,
        decision_ns: 1_000_000,
        max_removals_per_second: 3000,
        q_cap: 16_000,
        extent_words: 65536,
    }
}
#[test]
fn q_cap_rule_survives_paced_burst() {
    let cfg = config();
    let mut policy = CapturePolicy::new(cfg, 0, &mut engine()).unwrap();
    policy.started(0).unwrap();
    let mut selected = Capture::default();
    selected
        .start(
            (65536, CaptureEpoch::default()),
            65536,
            65536,
            65536,
            true,
            side(cfg.q_cap),
        )
        .unwrap();
    let mut fixed = Capture::default();
    fixed
        .start(
            (65536, CaptureEpoch::default()),
            65536,
            65536,
            65536,
            true,
            side(3000),
        )
        .unwrap();
    let mut cursor = 0;
    let mut present = vec![true; 65536];
    let mut fixed_cursor = 0;
    let mut fixed_next = 0;
    let mut visits = 0.0;
    for tick in 0..50001u64 {
        let now = tick * 1_000_000;
        while fixed_cursor < 65536 && fixed.submission_allowed().is_ok() && now >= fixed_next {
            fixed_next += cfg.paced_unit_ns;
            for _ in 0..41 {
                if fixed_cursor == 65536 {
                    break;
                }
                fixed
                    .visit(
                        fixed_cursor,
                        present[fixed_cursor].then(|| {
                            (
                                fixed_cursor as u64 + 1,
                                entry(fixed_cursor, 1, fixed_cursor as u64),
                            )
                        }),
                    )
                    .unwrap();
                fixed_cursor += 1;
            }
        }
        while policy.unit_due(now, selected.side_len().unwrap_or(0)) {
            policy.submitted(now).unwrap();
            visits += 41.0;
        }
        while visits >= 1.0 && cursor < 65536 {
            selected
                .visit(
                    cursor,
                    present[cursor].then(|| (cursor as u64 + 1, entry(cursor, 1, cursor as u64))),
                )
                .unwrap();
            cursor += 1;
            visits -= 1.0;
        }
        for _ in 0..3 {
            if let Some(victim) = (cursor..present.len()).find(|&slot| present[slot]) {
                present[victim] = false;
                selected.removed(victim as u64 + 1, entry(victim, 1, victim as u64));
                fixed.removed(victim as u64 + 1, entry(victim, 1, victim as u64));
            }
        }
        assert!(selected.submission_allowed().is_ok());
        if cursor == 65536 {
            break;
        }
    }
    assert_eq!(cursor, 65536);
    assert!(fixed_cursor > 0 && fixed_cursor < 65536);
    assert_eq!(fixed.submission_allowed(), Err(CaptureError::Abandoned));
    let mut invalid = cfg;
    invalid.q_cap = 1;
    assert!(CapturePolicy::new(invalid, 0, &mut engine()).is_err());
}
#[test]
fn stale_capture_handles_cannot_mix_snapshots_or_submit_units() {
    use std::cell::Cell;
    let s = storage(4, &index_config(&[4], (1, 1), 2));
    completed(&s, key(1)).publish(TRIES, &mut budget()).unwrap();
    let mut p = CapturePolicy::new(
        CaptureConfig {
            n_max: 4,
            slot_bound: 4,
            byte_trigger: 1,
            time_ceiling_ns: 1000,
            paced_unit_ns: 50,
            fast_unit_ns: 1,
            decision_ns: 1_000_000,
            max_removals_per_second: 3000,
            q_cap: 4,
            extent_words: 4,
        },
        0,
        &mut engine(),
    )
    .unwrap();
    p.changed_bytes(1);
    assert_eq!(
        s.try_start_capture(&mut p, 0, false, false, false),
        Err(CaptureError::NoFreeCheckpointSlot)
    );
    assert!(p.due(0, false, false));
    let first = s
        .try_start_capture(&mut p, 0, false, false, true)
        .unwrap()
        .unwrap();
    assert_eq!((first.counter, first.t0), (1, 1));
    finish(&s, first.counter).unwrap();
    p.finished();
    p.changed_bytes(1);
    let second = s
        .try_start_capture(&mut p, 1, false, false, true)
        .unwrap()
        .unwrap();
    assert_eq!((second.counter, second.t0), (2, 1));
    let called = Cell::new(false);
    assert_eq!(s.capture_next(first.counter), Err(CaptureError::Superseded));
    assert_eq!(
        s.capture_side_len(first.counter),
        Err(CaptureError::Superseded)
    );
    let capture = s.pool().capture_lock().unwrap();
    assert_eq!(
        s.capture_side_len(second.counter),
        Err(CaptureError::Unavailable)
    );
    drop(capture);
    assert_eq!(s.capture_side_len(second.counter), Ok(0));
    assert_eq!(
        s.submit_capture_unit(first.counter, || called.set(true)),
        Err(CaptureError::Superseded)
    );
    assert_eq!(finish(&s, first.counter), Err(CaptureError::Superseded));
    assert!(!called.get());
    assert_eq!(drain(&s).len(), 1);
}

#[test]
fn capture_triggers() {
    let cfg = config();
    let mut p = CapturePolicy::new(cfg, 0, &mut engine()).unwrap();
    assert!(!p.due(0, false, false));
    p.changed_bytes(99);
    assert!(!p.due(0, false, false));
    p.changed_bytes(1);
    assert!(p.due(0, false, false));
    p.started(500).unwrap();
    assert!(!p.due(10000, true, true));
    assert_eq!(p.started(1), Err(CaptureError::InFlight));
    p.finished();
    assert!(!p.due(500, false, false));
    assert!(!p.due(1499, false, false));
    assert!(p.due(1500, false, false));
    let p = CapturePolicy::new(cfg, 0, &mut engine()).unwrap();
    assert!(!p.due(0, true, false));
    assert!(p.due(0, true, true));
}
#[test]
fn load_guard_refuses() {
    let a = entry(0, 1, 0);
    let b = entry(1, 1, 1);
    for fault in 0..6 {
        let mut entries = vec![a.clone(), b.clone()];
        let mut lim = limits();
        let expected = match fault {
            0 => {
                entries[1].extents = entries[0].extents.clone();
                LoadRefusal::Overlap
            }
            1 => {
                entries[1].key = entries[0].key;
                LoadRefusal::Key
            }
            2 => {
                entries[1].allocation = entries[0].allocation;
                LoadRefusal::Slot
            }
            3 => {
                lim.reserve_units = 99;
                LoadRefusal::Units
            }
            4 => {
                entries[1].extents = vec![ExtentLocator::new(100, 1).unwrap().bits()];
                LoadRefusal::Bounds
            }
            _ => {
                lim.n_max = 1;
                LoadRefusal::Entries
            }
        };
        assert_eq!(load_guard(&entries, lim, &engine()), Err(expected));
        let loaded = guarded_load(entries, lim, &engine());
        assert!(matches!(loaded, GuardedLoad::Cold { .. }));
        let events: Vec<_> = loaded.events().collect();
        assert_eq!(events.len(), 3);
        assert!(events[..2].iter().all(|e| matches!(
            e,
            LoadEvent::Evict {
                cause: EvictCause::Refused,
                ..
            }
        )));
        assert_eq!(events[2], LoadEvent::Alarm { refusal: expected });
    }
}

pub(crate) fn recorded(seed: u64) -> CaptureTrace {
    use super::super::seeded::SplitMix64;
    use super::super::tables::SlotState;
    use std::collections::BTreeMap;
    use std::sync::atomic::Ordering;
    let mut s = storage(16, &index_config(&[16], (1, 1), 2));
    let mut events = Vec::new();
    let mut live = BTreeMap::new();
    let observe_insert = |id: super::super::AllocationId, entry| TraceEvent::Insert {
        step: s.pool().steps()[id.slot_index()].load(std::sync::atomic::Ordering::Relaxed),
        entry,
    };
    for n in 0..4 {
        let k = key(n);
        let (bound, expected) = observed_completed(&s, k);
        let id = bound.publish(TRIES, &mut budget()).unwrap();
        events.push(observe_insert(id, expected));
        live.insert(id.slot_index(), (k, id));
    }
    let raw = s.pool_report().unwrap().ledger.unwrap().raw;
    let payload_units = ((raw.total().unwrap() - raw.metadata) / super::super::IO_UNIT) as u64;
    s.start_capture(16, true, 16).unwrap();
    events.push(TraceEvent::Start {
        t0: s.pool().insert_step.load(Ordering::Relaxed),
    });
    let mut rng = SplitMix64::new(seed);
    let mut output = Vec::new();
    for turn in 0..16 {
        let changes = rng.below(3);
        for change in 0..changes {
            let position = rng.below(live.len() as u64) as usize;
            let slot = *live.keys().nth(position).unwrap();
            let (k, id) = live.remove(&slot).unwrap();
            s.remove(&k, id, TRIES, &mut budget()).unwrap();
            events.push(TraceEvent::Remove {
                allocation: id.record_tag(),
            });
            let _ = s.certify(&mut budget()).unwrap();
            s.service(&mut budget()).unwrap();
            let k = key(10 + (turn * 3 + change) as u8);
            let (bound, expected) = observed_completed(&s, k);
            let id = bound.publish(TRIES, &mut budget()).unwrap();
            events.push(observe_insert(id, expected));
            live.insert(id.slot_index(), (k, id));
        }
        if let Some(entry) = s.capture_next(1).unwrap() {
            output.push(entry.clone());
            events.push(TraceEvent::Emit { entry });
        }
        let mut owners = Vec::new();
        let mut access = s.pool().try_lock().unwrap();
        let mut tables = access.tables();
        for slot in 0..16 {
            if matches!(
                s.pool().gate_state(slot).0,
                SlotState::Resident | SlotState::Retired | SlotState::Filling
            ) {
                owners.push(s.pool().capture_entry(&mut tables, slot).unwrap().extents);
            }
        }
        access.release();
        let raw = s.pool_report().unwrap().ledger.unwrap().raw;
        events.push(TraceEvent::Ledger {
            free: (raw.free / super::super::IO_UNIT) as u64,
            reported_owned: ((raw.reserved + raw.resident + raw.retired + raw.waste)
                / super::super::IO_UNIT) as u64,
            owners,
        });
    }
    for entry in s.capture_saved(1).unwrap() {
        output.push(entry.clone());
        events.push(TraceEvent::Emit { entry });
    }
    events.push(TraceEvent::Complete);
    let record = serde_json::to_vec(&output).unwrap();
    let decoded: Vec<CaptureEntry> = serde_json::from_slice(&record).unwrap();
    let limit = LoadLimits {
        payload_start: 0,
        payload_end: payload_units,
        reserve_units: 1,
        slot_count: 16,
        n_max: 16,
        record_chunk_len: super::super::publish_tests::storage_config(16)
            .volume
            .record
            .chunk_len,
    };
    let loaded = guarded_load(decoded, limit, &engine());
    let load_events = loaded.events().collect();
    let admitted = match loaded {
        GuardedLoad::Warm(entries) => entries,
        GuardedLoad::Cold { .. } => Vec::new(),
    };
    events.push(TraceEvent::Load {
        limits: limit,
        entries: admitted,
        events: load_events,
    });
    finish(&s, 1).unwrap();
    let _ = super::super::test_platform::finalize(&mut s).unwrap();
    CaptureTrace {
        payload_units,
        events,
    }
}
pub(crate) const ORACLES: [CaptureOracle; 4] = [
    CaptureOracle::CaptureConsistent,
    CaptureOracle::UnitsExclusive,
    CaptureOracle::LedgerConserved,
    CaptureOracle::LoadGuardNeverFires,
];
pub(crate) fn mutate(trace: &mut CaptureTrace, oracle: CaptureOracle) {
    match oracle {
        CaptureOracle::CaptureConsistent => {
            trace
                .events
                .retain(|e| !matches!(e,TraceEvent::Emit {entry} if entry.slot()==0));
        }
        CaptureOracle::UnitsExclusive => {
            for e in &mut trace.events {
                if let TraceEvent::Ledger { owners, .. } = e {
                    owners[1] = owners[0].clone();
                }
            }
        }
        CaptureOracle::LedgerConserved => {
            for e in &mut trace.events {
                if let TraceEvent::Ledger { free, .. } = e {
                    *free += 1;
                }
            }
        }
        CaptureOracle::LoadGuardNeverFires => {
            for e in &mut trace.events {
                if let TraceEvent::Load { events, .. } = e {
                    events.push(LoadEvent::Alarm {
                        refusal: LoadRefusal::Overlap,
                    });
                }
            }
        }
    }
}

fn rejected_live_and_reloaded(trace: &CaptureTrace, oracle: CaptureOracle) {
    assert!(!oracle.judge(trace));
    let reload = serde_json::from_slice(&serde_json::to_vec(trace).unwrap()).unwrap();
    assert!(!oracle.judge(&reload));
}
#[test]
fn independent_metadata_observations_reject_captured_corruption() {
    let baseline = recorded(17);
    for (field, recovered) in (0..4).flat_map(|field| [(field, false), (field, true)]) {
        let mut corrupt = baseline.clone();
        let damage = |entry: &mut CaptureEntry| match field {
            0 => entry.session += 1,
            1 => entry.version += 1,
            2 => entry.deadline_ns += 1,
            _ => entry.lifetime_ms += 1,
        };
        for event in &mut corrupt.events {
            match event {
                TraceEvent::Emit { entry } if !recovered => damage(entry),
                TraceEvent::Load { entries, .. } if recovered => {
                    entries.iter_mut().for_each(damage)
                }
                _ => {}
            }
        }
        let inserts = |trace: &CaptureTrace| {
            serde_json::to_vec(
                &trace
                    .events
                    .iter()
                    .filter(|e| matches!(e, TraceEvent::Insert { .. }))
                    .collect::<Vec<_>>(),
            )
            .unwrap()
        };
        assert_eq!(inserts(&baseline), inserts(&corrupt));
        rejected_live_and_reloaded(&corrupt, CaptureOracle::CaptureConsistent);
    }
}
#[test]
fn allocation_owner_alias_preserves_totals_and_fails_exclusivity() {
    let mut corrupt = recorded(17);
    mutate(&mut corrupt, CaptureOracle::UnitsExclusive);
    assert!(CaptureOracle::LedgerConserved.judge(&corrupt));
    rejected_live_and_reloaded(&corrupt, CaptureOracle::UnitsExclusive);
}
#[test]
fn recorded_load_limits_reject_lower_bound_and_entry_limit() {
    let baseline = recorded(17);
    for entries_limit in [false, true] {
        let mut corrupt = baseline.clone();
        for event in &mut corrupt.events {
            if let TraceEvent::Load {
                limits, entries, ..
            } = event
            {
                if entries_limit {
                    limits.n_max = entries.len() - 1;
                } else {
                    limits.payload_start = entries
                        .iter()
                        .flat_map(|e| &e.extents)
                        .map(|&bits| ExtentLocator::from_bits(bits).start_unit())
                        .min()
                        .unwrap()
                        + 1;
                }
            }
        }
        rejected_live_and_reloaded(&corrupt, CaptureOracle::LoadGuardNeverFires);
    }
}

#[test]
fn sparse_slot_walk_sizes_reserve_and_storage_refuses_short_bound() {
    let mut cfg = config();
    cfg.n_max = 4096;
    cfg.slot_bound = 8192;
    cfg.q_cap = 384;
    assert!(matches!(
        CapturePolicy::new(cfg, 0, &mut engine()),
        Err(CaptureError::InvalidConfig)
    ));
    cfg.q_cap = 2_200;
    let mut policy = CapturePolicy::new(cfg, 0, &mut engine()).unwrap();
    policy.started(0).unwrap();
    let mut capture = Capture::default();
    capture
        .start(
            (8192, CaptureEpoch::default()),
            8192,
            4096,
            4096,
            true,
            side(cfg.q_cap),
        )
        .unwrap();
    let (mut cursor, mut emitted) = (0, 0);
    let mut present: Vec<bool> = (0..8192).map(|slot| slot >= 4096).collect();
    for tick in 0..10000 {
        for _ in 0..3 {
            if let Some(victim) = (cursor..8192).find(|&slot| present[slot]) {
                present[victim] = false;
                capture.removed(victim as u64 + 1, entry(victim, 1, victim as u64));
            }
        }
        let now = tick * 1_000_000;
        while cursor < 8192 && policy.unit_due(now, capture.side_len().unwrap_or(0)) {
            policy.submitted(now).unwrap();
            for _ in 0..41 {
                if cursor == 8192 {
                    break;
                }
                emitted += usize::from(
                    capture
                        .visit(
                            cursor,
                            present[cursor]
                                .then(|| (cursor as u64 + 1, entry(cursor, 1, cursor as u64))),
                        )
                        .unwrap()
                        .is_some(),
                );
                cursor += 1;
            }
        }
        assert!(capture.submission_allowed().is_ok());
        if cursor == 8192 {
            break;
        }
    }
    assert_eq!(cursor, 8192);
    assert_eq!(emitted + capture.take_saved().unwrap().len(), 4096);
    let s = storage(8, &index_config(&[8], (1, 1), 2));
    cfg.slot_bound = 4;
    let mut policy = CapturePolicy::new(cfg, 0, &mut engine()).unwrap();
    policy.changed_bytes(cfg.byte_trigger);
    assert_eq!(
        s.try_start_capture(&mut policy, 0, false, false, true),
        Err(CaptureError::SlotBoundExceeded)
    );
    assert!(policy.due(0, false, false));
    assert_eq!(s.pool().capture_lock().unwrap().counter(), 0);
    cfg.slot_bound = 8;
    let mut policy = CapturePolicy::new(cfg, 0, &mut engine()).unwrap();
    policy.changed_bytes(cfg.byte_trigger);
    assert!(matches!(
        s.try_start_capture(&mut policy, 0, false, false, true),
        Ok(Some(_))
    ));
}

#[test]
fn capture_policy_charges_maximum_extent_bytes_before_admission() {
    let mut cfg = config();
    let limit = super::super::geometry::EXTENT_LIMIT as usize;
    let entries = cfg.q_cap + 2;
    let bytes = std::mem::size_of::<CaptureEntry>() * entries + 8 * (cfg.extent_words + 2 * limit);
    let mut short = super::super::ledger::EngineBudget::new(bytes - 1);
    assert!(matches!(
        CapturePolicy::new(cfg, 0, &mut short),
        Err(CaptureError::Memory(_))
    ));
    assert_eq!(short.used(), 0);
    let mut exact = super::super::ledger::EngineBudget::new(bytes);
    let mut p = CapturePolicy::new(cfg, 0, &mut exact).unwrap();
    assert_eq!(exact.used(), bytes);
    p.started(0).unwrap();
    p.finished();
    p.started(1).unwrap();
    assert_eq!(exact.used(), bytes);
    cfg.extent_words = usize::MAX;
    let mut wide = super::super::ledger::EngineBudget::unlimited();
    CapturePolicy::new(cfg, 0, &mut wide).unwrap();
    assert_eq!(
        wide.used(),
        (std::mem::size_of::<CaptureEntry>() + 8 * limit) * entries
    );
    let mut large = config();
    large.n_max = 1 << 25;
    large.slot_bound = 1 << 25;
    large.q_cap = 1 << 24;
    large.extent_words = 1 << 25;
    let mut realistic = super::super::ledger::EngineBudget::new(4 << 30);
    CapturePolicy::new(large, 0, &mut realistic).unwrap();
    large.extent_words = 0;
    assert!(matches!(
        CapturePolicy::new(large, 0, &mut realistic),
        Err(CaptureError::InvalidConfig)
    ));
    large.extent_words = large.q_cap - 1;
    assert!(matches!(
        CapturePolicy::new(large, 0, &mut realistic),
        Err(CaptureError::InvalidConfig)
    ));
}

#[test]
fn full_membership_capacity_stays_paced_and_stalls_do_not_catch_up() {
    let mut cfg = config();
    cfg.n_max = 4;
    cfg.slot_bound = 4;
    cfg.q_cap = 4;
    let mut p = CapturePolicy::new(cfg, 0, &mut engine()).unwrap();
    assert_eq!(p.submitted(0), Err(CaptureError::Idle));
    p.started(0).unwrap();
    assert!(p.unit_due(0, 0));
    p.submitted(0).unwrap();
    assert!(!p.unit_due(cfg.fast_unit_ns, 0));
    assert_eq!(
        p.submitted(cfg.paced_unit_ns - 1),
        Err(CaptureError::NotDue)
    );
    let delayed = 10 * cfg.paced_unit_ns;
    p.submitted(delayed).unwrap();
    assert!(!p.unit_due(delayed, 0));
    assert!(p.unit_due(delayed + cfg.paced_unit_ns, 0));
}

#[test]
fn capture_refusals_leave_counter_and_cursor_unchanged() {
    let mut c = Capture::default();
    assert_eq!(
        c.start((0, CaptureEpoch::default()), 0, 0, 8, true, side(1)),
        Err(CaptureError::InvalidConfig)
    );
    assert_eq!(
        c.start((0, CaptureEpoch::default()), 4, 0, 8, true, side(0)),
        Err(CaptureError::InvalidConfig)
    );
    assert_eq!(c.counter(), 0);
    assert_eq!(
        c.start((1, CaptureEpoch::default()), 4, 1, 8, true, side(1)),
        Ok(1)
    );
    assert_eq!(
        c.start((1, CaptureEpoch::default()), 4, 1, 8, true, side(1)),
        Err(CaptureError::InFlight)
    );
    assert_eq!(c.take_saved(), Err(CaptureError::Incomplete));
    assert_eq!(c.visit(1, None), Err(CaptureError::Cursor));
    assert_eq!(
        c.visit(0, Some((1, entry(1, 1, 0)))),
        Err(CaptureError::Cursor)
    );
    assert_eq!(c.cursor(), Ok(0));
    assert_eq!(c.counter(), 1);
}

#[test]
fn capture_start_and_publication_refuse_capture_contention_without_mutation() {
    let mut s = storage(4, &index_config(&[4], (1, 1), 2));
    let old = completed(&s, key(1)).publish(TRIES, &mut budget()).unwrap();
    let mut cfg = config();
    cfg.n_max = 4;
    cfg.slot_bound = 4;
    cfg.q_cap = 4;
    let mut policy = CapturePolicy::new(cfg, 0, &mut engine()).unwrap();
    assert_eq!(
        s.try_start_capture(&mut policy, 0, false, false, true),
        Ok(None)
    );
    policy.changed_bytes(cfg.byte_trigger);
    let guard = s.pool().capture_lock().unwrap();
    assert_eq!(
        s.try_start_capture(&mut policy, 0, false, false, true),
        Err(CaptureError::Unavailable)
    );
    assert_eq!(guard.counter(), 0);
    assert!(policy.due(0, false, false));
    assert_eq!(
        completed(&s, key(2))
            .publish(TRIES, &mut budget())
            .err()
            .map(|(_, error)| error),
        Some(super::super::PublishError::Contended)
    );
    assert_eq!(
        s.remove(&key(1), old, TRIES, &mut budget()),
        Err(super::super::remove::RemoveError::Contended)
    );
    s.platform.ticks(&[Some(1), Some(1)]);
    let mut reader = s.register().unwrap();
    let observed = reader.lookup(&key(1), TRIES, &mut budget()).unwrap();
    assert_eq!(observed.id(), old);
    drop(observed);
    assert_eq!(
        reader.lookup(&key(2), TRIES, &mut budget()).err(),
        Some(super::super::LookupError::Missing)
    );
    drop(reader);
    drop(guard);
    s.try_start_capture(&mut policy, 0, false, false, true)
        .unwrap()
        .unwrap();
    assert_eq!(drain(&s).len(), 1);
    s.finish_capture(&mut policy, 1).unwrap();
    assert!(!policy.due(0, false, false));
    super::super::test_platform::finalize(&mut s).unwrap();
}

#[test]
fn submission_unwind_abandons_without_poisoning_membership() {
    let mut s = storage(4, &index_config(&[4], (1, 1), 2));
    completed(&s, key(1)).publish(TRIES, &mut budget()).unwrap();
    let counter = s.start_capture(4, true, 4).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        s.submit_capture_unit(counter, || panic!("submission cut"))
            .unwrap();
    }));
    assert!(result.is_err());
    assert!(!s.pool().capture.is_poisoned());
    assert_eq!(s.capture_next(counter), Err(CaptureError::Abandoned));
    completed(&s, key(2)).publish(TRIES, &mut budget()).unwrap();
    finish(&s, counter).unwrap();
    super::super::test_platform::finalize(&mut s).unwrap();
}

#[test]
fn a_released_pass_refuses_a_unit_submit() {
    use std::cell::Cell;
    let mut s = storage(4, &index_config(&[4], (1, 1), 2));
    let member = completed(&s, key(1)).publish(TRIES, &mut budget()).unwrap();
    let counter = s.start_capture(4, true, 4).unwrap();
    let submissions = Cell::new(0);
    s.submit_capture_unit(counter, || submissions.set(submissions.get() + 1))
        .unwrap();
    s.remove(&key(1), member, TRIES, &mut budget()).unwrap();
    assert_eq!(
        s.submit_capture_unit(counter, || submissions.set(submissions.get() + 1)),
        Err(CaptureError::Released)
    );
    assert_eq!(submissions.get(), 1);
    finish(&s, counter).unwrap();
    super::super::test_platform::finalize(&mut s).unwrap();
}

/// A poisoned capture mutex ends captures for the tenure while publication, invalidation and removal recover the guard, abandon the pass and continue, so a fault inside one publication stays shard-local.
#[test]
fn poisoned_capture_is_terminal_for_captures_while_membership_changes_continue() {
    let mut s = storage(4, &index_config(&[4], (1, 1), 2));
    completed(&s, key(1)).publish(TRIES, &mut budget()).unwrap();
    s.start_capture(4, true, 4).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = s.pool().capture_lock().unwrap();
        panic!("capture lock cut");
    }));
    assert!(result.is_err());
    assert_eq!(s.capture_next(1), Err(CaptureError::Poisoned));
    let new = completed(&s, key(2)).publish(TRIES, &mut budget()).unwrap();
    s.invalidate(&key(1), TRIES, &mut budget()).unwrap();
    assert!(s.pool().capture.is_poisoned());
    assert_eq!(s.start_capture(4, true, 4), Err(CaptureError::Poisoned));
    s.remove(&key(2), new, TRIES, &mut budget()).unwrap();
    s.close();
    let report = s
        .close_service(&mut super::super::WorkBudget::new(4096))
        .unwrap();
    assert_eq!(report.blockers.poisoned_gates, 0);
    let _ = s.certify(&mut budget()).unwrap();
    for _ in 0..8 {
        s.service(&mut budget()).unwrap();
    }
    let finalized = super::super::test_platform::finalize(&mut s).unwrap();
    assert!(
        matches!(finalized, super::super::Finalization::Drained),
        "{finalized:?}"
    );
    assert_eq!(s.capture_next(1), Err(CaptureError::Closed));
}

/// A member's retirement under a poisoned capture mutex recovers the guard, clears the step and returns the units, and the mutex stays poisoned.
#[test]
fn retirement_under_a_poisoned_capture_mutex_returns_the_units() {
    let s = storage(4, &index_config(&[4], (1, 1), 2));
    let bound = completed(&s, key(1));
    let id = bound.id();
    let (resident, lease) = bound.handoff(&mut budget()).ok().unwrap();
    drop(lease);
    {
        let capture = s.pool().capture_lock().unwrap();
        s.pool().capture_insert(&capture, id.slot_index());
    }
    s.start_capture(4, true, 4).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = s.pool().capture_lock().unwrap();
        panic!("capture lock cut");
    }));
    assert!(result.is_err());
    let before = s.pool_report().unwrap().ledger.unwrap().raw.free;
    assert_eq!(resident.retire(), super::super::RetireOutcome::Recorded);
    let _ = s.certify(&mut budget()).unwrap();
    for _ in 0..4 {
        s.service(&mut budget()).unwrap();
    }
    assert!(s.pool_report().unwrap().ledger.unwrap().raw.free > before);
    assert!(s.pool().capture.is_poisoned());
    let mut access = s.pool().try_lock().unwrap();
    assert_eq!(access.tables().step(id.slot_index()), 0);
    access.release();
    assert_eq!(s.capture_next(1), Err(CaptureError::Poisoned));
}

/// Under a poisoned mutex the recovered guard carries an abandoned pass, so invalidating an unvisited snapshot member saves nothing and needs no pool gate: the removal succeeds while another holder has the gate.
#[test]
fn a_poisoned_mutex_abandons_the_pass_so_removal_skips_the_save() {
    let s = storage(4, &index_config(&[4], (1, 1), 2));
    completed(&s, key(1)).publish(TRIES, &mut budget()).unwrap();
    s.start_capture(4, true, 4).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = s.pool().capture_lock().unwrap();
        panic!("capture lock cut");
    }));
    assert!(result.is_err());
    let gate = s.pool().try_lock().unwrap();
    s.invalidate(&key(1), TRIES, &mut budget()).unwrap();
    gate.release();
    assert!(s.pool().capture.is_poisoned());
}

/// A production fill publishes under a poisoned capture mutex; the mutex stays poisoned and the next capture start reports `Poisoned`.
#[test]
fn production_fill_publishes_under_a_poisoned_capture_mutex() {
    use super::super::publication_tests::{DEADLINE, filled, ready_with};
    use super::super::volume_fixture::{Device, arena};
    let s = ready_with(2, 16, 8);
    let buffers = arena();
    let mut device = Device::new(&s, &buffers);
    let fill = filled(&s, &mut device, &key(1), &[7; 20]);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = s.pool().capture_lock().unwrap();
        panic!("capture lock cut");
    }));
    assert!(result.is_err());
    let lease = fill
        .publish(&mut device.volume, DEADLINE, TRIES, &mut budget())
        .unwrap();
    assert!(s.pool().capture.is_poisoned());
    drop(lease);
    assert_eq!(s.start_capture(8, true, 8), Err(CaptureError::Poisoned));
}

#[test]
fn replacement_saves_the_unvisited_snapshot_member_before_reuse() {
    let mut s = storage(4, &index_config(&[4], (1, 1), 2));
    let (old, expected) = observed_completed(&s, key(1));
    let old = old.publish(TRIES, &mut budget()).unwrap();
    s.start_capture(4, true, 4).unwrap();
    let replacement = completed(&s, key(1)).replace(TRIES, &mut budget()).unwrap();
    assert_ne!(old, replacement.id);
    assert_eq!(replacement.replaced.map(|(id, _)| id), Some(old));
    s.service(&mut budget()).unwrap();
    assert_eq!(drain(&s), vec![expected]);
    assert_eq!(
        s.cut_intact((crate::net::ownership::Shard::new(7).unwrap(), 2), 1),
        Err(CaptureError::Released),
        "the replaced snapshot member makes the cut unpublishable"
    );
    finish(&s, 1).unwrap();
    super::super::test_platform::finalize(&mut s).unwrap();
}

#[test]
fn load_guard_refuses_scratch_exhaustion_and_unrepresentable_extents() {
    let a = entry(0, 1, 0);
    let short = super::super::ledger::EngineBudget::new(23);
    assert_eq!(
        load_guard(std::slice::from_ref(&a), limits(), &short),
        Err(LoadRefusal::Memory)
    );
    assert_eq!(short.used(), 0);
    let cold = guarded_load(vec![a.clone()], limits(), &short);
    assert_eq!(
        cold.events().collect::<Vec<_>>(),
        vec![
            LoadEvent::Evict {
                allocation: a.allocation,
                cause: EvictCause::Refused
            },
            LoadEvent::Alarm {
                refusal: LoadRefusal::Memory
            }
        ]
    );
    let exact = super::super::ledger::EngineBudget::new(24);
    for _ in 0..2 {
        assert_eq!(
            load_guard(std::slice::from_ref(&a), limits(), &exact),
            Ok(())
        );
    }
    assert_eq!(exact.used(), 0);
    assert_eq!(
        load_guard(&[], limits(), &super::super::ledger::EngineBudget::new(0)),
        Ok(())
    );
    let mut invalid = a.clone();
    invalid.tail = super::super::IO_UNIT as u16;
    assert_eq!(
        load_guard(&[invalid], limits(), &engine()),
        Err(LoadRefusal::Bounds)
    );
    let mut invalid = a.clone();
    invalid.extents = vec![a.extents[0]; super::super::geometry::EXTENT_LIMIT as usize + 1];
    assert_eq!(
        load_guard(&[invalid], limits(), &engine()),
        Err(LoadRefusal::Bounds)
    );
    let mut invalid = a;
    invalid.extents = vec![
        ExtentLocator::new(0, super::super::geometry::DIRECT_UNITS + 1)
            .unwrap()
            .bits(),
    ];
    let mut lim = limits();
    lim.payload_end = 1_000_000;
    assert_eq!(
        load_guard(&[invalid], lim, &engine()),
        Err(LoadRefusal::Bounds)
    );
}

#[test]
fn multi_extent_members_preserve_sequence_order_in_scan_and_removal() {
    use super::super::publish_tests::{PAGE, storage_config, storage_from};
    for remove in [false, true] {
        let mut cfg = storage_config(4);
        cfg.volume = crate::storage::test_volume(512 * super::super::IO_UNIT, 4);
        cfg.volume.block_roots = 1;
        cfg.body_cap = 200_000;
        let mut s = storage_from(
            &cfg,
            &index_config(&[4], (1, 1), 2),
            TestPlatform::heap(PAGE),
        );
        let id = completed(&s, key(1)).publish(TRIES, &mut budget()).unwrap();
        let object = super::super::sequence_tests::published_sequence(&s, id, 3);
        let words: Vec<_> = object
            .extents
            .iter()
            .map(|locator| locator.bits())
            .collect();
        assert_eq!(words.len(), 3);
        s.start_capture(4, true, 4).unwrap();
        if remove {
            s.remove(&key(1), id, TRIES, &mut budget()).unwrap();
            let _ = s.certify(&mut budget()).unwrap();
            for _ in 0..8 {
                s.service(&mut budget()).unwrap();
            }
            completed(&s, key(2)).publish(TRIES, &mut budget()).unwrap();
        }
        let captured = drain(&s);
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].allocation, id.record_tag());
        assert_eq!(captured[0].extents, words);
        let mut lim = limits();
        lim.payload_end = 512;
        lim.slot_count = 4;
        assert_eq!(load_guard(&captured, lim, &engine()), Ok(()));
        finish(&s, 1).unwrap();
        s.close();
        for _ in 0..8 {
            s.close_service(&mut super::super::WorkBudget::new(4096))
                .unwrap();
        }
        let _ = s.certify(&mut budget()).unwrap();
        for _ in 0..8 {
            s.service(&mut budget()).unwrap();
        }
        super::super::test_platform::finalize(&mut s).unwrap();
    }
}

#[test]
fn real_fill_replacement_saves_its_unvisited_predecessor() {
    use super::super::publication_tests::{DEADLINE, payload, ready_with};
    use super::super::volume_fixture::{Device, arena};
    let s = ready_with(2, 16, 8);
    let buffers = arena();
    let mut device = Device::new(&s, &buffers);
    let k = key(1);
    let mut first =
        super::super::writable_tests::reserve_at(&s, &k, super::super::CacheVersion(1), 4, 20)
            .unwrap();
    device.fill(&mut first, &payload(&k, &[7; 20]));
    let old_id = first.id();
    let old_word = s.pool().records()[old_id.slot_index()].locator().bits();
    let old = first
        .publish(&mut device.volume, DEADLINE, TRIES, &mut budget())
        .unwrap();
    s.start_capture(8, true, 8).unwrap();
    let mut second =
        super::super::writable_tests::reserve_at(&s, &k, super::super::CacheVersion(2), 4, 20)
            .unwrap();
    device.fill(&mut second, &payload(&k, &[9; 20]));
    let newer = second
        .publish(&mut device.volume, DEADLINE, TRIES, &mut budget())
        .unwrap();
    assert_ne!(old_id, newer.id());
    assert_eq!(s.capture_side_len(1), Ok(1));
    drop(old);
    let captured = drain(&s);
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].allocation, old_id.record_tag());
    assert_eq!(captured[0].version, 1);
    assert_eq!(captured[0].extents, vec![old_word]);
    assert_eq!(
        s.cut_intact((crate::net::ownership::Shard::new(7).unwrap(), 2), 1),
        Err(CaptureError::Released),
        "the replaced snapshot member makes the cut unpublishable"
    );
    finish(&s, 1).unwrap();
}

/// An exhausted insertion clock refuses a completed owner's publication and a fill's `Closed` without a membership change.
/// The fill's refusal retires its slot with `ABANDONED`, the tables pass the conservation judge, and one service pass frees the slot.
#[test]
fn exhausted_insertion_clock_closes_publication_without_membership_change() {
    use super::super::claim_exit_tests::{FREE, RETIRED, conserved_after_service, conserved_at};
    use super::super::publication_tests::{DEADLINE, payload, ready_with};
    use super::super::volume_fixture::{Device, arena};
    use std::sync::atomic::Ordering;
    let s = storage(4, &index_config(&[4], (1, 1), 2));
    s.pool().insert_step.store(u64::MAX, Ordering::Relaxed);
    assert_eq!(
        completed(&s, key(1))
            .publish(TRIES, &mut budget())
            .err()
            .map(|(_, error)| error),
        Some(super::super::PublishError::Closed)
    );
    assert_eq!(s.pool().eligible.load(Ordering::Relaxed), 0);
    let s = ready_with(2, 16, 8);
    let buffers = arena();
    let mut device = Device::new(&s, &buffers);
    let k = key(1);
    let mut fill =
        super::super::writable_tests::reserve_at(&s, &k, super::super::CacheVersion(1), 4, 20)
            .unwrap();
    device.fill(&mut fill, &payload(&k, &[7; 20]));
    let slot = fill.id().slot_index();
    s.pool().insert_step.store(u64::MAX, Ordering::Relaxed);
    let stable = super::super::publish_tests::report(&s, 0).sequence;
    assert_eq!(
        fill.publish(&mut device.volume, DEADLINE, TRIES, &mut budget())
            .err(),
        Some(super::super::FillPublishError::Closed)
    );
    assert_eq!(
        (
            super::super::publish_tests::report(&s, 0).sequence,
            s.is_closed()
        ),
        (stable + 2, false),
        "premise: the refusal came inside the visibility bracket on an open storage"
    );
    conserved_at(&s, slot, RETIRED);
    assert_eq!(s.pool().eligible.load(Ordering::Relaxed), 0);
    assert!(
        s.pool()
            .steps()
            .iter()
            .all(|step| step.load(Ordering::Relaxed) == 0)
    );
    conserved_after_service(&s, slot, FREE);
}

#[test]
fn eligible_count_survives_replacement_and_refuses_a_small_snapshot_limit() {
    use std::sync::atomic::Ordering;
    let mut s = storage(4, &index_config(&[4], (1, 1), 2));
    completed(&s, key(1)).publish(TRIES, &mut budget()).unwrap();
    let second = completed(&s, key(2)).publish(TRIES, &mut budget()).unwrap();
    assert_eq!(s.pool().eligible.load(Ordering::Relaxed), 2);
    let mut cfg = config();
    cfg.n_max = 1;
    cfg.slot_bound = 4;
    cfg.q_cap = 1;
    let mut policy = CapturePolicy::new(cfg, 0, &mut engine()).unwrap();
    policy.changed_bytes(cfg.byte_trigger);
    assert_eq!(
        s.try_start_capture(&mut policy, 0, false, false, true),
        Err(CaptureError::TooManyEntries)
    );
    assert_eq!(s.pool().capture_lock().unwrap().counter(), 0);
    s.remove(&key(2), second, TRIES, &mut budget()).unwrap();
    assert_eq!(s.pool().eligible.load(Ordering::Relaxed), 1);
    completed(&s, key(1)).replace(TRIES, &mut budget()).unwrap();
    assert_eq!(s.pool().eligible.load(Ordering::Relaxed), 1);
    s.try_start_capture(&mut policy, 0, false, false, true)
        .unwrap()
        .unwrap();
    assert_eq!(drain(&s).len(), 1);
    finish(&s, 1).unwrap();
    policy.finished();
    s.close();
    for _ in 0..8 {
        s.close_service(&mut super::super::WorkBudget::new(4096))
            .unwrap();
    }
    let _ = s.certify(&mut budget()).unwrap();
    for _ in 0..8 {
        s.service(&mut budget()).unwrap();
    }
    super::super::test_platform::finalize(&mut s).unwrap();
}

#[test]
fn load_guard_checks_shapes_partial_overlap_and_closed_boundaries() {
    let a = entry(0, 1, 0);
    let mut b = entry(1, 1, 1);
    assert_eq!(
        load_guard(&[a.clone(), b.clone()], limits(), &engine()),
        Ok(())
    );
    let mut lim = limits();
    lim.payload_end = 2;
    lim.reserve_units = 0;
    assert_eq!(load_guard(&[a.clone(), b.clone()], lim, &engine()), Ok(()));
    let mut invalid = a.clone();
    invalid.extents.clear();
    assert_eq!(
        load_guard(&[invalid], limits(), &engine()),
        Err(LoadRefusal::Bounds)
    );
    let mut invalid = a.clone();
    invalid.extents = vec![ExtentLocator::new(0, 0).unwrap().bits()];
    assert_eq!(
        load_guard(&[invalid], limits(), &engine()),
        Err(LoadRefusal::Bounds)
    );
    let mut invalid = a.clone();
    invalid.tail = 1;
    assert_eq!(
        load_guard(&[invalid], limits(), &engine()),
        Err(LoadRefusal::Bounds)
    );
    let mut invalid = a.clone();
    invalid.extents = vec![a.extents[0], a.extents[0]];
    assert_eq!(
        load_guard(&[invalid], limits(), &engine()),
        Err(LoadRefusal::Overlap)
    );
    let mut extended = a.clone();
    extended.extents = vec![ExtentLocator::new(0, 2).unwrap().bits()];
    b.extents = vec![ExtentLocator::new(1, 2).unwrap().bits()];
    assert_eq!(
        load_guard(&[extended, b], limits(), &engine()),
        Err(LoadRefusal::Overlap)
    );
    lim.reserve_units = 3;
    assert_eq!(load_guard(&[], lim, &engine()), Err(LoadRefusal::Limits));
    lim = limits();
    lim.record_chunk_len = 0;
    assert_eq!(load_guard(&[], lim, &engine()), Err(LoadRefusal::Limits));
    lim = limits();
    lim.payload_start = lim.payload_end + 1;
    assert_eq!(load_guard(&[], lim, &engine()), Err(LoadRefusal::Limits));
}

/// Publication requires a completed walk in an active pass that retains every snapshot member or saw it leave through
/// a removal the suffix recorded. Members inserted after `t0` may leave while the pass remains intact. A member with
/// an insertion step in `1..=t0` leaving unrecorded makes `intact` return `CaptureError::Released` until the pass
/// ends. A later completed pass yields a proof after a
/// snapshot member left an earlier pass. A proof names the tenure it was taken under and its pass counter.
#[test]
fn a_snapshot_member_leaving_makes_the_cut_unpublishable() {
    let cap = SideCap {
        entries: 2,
        words: 2,
    };
    let tenure = (crate::net::ownership::Shard::new(7).unwrap(), (3 << 32) | 4);
    let proof = |capture: &Capture| {
        capture
            .intact(tenure, CaptureEpoch::default())
            .map(|cut| (cut.tenure(), cut.counter()))
    };
    let mut capture = Capture::default();
    capture
        .start((5, CaptureEpoch::default()), 4, 2, 4, true, cap)
        .unwrap();
    assert_eq!(
        proof(&capture),
        Err(CaptureError::Incomplete),
        "the walk has not reached the slot count"
    );
    capture.advance(4).unwrap();
    capture.left(6, false);
    capture.left(0, false);
    assert_eq!(proof(&capture), Ok((tenure, 1)));
    capture.left(5, true);
    assert_eq!(
        proof(&capture),
        Ok((tenure, 1)),
        "a snapshot member whose removal the suffix recorded at or above the cut keeps the pass publishable"
    );
    assert_eq!(
        capture.intact(tenure, CaptureEpoch(1)).err(),
        Some(CaptureError::Replaced),
        "a recorded removal keeps the pass publishable only under the epoch the pass started in"
    );
    capture.left(5, false);
    assert_eq!(proof(&capture), Err(CaptureError::Released));
    let _ = capture.finish();
    assert_eq!(proof(&capture), Err(CaptureError::Idle));
    capture
        .start((7, CaptureEpoch::default()), 4, 2, 4, true, cap)
        .unwrap();
    capture.left(7, false);
    assert_eq!(
        proof(&capture),
        Err(CaptureError::Released),
        "a released pass reports Released before its walk completes"
    );
    let _ = capture.finish();
    capture
        .start((9, CaptureEpoch::default()), 4, 2, 4, true, cap)
        .unwrap();
    capture.advance(4).unwrap();
    assert_eq!(proof(&capture), Ok((tenure, 3)));
    capture.abandon();
    assert_eq!(proof(&capture), Err(CaptureError::Abandoned));
}
/// A capture start seals the suffix's open block under the capture mutex and records the cut on the pass: a record
/// appended before the start lies in a block below the cut, a record appended after it at or above the cut, and the
/// pass's proof carries the cut.
#[test]
fn a_capture_start_seals_the_suffix_cut_between_the_records_before_and_after_it() {
    let s = storage(4, &index_config(&[4], (1, 1), 2));
    let mut policy = CapturePolicy::new(config(), 0, &mut engine()).unwrap();
    policy.changed_bytes(config().byte_trigger);
    {
        let mut capture = s.pool().capture_lock().unwrap();
        open_suffix(&mut capture.suffix);
        let before = capture
            .suffix
            .append(0, &super::delta::Record::Insert(entry(0, 1, 0)))
            .unwrap();
        assert_eq!(before >> 32, 5);
    }
    let started = s
        .try_start_capture(&mut policy, 0, false, false, true)
        .unwrap()
        .unwrap();
    let cut = 6;
    let after = s
        .pool()
        .capture_lock()
        .unwrap()
        .suffix
        .append(0, &super::delta::Record::Insert(entry(1, 1, 8)))
        .unwrap();
    assert_eq!(
        after >> 32,
        cut,
        "a record after the start lands at the cut"
    );
    for _ in 0..s.pool().records().len() {
        s.capture_visit(started.counter, 1, |_| {}).unwrap();
    }
    assert_eq!(
        s.cut_intact(
            (crate::net::ownership::Shard::new(7).unwrap(), 2),
            started.counter
        )
        .unwrap()
        .cut(),
        cut,
        "the sealed block is below the proof's cut"
    );
    finish(&s, started.counter).unwrap();
}
/// Opens `log` at LSN 5 of a 20-block delta region, reserved to LSN 20.
fn open_suffix(log: &mut super::suffix::SuffixLog) {
    let layout = crate::failover::records::Layout {
        units: 21,
        slots: 0,
        slot_units: 0,
        entries: 0,
    };
    let limits = super::suffix::SuffixLimits {
        flush_ns: 1,
        queue_blocks: 8,
        oldest_ns: 2,
        uncertified: 1 << 20,
    };
    let suffix = crate::failover::records::Suffix {
        session: (3 << 32) | 2,
        start: 5,
        certified: 5,
        end: 20,
    };
    let identity = (
        super::super::record::Crc32c::detect(),
        crate::net::ownership::Shard::new(7).unwrap(),
    );
    assert!(log.open(identity, (limits, &layout), suffix, 0));
}
/// A poisoned capture mutex closes the suffix log for every membership change that follows: the open block, which
/// may hold a record of the interrupted change, is dropped, while a sealed, acknowledged block keeps its payload and
/// still drains, and the durable prefix does not move back.
#[test]
fn a_poisoned_capture_closes_the_suffix_and_keeps_its_sealed_blocks_draining() {
    let s = storage(4, &index_config(&[4], (1, 1), 2));
    let sealed = {
        let mut capture = s.pool().capture_lock().unwrap();
        open_suffix(&mut capture.suffix);
        let insert = |slot| super::delta::Record::Insert(entry(slot, 1, slot as u64 * 8));
        capture.suffix.append(0, &insert(0)).unwrap();
        capture.suffix.seal_cut();
        let (lsn, _) = super::suffix_tests::take(&mut capture.suffix).unwrap();
        capture.suffix.written(lsn);
        capture.suffix.append(0, &insert(1)).unwrap();
        capture.suffix.seal_cut();
        capture.suffix.append(0, &insert(2)).unwrap();
        *super::suffix_tests::take(&mut capture.suffix).unwrap().1
    };
    let pool = s.pool();
    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = pool.capture_lock().unwrap();
        panic!("poison the capture mutex");
    }));
    assert!(poisoned.is_err());
    assert_eq!(
        pool.capture_lock().err(),
        Some(super::super::gate::GateError::Poisoned)
    );
    let mut capture = pool.capture_membership_lock().unwrap();
    assert_eq!(capture.suffix.durable(), 6, "the durable prefix stays");
    let insert = super::delta::Record::Insert(entry(3, 1, 24));
    assert_eq!(
        capture.suffix.append(0, &insert),
        Err(super::suffix::SuffixRefusal::Closed)
    );
    capture.suffix.failed(6);
    let (lsn, bytes) = super::suffix_tests::take(&mut capture.suffix).unwrap();
    assert_eq!(
        (lsn, *bytes),
        (6, sealed),
        "the sealed block drains with its bytes"
    );
    capture.suffix.written(6);
    assert_eq!(
        super::suffix_tests::take(&mut capture.suffix),
        None,
        "the open block was dropped"
    );
    assert_eq!(capture.suffix.seal_cut(), 7);
}

/// A resident capture member, inserted before the pass starts, whose locator was rewritten into a sequence handle it does not own, so its return's side-list copy in `capture_remove` panics in `capture_entry`. Returns the member's transfer.
fn corrupt_returned_member(
    s: &Storage<TestPlatform>,
) -> super::super::release::ReturnTransfer<'_, TestPlatform> {
    let bound = completed(s, key(1));
    let slot = bound.id().slot_index();
    {
        let capture = s.pool().capture_lock().unwrap();
        s.pool().capture_insert(&capture, slot);
    }
    let handle = super::super::held::Held::Sequence {
        block: super::super::blocks::Block(0),
        count: 2,
    };
    s.pool().records()[slot].set_locator(handle.locator());
    s.start_capture(4, true, 4).unwrap();
    bound.release()
}

/// A return whose retirement's side-list copy panics on a corrupt member, on a thread that is not unwinding, poisons the pool gate and the capture mutex.
#[test]
fn a_returned_member_copy_panic_poisons_the_gate_and_capture_serialization() {
    use super::super::gate::GateError;
    let s = storage(4, &index_config(&[4], (1, 1), 2));
    let transfer = corrupt_returned_member(&s);
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        s.return_allocation(transfer, &mut budget())
    }));
    assert!(caught.is_err());
    assert_eq!(s.pool().try_lock_quiet().err(), Some(GateError::Poisoned));
    assert_eq!(s.pool().capture_lock().err(), Some(GateError::Poisoned));
    assert_eq!(s.capture_visit(1, 4, |_| {}), Err(CaptureError::Poisoned));
}

/// The same return made by a destructor of a thread that is already unwinding, its panic caught there. Guards taken there release unpoisoned on drop, so the copy's panic must poison both locks some other way, as `Pool::capture_entry_into`'s panic doc promises of the pool gate: afterwards `try_lock_quiet` and `capture_lock` report `Poisoned`, and a capture visit reports `Poisoned` instead of walking the corrupt member.
#[test]
fn a_returned_member_copy_panic_during_unwinding_poisons_the_gate_and_capture_serialization() {
    use super::super::gate::GateError;
    use super::super::release::ReturnTransfer;
    struct ReturnsOnDrop<'s>(
        &'s Storage<TestPlatform>,
        Option<ReturnTransfer<'s, TestPlatform>>,
    );
    impl Drop for ReturnsOnDrop<'_> {
        fn drop(&mut self) {
            let (s, transfer) = (self.0, self.1.take().unwrap());
            let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                s.return_allocation(transfer, &mut budget())
            }));
            assert!(caught.is_err());
        }
    }
    let s = storage(4, &index_config(&[4], (1, 1), 2));
    let transfer = corrupt_returned_member(&s);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _returner = ReturnsOnDrop(&s, Some(transfer));
        panic!("an unrelated panic with a live returner");
    }));
    assert!(outcome.is_err());
    let gate = s.pool().try_lock_quiet().err();
    let serialization = s.pool().capture_lock().err();
    assert_eq!(
        (gate, serialization),
        (Some(GateError::Poisoned), Some(GateError::Poisoned))
    );
    assert_eq!(s.capture_visit(1, 4, |_| {}), Err(CaptureError::Poisoned));
}

/// Runs `call`, which must panic, and returns the states of the pool gate and the capture mutex afterwards. With `unwinding`, a destructor of a thread that is already unwinding from an unrelated panic makes the call and catches its panic there.
fn lock_states_after_a_panicking_call(
    s: &Storage<TestPlatform>,
    unwinding: bool,
    call: impl FnOnce(),
) -> (
    Option<super::super::gate::GateError>,
    Option<super::super::gate::GateError>,
) {
    struct CallsOnDrop<F: FnOnce()>(Option<F>);
    impl<F: FnOnce()> Drop for CallsOnDrop<F> {
        fn drop(&mut self) {
            let call = self.0.take().unwrap();
            let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(call));
            assert!(caught.is_err(), "the call panics");
        }
    }
    let caller = CallsOnDrop(Some(call));
    if unwinding {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _caller = caller;
            panic!("an unrelated panic with a live caller");
        }));
        assert!(outcome.is_err());
    } else {
        drop(caller);
    }
    (
        s.pool().try_lock_quiet().err(),
        s.pool().capture_lock().err(),
    )
}

/// A retirement of a resident capture member whose locator names a sequence it does not own: `abandon` takes the pool gate and `retire_held`'s entry copy panics in `capture_entry`. The locks' states afterwards.
fn a_retired_corrupt_member(
    unwinding: bool,
) -> (
    Option<super::super::gate::GateError>,
    Option<super::super::gate::GateError>,
) {
    let s = storage(4, &index_config(&[4], (1, 1), 2));
    let bound = completed(&s, key(1));
    let slot = bound.id().slot_index();
    let (resident, lease) = bound.handoff(&mut budget()).ok().unwrap();
    drop(lease);
    {
        let capture = s.pool().capture_lock().unwrap();
        s.pool().capture_insert(&capture, slot);
    }
    let handle = super::super::held::Held::Sequence {
        block: super::super::blocks::Block(0),
        count: 2,
    };
    s.pool().records()[slot].set_locator(handle.locator());
    s.start_capture(4, true, 4).unwrap();
    lock_states_after_a_panicking_call(&s, unwinding, move || {
        let _ = resident.retire();
    })
}

/// A parked retirement of a resident capture member whose locator is then rewritten into a sequence it does not own: the service walk's park pass takes the pool gate and `retire_held`'s entry copy panics in `capture_entry`. The locks' states afterwards.
fn a_serviced_corrupt_parked_member(
    unwinding: bool,
) -> (
    Option<super::super::gate::GateError>,
    Option<super::super::gate::GateError>,
) {
    let s = storage(4, &index_config(&[4], (1, 1), 2));
    let bound = completed(&s, key(1));
    let slot = bound.id().slot_index();
    let (resident, lease) = bound.handoff(&mut budget()).ok().unwrap();
    drop(lease);
    {
        let capture = s.pool().capture_lock().unwrap();
        s.pool().capture_insert(&capture, slot);
    }
    s.start_capture(4, true, 4).unwrap();
    {
        let _hold = s.pool().capture_lock().unwrap();
        assert_eq!(resident.retire(), super::super::RetireOutcome::Parked);
    }
    let handle = super::super::held::Held::Sequence {
        block: super::super::blocks::Block(0),
        count: 2,
    };
    s.pool().records()[slot].set_locator(handle.locator());
    lock_states_after_a_panicking_call(&s, unwinding, || {
        for _ in 0..4 {
            let _ = s.service(&mut budget());
        }
    })
}

/// A retirement whose entry copy panics on a corrupt member, on a thread that is not unwinding, poisons the pool gate and the capture mutex (`storage/gate.rs`: "A holder that panics poisons the gate on release").
#[test]
fn a_retired_member_copy_panic_poisons_the_gate_and_capture_serialization() {
    use super::super::gate::GateError::Poisoned;
    assert_eq!(
        a_retired_corrupt_member(false),
        (Some(Poisoned), Some(Poisoned))
    );
}

/// The same retirement made by a destructor of a thread that is already unwinding poisons both locks too.
#[test]
fn a_retired_member_copy_panic_during_unwinding_poisons_the_gate_and_capture_serialization() {
    use super::super::gate::GateError::Poisoned;
    assert_eq!(
        a_retired_corrupt_member(true),
        (Some(Poisoned), Some(Poisoned))
    );
}

/// A service pass whose park pass retires a corrupt member, on a thread that is not unwinding, poisons the pool gate and the capture mutex.
#[test]
fn a_serviced_parked_member_copy_panic_poisons_the_gate_and_capture_serialization() {
    use super::super::gate::GateError::Poisoned;
    assert_eq!(
        a_serviced_corrupt_parked_member(false),
        (Some(Poisoned), Some(Poisoned))
    );
}

/// The same service pass made by a destructor of a thread that is already unwinding poisons both locks too.
#[test]
fn a_serviced_parked_member_copy_panic_during_unwinding_poisons_the_gate_and_capture_serialization()
{
    use super::super::gate::GateError::Poisoned;
    assert_eq!(
        a_serviced_corrupt_parked_member(true),
        (Some(Poisoned), Some(Poisoned))
    );
}

/// A service call over a retired slot that carries a waiting mark made under an earlier prefix, with a retired-summary bit set past the retired words: the call clears the waiting set under the pool gate before its passes begin, and `clear_waiting` indexes the waiting words by that bit and panics. The locks' states afterwards.
fn a_serviced_stale_waiting_set_under_a_corrupt_summary(
    unwinding: bool,
) -> (
    Option<super::super::gate::GateError>,
    Option<super::super::gate::GateError>,
) {
    let s = storage(4, &index_config(&[4], (1, 1), 2));
    let bound = completed(&s, key(1));
    let slot = bound.id().slot_index();
    let (resident, lease) = bound.handoff(&mut budget()).ok().unwrap();
    drop(lease);
    assert_eq!(resident.retire(), super::super::RetireOutcome::Recorded);
    {
        let mut access = s.pool().try_lock_quiet().unwrap();
        let mut tables = access.tables();
        assert_eq!(tables.state.ledger.retired, 1);
        tables.mark_waiting(slot);
        tables.state.waiting_under = tables.state.waiting_under.wrapping_add(1);
        assert_eq!(tables.retired_summary.len(), 1);
        tables.retired_summary[0] |= 1 << 1;
        access.release();
    }
    lock_states_after_a_panicking_call(&s, unwinding, || {
        let _ = s.service(&mut budget());
    })
}

/// A service call whose waiting-set clear panics on a corrupt retired summary, on a thread that is not unwinding, poisons the pool gate (`storage/gate.rs`: "A holder that panics poisons the gate on release"); the capture mutex was never taken.
#[test]
fn a_service_waiting_clear_panic_poisons_the_gate() {
    use super::super::gate::GateError::Poisoned;
    assert_eq!(
        a_serviced_stale_waiting_set_under_a_corrupt_summary(false),
        (Some(Poisoned), None)
    );
}

/// The same service call made by a destructor of a thread that is already unwinding poisons the pool gate too (`Storage::service`: "The pool gate is poisoned when the panic leaves, also on a thread that was already unwinding when the call began").
#[test]
fn a_service_waiting_clear_panic_during_unwinding_poisons_the_gate() {
    use super::super::gate::GateError::Poisoned;
    assert_eq!(
        a_serviced_stale_waiting_set_under_a_corrupt_summary(true),
        (Some(Poisoned), None)
    );
}

/// Starts a pass whose side list would hold `usize::MAX / 2` entries: the reservation's byte size overflows, so the
/// allocator is never asked and the refusal is deterministic.
fn start_with_an_unreservable_side_list(capture: &mut Capture) -> Result<u32, CaptureError> {
    assert!(
        size_of::<CaptureEntry>() > 2,
        "usize::MAX / 2 entries overflow the reservation's capacity"
    );
    capture.start(
        (1, CaptureEpoch::default()),
        usize::MAX,
        usize::MAX / 2,
        usize::MAX / 2,
        true,
        SideCap {
            entries: usize::MAX,
            words: 1,
        },
    )
}

/// The refusal from `capture`, whose counter is `before`: the counter stays, no pass is in flight, the refusal
/// repeats with the same result, and the next accepted start is pass `before + 1`.
fn allocation_refusal_keeps_the_counter(mut capture: Capture, before: u32) {
    assert_eq!(capture.counter(), before);
    for attempt in 0..2 {
        assert_eq!(
            start_with_an_unreservable_side_list(&mut capture),
            Err(CaptureError::Allocation),
            "attempt {attempt} from counter {before}"
        );
        assert_eq!(
            capture.counter(),
            before,
            "attempt {attempt}: a start refused with Allocation leaves the counter unchanged"
        );
        assert_eq!(
            capture.cursor(),
            Err(CaptureError::Idle),
            "attempt {attempt}: a refused start leaves no pass in flight"
        );
        assert_eq!(capture.check_counter(before), Err(CaptureError::Idle));
    }
    assert_eq!(
        capture.start(
            (1, CaptureEpoch::default()),
            4,
            1,
            8,
            true,
            SideCap {
                entries: 1,
                words: 1
            }
        ),
        Ok(before + 1),
        "the refused starts consumed no pass number"
    );
    assert_eq!(capture.counter(), before + 1);
    assert_eq!(capture.cursor(), Ok(0));
}

/// A first start refused with `Allocation` leaves the counter at zero and no pass in flight, so the next accepted
/// start is pass 1.
#[test]
fn a_first_start_refused_with_allocation_leaves_the_counter_at_zero() {
    allocation_refusal_keeps_the_counter(Capture::default(), 0);
}

/// A start refused with `Allocation` on a capture built at counter 1, 7 or `2^32 - 2`, the highest counter that
/// leaves a pass number to take, leaves the counter at that value.
#[test]
fn a_later_start_refused_with_allocation_leaves_the_counter_unchanged() {
    for counter in [1, 7, (1 << 32) - 2] {
        allocation_refusal_keeps_the_counter(Capture::at_counter(counter), counter as u32);
    }
}

/// After `clone_from`, the destination equals the source and its `extents.capacity()` equals `source.extents.len()`
/// regardless of initial capacity. If the initial capacity equals `source.extents.len()`, the destination keeps its
/// extent buffer.
#[test]
fn clone_from_equals_the_source_and_holds_exactly_its_extent_words() {
    let source = CaptureEntry {
        key: [7; 32],
        allocation: 5 << 32 | 9,
        session: 11,
        version: 13,
        deadline_ns: 17,
        lifetime_ms: 19,
        tail: 23,
        extents: vec![29, 31, 37],
    };
    // Every scalar field differs from the source's, so equality after `clone_from` shows that each one was copied.
    let held = |extents: Vec<u64>| CaptureEntry {
        key: [1; 32],
        allocation: 2,
        session: 3,
        version: 4,
        deadline_ns: 5,
        lifetime_ms: 6,
        tail: 8,
        extents,
    };
    let mut wide = Vec::with_capacity(8);
    wide.extend([41, 43, 47]);
    let cases = [
        (vec![41, 43, 47], true),
        (wide, false),
        (vec![41], false),
        (Vec::new(), false),
    ];
    for (at, (extents, fits)) in cases.into_iter().enumerate() {
        let mut entry = held(extents);
        let fit = entry.extents.capacity() == source.extents.len();
        assert_eq!(fit, fits, "premise of case {at}");
        let words = entry.extents.as_ptr();
        entry.clone_from(&source);
        assert_eq!(entry, source, "case {at}");
        assert_eq!(
            entry.extents.capacity(),
            source.extents.len(),
            "case {at}: extent capacity equals the source's extent count"
        );
        if fits {
            assert_eq!(
                entry.extents.as_ptr(),
                words,
                "case {at}: a destination whose extent capacity equals the source's extent count keeps its extent buffer"
            );
        }
    }
    let empty = CaptureEntry {
        extents: Vec::new(),
        ..source.clone()
    };
    for extents in [vec![41, 43], Vec::new()] {
        let mut entry = held(extents);
        entry.clone_from(&empty);
        assert_eq!(entry, empty);
        assert_eq!(
            entry.extents.capacity(),
            0,
            "a source with zero extents leaves extent capacity zero"
        );
    }
}
