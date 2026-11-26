//! Tests of `Storage::capture_visit`: batch bounds, agreement with single-slot visits, a panicking sink, and extent words across members.

use super::CaptureError;
use super::gate::GateError;
use super::publish_tests::{TRIES, budget, completed, index_config, key, storage};

fn finish(s: &super::owner::Storage<super::test_platform::TestPlatform>) {
    drop(s.pool().capture_lock().unwrap().finish());
}

/// A capture start that reads the epoch before a wholesale replacement and the readiness word after it refuses
/// `Unavailable`, so no pass starts under a stale epoch; the next start, with no replacement between its reads, runs.
#[test]
fn a_start_straddling_a_replacement_refuses_unavailable() {
    let s = storage(16, &index_config(&[16], (1, 1), 2));
    super::capture::REPLACE_AFTER_EPOCH.with(|at| at.set(true));
    let straddled = s.start_capture(16, true, 16);
    super::capture::REPLACE_AFTER_EPOCH.with(|at| at.set(false));
    assert_eq!(straddled.err(), Some(CaptureError::Unavailable));
    s.start_capture(16, true, 16).unwrap();
    finish(&s);
}

/// When `CaptureBusy` fires, `capture_membership_lock` returns
/// `GateError::Contended` and leaves the mutex free: `capture_lock` then
/// takes it, and `capture_membership_lock` takes it after `disarm`.
#[test]
fn a_fired_capture_busy_point_leaves_the_mutex_free() {
    use crate::sim::chaos::{acting, arm, sites};
    use std::{cell::RefCell, rc::Rc};
    let s = storage(4, &index_config(&[4], (1, 1), 2));
    let chooser = Rc::new(RefCell::new(crate::sim::choice::Chooser::record(
        7,
        &sites(1),
    )));
    let incarnation = chooser.borrow_mut().launch(1);
    let armed = arm(&chooser, (1, incarnation), [0, 1, 0]);
    assert_eq!(
        acting(|| s.pool().capture_membership_lock()).err(),
        Some(GateError::Contended)
    );
    drop(acting(|| s.pool().capture_lock()).expect("a free mutex"));
    assert_eq!(armed.disarm(), None);
    assert_eq!(chooser.borrow().decisions(), 1);
    drop(acting(|| s.pool().capture_membership_lock()).expect("a free mutex"));

    let held = s.pool().capture_lock().expect("a free mutex");
    let armed = arm(&chooser, (1, incarnation), [0, 1, 0]);
    assert_eq!(
        acting(|| s.pool().capture_membership_lock()).err(),
        Some(GateError::Contended)
    );
    assert_eq!(
        chooser.borrow().decisions(),
        2,
        "the point decides ahead of the mutex try"
    );
    assert_eq!(armed.disarm(), None);
    assert_eq!(
        acting(|| s.pool().capture_membership_lock()).err(),
        Some(GateError::Contended)
    );
    assert_eq!(chooser.borrow().decisions(), 2);
    drop(held);
}

/// Batches of five slots emit the entries a one-slot-per-call pass emits, in slot order, and no batch visits more than five slots.
#[test]
fn batched_visits_emit_the_single_slot_entries() {
    let s = storage(16, &index_config(&[16], (1, 1), 2));
    for n in 0..10 {
        completed(&s, key(n)).publish(TRIES, &mut budget()).unwrap();
    }
    s.start_capture(16, true, 16).unwrap();
    let (mut batched, mut visits) = (Vec::new(), Vec::new());
    loop {
        let visited = s.capture_visit(1, 5, |e| batched.push(e.clone())).unwrap();
        if visited == 0 {
            break;
        }
        visits.push(visited);
    }
    assert!(visits.iter().all(|&visited| visited <= 5));
    assert_eq!(visits.iter().sum::<usize>(), 16);
    assert_eq!(s.capture_saved(1).unwrap(), Vec::new());
    finish(&s);
    s.start_capture(16, true, 16).unwrap();
    let single: Vec<_> = (0..16).filter_map(|_| s.capture_next(2).unwrap()).collect();
    assert_eq!(s.capture_next(2), Ok(None));
    assert_eq!(batched.len(), 10);
    assert_eq!(batched, single);
}

/// `capture_visit` returns `Err(CaptureError::InvalidConfig)` for `max == 0` and preserves the cursor, reserving `Ok(0)` for the end of the walk.
#[test]
fn a_zero_batch_is_refused_and_leaves_the_cursor_in_place() {
    let s = storage(4, &index_config(&[4], (1, 1), 2));
    completed(&s, key(1)).publish(TRIES, &mut budget()).unwrap();
    s.start_capture(4, true, 4).unwrap();
    assert_eq!(
        s.capture_visit(1, 0, |_| {}),
        Err(CaptureError::InvalidConfig)
    );
    let mut seen = 0;
    assert_eq!(s.capture_visit(1, 4, |_| seen += 1), Ok(4));
    assert_eq!(seen, 1);
    assert_eq!(s.capture_visit(1, 4, |_| {}), Ok(0));
}

/// A sink that panics abandons the pass without poisoning capture serialization, so the next visit reports `Abandoned` and membership changes still commit.
#[test]
fn a_panicking_sink_abandons_the_pass_and_keeps_membership_usable() {
    let s = storage(4, &index_config(&[4], (1, 1), 2));
    let a = completed(&s, key(1)).publish(TRIES, &mut budget()).unwrap();
    s.start_capture(4, true, 4).unwrap();
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        s.capture_visit(1, 4, |_| panic!("sink"))
    }));
    assert!(caught.is_err());
    assert_eq!(s.capture_visit(1, 4, |_| {}), Err(CaptureError::Abandoned));
    assert!(s.pool().capture_lock().is_ok());
    s.remove(&key(1), a, TRIES, &mut budget()).unwrap();
    completed(&s, key(2)).publish(TRIES, &mut budget()).unwrap();
}

/// A member whose record names a sequence block it does not own panics `capture_visit`; afterwards `capture_lock` and `try_lock_quiet` report `Poisoned`.
#[test]
fn a_corrupt_member_poisons_the_gate_and_capture_serialization() {
    let s = storage(4, &index_config(&[4], (1, 1), 2));
    let a = completed(&s, key(1)).publish(TRIES, &mut budget()).unwrap();
    let handle = super::held::Held::Sequence {
        block: super::blocks::Block(0),
        count: 2,
    };
    s.pool().records()[a.slot_index()].set_locator(handle.locator());
    s.start_capture(4, true, 4).unwrap();
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        s.capture_visit(1, 4, |_| {})
    }));
    assert!(caught.is_err());
    assert_eq!(s.pool().capture_lock().err(), Some(GateError::Poisoned));
    assert_eq!(s.pool().try_lock_quiet().err(), Some(GateError::Poisoned));
}

/// A destructor of a thread that is already unwinding visits a corrupt member and catches the table-walk panic. Guards taken there release unpoisoned on drop, so the visit poisons both locks itself: afterwards `try_lock_quiet` and `capture_lock` report `Poisoned`, every capture call reports `Poisoned`, and a membership change still recovers the guard.
#[test]
fn a_corrupt_member_walked_during_unwinding_poisons_the_gate_and_capture_serialization() {
    type Fixture = super::owner::Storage<super::test_platform::TestPlatform>;
    struct VisitsOnDrop<'a>(&'a Fixture);
    impl Drop for VisitsOnDrop<'_> {
        fn drop(&mut self) {
            let s = self.0;
            let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                s.capture_visit(1, 4, |_| {})
            }));
            assert!(caught.is_err());
        }
    }
    let s = storage(4, &index_config(&[4], (1, 1), 2));
    let a = completed(&s, key(1)).publish(TRIES, &mut budget()).unwrap();
    let handle = super::held::Held::Sequence {
        block: super::blocks::Block(0),
        count: 2,
    };
    s.pool().records()[a.slot_index()].set_locator(handle.locator());
    s.start_capture(4, true, 4).unwrap();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _visitor = VisitsOnDrop(&s);
        panic!("an unrelated panic with a live visitor");
    }));
    assert!(outcome.is_err());
    assert_eq!(s.pool().try_lock_quiet().err(), Some(GateError::Poisoned));
    assert_eq!(s.pool().capture_lock().err(), Some(GateError::Poisoned));
    let poisoned = Err(CaptureError::Poisoned);
    assert_eq!(s.capture_visit(1, 4, |_| {}), poisoned);
    assert_eq!(s.capture_next(1).map(|_| 0), poisoned);
    assert_eq!(s.capture_side_len(1), poisoned);
    assert_eq!(s.capture_saved(1).map(|_| 0), poisoned);
    assert_eq!(s.submit_capture_unit(1, || 0), poisoned);
    assert_eq!(s.start_capture(4, true, 4).map(|_| 0), poisoned);
    assert_eq!(s.require_suffix().map(|()| 0), poisoned);
    assert_eq!(s.with_suffix(|_| 0), poisoned);
    assert!(s.pool().capture_membership_lock().is_ok());
    assert_eq!(s.pool().capture_lock().err(), Some(GateError::Poisoned));
}

/// One batch that visits a three-extent sequence and a one-extent member hands each member exactly its own extent words, so the refilled entry keeps no words from an earlier member.
#[test]
fn the_refilled_entry_carries_only_its_members_extents() {
    use super::publish_tests::{PAGE, storage_config, storage_from};
    let mut cfg = storage_config(4);
    cfg.volume = crate::storage::test_volume(512 * super::IO_UNIT, 4);
    cfg.volume.block_roots = 1;
    cfg.body_cap = 200_000;
    let mut s = storage_from(
        &cfg,
        &index_config(&[4], (1, 1), 2),
        super::test_platform::TestPlatform::heap(PAGE),
    );
    let long = completed(&s, key(1)).publish(TRIES, &mut budget()).unwrap();
    let object = super::sequence_tests::published_sequence(&s, long, 3);
    let words: Vec<_> = object.extents.iter().map(|l| l.bits()).collect();
    let short = completed(&s, key(2)).publish(TRIES, &mut budget()).unwrap();
    s.start_capture(4, true, 4).unwrap();
    let mut captured = Vec::new();
    while s.capture_visit(1, 4, |e| captured.push(e.clone())).unwrap() > 0 {}
    let of = |id: super::AllocationId| {
        captured
            .iter()
            .find(|e| e.allocation == id.record_tag())
            .unwrap()
    };
    assert_eq!(captured.len(), 2);
    assert_eq!(of(long).extents, words);
    assert_eq!(of(short).extents.len(), 1);
    finish(&s);
    s.close();
    for _ in 0..8 {
        s.close_service(&mut super::WorkBudget::new(4096)).unwrap();
    }
    let _ = s.certify(&mut budget()).unwrap();
    for _ in 0..8 {
        s.service(&mut budget()).unwrap();
    }
    super::test_platform::finalize(&mut s).unwrap();
}

/// The corrupt snapshot member of the removal tests below: published before the pass starts, its locator rewritten into a sequence handle it does not own, so the removal's side-list copy panics in `capture_entry`.
fn corrupt_member_under_a_pass() -> (
    super::owner::Storage<super::test_platform::TestPlatform>,
    super::AllocationId,
) {
    let s = storage(4, &index_config(&[4], (1, 1), 2));
    let a = completed(&s, key(1)).publish(TRIES, &mut budget()).unwrap();
    let handle = super::held::Held::Sequence {
        block: super::blocks::Block(0),
        count: 2,
    };
    s.pool().records()[a.slot_index()].set_locator(handle.locator());
    s.start_capture(4, true, 4).unwrap();
    (s, a)
}

/// A removal whose side-list copy panics on a corrupt member, on a thread that is not unwinding, poisons the pool gate and the capture mutex.
#[test]
fn a_removal_walk_panic_poisons_the_gate_and_capture_serialization() {
    let (s, a) = corrupt_member_under_a_pass();
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        s.remove(&key(1), a, TRIES, &mut budget())
    }));
    assert!(caught.is_err());
    assert_eq!(s.pool().try_lock_quiet().err(), Some(GateError::Poisoned));
    assert_eq!(s.pool().capture_lock().err(), Some(GateError::Poisoned));
}

/// The same removal made by a destructor of a thread that is already unwinding, its panic caught there. Guards taken there release unpoisoned on drop, so the removal poisons both locks itself: afterwards `try_lock_quiet` and `capture_lock` report `Poisoned`, a capture call reports `Poisoned`, and a membership change still recovers the guard.
#[test]
fn a_removal_walk_panic_during_unwinding_poisons_the_gate_and_capture_serialization() {
    type Fixture = super::owner::Storage<super::test_platform::TestPlatform>;
    struct RemovesOnDrop<'a>(&'a Fixture, super::AllocationId);
    impl Drop for RemovesOnDrop<'_> {
        fn drop(&mut self) {
            let (s, a) = (self.0, self.1);
            let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                s.remove(&key(1), a, TRIES, &mut budget())
            }));
            assert!(caught.is_err());
        }
    }
    let (s, a) = corrupt_member_under_a_pass();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _remover = RemovesOnDrop(&s, a);
        panic!("an unrelated panic with a live remover");
    }));
    assert!(outcome.is_err());
    assert_eq!(s.pool().try_lock_quiet().err(), Some(GateError::Poisoned));
    assert_eq!(s.pool().capture_lock().err(), Some(GateError::Poisoned));
    assert_eq!(s.capture_visit(1, 4, |_| {}), Err(CaptureError::Poisoned));
    assert!(s.pool().capture_membership_lock().is_ok());
}

/// The removal ends its mapping under the key's shard gate, so the same panic poisons that gate as well (`gate.rs`: "A holder that panics poisons the gate on release"), on a thread that is not unwinding and in a removal made by a destructor while its thread unwinds from another panic: the shard guard, taken during the unwind, would release open on drop.
#[test]
fn a_removal_walk_panic_poisons_the_shard_gate_even_during_unwinding() {
    type Fixture = super::owner::Storage<super::test_platform::TestPlatform>;
    struct RemovesOnDrop<'a>(&'a Fixture, super::AllocationId);
    impl Drop for RemovesOnDrop<'_> {
        fn drop(&mut self) {
            let (s, a) = (self.0, self.1);
            let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                s.remove(&key(1), a, TRIES, &mut budget())
            }));
            assert!(caught.is_err());
        }
    }
    for unwinding in [false, true] {
        let (s, a) = corrupt_member_under_a_pass();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let remover = RemovesOnDrop(&s, a);
            if unwinding {
                panic!("an unrelated panic with a live remover");
            }
            drop(remover);
        }));
        assert_eq!(outcome.is_err(), unwinding, "premise");
        let index = s.index.as_ref().unwrap();
        let poisoned = (0..index.geometry.shards().len())
            .filter_map(|shard| index.image.shard(crate::index::ShardIndex(shard)))
            .filter(|shard| {
                // SAFETY: the index mapping is live.
                let gate = unsafe { shard.gate(&index.mapping) };
                gate.try_lock().err() == Some(GateError::Poisoned)
            })
            .count();
        assert_eq!(
            poisoned, 1,
            "the removal's panic poisons its shard gate, unwinding={unwinding}"
        );
    }
}

/// The close sweep removes each occupant under the shard hold its read took (`closing.rs` `read_run`, ended inside `Storage::remove_held`), so the side-list copy's panic poisons that shard gate as well (`gate.rs`: "A holder that panics poisons the gate on release"), on a thread that is not unwinding and in a close service called by a destructor while its thread unwinds from another panic: the shard guard, taken during the unwind, would release open on drop.
#[test]
fn a_close_sweep_removal_panic_poisons_the_shard_gate_even_during_unwinding() {
    type Fixture = super::owner::Storage<super::test_platform::TestPlatform>;
    struct SweepsOnDrop<'a>(&'a Fixture);
    impl Drop for SweepsOnDrop<'_> {
        fn drop(&mut self) {
            let s = self.0;
            let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                s.close_service(&mut budget())
            }));
            assert!(caught.is_err(), "premise: the sweep's removal panics");
        }
    }
    for unwinding in [false, true] {
        let (s, _) = corrupt_member_under_a_pass();
        s.close();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let sweeper = SweepsOnDrop(&s);
            if unwinding {
                panic!("an unrelated panic with a live sweeper");
            }
            drop(sweeper);
        }));
        assert_eq!(outcome.is_err(), unwinding, "premise");
        assert_eq!(
            s.close_service(&mut budget()).err(),
            Some(super::closing::CloseError::Poisoned),
            "premise: the sweep's panic poisons the close cursor, unwinding={unwinding}"
        );
        let index = s.index.as_ref().unwrap();
        let poisoned = (0..index.geometry.shards().len())
            .filter_map(|shard| index.image.shard(crate::index::ShardIndex(shard)))
            .filter(|shard| {
                // SAFETY: the index mapping is live.
                let gate = unsafe { shard.gate(&index.mapping) };
                gate.try_lock().err() == Some(GateError::Poisoned)
            })
            .count();
        assert_eq!(
            poisoned, 1,
            "the sweep's panic poisons the occupant's shard gate, unwinding={unwinding}"
        );
    }
}
