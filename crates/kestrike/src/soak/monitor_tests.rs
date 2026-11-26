use std::num::NonZeroU8;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use super::*;
use crate::storage::owner_fixture::{
    Device, SimControl, SimDisk, TestPlatform, arena_on, heap_storage_on, last_read,
};
use crate::storage::{BufferArena, CommandToken, ControlRefusal};

const B_READ: Duration = Duration::from_micros(100);
const CONFIG: SoakConfig = SoakConfig {
    seed: 0x5eed,
    keys: NonZeroU8::new(4).unwrap(),
    body_cap: 100,
    capacity: 8,
    pressure: 2,
    cut_every: 8,
    patience: B_READ,
};

pub(super) type SimSoak<'s, 'a> = Soak<'s, 'a, TestPlatform, SimDisk, Vec<u8>>;

pub(super) fn fixture() -> (Storage<TestPlatform>, BufferArena<TestPlatform>) {
    (
        heap_storage_on(512 << 10, 64 << 10),
        arena_on(TestPlatform::heap(4096), 16, 8),
    )
}

fn soak<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    arena: &'a BufferArena<TestPlatform>,
) -> (SimSoak<'s, 'a>, SimControl) {
    let Device { volume, control } = Device::new(storage, arena);
    let reader = storage.register().unwrap();
    let mut soak = Soak::new(
        storage,
        volume,
        reader,
        SoakConfig {
            patience: Duration::from_secs(10),
            ..CONFIG
        },
        Vec::new(),
    );
    soak.device = Some(control.clone());
    soak.clock = Some(10);
    for n in 0..2 {
        soak.fill(n).unwrap();
        for _ in 0..100 {
            control.tick(64);
            let mut events = Vec::with_capacity(8);
            soak.volume.poll_storage(10, &mut events);
            assert!(events.is_empty());
            soak.advance();
            if soak.published[n as usize].is_some() {
                break;
            }
        }
        assert!(soak.published[n as usize].is_some());
    }
    soak.config.patience = B_READ;
    assert_eq!(soak.failure(), None);
    (soak, control)
}

fn held(soak: &mut SimSoak<'_, '_>, control: &SimControl, n: u8) -> CommandToken {
    soak.read(n).unwrap();
    let token = last_read(control).unwrap();
    control.try_hold(token).unwrap();
    let read = soak.reads.last().unwrap();
    assert_eq!(read.admitted_at, 10);
    assert_eq!(read.deadline, 110);
    token
}

fn monitored(soak: &SimSoak<'_, '_>) -> (Option<SoakFailure>, (u64, u64, u64)) {
    (soak.failure(), (soak.cancelled, soak.stalled, soak.missing))
}

fn closed(soak: SimSoak<'_, '_>, failure: Option<SoakFailure>) -> Option<SoakFailure> {
    let ended = soak.close();
    assert_eq!(ended.failure, failure);
    ended.failure
}

fn unsolicited_case() -> Option<SoakFailure> {
    let (storage, arena) = fixture();
    let (mut soak, control) = soak(&storage, &arena);
    let token = held(&mut soak, &control, 0);
    let read = &soak.reads[0];
    let (run, id, op) = (read.run, read.id, read.op);
    assert_eq!(read.cancellation, None);
    assert_eq!(soak.volume.cancel_read(op), Ok(()));
    soak.poll();
    assert_eq!(
        monitored(&soak),
        (Some(SoakFailure::Cancelled { run, id, op }), (1, 0, 0))
    );
    assert!(soak.reads.is_empty());
    assert_eq!(control.pending(), 1);
    assert_eq!(control.try_hold(token), Ok(()));
    assert_eq!(soak.volume.table_report().abandoned, 1);
    control.release(token);
    soak.config.patience = Duration::from_secs(1);
    let ended = soak.close();
    assert_eq!(ended.failure, Some(SoakFailure::Cancelled { run, id, op }));
    ended.failure
}

fn requested_case() -> Option<SoakFailure> {
    let (storage, arena) = fixture();
    let (mut soak, control) = soak(&storage, &arena);
    let token = held(&mut soak, &control, 0);
    let op = soak.reads[0].op;
    soak.cancel(0);
    assert_eq!(soak.reads[0].cancellation, Some(Ok(())));
    assert_eq!(soak.reads[0].op, op);
    soak.poll();
    assert!(soak.reads.is_empty());
    assert_eq!(monitored(&soak), (None, (0, 0, 0)));
    assert_eq!(control.pending(), 1);
    assert_eq!(control.try_hold(token), Ok(()));
    control.release(token);
    soak.config.patience = Duration::from_secs(1);
    let ended = soak.close();
    assert_eq!(ended.failure, None);
    ended.failure
}

fn other_read_case() -> Option<SoakFailure> {
    let (storage, arena) = fixture();
    let (mut soak, control) = soak(&storage, &arena);
    let first = held(&mut soak, &control, 0);
    let second = held(&mut soak, &control, 1);
    let (run, id, op) = (soak.reads[0].run, soak.reads[0].id, soak.reads[0].op);
    assert_ne!(soak.reads[1].id, id);
    assert_ne!(soak.reads[1].op, op);
    soak.cancel(1);
    assert_eq!(soak.reads[1].cancellation, Some(Ok(())));
    assert_eq!(soak.reads[0].cancellation, None);
    assert_eq!(soak.volume.cancel_read(op), Ok(()));
    soak.poll();
    assert!(soak.reads.is_empty());
    let cancelled = Some(SoakFailure::Cancelled { run, id, op });
    assert_eq!(monitored(&soak), (cancelled, (1, 0, 0)));
    control.release(first);
    control.release(second);
    soak.config.patience = Duration::from_secs(1);
    closed(soak, cancelled)
}

fn stalled_case() -> Option<SoakFailure> {
    let (storage, arena) = fixture();
    let (mut soak, control) = soak(&storage, &arena);
    let token = held(&mut soak, &control, 0);
    let (run, id, op) = (soak.reads[0].run, soak.reads[0].id, soak.reads[0].op);
    soak.read(1).unwrap();
    let other_id = soak.reads[1].id;
    soak.clock = Some(109);
    soak.poll();
    assert!(soak.reads.iter().all(|read| read.id != other_id));
    assert_eq!(monitored(&soak), (None, (0, 0, 0)));
    soak.clock = Some(110);
    soak.poll();
    assert_eq!(
        monitored(&soak),
        (
            Some(SoakFailure::Stalled {
                run,
                id,
                op,
                deadline: 110
            }),
            (0, 1, 0)
        )
    );
    assert_eq!(soak.reads[0].id, id);
    assert_eq!(soak.reads[0].cancellation, None);
    assert!(soak.reads[0].stalled);
    assert_eq!(control.pending(), 1);
    assert_eq!(control.try_hold(token), Ok(()));
    assert_eq!(soak.volume.table_report().pending, 1);
    soak.poll();
    assert_eq!(soak.stalled, 1);
    soak.cancel(0);
    soak.poll();
    assert_eq!(control.pending(), 1);
    assert_eq!(control.try_hold(token), Ok(()));
    control.release(token);
    soak.config.patience = Duration::from_secs(1);
    let ended = soak.close();
    assert_eq!(
        ended.failure,
        Some(SoakFailure::Stalled {
            run,
            id,
            op,
            deadline: 110
        })
    );
    assert!(
        String::from_utf8(ended.receipt)
            .unwrap()
            .contains("\"stalled\": 1")
    );
    ended.failure
}

fn other_key_case() -> Option<SoakFailure> {
    let storage = heap_storage_on(5 * crate::storage::IO_UNIT, 100);
    let arena = arena_on(TestPlatform::heap(4096), 16, 8);
    let (mut soak, _) = soak(&storage, &arena);
    let target = soak.published[1].unwrap();
    soak.poll();
    assert_eq!(storage.maintain_totals().evicted, 1);
    assert!(matches!(
        soak.reader.lookup(&key(0), TRIES, &mut budget()),
        Err(LookupError::Missing)
    ));
    assert_eq!(
        soak.reader
            .lookup(&key(1), TRIES, &mut budget())
            .unwrap()
            .id(),
        target.allocation
    );
    let target_resident = soak.published[1].unwrap().resident;
    let other_resident = soak.published[0].unwrap().resident;
    storage.invalidate(&key(1), TRIES, &mut budget()).unwrap();
    assert!(matches!(
        soak.reader.lookup(&key(1), TRIES, &mut budget()),
        Err(LookupError::Missing)
    ));
    assert!(soak.lookup(1).is_none());
    let missing = Some(SoakFailure::Missing {
        key: 1,
        generation: target.generation,
    });
    assert_eq!(monitored(&soak), (missing, (0, 0, 1)));
    assert!(target_resident);
    assert!(!other_resident);
    assert!(soak.published[1].is_none());
    closed(soak, missing)
}

fn target_eviction_case() -> Option<SoakFailure> {
    let storage = heap_storage_on(5 * crate::storage::IO_UNIT, 100);
    let arena = arena_on(TestPlatform::heap(4096), 16, 8);
    let (mut soak, _) = soak(&storage, &arena);
    let other = soak.published[1].unwrap();
    soak.poll();
    assert_eq!(storage.maintain_totals().evicted, 1);
    let other_resident = soak.published[1].unwrap().resident;
    assert_eq!(
        soak.reader
            .lookup(&key(1), TRIES, &mut budget())
            .unwrap()
            .id(),
        other.allocation
    );
    let target_resident = soak.published[0].unwrap().resident;
    assert!(matches!(
        soak.reader.lookup(&key(0), TRIES, &mut budget()),
        Err(LookupError::Missing)
    ));
    assert!(soak.lookup(0).is_none());
    assert_eq!(monitored(&soak), (None, (0, 0, 0)));
    assert!(!target_resident);
    assert!(other_resident);
    closed(soak, None)
}

fn own_invalidation_case() -> Option<SoakFailure> {
    let (storage, arena) = fixture();
    let (mut soak, _) = soak(&storage, &arena);
    soak.invalidate(0).unwrap();
    assert!(soak.published[0].is_none());
    assert!(soak.lookup(0).is_none());
    assert_eq!(monitored(&soak), (None, (0, 0, 0)));
    closed(soak, None)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Category {
    Passed,
    Cancelled,
    Stalled,
    Missing,
    Interrupted,
}

fn category(observed: Option<SoakFailure>) -> Category {
    match observed {
        None => Category::Passed,
        Some(SoakFailure::Cancelled { .. }) => Category::Cancelled,
        Some(SoakFailure::Stalled { .. }) => Category::Stalled,
        Some(SoakFailure::Missing { .. }) => Category::Missing,
        Some(SoakFailure::Interrupted) => Category::Interrupted,
        failure => panic!("unexpected monitor outcome: {failure:?}"),
    }
}

struct Case {
    name: &'static str,
    deadline: Duration,
    run: fn() -> Option<SoakFailure>,
}

const CASE_DEADLINE: Duration = Duration::from_secs(10);
const REQUIRED: [(&str, Category); 15] = [
    ("cancel/requested", Category::Passed),
    ("cancel/unsolicited", Category::Cancelled),
    ("cancel/other-read", Category::Cancelled),
    ("deadline/held-with-progress", Category::Stalled),
    ("missing/other-key", Category::Missing),
    ("missing/target-eviction", Category::Passed),
    ("missing/own-invalidation", Category::Passed),
    ("cancel/complete-after-refusal", Category::Passed),
    ("cancel/reused-read-slot", Category::Cancelled),
    ("deadline/terminal-tie-and-saturation", Category::Passed),
    ("deadline/close-before-cancel", Category::Stalled),
    ("missing/old-incarnation", Category::Missing),
    ("receipt/first-failure", Category::Interrupted),
    ("deadline/requested-withheld-terminal", Category::Stalled),
    ("cancel/refused-after-decision", Category::Cancelled),
];
const CASES: [Case; 15] = [
    Case {
        name: "cancel/requested",
        deadline: CASE_DEADLINE,
        run: requested_case,
    },
    Case {
        name: "cancel/unsolicited",
        deadline: CASE_DEADLINE,
        run: unsolicited_case,
    },
    Case {
        name: "cancel/other-read",
        deadline: CASE_DEADLINE,
        run: other_read_case,
    },
    Case {
        name: "deadline/held-with-progress",
        deadline: CASE_DEADLINE,
        run: stalled_case,
    },
    Case {
        name: "missing/other-key",
        deadline: CASE_DEADLINE,
        run: other_key_case,
    },
    Case {
        name: "missing/target-eviction",
        deadline: CASE_DEADLINE,
        run: target_eviction_case,
    },
    Case {
        name: "missing/own-invalidation",
        deadline: CASE_DEADLINE,
        run: own_invalidation_case,
    },
    Case {
        name: "cancel/complete-after-refusal",
        deadline: CASE_DEADLINE,
        run: cancellation_intent_precedes_control_and_refused_control_keeps_terminal_pending_case,
    },
    Case {
        name: "cancel/reused-read-slot",
        deadline: CASE_DEADLINE,
        run: reused_read_slot_requires_its_own_cancellation_intent_case,
    },
    Case {
        name: "deadline/terminal-tie-and-saturation",
        deadline: CASE_DEADLINE,
        run: terminal_wins_deadline_tie_and_deadline_saturates_case,
    },
    Case {
        name: "deadline/close-before-cancel",
        deadline: CASE_DEADLINE,
        run: close_sweeps_all_overdue_identities_before_cancellation_case,
    },
    Case {
        name: "missing/old-incarnation",
        deadline: CASE_DEADLINE,
        run: old_incarnation_eviction_keeps_republished_generation_obligated_case,
    },
    Case {
        name: "receipt/first-failure",
        deadline: CASE_DEADLINE,
        run: earlier_failure_survives_while_all_monitor_categories_count_case,
    },
    Case {
        name: "deadline/requested-withheld-terminal",
        deadline: CASE_DEADLINE,
        run: requested_cancel_withheld_terminal_case,
    },
    Case {
        name: "cancel/refused-after-decision",
        deadline: CASE_DEADLINE,
        run: refused_cancel_cannot_authorize_a_cancelled_terminal_case,
    },
];

fn witness(case: &Case) -> Option<SoakFailure> {
    let (done, finished) = mpsc::channel();
    let run = case.run;
    let worker = thread::spawn(move || {
        let observed = run();
        let _ = done.send(observed);
    });
    match finished.recv_timeout(case.deadline) {
        Ok(observed) => {
            worker.join().unwrap();
            observed
        }
        Err(RecvTimeoutError::Disconnected) => {
            std::panic::resume_unwind(worker.join().unwrap_err())
        }
        Err(RecvTimeoutError::Timeout) => panic!(
            "{} gave no witness within {:?}: missing evidence",
            case.name, case.deadline
        ),
    }
}

fn run_case(name: &str) -> Option<SoakFailure> {
    let case = CASES.iter().find(|case| case.name == name).unwrap();
    witness(case)
}

#[test]
fn every_frozen_monitor_case_has_an_identity_witness_and_read_bound() {
    assert_eq!(CONFIG.patience, B_READ);
    assert!(CONFIG.patience > Duration::ZERO);
    let mut witnessed = Vec::new();
    for case in &CASES {
        let observed = category(witness(case));
        assert!(!witnessed.iter().any(|&(name, _)| name == case.name));
        assert!(
            REQUIRED.contains(&(case.name, observed)),
            "{} observed {observed:?}",
            case.name
        );
        witnessed.push((case.name, observed));
    }
    assert!(REQUIRED.iter().all(|required| witnessed.contains(required)));
}

#[test]
fn unsolicited_cancelled_fails_before_device_custody_releases() {
    run_case("cancel/unsolicited");
}
#[test]
fn cancellation_of_another_read_cannot_authorize_a_terminal() {
    run_case("cancel/other-read");
}
#[test]
fn requested_cancellation_has_exact_identity_and_control_result() {
    run_case("cancel/requested");
}
#[test]
fn another_completion_leaves_held_reads_deadline_live() {
    run_case("deadline/held-with-progress");
}
#[test]
fn another_keys_eviction_cannot_authorize_missing() {
    run_case("missing/other-key");
}
#[test]
fn matching_removal_and_own_invalidation_authorize_missing() {
    run_case("missing/target-eviction");
    run_case("missing/own-invalidation");
}

fn terminal_wins_deadline_tie_and_deadline_saturates_case() -> Option<SoakFailure> {
    let (storage, arena) = fixture();
    let (mut soak, control) = soak(&storage, &arena);
    soak.read(0).unwrap();
    soak.clock = Some(110);
    soak.poll();
    assert!(soak.reads.is_empty());
    assert_eq!(soak.stalled, 0);
    assert_eq!(soak.failure(), None);
    soak.clock = Some(u64::MAX - 20);
    soak.read(1).unwrap();
    let op = soak.reads[0].op;
    let token = last_read(&control).unwrap();
    control.try_hold(token).unwrap();
    assert_eq!(soak.reads[0].admitted_at, u64::MAX - 20);
    assert_eq!(soak.reads[0].deadline, u64::MAX);
    soak.clock = Some(u64::MAX - 1);
    soak.poll();
    assert_eq!(soak.stalled, 0);
    assert_eq!(soak.failure(), None);
    assert_eq!(soak.reads.len(), 1);
    assert_eq!(soak.reads[0].op, op);
    assert_eq!(control.try_hold(token), Ok(()));
    control.release(token);
    soak.poll();
    assert!(soak.reads.is_empty());
    assert_eq!(soak.settled, 4);
    assert_eq!(soak.failure(), None);
    assert_eq!(soak.stalled, 0);
    let ended = soak.close();
    assert_eq!(ended.failure, None);
    ended.failure
}

fn old_incarnation_eviction_keeps_republished_generation_obligated_case() -> Option<SoakFailure> {
    let (storage, arena) = fixture();
    let (mut soak, _) = soak(&storage, &arena);
    let old = soak.published[0].unwrap();
    soak.invalidate(0).unwrap();
    soak.config.patience = Duration::from_secs(1);
    soak.fill(0).unwrap();
    for _ in 0..100 {
        soak.poll();
        if soak.published[0].is_some() {
            break;
        }
    }
    let current = soak.published[0].unwrap();
    assert_ne!(old.generation, current.generation);
    assert_ne!(old.allocation, current.allocation);
    soak.removed(RemovedMember {
        fingerprint: soak.fingerprints[0] ^ 1,
        allocation: current.allocation,
    });
    assert!(soak.published[0].unwrap().resident);
    let stale_same_slot = crate::storage::AllocationId::new(
        crate::storage::SlotIndex(current.allocation.slot_index()),
        current.allocation.incarnation() - 1,
    );
    assert_eq!(
        stale_same_slot.slot_index(),
        current.allocation.slot_index()
    );
    assert_ne!(stale_same_slot, current.allocation);
    soak.removed(RemovedMember {
        fingerprint: soak.fingerprints[0],
        allocation: stale_same_slot,
    });
    assert!(soak.published[0].unwrap().resident);
    soak.removed(RemovedMember {
        fingerprint: soak.fingerprints[0],
        allocation: old.allocation,
    });
    assert!(soak.published[0].unwrap().resident);
    let other = soak.published[1].unwrap();
    assert_ne!(other.allocation, current.allocation);
    soak.removed(RemovedMember {
        fingerprint: soak.fingerprints[0],
        allocation: other.allocation,
    });
    assert!(soak.published[0].unwrap().resident);
    storage.invalidate(&key(0), TRIES, &mut budget()).unwrap();
    assert!(soak.lookup(0).is_none());
    let missing = Some(SoakFailure::Missing {
        key: 0,
        generation: current.generation,
    });
    assert_eq!(monitored(&soak), (missing, (0, 0, 1)));
    closed(soak, missing)
}

fn earlier_failure_survives_while_all_monitor_categories_count_case() -> Option<SoakFailure> {
    let (storage, arena) = fixture();
    let (mut soak, control) = soak(&storage, &arena);
    soak.fail(SoakFailure::Interrupted);
    let token = held(&mut soak, &control, 0);
    soak.clock = Some(110);
    soak.poll();
    let op = soak.reads[0].op;
    soak.volume.cancel_read(op).unwrap();
    soak.poll();
    storage.invalidate(&key(1), TRIES, &mut budget()).unwrap();
    soak.lookup(1);
    assert_eq!((soak.cancelled, soak.stalled, soak.missing), (1, 1, 1));
    assert_eq!(soak.failure(), Some(SoakFailure::Interrupted));
    soak.checkpoint();
    control.release(token);
    soak.config.patience = Duration::from_secs(1);
    let ended = soak.close();
    assert_eq!(ended.failure, Some(SoakFailure::Interrupted));
    for line in String::from_utf8(ended.receipt).unwrap().lines() {
        for category in ["cancelled", "stalled", "missing"] {
            assert!(line.contains(&format!("\"{category}\": 1")), "{line}");
        }
    }
    ended.failure
}

thread_local! {
    static INTENT: std::cell::Cell<Option<(u64, u64, ReadOp)>> = const { std::cell::Cell::new(None) };
}

fn observe_intent(read: &Read) {
    assert_eq!(
        INTENT.with(std::cell::Cell::get),
        Some((read.run, read.id, read.op))
    );
    assert_eq!(read.cancellation, None);
}

fn cancellation_intent_precedes_control_and_refused_control_keeps_terminal_pending_case()
-> Option<SoakFailure> {
    let (storage, arena) = fixture();
    let (mut soak, control) = soak(&storage, &arena);
    soak.read(0).unwrap();
    let read = &soak.reads[0];
    INTENT.with(|intent| intent.set(Some((read.run, read.id, read.op))));
    soak.observe_cancel = Some(observe_intent);
    control.tick(64);
    let mut events = Vec::with_capacity(8);
    soak.volume.poll_storage(10, &mut events);
    assert!(events.iter().any(|event| matches!(
        event,
        ReadEvent::Done {
            status: ReadStatus::Complete,
            ..
        }
    )));
    soak.cancel(0);
    assert_eq!(soak.reads[0].cancellation, Some(Err(ControlRefusal::Stale)));
    assert_eq!(soak.reads.len(), 1);
    assert_eq!(soak.settled, 2);
    for event in events {
        match event {
            ReadEvent::Chunk { chunk, .. } => soak.reads[0].bytes.extend_from_slice(chunk.bytes()),
            ReadEvent::Done { op, status, .. } => soak.done(op, status),
        }
    }
    assert!(soak.reads.is_empty());
    assert_eq!(soak.failure(), None);
    soak.close().failure
}

fn close_sweeps_all_overdue_identities_before_cancellation_case() -> Option<SoakFailure> {
    let (storage, arena) = fixture();
    let (mut soak, control) = soak(&storage, &arena);
    let first = held(&mut soak, &control, 0);
    let second = held(&mut soak, &control, 1);
    let (run, id, op) = (soak.reads[0].run, soak.reads[0].id, soak.reads[0].op);
    soak.clock = Some(110);
    soak.observe_cancel = Some(|read| {
        assert!(read.stalled);
        assert_eq!(read.cancellation, None);
    });
    soak.config.patience = Duration::from_secs(1);
    let ended = soak.close();
    assert_eq!(
        ended.failure,
        Some(SoakFailure::Stalled {
            run,
            id,
            op,
            deadline: 110
        })
    );
    assert!(
        String::from_utf8(ended.receipt)
            .unwrap()
            .contains("\"stalled\": 2")
    );
    control.release(first);
    control.release(second);
    ended.failure
}

fn reused_read_slot_requires_its_own_cancellation_intent_case() -> Option<SoakFailure> {
    let (storage, arena) = fixture();
    let (mut soak, control) = soak(&storage, &arena);
    soak.read(0).unwrap();
    let (old, old_id) = (soak.reads[0].op, soak.reads[0].id);
    soak.cancel(0);
    assert_eq!(soak.reads[0].cancellation, Some(Ok(())));
    soak.poll();
    assert!(soak.reads.is_empty());
    assert_eq!(soak.failure(), None);
    let token = held(&mut soak, &control, 0);
    let read = &soak.reads[0];
    let (run, id, op) = (read.run, read.id, read.op);
    assert_ne!(id, old_id);
    assert_eq!(op.slot, old.slot);
    assert_ne!(op.generation, old.generation);
    assert_eq!(read.cancellation, None);
    soak.volume.cancel_read(op).unwrap();
    soak.poll();
    assert!(soak.reads.is_empty());
    let cancelled = Some(SoakFailure::Cancelled { run, id, op });
    assert_eq!(monitored(&soak), (cancelled, (1, 0, 0)));
    control.release(token);
    soak.config.patience = Duration::from_secs(1);
    closed(soak, cancelled)
}

#[test]
fn cancellation_intent_precedes_control_and_refused_control_keeps_terminal_pending() {
    run_case("cancel/complete-after-refusal");
}

#[test]
fn reused_read_slot_requires_its_own_cancellation_intent() {
    run_case("cancel/reused-read-slot");
}

#[test]
fn terminal_wins_deadline_tie_and_deadline_saturates() {
    run_case("deadline/terminal-tie-and-saturation");
}

#[test]
fn close_sweeps_all_overdue_identities_before_cancellation() {
    run_case("deadline/close-before-cancel");
}

#[test]
fn old_incarnation_eviction_keeps_republished_generation_obligated() {
    run_case("missing/old-incarnation");
}

#[test]
fn earlier_failure_survives_while_all_monitor_categories_count() {
    run_case("receipt/first-failure");
}

fn requested_cancel_withheld_terminal_case() -> Option<SoakFailure> {
    let (storage, arena) = fixture();
    let (mut soak, control) = soak(&storage, &arena);
    let token = held(&mut soak, &control, 0);
    let (run, id, op) = (soak.reads[0].run, soak.reads[0].id, soak.reads[0].op);
    soak.cancel(0);
    assert_eq!(soak.reads[0].cancellation, Some(Ok(())));
    assert!(!soak.reads[0].stalled);
    soak.events = Vec::new();
    soak.clock = Some(110);
    soak.poll();
    assert_eq!(
        soak.failure(),
        Some(SoakFailure::Stalled {
            run,
            id,
            op,
            deadline: 110
        })
    );
    assert_eq!(soak.stalled, 1);
    assert_eq!(soak.reads.len(), 1);
    assert_eq!(soak.reads[0].op, op);
    assert!(soak.reads[0].stalled);
    assert_eq!(control.try_hold(token), Ok(()));
    assert_eq!(control.pending(), 1);
    soak.events = Vec::with_capacity(8);
    soak.poll();
    assert!(soak.reads.is_empty());
    assert_eq!(soak.cancelled, 0);
    assert_eq!(soak.stalled, 1);
    assert_eq!(control.try_hold(token), Ok(()));
    control.release(token);
    soak.config.patience = Duration::from_secs(1);
    let ended = soak.close();
    assert_eq!(
        ended.failure,
        Some(SoakFailure::Stalled {
            run,
            id,
            op,
            deadline: 110
        })
    );
    ended.failure
}

// A cancellation decided before the soak's own request reaches the volume
// belongs to another caller. The refused request keeps the read until its
// terminal, and that Cancelled terminal is unauthorized.
fn refused_cancel_cannot_authorize_a_cancelled_terminal_case() -> Option<SoakFailure> {
    let (storage, arena) = fixture();
    let (mut soak, control) = soak(&storage, &arena);
    let token = held(&mut soak, &control, 0);
    let read = &soak.reads[0];
    let (run, id, op) = (read.run, read.id, read.op);
    INTENT.with(|intent| intent.set(Some((run, id, op))));
    soak.observe_cancel = Some(observe_intent);
    soak.volume.cancel_read(op).unwrap();
    soak.cancel(0);
    assert_eq!(soak.reads[0].cancellation, Some(Err(ControlRefusal::Stale)));
    assert_eq!(soak.reads.len(), 1);
    assert_eq!(soak.settled, 2);
    soak.poll();
    assert!(soak.reads.is_empty());
    assert_eq!(soak.settled, 3);
    assert_eq!(
        monitored(&soak),
        (Some(SoakFailure::Cancelled { run, id, op }), (1, 0, 0))
    );
    assert_eq!(control.try_hold(token), Ok(()));
    control.release(token);
    soak.config.patience = Duration::from_secs(1);
    let ended = soak.close();
    assert_eq!(ended.failure, Some(SoakFailure::Cancelled { run, id, op }));
    ended.failure
}

#[test]
fn requested_cancellation_keeps_deadline_live_until_observed_terminal() {
    run_case("deadline/requested-withheld-terminal");
}

#[test]
fn refused_control_cannot_authorize_a_cancelled_terminal() {
    run_case("cancel/refused-after-decision");
}
