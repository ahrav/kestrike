//! Deadlines, quarantine, loss and the per-tick census: every admitted read ends with exactly one `Done`, and nothing a command may still touch is freed before its terminal or a proven stop.

use std::cell::RefCell;
use std::panic::{AssertUnwindSafe, catch_unwind};

use super::super::device::custody_witness::judged;
use super::super::device::sim::{
    Fault, QuiesceMode, ScriptReason, ScriptRefusal, SimControl, Unwind,
};
use super::super::device::{
    Admission, DeviceStatus, PoolKind, QuiesceProgress, Quiesced, Refusal, RefusalReason, Released,
    SubmitRefusal,
};
use super::super::fill::FillSerial;
use super::super::grace_tests::refs;
use super::super::record::HeaderMismatch;
use super::super::seeded::SplitMix64;
use super::volume_tests::{
    CHUNK, DEPTH, Record, SESSION, TICK, TestVolume, arena, arena_with, attach, last_submitted,
    place, record, storage, write, write_set,
};
use super::{ReadEvent, ReadOp, ReadRefusal, ReadStatus, TickConfig, TickReport, attach::Owner};
use crate::sim::round::turn_until;
use crate::sim::round::{Act, Actor, round};

/// The `Done` events of `out`, in order, with every chunk dropped.
pub(super) fn dones(out: &mut Vec<ReadEvent<'_>>) -> Vec<(ReadOp, ReadStatus)> {
    out.drain(..)
        .filter_map(|event| match event {
            ReadEvent::Done { op, status, .. } => Some((op, status)),
            ReadEvent::Chunk { .. } => None,
        })
        .collect()
}

/// One device step of up to eight commands, then one tick at `now`, as one
/// controller round.
pub(super) fn step<'a>(
    volume: &mut TestVolume<'_, 'a>,
    control: &SimControl,
    now: u64,
    out: &mut Vec<ReadEvent<'a>>,
) {
    let mut tick = || control.tick(8);
    let mut poll = || {
        let _ = volume.poll_storage(now, out);
    };
    round(&mut [
        Act::new(Actor::Disk(0), &mut tick),
        Act::new(Actor::Volume(0), &mut poll),
    ]);
}

/// Whether a scripted input applied. A command that has finished, moved its
/// bytes, or already carries a fault rejects scripted input. Any other
/// refusal fails the run.
fn scripted(result: Result<(), ScriptRefusal>) -> bool {
    match result {
        Ok(()) => true,
        Err(ScriptRefusal {
            reason:
                ScriptReason::NotPending(_) | ScriptReason::Executed(_) | ScriptReason::Faulted(_),
            ..
        }) => false,
        Err(refusal) => panic!("{refusal:?}"),
    }
}

/// `s4n-timeout-cancels-and-holds`, `s4n-done-once`: a tick at the read's
/// deadline cancels its held command and delivers one `Done { TimedOut }`;
/// the command stays quarantined, the record keeps the one operation slot,
/// and later ticks deliver nothing. The late terminal frees the buffer and
/// the record silently. A read cancelled before its deadline ends
/// `Cancelled` only, however late its deadline passes.
#[test]
fn a_deadline_cancels_the_command_and_holds_its_record_and_buffer_until_the_real_terminal() {
    let storage = storage(1);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let record = record(0, 0, CHUNK, SESSION, 30);
    place(&storage, &control, &record);
    let op = volume.read_raw(&record.read, 10).expect("admitted");
    let token = last_submitted(&control);
    control.hold(token);
    let mut out = Vec::with_capacity(4);
    step(&mut volume, &control, 9, &mut out);
    assert!(out.is_empty(), "before its deadline the read waits");
    step(&mut volume, &control, 10, &mut out);
    assert_eq!(dones(&mut out), [(op, ReadStatus::TimedOut)]);
    let report = volume.report();
    assert_eq!((report.timed_out, report.quarantines), (1, 1));
    assert_eq!(volume.table_report().abandoned, 1);
    assert_eq!(arena.report(PoolKind::ReadResponse).quarantined, 1);
    assert_eq!(
        volume.read_raw(&record.read, u64::MAX),
        Err(ReadRefusal::OpsExhausted),
        "the record stays held"
    );
    for now in [11, 1 << 40] {
        step(&mut volume, &control, now, &mut out);
    }
    assert!(out.is_empty(), "one Done per operation");
    control.release(token);
    for _ in 0..4 {
        step(&mut volume, &control, 1 << 40, &mut out);
    }
    assert!(out.is_empty(), "the late terminal frees silently");
    assert_eq!(arena.report(PoolKind::ReadResponse).free, 4);
    assert_eq!(volume.table_report().abandoned, 0);
    let cancelled = volume
        .read_raw(&record.read, 1 << 41)
        .expect("the record is free again");
    let token = last_submitted(&control);
    control.hold(token);
    volume.cancel_read(cancelled).expect("live");
    step(&mut volume, &control, 1 << 42, &mut out);
    assert_eq!(dones(&mut out), [(cancelled, ReadStatus::Cancelled)]);
    control.release(token);
    for _ in 0..4 {
        step(&mut volume, &control, 1 << 42, &mut out);
    }
    assert!(out.is_empty());
    let report = volume.report();
    assert_eq!((report.timed_out, report.cancelled), (1, 1));
}

/// The custody check at the volume's held points: a read whose deadline
/// passed, and a read its caller cancelled, each end with one `Done` while
/// the device still holds their command, whose buffer the check judges in
/// storage custody; after each late terminal the device holds nothing.
#[test]
fn a_timed_out_or_cancelled_read_leaves_its_held_command_in_storage_custody() {
    let storage = storage(1);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let record = record(0, 0, CHUNK, SESSION, 30);
    place(&storage, &control, &record);
    let mut out = Vec::with_capacity(4);
    let timed_out = volume.read_raw(&record.read, 10).expect("admitted");
    let token = last_submitted(&control);
    control.hold(token);
    step(&mut volume, &control, 10, &mut out);
    assert_eq!(dones(&mut out), [(timed_out, ReadStatus::TimedOut)]);
    assert_eq!(judged(&control, &arena), (1, vec![token]));
    control.release(token);
    for _ in 0..4 {
        step(&mut volume, &control, 1 << 40, &mut out);
    }
    assert!(out.is_empty());
    assert_eq!(judged(&control, &arena), (0, vec![]));
    let cancelled = volume
        .read_raw(&record.read, 1 << 41)
        .expect("the record is free again");
    let token = last_submitted(&control);
    control.hold(token);
    volume.cancel_read(cancelled).expect("live");
    step(&mut volume, &control, 1 << 40, &mut out);
    assert_eq!(dones(&mut out), [(cancelled, ReadStatus::Cancelled)]);
    assert_eq!(judged(&control, &arena), (1, vec![token]));
    control.release(token);
    for _ in 0..4 {
        step(&mut volume, &control, 1 << 40, &mut out);
    }
    assert!(out.is_empty());
    assert_eq!(judged(&control, &arena), (0, vec![]));
}

/// `s4n-timeout-cancels-and-holds` (tokenless part): an operation with no
/// command outstanding frees at its deadline. One read waits for a response
/// buffer the test holds as a chunk, the other has its bytes in hand
/// mid-verification; at the deadline each ends `TimedOut` and its record is
/// gone at once, and the verifying one's buffer is back in its pool.
#[test]
fn an_operation_with_nothing_outstanding_frees_at_its_deadline() {
    for verifying in [false, true] {
        let storage = storage(2);
        let arena = arena_with(1, 2);
        let tick = TickConfig {
            validate_bytes: if verifying { 1000 } else { 1 << 20 },
            ..TICK
        };
        let (mut volume, control) = attach(&storage, &arena, tick);
        let record = record(0, 0, 4 * CHUNK, SESSION, 31);
        place(&storage, &control, &record);
        let op = volume.read_raw(&record.read, 50).expect("admitted");
        let mut out = Vec::with_capacity(8);
        let mut held = Vec::new();
        for now in 0..4 {
            step(&mut volume, &control, now, &mut out);
            held.extend(out.drain(..).map(|event| match event {
                ReadEvent::Chunk { chunk, .. } => chunk,
                other => panic!("{other:?}"),
            }));
        }
        assert_eq!(held.len(), usize::from(!verifying));
        assert_eq!(volume.table_report().pending, 0, "nothing is outstanding");
        assert_eq!(arena.report(PoolKind::ReadResponse).free, 0);
        assert_eq!(volume.reads.live(), 1);
        volume.poll_storage(50, &mut out);
        assert_eq!(dones(&mut out), [(op, ReadStatus::TimedOut)]);
        assert_eq!(volume.reads.live(), 0, "freed at once");
        assert_eq!(volume.report().quarantines, 0);
        assert_eq!(
            arena.report(PoolKind::ReadResponse).free,
            u32::from(verifying)
        );
        drop(held);
        assert_eq!(arena.report(PoolKind::ReadResponse).free, 1);
    }
}

/// `s4n-cancel-quarantines`, `s4n-quarantine-bound`: cancelled and timed-out
/// reads whose completions never come stay quarantined against the depth;
/// with three held writes, which take the write share and the unclaimed
/// metadata slot, they fill every table slot, and a write refuses
/// `TableFull` at once with the abandoned count the table report shows; a
/// read admitted then waits under a kept grant and takes no table slot.
#[test]
fn quarantined_and_pending_commands_that_fill_the_table_refuse_a_write_and_hold_a_read_waiting() {
    // Five read commands leave the writes three slots while no metadata command claims its slot.
    let storage = super::volume_tests::storage_shared(7, 5);
    let arena = arena_with(8, 4);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let record = record(0, 0, CHUNK, SESSION, 32);
    place(&storage, &control, &record);
    let mut ops = Vec::new();
    for _ in 0..5 {
        ops.push(volume.read_raw(&record.read, 100).expect("admitted"));
        control.fault(last_submitted(&control), Fault::DropCompletion);
    }
    for op in &ops[..3] {
        volume.cancel_read(*op).expect("live");
    }
    let mut out = Vec::with_capacity(16);
    step(&mut volume, &control, 100, &mut out);
    let ended = dones(&mut out);
    let count = |status| ended.iter().filter(|(_, s)| *s == status).count();
    assert_eq!(
        (count(ReadStatus::Cancelled), count(ReadStatus::TimedOut)),
        (3, 2)
    );
    let (_first, first) = write_set(&storage, &mut volume, 1);
    let (_second, second) = write_set(&storage, &mut volume, 1);
    let (_third, third) = write_set(&storage, &mut volume, 1);
    for set in [first, second, third] {
        let buffer = arena.acquire(PoolKind::ReceiveWrite).expect("free");
        write(&mut volume, set, buffer, 0).expect("submitted");
        control.hold(last_submitted(&control));
    }
    let table = volume.table_report();
    assert_eq!(
        (table.free_slots, table.pending, table.abandoned),
        (0, 3, 5)
    );
    let (_fourth, fourth) = write_set(&storage, &mut volume, 1);
    let buffer = arena.acquire(PoolKind::ReceiveWrite).expect("free");
    let (_buffer, refusal) = write(&mut volume, fourth, buffer, 0).expect_err("full");
    assert_eq!(refusal, Refusal::TableFull { abandoned: 5 });
    volume
        .read_raw(&record.read, u64::MAX)
        .expect("admitted to wait");
    let table = volume.table_report();
    assert_eq!((table.pending, table.abandoned), (3, 5));
    let report = volume.report();
    assert_eq!((report.quarantines, report.timed_out), (5, 2));
    assert_eq!(report.reads_waited, 1);
    assert_eq!(arena.report(PoolKind::ReadResponse).quarantined, 5);
}

/// `s4n-lost-refuses-closes` (device-gone part), `s4n-done-once` (lost
/// part): the device refusing a read's later command `DeviceGone` loses the
/// volume and ends that read `Lost`; a read with a command outstanding ends
/// `Lost` at its terminal, and one whose command is still held ends `Lost`
/// at the proven stop; a new read refuses `Lost` without a buffer, a record
/// or a command. `close` is idempotent, stays `Quiesced`, and no submit is
/// admitted after it. On a second volume, a read whose first submit is
/// refused for good stays `Submit` while the volume is live, and one whose
/// first submit meets the gone device refuses `Lost`, each owning nothing.
#[test]
fn a_device_gone_refusal_loses_the_volume_and_ends_every_admitted_read_once() {
    let storage = storage(3);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    // Reserved while the volume is live: its loss withdraws fill admission, and its close moves the readiness to `Closed`.
    let (_reservation, set) = write_set(&storage, &mut volume, 1);
    let short = record(0, 0, CHUNK, SESSION, 33);
    let long = record(16, 0, 4 * CHUNK, SESSION, 34);
    place(&storage, &control, &short);
    place(&storage, &control, &long);
    let held = volume.read_raw(&short.read, u64::MAX).expect("admitted");
    let token = last_submitted(&control);
    control.hold(token);
    let stopped = volume.read_raw(&short.read, u64::MAX).expect("admitted");
    control.hold(last_submitted(&control));
    let next = volume.read_raw(&long.read, u64::MAX).expect("admitted");
    volume.grant_read(next).expect("live");
    let mut out = Vec::with_capacity(8);
    turn_until(|| {
        let mut tick = || control.tick(8);
        // The device goes away just before the volume's two polls, so a
        // poll's submit meets the gone device.
        let mut poll = || {
            control.set_gone();
            let _ = volume.poll_storage(0, &mut out);
            let _ = volume.poll_storage(0, &mut out);
        };
        round(&mut [
            Act::new(Actor::Disk(0), &mut tick),
            Act::new(Actor::Volume(0), &mut poll),
        ]);
        volume.is_lost()
    });
    assert_eq!(dones(&mut out), [(next, ReadStatus::Lost)]);
    assert!(volume.is_lost());
    assert_eq!(volume.table_report().admission, Admission::Lost);
    assert_eq!(volume.readiness(), super::super::readiness::State::Withheld);
    assert_eq!(
        storage
            .reserve(
                Some(0),
                Some(1),
                &mut super::super::budget::WorkBudget::new(64)
            )
            .err(),
        Some(super::super::ReserveError::Closed)
    );
    let before = (
        arena.report(PoolKind::ReadResponse).free,
        volume.table_report().pending,
        volume.reads.live(),
        volume.report().reads_submitted,
    );
    assert_eq!(
        volume.read_raw(&short.read, u64::MAX),
        Err(ReadRefusal::Lost)
    );
    let after = (
        arena.report(PoolKind::ReadResponse).free,
        volume.table_report().pending,
        volume.reads.live(),
        volume.report().reads_submitted,
    );
    assert_eq!(after, before, "a refused read takes nothing");
    control.release(token);
    turn_until(|| {
        step(&mut volume, &control, 0, &mut out);
        !out.is_empty()
    });
    assert_eq!(dones(&mut out), [(held, ReadStatus::Lost)]);
    control.set_quiesce(QuiesceMode::Reset);
    let mut first = volume.close();
    for _ in 0..2 {
        volume.poll_storage(0, &mut out);
        first = volume.close();
    }
    assert_eq!(dones(&mut out), [(stopped, ReadStatus::Lost)]);
    assert_eq!(first, QuiesceProgress::Quiesced(Quiesced::DeviceStopped));
    for _ in 0..3 {
        assert_eq!(volume.close(), first, "close stays quiesced");
    }
    assert_eq!(
        volume.read_raw(&short.read, u64::MAX),
        Err(ReadRefusal::Lost)
    );
    let buffer = arena.acquire(PoolKind::ReceiveWrite).expect("free");
    assert!(write(&mut volume, set, buffer, 0).is_err());
    assert_eq!(volume.report().writes_submitted, 0);
    assert_eq!(
        volume.release().map_err(|_| ()),
        Ok(Quiesced::DeviceStopped)
    );
    drop(out);
    assert_eq!(arena.release().map_err(|_| ()), Ok(Released::Complete));
    let storage = super::volume_tests::storage(1);
    let arena = super::volume_tests::arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    place(&storage, &control, &short);
    let invalid = SubmitRefusal {
        reason: RefusalReason::InvalidRange,
        code: None,
    };
    control.refuse_next(invalid);
    assert_eq!(
        volume.read_raw(&short.read, u64::MAX),
        Err(ReadRefusal::Submit(Refusal::Device(invalid)))
    );
    assert!(!volume.is_lost());
    control.set_gone();
    assert_eq!(
        volume.read_raw(&short.read, u64::MAX),
        Err(ReadRefusal::Lost)
    );
    assert!(volume.is_lost());
    let owned = (
        arena.report(PoolKind::ReadResponse).free,
        volume.reads.live(),
        volume.report().reads_refused,
    );
    assert_eq!(owned, (4, 0, 2), "each refused read owns nothing");
}

/// `s4n-lost-refuses-closes` (unwind part), `s4n-done-once`: a driver call
/// that unwinds inside a tick loses the volume, and a read then refuses
/// `Lost` without a buffer or a command. After an unwound pick, the read's
/// command still completes and ends it `Lost`. After an unwound submit, the
/// table keeps that command under a token the volume never mapped, so the
/// read stays held through later ticks and ends `Lost` once, at the proven
/// stop, after which every buffer returns.
#[test]
fn a_driver_that_unwinds_in_a_tick_loses_the_volume_and_its_read_ends_once() {
    for at in [Unwind::Pick, Unwind::Submit] {
        let storage = storage(2);
        let arena = arena();
        let (mut volume, control) = attach(&storage, &arena, TICK);
        let long = record(0, 0, 4 * CHUNK, SESSION, 35);
        place(&storage, &control, &long);
        let op = volume.read_raw(&long.read, u64::MAX).expect("admitted");
        volume.grant_read(op).expect("live");
        let mut out = Vec::with_capacity(8);
        let mut unwound = None;
        turn_until(|| {
            let mut tick = || control.tick(8);
            let mut poll = || {
                control.unwind_next(Some(at));
                unwound = Some(catch_unwind(AssertUnwindSafe(|| {
                    volume.poll_storage(0, &mut out)
                })));
            };
            round(&mut [
                Act::new(Actor::Disk(0), &mut tick),
                Act::new(Actor::Volume(0), &mut poll),
            ]);
            unwound.as_ref().is_some_and(Result::is_err)
        });
        let unwound = unwound.expect("the round polled the volume");
        assert!(unwound.is_err(), "{at:?}");
        out.clear();
        assert!(volume.is_lost(), "{at:?}");
        let before = (
            arena.report(PoolKind::ReadResponse).free,
            volume.table_report().pending,
        );
        assert_eq!(before.1, 1, "{at:?}");
        let admission = match at {
            Unwind::Pick => Admission::Open,
            Unwind::Submit => Admission::Lost,
        };
        assert_eq!(volume.table_report().admission, admission, "{at:?}");
        assert_eq!(
            volume.read_raw(&long.read, u64::MAX),
            Err(ReadRefusal::Lost)
        );
        assert_eq!(
            (
                arena.report(PoolKind::ReadResponse).free,
                volume.table_report().pending,
            ),
            before,
            "{at:?}"
        );
        let mut ended = Vec::new();
        for _ in 0..4 {
            step(&mut volume, &control, 0, &mut out);
            ended.extend(dones(&mut out));
        }
        if at == Unwind::Submit {
            assert!(ended.is_empty(), "held until the proven stop");
            assert_eq!(volume.reads.live(), 1);
            assert_eq!(arena.report(PoolKind::ReadResponse).storage, 1);
        }
        control.set_quiesce(QuiesceMode::Reset);
        let mut progress = volume.close();
        for _ in 0..4 {
            volume.poll_storage(0, &mut out);
            ended.extend(dones(&mut out));
            progress = volume.close();
        }
        // After the unwound pick the read's own command returned, so nothing is outstanding.
        let proof = match at {
            Unwind::Pick => Quiesced::AllReturned,
            Unwind::Submit => Quiesced::DeviceStopped,
        };
        assert_eq!(progress, QuiesceProgress::Quiesced(proof), "{at:?}");
        assert_eq!(ended, [(op, ReadStatus::Lost)], "{at:?}");
        assert_eq!(volume.reads.live(), 0, "{at:?}");
        assert_eq!(volume.release().map_err(|_| ()), Ok(proof));
        drop(out);
        assert_eq!(arena.release().map_err(|_| ()), Ok(Released::Complete));
    }
}

#[test]
fn a_pre_receive_terminal_poll_unwind_keeps_custody_and_ends_the_read_once() {
    let storage = storage(1);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let record = record(0, 0, CHUNK, SESSION, 35);
    place(&storage, &control, &record);
    let op = volume.read_raw(&record.read, u64::MAX).unwrap();
    volume.grant_read(op).unwrap();
    control.tick(8);
    control.unwind_next(Some(Unwind::Pick));
    let mut out = Vec::with_capacity(8);
    assert!(catch_unwind(AssertUnwindSafe(|| volume.poll_terminals(0, &out))).is_err());
    assert_eq!(
        storage.readiness.state(),
        super::super::readiness::State::Withheld
    );
    assert!(volume.is_lost());
    assert_eq!(volume.table_report().pending, 1);
    assert_eq!(arena.report(PoolKind::ReadResponse).storage, 1);
    assert_eq!(
        volume.read_raw(&record.read, u64::MAX),
        Err(ReadRefusal::Lost)
    );
    let mut ended = Vec::new();
    for _ in 0..4 {
        step(&mut volume, &control, 0, &mut out);
        ended.extend(dones(&mut out));
    }
    assert_eq!(ended, [(op, ReadStatus::Lost)]);
    assert_eq!(volume.table_report().pending, 0);
    assert_eq!(volume.reads.live(), 0);
    assert_eq!(arena.report(PoolKind::ReadResponse).free, 4);
    volume.close();
}

/// In-flight write right, TERMINAL: a write submit whose driver call unwinds
/// leaves its command in the table under a token the volume never mapped, so
/// its set keeps counting it. With an earlier command of the set outstanding,
/// that command's terminal leaves the right held; with the unwound submit the
/// set's first, the right it installed stays held. The first tick after the
/// proven stop fails the set and releases the right, and everything releases.
#[test]
fn an_unwound_write_submit_keeps_its_sets_right_until_the_proven_stop() {
    for earlier in [true, false] {
        let storage = storage(1);
        let arena = arena();
        let (mut volume, control) = attach(&storage, &arena, TICK);
        let (reservation, set) = write_set(&storage, &mut volume, 1);
        let slot = reservation.id().slot_index();
        let first = earlier.then(|| {
            let buffer = arena.acquire(PoolKind::ReceiveWrite).expect("free");
            write(&mut volume, set, buffer, 0).expect("submitted");
            let token = last_submitted(&control);
            control.hold(token);
            token
        });
        control.unwind_next(Some(Unwind::Submit));
        let buffer = arena.acquire(PoolKind::ReceiveWrite).expect("free");
        let unwound = catch_unwind(AssertUnwindSafe(|| volume.write_at(set, buffer, 0))).is_err();
        assert!(unwound, "earlier {earlier}");
        assert!(volume.is_lost());
        if let Some(token) = first {
            control.release(token);
        }
        let mut out = Vec::with_capacity(8);
        for _ in 0..4 {
            step(&mut volume, &control, 0, &mut out);
        }
        let progress = volume.write_progress(set).expect("live");
        assert_eq!(progress.completed_units, u32::from(earlier));
        assert_eq!(
            progress.outstanding_units, progress.len_units,
            "the unwound command keeps its units, earlier {earlier}"
        );
        assert_eq!(
            refs(&storage, slot),
            1,
            "the unwound command keeps the right, earlier {earlier}"
        );
        control.set_quiesce(QuiesceMode::Reset);
        assert_eq!(
            volume.close(),
            QuiesceProgress::Quiesced(Quiesced::DeviceStopped)
        );
        step(&mut volume, &control, 0, &mut out);
        assert_eq!(refs(&storage, slot), 0, "earlier {earlier}");
        let stopped = volume.write_progress(set).expect("live");
        assert!(stopped.failed);
        assert_eq!(stopped.outstanding_units, 0, "earlier {earlier}");
        assert_eq!(
            volume.release().map_err(|_| ()),
            Ok(Quiesced::DeviceStopped)
        );
        drop((out, reservation));
        assert_eq!(arena.release().map_err(|_| ()), Ok(Released::Complete));
    }
}

/// A set's outstanding commands fall only where the volume's count of ended
/// write commands rises by as many: at an applied terminal, and at the proven
/// stop that fails a submit whose driver call unwound. A submit the driver
/// accepts, and one whose driver call unwinds, raises the outstanding
/// commands and leaves the count. The test follows one set through each
/// step; a caller that follows several sets applies the same rule to each.
#[test]
fn a_sets_outstanding_commands_fall_only_where_the_ended_write_count_rises() {
    for earlier in [true, false] {
        let storage = storage(1);
        let arena = arena();
        let (mut volume, control) = attach(&storage, &arena, TICK);
        let (reservation, set) = write_set(&storage, &mut volume, 1);
        let read = |volume: &TestVolume<'_, '_>| {
            (
                volume.write_outstanding(set).expect("live"),
                volume.write_ends(),
            )
        };
        // Checks one step that submitted `submitted` commands: the commands
        // that left the set since `seen` are the count's rise.
        let stepped =
            |volume: &TestVolume<'_, '_>, seen: (u32, u64), submitted: u32, step: &str| {
                let now = read(volume);
                assert_eq!(
                    u64::from(seen.0 + submitted - now.0),
                    now.1 - seen.1,
                    "{step}, earlier {earlier}: {seen:?} then {now:?}"
                );
                now
            };
        let mut seen = read(&volume);
        assert_eq!(seen.0, 0);
        let first = earlier.then(|| {
            let buffer = arena.acquire(PoolKind::ReceiveWrite).expect("free");
            write(&mut volume, set, buffer, 0).expect("submitted");
            let token = last_submitted(&control);
            control.hold(token);
            token
        });
        seen = stepped(&volume, seen, u32::from(earlier), "the first submit");
        control.unwind_next(Some(Unwind::Submit));
        let buffer = arena.acquire(PoolKind::ReceiveWrite).expect("free");
        let unwound = catch_unwind(AssertUnwindSafe(|| volume.write_at(set, buffer, 0))).is_err();
        assert!(unwound, "earlier {earlier}");
        seen = stepped(&volume, seen, 1, "the unwound submit");
        if let Some(token) = first {
            control.release(token);
        }
        let mut out = Vec::with_capacity(8);
        for _ in 0..4 {
            step(&mut volume, &control, 0, &mut out);
        }
        seen = stepped(&volume, seen, 0, "the first command's terminal");
        assert_eq!(seen.0, 1, "the unwound command stays outstanding");
        control.set_quiesce(QuiesceMode::Reset);
        assert_eq!(
            volume.close(),
            QuiesceProgress::Quiesced(Quiesced::DeviceStopped)
        );
        step(&mut volume, &control, 0, &mut out);
        seen = stepped(&volume, seen, 0, "the proven stop");
        assert_eq!(seen, (0, 1 + u64::from(earlier)), "earlier {earlier}");
        assert_eq!(
            volume.release().map_err(|_| ()),
            Ok(Quiesced::DeviceStopped)
        );
        drop((out, reservation));
        assert_eq!(arena.release().map_err(|_| ()), Ok(Released::Complete));
    }
}

/// `s4n-lost-refuses-closes` (close part): a driver call that unwinds inside
/// `close`'s quiesce loses the volume, so a read refuses `Lost`; a held read
/// then ends `Lost` once at the proven stop.
#[test]
fn a_driver_that_unwinds_in_close_loses_the_volume() {
    let storage = storage(1);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let record = record(0, 0, CHUNK, SESSION, 36);
    place(&storage, &control, &record);
    let op = volume.read_raw(&record.read, u64::MAX).expect("admitted");
    control.hold(last_submitted(&control));
    control.unwind_next(Some(Unwind::Pick));
    assert!(catch_unwind(AssertUnwindSafe(|| volume.close())).is_err());
    assert!(volume.is_lost());
    assert_eq!(
        volume.read_raw(&record.read, u64::MAX),
        Err(ReadRefusal::Lost)
    );
    control.set_quiesce(QuiesceMode::Reset);
    assert_eq!(
        volume.close(),
        QuiesceProgress::Quiesced(Quiesced::DeviceStopped)
    );
    let mut out = Vec::with_capacity(4);
    volume.poll_storage(0, &mut out);
    assert_eq!(dones(&mut out), [(op, ReadStatus::Lost)]);
    assert_eq!(
        volume.release().map_err(|_| ()),
        Ok(Quiesced::DeviceStopped)
    );
    drop(out);
    assert_eq!(arena.release().map_err(|_| ()), Ok(Released::Complete));
}

/// `s4n-timeout-cancels-and-holds`, Q-LOSTDONE: a deadline that passed first
/// decides the outcome. A read whose failed terminal arrives in the tick at
/// its deadline ends `TimedOut`, with nothing quarantined and its record
/// free; on a lost volume a read with nothing outstanding ends `TimedOut` at
/// its deadline.
#[test]
fn a_deadline_that_passed_first_decides_the_outcome() {
    let storage = storage(2);
    let arena = arena_with(1, 2);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let short = record(0, 0, CHUNK, SESSION, 37);
    let long = record(16, 0, 4 * CHUNK, SESSION, 38);
    place(&storage, &control, &short);
    place(&storage, &control, &long);
    let failed = volume.read_raw(&short.read, 10).expect("admitted");
    control.fault(
        last_submitted(&control),
        Fault::Status(DeviceStatus::Kernel(-5)),
    );
    let mut out = Vec::with_capacity(8);
    step(&mut volume, &control, 10, &mut out);
    assert_eq!(dones(&mut out), [(failed, ReadStatus::TimedOut)]);
    assert_eq!(volume.report().quarantines, 0);
    assert_eq!(volume.reads.live(), 0);
    let waiting = volume.read_raw(&long.read, 50).expect("admitted");
    let mut held = Vec::new();
    for now in 0..4 {
        step(&mut volume, &control, now, &mut out);
        held.extend(out.drain(..).map(|event| match event {
            ReadEvent::Chunk { chunk, .. } => chunk,
            other => panic!("{other:?}"),
        }));
    }
    assert_eq!(held.len(), 1, "the read waits for the one response buffer");
    control.unwind_next(Some(Unwind::Pick));
    assert!(catch_unwind(AssertUnwindSafe(|| volume.poll_storage(0, &mut out))).is_err());
    assert!(volume.is_lost());
    volume.poll_storage(50, &mut out);
    assert_eq!(dones(&mut out), [(waiting, ReadStatus::TimedOut)]);
}

/// Proven stop through ticks alone, and a `Done` for an operation whose
/// `read_raw` call unwound: a first submit whose driver call unwinds inside
/// `read_raw` leaves its operation admitted and loses the volume. With a
/// one-terminal burst `close` reports `Delivering` while two held reads'
/// records wait; later ticks alone deliver them, and the tick that finds the
/// table stopped and empty ends the unwound read `Lost`, once.
#[test]
fn ticks_alone_finish_a_proven_stop_and_end_an_unwound_first_submit_lost() {
    let storage = storage(3);
    let arena = arena();
    let tick = TickConfig {
        submit_burst: 1,
        terminal_burst: 1,
        ..TICK
    };
    let (mut volume, control) = attach(&storage, &arena, tick);
    let record = record(0, 0, CHUNK, SESSION, 39);
    place(&storage, &control, &record);
    let held: Vec<ReadOp> = (0..2)
        .map(|_| {
            let op = volume.read_raw(&record.read, u64::MAX).expect("admitted");
            control.hold(last_submitted(&control));
            op
        })
        .collect();
    control.unwind_next(Some(Unwind::Submit));
    let unwound = catch_unwind(AssertUnwindSafe(|| volume.read_raw(&record.read, u64::MAX)));
    assert!(unwound.is_err());
    assert!(volume.is_lost());
    assert_eq!(volume.reads.live(), 3);
    control.set_quiesce(QuiesceMode::Reset);
    assert_eq!(volume.close(), QuiesceProgress::Delivering { remaining: 2 });
    let mut out = Vec::with_capacity(4);
    let mut ended = Vec::new();
    for _ in 0..6 {
        volume.poll_storage(0, &mut out);
        ended.extend(dones(&mut out));
    }
    assert_eq!(ended.len(), 3, "{ended:?}");
    assert!(ended.iter().all(|(_, status)| *status == ReadStatus::Lost));
    let unreceived: Vec<_> = ended.iter().filter(|(op, _)| !held.contains(op)).collect();
    assert_eq!(unreceived.len(), 1, "{ended:?}");
    assert_eq!(volume.reads.live(), 0);
    assert_eq!(
        volume.release().map_err(|_| ()),
        Ok(Quiesced::DeviceStopped)
    );
    drop(out);
    assert_eq!(arena.release().map_err(|_| ()), Ok(Released::Complete));
}

/// A census of the volume's commands taken from its records and token map, apart from its counters.
struct Census {
    /// Read and write entries of the token map.
    mapped_reads: u64,
    mapped_writes: u64,
    /// Reads whose submit unwound, holding a command the table never mapped.
    unmapped: u64,
    /// The write sets' outstanding counts.
    outstanding_writes: u64,
}

/// Takes the census and checks that every mapped read names a live record holding that token.
fn census(volume: &mut TestVolume<'_, '_>, at: &str) -> Census {
    let (mut mapped_reads, mut mapped_writes) = (0, 0);
    for mapped in volume.tokens.iter().flatten() {
        let Owner::Read(slot) = mapped.owner else {
            mapped_writes += 1;
            continue;
        };
        mapped_reads += 1;
        let record = volume.reads.slot_mut(slot).map(|(_, record)| record.token);
        assert_eq!(record, Some(Some(mapped.token)), "{at}");
    }
    let unmapped = (0..volume.reads.len())
        .filter(|slot| {
            volume
                .reads
                .slot_mut(*slot)
                .is_some_and(|(_, record)| record.unmapped)
        })
        .count() as u64;
    let outstanding_writes = (0..volume.writes.len())
        .filter_map(|slot| {
            volume
                .writes
                .slot_mut(slot)
                .map(|(_, set)| set.progress.outstanding_commands)
        })
        .map(u64::from)
        .sum();
    Census {
        mapped_reads,
        mapped_writes,
        unmapped,
        outstanding_writes,
    }
}

/// Where a seed loses its volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Loss {
    TickSubmit,
    TickPick,
    ReadSubmit,
    WriteSubmit,
    Gone,
}

/// `s4n-tick-bounds`, `s4n-token-owner-total` and `s4n-done-once`
/// under seeded fault schedules: reads and write sets race every fault the
/// simulated device injects on first and later commands, held and reordered
/// completions, bytes that land before their completion posts, cancels,
/// deadlines, at most one loss per seed (a driver unwind inside a tick, inside a
/// read's or a write's submit, or the device going gone), outputs too small
/// for any event, and a quiesce that stays unproven before a reset proves
/// the stop. After every tick the raw ledger sums to the volume's bytes; each
/// pool's per-buffer obligation sets match its report; the table's pending
/// and abandoned commands match the volume's census of mapped tokens, unmapped
/// reads and pool custody; every mapped read names its record; for reads and
/// writes `submitted == done + failed + in flight`; and the `Done` statuses
/// and validated bytes the ticks returned match the counters. Every chunk
/// carries its record's payload bytes, every admitted read gets exactly one
/// `Done`, none gets a `Chunk` after it, and every right ends at the release.
#[test]
fn seeded_fault_schedules_conserve_the_ledger_the_table_the_pools_and_every_command() {
    const FAULTS: [Fault; 7] = [
        Fault::Status(DeviceStatus::Kernel(-5)),
        Fault::Short { units: 1 },
        Fault::CorruptSuccess,
        Fault::TornWrite { sectors: 3 },
        Fault::PartialReadFailure { sectors: 5 },
        Fault::DropCommand,
        Fault::DropCompletion,
    ];
    let mut seen = [false; 7];
    let (mut quarantine_full, mut pools_empty, mut later_faults, mut tiny_ticks) = (0, 0, 0, 0);
    let mut retired_under_writes = 0;
    let mut losses: Vec<Loss> = Vec::new();
    for seed in (0..30).chain([1190]) {
        let storage = storage(3);
        // Four receive-write buffers, the write share beside three read
        // commands and one metadata command, so writes can hold every one.
        let arena = arena_with(3, 4);
        let tick = TickConfig {
            submit_burst: 2,
            terminal_burst: 2,
            validate_bytes: 6000,
        };
        let (mut volume, control) = attach(&storage, &arena, tick);
        let payload_bytes = super::volume_tests::default_units() * crate::storage::IO_UNIT;
        assert_eq!(
            storage.pool_report().unwrap().ledger.unwrap().raw,
            crate::storage::RawPartition::new(
                crate::storage::TEST_METADATA_UNITS as usize * crate::storage::IO_UNIT,
                payload_bytes
            ),
            "the attached volume starts with its payload free beside its metadata prefix"
        );
        let mut rng = SplitMix64::new(seed);
        let records: Vec<Record> = (0..4)
            .map(|index| {
                let body = (1 + rng.below(4) as u32) * CHUNK - 7;
                record(index * 16, 0, body, SESSION, seed * 10 + index)
            })
            .collect();
        for record in &records {
            place(&storage, &control, record);
        }
        let mut live: Vec<(ReadOp, usize)> = Vec::new();
        // Reads admitted by a `read_raw` call whose first submit unwound, so the test holds no handle for them.
        let mut unreceived = 0;
        let mut ended: Vec<ReadOp> = Vec::new();
        let mut out = Vec::with_capacity(8);
        let mut tiny = Vec::with_capacity(1);
        let mut chunks = Vec::new();
        let mut held = Vec::new();
        let mut now = 0;
        // Done statuses: cancelled, timed out, header mismatch, chunk mismatch.
        let mut tally = [0u64; 4];
        let mut validated = 0u64;
        let loss_at = 100 + rng.below(100);
        let loss = [
            Loss::TickSubmit,
            Loss::TickPick,
            Loss::ReadSubmit,
            Loss::WriteSubmit,
            Loss::Gone,
        ][rng.below(5) as usize];
        for step in 0..420u64 {
            let at = format!("seed {seed} step {step}");
            now += rng.below(3);
            let admitting = step < 320;
            // Armed until a call of the chosen kind loses the volume.
            let armed = step >= loss_at && !volume.is_lost();
            if armed && loss == Loss::Gone {
                control.set_gone();
            }
            match rng.below(8) {
                0 | 1 if admitting => {
                    let index = rng.below(4) as usize;
                    let deadline = now + 5 + rng.below(40);
                    if armed && loss == Loss::ReadSubmit {
                        control.unwind_next(Some(Unwind::Submit));
                    }
                    let read = catch_unwind(AssertUnwindSafe(|| {
                        volume.read_raw(&records[index].read, deadline)
                    }));
                    control.unwind_next(None);
                    match read {
                        Err(_) => {
                            assert!(volume.is_lost(), "{at}");
                            losses.push(Loss::ReadSubmit);
                            unreceived += 1;
                        }
                        Ok(Ok(op)) => {
                            live.push((op, index));
                            if rng.below(2) == 0 {
                                let fault = rng.below(9) as usize;
                                if let Some(fault) = FAULTS.get(fault) {
                                    // The read may wait unsubmitted, so the last submitted command can be one that already finished or moved its bytes, which no fault reaches.
                                    if scripted(control.try_fault(last_submitted(&control), *fault))
                                    {
                                        seen[FAULTS.iter().position(|f| f == fault).unwrap()] =
                                            true;
                                    }
                                } else {
                                    let token = last_submitted(&control);
                                    scripted(control.try_hold(token));
                                    held.push(token);
                                }
                            }
                        }
                        Ok(Err(_)) => {}
                    }
                }
                // A cancel, or a grant that may find the read busy or already granted.
                2 if !live.is_empty() => {
                    let (op, _) = live[rng.below(live.len() as u64) as usize];
                    if rng.below(2) == 0 {
                        let _ = volume.cancel_read(op);
                    } else {
                        let _ = volume.grant_read(op);
                    }
                }
                3 if admitting => {
                    // A write set that submits one command and ends; its
                    // reservation's drop abandons the extent, which service
                    // returns once the set's right is released.
                    let _ = storage.service(&mut super::super::budget::WorkBudget::new(1 << 10));
                    if let Ok(reservation) = storage.reserve(
                        Some(0),
                        Some(super::super::device::IO_UNIT),
                        &mut super::super::budget::WorkBudget::new(64),
                    ) && let Some(set) = volume.begin_fill(
                        reservation.id(),
                        reservation.locator(),
                        reservation.locator().len_units(),
                        &super::volume_tests::ATTEMPT,
                        // Another serial than the attempt word's: the set's fill has ended, so the set frees at its last terminal.
                        FillSerial::new(2).unwrap(),
                    ) {
                        if let Ok(buffer) = arena.acquire(PoolKind::ReceiveWrite) {
                            if armed && loss == Loss::WriteSubmit {
                                control.unwind_next(Some(Unwind::Submit));
                            }
                            let written =
                                catch_unwind(AssertUnwindSafe(|| volume.write_at(set, buffer, 0)));
                            control.unwind_next(None);
                            match written {
                                Err(_) => {
                                    assert!(volume.is_lost(), "{at}");
                                    losses.push(Loss::WriteSubmit);
                                }
                                Ok(Ok(())) => {
                                    if let Some(fault) = FAULTS.get(rng.below(8) as usize) {
                                        scripted(
                                            control.try_fault(last_submitted(&control), *fault),
                                        );
                                    }
                                }
                                Ok(Err(_)) => {}
                            }
                        }
                        volume.end_fill(set);
                        drop(reservation);
                    }
                }
                4 if !held.is_empty() => {
                    control.release(held.swap_remove(rng.below(held.len() as u64) as usize));
                }
                5 => control.execute_tick(1 + rng.below(3) as u32),
                _ => chunks.clear(),
            }
            // Armed for this tick only, so no call outside a tick unwinds.
            let unwind = match loss {
                Loss::TickSubmit => Some(Unwind::Submit),
                Loss::TickPick => Some(Unwind::Pick),
                _ => None,
            };
            if armed && unwind.is_some() {
                control.unwind_next(unwind);
            }
            if step == 360 {
                control.set_quiesce(QuiesceMode::Unproven);
                let progress = volume.close();
                let table = volume.table_report();
                if table.pending + table.abandoned > 0 {
                    assert!(
                        !matches!(progress, QuiesceProgress::Quiesced(_)),
                        "{progress:?}, {at}"
                    );
                }
            }
            if step == 380 {
                control.set_quiesce(QuiesceMode::Reset);
            }
            if step >= 380 {
                let _ = volume.close();
            }
            let budget = 1 + rng.below(4) as u32;
            let bounds = rng.below(10) == 0;
            let polled = RefCell::new(&mut volume);
            let mut tick = || control.tick(budget);
            // `s4n-tick-bounds`: an output with fewer than two spare slots gets an empty report and stays empty.
            let mut bounded = || {
                let mut volume = polled.borrow_mut();
                assert_eq!(volume.poll_storage(now, &mut tiny), TickReport::default());
                assert!(tiny.is_empty(), "{at}");
                tiny_ticks += 1;
            };
            let mut poll = || {
                let mut volume = polled.borrow_mut();
                let allocations = crate::instrument::allocations();
                let ticked = catch_unwind(AssertUnwindSafe(|| volume.poll_storage(now, &mut out)));
                control.unwind_next(None);
                match ticked {
                    Ok(report) => {
                        assert_eq!(crate::instrument::allocations(), allocations, "{at}");
                        assert!(report.submitted <= 2 && report.terminals <= 2, "{at}");
                        assert!(report.validated_bytes <= 6000, "{at}");
                        validated += report.validated_bytes as u64;
                        // A tick submits only a read's later command, which a fault or a hold may meet mid-read.
                        if report.submitted > 0 && rng.below(3) == 0 {
                            let token = last_submitted(&control);
                            match FAULTS.get(rng.below(9) as usize) {
                                Some(fault) => control.fault(token, *fault),
                                None => {
                                    control.hold(token);
                                    held.push(token);
                                }
                            }
                            later_faults += 1;
                        }
                    }
                    Err(_) => {
                        assert!(volume.is_lost(), "{at}");
                        losses.push(loss);
                    }
                }
            };
            let mut acts = vec![Act::new(Actor::Disk(0), &mut tick)];
            if bounds {
                acts.push(Act::new(Actor::Volume(0), &mut bounded));
            }
            acts.push(Act::new(Actor::Volume(0), &mut poll));
            round(&mut acts);
            drop(acts);
            for event in out.drain(..) {
                match event {
                    ReadEvent::Chunk {
                        op, range, chunk, ..
                    } => {
                        let Some(&(_, index)) = live.iter().find(|(live, _)| *live == op) else {
                            panic!("a Chunk after its Done, {at}");
                        };
                        let payload = &records[index].payload;
                        assert_eq!(
                            chunk.bytes(),
                            &payload[range.start as usize..range.end as usize],
                            "{at}"
                        );
                        chunks.push(chunk);
                        let _ = volume.grant_read(op);
                    }
                    ReadEvent::Done { op, status, .. } => {
                        end(
                            (&mut live, &mut unreceived),
                            (volume.minted_reads(), &mut ended),
                            op,
                            status,
                            &at,
                        );
                        count(&mut tally, status, &at);
                    }
                }
            }
            let crate::storage::RawPartition {
                metadata,
                free,
                reserved,
                resident,
                retired,
                waste,
            } = storage.pool_report().unwrap().ledger.unwrap().raw;
            assert_eq!(
                metadata,
                crate::storage::TEST_METADATA_UNITS as usize * crate::storage::IO_UNIT,
                "{at}"
            );
            assert_eq!(
                free + reserved + resident + retired + waste,
                payload_bytes,
                "{at}"
            );
            let table = volume.table_report();
            // Report sanity: the table's slot counts partition its depth.
            let slots = table.free_slots + table.pending + table.abandoned + table.retired;
            assert_eq!(slots, u32::from(DEPTH), "{at}");
            // Reads and writes reach every slot outside the one-slot metadata share.
            quarantine_full += u32::from(table.free_slots <= 1 && table.abandoned > 0);
            // Pool custody from each buffer's obligation set, checked against the pool's counters.
            let (mut storage_held, mut quarantined, mut empty) = (0, 0, true);
            for kind in [PoolKind::ReadResponse, PoolKind::ReceiveWrite] {
                let pool = arena.report(kind);
                let [free, application, storage, detached, ..] = arena.pools().census(kind);
                assert_eq!(
                    (free, application, storage, detached),
                    (pool.free, pool.application, pool.storage, pool.quarantined),
                    "{kind:?}, {at}"
                );
                storage_held += storage;
                quarantined += detached;
                empty &= free == 0;
            }
            pools_empty += u32::from(empty);
            assert_eq!(
                table.pending + table.abandoned,
                storage_held + quarantined,
                "{at}"
            );
            assert_eq!(table.abandoned, quarantined, "{at}");
            let census = census(&mut volume, &at);
            // The volume's census is the independent side for the table's pending and abandoned commands.
            // A terminal taken from the table and not yet applied keeps its token mapped.
            // An unwound submit's command may already have come back, counted stale, while the
            // proven stop is still delivering, so each unmapped read holds at most one command.
            let owned = u64::from(table.pending + table.abandoned) + volume.scratch.len() as u64;
            let mapped = census.mapped_reads + census.mapped_writes;
            let unwound = census.unmapped + u64::from(volume.unwound_writes);
            assert!(
                (mapped..=mapped + unwound).contains(&owned),
                "{at}: {owned} owned, {mapped} mapped, {unwound} unwound"
            );
            assert_eq!(
                census.mapped_writes + u64::from(volume.unwound_writes),
                census.outstanding_writes,
                "{at}"
            );
            assert_eq!(
                u64::from(volume.write_held),
                census.outstanding_writes,
                "{at}: the write share holds the commands the sets have in flight"
            );
            retired_under_writes += u32::from(retired > 0 && census.outstanding_writes > 0);
            let report = volume.report();
            assert_eq!(
                report.reads_submitted,
                report.reads_done + report.reads_failed + census.mapped_reads,
                "{at}"
            );
            assert_eq!(
                report.writes_submitted,
                report.writes_done + report.writes_failed + census.mapped_writes,
                "{at}"
            );
            let counters = [
                report.cancelled,
                report.timed_out,
                report.header_mismatch,
                report.chunk_mismatch,
            ];
            assert_eq!(counters, tally, "{at}");
            assert_eq!(report.validated_bytes, validated, "{at}");
            assert!(
                arena.report(PoolKind::ReadResponse).application >= chunks.len() as u32,
                "{at}"
            );
        }
        if loss == Loss::Gone && volume.is_lost() {
            losses.push(Loss::Gone);
        }
        drop(chunks);
        assert!(
            volume.quiesced,
            "a reset proves the stop, seed {seed}\n{}",
            control.describe()
        );
        for _ in 0..8 {
            volume.poll_storage(u64::MAX, &mut out);
            for event in out.drain(..) {
                if let ReadEvent::Done { op, status, .. } = event {
                    let at = format!("seed {seed}");
                    end(
                        (&mut live, &mut unreceived),
                        (volume.minted_reads(), &mut ended),
                        op,
                        status,
                        &at,
                    );
                    count(&mut tally, status, &at);
                }
            }
        }
        assert!(
            live.is_empty() && unreceived == 0,
            "every admitted read ended once, seed {seed}: {live:?}, {unreceived} unreceived"
        );
        assert_eq!(volume.reads.live(), 0, "seed {seed}");
        let report = volume.report();
        let counters = [
            report.cancelled,
            report.timed_out,
            report.header_mismatch,
            report.chunk_mismatch,
        ];
        assert_eq!(counters, tally, "seed {seed}");
        assert!(volume.release().is_ok(), "seed {seed}");
        let pool = storage.live_pool().unwrap();
        for slot in 0..pool.records().len() {
            assert_eq!(
                pool.refs(slot),
                0,
                "every right ended, seed {seed} slot {slot}"
            );
        }
        drop((out, tiny));
        assert!(arena.release().is_ok(), "seed {seed}");
    }
    assert!(seen.iter().all(|seen| *seen), "every fault ran: {seen:?}");
    for kind in [
        Loss::TickSubmit,
        Loss::TickPick,
        Loss::ReadSubmit,
        Loss::WriteSubmit,
        Loss::Gone,
    ] {
        assert!(losses.contains(&kind), "{kind:?} lost a volume: {losses:?}");
    }
    assert!(
        quarantine_full > 0,
        "the table filled with quarantine outside the metadata share"
    );
    assert!(pools_empty > 0, "every pool was exhausted at once");
    assert!(later_faults > 0, "a later command met a fault or a hold");
    assert!(tiny_ticks > 0, "an output too small for any event");
    assert!(
        retired_under_writes > 0,
        "a retired extent waited on a write set's right"
    );
}

/// Ends `op` once: a live read, or else one of the `unreceived` reads whose first submit unwound, which can only end `Lost` or `TimedOut`.
/// Every `Done` names an identity the volume minted and no earlier `Done` named, whether or not the test holds a handle for it, so a fabricated or reused identity fails here.
fn end(
    (live, unreceived): (&mut Vec<(ReadOp, usize)>, &mut u32),
    (minted, ended): (&[(u32, u64)], &mut Vec<ReadOp>),
    op: ReadOp,
    status: ReadStatus,
    at: &str,
) {
    assert!(
        minted.contains(&(op.slot, op.generation)),
        "a Done for an identity the volume never minted, {op:?}, {at}"
    );
    assert!(!ended.contains(&op), "a second Done for {op:?}, {at}");
    ended.push(op);
    if let Some(index) = live.iter().position(|(live, _)| *live == op) {
        live.swap_remove(index);
        return;
    }
    assert!(*unreceived > 0, "a second Done, {at}");
    assert!(
        matches!(status, ReadStatus::Lost | ReadStatus::TimedOut),
        "{status:?}, {at}"
    );
    *unreceived -= 1;
}

/// Adds a delivered status to the tally of cancelled, timed-out, header-mismatch and chunk-mismatch reads.
/// Every placed record carries the key, incarnation and session its read expects, so each header mismatch is a layout or checksum failure.
fn count(tally: &mut [u64; 4], status: ReadStatus, at: &str) {
    match status {
        ReadStatus::Cancelled => tally[0] += 1,
        ReadStatus::TimedOut => tally[1] += 1,
        ReadStatus::HeaderMismatch(mismatch) => {
            assert!(
                !matches!(
                    mismatch,
                    HeaderMismatch::Key
                        | HeaderMismatch::Allocation { .. }
                        | HeaderMismatch::Session { .. }
                        | HeaderMismatch::CacheVersion { .. }
                        | HeaderMismatch::ForeignSession { .. }
                ),
                "{mismatch:?}, {at}"
            );
            tally[2] += 1;
        }
        ReadStatus::ChunkMismatch { .. } => tally[3] += 1,
        _ => {}
    }
}

#[test]
fn held_reads_end_at_their_own_deadline_cancel_or_terminal() {
    let storage = storage(4);
    let arena = arena_with(4, 4);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let records: Vec<Record> = (0..4)
        .map(|i| record(i * 16, 0, CHUNK, SESSION, 40 + i))
        .collect();
    let mut reads = Vec::new();
    for (record, deadline) in records.iter().zip([30, 20, 1 << 40, 1 << 40]) {
        place(&storage, &control, record);
        let op = volume.read_raw(&record.read, deadline).expect("admitted");
        let token = last_submitted(&control);
        control.hold(token);
        reads.push((op, token));
    }
    let mut out = Vec::with_capacity(16);
    for now in [1, 5, 19] {
        step(&mut volume, &control, now, &mut out);
        assert!(out.is_empty(), "no read has a step at {now}");
    }
    step(&mut volume, &control, 20, &mut out);
    assert_eq!(dones(&mut out), [(reads[1].0, ReadStatus::TimedOut)]);
    step(&mut volume, &control, 25, &mut out);
    assert!(out.is_empty(), "one Done per operation");
    volume.cancel_read(reads[3].0).expect("live");
    step(&mut volume, &control, 26, &mut out);
    assert_eq!(dones(&mut out), [(reads[3].0, ReadStatus::Cancelled)]);
    control.release(reads[2].1);
    step(&mut volume, &control, 27, &mut out);
    assert_eq!(dones(&mut out), [(reads[2].0, ReadStatus::Complete)]);
    step(&mut volume, &control, 29, &mut out);
    assert!(out.is_empty());
    step(&mut volume, &control, 30, &mut out);
    assert_eq!(dones(&mut out), [(reads[0].0, ReadStatus::TimedOut)]);
    for (_, token) in [reads[0], reads[1], reads[3]] {
        control.release(token);
    }
    for now in 31..35 {
        step(&mut volume, &control, now, &mut out);
    }
    assert!(out.is_empty(), "late terminals free silently");
    assert_eq!(volume.reads.live(), 0);
    assert_eq!(arena.report(PoolKind::ReadResponse).free, 4);
}

/// A proven quiesce ends device access to the arena; the driver's own native
/// state outlives the volume, so release hands the driver back and the
/// integrator stops and detaches it after the registration's undo.
#[test]
fn release_hands_back_the_attached_driver() {
    use super::super::device::{Disk, QuiesceStatus};
    let storage = storage(4);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    assert_eq!(
        volume.close(),
        QuiesceProgress::Quiesced(Quiesced::AllReturned)
    );
    let (proof, mut disk) = volume.release_driver().map_err(|_| ()).expect("released");
    assert_eq!(proof, Quiesced::AllReturned);
    let calls = control.driver_calls();
    assert_eq!(
        disk.quiesce(),
        QuiesceStatus::Pending,
        "the driver still runs"
    );
    assert_eq!(
        control.driver_calls(),
        calls + 1,
        "the handed-back driver answered"
    );
    assert_eq!(arena.release().map_err(|_| ()), Ok(Released::Complete));
}

crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
    a_device_gone_refusal_loses_the_volume_and_ends_every_admitted_read_once,
    a_driver_that_unwinds_in_a_tick_loses_the_volume_and_its_read_ends_once,
    an_operation_with_nothing_outstanding_frees_at_its_deadline,
    an_unwound_write_submit_keeps_its_sets_right_until_the_proven_stop,
    held_reads_end_at_their_own_deadline_cancel_or_terminal,
    quarantined_and_pending_commands_that_fill_the_table_refuse_a_write_and_hold_a_read_waiting,
    seeded_fault_schedules_conserve_the_ledger_the_table_the_pools_and_every_command,
);

/// The lifecycle census refuses a `Done` whose identity the volume never minted, even while a read whose first submit unwound is still unreceived.
#[test]
#[should_panic(expected = "a Done for an identity the volume never minted")]
fn a_done_with_a_fabricated_identity_fails_the_census() {
    let fabricated = ReadOp {
        slot: 3,
        generation: 9,
    };
    end(
        (&mut Vec::new(), &mut 1),
        (&[(3, 8), (4, 9)], &mut Vec::new()),
        fabricated,
        ReadStatus::Lost,
        "the control",
    );
}

/// The lifecycle census refuses a second `Done` for a minted identity that already ended, even while another unreceived read could absorb it.
#[test]
#[should_panic(expected = "a second Done for")]
fn a_second_done_for_an_ended_identity_fails_the_census() {
    let op = ReadOp {
        slot: 3,
        generation: 8,
    };
    let mut ended = Vec::new();
    end(
        (&mut Vec::new(), &mut 2),
        (&[(3, 8)], &mut ended),
        op,
        ReadStatus::Lost,
        "the control",
    );
    end(
        (&mut Vec::new(), &mut 1),
        (&[(3, 8)], &mut ended),
        op,
        ReadStatus::Lost,
        "the control",
    );
}

#[test]
fn a_read_whose_submit_the_device_refused_leaves_no_minted_identity() {
    let storage = storage(2);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let short = record(0, 0, CHUNK, SESSION, 33);
    place(&storage, &control, &short);
    let invalid = SubmitRefusal {
        reason: RefusalReason::InvalidRange,
        code: None,
    };
    control.refuse_next(invalid);
    assert_eq!(
        volume.read_raw(&short.read, u64::MAX),
        Err(ReadRefusal::Submit(Refusal::Device(invalid)))
    );
    assert_eq!(
        volume.minted_reads(),
        &[],
        "a refused read can emit no Done"
    );
    let admitted = volume.read_raw(&short.read, u64::MAX).expect("admitted");
    assert_eq!(
        volume.minted_reads(),
        &[(admitted.slot, admitted.generation)]
    );
    control.set_gone();
    assert_eq!(
        volume.read_raw(&short.read, u64::MAX),
        Err(ReadRefusal::Lost)
    );
    assert_eq!(
        volume.minted_reads(),
        &[(admitted.slot, admitted.generation)],
        "a read refused by a gone device can emit no Done"
    );
}
