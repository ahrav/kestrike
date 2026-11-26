//! Verified read information, explicit next-command grants and the drain proof of the read path.

use std::panic::{AssertUnwindSafe, catch_unwind};

use super::super::device::sim::{Mode, QuiesceMode, SimConfig, SimControl, StatusForm, Unwind};
use super::super::device::{IO_UNIT, PoolKind, SECTOR};
use super::super::ledger::EngineBudget;
use super::super::owner::Storage;
use super::super::record::{HeaderMismatch, RecordConfig, RecordIdentity};
use super::super::test_platform::TestPlatform;
use super::super::volume_fixture::{attached, drive, drive_from};
use super::read::Command;
use super::volume_tests::{
    CHUNK, DEPTH, KEY, Record, SESSION, TICK, TestVolume, arena, arena_with, arena_with_read_len,
    attach, last_submitted, place, queue_full, record, storage, storage_reading_ahead,
    storage_sized, submits,
};
use super::{AttachError, ControlRefusal, Grant, RawRead, ReadEvent, ReadOp, ReadStatus, Volume};
use crate::net::{
    BUFFERS_PER_READ, FragmentGeometry, GeometryError, GeometryInputs, GeometryRefusal,
};
use crate::sim::round::{Act, Actor, round, turn_until};

/// One device step and one tick at `now` as one controller round,
/// returning the events in order.
fn tick<'a>(volume: &mut TestVolume<'_, 'a>, control: &SimControl, now: u64) -> Vec<ReadEvent<'a>> {
    let mut out = Vec::with_capacity(8);
    let mut step = || control.tick(8);
    let mut poll = || {
        let _ = volume.poll_storage(now, &mut out);
    };
    round(&mut [
        Act::new(Actor::Disk(0), &mut step),
        Act::new(Actor::Volume(0), &mut poll),
    ]);
    out
}

/// [`tick`] once, and under a generated schedule, where a round may poll
/// before its device step, again until `decided` holds for the volume and
/// the events gathered so far, at most eight ticks; returns those events in
/// order.
fn tick_until<'a>(
    volume: &mut TestVolume<'_, 'a>,
    control: &SimControl,
    now: u64,
    decided: impl Fn(&TestVolume<'_, 'a>, &[ReadEvent<'a>]) -> bool,
) -> Vec<ReadEvent<'a>> {
    let mut events = Vec::new();
    turn_until(|| {
        events.extend(tick(volume, control, now));
        decided(volume, &events)
    });
    events
}

/// [`tick_until`] some event arrives.
fn first_tick<'a>(
    volume: &mut TestVolume<'_, 'a>,
    control: &SimControl,
    now: u64,
) -> Vec<ReadEvent<'a>> {
    tick_until(volume, control, now, |_, events| !events.is_empty())
}

/// Whether `events` hold a `Done`.
fn any_done(events: &[ReadEvent<'_>]) -> bool {
    events
        .iter()
        .any(|event| matches!(event, ReadEvent::Done { .. }))
}

/// A record whose payload spans five windows, so its read takes three commands: two of two windows, then one of one window.
fn three_commands() -> Record {
    record(0, 0, 4 * CHUNK, SESSION, 21)
}

/// The response pool's buffers by custody: free, application, storage and quarantined.
fn census(
    arena: &super::super::device::BufferArena<super::super::test_platform::TestPlatform>,
) -> [u32; 4] {
    let [free, application, storage, quarantined, ..] =
        arena.pools().census(PoolKind::ReadResponse);
    [free, application, storage, quarantined]
}

/// A header-valid empty payload ends `Complete` with
/// its record's full identity and zero lengths, emits no `Chunk`, and leaves
/// every response buffer where it started.
#[test]
fn an_empty_payload_completes_with_its_verified_info_and_no_chunk() {
    let storage = storage(2);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let empty = record(0, 0, 0, SESSION, 3);
    place(&storage, &control, &empty);
    let before = census(&arena);
    let op = volume.read_raw(&empty.read, u64::MAX).expect("admitted");
    let delivered = drive(&mut volume, &control, op);
    assert_eq!(delivered.status, ReadStatus::Complete);
    assert!(delivered.ranges.is_empty(), "no Chunk");
    let info = delivered.info.expect("the header verified");
    let identity = RecordIdentity {
        key: KEY,
        allocation: 3,
        session: SESSION,
        version: 0,
    };
    assert_eq!(*info.identity(), identity);
    assert_eq!(
        (info.metadata_len(), info.body_len(), info.payload_len()),
        (0, 0, 0)
    );
    assert_eq!(census(&arena), before, "the pool census is unchanged");
    assert!(volume.read_drained(op));
}

/// Every `Chunk` and the `Done` of a read whose header
/// verified carry the record's identity and both lengths, also when a later
/// chunk fails its checksum.
#[test]
fn every_event_after_a_verified_header_carries_its_identity_and_lengths() {
    let storage = storage(2);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let record = record(0, 37, 3 * CHUNK - 3, SESSION, 5);
    place(&storage, &control, &record);
    let op = volume.read_raw(&record.read, u64::MAX).expect("admitted");
    let delivered = drive(&mut volume, &control, op);
    assert_eq!(delivered.status, ReadStatus::Complete);
    assert_eq!(delivered.bytes, record.payload);
    let info = delivered.info.expect("verified");
    assert_eq!(info.identity().key, KEY);
    assert_eq!(info.identity().allocation, 5);
    assert_eq!((info.metadata_len(), info.body_len()), (37, 3 * CHUNK - 3));
    assert_eq!(info.payload_len(), record.payload.len() as u64);
    let mut forged = record.bytes.clone();
    forged[record.layout.header_bytes() + 2 * CHUNK as usize] ^= 0x01;
    control.write_device(
        crate::storage::volume_fixture::device_byte(&storage, record.read.locator),
        &forged,
    );
    let op = volume.read_raw(&record.read, u64::MAX).expect("admitted");
    let delivered = drive(&mut volume, &control, op);
    assert!(matches!(delivered.status, ReadStatus::ChunkMismatch { .. }));
    assert_eq!(
        delivered.info,
        Some(info),
        "the header verified before the chunk failed"
    );
}

/// A corrupt header crc, magic, version, lengths,
/// allocation, session or key ends the read `Done` with no information and
/// exposes no byte.
#[test]
fn every_header_failure_carries_no_info_and_exposes_no_byte() {
    let storage = storage(2);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let good = record(0, 0, CHUNK, SESSION, 8);
    let flipped = |at: usize| {
        let mut bytes = good.bytes.clone();
        bytes[at] ^= 0x01;
        bytes
    };
    let short = RawRead {
        locator: super::super::extent::ExtentLocator::new(
            good.read.locator.start_unit(),
            good.read.locator.len_units() - 1,
        )
        .expect("fits"),
        ..good.read
    };
    let stale_session = record(0, 0, CHUNK, SESSION + 1, 8);
    let cases: [(&str, Vec<u8>, RawRead); 7] = [
        ("magic", flipped(0), good.read),
        ("version", flipped(8), good.read),
        ("crc", flipped(20), good.read),
        ("lengths", good.bytes.clone(), short),
        (
            "allocation",
            good.bytes.clone(),
            RawRead {
                allocation: 9,
                ..good.read
            },
        ),
        ("session", stale_session.bytes.clone(), good.read),
        (
            "key",
            good.bytes.clone(),
            RawRead {
                key: [0; 32],
                ..good.read
            },
        ),
    ];
    for (name, bytes, read) in cases {
        control.write_device(
            crate::storage::volume_fixture::device_byte(&storage, good.read.locator),
            &bytes,
        );
        let op = volume.read_raw(&read, u64::MAX).expect("admitted");
        let delivered = drive(&mut volume, &control, op);
        let ReadStatus::HeaderMismatch(mismatch) = delivered.status else {
            panic!("{name}: {:?}", delivered.status);
        };
        let expected = match name {
            "magic" => matches!(mismatch, HeaderMismatch::Magic { .. }),
            "version" => matches!(mismatch, HeaderMismatch::Version { .. }),
            "crc" => matches!(mismatch, HeaderMismatch::HeaderCrc { .. }),
            "lengths" => matches!(mismatch, HeaderMismatch::Lengths { .. }),
            "allocation" => matches!(mismatch, HeaderMismatch::Allocation { .. }),
            "session" => matches!(mismatch, HeaderMismatch::Session { .. }),
            _ => mismatch == HeaderMismatch::Key,
        };
        assert!(expected, "{name}: {mismatch:?}");
        assert_eq!(delivered.info, None, "{name}");
        assert!(delivered.bytes.is_empty(), "{name}");
    }
    assert_eq!(arena.report(PoolKind::ReadResponse).free, 4);
}

/// A read submits only its first command on its own; each
/// later command waits outside the tick's work until one grant, which
/// submits it at once; a grant while that command is outstanding is kept and
/// spent by the tick that verified its bytes on the command after it, so a
/// second kept grant adds nothing; a grant while the last command is
/// outstanding admits nothing; and a grant after the outcome is stale.
#[test]
fn each_later_command_waits_for_one_grant_and_a_kept_grant_admits_one() {
    let storage = storage(2);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let record = three_commands();
    place(&storage, &control, &record);
    let op = volume.read_raw(&record.read, u64::MAX).expect("admitted");
    let first = first_tick(&mut volume, &control, 0);
    assert!(matches!(first.as_slice(), [ReadEvent::Chunk { .. }]));
    drop(first);
    for _ in 0..4 {
        assert!(
            tick(&mut volume, &control, 0).is_empty(),
            "no grant, no step"
        );
    }
    assert_eq!(submits(&control), 1);
    assert_eq!(
        volume.ready.members(),
        0,
        "a read waiting for a grant has no tick work"
    );
    assert!(!volume.read_drained(op));
    let allocations = crate::instrument::allocations();
    volume.grant_read(op).expect("live");
    assert_eq!(
        submits(&control),
        2,
        "the grant submitted the second command"
    );
    assert_eq!(
        volume.ready.members(),
        0,
        "a reading record has no tick work"
    );
    volume
        .grant_read(op)
        .expect("a grant during the command is kept");
    volume
        .grant_read(op)
        .expect("a second kept grant is accepted");
    assert!(!volume.read_drained(op));
    assert_eq!(
        crate::instrument::allocations(),
        allocations,
        "grants allocate nothing"
    );
    assert_eq!(
        submits(&control),
        2,
        "kept grants submit nothing by themselves"
    );
    let mut out = Vec::with_capacity(2);
    let mut report = None;
    turn_until(|| {
        let mut step = || control.tick(8);
        let mut poll = || report = Some(volume.poll_storage(0, &mut out));
        round(&mut [
            Act::new(Actor::Disk(0), &mut step),
            Act::new(Actor::Volume(0), &mut poll),
        ]);
        report.is_some_and(|report| report.terminals > 0)
    });
    assert_eq!(
        report.expect("the round polled the volume").submitted,
        1,
        "the tick that verified the command spent the kept grant"
    );
    assert!(matches!(out.as_slice(), [ReadEvent::Chunk { .. }]));
    out.clear();
    assert_eq!(submits(&control), 3, "two kept grants admitted one command");
    // A grant while the last command is outstanding is kept and admits nothing.
    let last = last_submitted(&control);
    control.hold(last);
    volume.grant_read(op).expect("kept");
    for _ in 0..4 {
        assert!(tick(&mut volume, &control, 0).is_empty());
    }
    control.release(last);
    let mut events = tick(&mut volume, &control, 0);
    events.extend(tick_until(&mut volume, &control, 0, |_, events| {
        any_done(events)
    }));
    let statuses: Vec<_> = events
        .iter()
        .map(|event| match event {
            ReadEvent::Chunk { .. } => None,
            ReadEvent::Done { status, .. } => Some(*status),
        })
        .collect();
    assert_eq!(statuses, [None, Some(ReadStatus::Complete)]);
    drop(events);
    assert_eq!(submits(&control), 3);
    assert_eq!(volume.grant_read(op), Err(ControlRefusal::Stale));
}

/// A grant whose submit finds no free
/// response buffer keeps the grant in the waiting set: the read holds nothing
/// more, the tick after a buffer frees retries the submit, and a `QueueFull`
/// refusal of that retry keeps the grant for the tick after it, which submits
/// the command once; a grant whose submit the device queue refuses as full is
/// kept the same way, and a grant that submits after a kept one takes the slot
/// out of the waiting set.
#[test]
fn a_grant_refused_as_full_is_kept_for_the_tick() {
    let storage = storage(2);
    let arena = arena_with(1, 1);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let record = three_commands();
    place(&storage, &control, &record);
    let op = volume.read_raw(&record.read, u64::MAX).expect("admitted");
    let first = first_tick(&mut volume, &control, 0);
    let [ReadEvent::Chunk { chunk, .. }] = first.as_slice() else {
        panic!("{first:?}");
    };
    assert_eq!(arena.report(PoolKind::ReadResponse).free, 0);
    volume.grant_read(op).expect("live");
    assert_eq!(submits(&control), 1, "no buffer, no submit");
    assert_eq!(volume.report().reads_refused, 0);
    assert_eq!(
        (volume.ready.members(), volume.waiting.members()),
        (0, 1),
        "the kept grant waits for room"
    );
    for _ in 0..3 {
        assert!(tick(&mut volume, &control, 0).is_empty());
        assert_eq!(submits(&control), 1);
    }
    let _ = chunk;
    drop(first);
    control.refuse_next(queue_full());
    let mut out = Vec::with_capacity(2);
    assert_eq!(volume.poll_storage(0, &mut out).submitted, 0);
    assert_eq!(
        volume.report().reads_refused,
        1,
        "the queue refused the retry"
    );
    assert_eq!(volume.poll_storage(0, &mut out).submitted, 1);
    assert_eq!(submits(&control), 2, "the kept grant admitted one command");
    turn_until(|| {
        let mut step = || control.tick(8);
        let mut poll = || assert_eq!(volume.poll_storage(0, &mut out).submitted, 0);
        round(&mut [
            Act::new(Actor::Disk(0), &mut step),
            Act::new(Actor::Volume(0), &mut poll),
        ]);
        !out.is_empty()
    });
    assert!(matches!(out.as_slice(), [ReadEvent::Chunk { .. }]));
    out.clear();
    for _ in 0..3 {
        assert!(tick(&mut volume, &control, 0).is_empty());
    }
    assert_eq!(submits(&control), 2, "the grant was spent");
    control.refuse_next(queue_full());
    assert_eq!(volume.grant_read(op), Ok(Grant::Added));
    assert_eq!(submits(&control), 2, "the queue refused the grant's submit");
    assert_eq!(volume.report().reads_refused, 2);
    assert_eq!(
        (volume.ready.members(), volume.waiting.members()),
        (0, 1),
        "the kept grant waits for room"
    );
    assert_eq!(
        volume.grant_read(op),
        Ok(Grant::Merged),
        "the kept grant already admits the command"
    );
    assert_eq!(
        submits(&control),
        3,
        "the second grant submitted the kept command"
    );
    assert_eq!(
        (volume.ready.members(), volume.waiting.members()),
        (0, 0),
        "a submitted command leaves the waiting set"
    );
    assert_eq!(volume.poll_storage(0, &mut out).submitted, 0);
    // The first two commands handed off chunks 0 to 3; the third carries chunk 4.
    let taken = record.layout.chunk(3).expect("in range").end;
    let delivered = drive_from(&mut volume, &control, op, taken);
    assert_eq!(delivered.status, ReadStatus::Complete);
    assert_eq!(delivered.bytes, record.payload[taken as usize..]);
}

/// A grant made while the first command is held is
/// kept, and the tick that verifies that command submits the next one; the
/// grant is then spent.
#[test]
fn a_grant_while_reading_is_kept_and_spent_by_the_next_submit() {
    let storage = storage(2);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let record = three_commands();
    place(&storage, &control, &record);
    let op = volume.read_raw(&record.read, u64::MAX).expect("admitted");
    let token = last_submitted(&control);
    control.hold(token);
    volume
        .grant_read(op)
        .expect("a grant while reading is kept");
    assert!(tick(&mut volume, &control, 0).is_empty());
    assert_eq!(submits(&control), 1);
    control.release(token);
    let mut out = Vec::with_capacity(2);
    let mut report = None;
    turn_until(|| {
        let mut step = || control.tick(8);
        let mut poll = || report = Some(volume.poll_storage(0, &mut out));
        round(&mut [
            Act::new(Actor::Disk(0), &mut step),
            Act::new(Actor::Volume(0), &mut poll),
        ]);
        report.is_some_and(|report| report.terminals > 0)
    });
    let report = report.expect("the round polled the volume");
    assert!(matches!(out.as_slice(), [ReadEvent::Chunk { .. }]));
    assert_eq!(
        report.submitted, 1,
        "the kept grant admitted the second command"
    );
    out.clear();
    for _ in 0..4 {
        let mut poll = || {
            let _ = volume.poll_storage(0, &mut out);
            out.clear();
        };
        let mut step = || control.tick(8);
        round(&mut [
            Act::new(Actor::Volume(0), &mut poll),
            Act::new(Actor::Disk(0), &mut step),
        ]);
    }
    assert_eq!(submits(&control), 2, "the grant was spent");
}

/// A cancel ends a read waiting for its grant and
/// clears a kept grant, so no later command is submitted; a deadline ends a
/// waiting read although no tick work names it; and after `close` a grant
/// refuses `Closed` while the waiting read ends `Quiesced`.
#[test]
fn cancel_deadline_and_close_end_a_read_waiting_for_its_grant() {
    let storage = storage(2);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let record = three_commands();
    place(&storage, &control, &record);
    // Cancel while waiting.
    let op = volume.read_raw(&record.read, u64::MAX).expect("admitted");
    drop(first_tick(&mut volume, &control, 0));
    volume.cancel_read(op).expect("live");
    let done = tick(&mut volume, &control, 0);
    assert!(matches!(
        done.as_slice(),
        [ReadEvent::Done {
            status: ReadStatus::Cancelled,
            info: Some(_),
            ..
        }]
    ));
    drop(done);
    assert_eq!(volume.grant_read(op), Err(ControlRefusal::Stale));
    assert!(volume.read_drained(op));
    // Cancel clears a kept grant.
    let before = submits(&control);
    let op = volume.read_raw(&record.read, u64::MAX).expect("admitted");
    let token = last_submitted(&control);
    control.hold(token);
    volume.grant_read(op).expect("kept");
    volume.cancel_read(op).expect("live");
    control.release(token);
    for _ in 0..4 {
        drop(tick(&mut volume, &control, 0));
    }
    assert_eq!(submits(&control), before + 1, "only the first command");
    assert!(volume.read_drained(op));
    // A deadline ends a waiting read.
    let op = volume.read_raw(&record.read, 10).expect("admitted");
    assert_eq!(
        first_tick(&mut volume, &control, 0).len(),
        1,
        "its first chunk"
    );
    assert!(tick(&mut volume, &control, 9).is_empty());
    let done = tick(&mut volume, &control, 10);
    assert!(matches!(
        done.as_slice(),
        [ReadEvent::Done {
            status: ReadStatus::TimedOut,
            info: Some(_),
            ..
        }]
    ));
    drop(done);
    assert!(volume.read_drained(op));
    // Close ends a waiting read.
    let op = volume.read_raw(&record.read, u64::MAX).expect("admitted");
    drop(first_tick(&mut volume, &control, 0));
    let _ = volume.close();
    assert_eq!(volume.grant_read(op), Err(ControlRefusal::Closed));
    // The first tick after close ends it and delivers its `Done`.
    let done = tick(&mut volume, &control, 0);
    assert!(matches!(
        done.as_slice(),
        [ReadEvent::Done {
            status: ReadStatus::Quiesced,
            ..
        }]
    ));
    drop(done);
    assert!(volume.read_drained(op));
    assert_eq!(arena.report(PoolKind::ReadResponse).free, 4);
}

/// A read waiting for its grant keeps its deadline in the bound a full sweep
/// recomputes: another read's deadline triggers a sweep that rebuilds the
/// bound, and the waiting read still ends `TimedOut` at its own deadline.
#[test]
fn a_waiting_read_times_out_after_a_sweep_rebuilt_the_bound() {
    let storage = storage(2);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let short = record(0, 0, CHUNK, SESSION, 4);
    let long = record(16, 0, 4 * CHUNK, SESSION, 21);
    place(&storage, &control, &short);
    place(&storage, &control, &long);
    let held = volume.read_raw(&short.read, 5).expect("admitted");
    let token = last_submitted(&control);
    control.hold(token);
    let waiting = volume.read_raw(&long.read, 10).expect("admitted");
    let first = first_tick(&mut volume, &control, 0);
    assert!(matches!(first.as_slice(), [ReadEvent::Chunk { op, .. }] if *op == waiting));
    drop(first);
    let swept = tick(&mut volume, &control, 5);
    assert!(matches!(
        swept.as_slice(),
        [ReadEvent::Done { op, status: ReadStatus::TimedOut, .. }] if *op == held
    ));
    drop(swept);
    assert!(tick(&mut volume, &control, 9).is_empty());
    let done = tick(&mut volume, &control, 10);
    assert!(matches!(
        done.as_slice(),
        [ReadEvent::Done { op, status: ReadStatus::TimedOut, info: Some(_) }] if *op == waiting
    ));
    drop(done);
    assert!(
        !volume.read_drained(held),
        "the held command keeps its record"
    );
    control.release(token);
    drop(tick_until(&mut volume, &control, 10, |volume, _| {
        volume.read_drained(held)
    }));
    assert!(volume.read_drained(held));
}

/// A read whose `Done` frees its record in a sweeping tick clears its ready
/// bit and drops its deadline from the bound: the rebuilt bound is the
/// waiting read's deadline, and a tick before that deadline produces no
/// events.
#[test]
fn a_read_freed_at_its_done_leaves_no_ready_bit_and_no_deadline() {
    let storage = storage(2);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let early = record(20, 0, 100, SESSION, 9);
    let short = record(30, 0, 100, SESSION, 10);
    let long = three_commands();
    for record in [&early, &short, &long] {
        place(&storage, &control, record);
    }
    // A read that frees at once leaves its deadline as the bound, so the
    // tick at 20 visits every live record.
    let first = volume.read_raw(&early.read, 10).expect("admitted");
    let ended = tick(&mut volume, &control, 0);
    assert!(matches!(
        ended.as_slice(),
        [ReadEvent::Chunk { .. }, ReadEvent::Done { op, status: ReadStatus::Complete, .. }] if *op == first
    ));
    drop(ended);
    let waiting = volume.read_raw(&long.read, 60).expect("admitted");
    let freed = volume.read_raw(&short.read, 30).expect("admitted");
    assert_eq!(volume.next_deadline, 10);
    let events = tick(&mut volume, &control, 20);
    let done: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            ReadEvent::Done { op, status, .. } => Some((*op, *status)),
            ReadEvent::Chunk { .. } => None,
        })
        .collect();
    assert_eq!(done, [(freed, ReadStatus::Complete)]);
    assert_eq!(
        events.len(),
        3,
        "a chunk of each read and the short read's Done"
    );
    drop(events);
    assert!(volume.read_drained(freed));
    assert_eq!(volume.ready.members(), 0, "neither read has tick work");
    assert_eq!(
        volume.next_deadline, 60,
        "the sweep keeps only the waiting read's deadline"
    );
    assert!(tick(&mut volume, &control, 59).is_empty());
    let timed_out = tick(&mut volume, &control, 60);
    assert!(matches!(
        timed_out.as_slice(),
        [ReadEvent::Done { op, status: ReadStatus::TimedOut, .. }] if *op == waiting
    ));
}

/// A grant kept while a command is outstanding admits nothing once the
/// volume closed: the command's terminal still hands off its verified
/// chunks, and the next tick ends the read `Quiesced` without a submit, a
/// refused submit or a held buffer.
#[test]
fn a_kept_grant_submits_nothing_after_close() {
    let storage = storage(2);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let record = three_commands();
    place(&storage, &control, &record);
    let op = volume.read_raw(&record.read, u64::MAX).expect("admitted");
    let token = last_submitted(&control);
    control.hold(token);
    volume.grant_read(op).expect("kept");
    let _ = volume.close();
    control.release(token);
    let chunk = first_tick(&mut volume, &control, 0);
    assert!(
        matches!(chunk.as_slice(), [ReadEvent::Chunk { .. }]),
        "{chunk:?}"
    );
    drop(chunk);
    let done = tick(&mut volume, &control, 0);
    assert!(matches!(
        done.as_slice(),
        [ReadEvent::Done {
            status: ReadStatus::Quiesced,
            info: Some(_),
            ..
        }]
    ));
    drop(done);
    assert_eq!(submits(&control), 1);
    assert_eq!(volume.report().reads_refused, 0);
    assert_eq!(arena.report(PoolKind::ReadResponse).free, 4);
}

/// A tick whose driver call unwinds loses the volume, and a read waiting for
/// its grant then ends `Lost`, with or without one.
/// The pick unwind leaves the table's admission open, so a grant before the
/// next tick reaches the volume's own loss state and submits no command.
#[test]
fn a_lost_volume_ends_a_read_waiting_for_its_grant() {
    for granted in [false, true] {
        let storage = storage(2);
        let arena = arena();
        let (mut volume, control) = attach(&storage, &arena, TICK);
        let record = three_commands();
        place(&storage, &control, &record);
        let op = volume.read_raw(&record.read, u64::MAX).expect("admitted");
        drop(tick(&mut volume, &control, 0));
        control.unwind_next(Some(Unwind::Pick));
        let mut out = Vec::with_capacity(2);
        assert!(catch_unwind(AssertUnwindSafe(|| volume.poll_storage(0, &mut out))).is_err());
        control.unwind_next(None);
        assert!(volume.is_lost());
        if granted {
            let before = submits(&control);
            assert_eq!(volume.grant_read(op), Ok(Grant::Added));
            assert_eq!(submits(&control), before, "a lost volume submits nothing");
        }
        let done = tick(&mut volume, &control, 0);
        assert!(
            matches!(
                done.as_slice(),
                [ReadEvent::Done {
                    op: of,
                    status: ReadStatus::Lost,
                    ..
                }] if *of == op
            ),
            "granted {granted}: {done:?}"
        );
        drop(done);
        assert!(volume.read_drained(op), "granted {granted}");
    }
}

/// A submit the device refuses `DeviceGone` loses the volume in the middle of
/// a tick's scan, and a read the same scan visits afterwards ends `Lost`
/// instead of verifying the bytes that arrived for it.
#[test]
fn a_loss_in_a_ticks_submit_ends_the_reads_visited_after_it_lost() {
    let storage = storage(2);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let long = three_commands();
    let short = record(20, 0, CHUNK, SESSION, 4);
    place(&storage, &control, &long);
    place(&storage, &control, &short);
    let granted = volume.read_raw(&long.read, u64::MAX).expect("admitted");
    let later = volume.read_raw(&short.read, u64::MAX).expect("admitted");
    assert!(
        granted.slot < later.slot,
        "the scan visits the granted read first"
    );
    volume
        .grant_read(granted)
        .expect("kept while its first command is outstanding");
    control.set_gone();
    let events = tick_until(&mut volume, &control, 0, |volume, _| volume.is_lost());
    assert!(volume.is_lost());
    let done: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            ReadEvent::Done { op, status, .. } => Some((*op, *status)),
            ReadEvent::Chunk { .. } => None,
        })
        .collect();
    assert_eq!(done, [(later, ReadStatus::Lost)], "{events:?}");
    drop(events);
    let ended = tick(&mut volume, &control, 0);
    assert!(matches!(
        ended.as_slice(),
        [ReadEvent::Done { op, status: ReadStatus::Lost, .. }] if *op == granted
    ));
}

/// A delivered `Done` proves no drain.
/// A cancelled or timed-out read whose command the device still holds stays
/// undrained until that command's terminal frees its record; once the slot
/// moved to a later generation the old handle is drained and the new one is
/// not.
#[test]
fn a_read_drains_only_when_its_record_frees_not_at_its_done() {
    for timed_out in [false, true] {
        let storage = storage(1);
        let arena = arena();
        let (mut volume, control) = attach(&storage, &arena, TICK);
        let record = three_commands();
        place(&storage, &control, &record);
        let deadline = if timed_out { 5 } else { u64::MAX };
        let op = volume.read_raw(&record.read, deadline).expect("admitted");
        let token = last_submitted(&control);
        control.hold(token);
        if !timed_out {
            volume.cancel_read(op).expect("live");
        }
        let done = tick(&mut volume, &control, 5);
        let expected = if timed_out {
            ReadStatus::TimedOut
        } else {
            ReadStatus::Cancelled
        };
        assert!(
            matches!(done.as_slice(), [ReadEvent::Done { status, info: None, .. }] if *status == expected),
            "{done:?}"
        );
        drop(done);
        for _ in 0..4 {
            assert!(tick(&mut volume, &control, 5).is_empty());
            assert!(!volume.read_drained(op), "the held command keeps custody");
        }
        assert_eq!(arena.report(PoolKind::ReadResponse).free, 3);
        control.release(token);
        let after = tick_until(&mut volume, &control, 5, |volume, _| {
            volume.read_drained(op)
        });
        assert!(after.is_empty(), "one Done per read");
        assert!(volume.read_drained(op));
        assert_eq!(arena.report(PoolKind::ReadResponse).free, 4);
        let next = volume.read_raw(&record.read, u64::MAX).expect("admitted");
        assert_eq!(next.slot, op.slot);
        assert_eq!(next.generation, op.generation + 1);
        assert!(
            volume.read_drained(op),
            "a moved generation drained the old record"
        );
        assert!(!volume.read_drained(next));
        let unreached = ReadOp {
            slot: next.slot,
            generation: next.generation + 1,
        };
        assert!(
            volume.read_drained(unreached),
            "a generation the slot never reached holds nothing"
        );
        let delivered = drive(&mut volume, &control, next);
        assert_eq!(delivered.status, ReadStatus::Complete);
        assert!(volume.read_drained(next));
    }
}

/// A later command whose submit unwound in
/// its grant keeps its read undrained through every tick until the proven stop
/// ends it `Lost`.
#[test]
fn an_unwound_later_submit_keeps_its_read_undrained_until_the_proven_stop() {
    let storage = storage(2);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let record = three_commands();
    place(&storage, &control, &record);
    let op = volume.read_raw(&record.read, u64::MAX).expect("admitted");
    drop(first_tick(&mut volume, &control, 0));
    control.unwind_next(Some(Unwind::Submit));
    assert!(catch_unwind(AssertUnwindSafe(|| volume.grant_read(op))).is_err());
    control.unwind_next(None);
    assert!(volume.is_lost());
    for now in 0..4 {
        assert!(tick(&mut volume, &control, now).is_empty());
        assert!(!volume.read_drained(op), "an unwound submit keeps custody");
    }
    control.set_quiesce(QuiesceMode::Reset);
    let mut ended = Vec::new();
    for _ in 0..4 {
        let _ = volume.close();
        for event in tick(&mut volume, &control, 0) {
            if let ReadEvent::Done { op: of, status, .. } = event {
                ended.push((of, status));
            }
        }
    }
    assert_eq!(ended, [(op, ReadStatus::Lost)]);
    assert!(volume.read_drained(op));
    assert!(volume.release().is_ok());
}

#[test]
fn a_release_right_after_the_proven_stop_frees_a_read_whose_submit_unwound() {
    for reads_ahead in [false, true] {
        let storage = if reads_ahead {
            storage_reading_ahead(2)
        } else {
            storage(2)
        };
        let arena = arena();
        let (mut volume, control) = attach(&storage, &arena, TICK);
        let record = three_commands();
        place(&storage, &control, &record);
        let op = volume.read_raw(&record.read, u64::MAX).expect("admitted");
        if !reads_ahead {
            drop(first_tick(&mut volume, &control, 0));
        }
        control.unwind_next(Some(Unwind::Submit));
        assert!(catch_unwind(AssertUnwindSafe(|| volume.grant_read(op))).is_err());
        control.unwind_next(None);
        assert!(volume.is_lost());
        control.set_quiesce(QuiesceMode::Reset);
        assert!(volume.release().is_ok(), "reads ahead {reads_ahead}");
    }
}

/// Every geometry attach admits plans a first command from the record's first
/// byte that holds the whole header and at least one chunk of a nonempty
/// payload, then contiguous whole-window commands, each carrying a chunk,
/// ending at the record's end; attach refuses some read span below the largest
/// header plus one chunk.
#[test]
fn every_admitted_geometry_plans_a_header_first_command_then_whole_windows() {
    let (mut admitted, mut refused) = (0, 0);
    for chunk_len in [4096, 8192, 16384] {
        for read_len in [8192, 16384, 32768] {
            for max_transfer in [8192, 12288, 16384, 1 << 20] {
                for body_cap in [1, 3 * 8192, 9 * 8192 + 5] {
                    let record = RecordConfig { chunk_len };
                    let Ok(storage) = storage_sized(1, record, body_cap) else {
                        continue;
                    };
                    let arena = arena_with_read_len(read_len);
                    let (disk, _control) = attached(SimConfig {
                        seed: 1,
                        capacity: 1 << 30,
                        queue_depth: u32::from(DEPTH),
                        max_transfer,
                        form: StatusForm::Kernel,
                        mode: Mode::Direct,
                        script: crate::storage::device::sim::SCRIPT,
                    });
                    let mut budget = EngineBudget::new(1 << 24);
                    let volume = match Volume::attach(
                        &storage,
                        &arena,
                        disk,
                        crate::storage::portable::scripted::ScriptedClock::trusted(),
                        crate::storage::ServingAuthority::fixture(),
                        DEPTH,
                        TICK,
                        &mut budget,
                    ) {
                        Ok(volume) => volume,
                        Err((error, _)) => {
                            let fit = matches!(error, AttachError::ReadCommandFit { .. });
                            if fit {
                                assert!(
                                    matches!(
                                        fragment_geometry(&storage, read_len, max_transfer),
                                        Err(GeometryError {
                                            reason: GeometryRefusal::HeaderFirst { .. }
                                                | GeometryRefusal::SpanBelowFragment { .. },
                                            ..
                                        })
                                    ),
                                    "the fragment geometry refuses what attach refuses"
                                );
                            }
                            refused += u32::from(fit);
                            continue;
                        }
                    };
                    admitted += 1;
                    let span = volume.read_windows * chunk_len;
                    assert!(span <= read_len.min(max_transfer));
                    let geometry = fragment_geometry(&storage, read_len, max_transfer);
                    let geometry = match geometry {
                        Ok(geometry) => {
                            assert_eq!(geometry.span(), span, "one command span");
                            Some(geometry)
                        }
                        Err(GeometryError {
                            reason: GeometryRefusal::SpanBelowFragment { span: found },
                            ..
                        }) => {
                            assert_eq!(found, span);
                            None
                        }
                        Err(error) => panic!("{error:?} for a span attach admits"),
                    };
                    for metadata in [0, 1, 128] {
                        for body in (0..=body_cap as u32).step_by(997).chain([body_cap as u32]) {
                            let layout = storage.record.layout(metadata, body);
                            commands_tile(&volume, &layout, span);
                            if let Some(geometry) = &geometry {
                                fragments_meet_planned_commands(&volume, &layout, geometry);
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(
        admitted > 20 && refused > 0,
        "{admitted} admitted, {refused} refused for a read span below the header and one chunk"
    );
}

/// Plans `layout`'s commands as the volume does and checks their shape.
fn commands_tile(
    volume: &TestVolume<'_, '_>,
    layout: &super::super::record::RecordLayout,
    span: u32,
) {
    let chunk_len = layout.chunk_len();
    // The read ends at the record's last sector, as a locator ended at the record's length bounds it.
    let record_end = layout.record_len().next_multiple_of(SECTOR as u64);
    let windows = volume.read_windows;
    let first = Command::plan(chunk_len, None, 0, record_end, windows);
    assert_eq!(first.offset, 0);
    assert!(first.len <= span);
    assert!(
        u64::from(first.len) >= layout.header_bytes() as u64,
        "{layout:?}"
    );
    let mut next = first.chunks_end(layout);
    assert!(next > 0 || layout.chunk_count() == 0, "{layout:?}");
    let mut end = u64::from(first.len);
    while next < layout.chunk_count() {
        let command = Command::plan(chunk_len, Some(layout), next, record_end, windows);
        assert_eq!(command.offset, end, "contiguous, {layout:?}");
        assert_eq!(command.offset % u64::from(chunk_len), 0, "{layout:?}");
        assert!(command.len <= span);
        let last = command.offset + u64::from(command.len) == record_end;
        assert!(last || command.len.is_multiple_of(chunk_len), "{layout:?}");
        assert!(command.end > next, "every command carries a chunk");
        next = command.end;
        end = command.offset + u64::from(command.len);
    }
    assert_eq!(
        end, record_end,
        "the commands end at the record's end, {layout:?}"
    );
}

fn fragment_geometry(
    storage: &Storage<TestPlatform>,
    read_len: u32,
    max_transfer: u32,
) -> Result<FragmentGeometry, GeometryError> {
    let root = storage.root().expect("live storage");
    let largest = storage
        .record
        .layout(root.metadata_cap as u32, root.body_cap as u32);
    FragmentGeometry::new(GeometryInputs {
        record_chunk_len: storage.record.chunk_len(),
        response_buffer_len: read_len,
        device_max_transfer: max_transfer,
        header_max: u32::try_from(largest.header_bytes()).expect("a header fits u32"),
    })
}

/// The volume's command plan is the oracle for `geometry.buffers`: each fragment meets one or two planned commands, and `buffers` names exactly those.
fn fragments_meet_planned_commands(
    volume: &TestVolume<'_, '_>,
    layout: &super::super::record::RecordLayout,
    geometry: &FragmentGeometry,
) {
    let (chunk_len, windows) = (layout.chunk_len(), volume.read_windows);
    let record_end = layout.record_len().next_multiple_of(SECTOR as u64);
    let mut commands = vec![Command::plan(chunk_len, None, 0, record_end, windows)];
    let mut next = commands[0].chunks_end(layout);
    while next < layout.chunk_count() {
        let command = Command::plan(chunk_len, Some(layout), next, record_end, windows);
        next = command.end;
        commands.push(command);
    }
    let header = layout.header_bytes() as u64;
    let payload = layout.payload_len();
    for index in 0..FragmentGeometry::fragments(payload) as u32 {
        let fragment = FragmentGeometry::fragment(index, payload);
        let (start, end) = (header + fragment.start, header + fragment.end);
        let met: Vec<u64> = (0..commands.len() as u64)
            .filter(|&k| {
                let command = &commands[k as usize];
                command.offset < end && start < command.offset + u64::from(command.len)
            })
            .collect();
        assert!(
            (1..=BUFFERS_PER_READ as usize).contains(&met.len()),
            "{layout:?} fragment {index}: {met:?}"
        );
        assert_eq!(
            geometry.buffers(header as u32, fragment),
            met[0]..met[met.len() - 1] + 1,
            "{layout:?} fragment {index}"
        );
    }
}

/// At every chunk length a `u32` holds, the first command, a later planned command, the last command and the command submitted ahead of the first each hand off chunks `first..upto` as exactly those chunks' payload bytes inside their buffer, for payloads one below, at and one past the first window's `chunk_len - 116` payload bytes, a table entry's growth and the largest payload, with the fewest windows that hold the header and one more, ending at the record's last sector or its last unit.
///
/// The Kani proofs in `read.rs` cover every reachable read for the chunk-length bands whose proofs finish within a lane's budget; this test checks these boundary reads at every chunk length.
#[test]
fn every_chunk_length_hands_off_chunks_inside_their_command_buffers() {
    let max_payload = 2 * u64::from(u32::MAX);
    for units in 1..=u32::MAX / IO_UNIT as u32 {
        let chunk_len = units * IO_UNIT as u32;
        let config = RecordConfig { chunk_len }
            .validate()
            .expect("a unit multiple is valid");
        let c = u64::from(chunk_len);
        let single = c - 116;
        for payload in [1, single - 1, single, single + 1, c + 1, max_payload] {
            let layout = config.layout((payload / 2) as u32, (payload - payload / 2) as u32);
            let least = layout.header_bytes() as u64 / c + 1;
            let sector_end = layout.record_len().next_multiple_of(SECTOR as u64);
            let unit_end = layout.record_units() * IO_UNIT as u64;
            for (windows, end) in [
                (least, unit_end),
                (least, sector_end),
                (least + 1, unit_end),
            ] {
                if windows * c > u64::from(u32::MAX) {
                    continue;
                }
                hand_off_checks(chunk_len, &layout, windows as u32, end, payload);
            }
        }
    }
}

/// The payload bytes chunks `first..upto` cover and where they lie in a command buffer read from record byte `offset`, from the record format alone: the payload is record bytes `header..header + payload`, window `k` is record bytes `k * c..(k + 1) * c`, and chunk `i` covers the payload bytes in window `header / c + i`.
fn contract_span(
    c: u64,
    (header, payload): (u64, u64),
    offset: u64,
    (first, upto): (u32, u32),
) -> (std::ops::Range<u64>, std::ops::Range<usize>) {
    let window = header / c;
    let start = ((window + u64::from(first)) * c).max(header);
    let end = ((window + u64::from(upto)) * c).min(header + payload);
    (
        start - header..end - header,
        (start - offset) as usize..(end - offset) as usize,
    )
}

/// Header bytes of a `payload`-byte record under `c`-byte windows, from the format: 108 bytes of fixed fields and `ceil(payload / c) + 1` four-byte table entries.
fn format_header(payload: u64, c: u64) -> u64 {
    108 + 4 * (payload.div_ceil(c) + 1)
}

/// [`contract_span`] and [`format_header`] against values worked by hand for a three-window payload under 4096-byte windows. The 124-byte header of four table entries shifts the payload 124 bytes into window 0, so chunk 0 is payload bytes `0..4096 - 124`, chunk 1 is `4096 - 124..8192 - 124`, and chunk 3 holds the last 124 payload bytes, which lie in window 3. Each buffer range is the chunk's record bytes less the command's starting record byte.
#[test]
fn the_handoff_oracle_matches_a_hand_worked_record() {
    assert_eq!(format_header(3 * 4096, 4096), 124);
    let record = (124, 3 * 4096);
    assert_eq!(
        contract_span(4096, record, 4096, (1, 3)),
        (3972..12164, 0..8192)
    );
    assert_eq!(
        contract_span(4096, record, 8192, (3, 4)),
        (12164..12288, 4096..4220)
    );
    assert_eq!(contract_span(4096, record, 0, (0, 1)), (0..3972, 124..4096));
}

/// The checks `every_chunk_length_hands_off_chunks_inside_their_command_buffers` applies to one read of `layout` ending at `end`, in commands of `windows` windows: the layout's header length equals [`format_header`]'s, and each handoff's payload range and buffer range equal [`contract_span`]'s. Comparing both ranges to the format-derived span catches a handoff whose payload and buffer ranges shrink together.
fn hand_off_checks(
    chunk_len: u32,
    layout: &super::super::record::RecordLayout,
    windows: u32,
    end: u64,
    payload: u64,
) {
    let c = u64::from(chunk_len);
    let header = format_header(payload, c);
    assert_eq!(
        layout.header_bytes() as u64,
        header,
        "chunk {c}, payload {payload}"
    );
    let mut first = Command::plan(chunk_len, None, 0, end, windows);
    first.end = first.chunks_end(layout);
    let mut commands = vec![first];
    for next in [first.end, layout.chunk_count() - 1] {
        if next < layout.chunk_count() {
            commands.push(Command::plan(chunk_len, Some(layout), next, end, windows));
        }
    }
    if first.leaves(end) {
        let mut ahead = first.following(chunk_len, end, windows);
        ahead.first = first.end;
        ahead.end = ahead.chunks_end(layout);
        commands.push(ahead);
    }
    for command in commands {
        assert!(command.end <= layout.chunk_count());
        for upto in [command.first + 1, command.end] {
            if upto <= command.first || upto > command.end {
                continue;
            }
            let (range, bytes) = command.handed_off(layout, upto);
            assert!(
                bytes.start <= bytes.end && bytes.end <= command.len as usize,
                "chunk {c}, payload {payload}, end {end}, command {command:?}, upto {upto}"
            );
            assert_eq!(
                (range, bytes),
                contract_span(c, (header, payload), command.offset, (command.first, upto)),
                "chunk {c}, payload {payload}, end {end}, command {command:?}, upto {upto}"
            );
        }
    }
}

crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
    a_grant_refused_as_full_is_kept_for_the_tick,
    a_grant_while_reading_is_kept_and_spent_by_the_next_submit,
    a_loss_in_a_ticks_submit_ends_the_reads_visited_after_it_lost,
    a_lost_volume_ends_a_read_waiting_for_its_grant,
    a_read_drains_only_when_its_record_frees_not_at_its_done,
    a_release_right_after_the_proven_stop_frees_a_read_whose_submit_unwound,
    an_empty_payload_completes_with_its_verified_info_and_no_chunk,
    an_unwound_later_submit_keeps_its_read_undrained_until_the_proven_stop,
    each_later_command_waits_for_one_grant_and_a_kept_grant_admits_one,
    every_event_after_a_verified_header_carries_its_identity_and_lengths,
    every_header_failure_carries_no_info_and_exposes_no_byte,
);
