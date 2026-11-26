//! Reading ahead after the header verified: a read holds a second command once a grant asks for it, the second command's bytes wait for the current command's hand-off, chunks reach the caller in payload order, and a cancel or a deadline ends the read once with both commands quarantined until their terminals. A read that reads three commands ahead holds up to four, its commands ahead of an unverified first command take their chunks in order once the header verifies, terminals arriving newest first still deliver chunks in payload order, a cancel or a deadline quarantines all four, and a failed command ahead or a failed header ends the read once and frees its record only after every later terminal. A grant to a read whose submitted commands reach its end returns `Exhausted` and stays unkept.

use super::super::device::{BufferArena, CommandToken, DeviceStatus, PoolKind};
use super::super::test_platform::TestPlatform;
use super::lifecycle_tests::{dones, step};
use super::volume_tests::TestVolume;
use super::volume_tests::{
    CHUNK, Record, SESSION, TICK, arena_with_read_len, arena_with_reads, attach, last_submitted,
    place, queue_full, record, storage_reading_ahead, storage_reading_ahead_by,
};
use super::{Grant, ReadEvent, ReadOp, ReadStatus};
use crate::sim::round::{catch_up, turn_until};
use crate::storage::device::sim::{Fault, SimControl};

/// Ticks once at `now` and returns the chunk ranges delivered, in order, dropping each chunk.
fn chunk_ranges(
    volume: &mut TestVolume<'_, '_>,
    control: &SimControl,
    now: u64,
) -> Vec<std::ops::Range<u64>> {
    let mut out = Vec::with_capacity(16);
    step(volume, control, now, &mut out);
    out.drain(..)
        .filter_map(|event| match event {
            ReadEvent::Chunk { range, .. } => Some(range),
            ReadEvent::Done { .. } => None,
        })
        .collect()
}

/// Ticks twice at `now` and returns the chunk ranges delivered, in order.
/// Under a generated schedule a tick may poll before its device step, so
/// the ticks continue, bounded, until `want` ranges arrived.
fn two_ticks_of_ranges(
    volume: &mut TestVolume<'_, '_>,
    control: &SimControl,
    now: u64,
    want: usize,
) -> Vec<std::ops::Range<u64>> {
    let mut ranges = chunk_ranges(volume, control, now);
    ranges.extend(chunk_ranges(volume, control, now));
    catch_up(|| {
        ranges.len() >= want || {
            ranges.extend(chunk_ranges(volume, control, now));
            false
        }
    });
    ranges
}

/// Ticks at `now` once, and under a generated schedule until a chunk
/// arrives, bounded; returns the chunk ranges delivered, in order.
fn first_ranges(
    volume: &mut TestVolume<'_, '_>,
    control: &SimControl,
    now: u64,
) -> Vec<std::ops::Range<u64>> {
    let mut ranges = Vec::new();
    turn_until(|| {
        ranges.extend(chunk_ranges(volume, control, now));
        !ranges.is_empty()
    });
    ranges
}

/// A read of a five-chunk body over two-chunk response buffers, stepped to its first hand-off, with its second command submitted and held and its third submitted ahead; returns the read and both commands' tokens.
fn two_commands_outstanding(
    volume: &mut TestVolume<'_, '_>,
    control: &SimControl,
) -> (ReadOp, CommandToken, CommandToken) {
    let placed = record(0, 0, 5 * CHUNK, SESSION, 1);
    place(volume.storage(), control, &placed);
    let op = volume.read_raw(&placed.read, u64::MAX).expect("admitted");
    let first = first_ranges(volume, control, 0);
    assert_eq!(first.first().map(|range| range.start), Some(0));
    volume.grant_read(op).expect("live");
    let current = last_submitted(control);
    control.hold(current);
    volume.grant_read(op).expect("live");
    let ahead = last_submitted(control);
    assert_ne!(ahead, current);
    assert_eq!(volume.table_report().pending, 2, "a command ahead");
    (op, current, ahead)
}

#[test]
fn granted_reads_stream_two_commands_at_a_time_in_payload_order() {
    let storage = storage_reading_ahead(2);
    let arena = arena_with_read_len(2 * CHUNK);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let placed = record(0, 0, 5 * CHUNK, SESSION, 1);
    place(&storage, &control, &placed);
    let op = volume.read_raw(&placed.read, u64::MAX).expect("admitted");
    let (mut bytes, mut most) = (Vec::new(), 0);
    let mut out = Vec::with_capacity(16);
    let status = 'read: {
        for _ in 0..64 {
            step(&mut volume, &control, 0, &mut out);
            for event in out.drain(..) {
                match event {
                    ReadEvent::Chunk { range, chunk, .. } => {
                        assert_eq!(range.start, bytes.len() as u64, "in order");
                        bytes.extend_from_slice(chunk.bytes());
                    }
                    ReadEvent::Done { status, .. } => break 'read status,
                }
            }
            let _ = volume.grant_read(op);
            let _ = volume.grant_read(op);
            most = most.max(volume.table_report().pending);
        }
        panic!("no Done\n{}", control.describe());
    };
    assert_eq!(status, ReadStatus::Complete);
    assert_eq!(bytes, placed.payload);
    assert_eq!(most, 2, "two commands outstanding at once");
}

/// A grant whose command ahead the device queue refused as full keeps the grant in the waiting set, and the next tick with room submits that command ahead while the current command is still outstanding.
#[test]
fn a_tick_retries_a_command_ahead_the_queue_refused_as_full() {
    let storage = storage_reading_ahead(2);
    let arena = arena_with_read_len(2 * CHUNK);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let placed = record(0, 0, 5 * CHUNK, SESSION, 1);
    place(&storage, &control, &placed);
    let op = volume.read_raw(&placed.read, u64::MAX).expect("admitted");
    let current = last_submitted(&control);
    control.hold(current);
    control.refuse_next(queue_full());
    volume.grant_read(op).expect("live");
    assert_eq!(
        (volume.table_report().pending, volume.report().reads_ahead),
        (1, 0),
        "the queue refused the command ahead"
    );
    assert!(
        chunk_ranges(&mut volume, &control, 0).is_empty(),
        "the current command is still held"
    );
    assert_eq!(
        (volume.table_report().pending, volume.report().reads_ahead),
        (2, 1),
        "the tick submitted the command ahead before the current command's terminal"
    );
    control.release(current);
    let ranges = two_ticks_of_ranges(&mut volume, &control, 0, 2);
    assert_eq!(
        ranges.len(),
        2,
        "the current command's chunks, then the ones ahead"
    );
    assert_eq!(ranges[0].end, ranges[1].start, "in payload order");
}

#[test]
fn bytes_ahead_wait_for_the_current_command_to_hand_off() {
    let storage = storage_reading_ahead(2);
    let arena = arena_with_read_len(2 * CHUNK);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let (_, current, _) = two_commands_outstanding(&mut volume, &control);
    assert!(
        chunk_ranges(&mut volume, &control, 0).is_empty(),
        "the bytes ahead wait"
    );
    control.release(current);
    let ranges = two_ticks_of_ranges(&mut volume, &control, 0, 2);
    assert_eq!(
        ranges.len(),
        2,
        "the current command's chunks, then the ones ahead"
    );
    assert_eq!(ranges[0].end, ranges[1].start, "in payload order");
}

#[test]
fn a_cancel_with_two_commands_outstanding_ends_once_and_drains_after_both_terminals() {
    let storage = storage_reading_ahead(2);
    let arena = arena_with_read_len(2 * CHUNK);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let (op, current, ahead) = two_commands_outstanding(&mut volume, &control);
    control.hold(ahead);
    volume.cancel_read(op).expect("live");
    let mut out = Vec::with_capacity(16);
    step(&mut volume, &control, 0, &mut out);
    let mut done = Vec::new();
    record_events(&mut out, &mut done);
    assert_eq!(done, [Seen::Done(op, ReadStatus::Cancelled)]);
    assert_eq!(volume.report().quarantines, 2);
    assert!(!volume.read_drained(op), "two terminals outstanding");
    control.release(current);
    step(&mut volume, &control, 0, &mut out);
    assert!(!volume.read_drained(op), "one terminal outstanding");
    control.release(ahead);
    for _ in 0..4 {
        step(&mut volume, &control, 0, &mut out);
    }
    assert!(out.is_empty(), "one Done, and no event after it");
    assert!(volume.read_drained(op));
    assert_eq!(arena.report(PoolKind::ReadResponse).free, 2);
}

#[test]
fn a_deadline_with_two_commands_outstanding_ends_the_read_once() {
    let storage = storage_reading_ahead(2);
    let arena = arena_with_read_len(2 * CHUNK);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let placed = record(0, 0, 5 * CHUNK, SESSION, 1);
    place(&storage, &control, &placed);
    let op = volume.read_raw(&placed.read, 100).expect("admitted");
    first_ranges(&mut volume, &control, 0);
    volume.grant_read(op).expect("live");
    let current = last_submitted(&control);
    control.hold(current);
    volume.grant_read(op).expect("live");
    let ahead = last_submitted(&control);
    control.hold(ahead);
    let mut out = Vec::with_capacity(16);
    step(&mut volume, &control, 100, &mut out);
    let mut done = Vec::new();
    record_events(&mut out, &mut done);
    assert_eq!(done, [Seen::Done(op, ReadStatus::TimedOut)]);
    assert_eq!(volume.report().quarantines, 2);
    control.release(current);
    control.release(ahead);
    for _ in 0..4 {
        step(&mut volume, &control, 100, &mut out);
    }
    assert!(out.is_empty(), "one Done, and no event after it");
    assert!(volume.read_drained(op));
}

/// A read that may hold three commands ahead streams four commands at a time, the three ahead submitted while the first command's header is still unverified, and delivers every byte in payload order.
#[test]
fn a_read_three_commands_ahead_streams_four_at_a_time_from_its_first_command() {
    let storage = storage_reading_ahead_by(2, 3);
    let arena = arena_with_reads(5, 2 * CHUNK);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let placed = record(0, 0, 11 * CHUNK, SESSION, 1);
    place(&storage, &control, &placed);
    let op = volume.read_raw(&placed.read, u64::MAX).expect("admitted");
    let first = last_submitted(&control);
    control.hold(first);
    for _ in 0..3 {
        volume.grant_read(op).expect("live");
    }
    assert_eq!(
        (volume.table_report().pending, volume.report().reads_ahead),
        (4, 3),
        "three commands ahead of the unverified first one"
    );
    control.release(first);
    let (mut bytes, mut most) = (Vec::new(), 0);
    let mut out = Vec::with_capacity(16);
    let status = 'read: {
        for _ in 0..64 {
            step(&mut volume, &control, 0, &mut out);
            for event in out.drain(..) {
                match event {
                    ReadEvent::Chunk { range, chunk, .. } => {
                        assert_eq!(range.start, bytes.len() as u64, "in order");
                        bytes.extend_from_slice(chunk.bytes());
                    }
                    ReadEvent::Done { status, .. } => break 'read status,
                }
            }
            for _ in 0..4 {
                let _ = volume.grant_read(op);
            }
            most = most.max(volume.table_report().pending);
        }
        panic!("no Done\n{}", control.describe());
    };
    assert_eq!(status, ReadStatus::Complete);
    assert_eq!(bytes, placed.payload);
    assert!(most <= 4, "at most the current command and three ahead");
}

/// A read of an eleven-chunk body over two-chunk response buffers that reads three commands ahead, with its first command and three commands ahead submitted and held before the header verifies, under `deadline`; returns the read, the record and all four tokens, oldest first.
fn four_commands_held(
    volume: &mut TestVolume<'_, '_>,
    control: &SimControl,
    deadline: u64,
) -> (ReadOp, Record, Vec<CommandToken>) {
    let placed = record(0, 0, 11 * CHUNK, SESSION, 1);
    place(volume.storage(), control, &placed);
    let op = volume.read_raw(&placed.read, deadline).expect("admitted");
    let mut held = vec![last_submitted(control)];
    control.hold(held[0]);
    for _ in 0..3 {
        volume.grant_read(op).expect("live");
        let token = last_submitted(control);
        control.hold(token);
        held.push(token);
    }
    assert_eq!(volume.table_report().pending, 4);
    (op, placed, held)
}

/// One read event as the caller saw it: a chunk's payload range and bytes, or a Done's read and status.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    Chunk(std::ops::Range<u64>, Vec<u8>),
    Done(ReadOp, ReadStatus),
}

/// Moves every event of `out` onto `trace`, in delivery order, copying each chunk's bytes before dropping the chunk returns its buffer.
fn record_events(out: &mut Vec<ReadEvent<'_>>, trace: &mut Vec<Seen>) {
    trace.extend(out.drain(..).map(|event| match event {
        ReadEvent::Chunk { range, chunk, .. } => Seen::Chunk(range, chunk.bytes().to_vec()),
        ReadEvent::Done { op, status, .. } => Seen::Done(op, status),
    }));
}

/// Releases every token in `held` in order and steps once at `now` after each, then steps four more times and asserts the read drains only after the last terminal with every response buffer back; returns every event the drain delivered.
fn drain_after_every_terminal(
    volume: &mut TestVolume<'_, '_>,
    control: &SimControl,
    arena: &BufferArena<TestPlatform>,
    op: ReadOp,
    held: &[CommandToken],
    now: u64,
) -> Vec<Seen> {
    let (mut out, mut trace) = (Vec::with_capacity(16), Vec::new());
    for &token in held {
        assert!(!volume.read_drained(op), "a terminal outstanding");
        control.release(token);
        step(volume, control, now, &mut out);
        record_events(&mut out, &mut trace);
    }
    for _ in 0..4 {
        step(volume, control, now, &mut out);
        record_events(&mut out, &mut trace);
    }
    assert!(volume.read_drained(op));
    assert_eq!(arena.report(PoolKind::ReadResponse).free, 5);
    trace
}

/// Asserts `trace` is one chunk per range of `ranges`, in order, each carrying those bytes of `payload`, then one Done of read `op` and nothing after it; returns the Done's status.
fn prefix_then_done(
    trace: &[Seen],
    op: ReadOp,
    ranges: &[std::ops::Range<u64>],
    payload: &[u8],
) -> ReadStatus {
    let Some((&Seen::Done(done, status), chunks)) = trace.split_last() else {
        panic!("the trace ends with a Done: {trace:?}");
    };
    assert_eq!(done, op);
    let expected: Vec<Seen> = ranges
        .iter()
        .map(|range| {
            let bytes = payload[range.start as usize..range.end as usize].to_vec();
            Seen::Chunk(range.clone(), bytes)
        })
        .collect();
    assert_eq!(
        chunks, expected,
        "exactly the verified prefix, then one Done and no event after it"
    );
    status
}

/// A cancel of a read with three commands ahead ends it once, quarantines all four commands, and drains it only after the last terminal, returning every buffer.
#[test]
fn a_cancel_with_three_commands_ahead_drains_after_every_terminal() {
    let storage = storage_reading_ahead_by(2, 3);
    let arena = arena_with_reads(5, 2 * CHUNK);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let (op, _, held) = four_commands_held(&mut volume, &control, u64::MAX);
    volume.cancel_read(op).expect("live");
    let mut out = Vec::with_capacity(16);
    step(&mut volume, &control, 0, &mut out);
    let mut done = Vec::new();
    record_events(&mut out, &mut done);
    assert_eq!(done, [Seen::Done(op, ReadStatus::Cancelled)]);
    assert_eq!(volume.report().quarantines, 4);
    let trace = drain_after_every_terminal(&mut volume, &control, &arena, op, &held, 0);
    assert_eq!(trace, [], "one Done, and no event after it");
}

/// A deadline reached with three commands ahead ends the read once `TimedOut`, quarantines all four commands, and drains it only after the last terminal.
#[test]
fn a_deadline_with_three_commands_ahead_drains_after_every_terminal() {
    let storage = storage_reading_ahead_by(2, 3);
    let arena = arena_with_reads(5, 2 * CHUNK);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let (op, _, held) = four_commands_held(&mut volume, &control, 100);
    let mut out = Vec::with_capacity(16);
    step(&mut volume, &control, 100, &mut out);
    let mut done = Vec::new();
    record_events(&mut out, &mut done);
    assert_eq!(done, [Seen::Done(op, ReadStatus::TimedOut)]);
    assert_eq!(volume.report().quarantines, 4);
    let trace = drain_after_every_terminal(&mut volume, &control, &arena, op, &held, 100);
    assert_eq!(trace, [], "one Done, and no event after it");
}

/// Hands the payload bytes `chunk` at `range` to the caller, who holds `bytes` so far: the chunk starts where those bytes end.
fn hand_off(range: &std::ops::Range<u64>, chunk: &[u8], bytes: &mut Vec<u8>) {
    assert_eq!(range.start, bytes.len() as u64, "in order");
    bytes.extend_from_slice(chunk);
}

/// Commands ahead whose terminals arrive newest first still reach the caller in payload order, and the read completes with every byte.
#[test]
fn commands_ahead_finishing_newest_first_deliver_in_payload_order() {
    newest_first_terminals_deliver_in_payload_order(|_, _| {});
}

/// Holds a read's first command and three commands ahead, releases them newest first, runs `plant` on the read after the last release, and asserts that every chunk the volume delivers starts where the caller's bytes end and that the read completes with every byte.
fn newest_first_terminals_deliver_in_payload_order(plant: fn(&mut TestVolume<'_, '_>, ReadOp)) {
    let storage = storage_reading_ahead_by(2, 3);
    let arena = arena_with_reads(5, 2 * CHUNK);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let (op, placed, held) = four_commands_held(&mut volume, &control, u64::MAX);
    let (mut bytes, mut out) = (Vec::new(), Vec::with_capacity(16));
    let take = |out: &mut Vec<ReadEvent<'_>>, bytes: &mut Vec<u8>| {
        let mut status = None;
        for event in out.drain(..) {
            match event {
                ReadEvent::Chunk { range, chunk, .. } => {
                    hand_off(&range, chunk.bytes(), bytes);
                }
                ReadEvent::Done { status: done, .. } => status = Some(done),
            }
        }
        status
    };
    for &token in held.iter().rev() {
        control.release(token);
        step(&mut volume, &control, 0, &mut out);
        assert_eq!(
            take(&mut out, &mut bytes),
            None,
            "the first command still held"
        );
        if token != held[0] {
            assert!(bytes.is_empty(), "bytes ahead wait for the first command");
        }
    }
    plant(&mut volume, op);
    let status = 'read: {
        for _ in 0..64 {
            if let Some(status) = take(&mut out, &mut bytes) {
                break 'read status;
            }
            for _ in 0..4 {
                let _ = volume.grant_read(op);
            }
            step(&mut volume, &control, 0, &mut out);
        }
        panic!("no Done\n{}", control.describe());
    };
    assert_eq!(status, ReadStatus::Complete);
    assert_eq!(bytes, placed.payload);
}

/// Exchanges the read's two commands ahead, so the volume takes the newer one next.
fn take_the_newer_command_ahead_first(volume: &mut TestVolume<'_, '_>, op: ReadOp) {
    let (_, record) = volume.reads.slot_mut(op.slot).expect("the read is live");
    let mut ahead = record.ahead.iter_mut();
    let (older, newer) = (
        ahead.next().expect("a command ahead"),
        ahead.next().expect("a second command ahead"),
    );
    std::mem::swap(older, newer);
}

/// Planted defect: once the first command has handed off, the read's two remaining commands ahead trade places in its queue, so the volume takes the newer one next. Its chunk starts one command past the bytes the caller holds, and the `hand_off` check of `commands_ahead_finishing_newest_first_deliver_in_payload_order` fails. The plant acts after all four terminals arrived, so the failure comes from the queue's order alone.
#[test]
#[should_panic(expected = "in order\n  left: 48996\n right: 32612")]
fn negative_control_a_reader_that_takes_the_newer_command_ahead_first_delivers_out_of_order() {
    newest_first_terminals_deliver_in_payload_order(take_the_newer_command_ahead_first);
}

/// A command ahead that fails while later commands ahead are outstanding ends the read with one `Done` of `ReadStatus::DeviceError` after the chunks before it, and the read drains after the later commands' terminals. The eleven-window payload's header contains 108 fixed bytes and twelve four-byte table entries, leaving `2 * CHUNK - 156` payload bytes in the first command.
#[test]
fn a_failed_command_ahead_ends_the_read_and_drains_after_later_terminals() {
    let storage = storage_reading_ahead_by(2, 3);
    let arena = arena_with_reads(5, 2 * CHUNK);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let (op, placed, held) = four_commands_held(&mut volume, &control, u64::MAX);
    control.fault(held[1], Fault::Status(DeviceStatus::Kernel(-5)));
    let (mut out, mut trace) = (Vec::with_capacity(16), Vec::new());
    control.release(held[0]);
    control.release(held[1]);
    for _ in 0..4 {
        step(&mut volume, &control, 0, &mut out);
        record_events(&mut out, &mut trace);
    }
    let prefix = 2 * u64::from(CHUNK) - (108 + 4 * 12);
    assert_eq!(
        prefix_then_done(
            &trace,
            op,
            std::slice::from_ref(&(0..prefix)),
            &placed.payload
        ),
        ReadStatus::DeviceError,
        "the read ends with later commands outstanding"
    );
    let drained = drain_after_every_terminal(&mut volume, &control, &arena, op, &held[2..], 0);
    assert_eq!(drained, [], "no event after the Done");
}

/// A first command whose header fails verification ends the read once with three commands ahead outstanding; each ahead's buffer returns uninspected after its terminal. Through the drain the caller sees one Done and no chunk.
#[test]
fn a_header_failure_with_three_commands_ahead_drains_after_their_terminals() {
    let storage = storage_reading_ahead_by(2, 3);
    let arena = arena_with_reads(5, 2 * CHUNK);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let (op, _, held) = four_commands_held(&mut volume, &control, u64::MAX);
    control.fault(held[0], Fault::CorruptSuccess);
    control.release(held[0]);
    let (mut out, mut trace) = (Vec::with_capacity(16), Vec::new());
    turn_until(|| {
        step(&mut volume, &control, 0, &mut out);
        !out.is_empty()
    });
    record_events(&mut out, &mut trace);
    assert!(
        matches!(
            prefix_then_done(&trace, op, &[], &[]),
            ReadStatus::HeaderMismatch(_)
        ),
        "the header fails with three commands ahead outstanding"
    );
    let drained = drain_after_every_terminal(&mut volume, &control, &arena, op, &held[1..], 0);
    assert_eq!(drained, [], "no event after the Done");
}

#[test]
fn a_header_failure_after_a_command_ahead_arrived_returns_its_buffer_at_the_done() {
    let storage = storage_reading_ahead_by(2, 3);
    let arena = arena_with_reads(5, 2 * CHUNK);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let (op, _, held) = four_commands_held(&mut volume, &control, u64::MAX);
    let mut out = Vec::with_capacity(16);
    control.release(held[2]);
    turn_until(|| {
        step(&mut volume, &control, 0, &mut out);
        volume.table_report().pending == 3
    });
    assert_eq!(
        volume.table_report().pending,
        3,
        "the second command ahead's terminal applied"
    );
    assert!(out.is_empty(), "nothing is exposed before the header");
    control.fault(held[0], Fault::CorruptSuccess);
    control.release(held[0]);
    turn_until(|| {
        step(&mut volume, &control, 0, &mut out);
        !out.is_empty()
    });
    let mut trace = Vec::new();
    record_events(&mut out, &mut trace);
    assert!(
        matches!(
            prefix_then_done(&trace, op, &[], &[]),
            ReadStatus::HeaderMismatch(_)
        ),
        "the header fails and exposes no chunk"
    );
    assert!(
        !volume.read_drained(op),
        "two commands ahead are outstanding"
    );
    assert_eq!(
        arena.report(PoolKind::ReadResponse).free,
        3,
        "the Done returns the first command's buffer and the arrived command's"
    );
    let drained =
        drain_after_every_terminal(&mut volume, &control, &arena, op, &[held[1], held[3]], 0);
    assert_eq!(drained, [], "no event after the Done");
}

/// Whether the read `op` holds a kept grant.
fn kept(volume: &TestVolume<'_, '_>, op: ReadOp) -> bool {
    volume
        .reads
        .get(op.slot, op.generation)
        .is_some_and(|record| record.granted)
}

/// A read whose submitted commands reach its end answers each further grant `Exhausted` and keeps none of them, before and after its header verified, while the volume has read-ahead depth to spare; the read still completes with every byte.
#[test]
fn a_grant_past_a_reads_last_command_is_exhausted_and_unkept() {
    let storage = storage_reading_ahead_by(2, 3);
    let arena = arena_with_reads(5, 2 * CHUNK);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    // Header and three body chunks span four windows: two commands of two windows each.
    let placed = record(0, 0, 3 * CHUNK, SESSION, 1);
    place(&storage, &control, &placed);
    let op = volume.read_raw(&placed.read, u64::MAX).expect("admitted");
    let first = last_submitted(&control);
    control.hold(first);
    assert_eq!(volume.grant_read(op), Ok(Grant::Added), "the last command");
    let last = last_submitted(&control);
    assert_ne!(last, first);
    control.hold(last);
    assert_eq!(
        volume.grant_read(op),
        Ok(Grant::Exhausted),
        "before the header verified"
    );
    assert_eq!(volume.report().reads_ahead, 1);
    assert!(!kept(&volume, op));
    control.release(first);
    let mut bytes = Vec::new();
    let mut out = Vec::with_capacity(16);
    turn_until(|| {
        step(&mut volume, &control, 0, &mut out);
        for event in out.drain(..) {
            if let ReadEvent::Chunk { chunk, .. } = event {
                bytes.extend_from_slice(chunk.bytes());
            }
        }
        !bytes.is_empty()
    });
    assert!(!bytes.is_empty(), "the first command handed off");
    assert_eq!(
        volume.grant_read(op),
        Ok(Grant::Exhausted),
        "after the header verified"
    );
    assert!(!kept(&volume, op));
    control.release(last);
    let status = 'read: {
        for _ in 0..16 {
            step(&mut volume, &control, 0, &mut out);
            for event in out.drain(..) {
                match event {
                    ReadEvent::Chunk { range, chunk, .. } => {
                        assert_eq!(range.start, bytes.len() as u64, "in order");
                        bytes.extend_from_slice(chunk.bytes());
                    }
                    ReadEvent::Done { status, .. } => break 'read status,
                }
            }
        }
        panic!("no Done\n{}", control.describe());
    };
    assert_eq!(status, ReadStatus::Complete);
    assert_eq!(bytes, placed.payload);
    assert_eq!(volume.report().reads_ahead, 1);
}

crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
    a_cancel_with_three_commands_ahead_drains_after_every_terminal,
    a_cancel_with_two_commands_outstanding_ends_once_and_drains_after_both_terminals,
    a_deadline_with_three_commands_ahead_drains_after_every_terminal,
    a_deadline_with_two_commands_outstanding_ends_the_read_once,
    a_grant_past_a_reads_last_command_is_exhausted_and_unkept,
    a_header_failure_after_a_command_ahead_arrived_returns_its_buffer_at_the_done,
    a_header_failure_with_three_commands_ahead_drains_after_their_terminals,
    a_tick_retries_a_command_ahead_the_queue_refused_as_full,
    bytes_ahead_wait_for_the_current_command_to_hand_off,
    commands_ahead_finishing_newest_first_deliver_in_payload_order,
    granted_reads_stream_two_commands_at_a_time_in_payload_order,
);

/// A grant whose command ahead the device queue refused as full, and a tick that sweeps because a second read waiting for its grant reached its deadline in that tick.
/// Bound, from `grant_read`'s doc ("a read whose command ahead found no room still submits it before its current command's terminal once room frees"): the sweeping tick has room and submits the command ahead while the current command is still held.
#[test]
fn a_sweeping_tick_retries_a_command_ahead_the_queue_refused_as_full() {
    let storage = storage_reading_ahead(2);
    let arena = arena_with_read_len(2 * CHUNK);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let timing = record(100, 0, 5 * CHUNK, SESSION, 2);
    place(&storage, &control, &timing);
    let timed = volume.read_raw(&timing.read, 50).expect("admitted");
    assert_eq!(first_ranges(&mut volume, &control, 0).len(), 1);
    let placed = record(0, 0, 5 * CHUNK, SESSION, 1);
    place(&storage, &control, &placed);
    let op = volume.read_raw(&placed.read, u64::MAX).expect("admitted");
    let current = last_submitted(&control);
    control.hold(current);
    control.refuse_next(queue_full());
    volume.grant_read(op).expect("live");
    assert_eq!(
        (volume.table_report().pending, volume.report().reads_ahead),
        (1, 0),
        "premise: the queue refused the command ahead"
    );
    let mut out = Vec::with_capacity(16);
    step(&mut volume, &control, 50, &mut out);
    assert_eq!(
        dones(&mut out),
        [(timed, ReadStatus::TimedOut)],
        "premise: the tick swept for the waiting read's deadline"
    );
    assert_eq!(
        (volume.table_report().pending, volume.report().reads_ahead),
        (2, 1),
        "the sweeping tick submitted the command ahead before the current command's terminal"
    );
}

/// The scene of [`a_sweeping_tick_retries_a_command_ahead_the_queue_refused_as_full`] with the read whose command ahead the queue refused admitted first, both reads at deadline 50, and an output with room for one event: the tick ends the read waiting for its grant and its sweep stops, leaving the read whose command ahead waits in the waiting set.
/// Bound, from `poll_storage`'s doc ("an operation whose deadline is at or below it ends `TimedOut` before it verifies or submits"): the tick submits no command ahead for the expired read, and the next tick ends it `TimedOut`.
#[test]
fn a_sweep_stopped_for_output_room_submits_no_command_ahead_past_its_deadline() {
    let storage = storage_reading_ahead(2);
    let arena = arena_with_read_len(2 * CHUNK);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let placed = record(0, 0, 5 * CHUNK, SESSION, 1);
    place(&storage, &control, &placed);
    let op = volume.read_raw(&placed.read, 50).expect("admitted");
    let current = last_submitted(&control);
    control.hold(current);
    let timing = record(100, 0, 5 * CHUNK, SESSION, 2);
    place(&storage, &control, &timing);
    let timed = volume.read_raw(&timing.read, 50).expect("admitted");
    assert_eq!(first_ranges(&mut volume, &control, 0).len(), 1);
    control.refuse_next(queue_full());
    volume.grant_read(op).expect("live");
    assert_eq!(
        (volume.table_report().pending, volume.report().reads_ahead),
        (1, 0),
        "premise: the queue refused the command ahead"
    );
    let mut out = Vec::with_capacity(2);
    step(&mut volume, &control, 50, &mut out);
    assert_eq!(
        dones(&mut out),
        [(timed, ReadStatus::TimedOut)],
        "premise: the tick ended the read waiting for its grant and its sweep stopped"
    );
    assert_eq!(
        (volume.table_report().pending, volume.report().reads_ahead),
        (1, 0),
        "the tick submitted a command ahead for a read past its deadline"
    );
    let mut out = Vec::with_capacity(16);
    step(&mut volume, &control, 50, &mut out);
    assert_eq!(dones(&mut out), [(op, ReadStatus::TimedOut)]);
    assert_eq!(volume.report().reads_ahead, 0);
}

/// Two reads at deadline 50: the first admitted waits for its grant, the second holds a kept grant whose next command the device queue refused, so it waits in the waiting set with nothing outstanding. A tick at 50 with an output with room for one event ends the first and its sweep stops before the second.
/// Bound, from `poll_storage`'s doc ("an operation whose deadline is at or below it ends `TimedOut` before it verifies or submits"): the tick submits no command for the expired waiting read, and the next tick ends it `TimedOut`.
#[test]
fn a_sweep_stopped_for_output_room_submits_no_next_command_past_its_deadline() {
    let storage = storage_reading_ahead(2);
    let arena = arena_with_read_len(2 * CHUNK);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let timing = record(100, 0, 5 * CHUNK, SESSION, 2);
    place(&storage, &control, &timing);
    let timed = volume.read_raw(&timing.read, 50).expect("admitted");
    assert_eq!(first_ranges(&mut volume, &control, 0).len(), 1);
    let placed = record(0, 0, 5 * CHUNK, SESSION, 1);
    place(&storage, &control, &placed);
    let op = volume.read_raw(&placed.read, 50).expect("admitted");
    assert_eq!(first_ranges(&mut volume, &control, 0).len(), 1);
    control.refuse_next(queue_full());
    volume.grant_read(op).expect("live");
    let submitted = volume.report().reads_submitted;
    assert_eq!(
        volume.table_report().pending,
        0,
        "premise: the queue refused the next command, so nothing is outstanding"
    );
    let mut out = Vec::with_capacity(2);
    step(&mut volume, &control, 50, &mut out);
    assert_eq!(
        dones(&mut out),
        [(timed, ReadStatus::TimedOut)],
        "premise: the tick ended the read waiting for its grant and its sweep stopped"
    );
    assert_eq!(
        (
            volume.table_report().pending,
            volume.report().reads_submitted
        ),
        (0, submitted),
        "the tick submitted a command for a read past its deadline"
    );
    let mut out = Vec::with_capacity(16);
    step(&mut volume, &control, 50, &mut out);
    assert_eq!(dones(&mut out), [(op, ReadStatus::TimedOut)]);
}
