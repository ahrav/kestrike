//! The tick's slot cursor under intermittent output room: a call with fewer than two spare output slots leaves the cursor, so every ready read, and every waiting read once the share has room, is reached within `read_ops` calls that have room, whatever calls without room fall between them.
//!
//! Each bound test alternates a call whose output has one spare slot with a call whose output has a fixed number of spare slots, at least two, stepping the device before each call.
//! In the slot and waiting-read tests a call with exactly two spare slots serves one read, which pushes its `Chunk` and `Done`, so the cursor alone decides which read a call reaches.
//! With `plant`, the test advances the cursor after each call without room, which restores the rule under which such a call moved it.

use std::cell::Cell;
use std::rc::Rc;

use super::super::device::sim::{Event, SimControl};
use super::super::volume_fixture::open_stepping;
use super::gate_fixture::{arena, attach_reserving, bounds_of, limits, ticks};
use super::lifecycle_tests::dones;
use super::volume_tests::{
    CHUNK, Record, SESSION, TICK, TestVolume, arena_with, attach, last_submitted, place,
    queue_full, record, storage, storage_shared,
};
use super::{
    ReadEvent, ReadOp, ReadStatus, ServingAuthority, ServingClock, TickConfig, TickReport,
};

/// Spare output slots of a call without room.
const BLOCKED: usize = 1;

/// Spare output slots of a call with room: one read's `Chunk` and `Done` fill them.
const ROOMY: usize = 2;

/// Calls with room each alternating run makes, in multiples of `read_ops`.
const LAPS: usize = 4;

/// One device step, then a call whose output has one spare slot, which reports nothing and pushes nothing; with `plant`, the test then advances the cursor.
/// The checks read the cursor only after this call returns, so a cursor the call itself moved yields the same trace as the planted one.
fn blocked(volume: &mut TestVolume<'_, '_>, control: &SimControl, now: u64, plant: bool) {
    control.tick(8);
    let mut narrow = Vec::with_capacity(BLOCKED);
    assert_eq!(volume.poll_storage(now, &mut narrow), TickReport::default());
    assert!(narrow.is_empty(), "a call without room pushes no event");
    if plant {
        volume.cursor = (volume.cursor + 1) % volume.reads.len();
    }
}

/// One device step, then a call whose output has `room` spare slots; returns the call's report, the outcomes it delivered and the number of events it pushed.
fn roomy(
    volume: &mut TestVolume<'_, '_>,
    control: &SimControl,
    now: u64,
    room: usize,
) -> (TickReport, Vec<(ReadOp, ReadStatus)>, usize) {
    control.tick(8);
    let mut out = Vec::with_capacity(room);
    assert_eq!(out.capacity(), room);
    let report = volume.poll_storage(now, &mut out);
    let pushed = out.len();
    (report, dones(&mut out), pushed)
}

/// Header and payload bytes of `record`, which a tick folds to verify it.
fn folded(record: &Record) -> usize {
    record.layout.header_bytes() + record.layout.payload_len() as usize
}

/// Two short reads on a two-slot volume whose byte budget verifies one read per call, under alternating room.
/// Every read that completes is reissued at once and takes the slot it freed, so the slot a call reaches holds a read with arrived bytes ready to verify until it ends `TimedOut`.
/// A read whose deadline is `expired` ends `TimedOut` and is not reissued.
///
/// Bound: a call with room reaches the slot at its cursor first and advances the cursor by one, so with `n = read_ops` slots each slot is reached within `n` calls with room.
/// The check asserts, after each call with room, that every live slot delivered a `Done` within the last `n` such calls, counting from the first; the witness asserts that each such call that completes a read folded the whole budget, so one read took it.
fn alternate(plant: bool, expired: [bool; 2]) {
    const NOW: u64 = 10;
    let storage = storage(2);
    let arena = arena_with(4, 1);
    let records = [
        record(0, 0, 100, SESSION, 61),
        record(2, 0, 100, SESSION, 62),
    ];
    let budget = folded(&records[0]);
    assert_eq!(budget, folded(&records[1]));
    let tick = TickConfig {
        validate_bytes: budget,
        ..TICK
    };
    let (mut volume, control) = attach(&storage, &arena, tick);
    let deadlines = expired.map(|expired| if expired { NOW } else { u64::MAX });
    let mut live = [true; 2];
    for (at, record) in records.iter().enumerate() {
        place(&storage, &control, record);
        let op = volume
            .read_raw(&record.read, deadlines[at])
            .expect("admitted");
        assert_eq!(op.slot as usize, at);
    }
    let n = volume.reads.len() as usize;
    // The call with room that last delivered each slot's `Done`; zero before the first.
    let mut last = [0; 2];
    for call in 1..=LAPS * n {
        blocked(&mut volume, &control, NOW, plant);
        let (report, ended, pushed) = roomy(&mut volume, &control, NOW, ROOMY);
        let [(op, status)] = ended[..] else {
            panic!("call {call} ended {ended:?}");
        };
        let slot = op.slot as usize;
        last[slot] = call;
        if expired[slot] {
            assert_eq!(status, ReadStatus::TimedOut, "call {call}");
            live[slot] = false;
        } else {
            assert_eq!(status, ReadStatus::Complete, "call {call}");
            assert_eq!(pushed, ROOMY, "call {call}: the read's Chunk and Done");
            assert_eq!(
                report.validated_bytes, budget,
                "call {call}: the served read took the whole budget"
            );
            let again = volume
                .read_raw(&records[slot].read, u64::MAX)
                .expect("admitted");
            assert_eq!(again.slot, op.slot, "the reissue takes the freed slot");
        }
        for (slot, &at) in last.iter().enumerate() {
            assert!(
                !live[slot] || call - at < n,
                "slot {slot} starved: no Done in the {n} calls with room through call {call}"
            );
        }
    }
    assert_eq!(
        live,
        expired.map(|expired| !expired),
        "only the expired read ended"
    );
}

#[test]
fn alternating_output_room_serves_each_slot_within_read_ops_calls_with_room() {
    alternate(false, [false; 2]);
}

#[test]
fn a_read_past_its_deadline_ends_timed_out_within_read_ops_calls_with_room() {
    // The control's history, and one whose expired slot is reached on the second call with room, the edge of the bound.
    alternate(false, [true, false]);
    alternate(false, [false, true]);
}

#[test]
#[should_panic(expected = "slot 0 starved: no Done in the 2 calls with room through call 2")]
fn negative_control_a_cursor_moved_by_each_call_without_room_starves_slot_0() {
    alternate(true, [false; 2]);
}

#[test]
#[should_panic(expected = "slot 0 starved: no Done in the 2 calls with room through call 2")]
fn negative_control_a_cursor_moved_by_each_call_without_room_never_times_slot_0_out() {
    alternate(true, [true, false]);
}

/// Waiting slots in slot order from `cursor`, wrapping once.
fn waiting_from(volume: &TestVolume<'_, '_>, cursor: u32) -> Vec<u32> {
    let count = volume.reads.len();
    (0..count)
        .map(|offset| (cursor + offset) % count)
        .filter(|&slot| volume.waiting.next(slot, slot + 1).is_some())
        .collect()
}

/// Four short reads on a share of one table slot under alternating room: one read holds the slot, three wait, and each completed read is reissued into the slot it freed, where it waits.
///
/// Bound: each call with room applies the held read's terminal, which frees the share, delivers that read and then submits the first waiting read from the call's cursor; the cursor advances by one per such call, so a read that began waiting after call `c` is submitted by call `c + n`, `n = read_ops`.
/// The check asserts that each call submits exactly the first waiting read from its cursor and that no read waits through `n` calls with room.
fn waiting_reads(plant: bool) {
    let storage = storage_shared(4, 1);
    let arena = arena_with(4, 1);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let records: Vec<Record> = (0..4)
        .map(|at| record(at * 10, 0, 100, SESSION, 70 + at))
        .collect();
    for (at, record) in records.iter().enumerate() {
        place(&storage, &control, record);
        let op = volume.read_raw(&record.read, u64::MAX).expect("admitted");
        assert_eq!(op.slot as usize, at);
    }
    let n = volume.reads.len() as usize;
    assert_eq!(waiting_from(&volume, 0), [1, 2, 3]);
    // The call with room after which each slot's read began waiting; zero before the first.
    let mut since = [0; 4];
    for call in 1..=LAPS * n {
        blocked(&mut volume, &control, 0, plant);
        let cursor = volume.cursor;
        let before = waiting_from(&volume, cursor);
        let (report, ended, _) = roomy(&mut volume, &control, 0, ROOMY);
        let after = waiting_from(&volume, cursor);
        let submitted: Vec<u32> = before
            .iter()
            .copied()
            .filter(|slot| !after.contains(slot))
            .collect();
        assert_eq!(report.submitted, 1, "call {call}: the freed share slot");
        assert_eq!(
            submitted,
            before[..1],
            "call {call} from cursor {cursor} submitted the first waiting read"
        );
        let [(op, ReadStatus::Complete)] = ended[..] else {
            panic!("call {call} ended {ended:?}");
        };
        let again = volume
            .read_raw(&records[op.slot as usize].read, u64::MAX)
            .expect("admitted");
        assert_eq!(again.slot, op.slot, "the reissue takes the freed slot");
        since[op.slot as usize] = call;
        for slot in waiting_from(&volume, 0) {
            assert!(
                call - since[slot as usize] < n,
                "waiting slot {slot} starved: not submitted in the {n} calls with room through call {call}"
            );
        }
    }
}

#[test]
fn a_waiting_read_submits_within_read_ops_calls_with_room_in_slot_order_from_the_cursor() {
    waiting_reads(false);
}

#[test]
#[should_panic(expected = "waiting slot 2 starved: not submitted in the 4 calls with room")]
fn negative_control_a_cursor_moved_by_each_call_without_room_starves_a_waiting_read() {
    waiting_reads(true);
}

/// With room for two submits, a waiting submit the device queue refuses as full ends the call's waiting submits with both reads still waiting; the next call submits both.
#[test]
fn a_waiting_submit_refused_as_full_ends_the_call_s_waiting_submits() {
    let storage = storage_shared(4, 2);
    let arena = arena_with(4, 1);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let mut held = Vec::new();
    for at in 0..4 {
        let placed = record(at * 10, 0, 100, SESSION, 80 + at);
        place(&storage, &control, &placed);
        volume.read_raw(&placed.read, u64::MAX).expect("admitted");
        if at < 2 {
            let token = last_submitted(&control);
            control.hold(token);
            held.push(token);
        }
    }
    assert_eq!(waiting_from(&volume, 0), [2, 3]);
    let refused = |control: &SimControl| {
        control
            .events()
            .iter()
            .filter(|event| matches!(event, Event::Refused { .. }))
            .count()
    };
    for token in held {
        control.release(token);
    }
    control.tick(8);
    control.refuse_next(queue_full());
    let before = refused(&control);
    let mut out = Vec::with_capacity(8);
    let report = volume.poll_storage(0, &mut out);
    assert_eq!(dones(&mut out).len(), 2, "both held reads complete");
    assert_eq!((report.terminals, report.submitted), (2, 0));
    assert_eq!(refused(&control) - before, 1, "one attempt, then none");
    assert_eq!(waiting_from(&volume, 0), [2, 3]);
    let report = volume.poll_storage(0, &mut out);
    assert_eq!(report.submitted, 2);
    assert!(waiting_from(&volume, 0).is_empty());
}

/// A call without output room leaves the cursor, the terminal and the read, after a proven stop too; a call with room and nothing to do leaves the cursor; the call after a proven stop with a live read serves it and advances the cursor, and later calls after the stop, with no live read, leave it.
#[test]
fn the_cursor_moves_only_on_a_call_that_serves() {
    use super::super::device::sim::QuiesceMode;
    let storage = storage(2);
    let arena = arena_with(4, 1);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let ready = record(10, 0, 100, SESSION, 91);
    place(&storage, &control, &ready);
    let first = volume.read_raw(&ready.read, u64::MAX).expect("admitted");
    for _ in 0..4 {
        blocked(&mut volume, &control, 0, false);
        assert_eq!(volume.cursor, 0, "a call without room keeps the cursor");
        assert_eq!(
            volume.table_report().pending,
            1,
            "the terminal stays with the table"
        );
    }
    let (_, ended, _) = roomy(&mut volume, &control, 0, ROOMY);
    assert_eq!(ended, [(first, ReadStatus::Complete)]);
    assert_eq!(volume.cursor, 1, "the call that served advanced the cursor");
    let placed = record(0, 0, CHUNK, SESSION, 90);
    place(&storage, &control, &placed);
    let op = volume.read_raw(&placed.read, u64::MAX).expect("admitted");
    control.hold(last_submitted(&control));
    let mut out = Vec::with_capacity(8);
    for _ in 0..4 {
        control.tick(8);
        assert_eq!(volume.poll_storage(0, &mut out), TickReport::default());
        assert_eq!(volume.cursor, 1, "a held read leaves nothing to do");
    }
    control.set_quiesce(QuiesceMode::Reset);
    let mut ended = Vec::new();
    let mut blocked_after_stop = false;
    for _ in 0..4 {
        volume.close();
        let cursor = volume.cursor;
        blocked(&mut volume, &control, 0, false);
        assert_eq!(
            volume.cursor, cursor,
            "a call without room keeps the cursor"
        );
        blocked_after_stop |= volume.quiesced && ended.is_empty();
        volume.poll_storage(0, &mut out);
        let delivered = dones(&mut out);
        if !delivered.is_empty() {
            assert!(
                volume.quiesced,
                "the delivering call follows the proven stop"
            );
            assert_eq!(volume.cursor, (cursor + 1) % volume.reads.len());
        }
        ended.extend(delivered);
    }
    assert_eq!(ended, [(op, ReadStatus::Quiesced)]);
    assert!(
        blocked_after_stop,
        "a call without room ran after the proven stop with the read live"
    );
    let cursor = volume.cursor;
    for _ in 0..2 {
        assert_eq!(volume.poll_storage(0, &mut out), TickReport::default());
        assert!(out.is_empty());
        assert_eq!(
            volume.cursor, cursor,
            "a call after the proven stop with no live read keeps the cursor"
        );
    }
}

/// A lost volume under alternating room ends every live read `Lost`.
///
/// Bound: each call with `room` spare slots visits the live reads in slot order and ends one per spare slot past the first, so `live` reads end within `ceil(live / (room - 1))` calls with room, `live` calls at two spare slots; with `room = live + 1` one call ends them all.
/// The scan starts at the cursor and visits every live record whatever the cursor's value, so this bound holds under either cursor rule.
#[test]
fn a_lost_volume_ends_every_live_read_within_its_bound_under_alternating_room() {
    const LIVE: usize = 3;
    for room in [ROOMY, LIVE + 1] {
        let storage = storage(LIVE as u32 + 1);
        let arena = arena_with(LIVE as u32 + 1, 1);
        let (mut volume, control) = attach(&storage, &arena, TICK);
        let mut ops = Vec::new();
        for at in 0..=LIVE as u64 {
            let placed = record(at * 10, 0, 100, SESSION, 100 + at);
            place(&storage, &control, &placed);
            if at < LIVE as u64 {
                ops.push(volume.read_raw(&placed.read, u64::MAX).expect("admitted"));
            } else {
                control.set_gone();
                let _ = volume.read_raw(&placed.read, u64::MAX);
            }
        }
        assert!(volume.is_lost(), "the submit met the gone device");
        let bound = LIVE.div_ceil(room - 1);
        let mut ended = Vec::new();
        let mut calls = 0;
        while ended.len() < LIVE {
            calls += 1;
            assert!(calls <= bound, "room {room}: {ended:?} after {bound} calls");
            blocked(&mut volume, &control, 0, false);
            ended.extend(roomy(&mut volume, &control, 0, room).1);
        }
        ended.sort_by_key(|(op, _)| op.slot);
        let expected: Vec<_> = ops.iter().map(|op| (*op, ReadStatus::Lost)).collect();
        assert_eq!(ended, expected, "room {room}");
    }
}

/// A serving clock the test sets; `None` is a clock fault.
struct Clock(Rc<Cell<Option<u64>>>);

impl ServingClock for Clock {
    fn now_us(&self) -> Option<u64> {
        self.0.get()
    }
}

/// Two reads in slots 0 and 1 of an open volume over a reservation-capable driver, each with its command held at the device, so both reads await their terminals.
/// With `report_due`, one deadline sample then reads a time past the Report period and every later reading of the serving clock is a fault, so each call defers the periodic Report and it stays due.
/// `idle` calls with room follow; each returns an empty report, leaves the output empty and leaves the registry's command log at its length.
/// The device then releases both commands and a call with exactly two spare output slots ends one read, the one in the slot at the cursor.
/// Returns that read and the two reads in slot order.
fn first_ended(report_due: bool, idle: usize) -> (ReadOp, [ReadOp; 2]) {
    let storage = storage(2);
    let arena = arena();
    let (mut volume, control, registry) =
        attach_reserving(&storage, &arena, ServingAuthority::fixture());
    let time = Rc::new(Cell::new(Some(0)));
    volume.set_serving_clock(Box::new(Clock(Rc::clone(&time))));
    open_stepping(
        &mut volume,
        |rounds| rounds < 64,
        |volume| ticks(volume, &control, 1),
    );

    let mut ops = Vec::new();
    let mut held = Vec::new();
    for (start, seed) in [(0, 90), (10, 91)] {
        let placed = record(start, 0, CHUNK, SESSION, seed);
        place(&storage, &control, &placed);
        ops.push(volume.read_raw(&placed.read, u64::MAX).expect("admitted"));
        let token = last_submitted(&control);
        control.hold(token);
        held.push(token);
    }
    assert_eq!([ops[0].slot, ops[1].slot], [0, 1]);
    let mut out = Vec::with_capacity(16);
    for _ in 0..4 {
        control.tick(8);
        assert_eq!(volume.poll_storage(0, &mut out), TickReport::default());
        assert!(out.is_empty(), "held reads leave nothing to do");
    }

    let reports = registry.borrow().log.len();
    if report_due {
        time.set(Some(bounds_of(limits()).report_period() + 1));
        volume.authority_deadlines();
        time.set(None);
    }
    for call in 0..idle {
        control.tick(8);
        assert_eq!(
            volume.poll_storage(0, &mut out),
            TickReport::default(),
            "call {call} has room and nothing to do"
        );
        assert!(out.is_empty(), "call {call} pushed nothing");
        assert_eq!(
            registry.borrow().log.len(),
            reports,
            "call {call} submitted no Report"
        );
        assert_eq!(
            volume.authority_report_due(),
            report_due,
            "premise: after call {call} a Report is due only where the clock defers it"
        );
    }

    for token in held {
        control.release(token);
    }
    control.tick(64);
    let mut two = Vec::with_capacity(2);
    assert_eq!(two.capacity(), 2);
    let _ = volume.poll_storage(0, &mut two);
    let ended = dones(&mut two);
    let (first, _) = ended.first().expect("the serving call ends one read");
    (*first, [ops[0], ops[1]])
}

/// Before the periodic Report falls due, a call with room and nothing to do leaves the cursor at slot 0, so the serving call that follows up to three of them ends the read in slot 0.
#[test]
fn idle_calls_with_no_report_due_leave_the_cursor() {
    for idle in [0, 1, 2, 3] {
        let (first, ops) = first_ended(false, idle);
        assert_eq!(first, ops[0], "after {idle} idle calls");
    }
}

/// A call that defers a due periodic Report has room and nothing to do, so it leaves the cursor at slot 0, and the serving call that follows up to three of them ends the read in slot 0.
#[test]
fn idle_calls_with_a_deferred_report_due_leave_the_cursor() {
    for idle in [0, 1, 2, 3] {
        let (first, ops) = first_ended(true, idle);
        assert_eq!(
            first, ops[0],
            "after {idle} calls with room and nothing to do, the serving call starts at the cursor's slot"
        );
    }
}

/// A periodic Report whose submit meets a gone device loses the volume on a call whose only work is that Report.
/// The loss leaves a sweep due, so the same call serves: it ends the read waiting for its grant `Lost` and advances the cursor.
#[test]
fn a_report_submit_that_loses_the_volume_serves_the_sweep_in_the_same_call() {
    use super::super::device::RefusalReason;
    let storage = storage(2);
    let arena = arena();
    let (mut volume, control, registry) =
        attach_reserving(&storage, &arena, ServingAuthority::fixture());
    let time = Rc::new(Cell::new(Some(0)));
    volume.set_serving_clock(Box::new(Clock(Rc::clone(&time))));
    open_stepping(
        &mut volume,
        |rounds| rounds < 64,
        |volume| ticks(volume, &control, 1),
    );
    // The record spans more than one command, so once the first command's chunks hand off the read waits for a grant, outside the ready and waiting sets.
    let placed = record(0, 0, 4 * CHUNK, SESSION, 92);
    place(&storage, &control, &placed);
    let op = volume.read_raw(&placed.read, u64::MAX).expect("admitted");
    let mut out = Vec::with_capacity(16);
    control.tick(8);
    let _ = volume.poll_storage(0, &mut out);
    assert!(
        matches!(out[..], [ReadEvent::Chunk { .. }]),
        "the first command's chunks handed off"
    );
    control.tick(8);
    assert_eq!(
        volume.poll_storage(0, &mut out),
        TickReport::default(),
        "premise: a read waiting for its grant leaves nothing to do"
    );
    assert!(
        !volume.ready.any() && !volume.waiting.any(),
        "premise: the read waits outside the ready and waiting sets"
    );
    let cursor = volume.cursor;
    registry.borrow_mut().refuse = Some(RefusalReason::DeviceGone);
    time.set(Some(bounds_of(limits()).report_period() + 1));
    let mut ended = Vec::with_capacity(16);
    let _ = volume.poll_storage(0, &mut ended);
    assert!(volume.is_lost(), "the refused Report lost the volume");
    assert_eq!(
        dones(&mut ended),
        [(op, ReadStatus::Lost)],
        "the call that lost the volume swept its live read"
    );
    assert_eq!(
        volume.cursor,
        (cursor + 1) % volume.reads.len(),
        "the call that served advanced the cursor"
    );
}

/// Holding the live read's device command leaves metadata submission as the only possible work; with `expired`, an expired serving window blocks that submission.
fn calls_beside_a_staged_unit(expired: bool, calls: usize) -> Vec<(TickReport, u32)> {
    use super::super::checkpoint::PossiblyNamed;
    let storage = storage(2);
    let arena = arena_with(4, 1);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let placed = record(0, 0, CHUNK, SESSION, 93);
    place(&storage, &control, &placed);
    let op = volume.read_raw(&placed.read, u64::MAX).expect("admitted");
    assert_eq!(op.slot, 0);
    control.hold(last_submitted(&control));
    let possible = PossiblyNamed::new(
        (crate::net::ownership::Shard::new(7).unwrap(), 2),
        super::placement_tests::test_layout(),
        None,
    );
    volume.stage_unit_read(&possible, (0, 0)).expect("staged");
    if expired {
        volume.authority_event(crate::failover::serving::Event::Expire { now: 0 });
    }
    let count = volume.reads.len();
    let mut out = Vec::with_capacity(16);
    (0..calls)
        .map(|call| {
            assert_eq!(
                volume.metadata_ready(),
                expired || call == 0,
                "premise: before call {call} the command is staged exactly when no call has run or the expired window blocks its submit"
            );
            let cursor = volume.cursor;
            control.tick(8);
            let report = volume.poll_storage(0, &mut out);
            assert!(out.is_empty(), "call {call} pushed nothing");
            let moved = (volume.cursor + count - cursor) % count;
            (report, moved)
        })
        .collect()
}

/// Leaving the cursor unchanged during idle polls preserves each read's turn while the serving window is expired.
#[test]
fn idle_calls_with_a_metadata_command_that_stays_staged_leave_the_cursor() {
    assert_eq!(
        calls_beside_a_staged_unit(true, 4),
        [(TickReport::default(), 0); 4]
    );
}

#[test]
fn the_calls_that_submit_a_metadata_command_and_take_its_terminal_each_advance_the_cursor() {
    let submit = TickReport {
        submitted: 1,
        ..TickReport::default()
    };
    let terminal = TickReport {
        terminals: 1,
        ..TickReport::default()
    };
    assert_eq!(
        calls_beside_a_staged_unit(false, 2),
        [(submit, 1), (terminal, 1)]
    );
}
