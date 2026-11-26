//! Every live read of a lost volume ends `Lost` within ceil(live / (room - 1)) calls with
//! room, a read that waits for its grant included.
//!
//! Each test holds three live reads on one volume. The first spans several commands: its first command's
//! chunk is handed off and it then waits for its grant with no command outstanding, outside the ready and
//! waiting sets, which is a premise the test asserts. The other two are short reads whose commands the device
//! holds. A fourth read's submit then meets the gone device, which loses the volume. From there calls with one
//! spare output slot alternate with calls with `room` spare slots, for room = 2 and room = live + 1. Each
//! call without room must report nothing and push nothing; every live read must deliver exactly one `Done`
//! with status `Lost` within the bound, counted in calls with room; and each ended read's record must drain.
//! The third test holds the short reads' commands on the device through the first call with room, in which
//! the read waiting for its grant must end `Lost` alone.
//!
//! The alternating calls follow `storage::volume::cursor_tests`, whose `blocked` and `roomy` are private.

use super::super::device::sim::SimControl;
use super::lifecycle_tests::dones;
use super::volume_tests::{
    CHUNK, SESSION, TICK, TestVolume, arena_with, attach, place, record, storage,
};
use super::{ReadEvent, ReadOp, ReadStatus, TickReport};

/// Live reads of each test.
const LIVE: usize = 3;

/// One device step, then a call whose output has one spare slot: it reports nothing and pushes nothing.
fn blocked(volume: &mut TestVolume<'_, '_>, control: &SimControl) {
    control.tick(8);
    let mut narrow = Vec::with_capacity(1);
    assert_eq!(volume.poll_storage(0, &mut narrow), TickReport::default());
    assert!(narrow.is_empty(), "a call without room pushes no event");
}

/// One device step, then a call whose output has `room` spare slots; returns the outcomes it delivered.
fn roomy(
    volume: &mut TestVolume<'_, '_>,
    control: &SimControl,
    room: usize,
) -> Vec<(ReadOp, ReadStatus)> {
    control.tick(8);
    let mut out = Vec::with_capacity(room);
    assert_eq!(out.capacity(), room);
    let _ = volume.poll_storage(0, &mut out);
    dones(&mut out)
}

/// `room` counts spare slots. When `held` is true, the device retains the short reads' commands through the
/// first call with spare slots.
fn lost_reads_end_within_the_bound(room: usize, held: bool) {
    let storage = storage(LIVE as u32 + 1);
    let arena = arena_with(LIVE as u32 + 1, 1);
    let (mut volume, control) = attach(&storage, &arena, TICK);

    // The read that waits for its grant: its record spans more than one command, so once the first command's
    // chunk is handed off the read holds no command and waits outside the ready and waiting sets.
    let spanning = record(0, 0, 4 * CHUNK, SESSION, 92);
    place(&storage, &control, &spanning);
    let waiting = volume.read_raw(&spanning.read, u64::MAX).expect("admitted");
    let mut handed_off = false;
    for _ in 0..4 {
        control.tick(8);
        let mut out = Vec::with_capacity(16);
        let _ = volume.poll_storage(0, &mut out);
        handed_off |= out
            .iter()
            .any(|event| matches!(event, ReadEvent::Chunk { .. }));
        assert!(
            out.iter()
                .all(|event| matches!(event, ReadEvent::Chunk { .. })),
            "premise: the spanning read has not ended"
        );
    }
    assert!(
        handed_off,
        "premise: the first command's chunk was handed off"
    );
    assert!(
        !volume.ready.any() && !volume.waiting.any(),
        "premise: the read waits for its grant outside the ready and waiting sets"
    );

    // Two short reads whose commands the device holds, then the submit that meets the gone device.
    let mut ops = vec![waiting];
    for at in 1..=LIVE as u64 {
        let placed = record(40 + at * 10, 0, 100, SESSION, 100 + at);
        place(&storage, &control, &placed);
        if at < LIVE as u64 {
            ops.push(volume.read_raw(&placed.read, u64::MAX).expect("admitted"));
        } else {
            control.set_gone();
            let _ = volume.read_raw(&placed.read, u64::MAX);
        }
    }
    assert!(volume.is_lost(), "premise: the submit met the gone device");
    assert_eq!(ops.len(), LIVE);
    let commands: Vec<_> = (control.held().iter())
        .map(|command| command.token)
        .collect();
    assert_eq!(
        commands.len(),
        LIVE - 1,
        "premise: the device holds one command of each short read and none of the waiting read"
    );

    let mut ended = Vec::new();
    if held {
        for &command in &commands {
            control.hold(command);
        }
        blocked(&mut volume, &control);
        ended.extend(roomy(&mut volume, &control, room));
        assert_eq!(
            ended,
            [(ops[0], ReadStatus::Lost)],
            "room {room}: the read waiting for its grant ends Lost alone while the device holds the other commands"
        );
        for &command in &commands {
            control.release(command);
        }
    }
    let live = LIVE - ended.len();
    let bound = live.div_ceil(room - 1);
    let mut calls = 0;
    while ended.len() < LIVE {
        calls += 1;
        assert!(
            calls <= bound,
            "room {room}: only {ended:?} ended Lost within {bound} calls with room"
        );
        blocked(&mut volume, &control);
        ended.extend(roomy(&mut volume, &control, room));
    }
    ended.sort_by_key(|(op, _)| op.slot);
    let expected: Vec<_> = ops.iter().map(|op| (*op, ReadStatus::Lost)).collect();
    assert_eq!(
        ended, expected,
        "room {room}: each live read ends Lost exactly once"
    );
    // Nothing is left to end: further calls deliver no second outcome.
    for _ in 0..2 {
        blocked(&mut volume, &control);
        assert_eq!(
            roomy(&mut volume, &control, room),
            [],
            "room {room}: a read ended twice"
        );
    }
    for op in ops {
        assert!(volume.read_drained(op), "room {room}: {op:?} did not drain");
    }
}

#[test]
fn every_live_read_of_a_lost_volume_ends_lost_within_the_bound_at_two_spare_slots() {
    lost_reads_end_within_the_bound(2, false);
}

#[test]
fn every_live_read_of_a_lost_volume_ends_lost_within_the_bound_at_live_plus_one_spare_slots() {
    lost_reads_end_within_the_bound(LIVE + 1, false);
}

#[test]
fn a_read_waiting_for_its_grant_ends_lost_while_the_device_holds_the_other_reads_commands() {
    for room in [2, LIVE + 1] {
        lost_reads_end_within_the_bound(room, true);
    }
}
