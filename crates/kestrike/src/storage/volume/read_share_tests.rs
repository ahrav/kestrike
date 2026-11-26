//! The read share: reads hold at most `read_commands` table slots concurrently, reads admitted past them wait under a kept grant for a slot, and the remaining slots stay available for writes.

use super::super::device::PoolKind;
use super::super::ledger::EngineBudget;
use super::lifecycle_tests::{dones, step};
use super::volume_tests::{
    CHUNK, DEPTH, SESSION, TICK, arena_with, attach, device, last_submitted, place, record,
    storage_shared, write, write_set,
};
use super::{AttachError, ReadStatus, TickReport, Volume};
use crate::sim::round::turn_until;
use crate::sim::round::{Act, Actor, round};

#[test]
fn reads_past_the_read_share_wait_and_each_submits_as_a_slot_frees() {
    let storage = storage_shared(3, 1);
    let arena = arena_with(3, 1);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let mut ops = Vec::new();
    for at in 0..3 {
        let placed = record(at * 10, 0, CHUNK, SESSION, at + 1);
        place(&storage, &control, &placed);
        ops.push(volume.read_raw(&placed.read, u64::MAX).expect("admitted"));
    }
    let report = volume.report();
    assert_eq!((report.reads_submitted, report.reads_waited), (1, 2));
    assert_eq!(volume.table_report().pending, 1);
    assert_eq!(arena.report(PoolKind::ReadResponse).free, 2);
    let mut out = Vec::with_capacity(16);
    let mut ended = Vec::new();
    for _ in 0..32 {
        step(&mut volume, &control, 0, &mut out);
        assert!(
            volume.table_report().pending <= 1,
            "one read command at a time"
        );
        ended.extend(dones(&mut out));
        if ended.len() == ops.len() {
            break;
        }
    }
    assert_eq!(ended.len(), 3);
    assert!(
        ended
            .iter()
            .all(|(_, status)| *status == ReadStatus::Complete)
    );
    assert_eq!(volume.report().reads_submitted, 3);
}

#[test]
fn a_waiting_read_ends_timed_out_at_its_deadline_without_a_command() {
    let storage = storage_shared(2, 1);
    let arena = arena_with(2, 1);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let first = record(0, 0, CHUNK, SESSION, 1);
    let second = record(10, 0, CHUNK, SESSION, 2);
    place(&storage, &control, &first);
    place(&storage, &control, &second);
    let held = volume.read_raw(&first.read, u64::MAX).expect("admitted");
    let token = last_submitted(&control);
    control.hold(token);
    let waiting = volume.read_raw(&second.read, 50).expect("admitted");
    let mut out = Vec::with_capacity(16);
    step(&mut volume, &control, 50, &mut out);
    assert_eq!(dones(&mut out), [(waiting, ReadStatus::TimedOut)]);
    assert_eq!(volume.report().reads_submitted, 1);
    assert_eq!(volume.table_report().pending, 1);
    control.release(token);
    let mut ended = Vec::new();
    for _ in 0..8 {
        step(&mut volume, &control, 50, &mut out);
        ended.extend(dones(&mut out));
    }
    assert_eq!(ended, [(held, ReadStatus::Complete)]);
}

#[test]
fn writes_keep_the_slots_outside_the_read_share() {
    let storage = storage_shared(4, 1);
    let arena = arena_with(4, 2);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let mut held = None;
    for at in 0..4 {
        let placed = record(at * 10, 0, CHUNK, SESSION, at + 1);
        place(&storage, &control, &placed);
        volume.read_raw(&placed.read, u64::MAX).expect("admitted");
        held.get_or_insert_with(|| {
            let token = last_submitted(&control);
            control.hold(token);
            token
        });
    }
    assert_eq!(volume.report().reads_waited, 3);
    let (_reservation, set) = write_set(&storage, &mut volume, 1);
    let buffer = arena.acquire(PoolKind::ReceiveWrite).expect("free");
    write(&mut volume, set, buffer, 0).expect("a write slot outside the read share");
    assert_eq!(volume.table_report().pending, 2);
    assert_eq!(volume.report().reads_submitted, 1);
}

#[test]
fn attach_admits_more_read_records_than_the_depth_with_a_share_below_it() {
    let refuse = |read_ops, read_commands| {
        let storage = storage_shared(read_ops, read_commands);
        let arena = arena_with(2, 1);
        let (disk, _control) = device(7);
        let mut budget = EngineBudget::new(1 << 24);
        Volume::attach(
            &storage,
            &arena,
            disk,
            crate::storage::portable::scripted::ScriptedClock::trusted(),
            crate::storage::ServingAuthority::fixture(),
            DEPTH,
            TICK,
            &mut budget,
        )
        .err()
        .map(|(error, _)| error)
    };
    assert_eq!(refuse(20, 6), None);
    assert_eq!(
        refuse(20, 7),
        Some(AttachError::MetadataCommandsOutOfRange {
            read_commands: 7,
            metadata_commands: 1,
            reservation_commands: 0,
            depth: DEPTH
        })
    );
    for read_commands in [0, u32::from(DEPTH)] {
        assert_eq!(
            refuse(20, read_commands),
            Some(AttachError::ReadCommandsOutOfRange {
                read_commands,
                depth: DEPTH
            })
        );
    }
}

/// A tick with the share full submits nothing, counts no refusal and does no
/// work however many reads wait; the tick after a slot frees submits waiting
/// reads up to the share, from the cursor, in slot order.
#[test]
fn ticks_with_a_full_share_skip_the_waiting_reads() {
    let storage = storage_shared(10, 2);
    let arena = arena_with(10, 1);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let mut tokens = Vec::new();
    for at in 0..10 {
        let placed = record(at * 10, 0, CHUNK, SESSION, at + 1);
        place(&storage, &control, &placed);
        volume.read_raw(&placed.read, u64::MAX).expect("admitted");
        if at < 2 {
            let token = last_submitted(&control);
            control.hold(token);
            tokens.push(token);
        }
    }
    let report = volume.report();
    assert_eq!((report.reads_submitted, report.reads_waited), (2, 8));
    assert_eq!((volume.ready.members(), volume.waiting.members()), (0, 8));
    let refused = report.reads_refused;
    let mut out = Vec::with_capacity(16);
    for _ in 0..16 {
        assert_eq!(volume.poll_storage(0, &mut out), TickReport::default());
    }
    assert_eq!(
        volume.report().reads_refused,
        refused,
        "no attempt without room"
    );
    assert_eq!(volume.report().reads_submitted, 2);
    control.release(tokens[0]);
    let mut tick = None;
    turn_until(|| {
        let mut step_disk = || control.tick(1);
        let mut poll = || tick = Some(volume.poll_storage(0, &mut out));
        round(&mut [
            Act::new(Actor::Disk(0), &mut step_disk),
            Act::new(Actor::Volume(0), &mut poll),
        ]);
        tick.is_some_and(|tick| tick.terminals > 0)
    });
    let tick = tick.expect("the round polled the volume");
    assert_eq!((tick.terminals, tick.submitted), (1, 1));
    assert_eq!(volume.report().reads_submitted, 3);
    assert_eq!(volume.waiting.members(), 7);
    assert_eq!(volume.table_report().pending, 2);
    assert_eq!(volume.report().reads_refused, refused);
}

#[test]
fn a_full_read_share_counts_waits_and_no_refusals() {
    let storage = storage_shared(3, 1);
    let arena = arena_with(3, 1);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    // The long read needs another command, whose grant waits while the short read occupies the read share.
    let long = record(0, 0, 4 * CHUNK, SESSION, 1);
    let short = record(40, 0, CHUNK, SESSION, 2);
    place(&storage, &control, &long);
    place(&storage, &control, &short);
    let op = volume.read_raw(&long.read, u64::MAX).expect("admitted");
    volume.read_raw(&short.read, u64::MAX).expect("admitted");
    let report = volume.report();
    assert_eq!(
        (
            report.reads_submitted,
            report.reads_waited,
            report.reads_refused
        ),
        (1, 1, 0),
        "a first command waiting for the share"
    );
    // The long read's terminal frees the share's slot, and the same tick submits the waiting short read into it.
    let mut out = Vec::with_capacity(16);
    turn_until(|| {
        step(&mut volume, &control, 0, &mut out);
        volume.report().reads_submitted > 1
    });
    assert_eq!(volume.report().reads_submitted, 2);
    volume.grant_read(op).expect("live");
    assert_eq!(volume.waiting.members(), 1, "the grant waits for the share");
    let report = volume.report();
    assert_eq!(
        (report.reads_submitted, report.reads_refused),
        (2, 0),
        "a later command waiting for the share"
    );
}

/// A cancelled waiting read leaves the waiting set with its `Done`, so the
/// slot that frees later goes to the next waiting read.
#[test]
fn a_cancelled_waiting_read_ends_and_submits_nothing() {
    let storage = storage_shared(3, 1);
    let arena = arena_with(3, 1);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let mut ops = Vec::new();
    for at in 0..3 {
        let placed = record(at * 10, 0, CHUNK, SESSION, at + 1);
        place(&storage, &control, &placed);
        ops.push(volume.read_raw(&placed.read, u64::MAX).expect("admitted"));
    }
    let token = last_submitted(&control);
    control.hold(token);
    volume.cancel_read(ops[1]).expect("live");
    assert_eq!((volume.ready.members(), volume.waiting.members()), (1, 1));
    let mut out = Vec::with_capacity(16);
    volume.poll_storage(0, &mut out);
    assert_eq!(dones(&mut out), [(ops[1], ReadStatus::Cancelled)]);
    assert!(volume.read_drained(ops[1]));
    control.release(token);
    let mut ended = Vec::new();
    for _ in 0..16 {
        step(&mut volume, &control, 0, &mut out);
        ended.extend(dones(&mut out));
        if ended.len() == 2 {
            break;
        }
    }
    assert_eq!(
        ended,
        [
            (ops[0], ReadStatus::Complete),
            (ops[2], ReadStatus::Complete)
        ]
    );
    assert_eq!(volume.report().reads_submitted, 2);
}

/// `close` ends a waiting read `Quiesced` without submitting it, and a
/// waiting read whose submit meets a gone device ends `Lost`, as a slot frees.
#[test]
fn close_and_loss_end_a_waiting_read_without_a_command() {
    for lose in [false, true] {
        let storage = storage_shared(2, 1);
        let arena = arena_with(2, 1);
        let (mut volume, control) = attach(&storage, &arena, TICK);
        let first = record(0, 0, CHUNK, SESSION, 1);
        let second = record(10, 0, CHUNK, SESSION, 2);
        place(&storage, &control, &first);
        place(&storage, &control, &second);
        let held = volume.read_raw(&first.read, u64::MAX).expect("admitted");
        let token = last_submitted(&control);
        control.hold(token);
        let waiting = volume.read_raw(&second.read, u64::MAX).expect("admitted");
        assert_eq!(volume.waiting.members(), 1);
        let mut out = Vec::with_capacity(16);
        if lose {
            control.set_gone();
            control.release(token);
            let mut ended = Vec::new();
            for _ in 0..8 {
                step(&mut volume, &control, 0, &mut out);
                ended.extend(dones(&mut out));
            }
            assert_eq!(
                ended,
                [(held, ReadStatus::Complete), (waiting, ReadStatus::Lost)]
            );
            assert!(volume.is_lost());
        } else {
            volume.close();
            assert_eq!((volume.ready.members(), volume.waiting.members()), (1, 0));
            volume.poll_storage(0, &mut out);
            assert_eq!(dones(&mut out), [(waiting, ReadStatus::Quiesced)]);
            assert!(!volume.read_drained(held));
        }
        assert_eq!(volume.waiting.members(), 0);
        assert_eq!(volume.report().reads_submitted, 1);
    }
}

crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
    a_cancelled_waiting_read_ends_and_submits_nothing,
    a_full_read_share_counts_waits_and_no_refusals,
    a_waiting_read_ends_timed_out_at_its_deadline_without_a_command,
    close_and_loss_end_a_waiting_read_without_a_command,
    reads_past_the_read_share_wait_and_each_submits_as_a_slot_frees,
    ticks_with_a_full_share_skip_the_waiting_reads,
);
