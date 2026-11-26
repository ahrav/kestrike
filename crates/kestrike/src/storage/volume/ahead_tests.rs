//! Reading ahead before the header verifies: for a record that spans several commands, a grant while the first command is outstanding submits the next command. Payload delivery waits for the header and follows command order, and a header mismatch or a cancel returns the command's buffer uninspected after its terminal.

use std::panic::{AssertUnwindSafe, catch_unwind};

use super::super::device::PoolKind;
use super::super::device::sim::Unwind;
use super::super::record::HeaderMismatch;
use super::lifecycle_tests::{dones, step};
use super::volume_tests::TestVolume;
use super::volume_tests::{
    CHUNK, SESSION, TICK, arena_with_read_len, attach, last_submitted, place, record,
    storage_reading_ahead,
};
use super::{ReadEvent, ReadOp, ReadStatus, TickConfig};
use crate::sim::round::turn_until;
use crate::storage::device::sim::SimControl;

/// Steps the read `op` to its `Done`, granting twice after every step, and returns its payload bytes, in order, and its status.
fn drive_granting(
    volume: &mut TestVolume<'_, '_>,
    control: &SimControl,
    op: ReadOp,
) -> (Vec<u8>, ReadStatus) {
    let mut bytes = Vec::new();
    let mut out = Vec::with_capacity(16);
    for _ in 0..64 {
        step(volume, control, 0, &mut out);
        for event in out.drain(..) {
            match event {
                ReadEvent::Chunk { range, chunk, .. } => {
                    assert_eq!(range.start, bytes.len() as u64, "in order");
                    bytes.extend_from_slice(chunk.bytes());
                }
                ReadEvent::Done { status, .. } => return (bytes, status),
            }
        }
        let _ = volume.grant_read(op);
        let _ = volume.grant_read(op);
    }
    panic!("no Done\n{}", control.describe());
}

#[test]
fn a_grant_before_the_header_verifies_submits_the_next_command_ahead() {
    let storage = storage_reading_ahead(2);
    let arena = arena_with_read_len(2 * CHUNK);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let placed = record(0, 0, 5 * CHUNK, SESSION, 1);
    place(&storage, &control, &placed);
    let op = volume.read_raw(&placed.read, u64::MAX).expect("admitted");
    let first = last_submitted(&control);
    control.hold(first);
    volume.grant_read(op).expect("live");
    let ahead = last_submitted(&control);
    assert_ne!(ahead, first, "a command ahead of the header");
    assert_eq!(volume.table_report().pending, 2);
    assert_eq!(volume.report().reads_ahead, 1);
    // The command ahead completes first; its bytes wait for the header and the first command's hand-off.
    let mut out = Vec::with_capacity(16);
    step(&mut volume, &control, 0, &mut out);
    assert!(out.is_empty(), "nothing is exposed before the header");
    control.release(first);
    let (bytes, status) = drive_granting(&mut volume, &control, op);
    assert_eq!(status, ReadStatus::Complete);
    assert_eq!(bytes, placed.payload);
}

#[test]
fn a_record_one_command_holds_takes_nothing_ahead() {
    let storage = storage_reading_ahead(2);
    let arena = arena_with_read_len(2 * CHUNK);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let placed = record(0, 0, CHUNK / 2, SESSION, 2);
    place(&storage, &control, &placed);
    let op = volume.read_raw(&placed.read, u64::MAX).expect("admitted");
    volume.grant_read(op).expect("live");
    assert_eq!(
        volume.table_report().pending,
        1,
        "the first command reads the extent"
    );
    let (bytes, status) = drive_granting(&mut volume, &control, op);
    assert_eq!(status, ReadStatus::Complete);
    assert_eq!(bytes, placed.payload);
    assert_eq!(volume.report().reads_ahead, 0);
}

#[test]
fn a_header_mismatch_with_a_command_ahead_exposes_nothing_and_drains_after_both_terminals() {
    let storage = storage_reading_ahead(2);
    let arena = arena_with_read_len(2 * CHUNK);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let stale = record(0, 0, 5 * CHUNK, SESSION + 1, 3);
    place(&storage, &control, &stale);
    let op = volume.read_raw(&stale.read, u64::MAX).expect("admitted");
    volume.grant_read(op).expect("live");
    let ahead = last_submitted(&control);
    control.hold(ahead);
    let mut out = Vec::with_capacity(16);
    turn_until(|| {
        step(&mut volume, &control, 0, &mut out);
        !out.is_empty()
    });
    assert!(
        out.iter()
            .all(|event| matches!(event, ReadEvent::Done { .. })),
        "no chunk"
    );
    let session = HeaderMismatch::Session {
        expected: SESSION,
        found: SESSION + 1,
    };
    assert_eq!(dones(&mut out), [(op, ReadStatus::HeaderMismatch(session))]);
    assert!(!volume.read_drained(op), "the command ahead is outstanding");
    control.release(ahead);
    for _ in 0..4 {
        step(&mut volume, &control, 0, &mut out);
    }
    assert!(out.is_empty(), "one Done and no chunk");
    assert!(volume.read_drained(op));
    assert_eq!(arena.report(PoolKind::ReadResponse).free, 2);
}

#[test]
fn a_header_mismatch_after_its_command_ahead_arrived_frees_the_read_and_both_buffers_at_its_done() {
    let storage = storage_reading_ahead(2);
    let arena = arena_with_read_len(2 * CHUNK);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let stale = record(0, 0, 5 * CHUNK, SESSION + 1, 5);
    place(&storage, &control, &stale);
    let op = volume.read_raw(&stale.read, u64::MAX).expect("admitted");
    let first = last_submitted(&control);
    control.hold(first);
    volume.grant_read(op).expect("live");
    assert_ne!(
        last_submitted(&control),
        first,
        "a command ahead of the header"
    );
    // The command ahead's terminal applies while the first command is held, so the read has nothing outstanding once the first command's terminal applies.
    let mut out = Vec::with_capacity(16);
    turn_until(|| {
        step(&mut volume, &control, 0, &mut out);
        volume.table_report().pending == 1
    });
    assert_eq!(
        volume.table_report().pending,
        1,
        "the command ahead's terminal applied"
    );
    assert!(out.is_empty(), "nothing is exposed before the header");
    control.release(first);
    turn_until(|| {
        step(&mut volume, &control, 0, &mut out);
        !out.is_empty()
    });
    assert!(
        out.iter()
            .all(|event| matches!(event, ReadEvent::Done { .. })),
        "no chunk"
    );
    let session = HeaderMismatch::Session {
        expected: SESSION,
        found: SESSION + 1,
    };
    assert_eq!(dones(&mut out), [(op, ReadStatus::HeaderMismatch(session))]);
    assert!(volume.read_drained(op), "the Done frees the read");
    assert_eq!(
        arena.report(PoolKind::ReadResponse).free,
        2,
        "the arrived command ahead's buffer returns with the first command's"
    );
}

#[test]
fn a_cancel_before_the_header_verifies_ends_once_after_both_terminals() {
    let storage = storage_reading_ahead(2);
    let arena = arena_with_read_len(2 * CHUNK);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let placed = record(0, 0, 5 * CHUNK, SESSION, 4);
    place(&storage, &control, &placed);
    let op = volume.read_raw(&placed.read, u64::MAX).expect("admitted");
    let first = last_submitted(&control);
    control.hold(first);
    volume.grant_read(op).expect("live");
    let ahead = last_submitted(&control);
    control.hold(ahead);
    volume.cancel_read(op).expect("live");
    let mut out = Vec::with_capacity(16);
    step(&mut volume, &control, 0, &mut out);
    assert_eq!(dones(&mut out), [(op, ReadStatus::Cancelled)]);
    assert_eq!(volume.report().quarantines, 2);
    control.release(ahead);
    step(&mut volume, &control, 0, &mut out);
    assert!(!volume.read_drained(op), "the first command is outstanding");
    control.release(first);
    for _ in 0..4 {
        step(&mut volume, &control, 0, &mut out);
    }
    assert!(out.is_empty(), "one Done");
    assert!(volume.read_drained(op));
    assert_eq!(arena.report(PoolKind::ReadResponse).free, 2);
}

#[test]
fn a_loss_while_verifying_with_a_command_ahead_exposes_nothing_and_ends_lost() {
    let storage = storage_reading_ahead(2);
    let arena = arena_with_read_len(2 * CHUNK);
    let tick = TickConfig {
        validate_bytes: 1000,
        ..TICK
    };
    let (mut volume, control) = attach(&storage, &arena, tick);
    let placed = record(0, 0, 5 * CHUNK, SESSION, 5);
    place(&storage, &control, &placed);
    let op = volume.read_raw(&placed.read, u64::MAX).expect("admitted");
    volume.grant_read(op).expect("live");
    let ahead = last_submitted(&control);
    control.hold(ahead);
    let mut out = Vec::with_capacity(16);
    step(&mut volume, &control, 0, &mut out);
    assert!(
        out.is_empty(),
        "the first command's bytes are mid-verification"
    );
    control.unwind_next(Some(Unwind::Pick));
    assert!(catch_unwind(AssertUnwindSafe(|| volume.poll_storage(0, &mut out))).is_err());
    control.unwind_next(None);
    assert!(volume.is_lost());
    for _ in 0..64 {
        step(&mut volume, &control, 0, &mut out);
    }
    let events: Vec<_> = out
        .drain(..)
        .map(|event| match event {
            ReadEvent::Chunk { range, .. } => Err(range),
            ReadEvent::Done { op, status, .. } => Ok((op, status)),
        })
        .collect();
    assert_eq!(
        events,
        [Ok((op, ReadStatus::Lost))],
        "no chunk after the loss"
    );
    assert!(!volume.read_drained(op), "the command ahead is outstanding");
    control.release(ahead);
    for _ in 0..4 {
        step(&mut volume, &control, 0, &mut out);
    }
    assert!(out.is_empty(), "one Done");
    assert!(volume.read_drained(op));
    assert_eq!(arena.report(PoolKind::ReadResponse).free, 2);
}

crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
    a_cancel_before_the_header_verifies_ends_once_after_both_terminals,
    a_grant_before_the_header_verifies_submits_the_next_command_ahead,
    a_header_mismatch_after_its_command_ahead_arrived_frees_the_read_and_both_buffers_at_its_done,
    a_header_mismatch_with_a_command_ahead_exposes_nothing_and_drains_after_both_terminals,
    a_loss_while_verifying_with_a_command_ahead_exposes_nothing_and_ends_lost,
    a_record_one_command_holds_takes_nothing_ahead,
);
