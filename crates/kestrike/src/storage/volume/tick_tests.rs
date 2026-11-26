//! A read's next command and its command ahead when the submit is refused for good: a command ahead refused `DeviceGone` loses the volume, ends the attempt and keeps the read's grant for its next command; a read whose later command is granted after the serving window expired, on a volume that stays open, ends `Quiesced` with no later byte.

use std::cell::Cell;
use std::rc::Rc;

use super::super::device::{Admission, PoolKind, RefusalReason, SubmitRefusal};
use super::authority_tests::Clock;
use super::lifecycle_tests::dones;
use super::volume_tests::{
    CHUNK, SESSION, TICK, TestVolume, arena, arena_with_read_len, attach, last_submitted, place,
    record, storage, storage_reading_ahead,
};
use super::{Grant, ReadEvent, ReadOp, ReadStatus};
use crate::failover::serving::Event;

/// Whether the read `op` holds a kept grant, or `None` once its record is free.
fn kept(volume: &TestVolume<'_, '_>, op: ReadOp) -> Option<bool> {
    volume
        .reads
        .get(op.slot, op.generation)
        .map(|record| record.granted)
}

fn device_gone() -> SubmitRefusal {
    SubmitRefusal {
        reason: RefusalReason::DeviceGone,
        code: None,
    }
}

/// A read of a five-chunk body over two-chunk response buffers on a volume that reads one command ahead, its
/// current command held at the device, is granted while the device refuses the next submit `DeviceGone`. The
/// refusal loses the volume and leaves no command ahead, and the read keeps the grant. After the current command's
/// terminal, a tick ends the read `Lost`.
#[test]
fn a_command_ahead_refused_as_device_gone_loses_the_volume_and_keeps_the_grant() {
    use super::lifecycle_tests::step;
    let storage = storage_reading_ahead(2);
    let arena = arena_with_read_len(2 * CHUNK);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let placed = record(0, 0, 5 * CHUNK, SESSION, 1);
    place(&storage, &control, &placed);
    let op = volume.read_raw(&placed.read, u64::MAX).expect("admitted");
    let current = last_submitted(&control);
    control.hold(current);
    assert_eq!(kept(&volume, op), Some(false), "no grant yet");
    assert_eq!(
        arena.report(PoolKind::ReadResponse).free,
        1,
        "one free response buffer for the command ahead"
    );
    assert!(volume.can_read_ahead(op.slot) && !volume.is_lost());

    control.refuse_next(device_gone());
    assert_eq!(volume.grant_read(op), Ok(Grant::Added));
    assert!(volume.is_lost(), "DeviceGone loses the volume");
    assert_eq!(
        (volume.table_report().pending, volume.report().reads_ahead),
        (1, 0),
        "the device refused the command ahead"
    );
    assert_eq!(
        kept(&volume, op),
        Some(true),
        "the refusal keeps the grant for the read's next command"
    );
    assert_eq!(
        arena.report(PoolKind::ReadResponse).free,
        1,
        "the refused command returned its buffer"
    );

    assert_eq!(volume.table_report().admission, Admission::Lost);

    control.release(current);
    let mut out = Vec::with_capacity(16);
    let mut ended = Vec::new();
    for _ in 0..8 {
        if !ended.is_empty() {
            break;
        }
        step(&mut volume, &control, 0, &mut out);
        ended.extend(dones(&mut out));
    }
    assert_eq!(ended, [(op, ReadStatus::Lost)]);
}

/// The contrast: the same grant with no refusal submits its command ahead and spends the grant, so the kept grant
/// above is the refusal's doing.
#[test]
fn a_command_ahead_the_device_accepts_spends_the_grant() {
    let storage = storage_reading_ahead(2);
    let arena = arena_with_read_len(2 * CHUNK);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let placed = record(0, 0, 5 * CHUNK, SESSION, 1);
    place(&storage, &control, &placed);
    let op = volume.read_raw(&placed.read, u64::MAX).expect("admitted");
    control.hold(last_submitted(&control));
    assert_eq!(volume.grant_read(op), Ok(Grant::Added));
    assert!(!volume.is_lost());
    assert_eq!(
        (volume.table_report().pending, volume.report().reads_ahead),
        (2, 1)
    );
    assert_eq!(kept(&volume, op), Some(false));
}

/// A read of several commands whose next command is granted after the serving window expired, on a volume that stays
/// open, ends `Quiesced`: its one `Done` follows the first command's chunks and no later byte is delivered.
#[test]
fn a_later_command_granted_after_the_window_expired_ends_the_read_quiesced() {
    later_command_granted(Refused::Expired);
}

enum Refused {
    /// The serving window expires before the grant while the volume stays open.
    Expired,
    /// The simulated device returns a scripted `InvalidRange` for the later command while the serving window stays open.
    InvalidRange,
}

/// `refused` selects how the later command of a three-chunk read is refused.
fn later_command_granted(refused: Refused) {
    use super::super::volume_fixture::step;
    let storage = storage(2);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    volume.authority.clock = Box::new(Clock(Rc::new(Cell::new(0))));
    let record = record(0, 0, 3 * CHUNK, SESSION, 61);
    place(&storage, &control, &record);
    let op = volume.read_raw(&record.read, u64::MAX).expect("admitted");

    // The first command completes and its chunks are handed off; no grant admits a command ahead of it.
    let mut out = Vec::with_capacity(8);
    let mut bytes = Vec::new();
    for _ in 0..16 {
        step(&mut volume, &control, &mut out);
        for event in out.drain(..) {
            match event {
                ReadEvent::Chunk { op: of, chunk, .. } => {
                    assert_eq!(of, op);
                    bytes.extend_from_slice(chunk.bytes());
                }
                ReadEvent::Done { status, .. } => panic!("ended {status:?} before any grant"),
            }
        }
        if !bytes.is_empty() && control.outstanding() == 0 {
            break;
        }
    }
    let first = record.layout.chunk(1).expect("in range").end as usize;
    assert_eq!(bytes, record.payload[..first], "the first command's chunks");
    assert!(first < record.payload.len(), "a later command remains");
    let submitted = control.accepted(super::super::device::Operation::Read);
    assert_eq!(volume.reads.live(), 1, "the read waits for its grant");

    match refused {
        Refused::Expired => {
            volume.authority_event(Event::Expire { now: 0 });
        }
        Refused::InvalidRange => {
            control.refuse_next(SubmitRefusal {
                reason: RefusalReason::InvalidRange,
                code: None,
            });
        }
    }
    assert!(!volume.closed, "the volume stays open");
    volume.grant_read(op).expect("the read is undecided");

    let mut out = Vec::with_capacity(2);
    control.tick(64);
    let _ = volume.poll_storage(0, &mut out);
    let [
        ReadEvent::Done {
            op: done, status, ..
        },
    ] = out.as_slice()
    else {
        panic!("exactly one Done and no chunk: {out:?}");
    };
    assert_eq!(*done, op, "the Done ends the granted read");
    assert_eq!(
        *status,
        ReadStatus::Quiesced,
        "a read whose later command is refused Closed ends Quiesced"
    );
    out.clear();
    for _ in 0..8 {
        step(&mut volume, &control, &mut out);
    }
    assert!(out.is_empty(), "nothing follows the Done");
    assert_eq!(
        control.accepted(super::super::device::Operation::Read),
        submitted,
        "the refused command never reached the device"
    );
    assert_eq!(volume.reads.live(), 0);
    assert_eq!(volume.table_report().pending, 0);
    volume.close();
}

/// The simulated device returns a scripted `InvalidRange` for the later command while the serving window stays open,
/// so the read's single `Done` fails the `Quiesced` status assertion.
#[test]
#[should_panic(expected = "a read whose later command is refused Closed ends Quiesced")]
fn negative_control_a_later_command_the_device_refuses_fails_the_quiesced_end() {
    later_command_granted(Refused::InvalidRange);
}
