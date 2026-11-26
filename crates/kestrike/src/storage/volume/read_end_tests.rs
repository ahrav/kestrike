//! A device read refuses `HeaderMismatch::Lengths` for a header whose lengths end past the
//! bytes the read covers. The scenario places one sealed one-extent record on the simulated device and reads
//! it with `Volume::read_raw` three times: under two locators whose record end stops short of the record length
//! the header's lengths derive, inside the same unit count, and under its true record end. A short end must
//! finish `Done` with `Lengths` naming the header's lengths and deliver no payload byte; the true end must
//! complete with every payload byte.
//!
//! Each read decides its verdict into plain values, lets its fixtures go, and the test asserts afterwards, so a
//! failure ends in a result line. A read that panics inside the cache leaks its fixtures and reports the panic
//! as its verdict.

use std::panic::{AssertUnwindSafe, catch_unwind};

use super::super::device::sim::{Event, SimControl};
use super::super::device::{IO_UNIT, SECTOR};
use super::super::record::HeaderMismatch;
use super::super::volume_fixture::drive;
use super::ReadStatus;
use super::volume_tests::{CHUNK, SESSION, TICK, arena, attach, place, record, storage};

/// The lengths the placed record's header states. They are the scenario's own inputs, so the expected
/// mismatch is built from them and not read back from the cache.
const METADATA_LEN: u32 = 100;
const BODY_LEN: u32 = 2 * CHUNK + 2_000;

/// Where a read's locator says the record ends, as an offset inside the record's last unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    /// One byte into the last unit: the read covers the last unit's first sector.
    FirstByte,
    /// The end of the last unit's first sector.
    FirstSector,
    /// The record's true length.
    True,
}

/// What one read showed, in plain values.
#[derive(Debug)]
struct Seen {
    status: ReadStatus,
    /// Payload bytes the read delivered.
    delivered: Vec<u8>,
    /// The payload the record holds.
    payload: Vec<u8>,
    /// Bytes the device executed for this read.
    moved: u64,
    /// The record length the header's lengths derive, and the offset of the record's last unit.
    record_len: u64,
    last_unit: u64,
}

fn moved(control: &SimControl) -> u64 {
    control
        .events()
        .iter()
        .filter_map(|event| match event {
            Event::Executed { len, .. } => Some(*len as u64),
            _ => None,
        })
        .sum()
}

/// Places the record and reads it under `end`. `Err` names a premise that failed to form or a panic of the read.
fn read(end: End) -> Result<Seen, String> {
    let storage = storage(2);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let mut placed = record(3, METADATA_LEN, BODY_LEN, SESSION, 1);
    let record_len = placed.layout.record_len();
    let last_unit = (placed.layout.record_units() - 1) * IO_UNIT as u64;
    // The record's bytes end past its last unit's first sector, so both short ends leave header-claimed bytes
    // outside the read while the locator keeps the record's unit count.
    let premise = (record_len > last_unit + SECTOR as u64
        && record_len.next_multiple_of(SECTOR as u64) < last_unit + IO_UNIT as u64)
        .then_some(())
        .ok_or(format!("premise: a record of {record_len} bytes does not end inside its last unit at {last_unit}"));
    let units = placed.read.locator.len_units();
    placed.read.locator = match end {
        End::FirstByte => placed.read.locator.ending_at(last_unit + 1),
        End::FirstSector => placed.read.locator.ending_at(last_unit + SECTOR as u64),
        End::True => placed.read.locator,
    };
    let premise = premise.and_then(|()| {
        (placed.read.locator.len_units() == units)
            .then_some(())
            .ok_or("premise: the short end changed the locator's unit count".to_string())
    });
    place(&storage, &control, &placed);
    let before = moved(&control);
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let op = volume
            .read_raw(&placed.read, u64::MAX)
            .map_err(|refusal| format!("premise: the read was refused admission: {refusal:?}"))?;
        Ok::<_, String>(drive(&mut volume, &control, op))
    }));
    let seen = match outcome {
        Ok(delivered) => premise.and(delivered).map(|delivered| Seen {
            status: delivered.status,
            delivered: delivered.bytes,
            payload: placed.payload.clone(),
            moved: moved(&control) - before,
            record_len,
            last_unit,
        }),
        Err(panic) => {
            let text = panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|text| text.to_string()))
                .unwrap_or_default();
            // The read unwound through the volume: its fixtures hold a command and a buffer mid-read, and
            // their destructors would object while this verdict is still undecided.
            std::mem::forget(volume);
            std::mem::forget(arena);
            std::mem::forget(storage);
            return Err(format!(
                "the read under {end:?} panicked inside the cache: {text}"
            ));
        }
    };
    drop(volume);
    drop(arena);
    drop(storage);
    seen
}

/// A header whose lengths end past the bytes the read covers ends the read `Lengths`, naming the header's
/// lengths, before any payload byte is delivered.
#[test]
fn a_header_claiming_bytes_past_the_read_s_end_fails_lengths_and_delivers_nothing() {
    let seen: Vec<(End, Result<Seen, String>)> = [End::FirstByte, End::FirstSector]
        .into_iter()
        .map(|end| (end, read(end)))
        .collect();
    for (end, seen) in seen {
        let seen = match seen {
            Ok(seen) => seen,
            Err(failure) => panic!("{failure}"),
        };
        // The read's end: the device moved no byte past the last unit's first sector, which the header's
        // lengths pass.
        assert!(
            seen.moved <= seen.last_unit + SECTOR as u64
                && seen.record_len > seen.last_unit + SECTOR as u64,
            "premise: the read under {end:?} moved {} bytes of a record of {} bytes whose last unit starts at {}",
            seen.moved,
            seen.record_len,
            seen.last_unit
        );
        assert_eq!(
            seen.status,
            ReadStatus::HeaderMismatch(HeaderMismatch::Lengths {
                metadata_len: METADATA_LEN,
                body_len: BODY_LEN,
            }),
            "a header whose lengths end past the bytes the read under {end:?} covers fails Lengths"
        );
        assert!(
            seen.delivered.is_empty(),
            "the read under {end:?} delivered {} payload bytes before the lengths refusal",
            seen.delivered.len()
        );
    }
}

/// The comparison without the fault: the same record read under its true record end completes with every
/// payload byte, and the device moves the record's bytes rounded up to its block.
#[test]
fn the_same_record_under_its_true_end_completes_with_every_payload_byte() {
    let seen = match read(End::True) {
        Ok(seen) => seen,
        Err(failure) => panic!("{failure}"),
    };
    assert_eq!(
        seen.status,
        ReadStatus::Complete,
        "the record read under its true end completes"
    );
    assert_eq!(
        seen.payload.len(),
        (METADATA_LEN + BODY_LEN) as usize,
        "premise: the record holds its lengths' payload"
    );
    assert!(
        seen.delivered == seen.payload,
        "the read under the true end delivers every payload byte"
    );
    assert_eq!(
        seen.moved,
        seen.record_len.next_multiple_of(SECTOR as u64),
        "the read under the true end covers the record's bytes, rounded up to the device block"
    );
}
