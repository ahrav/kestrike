//! `Kind` and `Status` are closed sets: an unlisted value rejects the
//! frame. The kinds are the bytes 1 to 28 and the statuses the values 1 to 28.
//!
//! The inputs are the byte-assembled version 3 vectors of `fuzz/corpus/frame`,
//! one for each kind byte 1 to 28. Each test edits the kind byte, or the status
//! field, of a vector at its literal offset and recomputes the header crc with
//! the bitwise crc of `net::frame_tests`, so the edited field is the only one
//! that is wrong. Every expected value is computed from the byte the test
//! wrote: a kind exactly for 1 to 28, and otherwise `FrameError::Kind` naming
//! that byte.

use super::datagram::HEADER_LEN;
use super::frame::tests::vectors;
use super::frame::{Field, FrameError, Kind, Status, canonical, checked, parse};
use super::frame_tests::{crc, reseal};

/// The header offset of the kind byte.
const KIND_AT: usize = 10;
/// The header offset of the big-endian status field.
const STATUS_AT: usize = 120;

/// Whether the property lists `byte` as a kind.
fn listed(byte: u8) -> bool {
    (1..=28).contains(&byte)
}

/// One corpus vector for each kind byte 1 to 28, in that order.
fn one_vector_of_each_kind() -> Vec<Vec<u8>> {
    let all = vectors();
    (1..=28u8)
        .map(|byte| {
            all.iter()
                .find(|(_, bytes)| bytes[KIND_AT] == byte)
                .unwrap_or_else(|| panic!("premise: no corpus vector has the kind byte {byte}"))
                .1
                .clone()
        })
        .collect()
}

/// `frame` with its kind byte set to `byte` and its header crc recomputed.
fn with_kind_byte(frame: &[u8], byte: u8) -> Vec<u8> {
    let mut edited = frame.to_vec();
    edited[KIND_AT] = byte;
    reseal(&mut edited);
    edited
}

/// What the three readers make of `bytes`: the kind byte `parse` and the ordered checks name, or their error, and the kind byte of the branch-light path.
fn read(bytes: &[u8]) -> (Result<u8, FrameError>, Result<u8, FrameError>, Option<u8>) {
    let (head, body) = bytes
        .split_first_chunk::<HEADER_LEN>()
        .expect("premise: a vector holds a whole header");
    (
        parse(crc(), bytes, false).map(|frame| frame.header().kind as u8),
        checked(crc(), bytes, false).map(|frame| frame.header().kind as u8),
        canonical(head, body).map(|kind| kind as u8),
    )
}

/// For every byte, `Kind::from_wire` gives a kind exactly for 1 to 28, and that kind's discriminant is the byte.
#[test]
fn from_wire_names_a_kind_exactly_for_the_bytes_1_to_28() {
    let wrong: Vec<(u8, Option<u8>)> = (0..=255u8)
        .map(|byte| (byte, Kind::from_wire(byte).map(|kind| kind as u8)))
        .filter(|&(byte, found)| found != listed(byte).then_some(byte))
        .collect();
    assert!(
        wrong.is_empty(),
        "the kind set is not the bytes 1 to 28; (byte, kind byte named): {wrong:?}"
    );
}

/// The control without the fault: a header canonical for each listed kind parses to that kind, before and after its crc is recomputed.
#[test]
fn a_canonical_header_of_each_listed_kind_parses_to_that_kind() {
    for (byte, frame) in (1..=28u8).zip(one_vector_of_each_kind()) {
        assert_eq!(
            with_kind_byte(&frame, byte),
            frame,
            "premise: recomputing the crc of the vector of kind byte {byte} keeps its bytes"
        );
        assert_eq!(
            read(&frame),
            (Ok(byte), Ok(byte), Some(byte)),
            "the canonical header of the listed kind byte {byte} parses to that kind"
        );
    }
}

/// On a header canonical for each of the 28 kinds, every unlisted kind byte fails `parse` and the ordered checks with `FrameError::Kind` naming the byte, and the branch-light path names no kind.
#[test]
fn an_unlisted_kind_byte_fails_with_the_kind_error_on_every_canonical_header() {
    let mut wrong = Vec::new();
    for (canonical_for, frame) in (1..=28u8).zip(one_vector_of_each_kind()) {
        for byte in (0..=255u8).filter(|&byte| !listed(byte)) {
            let found = read(&with_kind_byte(&frame, byte));
            let refused = Err(FrameError::Kind { found: byte });
            if found != (refused, refused, None) {
                wrong.push((canonical_for, byte, found));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} unlisted kind bytes did not fail with FrameError::Kind; the first (header's kind, byte written, what parse, the ordered checks and the branch-light path gave): {:?}",
        wrong.len(),
        wrong.first()
    );
}

/// A header canonical for INVALIDATED, kind 28, fails with `FrameError::Kind` once its kind byte is 29, 0 or 255; the bytes 27 and 28, which share the header's shape, parse to INVALIDATE and INVALIDATED.
#[test]
fn the_kind_byte_29_on_an_invalidated_header_fails_with_the_kind_error() {
    let invalidated = one_vector_of_each_kind().pop().unwrap();
    assert_eq!(
        invalidated[KIND_AT],
        Kind::Invalidated as u8,
        "premise: the last vector is INVALIDATED"
    );
    for byte in [27u8, 28] {
        assert_eq!(
            read(&with_kind_byte(&invalidated, byte)),
            (Ok(byte), Ok(byte), Some(byte)),
            "the listed kind byte {byte} on the INVALIDATED header parses to that kind"
        );
    }
    for byte in [29u8, 0, 255] {
        let refused = Err(FrameError::Kind { found: byte });
        assert_eq!(
            read(&with_kind_byte(&invalidated, byte)),
            (refused, refused, None),
            "the unlisted kind byte {byte} on the INVALIDATED header fails with FrameError::Kind"
        );
    }
}

/// The status half: `Status::from_wire` names a status exactly for 1 to 28, and an ERROR or a PUT ERROR whose status is 0, 29 or 65535 fails with `Field::Status`, while its vector's own status parses.
#[test]
fn an_unlisted_status_fails_error_and_put_error_with_the_status_field() {
    let wrong: Vec<(u16, Option<u16>)> = (0..=u16::MAX)
        .map(|value| (value, Status::from_wire(value).map(|status| status as u16)))
        .filter(|&(value, found)| found != (1..=28).contains(&value).then_some(value))
        .collect();
    assert!(
        wrong.is_empty(),
        "the status set is not the values 1 to 28; (value, status named): {wrong:?}"
    );
    let vectors = one_vector_of_each_kind();
    for kind in [Kind::Error, Kind::PutError] {
        let frame = &vectors[kind as usize - 1];
        let byte = kind as u8;
        assert_eq!(
            read(frame),
            (Ok(byte), Ok(byte), Some(byte)),
            "premise: the vector of {kind:?} parses with its own status"
        );
        for status in [0u16, 29, u16::MAX] {
            let mut edited = frame.clone();
            edited[STATUS_AT..STATUS_AT + 2].copy_from_slice(&status.to_be_bytes());
            reseal(&mut edited);
            let refused = Err(FrameError::Field {
                kind,
                field: Field::Status,
            });
            assert_eq!(
                read(&edited),
                (refused, refused, None),
                "the unlisted status {status} on {kind:?} fails with Field::Status"
            );
        }
    }
}
