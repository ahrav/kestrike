//! Tests of `Pool::extent_payload`: the payload length of a held object's
//! last extent is decoded from its locator's units and the stored record
//! tail, and the decoding panics on a record length no payload gives or a
//! locator that spans no unit.
//!
//! Each panicking test first decodes valid tails on the same pool, so the
//! panic belongs to the corrupt input alone. The last test decodes under
//! the pool gate and checks that the panic poisons it.

use super::extent::ExtentLocator;
use super::geometry::EXTENT_PAYLOAD;
use super::layout::IO_UNIT;
use super::lookup_tests::ready;
use super::owner::{Pool, Storage};
use super::slot_tests::poisons;
use super::test_platform::TestPlatform;

/// The header of a record whose nonempty payload lies within one window:
/// the 108 fixed bytes and a chunk table of two entries.
const HEADER: usize = 116;

fn locator(units: u32) -> ExtentLocator {
    ExtentLocator::new(8, units).unwrap()
}

/// Decodes last extents with valid tails: an empty payload's record, a
/// one-byte payload's, a tail of zero filling the last unit, and a second
/// unit holding one byte; an extent that is not the last carries the full
/// extent payload whatever its locator.
fn valid_tails_decode(live: &Pool) {
    assert_eq!(live.extent_payload(locator(1), Some(112)), 0);
    assert_eq!(live.extent_payload(locator(1), Some(117)), 1);
    assert_eq!(live.extent_payload(locator(1), Some(0)), IO_UNIT - HEADER);
    assert_eq!(
        live.extent_payload(locator(2), Some(1)),
        IO_UNIT + 1 - HEADER
    );
    assert_eq!(
        live.extent_payload(locator(1), None),
        EXTENT_PAYLOAD as usize
    );
}

fn pool(storage: &Storage<TestPlatform>) -> &Pool {
    storage.live_pool().unwrap()
}

/// A tail between an empty payload's record length and a one-byte
/// payload's gives a record length no payload has, and decoding it panics.
#[test]
#[should_panic(expected = "a held record's length names no payload")]
fn a_tail_in_the_gap_between_two_record_lengths_panics() {
    let storage = ready(8);
    let live = pool(&storage);
    valid_tails_decode(live);
    let _ = live.extent_payload(locator(1), Some(114));
}

/// A tail shorter than any header gives a record length no payload has,
/// and decoding it panics.
#[test]
#[should_panic(expected = "a held record's length names no payload")]
fn a_tail_shorter_than_a_header_panics() {
    let storage = ready(8);
    let live = pool(&storage);
    valid_tails_decode(live);
    let _ = live.extent_payload(locator(1), Some(1));
}

/// A locator of zero units panics under a tail that is valid on one unit.
#[test]
#[should_panic(expected = "a held record's locator spans no unit")]
fn a_locator_of_no_unit_panics() {
    let storage = ready(8);
    let live = pool(&storage);
    valid_tails_decode(live);
    let _ = live.extent_payload(ExtentLocator::from_bits(0), Some(117));
}

/// Decoding under the pool gate: valid tails leave the gate usable, and
/// a record length no payload gives poisons it.
#[test]
fn a_record_length_naming_no_payload_poisons_the_gate_it_is_decoded_under() {
    let storage = ready(8);
    let live = pool(&storage);
    {
        let held = live.lock().unwrap();
        valid_tails_decode(live);
        drop(held);
    }
    drop(live.lock().unwrap());
    poisons(&storage, "a held record's length names no payload", || {
        let _held = live.lock().unwrap();
        let _ = live.extent_payload(locator(1), Some(114));
    });
}
