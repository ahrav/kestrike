//! A reader accepts a record for an index entry only when the header's key equals the entry's key in all 32
//! bytes. One valid record is encoded, and then one bit of its key is changed at a time, every bit of every key
//! byte, in three ways: in the header, resealed with its header crc alone; in the record, encoded again under
//! the changed key; and in the identity handed to `admits`. The reader of the original identity refuses each as
//! [`HeaderMismatch::Key`].

use super::super::layout::IO_UNIT;
use super::header::{HEADER_CRC, KEY, header_crc};
use super::{
    Crc32c, ExpectedHeader, ExtentPosition, HeaderMismatch, RecordConfig, RecordIdentity,
    RecordLayout, admits, encode_header, verify_header,
};

const KEY_BYTES: usize = 32;

/// The identity the index entry names. Its session has an even, nonzero epoch, so a reader of the same session
/// accepts it.
const NAMED: RecordIdentity = RecordIdentity {
    key: [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF, 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2,
        0xE1, 0xF0,
    ],
    allocation: 0x0000_0007_0000_0003,
    session: 0x0000_0005_0000_0008,
    version: 41,
};

const READER: u64 = NAMED.session;

/// One record of three payload chunks, encoded under `identity`, with the layout that encoded it.
fn encoded(identity: &RecordIdentity) -> (RecordLayout, Vec<u8>) {
    let config = RecordConfig { chunk_len: 8192 }
        .validate()
        .expect("a valid chunk length");
    let layout = config.layout(64, 20_000);
    let mut bytes = vec![0u8; layout.record_units() as usize * IO_UNIT];
    let header = layout.header_bytes();
    for (at, byte) in bytes[header..header + layout.payload_len() as usize]
        .iter_mut()
        .enumerate()
    {
        *byte = (at as u8).wrapping_mul(31).wrapping_add(7);
    }
    encode_header(
        Crc32c::detect(),
        &layout,
        identity,
        ExtentPosition::FIRST,
        &mut bytes,
    )
    .expect("the buffer holds the record");
    (layout, bytes)
}

/// What the reader of `named` gets from `bytes`: `Ok(())` for a verified header, else the first failing check.
fn read(named: &RecordIdentity, layout: &RecordLayout, bytes: &[u8]) -> Result<(), HeaderMismatch> {
    let config = RecordConfig { chunk_len: 8192 }
        .validate()
        .expect("a valid chunk length");
    let expected = ExpectedHeader {
        identity: *named,
        reader: READER,
        position: ExtentPosition::FIRST,
        len_units: layout.record_units() as u32,
        lengths: None,
    };
    verify_header(Crc32c::detect(), &config, bytes, &expected).map(|_| ())
}

/// `NAMED` with bit `bit` of key byte `position` changed.
fn changed(position: usize, bit: u32) -> RecordIdentity {
    let mut identity = NAMED;
    identity.key[position] ^= 1 << bit;
    identity
}

/// Every single-bit change of the key: 32 positions by 8 bits.
fn changes() -> impl Iterator<Item = (usize, u32)> {
    (0..KEY_BYTES).flat_map(|position| (0..8).map(move |bit| (position, bit)))
}

/// The record as encoded verifies for the reader of its identity, and `admits` holds for equal identities, the
/// original and each changed one.
#[test]
fn the_unchanged_header_verifies_and_equal_identities_are_admitted() {
    let (layout, bytes) = encoded(&NAMED);
    assert!(
        layout.header_bytes() > KEY + KEY_BYTES,
        "the header holds the whole key"
    );
    assert_eq!(
        bytes[KEY..KEY + KEY_BYTES],
        NAMED.key,
        "the key field holds the named key"
    );
    assert_eq!(
        read(&NAMED, &layout, &bytes),
        Ok(()),
        "the unchanged record verifies"
    );
    assert!(
        admits(&NAMED, &NAMED, READER),
        "equal identities are admitted"
    );
    let refused: Vec<_> = changes()
        .filter(|&(position, bit)| {
            let other = changed(position, bit);
            !admits(&other, &other, READER)
        })
        .collect();
    assert_eq!(
        refused,
        [],
        "an identity is admitted for itself whatever its key"
    );
}

/// A header whose key differs in one bit and whose header crc was recomputed passes the header crc and must then
/// fail the identity check as `Key`, at every key position.
#[test]
fn a_header_resealed_with_one_key_bit_changed_is_refused_as_key_at_every_position() {
    let crc = Crc32c::detect();
    let (layout, original) = encoded(&NAMED);
    let header = layout.header_bytes();
    let mut wrong = Vec::new();
    for (position, bit) in changes() {
        let mut bytes = original.clone();
        bytes[KEY + position] ^= 1 << bit;
        let resealed = header_crc(crc, &bytes[..header]);
        bytes[HEADER_CRC..HEADER_CRC + 4].copy_from_slice(&resealed.to_le_bytes());
        let verdict = read(&NAMED, &layout, &bytes);
        if verdict != Err(HeaderMismatch::Key) {
            wrong.push(format!("key byte {position} bit {bit}: {verdict:?}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "a resealed header with another key must be refused as Key; {} of 256 were not: {:?}",
        wrong.len(),
        &wrong[..wrong.len().min(4)]
    );
}

/// A whole record encoded under a key that differs in one bit is a valid record of another key. The reader of the
/// named key must refuse it as `Key`, at every key position, and its own reader must accept it.
#[test]
fn a_record_encoded_under_a_key_changed_in_one_bit_is_refused_as_key_at_every_position() {
    let mut wrong = Vec::new();
    for (position, bit) in changes() {
        let other = changed(position, bit);
        let (layout, bytes) = encoded(&other);
        if bytes[KEY..KEY + KEY_BYTES] != other.key {
            wrong.push(format!(
                "key byte {position} bit {bit}: premise: the header does not hold the changed key"
            ));
            continue;
        }
        let own = read(&other, &layout, &bytes);
        if own != Ok(()) {
            wrong.push(format!(
                "key byte {position} bit {bit}: control: its own reader gets {own:?}"
            ));
            continue;
        }
        let verdict = read(&NAMED, &layout, &bytes);
        if verdict != Err(HeaderMismatch::Key) {
            wrong.push(format!("key byte {position} bit {bit}: {verdict:?}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "a record of another key must verify for its own reader and be refused as Key; {} of 256 did not: {:?}",
        wrong.len(),
        &wrong[..wrong.len().min(4)]
    );
}

/// `admits` is false for two identities that differ in one key bit and in nothing else, in both argument orders.
#[test]
fn admits_refuses_identities_that_differ_in_one_key_bit_at_every_position() {
    let admitted: Vec<_> = changes()
        .filter(|&(position, bit)| {
            let other = changed(position, bit);
            admits(&other, &NAMED, READER) || admits(&NAMED, &other, READER)
        })
        .collect();
    assert_eq!(
        admitted,
        [],
        "identities whose keys differ in one bit (key byte, bit) must not be admitted"
    );
}
