//! The context crc32c is the crc32c of the extent's context (the version, key, allocation, session, cache
//! version, both whole lengths, the index, the verified length and the offset, in that order) followed by its
//! payload.
//!
//! The encoder and the verifier share one function for this crc, so a test that reads the value back through
//! `verify_header` alone cannot see a field the function leaves out. Each test here builds the covered bytes
//! from its own inputs and takes their crc32c bit by bit (`fuzz_tests::crc32c`), then compares that with the
//! `u32` the encoder stored at header offset 104.

use super::super::device::IO_UNIT;
use super::super::geometry::EXTENT_PAYLOAD;
use super::fuzz_tests::crc32c;
use super::header::{BODY_LEN, CONTEXT_CRC, HEADER_CRC, METADATA_LEN, header_crc};
use super::{
    Crc32c, ExpectedHeader, ExtentPosition, HeaderMismatch, RecordConfig, RecordIdentity,
    RecordLayout, ValidRecordConfig, encode_header, verify_header,
};

const CHUNK: u32 = 8192;

/// The header version the format writes at offset 8.
const VERSION: u32 = 3;

const IDENTITY: RecordIdentity = RecordIdentity {
    key: [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF, 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2,
        0xE1, 0xF0,
    ],
    allocation: 0x0102_0304_0506_0708,
    session: 0x1122_3344_5566_7788,
    version: 0x0C0D_0E0F_1011_1213,
};

/// One shape of an extent's record: the object's whole lengths and the extent's place in it.
#[derive(Debug, Clone, Copy)]
struct Shape {
    name: &'static str,
    metadata_len: u32,
    body_len: u32,
    position: ExtentPosition,
}

/// One encoded record of a shape, with the payload the test wrote into it.
struct Record {
    shape: Shape,
    layout: RecordLayout,
    bytes: Vec<u8>,
    payload: Vec<u8>,
}

fn config() -> ValidRecordConfig {
    RecordConfig { chunk_len: CHUNK }.validate().expect("valid")
}

/// Payload byte `at` of a record seeded with `seed`: a fixed mix, so no two neighbours repeat.
fn payload_byte(seed: u64, at: u64) -> u8 {
    let mixed = (at ^ seed)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .rotate_left(23)
        .wrapping_add(seed);
    (mixed >> 32) as u8
}

/// Encodes the record of `shape`, its payload the extent's coverage of the object.
fn record(shape: Shape, seed: u64) -> Record {
    let config = config();
    let len = u64::from(shape.metadata_len) + u64::from(shape.body_len);
    let covered = (len - shape.position.offset).min(EXTENT_PAYLOAD);
    let layout = config.extent_layout(shape.metadata_len, shape.body_len, covered);
    let payload: Vec<u8> = (0..covered).map(|at| payload_byte(seed, at)).collect();
    let mut bytes = vec![0xAB; layout.record_units() as usize * IO_UNIT];
    let header = layout.header_bytes();
    bytes[header..header + payload.len()].copy_from_slice(&payload);
    encode_header(
        Crc32c::detect(),
        &layout,
        &IDENTITY,
        shape.position,
        &mut bytes,
    )
    .expect("the buffer holds the record");
    Record {
        shape,
        layout,
        bytes,
        payload,
    }
}

impl Record {
    /// What a reader of this extent expects, with the whole lengths named only for a later extent.
    fn expected(&self) -> ExpectedHeader {
        let later = self.shape.position.index > 0;
        ExpectedHeader {
            identity: IDENTITY,
            reader: IDENTITY.session,
            position: self.shape.position,
            len_units: self.layout.record_units() as u32,
            lengths: later.then_some((self.shape.metadata_len, self.shape.body_len)),
        }
    }

    fn stored_context_crc(&self) -> u32 {
        u32_at(&self.bytes, CONTEXT_CRC)
    }
}

/// The context of an extent as the property lists it, built from the test's inputs alone: the version, key, allocation, session, cache version, both whole lengths, the index, the verified length and the offset, little-endian, in that order.
fn context_fields(
    metadata_len: u32,
    body_len: u32,
    position: ExtentPosition,
    verified: u32,
) -> Vec<u8> {
    let mut context = Vec::with_capacity(84);
    context.extend_from_slice(&VERSION.to_le_bytes());
    context.extend_from_slice(&IDENTITY.key);
    context.extend_from_slice(&IDENTITY.allocation.to_le_bytes());
    context.extend_from_slice(&IDENTITY.session.to_le_bytes());
    context.extend_from_slice(&IDENTITY.version.to_le_bytes());
    context.extend_from_slice(&metadata_len.to_le_bytes());
    context.extend_from_slice(&body_len.to_le_bytes());
    context.extend_from_slice(&position.index.to_le_bytes());
    context.extend_from_slice(&verified.to_le_bytes());
    context.extend_from_slice(&position.offset.to_le_bytes());
    context
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"))
}

const SHAPES: [Shape; 6] = [
    Shape {
        name: "no payload",
        metadata_len: 0,
        body_len: 0,
        position: ExtentPosition::FIRST,
    },
    Shape {
        name: "one chunk, body alone",
        metadata_len: 0,
        body_len: 100,
        position: ExtentPosition::FIRST,
    },
    Shape {
        name: "one chunk, metadata and body",
        metadata_len: 37,
        body_len: 5000,
        position: ExtentPosition::FIRST,
    },
    Shape {
        name: "several chunks, metadata and body",
        metadata_len: 300,
        body_len: 3 * CHUNK + 17,
        position: ExtentPosition::FIRST,
    },
    Shape {
        name: "a full first extent of a two-extent object",
        metadata_len: 10,
        body_len: EXTENT_PAYLOAD as u32 + 2 * CHUNK,
        position: ExtentPosition::FIRST,
    },
    Shape {
        name: "the second extent, at index 1 and a nonzero offset",
        metadata_len: 10,
        body_len: EXTENT_PAYLOAD as u32 + 2 * CHUNK,
        position: ExtentPosition {
            index: 1,
            offset: EXTENT_PAYLOAD,
        },
    },
];

/// For each shape, the `u32` at header offset 104 is the crc32c of the context the test lists followed by the payload the test wrote, and header bytes 8..12, 16..80 and 88..104 are that context.
#[test]
fn the_stored_context_crc_is_the_crc32c_of_the_listed_fields_then_the_payload() {
    let mut chunk_counts = Vec::new();
    for (at, shape) in SHAPES.into_iter().enumerate() {
        let record = record(shape, 0xC0FF_EE00 + at as u64);
        let verified = u32::try_from(record.payload.len()).expect("an extent's payload fits");
        let fields = context_fields(shape.metadata_len, shape.body_len, shape.position, verified);
        let header = &record.bytes[..record.layout.header_bytes()];
        let placed = [&header[8..12], &header[16..80], &header[88..104]].concat();
        assert_eq!(
            placed, fields,
            "{}: header bytes 8..12, 16..80 and 88..104 hold the context fields in order",
            shape.name
        );
        let covered = [fields.as_slice(), record.payload.as_slice()].concat();
        assert_eq!(
            record.stored_context_crc(),
            crc32c(&covered),
            "{}: the context crc at offset 104 is the crc32c of the context then the payload",
            shape.name
        );
        chunk_counts.push(record.layout.chunk_count());
    }
    // The shapes reach an empty chunk table, a single chunk and several chunks.
    assert_eq!(chunk_counts[0], 0, "the empty object has no chunk");
    assert_eq!(chunk_counts[1], 1);
    assert_eq!(chunk_counts[2], 1);
    assert!(chunk_counts[3] > 1 && chunk_counts[4] > 1 && chunk_counts[5] > 1);
}

/// The sibling without a fault: every shape's record verifies at its own position.
#[test]
fn each_encoded_shape_verifies_at_its_own_position() {
    let (crc, config) = (Crc32c::detect(), config());
    for (at, shape) in SHAPES.into_iter().enumerate() {
        let record = record(shape, 0xC0FF_EE00 + at as u64);
        let verdict = verify_header(crc, &config, &record.bytes, &record.expected()).map(|_| ());
        assert_eq!(verdict, Ok(()), "{}", shape.name);
    }
}

/// A header whose `metadata_len` grows by one while `body_len` shrinks by one, with only the header crc resealed, fails verification at the context crc: the total is unchanged, so no earlier check reads the split.
#[test]
fn a_moved_split_between_metadata_and_body_fails_at_the_context_crc() {
    let (crc, config) = (Crc32c::detect(), config());
    let shape = SHAPES[2];
    let record = record(shape, 0x5EED);
    let expected = record.expected();
    assert_eq!(
        expected.lengths, None,
        "a first extent's reader names no lengths"
    );
    let header_len = record.layout.header_bytes();

    // The control: the same bytes with the header crc resealed and nothing moved still verify.
    let mut resealed = record.bytes.clone();
    let sealed = header_crc(crc, &resealed[..header_len]);
    resealed[HEADER_CRC..HEADER_CRC + 4].copy_from_slice(&sealed.to_le_bytes());
    let control = verify_header(crc, &config, &resealed, &expected).map(|_| ());

    let mut forged = record.bytes.clone();
    let (metadata_len, body_len) = (shape.metadata_len + 1, shape.body_len - 1);
    forged[METADATA_LEN..METADATA_LEN + 4].copy_from_slice(&metadata_len.to_le_bytes());
    forged[BODY_LEN..BODY_LEN + 4].copy_from_slice(&body_len.to_le_bytes());
    let sealed = header_crc(crc, &forged[..header_len]);
    forged[HEADER_CRC..HEADER_CRC + 4].copy_from_slice(&sealed.to_le_bytes());
    let verdict = verify_header(crc, &config, &forged, &expected).map(|_| ());

    // The crc the forged context would need, from the test's own bytes.
    let verified = u32::try_from(record.payload.len()).expect("an extent's payload fits");
    let moved = context_fields(metadata_len, body_len, shape.position, verified);
    let needed = crc32c(&[moved.as_slice(), record.payload.as_slice()].concat());
    let stored = record.stored_context_crc();

    assert_eq!(control, Ok(()), "a resealed, unmoved header verifies");
    assert_ne!(
        stored, needed,
        "the moved split changes the context's crc32c"
    );
    assert_eq!(
        verdict,
        Err(HeaderMismatch::ContextCrc {
            stored,
            computed: needed,
        }),
        "the moved split is refused at the context crc, which names the crc of the moved context"
    );
}
