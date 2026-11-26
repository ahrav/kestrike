//! The header crc32c covers the encoded header with its own field read as zero, `seal_header` writes every
//! header byte except the caller's first `chunk_count` table entries, so the header holds nothing a previous
//! use of the buffer left, and `encode_header` changes no byte past the header.
//!
//! The header of one record of four chunks and one spare table entry is produced through both producers,
//! `encode_header` and `put_chunk_crc` followed by `seal_header`, into three kinds of buffer that hold the same
//! payload: a zeroed one, one whose every other byte is a nonzero value no header of this record holds there,
//! and one that last held the sealed record of another object whose header is as long and whose table fills
//! the entry this record leaves spare. In each buffer the returned crc equals the stored field and the crc32c
//! of the header with bytes 12..16 read as zero, computed here by the production mechanism and by a bitwise
//! reference, the spare table entry is zero, the header verifies, and every byte past the header is as the
//! caller left it. The headers produced over the stale buffers equal, byte for byte, the header produced over
//! zeros.

use super::super::layout::IO_UNIT;
use super::header::HEADER_CRC;
use super::layout::{CHUNK_TABLE, CRC_BYTES};
use super::{
    Crc32c, ExpectedHeader, ExtentPosition, RecordConfig, RecordIdentity, RecordLayout,
    ValidRecordConfig, encode_header, put_chunk_crc, seal_header, verify_header,
};

/// The configured chunk length: one unit, so the record below spans several chunks.
const CHUNK: u32 = 4096;

/// The object's metadata bytes.
const METADATA_LEN: u32 = 100;

/// The object's body bytes: with the metadata, a payload of four chunks whose table has five entries.
const BODY_LEN: u32 = 3 * CHUNK + 500;

/// The body bytes of the object that used the buffer before: a payload of five chunks under a header as
/// long as this record's, so its fifth table entry lies where this record's spare entry does.
const EARLIER_BODY_LEN: u32 = 3 * CHUNK + 3912;

/// The identity of the record under test. Its session has an even, nonzero epoch, which a reader of the
/// same session accepts.
const IDENTITY: RecordIdentity = RecordIdentity {
    key: [0x5A; 32],
    allocation: 0x0000_0003_0000_0009,
    session: 0x0000_0007_0000_0004,
    version: 0x0C0D_0E0F_1011_1213,
};

/// The identity of the record that used the buffer before: every field differs from [`IDENTITY`]'s.
const EARLIER_IDENTITY: RecordIdentity = RecordIdentity {
    key: [0xC3; 32],
    allocation: 0x0000_0011_0000_0002,
    session: 0x0000_0005_0000_0002,
    version: 0x2122_2324_2526_2728,
};

/// How a header reaches the buffer.
#[derive(Debug, Clone, Copy)]
enum Producer {
    /// `encode_header` over the whole record.
    Encode,
    /// `put_chunk_crc` for each chunk, then `seal_header`, over the header's bytes alone.
    Seal,
}

/// Both producers, in the order the tests run them.
const PRODUCERS: [Producer; 2] = [Producer::Encode, Producer::Seal];

/// The record configuration every layout here derives from.
fn config() -> ValidRecordConfig {
    RecordConfig { chunk_len: CHUNK }
        .validate()
        .expect("one unit is a valid chunk length")
}

/// The layout of the record under test, with the premises the tests rest on: several chunks, and at
/// least one table entry past the chunk count.
fn layout() -> RecordLayout {
    let layout = config().layout(METADATA_LEN, BODY_LEN);
    assert!(
        layout.chunk_count() > 1,
        "premise: the record has several chunks, found {}",
        layout.chunk_count()
    );
    assert!(
        spare_table(&layout).len() >= CRC_BYTES,
        "premise: the chunk table has an entry past the chunk count"
    );
    layout
}

/// The header bytes of the chunk-table entries past the chunk count.
fn spare_table(layout: &RecordLayout) -> std::ops::Range<usize> {
    CHUNK_TABLE + layout.chunk_count() as usize * CRC_BYTES..layout.header_bytes()
}

/// Byte `at` of the payload of the object whose content `seed` names.
fn payload_byte(seed: u8, at: usize) -> u8 {
    (at as u8).wrapping_mul(31).wrapping_add((at >> 8) as u8) ^ seed
}

/// Copies the payload `seed` names into `record` after the header of `layout`.
fn put_payload(layout: &RecordLayout, seed: u8, record: &mut [u8]) {
    let header = layout.header_bytes();
    for (at, byte) in record[header..header + layout.payload_len() as usize]
        .iter_mut()
        .enumerate()
    {
        *byte = payload_byte(seed, at);
    }
}

/// A buffer of the record's units, one more unit past them, and the payload under test, whose other
/// bytes are what `stale` gives for each offset.
fn buffer(layout: &RecordLayout, stale: impl Fn(usize) -> u8) -> Vec<u8> {
    let len = (layout.record_units() as usize + 1) * IO_UNIT;
    let mut record: Vec<u8> = (0..len).map(stale).collect();
    put_payload(layout, 0x00, &mut record);
    record
}

/// A stale byte for offset `at`: never zero, and at every header offset another value than a header of
/// this record holds, as the test that uses it checks.
fn stale_byte(at: usize) -> u8 {
    0x80 | (at as u8).wrapping_mul(7)
}

/// The buffer after the sealed record of another object used it: that record's header, as long as this
/// record's, with its own crc at 12..16 and a chunk crc in the entry this record leaves spare, then the
/// payload under test copied over the earlier payload, whose last bytes remain past it.
fn reused_buffer(layout: &RecordLayout) -> Vec<u8> {
    let earlier = config().layout(METADATA_LEN, EARLIER_BODY_LEN);
    assert_eq!(
        earlier.header_bytes(),
        layout.header_bytes(),
        "premise: the earlier record's header is as long as this record's"
    );
    assert!(
        earlier.chunk_count() > layout.chunk_count(),
        "premise: the earlier record's table fills the entry this record leaves spare"
    );
    let mut record = vec![0; (layout.record_units() as usize + 1) * IO_UNIT];
    assert!(
        earlier.record_len() <= record.len() as u64,
        "premise: the earlier record fits the buffer"
    );
    put_payload(&earlier, 0xE7, &mut record);
    let earlier_crc = encode_header(
        Crc32c::detect(),
        &earlier,
        &EARLIER_IDENTITY,
        ExtentPosition::FIRST,
        &mut record,
    )
    .expect("the earlier record fits the buffer");
    assert_ne!(
        earlier_crc, 0,
        "premise: the earlier header crc is not zero"
    );
    assert!(
        record[spare_table(layout)].iter().any(|&byte| byte != 0),
        "premise: the earlier record left a chunk crc in the spare entry"
    );
    put_payload(layout, 0x00, &mut record);
    record
}

/// Produces the header of the record under test in `record` through `producer` and returns the header
/// crc the producer returned.
fn produce(producer: Producer, layout: &RecordLayout, record: &mut [u8]) -> u32 {
    let crc = Crc32c::detect();
    match producer {
        Producer::Encode => encode_header(crc, layout, &IDENTITY, ExtentPosition::FIRST, record)
            .expect("the buffer holds the record"),
        Producer::Seal => {
            let (header, payload) = record.split_at_mut(layout.header_bytes());
            for index in 0..layout.chunk_count() {
                let range = layout.chunk(index).expect("a chunk below the count");
                let chunk = &payload[range.start as usize..range.end as usize];
                put_chunk_crc(header, index, crc.checksum(chunk));
            }
            seal_header(crc, layout, &IDENTITY, ExtentPosition::FIRST, header)
        }
    }
}

/// The crc32c (Castagnoli, reflected, initial register and final xor of all ones) of `bytes`, one bit at
/// a time: a reference that shares no code with the production mechanism.
fn reference_crc32c(bytes: &[u8]) -> u32 {
    let mut register = !0u32;
    for &byte in bytes {
        register ^= u32::from(byte);
        for _ in 0..8 {
            let low = register & 1;
            register >>= 1;
            if low == 1 {
                register ^= 0x82F6_3B78;
            }
        }
    }
    !register
}

/// What the header at the start of `after` breaks, one line per clause, given `before`,
/// the buffer as the caller left it, and `returned`, the crc the producer returned. Empty when the header
/// keeps every clause.
fn broken_clauses(
    layout: &RecordLayout,
    before: &[u8],
    after: &[u8],
    returned: u32,
) -> Vec<String> {
    let mut broken = Vec::new();
    let header = &after[..layout.header_bytes()];
    let stored = u32::from_le_bytes(
        header[HEADER_CRC..HEADER_CRC + CRC_BYTES]
            .try_into()
            .expect("four bytes"),
    );
    if stored != returned {
        broken.push(format!(
            "the stored header crc {stored:#010x} is not the returned one {returned:#010x}"
        ));
    }
    let mut field_as_zero = header.to_vec();
    field_as_zero[HEADER_CRC..HEADER_CRC + CRC_BYTES].fill(0);
    let reference = reference_crc32c(&field_as_zero);
    let production = Crc32c::detect().checksum(&field_as_zero);
    if production != reference {
        broken.push(format!(
            "premise: the production crc32c {production:#010x} of the header is not the reference's {reference:#010x}"
        ));
    }
    if returned != reference {
        broken.push(format!(
            "the returned header crc {returned:#010x} is not the crc32c {reference:#010x} of the header with its own field read as zero"
        ));
    }
    let payload = &before[layout.header_bytes()..];
    for index in 0..layout.chunk_count() {
        let range = layout.chunk(index).expect("a chunk below the count");
        let chunk = reference_crc32c(&payload[range.start as usize..range.end as usize]);
        let at = CHUNK_TABLE + index as usize * CRC_BYTES;
        let entry = u32::from_le_bytes(header[at..at + CRC_BYTES].try_into().expect("four bytes"));
        if entry != chunk {
            broken.push(format!(
                "table entry {index} holds {entry:#010x}, not the crc32c {chunk:#010x} of chunk {index}"
            ));
        }
    }
    let spare = &header[spare_table(layout)];
    if spare.iter().any(|&byte| byte != 0) {
        broken.push(format!(
            "the table entries past the chunk count hold {spare:02x?}, not zeros"
        ));
    }
    let expected = ExpectedHeader {
        identity: IDENTITY,
        reader: IDENTITY.session,
        position: ExtentPosition::FIRST,
        len_units: layout.record_units() as u32,
        lengths: None,
    };
    if let Err(mismatch) = verify_header(Crc32c::detect(), &config(), after, &expected) {
        broken.push(format!("the header does not verify: {mismatch:?}"));
    }
    let past = layout.header_bytes();
    if let Some(at) = (past..after.len()).find(|&at| after[at] != before[at]) {
        broken.push(format!(
            "byte {at}, past the header of {past} bytes, changed from {:#04x} to {:#04x}",
            before[at], after[at]
        ));
    }
    broken
}

/// The header both producers give the record under test in a zeroed buffer, with its crc. The two
/// producers must agree there, and the header must keep every clause.
fn header_over_zeros(layout: &RecordLayout) -> (Vec<u8>, u32) {
    let mut headers = Vec::new();
    for producer in PRODUCERS {
        let before = buffer(layout, |_| 0);
        let mut after = before.clone();
        let returned = produce(producer, layout, &mut after);
        let broken = broken_clauses(layout, &before, &after, returned);
        assert!(
            broken.is_empty(),
            "{producer:?} into a zeroed buffer: {broken:#?}"
        );
        after.truncate(layout.header_bytes());
        headers.push((after, returned));
    }
    let seal = headers.pop().expect("two producers");
    let encode = headers.pop().expect("two producers");
    assert_eq!(
        encode, seal,
        "`encode_header` and `seal_header` give one header and one crc over zeros"
    );
    encode
}

/// Produces the header through each producer over a copy of `before`, a buffer a previous use left
/// bytes in, and returns what each breaks: a clause of the header's contract, or equality with `fresh`, the
/// header and crc produced over zeros. Empty when nothing stale survives.
fn broken_over(layout: &RecordLayout, before: &[u8], fresh: &(Vec<u8>, u32)) -> Vec<String> {
    let mut broken = Vec::new();
    for producer in PRODUCERS {
        let mut after = before.to_vec();
        let returned = produce(producer, layout, &mut after);
        let mut lines = broken_clauses(layout, before, &after, returned);
        if returned != fresh.1 {
            lines.push(format!(
                "the returned header crc {returned:#010x} is not the one {:#010x} returned over zeros",
                fresh.1
            ));
        }
        let header = &after[..layout.header_bytes()];
        if let Some(at) = (0..header.len()).find(|&at| header[at] != fresh.0[at]) {
            lines.push(format!(
                "header byte {at} is {:#04x}, and {:#04x} in the header produced over zeros; the buffer held {:#04x} there",
                header[at], fresh.0[at], before[at]
            ));
        }
        broken.extend(
            lines
                .into_iter()
                .map(|line| format!("{producer:?}: {line}")),
        );
    }
    broken
}

/// In a zeroed buffer both producers give one header, whose returned crc is the stored
/// field and the crc32c of the header with that field read as zero, whose spare table entry is zero and
/// which verifies, and no byte past the header changes.
#[test]
fn a_header_sealed_into_a_zeroed_buffer_keeps_every_clause() {
    let layout = layout();
    let (header, crc) = header_over_zeros(&layout);
    assert_eq!(header.len(), layout.header_bytes());
    assert_ne!(crc, 0, "premise: this record's header crc is not zero");
}

/// Every header byte, the crc field at 12..16 and the spare table entry included, starts as a nonzero
/// value this record's header does not hold there. The header each producer leaves equals the one
/// produced over zeros, with the same crc, and every byte past the header keeps its stale value.
#[test]
fn a_header_sealed_over_stale_bytes_is_the_header_sealed_over_zeros() {
    let layout = layout();
    let fresh = header_over_zeros(&layout);
    let before = buffer(&layout, stale_byte);
    for (at, &stale) in before.iter().enumerate().take(layout.header_bytes()) {
        assert_ne!(stale, 0, "premise: stale header byte {at} is not zero");
        let entry = (at.max(CHUNK_TABLE) - CHUNK_TABLE) / CRC_BYTES;
        let callers = at >= CHUNK_TABLE && entry < layout.chunk_count() as usize;
        assert!(
            callers || stale != fresh.0[at],
            "premise: stale header byte {at} differs from the header's own"
        );
    }
    let broken = broken_over(&layout, &before, &fresh);
    assert!(broken.is_empty(), "over stale bytes: {broken:#?}");
}

/// The buffer last held the sealed record of another object: its header crc lies at 12..16 and one of
/// its chunk crcs lies in the entry this record leaves spare. The header each producer leaves equals the
/// one produced over zeros, and sealing the same record again in place, over its own stored crc, returns
/// the same crc and changes no byte.
#[test]
fn a_buffer_that_held_another_record_keeps_nothing_of_its_header() {
    let layout = layout();
    let fresh = header_over_zeros(&layout);
    let before = reused_buffer(&layout);
    let mut broken = broken_over(&layout, &before, &fresh);
    for producer in PRODUCERS {
        let mut once = before.clone();
        let first = produce(producer, &layout, &mut once);
        let mut twice = once.clone();
        let second = produce(producer, &layout, &mut twice);
        if second != first {
            broken.push(format!(
                "{producer:?}: sealing again in place returned {second:#010x} after {first:#010x}"
            ));
        }
        if let Some(at) = (0..once.len()).find(|&at| once[at] != twice[at]) {
            broken.push(format!(
                "{producer:?}: sealing again in place changed byte {at} from {:#04x} to {:#04x}",
                once[at], twice[at]
            ));
        }
    }
    assert!(broken.is_empty(), "over another record: {broken:#?}");
}
