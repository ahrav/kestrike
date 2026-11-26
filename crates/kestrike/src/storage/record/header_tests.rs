//! Record configuration refusals, the inline layout against a reference model, pinned header offsets, the zeroed table tail, one forged field per mismatch variant, and resealed extents naming another context, read through the volume.
//! A forged header is resealed with its own crc over the span its lengths derive, so verification reaches the forged field's check.

use super::super::device::IO_UNIT;
use super::super::seeded::SplitMix64;
use super::super::writable_tests::bytes as content;
use super::fuzz_tests::{Expected, Judgment, PUBLISHED, literal, offset_unchecked, read_back};
use super::header::{
    ALLOCATION, BODY_LEN, CACHE_VERSION, CHUNK_COUNT, CHUNK_LEN, CONTEXT_CRC, EXTENT_INDEX,
    EXTENT_LEN, HEADER_CRC, HEADER_MAGIC, HEADER_VERSION, KEY, MAGIC, METADATA_LEN, OFFSET,
    SESSION, VERSION, feed_header, header_crc,
};
use super::layout::CHUNK_TABLE;
use super::{
    ChunkMismatch, Crc32c, EncodeError, ExpectedHeader, ExtentPosition, HeaderMismatch,
    RecordConfig, RecordConfigError, RecordIdentity, RecordLayout, ValidRecordConfig,
    encode_header, verify_header,
};

const CHUNK: u32 = 8192;

const IDENTITY: RecordIdentity = RecordIdentity {
    key: [0x5A; 32],
    allocation: 0x0102_0304_0506_0708,
    session: 0x1122_3344_5566_7788,
    version: 0x0C0D_0E0F_1011_1213,
};

fn config() -> ValidRecordConfig {
    config_of(CHUNK)
}

fn config_of(chunk_len: u32) -> ValidRecordConfig {
    RecordConfig { chunk_len }.validate().expect("valid")
}

/// One encoded record: header, payload and the zero tail to its last unit.
struct Record {
    layout: RecordLayout,
    bytes: Vec<u8>,
    header_crc: u32,
}

fn record(metadata_len: u32, body_len: u32, seed: u64) -> Record {
    extent_record(
        &config(),
        metadata_len,
        body_len,
        ExtentPosition::FIRST,
        seed,
    )
}

/// The record under `config` of the extent at `position` of an object of
/// `metadata_len` and `body_len` bytes, its payload the extent's coverage.
fn extent_record(
    config: &ValidRecordConfig,
    metadata_len: u32,
    body_len: u32,
    position: ExtentPosition,
    seed: u64,
) -> Record {
    let len = u64::from(metadata_len) + u64::from(body_len);
    let payload = (len - position.offset).min(super::super::geometry::EXTENT_PAYLOAD);
    let layout = config.extent_layout(metadata_len, body_len, payload);
    let mut rng = SplitMix64::new(seed);
    let mut bytes = vec![0xAB; layout.record_units() as usize * IO_UNIT];
    let header = layout.header_bytes();
    for byte in &mut bytes[header..header + layout.payload_len() as usize] {
        *byte = rng.next_u64() as u8;
    }
    let header_crc =
        encode_header(Crc32c::detect(), &layout, &IDENTITY, position, &mut bytes).expect("fits");
    Record {
        layout,
        bytes,
        header_crc,
    }
}

impl Record {
    fn expected(&self) -> ExpectedHeader {
        ExpectedHeader {
            position: ExtentPosition::FIRST,
            identity: IDENTITY,
            reader: IDENTITY.session,
            len_units: self.layout.record_units() as u32,
            lengths: None,
        }
    }

    fn header(&self) -> &[u8] {
        &self.bytes[..self.layout.header_bytes()]
    }

    fn chunk(&self, index: u32) -> &[u8] {
        let range = self.layout.chunk(index).expect("in range");
        let header = self.layout.header_bytes();
        &self.bytes[header + range.start as usize..header + range.end as usize]
    }
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"))
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("eight bytes"))
}

#[test]
fn record_config_refuses_each_invalid_field_distinctly() {
    let refuse = |chunk_len| RecordConfig { chunk_len }.validate().err();
    assert_eq!(refuse(0), Some(RecordConfigError::ZeroChunkLen));
    assert_eq!(
        refuse(4097),
        Some(RecordConfigError::ChunkLenNotUnitMultiple { chunk_len: 4097 })
    );
    assert_eq!(refuse(4096), None);
}

/// The reference model: a header of the fixed fields plus
/// `ceil(L / chunk_len) + 1` table entries, the payload directly after it,
/// and chunk `i` the payload bytes of the `i`-th record-aligned window that
/// holds any, found by scanning the windows one by one.
fn reference(payload: u64, chunk_len: u64) -> (u64, u64, Vec<(u64, u64)>) {
    let header = 108 + 4 * (payload.div_ceil(chunk_len) + 1);
    let end = header + payload;
    let mut chunks = Vec::new();
    let mut window = 0;
    while window * chunk_len < end {
        let (start, stop) = (window * chunk_len, (window + 1) * chunk_len);
        let (from, to) = (start.max(header), stop.min(end));
        if from < to {
            chunks.push((from - header, to - header));
        }
        window += 1;
    }
    (header, end.div_ceil(IO_UNIT as u64), chunks)
}

/// `RecordLayout` agrees with the reference model on header bytes, record
/// units and every chunk range, for payloads from empty through past four
/// windows, at every window and unit boundary plus and minus one, and at the
/// largest layout; the header depends only on the payload length; every
/// chunk lies inside one window; the table holds at least every chunk.
#[test]
fn a_record_length_names_one_payload_length_and_gaps_name_none() {
    let config = config_of(4096);
    let lengths: Vec<Option<u64>> = (0..=4096 + 128).map(|len| config.payload_of(len)).collect();
    assert!(lengths[..112].iter().all(Option::is_none));
    assert_eq!(lengths[112], Some(0));
    assert!(lengths[113..117].iter().all(Option::is_none));
    assert_eq!(lengths[117], Some(1));
    assert_eq!(lengths[116 + 4096], Some(4096));
    assert!(lengths[116 + 4097..116 + 4101].iter().all(Option::is_none));
    assert_eq!(lengths[116 + 4101], Some(4097));
}

#[test]
fn the_inline_layout_matches_a_reference_model() {
    for chunk_len in [4096u32, 8192, 3 * 4096] {
        let config = config_of(chunk_len);
        let window = u64::from(chunk_len);
        let mut lengths: Vec<u64> = (0..=64).collect();
        for boundary in (1..=5 * window / IO_UNIT as u64).map(|unit| unit * IO_UNIT as u64) {
            // Payload lengths that put the record's end at a unit or window
            // boundary, plus and minus one, for every header the model gives.
            for header in [112, 116, 120, 124, 128, 132] {
                for delta in [-1i64, 0, 1] {
                    let length = boundary as i64 - header + delta;
                    if length >= 0 {
                        lengths.push(length as u64);
                    }
                }
            }
            lengths.extend([boundary - 1, boundary, boundary + 1]);
        }
        lengths.push(2 * u64::from(u32::MAX));
        for payload in lengths {
            let (header, units, chunks) = reference(payload, window);
            let metadata = (payload / 2) as u32;
            let layout = config.layout(metadata, (payload - u64::from(metadata)) as u32);
            if let Ok(body) = u32::try_from(payload) {
                let split = config.layout(0, body);
                assert_eq!(split.header_bytes(), layout.header_bytes(), "L {payload}");
            }
            assert_eq!(layout.header_bytes() as u64, header, "L {payload}");
            assert_eq!(layout.record_units(), units, "L {payload}");
            assert_eq!(layout.record_len(), header + payload);
            assert_eq!(
                config.payload_of(header + payload),
                Some(payload),
                "L {payload}"
            );
            assert_eq!(layout.chunk_count() as usize, chunks.len(), "L {payload}");
            assert!((layout.header_bytes() - 108) / 4 >= layout.chunk_count() as usize);
            if chunks.len() > 64 {
                continue;
            }
            for (index, &(start, end)) in chunks.iter().enumerate() {
                let range = layout.chunk(index as u32).expect("in range");
                assert_eq!(
                    (range.start, range.end),
                    (start, end),
                    "L {payload} {index}"
                );
                let first = (header + range.start) / window;
                assert_eq!((header + range.end - 1) / window, first, "one window");
            }
            assert_eq!(layout.chunk(layout.chunk_count()), None);
        }
    }
}

#[test]
fn encoding_pins_every_field_offset_and_zeroes_the_table_tail() {
    let record = record(1000, 20_000, 1);
    let header = record.header();
    assert_eq!(u64_at(header, MAGIC), HEADER_MAGIC);
    assert_eq!(&header[..8], b"IMGCREC1");
    assert_eq!(u32_at(header, VERSION), HEADER_VERSION);
    assert_eq!(u32_at(header, HEADER_CRC), record.header_crc);
    assert_eq!(&header[KEY..KEY + 32], &IDENTITY.key);
    assert_eq!(u64_at(header, ALLOCATION), IDENTITY.allocation);
    assert_eq!(u64_at(header, SESSION), IDENTITY.session);
    assert_eq!(u64_at(header, CACHE_VERSION), IDENTITY.version);
    assert_eq!(u32_at(header, METADATA_LEN), 1000);
    assert_eq!(u32_at(header, BODY_LEN), 20_000);
    assert_eq!(u32_at(header, CHUNK_LEN), CHUNK);
    assert_eq!(u32_at(header, CHUNK_COUNT), 3);
    assert_eq!(u32_at(header, EXTENT_INDEX), 0);
    assert_eq!(u32_at(header, EXTENT_LEN), 21_000);
    assert_eq!(u64_at(header, OFFSET), 0);
    // 21,000 payload bytes after a 124-byte header end at record byte
    // 21,124, inside window 2: three chunks, one spare table entry.
    assert_eq!(record.layout.header_bytes(), 124);
    let crc = Crc32c::detect();
    for index in 0..3 {
        assert_eq!(
            u32_at(header, 108 + 4 * index as usize),
            crc.checksum(record.chunk(index))
        );
    }
    assert_eq!(u32_at(header, 120), 0, "table entries past the chunk count");
    // The context crc is the crc32c of the context fields followed by the
    // payload, computed here over one buffer with no combination.
    let mut context = Vec::new();
    context.extend_from_slice(&header[8..12]);
    context.extend_from_slice(&header[16..80]);
    context.extend_from_slice(&header[88..104]);
    context.extend_from_slice(&record.bytes[124..124 + 21_000]);
    assert_eq!(u32_at(header, CONTEXT_CRC), crc.checksum(&context));
    assert_eq!(
        [
            MAGIC,
            VERSION,
            HEADER_CRC,
            KEY,
            ALLOCATION,
            SESSION,
            CACHE_VERSION,
            METADATA_LEN,
            BODY_LEN
        ],
        [0, 8, 12, 16, 48, 56, 64, 72, 76]
    );
    assert_eq!(
        [
            CHUNK_LEN,
            CHUNK_COUNT,
            EXTENT_INDEX,
            EXTENT_LEN,
            OFFSET,
            CONTEXT_CRC,
            CHUNK_TABLE
        ],
        [80, 84, 88, 92, 96, 104, 108]
    );
    let mut zeroed = header.to_vec();
    zeroed[HEADER_CRC..HEADER_CRC + 4].fill(0);
    assert_eq!(crc.checksum(&zeroed), record.header_crc);
    assert!(
        record.bytes[124 + 21_000..]
            .iter()
            .all(|&byte| byte == 0xAB),
        "encoding writes no byte past the header"
    );
}

#[test]
fn encoding_refuses_a_short_record_and_writes_nothing() {
    let crc = Crc32c::detect();
    let layout = config().layout(0, CHUNK + 1);
    let mut out = vec![0xAB; layout.record_len() as usize - 1];
    assert_eq!(
        encode_header(crc, &layout, &IDENTITY, ExtentPosition::FIRST, &mut out),
        Err(EncodeError::Buffer {
            needed: layout.record_len(),
            len: out.len()
        })
    );
    assert!(out.iter().all(|&byte| byte == 0xAB));
}

#[test]
fn a_valid_header_verifies_and_every_chunk_passes() {
    let crc = Crc32c::detect();
    for (metadata, body) in [(0, 0), (1, 0), (0, CHUNK), (100, 3 * CHUNK + 7)] {
        let record = record(metadata, body, 2);
        let verified =
            verify_header(crc, &config(), &record.bytes, &record.expected()).expect("verifies");
        for index in 0..record.layout.chunk_count() {
            assert_eq!(
                verified.verify_chunk(crc, index, record.chunk(index)),
                Ok(())
            );
        }
        // The header alone verifies: no payload byte is needed or read.
        assert!(verify_header(crc, &config(), record.header(), &record.expected()).is_ok());
        assert_eq!(
            RecordLayout::from_header(
                crc,
                &config(),
                record.header(),
                record.layout.record_units() as u32
            ),
            Ok(record.layout)
        );
    }
}

#[test]
fn a_flipped_byte_anywhere_in_the_encoded_header_is_refused() {
    let record = record(10, 2 * CHUNK, 3);
    let crc = Crc32c::detect();
    let units = record.layout.record_units() as u32;
    for at in 0..record.layout.header_bytes() {
        let mut forged = record.bytes.clone();
        forged[at] ^= 0x01;
        let refused = verify_header(crc, &config(), &forged, &record.expected()).err();
        let from_header = RecordLayout::from_header(crc, &config(), &forged, units).err();
        let fixed = matches!(at, MAGIC..=11 | METADATA_LEN..CHUNK_TABLE);
        assert!(refused.is_some() && from_header.is_some(), "byte {at}");
        if !fixed {
            assert!(
                matches!(refused, Some(HeaderMismatch::HeaderCrc { .. })),
                "byte {at}: {refused:?}"
            );
        }
    }
}

/// Reseals `bytes` with the crc over the header its own lengths derive.
fn reseal(bytes: &mut [u8]) {
    let crc = Crc32c::detect();
    let payload = u64::from(u32_at(bytes, METADATA_LEN)) + u64::from(u32_at(bytes, BODY_LEN));
    let header = config().layout(0, payload as u32).header_bytes();
    let sealed = header_crc(crc, &bytes[..header]);
    bytes[HEADER_CRC..HEADER_CRC + 4].copy_from_slice(&sealed.to_le_bytes());
}

#[test]
fn each_forged_field_yields_its_own_mismatch_in_order() {
    let record = record(10, 2 * CHUNK, 4);
    let crc = Crc32c::detect();
    let forge_all = |fields: &[(usize, &[u8])]| {
        let mut forged = record.bytes.clone();
        for &(at, value) in fields {
            forged[at..at + value.len()].copy_from_slice(value);
        }
        reseal(&mut forged);
        verify_header(crc, &config(), &forged, &record.expected()).err()
    };
    let forge = |at: usize, value: &[u8]| forge_all(&[(at, value)]);
    // A body one unit longer spans one more unit than the extent holds.
    let longer = 2 * CHUNK + IO_UNIT as u32;
    let cases = [
        (
            MAGIC,
            7u64.to_le_bytes().to_vec(),
            HeaderMismatch::Magic { found: 7 },
        ),
        (
            VERSION,
            1u32.to_le_bytes().to_vec(),
            HeaderMismatch::Version { found: 1 },
        ),
        (
            BODY_LEN,
            longer.to_le_bytes().to_vec(),
            HeaderMismatch::Lengths {
                metadata_len: 10,
                body_len: longer,
            },
        ),
        (
            EXTENT_LEN,
            (2 * CHUNK).to_le_bytes().to_vec(),
            HeaderMismatch::ExtentLength {
                expected: u64::from(2 * CHUNK + 10),
                found: 2 * CHUNK,
            },
        ),
        (
            CHUNK_LEN,
            4096u32.to_le_bytes().to_vec(),
            HeaderMismatch::ChunkParameters {
                chunk_len: 4096,
                chunk_count: 3,
            },
        ),
        (
            CHUNK_COUNT,
            2u32.to_le_bytes().to_vec(),
            HeaderMismatch::ChunkParameters {
                chunk_len: CHUNK,
                chunk_count: 2,
            },
        ),
        (KEY + 31, vec![0], HeaderMismatch::Key),
        (
            ALLOCATION,
            9u64.to_le_bytes().to_vec(),
            HeaderMismatch::Allocation {
                expected: IDENTITY.allocation,
                found: 9,
            },
        ),
        (
            SESSION,
            5u64.to_le_bytes().to_vec(),
            HeaderMismatch::Session {
                expected: IDENTITY.session,
                found: 5,
            },
        ),
        (
            CACHE_VERSION,
            5u64.to_le_bytes().to_vec(),
            HeaderMismatch::CacheVersion {
                expected: IDENTITY.version,
                found: 5,
            },
        ),
        (
            EXTENT_INDEX,
            1u32.to_le_bytes().to_vec(),
            HeaderMismatch::ExtentIndex {
                expected: 0,
                found: 1,
            },
        ),
        (
            OFFSET,
            253_952u64.to_le_bytes().to_vec(),
            HeaderMismatch::Offset {
                expected: 0,
                found: 253_952,
            },
        ),
        (
            CONTEXT_CRC,
            0u32.to_le_bytes().to_vec(),
            HeaderMismatch::ContextCrc {
                stored: 0,
                computed: u32_at(&record.bytes, CONTEXT_CRC),
            },
        ),
    ];
    for (at, value, mismatch) in &cases {
        assert_eq!(forge(*at, value), Some(*mismatch), "field at {at}");
    }
    for (first, (at, _, mismatch)) in cases.iter().enumerate() {
        let later: Vec<(usize, &[u8])> = cases[first..]
            .iter()
            .map(|(at, value, _)| (*at, value.as_slice()))
            .collect();
        let found = forge_all(&later).expect("refused");
        assert_eq!(
            std::mem::discriminant(&found),
            std::mem::discriminant(mismatch),
            "field at {at} is checked before every later field"
        );
    }
    let mut unsealed = record.bytes.clone();
    unsealed[KEY] ^= 1;
    assert!(matches!(
        verify_header(crc, &config(), &unsealed, &record.expected()),
        Err(HeaderMismatch::HeaderCrc { .. })
    ));
    assert_eq!(
        verify_header(crc, &config(), &record.bytes[..107], &record.expected()).err(),
        Some(HeaderMismatch::Truncated {
            len: 107,
            needed: 108
        })
    );
    let header = record.layout.header_bytes();
    assert_eq!(
        verify_header(
            crc,
            &config(),
            &record.bytes[..header - 1],
            &record.expected()
        )
        .err(),
        Some(HeaderMismatch::Truncated {
            len: header - 1,
            needed: header
        })
    );
}

/// Writes `body_len` into a copy of `header` with the verified length the
/// whole lengths then give the one extent, as a forger consistent with the
/// verified-length check would.
fn with_body(header: &[u8], body_len: u32) -> Vec<u8> {
    let mut forged = header.to_vec();
    forged[BODY_LEN..BODY_LEN + 4].copy_from_slice(&body_len.to_le_bytes());
    let payload = u32_at(&forged, METADATA_LEN) + body_len;
    forged[EXTENT_LEN..EXTENT_LEN + 4].copy_from_slice(&payload.to_le_bytes());
    forged
}

#[test]
fn a_header_whose_lengths_move_the_span_fails_before_any_payload_byte() {
    let crc = Crc32c::detect();
    let record = record(10, 2 * CHUNK, 5);
    let header = record.header().to_vec();
    let expected = record.expected();
    let units = expected.len_units;
    let shorter = with_body(&header, 2 * CHUNK - 1);
    assert!(matches!(
        verify_header(crc, &config(), &shorter, &expected),
        Err(HeaderMismatch::HeaderCrc { .. })
    ));
    assert!(matches!(
        RecordLayout::from_header(crc, &config(), &shorter, units),
        Err(HeaderMismatch::HeaderCrc { .. })
    ));
    let mut alone = header.clone();
    alone[BODY_LEN..BODY_LEN + 4].copy_from_slice(&(2 * CHUNK - 1).to_le_bytes());
    assert_eq!(
        verify_header(crc, &config(), &alone, &expected).err(),
        Some(HeaderMismatch::ExtentLength {
            expected: u64::from(2 * CHUNK + 9),
            found: 2 * CHUNK + 10
        })
    );
    // Payload `3 * CHUNK - 1` to `3 * CHUNK + 1`: five table entries, not
    // four, in the same seven units and four chunks.
    let wide = self::record(10, 3 * CHUNK - 11, 7);
    let wide_units = wide.expected().len_units;
    let grown = with_body(&wide.bytes, 3 * CHUNK - 9);
    assert_eq!(config().layout(10, 3 * CHUNK - 9).header_bytes(), 128);
    assert!(matches!(
        RecordLayout::from_header(crc, &config(), &grown, wide_units),
        Err(HeaderMismatch::HeaderCrc { .. })
    ));
    assert_eq!(
        RecordLayout::from_header(crc, &config(), &grown[..124], wide_units),
        Err(HeaderMismatch::Truncated {
            len: 124,
            needed: 128
        })
    );
    let mut shrunk = with_body(&header, 2 * CHUNK - 10);
    assert!(matches!(
        RecordLayout::from_header(crc, &config(), &shrunk, units),
        Err(HeaderMismatch::HeaderCrc { .. })
    ));
    let resealed = header_crc(crc, &shrunk[..120]);
    shrunk[HEADER_CRC..HEADER_CRC + 4].copy_from_slice(&resealed.to_le_bytes());
    let layout = RecordLayout::from_header(crc, &config(), &shrunk, units).expect("resealed");
    assert_eq!(layout.header_bytes(), 120);
    // Two fewer windows: the chunk count the lengths derive differs.
    let fewer = with_body(&header, CHUNK - 200);
    let fewer_units = config().layout(10, CHUNK - 200).record_units() as u32;
    let expected_fewer = ExpectedHeader {
        len_units: fewer_units,
        lengths: None,
        ..expected
    };
    assert_eq!(
        verify_header(crc, &config(), &fewer, &expected_fewer).err(),
        Some(HeaderMismatch::ChunkParameters {
            chunk_len: CHUNK,
            chunk_count: 3
        })
    );
    let mut resplit = header.clone();
    resplit[METADATA_LEN..METADATA_LEN + 4].copy_from_slice(&11u32.to_le_bytes());
    let split = with_body(&resplit, 2 * CHUNK - 1);
    assert!(matches!(
        verify_header(crc, &config(), &split, &expected),
        Err(HeaderMismatch::HeaderCrc { .. })
    ));
    // The extent's own unit count decides: the true header fails against
    // an extent one unit longer or shorter.
    for len_units in [units - 1, units + 1] {
        assert_eq!(
            RecordLayout::from_header(crc, &config(), &header, len_units),
            Err(HeaderMismatch::Lengths {
                metadata_len: 10,
                body_len: 2 * CHUNK
            })
        );
    }
}

#[test]
fn a_flipped_payload_byte_fails_exactly_its_chunk() {
    let record = record(100, 3 * CHUNK + 7, 6);
    let crc = Crc32c::detect();
    let verified =
        verify_header(crc, &config(), &record.bytes, &record.expected()).expect("verifies");
    for index in 0..record.layout.chunk_count() {
        let mut chunk = record.chunk(index).to_vec();
        let at = chunk.len() / 2;
        chunk[at] ^= 0x80;
        assert_eq!(
            verified.verify_chunk(crc, index, &chunk),
            Err(ChunkMismatch { index })
        );
        for other in (0..record.layout.chunk_count()).filter(|&other| other != index) {
            assert_eq!(
                verified.verify_chunk(crc, other, record.chunk(other)),
                Ok(())
            );
        }
    }
    let last = record.layout.chunk_count() - 1;
    let mut padded = record.chunk(last).to_vec();
    padded.resize(IO_UNIT, 0);
    assert_eq!(
        verified.verify_chunk(crc, last, &padded),
        Err(ChunkMismatch { index: last }),
        "a padded tail is refused by its length"
    );
    assert_eq!(
        verified.verify_chunk(crc, last + 1, &[]),
        Err(ChunkMismatch { index: last + 1 })
    );
}

#[test]
fn encoding_and_verification_allocate_nothing() {
    let record = record(100, 2 * CHUNK, 7);
    let crc = Crc32c::detect();
    let mut out = record.bytes.clone();
    let config = config();
    let before = crate::instrument::allocations();
    let header_crc = encode_header(
        crc,
        &record.layout,
        &IDENTITY,
        ExtentPosition::FIRST,
        &mut out,
    )
    .expect("encodes");
    let verified = verify_header(crc, &config, &out, &record.expected()).expect("verifies");
    for index in 0..record.layout.chunk_count() {
        verified
            .verify_chunk(crc, index, record.chunk(index))
            .expect("matches");
    }
    assert_eq!(crate::instrument::allocations(), before);
    assert_eq!(header_crc, record.header_crc);
}

#[test]
fn folding_a_header_in_pieces_matches_the_one_shot_header_crc() {
    let record = record(10, 3 * CHUNK, 5);
    let crc = Crc32c::detect();
    let header = record.header();
    for first in 0..=header.len() {
        for second in first..=header.len().min(first + 20) {
            let mut running = crc.start();
            for range in [0..first, first..second, second..header.len()] {
                feed_header(&mut running, header, range);
            }
            assert_eq!(running.finish(), record.header_crc, "{first} {second}");
        }
    }
}

/// The second extent of a two-extent object stores its index and offset
/// little-endian, binds them into its context crc, verifies at that
/// position with every chunk passing, and refuses the same index at
/// another offset, other whole lengths than the first extent verified, an
/// index past the object's extents, and a verified length other than its
/// coverage.
#[test]
fn a_later_extent_verifies_at_its_own_position_alone() {
    let crc = Crc32c::detect();
    let full = super::super::geometry::EXTENT_PAYLOAD;
    let position = ExtentPosition {
        index: 1,
        offset: full,
    };
    let body = full as u32 + 2 * CHUNK;
    let mut record = extent_record(&config(), 10, body, position, 7);
    assert_eq!(record.layout.payload_len(), 10 + 2 * u64::from(CHUNK));
    let header = &record.bytes[..record.layout.header_bytes()];
    assert_eq!(header[EXTENT_INDEX..EXTENT_INDEX + 4], [1, 0, 0, 0]);
    assert_eq!(header[OFFSET..OFFSET + 8], full.to_le_bytes());
    let payload = &record.bytes[header.len()..][..record.layout.payload_len() as usize];
    let context = [&header[8..12], &header[16..80], &header[88..104], payload].concat();
    assert_eq!(u32_at(header, CONTEXT_CRC), crc.checksum(&context));
    let expected = ExpectedHeader {
        position,
        lengths: Some((10, body)),
        ..record.expected()
    };
    let verified = verify_header(crc, &config(), &record.bytes, &expected).expect("verifies");
    for index in 0..record.layout.chunk_count() {
        assert_eq!(
            verified.verify_chunk(crc, index, record.chunk(index)),
            Ok(())
        );
    }
    let refused =
        |expected: ExpectedHeader| verify_header(crc, &config(), &record.bytes, &expected).err();
    let lengths = HeaderMismatch::Lengths {
        metadata_len: 10,
        body_len: body,
    };
    let elsewhere = ExpectedHeader {
        position: ExtentPosition {
            offset: full + 1,
            ..position
        },
        ..expected
    };
    assert_eq!(
        refused(elsewhere),
        Some(HeaderMismatch::Offset {
            expected: full + 1,
            found: full
        })
    );
    let other = ExpectedHeader {
        lengths: Some((10, body + 1)),
        ..expected
    };
    assert_eq!(refused(other), Some(lengths));
    let past = ExpectedHeader {
        position: ExtentPosition {
            index: 2,
            ..position
        },
        ..expected
    };
    assert_eq!(refused(past), Some(lengths));
    // The second extent's verified length rewritten to a full extent's.
    record.bytes[EXTENT_LEN..EXTENT_LEN + 4].copy_from_slice(&(full as u32).to_le_bytes());
    assert_eq!(
        verify_header(crc, &config(), &record.bytes, &expected).err(),
        Some(HeaderMismatch::ExtentLength {
            expected: 10 + 2 * u64::from(CHUNK),
            found: full as u32
        })
    );
}

/// Under 4 KiB windows one extent holds up to 62 whole windows, so the
/// chunk table's middle run passes the 16-block join threshold at 34
/// windows, fills exactly three wide steps at 50 and reaches the longest
/// extent at 62.
#[test]
fn a_context_crc_over_many_windows_is_the_crc_of_its_fields_and_payload() {
    let crc = Crc32c::detect();
    let window = 4096;
    let config = config_of(window);
    for windows in (1..=12).chain([33, 34, 35, 48, 49, 50, 61, 62]) {
        let body = windows * window - 3000;
        let record = extent_record(&config, 10, body, ExtentPosition::FIRST, u64::from(windows));
        assert_eq!(record.layout.chunk_count(), windows);
        let header = record.header();
        let payload = &record.bytes[header.len()..][..record.layout.payload_len() as usize];
        let context = [&header[8..12], &header[16..80], &header[88..104], payload].concat();
        assert_eq!(
            u32_at(header, CONTEXT_CRC),
            crc.checksum(&context),
            "{windows} windows"
        );
        verify_header(crc, &config, &record.bytes, &record.expected()).expect("verifies");
    }
}

/// The first extent's index at the second extent's payload offset; a
/// one-extent object holds index 0 at offset 0.
const WRONG_OFFSET: ExtentPosition = ExtentPosition {
    index: 0,
    offset: 253_952,
};

/// Reads back the published extent with its header encoded again under
/// the identity `change` makes and at `position`, both crcs sealed over
/// the new fields.
fn resealed(
    change: fn(&mut RecordIdentity),
    position: ExtentPosition,
) -> (Judgment, Vec<u8>, Expected) {
    read_back(|mut image, chunk_len| {
        let mut identity = RecordIdentity {
            key: image[KEY..ALLOCATION].try_into().expect("a key"),
            allocation: u64_at(&image, ALLOCATION),
            session: u64_at(&image, SESSION),
            version: u64_at(&image, CACHE_VERSION),
        };
        change(&mut identity);
        let layout = RecordConfig { chunk_len }
            .validate()
            .expect("valid")
            .layout(u32_at(&image, METADATA_LEN), u32_at(&image, BODY_LEN));
        encode_header(Crc32c::detect(), &layout, &identity, position, &mut image)
            .expect("room for the header");
        image
    })
}

/// A resealed extent naming another key, allocation, session, extent
/// index or offset exposes zero bytes through the volume read, as the
/// literal parser says.
#[test]
fn a_resealed_extent_naming_another_context_exposes_zero_bytes() {
    type Change = fn(&mut RecordIdentity);
    let first = ExtentPosition::FIRST;
    let index = ExtentPosition {
        index: 1,
        offset: 0,
    };
    let unit = ExtentPosition {
        index: 0,
        offset: IO_UNIT as u64,
    };
    let cases: [(&str, Change, ExtentPosition); 8] = [
        ("key", |id| id.key[0] ^= 1, first),
        ("allocation", |id| id.allocation += 1, first),
        ("session", |id| id.session += 1, first),
        ("later session", |id| id.session += 2, first),
        ("cache version", |id| id.version += 1, first),
        ("index", |_| {}, index),
        ("unit offset", |_| {}, unit),
        ("offset", |_| {}, WRONG_OFFSET),
    ];
    for (name, change, position) in cases {
        let (read, image, expected) = resealed(change, position);
        let id = expected.identity;
        let wanted = match name {
            "key" => HeaderMismatch::Key,
            "allocation" => HeaderMismatch::Allocation {
                expected: id.allocation,
                found: id.allocation + 1,
            },
            "session" => HeaderMismatch::Session {
                expected: id.session,
                found: id.session + 1,
            },
            "later session" => HeaderMismatch::Session {
                expected: id.session,
                found: id.session + 2,
            },
            "cache version" => HeaderMismatch::CacheVersion {
                expected: id.version,
                found: id.version + 1,
            },
            "index" => HeaderMismatch::ExtentIndex {
                expected: 0,
                found: 1,
            },
            "unit offset" => HeaderMismatch::Offset {
                expected: 0,
                found: unit.offset,
            },
            _ => HeaderMismatch::Offset {
                expected: 0,
                found: WRONG_OFFSET.offset,
            },
        };
        assert_eq!(read.header, Err(wanted), "{name}");
        assert!(read.exposed.is_empty(), "{name}");
        assert_eq!(read, literal(&image, &expected), "{name}");
    }
}

/// Resealing under the published context is the positive control for
/// `a_resealed_extent_naming_another_context_exposes_zero_bytes`.
#[test]
fn an_extent_resealed_under_its_own_context_reads_back_whole() {
    let (read, image, expected) = resealed(|_| {}, ExtentPosition::FIRST);
    assert_eq!(read.header, Ok(()));
    assert_eq!((read.chunk, &read.other), (None, &None));
    assert!(
        read.exposed == content(PUBLISHED, 3),
        "the read exposes the published payload"
    );
    assert_eq!(read, literal(&image, &expected));
}

/// The planted reference that skips the offset check exposes the
/// resealed wrong-offset extent's whole payload, so it disagrees with
/// the volume read, which exposes none, and fails the judge.
#[test]
fn negative_control_an_offset_skipping_reference_exposes_a_wrong_offset_extent() {
    let (read, image, expected) = resealed(|_| {}, WRONG_OFFSET);
    let skipped = offset_unchecked(&image, &expected);
    assert_eq!(skipped.exposed, content(PUBLISHED, 3));
    assert_ne!(
        read, skipped,
        "the offset-skipping reference fails the judge"
    );
}

#[test]
fn session_predicate_rejects_foreign_or_future_sessions() {
    let crc = Crc32c::detect();
    let config = config();
    let mut rng = SplitMix64::new(0x1284_5E55);
    for case in 0..256 {
        let (reader, named) = super::predicate_tests::named(&mut rng);
        let (generation, epoch, key) = (reader >> 32, named.session & 0xFFFF_FFFF, named.key);
        let body = rng.below(3 * u64::from(CHUNK)) as u32;
        let layout = config.layout(0, body);
        let encoded = |identity: &RecordIdentity| {
            let mut bytes = vec![0; layout.record_units() as usize * IO_UNIT];
            encode_header(crc, &layout, identity, ExtentPosition::FIRST, &mut bytes).expect("fits");
            bytes
        };
        let check = |identity: &RecordIdentity, expected: RecordIdentity, reader: u64| {
            let expected = ExpectedHeader {
                identity: expected,
                reader,
                position: ExtentPosition::FIRST,
                len_units: layout.record_units() as u32,
                lengths: None,
            };
            verify_header(crc, &config, &encoded(identity), &expected)
                .err()
                .map(|mismatch| std::mem::discriminant(&mismatch))
        };
        let foreign = Some(std::mem::discriminant(&HeaderMismatch::ForeignSession {
            found: 0,
            reader: 0,
        }));
        assert_eq!(check(&named, named, reader), None, "case {case}");
        let other_generation = reader ^ 1 << (32 + rng.below(32));
        let earlier_reader = generation << 32 | (epoch - 2);
        for reader in [other_generation, earlier_reader] {
            assert_eq!(check(&named, named, reader), foreign, "case {case}");
        }
        for session in [named.session - 1, generation << 32, named.session + 1] {
            let written = RecordIdentity { session, ..named };
            assert_eq!(check(&written, written, reader), foreign, "case {case}");
        }
        let refusals = [
            (
                RecordIdentity {
                    key: [!key[0]; 32],
                    ..named
                },
                HeaderMismatch::Key,
            ),
            (
                RecordIdentity {
                    allocation: !named.allocation,
                    ..named
                },
                HeaderMismatch::Allocation {
                    expected: 0,
                    found: 0,
                },
            ),
            (
                RecordIdentity {
                    version: !named.version,
                    ..named
                },
                HeaderMismatch::CacheVersion {
                    expected: 0,
                    found: 0,
                },
            ),
        ];
        for (written, mismatch) in refusals {
            assert_eq!(
                check(&written, named, reader),
                Some(std::mem::discriminant(&mismatch)),
                "case {case}"
            );
        }
    }
}
