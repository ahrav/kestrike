//! Fixtures pin literal header bytes, header CRCs and chunk CRCs. Decoding
//! and production encoding match them, encoding keeps caller padding, and a
//! filled record reads back as header, payload, then a zero tail.

use super::super::owner_fixture::{Device, narrow};
use super::super::publish_tests::{TRIES, budget, key};
use super::super::volume_fixture::{SESSION, extent};
use super::super::writable_tests::reserve;
use super::{
    Crc32c, ExpectedHeader, ExtentPosition, HeaderMismatch, RecordConfig, RecordIdentity,
    encode_header, verify_header,
};

const CHUNK: u32 = 4096;
const MAGIC: usize = 0;
const VERSION: usize = 8;
const HEADER_CRC: usize = 12;
const KEY: usize = 16;
const ALLOCATION: usize = 48;
const SESSION_AT: usize = 56;
const CACHE_VERSION: usize = 64;
const METADATA_LEN: usize = 72;
const BODY_LEN: usize = 76;
const CHUNK_LEN: usize = 80;
const CHUNK_COUNT: usize = 84;
const EXTENT_INDEX: usize = 88;
const EXTENT_LEN: usize = 92;
const OFFSET: usize = 96;
const CONTEXT_CRC: usize = 104;
const TABLE: usize = 108;
const UNIT: usize = 4096;
const MAGIC_BYTES: [u8; 8] = *b"IMGCREC1";
pub(super) const IDENTITY: RecordIdentity = RecordIdentity {
    key: [
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 63,
    ],
    allocation: 0x0000_0004_0000_0001,
    session: (1 << 32) | 0x5E56,
    version: 7,
};

pub(super) struct Vector {
    pub(super) name: &'static str,
    pub(super) bytes: &'static [u8],
    pub(super) metadata_len: u32,
    pub(super) body_len: u32,
    pub(super) header_bytes: usize,
    pub(super) chunk_count: u32,
    pub(super) header_crc: u32,
    pub(super) chunk_crcs: &'static [u32],
    pub(super) header: &'static str,
}

pub(super) const VECTORS: [Vector; 5] = [
    Vector {
        name: "empty",
        bytes: include_bytes!("fixtures/empty.rec"),
        metadata_len: 0,
        body_len: 0,
        header_bytes: 112,
        chunk_count: 0,
        header_crc: 0x8B96_8813,
        chunk_crcs: &[],
        header: "494d474352454331030000001388968b090000000000000000000000000000000000000000000000000000000000003f0100000004000000565e00000100000007000000000000000000000000000000001000000000000000000000000000000000000000000000441b764100000000",
    },
    Vector {
        name: "metadata",
        bytes: include_bytes!("fixtures/metadata.rec"),
        metadata_len: 100,
        body_len: 0,
        header_bytes: 116,
        chunk_count: 1,
        header_crc: 0xCD44_9C8C,
        chunk_crcs: &[0x309E_994D],
        header: "494d474352454331030000008c9c44cd090000000000000000000000000000000000000000000000000000000000003f0100000004000000565e0000010000000700000000000000640000000000000000100000010000000000000064000000000000000000000020b9742d4d999e3000000000",
    },
    Vector {
        name: "body",
        bytes: include_bytes!("fixtures/body.rec"),
        metadata_len: 0,
        body_len: 3000,
        header_bytes: 116,
        chunk_count: 1,
        header_crc: 0x6F69_857A,
        chunk_crcs: &[0xF1AA_F908],
        header: "494d474352454331030000007a85696f090000000000000000000000000000000000000000000000000000000000003f0100000004000000565e000001000000070000000000000000000000b80b0000001000000100000000000000b80b00000000000000000000e6edc99a08f9aaf100000000",
    },
    Vector {
        name: "mixed",
        bytes: include_bytes!("fixtures/mixed.rec"),
        metadata_len: 64,
        body_len: 6000,
        header_bytes: 120,
        chunk_count: 2,
        header_crc: 0x6903_BF0D,
        chunk_crcs: &[0x35E0_D5AC, 0xDC43_050F],
        header: "494d474352454331030000000dbf0369090000000000000000000000000000000000000000000000000000000000003f0100000004000000565e00000100000007000000000000004000000070170000001000000200000000000000b0170000000000000000000096f9120facd5e0350f0543dc00000000",
    },
    Vector {
        name: "boundary",
        bytes: include_bytes!("fixtures/boundary.rec"),
        metadata_len: 10,
        body_len: 8062,
        header_bytes: 120,
        chunk_count: 2,
        header_crc: 0xCB8B_AB4E,
        chunk_crcs: &[0xC97E_D40E, 0xE206_0004],
        header: "494d474352454331030000004eab8bcb090000000000000000000000000000000000000000000000000000000000003f0100000004000000565e00000100000007000000000000000a0000007e1f0000001000000200000000000000881f00000000000000000000909c30580ed47ec9040006e200000000",
    },
];

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"))
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("eight bytes"))
}

pub(super) fn vector(name: &str) -> &'static Vector {
    VECTORS
        .iter()
        .find(|vector| vector.name == name)
        .expect("a fixture")
}

fn units(vector: &Vector) -> u32 {
    vector.bytes.len().div_ceil(UNIT) as u32
}

#[test]
fn each_fixture_holds_its_literal_header_and_decodes_to_its_fields() {
    let crc = Crc32c::detect();
    let config = RecordConfig { chunk_len: CHUNK }.validate().expect("valid");
    for vector in &VECTORS {
        let name = vector.name;
        let header = &vector.bytes[..vector.header_bytes];
        assert_eq!(header, &hex(vector.header)[..], "{name}");
        assert_eq!(
            vector.bytes.len(),
            vector.header_bytes + (vector.metadata_len + vector.body_len) as usize,
            "{name}"
        );
        assert_eq!(header[MAGIC..MAGIC + 8], MAGIC_BYTES, "{name}");
        assert_eq!(u32_at(header, VERSION), 3, "{name}");
        assert_eq!(u32_at(header, HEADER_CRC), vector.header_crc, "{name}");
        assert_eq!(header[KEY..KEY + 32], IDENTITY.key, "{name}");
        assert_eq!(u64_at(header, ALLOCATION), IDENTITY.allocation, "{name}");
        assert_eq!(u64_at(header, SESSION_AT), IDENTITY.session, "{name}");
        assert_eq!(u64_at(header, CACHE_VERSION), IDENTITY.version, "{name}");
        assert_eq!(u32_at(header, METADATA_LEN), vector.metadata_len, "{name}");
        assert_eq!(u32_at(header, BODY_LEN), vector.body_len, "{name}");
        assert_eq!(u32_at(header, CHUNK_LEN), CHUNK, "{name}");
        assert_eq!(u32_at(header, CHUNK_COUNT), vector.chunk_count, "{name}");
        assert_eq!(u32_at(header, EXTENT_INDEX), 0, "{name}");
        assert_eq!(
            u32_at(header, EXTENT_LEN),
            vector.metadata_len + vector.body_len,
            "{name}"
        );
        assert_eq!(u64_at(header, OFFSET), 0, "{name}");
        // The context crc is the crc32c of the version, key through body
        // length and index through offset, followed by the payload.
        let context = [
            &header[VERSION..HEADER_CRC],
            &header[KEY..CHUNK_LEN],
            &header[EXTENT_INDEX..CONTEXT_CRC],
            &vector.bytes[vector.header_bytes..],
        ]
        .concat();
        assert_eq!(
            u32_at(header, CONTEXT_CRC),
            crc.checksum(&context),
            "{name}: context crc"
        );
        let expected = ExpectedHeader {
            position: ExtentPosition::FIRST,
            identity: IDENTITY,
            reader: IDENTITY.session,
            len_units: units(vector),
            lengths: None,
        };
        let verified = verify_header(crc, &config, vector.bytes, &expected)
            .unwrap_or_else(|mismatch| panic!("{name}: {mismatch:?}"));
        let layout = config.layout(vector.metadata_len, vector.body_len);
        let claimed = config
            .claimed_layout(vector.bytes, 0, units(vector), None)
            .unwrap_or_else(|mismatch| panic!("{name}: {mismatch:?}"));
        assert_eq!(
            claimed, layout,
            "{name}: the decoder reads the literal lengths"
        );
        assert_eq!(layout.header_bytes(), vector.header_bytes, "{name}");
        assert_eq!(layout.chunk_count(), vector.chunk_count, "{name}");
        assert_eq!(claimed.metadata_len(), vector.metadata_len, "{name}");
        assert_eq!(claimed.body_len(), vector.body_len, "{name}");
        assert_eq!(claimed.record_len(), vector.bytes.len() as u64, "{name}");
        assert_eq!(
            vector.chunk_crcs.len(),
            vector.chunk_count as usize,
            "{name}"
        );
        let payload = &vector.bytes[vector.header_bytes..];
        for (index, &chunk_crc) in (0..).zip(vector.chunk_crcs) {
            assert_eq!(
                u32_at(header, TABLE + 4 * index as usize),
                chunk_crc,
                "{name} table entry {index}"
            );
            assert_eq!(verified.chunk_crc(index), chunk_crc, "{name} chunk {index}");
            let range = layout.chunk(index).expect("a chunk");
            let chunk = &payload[range.start as usize..range.end as usize];
            assert_eq!(
                verified.verify_chunk(crc, index, chunk),
                Ok(()),
                "{name} chunk {index}"
            );
        }
        let table_end = TABLE + 4 * vector.chunk_count as usize;
        assert!(
            header[table_end..].iter().all(|&byte| byte == 0),
            "{name}: zero table tail"
        );
    }
}

/// Distinct values make `HeaderMismatch::Allocation::found` distinguish the pinned allocation from the
/// pinned session.
#[test]
fn a_pinned_record_refuses_the_identity_with_allocation_and_session_exchanged() {
    let crc = Crc32c::detect();
    let config = RecordConfig { chunk_len: CHUNK }.validate().expect("valid");
    assert_ne!(IDENTITY.allocation, IDENTITY.session);
    let exchanged = RecordIdentity {
        allocation: IDENTITY.session,
        session: IDENTITY.allocation,
        ..IDENTITY
    };
    for vector in &VECTORS {
        let expected = ExpectedHeader {
            position: ExtentPosition::FIRST,
            identity: exchanged,
            reader: IDENTITY.session,
            len_units: units(vector),
            lengths: None,
        };
        assert_eq!(
            verify_header(crc, &config, vector.bytes, &expected).err(),
            Some(HeaderMismatch::Allocation {
                expected: IDENTITY.session,
                found: IDENTITY.allocation,
            }),
            "{}",
            vector.name
        );
    }
}

#[test]
fn production_encoding_equals_each_pinned_header_and_keeps_caller_padding() {
    let crc = Crc32c::detect();
    let config = RecordConfig { chunk_len: CHUNK }.validate().expect("valid");
    for vector in &VECTORS {
        let name = vector.name;
        let layout = config.layout(vector.metadata_len, vector.body_len);
        let mut record = vec![0xAB; units(vector) as usize * UNIT + UNIT];
        record[vector.header_bytes..vector.bytes.len()]
            .copy_from_slice(&vector.bytes[vector.header_bytes..]);
        let padding = record[vector.bytes.len()..].to_vec();
        let header_crc = encode_header(crc, &layout, &IDENTITY, ExtentPosition::FIRST, &mut record)
            .expect("fits");
        assert_eq!(header_crc, vector.header_crc, "{name}");
        assert_eq!(&record[..vector.bytes.len()], vector.bytes, "{name}");
        assert_eq!(
            record[vector.bytes.len()..],
            padding[..],
            "{name}: caller padding kept"
        );
    }
}

#[test]
fn the_boundary_record_ends_on_the_second_window() {
    let boundary = vector("boundary");
    assert_eq!(boundary.bytes.len(), 2 * CHUNK as usize);
    let layout = RecordConfig { chunk_len: CHUNK }
        .validate()
        .expect("valid")
        .layout(boundary.metadata_len, boundary.body_len);
    assert_eq!(layout.chunk(0), Some(0..3976));
    assert_eq!(layout.chunk(1), Some(3976..8072));
    assert_eq!(layout.chunk(2), None);
}

#[test]
fn a_filled_record_reads_back_as_header_payload_then_fill_zeros() {
    let (storage, arena) = narrow(CHUNK, 4, 16384);
    let mut device = Device::new(&storage, &arena);
    let capacity = 1 << 20;
    device.control.write_device(0, &vec![0xEE; capacity]);
    let mixed = vector("mixed");
    let payload = &mixed.bytes[mixed.header_bytes..];
    let object = key(9);
    let mut fill = reserve(
        &storage,
        &object,
        mixed.metadata_len as usize,
        mixed.body_len as usize,
    )
    .expect("a fill");
    device.fill(&mut fill, payload);
    let lease = fill
        .publish(&mut device.volume, u64::MAX, TRIES, &mut budget())
        .expect("published");
    let id = lease.id();
    let allocation = (id.slot_index() as u64) << 32 | u64::from(id.incarnation());
    let locator = storage.live_pool().expect("a live pool").records()[id.slot_index()].locator();
    let stored = extent(&storage, &device.control, locator);
    assert_eq!(stored.len(), units(mixed) as usize * UNIT);
    let mut expected = mixed.bytes.to_vec();
    expected[ALLOCATION..ALLOCATION + 8].copy_from_slice(&allocation.to_le_bytes());
    expected[SESSION_AT..SESSION_AT + 8].copy_from_slice(&SESSION.to_le_bytes());
    expected[CACHE_VERSION..CACHE_VERSION + 8].copy_from_slice(&0u64.to_le_bytes());
    expected[HEADER_CRC..HEADER_CRC + 4].copy_from_slice(&stored[HEADER_CRC..HEADER_CRC + 4]);
    // The context crc binds the allocation and session too.
    expected[CONTEXT_CRC..CONTEXT_CRC + 4].copy_from_slice(&stored[CONTEXT_CRC..CONTEXT_CRC + 4]);
    assert_eq!(
        &stored[..mixed.bytes.len()],
        &expected[..],
        "header then payload"
    );
    let identity = RecordIdentity {
        allocation,
        session: SESSION,
        version: 0,
        ..IDENTITY
    };
    let config = RecordConfig { chunk_len: CHUNK }.validate().expect("valid");
    let expected_header = ExpectedHeader {
        position: ExtentPosition::FIRST,
        identity,
        reader: SESSION,
        len_units: units(mixed),
        lengths: None,
    };
    let verified = verify_header(Crc32c::detect(), &config, &stored, &expected_header)
        .expect("the stored header verifies");
    for (index, &chunk_crc) in (0..).zip(mixed.chunk_crcs) {
        assert_eq!(verified.chunk_crc(index), chunk_crc, "chunk {index}");
    }
    assert!(
        stored[mixed.bytes.len()..].iter().all(|&byte| byte == 0),
        "the fill zeroes the unit's tail"
    );
    assert_eq!(
        device.read(&lease),
        payload,
        "the volume reads the payload back"
    );
}

/// The empty version-1 record, whose fixed fields end at byte 80, and the
/// empty version-2 record each refuse at their version before any length or
/// identity check.
#[test]
fn earlier_version_fixtures_refuse_at_their_version() {
    let config = RecordConfig { chunk_len: CHUNK }.validate().expect("valid");
    let expected = ExpectedHeader {
        position: super::ExtentPosition::FIRST,
        identity: IDENTITY,
        reader: IDENTITY.session,
        len_units: 1,
        lengths: None,
    };
    let fixtures: [(&[u8], u32); 2] = [
        (include_bytes!("fixtures/v1-empty.rec"), 1),
        (include_bytes!("fixtures/v2-empty.rec"), 2),
    ];
    for (old, version) in fixtures {
        assert_eq!(u32_at(old, VERSION), version);
        assert_eq!(
            verify_header(Crc32c::detect(), &config, old, &expected).err(),
            Some(super::HeaderMismatch::Version { found: version })
        );
    }
}
