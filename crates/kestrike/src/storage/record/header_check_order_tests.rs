//! Header verification names the first failing check in the documented order: the magic, the version, the
//! whole lengths, the verified length, the chunk parameters, the header crc, then the identity through the
//! read predicate (key, allocation, session, cache version, and the session against the reader's), the
//! extent index, the offset and the context crc.
//!
//! Each test encodes one valid one-extent record and forges it. A forged check is one field of the header
//! written with a value that fails that check alone, or, for the session against the reader's, a reader of
//! another generation. The header is then resealed with the crc over the header its own lengths derive, so
//! verification reaches the forged field's check; a forged header crc is the sealed crc with its low bit
//! flipped, stored after the reseal. The expected mismatch of a forged set is the earliest forged check in
//! `ORDER`, which is written from the property's text and not read back from `verify_header`.

use super::super::device::IO_UNIT;
use super::header::{
    ALLOCATION, BODY_LEN, CACHE_VERSION, CHUNK_LEN, CONTEXT_CRC, EXTENT_INDEX, EXTENT_LEN,
    HEADER_CRC, KEY, MAGIC, METADATA_LEN, OFFSET, SESSION, VERSION, header_crc,
};
use super::{
    Crc32c, ExpectedHeader, ExtentPosition, HeaderMismatch, RecordConfig, RecordIdentity,
    ValidRecordConfig, encode_header, verify_header,
};

const CHUNK: u32 = 8192;
const METADATA: u32 = 10;
const BODY: u32 = 2 * CHUNK;
/// A body one unit longer spans one more unit than the extent holds.
const LONGER: u32 = BODY + IO_UNIT as u32;

const IDENTITY: RecordIdentity = RecordIdentity {
    key: [0x5A; 32],
    allocation: 0x0102_0304_0506_0708,
    session: 0x1122_3344_5566_7788,
    version: 0x0C0D_0E0F_1011_1213,
};

/// A reader of another generation than `IDENTITY.session`'s.
const FOREIGN_READER: u64 = IDENTITY.session ^ (1 << 32);

/// The checks a forged header can fail, in the order the property states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Check {
    Magic,
    Version,
    Lengths,
    ExtentLength,
    ChunkParameters,
    HeaderCrc,
    Key,
    Allocation,
    Session,
    CacheVersion,
    ForeignSession,
    ExtentIndex,
    Offset,
    ContextCrc,
}

const ORDER: [Check; 14] = [
    Check::Magic,
    Check::Version,
    Check::Lengths,
    Check::ExtentLength,
    Check::ChunkParameters,
    Check::HeaderCrc,
    Check::Key,
    Check::Allocation,
    Check::Session,
    Check::CacheVersion,
    Check::ForeignSession,
    Check::ExtentIndex,
    Check::Offset,
    Check::ContextCrc,
];

/// The check a mismatch names; `Truncated` names none of `ORDER`.
fn named(mismatch: &HeaderMismatch) -> Option<Check> {
    Some(match mismatch {
        HeaderMismatch::Truncated { .. } => return None,
        HeaderMismatch::Magic { .. } => Check::Magic,
        HeaderMismatch::Version { .. } => Check::Version,
        HeaderMismatch::Lengths { .. } => Check::Lengths,
        HeaderMismatch::ExtentLength { .. } => Check::ExtentLength,
        HeaderMismatch::ChunkParameters { .. } => Check::ChunkParameters,
        HeaderMismatch::HeaderCrc { .. } => Check::HeaderCrc,
        HeaderMismatch::Key => Check::Key,
        HeaderMismatch::Allocation { .. } => Check::Allocation,
        HeaderMismatch::Session { .. } => Check::Session,
        HeaderMismatch::CacheVersion { .. } => Check::CacheVersion,
        HeaderMismatch::ForeignSession { .. } => Check::ForeignSession,
        HeaderMismatch::ExtentIndex { .. } => Check::ExtentIndex,
        HeaderMismatch::Offset { .. } => Check::Offset,
        HeaderMismatch::ContextCrc { .. } => Check::ContextCrc,
    })
}

fn config() -> ValidRecordConfig {
    RecordConfig { chunk_len: CHUNK }.validate().expect("valid")
}

/// A record's bytes with what its reader expects.
#[derive(Clone, PartialEq, Eq)]
struct Read {
    bytes: Vec<u8>,
    expected: ExpectedHeader,
}

impl Read {
    fn verify(&self) -> Option<HeaderMismatch> {
        verify_header(Crc32c::detect(), &config(), &self.bytes, &self.expected).err()
    }

    fn u32_at(&self, at: usize) -> u32 {
        u32::from_le_bytes(self.bytes[at..at + 4].try_into().expect("four bytes"))
    }
}

/// The valid record: one extent of `METADATA + BODY` payload bytes written under `IDENTITY`, read by a
/// reader of the writer's own session.
fn valid() -> Read {
    let layout = config().layout(METADATA, BODY);
    let mut bytes = vec![0xAB; layout.record_units() as usize * IO_UNIT];
    let header = layout.header_bytes();
    for (at, byte) in bytes[header..header + layout.payload_len() as usize]
        .iter_mut()
        .enumerate()
    {
        *byte = (at * 31 + 7) as u8;
    }
    encode_header(
        Crc32c::detect(),
        &layout,
        &IDENTITY,
        ExtentPosition::FIRST,
        &mut bytes,
    )
    .expect("fits");
    Read {
        bytes,
        expected: ExpectedHeader {
            identity: IDENTITY,
            reader: IDENTITY.session,
            position: ExtentPosition::FIRST,
            len_units: layout.record_units() as u32,
            lengths: None,
        },
    }
}

/// The crc over the header the lengths in `bytes` derive.
fn sealing(bytes: &[u8]) -> u32 {
    let u32_at = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"));
    let payload = u64::from(u32_at(METADATA_LEN)) + u64::from(u32_at(BODY_LEN));
    let header = config().layout(0, payload as u32).header_bytes();
    header_crc(Crc32c::detect(), &bytes[..header])
}

/// The valid record with every check of `checks` forged, resealed, and its stored header crc then damaged
/// when `checks` holds `HeaderCrc`.
fn forged(checks: &[Check]) -> Read {
    let mut read = valid();
    let mut put = |at: usize, value: &[u8]| read.bytes[at..at + value.len()].copy_from_slice(value);
    for check in checks {
        match check {
            Check::Magic => put(MAGIC, &7u64.to_le_bytes()),
            Check::Version => put(VERSION, &1u32.to_le_bytes()),
            Check::Lengths => put(BODY_LEN, &LONGER.to_le_bytes()),
            Check::ExtentLength => put(EXTENT_LEN, &BODY.to_le_bytes()),
            Check::ChunkParameters => put(CHUNK_LEN, &4096u32.to_le_bytes()),
            Check::Key => put(KEY + 31, &[0]),
            Check::Allocation => put(ALLOCATION, &9u64.to_le_bytes()),
            Check::Session => put(SESSION, &5u64.to_le_bytes()),
            Check::CacheVersion => put(CACHE_VERSION, &5u64.to_le_bytes()),
            Check::ExtentIndex => put(EXTENT_INDEX, &1u32.to_le_bytes()),
            Check::Offset => put(OFFSET, &253_952u64.to_le_bytes()),
            Check::ContextCrc => put(CONTEXT_CRC, &0u32.to_le_bytes()),
            Check::HeaderCrc | Check::ForeignSession => {}
        }
    }
    if checks.contains(&Check::ForeignSession) {
        read.expected.reader = FOREIGN_READER;
    }
    let sealed = sealing(&read.bytes);
    let stored = sealed ^ u32::from(checks.contains(&Check::HeaderCrc));
    read.bytes[HEADER_CRC..HEADER_CRC + 4].copy_from_slice(&stored.to_le_bytes());
    read
}

/// The premise of every forged case: the record verifies as written, and resealing it changes nothing, so
/// a mismatch below comes from a forged check.
#[test]
fn the_valid_record_verifies_and_its_reseal_is_its_own_crc() {
    let read = valid();
    assert_eq!(read.verify(), None);
    assert!(
        forged(&[]) == read,
        "the reseal of the valid record is the crc it was encoded with"
    );
}

/// Each forged check alone fails as itself, with the values the forgery wrote.
#[test]
fn each_forged_check_alone_is_the_mismatch_named() {
    let original = valid();
    let sealed = |check: Check| sealing(&forged(&[check]).bytes);
    let cases = [
        (Check::Magic, HeaderMismatch::Magic { found: 7 }),
        (Check::Version, HeaderMismatch::Version { found: 1 }),
        (
            Check::Lengths,
            HeaderMismatch::Lengths {
                metadata_len: METADATA,
                body_len: LONGER,
            },
        ),
        (
            Check::ExtentLength,
            HeaderMismatch::ExtentLength {
                expected: u64::from(METADATA + BODY),
                found: BODY,
            },
        ),
        (
            Check::ChunkParameters,
            HeaderMismatch::ChunkParameters {
                chunk_len: 4096,
                chunk_count: 3,
            },
        ),
        (
            Check::HeaderCrc,
            HeaderMismatch::HeaderCrc {
                stored: sealed(Check::HeaderCrc) ^ 1,
                computed: sealed(Check::HeaderCrc),
            },
        ),
        (Check::Key, HeaderMismatch::Key),
        (
            Check::Allocation,
            HeaderMismatch::Allocation {
                expected: IDENTITY.allocation,
                found: 9,
            },
        ),
        (
            Check::Session,
            HeaderMismatch::Session {
                expected: IDENTITY.session,
                found: 5,
            },
        ),
        (
            Check::CacheVersion,
            HeaderMismatch::CacheVersion {
                expected: IDENTITY.version,
                found: 5,
            },
        ),
        (
            Check::ForeignSession,
            HeaderMismatch::ForeignSession {
                found: IDENTITY.session,
                reader: FOREIGN_READER,
            },
        ),
        (
            Check::ExtentIndex,
            HeaderMismatch::ExtentIndex {
                expected: 0,
                found: 1,
            },
        ),
        (
            Check::Offset,
            HeaderMismatch::Offset {
                expected: 0,
                found: 253_952,
            },
        ),
        (
            Check::ContextCrc,
            HeaderMismatch::ContextCrc {
                stored: 0,
                computed: original.u32_at(CONTEXT_CRC),
            },
        ),
    ];
    assert_eq!(
        cases.map(|(check, _)| check),
        ORDER,
        "one case for each check of the order"
    );
    for (check, mismatch) in cases {
        let read = forged(&[check]);
        assert!(read != original, "{check:?}: the forgery changed the read");
        assert_eq!(read.verify(), Some(mismatch), "{check:?} forged alone");
    }
}

/// Of two forged checks, verification names the one the order puts first, for every pair of the order.
#[test]
fn the_earlier_of_two_forged_checks_is_the_one_named() {
    let mut wrong = Vec::new();
    for (first, &earlier) in ORDER.iter().enumerate() {
        for &later in &ORDER[first + 1..] {
            let found = forged(&[earlier, later]).verify();
            if found.as_ref().and_then(named) != Some(earlier) {
                wrong.push((earlier, later, found));
            }
        }
    }
    assert_eq!(
        wrong,
        [],
        "(earlier forged check, later forged check, what verification returned) of each pair that named another check than the earlier"
    );
}

/// A header whose stored crc does not match its bytes fails `HeaderCrc` with the stored and the computed
/// crc, whichever field of the identity also differs from the expected one, and under a reader the read
/// predicate refuses: the bytes of an unverified header name no identity.
#[test]
fn a_damaged_header_crc_is_named_before_any_identity_difference() {
    let identity = [
        Check::Key,
        Check::Allocation,
        Check::Session,
        Check::CacheVersion,
        Check::ForeignSession,
    ];
    for differing in identity {
        let read = forged(&[Check::HeaderCrc, differing]);
        let computed = sealing(&read.bytes);
        assert_eq!(
            forged(&[differing]).verify().as_ref().and_then(named),
            Some(differing),
            "premise: {differing:?} alone is refused as itself"
        );
        assert_eq!(
            read.verify(),
            Some(HeaderMismatch::HeaderCrc {
                stored: computed ^ 1,
                computed,
            }),
            "a damaged header crc with {differing:?} also differing"
        );
    }
    let read = forged(&ORDER[5..]);
    let computed = sealing(&read.bytes);
    assert_eq!(
        read.verify(),
        Some(HeaderMismatch::HeaderCrc {
            stored: computed ^ 1,
            computed,
        }),
        "a damaged header crc with every later check forged"
    );
}
