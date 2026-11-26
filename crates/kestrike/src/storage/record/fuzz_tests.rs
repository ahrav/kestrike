//! Record headers fuzzed against an independent literal parser. An input's
//! mutations apply twice: to a standalone record, raw or resealed under a
//! fresh header crc32c, which header verification judges through every
//! rung of its order, truncations included; and to a record published on
//! the simulated device, whose extent the mutated image replaces before
//! the volume's own read delivers what it verified. [`literal`] judges both
//! from the format's documentation alone: its own crc32c, its own field
//! reads, its own layout arithmetic.
//!
//! Header verification must name the literal parser's first failure with
//! its fields. The volume read must end with the literal parser's status
//! and deliver exactly its bytes: none when a header check fails, so an
//! identity failure exposes zero bytes, and exactly the chunks before the
//! first failing one when a chunk fails. The producer's zero tail and the
//! reader's acceptance of a valid-crc nonzero tail are pinned apart.
//!
//! Modes 0 and 1 mutate the fixed-geometry record raw and resealed and
//! take both judgments above. Mode 2 hands its raw tail to `claim_header`,
//! modes 3 and 4 scan a raw or resealed record through `inspect`, and
//! modes 5 and 6 mutate geometry-selected records raw and resealed;
//! [`super::claim_fuzz_tests`], [`super::scan_fuzz_tests`] and
//! [`super::geometry_fuzz_tests`] judge them. Every other mode is
//! unsupported.

use super::super::hit_tests::published;
use super::super::layout::{IO_UNIT, SECTOR};
use super::super::publish_tests::key;
use super::super::test_platform::TestPlatform;
use super::super::volume_fixture::{
    BUFFER, Device, arena_for_chunk, attach_with, drive, extent, settle,
};
use super::super::writable_tests::{bytes as content, wide};
use super::super::{ReadStatus, Storage};
use super::claim_fuzz_tests::claim_mode;
use super::crc32c_tests::oracle_advance;
use super::geometry_fuzz_tests::geometry_mode;
use super::header::{
    HEADER_MAGIC, HEADER_VERSION, HeaderMismatch, RecordIdentity, claim_header, encode_header,
    verify_header,
};
use super::layout::{RecordConfig, RecordLayout, ValidRecordConfig};
use super::scan_fuzz_tests::scan_mode;
use super::{Crc32c, ExpectedHeader, ExtentPosition, seal_header};
use crate::sim::fuzz::{Class, MAX_INPUT, Target};

/// The first byte of every input; a mode byte follows it, then the
/// mode's bytes.
pub(crate) const FORMAT: u8 = 1;

/// The most mutations one input applies.
const MAX_OPS: usize = 64;

/// The record target.
pub(crate) static RECORD: Target = Target {
    name: "record",
    run: record,
    seeds,
};

const CHUNK_LEN: u32 = 4096;
const METADATA: u32 = 100;
const BODY: u32 = 9_000;

/// Bytes of a header's fixed fields; its chunk table starts here.
pub(crate) const FIXED: usize = 108;

pub(crate) const IDENTITY: RecordIdentity = RecordIdentity {
    key: [0x5a; 32],
    allocation: 7 << 32 | 3,
    session: 1 << 32 | 12,
    version: 0x0b0b,
};

pub(crate) const ACCEPTING: [u64; 2] = [IDENTITY.session, IDENTITY.session + 2];

pub(crate) const REFUSING: [u64; 3] = [
    IDENTITY.session - 2,
    IDENTITY.session ^ 1 << 33,
    IDENTITY.session & !0xFFFF_FFFF,
];

fn config() -> ValidRecordConfig {
    RecordConfig {
        chunk_len: CHUNK_LEN,
    }
    .validate()
    .expect("a unit-multiple chunk length")
}

/// The valid record every input mutates, padded to its units.
pub(crate) fn valid() -> (RecordLayout, Vec<u8>) {
    let layout = config().layout(METADATA, BODY);
    let mut bytes = vec![0; layout.record_units() as usize * IO_UNIT];
    for (at, byte) in bytes[layout.header_bytes()..layout.record_len() as usize]
        .iter_mut()
        .enumerate()
    {
        *byte = (at * 31 % 251) as u8;
    }
    encode_header(
        Crc32c::detect(),
        &layout,
        &IDENTITY,
        ExtentPosition::FIRST,
        &mut bytes,
    )
    .expect("room for the record");
    (layout, bytes)
}

/// How a reader judged one record image: the first header failure, the
/// chunk that failed after a verified header, the bytes it exposed, and
/// any read end that names neither a verdict nor completion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Judgment {
    pub(crate) header: Result<(), HeaderMismatch>,
    pub(crate) chunk: Option<u32>,
    pub(crate) exposed: Vec<u8>,
    pub(crate) other: Option<ReadStatus>,
}

impl Judgment {
    fn refused(mismatch: HeaderMismatch) -> Self {
        Self {
            header: Err(mismatch),
            chunk: None,
            exposed: Vec::new(),
            other: None,
        }
    }

    /// The judgment a volume read's end and delivered bytes spell. An end
    /// other than completion or a mismatch, such as a short transfer or a
    /// device error, is kept whole, so it never equals a parser's verdict.
    fn of_read(status: ReadStatus, delivered: Vec<u8>) -> Self {
        let (header, chunk, other) = match status {
            ReadStatus::Complete => (Ok(()), None, None),
            ReadStatus::HeaderMismatch(mismatch) => (Err(mismatch), None, None),
            ReadStatus::ChunkMismatch { index } => (Ok(()), Some(index), None),
            other => (Ok(()), None, Some(other)),
        };
        Self {
            header,
            chunk,
            exposed: delivered,
            other,
        }
    }
}

/// What a record image is judged against: the identity the reader
/// expects, the index and payload offset of the extent it expects, the
/// record chunk length, the extent's units and, for a volume read of a
/// one-extent object, the bytes it covers: its locator's record end
/// rounded up to the device block, within the extent.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Expected {
    pub(crate) identity: RecordIdentity,
    pub(crate) reader: u64,
    pub(crate) index: u32,
    pub(crate) offset: u64,
    pub(crate) chunk_len: u32,
    pub(crate) units: u32,
    pub(crate) end: Option<u64>,
}

/// What the standalone record is judged against.
fn standalone() -> Expected {
    Expected {
        identity: IDENTITY,
        reader: IDENTITY.session,
        index: 0,
        offset: 0,
        chunk_len: CHUNK_LEN,
        units: valid().0.record_units() as u32,
        end: None,
    }
}

/// Header verification of the image `bytes` against `expected`'s
/// identity, extent position, units and chunk length.
pub(crate) fn verified(bytes: &[u8], expected: &Expected) -> Result<(), HeaderMismatch> {
    let header = ExpectedHeader {
        position: ExtentPosition {
            index: expected.index,
            offset: expected.offset,
        },
        identity: expected.identity,
        reader: expected.reader,
        len_units: expected.units,
        lengths: None,
    };
    let config = RecordConfig {
        chunk_len: expected.chunk_len,
    }
    .validate()
    .expect("an admitted chunk length");
    verify_header(Crc32c::detect(), &config, bytes, &header).map(|_| ())
}

/// Payload bytes of the published record. Behind its 128-byte header they
/// overlap four 8 KiB windows: 8,064 bytes of the header's, two full ones,
/// and 200 bytes of the fourth.
pub(crate) const PUBLISHED: usize = 3 * 8192 + 72;

/// Publishes a record on a fresh simulated device, replaces its extent with
/// what `mutate` makes of the published image under the record chunk
/// length, cut or zero-padded to the extent, reads it through the volume,
/// and returns what the read verified beside what the published image
/// expects.
pub(crate) fn read_back(
    mutate: impl FnOnce(Vec<u8>, u32) -> Vec<u8>,
) -> (Judgment, Vec<u8>, Expected) {
    read_back_from(&wide(2, 8), 0, &content(PUBLISHED, 3), mutate)
}

/// [`read_back`] of the one-extent object `payload` publishes on
/// `storage`, its first `metadata` bytes metadata.
pub(crate) fn read_back_from(
    storage: &Storage<TestPlatform>,
    metadata: usize,
    payload: &[u8],
    mutate: impl FnOnce(Vec<u8>, u32) -> Vec<u8>,
) -> (Judgment, Vec<u8>, Expected) {
    let chunk_len = storage.record.chunk_len();
    let buffers = arena_for_chunk(chunk_len);
    // The device moves at least one chunk per command.
    let (volume, control) = attach_with(storage, &buffers, BUFFER.max(chunk_len));
    let mut dev = Device { volume, control };
    let lease = published(storage, &mut dev, &key(1), metadata, payload);
    let locator = storage.live_pool().unwrap().records()[lease.id().slot_index()].locator();
    let pristine = extent(storage, &dev.control, locator);
    let session = u64_at(&pristine, 56);
    let expected = Expected {
        identity: RecordIdentity {
            key: pristine[16..48].try_into().expect("a key"),
            allocation: u64_at(&pristine, 48),
            session,
            version: u64_at(&pristine, 64),
        },
        reader: session,
        index: 0,
        offset: 0,
        chunk_len: storage.record.chunk_len(),
        units: locator.len_units(),
        // A read covers its locator's record end rounded up to the device
        // block, the simulated device's one sector, within the extent.
        end: Some(
            locator
                .record_end()
                .next_multiple_of(SECTOR as u64)
                .min(pristine.len() as u64),
        ),
    };
    let mut image = mutate(pristine.clone(), expected.chunk_len);
    image.resize(pristine.len(), 0);
    dev.control.write_device(
        super::super::volume_fixture::device_byte(storage, locator),
        &image,
    );
    let op = dev.volume.read(lease.duplicate(), u64::MAX).unwrap();
    let delivered = drive(&mut dev.volume, &dev.control, op);
    drop(lease);
    settle(&mut dev.volume, &dev.control);
    (
        Judgment::of_read(delivered.status, delivered.bytes),
        image,
        expected,
    )
}

/// CRC-32C, bit by bit over the reflected Castagnoli polynomial.
pub(crate) fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                crc >> 1 ^ 0x82f6_3b78
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

pub(crate) fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"))
}

pub(crate) fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("eight bytes"))
}

/// The header bytes a record of `payload` payload bytes holds under
/// `chunk_len`-byte windows: 108 fixed bytes and a table of
/// `ceil(payload / chunk_len) + 1` entries, the most windows the payload
/// can overlap.
pub(crate) fn header_len(payload: u64, chunk_len: u32) -> u64 {
    FIXED as u64 + 4 * (payload.div_ceil(u64::from(chunk_len)) + 1)
}

/// Returns the CRC-32C of `first ++ second`, given their CRC-32Cs `a` and `b`
/// and the length `len` of `second`.
fn crc32c_combine(a: u32, b: u32, len: u64) -> u32 {
    if len == 0 {
        return a;
    }
    oracle_advance(a, len) ^ b
}

/// The header crc32c of `header`, its crc field read as zero.
fn sealed_crc(header: &[u8]) -> u32 {
    let mut zeroed = header.to_vec();
    zeroed[12..16].fill(0);
    crc32c(&zeroed)
}

/// Payload bytes one extent of an object covers, from the format's
/// documentation: 248 KiB.
pub(crate) const EXTENT_BYTES: u64 = 253_952;

/// The largest object payload the format admits, metadata plus body:
/// 512 MiB.
const OBJECT_BYTES: u64 = 536_870_912;

/// The payload bytes extent `index` of an object of `metadata_len` and
/// `body_len` bytes covers, or `None` when the object passes 512 MiB or
/// holds no extent `index`. An object of `L` bytes holds `max(1,
/// ceil(L / 248 KiB))` extents, extent `i` covering `[i * 248 KiB,
/// min((i + 1) * 248 KiB, L))`.
pub(crate) fn coverage(metadata_len: u32, body_len: u32, index: u32) -> Option<u64> {
    let len = u64::from(metadata_len) + u64::from(body_len);
    let extents = len.div_ceil(EXTENT_BYTES).max(1);
    if len > OBJECT_BYTES || u64::from(index) >= extents {
        return None;
    }
    let start = u64::from(index) * EXTENT_BYTES;
    Some((start + EXTENT_BYTES).min(len) - start)
}

/// The payload the fixed fields at the start of `fixed`, at least 108
/// bytes, claim for their record: the [`coverage`] of the extent their
/// index field names, or the whole metadata and body when [`coverage`]
/// returns `None`.
pub(crate) fn claimed_payload(fixed: &[u8]) -> u64 {
    let (metadata_len, body_len) = (u32_at(fixed, 72), u32_at(fixed, 76));
    coverage(metadata_len, body_len, u32_at(fixed, 88))
        .unwrap_or(u64::from(metadata_len) + u64::from(body_len))
}

/// A header the literal parser accepted: its header bytes, the record
/// end, the chunk length, the index of the window holding the first
/// payload byte, and the chunk count.
struct Accepted {
    header: usize,
    end: u64,
    window: u64,
    first: u64,
    count: u64,
}

impl Accepted {
    /// The record bytes chunk `index` covers.
    fn chunk(&self, index: u64) -> std::ops::Range<u64> {
        let start = ((self.first + index) * self.window).max(self.header as u64);
        start..((self.first + index + 1) * self.window).min(self.end)
    }

    /// The crc32c the table at the start of `bytes` records for chunk
    /// `index`.
    fn stored(&self, bytes: &[u8], index: u64) -> u32 {
        u32_at(bytes, FIXED + 4 * index as usize)
    }
}

/// The reference reader checks, in order, the magic and version, the
/// other fixed fields, the lengths against an extent at the expected index
/// and against the extent's units, the verified length against its
/// coverage, the chunk parameters, for a read of a one-extent object the
/// lengths against the record end it covers and against one extent, the
/// derived header, its crc32c, the identity fields against the expected
/// identity, the session against `expected.reader`, the extent index and
/// offset, the context crc over the context fields and the table's chunk
/// crcs, then each chunk in order. A chunk the image ends inside fails.
pub(crate) fn literal(bytes: &[u8], expected: &Expected) -> Judgment {
    let accepted = match literal_header(bytes, expected, Some(expected.reader)) {
        Ok(accepted) => accepted,
        Err(mismatch) => return Judgment::refused(mismatch),
    };
    let mut exposed = Vec::new();
    for index in 0..accepted.count {
        let range = accepted.chunk(index);
        let (start, stop) = (range.start as usize, range.end as usize);
        let chunk = bytes.get(start..stop.min(bytes.len())).unwrap_or(&[]);
        let whole = stop <= bytes.len();
        if !whole || crc32c(chunk) != accepted.stored(bytes, index) {
            return Judgment {
                header: Ok(()),
                chunk: Some(index as u32),
                exposed,
                other: None,
            };
        }
        exposed.extend_from_slice(chunk);
    }
    Judgment {
        header: Ok(()),
        chunk: None,
        exposed,
        other: None,
    }
}

/// The header checks of [`literal`], in its order.
fn literal_header(
    bytes: &[u8],
    expected: &Expected,
    reader: Option<u64>,
) -> Result<Accepted, HeaderMismatch> {
    let (units, chunk) = (expected.units, expected.chunk_len);
    let truncated = HeaderMismatch::Truncated {
        len: bytes.len(),
        needed: FIXED,
    };
    if bytes.len() < 12 {
        return Err(truncated);
    }
    let magic = u64_at(bytes, 0);
    if magic != u64::from_le_bytes(*b"IMGCREC1") {
        return Err(HeaderMismatch::Magic { found: magic });
    }
    let version = u32_at(bytes, 8);
    if version != 3 {
        return Err(HeaderMismatch::Version { found: version });
    }
    if bytes.len() < FIXED {
        return Err(truncated);
    }
    let (metadata_len, body_len) = (u32_at(bytes, 72), u32_at(bytes, 76));
    let lengths = HeaderMismatch::Lengths {
        metadata_len,
        body_len,
    };
    let payload = coverage(metadata_len, body_len, expected.index).ok_or(lengths)?;
    let header = header_len(payload, chunk);
    if (header + payload).div_ceil(IO_UNIT as u64) != u64::from(units) {
        return Err(lengths);
    }
    let extent_len = u32_at(bytes, 92);
    if u64::from(extent_len) != payload {
        return Err(HeaderMismatch::ExtentLength {
            expected: payload,
            found: extent_len,
        });
    }
    let window = u64::from(chunk);
    let first = header / window;
    let count = if payload == 0 {
        0
    } else {
        (header + payload - 1) / window - first + 1
    };
    let (chunk_len, chunk_count) = (u32_at(bytes, 80), u32_at(bytes, 84));
    if (u64::from(chunk_len), u64::from(chunk_count)) != (window, count) {
        return Err(HeaderMismatch::ChunkParameters {
            chunk_len,
            chunk_count,
        });
    }
    let whole = u64::from(metadata_len) + u64::from(body_len);
    if expected
        .end
        .is_some_and(|end| header + payload > end || whole > EXTENT_BYTES)
    {
        return Err(lengths);
    }
    let header = header as usize;
    if bytes.len() < header {
        return Err(HeaderMismatch::Truncated {
            len: bytes.len(),
            needed: header,
        });
    }
    let (stored, computed) = (u32_at(bytes, 12), sealed_crc(&bytes[..header]));
    if stored != computed {
        return Err(HeaderMismatch::HeaderCrc { stored, computed });
    }
    let identity = expected.identity;
    if bytes[16..48] != identity.key {
        return Err(HeaderMismatch::Key);
    }
    let allocation = u64_at(bytes, 48);
    if allocation != identity.allocation {
        return Err(HeaderMismatch::Allocation {
            expected: identity.allocation,
            found: allocation,
        });
    }
    let session = u64_at(bytes, 56);
    if session != identity.session {
        return Err(HeaderMismatch::Session {
            expected: identity.session,
            found: session,
        });
    }
    let version = u64_at(bytes, 64);
    if version != identity.version {
        return Err(HeaderMismatch::CacheVersion {
            expected: identity.version,
            found: version,
        });
    }
    // A reader of generation `g` and epoch `e` reads a session of
    // generation `g` whose epoch is even, nonzero and at most `e`.
    if let Some(reader) = reader {
        let epoch = session & 0xFFFF_FFFF;
        let readable = session >> 32 == reader >> 32
            && epoch.is_multiple_of(2)
            && epoch != 0
            && epoch <= reader & 0xFFFF_FFFF;
        if !readable {
            return Err(HeaderMismatch::ForeignSession {
                found: session,
                reader,
            });
        }
    }
    let index = u32_at(bytes, 88);
    if index != expected.index {
        return Err(HeaderMismatch::ExtentIndex {
            expected: expected.index,
            found: index,
        });
    }
    let offset = u64_at(bytes, 96);
    if offset != expected.offset {
        return Err(HeaderMismatch::Offset {
            expected: expected.offset,
            found: offset,
        });
    }
    let accepted = Accepted {
        header,
        end: header as u64 + payload,
        window,
        first,
        count,
    };
    let context = [&bytes[8..12], &bytes[16..80], &bytes[88..104]].concat();
    let mut bound = crc32c(&context);
    for index in 0..count {
        let range = accepted.chunk(index);
        bound = crc32c_combine(
            bound,
            accepted.stored(bytes, index),
            range.end - range.start,
        );
    }
    let stored = u32_at(bytes, 104);
    if stored != bound {
        return Err(HeaderMismatch::ContextCrc {
            stored,
            computed: bound,
        });
    }
    Ok(accepted)
}

/// What a header claims about itself once it verified against its own
/// lengths, identity and position: the whole lengths, its extent's
/// payload, chunk length and count, its header bytes, the identity it
/// names, its header crc32c and each chunk's table crc32c.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Claim {
    pub(crate) lengths: (u32, u32),
    pub(crate) payload: u64,
    pub(crate) chunk_len: u32,
    pub(crate) chunk_count: u32,
    pub(crate) header: usize,
    pub(crate) identity: RecordIdentity,
    pub(crate) header_crc: u32,
    pub(crate) chunk_crcs: Vec<u32>,
}

/// The claim `claim_header` returns for `bytes` under `chunk_len`-byte
/// windows, projected onto [`Claim`], or its refusal.
pub(crate) fn claimed(bytes: &[u8], chunk_len: u32) -> Result<Claim, HeaderMismatch> {
    let config = RecordConfig { chunk_len }
        .validate()
        .expect("an admitted chunk length");
    let claim = claim_header(Crc32c::detect(), &config, bytes)?;
    let layout = claim.layout;
    Ok(Claim {
        lengths: (layout.metadata_len(), layout.body_len()),
        payload: layout.payload_len(),
        chunk_len: layout.chunk_len(),
        chunk_count: layout.chunk_count(),
        header: layout.header_bytes(),
        identity: claim.identity,
        header_crc: claim.header_crc,
        chunk_crcs: (0..layout.chunk_count())
            .map(|index| claim.verified.chunk_crc(index))
            .collect(),
    })
}

/// The literal parser's [`Claim`] for `bytes` under `chunk_len`-byte
/// windows: [`literal`]'s header checks against the identity, extent
/// index and offset the header names and the units its own lengths derive
/// for that extent, so the checks that can fail are truncation, magic,
/// version, lengths [`coverage`] refuses for that extent, the verified
/// length, the chunk parameters, the header crc and the context crc.
pub(crate) fn literal_claim(bytes: &[u8], chunk_len: u32) -> Result<Claim, HeaderMismatch> {
    // Below `FIXED` bytes the parser refuses before it reads an expected field,
    // so zeros stand in for the missing ones.
    let fixed = fixed_fields(bytes);
    let payload = claimed_payload(&fixed);
    let session = u64_at(&fixed, 56);
    let expected = Expected {
        identity: RecordIdentity {
            key: fixed[16..48].try_into().expect("a key"),
            allocation: u64_at(&fixed, 48),
            session,
            version: u64_at(&fixed, 64),
        },
        reader: session,
        index: u32_at(&fixed, 88),
        offset: u64_at(&fixed, 96),
        chunk_len,
        units: (header_len(payload, chunk_len) + payload).div_ceil(IO_UNIT as u64) as u32,
        end: None,
    };
    let accepted = literal_header(bytes, &expected, None)?;
    Ok(Claim {
        lengths: (u32_at(&fixed, 72), u32_at(&fixed, 76)),
        payload: accepted.end - accepted.header as u64,
        chunk_len,
        chunk_count: accepted.count as u32,
        header: accepted.header,
        identity: expected.identity,
        header_crc: u32_at(bytes, 12),
        chunk_crcs: (0..accepted.count)
            .map(|index| accepted.stored(bytes, index))
            .collect(),
    })
}

pub(crate) fn fixed_fields(bytes: &[u8]) -> [u8; FIXED] {
    let mut fixed = [0; FIXED];
    let present = bytes.len().min(FIXED);
    fixed[..present].copy_from_slice(&bytes[..present]);
    fixed
}

/// The standalone record `ops` make from the valid one; see [`apply`].
pub(crate) fn mutated(reseal: bool, ops: &[u8]) -> Option<Vec<u8>> {
    apply(valid().1, reseal, ops, CHUNK_LEN)
}

/// The record `ops` make from `bytes`, a record under `chunk_len`-byte
/// windows, or `None` for more ops than the bound; a trailing partial op
/// is ignored. With `reseal` set, a result that holds its `FIXED` fixed bytes
/// and the header they claim, sized by [`claimed_payload`], takes a fresh
/// header crc32c over that header.
/// Each op names its family in its first byte: a fixed-field byte, a `u32`
/// field, the first byte of one of the eight four-byte slots after the
/// fixed fields (chunk-table entries, then payload), any image byte, a
/// truncation, an identity byte, an extension, or a magic byte.
pub(crate) fn apply(
    mut bytes: Vec<u8>,
    reseal: bool,
    ops: &[u8],
    chunk_len: u32,
) -> Option<Vec<u8>> {
    let chunks = ops.as_chunks::<4>().0;
    if chunks.len() > MAX_OPS {
        return None;
    }
    let fields = [8, 12, 72, 76, 80, 84, 88, 92, 96, 104];
    for &[op, a, b, c] in chunks {
        let len = bytes.len();
        match op % 8 {
            0 if len > 0 => {
                let at = usize::from(a) % FIXED.min(len);
                bytes[at] = b;
            }
            1 => {
                let at = fields[usize::from(a) % fields.len()];
                if at + 4 <= len {
                    let old = u32_at(&bytes, at);
                    let new = if c & 1 == 1 {
                        u32::from(b) * u32::from(c)
                    } else {
                        old.wrapping_add(i32::from(b as i8) as u32)
                    };
                    bytes[at..at + 4].copy_from_slice(&new.to_le_bytes());
                }
            }
            2 => {
                let at = FIXED + 4 * (usize::from(a) % 8);
                if at < len {
                    bytes[at] ^= b | 1;
                }
            }
            3 if len > 0 => {
                let at = (usize::from(a) << 8 | usize::from(b)) * 7 % len;
                bytes[at] ^= c | 1;
            }
            4 => bytes.truncate((usize::from(a) << 8 | usize::from(b)) * 3 % (len + 1)),
            5 if len >= 72 => match a % 4 {
                0 => bytes[16 + usize::from(b) % 32] ^= c | 1,
                1 => bytes[48 + usize::from(b) % 8] ^= c | 1,
                2 => bytes[56 + usize::from(b) % 8] ^= c | 1,
                _ => bytes[64 + usize::from(b) % 8] ^= c | 1,
            },
            6 => bytes.extend(std::iter::repeat_n(b, usize::from(a))),
            7 if len >= 8 => bytes[usize::from(a) % 8] ^= b | 1,
            _ => {}
        }
    }
    if reseal && bytes.len() >= FIXED {
        let header = header_len(claimed_payload(&bytes), chunk_len) as usize;
        if header <= bytes.len() {
            let computed = sealed_crc(&bytes[..header]);
            bytes[12..16].copy_from_slice(&computed.to_le_bytes());
        }
    }
    Some(bytes)
}

/// A failure naming what the two judgments of `what` said.
pub(crate) fn disagree<T: std::fmt::Debug>(what: &str, ours: &T, theirs: &T) -> Class {
    Class::Failure {
        claim: format!("{what} judged {ours:?}; the literal parser {theirs:?}"),
        bundle: Vec::new(),
    }
}

/// The record target judged against [`key_first`], a control that fails
/// every input changing the key without a reseal; its failures replay and
/// minimize.
pub(crate) static RECORD_CONTROL: Target = Target {
    name: "record-control",
    run: |input| judge(input, key_first),
    seeds: Vec::new,
};

/// A reference with the wrong precedence: it checks the key before the
/// header crc32c.
pub(crate) fn key_first(bytes: &[u8], expected: &Expected) -> Judgment {
    if bytes.len() >= 48 && bytes[16..48] != expected.identity.key {
        return Judgment::refused(HeaderMismatch::Key);
    }
    literal(bytes, expected)
}

/// A reference that skips the offset check: it expects whatever offset the
/// header names.
pub(crate) fn offset_unchecked(bytes: &[u8], expected: &Expected) -> Judgment {
    let offset = bytes
        .get(96..104)
        .map_or(expected.offset, |_| u64_at(bytes, 96));
    literal(
        bytes,
        &Expected {
            offset,
            ..*expected
        },
    )
}

/// Judges one record input: header verification, `claim_header` and the
/// volume read its mode reaches must each agree with the literal parser,
/// and a scan with the literal scan.
fn record(input: &[u8]) -> Class {
    judge(input, literal)
}

/// [`record`] against the reference `reference`, which judges the
/// fixed-geometry modes; the claim and geometry modes judge against the
/// literal parser, and the scan modes against the literal scan.
pub(crate) fn judge(input: &[u8], reference: fn(&[u8], &Expected) -> Judgment) -> Class {
    if input.len() > MAX_INPUT {
        return Class::Invalid("the input passes its byte bound");
    }
    let [format, mode, ops @ ..] = input else {
        return Class::Invalid("the input holds fewer than its format and mode bytes");
    };
    if *format != FORMAT {
        return Class::Invalid("the input names another format");
    }
    match mode {
        0 | 1 => {}
        2 => return led(input, claim_mode(ops)),
        3 | 4 => return led(input, scan_mode(ops, *mode == 4)),
        5 | 6 => return led(input, geometry_mode(ops, *mode == 6)),
        _ => return Class::Unsupported(*mode),
    }
    let reseal = *mode == 1;
    let Some(bytes) = mutated(reseal, ops) else {
        return Class::Invalid("the ops pass their bound");
    };
    let base = standalone();
    for reader in ACCEPTING.into_iter().chain(REFUSING) {
        let expected = Expected { reader, ..base };
        let (ours, theirs) = (
            verified(&bytes, &expected),
            reference(&bytes, &expected).header,
        );
        if ours != theirs {
            let claim = format!(
                "header verification under reader {reader:#x} judged {ours:?}; the literal parser {theirs:?}"
            );
            return Class::Failure {
                claim,
                bundle: Vec::new(),
            };
        }
    }
    let (read, image, expected) = read_back(|pristine, chunk_len| {
        apply(pristine, reseal, ops, chunk_len).expect("ops the standalone record took")
    });
    let wanted = reference(&image, &expected);
    if read != wanted {
        return read_disagreement(&read, &wanted);
    }
    Class::Pass {
        run: read_bytes(input, 2),
    }
}

/// The bytes of `input` a run read: its `fixed` leading bytes and its whole
/// four-byte ops. A trailing partial op is ignored, so two inputs equal up
/// to it drive the same run.
pub(crate) fn read_bytes(input: &[u8], fixed: usize) -> Vec<u8> {
    let ops = input.len() - fixed;
    input[..input.len() - ops % 4].to_vec()
}

/// `class` with a pass's run led by the input's format and mode bytes,
/// which the mode's own judgment leaves out.
fn led(input: &[u8], class: Class) -> Class {
    match class {
        Class::Pass { run } => Class::Pass {
            run: [&input[..2], &run[..]].concat(),
        },
        other => other,
    }
}

/// The claim bounds fuzz-log output by reporting the payloads' lengths and
/// the first position they differ at.
pub(crate) fn read_disagreement(read: &Judgment, wanted: &Judgment) -> Class {
    let differs = read
        .exposed
        .iter()
        .zip(&wanted.exposed)
        .position(|(ours, theirs)| ours != theirs);
    Class::Failure {
        claim: format!(
            "the volume read ended {:?} chunk {:?} status {:?} delivering {} bytes; the literal parser {:?} chunk {:?} exposing {}; first differing byte {differs:?}",
            read.header,
            read.chunk,
            read.other,
            read.exposed.len(),
            wanted.header,
            wanted.chunk,
            wanted.exposed.len()
        ),
        bundle: Vec::new(),
    }
}

/// Seeds: the valid record and one mutation of each field family, each raw
/// and resealed, then the claim, geometry and scan modes' own.
pub(crate) fn seeds() -> Vec<(String, Vec<u8>)> {
    let mut seeds = fixed_seeds();
    seeds.extend(super::claim_fuzz_tests::seeds());
    seeds.extend(super::geometry_fuzz_tests::seeds());
    seeds.extend(super::scan_fuzz_tests::seeds());
    seeds
}

/// The fixed-geometry modes' seeds.
fn fixed_seeds() -> Vec<(String, Vec<u8>)> {
    let ops: [(&str, &[u8]); 16] = [
        ("valid", &[]),
        ("magic", &[7, 0, 1, 0]),
        ("lengths", &[1, 3, 40, 1]),
        ("extent-length", &[1, 7, 1, 0]),
        ("chunk-count", &[1, 5, 1, 0]),
        ("key", &[5, 0, 4, 1]),
        ("cache-version", &[5, 3, 2, 1]),
        ("extent-index", &[1, 6, 1, 0]),
        ("offset", &[1, 8, 1, 0]),
        ("context", &[1, 9, 1, 0]),
        ("payload", &[3, 0, 100, 1]),
        ("fixed-truncation", &[4, 0, 20, 0]),
        ("derived-truncation", &[4, 0, 37, 0]),
        ("chunk-truncation", &[4, 0, 42, 0]),
        ("table", &[2, 1, 1, 0]),
        ("record-end", &[0, 0x49, 2, 0, 1, 7, 136, 185]),
    ];
    ops.iter()
        .flat_map(|(name, ops)| {
            [0, 1].map(|mode| {
                let mut input = vec![FORMAT, mode];
                input.extend_from_slice(ops);
                (format!("{name}-{mode}.input"), input)
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    //! The record target's literal parser against header verification and
    //! the volume read on each rejection, its wrong-precedence control, the
    //! minimizer, and the two tail expectations.

    use super::*;

    /// The valid records judge whole: the standalone one verifies, and the
    /// published one reads back its every payload byte; every seed agrees.
    #[test]
    fn every_seed_agrees_and_the_valid_records_are_whole() {
        let (_, bytes) = valid();
        let expected = standalone();
        assert_eq!(verified(&bytes, &expected), Ok(()));
        assert_eq!(literal(&bytes, &expected).header, Ok(()));
        let (read, image, expected) = read_back(|image, _| image);
        assert_eq!((read.header, read.chunk), (Ok(()), None));
        assert_eq!(read.exposed, content(PUBLISHED, 3));
        assert_eq!(read, literal(&image, &expected));
        for (name, input) in seeds() {
            let class = (RECORD.run)(&input);
            if input[1] == 2 {
                assert!(
                    matches!(&class, Class::Pass { run } if input.starts_with(run)),
                    "{name}"
                );
                continue;
            }
            let whole = Class::Pass { run: input.clone() };
            assert_eq!(class, whole, "{name}");
            let mut partial = input.clone();
            partial.extend([9, 9, 9]);
            assert_eq!((RECORD.run)(&partial), whole, "{name} with a partial op");
        }
    }

    /// Header verification reaches each documented rejection in order,
    /// fixed-field and derived truncation included, naming the literal
    /// parser's first failure with its fields.
    #[test]
    fn header_verification_reaches_each_rejection_in_order() {
        let expected = standalone();
        let header = valid().0.header_bytes();
        let cases: [(bool, &[u8], &str); 15] = [
            (false, &[4, 0, 20, 0], "Truncated { len: 60, needed: 108 }"),
            (false, &[7, 0, 1, 0], "Magic"),
            (true, &[0, 8, 1, 0], "Version"),
            (true, &[1, 3, 40, 1], "Lengths"),
            (true, &[1, 7, 1, 0], "ExtentLength"),
            (true, &[1, 4, 1, 0], "ChunkParameters"),
            (true, &[4, 0, 37, 0], "Truncated { len: 111"),
            (false, &[5, 0, 4, 1], "HeaderCrc"),
            (true, &[5, 0, 4, 1], "Key"),
            (true, &[5, 1, 2, 1], "Allocation"),
            (true, &[5, 2, 2, 1], "Session"),
            (true, &[5, 3, 2, 1], "CacheVersion"),
            (true, &[1, 6, 1, 0], "ExtentIndex"),
            (true, &[1, 8, 1, 0], "Offset"),
            (true, &[1, 9, 1, 0], "ContextCrc"),
        ];
        assert_eq!(
            header, 124,
            "the derived-truncation case cuts inside the table"
        );
        for (reseal, ops, named) in cases {
            let bytes = mutated(reseal, ops).unwrap();
            let ours = verified(&bytes, &expected);
            assert_eq!(ours, literal(&bytes, &expected).header, "{named}");
            let said = format!("{:?}", ours.expect_err(named));
            assert!(said.starts_with(named), "{named}: {said}");
        }
        let (_, bytes) = valid();
        for reader in &REFUSING {
            let expected = Expected {
                reader: *reader,
                ..expected
            };
            let ours = verified(&bytes, &expected);
            assert_eq!(ours, literal(&bytes, &expected).header, "{reader:#x}");
            assert_eq!(
                ours,
                Err(HeaderMismatch::ForeignSession {
                    found: IDENTITY.session,
                    reader: *reader
                }),
                "{reader:#x}"
            );
        }
    }

    /// The volume read delivers no byte after an identity failure, a wrong
    /// extent index or offset, or a header whose lengths moved: a resealed
    /// claim that grows within the sector its locator's record ends in,
    /// verified length included, fails the context crc that binds those
    /// lengths, and a claim one byte past that sector fails its lengths. The
    /// read delivers exactly the chunks before a
    /// damaged one and the whole payload otherwise, as the literal parser
    /// says, its status included.
    #[test]
    fn the_volume_read_exposes_only_what_verified() {
        let cases: [(bool, &[u8], Option<u32>, usize); 17] = [
            (true, &[5, 0, 4, 1], None, 0),
            (true, &[5, 1, 2, 1], None, 0),
            (true, &[5, 2, 2, 1], None, 0),
            (true, &[5, 3, 2, 1], None, 0),
            (false, &[3, 0, 20, 1], Some(0), 0),
            (true, &[0, 0x49, 2, 0, 1, 7, 136, 185], None, 0),
            (true, &[1, 3, 1, 0, 1, 7, 1, 0], None, 0),
            (true, &[1, 3, 0x28, 0, 1, 7, 0x28, 0], None, 0),
            (true, &[1, 3, 1, 0], None, 0),
            (false, &[1, 3, 1, 0, 1, 7, 1, 0], None, 0),
            (
                true,
                &[
                    1, 3, 104, 0, 1, 3, 104, 0, 1, 3, 104, 0, 1, 7, 104, 0, 1, 7, 104, 0, 1, 7,
                    104, 0,
                ],
                None,
                0,
            ),
            (
                true,
                &[
                    1, 3, 104, 0, 1, 3, 104, 0, 1, 3, 104, 0, 1, 3, 1, 0, 1, 7, 104, 0, 1, 7, 104,
                    0, 1, 7, 104, 0, 1, 7, 1, 0,
                ],
                None,
                0,
            ),
            (true, &[1, 6, 1, 0], None, 0),
            (true, &[1, 8, 1, 0], None, 0),
            (false, &[3, 4, 160, 1], Some(1), 8192 - 128),
            (false, &[3, 9, 200, 1], Some(2), 2 * 8192 - 128),
            (true, &[], None, PUBLISHED),
        ];
        for (reseal, ops, chunk, exposed) in cases {
            let (read, image, expected) =
                read_back(|image, chunk_len| apply(image, reseal, ops, chunk_len).unwrap());
            assert_eq!(read, literal(&image, &expected), "{ops:?}");
            assert_eq!(
                (read.chunk, read.exposed.len()),
                (chunk, exposed),
                "{ops:?}"
            );
            assert_eq!(read.exposed, content(PUBLISHED, 3)[..exposed], "{ops:?}");
        }
        // A resealed claim one byte longer, its verified length moved with
        // it, passes every length check and fails at the context crc.
        let grown: &[u8] = &[1, 3, 1, 0, 1, 7, 1, 0];
        let (read, _, _) =
            read_back(|image, chunk_len| apply(image, true, grown, chunk_len).unwrap());
        assert!(
            matches!(read.header, Err(HeaderMismatch::ContextCrc { .. })),
            "{:?}",
            read.header
        );
    }

    /// A read that ends other than complete or with a mismatch never
    /// judges equal to the literal parser, even with every byte delivered.
    #[test]
    fn an_unfinished_read_never_matches_a_verdict() {
        let (_, image, expected) = read_back(|image, _| image);
        let whole = literal(&image, &expected);
        for status in [
            ReadStatus::Short,
            ReadStatus::DeviceError,
            ReadStatus::TimedOut,
        ] {
            let read = Judgment::of_read(status, whole.exposed.clone());
            assert_eq!(read.other, Some(status));
            assert_ne!(read, whole, "{status:?}");
        }
    }

    /// A reference that checks the key before the header crc32c disagrees
    /// with header verification on a key changed without a reseal, so the
    /// judge fails it; the documented order passes the same input.
    #[test]
    fn a_wrong_precedence_reference_fails_the_judge() {
        let input = [FORMAT, 0, 5, 0, 4, 1];
        assert!(matches!(
            (RECORD_CONTROL.run)(&input),
            Class::Failure { .. }
        ));
        assert_eq!(
            judge(&input, literal),
            Class::Pass {
                run: input.to_vec()
            }
        );
    }

    /// A failing input minimizes to its cause: the payload changes around
    /// it removed, one op is left, the unsealed key change, failing with
    /// the same claim.
    #[test]
    fn a_failing_input_minimizes_to_its_cause() {
        let input = [
            FORMAT, 0, 3, 9, 200, 1, 5, 0, 4, 1, 3, 4, 160, 1, 3, 0, 20, 1,
        ];
        let Class::Failure { claim, .. } = (RECORD_CONTROL.run)(&input) else {
            panic!("the control did not fail");
        };
        let (smallest, kept) = crate::sim::fuzz::minimized(&RECORD_CONTROL, &input).unwrap();
        assert_eq!(
            (smallest.len(), &smallest[..5], kept),
            (6, &[FORMAT, 0, 5, 0, 4][..], claim)
        );
        assert!(crate::sim::fuzz::minimized(&RECORD, &input).is_none());
    }

    /// The producer writes a zero tail: sealing over a header buffer full
    /// of stale bytes zeroes every chunk-table entry past the chunk count.
    #[test]
    fn the_producer_seals_a_zero_tail() {
        let (layout, _) = valid();
        let mut header = vec![0xee; layout.header_bytes()];
        seal_header(
            Crc32c::detect(),
            &layout,
            &IDENTITY,
            ExtentPosition::FIRST,
            &mut header,
        );
        let tail = FIXED + 4 * layout.chunk_count() as usize;
        assert!(tail < header.len());
        assert!(header[tail..].iter().all(|&byte| byte == 0));
        assert_eq!(u64_at(&header, 0), HEADER_MAGIC);
        assert_eq!(u32_at(&header, 8), HEADER_VERSION);
    }

    /// The reader accepts a valid-crc nonzero tail: a tail entry changed
    /// and resealed verifies, and the published record with such a tail
    /// reads back whole, as the literal parser, which reads no tail entry,
    /// agrees. The reader's acceptance stands apart from the producer's
    /// zero tail; the same change unsealed fails its crc32c.
    #[test]
    fn the_reader_accepts_a_resealed_nonzero_tail() {
        let (layout, _) = valid();
        let expected = standalone();
        let tail = [2, layout.chunk_count() as u8, 0x40, 0];
        assert_eq!(verified(&mutated(true, &tail).unwrap(), &expected), Ok(()));
        let raw = verified(&mutated(false, &tail).unwrap(), &expected);
        assert!(matches!(raw, Err(HeaderMismatch::HeaderCrc { .. })));
        let published = [2, 4, 0x40, 0];
        let (read, image, expected) =
            read_back(|image, chunk_len| apply(image, true, &published, chunk_len).unwrap());
        assert_ne!(u32_at(&image, FIXED + 4 * 4), 0, "a nonzero tail entry");
        assert_eq!(
            (read.header, read.chunk, read.exposed.len()),
            (Ok(()), None, PUBLISHED)
        );
        assert_eq!(read, literal(&image, &expected));
    }

    #[test]
    fn a_read_disagreement_names_the_lengths_and_the_first_differing_byte() {
        let read = Judgment {
            header: Ok(()),
            chunk: None,
            exposed: vec![0x5a; 65_536],
            other: None,
        };
        let wanted = Judgment {
            chunk: Some(1),
            exposed: Vec::new(),
            ..read.clone()
        };
        let Class::Failure { claim, .. } = read_disagreement(&read, &wanted) else {
            panic!("a disagreement is a failure");
        };
        assert!(claim.len() < 1024, "claim of {} bytes", claim.len());
        assert!(claim.contains("delivering 65536 bytes"), "{claim}");
        assert!(claim.contains("exposing 0"), "{claim}");
        assert!(claim.contains("first differing byte None"), "{claim}");
        let mut flipped = read.clone();
        flipped.exposed[7] ^= 1;
        let Class::Failure { claim, .. } = read_disagreement(&read, &flipped) else {
            panic!("a disagreement is a failure");
        };
        assert!(claim.len() < 1024, "claim of {} bytes", claim.len());
        assert!(claim.contains("first differing byte Some(7)"), "{claim}");
    }

    /// The literal crc32c is CRC-32C: the standard check value, and the
    /// reader's checksum of the record.
    #[test]
    fn the_literal_crc_is_crc32c() {
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
        let (_, bytes) = valid();
        assert_eq!(crc32c(&bytes), Crc32c::detect().checksum(&bytes));
    }
}
