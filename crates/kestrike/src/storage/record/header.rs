//! The record header: its byte layout, its encoding and its verification.
//!
//! The header is an extent's local header: it binds the extent's payload to the object and to the extent's place in it.
//! Layout, little-endian at fixed offsets: magic `u64` at 0, version `u32` at 8, header crc32c `u32` at 12, key at 16 (32 bytes), allocation `u64` at 48 (the slot index in its high 32 bits and the slot's incarnation in its low 32 bits), session `u64` at 56, the object's cache version `u64` at 64, the whole object's `metadata_len` `u32` at 72 and `body_len` `u32` at 76, `chunk_len` `u32` at 80, `chunk_count` `u32` at 84, the extent's index `u32` at 88, its verified payload length `u32` at 92, its absolute payload offset `u64` at 96, the context crc32c `u32` at 104, then one crc32c `u32` per payload chunk from 108.
//! The chunk table holds `ceil(payload_len / chunk_len) + 1` entries, one crc32c per payload chunk and zeros past the chunk count, and the payload starts at the byte after it.
//! Chunk crcs cover payload bytes alone, so window and wire crcs derive from them by linearity. The context crc32c is the crc32c of the extent's context, the version, key, allocation, session, cache version, both whole lengths, the index, the verified length and the offset in that order, followed by its payload, combined from the context's crc and the chunk table's crcs. It binds the chunk table to those fields: a header resealed with a changed context field and its old context crc, and otherwise matching the reader's expectation, fails [`HeaderMismatch::ContextCrc`], and each chunk's bytes are bound by its own table entry.
//! Each extent's verified length is its coverage of the whole payload, all of it for an object of one extent, whose position is [`ExtentPosition::FIRST`]; a fill writes and a read expects each extent's own index, offset and coverage of the whole lengths.
//! The header crc32c covers the encoded header with its own field read as zero.
//! Only version 3 is written or accepted; a header with the record magic and any other version fails at [`HeaderMismatch::Version`] whatever its length past the version field.
//!
//! Verification checks, in order: the magic and the version are present and match, the other fixed fields are present, the whole lengths against any an earlier extent verified and against an extent at the expected index, whose derived header and payload must fill exactly the extent's units, the verified length against that extent's coverage, the chunk parameters, for a device read the lengths against the record end the read covers and the read's extent count, the header bytes those lengths derive are present, the header crc over them, then the identity through the read predicate (key, allocation, session, cache version, and the session against the reader's), the extent index, the offset and the context crc, and names the first failure.
//! The crc span follows the header's own lengths only after they matched the extent's unit count and the chunk parameters matched them, so a corrupted length must also produce a matching crc over the moved span to pass.
//! The header is the one source of a record's lengths and checksums: [`ValidRecordConfig::claimed_layout`] derives the layout from its fixed fields, and a device read folds the header crc over the span they claim before [`check_header`].
//! On volume reads, [`check_header`] verifies identity through the read predicate, extent position, and context crc before payload bytes are checked or exposed. Chunk verification requires the returned [`VerifiedHeader`].
//! [`feed_header`] folds any in-order tiling of the header into one crc, so a caller can spread the header crc across bounded steps and pass the finished value to [`check_header`].

use std::ops::Range;

use super::super::geometry::{OBJECT_LIMIT, extent_count, extent_span};
use super::super::layout::IO_UNIT;
use super::crc32c::{Chunks, Crc32c, RunningCrc, register_after};
use super::layout::{CHUNK_TABLE, CRC_BYTES, RecordLayout, ValidRecordConfig};
use super::predicate::accepts;

/// Identifies a record header: `"IMGCREC1"` read little-endian.
pub(super) const HEADER_MAGIC: u64 = u64::from_le_bytes(*b"IMGCREC1");

/// The only header version this code writes or accepts.
pub(super) const HEADER_VERSION: u32 = 3;

/// The crc32c register after [`HEADER_VERSION`]'s bytes from the initial register, where the context crc starts: [`seal_header`] writes that version, and `claimed_layout` accepts a header only at that version.
const VERSION_REGISTER: u32 = register_after(!0, &HEADER_VERSION.to_le_bytes());

pub(super) const MAGIC: usize = 0;
pub(super) const VERSION: usize = 8;
pub(super) const HEADER_CRC: usize = 12;
pub(super) const KEY: usize = 16;
pub(super) const ALLOCATION: usize = 48;
pub(super) const SESSION: usize = 56;
pub(super) const CACHE_VERSION: usize = 64;
pub(super) const METADATA_LEN: usize = 72;
pub(super) const BODY_LEN: usize = 76;
pub(super) const CHUNK_LEN: usize = 80;
pub(super) const CHUNK_COUNT: usize = 84;
pub(super) const EXTENT_INDEX: usize = 88;
pub(super) const EXTENT_LEN: usize = 92;
pub(super) const OFFSET: usize = 96;
pub(super) const CONTEXT_CRC: usize = 104;

// The context crc covers three runs of adjacent fields, so each run must
// start and end where an excluded field ends and begins, and the chunk
// table starts right after the context crc.
const _: () = assert!(CHUNK_LEN == BODY_LEN + 4 && CONTEXT_CRC == OFFSET + 8);
const _: () = assert!(HEADER_CRC == VERSION + 4 && KEY == HEADER_CRC + 4);
const _: () = assert!(EXTENT_INDEX == CHUNK_COUNT + 4);
const _: () = assert!(CHUNK_TABLE == CONTEXT_CRC + 4);
const _: () =
    assert!((CHUNK_LEN - KEY).is_multiple_of(8) && (CONTEXT_CRC - EXTENT_INDEX).is_multiple_of(8));

/// Who a record belongs to: the object's key, its allocation, the session `g·2^32 + a` of the tenure that wrote it and the object's cache version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordIdentity {
    pub key: [u8; 32],
    /// The slot index in the high 32 bits and the slot's incarnation in the low 32 bits.
    /// Each slot counts its own incarnations, so the slot is what tells apart two records of one key and incarnation.
    pub allocation: u64,
    pub session: u64,
    /// The client's per-key version of the object's source.
    pub version: u64,
}

/// Where an extent lies in its object: its index and the absolute payload offset of its first byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExtentPosition {
    pub index: u32,
    pub offset: u64,
}

impl ExtentPosition {
    /// The first extent, at payload offset zero: the sole extent of a one-extent object.
    pub(crate) const FIRST: Self = Self {
        index: 0,
        offset: 0,
    };
}

/// What a reader expects of a header: the identity its index entry names, the reader's own session, the extent's place in its object, the units of the extent it read, and the whole object's `metadata_len` and `body_len` once an earlier extent's header verified them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExpectedHeader {
    pub identity: RecordIdentity,
    /// The reader's session `g·2^32 + a`, against which the read predicate checks the header's session.
    pub reader: u64,
    pub position: ExtentPosition,
    pub len_units: u32,
    pub lengths: Option<(u32, u32)>,
}

/// Encoding refused; the record is unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EncodeError {
    /// The record is shorter than its header plus payload.
    Buffer { needed: u64, len: usize },
}

/// The first header check that failed, in the module's verification order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderMismatch {
    /// The bytes end before the fixed fields or before the header their lengths derive.
    Truncated {
        len: usize,
        needed: usize,
    },
    Magic {
        found: u64,
    },
    Version {
        found: u32,
    },
    /// The whole lengths differ from those an earlier extent's header verified, pass the 512 MiB object limit or name no extent at the expected index, derive a header and payload that fill other than exactly the extent's units, or, for a device read, end past the bytes the read covers or name another extent count than the read's.
    Lengths {
        metadata_len: u32,
        body_len: u32,
    },
    /// The verified length is not the payload length the whole lengths give the extent at the expected index.
    ExtentLength {
        expected: u64,
        found: u32,
    },
    /// The chunk length is not the configured one, or the chunk count is not the one the lengths derive.
    ChunkParameters {
        chunk_len: u32,
        chunk_count: u32,
    },
    HeaderCrc {
        stored: u32,
        computed: u32,
    },
    Key,
    /// The allocation word differs from the index entry's.
    Allocation {
        expected: u64,
        found: u64,
    },
    /// The session differs from the index entry's.
    Session {
        expected: u64,
        found: u64,
    },
    /// The cache version differs from the index entry's.
    CacheVersion {
        expected: u64,
        found: u64,
    },
    /// The header's identity equals the entry's, and its session has another generation than the reader's or an odd, zero or later epoch.
    ForeignSession {
        found: u64,
        reader: u64,
    },
    /// The extent index is not the one the reader expects.
    ExtentIndex {
        expected: u32,
        found: u32,
    },
    /// The absolute payload offset is not the one the reader expects.
    Offset {
        expected: u64,
        found: u64,
    },
    /// The stored context crc differs from the one computed from the header's context fields and chunk table.
    ContextCrc {
        stored: u32,
        computed: u32,
    },
}

/// Chunk `index` is out of range, has the wrong length, or its crc32c differs from the header's table.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChunkMismatch {
    pub index: u32,
}

/// A header with verified crcs, lengths and extent position, with its chunk table. [`claim_header`] performs these structural checks; [`check_header`] also applies the read predicate.
#[derive(Debug, Clone, Copy)]
pub(crate) struct VerifiedHeader<'a> {
    #[cfg(test)]
    layout: RecordLayout,
    table: &'a [u8],
}

/// Encodes the header of the extent at `position` of a record with `layout` and `identity` into the first `layout.header_bytes()` bytes of `record`, computing each chunk's crc32c over the payload that follows, and returns the header crc32c.
///
/// `record` starts at the record's first byte; no byte past the header changes.
///
/// # Errors
///
/// `Buffer` when `record` is shorter than `layout.record_len()`; `record` is unchanged.
pub(crate) fn encode_header(
    crc: Crc32c,
    layout: &RecordLayout,
    identity: &RecordIdentity,
    position: ExtentPosition,
    record: &mut [u8],
) -> Result<u32, EncodeError> {
    let (needed, len) = (layout.record_len(), record.len());
    if (len as u64) < needed {
        return Err(EncodeError::Buffer { needed, len });
    }
    let (header, payload) = record.split_at_mut(layout.header_bytes());
    for index in 0..layout.chunk_count() {
        let range = layout.chunks(index, index + 1);
        let chunk_crc = crc.checksum(&payload[range.start as usize..range.end as usize]);
        put_chunk_crc(header, index, chunk_crc);
    }
    Ok(seal_header(crc, layout, identity, position, header))
}

/// Stores chunk `index`'s crc32c in the chunk table of `header`, a record's first bytes through its header.
pub(crate) fn put_chunk_crc(header: &mut [u8], index: u32, chunk_crc: u32) {
    put(
        header,
        CHUNK_TABLE + index as usize * CRC_BYTES,
        &chunk_crc.to_le_bytes(),
    );
}

/// Writes every fixed field of the header of the extent at `position` of a record with `layout` and `identity` into `header`, its first `layout.header_bytes()` bytes, zeroes the chunk-table entries past `chunk_count`, stores the context crc32c over the fields and the table, and stores and returns the header crc32c.
///
/// The first `chunk_count` table entries are the caller's, written through [`put_chunk_crc`] before the call; every other header byte is written here, so the header holds nothing a previous use of the buffer left.
///
/// # Panics
///
/// If `header` is shorter than `layout.header_bytes()`, or the payload spans 4 GiB or more; storage configuration bounds every admitted object at `OBJECT_LIMIT`, 512 MiB.
pub(crate) fn seal_header(
    crc: Crc32c,
    layout: &RecordLayout,
    identity: &RecordIdentity,
    position: ExtentPosition,
    header: &mut [u8],
) -> u32 {
    let header = &mut header[..layout.header_bytes()];
    put(header, MAGIC, &HEADER_MAGIC.to_le_bytes());
    put(header, VERSION, &HEADER_VERSION.to_le_bytes());
    put(header, HEADER_CRC, &[0; CRC_BYTES]);
    put(header, KEY, &identity.key);
    put(header, ALLOCATION, &identity.allocation.to_le_bytes());
    put(header, SESSION, &identity.session.to_le_bytes());
    put(header, CACHE_VERSION, &identity.version.to_le_bytes());
    put(header, METADATA_LEN, &layout.metadata_len().to_le_bytes());
    put(header, BODY_LEN, &layout.body_len().to_le_bytes());
    put(header, CHUNK_LEN, &layout.chunk_len().to_le_bytes());
    put(header, CHUNK_COUNT, &layout.chunk_count().to_le_bytes());
    put(header, EXTENT_INDEX, &position.index.to_le_bytes());
    let extent_len = u32::try_from(layout.payload_len())
        .expect("configuration bounds every object's payload below 4 GiB");
    put(header, EXTENT_LEN, &extent_len.to_le_bytes());
    put(header, OFFSET, &position.offset.to_le_bytes());
    header[CHUNK_TABLE + layout.chunk_count() as usize * CRC_BYTES..].fill(0);
    put(
        header,
        CONTEXT_CRC,
        &context_crc(crc, layout, header).to_le_bytes(),
    );
    // The header crc32c covers the entire header with `HEADER_CRC` set to zero.
    let header_crc = crc.checksum(header);
    put(header, HEADER_CRC, &header_crc.to_le_bytes());
    header_crc
}

impl ValidRecordConfig {
    /// The layout the fixed fields of `bytes`, a header from its first byte, claim for extent `index` of `len_units` units: magic, version, then the whole lengths, which must equal `lengths` when the caller names them and must give the object an extent at `index`, whose coverage of the payload sizes the record and whose header and payload must fill exactly `len_units` units, then the verified length against that coverage, then the chunk parameters. The identity and the offset are [`check_header`]'s.
    /// A device read trusts nothing here until the header crc32c over the returned layout's `header_bytes()` verifies.
    ///
    /// # Errors
    ///
    /// `Truncated` when `bytes` ends before the magic and version or, once they match, before the other fixed fields, else the first failing check in this order.
    #[inline]
    pub(crate) fn claimed_layout(
        &self,
        bytes: &[u8],
        index: u32,
        len_units: u32,
        lengths: Option<(u32, u32)>,
    ) -> Result<RecordLayout, HeaderMismatch> {
        let truncated = HeaderMismatch::Truncated {
            len: bytes.len(),
            needed: CHUNK_TABLE,
        };
        // The magic and version come first, so a record of another version,
        // whatever its fixed fields' length, refuses at its version.
        let Some(start) = bytes.get(..HEADER_CRC) else {
            return Err(truncated);
        };
        let magic = u64::from_le_bytes(field(start, MAGIC));
        if magic != HEADER_MAGIC {
            return Err(HeaderMismatch::Magic { found: magic });
        }
        let version = read_u32(start, VERSION);
        if version != HEADER_VERSION {
            return Err(HeaderMismatch::Version { found: version });
        }
        let Some(fixed) = bytes.get(..CHUNK_TABLE) else {
            return Err(truncated);
        };
        let (metadata_len, body_len) = (read_u32(fixed, METADATA_LEN), read_u32(fixed, BODY_LEN));
        let mismatch = HeaderMismatch::Lengths {
            metadata_len,
            body_len,
        };
        if lengths.is_some_and(|known| known != (metadata_len, body_len)) {
            return Err(mismatch);
        }
        let Some(payload) = coverage(metadata_len, body_len, index) else {
            return Err(mismatch);
        };
        let layout = self.extent_layout(metadata_len, body_len, payload);
        if layout.record_units() != u64::from(len_units) {
            return Err(mismatch);
        }
        let extent_len = read_u32(fixed, EXTENT_LEN);
        if u64::from(extent_len) != layout.payload_len() {
            return Err(HeaderMismatch::ExtentLength {
                expected: layout.payload_len(),
                found: extent_len,
            });
        }
        let (chunk_len, chunk_count) = (read_u32(fixed, CHUNK_LEN), read_u32(fixed, CHUNK_COUNT));
        if (chunk_len, chunk_count) != (layout.chunk_len(), layout.chunk_count()) {
            return Err(HeaderMismatch::ChunkParameters {
                chunk_len,
                chunk_count,
            });
        }
        Ok(layout)
    }
}

#[cfg(test)]
impl RecordLayout {
    /// The layout of the record whose header starts `bytes` and fills an extent of `len_units` units: [`ValidRecordConfig::claimed_layout`], then the header crc32c over the derived header bytes.
    ///
    /// # Errors
    ///
    /// The first failing check of `claimed_layout`, then `Truncated` when `bytes` ends before the derived header, then `HeaderCrc`.
    pub(crate) fn from_header(
        crc: Crc32c,
        config: &ValidRecordConfig,
        bytes: &[u8],
        len_units: u32,
    ) -> Result<Self, HeaderMismatch> {
        let layout = config.claimed_layout(bytes, 0, len_units, None)?;
        let header = derived_header(bytes, &layout)?;
        crc_matches(header, header_crc(crc, header))?;
        Ok(layout)
    }
}

/// The key, session, `metadata_len` and `body_len` the fixed fields at the
/// start of `bytes` name, or `None` when `bytes` ends before them; a test
/// lens reads them before it verifies the header against them.
#[cfg(test)]
pub(crate) fn framing(bytes: &[u8]) -> Option<([u8; 32], u64, u32, u32)> {
    let fixed = bytes.get(..CHUNK_LEN)?;
    Some((
        field(fixed, KEY),
        u64::from_le_bytes(field(fixed, SESSION)),
        read_u32(fixed, METADATA_LEN),
        read_u32(fixed, BODY_LEN),
    ))
}

/// Verifies `bytes`, which start at the record's first byte, against `expected` under `config`.
///
/// # Errors
///
/// The first failing check in the module's order.
pub(crate) fn verify_header<'a>(
    crc: Crc32c,
    config: &ValidRecordConfig,
    bytes: &'a [u8],
    expected: &ExpectedHeader,
) -> Result<VerifiedHeader<'a>, HeaderMismatch> {
    let layout = config.claimed_layout(
        bytes,
        expected.position.index,
        expected.len_units,
        expected.lengths,
    )?;
    let computed = header_crc(crc, derived_header(bytes, &layout)?);
    check_header(crc, bytes, &layout, expected, computed)
}

/// `bytes` through the header `layout` derives.
///
/// # Errors
///
/// `Truncated` when `bytes` ends before it.
fn derived_header<'a>(bytes: &'a [u8], layout: &RecordLayout) -> Result<&'a [u8], HeaderMismatch> {
    let needed = layout.header_bytes();
    bytes.get(..needed).ok_or(HeaderMismatch::Truncated {
        len: bytes.len(),
        needed,
    })
}

/// Compares the crc32c `header` stores with `computed`.
///
/// # Errors
///
/// `HeaderCrc` when they differ.
fn crc_matches(header: &[u8], computed: u32) -> Result<(), HeaderMismatch> {
    let stored = read_u32(header, HEADER_CRC);
    if stored != computed {
        return Err(HeaderMismatch::HeaderCrc { stored, computed });
    }
    Ok(())
}

/// Checks the header at the start of `bytes`, whose fixed fields claimed `layout` and whose crc32c over `layout.header_bytes()` bytes, with its own field read as zero, is `computed`: the header crc, then its identity against `expected` through [`admits`], then the extent index, the offset and the context crc.
///
/// # Errors
///
/// `Truncated` when `bytes` ends before the header, else the first failing check, from `HeaderCrc` on; a refused identity names its first differing field, or `ForeignSession` when only the session's check against the reader failed.
pub(crate) fn check_header<'a>(
    crc: Crc32c,
    bytes: &'a [u8],
    layout: &RecordLayout,
    expected: &ExpectedHeader,
    computed: u32,
) -> Result<VerifiedHeader<'a>, HeaderMismatch> {
    let header = derived_header(bytes, layout)?;
    let fields = fields(header);
    crc_matches(fields, computed)?;
    let found = header_identity(fields);
    if !admits(&found, &expected.identity, expected.reader) {
        return Err(refusal(&found, &expected.identity, expected.reader));
    }
    sealed(crc, header, layout, expected.position)
}

/// Whether a reader of session `reader` accepts a record whose header names `found` for the index entry naming `named`: the keys are equal and [`accepts`] holds.
pub(crate) fn admits(found: &RecordIdentity, named: &RecordIdentity, reader: u64) -> bool {
    found.key == named.key && accepts(compared(found), compared(named), reader)
}

/// The allocation word, session and cache version of `identity`, the words [`accepts`] compares.
fn compared(identity: &RecordIdentity) -> (u64, u64, u64) {
    (identity.allocation, identity.session, identity.version)
}

/// The mismatch that names why [`admits`] refused `found` for `named` under `reader`.
#[cold]
#[inline(never)]
fn refusal(found: &RecordIdentity, named: &RecordIdentity, reader: u64) -> HeaderMismatch {
    if found.key != named.key {
        HeaderMismatch::Key
    } else if found.allocation != named.allocation {
        HeaderMismatch::Allocation {
            expected: named.allocation,
            found: found.allocation,
        }
    } else if found.session != named.session {
        HeaderMismatch::Session {
            expected: named.session,
            found: found.session,
        }
    } else if found.version != named.version {
        HeaderMismatch::CacheVersion {
            expected: named.version,
            found: found.version,
        }
    } else {
        HeaderMismatch::ForeignSession {
            found: found.session,
            reader,
        }
    }
}

/// The identity the fixed fields of `header` name.
fn header_identity(header: &[u8]) -> RecordIdentity {
    RecordIdentity {
        key: field(header, KEY),
        allocation: u64::from_le_bytes(field(header, ALLOCATION)),
        session: u64::from_le_bytes(field(header, SESSION)),
        version: u64::from_le_bytes(field(header, CACHE_VERSION)),
    }
}

/// Checks the extent index and the offset of `header` against `expected`, then its context crc, and returns the verified header.
fn sealed<'a>(
    crc: Crc32c,
    header: &'a [u8],
    layout: &RecordLayout,
    expected: ExtentPosition,
) -> Result<VerifiedHeader<'a>, HeaderMismatch> {
    let fields = fields(header);
    let found = position(fields);
    if found.index != expected.index {
        return Err(HeaderMismatch::ExtentIndex {
            expected: expected.index,
            found: found.index,
        });
    }
    if found.offset != expected.offset {
        return Err(HeaderMismatch::Offset {
            expected: expected.offset,
            found: found.offset,
        });
    }
    let (stored, computed) = (
        read_u32(fields, CONTEXT_CRC),
        context_crc(crc, layout, header),
    );
    if stored != computed {
        return Err(HeaderMismatch::ContextCrc { stored, computed });
    }
    Ok(VerifiedHeader {
        #[cfg(test)]
        layout: *layout,
        table: &header[CHUNK_TABLE..],
    })
}

/// A header verified against the identity its own bytes name, for a reader
/// that holds no expected identity, such as a diagnostic scan. Its identity
/// is an observation of the bytes and grants no volume-read, live or
/// recovery authority.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ClaimedHeader<'a> {
    pub(crate) layout: RecordLayout,
    pub(crate) identity: RecordIdentity,
    /// The header crc32c the header stores, which verification recomputed.
    pub(crate) header_crc: u32,
    pub(crate) verified: VerifiedHeader<'a>,
}

/// The layout of the extent the fixed fields at the start of `bytes` place
/// by their own lengths and index, covering the whole payload when the
/// lengths name no extent at that index, or `None` when `bytes` ends before
/// the fixed fields.
pub(super) fn claimed_extent(config: &ValidRecordConfig, bytes: &[u8]) -> Option<RecordLayout> {
    let (metadata_len, body_len) = claimed_lengths(bytes)?;
    let index = read_u32(bytes, EXTENT_INDEX);
    let payload = coverage(metadata_len, body_len, index)
        .unwrap_or(u64::from(metadata_len) + u64::from(body_len));
    Some(config.extent_layout(metadata_len, body_len, payload))
}

/// The `metadata_len` and `body_len` the fixed fields at the start of
/// `bytes` claim, or `None` when `bytes` ends before them.
pub(super) fn claimed_lengths(bytes: &[u8]) -> Option<(u32, u32)> {
    let fixed = bytes.get(..CHUNK_TABLE)?;
    Some((read_u32(fixed, METADATA_LEN), read_u32(fixed, BODY_LEN)))
}

/// Verifies the header at the start of `bytes` against its own lengths and
/// identity: the module's checks in order, with the extent taken as the
/// units its lengths derive for the header's own index. The lengths and the identity agree
/// with themselves by construction, as do the extent index and offset,
/// read from the header too. The read predicate runs only in [`check_header`], against a reader's session and an
/// index entry, so a volume read can reject a header returned by `claim_header`. The checks that can fail are truncation,
/// magic, version, the lengths' geometry, the verified length, the chunk parameters, the header
/// crc and the context crc. The index must lie within the extents the
/// lengths give; the offset is accepted as recorded.
///
/// # Errors
///
/// `Truncated` when `bytes` ends before the magic and version, before the
/// other fixed fields once those match, or before the derived header,
/// else the first failing check of `Magic`, `Version`, `Lengths`, `ExtentLength`,
/// `ChunkParameters`, `HeaderCrc` and `ContextCrc`.
pub(crate) fn claim_header<'a>(
    crc: Crc32c,
    config: &ValidRecordConfig,
    bytes: &'a [u8],
) -> Result<ClaimedHeader<'a>, HeaderMismatch> {
    // Two `u32` lengths derive at most about 2^21 units, so the cast is exact.
    let index = bytes
        .get(..CHUNK_TABLE)
        .map_or(0, |fixed| read_u32(fixed, EXTENT_INDEX));
    let units = claimed_extent(config, bytes).map_or(0, |layout| layout.record_units() as u32);
    let layout = config.claimed_layout(bytes, index, units, None)?;
    let header = derived_header(bytes, &layout)?;
    let identity = header_identity(header);
    let header_crc = header_crc(crc, header);
    crc_matches(header, header_crc)?;
    let verified = sealed(crc, header, &layout, position(header))?;
    Ok(ClaimedHeader {
        layout,
        identity,
        header_crc,
        verified,
    })
}

impl VerifiedHeader<'_> {
    /// The crc32c the header records for chunk `index`, which must be below the layout's chunk count.
    pub(crate) fn chunk_crc(&self, index: u32) -> u32 {
        read_u32(self.table, index as usize * CRC_BYTES)
    }

    /// Checks that `bytes` are exactly chunk `index` of the payload under `crc`.
    ///
    /// # Errors
    ///
    /// `ChunkMismatch` when `index` is past the last chunk, `bytes` is not the chunk's length, or its crc32c differs from the table's.
    #[cfg(test)]
    pub(crate) fn verify_chunk(
        &self,
        crc: Crc32c,
        index: u32,
        bytes: &[u8],
    ) -> Result<(), ChunkMismatch> {
        let mismatch = ChunkMismatch { index };
        let range = self.layout.chunk(index).ok_or(mismatch)?;
        if bytes.len() as u64 != range.end - range.start {
            return Err(mismatch);
        }
        if crc.checksum(bytes) != self.chunk_crc(index) {
            return Err(mismatch);
        }
        Ok(())
    }
}

/// The extent position the header `header` records.
fn position(header: &[u8]) -> ExtentPosition {
    ExtentPosition {
        index: read_u32(header, EXTENT_INDEX),
        offset: u64::from_le_bytes(field(header, OFFSET)),
    }
}

/// The context crc32c of the extent whose header, with `layout`, is `header`: the crc32c of the context fields, the version, key through `body_len` and the index through the offset, followed by the extent's payload, whose crc32c is combined from the chunk table's entries in order with the payload length, the window's unit count and the last chunk's length.
/// The 10 context words after the version fold in place from [`VERSION_REGISTER`], and one `combine_chunks` call joins their crc with the chunk checksums, so the work is linear in the chunk table, which the header crc also covers. Every chunk between the first and the last spans one whole window, a whole number of I/O units, which the join's carry constants take.
fn context_crc(crc: Crc32c, layout: &RecordLayout, header: &[u8]) -> u32 {
    let fields = fields(header);
    debug_assert_eq!(read_u32(fields, VERSION), HEADER_VERSION);
    let mut context = RunningCrc::from_register(crc, VERSION_REGISTER);
    context.update_words(words::<{ (CHUNK_LEN - KEY) / 8 }>(fields, KEY));
    context.update_words(words::<{ (CONTEXT_CRC - EXTENT_INDEX) / 8 }>(
        fields,
        EXTENT_INDEX,
    ));
    let bound = context.finish();
    let count = layout.chunk_count();
    let entries = &header[CHUNK_TABLE..CHUNK_TABLE + count as usize * CRC_BYTES];
    let (checksums, _) = entries.as_chunks::<CRC_BYTES>();
    let last_len = count.checked_sub(1).map_or(0, |last| {
        let range = layout.chunks(last, count);
        range.end - range.start
    });
    crc.combine_chunks(
        bound,
        &Chunks {
            checksums,
            units: u64::from(layout.chunk_len()) / IO_UNIT as u64,
            last_len,
            len: layout.payload_len(),
        },
    )
}

/// The payload bytes extent `index` of an object of `metadata_len` and `body_len` bytes covers, or `None` when the object passes [`OBJECT_LIMIT`] or has no extent at `index`.
fn coverage(metadata_len: u32, body_len: u32, index: u32) -> Option<u64> {
    let len = u64::from(metadata_len) + u64::from(body_len);
    if len > OBJECT_LIMIT || u64::from(index) >= extent_count(len) {
        return None;
    }
    let (start, end) = extent_span(len, u64::from(index));
    Some(end - start)
}

/// The crc32c of an encoded header with its crc field read as zero.
pub(super) fn header_crc(crc: Crc32c, header: &[u8]) -> u32 {
    let mut running = crc.start();
    feed_header(&mut running, header, 0..header.len());
    running.finish()
}

/// Words of the shortest header: the fixed fields and one chunk-table entry.
const FIXED_WORDS: usize = (CHUNK_TABLE + CRC_BYTES) / 8;

const _: () = assert!((CHUNK_TABLE + CRC_BYTES).is_multiple_of(8));

/// Folds `header[range]` into `running`, reading the header crc field as zero, so successive in-order ranges that tile an encoded header finish to its header crc32c; `range` lies within `header`.
#[inline(always)]
pub(crate) fn feed_header(running: &mut RunningCrc, header: &[u8], range: Range<usize>) {
    let (field, end) = (HEADER_CRC..HEADER_CRC + CRC_BYTES, range.end);
    // The crc field is the high half of the second little-endian word, after the 4-byte version, so masking that word to its low half folds the version with the crc field as zero.
    let mask = u64::from(u32::MAX);
    if range.start == 0 && end >= FIXED_WORDS * 8 {
        // Every header holds its fixed fields and at least one table entry, 14 words, which fold in one masked word fold.
        running.update_words_masked::<FIXED_WORDS, 1>(words(header, MAGIC), mask);
        running.update(&header[FIXED_WORDS * 8..end]);
        return;
    }
    if range.start == 0 && end >= field.end {
        running.update_words_masked::<2, 1>(words(header, MAGIC), mask);
        running.update(&header[field.end..end]);
        return;
    }
    let zeros = range.start.max(field.start)..end.min(field.end);
    running.update(&header[range.start.min(field.start)..end.min(field.start)]);
    running.update(&[0; CRC_BYTES][..zeros.end.saturating_sub(zeros.start)]);
    running.update(&header[range.start.max(field.end).min(end)..end]);
}

/// The fixed fields at the start of `header`, an encoded header of at least [`CHUNK_TABLE`] bytes: one length check here, and the array's fixed length bounds every fixed-offset read of the fields.
///
/// # Panics
///
/// If `header` is shorter than [`CHUNK_TABLE`]; every header a layout derives holds its fixed fields and at least one table entry.
#[inline(always)]
fn fields(header: &[u8]) -> &[u8; CHUNK_TABLE] {
    let Some(fields) = header.first_chunk() else {
        unreachable!("a derived header holds its fixed fields")
    };
    fields
}

fn put(units: &mut [u8], at: usize, bytes: &[u8]) {
    units[at..at + bytes.len()].copy_from_slice(bytes);
}

fn field<const N: usize>(header: &[u8], at: usize) -> [u8; N] {
    let mut bytes = [0; N];
    bytes.copy_from_slice(&header[at..at + N]);
    bytes
}

/// The `N` eight-byte words of `header` from `at`, in place, so a fold reads them where they lie.
///
/// # Panics
///
/// If `header` ends before them, as indexing it does.
fn words<const N: usize>(header: &[u8], at: usize) -> &[[u8; 8]; N] {
    let (words, _) = header[at..at + 8 * N].as_chunks::<8>();
    let Some(words) = words.first_chunk() else {
        unreachable!("8 * N bytes hold N words")
    };
    words
}

fn read_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(field(bytes, at))
}
