//! Delta blocks: the self-validating units of a tenure's mutation suffix, their region of the metadata prefix, and
//! the record codec that packs membership mutations into them and reads them back.
//!
//! - The delta region is the prefix after the checkpoint slots: `J = M - (1 + K·S)` blocks, LSN `L` at prefix unit
//!   `1 + K·S + (L mod J)`. A unit may hold the block of an earlier LSN, which the identity check refuses.
//! - BLOCK-IDENTITY: block `L` of session `s` is a one-extent record header with key [`key`]`(shard)`, allocation
//!   and version `L`, session `s` and one chunk crc, so a block of another LSN, session or shard fails as `Header`.
//! - Payload: `0..8` the first part's sequence, `8..10` the part count, the parts, then zeros. A part is `kind u8,
//!   zero u8, len u16, seq u64, index u16, count u16` and `len` body bytes; a record is its `count` parts in index
//!   order, and a part ends short of its block only when its record ends, so a record spans consecutive blocks.
//! - A body is an INSERT (key, allocation, session, version, deadline, lifetime, tail, extent count and locators), a
//!   REMOVE (the identity and a cause byte) or a REPLACE (a REMOVE body then an INSERT body) in one record, so a
//!   replacement excludes its predecessor and installs its successor atomically (RECORD-ATOMIC). Multibyte fields
//!   are little-endian, except the shard inside [`key`].

use std::borrow::Cow;

pub use crate::failover::records::delta_blocks as blocks;
use crate::net::ownership::Shard;

use super::super::extent::ExtentLocator;
use super::super::geometry::{DIRECT_UNITS, EXTENT_LIMIT};
use super::super::record::{
    Crc32c, ExpectedHeader, ExtentPosition, HeaderMismatch, RecordIdentity, encode_header,
    header_bytes, verify_header,
};
use super::capture::CaptureEntry;
pub use super::checkpoint::UNIT_LEN;
use super::checkpoint::layout;
use super::load_guard::entry_in_bounds;

/// The bytes before a part's body.
pub const PART_HEADER: usize = 16;

/// The payload bytes before the first part.
const PARTS_AT: usize = 10;

/// The delta key of `shard`: `"IMGCKDL1"`, the shard big-endian, then zeros; no content hash of an object equals it.
pub fn key(shard: Shard) -> [u8; 32] {
    let mut key = [0; 32];
    key[..8].copy_from_slice(b"IMGCKDL1");
    key[8..12].copy_from_slice(&shard.get().to_be_bytes());
    key
}

/// Which block a unit must hold: the shard, the writing tenure's session and the LSN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Block {
    pub shard: Shard,
    pub session: u64,
    pub lsn: u64,
}

impl Block {
    fn identity(self) -> RecordIdentity {
        RecordIdentity {
            key: key(self.shard),
            allocation: self.lsn,
            session: self.session,
            version: self.lsn,
        }
    }
}

/// The identity of one membership incarnation, as its record header carries it.
pub type Identity = RecordIdentity;

pub fn identity_of(entry: &CaptureEntry) -> Identity {
    Identity {
        key: entry.key,
        allocation: entry.allocation,
        session: entry.session,
        version: entry.version,
    }
}

/// Why a REMOVE excluded its identity, or, on a REPLACE, `Evict` by the FILL writer's convention: replay validates the
/// byte and takes a record's effects from its kind and identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Cause {
    Evict = 0,
    Invalidate = 1,
    Expire = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    Insert(CaptureEntry),
    Remove {
        identity: Identity,
        cause: Cause,
    },
    /// `old` leaves and `new` enters in one record; `cause` is `Evict` by the FILL writer's convention.
    Replace {
        old: Identity,
        cause: Cause,
        new: CaptureEntry,
    },
}

const INSERT: u8 = 1;
const REMOVE: u8 = 2;
const REPLACE: u8 = 3;

/// The bytes of a REMOVE body.
const REMOVE_LEN: usize = 57;
/// The bytes of an INSERT body before its extents.
pub(super) const INSERT_FIXED: usize = 72;
/// The bytes of the widest body, a REPLACE of `EXTENT_LIMIT` extents.
const BODY_LIMIT: usize = REMOVE_LEN + INSERT_FIXED + 8 * EXTENT_LIMIT as usize;

/// A record's content as its writer holds it: the identity it excludes with the cause, the entry it installs, or
/// both for a replacement. The appender writes a record from these borrowed halves, so the writer keeps its entry.
#[derive(Debug, Clone, Copy)]
pub struct Change<'a> {
    pub removed: Option<(&'a Identity, Cause)>,
    pub inserted: Option<&'a CaptureEntry>,
}

/// The kind byte and body length of a [`Change`] whose entry, when it has one, passed [`shaped`]; only
/// [`Change::frame`] builds one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    kind: u8,
    len: usize,
}

impl Frame {
    pub(super) fn parts(self) -> (u8, usize) {
        (self.kind, self.len)
    }
}

impl Change<'_> {
    /// The change's [`Frame`], or `None` for a change with neither half or an entry that fails [`shaped`];
    /// `sorted` is the check's scratch space.
    pub fn frame(&self, sorted: &mut Vec<u64>) -> Option<Frame> {
        let kind = match (self.removed, self.inserted) {
            (None, Some(_)) => INSERT,
            (Some(_), None) => REMOVE,
            (Some(_), Some(_)) => REPLACE,
            (None, None) => return None,
        };
        let mut wide =
            |entry| shaped_in(entry, sorted).then_some(INSERT_FIXED + 8 * entry.extents.len());
        let len =
            self.removed.map_or(0, |_| REMOVE_LEN) + self.inserted.map_or(Some(0), &mut wide)?;
        Some(Frame { kind, len })
    }

    /// Appends to `out` the body of a change that has a [`frame`](Self::frame).
    pub fn write(&self, out: &mut Vec<u8>) {
        if let Some((identity, cause)) = self.removed {
            put_identity(out, identity);
            out.push(cause as u8);
        }
        if let Some(entry) = self.inserted {
            put_identity(out, &identity_of(entry));
            // The deadline, lifetime, tail and extent count, little-endian, as one 16-byte word.
            let (tail, count) = (u128::from(entry.tail), entry.extents.len() as u128);
            let timers = u128::from(entry.deadline_ns) | u128::from(entry.lifetime_ms) << 64;
            out.extend_from_slice(&(timers | tail << 96 | count << 112).to_le_bytes());
            for extent in &entry.extents {
                out.extend_from_slice(&extent.to_le_bytes());
            }
        }
    }
}

impl Record {
    /// The record's content, borrowed.
    #[cfg(test)]
    pub(crate) fn change(&self) -> Change<'_> {
        match self {
            Self::Insert(entry) => Change {
                removed: None,
                inserted: Some(entry),
            },
            Self::Remove { identity, cause } => Change {
                removed: Some((identity, *cause)),
                inserted: None,
            },
            Self::Replace { old, cause, new } => Change {
                removed: Some((old, *cause)),
                inserted: Some(new),
            },
        }
    }

    /// The kind byte and body bytes, or `None` for an entry that fails [`shaped`].
    #[cfg(test)]
    pub(crate) fn body(&self) -> Option<(u8, Vec<u8>)> {
        let change = self.change();
        let Frame { kind, len } = change.frame(&mut Vec::new())?;
        let mut out = Vec::with_capacity(len);
        change.write(&mut out);
        Some((kind, out))
    }

    /// The record of kind byte `kind` with body `bytes`, or `None` when the bytes are not exactly one body.
    #[inline]
    pub fn decode(kind: u8, bytes: &[u8]) -> Option<Self> {
        match kind {
            INSERT => entry(bytes).map(Self::Insert),
            REMOVE => removal(bytes).map(|(identity, cause)| Self::Remove { identity, cause }),
            REPLACE => {
                let (old, cause) = removal(bytes.get(..REMOVE_LEN)?)?;
                let new = entry(&bytes[REMOVE_LEN..])?;
                Some(Self::Replace { old, cause, new })
            }
            _ => None,
        }
    }
}

fn put_identity(out: &mut Vec<u8>, identity: &Identity) {
    let words = [identity.allocation, identity.session, identity.version].map(u64::to_le_bytes);
    out.extend_from_slice(&identity.key);
    out.extend_from_slice(words.as_flattened());
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}

fn identity(bytes: &[u8]) -> Identity {
    Identity {
        key: bytes[..32].try_into().unwrap(),
        allocation: u64_at(bytes, 32),
        session: u64_at(bytes, 40),
        version: u64_at(bytes, 48),
    }
}

fn removal(bytes: &[u8]) -> Option<(Identity, Cause)> {
    let causes = [Cause::Evict, Cause::Invalidate, Cause::Expire];
    let cause = *causes.get(usize::from(*bytes.get(56)?))?;
    (bytes.len() == REMOVE_LEN).then(|| (identity(bytes), cause))
}

fn entry(bytes: &[u8]) -> Option<CaptureEntry> {
    let count = usize::from(u16_at(bytes.get(..INSERT_FIXED)?, 70));
    let identity = (bytes.len() == INSERT_FIXED + 8 * count).then(|| identity(bytes))?;
    let words = bytes[INSERT_FIXED..].as_chunks::<8>().0;
    let entry = CaptureEntry {
        key: identity.key,
        allocation: identity.allocation,
        session: identity.session,
        version: identity.version,
        deadline_ns: u64_at(bytes, 56),
        lifetime_ms: u32::from_le_bytes(bytes[64..68].try_into().unwrap()),
        tail: u16_at(bytes, 68),
        extents: words.iter().map(|word| u64::from_le_bytes(*word)).collect(),
    };
    shaped(&entry).then_some(entry)
}

const _: () = assert!(DIRECT_UNITS < 128, "a span's length takes seven bits");

/// Whether `entry` passes the load guard's per-entry check with positive, direct and pairwise disjoint extents.
pub fn shaped(entry: &CaptureEntry) -> bool {
    shaped_in(entry, &mut Vec::new())
}

/// Like [`shaped`], using reusable scratch space in `sorted`: every call leaves it empty and keeps its capacity. The
/// call allocates only when the spans need the sort and the entry's extent count exceeds that capacity.
pub fn shaped_in(entry: &CaptureEntry, sorted: &mut Vec<u64>) -> bool {
    sorted.clear();
    let spans = || entry.extents.iter().map(|&bits| span(bits));
    let direct = |(start, end): (u64, u64)| start < end && end - start <= u64::from(DIRECT_UNITS);
    if !entry_in_bounds(entry.extents.len(), entry.tail) || !spans().all(direct) {
        return false;
    }
    // Spans each ending by the next one's start are disjoint as they lie; others sort first, as `start << 7 | length`.
    if !spans().zip(spans().skip(1)).all(|(a, b)| a.1 <= b.0) {
        sorted.extend(spans().map(|(start, end)| start << 7 | (end - start)));
        sorted.sort_unstable();
    }
    let apart = |pair: &[u64]| (pair[0] >> 7) + (pair[0] & 127) <= pair[1] >> 7;
    let disjoint = sorted.windows(2).all(apart);
    sorted.clear();
    disjoint
}

/// The units `[start, end)` extent `bits` covers.
pub fn span(bits: u64) -> (u64, u64) {
    let extent = ExtentLocator::from_bits(bits);
    let start = extent.start_unit();
    (start, start.saturating_add(u64::from(extent.len_units())))
}

/// Packs records into block payloads in push order; a payload seals once a part cannot hold one more body byte.
#[derive(Debug, Default)]
pub struct Packer {
    /// The open payload, empty until a part opens it, and the sealed payloads, oldest first.
    pub(super) open: Vec<u8>,
    pub(super) sealed: std::collections::VecDeque<Vec<u8>>,
    /// The emptied payloads of written blocks, whose allocations later payloads take. A payload is allocated only
    /// while none waits here, so the payloads in circulation number at most the blocks that wait unwritten at once
    /// and the open one.
    spares: Vec<Vec<u8>>,
    /// Where a body that spans blocks is built before its parts take it.
    spill: Vec<u8>,
}

/// The payload bytes of one block: the unit less the header of a one-chunk record.
const ROOM: usize = UNIT_LEN - header_bytes(UNIT_LEN as u64, UNIT_LEN as u64) as usize;

// A payload of `ROOM` bytes takes the header `ROOM` was derived from, so the two fill the unit.
const _: () = assert!(header_bytes(ROOM as u64, UNIT_LEN as u64) as usize + ROOM == UNIT_LEN);

/// The most body bytes of a part that opens an empty payload.
const PART_ROOM: usize = ROOM - PARTS_AT - PART_HEADER;

/// The payload bytes of one block.
pub const fn room() -> usize {
    ROOM
}

impl Packer {
    /// The body bytes a part opened in a payload of `open` bytes holds, at least one; `None` when the payload has
    /// room for no body byte after a part header and seals first.
    fn part_room(open: usize) -> Option<usize> {
        let free = ROOM - open.max(PARTS_AT);
        (free > PART_HEADER).then(|| free - PART_HEADER)
    }

    /// Where a body of `len` bytes would land if pushed onto an open payload of `open` bytes: its last part lies
    /// `last` blocks after that block, in `parts` parts; `None` when the parts exceed `u16::MAX`. A body of more
    /// than one part fills the first part's block, and every later part opens the next one.
    pub fn plan(open: usize, len: usize) -> Option<(usize, u16)> {
        let (sealed, first) = match Self::part_room(open) {
            Some(first) => (0, first),
            None => (1, PART_ROOM),
        };
        let later = len.saturating_sub(first).div_ceil(PART_ROOM);
        Some((sealed + later, u16::try_from(1 + later).ok()?))
    }

    /// Appends a record of kind `kind` as sequence `seq`, sealing full blocks as its parts fill them; `fill` appends
    /// the record's `len` body bytes.
    pub fn push(&mut self, seq: u64, (kind, len): (u8, usize), fill: impl FnOnce(&mut Vec<u8>)) {
        let planned = Self::plan(self.open.len(), len);
        let (_, count) = planned.expect("a body of at most u16::MAX extents fits u16::MAX parts");
        let first = self.part(seq, kind, (0, count));
        if count == 1 {
            // The whole body lands after its one part's header.
            fill(&mut self.open);
            self.close(first);
        } else {
            // A body that spans blocks is built once in the spill buffer and dealt out to its parts: the first
            // fills its block and each later one opens the next.
            let mut body = std::mem::take(&mut self.spill);
            body.clear();
            fill(&mut body);
            let (head, rest) = body.split_at(ROOM - self.open.len());
            self.open.extend_from_slice(head);
            self.close(first);
            for (index, part) in (1..count).zip(rest.chunks(PART_ROOM)) {
                let at = self.part(seq, kind, (index, count));
                self.open.extend_from_slice(part);
                self.close(at);
            }
            self.spill = body;
        }
        if Self::part_room(self.open.len()).is_none() {
            self.seal();
        }
    }

    /// Opens part `index` of the `count` parts of record `seq` and returns its header's offset: seals a payload
    /// with room for no body byte, starts an empty payload at `seq`, and writes the part's header with a zero
    /// length, which [`close`](Self::close) fills in.
    fn part(&mut self, seq: u64, kind: u8, (index, count): (u16, u16)) -> usize {
        if Self::part_room(self.open.len()).is_none() {
            self.seal();
        }
        if self.open.is_empty() {
            self.open = self.spares.pop().unwrap_or_default();
            self.open.reserve_exact(ROOM);
            self.open.extend_from_slice(&seq.to_le_bytes());
            self.open.extend_from_slice(&[0; PARTS_AT - 8]);
        }
        let at = self.open.len();
        // The kind byte, a zero byte, the length, the sequence, the index and the count.
        let places = u128::from(seq) << 32 | u128::from(index) << 96 | u128::from(count) << 112;
        self.open
            .extend_from_slice(&(u128::from(kind) | places).to_le_bytes());
        at
    }

    /// Closes the part whose header lies at `at`: stores its body length and counts it in the payload's part count.
    fn close(&mut self, at: usize) {
        let take = (self.open.len() - at - PART_HEADER) as u16;
        self.open[at + 2..at + 4].copy_from_slice(&take.to_le_bytes());
        let parts = (u16_at(&self.open, 8) + 1).to_le_bytes();
        self.open[8..10].copy_from_slice(&parts);
    }

    /// Closes the open payload when it holds a part.
    pub fn seal(&mut self) {
        if !self.open.is_empty() {
            self.open.resize(ROOM, 0);
            self.sealed.push_back(std::mem::take(&mut self.open));
        }
    }

    /// Takes back the payload of a block whose write persisted: its allocation serves a later payload.
    pub fn recycle(&mut self, mut payload: Vec<u8>) {
        payload.clear();
        self.spares.push(payload);
    }
}

/// Encodes block `block` with payload `payload`, which [`Packer`] sealed, into `unit`: the payload after the
/// header's bytes, zeros after a payload short of the unit's room, and the header, whose chunk checksum covers
/// both, in the unit's first bytes, so the call writes every byte of the unit.
pub fn seal_into(crc: Crc32c, block: Block, payload: &[u8], unit: &mut [u8; UNIT_LEN]) {
    let (_, layout) = layout();
    let body = &mut unit[layout.header_bytes()..];
    body[..payload.len()].copy_from_slice(payload);
    body[payload.len()..].fill(0);
    let (identity, first) = (block.identity(), ExtentPosition::FIRST);
    encode_header(crc, &layout, &identity, first, &mut unit[..]).expect("a unit holds its block");
}

/// The unit bytes of block `block` with payload `payload`, which [`Packer`] sealed.
#[cfg(test)]
pub fn seal(crc: Crc32c, block: Block, payload: &[u8]) -> Box<[u8; UNIT_LEN]> {
    let mut unit = Box::new([0; UNIT_LEN]);
    seal_into(crc, block, payload, &mut unit);
    unit
}

/// Why a unit holds no valid block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockHole {
    /// The record header failed: magic, crc, or an identity of another LSN, session or shard.
    Header(HeaderMismatch),
    /// The payload's chunk crc differs from the header's.
    Chunk,
    /// The parts are malformed: a count, length, index or sequence out of place, a nonzero trailing byte, or a record
    /// that is not exactly one body of its kind.
    Content,
    /// The device could not read the unit, or the bytes are not a whole unit.
    Unread,
}

/// A part's header: its record's kind byte and sequence, and the part's index among the record's `count` parts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head {
    pub kind: u8,
    pub seq: u64,
    pub index: u16,
    pub count: u16,
}

/// A part: its header and its body, which lies in the block's bytes.
pub type Part<'a> = (Head, &'a [u8]);

/// The parts of a valid block, in order; the first part's sequence is the block's first sequence.
pub type Decoded<'a> = Vec<Part<'a>>;

/// Decodes `bytes` as block `expected` for a reader of session `reader`, into the storage of `parts`.
///
/// # Errors
///
/// `Unread` for bytes of another length, `Header` for a failed identity, then `Chunk`, then `Content` unless at
/// least one part lies inside the payload, each is well formed and continues the one before it or opens the next
/// sequence, an unfinished last part reaches the payload's end, and the bytes after the last part are zero.
pub fn decode<'a>(
    crc: Crc32c,
    expected: Block,
    reader: u64,
    bytes: &'a [u8],
    mut parts: Decoded<'a>,
) -> Result<Decoded<'a>, BlockHole> {
    let (config, layout) = layout();
    if bytes.len() != UNIT_LEN {
        return Err(BlockHole::Unread);
    }
    let header = ExpectedHeader {
        identity: expected.identity(),
        reader,
        position: ExtentPosition::FIRST,
        len_units: 1,
        lengths: Some((0, layout.body_len())),
    };
    let verified = verify_header(crc, &config, bytes, &header).map_err(BlockHole::Header)?;
    let payload = &bytes[layout.header_bytes()..];
    if crc.checksum(payload) != verified.chunk_crc(0) {
        return Err(BlockHole::Chunk);
    }
    let total = usize::from(u16_at(payload, 8));
    parts.clear();
    let mut at = PARTS_AT;
    let mut open = false;
    let slice = |from: usize, len: usize| payload.get(from..from + len).ok_or(BlockHole::Content);
    for _ in 0..total {
        let raw = slice(at, PART_HEADER)?;
        let (kind, len) = (raw[0], usize::from(u16_at(raw, 2)));
        let (seq, index, count) = (u64_at(raw, 4), u16_at(raw, 12), u16_at(raw, 14));
        let body = slice(at + PART_HEADER, len)?;
        let framed = raw[1] == 0 && (INSERT..=REPLACE).contains(&kind) && index < count && len != 0;
        // A block's first part may continue the record of the block before it; every later record opens at index 0.
        let continues = match parts.last() {
            Some((last, _)) => index == 0 && last.seq.checked_add(1) == Some(seq),
            None => seq == u64_at(payload, 0),
        };
        if open || !framed || !continues {
            return Err(BlockHole::Content);
        }
        open = index + 1 < count;
        at += PART_HEADER + len;
        let head = Head {
            kind,
            seq,
            index,
            count,
        };
        parts.push((head, body));
    }
    if parts.is_empty() || open && at != payload.len() || payload[at..].iter().any(|&b| b != 0) {
        return Err(BlockHole::Content);
    }
    Ok(parts)
}

/// Regroups parts into records across blocks: [`admit`](Self::admit) owns the continuation rule between blocks, so a
/// record completes only when every part arrived (RECORD-ATOMIC); a suffix's first block opens a record, and after a
/// reset, parts of an unseen record drop.
#[derive(Debug, Default)]
pub struct Assembler {
    /// The latest part's header and the body so far of a record that spans blocks.
    pub(super) open: Option<(Head, Vec<u8>)>,
    last: Option<u64>,
    /// A reset followed a hole, so the next block may open with a part of an unseen record.
    resumed: bool,
}

impl Assembler {
    /// Whether `block`'s first part continues the record or sequence the blocks before it left.
    ///
    /// # Errors
    ///
    /// `Content` when it does not or the block holds no part.
    pub fn admit(&self, block: &Decoded) -> Result<(), BlockHole> {
        let (first, _) = block.first().ok_or(BlockHole::Content)?;
        let continues = match (&self.open, self.last) {
            (Some((open, _)), _) => {
                (open.kind, open.seq, open.index + 1, open.count)
                    == (first.kind, first.seq, first.index, first.count)
            }
            (None, Some(last)) => first.index == 0 && last.checked_add(1) == Some(first.seq),
            (None, None) => self.resumed || first.index == 0,
        };
        continues.then_some(()).ok_or(BlockHole::Content)
    }

    /// Feeds the next part of an admitted block and returns the whole body of the record it completes.
    ///
    /// # Errors
    ///
    /// `Content` when the joined body passes the widest body.
    #[inline]
    pub fn feed<'a>(&mut self, (head, body): Part<'a>) -> Result<Option<Cow<'a, [u8]>>, BlockHole> {
        let joined = match self.open.take() {
            Some(open) if open.1.len() + body.len() > BODY_LIMIT => return Err(BlockHole::Content),
            Some((_, open)) => Cow::Owned([&open, body].concat()),
            None if head.index == 0 => Cow::Borrowed(body),
            None => return Ok(None),
        };
        if head.index + 1 < head.count {
            self.open = Some((head, joined.into_owned()));
            return Ok(None);
        }
        self.last = Some(head.seq);
        Ok(Some(joined))
    }

    /// The REMOVE half of an open REPLACE whose first part arrived whole, for the partial-record control.
    #[cfg(test)]
    pub(crate) fn open_removal(&self) -> Option<Identity> {
        let (_, open) = self
            .open
            .as_ref()
            .filter(|(head, _)| head.kind == REPLACE)?;
        removal(open.get(..REMOVE_LEN)?).map(|(identity, _)| identity)
    }

    /// Drops the open record and the sequence after a hole.
    pub fn reset(&mut self) {
        (self.open, self.last, self.resumed) = (None, None, true);
    }
}
