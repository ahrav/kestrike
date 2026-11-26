//! Checkpoint units: one checkpoint encoded into the units of a slot, and the decode that admits a unit only when it
//! carries the named checkpoint's identity and an intact payload, and admits the slot's entries only through the load
//! guard (`SelfValidatingRead`).
//!
//! - Unit `j` of checkpoint `c` by session `s` is a one-extent record in the record header format: key
//!   [`key`]`(shard)`, allocation word `c·2^32 + j`, session `s`, cache version `c`, and one chunk crc over the
//!   unit's payload. A reader checks the identity through the read predicate, so a unit written by another capture,
//!   another session or another shard fails before its payload is read.
//! - Unit 0 carries the row, entry and unit counts. Each later unit carries up to [`UNIT_ENTRIES`] rows of
//!   [`ROW_LEN`] bytes, one row per extent of an entry, entries in capture order and extents in sequence order. An
//!   entry whose rows exceed the slot's remaining rows is left out, and the entries after it are still encoded.
//! - A slot's entries are returned only after every unit the checkpoint names arrived or failed, the rows of the
//!   decoded units regrouped into whole entries, and the load guard, checked by destination jobs that each own one
//!   shard of the keys, slots and payload units, judged those entries. A unit that fails its identity or crc check,
//!   or its read, loses only the entries with a row on it (`LossIsFaultLocal`), and the decode lists it as failed or
//!   unread. Intact units that contradict each other or
//!   unit 0's counts violate the checkpoint's encoding invariants.
//! - The checkpoint's ancestry suffixes replay as one job beside the slot's windows, and each destination gives its
//!   whole entries their fate under the replay's [`Patch`] and withholds those of a session the reader does not admit,
//!   as the replay withholds them; the load is the destination's kept entries and the suffix's live entries routed to
//!   it, and the guard's rules hold over that final set.
//!
//! Payload layout, at byte offsets after the record header:
//!
//! - Unit 0: `0..8` row count, `8..16` entry count, `16..20` unit count, then zeros.
//! - A later unit: `0..4` its row count, `4..8` zero, then its rows from byte 8, then zeros.
//! - A row: `0..32` entry key, `32..40` allocation, `40..48` session, `48..56` cache version, `56..64` deadline,
//!   `64..68` lifetime, `68..70` tail, `70..72` the extent's index in its entry, `72..74` the entry's extent count,
//!   `74..80` zero, `80..88` the extent's locator bits, `88..96` zero.
//!
//! Every multibyte field is little-endian, as in the record header, except the shard inside [`key`], which is
//! big-endian.

use crate::failover::records::{
    ENTRY_BYTES, Layout, Suffix, UNIT_ENTRIES, UNIT_OVERHEAD, slot_units,
};
use crate::index::{Key, KeyHasher, LANES, reduce};
use crate::net::ownership::Shard;

use std::collections::BTreeMap;
use std::sync::Arc;

use super::super::IO_UNIT;
use super::super::allocation::AllocationId;
use super::super::geometry::{DIRECT_UNITS, EXTENT_LIMIT};
use super::super::ledger::EngineBudget;
use super::super::prefetch::hint;
use super::super::record::{
    Crc32c, ExpectedHeader, ExtentPosition, HeaderMismatch, RecordConfig, RecordIdentity,
    RecordLayout, RecordPricer, ValidRecordConfig, admits, encode_header, verify_header,
};
use super::capture::CaptureEntry;
use super::delta::{Identity, identity_of};
use super::delta_replay::{Fate, Patch, Seek, SuffixReport, lsns, patch};
use super::load_guard::{
    LoadLimits, LoadRefusal, checked, entry_in_bounds, extent_range, fingerprint, key_high,
    last_fits, shared_key,
};

/// The bytes of one checkpoint unit.
pub const UNIT_LEN: usize = IO_UNIT;

/// The bytes of one row.
pub const ROW_LEN: usize = ENTRY_BYTES;

/// Rows a unit after unit 0 holds.
const ROWS: usize = UNIT_ENTRIES as usize;

/// The per-unit row count sits at the payload's start, and rows follow it.
const ROWS_AT: usize = 8;

const _: () = assert!(ROWS_AT + ROWS * ROW_LEN <= UNIT_LEN - UNIT_OVERHEAD);

/// The checkpoint key of `shard`: `"IMGCKCK1"`, then the shard big-endian, then zeros. Object keys are content
/// hashes of 32 bytes, so a checkpoint key names no object.
pub fn key(shard: Shard) -> [u8; 32] {
    let mut key = [0; 32];
    key[..8].copy_from_slice(b"IMGCKCK1");
    key[8..12].copy_from_slice(&shard.get().to_be_bytes());
    key
}

/// Which checkpoint a unit belongs to: the shard, the capturing session `s` and the capture number `c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    pub shard: Shard,
    pub session: u64,
    pub capture: u32,
}

impl Checkpoint {
    fn identity(self, unit: u32) -> RecordIdentity {
        RecordIdentity {
            key: key(self.shard),
            allocation: (u64::from(self.capture) << 32) | u64::from(unit),
            session: self.session,
            version: u64::from(self.capture),
        }
    }
}

/// The record layout of every unit: one extent of `UNIT_LEN` bytes whose payload follows the header.
pub(super) fn layout() -> (ValidRecordConfig, RecordLayout) {
    let config = RecordConfig {
        chunk_len: UNIT_LEN as u32,
    }
    .validate()
    .expect("one unit is a valid chunk length");
    let payload = config
        .payload_of(UNIT_LEN as u64)
        .expect("a unit holds a payload after its header");
    (config, config.layout(0, payload as u32))
}

/// The units a checkpoint of `rows` rows spans: unit 0 and one unit per [`UNIT_ENTRIES`] rows, the slot sizing of
/// [`slot_units`] applied to rows.
pub fn units(rows: u64) -> u64 {
    slot_units(rows)
}

/// The rows `entries` encode to: one per extent.
pub fn rows(entries: &[CaptureEntry]) -> u64 {
    entries.iter().map(|entry| entry.extents.len() as u64).sum()
}

/// Why an entry set cannot be encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeRefusal {
    /// An entry owns no extent, or more than `u16::MAX`.
    Extents {
        allocation: u64,
    },
    EmptySlot,
    /// The allocator refused a unit or the unit list.
    Memory,
}

/// Encodes `entries` as the units of checkpoint `checkpoint` in a slot of `slot_units` units, unit 0 first. Each
/// extent takes one row and the slot holds at most `(slot_units - 1) · UNIT_ENTRIES` rows, so the encode skips each
/// entry whose rows exceed the remaining capacity and keeps capture order among the entries it encodes.
///
/// # Errors
///
/// `Extents` for an entry with no extent or more than `u16::MAX`, `EmptySlot` when `slot_units` is zero, `Memory`
/// when the allocator refuses a unit or the unit list.
pub fn encode(
    crc: Crc32c,
    checkpoint: Checkpoint,
    entries: &[CaptureEntry],
    slot_units: u32,
) -> Result<Vec<Box<[u8; UNIT_LEN]>>, EncodeRefusal> {
    let counted = Counted::of(entries);
    encode_counted(
        crc,
        checkpoint,
        (entries, counted),
        slot_units,
        &mut Vec::new(),
    )
}

/// The rows of an entry set and the allocation of its first entry that owns no extent or more than `u16::MAX`,
/// from one pass over the entries.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Counted {
    pub(crate) rows: u64,
    invalid: Option<u64>,
}

impl Counted {
    pub(crate) fn of(entries: &[CaptureEntry]) -> Self {
        let mut counted = Self::default();
        for entry in entries {
            counted.add(entry.allocation, entry.extents.len());
        }
        counted
    }

    /// Counts one more entry of `extents` extents.
    fn add(&mut self, allocation: u64, extents: usize) {
        self.rows += extents as u64;
        if self.invalid.is_none() && (extents == 0 || extents > usize::from(u16::MAX)) {
            self.invalid = Some(allocation);
        }
    }
}

/// The words of one row before its extent count: the key in four words, the allocation, the session, the cache
/// version, the deadline, and the lifetime with the tail in the 16 bits above it. Each word is the value its eight
/// row bytes hold little-endian, so a row is these words, the extent's index above the tail, the extent count, the
/// extent and a zero word.
const FIELDS: usize = 9;

/// One member as the encode reads it: its rows' leading words and its extent words.
#[derive(Clone, Copy)]
pub(crate) struct Member<'a> {
    fields: &'a [u64; FIELDS],
    extents: &'a [u64],
}

/// The leading words of `entry`'s rows.
fn fields(entry: &CaptureEntry) -> [u64; FIELDS] {
    let key = |at: usize| {
        let mut word = [0; 8];
        word.copy_from_slice(&entry.key[8 * at..8 * at + 8]);
        u64::from_le_bytes(word)
    };
    [
        key(0),
        key(1),
        key(2),
        key(3),
        entry.allocation,
        entry.session,
        entry.version,
        entry.deadline_ns,
        u64::from(entry.lifetime_ms) | (u64::from(entry.tail) << 32),
    ]
}

/// An entry set the encode reads in capture order.
pub(crate) trait Members {
    /// Calls `each` with every member in capture order, until one call fails.
    ///
    /// # Errors
    ///
    /// The first error `each` returns.
    fn members(
        &self,
        each: impl FnMut(Member<'_>) -> Result<(), EncodeRefusal>,
    ) -> Result<(), EncodeRefusal>;
}

impl Members for [CaptureEntry] {
    fn members(
        &self,
        mut each: impl FnMut(Member<'_>) -> Result<(), EncodeRefusal>,
    ) -> Result<(), EncodeRefusal> {
        self.iter().try_for_each(|entry| {
            each(Member {
                fields: &fields(entry),
                extents: &entry.extents,
            })
        })
    }
}

/// The words a [`Cut`] packs of one member before its extent words: its rows' leading words and its extent count.
const HEAD: usize = FIELDS + 1;

/// The words of one [`Cut`] chunk: 64 KiB, which holds the 451 words of one walk turn's one-extent members many
/// times over. A member larger than a chunk gets a chunk of its own size.
const CHUNK: usize = 8192;

/// A capture's cut as its walk copies it: each walked member's fields and extent words packed into word chunks of a
/// fixed size, and the side list the walk took at its end. A push writes into the chunk in use or the next one, so
/// it moves no member copied before it, and the copy's work a turn is bounded by that turn's members.
/// [`recycle`](Self::recycle) empties the cut and keeps its chunks, so the next walk writes into memory the tenure
/// already holds.
#[derive(Debug, Default)]
pub struct Cut {
    chunks: Vec<Vec<u64>>,
    /// The chunks that hold members, the first `used`; the last of them takes the next push.
    used: usize,
    saved: Vec<CaptureEntry>,
    members: usize,
    counted: Counted,
    /// The bytes the chunks reserved, those kept empty included.
    chunked: usize,
}

impl Cut {
    pub fn new() -> Self {
        Self::default()
    }

    /// Copies `entry` behind the members pushed before it. A member that needs one more chunk takes the next kept
    /// chunk when that holds it, and otherwise reserves a chunk only when `budget` holds the cut's bytes with it.
    ///
    /// # Errors
    ///
    /// [`EncodeRefusal::Memory`] when `budget` cannot hold the new chunk or the allocator refuses it; the cut keeps
    /// the members it held.
    #[inline]
    pub fn push(
        &mut self,
        entry: &CaptureEntry,
        budget: &EngineBudget,
    ) -> Result<(), EncodeRefusal> {
        let extents = &entry.extents[..];
        let words = HEAD + extents.len();
        let room =
            (self.chunks[..self.used].last()).map_or(0, |chunk| chunk.capacity() - chunk.len());
        if room < words {
            self.advance(words, budget)?;
        }
        let chunk = &mut self.chunks[self.used - 1];
        let [f0, f1, f2, f3, f4, f5, f6, f7, f8] = fields(entry);
        // A member of one extent, the common shape, is one copy of a length the compiler knows.
        match extents {
            [extent] => chunk.extend_from_slice(&[f0, f1, f2, f3, f4, f5, f6, f7, f8, 1, *extent]),
            _ => {
                chunk.extend_from_slice(&[
                    f0,
                    f1,
                    f2,
                    f3,
                    f4,
                    f5,
                    f6,
                    f7,
                    f8,
                    extents.len() as u64,
                ]);
                chunk.extend_from_slice(extents);
            }
        }
        self.members += 1;
        self.counted.add(entry.allocation, extents.len());
        Ok(())
    }

    /// Moves the fill to the next chunk for a member of `words` words: the kept chunk behind those in use when it
    /// holds the member, and otherwise a chunk reserved for it. Kept out of line so the push of a member that fits
    /// the chunk in use stays a few stores inside its caller's loop.
    #[cold]
    #[inline(never)]
    fn advance(&mut self, words: usize, budget: &EngineBudget) -> Result<(), EncodeRefusal> {
        if (self.chunks.get(self.used)).is_none_or(|kept| kept.capacity() < words) {
            self.grow(words.max(CHUNK), budget)?;
        }
        self.used += 1;
        Ok(())
    }

    /// Reserves a chunk of `words` words behind the chunks in use when `budget` holds the cut with it.
    fn grow(&mut self, words: usize, budget: &EngineBudget) -> Result<(), EncodeRefusal> {
        self.chunks
            .try_reserve(1)
            .map_err(|_| EncodeRefusal::Memory)?;
        let bytes = (words.checked_mul(size_of::<u64>()))
            .and_then(|chunk| chunk.checked_add(self.bytes()))
            .ok_or(EncodeRefusal::Memory)?;
        let mut scratch = *budget;
        scratch.charge(bytes).map_err(|_| EncodeRefusal::Memory)?;
        let mut chunk = Vec::new();
        chunk
            .try_reserve_exact(words)
            .map_err(|_| EncodeRefusal::Memory)?;
        self.chunked += chunk.capacity() * size_of::<u64>();
        self.chunks.insert(self.used, chunk);
        Ok(())
    }

    /// Moves the side list `saved` behind the walked members; its entries stay under the charge that held them.
    pub fn save(&mut self, saved: Vec<CaptureEntry>) {
        for entry in &saved {
            self.counted.add(entry.allocation, entry.extents.len());
        }
        self.members += saved.len();
        self.saved = saved;
    }

    /// Empties the cut for the next walk, which writes into the chunks this one reserved, and returns the side
    /// list for the caller to free where it chooses.
    pub fn recycle(&mut self) -> Vec<CaptureEntry> {
        for chunk in &mut self.chunks[..self.used] {
            chunk.clear();
        }
        (self.used, self.members, self.counted) = (0, 0, Counted::default());
        std::mem::take(&mut self.saved)
    }

    /// Frees the chunks behind those in use, so a cut recycled after a whole walk keeps what that walk filled.
    pub fn trim(&mut self) {
        for chunk in self.chunks.drain(self.used..) {
            self.chunked -= chunk.capacity() * size_of::<u64>();
        }
    }

    /// The most bytes one walk turn reserves when each member it copies takes fewer words than a chunk and the turn's
    /// members together take fewer than a chunk: none while a kept chunk follows the chunk in use, and otherwise one
    /// chunk and the chunk list's growth for it.
    #[inline]
    pub fn turn_reserve(&self) -> usize {
        if self.chunks.len() > self.used {
            return 0;
        }
        let list = match self.chunks.len() == self.chunks.capacity() {
            true => self.chunks.capacity().max(4) * size_of::<Vec<u64>>(),
            false => 0,
        };
        CHUNK * size_of::<u64>() + list
    }

    /// The members copied and saved.
    pub fn len(&self) -> usize {
        self.members
    }

    pub fn is_empty(&self) -> bool {
        self.members == 0
    }

    /// The bytes the cut's chunks and its chunk list reserved; the side list is outside them.
    pub fn bytes(&self) -> usize {
        self.chunked + self.chunks.capacity() * size_of::<Vec<u64>>()
    }

    pub(crate) fn counted(&self) -> Counted {
        self.counted
    }
}

impl Members for Cut {
    fn members(
        &self,
        mut each: impl FnMut(Member<'_>) -> Result<(), EncodeRefusal>,
    ) -> Result<(), EncodeRefusal> {
        for chunk in &self.chunks[..self.used] {
            let mut rest = &chunk[..];
            while let Some((head, after)) = rest.split_first_chunk::<HEAD>() {
                let [fields @ .., count] = head;
                let (extents, after) = after.split_at(*count as usize);
                each(Member { fields, extents })?;
                rest = after;
            }
        }
        self.saved.members(each)
    }
}

/// The unit buffers of an encode: unit 0 first, each [`UNIT_LEN`] bytes.
pub type Units = Vec<Box<[u8; UNIT_LEN]>>;

/// [`encode`] of `members` whose rows and first invalid entry `counted` holds, into the buffers of `kept` first and
/// fresh zeroed buffers after them. Each data unit's header is encoded as the unit fills, while its bytes are still
/// cached; unit 0's and the last unit's once every row is placed. On success `kept` holds the buffers the encode did
/// not use, in their order. A refusal for an unencodable member or an empty slot leaves `kept` as it was, and a
/// refusal of memory drops its buffers.
///
/// Every byte of a returned unit is written by this call, whatever a kept buffer held: the header by its seal, the
/// counts and rows by the fill, and every other payload byte as zero directly before the seal.
pub(crate) fn encode_counted<M: Members + ?Sized>(
    crc: Crc32c,
    checkpoint: Checkpoint,
    (members, counted): (&M, Counted),
    slot_units: u32,
    kept: &mut Units,
) -> Result<Units, EncodeRefusal> {
    if let Some(allocation) = counted.invalid {
        return Err(EncodeRefusal::Extents { allocation });
    }
    let data_units = slot_units.checked_sub(1).ok_or(EncodeRefusal::EmptySlot)?;
    let room = u64::from(data_units) * UNIT_ENTRIES;
    let (_, layout) = layout();
    let start = layout.header_bytes();
    // Zeroes unit `at`'s payload from byte `written` on, past what the fill wrote, and seals the unit.
    let seal = |at: usize, unit: &mut [u8; UNIT_LEN], written: usize| {
        #[cfg(test)]
        let written = match STALE_TAIL.with(std::cell::Cell::get) {
            true => UNIT_LEN - start,
            false => written,
        };
        unit[start + written..].fill(0);
        encode_header(
            crc,
            &layout,
            &checkpoint.identity(at as u32),
            ExtentPosition::FIRST,
            &mut unit[..],
        )
        .expect("a unit holds its record");
    };
    // The payload bytes a data unit of `filled` rows holds: its count, four zero bytes, then its rows.
    let rows_end = |filled: usize| ROWS_AT + filled * ROW_LEN;
    let mut out = std::mem::take(kept);
    let wanted = units(counted.rows.min(room)) as usize;
    out.try_reserve_exact(wanted.saturating_sub(out.len()))
        .map_err(|_| EncodeRefusal::Memory)?;
    // The encode's units are the first `used` of `out`; the buffers behind them are kept ones it has not reached.
    let mut used = 0;
    next_unit(&mut out, &mut used)?;
    let (mut rows, mut entries) = (0u64, 0u64);
    let mut filled = ROWS;
    members.members(|member| {
        let extents = member.extents.len() as u64;
        if extents > room - rows {
            return Ok(());
        }
        rows += extents;
        entries += 1;
        for (index, extent) in member.extents.iter().enumerate() {
            if filled == ROWS {
                let full = used - 1;
                if full > 0 {
                    seal(full, &mut out[full], rows_end(ROWS));
                }
                next_unit(&mut out, &mut used)?;
                let unit = &mut out[used - 1];
                unit[start + 4..start + ROWS_AT].fill(0);
                filled = 0;
            }
            let unit = &mut out[used - 1];
            let at = start + ROWS_AT + filled * ROW_LEN;
            put_row(&mut unit[at..at + ROW_LEN], &member, index as u16, *extent);
            filled += 1;
            unit[start..start + 4].copy_from_slice(&(filled as u32).to_le_bytes());
        }
        Ok(())
    })?;
    kept.extend(out.drain(used..));
    let count = out.len() as u32;
    let first = &mut out[0];
    first[start..start + 8].copy_from_slice(&rows.to_le_bytes());
    first[start + 8..start + 16].copy_from_slice(&entries.to_le_bytes());
    first[start + 16..start + 20].copy_from_slice(&count.to_le_bytes());
    seal(0, &mut out[0], 20);
    let last = out.len() - 1;
    if last > 0 {
        seal(last, &mut out[last], rows_end(filled));
    }
    Ok(out)
}

/// Makes the buffer behind the first `used` of `out` the encode's next unit: the kept buffer there, or a fresh zeroed
/// one.
fn next_unit(out: &mut Units, used: &mut usize) -> Result<(), EncodeRefusal> {
    if *used == out.len() {
        out.push(zeroed()?);
    }
    *used += 1;
    Ok(())
}

#[cfg(test)]
thread_local! {
    /// A planted defect: a unit's seal leaves the payload past what the fill wrote as the buffer held it, so a kept
    /// buffer carries an earlier encode's bytes into the unit.
    pub(crate) static STALE_TAIL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn zeroed() -> Result<Box<[u8; UNIT_LEN]>, EncodeRefusal> {
    let unit = zeros::<u8>(UNIT_LEN).ok_or(EncodeRefusal::Memory)?;
    Ok(unit
        .into_boxed_slice()
        .try_into()
        .expect("the vector holds UNIT_LEN bytes"))
}

/// Whether any byte of `bytes` is nonzero, tested eight bytes at a time.
fn nonzero(bytes: &[u8]) -> bool {
    let (words, rest) = bytes.as_chunks::<8>();
    words.iter().any(|word| u64::from_ne_bytes(*word) != 0) || rest.iter().any(|&b| b != 0)
}

fn zeros<T: Clone + Default>(len: usize) -> Option<Vec<T>> {
    let mut zeros = Vec::new();
    zeros.try_reserve_exact(len).ok()?;
    zeros.resize(len, T::default());
    Some(zeros)
}

/// Writes the row of extent `extent`, the `index`th of `member`, whose extent count a row's 16 bits hold.
fn put_row(row: &mut [u8], member: &Member<'_>, index: u16, extent: u64) {
    let [f0, f1, f2, f3, f4, f5, f6, f7, expiry] = *member.fields;
    let count = member.extents.len() as u16;
    let words = [
        f0,
        f1,
        f2,
        f3,
        f4,
        f5,
        f6,
        f7,
        expiry | (u64::from(index) << 48),
        u64::from(count),
        extent,
        0,
    ];
    for (at, word) in words.into_iter().enumerate() {
        row[8 * at..8 * at + 8].copy_from_slice(&word.to_le_bytes());
    }
}

/// One decoded row: an extent of an entry, with the entry's fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Row {
    key: [u8; 32],
    allocation: u64,
    session: u64,
    version: u64,
    deadline_ns: u64,
    lifetime_ms: u32,
    tail: u16,
    index: u16,
    count: u16,
    extent: u64,
    /// The key's routing fingerprint and its destination, in a row that opens its entry.
    print: u64,
    dest: u32,
}

impl Row {
    /// `left` counts the rows remaining after this row; each row supplies at most one extent.
    fn open(&self, left: usize) -> CaptureEntry {
        let room = usize::from(self.count)
            .min(left + 1)
            .min(EXTENT_LIMIT as usize);
        let mut extents = Vec::with_capacity(room);
        extents.push(self.extent);
        CaptureEntry {
            key: self.key,
            allocation: self.allocation,
            session: self.session,
            version: self.version,
            deadline_ns: self.deadline_ns,
            lifetime_ms: self.lifetime_ms,
            tail: self.tail,
            extents,
        }
    }

    /// The entry of a row that is its entry's only one, without its extent.
    fn loaded(&self) -> Loaded {
        Loaded {
            identity: Identity {
                key: self.key,
                allocation: self.allocation,
                session: self.session,
                version: self.version,
            },
            deadline_ns: self.deadline_ns,
            lifetime_ms: self.lifetime_ms,
            tail: self.tail,
            extents: 1,
            print: self.print,
        }
    }

    /// Whether this row continues `entry`: every entry field matches.
    fn continues(&self, entry: &CaptureEntry) -> bool {
        (
            self.key,
            self.allocation,
            self.session,
            self.version,
            self.deadline_ns,
            self.lifetime_ms,
            self.tail,
        ) == (
            entry.key,
            entry.allocation,
            entry.session,
            entry.version,
            entry.deadline_ns,
            entry.lifetime_ms,
            entry.tail,
        )
    }

    fn slot(&self) -> usize {
        AllocationId::of_record_tag(self.allocation).slot_index()
    }
}

fn row(bytes: &[u8; ROW_LEN]) -> Option<Row> {
    let u64_at = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    let u16_at = |at: usize| u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap());
    // Bytes `74..80` are the word at 72 above its low 16 bits, which hold the extent count.
    if u64_at(72) >> 16 != 0 || u64_at(88) != 0 {
        return None;
    }
    let (index, count) = (u16_at(70), u16_at(72));
    (count > 0 && index < count).then(|| Row {
        key: bytes[..32].try_into().unwrap(),
        allocation: u64_at(32),
        session: u64_at(40),
        version: u64_at(48),
        deadline_ns: u64_at(56),
        lifetime_ms: u32::from_le_bytes(bytes[64..68].try_into().unwrap()),
        tail: u16_at(68),
        index,
        count,
        extent: u64_at(80),
        print: 0,
        dest: 0,
    })
}

/// The damage of one unit of a slot, or of the slot's counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitDamage {
    /// The unit's record header failed: magic, crc, identity or position.
    Header { unit: u32, mismatch: HeaderMismatch },
    /// The payload's chunk crc differs from the header's.
    Chunk { unit: u32 },
    /// A count, a reserved byte or a row is malformed, a data unit before the last is short, or the rows do not
    /// regroup into the counted entries.
    Content { unit: u32 },
    /// The unit count unit 0 records differs from the count the store names.
    Units { recorded: u32, named: u32 },
    /// The device could not read the unit.
    Unread { unit: u32 },
}

/// The damage of a decoded slot: the first damage by the precedence [`SlotDecode::finish`] states, which names the
/// unit of a cross-unit inconsistency, and the undecoded units, split by whether a read may still load them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Damage {
    pub first: UnitDamage,
    /// Units that failed their identity, crc or content check; the entries with a row on them are lost.
    pub failed: Vec<u32>,
    /// Units the device could not read; a later read of the slot may load them.
    pub unread: Vec<u32>,
}

impl Damage {
    /// The alarm the damage raises: `Unreadable` when the first damage is a failed read, which a failed check
    /// outranks, and `StaleWrite` otherwise.
    pub fn alarm(&self) -> LoadRefusal {
        match self.first {
            UnitDamage::Unread { .. } => LoadRefusal::Unreadable,
            _ => LoadRefusal::StaleWrite,
        }
    }
}

/// Emptied read buffers a decode keeps for reuse: one per read a caller keeps in flight.
pub const SPARES: usize = super::super::checkpoint::READ_DEPTH;

/// One whole entry of a load: its identity, expiry and tail, the count of its extents in its chunk's run, and its
/// key's routing fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Loaded {
    pub identity: Identity,
    pub deadline_ns: u64,
    pub lifetime_ms: u32,
    pub tail: u16,
    pub extents: u16,
    pub print: u64,
}

impl Loaded {
    /// `entry`, of at most `u16::MAX` extents, with its key's routing fingerprint `print`.
    fn of(entry: &CaptureEntry, print: u64) -> Self {
        Self {
            identity: identity_of(entry),
            deadline_ns: entry.deadline_ns,
            lifetime_ms: entry.lifetime_ms,
            tail: entry.tail,
            extents: entry.extents.len() as u16,
            print,
        }
    }
}

/// Whole entries in order, and their extents in one run: each entry's extents in sequence order, the entries' runs in
/// entry order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Entries {
    entries: Vec<Loaded>,
    extents: Vec<u64>,
}

impl Entries {
    /// Entries with room for `entries` entries of `extents` extents in all; `None` when the allocator refuses it.
    fn reserved(entries: usize, extents: usize) -> Option<Self> {
        let mut held = Self::default();
        let room = [
            held.entries.try_reserve_exact(entries),
            held.extents.try_reserve_exact(extents),
        ];
        room.iter().all(Result::is_ok).then_some(held)
    }

    /// Entries that hold `entries` placeholder entries and `extents` zero extents, which a [`Regroup`] replaces in
    /// place; `None` when the allocator refuses it.
    fn placed(entries: usize, extents: usize) -> Option<Self> {
        let mut held = Self::reserved(entries, extents)?;
        let empty = Loaded {
            identity: Identity {
                key: [0; 32],
                allocation: 0,
                session: 0,
                version: 0,
            },
            deadline_ns: 0,
            lifetime_ms: 0,
            tail: 0,
            extents: 0,
            print: 0,
        };
        held.entries.resize(entries, empty);
        held.extents.resize(extents, 0);
        Some(held)
    }

    /// Appends `entry`, of at most `u16::MAX` extents, with its key's routing fingerprint `print`.
    fn push(&mut self, entry: &CaptureEntry, print: u64) {
        self.entries.push(Loaded::of(entry, print));
        self.extents.extend_from_slice(&entry.extents);
    }
}

/// A destination's whole entries of one window, of the owner's stitching or of the suffix: a run of entries and of
/// their extents in storage the window's destinations share, less the entries a window job or the destination's seal
/// dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    held: Arc<Entries>,
    entries: std::ops::Range<usize>,
    extents: std::ops::Range<usize>,
    /// One bit per dropped entry of the run; empty while the chunk holds every entry.
    dropped: Mask,
}

impl Chunk {
    /// The chunk of every entry of `held`.
    fn of(held: Entries) -> Self {
        let (entries, extents) = (0..held.entries.len(), 0..held.extents.len());
        Self {
            held: Arc::new(held),
            entries,
            extents,
            dropped: Vec::new(),
        }
    }

    /// The entries the chunk holds.
    pub fn len(&self) -> usize {
        let dropped: u32 = self.dropped.iter().map(|word| word.count_ones()).sum();
        self.entries.len() - dropped as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The address and the entry capacity of the storage the chunk's run lies in.
    #[cfg(test)]
    pub(crate) fn storage(&self) -> (usize, usize) {
        (
            Arc::as_ptr(&self.held) as usize,
            self.held.entries.capacity(),
        )
    }

    /// Each entry of the run with its extents, in order, dropped or not.
    fn run(&self) -> impl Iterator<Item = (&Loaded, &[u64])> + Clone {
        let mut rest = &self.held.extents[self.extents.clone()];
        self.held.entries[self.entries.clone()]
            .iter()
            .map(move |entry| {
                let (own, later) = rest.split_at(usize::from(entry.extents));
                rest = later;
                (entry, own)
            })
    }

    /// Each entry the chunk holds with its place in the run and its extents, in order.
    pub fn placed(&self) -> impl Iterator<Item = (usize, &Loaded, &[u64])> {
        let kept = self
            .run()
            .enumerate()
            .filter(|(at, _)| !bit(&self.dropped, *at));
        kept.map(|(at, (entry, extents))| (at, entry, extents))
    }

    /// The entry at place `at` of the run, a place [`placed`](Self::placed) gave.
    ///
    /// # Panics
    ///
    /// When `at` lies past the run.
    pub fn at(&self, at: usize) -> &Loaded {
        &self.held.entries[self.entries.clone()][at]
    }
}

#[cfg(test)]
impl Chunk {
    /// The chunk of `entries`, each with its key's routing fingerprint, in their order.
    pub(crate) fn holding(entries: &[(CaptureEntry, u64)]) -> Self {
        let extents = entries.iter().map(|(entry, _)| entry.extents.len()).sum();
        let mut held = Entries::reserved(entries.len(), extents).expect("the test chunk fits");
        for (entry, print) in entries {
            held.push(entry, *print);
        }
        Self::of(held)
    }

    /// This chunk less the entries at `places` of its run, dropped as a seal drops a superseded entry.
    pub(crate) fn without(mut self, places: &[usize]) -> Self {
        self.dropped.resize(self.entries.len().div_ceil(64), 0);
        for &at in places {
            self.dropped[at / 64] |= 1 << (at % 64);
        }
        self
    }
}

/// One bit per entry of a chunk, in its entries' order; a missing word holds no bit.
type Mask = Vec<u64>;

/// A named slot's load with its ancestry suffixes. A caller installs `shards` once `verdict` is `Ok` and
/// [`installable`](Self::installable) holds, raises the damage's alarm and reports the suffix; the warm install also
/// refuses a load that withheld a slot or suffix entry.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotLoad {
    /// `Ok` when the final entries pass the load guard, else the refusal by the precedence [`SlotDecode::finish`]
    /// states; the warm install also refuses an `Ok` load that withheld a slot or suffix entry.
    pub verdict: Result<(), LoadRefusal>,
    /// Each destination's final entries: the slot's whole entries of sessions the reader admits that the suffix left in
    /// place, in unit order, then the suffix's live entries, in replay order. Element `d` is destination `d`, which
    /// holds every entry whose fingerprint the index's shard reduction routes to the `d`th enabled shard; `d` is that
    /// shard's position among the enabled shards, not its shard index.
    pub shards: Vec<Vec<Chunk>>,
    pub damage: Option<Damage>,
    /// The replay's report, whose `superseded` names the suffix's superseded entries.
    pub suffix: SuffixReport,
    /// The slot's entries a suffix entry superseded.
    pub slot_superseded: u64,
    /// The slot's entries withheld because the reader does not admit their session.
    pub slot_withheld: u64,
    /// The slot's whole entries the decode found on its intact units, before the suffix.
    pub slot_found: u64,
    /// The replay's patch, which the load holds until it is dropped: finishing a load then releases no large
    /// allocation while the helpers release the seals' buffers.
    patch: Arc<Patch>,
}

impl SlotLoad {
    /// The whole, warm load of `shards` under an empty suffix, as a guard that accepted them hands it over.
    #[cfg(test)]
    pub(crate) fn handed(shards: Vec<Vec<Chunk>>) -> Self {
        Self {
            verdict: Ok(()),
            shards,
            damage: None,
            suffix: SuffixReport::default(),
            slot_superseded: 0,
            slot_withheld: 0,
            slot_found: 0,
            patch: Arc::new(Patch::new(&SuffixReport::default(), std::iter::empty())),
        }
    }

    /// Unread units and blocks may yield entries on a later read, so a caller rereads the slot before it installs a
    /// load with an unread unit or suffix block, and a load whose suffix history is damaged does not install.
    pub fn installable(&self) -> bool {
        let unread = self
            .damage
            .as_ref()
            .is_some_and(|damage| !damage.unread.is_empty());
        !unread && self.suffix.installable()
    }
}

/// One destination's share of the load guard: its slots and payload units through one bit each, and the whole entries
/// routed to it, whose keys its seal compares. One job at a time holds it (ONE-OWNER-PER-RANGE), and its flags are
/// unions over the facts it applied, whatever their order.
#[derive(Debug, Default)]
struct DestGuard {
    /// Set for every slot of the range an entry names, and every unit of the range an in-bounds extent covers.
    slots: Vec<u64>,
    marked: Vec<u64>,
    /// The whole entries routed here, in unit order, and the chunks among them no window job classified under the
    /// patch, by their place.
    chunks: Vec<Chunk>,
    pending: Vec<usize>,
    /// The key fingerprint of each entry in `chunks`, in their order, and their in-bounds units.
    words: Vec<u64>,
    units: u64,
    /// Two entries share a slot.
    slot: bool,
    /// Two in-bounds extents cover a common unit.
    overlap: bool,
    /// Set by [`seal`](Self::seal): `Key` when two entries share a key, or `Memory` when the allocator refused the key
    /// comparison's scratch.
    key: Option<LoadRefusal>,
    /// What the dropped entries take, final once sealed; a seal that got its key scratch takes their units from
    /// `units`.
    gone: Gone,
    sealed: bool,
    /// The bitmaps and key words the seal is done with, which [`Done::spent`] hands to the job's runner.
    spent: Vec<Vec<u64>>,
}

/// The guard requests the bitmap word of the span this many spans ahead of the one it marks, and a classification
/// requests the patch's filter words of the entry this many entries ahead of the one it judges.
const AHEAD: usize = 8;

#[cfg(test)]
thread_local! {
    /// Destination jobs on this thread check overlap only among one window's extents: a negative control.
    pub(crate) static PER_WINDOW: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Destination jobs run on this thread panic: the containment tests' planted helper failure.
    pub(crate) static PANIC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Window jobs run on this thread panic.
    pub(crate) static WINDOW_PANIC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Replay jobs run on this thread panic.
    pub(crate) static REPLAY_PANIC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Seals on this thread keep the entries the patch supersedes: a negative control.
    pub(crate) static KEEP_SUPERSEDED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Seals on this thread keep every entry of a chunk no window job classified: a negative control.
    pub(crate) static SKIP_UNCLASSIFIED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// The seal of this destination, on this thread, finds its scratch refused.
    pub(crate) static SEAL_REFUSED: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    /// Destination jobs on this thread find the room for a window refused.
    pub(crate) static ROOM_REFUSED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Window jobs on this thread find their chunk reservations refused.
    pub(crate) static CHUNKS_REFUSED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

impl DestGuard {
    /// `apply` returns `true` after applying `facts`, or `false` before applying them if reserving storage for the
    /// window's fingerprints, chunks, or pending places fails.
    fn apply(&mut self, facts: Facts, dest: usize, limits: &LoadLimits) -> bool {
        let units = facts.units + units_of(&facts.stitched.extents, limits);
        let stitched = Some(facts.stitched).filter(|stitched| !stitched.entries.is_empty());
        let stitched = stitched.map(Chunk::of);
        let added = stitched.as_ref().map_or(0, |chunk| chunk.entries.len());
        let added = added + facts.entries.entries.len();
        let room = [self.chunks.try_reserve(3), self.pending.try_reserve(2)];
        if self.words.try_reserve(added).is_err() || room.iter().any(Result::is_err) {
            return false;
        }
        #[cfg(test)]
        if ROOM_REFUSED.with(std::cell::Cell::get) {
            return false;
        }
        self.units += units;
        self.gone.add(facts.gone);
        #[cfg(test)]
        if PER_WINDOW.with(std::cell::Cell::get) {
            self.marked.fill(0);
        }
        let (slots, spans) = facts.marks.of(dest);
        // Each loop gathers its flag in a local and the guard takes it once: a flag updated in the guard for every
        // mark is a load, an `or` and a store of the guard's byte per mark, each load waiting on the store before it.
        let mut shared = false;
        for &slot in slots {
            shared |= mark(&mut self.slots, slot, slot + 1);
        }
        self.slot |= shared;
        // A window's spans land on bitmap words far apart, so the guard requests each span's first word while it
        // marks the spans before it.
        let words = self.marked.as_ptr();
        let mut overlap = false;
        for (at, &(start, end)) in spans.iter().enumerate() {
            if let Some(&(ahead, _)) = spans.get(at + AHEAD) {
                hint(words.wrapping_add((ahead / 64) as usize).cast());
            }
            overlap |= mark(&mut self.marked, start, end);
        }
        self.overlap |= overlap;
        // A chunk the patch classified holds its drops; any other waits for the seal.
        let chunks = [(stitched, false), (Some(facts.entries), facts.classified)];
        for (chunk, classified) in chunks {
            let Some(chunk) = chunk.filter(|chunk| !chunk.entries.is_empty()) else {
                continue;
            };
            let keys = chunk
                .run()
                .map(|(entry, _)| fingerprint(&entry.identity.key));
            self.words.extend(keys);
            if !classified {
                self.pending.push(self.chunks.len());
            }
            self.chunks.push(chunk);
        }
        true
    }

    /// Allocates the bits of `context`'s ranges once, and room for the key words of a sixteenth more entries than an
    /// even share of the slot's rows, so the words of an evenly routed slot never move; false when the allocator
    /// refuses either.
    fn allocate(&mut self, context: &Context) -> bool {
        if self.slots.is_empty() {
            let (slots, units) = (context.slots.div_ceil(64), context.units.div_ceil(64));
            match (zeros(slots as usize), zeros(units as usize)) {
                (Some(slots), Some(marked)) => (self.slots, self.marked) = (slots, marked),
                _ => return false,
            }
            let share = (context.named as usize).saturating_sub(1) * ROWS / context.destinations;
            if self.words.try_reserve_exact(share + share / 16).is_err() {
                return false;
            }
        }
        true
    }

    /// Whether two entries here share a key: the batch guard's sort of their fingerprints and comparison of the keys of
    /// every run of equal fingerprint bits. Equal keys route to one destination, so the destinations' checks together
    /// cover every pair. The unit bitmap, whose flags are final, becomes the sort's scratch as it stands, grown to the
    /// entries when they outnumber its words. `Memory` when the allocator refuses that growth.
    fn shared_key(&mut self) -> Option<LoadRefusal> {
        let mut words = std::mem::take(&mut self.words);
        let mut aux = std::mem::take(&mut self.marked);
        let count = words.len();
        let more = count.saturating_sub(aux.len());
        if aux.try_reserve_exact(more).is_err() {
            return Some(LoadRefusal::Memory);
        }
        aux.resize(aux.len() + more, 0);
        let high = key_high(count);
        for (at, word) in words.iter_mut().enumerate() {
            *word = *word & high | at as u64;
        }
        let starts: Vec<usize> = (self.chunks.iter())
            .scan(0, |start, chunk| {
                Some(std::mem::replace(start, *start + chunk.entries.len()))
            })
            .collect();
        let key_at = |at: usize| {
            let chunk = starts.partition_point(|&start| start <= at) - 1;
            let run = &self.chunks[chunk];
            &run.held.entries[run.entries.start + at - starts[chunk]]
                .identity
                .key
        };
        let shared = shared_key(key_at, &mut words, &mut aux[..count], high);
        self.spent.extend([words, aux]);
        shared.then_some(LoadRefusal::Key)
    }

    /// Sets the slot bitmap, whose flags are final, aside as spent, compares the keys of every entry here, which
    /// spends the unit bitmap and the key words, then classifies each chunk no window job classified under `patch`:
    /// its drops, like those the window jobs made, leave the kept units. A dropped entry stays in its window's
    /// storage, and its chunk leaves it out.
    fn seal(&mut self, patch: &Patch, context: &Context) {
        self.spent.push(std::mem::take(&mut self.slots));
        self.key = self.shared_key();
        self.sealed = true;
        if self.key == Some(LoadRefusal::Memory) {
            return;
        }
        let pending = std::mem::take(&mut self.pending);
        #[cfg(test)]
        let pending = match SKIP_UNCLASSIFIED.with(std::cell::Cell::get) {
            true => Vec::new(),
            false => pending,
        };
        for at in pending {
            let gone = classify(&mut self.chunks[at], Some(patch), context);
            self.gone.add(gone);
        }
        self.units -= self.gone.units;
    }
}

/// What dropped entries take from a destination's kept entries: their in-bounds units, their count, and among them
/// the entries a patch superseded and the entries withheld for a session the reader does not admit.
#[derive(Debug, Default, Clone, Copy)]
struct Gone {
    units: u64,
    dropped: u64,
    superseded: u64,
    withheld: u64,
}

impl Gone {
    fn add(&mut self, more: Self) {
        self.units += more.units;
        self.dropped += more.dropped;
        self.superseded += more.superseded;
        self.withheld += more.withheld;
    }
}

/// The in-bounds units of `extents` under `limits`.
fn units_of(extents: &[u64], limits: &LoadLimits) -> u64 {
    let spans = (extents.iter()).filter_map(|&bits| extent_range(bits, limits).ok());
    spans.map(|(start, end)| end - start).sum()
}

/// Whether bit `at` of `bits` is set; a missing word holds no bit.
fn bit(bits: &[u64], at: usize) -> bool {
    bits.get(at / 64)
        .is_some_and(|word| word >> (at % 64) & 1 == 1)
}

/// Drops from `chunk` each entry it still holds of a session the reader of `context` does not admit and, under a
/// `patch`, each one the patch excludes or supersedes, and returns what the drops take. A chunk that drops no entry
/// keeps an empty mask.
fn classify(chunk: &mut Chunk, patch: Option<&Patch>, context: &Context) -> Gone {
    let patch = patch.filter(|patch| !patch.is_empty());
    let (mut gone, mut dropped) = (Gone::default(), std::mem::take(&mut chunk.dropped));
    let (mut ahead, mut seek) = (chunk.run().skip(AHEAD), Seek::default());
    for (at, (entry, extents)) in chunk.run().enumerate() {
        if let (Some(patch), Some((entry, extents))) = (patch, ahead.next()) {
            patch.request(&entry.identity, extents);
        }
        if bit(&dropped, at) {
            continue;
        }
        let misfit = !admits(&entry.identity, &entry.identity, context.reader);
        let fate = match patch {
            Some(patch) if !misfit => patch.fate(&mut seek, &entry.identity, extents),
            _ => Fate::Kept,
        };
        #[cfg(test)]
        let fate = match fate {
            Fate::Superseded if KEEP_SUPERSEDED.with(std::cell::Cell::get) => Fate::Kept,
            fate => fate,
        };
        if misfit || fate != Fate::Kept {
            dropped.resize(chunk.entries.len().div_ceil(64), 0);
            dropped[at / 64] |= 1 << (at % 64);
            gone.add(Gone {
                units: units_of(extents, &context.limits),
                dropped: 1,
                superseded: u64::from(fate == Fate::Superseded),
                withheld: u64::from(misfit),
            });
        }
    }
    drop(ahead);
    chunk.dropped = dropped;
    gone
}

/// The guard's refusal, as [`SlotDecode::finish`] states it, of the `found` whole slot entries in the batch guard's
/// order, then of the final set of `entries` entries over `units` in-bounds units. The row checks and the guards' slot
/// and unit bitmaps cover every decoded row, the rows of an entry a damaged unit cut included; each guard's seal
/// compares the keys of the whole entries routed to it.
fn verdict(
    context: &Context,
    tally: Tally,
    (found, entries, units): (u64, u64, u64),
    guards: &[DestGuard],
) -> Result<(), LoadRefusal> {
    let (_, capacity) = context.checked?;
    let slot = guards.iter().any(|g| g.slot);
    let key = guards.iter().find_map(|g| g.key);
    let n_max = context.limits.n_max as u64;
    let rules = [
        (found > n_max, LoadRefusal::Entries),
        (tally.shape, LoadRefusal::Bounds),
        (key.is_some(), key.unwrap_or(LoadRefusal::Key)),
        (tally.slot || slot, LoadRefusal::Slot),
        (tally.bounds, LoadRefusal::Bounds),
        (tally.total > capacity, LoadRefusal::Units),
        (guards.iter().any(|g| g.overlap), LoadRefusal::Overlap),
        (entries > n_max, LoadRefusal::Entries),
        (units > capacity, LoadRefusal::Units),
    ];
    let first = rules.into_iter().find(|(fails, _)| *fails);
    first.map_or(Ok(()), |(_, refusal)| Err(refusal))
}

fn shares(limits: &LoadLimits, destinations: usize) -> (u64, u64) {
    let count = destinations.max(1) as u64;
    let payload = limits.payload_end.saturating_sub(limits.payload_start);
    let slots = slot_bits(limits).div_ceil(count).max(1);
    (slots, payload.div_ceil(count).max(1))
}

fn guard_len((slots, payload): (u64, u64)) -> u128 {
    u128::from(slots.div_ceil(64) + payload.div_ceil(64)) * 8
}

/// The bytes of one destination's slot and unit bitmaps under `limits` over `destinations` destinations, which a
/// destination job holds under its input charge; a pool whose `input_bytes` is below it admits no destination job.
pub fn guard_bytes(limits: &LoadLimits, destinations: usize) -> usize {
    guard_len(shares(limits, destinations)) as usize
}

/// The slots a slot bitmap covers: the slot count, at most `2^32`, since a slot index is the high 32 bits of an
/// allocation tag.
fn slot_bits(limits: &LoadLimits) -> u64 {
    (limits.slot_count as u64).min(1 << 32)
}

/// Sets bits `[start, end)` of `bits`, which holds at least `end` bits, and returns whether any was already set.
pub(crate) fn mark(bits: &mut [u64], start: u64, end: u64) -> bool {
    let mut seen = false;
    let mut at = start;
    while at < end {
        let low = at % 64;
        let len = (end - at).min(64 - low);
        let mask = (u64::MAX >> (64 - len)) << low;
        let word = &mut bits[(at / 64) as usize];
        seen |= *word & mask != 0;
        *word |= mask;
        at += len;
    }
    seen
}

/// What every job of one slot decode reads, and its `destinations` destinations: destination `d` owns the keys whose
/// `hasher` fingerprints route to the `d`th of `destinations` enabled shards, the slots `[d·slots, (d+1)·slots)` and
/// the payload units `d·units` to `(d+1)·units` past the payload start, so every key, slot and unit has one
/// destination.
#[derive(Debug)]
struct Context {
    crc: Crc32c,
    checkpoint: Checkpoint,
    reader: u64,
    named: u32,
    config: ValidRecordConfig,
    layout: RecordLayout,
    limits: LoadLimits,
    checked: Result<(RecordPricer, u64), LoadRefusal>,
    hasher: KeyHasher,
    destinations: usize,
    slots: u64,
    units: u64,
}

/// What decoded units add to a decode: unit 0's counts and whether it contradicts them or the named count, the data
/// rows, the first short data unit before the last, the last unit's rows, and the row checks that need no other row:
/// an entry's shape, an extent's or last record's bounds, a slot past the count, and the in-bounds extent total.
#[derive(Debug, Clone, Copy, Default)]
struct Tally {
    counts: Option<(u64, u64)>,
    unit_0: bool,
    rows: u64,
    short: Option<usize>,
    last: Option<usize>,
    shape: bool,
    bounds: bool,
    slot: bool,
    total: u64,
}

impl Tally {
    /// Adds the tally of later units.
    fn add(&mut self, later: Tally) {
        self.counts = self.counts.or(later.counts);
        self.unit_0 |= later.unit_0;
        self.rows += later.rows;
        self.short = self.short.or(later.short);
        self.last = self.last.or(later.last);
        self.shape |= later.shape;
        self.bounds |= later.bounds;
        self.slot |= later.slot;
        self.total = self.total.saturating_add(later.total);
    }
}

/// What a window job counts and collects for one destination as it checks its rows: the openers routed to it, the
/// rows from each of them up to the next opener, and the slots and extent spans of its ranges, relative to them.
#[derive(Debug, Default)]
struct Routed {
    openers: usize,
    /// The window's rows from each opener routed here up to the next opener: the most extents the window's own
    /// entries here hold.
    rows: usize,
    slots: Vec<u64>,
    spans: Vec<(u64, u64)>,
}

/// One window's slots and extent spans, each destination's in one run: `ends[d]` is the end of destination `d`'s
/// slots and of its spans.
#[derive(Debug, Default)]
struct Marks {
    slots: Vec<u64>,
    spans: Vec<(u64, u64)>,
    ends: Vec<(usize, usize)>,
}

impl Marks {
    /// The slots and the spans of destination `dest`.
    fn of(&self, dest: usize) -> (&[u64], &[(u64, u64)]) {
        let (from, to) = (
            dest.checked_sub(1).map_or((0, 0), |at| self.ends[at]),
            self.ends[dest],
        );
        (&self.slots[from.0..to.0], &self.spans[from.1..to.1])
    }
}

/// One window's facts for one destination: the window's marks, which hold the destination's slots and spans, and the
/// whole entries routed to it: the entries the window completed that opened before it, then the window's own, whose
/// chunk leaves out the entries the window's job dropped, with the in-bounds units of every entry of the run.
#[derive(Debug)]
struct Facts {
    marks: Arc<Marks>,
    stitched: Entries,
    entries: Chunk,
    units: u64,
    /// What the entries the window's job dropped take, and whether the job held the patch: a job without it drops
    /// only the entries of a session the reader does not admit.
    gone: Gone,
    classified: bool,
}

/// The decode of units `[first, first + count)` from `bytes`, whose missing whole units count as unread, classifying
/// its entries under the suffix's patch once the replay landed.
#[derive(Debug)]
pub struct Window {
    context: Arc<Context>,
    first: u32,
    count: u32,
    bytes: Vec<u8>,
    patch: Option<Arc<Patch>>,
}

/// A decoded window: each undecoded unit with its failed check or `None` when unread, and its regroup, tally and facts.
#[derive(Debug)]
pub struct WindowOut {
    context: Arc<Context>,
    first: u32,
    count: u32,
    damage: Vec<(u32, Option<UnitDamage>)>,
    regroup: Regroup,
    tally: Tally,
    facts: Vec<Facts>,
    /// A reservation for the window's entry chunks failed.
    refused: bool,
    /// The window's read buffer, emptied, which the decode keeps for a later read's copy.
    bytes: Vec<u8>,
}

/// A destination's guard, the facts of each stitched window it applies next, and the patch it seals with once every
/// unit stitched.
#[derive(Debug)]
pub struct DestJob {
    context: Arc<Context>,
    dest: usize,
    guard: DestGuard,
    windows: Vec<Facts>,
    applied: usize,
    patch: Option<Arc<Patch>>,
    refused: bool,
}

/// The replay of the checkpoint's ancestry from `cut` over the delta region of `prefix`, reading each LSN from the
/// read that holds it in `blocks`, by first LSN; an LSN no read holds whole is unread.
#[derive(Debug)]
pub struct ReplayJob {
    context: Arc<Context>,
    prefix: Layout,
    cut: u64,
    ancestry: Vec<Suffix>,
    blocks: BTreeMap<u64, Vec<u8>>,
}

/// A finished replay: its patch, report, live entries by destination, and the payload units they cover.
#[derive(Debug)]
pub struct Replayed {
    context: Arc<Context>,
    patch: Arc<Patch>,
    report: SuffixReport,
    chunks: Vec<Chunk>,
    units: u64,
}

/// A job of one slot decode. It owns what it writes and shares only the decode's immutable context and patches, so
/// [`run`] runs it anywhere.
#[derive(Debug)]
#[must_use]
pub enum Work {
    Window(Box<Window>),
    Dest(Box<DestJob>),
    Replay(Box<ReplayJob>),
}

/// A finished [`Work`], which [`SlotDecode::landed`] adopts.
#[derive(Debug)]
#[must_use]
pub enum Done {
    Window(Box<WindowOut>),
    Dest(Box<DestJob>),
    Replay(Box<Replayed>),
}

impl Done {
    /// Takes the buffers a sealed destination job is done with. A runner on another thread than the decode's frees
    /// them after it handed the job back, so their release, which the kernel serializes across threads, stays off
    /// the path to [`SlotDecode::finish`]; a job landed with them frees them with its guard.
    pub fn spent(&mut self) -> Vec<Vec<u64>> {
        match self {
            Self::Dest(job) => std::mem::take(&mut job.guard.spent),
            _ => Vec::new(),
        }
    }
}

/// Runs `work`: a window's decode, a destination's guard applying its windows' facts and sealing, or the replay.
pub fn run(work: Work) -> Done {
    match work {
        Work::Window(window) => Done::Window(Box::new(window.decode())),
        Work::Dest(mut job) => {
            #[cfg(test)]
            assert!(
                !PANIC.with(std::cell::Cell::get),
                "a planted slot job panic"
            );
            job.refused |= !job.guard.sealed && !job.guard.allocate(&job.context);
            if job.refused || job.guard.sealed {
                return Done::Dest(job);
            }
            for facts in std::mem::take(&mut job.windows) {
                job.applied += 1;
                if !job.guard.apply(facts, job.dest, &job.context.limits) {
                    job.refused = true;
                    return Done::Dest(job);
                }
            }
            if let Some(patch) = &job.patch {
                job.guard.seal(patch, &job.context);
                #[cfg(test)]
                if SEAL_REFUSED.with(std::cell::Cell::get) == Some(job.dest) {
                    job.guard.key = Some(LoadRefusal::Memory);
                }
            }
            job.refused |= job.guard.key == Some(LoadRefusal::Memory);
            Done::Dest(job)
        }
        Work::Replay(job) => Done::Replay(Box::new(job.replay())),
    }
}

impl ReplayJob {
    /// Replays the suffix, whose live entries fit the limits, routes them and sums their units. Invalid limits, which the
    /// slot's verdict refuses, replay nothing and leave the suffix's first LSN unread, so the report stays uninstallable.
    fn replay(self) -> Replayed {
        #[cfg(test)]
        assert!(!REPLAY_PANIC.with(std::cell::Cell::get));
        let context = &self.context;
        let reader = (context.crc, context.checkpoint.shard, context.reader);
        let (live, report, patch) = patch(
            reader,
            (&self.prefix, &context.limits),
            self.cut,
            &self.ancestry,
            |lsn, unit| {
                let held = self.blocks.range(..=lsn).next_back();
                let at = held.map_or(0, |(first, _)| (lsn - first) as usize * UNIT_LEN);
                let bytes = held.and_then(|(_, bytes)| bytes.get(at..at + UNIT_LEN));
                bytes.inspect(|bytes| unit.copy_from_slice(bytes)).is_some()
            },
        )
        .unwrap_or_else(|_| {
            let first = self
                .ancestry
                .first()
                .map_or(self.cut, |suffix| suffix.start.max(self.cut));
            let unread = vec![first];
            (
                Vec::new(),
                SuffixReport {
                    unread,
                    ..SuffixReport::default()
                },
                Patch::new(&SuffixReport::default(), std::iter::empty()),
            )
        });
        let mut units = 0u64;
        let mut chunks: Vec<Entries> = (0..context.destinations)
            .map(|_| Entries::default())
            .collect();
        for entry in live {
            units = units.saturating_add(units_of(&entry.extents, &context.limits));
            let (print, dest) = context.route(&entry.key);
            chunks[dest].push(&entry, print);
        }
        let chunks = chunks.into_iter().map(Chunk::of).collect();
        Replayed {
            context: Arc::clone(context),
            patch: Arc::new(patch),
            report,
            chunks,
            units,
        }
    }
}

impl Window {
    /// Decodes each unit, checks and routes every decoded row, and regroups the rows.
    fn decode(self) -> WindowOut {
        #[cfg(test)]
        assert!(!WINDOW_PANIC.with(std::cell::Cell::get));
        let (context, first) = (&self.context, self.first);
        let (mut damage, mut tally) = (Vec::new(), Tally::default());
        // Every decoded unit's rows lie in one vector, each unit's in the range it decoded to.
        let mut rows: Vec<Row> = Vec::with_capacity(self.count as usize * ROWS);
        let units: Vec<Option<std::ops::Range<usize>>> = (first..first + self.count)
            .map(|unit| {
                let (at, from) = ((unit - first) as usize * UNIT_LEN, rows.len());
                let decoded = match self.bytes.get(at..at + UNIT_LEN) {
                    Some(bytes) => context
                        .unit(unit, bytes, &mut tally, &mut rows)
                        .map_err(Some),
                    None => Err(None),
                };
                decoded
                    .map(|()| from..rows.len())
                    .map_err(|failed| damage.push((unit, failed)))
                    .ok()
            })
            .collect();
        // Each destination's spans reserve a quarter above an even share of the window's rows, and the destination of
        // the first row's slot reserves every row's slot, since a capture pass emits its members in slot order.
        let share = rows.len() / context.destinations;
        let mut routed = Vec::new();
        routed.resize_with(context.destinations, || Routed {
            spans: Vec::with_capacity(share + share / 4 + 8),
            ..Routed::default()
        });
        if let Some(row) = rows.first() {
            let dest = (row.slot() as u64 / context.slots) as usize;
            routed[dest.min(context.destinations - 1)]
                .slots
                .reserve(rows.len());
        }
        // The destination of the entry the latest opening row opened, which takes the rows up to the next opener.
        let mut dest = None;
        for row in &mut rows {
            context.check(row, &mut tally, &mut routed);
            dest = if row.index == 0 { Some(row.dest) } else { dest };
            if let Some(dest) = dest {
                routed[dest as usize].rows += 1;
            }
        }
        // The window's whole entries regroup into storage its destinations share, each destination's in one run. A
        // run starts where the runs before it end and has room for one entry per opener routed to the destination
        // and one extent per row from each of those openers up to the next opener, the most entries and extents the
        // window completes there. A refused reservation fails the decode, and the window regroups nothing.
        let mut end = (0, 0);
        let starts = routed.iter().map(|routed| {
            let start = end;
            end = (start.0 + routed.openers, start.1 + routed.rows);
            start
        });
        let starts: Vec<(usize, usize)> = starts.collect();
        let held = Entries::placed(end.0, end.1);
        #[cfg(test)]
        let held = held.filter(|_| !CHUNKS_REFUSED.with(std::cell::Cell::get));
        let refused = held.is_none();
        let mut regroup = Regroup {
            named: context.named as usize,
            chunks: vec![held.unwrap_or_default()],
            places: starts.clone(),
            ..Regroup::default()
        };
        for (at, unit) in (first as usize..).zip(units).filter(|_| !refused) {
            regroup.unit(at, unit.map(|unit| &rows[unit]));
        }
        let ends = std::mem::take(&mut regroup.places);
        let held = regroup.chunks.pop().unwrap_or_default();
        let mut marks = Marks::default();
        for routed in routed.iter().filter(|_| !refused) {
            marks.slots.extend_from_slice(&routed.slots);
            marks.spans.extend_from_slice(&routed.spans);
            marks.ends.push((marks.slots.len(), marks.spans.len()));
        }
        marks
            .ends
            .resize(routed.len(), (marks.slots.len(), marks.spans.len()));
        let runs = starts.iter().zip(&ends).map(|(start, end)| match refused {
            true => (0..0, 0..0),
            false => (start.0..end.0, start.1..end.1),
        });
        let runs: Vec<_> = runs.collect();
        let (held, marks) = (Arc::new(held), Arc::new(marks));
        let facts = runs.into_iter().map(|(entries, extents)| {
            let units = units_of(&held.extents[extents.clone()], &context.limits);
            let mut entries = Chunk {
                held: Arc::clone(&held),
                entries,
                extents,
                dropped: Vec::new(),
            };
            Facts {
                marks: Arc::clone(&marks),
                stitched: Entries::default(),
                units,
                gone: classify(&mut entries, self.patch.as_deref(), context),
                classified: self.patch.is_some(),
                entries,
            }
        });
        let facts = facts.collect();
        let mut bytes = self.bytes;
        bytes.clear();
        WindowOut {
            context: Arc::clone(context),
            first,
            count: self.count,
            damage,
            regroup,
            tally,
            facts,
            refused,
            bytes,
        }
    }
}

/// The decode of one named slot and its ancestry suffixes as jobs on the recovery helpers: a caller runs each
/// `window` and [`work`](Self::work) job through [`run`], hands each suffix read to
/// `blocks`, returns each job through [`landed`](Self::landed), and calls [`finish`](Self::finish) once
/// [`done`](Self::done). Windows stitch in unit order, regrouping only a window's rows before its first opening row;
/// each destination's guard moves into one job with every stitched window it has not applied, and a window is
/// released once every destination applied it. The replay job runs once every suffix LSN landed, and each guard seals
/// with its patch in the job after every unit stitched.
#[derive(Debug)]
pub struct SlotDecode {
    context: Arc<Context>,
    /// Windows that landed before every earlier unit stitched, by first unit; every unit before `next` stitched.
    landed: BTreeMap<u32, Box<WindowOut>>,
    next: u32,
    regroup: Regroup,
    tally: Tally,
    damage: Option<UnitDamage>,
    failed: Vec<u32>,
    unread: Vec<u32>,
    /// The whole entries the stitched windows routed.
    found: u64,
    /// Per destination: its guard while no job holds it, the facts of the stitched windows it has not taken, and the
    /// windows it applied.
    homes: Vec<Option<DestGuard>>,
    queues: Vec<Vec<Facts>>,
    confirmed: Vec<usize>,
    /// The replay until it is dispatched, the suffix LSNs still to land and the suffix reads landed, and the replay's
    /// result once it landed.
    replay: Option<Box<ReplayJob>>,
    left: u64,
    reads: usize,
    replayed: Option<Box<Replayed>>,
    /// A helper failed a job, or the allocator refused a guard's bitmaps, a window's chunks, a destination's room or a
    /// seal's scratch.
    helper_failed: bool,
    /// Emptied read buffers of landed windows, at most [`SPARES`], which [`spare`](Self::spare) hands out for the
    /// owner's copy of a later read.
    spares: Vec<Vec<u8>>,
}

impl SlotDecode {
    /// A decode of the `units` units of `checkpoint` and of the suffixes `ancestry` from `cut` over the delta region of
    /// `prefix`, for a reader of session `reader`, guarded by `limits`, over `destinations` destinations whose keys
    /// route by `hasher`, one per enabled shard in enabled-shard order; `None` for zero `units` or zero
    /// `destinations`, when the suffix LSN count overflows `u64`, or when the allocator refuses the destination table.
    /// Each destination's first job allocates its guard.
    pub fn new(
        crc: Crc32c,
        checkpoint: Checkpoint,
        units: u32,
        reader: u64,
        limits: LoadLimits,
        (hasher, destinations): (KeyHasher, usize),
        (prefix, cut, ancestry): (Layout, u64, &[Suffix]),
    ) -> Option<Self> {
        if units == 0 || destinations == 0 {
            return None;
        }
        let (slots, payload) = shares(&limits, destinations);
        let (config, layout) = layout();
        let context = Context {
            crc,
            checkpoint,
            reader,
            named: units,
            config,
            layout,
            limits,
            checked: checked(limits),
            hasher,
            destinations,
            slots,
            units: payload,
        };
        let context = Arc::new(context);
        let regroup = Regroup {
            named: units as usize,
            opened: Some(0),
            chunks: zeros(destinations)?,
            ..Regroup::default()
        };
        let mut lsns = ancestry.iter().map(|suffix| lsns(suffix, cut, &prefix));
        let (mut homes, mut queues) = (Vec::new(), Vec::new());
        homes.try_reserve_exact(destinations).ok()?;
        queues.try_reserve_exact(destinations).ok()?;
        homes.resize_with(destinations, || Some(DestGuard::default()));
        queues.resize_with(destinations, Vec::new);
        Some(Self {
            homes,
            queues,
            confirmed: zeros(destinations)?,
            replay: Some(Box::new(ReplayJob {
                context: Arc::clone(&context),
                prefix,
                cut,
                ancestry: ancestry.to_vec(),
                blocks: BTreeMap::new(),
            })),
            left: lsns.try_fold(0, |sum: u64, lsns| {
                sum.checked_add(lsns.end.saturating_sub(lsns.start))
            })?,
            context,
            landed: BTreeMap::new(),
            next: 0,
            regroup,
            tally: Tally::default(),
            damage: None,
            failed: Vec::new(),
            unread: Vec::new(),
            found: 0,
            reads: 0,
            replayed: None,
            helper_failed: false,
            spares: Vec::new(),
        })
    }

    /// The estimated peak bytes a decode of `units` units under `limits` over `destinations` holds with at most
    /// `windows` windows of `window_len` bytes held and up to `SPARES` emptied read buffers kept for reuse, each
    /// counted as a full held window, beside its suffix's replay. Per row of a full slot: its entry with
    /// its routing fingerprint, its one extent's word in its window's run, its key fingerprint word, which may double
    /// while it grows past its guard's reservation, beside the seal's sort scratch, and its drop bit in a mask of up
    /// to two bits a row; and per window of the slot and destination, four chunk handles, four pending places and
    /// two masks of the least capacity, four words. A held window also counts each row's slot and span pieces
    /// twice, in its destination's list and in the window's marks, each list holding up to its reservation or twice
    /// its length. `None` when the estimate overflows `usize`.
    pub fn bytes(
        units: u32,
        limits: &LoadLimits,
        destinations: usize,
        (windows, window_len): (usize, usize),
    ) -> Option<usize> {
        let count = destinations.max(1);
        let share = shares(limits, count);
        let pieces = (u64::from(DIRECT_UNITS).div_ceil(share.1) + 1).min(count as u64) as usize;
        let per_row = size_of::<Loaded>() + size_of::<u64>() + 3 * size_of::<u64>();
        let window_row = size_of::<Row>() + size_of::<CaptureEntry>() + 2 * size_of::<u64>();
        let facts_row = 4 * (size_of::<u64>() + pieces * size_of::<(u64, u64)>());
        let window_unit = 3 * size_of::<(usize, Option<Vec<Row>>)>()
            + 2 * size_of::<(u32, Option<UnitDamage>)>()
            + ROWS * (window_row + facts_row);
        let per_dest = 2 * size_of::<Facts>() + size_of::<Vec<Facts>>();
        let (window_len, window_unit) = (window_len as u128, window_unit as u128);
        let per_window = window_len
            + size_of::<(Window, WindowOut)>() as u128
            + window_len / UNIT_LEN as u128 * window_unit
            + count as u128 * per_dest as u128;
        // A guard's list of spent buffers holds up to four handles.
        let guard = size_of::<Option<DestGuard>>()
            + size_of::<usize>()
            + size_of::<DestGuard>()
            + 4 * size_of::<Vec<u64>>();
        let map_node = 12 * size_of::<(u32, Box<WindowOut>)>() + 4 * size_of::<usize>();
        let replay = size_of::<(ReplayJob, Replayed, Patch)>() + 2 * size_of::<usize>() + 64;
        let queues = size_of::<Chunk>() + size_of::<Vec<Facts>>() + size_of::<Option<Vec<u64>>>();
        let fixed = size_of::<Arc<Context>>()
            + size_of::<Context>()
            + 2 * size_of::<usize>()
            + map_node
            + replay;
        let rows = u128::from(units.saturating_sub(1)) * ROWS as u128;
        let chunks =
            u128::from(units).div_ceil((window_len / UNIT_LEN as u128).max(1)) * count as u128;
        let chunk =
            4 * size_of::<Chunk>() + 4 * size_of::<usize>() + 2 * size_of::<[u64; 4]>() + 32;
        let held = (windows as u128 + SPARES as u128).checked_mul(per_window)?;
        let total = (rows * per_row as u128 + u128::from(units) * 8 + rows.div_ceil(4))
            .checked_add(held)?
            .checked_add(chunks.checked_mul(chunk as u128)?)?
            .checked_add(count as u128 * (guard_len(share) + guard as u128))?
            .checked_add(fixed as u128 + count as u128 * queues as u128)?;
        usize::try_from(total).ok()
    }

    /// The damage found so far, if any.
    #[cfg(test)]
    pub(super) fn damage(&self) -> Option<UnitDamage> {
        self.damage
    }

    /// The bytes of the bitmaps a destination's first job allocates.
    #[cfg(test)]
    pub(super) fn guard_capacity(&self) -> usize {
        let mut guard = DestGuard::default();
        assert!(guard.allocate(&self.context));
        (guard.slots.capacity() + guard.marked.capacity()) * 8
    }

    /// The decode job of units `[first, first + count)`, clipped to the named units, from `bytes`, the whole units a
    /// read returned in a buffer the job takes; the units past them count as unread. The job classifies its entries
    /// under the patch once the replay landed.
    pub(in crate::storage) fn window(&self, first: u32, count: u32, mut bytes: Vec<u8>) -> Work {
        let count = count.min(self.context.named.saturating_sub(first));
        bytes.truncate((bytes.len() / UNIT_LEN).min(count as usize) * UNIT_LEN);
        bytes.shrink_to_fit();
        Work::Window(Box::new(Window {
            context: Arc::clone(&self.context),
            first,
            count,
            bytes,
            patch: (self.replayed.as_ref()).map(|replayed| Arc::clone(&replayed.patch)),
        }))
    }

    /// Takes `bytes`, a read of the `count` suffix LSNs from `lsn`, empty when the read failed; the replay reads a
    /// unit the bytes do not hold whole as unread.
    pub(in crate::storage) fn blocks(&mut self, lsn: u64, count: u64, mut bytes: Vec<u8>) {
        bytes.truncate((bytes.len() / UNIT_LEN).min(count as usize) * UNIT_LEN);
        bytes.shrink_to_fit();
        if let Some(replay) = &mut self.replay {
            replay.blocks.insert(lsn, bytes);
        }
        self.left = self.left.saturating_sub(count);
        self.reads += 1;
    }

    /// The next job, none once a helper failed a job ([`fail`](Self::fail)) or the decode failed as
    /// [`landed`](Self::landed) states: the replay once every suffix LSN
    /// landed, else a destination whose guard is home and unsealed and that has a stitched window to apply or, once
    /// every unit stitched and the patch landed, its seal.
    #[must_use]
    pub fn work(&mut self) -> Option<Work> {
        if self.helper_failed {
            return None;
        }
        if self.left == 0
            && let Some(replay) = self.replay.take()
        {
            return Some(Work::Replay(replay));
        }
        let stitched = self.next >= self.context.named;
        let patch = (self.replayed.as_ref())
            .and_then(|replayed| stitched.then(|| Arc::clone(&replayed.patch)));
        let ready = |at: &usize| {
            self.homes[*at].as_ref().is_some_and(|guard| {
                !guard.sealed && (!self.queues[*at].is_empty() || patch.is_some())
            })
        };
        let dest = (0..self.homes.len())
            .filter(ready)
            .min_by_key(|&at| self.confirmed[at])?;
        let guard = self.homes[dest].take()?;
        Some(Work::Dest(Box::new(DestJob {
            context: Arc::clone(&self.context),
            dest,
            guard,
            windows: std::mem::take(&mut self.queues[dest]),
            applied: 0,
            patch,
            refused: false,
        })))
    }

    /// Adopts a finished job: a window stitches once every earlier unit has, so damage is taken in unit order, and
    /// queues its facts and entries for their destinations; a repeated window is dropped. A destination's guard returns
    /// home with the windows it did not apply queued first, failing the decode when the allocator refused its bitmaps,
    /// a window's room or its seal's scratch; a window whose chunk reservation failed fails the decode, and the
    /// replay's result is kept.
    pub fn landed(&mut self, done: Done) {
        let ours = |context: &Arc<Context>| Arc::ptr_eq(context, &self.context);
        match done {
            Done::Window(mut out) if out.first >= self.next && ours(&out.context) => {
                self.helper_failed |= out.refused;
                if self.spares.len() < SPARES {
                    self.spares.push(std::mem::take(&mut out.bytes));
                }
                self.landed.entry(out.first).or_insert(out);
            }
            Done::Dest(mut job) if ours(&job.context) => {
                self.confirmed[job.dest] += job.applied;
                self.helper_failed |= job.refused;
                job.windows.append(&mut self.queues[job.dest]);
                self.queues[job.dest] = job.windows;
                self.homes[job.dest] = Some(job.guard);
            }
            Done::Replay(replayed) if ours(&replayed.context) => self.replayed = Some(replayed),
            _ => {}
        }
        while let Some(out) = self.landed.remove(&self.next) {
            self.next += out.count;
            self.regroup.append(out.regroup);
            self.tally.add(out.tally);
            for (unit, damage) in out.damage {
                if let Some(damage) = damage {
                    self.failed.push(unit);
                    if (self.damage).is_none_or(|held| matches!(held, UnitDamage::Unread { .. })) {
                        self.damage = Some(damage);
                    }
                } else {
                    self.unread.push(unit);
                    self.damage.get_or_insert(UnitDamage::Unread { unit });
                }
            }
            for (dest, mut facts) in out.facts.into_iter().enumerate() {
                facts.stitched = std::mem::take(&mut self.regroup.chunks[dest]);
                self.found += (facts.stitched.entries.len() + facts.entries.entries.len()) as u64;
                self.queues[dest].push(facts);
            }
        }
    }

    /// The reads released: the slot windows every destination applied, in unit order, and the suffix reads landed.
    pub fn released(&self) -> usize {
        self.confirmed.iter().min().copied().unwrap_or(0) + self.reads
    }

    /// The bytes of one destination's slot and unit bitmaps, which a destination job holds under its input charge.
    /// [`bytes`](Self::bytes) counts the entries, fingerprints and seal scratch a guard holds beside them.
    pub fn guard_bytes(&self) -> usize {
        guard_len((self.context.slots, self.context.units)) as usize
    }

    /// An emptied buffer of a landed window, for the caller's copy of its next read: a fresh one when none is spare.
    pub(in crate::storage) fn spare(&mut self) -> Vec<u8> {
        self.spares.pop().unwrap_or_default()
    }

    #[cfg(test)]
    pub(in crate::storage) fn spares_is_empty(&self) -> bool {
        self.spares.is_empty()
    }

    /// Records that a recovery helper failed a job of this decode.
    pub fn fail(&mut self) {
        self.helper_failed = true;
    }

    /// Whether a helper failed a job ([`fail`](Self::fail)), the decode failed as [`landed`](Self::landed) states, or
    /// every unit stitched and every guard is home,
    /// sealed after applying every window.
    pub fn done(&self) -> bool {
        let sealed =
            (self.homes.iter()).all(|home| home.as_ref().is_some_and(|guard| guard.sealed));
        self.helper_failed || (self.next >= self.context.named && sealed)
    }
}

impl Context {
    /// Decodes unit `unit` from `bytes`: its rows onto the end of `rows`, or for unit 0 its counts in `tally`. A unit
    /// that fails its identity, crc or content check adds no row (CHECK-BEFORE-ROUTE).
    #[inline(never)]
    fn unit(
        &self,
        unit: u32,
        bytes: &[u8],
        tally: &mut Tally,
        rows: &mut Vec<Row>,
    ) -> Result<(), UnitDamage> {
        let content = UnitDamage::Content { unit };
        let named = self.named;
        let expected = ExpectedHeader {
            identity: self.checkpoint.identity(unit),
            reader: self.reader,
            position: ExtentPosition::FIRST,
            len_units: 1,
            lengths: Some((0, self.layout.body_len())),
        };
        let verified = verify_header(self.crc, &self.config, bytes, &expected)
            .map_err(|mismatch| UnitDamage::Header { unit, mismatch })?;
        let payload = &bytes[self.layout.header_bytes()..];
        if self.crc.checksum(payload) != verified.chunk_crc(0) {
            return Err(UnitDamage::Chunk { unit });
        }
        let u64_at = |at: usize| u64::from_le_bytes(payload[at..at + 8].try_into().unwrap());
        if unit == 0 {
            let recorded = u32::from_le_bytes(payload[16..20].try_into().unwrap());
            let (rows, entries) = (u64_at(0), u64_at(8));
            let contradicts = if recorded != named {
                Some(UnitDamage::Units { recorded, named })
            } else {
                (units(rows) != u64::from(named) || entries > rows || nonzero(&payload[20..]))
                    .then_some(content)
            };
            if let Some(damage) = contradicts {
                // Unit 0 passed its identity and crc checks, so a count it contradicts marks another encoding.
                tally.unit_0 = true;
                return Err(damage);
            }
            tally.counts = Some((rows, entries));
        } else {
            let filled = u32::from_le_bytes(payload[..4].try_into().unwrap()) as usize;
            let unused = &payload[ROWS_AT + filled.min(ROWS) * ROW_LEN..];
            if filled == 0 || filled > ROWS || payload[4..ROWS_AT] != [0; 4] || nonzero(unused) {
                return Err(content);
            }
            let (packed, _) = payload[ROWS_AT..ROWS_AT + filled * ROW_LEN].as_chunks::<ROW_LEN>();
            let from = rows.len();
            rows.extend(packed.iter().map_while(row));
            if rows.len() - from < filled {
                rows.truncate(from);
                return Err(content);
            }
            tally.rows += filled as u64;
            if filled < ROWS && unit + 1 < named {
                tally.short.get_or_insert(unit as usize);
            }
            if unit + 1 == named {
                tally.last = Some(filled);
            }
        }
        Ok(())
    }

    /// The routing fingerprint of `key` and its destination.
    fn route(&self, key: &Key) -> (u64, usize) {
        let mut words = [0; LANES];
        self.hasher
            .fingerprints(std::slice::from_ref(key), &mut words);
        (words[0], reduce(words[0], self.destinations))
    }

    /// Adds `row`'s checks that need no other row to `tally`, routes an opening row's key into `row.print` and
    /// `row.dest`, counts it as its destination's opener, and routes its slot and in-bounds extent to their destinations'
    /// `facts`.
    fn check(&self, row: &mut Row, tally: &mut Tally, facts: &mut [Routed]) {
        if row.index == 0 {
            tally.shape |= !entry_in_bounds(usize::from(row.count), row.tail);
            let (print, dest) = self.route(&row.key);
            (row.print, row.dest) = (print, dest as u32);
            facts[dest].openers += 1;
            let slot = row.slot() as u64;
            match row.slot() < self.limits.slot_count {
                true => facts[(slot / self.slots) as usize]
                    .slots
                    .push(slot % self.slots),
                false => tally.slot = true,
            }
        }
        match extent_range(row.extent, &self.limits) {
            Ok((start, end)) => {
                tally.total = tally.total.saturating_add(end - start);
                let from = self.limits.payload_start;
                let (mut at, end) = (start - from, end - from);
                while at < end {
                    let (dest, base) = (at / self.units, at / self.units * self.units);
                    let edge = (base + self.units).min(end);
                    facts[dest as usize].spans.push((at - base, edge - base));
                    at = edge;
                }
            }
            Err(_) => tally.bounds = true,
        }
        if row.index + 1 == row.count
            && let Ok((record, _)) = &self.checked
        {
            tally.bounds |= !last_fits(record, row.extent, row.tail);
        }
    }
}

impl SlotDecode {
    /// The load of the slot and its suffix: the final entries by destination and their verdict, the damage found, if
    /// any, and the suffix's report. A short data unit before the last, a row that breaks an entry other than by
    /// continuing the entry an undecoded unit cut, an intact unit 0 that contradicts the named count, rows or entries
    /// above unit 0's counts, a last unit holding other rows than those counts imply, and counts missed while every unit
    /// decoded cannot follow from another unit's damage: the slot holds an encoding other than the one its identity
    /// names, so it loads cold with the stale-write refusal. Every other damage keeps the entries of the intact units
    /// (`LossIsFaultLocal`).
    ///
    /// The verdict of an inconsistent slot is the stale-write refusal, whatever the guard decides. Otherwise it is the
    /// first failing rule of: the guard's rules over the slot's whole entries in the batch guard's order, then over the
    /// final set `Entries` past `n_max` and `Units` when the in-bounds units of the kept whole slot entries and the
    /// suffix's live entries pass the capacity, so the rows of an entry a damaged unit cut count in the slot's rules
    /// alone. A slot entry of a session the reader does not admit is
    /// withheld, outside the final set. The replay keeps
    /// only suffix entries that fit the limits, and keys, slots and units are pairwise distinct in the final set once
    /// the slot passes the guard, by ONE-OWNER.
    ///
    /// The first damage is the lowest failed unit's, else the lowest unread unit's, except that a cross-unit
    /// inconsistency outranks a failed read. Each rule of the verdict is a predicate over the decoded rows and the
    /// replayed records, so the load is independent of window and job order. `None` when the decode is not done, a
    /// helper failed a job, or the allocator refused a guard's bitmaps, a window's chunks, a destination's room or a
    /// seal's scratch, so the caller keeps the record; the stale-write precedence applies to a load returned.
    #[must_use]
    pub fn finish(mut self) -> Option<SlotLoad> {
        if self.helper_failed || !self.done() {
            return None;
        }
        let last = self.context.named as usize - 1;
        if self.regroup.open.is_some() {
            self.regroup.broken.get_or_insert(last);
            self.regroup.foreign = true;
        }
        let mut guards = Vec::with_capacity(self.homes.len());
        guards.extend(self.homes.drain(..).flatten());
        let Tally {
            rows,
            short,
            last: tail_rows,
            counts,
            unit_0,
            ..
        } = self.tally;
        let Regroup {
            broken,
            foreign,
            starts,
            ..
        } = self.regroup;
        let Replayed {
            report,
            chunks,
            units: suffix,
            patch,
            ..
        } = *self.replayed?;
        let (held, failed, unread, found) = (self.damage, self.failed, self.unread, self.found);
        let content = |at: usize| UnitDamage::Content { unit: at as u32 };
        let contradicts = counts.is_some_and(|(counted, whole)| {
            starts > whole
                || whole.saturating_sub(found) > counted.saturating_sub(rows)
                || tail_rows.is_some_and(|filled| {
                    (last as u64 - 1) * ROWS as u64 + filled as u64 != counted
                })
        });
        let inconsistent = short.is_some() || foreign || unit_0 || contradicts;
        // An inconsistency among decoded units outranks a failed read; a broken entry may follow the gap an unread
        // unit left.
        let first = match held {
            Some(UnitDamage::Unread { .. }) if inconsistent => {
                Some(content(short.or(broken).unwrap_or(last)))
            }
            _ => held.or(short.map(content)).or(broken.map(content)),
        }
        .or(inconsistent.then(|| content(last)));
        let sum = |count: fn(&DestGuard) -> u64| guards.iter().map(count).sum::<u64>();
        let live = chunks.iter().map(|chunk| chunk.len() as u64).sum::<u64>();
        let entries = found - sum(|g| g.gone.dropped) + live;
        let units = sum(|g| g.units).saturating_add(suffix);
        let verdict = match verdict(&self.context, self.tally, (found, entries, units), &guards) {
            _ if inconsistent => Err(LoadRefusal::StaleWrite),
            verdict => verdict,
        };
        let (slot_superseded, slot_withheld) =
            (sum(|g| g.gone.superseded), sum(|g| g.gone.withheld));
        // Each destination's chunk list takes the suffix's chunk in place, so the load allocates no new list.
        let shards = (guards.into_iter().zip(chunks))
            .map(|(guard, live)| {
                let mut chunks = guard.chunks;
                chunks.extend(Some(live).filter(|live| !live.is_empty()));
                chunks
            })
            .collect();
        Some(SlotLoad {
            verdict,
            shards,
            damage: first.map(|first| Damage {
                first,
                failed,
                unread,
            }),
            suffix: report,
            slot_superseded,
            slot_withheld,
            slot_found: found,
            patch,
        })
    }
}

/// Rows regrouped into whole entries in capture order, with their keys' fingerprints, each routed to its destination's
/// chunk, as [`unit`](Self::unit) states.
#[derive(Debug, Default)]
struct Regroup {
    /// The slot's named unit count, which bounds the rows still to come.
    named: usize,
    /// The rows of each unit before the first opening row, `None` for an undecoded unit, and that row's unit.
    lead: Vec<(usize, Option<Vec<Row>>)>,
    opened: Option<usize>,
    first: Option<Row>,
    /// Each destination's whole entries, or the one storage a window's destinations share.
    chunks: Vec<Entries>,
    /// Where each destination's next entry and extent go in the shared storage; empty when each destination's
    /// entries go to the end of its own chunk.
    places: Vec<(usize, usize)>,
    /// The open entry, with its fingerprint and destination, the extent index the next row must carry and the entry's
    /// extent count; an orphan entry, opened by a continuation row, consumes its rows and is never kept.
    open: Option<(CaptureEntry, (u64, u32), u16, u16)>,
    orphan: bool,
    /// The entry the last undecoded unit cut.
    cut: Option<(CaptureEntry, (u64, u32), u16, u16)>,
    /// The most rows the undecoded data units since the last regrouped row hold; while nonzero, the next row may
    /// continue the entry those units cut.
    hidden: usize,
    starts: u64,
    /// The first unit whose rows break an entry.
    broken: Option<usize>,
    /// A row break contradicts the decoded entry sequence.
    foreign: bool,
}

impl Regroup {
    /// Regroups `rows`, the rows of unit `at`, into whole entries; `None` stands for a unit that did not decode.
    /// Callers pass each unit once, in unit order; until `opened` is set, rows before the first opening row go to
    /// `lead`. A missing unit or a row that does not continue the open entry drops that entry. A break is foreign
    /// unless it is a continuation row after an undecoded unit, before the next row that opens an entry.
    fn unit(&mut self, at: usize, mut rows: Option<&[Row]>) {
        if self.opened.is_none() {
            let opens = rows.and_then(|rows| rows.iter().position(|row| row.index == 0));
            let (lead, body) = rows
                .map(|rows| rows.split_at(opens.unwrap_or(rows.len())))
                .unzip();
            self.lead.push((at, lead.map(<[Row]>::to_vec)));
            if opens.is_none() {
                return;
            }
            self.first = body.and_then(|rows: &[Row]| rows.first().copied());
            (rows, self.opened) = (body, Some(at));
        }
        let Some(rows) = rows else {
            if let Some(open) = self.open.take() {
                self.cut = Some(open);
            }
            // Entry rows reside in data units (`at > 0`), so only an undecoded data unit can interrupt an entry.
            if at > 0 {
                self.hidden += ROWS;
            }
            return;
        };
        // Every unit from `at` on holds at most `ROWS` rows, so `left` bounds the rows still to come.
        let mut left = (self.named - at) * ROWS;
        // Each row is read where it lies in `rows`: a copy of the 96-byte row to the stack is stored in wide pieces, and
        // the loop's first reads are narrow fields out of the middle of those stores.
        for row in rows {
            left -= 1;
            let (entry, route) = match self.open.take() {
                Some((mut entry, route, next, count))
                    if row.index == next && row.count == count && row.continues(&entry) =>
                {
                    entry.extents.push(row.extent);
                    (entry, route)
                }
                // The general arm below with no held or cut entry and no hidden rows.
                None if row.index == 0 && self.cut.is_none() && self.hidden == 0 => {
                    self.starts += 1;
                    self.orphan = false;
                    if row.count == 1 {
                        self.put(row.dest as usize, row.loaded(), &[row.extent]);
                        continue;
                    }
                    (row.open(left), (row.print, row.dest))
                }
                held => {
                    if !self.resumes(at, held.is_some(), row) {
                        self.starts += 1;
                    }
                    self.orphan = row.index != 0;
                    (row.open(left), (row.print, row.dest))
                }
            };
            if row.index + 1 < row.count {
                self.open = Some((entry, route, row.index + 1, row.count));
            } else if !std::mem::take(&mut self.orphan) {
                let (print, dest) = route;
                self.put(dest as usize, Loaded::of(&entry, print), &entry.extents);
            }
        }
    }

    /// Adds the whole entry `entry` of extents `extents` to destination `dest`: at the destination's place in the
    /// shared storage, which then moves past the entry, or at the end of the destination's chunk. A destination's
    /// run in the shared storage has room for one entry per opener routed to it and one extent per row from each of
    /// those openers up to the next opener, so every place lies inside the run.
    // Forced inline into the row loop: an outlined call takes `entry` through the caller's stack, where the loop stores
    // it field by field, and reads it back in wide pieces to copy it to its place.
    #[inline(always)]
    fn put(&mut self, dest: usize, entry: Loaded, extents: &[u64]) {
        let Some((at, extent)) = self.places.get_mut(dest) else {
            let chunk = &mut self.chunks[dest];
            chunk.entries.push(entry);
            return chunk.extents.extend_from_slice(extents);
        };
        let held = &mut self.chunks[0];
        held.entries[*at] = entry;
        held.extents[*extent..*extent + extents.len()].copy_from_slice(extents);
        (*at, *extent) = (*at + 1, *extent + extents.len());
    }

    /// Judges `row`, the first row at unit `at` after the open entry was lost, against the entry an undecoded unit cut
    /// and the `hidden` rows. `held` means the row broke an open entry and makes the break foreign; a break is also
    /// foreign when `hidden == 0` or the hidden rows cannot account for the break. [`append`](Self::append) passes a
    /// later window's first opening row. Returns whether the row continues the cut entry.
    fn resumes(&mut self, at: usize, held: bool, row: &Row) -> bool {
        let (cut, hidden) = (self.cut.take(), std::mem::take(&mut self.hidden));
        let index = row.index;
        let names_cut = cut.as_ref().is_some_and(|(entry, ..)| row.continues(entry));
        let continues = names_cut
            && cut.as_ref().is_some_and(|(_, _, next, count)| {
                row.count == *count && index >= *next && usize::from(index - next) == hidden
            });
        let rest = cut.map_or(0, |(_, _, next, count)| usize::from(count - next));
        let fits = continues || (!names_cut && rest + usize::from(index) <= hidden);
        if held || index != 0 || !fits {
            self.broken.get_or_insert(at);
            self.foreign |= held || hidden == 0 || !fits;
        }
        continues
    }

    /// Continues this regroup with `later`, the units after it: `later`'s lead regroups here, and its first opening row
    /// breaks the entry still open here. `later`'s completed chunks were handed to their destinations before the call,
    /// so `append` takes only its open, cut and lead state.
    fn append(&mut self, mut later: Regroup) {
        for (at, rows) in std::mem::take(&mut later.lead) {
            self.unit(at, rows.as_deref());
        }
        let (Some(at), Some(first)) = (later.opened, later.first) else {
            return;
        };
        let held = self.open.take().is_some();
        self.resumes(at, held, &first);
        self.broken = self.broken.or(later.broken);
        self.foreign |= later.foreign;
        self.starts += later.starts;
        (self.open, self.orphan) = (later.open, later.orphan);
        (self.cut, self.hidden) = (later.cut, later.hidden);
    }
}

#[cfg(kani)]
mod verification {
    use super::super::capture::CaptureEntry;
    use super::{Checkpoint, Member, ROW_LEN, fields, put_row, row};
    use crate::net::ownership::Shard;

    /// Over two symbolic `(shard, session, capture, unit)` tuples: the unit identities are equal exactly when the
    /// tuples are, so a unit of another shard, session, capture or unit index fails a reader's identity check; the
    /// allocation word holds the capture above the unit index and the version is the capture.
    #[kani::proof]
    fn unit_identity_is_injective() {
        let (Some(s1), Some(s2)) = (Shard::new(kani::any()), Shard::new(kani::any())) else {
            return;
        };
        let a = Checkpoint {
            shard: s1,
            session: kani::any(),
            capture: kani::any(),
        };
        let b = Checkpoint {
            shard: s2,
            session: kani::any(),
            capture: kani::any(),
        };
        let (i, j): (u32, u32) = (kani::any(), kani::any());
        let (x, y) = (a.identity(i), b.identity(j));
        kani::cover!(x == y);
        kani::cover!(a == b && i != j);
        assert_eq!(x == y, (a, i) == (b, j));
        assert_eq!(x.allocation >> 32, u64::from(a.capture));
        assert_eq!(x.allocation as u32, i);
        assert_eq!(x.version, u64::from(a.capture));
        assert_eq!(x.session, a.session);
    }

    /// Over symbolic row bytes: [`row`] admits exactly the rows whose reserved bytes are zero and whose extent index
    /// lies below a nonzero extent count, and [`put_row`] of an admitted row's fields, for an entry of up to three
    /// extents, writes the same bytes back.
    #[kani::proof]
    #[kani::unwind(97)]
    fn row_codec_round_trips_and_refuses_reserved_bytes() {
        let bytes: [u8; ROW_LEN] = kani::any();
        let index = u16::from_le_bytes([bytes[70], bytes[71]]);
        let count = u16::from_le_bytes([bytes[72], bytes[73]]);
        let zero = bytes[74..80].iter().chain(&bytes[88..96]).all(|&b| b == 0);
        let decoded = row(&bytes);
        kani::cover!(decoded.is_some());
        kani::cover!(decoded.is_none() && zero);
        assert_eq!(decoded.is_some(), zero && count > 0 && index < count);
        let Some(decoded) = decoded else {
            return;
        };
        kani::assume(decoded.count <= 3);
        let entry = CaptureEntry {
            key: decoded.key,
            allocation: decoded.allocation,
            session: decoded.session,
            version: decoded.version,
            deadline_ns: decoded.deadline_ns,
            lifetime_ms: decoded.lifetime_ms,
            tail: decoded.tail,
            extents: vec![decoded.extent; usize::from(decoded.count)],
        };
        let mut written = [0; ROW_LEN];
        let member = Member {
            fields: &fields(&entry),
            extents: &entry.extents,
        };
        put_row(&mut written, &member, decoded.index, decoded.extent);
        assert!(written == bytes);
    }
}
