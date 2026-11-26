//! Replay of a tenure chain's mutation suffixes over the named checkpoint's entries: the blocks of each ancestry
//! suffix from the cut, read and checked one by one, their records regrouped whole, and the frontier applied in the
//! preservation model's order.
//!
//! - CHECK-BEFORE-APPLY: a block applies only after its identity, crc, content and continuation checks, and a record
//!   only when whole; any failed check is a hole.
//! - FRONTIER: every REMOVE, and the REMOVE half of every REPLACE, in a whole record of any suffix excludes its
//!   identity whatever the holes: a tombstone depends on no other record, and an identity names one incarnation.
//! - NO-SKIP: an INSERT applies only before its suffix's first hole; the inserts behind it are named as dropped. A
//!   hole below the certified end, in a block that passed its identity and crc checks, or followed by such a block
//!   of its suffix, which the one-outstanding writer wrote only after it, is damage; any other hole is the tail.
//! - ONE-OWNER: the checkpoint is level 0 and suffix `k` level `k + 1`. A later entry of a key supersedes earlier
//!   ones; an entry sharing a payload unit or a slot with an entry of a later level, superseded or not, is
//!   superseded, because that level's tenure allocated it only after its recovery excluded the earlier owner; two
//!   entries of one level sharing a unit or slot, neither superseded, are both withheld. Loss stays local to the
//!   entries a fault names; [`SuffixReport::installable`] states the replay's own condition for installing, and the
//!   warm install also refuses a load that withheld any entry.
//!
//! [`patch`] replays the suffixes alone and returns a [`Patch`] that gives each checkpoint entry its ONE-OWNER fate
//! separately: checkpoint entries that passed the load guard share no key, slot or unit, so a checkpoint entry is
//! superseded exactly when it meets a key, slot or unit of a suffix entry no record excluded, and no checkpoint entry
//! changes a suffix entry's fate.

use crate::failover::records::{Layout, Suffix};
use crate::index::Key;
use crate::net::ownership::Shard;

use super::super::allocation::AllocationId;
use super::super::geometry::DIRECT_UNITS;
use super::super::prefetch::hint_read;
use super::super::record::{Crc32c, admits};
use super::capture::CaptureEntry;
use super::delta::{
    Assembler, Block, BlockHole, INSERT_FIXED, Identity, PART_HEADER, Part, Record, UNIT_LEN,
    blocks, decode, identity_of, room, span,
};
use super::load_guard::{
    LoadLimits, LoadRefusal, checked, extent_range, fingerprint, last_fits, sort_high,
};

/// A hole in a suffix: the first block that failed and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hole {
    pub lsn: u64,
    pub cause: BlockHole,
}

/// What a replay found beside its live entries. A caller installs the entries only once the report is
/// [`installable`](Self::installable), and reports the holes.
#[must_use]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SuffixReport {
    /// Identities a REMOVE or a REPLACE excluded.
    pub excluded: Vec<Identity>,
    /// Identities a later entry of their key, or of a later level sharing a unit or slot, superseded.
    pub superseded: Vec<Identity>,
    /// Identities withheld because an entry of their level shares a unit or slot.
    pub withheld: Vec<Identity>,
    /// Whole inserts behind their suffix's first hole.
    pub dropped: Vec<Identity>,
    /// The first hole of each suffix that is damage.
    pub damage: Vec<Hole>,
    /// The first hole of each suffix that ends its unflushed tail.
    pub tails: Vec<Hole>,
    /// The LSNs whose unit the device could not read, the region's end of each suffix recorded longer than it, and,
    /// when the replay refuses its limits, the first LSN it leaves unread.
    pub unread: Vec<u64>,
}

impl SuffixReport {
    /// Whether the replay's entries meet its condition for installing: no LSN is unread and no suffix has a damage
    /// hole. The warm install also refuses a load that withheld a slot or suffix entry. An unread
    /// unit may yield its records on a later read. Under a damage hole the entries are a partial history of the
    /// hole's suffix: they lack the inserts the hole lost and every insert behind it, and may keep an entry whose
    /// REMOVE the hole held. Dropped inserts, tails, exclusions, supersessions and withheld entries are the replay's
    /// outcome and leave the report installable; the warm install still refuses a load with a withheld entry.
    pub fn installable(&self) -> bool {
        self.unread.is_empty() && self.damage.is_empty()
    }
}

/// Whether a [`shaped`](super::delta::shaped) `entry` fits `limits` for the reader of session `reader`: of a session the reader admits, its
/// slot below the count, every extent inside the payload area and a last record that fits. A decoded insert is
/// already shaped; a checkpoint entry is checked for its shape as well.
///
/// # Errors
///
/// `Limits` when `limits` are invalid.
fn ranged(
    limits: &LoadLimits,
    reader: u64,
) -> Result<impl Fn(&CaptureEntry) -> bool + '_, LoadRefusal> {
    let (pricer, _) = checked(*limits)?;
    Ok(move |entry: &CaptureEntry| {
        let (identity, extents) = (identity_of(entry), &entry.extents);
        let inside = |&bits: &u64| extent_range(bits, limits).is_ok();
        let last = extents.last().copied().unwrap_or_default();
        let admitted = admits(&identity, &identity, reader) && entry.slot() < limits.slot_count;
        admitted && extents.iter().all(inside) && last_fits(&pricer, last, entry.tail)
    })
}

/// The result of a replay over the checkpoint's entries.
#[cfg(test)]
#[must_use]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SuffixLoad {
    /// The live entries, checkpoint order then replay order.
    pub entries: Vec<CaptureEntry>,
    pub report: SuffixReport,
}

#[cfg(test)]
impl SuffixLoad {
    pub fn installable(&self) -> bool {
        self.report.installable()
    }
}

/// The fields of an identity, in a total order.
type Fields = ([u8; 32], u64, u64, u64);

fn fields(id: Identity) -> Fields {
    (id.key, id.allocation, id.session, id.version)
}

/// Items in the order of the bucket their key hashes to, then their own, and the end of each bucket's run among
/// them: a search reads the ends of one bucket and searches its sorted run.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Bucketed<T> {
    items: Vec<T>,
    ends: Vec<usize>,
}

impl<T: Ord + Copy + Default> Bucketed<T> {
    /// `items` under one bucket per item, rounded up to a power of two, where `key` gives an item's key: a count
    /// of each bucket's items gives its run, each item goes to the next place of its bucket's run, and each run
    /// then sorts.
    pub(super) fn new(items: impl Iterator<Item = T> + Clone, key: fn(&T) -> &Key) -> Self {
        let count = items.clone().count();
        let bits = count.next_power_of_two().trailing_zeros();
        let bucket = |item: &T| bucket(key(item), bits);
        let mut ends = vec![0; 1 << bits];
        for item in items.clone() {
            ends[bucket(&item)] += 1;
        }
        let mut start = 0;
        for count in &mut ends {
            start += std::mem::replace(count, start);
        }
        let mut placed = vec![T::default(); count];
        for item in items {
            let at = &mut ends[bucket(&item)];
            placed[*at] = item;
            *at += 1;
        }
        let mut from = 0;
        for &end in &ends {
            placed[from..end].sort_unstable();
            from = end;
        }
        Self {
            items: placed,
            ends,
        }
    }

    /// Whether the items hold `item`, whose key is `key`.
    pub(super) fn holds(&self, item: &T, key: &Key) -> bool {
        let bucket = bucket(key, self.ends.len().trailing_zeros());
        let from = bucket.checked_sub(1).map_or(0, |before| self.ends[before]);
        let run = &self.items[from..self.ends[bucket]];
        if run.len() <= SCAN {
            run.contains(item)
        } else {
            run.binary_search(item).is_ok()
        }
    }
}

/// Binary search keeps lookup comparisons logarithmic for collision-heavy buckets above this threshold.
const SCAN: usize = 8;

/// The bucket of `key` among `2^bits`: the top bits of the product that also places its filter word.
fn bucket(key: &Key, bits: u32) -> usize {
    (key_word(key).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 1 >> (63 - bits)) as usize
}

/// What a replayed suffix does to the checkpoint's entries, as [`fate`](Self::fate) states: the identities its records
/// excluded and the keys of the suffix entries no record excluded, each by its key's bucket, and those entries' slots
/// and units, each sorted and the units as disjoint spans.
#[derive(Debug, PartialEq, Eq)]
pub struct Patch {
    excluded: Bucketed<Fields>,
    keys: Bucketed<Key>,
    slots: Vec<usize>,
    spans: Vec<(u64, u64)>,
    /// The end of every [`STRIDE`]th span, which a span search reads before the spans themselves.
    ends: Vec<u64>,
    /// A hashed bit filter, at least 32 bits per word, over the keys of the excluded identities and the suffix
    /// entries and the 64-unit blocks their spans touch, each setting three bits of one filter word: an entry that
    /// meets the patch by its key or a unit finds every bit of its key or of a block of its extents set.
    filter: Vec<u64>,
}

/// The count of spans from one sampled span to the next.
const STRIDE: usize = 64;

/// The filter word of a key.
fn key_word(key: &Key) -> u64 {
    (key.as_chunks::<8>().0.iter()).fold(0, |word, part| word ^ u64::from_le_bytes(*part))
}

/// The filter words of the 64-unit blocks the units `[start, end)` touch.
fn block_words((start, end): (u64, u64)) -> impl Iterator<Item = u64> {
    (start >> 6..=end.saturating_sub(1).max(start) >> 6).map(|block| block ^ 0xA5A5_0000_0000_0000)
}

/// The slot index `identity`'s allocation names.
fn slot_of(identity: &Identity) -> usize {
    AllocationId::of_record_tag(identity.allocation).slot_index()
}

/// Where a slot search of a [`Patch`] ended, and the slot it searched.
#[derive(Debug, Default)]
pub struct Seek {
    at: usize,
    below: Option<usize>,
}

/// A checkpoint entry's fate under a [`Patch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fate {
    Kept,
    Excluded,
    Superseded,
}

impl Patch {
    /// The patch of `report`'s exclusions and of `entries`, the suffix entries no record excluded.
    pub(super) fn new<'a>(
        report: &SuffixReport,
        entries: impl Iterator<Item = &'a CaptureEntry> + Clone,
    ) -> Self {
        let entries = || entries.clone();
        let excluded = report.excluded.iter().copied().map(fields);
        let mut patch = Self {
            excluded: Bucketed::new(excluded, |fields| &fields.0),
            keys: Bucketed::new(entries().map(|entry| entry.key), |key| key),
            slots: entries().map(CaptureEntry::slot).collect(),
            spans: (entries().flat_map(|entry| entry.extents.iter().map(|&bits| span(bits))))
                .collect(),
            ends: Vec::new(),
            filter: Vec::new(),
        };
        patch.slots.sort_unstable();
        patch.spans.sort_unstable();
        patch.spans.dedup_by(|later, earlier| {
            let joins = later.0 <= earlier.1;
            if joins {
                earlier.1 = earlier.1.max(later.1);
            }
            joins
        });
        patch.ends = (patch.spans.iter().step_by(STRIDE).map(|span| span.1)).collect();
        // The filter over the keys of the excluded identities and of the entries, and over the spans.
        let keys = patch.excluded.items.iter().map(|fields| &fields.0);
        let keys = keys.chain(&patch.keys.items);
        let words: Vec<u64> = (keys.map(key_word))
            .chain(patch.spans.iter().flat_map(|&span| block_words(span)))
            .collect();
        patch.filter = vec![0; (32 * words.len()).next_power_of_two().max(64) / 64];
        for word in words {
            let (at, bits) = patch.probe(word);
            patch.filter[at] |= bits;
        }
        patch
    }

    /// The filter word of `word` and its three bits there, by multiplicative hashing: the product's top bits select
    /// the filter word and its low eighteen bits the three bits.
    fn probe(&self, word: u64) -> (usize, u64) {
        let hashed = word.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        let at = hashed >> 1 >> (63 - self.filter.len().trailing_zeros());
        let bits = 1 << (hashed & 63) | 1 << (hashed >> 6 & 63) | 1 << (hashed >> 12 & 63);
        (at as usize, bits)
    }

    /// The first span that ends past unit `start`. The search starts at the last sampled span that ends at or before
    /// `start`, or at the first span when none does, and covers the two [`STRIDE`]s of spans from there, which hold
    /// the span.
    fn span_past(&self, start: u64) -> Option<&(u64, u64)> {
        let run = self
            .ends
            .partition_point(|&end| end <= start)
            .saturating_sub(1)
            * STRIDE;
        let spans = &self.spans[run..];
        let spans = &spans[..spans.len().min(2 * STRIDE)];
        spans.get(spans.partition_point(|span| span.1 <= start))
    }

    /// Requests the filter words [`fate`](Self::fate) reads for the key and for the first 64-unit block of the first
    /// extent of the entry of identity `entry` and extents `extents`.
    pub fn request(&self, entry: &Identity, extents: &[u64]) {
        let block = extents.first().map_or(0, |&bits| span(bits).0 >> 6);
        for word in [key_word(&entry.key), block ^ 0xA5A5_0000_0000_0000] {
            hint_read((&raw const self.filter[self.probe(word).0]).cast());
        }
    }

    fn hits(&self, word: u64) -> bool {
        let (at, bits) = self.probe(word);
        self.filter[at] & bits == bits
    }

    /// Whether the patch changes no entry.
    pub fn is_empty(&self) -> bool {
        self.excluded.items.is_empty() && self.keys.items.is_empty()
    }

    /// Whether a suffix entry names `slot`. `seek` holds where the search of the slot before it ended: a slot at or
    /// above that one, the order a capture pass emits its members in, is found by stepping forward from there, and a
    /// lower slot by a search of every slot.
    fn names(&self, seek: &mut Seek, slot: usize) -> bool {
        if seek.below.is_none_or(|below| slot < below) {
            seek.at = self.slots.partition_point(|&held| held < slot);
        }
        while self.slots.get(seek.at).is_some_and(|&held| held < slot) {
            seek.at += 1;
        }
        seek.below = Some(slot);
        self.slots.get(seek.at) == Some(&slot)
    }

    /// The fate of the checkpoint entry of identity `entry` and extents `extents`: `Excluded` when a record excluded
    /// the identity, else `Superseded` when the entry shares a key, a slot or a payload unit with a suffix entry, else
    /// `Kept`: the fate ONE-OWNER gives a checkpoint entry that shares no key, slot or unit with another checkpoint
    /// entry. A caller passes a run of entries with one `seek`, which makes the slot searches of entries in
    /// ascending slot order one forward walk; the fate is the same under any `seek` that only this patch's searches
    /// have moved.
    pub fn fate(&self, seek: &mut Seek, entry: &Identity, extents: &[u64]) -> Fate {
        let meets = |&bits: &u64| {
            let (start, end) = span(bits);
            #[cfg(test)]
            if planted(Plant::SpanBlind) {
                return false;
            }
            // A span past `DIRECT_UNITS` units fails the guard's bounds; it skips the filter, whose probes grow with it.
            (end - start > u64::from(DIRECT_UNITS)
                || block_words((start, end)).any(|w| self.hits(w)))
                && self.span_past(start).is_some_and(|span| span.0 < end)
        };
        let key = self.hits(key_word(&entry.key));
        let slot = self.names(seek, slot_of(entry));
        if key && self.excluded.holds(&fields(*entry), &entry.key) {
            Fate::Excluded
        } else if key && self.keys.holds(&entry.key, &entry.key)
            || slot
            || extents.iter().any(meets)
        {
            Fate::Superseded
        } else {
            Fate::Kept
        }
    }
}

/// A planted defect for a negative control.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Plant {
    /// Inserts after a hole apply.
    SkipHoles,
    /// A REPLACE cut by a hole excludes its old identity from its first part alone.
    PartialRecord,
    /// No record excludes.
    NoExclusion,
    /// The last suffix drops its intact inserts of even slots and names them as dropped.
    DropIntact,
    /// A checkpoint entry sharing only units with a suffix entry is kept.
    SpanBlind,
    /// Every insert, a REPLACE's new entry included, leaves the replay before it applies: it supersedes nothing and
    /// enters no level.
    DropInserts,
}

#[cfg(test)]
thread_local! {
    pub(crate) static PLANT: std::cell::Cell<Option<Plant>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn planted(plant: Plant) -> bool {
    PLANT.with(std::cell::Cell::get) == Some(plant)
}

/// The LSNs of `suffix` a replay from `cut` reads over the delta region of `layout`: from the later of its start and
/// the cut to the earlier of its end and the region's end, `start + J`.
pub fn lsns(suffix: &Suffix, cut: u64, layout: &Layout) -> std::ops::Range<u64> {
    suffix.start.max(cut)..suffix.end.min(suffix.start.saturating_add(blocks(layout)))
}

/// Replays `ancestry` over `entries`, the named checkpoint's, from `cut`, as [`records`] reads it; the batch form of
/// [`patch`] and [`Patch::fate`], which resolves the checkpoint's entries with the suffix's.
#[cfg(test)]
pub fn replay(
    reader: (Crc32c, Shard, u64),
    (layout, limits): (&Layout, &LoadLimits),
    mut entries: Vec<CaptureEntry>,
    cut: u64,
    ancestry: &[Suffix],
    read: impl FnMut(u64, &mut [u8; UNIT_LEN]) -> bool,
) -> Result<SuffixLoad, LoadRefusal> {
    let ranged = ranged(limits, reader.2)?;
    let unfit = entries.extract_if(.., |entry| !(super::delta::shaped(entry) && ranged(entry)));
    let unfit: Vec<Identity> = unfit.map(|entry| identity_of(&entry)).collect();
    let (entries, levels, mut report) =
        records(reader, (layout, limits), entries, cut, ancestry, read)?;
    report.withheld.splice(0..0, unfit);
    let fate = keys(&entries, &report.excluded);
    let entries = resolve(entries, fate, &levels, &mut report);
    Ok(SuffixLoad { entries, report })
}

/// Replays `ancestry` alone from `cut`, as [`records`] reads it: the suffix's live entries in replay order, its report,
/// and the patch that gives each checkpoint entry its fate.
///
/// # Errors
///
/// `Limits` when `limits` are invalid.
pub fn patch(
    reader: (Crc32c, Shard, u64),
    (layout, limits): (&Layout, &LoadLimits),
    cut: u64,
    ancestry: &[Suffix],
    read: impl FnMut(u64, &mut [u8; UNIT_LEN]) -> bool,
) -> Result<(Vec<CaptureEntry>, SuffixReport, Patch), LoadRefusal> {
    let (entries, levels, mut report) =
        records(reader, (layout, limits), Vec::new(), cut, ancestry, read)?;
    let fate = keys(&entries, &report.excluded);
    let unexcluded = entries
        .iter()
        .zip(&fate)
        .filter(|(_, fate)| **fate != EXCLUDED);
    let patch = Patch::new(&report, unexcluded.map(|(entry, _)| entry));
    Ok((resolve(entries, fate, &levels, &mut report), report, patch))
}

/// The bytes a replay of `blocks` blocks holds at most: each block's unit and parts, and per payload byte its share of
/// the records that byte completes, at most one insert per [`PART_HEADER`] and [`INSERT_FIXED`] bytes, and of their
/// extents, at most one per 8 bytes. A REMOVE body packs denser, but a REMOVE holds only its excluded identity in the
/// report, the patch and a key run, its sort words and one filter word, which a record's share over the bytes of a
/// REMOVE's part covers with the two ends of its identity's bucket. A record holds its entry, its routed copy, its
/// report identity, its key run's identities and key, its key and slot sort words, its fate, its slot pair, its patch
/// key and slot, its key's filter word and the two ends of its key's bucket; an extent holds its locator, in its
/// entry and then in its destination's run, its span sort words, its overlap claim, its patch span and two filter
/// words, an extent spanning at most `DIRECT_UNITS` units and so two 64-unit blocks. Each vector holds up to twice
/// its length, each filter word up to eight filter bytes, and a patch up to two buckets per key. `None` when the
/// bound overflows `usize`.
pub fn bytes(blocks: u64) -> Option<usize> {
    let record = 2 * (size_of::<CaptureEntry>() + size_of::<(CaptureEntry, u64)>())
        + 4 * size_of::<Identity>()
        + 2 * (size_of::<Key>() + size_of::<usize>())
        + 2 * size_of::<(usize, usize)>()
        + 4 * size_of::<u64>()
        + 1
        + (size_of::<u64>() + 8)
        + 2 * size_of::<usize>()
        + 64;
    let extent = 2 * size_of::<u64>()
        + 3 * size_of::<u64>()
        + size_of::<(u64, usize)>()
        + 2 * size_of::<(u64, u64)>()
        + 2 * (size_of::<u64>() + 8);
    let per_byte = record.div_ceil(PART_HEADER + INSERT_FIXED) + extent.div_ceil(8);
    let parts = size_of::<Part>().div_ceil(PART_HEADER);
    usize::try_from(blocks)
        .ok()?
        .checked_mul(UNIT_LEN + room() * (per_byte + parts))
}

/// Replays the records of `ancestry` from `cut` after `entries`, for the reader of session `reader` over the delta
/// region of `layout`: `entries` followed by the inserts each record applies, in replay order, the end of each level,
/// `entries` first, and the report without supersession. An insert that does not fit `limits` for the reader is a
/// hole. `read` fills the buffer with LSN `lsn`'s unit and returns whether it did, once per LSN of each suffix's
/// [`lsns`], oldest suffix first, LSNs ascending: blocks after a hole are still read for their exclusions; a failed
/// read is `Unread`. A suffix longer than the region is read to the region's end, which is then unread, and a record
/// still open at a suffix's end is damage.
///
/// # Errors
///
/// `Limits` when `limits` are invalid.
fn records(
    (crc, shard, reader): (Crc32c, Shard, u64),
    (layout, limits): (&Layout, &LoadLimits),
    mut entries: Vec<CaptureEntry>,
    cut: u64,
    ancestry: &[Suffix],
    mut read: impl FnMut(u64, &mut [u8; UNIT_LEN]) -> bool,
) -> Result<(Vec<CaptureEntry>, Vec<usize>, SuffixReport), LoadRefusal> {
    let ranged = ranged(limits, reader)?;
    let mut load = SuffixReport::default();
    let mut levels = vec![entries.len()];
    let (mut unit, mut spare) = (Box::new([0; UNIT_LEN]), Vec::new());
    for suffix in ancestry {
        let (mut assembler, mut first) = (Assembler::default(), None::<(Hole, bool)>);
        let (session, region) = (suffix.session, suffix.start.saturating_add(blocks(layout)));
        load.unread.extend((suffix.end > region).then_some(region));
        for lsn in lsns(suffix, cut, layout) {
            let block = Block {
                shard,
                session,
                lsn,
            };
            let decoded = if read(lsn, &mut unit) {
                decode(crc, block, reader, &unit[..], spare)
            } else {
                Err(BlockHole::Unread)
            };
            let passed = matches!(decoded, Ok(_) | Err(BlockHole::Content));
            let decoded = decoded.and_then(|decoded| assembler.admit(&decoded).map(|()| decoded));
            let mut failed = decoded.as_ref().err().copied();
            load.unread
                .extend((failed == Some(BlockHole::Unread)).then_some(lsn));
            if let (Some((_, damaged)), true) = (first.as_mut(), passed) {
                *damaged = true;
            }
            for &part in decoded.iter().flatten() {
                let record = match assembler.feed(part) {
                    Ok(Some(body)) => Record::decode(part.0.kind, &body),
                    Ok(None) => continue,
                    Err(_) => None,
                };
                let Some(record) = record else {
                    failed.get_or_insert(BlockHole::Content);
                    assembler.reset();
                    continue;
                };
                let (removed, inserted) = match record {
                    Record::Insert(entry) => (None, Some(entry)),
                    Record::Remove { identity, .. } => (Some(identity), None),
                    Record::Replace { old, new, .. } => (Some(old), Some(new)),
                };
                #[cfg(test)]
                let inserted = inserted.filter(|_| !planted(Plant::DropInserts));
                if inserted.as_ref().is_some_and(|entry| !ranged(entry)) {
                    failed.get_or_insert(BlockHole::Content);
                    continue;
                }
                #[cfg(test)]
                let removed = removed.filter(|_| !planted(Plant::NoExclusion));
                load.excluded.extend(removed);
                #[cfg(test)]
                let first = first.filter(|_| !planted(Plant::SkipHoles));
                #[cfg(test)]
                let failed = failed.or_else(|| {
                    let even = inserted.as_ref().is_some_and(|entry| entry.slot() % 2 == 0);
                    (planted(Plant::DropIntact) && levels.len() == ancestry.len() && even)
                        .then_some(BlockHole::Content)
                });
                match inserted {
                    Some(entry) if first.is_none() && failed.is_none() => entries.push(entry),
                    Some(entry) => load.dropped.push(identity_of(&entry)),
                    None => {}
                }
            }
            if let Some(cause) = failed {
                first.get_or_insert((Hole { lsn, cause }, lsn < suffix.certified || passed));
                #[cfg(test)]
                if planted(Plant::PartialRecord) {
                    load.excluded.extend(assembler.open_removal());
                }
                // A record failure resets the assembler at the record; a later record of the block stays open.
                if decoded.is_err() {
                    assembler.reset();
                }
            }
            // Collecting in place keeps a decoded block's vector for the next; `decode` clears it, a hole frees it.
            let parts = decoded.unwrap_or_default().into_iter();
            spare = parts.map(|(head, _)| (head, &[][..])).collect();
        }
        let (lsn, cause) = (suffix.end.min(region).saturating_sub(1), BlockHole::Content);
        match first {
            Some((hole, true)) => load.damage.push(hole),
            Some((hole, false)) => load.tails.push(hole),
            None if assembler.open.is_some() => load.damage.push(Hole { lsn, cause }),
            None => {}
        }
        levels.push(entries.len());
    }
    Ok((entries, levels, load))
}

/// The fate [`keys`] gives an entry a record excluded.
const EXCLUDED: u8 = 3;

/// The key fates of `entries`, in replay order, under the identities `excluded` names: [`EXCLUDED`] for an entry
/// `excluded` names, 2 for an entry a later entry of its key that is not excluded supersedes, and 0 otherwise.
fn keys(entries: &[CaptureEntry], excluded: &[Identity]) -> Vec<u8> {
    // Entries, then exclusions, as `fingerprint << bits | index`: a run of one fingerprint holds every identity of a key.
    let gone = excluded.iter().map(|gone| &gone.key);
    let ids = entries.iter().map(|entry| &entry.key).chain(gone).zip(0..);
    let bits = usize::BITS - (entries.len() + excluded.len()).leading_zeros();
    let at = |key: &u64| (key & ((1 << bits) - 1)) as usize;
    let mut keys: Vec<u64> = ids.map(|(key, at)| fingerprint(key) << bits | at).collect();
    let mut aux = vec![0; keys.len()];
    let keys = sort_high(&mut keys, &mut aux, 0, u64::BITS);
    let (mut fate, mut named, mut kept) = (vec![0u8; entries.len()], Vec::new(), Vec::new());
    // A read hint for the entry or exclusion of each key 32 ahead lets the core overlap the cache misses of the runs.
    let mut ahead = keys.iter().skip(32).map(|key| match entries.get(at(key)) {
        Some(entry) => (&raw const *entry).cast::<u8>(),
        None => (&raw const excluded[at(key) - entries.len()]).cast(),
    });
    let runs = keys.chunk_by(|a, b| a >> bits == b >> bits);
    let runs = runs.inspect(|run| ahead.by_ref().take(run.len()).for_each(hint_read));
    let quad = |id: &Identity| (id.allocation, id.session, id.version, id.key);
    let named_by = |x: &u64| quad(&excluded[at(x) - entries.len()]);
    for run in runs.filter(|run| run.len() > 1) {
        let (members, gone) = run.split_at(run.partition_point(|key| at(key) < fate.len()));
        // The run's exclusions, sorted for a search, and the keys of its entries with a later entry none names.
        named.splice(.., gone.iter().map(named_by));
        named.sort_unstable();
        kept.clear();
        for member in members.iter().map(at).rev() {
            let identity = quad(&identity_of(&entries[member]));
            let later = 2 * u8::from(kept.contains(&identity.3));
            fate[member] = named.binary_search(&identity).map_or(later, |_| EXCLUDED);
            kept.extend((fate[member] == 0).then_some(identity.3));
        }
    }
    fate
}

/// Keeps at most one owner per key, payload unit and slot among the `entries` [`keys`] did not exclude, by ONE-OWNER,
/// and returns the live ones. `entries` are shaped and in replay order with `levels[k]` entries through level `k`, and
/// `fate` is their key fate. An entry conflicts with the latest entry of its slot and with every entry whose span
/// overlaps one of its own.
fn resolve(
    mut entries: Vec<CaptureEntry>,
    mut fate: Vec<u8>,
    levels: &[usize],
    load: &mut SuffixReport,
) -> Vec<CaptureEntry> {
    // Fates: `EXCLUDED`, 2 for a superseded entry, 1 for a withheld one and 0 for a live one.
    let rest = || (0..entries.len()).rev().filter(|&at| fate[at] != EXCLUDED);
    let claims = |at: usize| entries[at].extents.iter().map(|&bits| span(bits));
    let packed = |at: usize| claims(at).map(move |(start, end)| (start << 7 | (end - start), at));
    let end = |span: u64| (span >> 7) + (span & 127);
    // Conflicting pairs, the earlier entry first: each entry of a shared slot with the slot's latest entry, the last of
    // its run of `(slot, index)` pairs.
    let mut slots: Vec<(usize, usize)> = rest().map(|at| (entries[at].slot(), at)).collect();
    slots.sort_unstable();
    let mut pairs: Vec<(usize, usize)> = Vec::new();
    for run in slots.chunk_by(|a, b| a.0 == b.0) {
        let latest = run[run.len() - 1].1;
        pairs.extend(run[..run.len() - 1].iter().map(|&(_, at)| (at, latest)));
    }
    // Each claimed span as `start << 7 | length`.
    let mut spans: Vec<u64> = rest()
        .flat_map(|at| packed(at).map(|claim| claim.0))
        .collect();
    let spread = u64::BITS - spans.iter().fold(0, |top, span| top | span).leading_zeros();
    let mut aux = vec![0; spans.len()];
    let spans = sort_high(&mut spans, &mut aux, 0, spread);
    // Sorted spans with no neighbors overlapping are disjoint; any other spans are sorted again with their entries.
    let clear = spans.windows(2).all(|pair| end(pair[0]) <= pair[1] >> 7);
    let mut owned: Vec<(u64, usize)> = rest().filter(|_| !clear).flat_map(packed).collect();
    owned.sort_unstable();
    // Pairs of entries whose claims overlap, earlier first, walked for each rule: n claims of one unit make n(n-1)/2.
    let after = |at: usize| owned[at + 1..].iter().zip(std::iter::repeat(owned[at]));
    let lapping = |at: usize| after(at).take_while(|(b, a)| b.0 >> 7 < end(a.0));
    let ordered = |(b, a): (&(u64, usize), (u64, usize))| (a.1.min(b.1), a.1.max(b.1));
    let laps = || (0..owned.len()).flat_map(lapping).map(ordered);
    let clashes = || pairs.iter().copied().chain(laps());
    // A later level supersedes; in one level an earlier entry that is not superseded is withheld, and so is its peer.
    let higher = |(a, b): (usize, usize)| levels.iter().any(|&end| a < end && end <= b);
    let superseded = clashes().filter(|&pair| higher(pair));
    superseded.for_each(|(earlier, _)| fate[earlier] = 2);
    let peers = clashes().filter(|&pair| !higher(pair));
    peers.for_each(|(earlier, later)| {
        if fate[earlier] != 2 {
            (fate[earlier], fate[later]) = (1, fate[later].max(1));
        }
    });
    let fated = |mark| entries.iter().zip(&fate).filter(move |e| *e.1 == mark);
    load.withheld.extend(fated(1).map(|e| identity_of(e.0)));
    load.superseded.extend(fated(2).map(|e| identity_of(e.0)));
    let mut fates = fate.iter();
    entries.retain(|_| fates.next() == Some(&0));
    entries
}
