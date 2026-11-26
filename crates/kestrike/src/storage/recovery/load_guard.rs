//! Admission of a recovered checkpoint: a warm start loads every entry, a cold start loads none.
//!
//! `load_guard` checks the whole entry set against the pool's limits, and the named-slot reader's decode checks the same rules, in the same order, as its windows decode, then the rules a final set of the slot's entries and its suffix's can fail; `guarded_load` turns the batch verdict into either the entries themselves or one eviction event per entry plus one alarm naming the refusal. Admission is all-or-nothing, so a loaded pool holds distinct keys, distinct in-range slots, and pairwise disjoint extents whose total fits the payload minus the reserve.

use super::super::IO_UNIT;
use super::super::extent::{ExtentLocator, LOCATOR_LEN_LIMIT};
use super::super::geometry::{DIRECT_UNITS, EXTENT_LIMIT};
use super::super::ledger::EngineBudget;
use super::super::record::{RecordConfig, RecordPricer};
use super::capture::CaptureEntry;
/// Pool limits a recovered checkpoint must fit, in units and slots.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct LoadLimits {
    /// First payload unit an extent may start at.
    pub payload_start: u64,
    /// One past the last payload unit an extent may cover.
    pub payload_end: u64,
    /// Units held back from loaded extents: the total may fill `payload_end - payload_start - reserve_units`.
    pub reserve_units: u64,
    /// Slot indexes are below this.
    pub slot_count: usize,
    /// Most entries a checkpoint may carry.
    pub n_max: usize,
    pub record_chunk_len: u32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub enum LoadRefusal {
    /// The load exceeds a limit outside the entries: at a warm read, a slot the reader refuses, such as a checkpoint
    /// wider than the layout's slot; at a warm install, a restored set that routes more keys to an index shard than its
    /// visible limit.
    Limits,
    Memory,
    /// An entry lies outside the guard's limits; at a warm install, also an extent, tail or slot past the destination
    /// pool's geometry, or a chunk or a place in its run that 32 bits cannot name.
    Bounds,
    /// Two entries share a key.
    Key,
    /// An entry's slot is `>= slot_count` or shared with another entry; at a warm install, also a slot the pool holds or
    /// whose incarnation it already issued, or a reservation past the insertion clock.
    Slot,
    /// Two extents cover a common unit.
    Overlap,
    /// The running extent total exceeds `payload_end - payload_start - reserve_units` or overflows.
    Units,
    /// More than `n_max` entries.
    Entries,
    /// A unit of the named slot failed its identity, crc or count check: a stale write attempt landed on it.
    StaleWrite,
    /// The device could not read a unit of the named slot.
    Unreadable,
    /// A warm install found an admitted entry whose restoration and retained-set membership remain unresolved, a slot
    /// load that withheld an entry, or a clock that withholds every pair.
    Unrestorable,
}
/// Why a checkpoint entry was evicted at load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub enum EvictCause {
    /// The checkpoint as a whole failed `load_guard` or the reader's streamed guard.
    Refused,
    /// A unit of the checkpoint's slot failed its check.
    StaleWriteLoss,
    /// The device could not read a unit of the checkpoint's slot.
    Unreadable,
}
/// What a cold start reports: one `Evict` per checkpoint entry, in checkpoint order, then one `Alarm`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub enum LoadEvent {
    Evict { allocation: u64, cause: EvictCause },
    Alarm { refusal: LoadRefusal },
}
/// Outcome of `guarded_load`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardedLoad {
    /// Every entry passed; the vector is the input, unchanged.
    Warm(Vec<CaptureEntry>),
    Cold {
        entries: Vec<CaptureEntry>,
        refusal: LoadRefusal,
    },
}
impl GuardedLoad {
    pub fn events(&self) -> impl Iterator<Item = LoadEvent> + '_ {
        let (entries, refusal) = match self {
            Self::Warm(_) => (&[][..], None),
            Self::Cold { entries, refusal } => (entries.as_slice(), Some(*refusal)),
        };
        entries
            .iter()
            .map(move |e| LoadEvent::Evict {
                allocation: e.allocation,
                cause: match refusal {
                    Some(LoadRefusal::StaleWrite) => EvictCause::StaleWriteLoss,
                    Some(LoadRefusal::Unreadable) => EvictCause::Unreadable,
                    _ => EvictCause::Refused,
                },
            })
            .chain(refusal.map(|refusal| LoadEvent::Alarm { refusal }))
    }
}
/// Checks `entries` against `limits` as a set.
///
/// Successful validation requires at most `n_max` entries, distinct keys, distinct slots below `slot_count`, and at least one extent per entry. Each extent has positive length, lies within `[payload_start, payload_end)`, and is disjoint from all other extents. The limits define a capacity after subtracting reserve, and the extent total fits that capacity.
///
/// The refusal is the first failing rule in the order `Limits`, `Entries`, `Bounds` for an entry's extent count or tail, `Key`, `Slot`, `Bounds` for an extent outside the payload area or a last record with no payload, `Units`, `Overlap`; each of these rules holds or fails for the set as a whole.
pub fn load_guard(
    entries: &[CaptureEntry],
    limits: LoadLimits,
    budget: &EngineBudget,
) -> Result<(), LoadRefusal> {
    let (record, capacity) = checked(limits)?;
    if entries.len() > limits.n_max {
        return Err(LoadRefusal::Entries);
    }
    let extent_count = entries.iter().try_fold(0usize, |n, e| {
        if !entry_in_bounds(e.extents.len(), e.tail) {
            return Err(LoadRefusal::Bounds);
        }
        n.checked_add(e.extents.len()).ok_or(LoadRefusal::Memory)
    })?;
    let slot_words = limits.slot_count.div_ceil(64) * usize::from(!entries.is_empty());
    let words = (entries.len().checked_add(extent_count))
        .and_then(|words| words.checked_add(extent_count.max(slot_words)))
        .ok_or(LoadRefusal::Memory)?;
    let mut scratch = *budget;
    (words.checked_mul(std::mem::size_of::<u64>()))
        .and_then(|bytes| scratch.charge(bytes).ok())
        .ok_or(LoadRefusal::Memory)?;
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(words)
        .map_err(|_| LoadRefusal::Memory)?;
    buffer.resize(words, 0);
    // Fingerprints, packed extents, then the sort buffer, which holds the slot bitmap until the sorts reuse it.
    let (keys, rest) = buffer.split_at_mut(entries.len());
    let (ranges, aux) = rest.split_at_mut(extent_count);
    let high = key_high(entries.len());
    let mut slot_refused = false;
    for (index, entry) in entries.iter().enumerate() {
        keys[index] = fingerprint(&entry.key) & high | index as u64;
        let (slot, bit) = (entry.slot(), 1u64 << (entry.slot() % 64));
        match aux.get_mut(slot / 64).filter(|_| slot < limits.slot_count) {
            Some(word) if *word & bit == 0 => *word |= bit,
            _ => slot_refused = true,
        }
    }
    if shared_key(|at| &entries[at].key, keys, &mut aux[..entries.len()], high) {
        return Err(LoadRefusal::Key);
    }
    if slot_refused {
        return Err(LoadRefusal::Slot);
    }
    let (mut units, mut count, mut bounds) = (0u64, 0, false);
    for entry in entries {
        for &bits in &entry.extents {
            let Ok((start, end)) = extent_range(bits, &limits) else {
                bounds = true;
                continue;
            };
            let len = end - start;
            units = units.saturating_add(len);
            // The start sits above the length, so numeric order is start order.
            ranges[count] = start << LEN_BITS | len;
            count += 1;
        }
        bounds |= !last_fits(&record, entry.extents[entry.extents.len() - 1], entry.tail);
    }
    if bounds {
        return Err(LoadRefusal::Bounds);
    }
    if units > capacity {
        return Err(LoadRefusal::Units);
    }
    let (low, top) = ranges
        .iter()
        .fold((u64::MAX, 0), |(low, top), &v| (low.min(v), top.max(v)));
    let spread = u64::BITS - top.saturating_sub(low).leading_zeros();
    let sorted = sort_high(ranges, &mut aux[..extent_count], low, spread);
    if sorted
        .windows(2)
        .any(|pair| (pair[0] >> LEN_BITS) + (pair[0] & LEN_MASK) > pair[1] >> LEN_BITS)
    {
        return Err(LoadRefusal::Overlap);
    }
    Ok(())
}

/// The fingerprint bits above the index of one of `count` entries, which [`shared_key`]'s words keep.
pub(super) fn key_high(count: usize) -> u64 {
    let index_bits = usize::BITS - count.saturating_sub(1).leading_zeros();
    u64::MAX.checked_shl(index_bits).unwrap_or(0)
}

/// Whether two keys share a value, where `key_at(i)` is the `i`th key, `words[i]` is a fingerprint of it `& high | i`
/// for the `high` of [`key_high`], equal keys having equal fingerprints, and `aux` is as long as `words`: the words
/// order by their top fingerprint bits, each run of equal top bits longer than one word sorts, and the keys of each
/// run of equal fingerprint bits within it are compared.
pub(super) fn shared_key<'a>(
    key_at: impl Fn(usize) -> &'a [u8; 32],
    words: &mut [u64],
    aux: &mut [u64],
    high: u64,
) -> bool {
    let key = |value: u64| key_at((value & !high) as usize);
    let ordered = order_high(words, aux, 0, u64::BITS);
    // The fingerprint bits the order covers: words equal in them lie in one run.
    let top = high & u64::MAX << (u64::BITS - SORT_BITS);
    let mut from = 0;
    for at in 1..=ordered.len() {
        if (ordered.get(at)).is_some_and(|next| (next ^ ordered[from]) & top == 0) {
            continue;
        }
        let run = &mut ordered[from..at];
        from = at;
        if run.len() < 2 {
            continue;
        }
        run.sort_unstable();
        let mut prints = run.chunk_by_mut(|a, b| (*a ^ *b) & high == 0);
        let shared = prints.any(|run| {
            run.sort_unstable_by_key(|value| key(*value));
            run.windows(2).any(|pair| key(pair[0]) == key(pair[1]))
        });
        if shared {
            return true;
        }
    }
    false
}

/// The record pricer of `limits` and the units its extents may total, or `Limits` when either is invalid.
pub(super) fn checked(limits: LoadLimits) -> Result<(RecordPricer, u64), LoadRefusal> {
    let record = RecordConfig {
        chunk_len: limits.record_chunk_len,
    }
    .validate()
    .map_err(|_| LoadRefusal::Limits)?;
    let capacity = limits
        .payload_end
        .checked_sub(limits.payload_start)
        .and_then(|p| p.checked_sub(limits.reserve_units))
        .ok_or(LoadRefusal::Limits)?;
    Ok((record.pricer(), capacity))
}

/// Whether an entry of `extents` extents and tail `tail` passes the per-entry check: at least one and at most
/// `EXTENT_LIMIT` extents, and a tail inside one unit.
pub(super) fn entry_in_bounds(extents: usize, tail: u16) -> bool {
    extents > 0 && extents <= EXTENT_LIMIT as usize && usize::from(tail) < IO_UNIT
}

/// The units `[start, end)` extent `bits` covers, when its length is positive and at most `DIRECT_UNITS` and it lies
/// inside `[payload_start, payload_end)`.
///
/// # Errors
///
/// `Bounds` otherwise.
pub(super) fn extent_range(bits: u64, limits: &LoadLimits) -> Result<(u64, u64), LoadRefusal> {
    let extent = ExtentLocator::from_bits(bits);
    let (start, len) = (extent.start_unit(), u64::from(extent.len_units()));
    let end = start.checked_add(len).ok_or(LoadRefusal::Bounds)?;
    if len == 0
        || len > u64::from(DIRECT_UNITS)
        || start < limits.payload_start
        || end > limits.payload_end
    {
        return Err(LoadRefusal::Bounds);
    }
    Ok((start, end))
}

/// Whether a record whose last extent is `last`, of at least one unit, and whose last unit holds `tail` bytes has a
/// payload under `record`.
pub(super) fn last_fits(record: &RecordPricer, last: u64, tail: u16) -> bool {
    let last = ExtentLocator::from_bits(last);
    last.len_units() > 0
        && record
            .payload_of(super::super::layout::record_len(last.len_units(), tail))
            .is_some()
}
const LEN_BITS: u32 = LOCATOR_LEN_LIMIT.trailing_zeros();
const LEN_MASK: u64 = (1 << LEN_BITS) - 1;
const SORT_BITS: u32 = 24;
// Equal keys have equal fingerprints; every key byte reaches the result.
pub(super) fn fingerprint(key: &[u8; 32]) -> u64 {
    let word = |i: usize| u64::from_le_bytes(key[8 * i..8 * i + 8].try_into().unwrap_or_default());
    let folded =
        word(0) ^ word(1).rotate_left(16) ^ word(2).rotate_left(32) ^ word(3).rotate_left(48);
    let mixed = (folded ^ folded >> 31).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    mixed ^ mixed >> 29
}
/// A partition at most this long sorts by comparison, which costs less there than two counting passes.
const SMALL_RUN: usize = 256;
// Each `value - low` is below `2^spread`, and `aux` is as long as `values`. The values move into `aux` in the order of their top `SORT_BITS` bits: one counting pass orders them by the top byte of those bits, then each partition of one top byte longer than `SMALL_RUN` orders by the two lower bytes through its own part of `values`, inside a cache when the partition fits one, and a shorter one sorts in place.
pub(super) fn order_high<'a>(
    values: &mut [u64],
    aux: &'a mut [u64],
    low: u64,
    spread: u32,
) -> &'a mut [u64] {
    let shift = spread.saturating_sub(SORT_BITS);
    // Moves `source` into `target` in the order of byte `digit` of the top bits, equal bytes keeping their order,
    // and returns the end of each byte's values in `target`.
    let pass = |source: &[u64], target: &mut [u64], digit: u32| {
        let byte = |value: u64| ((value - low) >> shift >> (8 * digit) & 0xff) as usize;
        let mut next = [0usize; 256];
        for &value in source {
            next[byte(value)] += 1;
        }
        let mut start = 0;
        for count in &mut next {
            start += std::mem::replace(count, start);
        }
        for &value in source {
            let at = &mut next[byte(value)];
            target[*at] = value;
            *at += 1;
        }
        next
    };
    let mut start = 0;
    for end in pass(values, aux, SORT_BITS / 8 - 1) {
        let (ordered, scratch) = (&mut aux[start..end], &mut values[start..end]);
        start = end;
        if ordered.len() <= SMALL_RUN {
            ordered.sort_unstable();
            continue;
        }
        pass(ordered, scratch, 0);
        pass(scratch, ordered, 1);
    }
    aux
}
// As `order_high`, then each run of equal top bits is sorted, so the returned slice, `aux`, is sorted.
pub(super) fn sort_high<'a>(
    values: &mut [u64],
    aux: &'a mut [u64],
    low: u64,
    spread: u32,
) -> &'a mut [u64] {
    let shift = spread.saturating_sub(SORT_BITS);
    let sorted = order_high(values, aux, low, spread);
    for run in sorted.chunk_by_mut(|a, b| (*a - low) >> shift == (*b - low) >> shift) {
        run.sort_unstable();
    }
    sorted
}
/// `Warm(entries)` when `load_guard` passes; otherwise `Cold` with an `Evict { cause: Refused }` for every entry in order followed by `Alarm { refusal }`.
pub fn guarded_load(
    entries: Vec<CaptureEntry>,
    limits: LoadLimits,
    budget: &EngineBudget,
) -> GuardedLoad {
    match load_guard(&entries, limits, budget) {
        Ok(()) => GuardedLoad::Warm(entries),
        Err(refusal) => GuardedLoad::Cold { entries, refusal },
    }
}
