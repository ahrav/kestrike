//! Acknowledged-invalidation coverage kept in a shard's `B` store pages, and the fencing that carries it from one
//! tenure to the next.
//!
//! A page holds a fence, the session of the last tenure that fenced it, a saturation flag and entries
//! `(key, version interval)` over the client's per-key versions; key `k` lives on page [`page_of`]`(k)`. Every page
//! write is an exact-version compare-and-swap on a value the tenure read or wrote, and keeps the page's fence and
//! blocked set at least as large as the value it replaces. The module upholds:
//!
//! - FENCE-BEFORE-USE: a tenure adopts a page's blocked set only from the acknowledged success of its own write that
//!   set or confirmed its fence on that page. A read showing the tenure's own fence can only come from its own
//!   write whose reply was lost, so the fence step writes the page again before adopting it. [`Fencing::coverage`]
//!   answers only once every page is fenced.
//! - CARRY-FORWARD: a coverage write an earlier tenure submitted either commits before a successor's fence
//!   commits, and the fence's read carries its entry, or fails its version condition. So every INVALIDATE an
//!   earlier tenure acknowledged is in a successor's coverage once the successor fenced every page.
//! - COVER-BEFORE-SUBMIT: everything a coverage write will block, its interval, a hull or a saturation, enters the
//!   tenure's coverage before the write is submitted.
//! - ACK-ON-COMMIT: [`Fencing::cover_page`] returns [`Progress::Done`], the INVALIDATE's acknowledgment point, only on
//!   the acknowledged success of its own compare-and-swap with the page's fence equal to the tenure's session.
//!   [`Fencing::cover_begin`] and [`Fencing::cover_end`] split that step at its store request, and `cover_end`
//!   returns [`Cover::Done`] under the same rule; `cover_page` runs the two halves.
//! - PAGE-CAP: a merge whose page would exceed `C_page` is written saturated, and a size rejection re-reads the page
//!   and writes it saturated. A read page above `C_page` is refused. The in-memory coverage applies the same hull
//!   and page bounds, so the entries it holds for a page encode within `C_page` whatever the store's outcomes.
//! - A page read showing a fence above the tenure's session withdraws the tenure ([`Withdraw::NewerFence`]). After
//!   withdrawal, [`Fencing::fence`], [`Fencing::fence_all`], [`Fencing::cover_page`] and [`Fencing::cover_begin`]
//!   return the withdrawal error before issuing a request, [`Fencing::cover_end`] returns it for the reply it awaits
//!   and applies nothing, and [`Fencing::coverage`] answers `None`.
//! - REPLY-PAIRING: [`Fencing::cover_end`] applies only the reply to the one request the fencing awaits, the last
//!   [`PageRequest`] it issued, named by the fencing's process-unique identity and its request count, and refuses
//!   any other reply with [`Withdraw::Unpaired`] before changing a known value, the fenced count or the coverage.
//! - KEY-MARKS: for each fenced page the fencing holds the mark of every key of the page's known value. A coverage
//!   write states an entry new to its page only when the entry's mark is new, so a merge that reads no page entry
//!   merges into a value with no interval of its key; every other merge takes the page's own intervals of its key.
//! - ONE-MERGE: a coverage write commits the bytes of one [`merged`] per entry, in order. [`Fencing::cover_begin`]
//!   decides each entry's merge, on the thread that begins the write, and [`PageRequest::run`] builds the value
//!   from the known value and those decisions, on the thread that issues the write.
//! - KEY-INDEX: the thread that issues a page's write or read builds a [`KeyIndex`] from every chunk of the value the
//!   store returned, from each key to the positions of its chunks, before it records that value's version and chunk
//!   count, and the reply carries the index to the fencing of that page. A write of keys the page holds takes their
//!   chunks from the index only when the index names the version and chunk count of the page's known value, every
//!   position it returns for a key holds that key, the positions ascend and the lookups stay within their budget.
//!   Those checks refuse a wrong position; that the index lists every chunk of a key rests on the build, so an index
//!   serves only the page it was built for. On any other answer, and with no index, the write takes its keys' chunks
//!   from one pass over the page.

use std::fmt;
use std::hash::{BuildHasher, RandomState};
use std::num::NonZeroU16;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::super::store::{
    Client, Key, Read, Refusal, Regression, Store, StoreError, Version, WatermarkLog,
};
use crate::failover::records::{CoveragePage, ShardRecord};
use crate::net::ownership::Shard;
use crate::storage::{CacheVersion, Session};

#[cfg(test)]
mod ack_tests;
#[cfg(test)]
mod crash_tests;
#[cfg(test)]
mod index_tests;
#[cfg(test)]
mod tests;

/// The bytes of one encoded entry: the 32-byte key, then the interval's low and high bounds, each a little-endian
/// `u64`. A page's entry bytes are its entries' encodings in order; the page record's format version covers this
/// layout.
pub const ENTRY_LEN: usize = 48;

/// The encoded bytes of a page holding `entries` entries.
pub fn page_len(entries: usize) -> usize {
    CoveragePage::default().encoded_len() + entries * ENTRY_LEN
}

/// An inclusive interval of one key's versions, with `low <= high`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Interval {
    low: CacheVersion,
    high: CacheVersion,
}

impl Interval {
    /// The interval `[low, high]`, or `None` when `low > high`.
    pub fn new(low: CacheVersion, high: CacheVersion) -> Option<Self> {
        (low <= high).then_some(Self { low, high })
    }

    pub fn low(self) -> CacheVersion {
        self.low
    }

    pub fn high(self) -> CacheVersion {
        self.high
    }

    pub fn contains(self, version: CacheVersion) -> bool {
        self.low <= version && version <= self.high
    }

    fn hull(self, other: Self) -> Self {
        Self {
            low: self.low.min(other.low),
            high: self.high.max(other.high),
        }
    }

    fn within(self, other: Self) -> bool {
        other.low <= self.low && self.high <= other.high
    }
}

/// A key and an interval of its versions that an INVALIDATE covers.
pub type Entry = ([u8; 32], Interval);

/// The entry bytes of `entries`, in the layout [`ENTRY_LEN`] states.
pub fn encode_entries(entries: &[Entry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(entries.len() * ENTRY_LEN);
    for (key, interval) in entries {
        out.extend_from_slice(key);
        out.extend(interval.low.0.to_le_bytes());
        out.extend(interval.high.0.to_le_bytes());
    }
    out
}

/// The entries `bytes` encode, or `None` when its length is not a multiple of [`ENTRY_LEN`] or an interval has
/// `low > high`.
pub fn decode_entries(bytes: &[u8]) -> Option<Vec<Entry>> {
    let (chunks, rest) = bytes.as_chunks::<ENTRY_LEN>();
    if !rest.is_empty() {
        return None;
    }
    let bound = |bytes: &[u8]| {
        CacheVersion(u64::from_le_bytes(
            bytes
                .try_into()
                .expect("an entry's bounds are 8 bytes each"),
        ))
    };
    let mut entries = Vec::with_capacity(chunks.len());
    for chunk in chunks {
        let (key, bounds) = chunk.split_at(32);
        let (low, high) = bounds.split_at(8);
        let key = key.try_into().expect("an entry's key is 32 bytes");
        entries.push((key, Interval::new(bound(low), bound(high))?));
    }
    Some(entries)
}

/// The page of `key` among `pages`: its first 8 bytes as a little-endian `u64`, mod `pages`.
pub fn page_of(key: &[u8; 32], pages: NonZeroU16) -> u16 {
    let (head, _) = key.split_first_chunk::<8>().expect("a key holds 8 bytes");
    (u64::from_le_bytes(*head) % u64::from(pages.get())) as u16
}

/// The key of one encoded entry.
fn entry_key(chunk: &[u8; ENTRY_LEN]) -> &[u8; 32] {
    chunk.first_chunk::<32>().expect("an entry holds its key")
}

/// The low and high bounds of one encoded entry.
fn bounds(chunk: &[u8; ENTRY_LEN]) -> (CacheVersion, CacheVersion) {
    let bound = |at: usize| {
        CacheVersion(u64::from_le_bytes(
            chunk[at..at + 8]
                .try_into()
                .expect("an entry's bounds are 8 bytes each"),
        ))
    };
    (bound(32), bound(40))
}

/// The entry one encoded entry holds, or `None` when its interval has `low > high`.
fn entry_of(chunk: &[u8; ENTRY_LEN]) -> Option<Entry> {
    let (low, high) = bounds(chunk);
    Some((*entry_key(chunk), Interval::new(low, high)?))
}

/// Whether `bytes` encodes entries, each with `low <= high` and a key on page `page` of `pages`.
fn entries_on(bytes: &[u8], page: u16, pages: NonZeroU16) -> bool {
    let (chunks, rest) = bytes.as_chunks::<ENTRY_LEN>();
    rest.is_empty()
        && chunks
            .iter()
            .all(|chunk| entry_of(chunk).is_some() && page_of(entry_key(chunk), pages) == page)
}

/// The bounds a coverage write keeps: past `intervals` intervals of one key on a page, the key's intervals become
/// their hull; past `page_bytes` encoded bytes, the page is written saturated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub intervals: usize,
    pub page_bytes: usize,
}

/// The value a coverage write of `entry` puts over `page`: `page` itself when it is saturated or already blocks
/// `entry`; otherwise `page` with `entry` added in place of the key's intervals it contains, the key's intervals
/// replaced by their hull past `limits.intervals`, and the whole page saturated when its encoding would exceed
/// `limits.page_bytes`. The result's blocked set contains `page`'s, and its fence is `page`'s. `None` when `page`'s
/// entries do not decode.
pub fn merged(page: &CoveragePage, entry: Entry, limits: Limits) -> Option<CoveragePage> {
    let (chunks, rest) = page.entries.as_chunks::<ENTRY_LEN>();
    let decodes = rest.is_empty()
        && chunks.iter().all(|chunk| {
            let (low, high) = bounds(chunk);
            low <= high
        });
    decodes.then(|| {
        let mut draft = Draft::of(page);
        merge(&mut draft, entry, limits, Held::Unread);
        draft.next().over(page)
    })
}

#[cfg(test)]
thread_local! {
    /// A planted defect: `merge`, which every coverage write runs, keeps the new entry alone, so a coverage write drops
    /// what the page blocked.
    pub(crate) static SHRINKS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// What a merge blocks beyond the page's blocked set and the merged entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Change {
    /// The combined blocked set of the page and the entry equals the merged value's blocked set.
    Entry,
    /// The merged value holds this hull in place of the key's intervals.
    Hull(Interval),
    Saturated,
}

/// A page value that merges build over the value `head` came from. Its entries are `head`'s without the chunks at
/// `dropped`, then `tail`'s. A merge that is told what the draft holds of its key reads no entry: it records the
/// chunks of `head` it removes in `dropped` and appends to `tail`. A merge that is told nothing first moves the
/// remaining entries of `head` into `tail`, as a saturation empties both.
struct Draft<'a> {
    fence: u64,
    saturated: bool,
    head: &'a [u8],
    /// The indices of the chunks of `head` that merges removed, each once.
    dropped: Vec<u32>,
    tail: Vec<u8>,
}

impl<'a> Draft<'a> {
    /// The draft of `page` itself, whose entries decode.
    fn of(page: &'a CoveragePage) -> Self {
        Self {
            fence: page.fence,
            saturated: page.saturated,
            head: &page.entries,
            dropped: Vec::new(),
            tail: Vec::new(),
        }
    }

    fn count(&self) -> usize {
        self.head.len() / ENTRY_LEN - self.dropped.len() + self.tail.len() / ENTRY_LEN
    }

    /// Moves the remaining entries of `head` in front of `tail`'s, so `tail` holds every entry.
    fn flatten(&mut self) {
        if !self.head.is_empty() {
            self.dropped.sort_unstable();
            self.tail = edited(self.head, &self.dropped, &self.tail);
            self.head = &[];
            self.dropped.clear();
        }
    }

    /// The drafted value: whole when `head` holds no entry, otherwise the edits to the value `head` came from.
    fn next(mut self) -> Next {
        if self.head.is_empty() {
            Next::Whole(CoveragePage {
                fence: self.fence,
                saturated: self.saturated,
                entries: self.tail,
            })
        } else {
            self.dropped.sort_unstable();
            Next::Edited {
                dropped: self.dropped,
                appended: self.tail,
            }
        }
    }
}

/// The entries of `head` without the chunks at `dropped`, which ascend, followed by `tail`.
fn edited(head: &[u8], dropped: &[u32], tail: &[u8]) -> Vec<u8> {
    let mut entries = Vec::with_capacity(head.len() - dropped.len() * ENTRY_LEN + tail.len());
    let mut from = 0;
    for &index in dropped {
        let at = index as usize * ENTRY_LEN;
        entries.extend_from_slice(&head[from..at]);
        from = at + ENTRY_LEN;
    }
    entries.extend_from_slice(&head[from..]);
    entries.extend_from_slice(tail);
    entries
}

/// The value of a coverage write, as [`Draft::next`] leaves it. [`Next::over`] builds an edited value on the
/// thread that issues the write, so the thread that drafted it copies no entry of the page.
#[derive(Debug)]
enum Next {
    Whole(CoveragePage),
    /// The basis without its entries at `dropped`, which ascend, followed by the entries of `appended`. The value
    /// keeps the basis's fence and saturation flag.
    Edited {
        dropped: Vec<u32>,
        appended: Vec<u8>,
    },
}

impl Next {
    /// The value over `basis`, the value the draft started from.
    fn over(self, basis: &CoveragePage) -> CoveragePage {
        match self {
            Self::Whole(page) => page,
            Self::Edited { dropped, appended } => CoveragePage {
                entries: edited(&basis.entries, &dropped, &appended),
                ..*basis
            },
        }
    }
}

/// What a draft holds of one entry's key, as the caller of [`merge`] states it.
#[derive(Clone, Copy)]
enum Held<'h> {
    /// No interval of the key.
    None,
    /// These intervals of the key, each the chunk of `head` at its index, and none in `tail`. The statement is
    /// about the value the draft started from and holds while no earlier merge had the key.
    Head(&'h [(u32, Interval)]),
    /// Nothing stated: the merge reads the draft's entries.
    Unread,
}

/// `merge` applies [`merged`] to `draft`, reading the draft's entries only when `held` states nothing.
fn merge(draft: &mut Draft<'_>, entry: Entry, limits: Limits, held: Held<'_>) -> Change {
    #[cfg(test)]
    if SHRINKS.with(std::cell::Cell::get) {
        (draft.head, draft.dropped, draft.tail) = (&[], Vec::new(), Vec::new());
    }
    let (key, interval) = entry;
    // Once `head` is empty its chunks are gone or in `tail`, so a statement about them no longer locates them.
    let held = match held {
        Held::Head(_) if draft.head.is_empty() => Held::Unread,
        held => held,
    };
    if matches!(held, Held::Unread) {
        draft.flatten();
    }
    let head = key_head(&key);
    let keyed =
        |chunk: &[u8; ENTRY_LEN]| key_head(entry_key(chunk)) == head && entry_key(chunk) == &key;
    let (mut blocked, mut count, mut kept, mut hull) = (false, 0, 0, interval);
    let mut meet = |other: Interval| {
        count += 1;
        blocked |= interval.within(other);
        hull = hull.hull(other);
        kept += usize::from(!other.within(interval));
    };
    match held {
        Held::None => {}
        Held::Head(chunks) => chunks.iter().for_each(|&(_, other)| meet(other)),
        Held::Unread => {
            let (chunks, _) = draft.tail.as_chunks::<ENTRY_LEN>();
            for chunk in chunks.iter().filter(|chunk| keyed(chunk)) {
                let (low, high) = bounds(chunk);
                meet(Interval { low, high });
            }
        }
    }
    if draft.saturated || blocked {
        return Change::Entry;
    }
    let hulled = kept + 1 > limits.intervals;
    let removed = if hulled { count } else { count - kept };
    let entries = draft.count() - removed + 1;
    if page_len(entries) > limits.page_bytes {
        (draft.saturated, draft.head) = (true, &[]);
        (draft.dropped, draft.tail) = (Vec::new(), Vec::new());
        return Change::Saturated;
    }
    let removes = |other: Interval| hulled || other.within(interval);
    match held {
        _ if removed == 0 => {}
        Held::Head(chunks) => {
            let gone = chunks.iter().filter(|(_, other)| removes(*other));
            draft.dropped.extend(gone.map(|&(index, _)| index));
        }
        Held::None | Held::Unread => {
            let (chunks, _) = draft.tail.as_chunks::<ENTRY_LEN>();
            let mut remaining = Vec::with_capacity(entries * ENTRY_LEN);
            for chunk in chunks {
                let (low, high) = bounds(chunk);
                if !(keyed(chunk) && removes(Interval { low, high })) {
                    remaining.extend_from_slice(chunk);
                }
            }
            draft.tail = remaining;
        }
    }
    let (added, change) = if hulled {
        (hull, Change::Hull(hull))
    } else {
        (interval, Change::Entry)
    };
    draft.tail.extend_from_slice(&key);
    draft.tail.extend(added.low.0.to_le_bytes());
    draft.tail.extend(added.high.0.to_le_bytes());
    change
}

/// A word that equal keys share, so [`merge`] compares it before whole keys.
fn key_head(key: &[u8; 32]) -> u64 {
    u64::from_ne_bytes(*key.first_chunk::<8>().expect("a key holds 8 bytes"))
}

/// The bits of the filter [`keyed`] tests each page entry against.
const FILTER_BITS: u32 = 12;

/// The filter bit of a key head: the top [`FILTER_BITS`] bits of its product with an odd word.
fn filter_bit(head: u64) -> usize {
    (head.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> (u64::BITS - FILTER_BITS)) as usize
}

/// For each of `entries`, what `page` holds of its key: `None` when an earlier entry has its key, otherwise the
/// chunks of `page` with its key, by position, which an entry that `fresh` states new to the page has none of. With
/// `lookup`, an index and the version of the value whose entries `page` holds, the chunks of each other entry come
/// from [`KeyIndex::found`] when it answers for the batch. Otherwise one pass over the page tests each of its
/// entries against a filter of the other entries' key heads and, on a filter hit, compares the whole key against
/// each batch entry with the same head, so the pass costs one filter test per page entry whatever the batch's size.
fn keyed(
    page: &[u8],
    entries: &[Entry],
    fresh: &[bool],
    lookup: Option<(&KeyIndex, Version)>,
) -> Vec<Option<Vec<(u32, Interval)>>> {
    let mut heads: Vec<(u64, usize)> = (entries.iter().enumerate())
        .map(|(at, (key, _))| (key_head(key), at))
        .collect();
    heads.sort_unstable();
    let mut held = vec![Some(Vec::new()); entries.len()];
    for (at, &(head, entry)) in heads.iter().enumerate() {
        // `heads` holds equal heads in entry order, so the entries before `at` with this head are the earlier ones.
        let repeats = (heads[..at].iter().rev())
            .take_while(|(other, _)| *other == head)
            .any(|&(_, earlier)| entries[earlier].0 == entries[entry].0);
        if repeats {
            held[entry] = None;
        }
    }
    if !(held.iter().zip(fresh)).any(|(held, &fresh)| held.is_some() && !fresh) {
        return held;
    }
    #[cfg(test)]
    let lookup = lookup.filter(|_| INDEX_PLANT.with(std::cell::Cell::get) != IndexPlant::Unused);
    if let Some((index, version)) = lookup {
        let found = index.found(page, version, entries, fresh, &mut held);
        #[cfg(test)]
        LOOKUPS.with(|lookups| {
            if let Some(lookups) = lookups.borrow_mut().as_mut() {
                lookups.push(found);
            }
        });
        if found.is_ok() {
            return held;
        }
    }
    let mut filter = [0_u64; 1 << (FILTER_BITS - 6)];
    for &(head, entry) in &heads {
        if held[entry].is_some() && !fresh[entry] {
            let bit = filter_bit(head);
            filter[bit >> 6] |= 1 << (bit & 63);
        }
    }
    let (chunks, _) = page.as_chunks::<ENTRY_LEN>();
    for (position, chunk) in (0..).zip(chunks) {
        let head = key_head(entry_key(chunk));
        let bit = filter_bit(head);
        if filter[bit >> 6] >> (bit & 63) & 1 == 1 {
            let from = heads.partition_point(|&(other, _)| other < head);
            let same = heads[from..].iter().take_while(|(other, _)| *other == head);
            for &(_, entry) in same.filter(|&&(_, entry)| entries[entry].0 == *entry_key(chunk)) {
                if let Some(chunks) = &mut held[entry] {
                    let (low, high) = bounds(chunk);
                    chunks.push((position, Interval { low, high }));
                }
            }
        }
    }
    held
}

/// Applies [`merge`] to the draft of `page` for each of `entries` in order, passes each entry's change to
/// `changed`, and returns the drafted value. `fresh[i]` states that neither `page` nor an entry before `entries[i]`
/// holds an interval of its key; `false` is always a valid statement. `lookup`, when present, is a [`KeyIndex`] and
/// the version of the value `page` is. A batch of fresh entries reads no page entry. Any other batch finds its keys'
/// chunks in [`keyed`], through the index or in one pass over the page, and each of its merges takes what was found,
/// except the merge of an entry whose key an earlier entry has, which reads the draft.
fn merge_each(
    page: &CoveragePage,
    entries: &[Entry],
    fresh: &[bool],
    limits: Limits,
    lookup: Option<(&KeyIndex, Version)>,
    mut changed: impl FnMut(Entry, Change),
) -> Next {
    let mut draft = Draft::of(page);
    if fresh.iter().all(|&fresh| fresh) {
        for &entry in entries {
            changed(entry, merge(&mut draft, entry, limits, Held::None));
        }
        return draft.next();
    }
    let found = keyed(&page.entries, entries, fresh, lookup);
    for ((&entry, &fresh), found) in entries.iter().zip(fresh).zip(&found) {
        let held = match found {
            _ if fresh => Held::None,
            None => Held::Unread,
            Some(chunks) if chunks.is_empty() => Held::None,
            Some(chunks) => Held::Head(chunks),
        };
        changed(entry, merge(&mut draft, entry, limits, held));
    }
    draft.next()
}

/// The saturated page with fence `fence`: no entries, and every version of every key on it blocked.
fn saturated(fence: u64) -> CoveragePage {
    CoveragePage {
        fence,
        saturated: true,
        entries: Vec::new(),
    }
}

/// A tenure's in-memory coverage, `Cov_T`: intervals per key and the saturated pages. `(k, v)` is covered when `v`
/// lies in an interval of `k` or `k`'s page is saturated, and a covered pair stays covered. An interval that a held
/// interval of its key contains, or one on a saturated page, is not held. Past `limits.intervals` intervals a key
/// holds their hull, and a page whose held intervals would encode past `limits.page_bytes` saturates, dropping its
/// keys.
///
/// The held intervals are one entry per `(key, interval)` in an open-addressing table of groups of eight slots.
/// Each group has one control word of eight bytes, one per slot: [`EMPTY`], [`DELETED`], or the control byte of
/// a full slot's [`KeyHash`]. A key's probe sequence visits groups triangularly from its hash's group and ends at the
/// first group holding an [`EMPTY`] byte; an entry lies in a group of its key's probe sequence at or before that
/// group. A group's byte becomes [`EMPTY`] again only while the group holds another [`EMPTY`] byte, so later
/// probes continue past every group that an insertion found full. Full and deleted slots occupy at most seven
/// eighths of the table, so every probe reaches a group with an [`EMPTY`] byte. A saturation removes its page's
/// entries in place and rebuilds the table at its capacity once the removals since the last rebuild exceed one slot
/// in [`REMOVAL_SHARE`], so the other pages' entries are rehashed at most once per batch of removals exceeding
/// `1 / REMOVAL_SHARE` of the table's capacity.
///
/// The hash is NH over the key's eight 32-bit words (Black et al., *UMAC: Fast and Secure Message Authentication*,
/// CRYPTO 1999), whose sums of two distinct keys agree with probability at most `2^-32`, multiplied by an odd
/// word, whose top bits pick the first group as a multiply-shift hash (Dietzfelbinger et al., *A Reliable
/// Randomized Algorithm for the Closest-Pair Problem*, 1997). Every coverage draws its hash keys from
/// [`RandomState`], so two distinct cache keys chosen independently of them share a first group with probability
/// at most `2^-32 + 2 / groups`.
#[derive(Clone)]
pub struct Coverage {
    pages: NonZeroU16,
    limits: Limits,
    seeds: [u64; 5],
    control: Vec<u64>,
    slots: Vec<Entry>,
    full: usize,
    deleted: usize,
    removed: usize,
    /// The number of intervals the table holds for each page's keys.
    on_page: Vec<usize>,
    saturated: Vec<bool>,
    saturated_pages: usize,
}

/// A slot's control byte from the table's build until an insertion fills the slot, and after a removal from a group
/// that holds another [`EMPTY`] byte.
const EMPTY: u8 = 0xFF;
/// A slot's control byte after its entry was removed from a group that held no [`EMPTY`] byte.
const DELETED: u8 = 0x80;
const LANES: u64 = 0x0101_0101_0101_0101;
const HIGH: u64 = 0x8080_8080_8080_8080;
const REMOVAL_SHARE: usize = 16;

/// The 64-bit keyed hash of a key: its top 32 bits choose the key's first group and bits 24 to 30 are its control
/// byte.
#[derive(Clone, Copy)]
struct KeyHash(u64);

impl KeyHash {
    /// The hash of `key` under `seeds`: NH over the key's eight 32-bit words, multiplied by the odd `seeds[4]`.
    #[inline]
    fn of(seeds: &[u64; 5], key: &[u8; 32]) -> Self {
        let (words, _) = key.as_chunks::<4>();
        let mut sum = 0u64;
        for (pair, seed) in words.as_chunks::<2>().0.iter().zip(seeds) {
            let low = u32::from_le_bytes(pair[0]).wrapping_add(*seed as u32);
            let high = u32::from_le_bytes(pair[1]).wrapping_add((seed >> 32) as u32);
            sum = sum.wrapping_add(u64::from(low) * u64::from(high));
        }
        Self(sum.wrapping_mul(seeds[4]))
    }

    /// The key's 32-bit mark: the top 32 bits of the hash with the low bit set, so no mark is 0.
    fn mark(self) -> u32 {
        (self.0 >> 32) as u32 | 1
    }

    fn byte(self) -> u8 {
        ((self.0 >> 24) & 0x7F) as u8
    }

    fn group(self, groups: usize) -> usize {
        (((self.0 >> 32) * groups as u64) >> 32) as usize
    }
}

/// The keys of one page's known value, as 32-bit marks of their hashes in an open-addressing table at most half
/// full, so a coverage write learns which of its keys the page holds without reading the page. [`Marks::of`] sizes
/// the table for the value's entry count, which is at least its key count. [`Marks::insert`] grows the table when
/// one more mark would pass half full, to the smallest size that holds that mark at half full, so a table that
/// only `insert` built is, past 8 slots, at least a quarter full. [`Marks::insert`]
/// returns `false` for every hash inserted before and, for another hash, with probability about `len / 2^31` over
/// the hash keys. A mark is the top 32 bits of its [`KeyHash`] with the low bit set; its top bits choose its first
/// slot, and a probe runs through the following slots to the first free one, which holds 0.
#[derive(Debug, Clone, Default)]
struct Marks {
    /// Empty, or a power of two of at least 8 slots.
    slots: Vec<u32>,
    len: usize,
}

impl Marks {
    /// The marks of the keys `value` holds, hashed by `coverage`.
    fn of(value: &CoveragePage, coverage: &Coverage) -> Self {
        let (chunks, _) = value.entries.as_chunks::<ENTRY_LEN>();
        let mut marks = Self::default();
        if !chunks.is_empty() {
            marks.grow(chunks.len());
        }
        for chunk in chunks {
            marks.insert(coverage.hash(entry_key(chunk)));
        }
        marks
    }

    /// Rebuilds the table as the smallest that holds `len` marks at half full.
    fn grow(&mut self, len: usize) {
        let slots = table_slots(len);
        let held = std::mem::replace(&mut self.slots, vec![0; slots]);
        for mark in held.into_iter().filter(|&mark| mark != 0) {
            let at = self.slot(mark);
            self.slots[at] = mark;
        }
    }

    /// The slot that holds `mark`, or the free slot its probe ends at.
    fn slot(&self, mark: u32) -> usize {
        let mask = self.slots.len() - 1;
        let mut at = home_slot(mark, self.slots.len());
        while self.slots[at] != 0 && self.slots[at] != mark {
            at = (at + 1) & mask;
        }
        at
    }

    /// Adds the mark of `hash` and returns whether the table lacked it.
    fn insert(&mut self, hash: KeyHash) -> bool {
        if 2 * (self.len + 1) > self.slots.len() {
            self.grow(self.len + 1);
        }
        let mark = hash.mark();
        let at = self.slot(mark);
        let fresh = self.slots[at] == 0;
        self.slots[at] = mark;
        self.len += usize::from(fresh);
        fresh
    }
}

/// The slot count of an open-addressing table at most half full for `len` entries: the smallest power of two of at
/// least `2 * len` and at least 8.
fn table_slots(len: usize) -> usize {
    (2 * len).next_power_of_two().max(8)
}

/// The slot a probe for `mark` starts at in a table of `slots` slots, a power of two of at least 8 and at most
/// `2^32`: the mark's top bits.
fn home_slot(mark: u32, slots: usize) -> usize {
    mark as usize >> (u32::BITS - slots.trailing_zeros())
}

/// A build's version and count and its slots.
#[cfg(test)]
type Built = (Option<(Version, usize)>, Vec<u64>);

/// The positions of the chunks of one page value by key, which the thread that issued the page's write or read
/// builds from the value the store returned ([`KeyIndex::build`]), so a coverage write of keys the page holds finds
/// their chunks without a pass over the page. `slots` is empty until the first build; once a build names a value
/// it is an open-addressing table at most half full, a power of two of at least 8 slots: 0 for a free slot,
/// otherwise a chunk's key mark ([`KeyHash::mark`] under `seeds`) in the high 32 bits and its position in the low
/// 32. A key's chunks lie in ascending position order on the probe from [`home_slot`] of its mark through the
/// following slots to the first free one. `of` names the value's version and chunk count, and is `None` before a
/// build and after a build that stopped; a probe of `slots` runs only while `of` names a value.
#[derive(Clone)]
struct KeyIndex {
    seeds: [u64; 5],
    of: Option<(Version, usize)>,
    slots: Vec<u64>,
    /// Under [`IndexPlant::Stale`] and [`IndexPlant::Restamped`], the last build's version, count and slots, which
    /// the next build hands back in place of its own.
    #[cfg(test)]
    previous: Option<Built>,
}

/// Why [`KeyIndex::found`] answered nothing, so the caller takes the batch's chunks from a pass over the page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unindexed {
    /// The index names another version or chunk count than the value it is asked about, or no value.
    Stale,
    /// The index lists no chunk for a key.
    Miss,
    /// A position the index lists for a key's mark is past the value's chunks, holds another key, or does not
    /// ascend. A current index answers it when another key of the page shares the key's mark, which happens with
    /// probability about `len / 2^31` over the hash keys; the key check keeps the key from taking the other key's
    /// chunks.
    Mismatch,
    /// The batch's probes visited more slots than its budget, one per chunk of the value and two per looked-up key.
    Crowded,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IndexPlant {
    /// The index as built.
    Used,
    /// [`keyed`] never consults an index: a run without the index.
    Unused,
    /// Planted defect: every position the index returns is one chunk past the one it names.
    OffByOne,
    /// Planted defect: each build after an index's first hands back the index of the value the previous build
    /// indexed, with that value's version and count: an index one write stale.
    Stale,
    /// Planted defect: as [`IndexPlant::Stale`], with the version and count of the new value.
    Restamped,
}

#[cfg(test)]
thread_local! {
    pub(crate) static INDEX_PLANT: std::cell::Cell<IndexPlant> = const { std::cell::Cell::new(IndexPlant::Used) };
    /// While `Some`, the answer of each batch [`keyed`] asked an index about, in order.
    static LOOKUPS: std::cell::RefCell<Option<Vec<Result<(), Unindexed>>>> =
        const { std::cell::RefCell::new(None) };
}

impl fmt::Debug for KeyIndex {
    /// Formats the value the index names and its slot count; the seeds stay private, as [`Coverage`]'s do.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyIndex")
            .field("of", &self.of)
            .field("slots", &self.slots.len())
            .finish_non_exhaustive()
    }
}

impl KeyIndex {
    /// An index that names no value, hashing keys under `seeds`.
    fn new(seeds: [u64; 5]) -> Self {
        Self {
            seeds,
            of: None,
            slots: Vec::new(),
            #[cfg(test)]
            previous: None,
        }
    }

    /// Rebuilds the index as the index of `read`, in the slots it already holds unless they exceed four times the
    /// table the value needs. The build stops, leaving an index that names no value, when its probes visit more
    /// than eight occupied slots per chunk, or for a value of more than `2^31` chunks, past what a 32-bit position
    /// and mark address; the page codec's 32-bit entry length keeps every value below `2^27` chunks.
    fn build(&mut self, read: &Read<CoveragePage>) {
        let (chunks, _) = read.value().entries.as_chunks::<ENTRY_LEN>();
        self.of = None;
        if chunks.len() > 1 << 31 {
            return;
        }
        let len = table_slots(chunks.len());
        if self.slots.capacity() > 4 * len {
            self.slots = Vec::new();
        }
        self.slots.clear();
        self.slots.resize(len, 0);
        let mask = len - 1;
        let mut budget = 8 * chunks.len();
        for (position, chunk) in (0_u32..).zip(chunks) {
            let mark = KeyHash::of(&self.seeds, entry_key(chunk)).mark();
            let mut at = home_slot(mark, len);
            while self.slots[at] != 0 {
                let Some(left) = budget.checked_sub(1) else {
                    return;
                };
                budget = left;
                at = (at + 1) & mask;
            }
            self.slots[at] = u64::from(mark) << 32 | u64::from(position);
        }
        self.of = Some((read.version(), chunks.len()));
        #[cfg(test)]
        self.planted(read);
    }

    /// Applies [`IndexPlant::Stale`] or [`IndexPlant::Restamped`] to the build just made of `read`.
    #[cfg(test)]
    fn planted(&mut self, read: &Read<CoveragePage>) {
        let plant = INDEX_PLANT.with(std::cell::Cell::get);
        if matches!(plant, IndexPlant::Stale | IndexPlant::Restamped) {
            let built = (self.of, self.slots.clone());
            if let Some((of, slots)) = self.previous.replace(built) {
                self.slots = slots;
                self.of = match plant {
                    IndexPlant::Stale => of,
                    _ => Some((read.version(), read.value().entries.len() / ENTRY_LEN)),
                };
            }
        }
    }

    /// Appends to `found` the chunks of `chunks`, the entries of the value the index names, that hold `key`, with
    /// their positions. Each position the index lists for the key's mark is checked against the key of the chunk
    /// there before the chunk is taken. Each visited slot spends one of `budget`.
    ///
    /// # Errors
    ///
    /// [`Unindexed::Miss`], [`Unindexed::Mismatch`] or [`Unindexed::Crowded`], with `found` holding whatever was
    /// appended before the answer.
    fn chunks(
        &self,
        chunks: &[[u8; ENTRY_LEN]],
        key: &[u8; 32],
        found: &mut Vec<(u32, Interval)>,
        budget: &mut usize,
    ) -> Result<(), Unindexed> {
        let mark = KeyHash::of(&self.seeds, key).mark();
        let mask = self.slots.len() - 1;
        let mut at = home_slot(mark, self.slots.len());
        let mut next = 0_u32;
        let mut appended = false;
        while self.slots[at] != 0 {
            *budget = budget.checked_sub(1).ok_or(Unindexed::Crowded)?;
            let slot = self.slots[at];
            if (slot >> 32) as u32 == mark {
                let position = slot as u32;
                #[cfg(test)]
                let position = match INDEX_PLANT.with(std::cell::Cell::get) {
                    IndexPlant::OffByOne => position.wrapping_add(1),
                    _ => position,
                };
                let chunk = (chunks.get(position as usize))
                    .filter(|chunk| position >= next && entry_key(chunk) == key)
                    .ok_or(Unindexed::Mismatch)?;
                let (low, high) = bounds(chunk);
                found.push((position, Interval { low, high }));
                (next, appended) = (position + 1, true);
            }
            at = (at + 1) & mask;
        }
        if !appended {
            return Err(Unindexed::Miss);
        }
        Ok(())
    }

    /// Fills `held[i]`, an empty vector for each entry that `fresh` does not state new and whose `held[i]` is
    /// `Some`, with the chunks of `page`, the entries of the value at `version`, that [`KeyIndex::chunks`] answers
    /// for its key. The index answers only when it names that value's version and chunk count. The batch's probes
    /// share a budget of one slot per chunk of the value and two per looked-up key, so the lookups cost no more
    /// than the pass they replace and that budget again.
    ///
    /// # Errors
    ///
    /// [`Unindexed::Stale`] before any probe, or the first other answer, after which every `held[i]` is emptied
    /// again.
    fn found(
        &self,
        page: &[u8],
        version: Version,
        entries: &[Entry],
        fresh: &[bool],
        held: &mut [Option<Vec<(u32, Interval)>>],
    ) -> Result<(), Unindexed> {
        let (chunks, _) = page.as_chunks::<ENTRY_LEN>();
        if self.of != Some((version, chunks.len())) {
            return Err(Unindexed::Stale);
        }
        let mut budget = chunks.len() + 2 * entries.len();
        for (at, (key, _)) in entries.iter().enumerate() {
            if let (false, Some(found)) = (fresh[at], held[at].as_mut())
                && let Err(why) = self.chunks(chunks, key, found, &mut budget)
            {
                held.iter_mut().flatten().for_each(Vec::clear);
                return Err(why);
            }
        }
        Ok(())
    }
}

/// The slots of `control` whose byte is `byte`, as the high bit of each such byte, with possible extra bits above
/// a match; callers check every candidate.
fn matching(control: u64, byte: u8) -> u64 {
    let x = control ^ (u64::from(byte) * LANES);
    x.wrapping_sub(LANES) & !x & HIGH
}

/// The slots of `control` that are [`EMPTY`].
fn empty(control: u64) -> u64 {
    control & (control << 1) & HIGH
}

/// The slots of `control` that are [`EMPTY`] or [`DELETED`].
fn free(control: u64) -> u64 {
    control & HIGH
}

/// Passes `word` to `black_box`, whose best-effort hint keeps the caller's load of `word` in the compiled code.
/// [`Coverage::absorb_valid`] loads the first-group control word of each entry in a batch this way before the
/// batch's insertions probe those groups.
fn touch(word: u64) {
    std::hint::black_box(word);
}

impl fmt::Debug for Coverage {
    /// Formats the coverage's pages, limits, held entries, per-page interval counts and saturated pages. The hash keys
    /// remain private to the coverage, so cache keys stay independent of them, as the collision bound in [`Coverage`]
    /// requires.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Coverage")
            .field("pages", &self.pages)
            .field("limits", &self.limits)
            .field("entries", &self.entries())
            .field("on_page", &self.on_page)
            .field("saturated", &self.saturated)
            .finish_non_exhaustive()
    }
}

impl PartialEq for Coverage {
    fn eq(&self, other: &Self) -> bool {
        self.pages == other.pages
            && self.limits == other.limits
            && self.on_page == other.on_page
            && self.saturated == other.saturated
            && self.entries() == other.entries()
    }
}

impl Eq for Coverage {}

impl Coverage {
    fn new(pages: NonZeroU16, limits: Limits) -> Self {
        #[expect(
            clippy::disallowed_methods,
            reason = "slot placement under these seeds changes table capacity, which warm attach budgets; whether a simulated run reaches that budget edge is unverified"
        )]
        let state = RandomState::new();
        let mut seeds = [0; 5];
        for (seed, n) in seeds.iter_mut().zip(0u8..) {
            *seed = state.hash_one(n);
        }
        seeds[4] |= 1;
        Self {
            pages,
            limits,
            seeds,
            control: Vec::new(),
            slots: Vec::new(),
            full: 0,
            deleted: 0,
            removed: 0,
            on_page: vec![0; usize::from(pages.get())],
            saturated: vec![false; usize::from(pages.get())],
            saturated_pages: 0,
        }
    }

    /// The exact blocked set of `values`, the values of pages `0..B` in order.
    #[cfg(test)]
    pub(crate) fn of_pages(pages: NonZeroU16, values: &[CoveragePage]) -> Self {
        let unbounded = Limits {
            intervals: usize::MAX,
            page_bytes: usize::MAX,
        };
        let mut coverage = Self::new(pages, unbounded);
        for (page, value) in (0..).zip(values) {
            assert!(coverage.absorb(page, value), "page {page} absorbs");
        }
        coverage
    }

    #[cfg(test)]
    pub(crate) fn insert(&mut self, (key, interval): Entry) {
        self.add(key, interval);
    }

    /// The intervals held for `key`, in order.
    #[cfg(test)]
    pub(crate) fn intervals_of(&self, key: &[u8; 32]) -> Vec<Interval> {
        self.entries()
            .into_iter()
            .filter(|(other, _)| other == key)
            .map(|(_, interval)| interval)
            .collect()
    }

    /// The held entries, in order.
    fn entries(&self) -> Vec<Entry> {
        let mut entries: Vec<Entry> = self.full_slots().map(|at| self.slots[at]).collect();
        entries.sort_unstable();
        entries
    }

    /// The indices of the full slots.
    fn full_slots(&self) -> impl Iterator<Item = usize> + '_ {
        (0..).zip(&self.control).flat_map(|(group, &control)| {
            (0..8)
                .filter(move |byte| (control >> (byte * 8)) & 0x80 == 0)
                .map(move |byte| group * 8 + byte)
        })
    }

    /// The key's hash: NH over its 32-bit words under `seeds[..4]`, then the product with the odd `seeds[4]`.
    fn hash(&self, key: &[u8; 32]) -> KeyHash {
        KeyHash::of(&self.seeds, key)
    }

    /// Whether `(key, version)` is covered: the membership test that FILL admission and residency query.
    #[inline]
    pub fn covers(&self, key: &[u8; 32], version: CacheVersion) -> bool {
        self.find(key, self.hash(key), |interval| interval.contains(version))
            .is_some()
            || self.page_saturated(key)
    }

    /// Whether the coverage excludes `version` of `key` from FILL admission and from warm recovery, the one rule both
    /// apply: a nonzero version while an interval of `key` contains it, and version 0, judged by its key, while any
    /// interval of `key` is held. A saturated page of `key` excludes every version.
    pub(crate) fn excludes(&self, key: &[u8; 32], version: CacheVersion) -> bool {
        if version == CacheVersion(0) {
            self.find(key, self.hash(key), |_| true).is_some() || self.page_saturated(key)
        } else {
            self.covers(key, version)
        }
    }

    fn page_saturated(&self, key: &[u8; 32]) -> bool {
        self.saturated_pages != 0 && self.saturated[usize::from(page_of(key, self.pages))]
    }

    pub(crate) fn heap_bytes(&self) -> usize {
        size_of::<u64>() * self.control.capacity()
            + size_of::<Entry>() * self.slots.capacity()
            + size_of::<usize>() * self.on_page.capacity()
            + size_of::<bool>() * self.saturated.capacity()
    }

    /// The slot of an entry of `key`, whose hash is `hash`, with an interval that `matches`.
    fn find(
        &self,
        key: &[u8; 32],
        hash: KeyHash,
        mut matches: impl FnMut(Interval) -> bool,
    ) -> Option<usize> {
        let groups = self.control.len();
        if groups == 0 {
            return None;
        }
        let mut group = hash.group(groups);
        let mut step = 0;
        loop {
            let control = self.control[group];
            let mut candidates = matching(control, hash.byte());
            while candidates != 0 {
                let at = group * 8 + (candidates.trailing_zeros() / 8) as usize;
                candidates &= candidates - 1;
                let (held, interval) = &self.slots[at];
                if held == key && matches(*interval) {
                    return Some(at);
                }
            }
            if empty(control) != 0 {
                return None;
            }
            step += 1;
            group = (group + step) & (groups - 1);
        }
    }

    /// Sets slot `at`'s control byte to `byte`.
    fn mark(&mut self, at: usize, byte: u8) {
        let shift = (at % 8) * 8;
        let control = &mut self.control[at / 8];
        *control = (*control & !(0xFF << shift)) | (u64::from(byte) << shift);
    }

    /// Places `entry`, whose hash is `hash`, in the first free slot of its probe sequence; the table has one.
    fn place(&mut self, entry: Entry, hash: KeyHash) {
        let groups = self.control.len();
        let mut group = hash.group(groups);
        let mut step = 0;
        while free(self.control[group]) == 0 {
            step += 1;
            group = (group + step) & (groups - 1);
        }
        let byte = (free(self.control[group]).trailing_zeros() / 8) as usize;
        let at = group * 8 + byte;
        if (self.control[group] >> (byte * 8)) as u8 == DELETED {
            self.deleted -= 1;
        }
        self.mark(at, hash.byte());
        self.slots[at] = entry;
        self.full += 1;
    }

    /// Rebuilds the table with `groups` groups, a power of two, holding every full slot's entry.
    fn rebuild(&mut self, groups: usize) {
        let filler = (
            [0; 32],
            Interval {
                low: CacheVersion(0),
                high: CacheVersion(0),
            },
        );
        let slots = std::mem::replace(&mut self.slots, vec![filler; groups * 8]);
        let control = std::mem::replace(&mut self.control, vec![u64::MAX; groups]);
        self.full = 0;
        self.deleted = 0;
        self.removed = 0;
        for (group, control) in control.into_iter().enumerate() {
            for byte in 0..8 {
                if (control >> (byte * 8)) & 0x80 == 0 {
                    let entry = slots[group * 8 + byte];
                    self.place(entry, self.hash(&entry.0));
                }
            }
        }
    }

    /// Grows or rebuilds the table so that `more` further entries fit within seven eighths of its slots.
    fn reserve(&mut self, more: usize) {
        let slots = self.control.len() * 8;
        if (self.full + self.deleted + more) * 8 > slots * 7 {
            let wanted = (self.full + more) * 8 / 7 + 1;
            self.rebuild((wanted.div_ceil(8)).next_power_of_two().max(2));
        }
    }

    /// Removes the entry at slot `at`.
    fn remove(&mut self, at: usize) {
        let byte = if empty(self.control[at / 8]) != 0 {
            EMPTY
        } else {
            self.deleted += 1;
            DELETED
        };
        self.mark(at, byte);
        self.full -= 1;
        self.removed += 1;
    }

    /// Covers every version of `key` in `interval`.
    fn add(&mut self, key: [u8; 32], interval: Interval) {
        let hash = self.hash(&key);
        self.add_on(page_of(&key, self.pages), key, interval, hash);
    }

    /// [`Coverage::add`] of `key`, which lies on page `page` and has hash `hash`.
    fn add_on(&mut self, page: u16, key: [u8; 32], interval: Interval, hash: KeyHash) {
        let at = usize::from(page);
        if self.saturated[at] {
            return;
        }
        let (mut held, mut kept, mut hull, mut inside) = (0, 0, interval, false);
        if self
            .find(&key, hash, |other| {
                held += 1;
                hull = hull.hull(other);
                if other.within(interval) {
                    inside = true;
                } else {
                    kept += 1;
                }
                interval.within(other)
            })
            .is_some()
        {
            return;
        }
        let after = if kept + 1 > self.limits.intervals {
            while let Some(slot) = self.find(&key, hash, |_| true) {
                self.remove(slot);
            }
            self.reserve(1);
            self.place((key, hull), hash);
            1
        } else {
            if inside {
                while let Some(slot) = self.find(&key, hash, |other| other.within(interval)) {
                    self.remove(slot);
                }
            }
            self.reserve(1);
            self.place((key, interval), hash);
            kept + 1
        };
        self.on_page[at] = self.on_page[at] - held + after;
        if page_len(self.on_page[at]) > self.limits.page_bytes {
            self.saturate(page);
        }
    }

    fn saturate(&mut self, page: u16) {
        let at = usize::from(page);
        if self.saturated[at] {
            return;
        }
        self.saturated[at] = true;
        self.saturated_pages += 1;
        let mut left = std::mem::take(&mut self.on_page[at]);
        let pages = self.pages;
        for group in 0..self.control.len() {
            if left == 0 {
                break;
            }
            let mut full = !self.control[group] & HIGH;
            while full != 0 {
                let slot = group * 8 + (full.trailing_zeros() / 8) as usize;
                full &= full - 1;
                if page_of(&self.slots[slot].0, pages) == page {
                    self.remove(slot);
                    left -= 1;
                }
            }
        }
        debug_assert_eq!(left, 0, "on_page counts the page's full slots");
        let slots = self.control.len() * 8;
        if self.removed * REMOVAL_SHARE > slots {
            self.rebuild(self.control.len());
        }
    }

    /// Covers the blocked set of `value`, the value of page `page`. Returns `false` and covers nothing when `page` is
    /// at or past `B`, or `value`'s entries do not decode or hold a key of another page.
    #[must_use]
    fn absorb(&mut self, page: u16, value: &CoveragePage) -> bool {
        if usize::from(page) >= self.saturated.len()
            || !entries_on(&value.entries, page, self.pages)
        {
            return false;
        }
        self.absorb_valid(page, value);
        true
    }

    /// Grows the table once so that the entries of every page in `values` fit, as [`Coverage::absorb_valid`] would
    /// reserve for each page in turn.
    fn reserve_for<'a>(&mut self, values: impl IntoIterator<Item = &'a CoveragePage>) {
        let entries = values
            .into_iter()
            .filter(|value| !value.saturated)
            .map(|value| value.entries.len() / ENTRY_LEN)
            .sum();
        self.reserve(entries);
    }

    /// `absorb_valid` requires a `value` whose entries [`entries_on`] accepts for page `page`, below `B`.
    fn absorb_valid(&mut self, page: u16, value: &CoveragePage) {
        if value.saturated {
            self.saturate(page);
            return;
        }
        let (chunks, _) = value.entries.as_chunks::<ENTRY_LEN>();
        self.reserve(chunks.len());
        let mut hashes = [KeyHash(0); 32];
        for batch in chunks.chunks(hashes.len()) {
            for (hash, chunk) in hashes.iter_mut().zip(batch) {
                *hash = self.hash(entry_key(chunk));
                touch(self.control[hash.group(self.control.len())]);
            }
            for (&hash, chunk) in hashes.iter().zip(batch) {
                let (key, interval) = entry_of(chunk).expect("entries_on checked every interval");
                self.add_on(page, key, interval, hash);
            }
        }
    }

    /// `absorb_accepted` requires a `value` whose entries [`entries_on`] accepts for page `page`, below `B`.
    fn absorb_accepted(&mut self, page: u16, value: &CoveragePage) {
        debug_assert!(
            usize::from(page) < self.saturated.len()
                && entries_on(&value.entries, page, self.pages),
            "page {page}'s value was accepted by checked or built from an accepted value"
        );
        self.absorb_valid(page, value);
    }
}

/// The coverage growth monitor. Over the page values a tenure holds as committed: the saturated pages, the largest
/// page's encoded bytes, to compare against `C_page`, and the `(key, interval)` entries the pages hold.
/// `held_saturated_pages` counts the pages the in-memory coverage holds saturated while their known value is not,
/// whose keys the tenure refuses to admit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Growth {
    pub saturated_pages: usize,
    pub largest_page_bytes: usize,
    pub pairs: usize,
    pub held_saturated_pages: usize,
}

/// Why [`Fencing::new`] refuses, checked in this order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FencingRefusal {
    /// The session's `E` bump was on another shard than the record's.
    Shard,
    /// The session's generation is not the record's.
    Generation,
    /// The record's `C_page` is smaller than the encoded empty page.
    PageCap,
}

/// Why [`Fencing::fenced`] refuses: the fencing's construction, a withdrawing step, or a page still unfenced after
/// its rounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceRefused {
    Fencing(FencingRefusal),
    Fence(Withdraw),
    /// Page `page` remains unresolved after the rounds.
    Unresolved {
        page: u16,
    },
}

/// Why a tenure withdraws from its shard's coverage pages. The [`Fencing`] latches every cause [`Fencing::fence`],
/// [`Fencing::fence_all`], [`Fencing::cover_page`] and [`Fencing::cover_end`] return after a request or a read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Withdraw {
    /// Page `page` holds `fence`, the session of a later tenure: the tenure is deposed.
    NewerFence { page: u16, fence: u64 },
    /// Every store-client error a step treats as terminal. The steps answer an unavailable read, an unknown
    /// outcome, a failed condition and the merged coverage write's size rejection themselves; a rejected fence or
    /// saturated write, and any other error, lands here.
    Store(StoreError),
    /// Page `page` holds entry bytes that do not decode, an entry whose key lies on another page, an encoding longer
    /// than `C_page`, or more intervals of one key than the tenure's interval bound.
    Malformed { page: u16 },
    /// The caller named page `page`, at or past the shard's page count `B`.
    NoPage { page: u16 },
    /// The reply passed to [`Fencing::cover_end`] answers no request the fencing awaits: a reply to another
    /// fencing's request, of the same session or another, to a request already applied, or to one a later
    /// [`Fencing::cover_begin`] replaced. Nothing is applied, and the fencing does not latch it.
    Unpaired,
}

/// The result of a fence or coverage step that did not withdraw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    /// The page is fenced, or the INVALIDATE's coverage write committed and may be acknowledged.
    Done,
    /// Nothing was adopted beyond what the step proved; the caller repeats the step.
    Unresolved,
}

/// The identities [`Fencing::new`] hands out, one per fencing of the process; 0 names no fencing.
static FENCINGS: AtomicU64 = AtomicU64::new(1);

/// The identity of one request of a coverage step: the process-unique identity of the [`Fencing`] that issued it,
/// and the count of requests that fencing issued up to and including it. A test-only clone of a fencing keeps the
/// original's identity.
#[derive(Debug, Clone, Copy)]
struct Step {
    fencing: u64,
    n: u64,
}

impl PartialEq for Step {
    fn eq(&self, other: &Self) -> bool {
        #[cfg(test)]
        if UNBOUND_REPLIES.with(std::cell::Cell::get) {
            return true;
        }
        (self.fencing, self.n) == (other.fencing, other.n)
    }
}

impl Eq for Step {}

/// The store request of one coverage step on one page. [`PageRequest::run`] issues it on the thread that calls it:
/// the store lane, or the caller of a synchronous composition ([`Fencing::cover_page`], `Owner::cover_pending`).
/// Only a [`Fencing`] builds one, and its reply carries the request's [`Step`], so the fencing applies the reply
/// only to the request it awaits.
#[derive(Debug)]
#[must_use = "a coverage step waits for the reply to its request"]
pub struct PageRequest {
    step: Step,
    shard: Shard,
    page: u16,
    op: Op,
    /// The page's [`KeyIndex`], which [`PageRequest::run`] rebuilds for the value the store returns and the reply
    /// carries back.
    index: Box<KeyIndex>,
}

#[derive(Debug)]
enum Op {
    /// An exact-version compare-and-swap of `next` on `basis`, the page's known value, which the request shares
    /// with the fencing. `saturating` marks the saturated write that follows a size rejection.
    Write {
        basis: Arc<Read<CoveragePage>>,
        next: Next,
        saturating: bool,
    },
    /// A read of the page; `saturate` marks the re-read after a size rejection, which the saturated write follows.
    Reread { saturate: bool },
}

impl PageRequest {
    /// The page the request reads or writes.
    pub fn page(&self) -> u16 {
        self.page
    }

    /// Issues the request's one store call on `client`, the client of the store the fencing fenced. A write first
    /// builds its value from its basis and the edits the fencing drafted. The [`KeyIndex`] the request carries is
    /// rebuilt for the value the store returned (KEY-INDEX), and kept as it was when the call returned none.
    pub fn run<S: Store, L: WatermarkLog>(self, client: &mut Client<S, L>) -> PageReply {
        let Self {
            step,
            shard,
            page,
            op,
            mut index,
        } = self;
        let answer = match op {
            Op::Write {
                basis,
                next,
                saturating,
            } => {
                let next = next.over(basis.value());
                Answer::Written {
                    saturating,
                    written: client.replace(&basis, next),
                }
            }
            Op::Reread { saturate } => Answer::Reread {
                saturate,
                read: client.read::<CoveragePage>(Key::Page(shard, page)),
            },
        };
        if let Answer::Written {
            written: Ok(value), ..
        }
        | Answer::Reread {
            read: Ok(value), ..
        } = &answer
        {
            index.build(value);
        }
        PageReply {
            step,
            page,
            answer,
            index,
        }
    }

    /// A re-read of `page` that no fencing awaits.
    #[cfg(test)]
    pub(crate) fn reread(shard: Shard, page: u16) -> Self {
        Self {
            step: Step { fencing: 0, n: 0 },
            shard,
            page,
            op: Op::Reread { saturate: false },
            index: Box::new(KeyIndex::new([1; 5])),
        }
    }
}

/// The store's answer to one [`PageRequest`], which [`Fencing::cover_end`] applies.
#[derive(Debug)]
pub struct PageReply {
    step: Step,
    page: u16,
    answer: Answer,
    /// The request's [`KeyIndex`], rebuilt for the value the store returned and as it was when none returned.
    index: Box<KeyIndex>,
}

#[derive(Debug)]
enum Answer {
    Written {
        saturating: bool,
        written: Result<Read<CoveragePage>, StoreError>,
    },
    Reread {
        saturate: bool,
        read: Result<Read<CoveragePage>, StoreError>,
    },
}

/// What [`Fencing::cover_end`] decided for a coverage step.
#[derive(Debug)]
pub enum Cover {
    /// The step's write committed with an acknowledged success, the acknowledgment point of every entry it carried.
    Done,
    /// The step ended with no acknowledged commit and no value of the page from the store, an unknown outcome or an
    /// unavailable re-read; its entries stay in the coverage, and a later step writes them.
    Unresolved,
    /// The step ended with no acknowledged commit, and the re-read after a failed condition became the page's known
    /// value, the basis of a later step that writes the entries.
    Rebased,
    /// The step continues with this request, whose reply goes to [`Fencing::cover_end`] in turn.
    Next(PageRequest),
}

#[cfg(test)]
thread_local! {
    /// A planted defect for tests: while set, [`Fencing::cover_end`] returns [`Cover::Done`] for a write whose
    /// outcome is unknown, which lacks an acknowledged success, so the ACK-ON-COMMIT checks can show they fail.
    pub(crate) static ACK_ON_UNKNOWN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// A planted defect for tests: while set, every two [`Step`]s compare equal, so [`Fencing::cover_end`] applies a
    /// reply to whichever request the fencing awaits.
    pub(crate) static UNBOUND_REPLIES: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// The most pages of a shard whose kept growth figures a debug build checks against a pass over the known values
/// each time a known value changes.
const RECOUNTED_PAGES: usize = 64;

/// A fenced shard's coverage pages as the tenure last knows them: the known values that read saturated, of the page
/// count, and the largest known value's encoding, of the page capacity. `largest` and `capacity` measure page size in
/// encoded bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageCensus {
    pub saturated: usize,
    pub pages: usize,
    pub largest: usize,
    pub capacity: usize,
}

/// One tenure's fencing of its shard's coverage pages, with the coverage it holds. Page `p` is fenced exactly when
/// `known[p]` holds a value, which is the value the tenure's own acknowledged write committed or a later read of
/// the page; its fence is the tenure's session. `fenced` counts the fenced pages. `marks[p]` holds the mark of
/// every key of `known[p]`, under the coverage's hash keys, and may hold the marks of keys that coverage writes of
/// the page carried since a read of the page last became its known value. `index[p]` holds page p's [`KeyIndex`]
/// while no request of the page carries it: the index the page's last applied reply brought, or `None` before the
/// page's first applied reply and after a request or reply that carried the index was dropped. A use checks it
/// against the known value (KEY-INDEX). `id` is the fencing's process-unique
/// identity, `steps` counts the coverage requests it issued, and `awaiting` holds the count of the one whose reply
/// [`Fencing::cover_end`] takes.
///
/// [`Fencing::install`] is the one writer of `known` and keeps the growth figures of the known values beside it,
/// so [`Fencing::census`] reads them in constant time: `saturated` counts the known values that read saturated,
/// `pairs` sums their `(key, interval)` entries, and `lengths` is a max tournament over their encoded lengths. Leaf
/// `B + p` of `lengths` holds page `p`'s encoded length, 0 while the page is unfenced; each node `n` below `B` holds
/// the larger of nodes `2n` and `2n + 1`; node 1 holds the largest known length. With `B = 1` the one leaf is node 1.
#[cfg_attr(test, derive(Clone))]
pub struct Fencing {
    shard: Shard,
    own: u64,
    known: Vec<Option<Arc<Read<CoveragePage>>>>,
    marks: Vec<Marks>,
    index: Vec<Option<Box<KeyIndex>>>,
    fenced: usize,
    saturated: usize,
    pairs: usize,
    lengths: Vec<usize>,
    coverage: Coverage,
    withdrawn: Option<Withdraw>,
    id: u64,
    steps: u64,
    awaiting: Option<u64>,
}

impl fmt::Debug for Fencing {
    /// Formats the fencing's shard, session, known page values, fenced count, coverage, withdrawal and request
    /// counts: the state two fencings share after equal inputs and equal store replies, so their output is equal.
    /// The output leaves out `id`, which each [`Fencing::new`] call draws anew, and `marks`, which are hashes under
    /// the coverage's hash keys, private to the [`Coverage`].
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fencing")
            .field("shard", &self.shard)
            .field("own", &self.own)
            .field("known", &self.known)
            .field("fenced", &self.fenced)
            .field("coverage", &self.coverage)
            .field("withdrawn", &self.withdrawn)
            .field("steps", &self.steps)
            .field("awaiting", &self.awaiting)
            .finish_non_exhaustive()
    }
}

impl Fencing {
    /// The fencing of `record`'s `B` pages by the tenure of `session`, keeping at most `intervals` intervals of one
    /// key on a page and `record`'s `C_page` bytes per page.
    ///
    /// # Errors
    ///
    /// The first [`FencingRefusal`] that applies.
    pub fn new(
        record: &ShardRecord,
        session: &Session,
        intervals: usize,
    ) -> Result<Self, FencingRefusal> {
        let page_bytes = usize::try_from(record.page_cap.get()).expect("a u32 fits a 64-bit usize");
        if session.shard() != record.shard {
            return Err(FencingRefusal::Shard);
        }
        if session.generation() != record.generation {
            return Err(FencingRefusal::Generation);
        }
        if page_bytes < page_len(0) {
            return Err(FencingRefusal::PageCap);
        }
        let limits = Limits {
            intervals,
            page_bytes,
        };
        Ok(Self {
            shard: record.shard,
            own: session.get(),
            known: vec![None; usize::from(record.pages.get())],
            marks: vec![Marks::default(); usize::from(record.pages.get())],
            index: vec![None; usize::from(record.pages.get())],
            fenced: 0,
            saturated: 0,
            pairs: 0,
            lengths: vec![0; 2 * usize::from(record.pages.get())],
            coverage: Coverage::new(record.pages, limits),
            withdrawn: None,
            id: FENCINGS.fetch_add(1, Ordering::Relaxed),
            steps: 0,
            awaiting: None,
        })
    }

    /// The complete fencing of `record`'s pages by the tenure of `session`, in at most `rounds` [`fence_all`]
    /// passes: the step every tenure runs before it serves, so its acknowledged coverage precedes successor admission.
    ///
    /// # Errors
    ///
    /// [`FenceRefused`]: the construction's refusal, the first withdrawing step, or the lowest page still unfenced
    /// after `rounds` passes.
    ///
    /// [`fence_all`]: Self::fence_all
    pub fn fenced<S: Store, L: WatermarkLog>(
        client: &mut Client<S, L>,
        record: &ShardRecord,
        session: &Session,
        intervals: usize,
        rounds: usize,
    ) -> Result<Self, FenceRefused> {
        let mut fencing = Self::new(record, session, intervals).map_err(FenceRefused::Fencing)?;
        for _ in 0..rounds {
            if fencing.fence_all(client).map_err(FenceRefused::Fence)? == Progress::Done {
                return Ok(fencing);
            }
        }
        let page = (0..record.pages.get())
            .find(|&page| fencing.known(page).is_none())
            .expect("an unresolved fencing leaves a page unfenced");
        Err(FenceRefused::Unresolved { page })
    }

    /// Whether every page is fenced: the fencing progress, which a withdrawal leaves as it was. Until then the tenure
    /// serves misses only: it admits no FILL, restores nothing and acknowledges no INVALIDATE. [`Fencing::coverage`]
    /// is the serving gate.
    pub fn complete(&self) -> bool {
        self.fenced == self.known.len()
    }

    /// The coverage that FILL admission and residency check against, once every page is fenced and while the
    /// tenure is not withdrawn.
    pub fn coverage(&self) -> Option<&Coverage> {
        (self.withdrawn.is_none() && self.complete()).then_some(&self.coverage)
    }

    /// Page `page`'s known value, present once the tenure fenced it.
    pub fn known(&self, page: u16) -> Option<&Read<CoveragePage>> {
        self.known.get(usize::from(page))?.as_deref()
    }

    /// The census of the pages' known values once the tenure fenced every page, `None` before; a withdrawn tenure
    /// keeps its last census. It counts the known values only, which an acknowledged write or a read set, so an
    /// in-memory saturation whose write has no known outcome, which [`Growth::held_saturated_pages`] counts, is
    /// outside `saturated`.
    pub fn census(&self) -> Option<PageCensus> {
        self.complete().then(|| {
            let committed = self.committed();
            PageCensus {
                saturated: committed.saturated_pages,
                pages: self.known.len(),
                largest: committed.largest_page_bytes,
                capacity: self.coverage.limits.page_bytes,
            }
        })
    }

    /// The growth monitor's figures over the fenced pages' known values, with no in-memory saturation, read from
    /// the figures [`Fencing::install`] keeps.
    fn committed(&self) -> Growth {
        Growth {
            saturated_pages: self.saturated,
            largest_page_bytes: self.lengths[1],
            pairs: self.pairs,
            held_saturated_pages: 0,
        }
    }

    /// [`Fencing::committed`] computed by one pass over the known values, which the kept figures must equal.
    fn recounted(&self) -> Growth {
        self.known.iter().flatten().map(|read| read.value()).fold(
            Growth::default(),
            |growth, page| Growth {
                saturated_pages: growth.saturated_pages + usize::from(page.saturated),
                largest_page_bytes: growth.largest_page_bytes.max(page.encoded_len()),
                pairs: growth.pairs + page.entries.len() / ENTRY_LEN,
                held_saturated_pages: 0,
            },
        )
    }

    /// The growth monitor's figures over the fenced pages' known values and the in-memory saturations.
    pub fn growth(&self) -> Growth {
        let committed = self.committed();
        let held_saturated_pages = (0..)
            .zip(&self.coverage.saturated)
            .filter(|&(page, &held)| {
                held && !self.known(page).is_some_and(|read| read.value().saturated)
            })
            .count();
        Growth {
            held_saturated_pages,
            ..committed
        }
    }

    /// A read of page `page` that returned no value yields `Ok(None)`.
    ///
    /// # Errors
    ///
    /// [`Withdraw::NewerFence`] when the page's fence is above the tenure's session; [`Withdraw::Malformed`] when
    /// its entries do not decode or hold a key of another page, its encoding exceeds `C_page`, or it holds more
    /// intervals per key than `self.coverage.limits.intervals.max(1)`, as a page written under a larger bound can;
    /// [`Withdraw::Store`] for any other client error.
    fn checked(
        &self,
        page: u16,
        read: Result<Read<CoveragePage>, StoreError>,
    ) -> Result<Option<Read<CoveragePage>>, Withdraw> {
        let read = match read {
            Ok(read) => read,
            Err(StoreError::Unavailable) => return Ok(None),
            Err(error) => return Err(Withdraw::Store(error)),
        };
        let fence = read.value().fence;
        if fence > self.own {
            return Err(Withdraw::NewerFence { page, fence });
        }
        // A page holding more intervals of one key than this tenure's bound would adopt as their hull, covering gaps.
        // A writer with an interval bound of 0 retains one hull interval per key, so fencing uses a minimum bound of 1.
        let mut keys: Vec<_> = (read.value().entries.as_chunks().0.iter())
            .map(entry_key)
            .collect();
        keys.sort_unstable();
        let bound = self.coverage.limits.intervals.max(1);
        if read.value().encoded_len() > self.coverage.limits.page_bytes
            || !entries_on(&read.value().entries, page, self.coverage.pages)
            || keys.chunk_by(|a, b| a == b).any(|run| run.len() > bound)
        {
            return Err(Withdraw::Malformed { page });
        }
        Ok(Some(read))
    }

    /// Takes `read` as page `page`'s known value, counting the page fenced when it was not, and moves the kept
    /// growth figures from the value it replaces to `read`: the saturated count, the pair count, and the page's
    /// leaf of the length tournament with its ancestors, up to the first one the new length leaves as it was. A
    /// page's length can fall, as when a merge replaces a key's intervals with their hull or the page is written
    /// saturated, so each ancestor is recomputed from both children. Debug builds compare the kept figures with
    /// [`Fencing::recounted`] for a shard of at most [`RECOUNTED_PAGES`] pages, where that pass is cheap. The caller
    /// keeps `marks[page]` holding the mark of every key of `read`.
    fn install(&mut self, page: u16, read: Read<CoveragePage>) {
        let value = read.value();
        let (saturated, pairs, length) = (
            usize::from(value.saturated),
            value.entries.len() / ENTRY_LEN,
            value.encoded_len(),
        );
        let slot = &mut self.known[usize::from(page)];
        match slot.as_ref().map(|read| read.value()) {
            Some(replaced) => {
                self.saturated -= usize::from(replaced.saturated);
                self.pairs -= replaced.entries.len() / ENTRY_LEN;
            }
            None => self.fenced += 1,
        }
        self.saturated += saturated;
        self.pairs += pairs;
        *slot = Some(Arc::new(read));
        let mut node = self.known.len() + usize::from(page);
        self.lengths[node] = length;
        while node > 1 {
            node /= 2;
            let larger = self.lengths[2 * node].max(self.lengths[2 * node + 1]);
            if self.lengths[node] == larger {
                break;
            }
            self.lengths[node] = larger;
        }
        debug_assert!(
            self.known.len() > RECOUNTED_PAGES || self.committed() == self.recounted(),
            "the kept growth figures equal a pass over the known values"
        );
    }

    /// Takes `read`, a value the store returned for page `page`, as the page's known value, and marks its keys.
    fn set_known(&mut self, page: u16, read: Read<CoveragePage>) {
        self.marks[usize::from(page)] = Marks::of(read.value(), &self.coverage);
        self.install(page, read);
    }

    /// Page `page`'s [`KeyIndex`] for a request of the page: the one the fencing holds, or a new one that names no
    /// value when the slot is empty.
    fn take_index(&mut self, page: u16) -> Box<KeyIndex> {
        let seeds = self.coverage.seeds;
        self.index[usize::from(page)]
            .take()
            .unwrap_or_else(|| Box::new(KeyIndex::new(seeds)))
    }

    /// Takes `read` as page `page`'s known value and covers its blocked set.
    fn adopt(&mut self, page: u16, read: Read<CoveragePage>) {
        self.coverage.absorb_accepted(page, read.value());
        self.set_known(page, read);
    }

    /// Records the withdrawal that `result` carries and returns `result`. [`Fencing::fence`] returns
    /// [`Withdraw::NoPage`] and [`Fencing::cover_end`] returns [`Withdraw::Unpaired`] before any step, so neither
    /// reaches here.
    fn latched<T>(&mut self, result: Result<T, Withdraw>) -> Result<T, Withdraw> {
        if let Err(withdraw) = result {
            self.withdrawn.get_or_insert(withdraw);
        }
        result
    }

    /// Fences page `page`: reads it and writes it back with the tenure's session as its fence by an exact-version
    /// compare-and-swap on the read version, which confirms the fence when the read already shows it. The page's
    /// blocked set enters the coverage only on that write's acknowledged success. A fenced page returns
    /// [`Progress::Done`] with no request.
    ///
    /// # Errors
    ///
    /// The latched withdrawal, with no request; [`Withdraw::NoPage`] when `page` is at or past `B`;
    /// [`Fencing::checked`]'s errors, with no write issued; [`Withdraw::Store`] when the write's error is neither a
    /// failed condition nor an unknown outcome.
    pub fn fence<S: Store, L: WatermarkLog>(
        &mut self,
        client: &mut Client<S, L>,
        page: u16,
    ) -> Result<Progress, Withdraw> {
        if let Some(withdraw) = self.withdrawn {
            return Err(withdraw);
        }
        if usize::from(page) >= self.known.len() {
            return Err(Withdraw::NoPage { page });
        }
        self.fence_pages(client, &[page])
    }

    /// Fences every page not yet fenced, each as [`Fencing::fence`] does, with the pages' reads issued as one
    /// [`Client::read_all`] in page order and then the writes of the pages whose reads passed their checks as one
    /// [`Client::replace_all`]. Each page's write conditions on its own read, so the per-page order of
    /// FENCE-BEFORE-USE and CARRY-FORWARD holds for every page. [`Progress::Done`] once every page is fenced, and
    /// [`Progress::Unresolved`] when a page's read returned no value or its write failed its condition or had an
    /// unknown outcome; those pages stay unfenced for the next call.
    ///
    /// # Errors
    ///
    /// A latched withdrawal returns before requests begin. Otherwise, [`Fencing`] latches and returns the first
    /// withdrawal in page order: [`Fencing::checked`]'s errors, before any write is issued, then
    /// [`Withdraw::Store`] for any other write error.
    pub fn fence_all<S: Store, L: WatermarkLog>(
        &mut self,
        client: &mut Client<S, L>,
    ) -> Result<Progress, Withdraw> {
        if let Some(withdraw) = self.withdrawn {
            return Err(withdraw);
        }
        let pages: Vec<u16> = (0..).take(self.known.len()).collect();
        self.fence_pages(client, &pages)
    }

    /// Each page in `pages` must index `self.known`. Reads the unfenced ones, then writes each read page back with
    /// the tenure's session as its fence by an exact-version compare-and-swap on its read version. Returns
    /// [`Progress::Done`] when every page in `pages` is fenced.
    fn fence_pages<S: Store, L: WatermarkLog>(
        &mut self,
        client: &mut Client<S, L>,
        pages: &[u16],
    ) -> Result<Progress, Withdraw> {
        let unfenced: Vec<u16> = pages
            .iter()
            .copied()
            .filter(|&page| self.known(page).is_none())
            .collect();
        let keys: Vec<Key> = unfenced
            .iter()
            .map(|&page| Key::Page(self.shard, page))
            .collect();
        let mut basis = Vec::with_capacity(unfenced.len());
        for (page, read) in unfenced.into_iter().zip(client.read_all(&keys)) {
            match self.checked(page, read) {
                Ok(Some(read)) => basis.push((page, read)),
                Ok(None) => {}
                Err(withdraw) => return self.latched(Err(withdraw)),
            }
        }
        let own = self.own;
        let written = client.replace_all(basis.iter().map(|(_, read)| {
            let next = CoveragePage {
                fence: own,
                ..read.value().clone()
            };
            (read, next)
        }));
        self.coverage
            .reserve_for(written.iter().flatten().map(Read::value));
        for ((page, _), written) in basis.iter().zip(written) {
            match written {
                Ok(written) => self.adopt(*page, written),
                Err(StoreError::Unknown | StoreError::Refused(Refusal::Condition)) => {}
                Err(error) => return self.latched(Err(Withdraw::Store(error))),
            }
        }
        let fenced = pages.iter().all(|&page| self.known(page).is_some());
        Ok(if fenced {
            Progress::Done
        } else {
            Progress::Unresolved
        })
    }

    /// Covers `entries`, all on one page, for INVALIDATEs that share one write. Each entry enters the coverage at
    /// once. Once every page is fenced, the page's known value with each entry [`merged`] in turn enters the
    /// coverage and is written by an exact-version compare-and-swap on the page's known version, whose fence is the
    /// tenure's session. [`Progress::Done`] only on that write's acknowledged success, or on the acknowledged success
    /// of the saturated write that follows its size rejection, and it acknowledges every entry. A failed condition
    /// re-reads the page as its next basis, and an unknown outcome keeps the basis; both return
    /// [`Progress::Unresolved`].
    ///
    /// # Errors
    ///
    /// The latched withdrawal, with no request; [`Fencing::checked`]'s errors on a re-read;
    /// [`Withdraw::Store`] for any other write error.
    ///
    /// # Panics
    ///
    /// When `entries` is empty or names keys of two pages.
    pub fn cover_page<S: Store, L: WatermarkLog>(
        &mut self,
        client: &mut Client<S, L>,
        entries: &[Entry],
    ) -> Result<Progress, Withdraw> {
        let Some(mut request) = self.cover_begin(entries)? else {
            return Ok(Progress::Unresolved);
        };
        loop {
            match self.cover_end(request.run(client))? {
                Cover::Done => return Ok(Progress::Done),
                Cover::Unresolved | Cover::Rebased => return Ok(Progress::Unresolved),
                Cover::Next(next) => request = next,
            }
        }
    }

    /// The first half of [`Fencing::cover_page`], up to its store request. Each entry, and then each hull or
    /// saturation the page's merge makes, enters the coverage before the call returns, so FILL admission refuses
    /// what the write will block before the write is issued (COVER-BEFORE-SUBMIT); the entries stay in the coverage
    /// whatever later happens to the request. Once every page is fenced, it returns the exact-version write of the
    /// merged page on the page's known value, and [`Fencing::cover_end`] then awaits that request's reply alone: a
    /// later call replaces the awaited request, and the earlier one's reply is refused. While a page is unfenced it
    /// returns `Ok(None)` with no request.
    ///
    /// Under a warm bootstrap the call changes the coverage that the warm source checks restored entries against,
    /// so its caller makes no call before the warm load's `LoadComplete`.
    ///
    /// # Errors
    ///
    /// The latched withdrawal, before any change to the coverage.
    ///
    /// # Panics
    ///
    /// When `entries` is empty or names keys of two pages.
    pub fn cover_begin(&mut self, entries: &[Entry]) -> Result<Option<PageRequest>, Withdraw> {
        if let Some(withdraw) = self.withdrawn {
            return Err(withdraw);
        }
        let page = page_of(&entries[0].0, self.coverage.pages);
        for &(key, interval) in entries {
            let on = page_of(&key, self.coverage.pages);
            assert_eq!(on, page, "one write covers one page");
            self.coverage.add(key, interval);
        }
        if !self.complete() {
            return Ok(None);
        }
        let basis = self.known[usize::from(page)]
            .clone()
            .expect("every page is fenced and page_of is below B");
        let index = self.index[usize::from(page)].as_deref();
        let (coverage, marks) = (&mut self.coverage, &mut self.marks[usize::from(page)]);
        // An entry's mark is new exactly when no key of the known value and no earlier entry has its mark, and the
        // marks then hold every key the write can commit.
        let fresh: Vec<bool> = (entries.iter())
            .map(|(key, _)| marks.insert(coverage.hash(key)))
            .collect();
        let limits = coverage.limits;
        let merged = |entry: Entry, change| match change {
            Change::Entry => {}
            Change::Hull(hull) => coverage.add(entry.0, hull),
            Change::Saturated => coverage.saturate(page),
        };
        let lookup = index.map(|index| (index, basis.version()));
        let next = merge_each(basis.value(), entries, &fresh, limits, lookup, merged);
        let write = Op::Write {
            basis,
            next,
            saturating: false,
        };
        Ok(Some(self.issue(page, write)))
    }

    /// The second half of [`Fencing::cover_page`]: applies `reply`, the reply to the request the fencing awaits,
    /// from [`Fencing::cover_begin`] or an earlier [`Cover::Next`]. It returns [`Cover::Done`] only on the
    /// acknowledged success of the step's write, and adopts the committed value as the page's known value
    /// (ACK-ON-COMMIT). An unknown outcome keeps the basis and returns [`Cover::Unresolved`]. A failed condition
    /// returns [`Cover::Next`] with a re-read, which adopts the read page as the next basis and returns
    /// [`Cover::Rebased`], or [`Cover::Unresolved`] when the read is unavailable. A size rejection of the merged write returns [`Cover::Next`] with a re-read, which
    /// returns the saturated write in [`Cover::Next`].
    ///
    /// # Errors
    ///
    /// [`Withdraw::Unpaired`], with nothing applied, when `reply` answers no request the fencing awaits. Otherwise
    /// the latched withdrawal; [`Fencing::checked`]'s errors on a re-read; [`Withdraw::Store`] with
    /// [`StoreError::Regression`] for a re-read whose fence is below the tenure's session; [`Withdraw::Store`] for a
    /// rejected saturated write and any other write error. Each error but `Unpaired` latches.
    pub fn cover_end(&mut self, reply: PageReply) -> Result<Cover, Withdraw> {
        let awaited = (self.awaiting).map(|n| Step {
            fencing: self.id,
            n,
        });
        if awaited != Some(reply.step) {
            return Err(Withdraw::Unpaired);
        }
        self.awaiting = None;
        if let Some(withdraw) = self.withdrawn {
            return Err(withdraw);
        }
        let PageReply {
            page,
            answer,
            index,
            ..
        } = reply;
        // The index names the value this reply returned, or the one the page's slot held when it returned none; a
        // later use checks it against the known value (KEY-INDEX).
        self.index[usize::from(page)] = Some(index);
        let covered = match answer {
            // The store rejects on size before it checks the condition, so the rejected write's basis may be stale,
            // and the re-read supplies the page's current version for the saturated write.
            Answer::Written {
                saturating: false,
                written: Err(StoreError::Refused(Refusal::Rejected)),
            } => Ok(Cover::Next(self.issue(page, Op::Reread { saturate: true }))),
            Answer::Written { written, .. } => self.settle(page, written),
            Answer::Reread { saturate, read } => self.reread(page, read, saturate),
        };
        self.latched(covered)
    }

    /// Issues the next coverage request, on page `page`, as the one request the fencing awaits. The request carries
    /// the page's [`KeyIndex`].
    fn issue(&mut self, page: u16, op: Op) -> PageRequest {
        self.steps += 1;
        self.awaiting = Some(self.steps);
        PageRequest {
            step: Step {
                fencing: self.id,
                n: self.steps,
            },
            shard: self.shard,
            page,
            op,
            index: self.take_index(page),
        }
    }

    /// The shard's page count `B`.
    pub fn pages(&self) -> NonZeroU16 {
        self.coverage.pages
    }

    pub fn shard(&self) -> Shard {
        self.shard
    }

    /// The tenure's session value, which every fence written by [`Fencing::fence`] and [`Fencing::fence_all`] carries.
    pub fn session(&self) -> u64 {
        self.own
    }

    /// Adds `entry` to the coverage with no request, so FILL admission refuses its versions while its write waits.
    pub fn hold(&mut self, (key, interval): Entry) {
        self.coverage.add(key, interval);
    }

    /// Whether FILL admission may admit `version` of `key`: every page is fenced, the tenure is not withdrawn, and
    /// the coverage, pending entries included, does not [exclude](Coverage::excludes) the version, the rule warm
    /// recovery applies to a stored entry.
    pub fn admits(&self, key: &[u8; 32], version: CacheVersion) -> bool {
        self.coverage()
            .is_some_and(|coverage| !coverage.excludes(key, version))
    }

    /// Settles a coverage write of page `page`, whose value the caller covered before submitting it: adopts the
    /// committed value on an acknowledged success, requests a re-read after a failed condition, and keeps the basis
    /// after an unknown outcome, which proves neither a commit nor its absence.
    fn settle(
        &mut self,
        page: u16,
        written: Result<Read<CoveragePage>, StoreError>,
    ) -> Result<Cover, Withdraw> {
        #[cfg(test)]
        if ACK_ON_UNKNOWN.with(std::cell::Cell::get) && written == Err(StoreError::Unknown) {
            return Ok(Cover::Done);
        }
        match written {
            Ok(written) => {
                // The committed value holds keys of its basis and of the write's entries, which are marked, and a
                // saturated value holds none.
                if written.value().saturated {
                    self.marks[usize::from(page)] = Marks::default();
                }
                self.install(page, written);
                Ok(Cover::Done)
            }
            Err(StoreError::Refused(Refusal::Condition)) => Ok(Cover::Next(
                self.issue(page, Op::Reread { saturate: false }),
            )),
            Err(StoreError::Unknown) => Ok(Cover::Unresolved),
            Err(error) => Err(Withdraw::Store(error)),
        }
    }

    /// Applies a re-read of page `page`, which the tenure fenced; an unavailable read keeps the known value. Fences
    /// never decrease and a newer one withdraws; a fence below the tenure's session on a page the tenure fenced shows
    /// the store lost the tenure's write, a regression. So an accepted read shows the tenure's own fence. After a
    /// failed condition the read becomes the known value and its blocked set enters the coverage. After a size
    /// rejection (`saturate`) the read only supplies the known version: the saturation, which blocks every pair on
    /// the page, enters the coverage, and the saturated write on the known value follows.
    fn reread(
        &mut self,
        page: u16,
        read: Result<Read<CoveragePage>, StoreError>,
        saturate: bool,
    ) -> Result<Cover, Withdraw> {
        let read = self.checked(page, read)?;
        if read
            .as_ref()
            .is_some_and(|read| read.value().fence < self.own)
        {
            let regression = Regression::Value(Key::Page(self.shard, page));
            return Err(Withdraw::Store(StoreError::Regression(regression)));
        }
        if !saturate {
            let Some(read) = read else {
                return Ok(Cover::Unresolved);
            };
            self.adopt(page, read);
            return Ok(Cover::Rebased);
        }
        if let Some(read) = read {
            self.set_known(page, read);
        }
        let next = saturated(self.own);
        self.coverage.absorb_accepted(page, &next);
        let basis = self.known[usize::from(page)]
            .clone()
            .expect("cover fenced every page first");
        let write = Op::Write {
            basis,
            next: Next::Whole(next),
            saturating: true,
        };
        Ok(Cover::Next(self.issue(page, write)))
    }

    #[cfg(test)]
    pub(crate) fn partial(&self) -> &Coverage {
        &self.coverage
    }

    #[cfg(test)]
    pub(crate) fn replace_coverage(&mut self, coverage: Coverage) {
        self.coverage = coverage;
        for (marks, known) in self.marks.iter_mut().zip(&self.known) {
            if let Some(read) = known {
                *marks = Marks::of(read.value(), &self.coverage);
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn read_as_fenced<S: Store, L: WatermarkLog>(
        &mut self,
        client: &mut Client<S, L>,
        page: u16,
    ) -> Progress {
        let Ok(read) = client.read::<CoveragePage>(Key::Page(self.shard, page)) else {
            return Progress::Unresolved;
        };
        self.adopt(page, read);
        Progress::Done
    }
}
