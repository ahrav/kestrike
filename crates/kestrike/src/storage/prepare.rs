//! Lookup preparation: the routes of a window of keys derived ahead of the
//! lookups that consume them, each bound to the key and ordinal it was
//! derived for, with the search's first lines hinted so their misses
//! overlap the lookups before it.
//!
//! A [`Preparation`] is bound to one storage, its origin, and holds a ring
//! of [`SLOTS`] entries, the ordinal of the window's first key and two
//! cursors: the end of the last group resolved and the next position to
//! stage. Each entry owns a copy of its key, its ordinal, its unpaid route
//! and references to the route's base bucket and chain summary in the
//! index mapping; the lookup that consumes the entry takes every pin,
//! reservation and charge. An entry's key is copied from the caller's slice
//! in the same call that hashes it, so its key and its route always come
//! from the same bytes. [`prime`](Preparation::prime) and
//! [`advance`](Preparation::advance) read the caller's key slice only for
//! the duration of the call, so a caller may rewrite its buffer between
//! calls and every entry keeps the key it was derived for.
//! [`prime`](Preparation::prime) empties the ring and resets the cursors
//! before it reads a new window's keys, and [`reset`](Preparation::reset)
//! does the same alone, so each window starts with an empty ring and
//! hashes each of its groups afresh.
//!
//! The lookahead runs in three stages over the keys ahead of the one being
//! looked up. Before the key at window position `i` is looked up, position
//! `i + DEPTH`'s route, resolved to its base bucket and chain summary, has
//! its summary's line hinted. Then position `i + STAGE`'s summary, hinted
//! `DEPTH - STAGE` lookups earlier, is read. When it excludes the key's tag,
//! the key's search ends at the summary and so does its lookahead; when it
//! admits the tag, both lines of its base bucket and the two record lines
//! of its placement window are hinted, so those misses overlap the `STAGE`
//! lookups before it. The two bucket lines hold the control word, link and
//! all fourteen pairs, and the window lines hold the record of every key the
//! window placed. Last, position `i + PEEK`'s base bucket, hinted
//! `STAGE - PEEK` lookups earlier, is read for the pair that carries the
//! key's tag, and the record line of the slot that pair names is hinted for
//! reading, so that line's miss overlaps the `PEEK` lookups before it. A
//! key claimed while its window was full has its record outside the
//! window's lines, where this hint is the only one that reaches it; a
//! record inside them is asked for a second time, by its own line. An
//! absent key whose summary excludes its tag therefore costs the lookahead
//! one summary line.
//! [`prime`](Preparation::prime) derives the first `DEPTH` routes and stages
//! the first `STAGE`; a caller with work between the derivation and its
//! first lookup runs the two halves itself, [`derive_ahead`](Preparation::derive_ahead)
//! then [`stage_first`](Preparation::stage_first), with
//! [`hint_head`](Preparation::hint_head) covering the first `HEAD`
//! positions it looks up before the staged hints could land.
//! [`advance`](Preparation::advance) at position `i` derives `i + DEPTH`
//! and, from position 1 on, stages through `i + STAGE` and reads the bucket
//! of `i + PEEK`, so position 1 stages two entries and each later position
//! one: the summaries position 0 would stage, and the bucket it would read,
//! were hinted moments earlier.
//!
//! Keys are hashed in aligned groups of the hasher's lane width. On an
//! x86_64 CPU that reports `avx512f` and `vpclmulqdq`, the lookahead's first
//! derivation in a group hashes the whole group and resolves an entry for
//! each of its keys, out of line, so the per-element path carries one call
//! per group: a full group of eight keys runs one multi-key pass, a final
//! group shorter than eight runs one scalar pass per key, and each route is
//! cut from its key's word. The group's later derivations find their
//! entries resolved and only hint their summaries, so each summary is still
//! hinted `DEPTH` lookups ahead. The ring holds a whole group beside the
//! `DEPTH - 1` positions still waiting when that group resolves. Elsewhere
//! each key is hashed and resolved alone when the lookahead reaches it.
//!
//! [`take`](Preparation::take) removes the entry whose ordinal equals the
//! one asked for and passes its route into the [`PreparedLookup`] only when
//! the entry's key equals the key asked for; an entry with another key is
//! discarded, and an entry with another ordinal stays in the ring. A
//! context without a route makes the lookup derive its own. Either way the
//! context owns the key asked for. A route is advisory: the summary and
//! bucket reads here are `Relaxed` and outside any pin or sequence check, so
//! a stale word wastes or skips hints alone, and the lookup that consumes
//! the context pins, pays its guard bundle and hash charge, searches,
//! validates and acquires under its own bracket exactly as an unrouted
//! lookup does.

use std::sync::atomic::{AtomicU64, Ordering};

use super::budget::WorkBudget;
use super::lease::{ExtentLease, ReadRight};
use super::lookup::{GUARD_STEPS, LookupError};
use super::os::Platform;
use super::owner::{IndexOwner, Pool, Storage};
use super::prefetch::hint_read;
use super::register::Registration;
use crate::index::{Bucket, HASH_CHARGE, Key, KeyRoute, LANES, Prefetch, excludes};

/// The least a lookup must have left to reach its hash charge: its guard
/// bundle, then the pass. A caller derives routes ahead only while its
/// budget covers this much.
pub(crate) const AHEAD: usize = GUARD_STEPS + HASH_CHARGE;

/// Routes in flight: position `i + DEPTH`'s summary is hinted before
/// position `i` is looked up.
pub(super) const DEPTH: usize = 8;

/// Distance ahead of the running lookup at which a route is staged:
/// position `i + STAGE`'s summary is read before position `i` is looked up,
/// `DEPTH - STAGE` lookups after its hint, and its bucket and window misses
/// overlap the `STAGE` lookups before it.
pub(super) const STAGE: usize = 4;

/// Window positions whose search lines [`hint_head`](Preparation::hint_head)
/// hints before their summaries arrive: the positions a caller looks up
/// within a lookup's time of its staging.
pub(super) const HEAD: usize = 2;

/// Distance ahead of the running lookup at which a staged route's base
/// bucket is read for the record its key's pair names: position
/// `i + PEEK`'s bucket, hinted `STAGE - PEEK` lookups earlier, is read
/// before position `i` is looked up, and its record's miss overlaps the
/// `PEEK` lookups before it.
pub(super) const PEEK: usize = 1;

const _: () = assert!(STAGE < DEPTH && HEAD <= STAGE && PEEK < STAGE);

/// One lookup's identity: the storage it is for, the full key it owns, and
/// the route preparation derived for that key against that storage's
/// index, or none. Its fields are private to this module, so every context
/// comes from this module's constructors and a route always belongs to the
/// key and origin beside it. The route selects where the search
/// starts and authorizes nothing.
pub(crate) struct PreparedLookup<'s, P: Platform> {
    origin: &'s Storage<P>,
    key: Key,
    route: Option<KeyRoute>,
}

impl<'s, P: Platform> PreparedLookup<'s, P> {
    /// The context of a lookup with no prepared route: `key` copied, nothing
    /// hashed, hinted, pinned or charged.
    pub(super) fn scalar(origin: &'s Storage<P>, key: &Key) -> Self {
        Self {
            origin,
            key: *key,
            route: None,
        }
    }

    /// The key the lookup is for.
    pub(super) fn key(&self) -> &Key {
        &self.key
    }

    /// This context when it is for `key`, else `None`, so a route serves
    /// only the key it was prepared for.
    pub(crate) fn for_key(&self, key: &Key) -> Option<&Self> {
        (self.key == *key).then_some(self)
    }

    /// Whether the context was prepared for `storage`.
    #[inline(always)]
    pub(super) fn is_for(&self, storage: &Storage<P>) -> bool {
        std::ptr::eq(self.origin, storage)
    }

    /// The prepared route, for a test that holds it to the scalar route.
    #[cfg(test)]
    pub(super) fn route(&self) -> Option<KeyRoute> {
        self.route
    }

    /// The route when `storage` is the context's origin, so a route never
    /// searches another storage's index.
    #[inline(always)]
    pub(super) fn route_for(&self, storage: &Storage<P>) -> Option<KeyRoute> {
        if self.is_for(storage) {
            self.route
        } else {
            None
        }
    }
}

impl<'s, P: Platform> Registration<'s, P> {
    /// [`lookup`](Self::lookup) of `prepared`'s key, starting its search
    /// from the prepared route when `prepared` is this storage's. The lease
    /// carries the context's key; every charge and check lands where the
    /// unrouted lookup puts it. A context for another storage is looked up
    /// by its key alone.
    ///
    /// # Errors
    ///
    /// [`LookupError`], as [`lookup`](Self::lookup) returns it.
    #[inline(always)]
    pub(super) fn lookup_prepared(
        &mut self,
        prepared: &PreparedLookup<'s, P>,
        retries: usize,
        budget: &mut WorkBudget,
    ) -> Result<ExtentLease<'s, P>, LookupError> {
        let route = prepared.route_for(self.storage());
        self.lookup_routed(&prepared.key, route, retries, budget)
    }

    /// [`lookup_right`](Self::lookup_right) of `prepared`'s key, starting
    /// its search from the prepared route when `prepared` is this
    /// storage's: the right alone, under `Credit::Read`, with every charge
    /// and check where the unrouted read's lookup puts it. The volume read
    /// refuses a context for another storage before calling it.
    ///
    /// # Errors
    ///
    /// [`LookupError`], as [`lookup_right`](Self::lookup_right) returns it.
    #[inline(always)]
    pub(super) fn lookup_right_prepared(
        &mut self,
        prepared: &PreparedLookup<'s, P>,
        retries: usize,
        budget: &mut WorkBudget,
    ) -> Result<ReadRight<'s, P>, LookupError> {
        let route = prepared.route_for(self.storage());
        self.lookup_right(&prepared.key, route, retries, budget)
    }
}

/// One window position's lookahead: the ordinal and key it was derived
/// for, its unpaid route, and the base bucket and chain summary the route
/// starts from.
#[derive(Clone, Copy)]
struct Entry<'s> {
    ordinal: usize,
    key: Key,
    route: KeyRoute,
    start: &'s Bucket,
    summary: &'s AtomicU64,
}

/// Ring entries: a whole group of [`LANES`] resolved at once beside the
/// `DEPTH - 1` positions still waiting for their lookups. A power of two,
/// so a ring position is a mask of the window position.
pub(super) const SLOTS: usize = 2 * LANES;

const _: () = assert!(SLOTS.is_power_of_two() && SLOTS >= DEPTH + LANES - 1);

/// The reusable lookahead over one storage's index; see the module
/// documentation for its stages and its reset rule.
pub(crate) struct Preparation<'s, P: Platform> {
    origin: &'s Storage<P>,
    /// Position `j`'s entry sits at `ring[j % SLOTS]` from its resolution
    /// until it is taken or replaced by position `j + SLOTS`'s.
    ring: [Option<Entry<'s>>; SLOTS],
    /// The ordinal of the window's first key.
    base: usize,
    /// The position past the last group resolved; a hasher of lane width one
    /// never moves it.
    resolved: usize,
    /// The next position the lookahead stages.
    staged: usize,
}

impl<'s, P: Platform> Preparation<'s, P> {
    /// An empty preparation over `origin`.
    pub(crate) fn new(origin: &'s Storage<P>) -> Self {
        Self {
            origin,
            ring: [None; SLOTS],
            base: 0,
            resolved: 0,
            staged: 0,
        }
    }

    /// Whether the ring holds no entry.
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.ring.iter().all(Option::is_none)
    }

    /// Discards every entry and resets the cursors.
    pub(crate) fn reset(&mut self) {
        *self = Self::new(self.origin);
    }

    /// Resets, then starts a window of `keys` whose first key has ordinal
    /// `base`: derives the routes of the first [`DEPTH`] keys and stages the
    /// first [`STAGE`]. Nothing is charged.
    pub(crate) fn prime(&mut self, keys: &[Key], base: usize) {
        self.derive_ahead(keys, base);
        self.stage_first();
    }

    /// The first half of [`prime`](Self::prime): resets, then derives the
    /// routes of the first [`DEPTH`] keys of a window whose first key has
    /// ordinal `base`, hinting each summary's line. A caller with work to do
    /// before its first lookup, such as the tags of the window's frames,
    /// does that work between this and [`stage_first`](Self::stage_first),
    /// so the summaries arrive before the staging reads them.
    pub(crate) fn derive_ahead(&mut self, keys: &[Key], base: usize) {
        self.reset();
        self.base = base;
        let Some(index) = self.origin.index() else {
            return;
        };
        for position in 0..DEPTH {
            self.derive(index, keys, position);
        }
    }

    /// Hints the search lines of the first [`HEAD`] derived positions
    /// without reading their summaries: these positions are looked up
    /// before the staging that follows the caller's work could fetch their
    /// lines. An absent key among them costs its bucket and window hints.
    pub(crate) fn hint_head(&self) {
        let pool = self.origin.live_pool();
        for first in self.ring[..HEAD].iter().flatten() {
            hint_search(pool, first);
        }
    }

    /// The second half of [`prime`](Self::prime): stages the first
    /// [`STAGE`] derived positions.
    pub(crate) fn stage_first(&mut self) {
        let pool = self.origin.live_pool();
        for first in self.ring[..STAGE].iter().flatten() {
            stage(pool, first);
        }
        self.staged = STAGE;
    }

    /// The lookahead before the key at `ordinal` is looked up, once its
    /// entry was taken: derives the route `DEPTH` positions ahead and, from
    /// the window's second position on, stages through `STAGE` positions
    /// ahead and reads the bucket `PEEK` positions ahead for its record
    /// hint. Called in ascending ordinal order, it hashes each group once.
    /// `keys` is the window [`prime`](Self::prime) read; an `ordinal` outside
    /// it leaves the preparation unchanged.
    #[inline(always)]
    pub(crate) fn advance(&mut self, keys: &[Key], ordinal: usize) {
        let Some(index) = self.origin.index() else {
            return;
        };
        let position = ordinal.wrapping_sub(self.base);
        if position >= keys.len() {
            return;
        }
        self.derive(index, keys, position + DEPTH);
        if position != 0 {
            let pool = self.origin.live_pool();
            while self.staged <= position + STAGE {
                if let Some(next) = &self.ring[self.staged % SLOTS] {
                    stage(pool, next);
                }
                self.staged += 1;
            }
            if let (Some(pool), Some(next)) = (pool, &self.ring[(position + PEEK) % SLOTS]) {
                peek(pool, next);
            }
        }
    }

    /// A lookup context for `key` over this preparation's storage with no
    /// route, for a lookup no window prepared.
    pub(crate) fn scalar(&self, key: &Key) -> PreparedLookup<'s, P> {
        PreparedLookup::scalar(self.origin, key)
    }

    /// The lookup context for `key` at `ordinal`: the entry derived for that
    /// ordinal leaves the ring, and its route rides along only when the
    /// entry was derived for `key`. An entry whose key differs is
    /// discarded; with none, the context carries no route.
    #[inline(always)]
    pub(crate) fn take(&mut self, ordinal: usize, key: &Key) -> PreparedLookup<'s, P> {
        let position = ordinal.wrapping_sub(self.base);
        let slot = &mut self.ring[position % SLOTS];
        let route = match slot {
            Some(entry) if entry.ordinal == ordinal => {
                let route = (entry.key == *key).then_some(entry.route);
                *slot = None;
                route
            }
            _ => None,
        };
        PreparedLookup {
            origin: self.origin,
            key: *key,
            route,
        }
    }

    /// Position `position`'s entry, then its summary line hinted for
    /// reading. A hasher whose passes run one key at a time routes the key
    /// directly; otherwise a position past the last resolved group has its
    /// group hashed and resolved now, and in ascending order any other
    /// position's entry was resolved with its group. Nothing past the window
    /// is derived, and a
    /// position whose route has no start keeps no entry; its lookup then
    /// derives its own route.
    #[inline(always)]
    fn derive(&mut self, index: &'s IndexOwner, keys: &[Key], position: usize) {
        let Some(key) = keys.get(position) else {
            return;
        };
        let at = position % SLOTS;
        if index.hasher.lane_width() == 1 {
            let ordinal = self.base.wrapping_add(position);
            self.ring[at] = index
                .hasher
                .route_unpaid(key, &index.geometry, Prefetch::NONE)
                .and_then(|route| resolve(index, ordinal, *key, route));
        } else if position >= self.resolved {
            debug_assert_eq!(index.hasher.lane_width(), LANES);
            self.resolve_group(index, keys, position - position % LANES);
        }
        if let Some(entry) = &self.ring[at] {
            hint_read(std::ptr::from_ref(entry.summary).cast());
        }
    }

    /// Hashes the group of `keys` that starts at position `start`, at most
    /// [`LANES`] keys, and resolves each key's entry into its ring position
    /// from its own word and its own bytes. An index without an enabled shard
    /// routes no key, so its groups are not hashed. Kept out of line, so the
    /// batch loop carries one call per group rather than the group's routes.
    #[inline(never)]
    fn resolve_group(&mut self, index: &'s IndexOwner, keys: &[Key], start: usize) {
        let group = &keys[start..keys.len().min(start + LANES)];
        self.resolved = start + group.len();
        if index.geometry.enabled().is_empty() {
            return;
        }
        let mut words = [0; LANES];
        index.hasher.fingerprints(group, &mut words);
        for (lane, (key, word)) in group.iter().zip(words).enumerate() {
            let position = start + lane;
            self.ring[position % SLOTS] = index
                .hasher
                .reroute_unpaid(word, &index.geometry)
                .and_then(|route| resolve(index, self.base.wrapping_add(position), *key, route));
        }
    }
}

/// The entry for `key` at `ordinal` on `route`: the base bucket and chain
/// summary resolved from the run the route names. `None` when the route
/// names no run, base bucket or summary.
#[inline(always)]
fn resolve<'s>(
    index: &'s IndexOwner,
    ordinal: usize,
    key: Key,
    route: KeyRoute,
) -> Option<Entry<'s>> {
    let run = index.image.runs().get(route.position())?;
    // SAFETY: `index` is the one `Storage::index` returned for `'s` after its
    // live-phase check, so the index mapping is owned and initialized for
    // `'s`; the run is this image's; every shared field is an atomic.
    let (_, tables) = unsafe { index.image.reader_tables(&index.mapping, run) };
    let start = tables.buckets.get(route.bucket())?;
    let summary = tables.summaries.get(route.bucket())?;
    Some(Entry {
        ordinal,
        key,
        route,
        start,
        summary,
    })
}

/// Reads `next`'s chain summary, hinted when its route was derived, and,
/// when the summary admits the route's tag, hints both lines of its base
/// bucket for reading and the record lines of its placement window in
/// `pool` for writing. The read runs outside any pin or sequence check: a
/// stale word skips or wastes hints alone, and the lookup reads its summary
/// again under its own bracket.
#[inline(always)]
fn stage(pool: Option<&Pool>, next: &Entry<'_>) {
    if excludes(next.summary.load(Ordering::Relaxed), next.route.tag()) {
        return;
    }
    hint_search(pool, next);
}

/// Reads `next`'s base bucket, hinted when its route was staged, and hints
/// for reading the record line of the slot that the lowest pair carrying
/// the route's tag names. A key claimed while its placement window was full
/// has its record outside the window's lines, and this hint is the one that
/// reaches it; a record inside the window is asked for again by its own
/// line. The slot comes from an unpinned read, so the hint asks for the
/// line without taking it from a core that is writing it; the lookup's
/// validation asks for it for writing once its own scan names the slot. A
/// summary that excludes the tag left the bucket unhinted, so the bucket is
/// not read. Every load is `Relaxed` and outside any pin or sequence check:
/// a stale slot, bounded by the pool's slot count, wastes a hint alone.
#[inline(always)]
fn peek(pool: &Pool, next: &Entry<'_>) {
    let tag = next.route.tag();
    if excludes(next.summary.load(Ordering::Relaxed), tag) {
        return;
    }
    if let Some(slot) = next.start.peek_slot(tag)
        && slot < pool.descriptor().slot_count
    {
        pool.prefetch_record_read(slot);
    }
}

/// The hint requests both lines of `next`'s base bucket and its placement
/// window's record generations for reading, and the window's record lines in
/// `pool` for writing.
#[inline(always)]
fn hint_search(pool: Option<&Pool>, next: &Entry<'_>) {
    let first = std::ptr::from_ref(next.start).cast::<u8>();
    hint_read(first);
    hint_read(first.wrapping_add(size_of::<Bucket>() / 2));
    if let Some(pool) = pool {
        pool.prefetch_read_window(next.route.fingerprint());
    }
}
