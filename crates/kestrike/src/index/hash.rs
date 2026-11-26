//! Full-key hashing: one pair of SipHash keys, drawn once at initialization
//! from `std`'s `RandomState` and held immutably as the initial SipHash
//! state, derives a shard route, a base bucket, a 16-bit tag and a 64-bit
//! fingerprint for every complete 32-byte key from one pass.
//!
//! The pass is SipHash-1-3 over exactly the 32 key bytes: no label, no
//! length prefix (`Hash for [u8; N]` would prefix one) and no terminator
//! (`write_str` would append one). Its 64 bits are the fingerprint, and the
//! route and the bucket are fields of the same word: the bucket is the low
//! bits, masked by `B - 1`; the route reduces the low [`ROUTE_BITS`] (57)
//! into the list of enabled shards by a widening multiply and a shift by the
//! same count, so the shard is decided by the top of those bits, the
//! fingerprint's high seven never enter it, and a disabled shard is never
//! selected. The reduction is bounded but not unbiased: over `k` shards the
//! relative bias is at most `k / 2^57`. The bucket's bits lie inside the
//! route's range (a bucket array fits `isize::MAX`, so `B < 2^56`) and reach
//! the shard only through the carry into the product's high part: two words
//! that differ only in their bucket bits select the same shard unless they
//! straddle a boundary of the reduction. Each field is a keyed function of
//! the whole key with the pass's full diffusion.
//! Within one bucket the pair filter is the tag, the 16 bits directly above
//! the bucket's; tag equality makes a pair a candidate and the slot's
//! incarnation and fingerprint equality decide, so two keys of one bucket
//! share a tag with chance `2^-16` and the cost is one record read. The
//! fingerprint is the object's identity in RAM. Two keys of one bucket of a
//! shard with `B` buckets, out of `k` enabled shards, share the word's low
//! `log2(B)` bits and a shard, and the shard is the top of the low 57 bits,
//! which costs about `log2(k)` more bits: the pair's words agree with chance
//! `2^-64` and the pair shares a shard and a bucket with chance about
//! `1 / (k·B)`, so they share the whole word with chance about
//! `k·B·2^-64 = 2^-(64 - log2(B) - log2(k))`. Two such keys have one visible object between them:
//! publishing either displaces the other's, and invalidating either removes
//! it. A read checks the full key against the record's header on the device
//! before any byte, so a lease on the other key's object ends its read with
//! a key mismatch. Every field is cut from the pass's one output word, so a
//! derivation costs one SipHash pass.
//!
//! The implementation is SipHash-1-3 with `std`'s finalization, independent
//! of `std`'s `DefaultHasher`, whose algorithm is unspecified across
//! releases. `siphash13` and its rounds are `#[inline(always)]` and take the
//! key's four words as whole message blocks. [`KeyHasher::route`] is
//! `#[inline(always)]` as well.
//!
//! A caller holding several keys at once, the lookup preparation's
//! lookahead, derives their fingerprints together through
//! `KeyHasher::fingerprints`: the hasher's multi-key mechanism, chosen once
//! when the hasher is drawn, runs a full group of eight passes in the lanes
//! of AVX-512 vectors on an x86_64 CPU that reports `avx512f` and
//! `vpclmulqdq`, and one scalar pass per key for a shorter group or on any
//! other CPU; every lane's word is the scalar pass's word for its key.
//! The caller then cuts each route from its word through
//! `KeyHasher::reroute_unpaid`.
//!
//! A caller who supplies its shards' bucket runs has the key's chain summary
//! and base bucket prefetched after the hash pass and the shard reduction,
//! before the route is returned: a publisher's gate acquire and its scan
//! setup still lie between the derivation and the demand load, and the hint
//! starts the fetch ahead of them. It is a hint only: nothing is read, no route depends on it, and
//! a caller with no runs gets none.
//!
//! The key pair is drawn once by the index owner, off the request path:
//! `RandomState::new` is the only step that reads the per-thread key cache,
//! which the first state built on a thread fills from the kernel random
//! source; the pair is two keyed outputs of that state, so it is
//! unpredictable without the state's own keys, which `std` never exposes.
//! After that, deriving is arithmetic on the state words: it allocates
//! nothing, takes no lock and reads no thread-local. The state and its
//! outputs are never persisted or used as identity, and `Debug` does not
//! print them; a cloned hasher gives identical routing within one process,
//! and each process draws its own pair. All fields come from one pass, so a
//! recovery of the key exposes every field together. Every derivation costs
//! [`HASH_CHARGE`]. [`KeyHasher::route`] charges it before the pass, so a
//! zero budget hashes nothing; [`KeyHasher::route_unpaid`] leaves the charge
//! to the caller that uses the route, so a batch can hash first and pay at
//! its budget decision.

use std::fmt;
use std::hash::{BuildHasher, RandomState};

use super::bucket::Bucket;
use super::geometry::{ShardIndex, ValidatedIndex};
use super::lanes::{LANES, Lanes};
use crate::storage::prefetch::{hint, hint_read};
use crate::storage::{BudgetExhausted, WorkBudget, WorkKind};

/// A complete representation key. Every byte is significant; all-zero and
/// shared-prefix keys are legal.
pub type Key = [u8; 32];

/// Steps one derivation debits: its one pass.
pub const HASH_CHARGE: usize = 1;

/// Bytes of the hash state the index owner holds: the four words of the
/// initial SipHash state, the key pair under the SipHash constants.
pub const HASH_STATE_BYTES: usize = std::mem::size_of::<State>();

/// Bytes hashed per pass: the key.
pub(super) const MESSAGE_BYTES: usize = std::mem::size_of::<Key>();

/// Low bits of the fingerprint the route is reduced from. The shard is the
/// high part of their product with the shard count, so it is decided by the
/// top of these bits and the fingerprint's high seven bits never enter it.
/// The bucket mask keeps bits of the same range, which reach the shard only
/// through the carry into the product's high part. The width is part of the
/// routing contract: another width sends keys to other shards.
const ROUTE_BITS: u32 = 57;

/// The SipHash key pair.
#[derive(Clone, Copy)]
struct Keys {
    k0: u64,
    k1: u64,
}

/// The four SipHash state words.
pub(super) type State = [u64; 4];

impl Keys {
    /// The initial state every pass starts from: the pair xored with the
    /// SipHash constants. Held instead of the pair so a derivation loads
    /// four words rather than rebuilding four 64-bit constants.
    fn initial_state(self) -> State {
        [
            self.k0 ^ 0x736f6d6570736575,
            self.k1 ^ 0x646f72616e646f6d,
            self.k0 ^ 0x6c7967656e657261,
            self.k1 ^ 0x7465646279746573,
        ]
    }
}

/// One enabled shard as a derivation's prefetch target and a reader's
/// destination: the byte offset of its bucket array within the index
/// mapping, what a search needs of it, and the byte offset of its control
/// record.
/// A run table lists the enabled shards in the order of
/// [`ValidatedIndex::enabled`], so the route selects a run exactly as it
/// selects the shard, and a reader resolves the shard's tables from the one
/// run its route names instead of walking from the enabled entry to the
/// shard image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BucketRun {
    /// The byte offset of the first bucket.
    pub(crate) offset: usize,
    /// The byte offset of the first chain summary.
    pub(crate) summaries: usize,
    /// `B - 1`, which selects the base bucket from a hash word.
    pub(crate) bucket_mask: usize,
    /// The bucket count `B + A`.
    pub(crate) buckets: usize,
    /// The base bucket count `B`, which is also the index of overflow
    /// bucket zero.
    pub(crate) base: usize,
    /// Overflow links a chain may follow, `D`.
    pub(crate) depth: usize,
    /// The byte offset of the shard's control record.
    pub(crate) control: usize,
}

/// What a derivation may prefetch: the base of the mapping the runs lie in,
/// the runs, and whether the caller will store to the lines. The base is
/// only an address: the hint never reads through it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Prefetch<'r> {
    pub(crate) base: *const u8,
    pub(crate) runs: &'r [BucketRun],
    pub(crate) for_write: bool,
}

impl Prefetch<'static> {
    /// No hint.
    pub(crate) const NONE: Self = Self {
        base: std::ptr::null(),
        runs: &[],
        for_write: false,
    };
}

impl Prefetch<'_> {
    /// Hints the lines a search of `run` for `word` begins with: the base
    /// bucket's chain summary, then both lines of the base bucket. Each
    /// hint is a direct call of the one `#[inline]` hint function the
    /// caller's purpose selects.
    #[inline(always)]
    fn hint(&self, run: &BucketRun, word: u64) {
        let bucket = (word as usize) & run.bucket_mask;
        let summary = self
            .base
            .wrapping_add(run.summaries)
            .wrapping_add(bucket * size_of::<std::sync::atomic::AtomicU64>());
        let first = self
            .base
            .wrapping_add(run.offset)
            .wrapping_add(bucket * size_of::<Bucket>());
        let second = first.wrapping_add(size_of::<Bucket>() / 2);
        if self.for_write {
            hint(summary);
            hint(first);
            hint(second);
        } else {
            hint_read(summary);
            hint_read(first);
            hint_read(second);
        }
    }
}

/// Where a key lives in the index and how its pairs are filtered. Produced
/// only by the hasher's derivation ([`KeyHasher::route`] and its prefetching
/// and unpaid forms) against one validated index, so the bucket lies below
/// that index's `B[shard]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyRoute {
    shard: ShardIndex,
    position: usize,
    bucket: usize,
    fingerprint: u64,
    tag: u16,
}

impl KeyRoute {
    pub fn shard(&self) -> ShardIndex {
        self.shard
    }

    /// The shard's position among the enabled shards: its index in
    /// [`ValidatedIndex::enabled`] and in a run table.
    pub(crate) fn position(&self) -> usize {
        self.position
    }

    /// Base bucket within the shard, below `B[shard]`.
    pub fn bucket(&self) -> usize {
        self.bucket
    }

    /// All 64 bits of the pass, from which every other field is cut.
    pub fn fingerprint(&self) -> u64 {
        self.fingerprint
    }

    /// The 16 bits of the word directly above the bucket bits, zero past
    /// bit 63: the pair filter within the bucket. Equality makes a pair a
    /// candidate; the slot's incarnation and the fingerprint decide.
    pub fn tag(&self) -> u16 {
        self.tag
    }
}

/// Why no route was derived. Nothing was hashed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteError {
    /// The budget could not pay [`HASH_CHARGE`].
    BudgetExhausted,
    /// Every shard is disabled, so no key has a home.
    NoEnabledShard,
}

impl From<BudgetExhausted> for RouteError {
    fn from(_: BudgetExhausted) -> Self {
        Self::BudgetExhausted
    }
}

/// A deterministic replacement for the pass: the key to the 64-bit word the
/// fields are cut from. Tests install one to force a chosen fingerprint
/// collision, which the keyed state cannot be steered into; it certifies
/// nothing about production hashing.
#[cfg(test)]
pub(crate) type Seam = fn(&Key) -> u64;

#[cfg(test)]
thread_local! {
    /// Counts derivations on this thread.
    pub(crate) static DERIVATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The engine's keyed hash state. Drawn once and never reseeded; a clone
/// routes identically.
#[derive(Clone)]
pub struct KeyHasher {
    initial: State,
    lanes: Lanes,
    #[cfg(test)]
    seam: Option<Seam>,
}

impl fmt::Debug for KeyHasher {
    /// The keys stay out of logs, as `RandomState`'s do.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyHasher").finish_non_exhaustive()
    }
}

impl KeyHasher {
    /// Draws the key pair from the per-thread key cache. The index owner
    /// calls it once at initialization and keeps it off the request path:
    /// this is the one call that touches thread-local key state.
    pub fn seeded() -> Self {
        #[expect(
            clippy::disallowed_methods,
            reason = "mixed and cluster worlds replace these keys through sim::entropy::key_pair; the recovery world and the long-run recorded upload keep host keys, and whether their results depend on them is unverified"
        )]
        let state = RandomState::new();
        Self::with_keys(Keys {
            k0: state.hash_one(0u8),
            k1: state.hash_one(1u8),
        })
    }

    fn with_keys(keys: Keys) -> Self {
        Self {
            initial: keys.initial_state(),
            lanes: Lanes::detect(),
            #[cfg(test)]
            seam: None,
        }
    }

    /// A hasher keyed by the pair `(k0, k1)` in place of a drawn one, so a
    /// test fixes every route the keyed rounds give.
    #[cfg(test)]
    pub(crate) fn with_key_pair(k0: u64, k1: u64) -> Self {
        Self::with_keys(Keys { k0, k1 })
    }

    /// A hasher whose pass is `seam` instead of the keyed rounds. The keys
    /// are still drawn from `RandomState` so the value has production's
    /// shape; no derivation reads them, so the draw leaves every route and
    /// fingerprint to `seam`.
    #[cfg(test)]
    pub(crate) fn with_seam(seam: Seam) -> Self {
        Self {
            seam: Some(seam),
            ..Self::seeded()
        }
    }

    /// This hasher with its multi-key passes run by `lanes`, so a test holds
    /// each mechanism the CPU runs to the scalar words.
    #[cfg(test)]
    pub(crate) fn with_lanes(self, lanes: Lanes) -> Self {
        Self { lanes, ..self }
    }

    /// The one pass: the 32 key bytes as the whole message.
    #[inline]
    fn pass(&self, key: &Key) -> u64 {
        #[cfg(test)]
        DERIVATIONS.with(|count| count.set(count.get() + 1));
        #[cfg(test)]
        if let Some(seam) = self.seam {
            return seam(key);
        }
        siphash13(self.initial, key)
    }

    /// Derives `key`'s shard, base bucket, fingerprint and tag against
    /// `index`, charging [`HASH_CHARGE`] first. Always inlined: see the
    /// module documentation.
    ///
    /// # Errors
    ///
    /// `BudgetExhausted` if the charge cannot be paid (the affordable steps
    /// are debited, nothing is hashed); `NoEnabledShard` if `index` has no
    /// enabled shard (nothing is debited).
    #[inline(always)]
    pub fn route(
        &self,
        key: &Key,
        index: &ValidatedIndex,
        budget: &mut WorkBudget,
    ) -> Result<KeyRoute, RouteError> {
        self.route_prefetching(key, index, budget, Prefetch::NONE)
    }

    /// [`route`](Self::route), with the key's base bucket prefetched once
    /// the pass finishes, as `prefetch` describes. The route is the same and
    /// so is the charge; the hint decides nothing. Always inlined so that
    /// `route` is.
    #[inline(always)]
    pub(crate) fn route_prefetching(
        &self,
        key: &Key,
        index: &ValidatedIndex,
        budget: &mut WorkBudget,
        prefetch: Prefetch<'_>,
    ) -> Result<KeyRoute, RouteError> {
        if index.enabled().is_empty() {
            return Err(RouteError::NoEnabledShard);
        }
        budget.debit_n(WorkKind::Hash, HASH_CHARGE)?;
        Ok(self.derive(key, index, prefetch))
    }

    /// [`route_prefetching`](Self::route_prefetching) of a key whose pass
    /// already ran against `index`, from the `fingerprint` that earlier
    /// route returned: the same route, charge and hint, without repeating
    /// the pass. `index`'s enabled shards are fixed when it is validated and
    /// the hasher's keys never change, so the earlier route stays the key's
    /// route for as long as both live.
    ///
    /// # Errors
    ///
    /// `NoEnabledShard` if `index` has no enabled shard (nothing is
    /// debited); `BudgetExhausted` if [`HASH_CHARGE`] cannot be paid (the
    /// affordable steps are debited).
    #[inline(always)]
    pub(crate) fn reroute_prefetching(
        &self,
        fingerprint: u64,
        index: &ValidatedIndex,
        budget: &mut WorkBudget,
        prefetch: Prefetch<'_>,
    ) -> Result<KeyRoute, RouteError> {
        if index.enabled().is_empty() {
            return Err(RouteError::NoEnabledShard);
        }
        budget.debit_n(WorkKind::Hash, HASH_CHARGE)?;
        Ok(cut(fingerprint, index, prefetch))
    }

    /// Issues the derivation's prefetch hint for `fingerprint`'s base bucket
    /// alone; the budget stays where it is and the caller keeps only its
    /// fingerprint. A caller that holds a fingerprint it will commit later
    /// hints the bucket here, so the lines are in flight across the work
    /// before the commit's own, charged derivation repeats the hint. The
    /// hint reads nothing through the mapping.
    #[inline(always)]
    pub(crate) fn hint_route(
        &self,
        fingerprint: u64,
        index: &ValidatedIndex,
        prefetch: Prefetch<'_>,
    ) {
        if !index.enabled().is_empty() {
            let _ = cut(fingerprint, index, prefetch);
        }
    }

    /// [`route_prefetching`](Self::route_prefetching) without the charge.
    /// The caller debits [`HASH_CHARGE`] when it uses the route, so the pass
    /// may run ahead of the budget decision without moving it. `None` when
    /// `index` has no enabled shard. Always inlined, with the derivation
    /// spelled as an explicit `if`/`else`, so the pass inlines into the
    /// caller and the route stays in registers.
    #[inline(always)]
    pub(crate) fn route_unpaid(
        &self,
        key: &Key,
        index: &ValidatedIndex,
        prefetch: Prefetch<'_>,
    ) -> Option<KeyRoute> {
        if index.enabled().is_empty() {
            None
        } else {
            Some(self.derive(key, index, prefetch))
        }
    }

    /// The passes of `keys`, at most [`LANES`] of them, into the leading
    /// words of `words`: `words[i]` is the fingerprint [`route_unpaid`] of
    /// `keys[i]` returns, and the words past `keys.len()` keep their values.
    /// A full group of [`LANES`] keys runs on the hasher's multi-key
    /// mechanism and a shorter one runs a scalar pass per key; nothing is
    /// charged, so the caller debits [`HASH_CHARGE`] for each route it
    /// uses, as for [`route_unpaid`].
    ///
    /// [`route_unpaid`]: Self::route_unpaid
    #[inline]
    pub(crate) fn fingerprints(&self, keys: &[Key], words: &mut [u64; LANES]) {
        debug_assert!(
            keys.len() <= LANES,
            "a multi-key pass takes at most {LANES} keys"
        );
        #[cfg(test)]
        DERIVATIONS.with(|count| count.set(count.get() + keys.len()));
        #[cfg(test)]
        if let Some(seam) = self.seam {
            for (word, key) in words.iter_mut().zip(keys) {
                *word = seam(key);
            }
            return;
        }
        self.lanes.siphash13(&self.initial, keys, words);
    }

    /// Keys the multi-key pass hashes together on this CPU: [`LANES`] when
    /// the pass uses AVX-512, otherwise one.
    pub(crate) fn lane_width(&self) -> usize {
        self.lanes.width()
    }

    /// Reproduces the route [`route_unpaid`](Self::route_unpaid) gives a key
    /// from the `fingerprint` its pass gave, from
    /// [`fingerprints`](Self::fingerprints) or an earlier route, with
    /// `Prefetch::NONE`; a caller that prefetches hints the route's lines
    /// itself. `None` when `index` has no enabled shard.
    #[inline(always)]
    pub(crate) fn reroute_unpaid(
        &self,
        fingerprint: u64,
        index: &ValidatedIndex,
    ) -> Option<KeyRoute> {
        (!index.enabled().is_empty()).then(|| cut(fingerprint, index, Prefetch::NONE))
    }

    /// The pass, then [`cut`].
    ///
    /// # Panics
    ///
    /// If `index` has no enabled shard: the route indexes them.
    #[inline(always)]
    fn derive(&self, key: &Key, index: &ValidatedIndex, prefetch: Prefetch<'_>) -> KeyRoute {
        cut(self.pass(key), index, prefetch)
    }
}

/// Routes a pass's `word` against `index`'s enabled shards: selects the
/// shard, issues the prefetch hint for its run, then selects the base
/// bucket, fingerprint and tag.
///
/// # Panics
///
/// If `index` has no enabled shard: the route indexes them.
#[inline(always)]
fn cut(word: u64, index: &ValidatedIndex, prefetch: Prefetch<'_>) -> KeyRoute {
    let enabled = index.enabled();
    let count = enabled.len();
    let position = reduce(word, count);
    // A run table lists the enabled shards in route order, so one
    // reduction selects both the shard and its run.
    if let Some(run) = prefetch.runs.get(position) {
        prefetch.hint(run, word);
    }
    // The reduction is below every `count >= 1`, so the lookup fails only
    // for an empty list. Its test is a compare beside the route's
    // dependency chain; a clamp of `position` would be a step on it.
    let Some(selected) = enabled.get(position) else {
        no_enabled_shard()
    };
    KeyRoute {
        shard: selected.shard,
        position,
        bucket: (word as usize) & selected.bucket_mask,
        fingerprint: word,
        // Geometry sizes `B` as a power of two, so the trailing ones of
        // `B - 1` equal log2(B), the hash bits the bucket index consumes.
        tag: (word >> selected.bucket_mask.trailing_ones()) as u16,
    }
}

/// The panic of a route cut against an index with no enabled shard, out of
/// line so that each cut carries one call for it.
#[cold]
#[inline(never)]
fn no_enabled_shard() -> ! {
    panic!("a route needs an enabled shard")
}

/// Reduces the low [`ROUTE_BITS`] of a fingerprint to `0..count` by the
/// high part of their product with `count`, which is bounded for every
/// `count >= 1` and costs one widening multiply. The bits are shifted to
/// the top of the word first, which drops the fingerprint's high bits and
/// leaves the result as the product's high word.
#[inline(always)]
pub(crate) fn reduce(fingerprint: u64, count: usize) -> usize {
    let scaled = fingerprint << (u64::BITS - ROUTE_BITS);
    ((u128::from(scaled) * count as u128) >> u64::BITS) as usize
}

/// SipHash-1-3 of the 32-byte message `key` from `initial`, with the
/// finalization of `std`'s `DefaultHasher`: the length byte in the top of an
/// otherwise empty tail block, then `0xff` into `v2` and three rounds. The
/// key's four words are the four whole blocks, so no byte is shifted or
/// masked on the way in.
#[inline(always)]
pub(super) fn siphash13(initial: State, key: &Key) -> u64 {
    let (words, []) = key.as_chunks::<8>() else {
        unreachable!("a 32-byte key is four whole words")
    };
    let mut v = initial;
    for word in words {
        compress(&mut v, u64::from_le_bytes(*word));
    }
    compress(&mut v, (MESSAGE_BYTES as u64) << 56);
    v[2] ^= 0xff;
    for _ in 0..3 {
        sip_round(&mut v);
    }
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

/// One message block into the state: SipHash-1-3's single compression
/// round.
#[inline(always)]
fn compress(v: &mut State, block: u64) {
    v[3] ^= block;
    sip_round(v);
    v[0] ^= block;
}

/// One SipRound.
#[inline(always)]
fn sip_round(v: &mut State) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13);
    v[1] ^= v[0];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(16);
    v[3] ^= v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(21);
    v[3] ^= v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(17);
    v[1] ^= v[2];
    v[2] = v[2].rotate_left(32);
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use crate::index::geometry::{IndexConfig, Ratio, ShardLimits};
    use crate::storage::StorageConfig;

    fn geometry(limits: &[usize]) -> ValidatedIndex {
        let storage = StorageConfig {
            page_size: 4096,
            engine_budget: usize::MAX,
            body_cap: 3000,
            metadata_cap: Some(64),
            lease_limit: 8,
            object_rights: 8,
            reader_limit: 2,
            volume: crate::storage::test_volume(2 * 4096, 1 << 20),
        }
        .validate()
        .unwrap();
        IndexConfig {
            shards: ShardLimits::Explicit(limits),
            load: Ratio {
                numerator: 1,
                denominator: 2,
            },
            overflow: Ratio {
                numerator: 1,
                denominator: 4,
            },
            depth: 1,
            batch_max: 4,
            fills: &[0; 8][..limits.len()],
        }
        .validate(&storage)
        .unwrap()
    }

    fn budget() -> WorkBudget {
        WorkBudget::new(8)
    }

    /// The route the module documentation describes, spelled out from the
    /// raw pass, so the test pins each field to its bits and to its width.
    fn expected_route(hasher: &KeyHasher, key: &Key, index: &ValidatedIndex) -> KeyRoute {
        let enabled = index.enabled();
        let word = hasher.pass(key);
        let low = word & ((1 << ROUTE_BITS) - 1);
        let position = ((u128::from(low) * enabled.len() as u128) >> ROUTE_BITS) as usize;
        let selected = enabled[position];
        KeyRoute {
            shard: selected.shard,
            position,
            bucket: word as usize & selected.bucket_mask,
            fingerprint: word,
            tag: (word >> (selected.bucket_mask + 1).trailing_zeros()) as u16,
        }
    }

    /// Every key byte changes the pass, so it changes the fingerprint; the
    /// route is the word's low 57 bits reduced and the bucket its low bits
    /// masked, so the high seven bits never enter the route and the bucket's
    /// bits reach it only through the reduction's carry; all-zero and
    /// shared-prefix keys route within bounds; a disabled shard is never
    /// selected; a cloned state routes identically.
    ///
    /// Probability bounds, for a reader tempted to tighten them, under the
    /// ideal of a uniform 64-bit output: each `assert_ne!` fails with chance
    /// `2^-64`, 32 of them together below `10^-17`; flipping the lowest bit
    /// moves the route across a boundary of the reduction over three shards
    /// with chance below `3 * 2^-57`; 512 distinct fingerprints collide with
    /// chance below `10^-14`; every enabled shard receives at least one of
    /// 544 routes with failure chance
    /// `3 * (2/3 + 2^-57)^544 < 10^-95`.
    #[test]
    fn every_byte_influences_the_outputs_within_bounds() {
        let hasher = KeyHasher::seeded();
        let limits = [64usize, 0, 32, 0, 16];
        let index = geometry(&limits);
        let zero: Key = [0; 32];
        let base = hasher.route(&zero, &index, &mut budget()).unwrap();
        assert_eq!(base, expected_route(&hasher, &zero, &index));
        let mut routes_seen = [false; 5];
        for byte in 0..32 {
            let mut key = zero;
            key[byte] = 1;
            let changed = hasher.route(&key, &index, &mut budget()).unwrap();
            assert_eq!(changed, expected_route(&hasher, &key, &index), "{byte}");
            assert_ne!(changed.fingerprint(), base.fingerprint(), "{byte}");
            routes_seen[changed.shard().0] = true;
            let shard = index.shard(changed.shard()).unwrap();
            assert!(shard.is_enabled());
            assert!(changed.bucket() < shard.base);
        }
        // The route reads no high bit and the bucket bits only through the
        // reduction's carry: a word that differs only in its high seven bits
        // keeps its route and bucket bits, one that differs only in its
        // lowest bit keeps its route and high bits, and one that differs only
        // in bit 56 keeps its bucket bits and high bits but not its route.
        // The bucket bits compared are the ones every enabled shard's mask
        // keeps. The shifts and masks below are spelled as literals, so a
        // change of the route width fails here.
        assert_eq!(ROUTE_BITS, 57);
        let word = hasher.pass(&zero);
        let cut = |word: u64| {
            let low = word & ((1 << 57) - 1);
            let selected = index.enabled()[((u128::from(low) * 3) >> 57) as usize];
            (selected.shard, word & 0xF, (word >> 57) as u8)
        };
        let (shard, low, high) = cut(word);
        assert_eq!(cut(word ^ (0x7F << 57)), (shard, low, high ^ 0x7F));
        assert_eq!(cut(word ^ 1), (shard, low ^ 1, high));
        let (moved, low_moved, high_moved) = cut(word ^ (1 << 56));
        assert_ne!(moved, shard);
        assert_eq!((low_moved, high_moved), (low, high));
        // Shared-prefix keys spread over the enabled shards and never land
        // on a disabled one.
        let mut fingerprints = std::collections::HashSet::new();
        for suffix in 0..512u32 {
            let mut key: Key = [0xAB; 32];
            key[28..].copy_from_slice(&suffix.to_le_bytes());
            let route = hasher.route(&key, &index, &mut budget()).unwrap();
            assert_eq!(route, expected_route(&hasher, &key, &index));
            let shard = index.shard(route.shard()).unwrap();
            assert!(shard.is_enabled(), "{route:?}");
            assert!(route.bucket() < shard.base);
            routes_seen[route.shard().0] = true;
            fingerprints.insert(route.fingerprint());
        }
        assert_eq!(routes_seen, [true, false, true, false, true]);
        assert_eq!(fingerprints.len(), 512);
        // A cloned state routes identically.
        let twin = hasher.clone();
        for suffix in 0..64u8 {
            let key: Key = [suffix; 32];
            assert_eq!(
                hasher.route(&key, &index, &mut budget()),
                twin.route(&key, &index, &mut budget())
            );
        }
    }

    /// A derivation with prefetch runs names the same route and charges the
    /// same as one without, with one run or several, so the hint decides
    /// nothing; a reroute from the route's fingerprint names the same route
    /// with the same charge and no pass; a zero budget refuses both charged
    /// forms.
    #[test]
    fn a_prefetching_derivation_routes_and_charges_the_same() {
        let hasher = KeyHasher::seeded();
        let limits = [64usize, 0, 32];
        let index = geometry(&limits);
        let chained = |offset: usize, bucket_mask: usize| BucketRun {
            offset,
            summaries: offset / 2,
            bucket_mask,
            buckets: bucket_mask + 1,
            base: bucket_mask + 1,
            depth: 1,
            control: 0,
        };
        let one = [chained(4096, 63)];
        let several = [chained(4096, 63), chained(16384, 15), chained(65536, 31)];
        let table = [0u8; 8];
        for byte in 0..64u8 {
            let key: Key = [byte; 32];
            let mut plain = budget();
            let expected = hasher.route(&key, &index, &mut plain).unwrap();
            for runs in [&one[..], &several[..]] {
                for for_write in [false, true] {
                    let prefetch = Prefetch {
                        base: table.as_ptr(),
                        runs,
                        for_write,
                    };
                    let mut charged = budget();
                    let route = hasher
                        .route_prefetching(&key, &index, &mut charged, prefetch)
                        .unwrap();
                    assert_eq!(route, expected);
                    assert_eq!(charged, plain);
                    // The reroute from the route's fingerprint names the same route and charges the same, without a pass.
                    let passes = DERIVATIONS.with(Cell::get);
                    let mut rerouted = budget();
                    let again = hasher
                        .reroute_prefetching(
                            expected.fingerprint(),
                            &index,
                            &mut rerouted,
                            prefetch,
                        )
                        .unwrap();
                    assert_eq!(again, expected);
                    assert_eq!(rerouted, plain);
                    assert_eq!(DERIVATIONS.with(Cell::get), passes);
                }
            }
        }
        let mut zero = WorkBudget::new(0);
        let prefetch = Prefetch {
            base: table.as_ptr(),
            runs: &one,
            for_write: true,
        };
        assert_eq!(
            hasher.route_prefetching(&[0; 32], &index, &mut zero, prefetch),
            Err(RouteError::BudgetExhausted)
        );
        assert_eq!(zero.remaining(), 0);
        assert_eq!(
            hasher.reroute_prefetching(0, &index, &mut zero, prefetch),
            Err(RouteError::BudgetExhausted)
        );
    }

    /// Builds blocks byte by byte so this oracle shares none of `siphash13`'s
    /// word packing, and takes any message length so the published vector
    /// pins it.
    fn reference_siphash13(k0: u64, k1: u64, message: &[u8]) -> u64 {
        let mut v = [
            k0 ^ 0x736f6d6570736575,
            k1 ^ 0x646f72616e646f6d,
            k0 ^ 0x6c7967656e657261,
            k1 ^ 0x7465646279746573,
        ];
        let round = |v: &mut [u64; 4]| {
            v[0] = v[0].wrapping_add(v[1]);
            v[1] = v[1].rotate_left(13) ^ v[0];
            v[0] = v[0].rotate_left(32);
            v[2] = v[2].wrapping_add(v[3]);
            v[3] = v[3].rotate_left(16) ^ v[2];
            v[0] = v[0].wrapping_add(v[3]);
            v[3] = v[3].rotate_left(21) ^ v[0];
            v[2] = v[2].wrapping_add(v[1]);
            v[1] = v[1].rotate_left(17) ^ v[2];
            v[2] = v[2].rotate_left(32);
        };
        let (blocks, remainder) = message.as_chunks::<8>();
        for block in blocks {
            let mut m = 0u64;
            for (i, &byte) in block.iter().enumerate() {
                m |= u64::from(byte) << (8 * i);
            }
            v[3] ^= m;
            round(&mut v);
            v[0] ^= m;
        }
        let mut tail = (message.len() as u64 & 0xff) << 56;
        for (i, &byte) in remainder.iter().enumerate() {
            tail |= u64::from(byte) << (8 * i);
        }
        v[3] ^= tail;
        round(&mut v);
        v[0] ^= tail;
        v[2] ^= 0xff;
        for _ in 0..3 {
            round(&mut v);
        }
        v[0] ^ v[1] ^ v[2] ^ v[3]
    }

    /// Pins the oracle to the SipHash-1-3 vector for the message
    /// `0, 1, ..., 32` under the key `0, 1, ..., 15`, then tests `pass`
    /// against the byte-at-a-time oracle over several key pairs and keys
    /// that exercise every byte position. Under the oracle a label, a length
    /// prefix or a terminator is another message with another value.
    #[test]
    fn a_pass_is_siphash13_over_exactly_the_key() {
        let reference_pair = (0x0706050403020100, 0x0f0e0d0c0b0a0908);
        let vector = u64::from_le_bytes([0xbf, 0xf9, 0x8f, 0x7a, 0xe5, 0xb9, 0x54, 0x4d]);
        let message: Vec<u8> = (0..=32u8).collect();
        assert_eq!(
            reference_siphash13(reference_pair.0, reference_pair.1, &message),
            vector
        );

        let mut keys = vec![[b'k'; 32], [0; 32], [0xff; 32]];
        for byte in 0..32 {
            let mut key = [0u8; 32];
            key[byte] = 0x80 | byte as u8;
            keys.push(key);
        }
        keys.push(std::array::from_fn(|i| i as u8 * 7 + 3));
        keys.push(std::array::from_fn(|i| i as u8));
        let pairs = [
            (0, 0),
            reference_pair,
            (u64::MAX, u64::MAX),
            (0x8000_0000_0000_0001, 0x0123_4567_89ab_cdef),
        ];
        for (k0, k1) in pairs {
            let hasher = KeyHasher::with_keys(Keys { k0, k1 });
            for key in &keys {
                let word = hasher.pass(key);
                assert_eq!(
                    word,
                    reference_siphash13(k0, k1, key),
                    "{k0:#x} {k1:#x} {key:?}"
                );
                for label in [0u8, 0x52, 0xff] {
                    let mut labelled = vec![label];
                    labelled.extend_from_slice(key);
                    assert_ne!(word, reference_siphash13(k0, k1, &labelled));
                }
                let mut prefixed = (key.len() as u64).to_le_bytes().to_vec();
                prefixed.extend_from_slice(key);
                assert_ne!(word, reference_siphash13(k0, k1, &prefixed));
                let mut terminated = key.to_vec();
                terminated.push(0xff);
                assert_ne!(word, reference_siphash13(k0, k1, &terminated));
            }
        }
    }

    thread_local! {
        /// Passes the counting seam has performed on this thread.
        static PASSES: Cell<usize> = const { Cell::new(0) };
    }

    fn counting(key: &Key) -> u64 {
        PASSES.with(|passes| passes.set(passes.get() + 1));
        u64::from_le_bytes(key[..8].try_into().unwrap())
    }

    /// Zero work hashes nothing, witnessed by a counting seam; otherwise the
    /// fixed charge is debited before the pass; an index with no enabled
    /// shard refuses without debiting or hashing.
    #[test]
    fn a_derivation_charges_the_fixed_hash_cost_before_the_pass_or_hashes_nothing() {
        let hasher = KeyHasher::with_seam(counting);
        let limits = [8usize];
        let index = geometry(&limits);
        let key: Key = [1; 32];
        PASSES.with(|passes| passes.set(0));
        let mut zero = WorkBudget::new(0);
        assert_eq!(
            hasher.route(&key, &index, &mut zero),
            Err(RouteError::BudgetExhausted)
        );
        assert_eq!((zero.counters().hashes, PASSES.get()), (0, 0));
        let mut exact = WorkBudget::new(HASH_CHARGE);
        assert!(hasher.route(&key, &index, &mut exact).is_ok());
        assert_eq!((exact.counters().hashes, exact.remaining()), (1, 0));
        assert_eq!(exact.counters().comparisons, 0);
        assert_eq!(PASSES.get(), 1);
        let none = [0usize, 0];
        let empty = geometry(&none);
        let mut untouched = budget();
        assert_eq!(
            hasher.route(&key, &empty, &mut untouched),
            Err(RouteError::NoEnabledShard)
        );
        assert_eq!(untouched, budget());
        assert_eq!(PASSES.get(), 1);
    }

    /// After the key pair is drawn, deriving allocates nothing; the draw's
    /// cost and the toolchain are printed to the test log as the audit's
    /// record. The keys and `Debug` output stay out of the value's shape:
    /// the initial state is four words and the formatter prints no key.
    #[test]
    fn derivation_allocates_nothing_after_the_state_is_built() {
        let limits = [16usize, 16];
        let index = geometry(&limits);
        let before_build = crate::instrument::allocations();
        let hasher = KeyHasher::seeded();
        let build_cost = crate::instrument::allocations() - before_build;
        // Printing the record allocates; the derivation window opens after.
        eprintln!(
            "{}: RandomState build allocations = {build_cost}",
            env!("KESTRIKE_RUSTC_VERSION"),
        );
        let before_routes = crate::instrument::allocations();
        let mut spent = WorkBudget::new(HASH_CHARGE * 256);
        for byte in 0..=255u8 {
            let key: Key = [byte; 32];
            let route = hasher.route(&key, &index, &mut spent).unwrap();
            assert!(route.bucket() < 16);
        }
        assert_eq!(
            crate::instrument::allocations(),
            before_routes,
            "{}: hashing allocated",
            env!("KESTRIKE_RUSTC_VERSION")
        );
        assert_eq!(HASH_STATE_BYTES, 32);
        assert_eq!(format!("{hasher:?}"), "KeyHasher { .. }");
    }

    /// A multi-key pass of any length up to [`LANES`] gives each key the
    /// fingerprint its own route has and charges nothing; under a seam each
    /// word is the seam's; both count one derivation per key.
    #[test]
    fn a_multi_key_pass_gives_each_key_its_route_fingerprint() {
        let hasher = KeyHasher::seeded();
        let limits = [16usize, 0, 16];
        let index = geometry(&limits);
        let keys: Vec<Key> = (0..LANES as u8)
            .map(|n| std::array::from_fn(|i| n ^ (i as u8).wrapping_mul(29)))
            .collect();
        for len in 0..=LANES {
            let mut words = [u64::MAX; LANES];
            let before = DERIVATIONS.with(Cell::get);
            hasher.fingerprints(&keys[..len], &mut words);
            assert_eq!(DERIVATIONS.with(Cell::get) - before, len);
            for (key, word) in keys[..len].iter().zip(words) {
                let route = hasher.route_unpaid(key, &index, Prefetch::NONE).unwrap();
                assert_eq!(word, route.fingerprint());
                assert_eq!(hasher.reroute_unpaid(word, &index), Some(route));
            }
        }
        let seamed = KeyHasher::with_seam(counting);
        let mut words = [0; LANES];
        PASSES.with(|passes| passes.set(0));
        seamed.fingerprints(&keys[..3], &mut words);
        assert_eq!(PASSES.get(), 3);
        for (key, word) in keys[..3].iter().zip(words) {
            assert_eq!(word, counting(key));
        }
        let none = [0usize, 0];
        assert_eq!(hasher.reroute_unpaid(1, &geometry(&none)), None);
    }

    /// The deterministic seam gives two distinct full keys equal fingerprints
    /// and routes, so probe and comparison paths can be driven into a chosen
    /// collision the keyed state cannot be steered into.
    #[test]
    fn the_seam_forces_a_full_fingerprint_collision() {
        fn collide(key: &Key) -> u64 {
            // Only the first byte matters, so keys differing elsewhere
            // collide.
            u64::from(key[0]) << 8
        }
        let hasher = KeyHasher::with_seam(collide);
        let limits = [8usize, 8];
        let index = geometry(&limits);
        let one: Key = {
            let mut k = [0; 32];
            k[0] = 5;
            k[31] = 1;
            k
        };
        let two: Key = {
            let mut k = [0; 32];
            k[0] = 5;
            k[31] = 2;
            k
        };
        assert_ne!(one, two);
        let a = hasher.route(&one, &index, &mut budget()).unwrap();
        let b = hasher.route(&two, &index, &mut budget()).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.fingerprint(), 5 << 8);
        // The real state does not collide on these keys.
        let real = KeyHasher::seeded();
        assert_ne!(
            real.route(&one, &index, &mut budget())
                .unwrap()
                .fingerprint(),
            real.route(&two, &index, &mut budget())
                .unwrap()
                .fingerprint()
        );
    }

    /// A seamed hasher's route reads no key: a hasher with the seam over a
    /// drawn `RandomState` pair routes every key as one with the same seam
    /// over a fixed pair does, so the collision seam's ambient draw is inert.
    #[test]
    fn a_seamed_hasher_routes_without_its_drawn_keys() {
        let index = geometry(&[16usize, 16]);
        let drawn = KeyHasher::with_seam(counting);
        let fixed = KeyHasher {
            seam: Some(counting),
            ..KeyHasher::with_key_pair(1, 2)
        };
        for n in 0..LANES as u8 {
            let key: Key = std::array::from_fn(|i| n.wrapping_mul(31) ^ i as u8);
            assert_eq!(
                drawn.route_unpaid(&key, &index, Prefetch::NONE),
                fixed.route_unpaid(&key, &index, Prefetch::NONE)
            );
        }
    }

    /// The reduction lands in range for every count and every extreme word,
    /// and reads only the low [`ROUTE_BITS`] bits.
    #[test]
    fn reduction_is_bounded_for_every_count() {
        for count in [1usize, 2, 3, 5, 7, 64, 1000, usize::MAX >> 1] {
            for hash in [0u64, 1, u64::MAX / 2, u64::MAX - 1, u64::MAX] {
                assert!(reduce(hash, count) < count, "{hash} {count}");
            }
        }
        assert_eq!(reduce(u64::MAX, 3), 2);
        assert_eq!(reduce((1 << ROUTE_BITS) - 1, 3), 2);
        assert_eq!(reduce(u64::MAX << ROUTE_BITS, 3), 0);
        assert_eq!(reduce(0, 3), 0);
    }
}
