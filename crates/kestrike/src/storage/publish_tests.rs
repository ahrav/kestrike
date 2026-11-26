//! Publication and snapshot against an independent oracle: generated
//! insert-only histories on tiny geometries, every refusal cut, the
//! deterministic fingerprint collision, the terminal sequence, index
//! placement and rollback, and the allocation audit, on the heap-backed
//! platform.
//!
//! The oracle is a locked map of keys with its own count of visible keys,
//! claims and overflow buckets, and its own expected identity per key; it
//! never reads a production counter to decide what to expect.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::Ordering;

use super::budget::WorkBudget;
use super::config::StorageConfig;
use super::finalize::{Finalization, Progress};
use super::gate::GateError;
use super::init::{Cleanup, InitError, InitPhase};
use super::layout::IO_UNIT;
use super::mapping::Region;
use super::os::OsCode;
use super::owner::Storage;
use super::placement::PlacementConfig;
use super::publish::{Pair, publish_restored};
use super::snapshot::SnapshotError;
use super::test_platform::{Fail, Op, TestPlatform};
use super::test_platform::{blocked, finalize};
use super::{AllocationId, Completed, PublishError, ShardReport};
use crate::index::{
    BucketView, CONTROL_MASK, HASH_CHARGE, Identity, IndexConfig, Key, KeyHasher, OverflowLink,
    Prefetch, Ratio, ShardIndex, ShardLimits, TERMINAL,
};

/// A control bit outside every lane, which no store ever sets.
const RESERVED_BIT: u64 = 1 << 60;
const _: () = assert!(RESERVED_BIT & CONTROL_MASK == 0);

pub(super) const PAGE: usize = 4096;
pub(super) const READERS: usize = 2;
pub(super) const TRIES: usize = 2;
pub(super) const RETRIES: usize = 3;
pub(super) const BATCH_MAX: usize = 4;

/// A retirement obligation stays on the thread that committed the clear.
/// `Retirement` is private to the storage module, so no doctest reaches it;
/// the `AmbiguousIf` lookup compiles only while exactly one implementation
/// applies, which holds only while the type lacks `Send`.
const _: () = {
    trait AmbiguousIfSend<A> {
        fn item() {}
    }
    impl<T: ?Sized> AmbiguousIfSend<()> for T {}
    impl<T: ?Sized + Send> AmbiguousIfSend<u8> for T {}
    let _ = <super::publish::Retirement<'static, TestPlatform> as AmbiguousIfSend<_>>::item;
};

/// A volume of one unit per slot plus the one-unit clean reserve, so every
/// slot the fixture's objects fill holds an extent.
pub(super) fn storage_config(slot_count: usize) -> StorageConfig {
    StorageConfig {
        page_size: PAGE,
        engine_budget: 1 << 24,
        body_cap: 200,
        metadata_cap: Some(16),
        lease_limit: 16,
        object_rights: 8,
        reader_limit: READERS,
        volume: crate::storage::test_volume((slot_count + 1) * IO_UNIT, slot_count),
    }
}

/// Zero fill records for every shard a fixture may configure.
pub(super) const NO_FILLS: [usize; 16] = [0; 16];

pub(super) fn index_config<'a>(
    limits: &'a [usize],
    overflow: (usize, usize),
    depth: usize,
) -> IndexConfig<'a> {
    IndexConfig {
        shards: ShardLimits::Explicit(limits),
        load: Ratio {
            numerator: 1,
            denominator: 2,
        },
        overflow: Ratio {
            numerator: overflow.0,
            denominator: overflow.1,
        },
        depth,
        batch_max: BATCH_MAX,
        fills: &NO_FILLS[..limits.len()],
    }
}

pub(super) fn storage_with(
    slot_count: usize,
    index: &IndexConfig<'_>,
    platform: TestPlatform,
) -> Storage<TestPlatform> {
    storage_from(&storage_config(slot_count), index, platform)
}

/// An indexed storage on `platform` from an explicit storage configuration.
pub(super) fn storage_from<P: super::os::Platform>(
    storage_config: &StorageConfig,
    index: &IndexConfig<'_>,
    platform: P,
) -> Storage<P> {
    let config = storage_config.validate().unwrap();
    let validated = index.validate(&config).unwrap();
    let placement = PlacementConfig { control_home: 0 };
    Storage::initialize_indexed(&config, validated, &placement, platform).unwrap()
}

pub(super) fn storage(slot_count: usize, index: &IndexConfig<'_>) -> Storage<TestPlatform> {
    storage_with(slot_count, index, TestPlatform::heap(PAGE))
}

/// Room for a Miri run, where a weak compare-exchange fails spuriously most
/// of the time.
pub(super) fn budget() -> WorkBudget {
    WorkBudget::new(1024)
}

pub(super) fn completed<'s>(
    storage: &'s Storage<TestPlatform>,
    key: Key,
) -> Completed<'s, TestPlatform> {
    let mut allocation = storage.reserve(Some(4), Some(20), &mut budget()).unwrap();
    allocation.mark_written();
    allocation
        .complete(key, u64::MAX, &mut budget())
        .ok()
        .unwrap()
}

pub(super) fn key(n: u8) -> Key {
    let mut key = [0u8; 32];
    key[0] = n;
    key[31] = n.wrapping_mul(7);
    key
}

pub(super) fn report(storage: &Storage<TestPlatform>, shard: usize) -> ShardReport {
    storage.shard_report(ShardIndex(shard)).unwrap()
}

/// Returns a refused owner's block at once, so the slot is free again.
pub(super) fn discard(storage: &Storage<TestPlatform>, owner: Completed<'_, TestPlatform>) {
    assert_eq!(
        storage.return_allocation(owner.release(), &mut budget()),
        Ok(super::ReturnOutcome::Returned)
    );
}

pub(super) fn refs(storage: &Storage<TestPlatform>, id: AllocationId) -> usize {
    let pool = storage.live_pool().unwrap();
    pool.refs(id.slot_index())
}

/// The allocation a copied candidate names, at its slot's full incarnation.
pub(super) fn resolved(storage: &Storage<TestPlatform>, candidate: &Identity) -> AllocationId {
    storage.pool().resolve(*candidate).unwrap().0
}

pub(super) fn candidates(storage: &Storage<TestPlatform>, key: &Key) -> Vec<AllocationId> {
    let mut reader = storage.register().unwrap();
    reader
        .enter()
        .unwrap()
        .snapshot(key, RETRIES, &mut budget())
        .unwrap()
        .unwrap()
        .iter()
        .map(|c| resolved(storage, c))
        .collect()
}

/// A seam that gives every key sharing its first byte's high nibble one
/// base bucket and one tag and routes every key to shard zero, so a chain can
/// be filled on purpose. Each key keeps its own fingerprint: bits 32 to 47
/// hold a position-weighted sum of its bytes, in which keys differing in one
/// byte differ, and which stays below the route's reduction for eight shards.
pub(super) fn one_chain(key: &Key) -> u64 {
    let spread = key.iter().zip(1u64..).fold(0u64, |sum, (&byte, position)| {
        sum.wrapping_add(u64::from(byte) * (2 * position - 1))
    });
    u64::from(key[0] >> 4) | (spread & 0xFFFF) << 32
}

/// [`one_chain`] with the fingerprint alone: every key sharing its first
/// byte's high nibble has one whole fingerprint, the collision a keyed
/// state cannot be steered into.
pub(super) fn one_fingerprint(key: &Key) -> u64 {
    u64::from(key[0] >> 4)
}

/// A seam that routes keys with a first byte below 128 to the first enabled
/// shard and the rest to the last, with one base bucket and one tag per
/// half; the first byte's low seven bits fill the fingerprint's high seven,
/// which the route never reads, so keys of distinct first bytes keep
/// distinct fingerprints.
pub(super) fn by_first_byte(key: &Key) -> u64 {
    let half = if key[0] < 128 { 0 } else { u64::MAX >> 7 };
    half | u64::from(key[0] & 0x7F) << 57
}

/// Replaces the storage's keyed state with `seam`.
pub(super) fn install_seam(storage: &mut Storage<TestPlatform>, seam: crate::index::Seam) {
    storage.install_hasher(KeyHasher::with_seam(seam));
}

/// The generated histories' seam, one word cut as production cuts it: the
/// route bits just below the high seven from the key's first byte, so shard
/// `key[0] % 8` of eight scales to the enabled count; the bucket, the low
/// byte, from its last; and the fingerprint bits between from the first,
/// all by arithmetic the oracle in the removal tests repeats, so nothing
/// about placement comes from the production hasher.
pub(super) fn spread(key: &Key) -> u64 {
    (u64::from(key[0] % 8) << 54) | (u64::from(key[0]) * 0x9E37_79B9) << 8 | u64::from(key[31])
}

/// The deterministic seam gives distinct keys one tag and one chain, each
/// with its own fingerprint: two are published, the snapshot returns both as candidates, the
/// chain examines at most `14 * (1 + D)` pairs, and the key already last in
/// the chain is refused as present.
#[test]
fn colliding_keys_share_a_chain_and_the_present_key_is_refused() {
    let slot_count = 36;
    // `N = 32` exceeds the chain's 28 pairs, so the chain bound binds first.
    let limits = [32usize];
    let config = index_config(&limits, (1, 1), 1);
    let mut storage = storage(slot_count, &config);
    install_seam(&mut storage, one_chain);
    let depth = 1;
    let geometry = storage.index.as_ref().unwrap().geometry.shards()[0];
    // Keys whose first byte is 0x10 share the seam's low word 1, so they
    // share one tag and one base bucket.
    let colliding = |n: u8| {
        let mut k = key(0x10);
        k[1] = n;
        k
    };
    let first = colliding(0);
    let second = colliding(1);
    let a = completed(&storage, first)
        .publish(TRIES, &mut budget())
        .unwrap();
    let b = completed(&storage, second)
        .publish(TRIES, &mut budget())
        .unwrap();
    let mut reader = storage.register().unwrap();
    let mut spent = WorkBudget::new(64);
    let mut pinned = reader.enter().unwrap();
    let candidates = pinned
        .snapshot(&first, RETRIES, &mut spent)
        .unwrap()
        .unwrap();
    let ids: Vec<AllocationId> = candidates.iter().map(|c| resolved(&storage, c)).collect();
    assert_eq!(ids, [a, b]);
    pinned.exit();
    // The whole chain bound is prepaid before the scan: `1 + D` visits and
    // `14 (1 + D)` comparisons plus the two validations, whatever the scan
    // then reads; the hash pass carries its one charge.
    assert_eq!(spent.counters().visits, 1 + depth);
    assert_eq!(spent.counters().comparisons, 14 * (1 + depth) + 2);
    assert_eq!(spent.counters().hashes, HASH_CHARGE);

    // Fill the chain to its depth bound: 14 pairs per bucket, D = 1 link.
    let mut published = vec![a, b];
    for n in 2..28u8 {
        published.push(
            completed(&storage, colliding(n))
                .publish(TRIES, &mut budget())
                .unwrap(),
        );
    }
    assert_eq!(report(&storage, 0).visible, 28);
    assert_eq!(report(&storage, 0).free_overflow, geometry.overflow - 1);
    let mut pinned = reader.enter().unwrap();
    let candidates = pinned
        .snapshot(&first, RETRIES, &mut WorkBudget::new(64))
        .unwrap()
        .unwrap();
    assert_eq!(candidates.len(), 14 * (1 + depth));
    let ids: Vec<AllocationId> = candidates.iter().map(|c| resolved(&storage, c)).collect();
    assert_eq!(ids, published);
    // The key last in the chain is present: refused with nothing changed.
    let before = report(&storage, 0);
    let (owner, error) = completed(&storage, colliding(27))
        .publish(TRIES, &mut budget())
        .err()
        .unwrap();
    assert_eq!(error, PublishError::Present);
    assert_eq!(report(&storage, 0), before);
    assert_eq!(refs(&storage, owner.id()), 0);
    discard(&storage, owner);
    // One more distinct colliding key finds the chain full at its bound
    // while `N` still has room: the refusal is the chain's, not the limit's.
    let (owner, error) = completed(&storage, colliding(28))
        .publish(TRIES, &mut budget())
        .err()
        .unwrap();
    assert_eq!(error, PublishError::IndexFull);
    assert_eq!(report(&storage, 0), before);
    assert!(before.visible < 32);
    assert!(
        before.free_overflow > 0,
        "the depth bound refused, not the stack"
    );
    discard(&storage, owner);
}

/// A seam that puts every key in base bucket zero of a two-bucket shard
/// with the key's second byte as its tag: the bucket is the word's low bit,
/// the tag the sixteen bits above it.
pub(super) fn tag_by_second_byte(key: &Key) -> u64 {
    u64::from(key[1]) << 1
}

/// An insert stores the exact union of the chain's summary bits inside its
/// bracket, a removal leaves the word as a superset, the next insert into
/// the chain drops the removed tag's bits again, and a lookup whose tag the
/// summary excludes proves absence from the summary word alone: it loads
/// the sequence, the summary and the sequence again, and no bucket word.
#[test]
fn the_chain_summary_is_exact_after_an_insert_and_a_superset_after_a_removal() {
    use crate::index::{SUMMARY_BITS, excludes, summary_bits};
    let limits = [8usize];
    let config = index_config(&limits, (1, 1), 1);
    let mut storage = storage(16, &config);
    install_seam(&mut storage, tag_by_second_byte);
    let geometry = storage.index.as_ref().unwrap().geometry.shards()[0];
    assert_eq!(geometry.base, 2, "the seam's bucket bit needs two buckets");
    let summary = |storage: &Storage<TestPlatform>| {
        let index = storage.index.as_ref().unwrap();
        let shard = index.image.shard(ShardIndex(0)).unwrap();
        // SAFETY: the index mapping is live and no publisher runs.
        let summaries = unsafe { shard.summaries(&index.mapping) };
        assert_eq!(summaries.len(), geometry.base);
        summaries[0].load(Ordering::SeqCst)
    };
    let tagged = |tag: u8| {
        let mut k = key(0x20);
        k[1] = tag;
        k
    };
    assert_eq!(summary(&storage), 0);
    // Three tags whose summary bits are pairwise disjoint: bits 3..9 of the
    // tag select the first bit, so tags 8, 16 and 24 select bits 1, 2 and 3
    // beside the shared bit 0 from the empty bits 9..15.
    let (first, second, third) = (tagged(8), tagged(16), tagged(24));
    assert_eq!(summary_bits(8), 0b0011);
    assert_eq!(summary_bits(16), 0b0101);
    assert_eq!(summary_bits(24), 0b1001);
    completed(&storage, first)
        .publish(TRIES, &mut budget())
        .unwrap();
    assert_eq!(summary(&storage), summary_bits(8));
    completed(&storage, second)
        .publish(TRIES, &mut budget())
        .unwrap();
    assert_eq!(summary(&storage), summary_bits(8) | summary_bits(16));
    // A removal leaves the summary a superset of the remaining tag.
    super::attempt_tests::invalidate(&storage, &first).unwrap();
    assert_eq!(summary(&storage), summary_bits(8) | summary_bits(16));
    assert_eq!(report(&storage, 0).visible, 1);
    // The next insert stores the exact union over the chain again, without
    // the removed tag's bit.
    completed(&storage, third)
        .publish(TRIES, &mut budget())
        .unwrap();
    assert_eq!(summary(&storage), summary_bits(16) | summary_bits(24));
    // A replacement of a present key changes no bit.
    completed(&storage, second)
        .replace(TRIES, &mut budget())
        .unwrap();
    assert_eq!(summary(&storage), summary_bits(16) | summary_bits(24));
    assert_eq!(report(&storage, 0).visible, 2);
    // The removed tag's lookup is excluded by the summary and reads no
    // bucket: beside the guard bundle's three deciding loads, one load each
    // for the opening sequence, the summary and the closing sequence, then
    // the absence bracket's cutoff and sequence.
    const GUARD_LOADS: usize = 3;
    const ABSENCE_LOADS: usize = 2;
    let excluded = first;
    assert!(excludes(summary(&storage), 8));
    let mut reader = storage.register().unwrap();
    super::probe::arm();
    let outcome = reader.lookup(&excluded, RETRIES, &mut budget());
    super::probe::disarm();
    let observed = super::probe::counts();
    assert_eq!(outcome.err(), Some(super::LookupError::Missing));
    assert_eq!(observed.loads, GUARD_LOADS + 3 + ABSENCE_LOADS);
    // A present key's lookup passes the summary, scans its bucket and goes
    // on to its candidate.
    storage.platform.ticks(&[Some(1)]);
    super::probe::arm();
    let lease = reader.lookup(&third, RETRIES, &mut budget()).unwrap();
    super::probe::disarm();
    let observed = super::probe::counts();
    assert!(observed.loads > GUARD_LOADS + 4);
    drop(lease);
    // An absent key whose summary bits the chain happens to hold, here a
    // tag differing from a present one in the lane's three bits alone,
    // scans the chain and is `Missing` through the scan's own bracket.
    let colliding = tagged(16 | 0b101);
    assert_eq!(summary_bits(16 | 0b101), summary_bits(16));
    assert!(!excludes(summary(&storage), 16 | 0b101));
    super::probe::arm();
    let outcome = reader.lookup(&colliding, RETRIES, &mut budget());
    super::probe::disarm();
    let observed = super::probe::counts();
    assert_eq!(outcome.err(), Some(super::LookupError::Missing));
    assert_eq!(observed.loads, GUARD_LOADS + 4 + ABSENCE_LOADS);
    assert_eq!(SUMMARY_BITS, 64);
}

/// Every refusal cut leaves the shard report, the sequence and the oracle
/// unchanged, refunds only the call's own claims with a distinct receipt,
/// and a popped-then-aborted bucket is back on the stack.
#[test]
fn every_refusal_leaves_the_shard_unchanged_and_refunds_only_its_own_claims() {
    let slot_count = 24;
    let limits = [16usize];
    let config = index_config(&limits, (1, 1), 1);
    let mut storage = storage(slot_count, &config);
    install_seam(&mut storage, one_chain);
    let allocations = crate::instrument::allocations();

    // Zero tries: no gate attempt, no hash charge beyond the pass.
    let owner = completed(&storage, key(0x21));
    let before = report(&storage, 0);
    let mut zero = WorkBudget::new(16);
    let (owner, error) = owner.publish(0, &mut zero).err().unwrap();
    assert_eq!(error, PublishError::Contended);
    assert_eq!(zero.counters().coordination_attempts, 0);
    assert_eq!(zero.counters().hashes, 1);
    assert_eq!(report(&storage, 0), before);
    assert_eq!(crate::instrument::allocations(), allocations, "zero tries");

    // Zero budget: no hash, no probe.
    let mut none = WorkBudget::new(0);
    let (owner, error) = owner.publish(TRIES, &mut none).err().unwrap();
    assert_eq!(error, PublishError::BudgetExhausted);
    assert_eq!(none.counters(), WorkBudget::new(0).counters());
    assert_eq!(report(&storage, 0), before);

    // Gate held elsewhere: every paid try fails, counted in the shard.
    let index = storage.index.as_ref().unwrap();
    let shard = index.image.shard(ShardIndex(0)).unwrap();
    // SAFETY: the index mapping is live.
    let gate = unsafe { shard.gate(&index.mapping) };
    let held = gate.try_lock().unwrap();
    let mut spent = budget();
    let (owner, error) = owner.publish(TRIES, &mut spent).err().unwrap();
    assert_eq!(error, PublishError::Contended);
    assert_eq!(spent.counters().coordination_attempts, TRIES);
    assert_eq!(
        report(&storage, 0).failed_tries,
        before.failed_tries + TRIES
    );
    drop(held);
    assert_eq!(crate::instrument::allocations(), allocations, "held gate");
    let before = report(&storage, 0);

    // Unaffordable walk: the pass and the try are paid, the visit is not;
    // the claim is refunded.
    let mut short = WorkBudget::new(2);
    let (owner, error) = owner.publish(TRIES, &mut short).err().unwrap();
    assert_eq!(error, PublishError::BudgetExhausted);
    assert_eq!(short.counters().coordination_attempts, 1);
    assert_eq!(short.counters().visits, 0);
    assert_eq!(report(&storage, 0), before);
    assert_eq!(crate::instrument::allocations(), allocations, "short walk");

    // Fill the base bucket so the next key pops an overflow bucket, then
    // make the anchor refuse: the popped bucket is back on the stack.
    let filled: [AllocationId; 14] = std::array::from_fn(|n| {
        completed(&storage, key(0x21 + n as u8))
            .publish(TRIES, &mut budget())
            .unwrap()
    });
    assert_eq!(filled.len(), 14);
    let (owner, error) = owner.publish(TRIES, &mut budget()).err().unwrap();
    assert_eq!(error, PublishError::Present);
    discard(&storage, owner);
    let before = report(&storage, 0);
    assert_eq!(before.free_overflow, 2);
    let owner = completed(&storage, key(0x2F));
    let id = owner.id();
    {
        let pool = storage.live_pool().unwrap();
        pool.set_refs(id.slot_index(), 5);
    }
    let (owner, error) = owner.publish(TRIES, &mut budget()).err().unwrap();
    assert_eq!(error, PublishError::AnchorPresent);
    assert_eq!(report(&storage, 0), before);
    {
        let pool = storage.live_pool().unwrap();
        pool.set_refs(id.slot_index(), 0);
        pool.edit_word(id.slot_index(), |word| word | 1 << 43);
    }
    // An idle count beside a reserved bit refuses the anchor too.
    let (owner, error) = owner.publish(TRIES, &mut budget()).err().unwrap();
    assert_eq!(error, PublishError::AnchorPresent);
    assert_eq!(report(&storage, 0), before);
    {
        let pool = storage.live_pool().unwrap();
        pool.edit_word(id.slot_index(), |word| word & !(1 << 43));
    }
    // With the anchor idle the same owner publishes into the popped bucket.
    let published = owner.publish(TRIES, &mut budget()).unwrap();
    assert_eq!(published, id);
    assert_eq!(report(&storage, 0).free_overflow, 1);
    assert_eq!(report(&storage, 0).visible, 15);
    completed(&storage, key(0x20))
        .publish(TRIES, &mut budget())
        .unwrap();
    assert_eq!(crate::instrument::allocations(), allocations, "popped");

    // The additional-key limit: `N = 16` reached, refused before any walk.
    let owner = completed(&storage, key(0x30));
    let before = report(&storage, 0);
    let mut spent = budget();
    let (owner, error) = owner.publish(TRIES, &mut spent).err().unwrap();
    assert_eq!(error, PublishError::IndexFull);
    assert_eq!(spent.counters().visits, 0);
    assert_eq!(report(&storage, 0), before);
    discard(&storage, owner);

    // Closed admission refuses before hashing.
    let owner = completed(&storage, key(0x31));
    storage.close();
    let mut spent = budget();
    let (owner, error) = owner.publish(TRIES, &mut spent).err().unwrap();
    assert_eq!(error, PublishError::Closed);
    assert_eq!(spent.counters().hashes, 0);
    discard(&storage, owner);
    assert_eq!(crate::instrument::allocations(), allocations);
}

/// A shard at its limit refuses `IndexFull` while another shard accepts; zero
/// retries make no snapshot attempt and a foreign registration is refused.
#[test]
fn a_full_shard_refuses_while_another_accepts() {
    let slot_count = 12;
    // Shard 0 holds one key, shard 1 three; no overflow at all. Keys below
    // 128 route to shard 0, the rest to shard 1.
    let limits = [1usize, 3];
    let config = index_config(&limits, (0, 1), 0);
    let mut storage = storage(slot_count, &config);
    install_seam(&mut storage, by_first_byte);
    let publish = |k: Key| {
        let owner = completed(&storage, k);
        match owner.publish(TRIES, &mut budget()) {
            Ok(_) => true,
            Err((owner, PublishError::IndexFull)) => {
                discard(&storage, owner);
                false
            }
            Err((_, error)) => panic!("{error:?}"),
        }
    };
    assert!(publish(key(1)));
    assert_eq!(report(&storage, 0).visible, 1);
    // Shard 0 is at its limit; shard 1 keeps admitting.
    assert!(!publish(key(2)));
    assert!(publish(key(200)));
    assert!(!publish(key(3)));
    assert!(publish(key(201)));
    assert!(publish(key(202)));
    assert_eq!(report(&storage, 1).visible, 3);
    assert!(!publish(key(203)));
    assert!(!publish(key(4)));
    assert_eq!(report(&storage, 0).visible, 1);
    assert_eq!(report(&storage, 1).visible, 3);
    assert_eq!(
        report(&storage, 0).reserved + report(&storage, 1).reserved,
        0
    );

    // Zero retries: nothing read, only the hash pass paid.
    let mut reader = storage.register().unwrap();
    let mut spent = budget();
    assert_eq!(
        reader.enter().unwrap().snapshot(&key(1), 0, &mut spent),
        Ok(None)
    );
    assert_eq!(spent.counters().visits, 0);
    assert_eq!(spent.counters().hashes, 1);
}

/// A tiny sequence maximum drives the terminal transition: the commit that
/// would land on the final value makes the shard terminal instead,
/// publication refuses `IndexFull`, snapshots return `Contended`, the lost
/// capacity is reported, nothing is reissued and the other shard serves; a
/// poisoned gate refuses every later publication with `Contended`.
#[test]
fn the_terminal_sequence_stops_one_shard_and_a_poisoned_gate_refuses() {
    let slot_count = 16;
    let limits = [4usize, 4];
    let config = index_config(&limits, (1, 1), 1);
    let mut storage = storage(slot_count, &config);
    install_seam(&mut storage, by_first_byte);
    let index = storage.index.as_ref().unwrap();
    let shard = index.image.shard(ShardIndex(0)).unwrap();
    // SAFETY: the index mapping is live.
    let control = unsafe { shard.control(&index.mapping) };
    // Two commits from here: the first lands on TERMINAL - 2, the second
    // would land on TERMINAL and transitions instead.
    control.sequence.store(TERMINAL - 4, Ordering::SeqCst);
    let mut reader = storage.register().unwrap();
    let first = completed(&storage, key(1))
        .publish(TRIES, &mut budget())
        .unwrap();
    assert_eq!(report(&storage, 0).sequence, TERMINAL - 2);
    assert_eq!(
        reader
            .enter()
            .unwrap()
            .snapshot(&key(1), RETRIES, &mut budget())
            .unwrap()
            .unwrap()
            .first()
            .map(|c| resolved(&storage, c)),
        Some(first)
    );
    let (owner, error) = completed(&storage, key(2))
        .publish(TRIES, &mut budget())
        .err()
        .unwrap();
    assert_eq!(error, PublishError::IndexFull);
    let after = report(&storage, 0);
    assert!(after.terminal, "{after:?}");
    assert_eq!(after.sequence, TERMINAL);
    assert_eq!(after.visible, 1);
    assert_eq!(after.lost_capacity, 4 - 1);
    assert_eq!(refs(&storage, owner.id()), 0);
    discard(&storage, owner);
    // The published key is no longer readable: the snapshot is contended,
    // consuming every retry and its prepaid bound with no bucket read; a key
    // never published is contended too, never absent.
    let mut spent = budget();
    assert_eq!(
        reader
            .enter()
            .unwrap()
            .snapshot(&key(1), RETRIES, &mut spent),
        Ok(None)
    );
    let depth = storage.index_geometry().unwrap().depth();
    assert_eq!(spent.counters().visits, RETRIES * (1 + depth));
    assert_eq!(
        spent.counters().comparisons,
        RETRIES * (14 * (1 + depth) + 2)
    );
    assert_eq!(
        reader
            .enter()
            .unwrap()
            .snapshot(&key(9), RETRIES, &mut budget()),
        Ok(None)
    );
    // Further publication on shard zero refuses without touching the word;
    // shard one still serves.
    let (owner, error) = completed(&storage, key(3))
        .publish(TRIES, &mut budget())
        .err()
        .unwrap();
    assert_eq!(error, PublishError::IndexFull);
    assert_eq!(report(&storage, 0).sequence, TERMINAL);
    discard(&storage, owner);
    let served = completed(&storage, key(200))
        .publish(TRIES, &mut budget())
        .unwrap();
    assert_eq!(
        reader
            .enter()
            .unwrap()
            .snapshot(&key(200), RETRIES, &mut budget())
            .unwrap()
            .unwrap()
            .first()
            .map(|c| resolved(&storage, c)),
        Some(served)
    );
    assert!(!report(&storage, 1).terminal);

    // A holder that unwinds under shard one's gate poisons it: later
    // publications refuse `Contended` and the sequence stays even.
    let shard_one = index.image.shard(ShardIndex(1)).unwrap();
    // SAFETY: as above.
    let gate = unsafe { shard_one.gate(&index.mapping) };
    let sequence_before = report(&storage, 1).sequence;
    std::thread::scope(|scope| {
        let handle = scope.spawn(|| {
            let _held = gate.try_lock().unwrap();
            panic!("poison the shard gate");
        });
        assert!(handle.join().is_err());
    });
    let (owner, error) = completed(&storage, key(201))
        .publish(TRIES, &mut budget())
        .err()
        .unwrap();
    assert_eq!(error, PublishError::Contended);
    discard(&storage, owner);
    assert_eq!(report(&storage, 1).sequence, sequence_before);
    assert_eq!(report(&storage, 1).failed_tries, 1);
    // The poisoned gate consumes one attempt, not the allowance.
    let mut spent = budget();
    let (owner, _) = completed(&storage, key(202))
        .publish(TRIES, &mut spent)
        .err()
        .unwrap();
    assert_eq!(spent.counters().coordination_attempts, 1);
    discard(&storage, owner);
}

/// The index mapping is placed after every pool mapping, its extent is the
/// inventory's shard bytes plus the scratch, `E_used` includes it with the
/// geometry tables and hash state by independent arithmetic, every
/// construction cut releases the acquired mappings exactly once, a refused
/// release stays retained, and teardown refuses while a registration exists.
#[test]
fn index_placement_is_charged_and_rolled_back_exactly() {
    let slot_count = 8;
    let limits = [5usize, 0, 3];
    let config = index_config(&limits, (1, 2), 1);
    // Without an index, for the baseline charge.
    let plain = {
        let validated = storage_config(slot_count).validate().unwrap();
        let placement = PlacementConfig { control_home: 0 };
        Storage::initialize(&validated, &placement, TestPlatform::heap(PAGE)).unwrap()
    };
    let baseline = plain.engine_used();
    assert_eq!(plain.index_extent(), None);
    assert_eq!(plain.shard_report(ShardIndex(0)), None);
    {
        let (owner, error) = completed(&plain, key(1))
            .publish(TRIES, &mut budget())
            .err()
            .unwrap();
        assert_eq!(error, PublishError::NoIndex);
        discard(&plain, owner);
        let mut reader = plain.register().unwrap();
        assert_eq!(
            reader
                .enter()
                .unwrap()
                .snapshot(&key(1), RETRIES, &mut budget()),
            Err(SnapshotError::NoIndex)
        );
    }
    drop(plain);

    let platform = TestPlatform::heap(PAGE);
    let log = platform.log();
    let mut storage = storage_with(slot_count, &config, platform);
    let validated = storage_config(slot_count).validate().unwrap();
    let inventory = config.validate(&validated).unwrap().inventory();
    // Independent extent: each enabled shard's page-rounded run of 14-pair
    // buckets at load 1/2 and overflow 1/2, then the `R * 14 * (1 + D)`
    // 8-byte scratch entries, rounded to pages.
    let shard_pages: usize = [5usize, 3]
        .iter()
        .map(|&n| {
            let base = (n * 2usize).div_ceil(14).max(1).next_power_of_two();
            let overflow = n.div_ceil(28);
            let bytes = (base + overflow) * 128 + overflow * 8;
            (bytes.div_ceil(128) * 128 + 384).div_ceil(PAGE) * PAGE
        })
        .sum();
    let scratch_bytes = READERS * 14 * 2 * 8;
    let expected_extent = (shard_pages + scratch_bytes).div_ceil(PAGE) * PAGE;
    assert_eq!(storage.index_extent(), Some(expected_extent));
    assert_eq!(inventory.shard_bytes, shard_pages);
    assert_eq!(inventory.mapping_bytes, expected_extent);
    // Two enabled shards each leave one run record in the image, and three
    // configured shards each leave one placement record for their arrays
    // and one for their fill table.
    let run_bytes = 2 * size_of::<crate::index::BucketRun>();
    assert_eq!(inventory.run_bytes, run_bytes);
    let image_bytes = 3
        * (size_of::<Option<super::shards::ShardImage>>()
            + size_of::<Option<super::image::FillImage>>());
    assert_eq!(inventory.image_bytes, image_bytes);
    assert_eq!(
        storage.engine_used(),
        baseline
            + expected_extent
            + inventory.geometry_bytes
            + inventory.hash_state_bytes
            + run_bytes
            + image_bytes
    );
    // The inventory's total is the charge, so a caller may budget from it.
    assert_eq!(storage.engine_used(), baseline + inventory.total);
    let mapped = log.ranges(Op::Map);
    assert_eq!(mapped.len(), 3);
    assert_eq!(mapped[2].1, expected_extent);
    assert_eq!(report(&storage, 0).free_overflow, 1);
    assert_eq!(storage.shard_report(ShardIndex(1)), None);
    assert_eq!(report(&storage, 2).free_overflow, 1);

    // Teardown refuses while a registration record is claimed (a leaked
    // handle; a live one is a compile error) and drains once it is
    // released, unmapping the index mapping first.
    let registration = storage.register().unwrap();
    let index_of = registration.index();
    std::mem::forget(registration);
    assert_eq!(blocked(&mut storage).registrations, 1);
    storage.registrations()[index_of.0]
        .claimed
        .store(false, Ordering::Release);
    assert_eq!(finalize(&mut storage), Ok(Finalization::Drained));
    let unmapped = log.ranges(Op::Unmap);
    assert_eq!(unmapped[0], mapped[2]);
    assert_eq!(unmapped.len(), 3);

    // Every cut at or after the index mapping rolls back every acquired
    // mapping exactly once, most recent first, with no reachable storage.
    let code = OsCode(12);
    let cuts = [
        (
            Fail {
                op: Op::Map,
                ordinal: 3,
                code,
                region: None,
            },
            InitError::Os {
                phase: InitPhase::Map,
                region: Region::Index,
                code,
            },
            2,
        ),
        (
            Fail {
                op: Op::Cut(InitPhase::ControlInit),
                ordinal: 0,
                code,
                region: Some(Region::Index),
            },
            InitError::Os {
                phase: InitPhase::ControlInit,
                region: Region::Index,
                code,
            },
            3,
        ),
        (
            Fail {
                op: Op::Cut(InitPhase::Transfer),
                ordinal: 0,
                code,
                region: Some(Region::Root),
            },
            InitError::Os {
                phase: InitPhase::Transfer,
                region: Region::Root,
                code,
            },
            3,
        ),
    ];
    for (fail, expected, mapped) in cuts {
        let platform = TestPlatform::heap(PAGE);
        let log = platform.log();
        platform.fail_at(fail);
        let validated = storage_config(slot_count).validate().unwrap();
        let index = config.validate(&validated).unwrap();
        let placement = PlacementConfig { control_home: 0 };
        let failure = Storage::initialize_indexed(&validated, index, &placement, platform)
            .err()
            .unwrap();
        assert_eq!(failure.error, expected, "{fail:?}");
        assert!(matches!(failure.cleanup, Cleanup::Complete));
        let ranges = log.ranges(Op::Map);
        assert_eq!(ranges.len(), mapped, "{fail:?}");
        let mut expected_unmaps = ranges;
        expected_unmaps.reverse();
        assert_eq!(log.ranges(Op::Unmap), expected_unmaps, "{fail:?}");
    }

    // A refused release of the index mapping stays retained and charged.
    let platform = TestPlatform::heap(PAGE);
    let log = platform.log();
    platform.fail_at(Fail {
        op: Op::Unmap,
        ordinal: 1,
        code,
        region: None,
    });
    let mut storage = storage_with(slot_count, &config, platform);
    let used = storage.engine_used();
    assert!(matches!(
        finalize(&mut storage),
        Ok(Finalization::Closing(Progress {
            retained: 1,
            remaining: 0,
            ..
        }))
    ));
    let retained: Vec<_> = storage.retained().collect();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].region, Region::Index);
    assert_eq!(storage.engine_used(), used);
    assert_eq!(log.ranges(Op::Unmap).len(), 3);
}

/// Malformed tables fail closed: a reserved control bit, an out-of-range
/// link and a link where the depth bound allows none each refuse `Corrupt`
/// from the scan and from publication, which poisons the
/// gate so the next attempt is `Contended`; a free-stack top past the stack,
/// which no reader touches, and a pair naming an unanchored slot, other
/// incarnation bits or a slot past the slot count refuse publication the
/// same way; an odd
/// sequence under an open gate is corruption to a publisher and busy to a
/// reader.
#[test]
fn malformed_tables_fail_closed_on_every_scan_and_every_publication() {
    let plant = |depth: usize, corrupt: &dyn Fn(&Storage<TestPlatform>)| {
        let slot_count = 8;
        let limits = [4usize];
        let config = index_config(&limits, (1, 1), depth);
        let mut storage = storage(slot_count, &config);
        install_seam(&mut storage, one_chain);
        let published = completed(&storage, key(1))
            .publish(TRIES, &mut budget())
            .unwrap();
        corrupt(&storage);
        let mut reader = storage.register().unwrap();
        let excluded = key(0x80);
        let route = storage.route(&excluded).unwrap();
        let index = storage.index.as_ref().unwrap();
        let shard = index.image.shard(route.shard()).unwrap();
        // SAFETY: the index mapping is live and no publisher runs.
        let summary =
            unsafe { shard.summaries(&index.mapping) }[route.bucket()].load(Ordering::SeqCst);
        assert!(crate::index::excludes(summary, route.tag()));
        assert_eq!(
            reader
                .enter()
                .unwrap()
                .snapshot(&excluded, RETRIES, &mut budget()),
            Ok(Some(&[][..]))
        );
        let mut spent = budget();
        assert_eq!(
            reader
                .enter()
                .unwrap()
                .snapshot(&key(2), RETRIES, &mut spent),
            Err(SnapshotError::Corrupt)
        );
        // The failed scan cost exactly its prepaid bound, nothing more.
        let depth = storage.index_geometry().unwrap().depth();
        assert_eq!(spent.counters().visits, 1 + depth);
        let (owner, error) = completed(&storage, key(2))
            .publish(TRIES, &mut budget())
            .err()
            .unwrap();
        assert_eq!(error, PublishError::Corrupt);
        assert_eq!(refs(&storage, owner.id()), 0);
        assert_eq!(refs(&storage, published), 1);
        discard(&storage, owner);
        let (owner, error) = completed(&storage, key(3))
            .publish(TRIES, &mut budget())
            .err()
            .unwrap();
        assert_eq!(error, PublishError::Contended);
        discard(&storage, owner);
        // The poisoned gate refuses every mutation; exact removal names the
        // poisoning, so a caller does not retry it as a busy gate.
        assert_eq!(
            storage.remove(&key(1), published, TRIES, &mut budget()),
            Err(super::remove::RemoveError::Poisoned)
        );
        assert_eq!(
            storage.invalidate(&key(1), TRIES, &mut budget()),
            Err(super::InvalidateError::Contended)
        );
        assert_eq!(report(&storage, 0).failed_tries, 3);
    };
    fn base_bucket(storage: &Storage<TestPlatform>) -> (&crate::index::Bucket, usize) {
        let index = storage.index.as_ref().unwrap();
        let shard = index.image.shard(ShardIndex(0)).unwrap();
        // SAFETY: the index mapping is live.
        let buckets = unsafe { shard.buckets(&index.mapping) };
        (&buckets[0], shard.geometry.overflow)
    }
    plant(1, &|storage| {
        base_bucket(storage).0.corrupt(1 | RESERVED_BIT, 0);
    });
    plant(1, &|storage| {
        let (bucket, overflow) = base_bucket(storage);
        bucket.corrupt(1, OverflowLink::encode(overflow).unwrap().raw());
    });
    plant(0, &|storage| {
        base_bucket(storage)
            .0
            .corrupt(1, OverflowLink::encode(0).unwrap().raw());
    });

    // A free-stack top past the stack: the walk passes, the pop refuses.
    let slot_count = 20;
    let limits = [16usize];
    let config = index_config(&limits, (1, 1), 1);
    let mut storage = storage(slot_count, &config);
    install_seam(&mut storage, one_chain);
    for n in 1..=14u8 {
        completed(&storage, key(n))
            .publish(TRIES, &mut budget())
            .unwrap();
    }
    let index = storage.index.as_ref().unwrap();
    let shard = index.image.shard(ShardIndex(0)).unwrap();
    // SAFETY: the index mapping is live.
    let control = unsafe { shard.control(&index.mapping) };
    control
        .free_top
        .store(shard.geometry.overflow + 1, Ordering::Relaxed);
    let (owner, error) = completed(&storage, key(15))
        .publish(TRIES, &mut budget())
        .err()
        .unwrap();
    assert_eq!(error, PublishError::Corrupt);
    assert_eq!(report(&storage, 0).reserved, 0);
    discard(&storage, owner);

    // A free-stack entry cannot name a bucket already linked into a chain;
    // the pop refuses before the stack top moves.
    let slot_count = 36;
    let limits = [32usize];
    let config = index_config(&limits, (1, 1), 2);
    let mut storage = self::storage(slot_count, &config);
    install_seam(&mut storage, one_chain);
    // Keys whose first byte is 0x11 share one fingerprint and one chain.
    let colliding = |n: u8| {
        let mut k = key(0x11);
        k[1] = n;
        k
    };
    let published: Vec<AllocationId> = (0..28u8)
        .map(|n| {
            completed(&storage, colliding(n))
                .publish(TRIES, &mut budget())
                .unwrap()
        })
        .collect();
    let index = storage.index.as_ref().unwrap();
    let shard = index.image.shard(ShardIndex(0)).unwrap();
    let before = report(&storage, 0);
    assert_eq!(before.visible, 28);
    assert_eq!(before.free_overflow, shard.geometry.overflow - 1);
    {
        // SAFETY: the index mapping is live and no gate is held, so this is
        // the only reference into the stack.
        let stack = unsafe { shard.hold(&index.mapping) }.stack;
        // The entry below the top is popped next.
        stack[before.free_overflow - 1] = 0;
    }
    let (owner, error) = completed(&storage, colliding(28))
        .publish(TRIES, &mut budget())
        .err()
        .unwrap();
    assert_eq!(error, PublishError::Corrupt);
    assert_eq!(report(&storage, 0), before);
    assert_eq!(refs(&storage, owner.id()), 0);
    discard(&storage, owner);
    let mut reader = storage.register().unwrap();
    let mut pinned = reader.enter().unwrap();
    let candidates = pinned
        .snapshot(&key(0x11), RETRIES, &mut WorkBudget::new(64))
        .unwrap()
        .unwrap();
    assert_eq!(
        candidates
            .iter()
            .map(|c| resolved(&storage, c))
            .collect::<Vec<_>>(),
        published
    );
    drop(pinned);
    let (owner, error) = completed(&storage, key(0x18))
        .publish(TRIES, &mut budget())
        .err()
        .unwrap();
    assert_eq!(error, PublishError::Contended);
    discard(&storage, owner);

    // The pop rejects a free bucket whose control word or link is nonzero.
    for (control_word, next) in [(1u64, 0usize), (0, OverflowLink::encode(1).unwrap().raw())] {
        let slot_count = 20;
        let limits = [16usize];
        let config = index_config(&limits, (1, 1), 1);
        let mut storage = self::storage(slot_count, &config);
        install_seam(&mut storage, one_chain);
        for n in 0x10..=0x1Du8 {
            completed(&storage, key(n))
                .publish(TRIES, &mut budget())
                .unwrap();
        }
        let index = storage.index.as_ref().unwrap();
        let shard = index.image.shard(ShardIndex(0)).unwrap();
        // SAFETY: the index mapping is live.
        let buckets = unsafe { shard.buckets(&index.mapping) };
        // The first pop takes overflow bucket zero.
        buckets[shard.geometry.base].corrupt(control_word, next);
        let before = report(&storage, 0);
        let (owner, error) = completed(&storage, key(0x1E))
            .publish(TRIES, &mut budget())
            .err()
            .unwrap();
        assert_eq!(error, PublishError::Corrupt, "{control_word:#b} {next}");
        assert_eq!(report(&storage, 0), before);
        assert_eq!(refs(&storage, owner.id()), 0);
        discard(&storage, owner);
    }

    // The walk refuses a pair that names an unanchored slot before reading its fingerprint.
    let slot_count = 8;
    let limits = [4usize];
    let config = index_config(&limits, (1, 1), 1);
    let mut storage = self::storage(slot_count, &config);
    install_seam(&mut storage, one_chain);
    let anchored = completed(&storage, key(0x11))
        .publish(TRIES, &mut budget())
        .unwrap();
    {
        let pool = storage.live_pool().unwrap();
        pool.set_refs(anchored.slot_index(), 0);
    }
    let before = report(&storage, 0);
    let (owner, error) = completed(&storage, key(0x12))
        .publish(TRIES, &mut budget())
        .err()
        .unwrap();
    assert_eq!(error, PublishError::Corrupt);
    assert_eq!(report(&storage, 0), before);
    assert_eq!(refs(&storage, owner.id()), 0);
    discard(&storage, owner);
    let (owner, error) = completed(&storage, key(0x13))
        .publish(TRIES, &mut budget())
        .err()
        .unwrap();
    assert_eq!(error, PublishError::Contended);
    discard(&storage, owner);

    // The walk refuses a tag-matching pair whose incarnation bits differ
    // from its slot's current incarnation: an occupied pair's anchor keeps
    // the slot at the incarnation it names.
    let mut storage = self::storage(slot_count, &config);
    install_seam(&mut storage, one_chain);
    let anchored = completed(&storage, key(0x11))
        .publish(TRIES, &mut budget())
        .unwrap();
    let route = storage.route(&key(0x12)).unwrap();
    {
        let index = storage.index.as_ref().unwrap();
        let shard = index.image.shard(ShardIndex(0)).unwrap();
        // SAFETY: the index mapping is live and no gate is held.
        let bucket = &unsafe { shard.buckets(&index.mapping) }[route.bucket()];
        let forged = AllocationId::new(anchored.slot(), anchored.incarnation() + 1);
        bucket.publish_pair(0, 0, route.tag(), forged);
    }
    let before = report(&storage, 0);
    let (owner, error) = completed(&storage, key(0x12))
        .publish(TRIES, &mut budget())
        .err()
        .unwrap();
    assert_eq!(error, PublishError::Corrupt);
    assert_eq!(report(&storage, 0), before);
    assert_eq!(refs(&storage, owner.id()), 0);
    discard(&storage, owner);

    // The walk refuses a tag-matching pair whose slot lies past the slot
    // count before loading anything of that slot.
    let mut storage = self::storage(slot_count, &config);
    install_seam(&mut storage, one_chain);
    let route = storage.route(&key(0x12)).unwrap();
    {
        let index = storage.index.as_ref().unwrap();
        let shard = index.image.shard(ShardIndex(0)).unwrap();
        // SAFETY: the index mapping is live and no gate is held.
        let bucket = &unsafe { shard.buckets(&index.mapping) }[route.bucket()];
        let outside = AllocationId::new(super::tables::SlotIndex(slot_count), 1);
        bucket.publish_pair(0, 0, route.tag(), outside);
    }
    let before = report(&storage, 0);
    let (owner, error) = completed(&storage, key(0x12))
        .publish(TRIES, &mut budget())
        .err()
        .unwrap();
    assert_eq!(error, PublishError::Corrupt);
    assert_eq!(report(&storage, 0), before);
    assert_eq!(refs(&storage, owner.id()), 0);
    discard(&storage, owner);

    // An odd sequence under an open gate.
    let mut storage = self::storage(slot_count, &config);
    install_seam(&mut storage, one_chain);
    let index = storage.index.as_ref().unwrap();
    let shard = index.image.shard(ShardIndex(0)).unwrap();
    // SAFETY: as above.
    let control = unsafe { shard.control(&index.mapping) };
    control.sequence.store(1, Ordering::SeqCst);
    let mut reader = storage.register().unwrap();
    let mut spent = budget();
    assert_eq!(
        reader
            .enter()
            .unwrap()
            .snapshot(&key(1), RETRIES, &mut spent),
        Ok(None)
    );
    // Every attempt prepays the bound and reads only the odd sequence.
    let depth = storage.index_geometry().unwrap().depth();
    assert_eq!(spent.counters().visits, RETRIES * (1 + depth));
    assert_eq!(
        spent.counters().comparisons,
        RETRIES * (14 * (1 + depth) + 2)
    );
    let (owner, error) = completed(&storage, key(1))
        .publish(TRIES, &mut budget())
        .err()
        .unwrap();
    assert_eq!(error, PublishError::Corrupt);
    discard(&storage, owner);
    let (owner, error) = completed(&storage, key(1))
        .publish(TRIES, &mut budget())
        .err()
        .unwrap();
    assert_eq!(error, PublishError::Contended);
    discard(&storage, owner);
    assert_eq!(report(&storage, 0).sequence, 1);
}

/// An exhausted free stack refuses `IndexFull` with the chain unfull at its
/// depth bound and `N` unreached, leaving the shard unchanged; a zero
/// budget refuses a snapshot before hashing.
#[test]
fn an_exhausted_stack_refuses_and_a_zero_budget_reads_nothing() {
    let slot_count = 36;
    // `A = 1`, `D = 2`: one overflow bucket, room for two links.
    let limits = [32usize];
    let config = index_config(&limits, (1, 4), 2);
    let mut storage = storage(slot_count, &config);
    install_seam(&mut storage, one_chain);
    assert_eq!(report(&storage, 0).free_overflow, 1);
    // Keys whose first byte is 0x11 share one fingerprint and one chain.
    let colliding = |n: u8| {
        let mut k = key(0x11);
        k[1] = n;
        k
    };
    for n in 0..28u8 {
        completed(&storage, colliding(n))
            .publish(TRIES, &mut budget())
            .unwrap();
    }
    let before = report(&storage, 0);
    assert_eq!(before.free_overflow, 0);
    assert_eq!(before.visible, 28);
    let (owner, error) = completed(&storage, colliding(28))
        .publish(TRIES, &mut budget())
        .err()
        .unwrap();
    assert_eq!(error, PublishError::IndexFull);
    assert_eq!(report(&storage, 0), before);
    discard(&storage, owner);

    let mut reader = storage.register().unwrap();
    let mut spent = WorkBudget::new(0);
    assert_eq!(
        reader
            .enter()
            .unwrap()
            .snapshot(&key(0x11), RETRIES, &mut spent),
        Err(SnapshotError::BudgetExhausted)
    );
    assert_eq!(spent.counters(), Default::default());
}

#[test]
fn the_place_walk_stops_at_the_chains_first_free_pair() {
    let limits = [32usize];
    let mut storage = storage(36, &index_config(&limits, (1, 1), 2));
    install_seam(&mut storage, one_chain);
    let colliding = |n: u8| {
        let mut k = key(0x11);
        k[1] = n;
        k
    };
    for n in 0..15u8 {
        completed(&storage, colliding(n))
            .publish(TRIES, &mut budget())
            .unwrap();
    }
    let walked = |storage: &Storage<TestPlatform>| {
        let index = storage.index.as_ref().unwrap();
        let shard = index.image.shard(ShardIndex(0)).unwrap();
        let route = index
            .hasher
            .route(&colliding(99), &index.geometry, &mut budget())
            .unwrap();
        // SAFETY: the index mapping is live and initialized, and this test
        // runs one thread with no other hold or gate holder alive, so this
        // hold stands in for the gate holder's and is the only reference
        // into the shard's tables.
        let (mut hold, control) =
            unsafe { (shard.hold(&index.mapping), shard.control(&index.mapping)) };
        let mut spent = budget();
        let end = super::publish::walk_to_free(shard, &hold, &route, &mut spent).unwrap();
        let (place, popped) = super::publish::place(shard, &mut hold, control, &end).unwrap();
        assert!(popped.is_none());
        let counters = spent.counters();
        assert_eq!(counters.comparisons, 0);
        (place.bucket == route.bucket(), place.pair, counters.visits)
    };
    let linked = report(&storage, 0).free_overflow;
    assert_eq!(walked(&storage), (false, 1, 2));
    let removed = storage
        .invalidate(&colliding(3), TRIES, &mut budget())
        .unwrap();
    assert!(removed.removed.is_some());
    assert_eq!(report(&storage, 0).free_overflow, linked);
    assert_eq!(walked(&storage), (true, 3, 1));
}

/// Real threads: two publishers insert disjoint keys while readers snapshot
/// every key repeatedly until the last publication. Each copy names only
/// published identities under one tag and the key's own at most once, a key
/// seen once stays seen (the reader's view is
/// monotone across its own attempts), `V + P_index <= N` holds in every
/// sample, some reader observes the publishers mid-way (each publisher
/// waits for that after its first publication), and every key is found once
/// the publishers finish.
#[test]
#[cfg_attr(
    miri,
    ignore = "real-thread stress; the loom kernel covers the protocol"
)]
fn concurrent_readers_see_stable_states_only() {
    use std::sync::Barrier;
    use std::sync::atomic::AtomicUsize;

    const KEYS: u8 = 48;
    let slot_count = 128;
    // Either shard can take every key, whatever the hash routes.
    let limits = [48usize, 48];
    let config = index_config(&limits, (2, 2), 2);
    let mut storage = storage(slot_count, &config);
    // A fixed key pair, under which no two of the keys share a bucket and a
    // tag, so the final lookups find each key's identity alone on every run.
    storage.install_hasher(KeyHasher::with_key_pair(0x5eed_0001, 0x5eed_0002));
    let storage = storage;
    // Every owner is completed before any thread starts, so the identities
    // are known; each publisher takes every other key.
    let owners: Vec<Completed<'_, TestPlatform>> =
        (1..=KEYS).map(|n| completed(&storage, key(n))).collect();
    let expected: BTreeMap<u8, AllocationId> =
        (1..=KEYS).zip(owners.iter().map(Completed::id)).collect();
    let (odd, even): (Vec<_>, Vec<_>) = owners
        .into_iter()
        .enumerate()
        .partition(|(index, _)| index % 2 == 0);
    let start = Barrier::new(READERS + 2);
    let published = AtomicUsize::new(0);
    let partial = AtomicUsize::new(0);
    let exited = AtomicUsize::new(0);
    /// Counts the reader's exit on drop, also while its failure unwinds.
    struct ReaderExit<'a>(&'a AtomicUsize);
    impl Drop for ReaderExit<'_> {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let publish = |owners: Vec<(usize, Completed<'_, TestPlatform>)>| {
        start.wait();
        for (_, mut owner) in owners {
            // Bounded tries per call; a contended gate yields the core
            // rather than spinning against its holder.
            loop {
                match owner.publish(TRIES, &mut WorkBudget::new(usize::MAX)) {
                    Ok(_) => break,
                    Err((back, PublishError::Contended)) => owner = back,
                    Err((_, error)) => panic!("{error:?}"),
                }
                std::thread::yield_now();
            }
            published.fetch_add(1, Ordering::Relaxed);
            // Each publisher holds after its first publication until a reader
            // has looked up a key with some but not every key published, so
            // the readers overlap the publishers on every run. Readers that
            // all exited release it too, so the scope joins and reports a
            // failed reader's panic.
            while partial.load(Ordering::Relaxed) == 0 && exited.load(Ordering::Relaxed) < READERS {
                std::thread::yield_now();
            }
        }
    };
    std::thread::scope(|scope| {
        for reader in 0..READERS {
            let (expected, storage, start, published, partial, exited) =
                (&expected, &storage, &start, &published, &partial, &exited);
            scope.spawn(move || {
                let _exit = ReaderExit(exited);
                let mut registration = storage.register().unwrap();
                let mut seen = BTreeSet::new();
                start.wait();
                let mut done = false;
                while !done {
                    done = published.load(Ordering::Relaxed) == usize::from(KEYS);
                    for n in 1..=KEYS {
                        for (shard, limit) in limits.iter().enumerate() {
                            let sample = report(storage, shard);
                            assert!(sample.visible + sample.reserved <= *limit);
                        }
                        let mut budget = WorkBudget::new(usize::MAX);
                        match registration
                            .enter()
                            .unwrap()
                            .snapshot(&key(n), RETRIES, &mut budget)
                        {
                            Ok(Some(copy)) => {
                                // Another key may share the bucket and the
                                // tag, so each candidate is some published
                                // identity under the key's route tag, and
                                // the key's own appears at most once.
                                let ids: Vec<AllocationId> =
                                    copy.iter().map(|found| resolved(storage, found)).collect();
                                assert!(
                                    ids.iter().all(|id| expected.values().any(|e| e == id)),
                                    "reader {reader}: {copy:?}"
                                );
                                let tag = storage.route(&key(n)).unwrap().tag();
                                assert!(
                                    copy.iter().all(|found| found.tag == tag),
                                    "reader {reader}: {copy:?}"
                                );
                                let own = ids.iter().filter(|id| **id == expected[&n]).count();
                                assert!(own <= 1, "reader {reader}: {copy:?}");
                                if own == 1 {
                                    seen.insert(n);
                                } else {
                                    assert!(!seen.contains(&n), "key {n} vanished");
                                }
                            }
                            Ok(None) => {
                                // Bounded retries per call; a busy shard
                                // yields the core, and the pass after the
                                // last publication sees every key.
                                done = false;
                                std::thread::yield_now();
                            }
                            Err(error) => panic!("{error:?}"),
                        }
                        let so_far = published.load(Ordering::Relaxed);
                        if 0 < so_far && so_far < usize::from(KEYS) {
                            partial.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                assert_eq!(seen.len(), usize::from(KEYS));
            });
        }
        scope.spawn(|| publish(odd));
        scope.spawn(|| publish(even));
    });
    assert!(
        partial.load(Ordering::Relaxed) > 0,
        "no reader overlapped the publishers"
    );
    let mut registration = storage.register().unwrap();
    for (n, id) in &expected {
        let mut pinned = registration.enter().unwrap();
        let copy = pinned
            .snapshot(&key(*n), RETRIES, &mut budget())
            .unwrap()
            .unwrap();
        assert_eq!(
            copy.iter()
                .map(|c| resolved(&storage, c))
                .collect::<Vec<_>>(),
            [*id]
        );
    }
    assert_eq!(
        report(&storage, 0).visible + report(&storage, 1).visible,
        usize::from(KEYS)
    );
}

/// Small enough for Miri: two readers snapshot on their own threads, each
/// through its own scratch run, while a third thread publishes three keys
/// and holds the free stack as `&mut` under the gate; the retagging and the
/// disjointness of those `&mut`s are what the run checks.
#[test]
fn two_readers_and_a_publisher_share_the_mapping_soundly() {
    let slot_count = 8;
    let limits = [4usize];
    let config = index_config(&limits, (1, 1), 1);
    let mut storage = storage(slot_count, &config);
    install_seam(&mut storage, one_chain);
    let owners: Vec<Completed<'_, TestPlatform>> = (0x11..=0x13u8)
        .map(|n| completed(&storage, key(n)))
        .collect();
    let expected: Vec<AllocationId> = owners.iter().map(Completed::id).collect();
    std::thread::scope(|scope| {
        for _ in 0..READERS {
            let storage = &storage;
            scope.spawn(move || {
                let mut registration = storage.register().unwrap();
                for _ in 0..4 {
                    for n in 0x11..=0x13u8 {
                        let mut pinned = registration.enter().unwrap();
                        let result = pinned.snapshot(&key(n), RETRIES, &mut budget());
                        assert!(result.is_ok(), "{result:?}");
                    }
                    std::thread::yield_now();
                }
            });
        }
        scope.spawn(|| {
            for mut owner in owners {
                loop {
                    match owner.publish(TRIES, &mut budget()) {
                        Ok(_) => break,
                        Err((back, PublishError::Contended)) => owner = back,
                        Err((_, error)) => panic!("{error:?}"),
                    }
                    std::thread::yield_now();
                }
            }
        });
    });
    let mut registration = storage.register().unwrap();
    let mut pinned = registration.enter().unwrap();
    let copy = pinned
        .snapshot(&key(0x11), RETRIES, &mut budget())
        .unwrap()
        .unwrap();
    assert_eq!(
        copy.iter()
            .map(|c| resolved(&storage, c))
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(report(&storage, 0).visible, 3);
}

/// Publication and snapshot allocate nothing after initialization, and the
/// oracle's blank scratch entry never names an issued identity.
#[test]
fn publish_and_snapshot_allocate_nothing() {
    let slot_count = 8;
    let limits = [4usize];
    let config = index_config(&limits, (1, 1), 1);
    let storage = storage(slot_count, &config);
    let mut reader = storage.register().unwrap();
    let owner = completed(&storage, key(1));
    let allocations = crate::instrument::allocations();
    let id = owner.publish(TRIES, &mut budget()).unwrap();
    let found = *reader
        .enter()
        .unwrap()
        .snapshot(&key(1), RETRIES, &mut budget())
        .unwrap()
        .unwrap()
        .first()
        .unwrap();
    assert_eq!(resolved(&storage, &found), id);
    let mut pinned = reader.enter().unwrap();
    let absent = pinned
        .snapshot(&key(2), RETRIES, &mut budget())
        .unwrap()
        .unwrap();
    assert!(absent.is_empty());
    assert_eq!(crate::instrument::allocations(), allocations);
    let blank = Identity::unpack(0);
    assert_ne!(found, blank);
    assert!(!storage.identity_is_current(AllocationId::new(super::tables::SlotIndex(0), 0)));
}

/// A derivation's base-bucket hint is addresses only: on a storage whose
/// shard list has a disabled shard, every key routes as it does with no
/// hint, for reading and for writing, the routes allocate nothing, and every
/// bucket's control and link words read as they did before.
#[test]
fn the_start_hint_routes_the_same_and_changes_no_bucket() {
    let slot_count = 16;
    let limits = [0usize, 16];
    let storage = storage(slot_count, &index_config(&limits, (1, 1), 1));
    completed(&storage, key(0x21))
        .publish(TRIES, &mut budget())
        .unwrap();
    let words = || -> Vec<(u64, usize)> {
        let index = storage.index.as_ref().unwrap();
        let shard = index.image.shard(ShardIndex(1)).unwrap();
        // SAFETY: the index mapping is live and no publisher runs.
        unsafe { shard.buckets(&index.mapping) }
            .iter()
            .map(|bucket| (bucket.control(), bucket.next()))
            .collect()
    };
    let before = words();
    assert_eq!(
        before.iter().filter(|(control, _)| *control != 0).count(),
        1
    );
    let index = storage.index().unwrap();
    let allocations = crate::instrument::allocations();
    for byte in 0..64u8 {
        let key: Key = [byte; 32];
        let plain = index
            .hasher
            .route_unpaid(&key, &index.geometry, Prefetch::NONE);
        assert_eq!(plain.map(|route| route.shard()), Some(ShardIndex(1)));
        for for_write in [false, true] {
            let hinted =
                index
                    .hasher
                    .route_unpaid(&key, &index.geometry, index.prefetch(for_write));
            assert_eq!(hinted, plain);
        }
    }
    assert_eq!(crate::instrument::allocations(), allocations);
    assert_eq!(words(), before);
}

/// The steps three bindings cost: one hash and one visit each, and one
/// comparison.
const WHOLE: usize = 7;

/// Three restored bindings for the keys 1 to 3: each routes by its key's
/// word under the [`spread`] seam and names its own identity.
fn bindings() -> [Pair; 3] {
    std::array::from_fn(|n| Pair {
        fingerprint: spread(&key(n as u8 + 1)),
        tag: (n as u64) << 32 | 1,
    })
}

/// A storage with one shard that admits `limit` keys, under the [`spread`]
/// seam.
fn one_shard(limit: usize) -> Storage<TestPlatform> {
    let limits = [limit];
    let config = index_config(&limits, (1, 1), 1);
    let mut storage = storage(8, &config);
    install_seam(&mut storage, spread);
    storage
}

/// What one try at the shard's gate answers; a try that takes the gate
/// releases it.
fn gate_try(storage: &Storage<TestPlatform>) -> Result<(), GateError> {
    super::attempt_tests::gate(storage).try_lock().map(drop)
}

/// The slot and the low incarnation bits of the one binding a reader's
/// snapshot finds for key `n + 1`; `None` when it finds none.
fn binding_of(storage: &Storage<TestPlatform>, n: usize) -> Option<(u32, u16)> {
    let mut reader = storage.register().unwrap();
    let mut protected = reader.enter().unwrap();
    let found = protected
        .snapshot(&key(n as u8 + 1), RETRIES, &mut budget())
        .unwrap()
        .unwrap();
    assert!(found.len() <= 1, "one binding per key");
    found
        .first()
        .map(|identity| (identity.slot, identity.incarnation_low))
}

/// For each of the three keys, the binding a reader's snapshot finds.
fn published(storage: &Storage<TestPlatform>) -> [Option<(u32, u16)>; 3] {
    std::array::from_fn(|n| binding_of(storage, n))
}

/// What [`published`] reads when the first `count` bindings are published:
/// for each of them the slot and the low incarnation bits its tag names.
fn leading(count: usize) -> [Option<(u32, u16)>; 3] {
    let bindings = bindings();
    std::array::from_fn(|n| {
        (n < count).then(|| ((bindings[n].tag >> 32) as u32, bindings[n].tag as u16))
    })
}

/// A restored publication whose allowance ends at the route or inside the
/// preparation of one of its three bindings, which share one hold of the
/// shard gate, refuses `BudgetExhausted` with the count of leading bindings
/// it published, which stay published, and leaves the shard gate free and
/// unpoisoned, so the caller's next call publishes the rest.
#[test]
fn a_spent_allowance_refuses_with_the_published_count_and_leaves_the_gate_open() {
    let mut counts = Vec::new();
    for steps in 0..WHOLE {
        let storage = one_shard(8);
        let mut allowance = WorkBudget::new(steps);
        let (count, error) = publish_restored(&storage, &bindings(), &mut allowance).unwrap_err();
        assert_eq!(error, PublishError::BudgetExhausted, "{steps} steps");
        assert_eq!(
            gate_try(&storage),
            Ok(()),
            "the refusal at {steps} steps kept or poisoned the shard gate"
        );
        assert_eq!(report(&storage, 0).visible, count, "{steps} steps");
        assert_eq!(published(&storage), leading(count), "{steps} steps");
        assert_eq!(
            publish_restored(&storage, &bindings()[count..], &mut budget()),
            Ok(()),
            "the next call publishes the bindings the refusal at {steps} steps left"
        );
        assert_eq!(report(&storage, 0).visible, 3);
        assert_eq!(published(&storage), leading(3));
        counts.push(count);
    }
    assert_eq!(
        counts,
        [0, 0, 1, 1, 2, 2, 2],
        "the allowances end before and inside the hold of each binding"
    );
    let storage = one_shard(8);
    let mut allowance = WorkBudget::new(WHOLE);
    assert_eq!(
        publish_restored(&storage, &bindings(), &mut allowance),
        Ok(())
    );
    assert_eq!(published(&storage), leading(3));
}

/// A shard full at its key limit refuses `IndexFull` with the count of the
/// bindings that fit, which stay published, and releases the gate
/// unpoisoned: the next call meets the full table again with the gate free.
#[test]
fn a_full_table_refuses_with_the_published_count_and_leaves_the_gate_open() {
    let storage = one_shard(2);
    assert_eq!(
        publish_restored(&storage, &bindings(), &mut budget()),
        Err((2, PublishError::IndexFull))
    );
    assert_eq!(
        gate_try(&storage),
        Ok(()),
        "a full table kept or poisoned the shard gate"
    );
    assert_eq!(report(&storage, 0).visible, 2);
    assert_eq!(published(&storage), leading(2));
    assert_eq!(
        publish_restored(&storage, &bindings()[2..], &mut budget()),
        Err((0, PublishError::IndexFull)),
        "the next call meets the full table, not a poisoned gate"
    );
    assert_eq!(gate_try(&storage), Ok(()));
    assert_eq!(published(&storage), leading(2));
}

/// A shard gate another holder has refuses `Contended` with nothing
/// published and the holder's hold intact; once the holder releases it, the
/// caller's next call publishes every binding.
#[test]
fn a_gate_another_holder_has_refuses_contended_and_is_left_to_the_next_call() {
    let storage = one_shard(8);
    let held = super::attempt_tests::gate(&storage).try_lock().unwrap();
    assert_eq!(
        publish_restored(&storage, &bindings(), &mut budget()),
        Err((0, PublishError::Contended))
    );
    assert_eq!(
        gate_try(&storage),
        Err(GateError::Contended),
        "the holder keeps its hold"
    );
    drop(held);
    assert_eq!(published(&storage), leading(0));
    assert_eq!(
        publish_restored(&storage, &bindings(), &mut budget()),
        Ok(())
    );
    assert_eq!(published(&storage), leading(3));
}

/// A bucket whose control word carries a reserved bit is a malformed table:
/// the publication refuses `Corrupt` with the count of the bindings before
/// it, which stay published, and poisons the gate, so the next call refuses
/// `Corrupt` as well.
#[test]
fn a_malformed_table_refuses_corrupt_and_poisons_the_gate() {
    let storage = one_shard(8);
    let second = storage.route(&key(2)).unwrap();
    assert_ne!(
        storage.route(&key(1)).unwrap().bucket(),
        second.bucket(),
        "the first binding's bucket stays well formed"
    );
    {
        let index = storage.index.as_ref().unwrap();
        let shard = index.image.shard(ShardIndex(0)).unwrap();
        // SAFETY: the index mapping is live and no publisher runs.
        let buckets = unsafe { shard.buckets(&index.mapping) };
        let bucket = &buckets[second.bucket()];
        bucket.corrupt(bucket.control() | RESERVED_BIT, bucket.next());
    }
    assert_eq!(
        publish_restored(&storage, &bindings(), &mut budget()),
        Err((1, PublishError::Corrupt))
    );
    assert_eq!(gate_try(&storage), Err(GateError::Poisoned));
    assert_eq!(
        report(&storage, 0).visible,
        1,
        "the first binding stays published"
    );
    assert_eq!(binding_of(&storage, 0), leading(1)[0]);
    assert_eq!(
        publish_restored(&storage, &bindings()[1..], &mut budget()),
        Err((0, PublishError::Corrupt)),
        "a poisoned gate ends every later call"
    );
    assert_eq!(report(&storage, 0).visible, 1);
    assert_eq!(binding_of(&storage, 0), leading(1)[0]);
}
