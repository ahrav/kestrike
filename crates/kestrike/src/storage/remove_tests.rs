//! Tests for exact removal, replacement and invalidation: the mixed-history
//! oracle, bucket recycling, slot-neutral replacement, the retirement
//! obligation each ended mapping produces, the revocation ordering point,
//! terminal and closed shards, and zero allocation.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;

use super::allocation::RetireOutcome;
use super::budget::WorkBudget;
use super::gate::{Gate, GateError};
use super::owner::Storage;
use super::publish_tests::{
    PAGE, RETRIES, TRIES, budget, by_first_byte, candidates, completed, discard, index_config,
    install_seam, key, one_chain, refs, report, resolved, spread, storage, storage_config,
};
use super::register::PinError;
use super::remove::RemoveError;
use super::snapshot::SnapshotError;
use super::tables::{SlotIndex, SlotState};
use super::test_platform::TestPlatform;
use super::word::ANCHORED;
use super::{AllocationId, Completed, InvalidateError, PlacementConfig, PublishError, ShardReport};
use crate::index::BucketView;
use crate::index::OverflowLink;
use crate::index::{
    CONTROL_MASK, HASH_CHARGE, Key, PAIRS, ShardIndex, TERMINAL, ValidatedIndex, occupied_pairs,
};

/// A control bit outside every lane, which no store ever sets.
const RESERVED_BIT: u64 = 1 << 60;
const _: () = assert!(RESERVED_BIT & CONTROL_MASK == 0);

fn era(storage: &Storage<TestPlatform>) -> u64 {
    storage.era_report().unwrap().era
}

fn slot_flag(storage: &Storage<TestPlatform>, id: AllocationId) -> u64 {
    storage.live_pool().unwrap().flags(id.slot_index())
}

fn retire_era(storage: &Storage<TestPlatform>, id: AllocationId) -> u64 {
    storage.live_pool().unwrap().retire_era(id.slot_index())
}

/// The retirement record an ended mapping must have left: the slot retired
/// in the ledger, its era stamp equal to the era before the bump, the anchor
/// marked as awaiting grace and still held.
fn assert_retired(storage: &Storage<TestPlatform>, id: AllocationId, stamp: u64) {
    assert_eq!(refs(storage, id), 1, "{id:?}");
    assert_ne!(slot_flag(storage, id) & ANCHORED, 0, "{id:?}");
    assert_eq!(retire_era(storage, id), stamp, "{id:?}");
    assert_eq!(
        storage.slot_state(SlotIndex(id.slot_index())).map(|s| s.0),
        Some(SlotState::Retired)
    );
}

/// One shard's model: keys with their identity and bucket, pair counts per
/// bucket, the overflow buckets linked behind each base bucket in link order,
/// the free stack in pop order (last is next), and the retirement stamps of
/// every ended identity.
struct ShardModel {
    keys: BTreeMap<Key, (AllocationId, usize)>,
    occupied: Vec<usize>,
    chains: Vec<Vec<usize>>,
    stack: Vec<usize>,
}

/// What the oracle predicts an operation does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Predicted {
    /// A vacant key is admitted into `bucket`, popping `pops` first.
    Insert {
        bucket: usize,
        pops: Option<usize>,
    },
    /// The key's mapping ends; `recycles` names the overflow bucket that
    /// empties and returns to the stack.
    Remove {
        recycles: Option<usize>,
    },
    /// The incumbent's pair is taken in place.
    Swap {
        incumbent: AllocationId,
    },
    Absent,
    Full,
}

/// The base bucket a seam routes `key` to under `mask`.
type BucketOf = fn(&Key, usize) -> usize;

struct Oracle {
    index: ValidatedIndex,
    shards: Vec<ShardModel>,
    bucket_of: BucketOf,
    /// Ended identities with the era each was stamped.
    retired: Vec<(AllocationId, u64)>,
    /// The era before any retirement: every retirement bumps it once.
    first_era: u64,
    used: usize,
}

impl Oracle {
    fn new(storage: &Storage<TestPlatform>, index: ValidatedIndex, bucket_of: BucketOf) -> Self {
        let shards = index
            .shards()
            .iter()
            .map(|g| ShardModel {
                keys: BTreeMap::new(),
                occupied: vec![0; g.base + g.overflow],
                chains: vec![Vec::new(); g.base],
                stack: (0..g.overflow).rev().collect(),
            })
            .collect();
        Self {
            index,
            shards,
            bucket_of,
            retired: Vec::new(),
            first_era: era(storage),
            used: storage.engine_used(),
        }
    }

    /// The seam's arithmetic, repeated: `spread`'s shard, and the bucket
    /// function of the seam in use.
    fn route(&self, key: &Key) -> (usize, usize) {
        let enabled = self.index.enabled();
        let shard = enabled[usize::from(key[0] % 8) * enabled.len() / 8];
        (shard.shard.0, (self.bucket_of)(key, shard.bucket_mask))
    }

    fn predict_insert(&self, key: &Key) -> Predicted {
        let (shard, base) = self.route(key);
        let geometry = &self.index.shards()[shard];
        let model = &self.shards[shard];
        if model.keys.len() >= geometry.visible {
            return Predicted::Full;
        }
        let chain: Vec<usize> = std::iter::once(base)
            .chain(model.chains[base].iter().map(|o| geometry.base + o))
            .collect();
        match chain.iter().find(|b| model.occupied[**b] < PAIRS) {
            Some(bucket) => Predicted::Insert {
                bucket: *bucket,
                pops: None,
            },
            None => match model.stack.last() {
                Some(next) if chain.len() - 1 < self.index.depth() => Predicted::Insert {
                    bucket: geometry.base + next,
                    pops: Some(*next),
                },
                _ => Predicted::Full,
            },
        }
    }

    fn predict_remove(&self, key: &Key) -> Predicted {
        let (shard, base) = self.route(key);
        let geometry = &self.index.shards()[shard];
        let model = &self.shards[shard];
        assert!(base < geometry.base);
        match model.keys.get(key) {
            None => Predicted::Absent,
            Some((_, bucket)) => Predicted::Remove {
                recycles: (*bucket >= geometry.base && model.occupied[*bucket] == 1)
                    .then(|| bucket - geometry.base),
            },
        }
    }

    fn apply_insert(&mut self, key: Key, id: AllocationId, bucket: usize, pops: Option<usize>) {
        let (shard, base) = self.route(&key);
        let model = &mut self.shards[shard];
        if let Some(overflow) = pops {
            assert_eq!(model.stack.pop(), Some(overflow));
            model.chains[base].push(overflow);
        }
        model.occupied[bucket] += 1;
        assert!(model.keys.insert(key, (id, bucket)).is_none());
    }

    fn apply_remove(&mut self, key: &Key, stamp: u64) -> AllocationId {
        let (shard, base) = self.route(key);
        let geometry_base = self.index.shards()[shard].base;
        let model = &mut self.shards[shard];
        let (id, bucket) = model.keys.remove(key).unwrap();
        model.occupied[bucket] -= 1;
        if bucket >= geometry_base && model.occupied[bucket] == 0 {
            let overflow = bucket - geometry_base;
            model.chains[base].retain(|o| *o != overflow);
            model.stack.push(overflow);
        }
        assert!(!self.retired.iter().any(|(r, _)| *r == id));
        self.retired.push((id, stamp));
        id
    }

    fn apply_swap(&mut self, key: &Key, id: AllocationId, stamp: u64) {
        let (shard, _) = self.route(key);
        let entry = self.shards[shard].keys.get_mut(key).unwrap();
        let incumbent = std::mem::replace(&mut entry.0, id);
        assert!(!self.retired.iter().any(|(r, _)| *r == incumbent));
        self.retired.push((incumbent, stamp));
    }

    /// Every prefix check: `V`, `P_index = 0`, the free stack's contents,
    /// every chain's links and every bucket's occupancy against the model,
    /// the disjoint overflow sets totalling `A`, the era and the pool ledger
    /// against the retirements, the engine ledger, every probe's exact
    /// candidate set, and every retirement record.
    fn check(&self, storage: &Storage<TestPlatform>, probe_keys: &[Key]) {
        assert_eq!(storage.engine_used(), self.used);
        assert_eq!(era(storage), self.first_era + self.retired.len() as u64);
        let ledger = storage.pool_report().unwrap().ledger.unwrap();
        assert_eq!(ledger.slots.retired, self.retired.len());
        assert_eq!(ledger.raw.retired, self.retired.len() * 24);
        let index = storage.index.as_ref().unwrap();
        let mut reader = storage.register().unwrap();
        for (shard, geometry) in self.index.shards().iter().enumerate() {
            if !geometry.is_enabled() {
                continue;
            }
            let report = report(storage, shard);
            let model = &self.shards[shard];
            assert_eq!(report.visible, model.keys.len(), "{shard}");
            assert_eq!(report.reserved, 0);
            assert_eq!(report.free_overflow, model.stack.len(), "{shard}");
            // The tables themselves: every link, every occupancy count and
            // the stack's contents, read under no writer.
            let image = index.image.shard(ShardIndex(shard)).unwrap();
            // SAFETY: the index mapping is live and no publisher runs.
            let (buckets, stack) =
                unsafe { (image.buckets(&index.mapping), image.stack(&index.mapping)) };
            let mut linked = std::collections::BTreeSet::new();
            for (base, chain) in model.chains.iter().enumerate() {
                let mut bucket = base;
                for overflow in chain {
                    assert_eq!(
                        OverflowLink::decode(buckets[bucket].next()),
                        Some(*overflow),
                        "{shard}/{base}"
                    );
                    assert!(linked.insert(*overflow));
                    bucket = geometry.base + overflow;
                }
                assert_eq!(OverflowLink::decode(buckets[bucket].next()), None);
            }
            for (bucket, count) in model.occupied.iter().enumerate() {
                assert_eq!(
                    occupied_pairs(buckets[bucket].control()),
                    *count,
                    "{bucket}"
                );
            }
            let free: std::collections::BTreeSet<usize> =
                stack[..report.free_overflow].iter().copied().collect();
            assert_eq!(free.len(), model.stack.len());
            assert_eq!(
                free,
                model
                    .stack
                    .iter()
                    .copied()
                    .collect::<std::collections::BTreeSet<_>>()
            );
            assert!(linked.is_disjoint(&free));
            assert_eq!(linked.len() + free.len(), geometry.overflow);
            for overflow in &linked {
                assert!(model.occupied[geometry.base + overflow] > 0);
            }
        }
        for probe in probe_keys {
            let (shard, _) = self.route(probe);
            let expected: Vec<AllocationId> = self.shards[shard]
                .keys
                .get(probe)
                .map(|(id, _)| *id)
                .into_iter()
                .collect();
            let found: Vec<AllocationId> = reader
                .enter()
                .unwrap()
                .snapshot(probe, RETRIES, &mut WorkBudget::new(64))
                .unwrap()
                .unwrap()
                .iter()
                .map(|c| resolved(storage, c))
                .collect();
            assert_eq!(found, expected, "{probe:?}");
        }
        for (id, stamp) in &self.retired {
            assert_retired(storage, *id, *stamp);
        }
    }
}

/// `spread` with every key in base bucket zero, so chains grow, buckets are
/// popped and recycled and every removal shape occurs.
fn spread_one_bucket(key: &Key) -> u64 {
    spread(key) & !0xFF
}

/// Generated mixed histories of inserts, exact removals, replacements and
/// invalidations over one and two shards, under a spreading seam and a
/// one-bucket seam, checked against the oracle after every step: the oracle
/// predicts each outcome from its own model of the chains, the stack and the
/// retired identities, then the tables, every report, the ledgers, the era,
/// every probe and every retirement record are compared, on every enabled
/// shard. Depth zero, one and two run under both seams, so the pop's depth
/// check runs against each bound. Every outcome class occurs, plus at least one
/// removal that keeps its bucket, one that recycles it and one publication
/// that pops one.
#[test]
fn generated_mixed_histories_agree_with_the_oracle_at_every_prefix() {
    let overflow_ratios: [(usize, usize); 2] = [(1, 2), (1, 1)];
    let shard_limits: [&[usize]; 4] = [&[16], &[15, 16], &[18, 0], &[20, 17]];
    let seams: [(crate::index::Seam, BucketOf); 2] = [
        (spread, |key, mask| usize::from(key[31]) & mask),
        (spread_one_bucket, |_, _| 0),
    ];
    let mut seed = 0x9E37_79B9u32;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        seed
    };
    let mut outcomes = [0usize; 9];
    let mut shapes = [0usize; 3];
    for (seam, bucket_of) in seams {
        for limits in shard_limits {
            for overflow in overflow_ratios {
                for depth in [0, 1, 2] {
                    let total: usize = limits.iter().sum();
                    // Room for every ended identity to stay retired and anchored.
                    let slot_count = total * 12 + 8;
                    let config = index_config(limits, overflow, depth);
                    let mut storage = storage(slot_count, &config);
                    install_seam(&mut storage, seam);
                    let index = storage.index.as_ref().unwrap().geometry.clone();
                    let mut oracle = Oracle::new(&storage, index.clone(), bucket_of);
                    let keys: Vec<Key> = (1..=(total as u8 + 3)).map(key).collect();
                    for step in 0..48 {
                        let roll = next();
                        let candidate = keys[roll as usize % keys.len()];
                        let (shard, _) = oracle.route(&candidate);
                        let sequence_before = report(&storage, shard).sequence;
                        let before = report(&storage, shard);
                        run_step(
                            &storage,
                            &mut oracle,
                            &candidate,
                            shard,
                            roll,
                            step,
                            sequence_before,
                            before,
                            &mut outcomes,
                            &mut shapes,
                        );
                        oracle.check(&storage, &keys);
                    }
                }
            }
        }
    }
    // Every outcome class occurred: insert, insert refused as present,
    // invalidate present, invalidate absent, swap, replace refused, remove,
    // remove absent, insert refused as full; and every removal shape: base
    // or shared bucket kept, bucket recycled, pop.
    assert!(outcomes.iter().all(|n| *n > 0), "{outcomes:?}");
    assert!(shapes.iter().all(|n| *n > 0), "{shapes:?}");
}

/// One generated step against the oracle.
#[expect(
    clippy::too_many_arguments,
    reason = "a test step over the loop's state"
)]
fn run_step(
    storage: &Storage<TestPlatform>,
    oracle: &mut Oracle,
    candidate: &Key,
    shard: usize,
    roll: u32,
    step: usize,
    sequence_before: u64,
    before: super::ShardReport,
    outcomes: &mut [usize; 9],
    shapes: &mut [usize; 3],
) {
    let candidate = *candidate;
    let stamp = era(storage);
    match (roll >> 16) % 5 {
        0 | 1 => {
            let owner = completed(storage, candidate);
            let id = owner.id();
            let predicted = oracle.predict_insert(&candidate);
            let present = oracle.shards[shard].keys.contains_key(&candidate);
            match (owner.publish(TRIES, &mut budget()), predicted, present) {
                (Ok(published), Predicted::Insert { bucket, pops }, false) => {
                    assert_eq!(published, id);
                    shapes[2] += usize::from(pops.is_some());
                    oracle.apply_insert(candidate, id, bucket, pops);
                    assert_eq!(report(storage, shard).sequence, sequence_before + 2);
                    outcomes[0] += 1;
                }
                (Err((owner, PublishError::IndexFull)), Predicted::Full, _) => {
                    assert_eq!(report(storage, shard), before);
                    discard(storage, owner);
                    outcomes[8] += 1;
                }
                (Err((owner, PublishError::Present)), _, true) => {
                    assert_eq!(report(storage, shard), before);
                    discard(storage, owner);
                    outcomes[1] += 1;
                }
                (outcome, predicted, present) => panic!(
                    "{step}: predicted {predicted:?} present {present}, got {:?}",
                    outcome.map_err(|(_, e)| e)
                ),
            }
        }
        2 => {
            let predicted = oracle.predict_remove(&candidate);
            match (
                storage.invalidate(&candidate, TRIES, &mut budget()),
                predicted,
            ) {
                (Ok(ack), Predicted::Remove { recycles }) => {
                    shapes[usize::from(recycles.is_some())] += 1;
                    let id = oracle.apply_remove(&candidate, stamp);
                    assert_eq!(ack.removed, Some((id, RetireOutcome::Recorded)));
                    assert_eq!(ack.sequence, sequence_before + 2);
                    assert_eq!(era(storage), stamp + 1);
                    outcomes[2] += 1;
                }
                (Ok(ack), Predicted::Absent) => {
                    assert_eq!(ack.removed, None);
                    assert_eq!(ack.sequence, sequence_before + 2);
                    assert_eq!(era(storage), stamp);
                    outcomes[3] += 1;
                }
                (outcome, predicted) => {
                    panic!("{step}: predicted {predicted:?}, got {outcome:?}")
                }
            }
            assert_eq!(report(storage, shard).sequence, sequence_before + 2);
        }
        3 => {
            // Exact removal by identity: the model's identity, or a stale
            // one half of the time.
            let known = oracle.shards[shard].keys.get(&candidate).map(|e| e.0);
            let stale = (roll >> 8) & 1 == 1;
            let target = match (known, stale) {
                (Some(id), false) => id,
                _ => AllocationId::new(super::tables::SlotIndex(0), u32::MAX - 1),
            };
            let predicted = oracle.predict_remove(&candidate);
            match (
                storage.remove(&candidate, target, TRIES, &mut budget()),
                predicted,
                stale,
            ) {
                (Ok(RetireOutcome::Recorded), Predicted::Remove { recycles }, false) => {
                    shapes[usize::from(recycles.is_some())] += 1;
                    assert_eq!(oracle.apply_remove(&candidate, stamp), target);
                    assert_eq!(report(storage, shard).sequence, sequence_before + 2);
                    assert_eq!(era(storage), stamp + 1);
                    outcomes[6] += 1;
                }
                (Err(RemoveError::Absent), Predicted::Absent, _)
                | (Err(RemoveError::Absent), Predicted::Remove { .. }, true) => {
                    // No step, nothing moved.
                    assert_eq!(report(storage, shard), before);
                    assert_eq!(era(storage), stamp);
                    outcomes[7] += 1;
                }
                (outcome, predicted, stale) => {
                    panic!("{step}: predicted {predicted:?} stale {stale}, got {outcome:?}")
                }
            }
        }
        _ => {
            let owner = completed(storage, candidate);
            let id = owner.id();
            let incumbent = oracle.shards[shard].keys.get(&candidate).map(|e| e.0);
            let predicted = match incumbent {
                Some(incumbent) => Predicted::Swap { incumbent },
                None => oracle.predict_insert(&candidate),
            };
            match (owner.replace(TRIES, &mut budget()), predicted) {
                (Ok(replacement), Predicted::Swap { incumbent }) => {
                    assert_eq!(replacement.id, id);
                    assert_eq!(
                        replacement.replaced,
                        Some((incumbent, RetireOutcome::Recorded))
                    );
                    oracle.apply_swap(&candidate, id, stamp);
                    assert_eq!(report(storage, shard).sequence, sequence_before + 2);
                    assert_eq!(era(storage), stamp + 1);
                    outcomes[4] += 1;
                }
                (Ok(replacement), Predicted::Insert { bucket, pops }) => {
                    assert_eq!(replacement.id, id);
                    assert_eq!(replacement.replaced, None);
                    shapes[2] += usize::from(pops.is_some());
                    oracle.apply_insert(candidate, id, bucket, pops);
                    outcomes[0] += 1;
                }
                (Err((owner, PublishError::IndexFull)), Predicted::Full) => {
                    assert_eq!(report(storage, shard), before);
                    discard(storage, owner);
                    outcomes[5] += 1;
                }
                (outcome, predicted) => panic!(
                    "{step}: predicted {predicted:?}, got {:?}",
                    outcome.map_err(|(_, e)| e)
                ),
            }
        }
    }
}

/// Removing the sole entry of an overflow bucket unlinks and recycles it;
/// removing an entry with a live neighbour keeps the bucket linked; a middle
/// bucket that empties is unlinked with its successor relinked; each ended
/// mapping leaves one retirement record with the anchor held; an absent
/// identity is refused with nothing changed; service releases the anchor only
/// after a certification pass permits it, and a reader pinned before the
/// removal holds it through that pass.
#[test]
fn removal_recycles_emptied_buckets_and_records_one_retirement_each() {
    let slot_count = 48;
    // One chain, `A = 2`, `D = 2`: base plus two overflow buckets.
    let limits = [32usize];
    let config = index_config(&limits, (1, 2), 2);
    let mut storage = storage(slot_count, &config);
    install_seam(&mut storage, one_chain);
    let geometry = storage.index.as_ref().unwrap().geometry.shards()[0];
    assert_eq!(geometry.overflow, 2);
    // Keys whose first byte is 0x11 share one fingerprint and one chain.
    let k = |n: u8| {
        let mut k = key(0x11);
        k[1] = n;
        k
    };
    let first = k(0);
    let published: Vec<AllocationId> = (0..30u8)
        .map(|n| {
            completed(&storage, k(n))
                .publish(TRIES, &mut budget())
                .unwrap()
        })
        .collect();
    // Base holds keys 0..14, overflow 0 holds 14..28, overflow 1 holds 28
    // and 29.
    assert_eq!(report(&storage, 0).free_overflow, 0);
    assert_eq!(candidates(&storage, &first), published);
    let mut reader = storage.register().unwrap();

    // A live neighbour keeps overflow 1 linked.
    let stamp = era(&storage);
    let before = report(&storage, 0);
    assert_eq!(
        storage.remove(&k(28), published[28], TRIES, &mut budget()),
        Ok(RetireOutcome::Recorded)
    );
    assert_retired(&storage, published[28], stamp);
    let after = report(&storage, 0);
    assert_eq!((after.visible, after.free_overflow), (29, 0));
    assert_eq!(after.sequence, before.sequence + 2);
    let mut remaining = published.clone();
    remaining.remove(28);
    assert_eq!(candidates(&storage, &first), remaining);

    // The middle bucket empties: unlinked, its successor relinked, recycled.
    for (n, id) in published.iter().enumerate().take(28).skip(14) {
        assert_eq!(
            storage.remove(&k(n as u8), *id, TRIES, &mut budget()),
            Ok(RetireOutcome::Recorded)
        );
    }
    let after = report(&storage, 0);
    assert_eq!((after.visible, after.free_overflow), (15, 1));
    let mut expected: Vec<AllocationId> = published[..14].to_vec();
    expected.push(published[29]);
    assert_eq!(candidates(&storage, &first), expected);
    // The tail bucket empties: the predecessor's link becomes none and both
    // overflow buckets are free; the next two pops come back last-in first.
    assert_eq!(
        storage.remove(&k(29), published[29], TRIES, &mut budget()),
        Ok(RetireOutcome::Recorded)
    );
    let after = report(&storage, 0);
    assert_eq!((after.visible, after.free_overflow), (14, 2));
    assert_eq!(candidates(&storage, &first), published[..14]);
    let relinked = completed(&storage, k(29))
        .publish(TRIES, &mut budget())
        .unwrap();
    assert_eq!(report(&storage, 0).free_overflow, 1);
    let mut expected: Vec<AllocationId> = published[..14].to_vec();
    expected.push(relinked);
    assert_eq!(candidates(&storage, &first), expected);
    // The surviving overflow bucket's free pairs fill first, in pair order;
    // the recycled bucket is the next pop.
    let more: Vec<AllocationId> = (30..43u8)
        .map(|n| {
            completed(&storage, k(n))
                .publish(TRIES, &mut budget())
                .unwrap()
        })
        .collect();
    assert_eq!(report(&storage, 0).free_overflow, 1);
    let popped = completed(&storage, k(43))
        .publish(TRIES, &mut budget())
        .unwrap();
    assert_eq!(report(&storage, 0).free_overflow, 0);
    expected.extend(more);
    expected.push(popped);
    assert_eq!(candidates(&storage, &first), expected);

    // Absent identity: refused, nothing changed.
    let before = report(&storage, 0);
    assert_eq!(
        storage.remove(&k(14), published[14], TRIES, &mut budget()),
        Err(RemoveError::Absent)
    );
    assert_eq!(report(&storage, 0), before);
    // The same key, another identity: refused too.
    assert_eq!(
        storage.remove(&first, published[14], TRIES, &mut budget()),
        Err(RemoveError::Absent)
    );
    // An identity whose incarnation shares the stored pair's low 16 bits
    // but not the full value: refused, nothing changed.
    let alias = AllocationId::new(popped.slot(), popped.incarnation() + (1 << 16));
    assert_eq!(
        storage.remove(&k(43), alias, TRIES, &mut budget()),
        Err(RemoveError::Absent)
    );
    assert_eq!(report(&storage, 0), before);

    // Every ended identity still holds its anchor and its payload charge.
    let ledger = storage.pool_report().unwrap().ledger.unwrap();
    assert_eq!(ledger.slots.retired, 16);
    assert_eq!(ledger.raw.retired, 16 * 24);
    for id in &published[14..30] {
        assert_eq!(refs(&storage, *id), 1);
    }
    // A reader pinned before a removal holds that anchor through the pass;
    // the earlier retirements release.
    let protected = reader.enter().unwrap();
    let stamp = era(&storage);
    assert_eq!(
        storage.remove(&k(1), published[1], TRIES, &mut budget()),
        Ok(RetireOutcome::Recorded)
    );
    assert_retired(&storage, published[1], stamp);
    assert!(
        storage
            .certify(&mut WorkBudget::new(400))
            .unwrap()
            .certified
            .is_some()
    );
    let pass = storage.service(&mut WorkBudget::new(4000)).unwrap();
    assert_eq!((pass.released, pass.serviced, pass.held), (16, 16, 1));
    assert_eq!(refs(&storage, published[1]), 1);
    assert_eq!(refs(&storage, published[14]), 0);
    protected.exit();
    assert!(
        storage
            .certify(&mut WorkBudget::new(400))
            .unwrap()
            .certified
            .is_some()
    );
    let pass = storage.service(&mut WorkBudget::new(4000)).unwrap();
    assert_eq!((pass.released, pass.serviced, pass.held), (1, 1, 0));
    assert_eq!(refs(&storage, published[1]), 0);
    let ledger = storage.pool_report().unwrap().ledger.unwrap();
    assert_eq!(ledger.slots.retired, 0);
}

/// At `V = N` a funded replacement succeeds leaving `V` and `P_index`
/// unchanged and retiring the incumbent; after the incumbent's removal the
/// replacement needs admission and refuses `IndexFull`; the zero-try,
/// walk-budget, anchor-present and vacant-pop-rollback cuts leave the
/// incumbent's mapping, bytes and charges intact with only the replacement's
/// claims refunded.
#[test]
fn replacement_is_slot_neutral_and_every_cut_preserves_the_incumbent() {
    let slot_count = 16;
    let limits = [1usize];
    let config = index_config(&limits, (1, 1), 1);
    let mut storage = storage(slot_count, &config);
    install_seam(&mut storage, one_chain);
    let incumbent = completed(&storage, key(0x21))
        .publish(TRIES, &mut budget())
        .unwrap();
    assert_eq!(report(&storage, 0).visible, 1);
    let ledger_before = storage.pool_report().unwrap().ledger.unwrap();

    // Cuts: zero tries, a budget that dies in the walk, an anchor present.
    let before = report(&storage, 0);
    let cuts: [(usize, WorkBudget); 2] = [(0, budget()), (TRIES, WorkBudget::new(3))];
    for (tries, mut spent) in cuts {
        let owner = completed(&storage, key(0x21));
        let (owner, error) = owner.replace(tries, &mut spent).err().unwrap();
        assert!(matches!(
            error,
            PublishError::Contended | PublishError::BudgetExhausted
        ));
        assert_eq!(report(&storage, 0), before);
        assert_eq!(candidates(&storage, &key(0x21)), [incumbent]);
        assert_eq!(refs(&storage, incumbent), 1);
        assert_eq!(refs(&storage, owner.id()), 0);
        discard(&storage, owner);
    }
    {
        let owner = completed(&storage, key(0x21));
        let refs_word = storage.live_pool().unwrap();
        refs_word.set_refs(owner.id().slot_index(), 1);
        let (owner, error) = owner.replace(TRIES, &mut budget()).err().unwrap();
        assert_eq!(error, PublishError::AnchorPresent);
        assert_eq!(report(&storage, 0), before);
        assert_eq!(candidates(&storage, &key(0x21)), [incumbent]);
        refs_word.set_refs(owner.id().slot_index(), 0);
        discard(&storage, owner);
    }
    assert_eq!(
        storage.pool_report().unwrap().ledger.unwrap(),
        ledger_before
    );

    // The funded replacement at `V = N`.
    let stamp = era(&storage);
    let owner = completed(&storage, key(0x21));
    let id = owner.id();
    let replacement = owner.replace(TRIES, &mut budget()).unwrap();
    assert_eq!(replacement.id, id);
    assert_eq!(
        replacement.replaced,
        Some((incumbent, RetireOutcome::Recorded))
    );
    let after = report(&storage, 0);
    assert_eq!((after.visible, after.reserved), (1, 0));
    assert_eq!(after.sequence, before.sequence + 2);
    assert_eq!(candidates(&storage, &key(0x21)), [id]);
    assert_retired(&storage, incumbent, stamp);
    assert_eq!(refs(&storage, id), 1);
    // The incumbent's bytes are still charged, as retired.
    let ledger = storage.pool_report().unwrap().ledger.unwrap();
    assert_eq!(ledger.slots.retired, 1);
    assert_eq!(ledger.slots.resident, ledger_before.slots.resident);

    // Independent removal, then the replacement needs admission: another
    // key fills the shard, so the vacant-key replacement refuses.
    assert_eq!(
        storage.remove(&key(0x21), id, TRIES, &mut budget()),
        Ok(RetireOutcome::Recorded)
    );
    assert_eq!(report(&storage, 0).visible, 0);
    let other = completed(&storage, key(0x22))
        .publish(TRIES, &mut budget())
        .unwrap();
    let (owner, error) = completed(&storage, key(0x21))
        .replace(TRIES, &mut budget())
        .err()
        .unwrap();
    assert_eq!(error, PublishError::IndexFull);
    assert_eq!(candidates(&storage, &key(0x22)), [other]);
    discard(&storage, owner);
    // With room, the replacement of a vacant key is an insert.
    assert_eq!(
        storage.remove(&key(0x22), other, TRIES, &mut budget()),
        Ok(RetireOutcome::Recorded)
    );
    let replacement = completed(&storage, key(0x21))
        .replace(TRIES, &mut budget())
        .unwrap();
    assert_eq!(replacement.replaced, None);
    assert_eq!(candidates(&storage, &key(0x21)), [replacement.id]);

    // A vacant-key replacement that must pop an overflow bucket and then
    // finds its anchor taken: the bucket is pushed back and the claim is
    // refunded.
    let slot_count = 24;
    let limits = [16usize];
    let config = index_config(&limits, (1, 1), 1);
    let mut storage = self::storage(slot_count, &config);
    install_seam(&mut storage, one_chain);
    for n in 1..=14u8 {
        completed(&storage, key(n))
            .publish(TRIES, &mut budget())
            .unwrap();
    }
    let before = report(&storage, 0);
    let owner = completed(&storage, key(15));
    let refs_word = storage.live_pool().unwrap();
    refs_word.set_refs(owner.id().slot_index(), 1);
    let (owner, error) = owner.replace(TRIES, &mut budget()).err().unwrap();
    assert_eq!(error, PublishError::AnchorPresent);
    assert_eq!(report(&storage, 0), before);
    refs_word.set_refs(owner.id().slot_index(), 0);
    let replacement = owner.replace(TRIES, &mut budget()).unwrap();
    assert_eq!(replacement.replaced, None);
    assert_eq!(report(&storage, 0).free_overflow, before.free_overflow - 1);
}

/// Invalidation removes a present key and acknowledges an absent one with a
/// sequence step either way; the committed values are totally ordered with
/// the shard's publications, and a publication after an invalidation of the
/// same key carries a greater value; exhausted gate attempts refuse
/// `Contended` with the mapping, sequence and counts unchanged and the failed
/// tries counted; a closed storage refuses `Closed`.
#[test]
fn invalidation_is_the_revocation_ordering_point() {
    let slot_count = 16;
    let limits = [4usize];
    let config = index_config(&limits, (1, 1), 1);
    let mut storage = storage(slot_count, &config);
    install_seam(&mut storage, one_chain);
    let mut log: Vec<(&str, u64)> = Vec::new();
    let first = completed(&storage, key(0x31))
        .publish(TRIES, &mut budget())
        .unwrap();
    log.push(("publish", report(&storage, 0).sequence));
    let stamp = era(&storage);
    let ack = storage
        .invalidate(&key(0x31), TRIES, &mut budget())
        .unwrap();
    assert_eq!(ack.removed, Some((first, RetireOutcome::Recorded)));
    log.push(("invalidate", ack.sequence));
    assert_retired(&storage, first, stamp);
    assert_eq!(candidates(&storage, &key(0x31)), []);
    let absent = storage
        .invalidate(&key(0x32), TRIES, &mut budget())
        .unwrap();
    assert_eq!(absent.removed, None);
    log.push(("invalidate absent", absent.sequence));
    assert_eq!(era(&storage), stamp + 1);
    let second = completed(&storage, key(0x31))
        .publish(TRIES, &mut budget())
        .unwrap();
    log.push(("publish again", report(&storage, 0).sequence));
    assert_eq!(candidates(&storage, &key(0x31)), [second]);
    for pair in log.windows(2) {
        assert!(pair[0].1 < pair[1].1, "{log:?}");
    }
    assert!(log[1].1 < log[3].1);

    // Exhausted attempts under a held gate: nothing attributable changes.
    let index = storage.index.as_ref().unwrap();
    let shard = index.image.shard(crate::index::ShardIndex(0)).unwrap();
    // SAFETY: the index mapping is live.
    let gate = unsafe { shard.gate(&index.mapping) };
    let before = report(&storage, 0);
    let held = gate.try_lock().unwrap();
    let mut spent = budget();
    assert_eq!(
        storage.invalidate(&key(0x31), TRIES, &mut spent),
        Err(InvalidateError::Contended)
    );
    assert_eq!(spent.counters().coordination_attempts, TRIES);
    held.release();
    let after = report(&storage, 0);
    assert_eq!(after.failed_tries, before.failed_tries + TRIES);
    assert_eq!(
        (after.sequence, after.visible),
        (before.sequence, before.visible)
    );
    assert_eq!(candidates(&storage, &key(0x31)), [second]);
    assert_eq!(
        storage.invalidate(&key(0x31), 0, &mut budget()),
        Err(InvalidateError::Contended)
    );

    // Closed: replacement, invalidation and a new protected interval
    // refuse; internal removal completes and the mapping is gone.
    let owner = completed(&storage, key(0x31));
    let mut reader = storage.register().unwrap();
    let visible = report(&storage, 0).visible;
    storage.close();
    let (owner, error) = owner.replace(TRIES, &mut budget()).err().unwrap();
    assert_eq!(error, PublishError::Closed);
    discard(&storage, owner);
    assert_eq!(
        storage.invalidate(&key(0x31), TRIES, &mut budget()),
        Err(InvalidateError::Closed)
    );
    assert_eq!(
        storage.remove(&key(0x31), second, TRIES, &mut budget()),
        Ok(RetireOutcome::Recorded)
    );
    assert_eq!(report(&storage, 0).visible, visible - 1);
    assert_eq!(reader.enter().err(), Some(PinError::Closed));
}

/// In a terminal shard funded removal and invalidation succeed under the
/// terminal value while the snapshot stays contended, and a shard whose next
/// commit would exhaust the sequence becomes terminal through a removal.
#[test]
fn a_terminal_shard_still_ends_mappings() {
    let slot_count = 16;
    let limits = [4usize];
    let config = index_config(&limits, (1, 1), 1);
    let mut storage = storage(slot_count, &config);
    install_seam(&mut storage, one_chain);
    let index = storage.index.as_ref().unwrap();
    let shard = index.image.shard(crate::index::ShardIndex(0)).unwrap();
    // SAFETY: the index mapping is live.
    let control = unsafe { shard.control(&index.mapping) };
    let first = completed(&storage, key(0x41))
        .publish(TRIES, &mut budget())
        .unwrap();
    let second = completed(&storage, key(0x42))
        .publish(TRIES, &mut budget())
        .unwrap();
    // The next commit would land on the reserved value.
    control.sequence.store(TERMINAL - 2, Ordering::SeqCst);
    let ack = storage
        .invalidate(&key(0x41), TRIES, &mut budget())
        .unwrap();
    assert_eq!(ack.sequence, TERMINAL);
    assert_eq!(ack.removed.map(|r| r.0), Some(first));
    let after = report(&storage, 0);
    assert!(after.terminal);
    // The capacity lost counts the entry this removal freed.
    assert_eq!((after.visible, after.lost_capacity), (1, 4 - 1));
    let mut reader = storage.register().unwrap();
    assert_eq!(
        reader
            .enter()
            .unwrap()
            .snapshot(&key(0x42), RETRIES, &mut budget()),
        Ok(None)
    );
    assert_eq!(
        storage.remove(&key(0x42), second, TRIES, &mut budget()),
        Ok(RetireOutcome::Recorded)
    );
    assert_eq!(report(&storage, 0).visible, 0);
    assert_eq!(report(&storage, 0).sequence, TERMINAL);
    let absent = storage
        .invalidate(&key(0x42), TRIES, &mut budget())
        .unwrap();
    assert_eq!((absent.sequence, absent.removed), (TERMINAL, None));
    let (owner, error) = completed(&storage, key(0x43))
        .replace(TRIES, &mut budget())
        .err()
        .unwrap();
    assert_eq!(error, PublishError::IndexFull);
    discard(&storage, owner);
    // Terminal never bypasses close: the close check comes first.
    let third = completed(&storage, key(0x43))
        .publish(TRIES, &mut budget())
        .err()
        .map(|(owner, error)| {
            assert_eq!(error, PublishError::IndexFull);
            owner
        })
        .unwrap();
    let replacement = completed(&storage, key(0x44));
    storage.close();
    assert_eq!(
        storage.invalidate(&key(0x42), TRIES, &mut budget()),
        Err(InvalidateError::Closed)
    );
    let (owner, error) = replacement.replace(TRIES, &mut budget()).err().unwrap();
    assert_eq!(error, PublishError::Closed);
    discard(&storage, owner);
    discard(&storage, third);
}

/// A malformed table refuses removal `Corrupt` and poisons the gate: a
/// reserved control bit found by the walk, a found pair with `V` already
/// zero, and an emptied bucket whose stack top is past the stack or whose
/// outgoing link is out of range or names the bucket itself.
#[test]
fn malformed_tables_refuse_removal_and_poison_the_gate() {
    let plant =
        |corrupt: &dyn Fn(&Storage<TestPlatform>, &[AllocationId]),
         removal: fn(&Storage<TestPlatform>, &[AllocationId]) -> RemoveError| {
            for exhausting in [false, true] {
                let slot_count = 24;
                let limits = [16usize];
                let config = index_config(&limits, (1, 1), 1);
                let mut storage = storage(slot_count, &config);
                install_seam(&mut storage, one_chain);
                // Fourteen keys fill the base bucket; the last one is alone
                // in overflow bucket zero.
                let published: Vec<AllocationId> = (1..=15u8)
                    .map(|n| {
                        completed(&storage, key(n))
                            .publish(TRIES, &mut budget())
                            .unwrap()
                    })
                    .collect();
                if exhausting {
                    control(&storage)
                        .sequence
                        .store(TERMINAL - 2, Ordering::SeqCst);
                }
                corrupt(&storage, &published);
                let before = report(&storage, 0);
                assert_eq!(
                    removal(&storage, &published),
                    RemoveError::Corrupt,
                    "{exhausting}"
                );
                assert_eq!(report(&storage, 0), before, "{exhausting}");
                assert_eq!(
                    storage.invalidate(&key(0x11), TRIES, &mut budget()),
                    Err(InvalidateError::Contended)
                );
                for id in &published {
                    assert_eq!(refs(&storage, *id), 1);
                }
            }
        };
    fn control(storage: &Storage<TestPlatform>) -> &super::shards::ShardControl {
        let index = storage.index.as_ref().unwrap();
        let shard = index.image.shard(ShardIndex(0)).unwrap();
        // SAFETY: the index mapping is live.
        unsafe { shard.control(&index.mapping) }
    }
    fn bucket(storage: &Storage<TestPlatform>, at: usize) -> &crate::index::Bucket {
        let index = storage.index.as_ref().unwrap();
        let shard = index.image.shard(ShardIndex(0)).unwrap();
        // SAFETY: the index mapping is live.
        unsafe { &shard.buckets(&index.mapping)[at] }
    }
    let overflow_link = |storage: &Storage<TestPlatform>| {
        let shard = &storage.index.as_ref().unwrap().geometry.shards()[0];
        OverflowLink::encode(shard.overflow).unwrap().raw()
    };
    // A reserved control bit in the base bucket.
    plant(
        &|storage, _| {
            let base = bucket(storage, 0);
            base.corrupt(base.control() | RESERVED_BIT, base.next());
        },
        |storage, ids| {
            storage
                .remove(&key(1), ids[0], TRIES, &mut budget())
                .unwrap_err()
        },
    );
    // A found pair with `V` zero.
    plant(
        &|storage, _| control(storage).visible.store(0, Ordering::Relaxed),
        |storage, ids| {
            storage
                .remove(&key(1), ids[0], TRIES, &mut budget())
                .unwrap_err()
        },
    );
    // The emptied overflow bucket's stack top is past the stack.
    plant(
        &|storage, _| {
            control(storage)
                .free_top
                .store(usize::MAX / 2, Ordering::Relaxed)
        },
        |storage, ids| {
            storage
                .remove(&key(15), ids[14], TRIES, &mut budget())
                .unwrap_err()
        },
    );
    // The emptied overflow bucket links to itself: a cycle every reader
    // refuses at the depth bound, which the predecessor would take over.
    plant(
        &|storage, _| {
            let shard = &storage.index.as_ref().unwrap().geometry.shards()[0];
            let link = bucket(storage, 0).next();
            let overflow = OverflowLink::decode(link).unwrap();
            let tail = bucket(storage, shard.base + overflow);
            tail.corrupt(tail.control(), link);
        },
        |storage, ids| {
            storage
                .remove(&key(15), ids[14], TRIES, &mut budget())
                .unwrap_err()
        },
    );
    // The emptied overflow bucket's outgoing link is out of range.
    plant(
        &|storage, _| {
            let shard = &storage.index.as_ref().unwrap().geometry.shards()[0];
            let tail = bucket(storage, shard.base);
            tail.corrupt(tail.control(), overflow_link(storage));
        },
        |storage, ids| {
            storage
                .remove(&key(15), ids[14], TRIES, &mut budget())
                .unwrap_err()
        },
    );
}

/// A removal that empties an overflow bucket on a cycle back to it refuses
/// `Corrupt` and poisons the gate: the chain base, o0, o1 with o1 linked back
/// to o0, which every reader refuses at the depth bound, is not handed to the
/// base bucket as base, o1, o0 with o0 pushed to the free stack.
#[test]
fn removal_refuses_to_recycle_an_overflow_bucket_its_carried_chain_returns_to() {
    let config = index_config(&[64usize], (1, 1), 2);
    let mut storage = storage(96, &config);
    install_seam(&mut storage, one_chain);
    // One chain: the low nibble varies the key, byte 30 the fingerprint.
    let key = |n: u8| {
        let mut key = [0u8; 32];
        key[0] = n & 15;
        key[30] = n;
        key
    };
    // Fourteen keys in the base bucket, fourteen in o0, one in o1.
    let ids: Vec<AllocationId> = (0..29)
        .map(|n| {
            completed(&storage, key(n))
                .publish(TRIES, &mut budget())
                .unwrap()
        })
        .collect();
    for n in 14..27u8 {
        storage
            .remove(&key(n), ids[usize::from(n)], TRIES, &mut budget())
            .unwrap();
    }
    let index = storage.index.as_ref().unwrap();
    let base = index.geometry.shards()[0].base;
    let shard = index.image.shard(ShardIndex(0)).unwrap();
    // SAFETY: the index mapping is live.
    let buckets = unsafe { shard.buckets(&index.mapping) };
    let to_o0 = buckets[0].next();
    let o0 = base + OverflowLink::decode(to_o0).unwrap();
    let o1 = base + OverflowLink::decode(buckets[o0].next()).unwrap();
    buckets[o1].corrupt(buckets[o1].control(), to_o0);
    let corrupt = |storage: &Storage<TestPlatform>| {
        let mut reader = storage.register().unwrap();
        let mut entered = reader.enter().unwrap();
        entered.snapshot(&key(1), RETRIES, &mut budget()).err()
    };
    assert_eq!(corrupt(&storage), Some(SnapshotError::Corrupt));
    let before = report(&storage, 0);
    assert_eq!(
        storage.remove(&key(27), ids[27], TRIES, &mut budget()),
        Err(RemoveError::Corrupt),
        "a removal recycled a bucket its carried chain returns to"
    );
    assert_eq!(report(&storage, 0), before);
    assert_eq!(buckets[0].next(), to_o0);
    assert_eq!(corrupt(&storage), Some(SnapshotError::Corrupt));
    assert_eq!(
        storage.invalidate(&key(28), TRIES, &mut budget()),
        Err(InvalidateError::Contended)
    );
}

/// The walk charges every occupied pair of a bucket before it loads a
/// pair word, so a match in the first pair pays for the pairs behind it,
/// and a budget that covers the visit but not its pairs refuses before any
/// fingerprint comparison is charged.
#[test]
fn the_walk_charges_a_buckets_occupied_pairs_before_its_words() {
    let slot_count = 16;
    let limits = [8usize];
    let config = index_config(&limits, (1, 1), 1);
    let mut storage = storage(slot_count, &config);
    install_seam(&mut storage, one_chain);
    let a = completed(&storage, key(0x11))
        .publish(TRIES, &mut budget())
        .unwrap();
    completed(&storage, key(0x12))
        .publish(TRIES, &mut budget())
        .unwrap();
    // The hash pass, one gate attempt, one visit: the pairs are refused.
    let mut spent = WorkBudget::new(HASH_CHARGE + 1 + 1);
    assert_eq!(
        storage.invalidate(&key(0x11), TRIES, &mut spent),
        Err(InvalidateError::BudgetExhausted)
    );
    assert_eq!(spent.counters().visits, 1);
    assert_eq!(spent.counters().comparisons, 0);
    assert_eq!(candidates(&storage, &key(0x11)).len(), 2);
    // The first pair matches: both occupied pairs and one fingerprint.
    let mut spent = budget();
    let ack = storage.invalidate(&key(0x11), TRIES, &mut spent).unwrap();
    assert_eq!(ack.removed.map(|r| r.0), Some(a));
    assert_eq!(spent.counters().visits, 1);
    assert_eq!(spent.counters().comparisons, 2 + 1);
}

/// Invalidation compares the fingerprint: colliding tags in one chain are
/// told apart, an absent colliding key is acknowledged with nothing removed,
/// and the removed identity is the one whose fingerprint matched.
#[test]
fn invalidation_distinguishes_colliding_tags_by_fingerprint() {
    let slot_count = 16;
    let limits = [8usize];
    let config = index_config(&limits, (1, 1), 1);
    let mut storage = storage(slot_count, &config);
    install_seam(&mut storage, one_chain);
    let a = completed(&storage, key(0x11))
        .publish(TRIES, &mut budget())
        .unwrap();
    let b = completed(&storage, key(0x12))
        .publish(TRIES, &mut budget())
        .unwrap();
    let before = report(&storage, 0);
    let mut spent = budget();
    let absent = storage.invalidate(&key(0x13), TRIES, &mut spent).unwrap();
    assert_eq!(absent.removed, None);
    // One visit, two occupied pairs, two fingerprint comparisons.
    assert_eq!(spent.counters().visits, 1);
    assert_eq!(spent.counters().comparisons, 2 + 2);
    assert_eq!(spent.counters().hashes, 1);
    assert_eq!(report(&storage, 0).visible, before.visible);
    assert_eq!(candidates(&storage, &key(0x11)), [a, b]);
    let mut spent = budget();
    let ack = storage.invalidate(&key(0x12), TRIES, &mut spent).unwrap();
    assert_eq!(ack.removed.map(|r| r.0), Some(b));
    assert_eq!(spent.counters().comparisons, 2 + 2);
    assert_eq!(candidates(&storage, &key(0x11)), [a]);
    // Exact removal compares the identity: one comparison per occupied
    // pair and one per tag match, no fingerprint read.
    let mut spent = budget();
    assert_eq!(
        storage.remove(&key(0x11), b, TRIES, &mut spent),
        Err(RemoveError::Absent)
    );
    assert_eq!(spent.counters().comparisons, 1 + 1);
    let mut spent = budget();
    assert_eq!(
        storage.remove(&key(0x11), a, TRIES, &mut spent),
        Ok(RetireOutcome::Recorded)
    );
    assert_eq!(spent.counters().visits, 1);
    assert_eq!(spent.counters().comparisons, 1 + 1);
    assert_eq!(spent.counters().coordination_attempts, 1);
    // Refusals before the walk.
    let before = report(&storage, 0);
    assert_eq!(
        storage.remove(&key(0x11), a, 0, &mut budget()),
        Err(RemoveError::Contended)
    );
    assert_eq!(
        storage.remove(&key(0x11), a, TRIES, &mut WorkBudget::new(1)),
        Err(RemoveError::BudgetExhausted)
    );
    assert_eq!(
        storage.invalidate(&key(0x11), TRIES, &mut WorkBudget::new(1)),
        Err(InvalidateError::BudgetExhausted)
    );
    assert_eq!(report(&storage, 0), before);
}

/// A removal selects a bucket's pairs by their control lanes' filter bits,
/// as the reader's scan does, and loads only the selected words. A pair
/// whose lane is planted under another filter stays occupied, and both the
/// scan and the removal select only the pairs whose lane filters match the
/// key's tag: the invalidation of the planted pair's key acknowledges an
/// absent key, charging every occupied pair plus one fingerprint comparison
/// per selected pair, and the pairs whose lanes match stay found and
/// removable.
#[test]
fn a_removal_selects_the_pairs_a_scan_selects() {
    let slot_count = 16;
    let limits = [8usize];
    let config = index_config(&limits, (1, 1), 1);
    let mut storage = storage(slot_count, &config);
    install_seam(&mut storage, one_chain);
    let ids: Vec<AllocationId> = (1..=4u8)
        .map(|n| {
            completed(&storage, key(n))
                .publish(TRIES, &mut budget())
                .unwrap()
        })
        .collect();
    assert_eq!(candidates(&storage, &key(1)), ids);
    let index = storage.index.as_ref().unwrap();
    let shard = index.image.shard(ShardIndex(0)).unwrap();
    // SAFETY: the index mapping is live.
    let base = unsafe { &shard.buckets(&index.mapping)[0] };
    let (control, next) = (base.control(), base.next());
    // Every key routes to one base bucket under one tag, and key 1
    // publishes first, so key 1 holds pair 0.
    let filter = 0b1110;
    let planted = (control & !filter) | ((control & filter) + 0b0010) & filter;
    assert_ne!(planted, control);
    base.corrupt(planted, next);
    assert_eq!(candidates(&storage, &key(1)), ids[1..]);
    let before = report(&storage, 0);
    let mut spent = budget();
    let absent = storage.invalidate(&key(1), TRIES, &mut spent).unwrap();
    assert_eq!(absent.removed, None);
    assert_eq!(spent.counters().visits, 1);
    assert_eq!(spent.counters().comparisons, 4 + 3);
    assert_eq!(report(&storage, 0).visible, before.visible);
    assert_eq!(base.control(), planted);
    let ack = storage.invalidate(&key(3), TRIES, &mut budget()).unwrap();
    assert_eq!(ack.removed.map(|r| r.0), Some(ids[2]));
    assert_eq!(candidates(&storage, &key(1)), [ids[1], ids[3]]);
}

/// Under a busy pool gate every ended mapping parks its obligation: the
/// flag and mark are set, the stamp landed, the ledger is untouched and the
/// anchor held; once the gate is free and a certification pass has run, a
/// service pass recovers every one.
#[test]
fn ended_mappings_park_their_obligation_under_a_busy_pool_and_service_recovers() {
    let slot_count = 32;
    let limits = [8usize];
    let config = index_config(&limits, (1, 1), 1);
    let mut storage = storage(slot_count, &config);
    install_seam(&mut storage, one_chain);
    let published: Vec<AllocationId> = (0x11..=0x16u8)
        .map(|n| {
            completed(&storage, key(n))
                .publish(TRIES, &mut budget())
                .unwrap()
        })
        .collect();
    let replacement = completed(&storage, key(0x13));
    let live = storage.live_pool().unwrap();
    let ledger_before = storage.pool_report().unwrap().ledger.unwrap();
    let held = live.lock().unwrap();
    let mut stamps = Vec::new();
    stamps.push((published[0], era(&storage)));
    assert_eq!(
        storage.remove(&key(0x11), published[0], TRIES, &mut budget()),
        Ok(RetireOutcome::Parked)
    );
    stamps.push((published[1], era(&storage)));
    assert_eq!(
        storage
            .invalidate(&key(0x12), TRIES, &mut budget())
            .unwrap()
            .removed,
        Some((published[1], RetireOutcome::Parked))
    );
    stamps.push((published[2], era(&storage)));
    assert_eq!(
        replacement.replace(TRIES, &mut budget()).unwrap().replaced,
        Some((published[2], RetireOutcome::Parked))
    );
    assert_eq!(live.telemetry().pending_marks.load(Ordering::Acquire), 3);
    for (id, stamp) in &stamps {
        assert_eq!(refs(&storage, *id), 1);
        assert_ne!(slot_flag(&storage, *id) & ANCHORED, 0);
        assert_eq!(retire_era(&storage, *id), *stamp);
    }
    assert_eq!(report(&storage, 0).visible, 4);
    assert_eq!(candidates(&storage, &key(0x11)).len(), 4);
    held.release();
    // The ledger has not moved: the obligations are parked, not recorded.
    assert_eq!(
        storage.pool_report().unwrap().ledger.unwrap(),
        ledger_before
    );
    assert!(
        storage
            .certify(&mut WorkBudget::new(400))
            .unwrap()
            .certified
            .is_some()
    );
    let pass = storage.service(&mut WorkBudget::new(400)).unwrap();
    assert_eq!((pass.released, pass.serviced, pass.held), (3, 3, 0));
    for (id, _) in &stamps {
        assert_eq!(refs(&storage, *id), 0);
    }
    assert_eq!(live.telemetry().pending_marks.load(Ordering::Acquire), 0);
}

/// The negative control "refund old payload early": a retired object's
/// payload bytes stay charged as retired until the return path; moving them
/// to free after the removal fails the ledger check.
#[test]
#[should_panic(expected = "payload stays charged")]
fn negative_control_refunding_the_old_payload_early_fails() {
    let slot_count = 16;
    let limits = [4usize];
    let config = index_config(&limits, (1, 1), 1);
    let storage = storage(slot_count, &config);
    let first = completed(&storage, key(1))
        .publish(TRIES, &mut budget())
        .unwrap();
    assert_eq!(
        storage.remove(&key(1), first, TRIES, &mut budget()),
        Ok(RetireOutcome::Recorded)
    );
    let live = storage.live_pool().unwrap();
    {
        let mut held = live.lock().unwrap();
        held.tables()
            .extents()
            .release(
                live.records()[first.slot_index()].locator(),
                super::extent::HeldPhase::Retired,
                24,
            )
            .unwrap();
        held.release();
    }
    let ledger = storage.pool_report().unwrap().ledger.unwrap();
    assert_eq!(ledger.raw.retired, 24, "payload stays charged");
}

/// Removal, replacement and invalidation allocate nothing: a recycling
/// removal, the publication that pops the bucket back, an exact replacement,
/// present and absent invalidations, the absent and zero-try refusals, and
/// the replacement of a vacant key that inserts.
#[test]
fn ending_mappings_allocates_nothing() {
    let slot_count = 32;
    let limits = [32usize];
    let config = index_config(&limits, (1, 2), 2);
    let mut storage = storage(slot_count, &config);
    install_seam(&mut storage, one_chain);
    // Base full, one overflow bucket holding one key.
    let published: Vec<AllocationId> = (0x11..=0x1Fu8)
        .map(|n| {
            completed(&storage, key(n))
                .publish(TRIES, &mut budget())
                .unwrap()
        })
        .collect();
    let replacement: Completed<'_, TestPlatform> = completed(&storage, key(0x12));
    let popper: Completed<'_, TestPlatform> = completed(&storage, key(0x10));
    let vacant: Completed<'_, TestPlatform> = completed(&storage, key(0x20));
    let allocations = crate::instrument::allocations();
    // Recycle the overflow bucket, then pop it back.
    assert_eq!(
        storage.remove(&key(0x1F), published[14], TRIES, &mut budget()),
        Ok(RetireOutcome::Recorded)
    );
    assert_eq!(report(&storage, 0).free_overflow, 2);
    popper.publish(TRIES, &mut budget()).unwrap();
    assert_eq!(report(&storage, 0).free_overflow, 1);
    let replaced = replacement.replace(TRIES, &mut budget()).unwrap();
    assert!(replaced.replaced.is_some());
    assert!(
        storage
            .invalidate(&key(0x11), TRIES, &mut budget())
            .unwrap()
            .removed
            .is_some()
    );
    assert!(
        storage
            .invalidate(&key(0x1F), TRIES, &mut budget())
            .unwrap()
            .removed
            .is_none()
    );
    assert_eq!(
        storage.remove(&key(0x1F), published[14], TRIES, &mut budget()),
        Err(RemoveError::Absent)
    );
    assert_eq!(
        storage.invalidate(&key(0x11), 0, &mut budget()),
        Err(InvalidateError::Contended)
    );
    let (vacant, _) = vacant.replace(0, &mut budget()).err().unwrap();
    let inserted = vacant.replace(TRIES, &mut budget()).unwrap();
    assert_eq!(inserted.replaced, None);
    assert_eq!(crate::instrument::allocations(), allocations);
    assert!(candidates(&storage, &key(0x20)).contains(&inserted.id));
}

/// An invalidation hints the key's placement window beside its route's
/// summary and bucket: for an absent key, whose walk finds nothing to
/// retire, those are its only write hints.
#[test]
fn an_invalidation_hints_the_keys_placement_window() {
    let slot_count = 16;
    let limits = [8usize];
    let config = index_config(&limits, (1, 1), 1);
    let storage = storage(slot_count, &config);
    let writes = || super::prefetch::WRITE_HINTS.with(std::cell::Cell::get);
    let before = writes();
    let absent = storage
        .invalidate(&key(0x13), TRIES, &mut budget())
        .unwrap();
    assert_eq!(absent.removed, None);
    // The route's summary and both bucket lines, then the window's lines.
    assert_eq!(writes() - before, 3 + super::free::WINDOW_LINES);
}

/// Resident invalidation calls `prefetch_slot` twice and `prefetch_retirement` once to request retirement and slot-return lines before the pool gate.
#[test]
fn an_invalidation_of_a_resident_hints_its_retirement_and_return_lines() {
    let slot_count = 16;
    let limits = [8usize];
    let config = index_config(&limits, (1, 1), 1);
    let storage = storage(slot_count, &config);
    completed(&storage, key(0x13))
        .publish(TRIES, &mut budget())
        .unwrap();
    let hints = || {
        (
            super::prefetch::WRITE_HINTS.with(std::cell::Cell::get),
            super::prefetch::READ_HINTS.with(std::cell::Cell::get),
        )
    };
    let (writes, reads) = hints();
    let present = storage
        .invalidate(&key(0x13), TRIES, &mut budget())
        .unwrap();
    assert!(present.removed.is_some());
    let (after_writes, after_reads) = hints();
    let absent_key = 3 + super::free::WINDOW_LINES;
    let (record_and_link, retirement_entries) = (2, 7);
    assert_eq!(
        after_writes - writes,
        absent_key + 2 * record_and_link + retirement_entries
    );
    assert_eq!(after_reads - reads, 1, "the tail");
}

/// An incumbent replacement calls `prefetch_slot` twice and `prefetch_retirement` once to let retirement and slot-return cache-line fetches overlap work before the pool gate; a vacant-key replacement issues three route write hints.
#[test]
fn a_replacement_hints_its_incumbents_retirement_and_return_lines() {
    let slot_count = 16;
    let limits = [8usize];
    let config = index_config(&limits, (1, 1), 1);
    let storage = storage(slot_count, &config);
    let replace = || {
        let hints = || {
            (
                super::prefetch::WRITE_HINTS.with(std::cell::Cell::get),
                super::prefetch::READ_HINTS.with(std::cell::Cell::get),
            )
        };
        let owner = completed(&storage, key(0x13));
        let (writes, reads) = hints();
        let replaced = owner.replace(TRIES, &mut budget()).unwrap().replaced;
        let (after_writes, after_reads) = hints();
        (
            replaced.is_some(),
            after_writes - writes,
            after_reads - reads,
        )
    };
    let route = 3;
    let (record_and_link, retirement_entries) = (2, 7);
    assert_eq!(replace(), (false, route, 0));
    assert_eq!(
        replace(),
        (true, route + 2 * record_and_link + retirement_entries, 1)
    );
}

/// A pending pair holds its overflow bucket: removing the bucket's only
/// visible pair beside a pending one keeps the bucket linked and off the
/// free stack, every visible key still found; once the pending pair is
/// cancelled the bucket stays linked and empty, and the next publication
/// fills it in place.
#[test]
fn a_pending_pair_keeps_its_emptied_overflow_bucket_linked() {
    let slot_count = 48;
    let limits = [32usize];
    let config = index_config(&limits, (1, 2), 2);
    let mut storage = storage(slot_count, &config);
    install_seam(&mut storage, one_chain);
    let k = |n: u8| {
        let mut k = key(0x11);
        k[1] = n;
        k
    };
    // Base holds keys 0..14 and overflow 0 holds key 14.
    let published: Vec<AllocationId> = (0..15u8)
        .map(|n| {
            completed(&storage, k(n))
                .publish(TRIES, &mut budget())
                .unwrap()
        })
        .collect();
    assert_eq!(report(&storage, 0).free_overflow, 1);
    let route = storage.route(&k(0)).unwrap();
    let index = storage.index.as_ref().unwrap();
    let shard = index.image.shard(crate::index::ShardIndex(0)).unwrap();
    let geometry = index.geometry.shards()[0];
    // SAFETY: the index mapping is live and nothing else holds the gate.
    let buckets = &unsafe { shard.tables(&index.mapping) }.buckets;
    let overflow = &buckets[geometry.base];
    assert_eq!(
        crate::index::OverflowLink::decode(buckets[route.bucket()].next()),
        Some(0)
    );
    let pending = AllocationId::new(SlotIndex(40), 1);
    assert!(overflow.reserve_pair(5, route.tag(), pending));
    let before = report(&storage, 0);
    assert_eq!(
        storage.remove(&k(14), published[14], TRIES, &mut budget()),
        Ok(RetireOutcome::Recorded)
    );
    let after = report(&storage, 0);
    assert_eq!(
        (after.visible, after.free_overflow),
        (14, before.free_overflow)
    );
    assert_eq!(
        crate::index::OverflowLink::decode(buckets[route.bucket()].next()),
        Some(0),
        "a bucket holding a pending pair was unlinked"
    );
    assert!(crate::index::is_pending(overflow.control(), 5));
    assert_eq!(candidates(&storage, &k(0)), published[..14]);
    // The removal walk skips the pending pair: its identity is absent and
    // its lane stays pending.
    let before = report(&storage, 0);
    assert_eq!(
        storage.remove(&k(0), pending, TRIES, &mut budget()),
        Err(RemoveError::Absent)
    );
    assert_eq!(report(&storage, 0), before);
    assert!(crate::index::is_pending(overflow.control(), 5));
    // Cancelled, the bucket is empty but still linked; the next key fills
    // its lowest free pair.
    assert!(overflow.cancel_pair(5));
    assert_eq!(overflow.control() & crate::index::CONTROL_MASK, 0);
    let refill = completed(&storage, k(15))
        .publish(TRIES, &mut budget())
        .unwrap();
    assert_eq!(report(&storage, 0).free_overflow, before.free_overflow);
    let mut expected = published[..14].to_vec();
    expected.push(refill);
    assert_eq!(candidates(&storage, &k(0)), expected);
}

/// A removal that empties an overflow bucket of a chain one link longer than
/// the depth bound refuses `Corrupt` and poisons the gate: the chain base,
/// o0, o1 with o1 linked to a free-stack bucket, which every reader refuses
/// at the depth bound, is not handed to the base bucket as base, o1 and the
/// free bucket, a chain within the bound that readers accept.
#[test]
fn removal_refuses_to_shorten_a_chain_past_the_depth_bound_into_one_readers_accept() {
    let config = index_config(&[64usize], (1, 1), 2);
    let mut storage = storage(96, &config);
    install_seam(&mut storage, one_chain);
    // The high nibble of byte 0 picks the chain, the low nibble varies the
    // key, byte 30 the fingerprint.
    let key = |chain: u8, n: u8| {
        let mut key = [0u8; 32];
        key[0] = chain << 4 | (n & 15);
        key[29] = chain;
        key[30] = n;
        key
    };
    let publish = |key: [u8; 32]| {
        completed(&storage, key)
            .publish(TRIES, &mut budget())
            .unwrap()
    };
    // Chain 0: fourteen keys in the base bucket, fourteen in o0, one in o1;
    // then o0 keeps one.
    let ids: Vec<AllocationId> = (0..29).map(|n| publish(key(0, n))).collect();
    for n in 14..27u8 {
        storage
            .remove(&key(0, n), ids[usize::from(n)], TRIES, &mut budget())
            .unwrap();
    }
    // Chain 1 takes a third overflow bucket and frees it again.
    let others: Vec<AllocationId> = (0..15).map(|n| publish(key(1, n))).collect();
    let index = storage.index.as_ref().unwrap();
    let base = index.geometry.shards()[0].base;
    let shard = index.image.shard(ShardIndex(0)).unwrap();
    // SAFETY: the index mapping is live.
    let buckets = unsafe { shard.buckets(&index.mapping) };
    let to_free = buckets[1].next();
    let free = base + OverflowLink::decode(to_free).unwrap();
    storage
        .remove(&key(1, 14), others[14], TRIES, &mut budget())
        .unwrap();
    assert!(OverflowLink::decode(buckets[1].next()).is_none());
    let to_o0 = buckets[0].next();
    let o0 = base + OverflowLink::decode(to_o0).unwrap();
    let o1 = base + OverflowLink::decode(buckets[o0].next()).unwrap();
    assert!(free != o0 && free != o1);
    assert!(OverflowLink::decode(buckets[free].next()).is_none());
    // One planted word: o1, the chain's last bucket, links the free bucket.
    buckets[o1].corrupt(buckets[o1].control(), to_free);
    let read = |storage: &Storage<TestPlatform>| {
        let mut reader = storage.register().unwrap();
        let mut entered = reader.enter().unwrap();
        entered
            .snapshot(&key(0, 31), RETRIES, &mut budget())
            .map(|found| found.map(<[_]>::len))
    };
    assert_eq!(read(&storage), Err(SnapshotError::Corrupt));
    let before = report(&storage, 0);
    assert_eq!(
        storage.remove(&key(0, 27), ids[27], TRIES, &mut budget()),
        Err(RemoveError::Corrupt),
        "a removal shortened a chain past the depth bound into one through a free bucket"
    );
    assert_eq!(report(&storage, 0), before);
    assert_eq!(buckets[0].next(), to_o0);
    assert_eq!(read(&storage), Err(SnapshotError::Corrupt));
}

/// An overflow-bucket removal charges one visit per bucket read by either
/// the walk or the carried-chain check. With a full base bucket and one key
/// each in o0 and o1, removing either overflow key costs three visits.
#[test]
fn a_removal_pays_for_each_bucket_of_the_carried_chain_it_checks() {
    let config = index_config(&[64usize], (1, 1), 2);
    let key = |n: u8| {
        let mut key = [0u8; 32];
        key[0] = n & 15;
        key[30] = n;
        key
    };
    let chain = || {
        let mut storage = storage(96, &config);
        install_seam(&mut storage, one_chain);
        let ids: Vec<AllocationId> = (0..29)
            .map(|n| {
                completed(&storage, key(n))
                    .publish(TRIES, &mut budget())
                    .unwrap()
            })
            .collect();
        for n in 14..27u8 {
            storage
                .remove(&key(n), ids[usize::from(n)], TRIES, &mut budget())
                .unwrap();
        }
        (storage, ids)
    };
    let visits = |n: u8| {
        let (storage, ids) = chain();
        let mut paid = budget();
        storage
            .remove(&key(n), ids[usize::from(n)], TRIES, &mut paid)
            .unwrap();
        (
            paid.counters().visits,
            budget().remaining() - paid.remaining(),
        )
    };
    let (through_check, steps) = visits(27);
    let (through_walk, _) = visits(28);
    assert_eq!((through_check, through_walk), (3, 3));
    let (storage, ids) = chain();
    let before = report(&storage, 0);
    assert_eq!(
        storage.remove(&key(27), ids[27], TRIES, &mut WorkBudget::new(steps - 1)),
        Err(RemoveError::BudgetExhausted)
    );
    assert_eq!(report(&storage, 0), before);
    storage
        .remove(&key(27), ids[27], TRIES, &mut WorkBudget::new(steps))
        .unwrap();
}

/// A key the seam routes to shard 1.
const ROUTED_TO_ONE: u8 = 0x91;

/// Two enabled shards under a seam that routes keys by their first byte,
/// with one object published in shard 1.
fn two_shards() -> (Storage<TestPlatform>, Key, AllocationId) {
    let limits = [4usize, 4];
    let config = index_config(&limits, (1, 1), 1);
    let mut storage = storage(12, &config);
    install_seam(&mut storage, by_first_byte);
    let key = key(ROUTED_TO_ONE);
    let id = completed(&storage, key)
        .publish(TRIES, &mut budget())
        .unwrap();
    assert_eq!(storage.route(&key).unwrap().shard(), ShardIndex(1));
    (storage, key, id)
}

/// The gate of the shard at index `shard`.
fn gate_of(storage: &Storage<TestPlatform>, shard: usize) -> &Gate {
    let index = storage.index.as_ref().unwrap();
    // SAFETY: the index mapping is live.
    unsafe {
        index
            .image
            .shard(ShardIndex(shard))
            .unwrap()
            .gate(&index.mapping)
    }
}

/// Both shards' reports, the key's candidates and the published object's
/// reference count.
fn mappings(
    storage: &Storage<TestPlatform>,
    key: &Key,
    id: AllocationId,
) -> ([ShardReport; 2], Vec<AllocationId>, usize) {
    (
        [report(storage, 0), report(storage, 1)],
        candidates(storage, key),
        refs(storage, id),
    )
}

/// What the next try at `gate` answers; a try that takes the gate releases
/// it.
fn gate_state(gate: &Gate) -> Result<(), GateError> {
    gate.try_lock().map(|guard| guard.release())
}

/// An exact removal under the caller's hold on shard 0, for a fingerprint
/// whose route names shard 1, found a malformed table: it refuses `Corrupt`
/// and poisons the gate it was given, leaves the other shard's gate open,
/// and changes no mapping.
#[test]
fn a_route_naming_another_shard_than_the_held_one_poisons_the_held_gate() {
    let (storage, key, id) = two_shards();
    let fingerprint = storage.route(&key).unwrap().fingerprint();
    let before = mappings(&storage, &key, id);
    let guard = gate_of(&storage, 0).try_lock().unwrap();
    assert_eq!(
        storage.remove_held(guard, ShardIndex(0), fingerprint, id, &mut budget()),
        Err(RemoveError::Corrupt)
    );
    assert_eq!(
        gate_state(gate_of(&storage, 0)),
        Err(GateError::Poisoned),
        "the next acquisition of the held gate finds it poisoned"
    );
    assert_eq!(gate_state(gate_of(&storage, 1)), Ok(()));
    assert_eq!(mappings(&storage, &key, id), before, "no mapping changed");
}

/// A removal told that its hold is on a shard the index has no image of
/// refuses `Corrupt` and poisons the gate it was given, and changes no
/// mapping.
#[test]
fn a_held_shard_without_an_image_poisons_the_supplied_gate() {
    let (storage, key, id) = two_shards();
    let fingerprint = storage.route(&key).unwrap().fingerprint();
    let before = mappings(&storage, &key, id);
    let guard = gate_of(&storage, 1).try_lock().unwrap();
    assert_eq!(
        storage.remove_held(guard, ShardIndex(2), fingerprint, id, &mut budget()),
        Err(RemoveError::Corrupt)
    );
    assert_eq!(gate_state(gate_of(&storage, 1)), Err(GateError::Poisoned));
    assert_eq!(gate_state(gate_of(&storage, 0)), Ok(()));
    assert_eq!(mappings(&storage, &key, id), before, "no mapping changed");
}

/// An exact removal by a storage with no index refuses `NoIndex` before it
/// reads a route, and releases the gate it was given unpoisoned. The gate is
/// a shard gate of a second, indexed storage.
#[test]
fn a_storage_without_an_index_releases_the_supplied_gate_and_refuses_no_index() {
    let (indexed, key, id) = two_shards();
    let fingerprint = indexed.route(&key).unwrap().fingerprint();
    let plain = Storage::initialize(
        &storage_config(8).validate().unwrap(),
        &PlacementConfig { control_home: 0 },
        TestPlatform::heap(PAGE),
    )
    .unwrap();
    let guard = gate_of(&indexed, 0).try_lock().unwrap();
    assert_eq!(
        plain.remove_held(guard, ShardIndex(0), fingerprint, id, &mut budget()),
        Err(RemoveError::NoIndex)
    );
    assert_eq!(
        gate_state(gate_of(&indexed, 0)),
        Ok(()),
        "released unpoisoned"
    );
}

/// A removal whose allowance cannot pay the reroute refuses
/// `BudgetExhausted` before its route is known, so it releases the held
/// gate unpoisoned and changes no mapping, where a route naming another
/// shard poisons that gate; the same removal, funded and under a hold on
/// the shard the route names, removes the pair and releases that gate.
#[test]
fn an_unfunded_reroute_releases_the_held_gate_and_the_named_shard_s_hold_removes_the_pair() {
    let (storage, key, id) = two_shards();
    let fingerprint = storage.route(&key).unwrap().fingerprint();
    let before = mappings(&storage, &key, id);
    let guard = gate_of(&storage, 0).try_lock().unwrap();
    assert_eq!(
        storage.remove_held(
            guard,
            ShardIndex(0),
            fingerprint,
            id,
            &mut WorkBudget::new(0)
        ),
        Err(RemoveError::BudgetExhausted)
    );
    assert_eq!(
        gate_state(gate_of(&storage, 0)),
        Ok(()),
        "released unpoisoned"
    );
    assert_eq!(mappings(&storage, &key, id), before);
    let guard = gate_of(&storage, 1).try_lock().unwrap();
    assert_eq!(
        storage.remove_held(guard, ShardIndex(1), fingerprint, id, &mut budget()),
        Ok(RetireOutcome::Recorded)
    );
    assert_eq!(gate_state(gate_of(&storage, 1)), Ok(()));
    assert_eq!(report(&storage, 1).visible, 0);
}
