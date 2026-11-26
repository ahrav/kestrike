//! SIEVE selection, exact-identity commit and the eviction mark, against a
//! hand-derived SIEVE oracle and through the public storage surface plus
//! the internal eviction step.
//!
//! The oracle keeps one domain's members newest first, their visited bits
//! and the hand, and evicts as SIEVE does with retention: a retained member
//! keeps its bit and its place. Victim sequences must match the engine's
//! exactly; three broken oracles, one that resets the hand to the tail when
//! the hand's member leaves, one that clears a retained member's bit and one
//! that credits a failed, expired or detached join with a hit, must
//! disagree with the engine on the histories built to tell them apart.
//!
//! Joined reads replay through a fill a follower joined: a successful join
//! records one hit on the incarnation it read, the replacement the fill
//! published; a failed, expired or detached join records none.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Barrier};

use super::budget::WorkBudget;
use super::config::StorageConfig;
use super::evict::{
    COMMIT_TRIES, Commit, EvictError, EvictReport, INTERPOSE_BEFORE_COMMIT, SELECT_CONTROLS,
    SELECT_MIN, SELECT_PER_VISIT,
};
use super::gate::GateError;
use super::lookup_tests::hit_key;
use super::lookup_tests::{body, key, lookup};
use super::owner::Storage;
use super::policy::{Node, POLICY_NONE, PolicySlot, check_domain, check_in_flight_units};
use super::probe::{self, Event};
use super::publish_tests::{PAGE, RETRIES, index_config, storage_config, storage_from};
use super::remove::RemoveError;
use super::tables::{SlotIndex, SlotState};
use super::test_platform::TestPlatform;
use super::word::{DETACHED, EVICTED, LINKED};
use super::{AllocationId, ExtentLease, RetireOutcome};
use crate::index::IndexConfig;

const DEADLINE: u64 = u64::MAX;

/// An indexed storage with `slots` slots and as many visible keys, two fill
/// records and the clock at 1.
pub(super) fn ready(slots: usize) -> Storage<TestPlatform> {
    let slot_count = slots;
    let limits = [slots];
    let fills = [2usize];
    let index = IndexConfig {
        fills: &fills,
        ..index_config(&limits, (1, 1), 1)
    };
    let config = StorageConfig {
        lease_limit: 64,
        ..storage_config(slot_count)
    };
    let storage = storage_from(&config, &index, TestPlatform::heap(PAGE));
    storage.platform.ticks(&[Some(1)]);
    storage
}

fn publish(storage: &Storage<TestPlatform>, n: u8) -> usize {
    super::lookup_tests::publish(storage, key(n), DEADLINE, &body(n)).slot_index()
}

pub(super) fn generous() -> WorkBudget {
    WorkBudget::new(1 << 16)
}

fn evict(storage: &Storage<TestPlatform>) -> EvictReport {
    storage.evict_step(&mut generous(), |_, _| true).unwrap()
}

fn victim(report: &EvictReport) -> Option<usize> {
    match report.commit {
        Some(Commit::Evicted { victim, .. }) => Some(victim.slot_index()),
        _ => None,
    }
}

/// The domain's members head to tail, its hand and counts, after checking
/// its structure.
fn domain(storage: &Storage<TestPlatform>) -> (Vec<usize>, u32, u32, u32) {
    let live = storage.live_pool().unwrap();
    let mut access = live.lock().unwrap();
    let mut tables = access.tables();
    let nodes = tables.queue().nodes();
    let d = *tables.domain;
    let in_domain = |slot: usize| {
        matches!(
            live.gate_state(slot).0,
            SlotState::Resident | SlotState::Retired
        )
    };
    check_domain(&nodes, &d, in_domain);
    check_in_flight_units(&nodes, &d, in_domain, |slot| {
        u64::from(tables.held_units(slot))
    });
    (tables.queue().members(), d.hand, d.detached, d.in_flight)
}

fn node(storage: &Storage<TestPlatform>, slot: usize) -> Node {
    let live = storage.live_pool().unwrap();
    live.lock().unwrap().tables().queue().nodes()[slot]
}

pub(super) fn drain(storage: &Storage<TestPlatform>) {
    for _ in 0..4 {
        let _ = storage.certify(&mut generous()).unwrap();
        storage.service(&mut generous()).unwrap();
    }
}

/// A follower of `n`'s fill, joined within no follower limit.
fn join(storage: &Storage<TestPlatform>, n: u8) -> super::FillFollower<'_, TestPlatform> {
    storage
        .join_fill(&key(n), u64::MAX, RETRIES, &mut generous())
        .unwrap()
}

/// Every slot's hint, by hits: one lookup, the lease dropped at once.
fn hit(storage: &Storage<TestPlatform>, n: u8) {
    let mut reader = storage.register().unwrap();
    drop(lookup(&mut reader, &key(n), RETRIES).unwrap());
}

/// Sieve models retention-aware SIEVE within one domain with three
/// switchable faults.
#[derive(Clone)]
struct Sieve {
    list: Vec<usize>,
    visited: BTreeSet<usize>,
    hand: Option<usize>,
    /// Fault: the hand's member leaving resets the hand to the tail.
    reset_hand: bool,
    /// Fault: a retained member's bit is cleared.
    clear_retained: bool,
    /// Fault: a join that ends without reading credits the key's object.
    credit_failed: bool,
    /// Visits, visited-bit clears and visits to retained members during the
    /// last `evict` call.
    counts: (usize, usize, usize),
}

impl Sieve {
    fn new() -> Self {
        Self {
            list: Vec::new(),
            visited: BTreeSet::new(),
            hand: None,
            reset_hand: false,
            clear_retained: false,
            credit_failed: false,
            counts: (0, 0, 0),
        }
    }

    fn insert(&mut self, slot: usize) {
        self.list.insert(0, slot);
        self.visited.remove(&slot);
    }

    fn hit(&mut self, slot: usize) {
        self.visited.insert(slot);
    }

    /// A join of a key whose object sits in `slot`, if any, that ended
    /// without reading: no hit, except under the fault.
    fn unread_join(&mut self, slot: Option<usize>) {
        if self.credit_failed
            && let Some(slot) = slot
        {
            self.hit(slot);
        }
    }

    /// A replacement of `old`, if any, by `new`.
    fn replace(&mut self, old: Option<usize>, new: usize) {
        if let Some(old) = old {
            self.remove(old);
        }
        self.insert(new);
    }

    fn head_side(&self, slot: usize) -> Option<usize> {
        let at = self.list.iter().position(|&s| s == slot).unwrap();
        at.checked_sub(1).map(|at| self.list[at])
    }

    fn remove(&mut self, slot: usize) {
        if self.hand == Some(slot) {
            self.hand = if self.reset_hand {
                None
            } else {
                self.head_side(slot)
            };
        }
        self.list.retain(|&s| s != slot);
        self.visited.remove(&slot);
    }

    fn evict(&mut self, retained: &BTreeSet<usize>) -> Option<usize> {
        self.counts = (0, 0, 0);
        let tail = *self.list.last()?;
        let pass = self.list.len();
        let mut at = self.hand.unwrap_or(tail);
        let (mut in_pass, mut passes, mut cleared) = (0, 0, false);
        loop {
            in_pass += 1;
            self.counts.0 += 1;
            let next = self.head_side(at).unwrap_or(tail);
            if retained.contains(&at) {
                self.counts.2 += 1;
                if self.clear_retained {
                    self.visited.remove(&at);
                }
            } else if self.visited.remove(&at) {
                self.counts.1 += 1;
                cleared = true;
            } else {
                self.hand = self.head_side(at);
                self.list.retain(|&s| s != at);
                return Some(at);
            }
            at = next;
            if in_pass == pass {
                passes += 1;
                in_pass = 0;
                if passes == 2 || !cleared {
                    self.hand = Some(at);
                    return None;
                }
                cleared = false;
            }
        }
    }
}

/// One history step, applied to the engine and the oracles alike.
#[derive(Clone, Copy, Debug)]
enum Op {
    Publish(u8),
    Hit(u8),
    /// Take a lease on a key and keep it: its member is retained.
    Hold(u8),
    Release(u8),
    Invalidate(u8),
    Evict,
    /// Certification and service: retired extents return and slots reuse.
    Drain,
    /// A fill of the key with a follower joined publishes, replacing any
    /// object of the key, and the follower reads the version: one hit.
    JoinRead(u8),
    /// A fill of the key with a follower joined fails: no hit.
    JoinFailed(u8),
    /// A fill of the key with a follower joined publishes and the follower
    /// finds the version expired: a replacement and no hit.
    JoinExpired(u8),
    /// A fill of the key with a follower joined publishes and the follower
    /// detaches unread, as its own deadline or a cancellation ends it: a
    /// replacement and no hit.
    JoinDetached(u8),
}

/// Runs `ops` on a fresh storage and on the oracle, returning the engine's
/// victims, which are asserted equal to the oracle's at every eviction,
/// and each faulty oracle's victims.
/// Victim sequences: one entry per eviction, `None` for no victim.
type Victims = Vec<Option<usize>>;

/// An op that does not apply to the current state (publishing a published
/// key, hitting, holding or invalidating an absent one, releasing an unheld
/// one, holding a held one) is skipped on both sides, so generated histories
/// replay as written.
fn replay(ops: &[Op]) -> [Victims; 4] {
    replay_planted(ops, false).0
}

/// The engine's victims of [`replay`] as the keys they held, which compare
/// across storages whose keyed slot placement differs.
fn victim_keys(ops: &[Op]) -> Vec<Option<u8>> {
    replay_planted(ops, false).1
}

/// [`replay`], with the engine side planting a hit on the key's object at
/// every failed join when `plant` is set.
fn replay_planted(ops: &[Op], plant: bool) -> ([Victims; 4], Vec<Option<u8>>) {
    let storage = ready(32);
    let buffers = super::volume_fixture::arena_with(4, 5);
    let mut dev = super::volume_fixture::Device::new(&storage, &buffers);
    let mut reader = storage.register().unwrap();
    let mut slot_of: BTreeMap<u8, usize> = BTreeMap::new();
    let mut held: BTreeMap<u8, (ExtentLease<'_, TestPlatform>, usize)> = BTreeMap::new();
    let mut retained = BTreeSet::new();
    // The correct oracle first, then the three faulty ones, each fed every
    // step alike.
    let mut sieves = [
        Sieve::new(),
        Sieve {
            reset_hand: true,
            ..Sieve::new()
        },
        Sieve {
            clear_retained: true,
            ..Sieve::new()
        },
        Sieve {
            credit_failed: true,
            ..Sieve::new()
        },
    ];
    let mut victims: [Victims; 4] = Default::default();
    let mut keys = Vec::new();
    for &op in ops {
        let applies = match op {
            Op::Publish(n) => !slot_of.contains_key(&n),
            Op::Hit(n) | Op::Invalidate(n) => slot_of.contains_key(&n),
            Op::Hold(n) => slot_of.contains_key(&n) && !held.contains_key(&n),
            Op::Release(n) => held.contains_key(&n),
            Op::Evict | Op::Drain => true,
            Op::JoinRead(_) | Op::JoinFailed(_) | Op::JoinExpired(_) | Op::JoinDetached(_) => true,
        };
        if !applies {
            continue;
        }
        match op {
            Op::Publish(n) => {
                let slot = publish(&storage, n);
                slot_of.insert(n, slot);
                for sieve in &mut sieves {
                    sieve.insert(slot);
                }
            }
            Op::Hit(n) => {
                drop(lookup(&mut reader, &key(n), RETRIES).unwrap());
                for sieve in &mut sieves {
                    sieve.hit(slot_of[&n]);
                }
            }
            Op::Hold(n) => {
                let lease = lookup(&mut reader, &key(n), RETRIES).unwrap();
                held.insert(n, (lease, slot_of[&n]));
                retained.insert(slot_of[&n]);
                for sieve in &mut sieves {
                    sieve.hit(slot_of[&n]);
                }
            }
            Op::Release(n) => {
                let (lease, slot) = held.remove(&n).unwrap();
                drop(lease);
                retained.remove(&slot);
            }
            Op::Invalidate(n) => {
                let removed = super::attempt_tests::invalidate(&storage, &key(n)).unwrap();
                assert!(removed.removed.is_some());
                for sieve in &mut sieves {
                    sieve.remove(slot_of[&n]);
                }
                slot_of.remove(&n);
            }
            Op::Evict => {
                let report = evict(&storage);
                let engine = victim(&report);
                let expected = sieves[0].evict(&retained);
                assert_eq!(engine, expected, "after {op:?} in {ops:?}");
                assert_eq!(
                    (report.visited, report.cleared, report.held),
                    sieves[0].counts,
                    "visits, clears and retained members after {op:?} in {ops:?}"
                );
                if sieves[0].list.is_empty() && engine.is_none() {
                    assert!(
                        !report.blocked_by_readers_or_io,
                        "an empty domain with room"
                    );
                }
                keys.push(
                    slot_of
                        .iter()
                        .find(|(_, slot)| Some(**slot) == engine)
                        .map(|(&n, _)| n),
                );
                slot_of.retain(|_, slot| Some(*slot) != engine);
                victims[0].push(engine);
                for (faulty, sieve) in victims[1..].iter_mut().zip(&mut sieves[1..]) {
                    faulty.push(sieve.evict(&retained));
                }
            }
            Op::Drain => {
                dev.persist_journal();
                drain(&storage);
            }
            Op::JoinFailed(n) => {
                // A reservation the volume's capacity refuses applies to
                // neither side.
                let Ok(fill) = super::publication_tests::reserved(&storage, &key(n), &body(n))
                else {
                    super::attempt_tests::service(&storage);
                    continue;
                };
                let follower = join(&storage, n);
                fill.fail(super::FillFailure::DeviceError);
                let (_, error) = follower.acquire(RETRIES, &mut generous()).unwrap_err();
                assert_eq!(
                    error,
                    super::JoinedReadError::Failed(super::FillFailure::DeviceError)
                );
                if plant && slot_of.contains_key(&n) {
                    hit(&storage, n);
                }
                super::attempt_tests::service(&storage);
                for sieve in &mut sieves {
                    sieve.unread_join(slot_of.get(&n).copied());
                }
            }
            Op::JoinRead(n) | Op::JoinExpired(n) | Op::JoinDetached(n) => {
                let Ok(mut fill) = super::publication_tests::reserved(&storage, &key(n), &body(n))
                else {
                    super::attempt_tests::service(&storage);
                    continue;
                };
                dev.fill(
                    &mut fill,
                    &super::publication_tests::payload(&key(n), &body(n)),
                );
                let follower = join(&storage, n);
                let deadline = if matches!(op, Op::JoinExpired(_)) {
                    5 * super::publication_tests::SECOND
                } else {
                    DEADLINE
                };
                let new = fill
                    .publish(&mut dev.volume, deadline, RETRIES, &mut generous())
                    .unwrap()
                    .id()
                    .slot_index();
                let old = slot_of.insert(n, new);
                for sieve in &mut sieves {
                    sieve.replace(old, new);
                }
                match op {
                    Op::JoinRead(_) => {
                        let lease = follower.acquire(RETRIES, &mut generous()).unwrap();
                        assert_eq!(lease.id().slot_index(), new);
                        drop(lease);
                        for sieve in &mut sieves {
                            sieve.hit(new);
                        }
                    }
                    Op::JoinExpired(_) => {
                        storage
                            .platform
                            .ticks(&[Some(6 * super::publication_tests::SECOND)]);
                        let (_, error) = follower.acquire(RETRIES, &mut generous()).unwrap_err();
                        assert_eq!(error, super::JoinedReadError::Expired);
                        storage.platform.ticks(&[Some(1)]);
                        for sieve in &mut sieves {
                            sieve.unread_join(Some(new));
                        }
                    }
                    _ => {
                        follower.detach();
                        for sieve in &mut sieves {
                            sieve.unread_join(Some(new));
                        }
                    }
                }
                super::attempt_tests::service(&storage);
            }
        }
        // The domain equals the oracle's list after every step, and the
        // hand names what the oracle's does.
        let (members, hand, _, _) = domain(&storage);
        assert_eq!(members, sieves[0].list, "after {op:?}");
        let expected_hand = sieves[0].hand.map_or(POLICY_NONE, |slot| slot as u32);
        assert_eq!(hand, expected_hand, "hand after {op:?}");
    }
    drop(held);
    (victims, keys)
}

/// Hand-derived victim sequences: empty, single, wrap, all visited, sizes
/// one and two under repeated hits, unlink of the hand's slot, head and tail
/// mid-lap, a retained member released between calls, and a bind at the
/// head between calls. The engine matches the oracle at every eviction, and
/// the explicit sequences pin the oracle itself.
#[test]
fn victim_sequences_match_the_sieve_oracle() {
    use Op::*;
    // Publishing 1..=4 in order gives slots 0..=3 on a fresh storage.
    let slots = |ns: &[u8]| ns.iter().map(|&n| Some(n as usize - 1)).collect::<Vec<_>>();
    let cases: Vec<(&str, Vec<Op>, Victims)> = vec![
        ("empty", vec![Evict], vec![None]),
        (
            "single",
            vec![Publish(1), Evict, Evict],
            vec![Some(0), None],
        ),
        (
            "wrap",
            vec![
                Publish(1),
                Publish(2),
                Publish(3),
                Publish(4),
                Hit(1),
                Hit(3),
                Evict,
                Evict,
                Evict,
                Evict,
            ],
            slots(&[2, 4, 1, 3]),
        ),
        (
            "all visited",
            vec![
                Publish(1),
                Publish(2),
                Publish(3),
                Hit(1),
                Hit(2),
                Hit(3),
                Evict,
            ],
            slots(&[1]),
        ),
        (
            "size one, repeated hits",
            vec![Publish(1), Hit(1), Hit(1), Evict],
            slots(&[1]),
        ),
        (
            "size two, repeated hits",
            vec![
                Publish(1),
                Publish(2),
                Hit(1),
                Hit(2),
                Hit(1),
                Evict,
                Hit(2),
                Evict,
            ],
            slots(&[1, 2]),
        ),
        (
            "unlink of the hand's slot",
            vec![
                Publish(1),
                Publish(2),
                Publish(3),
                Publish(4),
                Hit(1),
                Evict,
                Invalidate(3),
                Evict,
            ],
            slots(&[2, 4]),
        ),
        (
            "head and tail mid-lap",
            vec![
                Publish(1),
                Publish(2),
                Publish(3),
                Publish(4),
                Hit(1),
                Hit(2),
                Hit(3),
                Hit(4),
                Evict,
                Publish(5),
                Invalidate(4),
                Invalidate(2),
                Evict,
            ],
            slots(&[1, 3]),
        ),
        (
            "retained released between calls",
            vec![
                Publish(1),
                Publish(2),
                Publish(3),
                Hold(1),
                Evict,
                Release(1),
                Evict,
                Evict,
            ],
            slots(&[2, 3, 1]),
        ),
        (
            "bind at the head between calls",
            vec![
                Publish(1),
                Publish(2),
                Hit(1),
                Evict,
                Publish(3),
                Evict,
                Evict,
            ],
            slots(&[2, 1, 3]),
        ),
    ];
    for (name, ops, expected) in cases {
        let [engine, _, _, _] = replay(&ops);
        assert_eq!(engine, expected, "{name}");
    }
}

/// Differential replay: generated histories over publication, hits,
/// invalidation and service, without leases and with held leases, replay on the engine
/// and the oracle with identical victims and identical lists and hands after
/// every step.
#[test]
fn generated_histories_replay_identically_on_the_engine_and_the_oracle() {
    for (seed, leases) in [
        (0x9E37_79B9u32, false),
        (0x2545_F491, false),
        (0x85EB_CA6B, true),
        (0xC2B2_AE35, true),
    ] {
        let mut seed = seed;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as usize
        };
        let ops: Vec<Op> = (0..300)
            .map(|_| {
                let n = (next() % 12) as u8 + 1;
                match next() % if leases { 7 } else { 5 } {
                    0 | 1 => Op::Publish(n),
                    2 => Op::Hit(n),
                    3 => Op::Evict,
                    4 if next() % 4 == 0 => Op::Drain,
                    4 => Op::Invalidate(n),
                    5 => Op::Hold(n),
                    _ => Op::Release(n),
                }
            })
            .collect();
        let [engine, _, _, _] = replay(&ops);
        assert!(engine.iter().filter(|v| v.is_some()).count() > 10);
    }
}

/// Joined reads train the policy exactly as the oracle says: a successful
/// join's one hit keeps its incarnation past the hand, and a failed,
/// expired or detached join leaves its object unvisited, so SIEVE evicts it
/// in insertion order, which the crediting oracle gets wrong.
#[test]
fn joined_reads_train_sieve_only_on_success() {
    use Op::*;
    for (name, ops, unread) in [
        (
            "a failed join",
            vec![Publish(1), Publish(2), JoinFailed(1), Evict],
            true,
        ),
        (
            "an expired join",
            vec![Publish(2), JoinExpired(1), Publish(3), Evict, Evict],
            true,
        ),
        (
            "a detached join",
            vec![Publish(2), JoinDetached(1), Publish(3), Evict, Evict],
            true,
        ),
        (
            "a read join",
            vec![Publish(2), JoinRead(1), Publish(3), Evict, Evict],
            false,
        ),
    ] {
        let [engine, _, _, crediting] = replay(&ops);
        assert!(engine.iter().any(Option::is_some), "{name}");
        assert_eq!(engine != crediting, unread, "{name}");
    }
    // The read join's hit keeps its version past the hand: the same history
    // with the follower detached unread evicts it second instead.
    let read = victim_keys(&[Publish(2), JoinRead(1), Publish(3), Evict, Evict]);
    let unread = victim_keys(&[Publish(2), JoinDetached(1), Publish(3), Evict, Evict]);
    assert_eq!(read, [Some(2), Some(3)], "the read version is kept");
    assert_eq!(unread, [Some(2), Some(1)], "the unread version goes second");
    // A failed join changes nothing: its key's object stays first in line.
    let engine = victim_keys(&[Publish(1), Publish(2), JoinFailed(1), Evict]);
    let control = victim_keys(&[Publish(1), Publish(2), Evict]);
    assert_eq!(engine, control, "a failed join changes nothing");
}

/// Generated histories with joins replay identically on the engine and the
/// oracle, and the crediting oracle disagrees with the engine on them.
#[test]
fn generated_histories_with_joins_replay_identically() {
    for seed in [0x1B87_3593u32, 0xCC9E_2D51] {
        let mut seed = seed;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as usize
        };
        let ops: Vec<Op> = (0..200)
            .map(|_| {
                let n = (next() % 10) as u8 + 1;
                match next() % 12 {
                    0 | 1 => Op::Publish(n),
                    2 => Op::Hit(n),
                    3 | 4 => Op::Evict,
                    5 => Op::Drain,
                    6 => Op::Invalidate(n),
                    7 => Op::JoinRead(n),
                    8 => Op::JoinFailed(n),
                    9 => Op::JoinExpired(n),
                    10 => Op::JoinDetached(n),
                    _ => Op::Hold(n),
                }
            })
            .map(|op| match op {
                Op::Hold(n) if n % 2 == 0 => Op::Release(n),
                op => op,
            })
            .collect();
        let [engine, _, _, crediting] = replay(&ops);
        assert!(engine.iter().filter(|v| v.is_some()).count() > 10);
        assert_ne!(engine, crediting, "the crediting oracle must disagree");
    }
}

/// The planted engine records a hit at a failed join, which the replay's
/// oracle comparison rejects.
#[test]
#[should_panic(expected = "after Evict in")]
fn negative_control_a_failed_join_that_records_a_hit_fails_the_oracle() {
    use Op::*;
    replay_planted(&[Publish(1), Publish(2), JoinFailed(1), Evict], true);
}

/// The hand-reset and retained-clearing oracles each disagree with the
/// engine: resetting the hand to the tail when the hand's member is
/// invalidated revisits the tail early, and clearing a retained member's bit
/// makes it the victim once released.
#[test]
fn controls_without_hand_repair_or_with_retained_clearing_disagree() {
    use Op::*;
    let hand = [
        Publish(1),
        Publish(2),
        Publish(3),
        Publish(4),
        Hit(1),
        Evict,
        Invalidate(3),
        Evict,
    ];
    let [engine, reset, _, _] = replay(&hand);
    assert_ne!(engine, reset, "a history the hand repair must decide");
    let retained = [
        Publish(1),
        Publish(2),
        Publish(3),
        Hold(1),
        Evict,
        Hit(3),
        Release(1),
        Evict,
    ];
    let [engine, _, clearing, _] = replay(&retained);
    assert_ne!(engine, clearing, "a history retained clearing must change");
}

/// All leased: one pass, every visit retained, no removal, the blocked flag,
/// at most `len` visits. All visited and anchor-only: the second pass finds
/// the candidate. All retired behind a held gate: every member is detached
/// on sighting and the full domain reports blocked with nothing removed.
#[test]
fn a_domain_without_a_candidate_reports_blocked_within_its_pass_bound() {
    let storage = ready(8);
    let mut reader = storage.register().unwrap();
    let leases: Vec<_> = (1..=3)
        .map(|n| {
            publish(&storage, n);
            lookup(&mut reader, &key(n), RETRIES).unwrap()
        })
        .collect();
    let report = evict(&storage);
    assert_eq!(report.commit, None);
    assert!(report.blocked_by_readers_or_io);
    assert_eq!((report.visited, report.held, report.cleared), (3, 3, 0));
    assert_eq!(domain(&storage).0.len(), 3);
    drop(leases);
    let report = evict(&storage);
    assert!(report.visited <= 2 * 3, "{report:?}");
    assert_eq!((report.cleared, report.visited), (3, 4));
    assert!(matches!(report.commit, Some(Commit::Evicted { .. })));
    assert!(!report.blocked_by_readers_or_io);
}

/// A walk debits one visit bundle per member it visits: three leased
/// members are visited in one pass without a candidate, and the step pays
/// the selection controls and three bundles, nothing more.
#[test]
fn a_walk_debits_one_visit_bundle_per_member_visited() {
    let storage = ready(8);
    let mut reader = storage.register().unwrap();
    let leases: Vec<_> = (1..=3)
        .map(|n| {
            publish(&storage, n);
            lookup(&mut reader, &key(n), RETRIES).unwrap()
        })
        .collect();
    let mut spent = generous();
    let report = storage.evict_step(&mut spent, |_, _| true).unwrap();
    assert_eq!((report.commit, report.visited), (None, 3));
    assert_eq!(
        generous().remaining() - spent.remaining(),
        SELECT_CONTROLS + 3 * SELECT_PER_VISIT
    );
    assert_eq!(
        (spent.counters().visits, spent.counters().comparisons),
        (3, 3 * 3)
    );
    drop(leases);
}

#[test]
fn an_allowance_ending_inside_a_run_stops_the_walk_at_its_last_funded_visit() {
    use super::word::VISITED;
    use std::sync::atomic::Ordering;
    for leased in [false, true] {
        let storage = ready(8);
        let mut reader = storage.register().unwrap();
        let slots: Vec<usize> = (1..=6).map(|n| publish(&storage, n)).collect();
        // Without `leased` every member is hit; with it the five oldest keep
        // a lease each and the newest is never looked up.
        let hits = if leased { 1..=5 } else { 1..=6 };
        let leases: Vec<_> = hits
            .map(|n| {
                let lease = lookup(&mut reader, &key(n), RETRIES).unwrap();
                leased.then_some(lease)
            })
            .collect();
        let live = storage.live_pool().unwrap();
        let visited =
            |slot: usize| live.records()[slot].ident.load(Ordering::Relaxed) & VISITED != 0;
        let funded = SELECT_CONTROLS + storage.commit_bundle() + 3 * SELECT_PER_VISIT;
        let report = storage
            .evict_step(&mut WorkBudget::new(funded), |_, _| true)
            .unwrap();
        assert_eq!(report.commit, None);
        assert!(report.budget_exhausted && !report.blocked_by_readers_or_io);
        let (cleared, held) = if leased { (0, 3) } else { (3, 0) };
        assert_eq!(
            (report.visited, report.cleared, report.held),
            (3, cleared, held)
        );
        assert_eq!(domain(&storage).1, slots[3] as u32);
        for (oldest, &slot) in slots.iter().enumerate() {
            let set = if leased { oldest < 5 } else { oldest >= 3 };
            assert_eq!(visited(slot), set, "{leased} {oldest}");
        }
        let report = evict(&storage);
        let (expected, visits, cleared, held) = if leased {
            (slots[5], 3, 0, 2)
        } else {
            (slots[0], 4, 3, 0)
        };
        assert_eq!(victim(&report), Some(expected), "{leased}");
        assert_eq!(
            (report.visited, report.cleared, report.held),
            (visits, cleared, held)
        );
        drop(leases);
    }
}

/// A domain whose members all retired while the gate was held, its readers
/// still holding them: each visit detaches one, within `2 * len` visits, the
/// list empties and nothing is removed, and the pass reports blocked. With
/// every extent of the volume retired and none usable, the next call on the
/// empty domain reports blocked from the ledger alone.
#[test]
fn a_domain_of_parked_retirements_detaches_every_member_and_reports_blocked() {
    let storage = ready(16);
    let body = vec![7u8; 100];
    let mut keys = Vec::new();
    // Every unit but the one-unit clean reserve.
    while storage.pool_report().unwrap().ledger.unwrap().raw.free != crate::storage::IO_UNIT {
        let n = keys.len() as u8 + 1;
        super::lookup_tests::publish(&storage, key(n), DEADLINE, &body);
        keys.push(key(n));
    }
    let live = storage.live_pool().unwrap();
    let mut reader = storage.register().unwrap();
    let held: Vec<_> = keys
        .iter()
        .map(|k| lookup(&mut reader, k, RETRIES).unwrap())
        .collect();
    {
        let _gate = live.lock().unwrap();
        for k in &keys {
            super::attempt_tests::invalidate(&storage, k).unwrap();
        }
    }
    let members = keys.len();
    let report = storage.evict_step(&mut generous(), |_, _| true).unwrap();
    assert_eq!(report.detached_seen, members);
    assert!(report.visited <= 2 * members);
    assert_eq!(report.commit, None);
    assert!(report.blocked_by_readers_or_io);
    let report = storage.evict_step(&mut generous(), |_, _| true).unwrap();
    assert_eq!((report.visited, report.commit), (0, None));
    assert!(
        report.blocked_by_readers_or_io,
        "usable 0 and detached extents"
    );
    drop(held);
    drain(&storage);
    let report = storage.evict_step(&mut generous(), |_, _| true).unwrap();
    assert!(!report.blocked_by_readers_or_io, "the blocks returned");
}

/// Budgets 0, 1 and one short of the minimum refuse before the gate with
/// nothing debited; exactly the minimum makes one decision, a commit, and
/// never refuses it for budget. The commit bundle is the literal
/// `HASH_CHARGE + COMMIT_TRIES + (1 + D) + 2 * 14 (1 + D) + 2 * fill_max +
/// MARK_TRY` for this fixture: `1 + 2 + 2 + 56 + 4 + 2` with `D = 1` and one
/// fill table of two records.
#[test]
fn the_minimum_allowance_commits_and_less_does_nothing() {
    let storage = ready(8);
    let slot = publish(&storage, 1);
    assert_eq!(storage.commit_bundle(), 67);
    let minimum = SELECT_MIN + storage.commit_bundle();
    for allowance in [0, 1, minimum - 1] {
        let mut spent = WorkBudget::new(allowance);
        assert_eq!(
            storage.evict_step(&mut spent, |_, _| true),
            Err(EvictError::BudgetExhausted)
        );
        assert_eq!(spent.remaining(), allowance);
        assert_eq!(spent.counters(), WorkBudget::new(0).counters());
    }
    assert_eq!(domain(&storage).0, [slot]);
    let mut exact = WorkBudget::new(minimum);
    let report = storage.evict_step(&mut exact, |_, _| true).unwrap();
    assert_eq!(victim(&report), Some(slot));
    assert_eq!(report.visited, 1);
    assert!(!report.mark_pending);
}

/// A walk that chooses nothing is charged the selection controls and one
/// visit bundle per visit, by kind: each run's visits are debited as one
/// total when it ends, and the counters and the remainder come out as
/// per-visit debits would leave them. Eviction meets three held members;
/// the expiry sweep, sampled at their deadline so the pool's bound lets it
/// run, meets the same three and every remaining slot.
#[test]
fn a_walk_is_charged_one_bundle_per_visit_by_kind() {
    let storage = ready(8);
    let mut reader = storage.register().unwrap();
    let leases: Vec<_> = (1..=3)
        .map(|n| {
            super::lookup_tests::publish(&storage, key(n), 2 * 1_000_000_000, &body(n));
            lookup(&mut reader, &key(n), RETRIES).unwrap()
        })
        .collect();
    let slots = storage.live_pool().unwrap().records().len();
    let mut evicting = generous();
    let report = storage.evict_step(&mut evicting, |_, _| true).unwrap();
    assert_eq!((report.visited, report.held, report.commit), (3, 3, None));
    let mut sweeping = generous();
    storage.platform.ticks(&[Some(2 * 1_000_000_000)]);
    let swept = storage.expire_step(&mut sweeping).unwrap();
    assert_eq!((swept.visited, swept.held, swept.commit), (slots, 3, None));
    for (budget, visited) in [(evicting, report.visited), (sweeping, swept.visited)] {
        let counters = budget.counters();
        assert_eq!(counters.coordination_attempts, 1);
        assert_eq!(counters.visits, visited);
        assert_eq!(counters.comparisons, 3 * visited);
        assert_eq!(counters.updates, SELECT_CONTROLS - 1 + visited);
        assert_eq!(
            generous().remaining() - budget.remaining(),
            SELECT_CONTROLS + visited * SELECT_PER_VISIT
        );
    }
    drop(leases);
}

/// A mid-walk budget refusal leaves the pair in place: every allowance
/// below the commit's cost refuses and the key stays visible.
#[test]
fn a_debit_refusal_mid_walk_leaves_the_pair_intact() {
    let storage = ready(8);
    let slot = publish(&storage, 1);
    let live = storage.live_pool().unwrap();
    let id = AllocationId::new(SlotIndex(slot), live.incarnation(slot));
    // Every allowance short of the whole commit refuses, the fill-table
    // scan after the found pair included, and leaves the pair visible.
    let mut allowance = 0;
    loop {
        let mut short = WorkBudget::new(allowance);
        let fingerprint = storage.route(&key(1)).unwrap().fingerprint();
        match storage.remove_exact(fingerprint, id, true, COMMIT_TRIES, &mut short) {
            Err(RemoveError::BudgetExhausted) => {
                hit(&storage, 1);
                assert_eq!(domain(&storage).0, [slot], "{allowance}");
            }
            Ok(_) => break,
            Err(other) => panic!("{allowance}: {other:?}"),
        }
        allowance += 1;
    }
    assert!(
        allowance > 4,
        "the refusals reached past the walk into the scan"
    );
    assert!(allowance <= storage.commit_bundle());
}

/// A current attempt for the victim's key refuses the commit as
/// `Replacing`: the incumbent stays visible and linked, the attempt stays
/// current, and the hand moves past it. After the attempt ends, the next lap
/// evicts it.
#[test]
fn a_replacing_key_is_refused_with_the_attempt_intact() {
    let storage = ready(8);
    let slot = publish(&storage, 1);
    let other = publish(&storage, 2);
    let attempt = super::attempt_tests::begin(&storage, &key(1)).unwrap();
    let report = evict(&storage);
    assert_eq!(report.commit, Some(Commit::Replacing));
    let records = super::attempt_tests::records(&storage);
    assert!(records.contains(&super::attempt_tests::live(attempt.serial())));
    hit(&storage, 1);
    assert_eq!(domain(&storage).0, [other, slot]);
    assert_eq!(victim(&evict(&storage)), Some(other));
    attempt.abort();
    super::attempt_tests::service(&storage);
    assert_eq!(victim(&evict(&storage)), Some(slot));
}

thread_local! {
    static STORAGE: std::cell::Cell<Option<&'static Storage<TestPlatform>>> =
        const { std::cell::Cell::new(None) };
}

/// A candidate invalidated between selection and commit is `Absent`: no
/// mutation, the `Absent` event, and the invalidation's own retirement
/// detached it once.
#[test]
fn a_stale_candidate_is_absent_and_changes_nothing() {
    let storage: &'static Storage<TestPlatform> = Box::leak(Box::new(ready(8)));
    let slot = publish(storage, 1);
    STORAGE.with(|cell| cell.set(Some(storage)));
    INTERPOSE_BEFORE_COMMIT.with(|hook| {
        hook.set(Some(|| {
            let storage = STORAGE.with(std::cell::Cell::get).unwrap();
            super::attempt_tests::invalidate(storage, &key(1)).unwrap();
        }))
    });
    probe::arm();
    let report = evict(storage);
    let events = probe::events().events;
    probe::disarm();
    assert_eq!(report.commit, Some(Commit::Absent));
    assert!(events.contains(&Event::Absent { slot }));
    let (members, _, detached, in_flight) = domain(storage);
    assert!(members.is_empty());
    assert_eq!((detached, in_flight), (1, 0));
    assert!(!report.mark_pending);
}

/// A candidate whose key was invalidated and republished under a new
/// identity between selection and commit is `Absent`: the commit matches
/// the exact identity, so the new pair stays visible and its member linked.
#[test]
fn a_candidate_replaced_before_commit_leaves_the_new_identity() {
    let storage: &'static Storage<TestPlatform> = Box::leak(Box::new(ready(8)));
    let slot = publish(storage, 1);
    STORAGE.with(|cell| cell.set(Some(storage)));
    INTERPOSE_BEFORE_COMMIT.with(|hook| {
        hook.set(Some(|| {
            let storage = STORAGE.with(std::cell::Cell::get).unwrap();
            super::attempt_tests::invalidate(storage, &key(1)).unwrap();
            publish(storage, 1);
        }))
    });
    let report = evict(storage);
    assert_eq!(report.commit, Some(Commit::Absent));
    let (members, _, _, in_flight) = domain(storage);
    assert_eq!(members.len(), 1);
    assert_ne!(members[0], slot);
    assert_eq!(in_flight, 0);
    let mut reader = storage.register().unwrap();
    let lease = lookup(&mut reader, &key(1), RETRIES).unwrap();
    assert_eq!(hit_key(&lease), key(1));
}

/// A held shard gate makes the commit `Contended`: the candidate stays
/// linked and visible, and the hand has moved past it.
#[test]
fn a_held_shard_gate_leaves_the_candidate_linked() {
    let storage = ready(8);
    let first = publish(&storage, 1);
    let second = publish(&storage, 2);
    let guard = super::attempt_tests::gate(&storage).try_lock().unwrap();
    let report = evict(&storage);
    drop(guard);
    assert_eq!(report.commit, Some(Commit::Contended));
    let (members, hand, _, _) = domain(&storage);
    assert_eq!(members, [second, first]);
    assert_eq!(hand, second as u32);
    // Revisited next lap: the hand's member first, then the refused one.
    assert_eq!(victim(&evict(&storage)), Some(second));
    assert_eq!(victim(&evict(&storage)), Some(first));
}

/// A bind at the head between the selection hold and the mark hold of one
/// call joins the list without moving the hand, and the next laps take the
/// hand's member, then the new one.
#[test]
fn a_bind_between_the_holds_of_one_call_keeps_the_hand() {
    let storage: &'static Storage<TestPlatform> = Box::leak(Box::new(ready(8)));
    let first = publish(storage, 1);
    let second = publish(storage, 2);
    STORAGE.with(|cell| cell.set(Some(storage)));
    INTERPOSE_BEFORE_COMMIT.with(|hook| {
        hook.set(Some(|| {
            let storage = STORAGE.with(std::cell::Cell::get).unwrap();
            publish(storage, 3);
        }))
    });
    assert_eq!(victim(&evict(storage)), Some(first));
    let (members, hand, _, _) = domain(storage);
    assert_eq!(members.len(), 2);
    assert_eq!(members[1], second);
    assert_eq!(hand, second as u32);
    let third = members[0];
    assert_eq!(victim(&evict(storage)), Some(second));
    assert_eq!(victim(&evict(storage)), Some(third));
}

thread_local! {
    /// The barrier a test's commit hook shares with its gate holder. Per
    /// thread, so tests running in parallel never share one.
    static BARRIER: std::cell::RefCell<Option<Arc<Barrier>>> =
        const { std::cell::RefCell::new(None) };
}

fn shared_barrier() -> Arc<Barrier> {
    BARRIER.with(|cell| cell.borrow().clone().unwrap())
}

/// Holds the pool gate on another thread from the commit until released,
/// so the victim's retirement parks and the call-end mark try fails.
pub(super) fn hold_pool_gate_during_commit(
    storage: &'static Storage<TestPlatform>,
) -> std::thread::JoinHandle<()> {
    let barrier = Arc::new(Barrier::new(2));
    BARRIER.with(|cell| *cell.borrow_mut() = Some(Arc::clone(&barrier)));
    let holder = std::thread::spawn(move || {
        barrier.wait();
        let live = storage.live_pool().unwrap();
        let guard = live.lock().unwrap();
        barrier.wait();
        barrier.wait();
        drop(guard);
    });
    INTERPOSE_BEFORE_COMMIT.with(|hook| {
        hook.set(Some(|| {
            let barrier = shared_barrier();
            barrier.wait();
            barrier.wait();
        }))
    });
    holder
}

pub(super) fn release_holder(holder: std::thread::JoinHandle<()>) {
    shared_barrier().wait();
    holder.join().unwrap();
}

/// With the pool gate busy from the commit on, the mark stays pending, the
/// next call's busy gate leaves it pending, and a free gate applies it in
/// the first hold before any selection: the victim is marked evicted and
/// counted in flight, and no second victim is chosen in that call ahead of
/// the mark. Release, return and rebind as the next incarnation before the
/// mark applies leave the new occupant unmarked and count a stale mark; the
/// new occupant's record stays resident with its retirement parked and
/// anchored, so a mark without the incarnation compare would have counted it
/// in flight. The call-end mark try is observed busy, then taken. A mark
/// left on a returned, free slot whose incarnation still matches is stale
/// too.
#[test]
fn a_pending_mark_applies_first_and_a_reused_slot_counts_it_stale() {
    let storage: &'static Storage<TestPlatform> = Box::leak(Box::new(ready(8)));
    let victim_slot = publish(storage, 1);
    let other = publish(storage, 2);
    let holder = hold_pool_gate_during_commit(storage);
    probe::arm();
    let report = evict(storage);
    let counts = probe::counts();
    probe::disarm();
    assert_eq!(victim(&report), Some(victim_slot));
    assert!(report.mark_pending);
    // The selection hold's try, then the call-end mark try found busy.
    assert_eq!((counts.gate_taken, counts.gate_busy), (1, 1));
    let live = storage.live_pool().unwrap();
    assert_eq!(
        storage.evict_step(&mut generous(), |_, _| true),
        Err(EvictError::Gate(GateError::Contended))
    );
    assert!(live.pending_mark().is_pending(), "a busy call end keeps it");
    release_holder(holder);
    // The retirement parked behind the held gate: the victim is still
    // linked until an observer sights it.
    assert_eq!(node(storage, victim_slot).state, LINKED);
    // The mark applies first: the victim leaves the list and is in flight;
    // selection then chooses the other member.
    probe::arm();
    let report = evict(storage);
    let events = probe::events().events;
    let counts = probe::counts();
    probe::disarm();
    assert_eq!((counts.gate_taken, counts.gate_busy), (1, 0));
    assert!(events.contains(&Event::Detached { slot: victim_slot }));
    // The mark detached the victim before selection: selection sighted no
    // retirement and visited only the other member.
    assert_eq!((report.detached_seen, report.visited), (0, 1));
    assert_eq!(victim(&report), Some(other));
    assert_eq!(node(storage, victim_slot).state, DETACHED | EVICTED);
    let (members, _, _, in_flight) = domain(storage);
    assert!(members.is_empty());
    assert_eq!(in_flight, 2);
    assert!(!report.mark_pending);
    drain(storage);
    let (_, _, detached, in_flight) = domain(storage);
    assert_eq!((detached, in_flight), (0, 0), "returns clear both");

    // Stale: the victim returns and its slot is reused before the mark.
    let storage: &'static Storage<TestPlatform> = Box::leak(Box::new(ready(1)));
    let slot = publish(storage, 1);
    let live = storage.live_pool().unwrap();
    let first = live.incarnation(slot);
    let holder = hold_pool_gate_during_commit(storage);
    assert_eq!(victim(&evict(storage)), Some(slot));
    release_holder(holder);
    assert!(live.pending_mark().is_pending());
    drain(storage);
    assert_eq!(publish(storage, 2), slot);
    let second = live.incarnation(slot);
    assert_ne!(first, second);
    assert_eq!(
        storage.slot_state(SlotIndex(slot)).unwrap().0,
        SlotState::Resident
    );
    // The new occupant retires behind a held gate, so it is flagged when the
    // mark applies: a mark keyed on the flag would take it for the victim.
    {
        let _gate = live.lock().unwrap();
        super::attempt_tests::invalidate(storage, &key(2)).unwrap();
    }
    probe::arm();
    let report = storage.evict_step(&mut generous(), |_, _| true).unwrap();
    let events = probe::events().events;
    probe::disarm();
    assert_eq!(report.stale_marks, 1);
    assert!(events.contains(&Event::StaleMark { slot }));
    assert_eq!(report.detached_seen, 1, "selection sighted the retirement");
    let (_, _, detached, in_flight) = domain(storage);
    assert_eq!(
        (detached, in_flight),
        (1, 0),
        "the new occupant is not marked"
    );
    assert_eq!(node(storage, slot).state, DETACHED);

    // Stale on a free slot: the victim returns and nothing rebinds before
    // the mark, so the incarnation still matches but the slot is free.
    let storage: &'static Storage<TestPlatform> = Box::leak(Box::new(ready(2)));
    let slot = publish(storage, 1);
    let live = storage.live_pool().unwrap();
    let incarnation = live.incarnation(slot);
    let holder = hold_pool_gate_during_commit(storage);
    assert_eq!(victim(&evict(storage)), Some(slot));
    release_holder(holder);
    drain(storage);
    assert!(live.pending_mark().is_pending());
    assert_eq!(
        storage.slot_state(SlotIndex(slot)).unwrap(),
        (SlotState::Free, incarnation),
        "the return keeps the incarnation, so only the state guard refuses"
    );
    let report = storage.evict_step(&mut generous(), |_, _| true).unwrap();
    assert_eq!(report.stale_marks, 1);
    assert_eq!(node(storage, slot), Node::CLEAR);
    assert_eq!(domain(storage).3, 0);
}

/// An evicted extent held by a lease acquired after selection: its bytes
/// stay readable, the mark clears once when service finds the anchor
/// released with the right remaining, and the later return changes no
/// count. `in_flight` equals the evicted count and `detached` the detached
/// count at every step.
#[test]
fn an_evicted_extent_held_by_rights_leaves_in_flight_once() {
    thread_local! {
        static LEASE: std::cell::RefCell<Option<ExtentLease<'static, TestPlatform>>> =
            const { std::cell::RefCell::new(None) };
    }
    let storage: &'static Storage<TestPlatform> = Box::leak(Box::new(ready(8)));
    let slot = publish(storage, 1);
    STORAGE.with(|cell| cell.set(Some(storage)));
    INTERPOSE_BEFORE_COMMIT.with(|hook| {
        hook.set(Some(|| {
            let storage = STORAGE.with(std::cell::Cell::get).unwrap();
            let mut reader = storage.register().unwrap();
            let lease = lookup(&mut reader, &key(1), RETRIES).unwrap();
            LEASE.with(|cell| *cell.borrow_mut() = Some(lease));
        }))
    });
    let report = evict(storage);
    assert_eq!(victim(&report), Some(slot));
    assert!(matches!(
        report.commit,
        Some(Commit::Evicted {
            retirement: RetireOutcome::Recorded,
            ..
        })
    ));
    assert_eq!(domain(storage).3, 1);
    // Before grace the anchor still counts: service holds the slot and the
    // extent stays in flight.
    assert_eq!(storage.service(&mut generous()).unwrap().held, 1);
    assert_eq!(domain(storage).3, 1);
    assert_eq!(node(storage, slot).state, DETACHED | EVICTED);
    let _ = storage.certify(&mut generous()).unwrap();
    let serviced = storage.service(&mut generous()).unwrap();
    assert_eq!(serviced.held, 1);
    let (_, _, detached, in_flight) = domain(storage);
    assert_eq!(
        (detached, in_flight),
        (1, 0),
        "held by rights, no longer in flight"
    );
    assert_eq!(node(storage, slot).state, DETACHED);
    assert_eq!(storage.service(&mut generous()).unwrap().held, 1);
    assert_eq!(domain(storage).2, 1);
    assert_eq!(domain(storage).3, 0);
    assert_eq!(node(storage, slot).state, DETACHED);
    let lease = LEASE.with(|cell| cell.borrow_mut().take()).unwrap();
    assert_eq!(hit_key(&lease), key(1), "an evicted object stays leased");
    drop(lease);
    drain(storage);
    let (_, _, detached, in_flight) = domain(storage);
    assert_eq!((detached, in_flight), (0, 0));
}

/// Four removals race on one key: eviction, invalidation, a replacing
/// publication and an expiry-style exact removal without the association
/// check. Exactly one retirement of the incumbent follows: its slot is
/// unlinked once and detached once, and the ledger's retired slots count
/// it once.
#[test]
fn a_four_way_race_on_one_key_retires_the_incumbent_once() {
    for _ in 0..50 {
        let storage = ready(8);
        let slot = publish(&storage, 1);
        let live = storage.live_pool().unwrap();
        let id = AllocationId::new(SlotIndex(slot), live.incarnation(slot));
        let barrier = Barrier::new(4);
        let outcomes = std::thread::scope(|scope| {
            let evict = scope.spawn(|| {
                barrier.wait();
                storage
                    .evict_step(&mut generous(), |_, _| true)
                    .ok()
                    .and_then(|report| report.commit)
            });
            let invalidate = scope.spawn(|| {
                barrier.wait();
                storage
                    .invalidate(&key(1), 64, &mut generous())
                    .ok()
                    .and_then(|ended| ended.removed)
            });
            let replace = scope.spawn(|| {
                barrier.wait();
                // Completion takes the pool gate with one try, so under the
                // race it may be refused; the replacement then does nothing.
                let body = body(1);
                let mut allocation = storage
                    .reserve(Some(4), Some(body.len()), &mut generous())
                    .ok()?;
                allocation.mark_written();
                let completed = allocation
                    .complete(key(1), DEADLINE, &mut generous())
                    .ok()?;
                completed.replace(64, &mut generous()).ok()
            });
            let expire = scope.spawn(|| {
                barrier.wait();
                let fingerprint = storage.route(&key(1)).unwrap().fingerprint();
                storage
                    .remove_exact(fingerprint, id, false, 64, &mut generous())
                    .map(|retirement| retirement.record())
            });
            (
                evict.join().unwrap(),
                invalidate.join().unwrap(),
                replace.join().unwrap(),
                expire.join().unwrap(),
            )
        });
        let removals =
            usize::from(matches!(outcomes.0, Some(Commit::Evicted { victim, .. }) if victim == id))
                + usize::from(outcomes.1.is_some_and(|(removed, _)| removed == id))
                + usize::from(
                    outcomes.2.is_some_and(|done| {
                        done.replaced.is_some_and(|(replaced, _)| replaced == id)
                    }),
                )
                + usize::from(outcomes.3.is_ok());
        assert_eq!(removals, 1, "{outcomes:?}");
        drain(&storage);
        let _ = storage.evict_step(&mut generous(), |_, _| true);
        drain(&storage);
        let (members, _, detached, in_flight) = domain(&storage);
        assert!(!members.contains(&slot) || live.incarnation(slot) != id.incarnation());
        assert_eq!((detached, in_flight), (0, 0));
    }
}

/// Structural: the reservation path runs no policy step, eviction takes no
/// waiting lock, and the selection hold is released before the commit takes
/// the shard gate.
#[test]
fn eviction_never_nests_gates_and_reservation_never_evicts() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/storage");
    let read = |name: &str| std::fs::read_to_string(format!("{dir}/{name}")).unwrap();
    let reserve = read("reserve.rs");
    assert!(!reserve.contains("evict") && !reserve.contains("select("));
    let evict = read("evict.rs");
    let production = &evict[..evict.find("#[cfg(test)]\nthread_local!").unwrap()];
    assert!(
        !production.contains(".lock()"),
        "a waiting lock in eviction"
    );
    let release = production.find("access.release();").unwrap();
    let commit = production.find("self.commit(").unwrap();
    assert!(release < commit, "the commit runs under the selection hold");
    let _ = SELECT_PER_VISIT;
}

/// Seeded histories over publication, hits, held leases, invalidation with
/// the pool gate free and held, funded and underfunded eviction, and
/// service: after every event `detached` equals the detached count and
/// `in_flight` the evicted count (checked by the domain snapshot), neither
/// goes negative, and a final drain with every lease gone returns both to
/// zero. The history must evict, evict under a held lease acquired later,
/// and meet a busy gate.
#[test]
fn counts_track_the_node_bits_at_every_prefix() {
    for seed in [0x2545_F491u32, 0x9E37_79B9, 0x7F4A_7C15] {
        let storage = ready(24);
        let mut reader = storage.register().unwrap();
        let mut seed = seed;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as usize
        };
        let mut published = BTreeSet::new();
        let mut leases: Vec<ExtentLease<'_, TestPlatform>> = Vec::new();
        let (mut evicted, mut busy) = (0, 0);
        let minimum = SELECT_MIN + storage.commit_bundle();
        for _ in 0..400 {
            let n = (next() % 20) as u8 + 1;
            match next() % 8 {
                0 | 1 if !published.contains(&n) => {
                    if super::lookup_tests::reserved(&storage) < 40 {
                        let body = body(n);
                        let Ok(mut allocation) =
                            storage.reserve(Some(4), Some(body.len()), &mut generous())
                        else {
                            continue;
                        };
                        allocation.mark_written();
                        let completed = allocation.complete(key(n), DEADLINE, &mut generous());
                        if let Ok(completed) = completed
                            && completed.publish(2, &mut generous()).is_ok()
                        {
                            published.insert(n);
                        }
                    }
                }
                2 if published.contains(&n) => {
                    if let Ok(lease) = lookup(&mut reader, &key(n), RETRIES)
                        && next() % 2 == 0
                        && leases.len() < 6
                    {
                        leases.push(lease);
                    }
                }
                3 if !leases.is_empty() => {
                    leases.swap_remove(next() % leases.len());
                }
                4 if !published.is_empty() => {
                    // A published key, so every invalidation ends a mapping.
                    let m = *published.iter().nth(next() % published.len()).unwrap();
                    let live = storage.live_pool().unwrap();
                    let gate = (next() % 3 == 0).then(|| live.lock().unwrap());
                    busy += usize::from(gate.is_some());
                    if super::attempt_tests::invalidate(&storage, &key(m)).is_ok() {
                        published.remove(&m);
                    }
                }
                5 | 6 => {
                    let allowance = minimum + next() % (4 * SELECT_PER_VISIT);
                    if let Ok(report) =
                        storage.evict_step(&mut WorkBudget::new(allowance), |_, _| true)
                        && let Some(Commit::Evicted { .. }) = report.commit
                    {
                        evicted += 1;
                        // The victim's key is no longer visible.
                        published.retain(|&m| lookup(&mut reader, &key(m), RETRIES).is_ok());
                    }
                }
                _ => drain(&storage),
            }
            domain(&storage);
        }
        assert!(evicted > 0 && busy > 0, "{evicted} {busy}");
        leases.clear();
        drain(&storage);
        let _ = storage.evict_step(&mut generous(), |_, _| true);
        drain(&storage);
        let (_, _, detached, in_flight) = domain(&storage);
        assert_eq!((detached, in_flight), (0, 0));
    }
}

/// A mark that applies only after service released the victim's anchor
/// while a right remains finds the extent held, not in flight: it marks
/// nothing and counts nothing, so `in_flight` never counts an extent past
/// grace.
#[test]
fn a_late_mark_after_the_anchor_release_counts_nothing_in_flight() {
    thread_local! {
        static LEASE: std::cell::RefCell<Option<ExtentLease<'static, TestPlatform>>> =
            const { std::cell::RefCell::new(None) };
    }
    let storage: &'static Storage<TestPlatform> = Box::leak(Box::new(ready(8)));
    let slot = publish(storage, 1);
    STORAGE.with(|cell| cell.set(Some(storage)));
    let barrier = Arc::new(Barrier::new(2));
    BARRIER.with(|cell| *cell.borrow_mut() = Some(Arc::clone(&barrier)));
    let holder = std::thread::spawn(move || {
        barrier.wait();
        let live = storage.live_pool().unwrap();
        let guard = live.lock().unwrap();
        barrier.wait();
        barrier.wait();
        drop(guard);
    });
    INTERPOSE_BEFORE_COMMIT.with(|hook| {
        hook.set(Some(|| {
            let storage = STORAGE.with(std::cell::Cell::get).unwrap();
            let mut reader = storage.register().unwrap();
            let lease = lookup(&mut reader, &key(1), RETRIES).unwrap();
            LEASE.with(|cell| *cell.borrow_mut() = Some(lease));
            let barrier = shared_barrier();
            barrier.wait();
            barrier.wait();
        }))
    });
    let report = evict(storage);
    assert_eq!(victim(&report), Some(slot));
    assert!(report.mark_pending);
    release_holder(holder);
    let _ = storage.certify(&mut generous()).unwrap();
    assert_eq!(storage.service(&mut generous()).unwrap().held, 1);
    let report = evict(storage);
    assert_eq!(report.stale_marks, 0);
    assert!(!report.mark_pending);
    assert_eq!(node(storage, slot).state, DETACHED);
    assert_eq!(domain(storage).3, 0, "a held extent is not in flight");
    drop(LEASE.with(|cell| cell.borrow_mut().take()));
    drain(storage);
    let (_, _, detached, in_flight) = domain(storage);
    assert_eq!((detached, in_flight), (0, 0));
}

/// The read hints after a step's last gate exchange: for the member the hand
/// names, its chain summary and both base-bucket lines, which the next
/// commit's walk reads first, and the record of the member past it when one
/// exists; nothing when the hand names no member. No write hint: a hit on
/// the member makes the next selection pass it, and a write hint would have
/// taken those lines from readers on other cores for nothing.
#[test]
fn the_step_end_hints_the_hand_members_bucket_and_the_record_past_it() {
    let storage = ready(4);
    let older = publish(&storage, 1);
    let newer = publish(&storage, 2);
    let live = storage.live_pool().unwrap();
    let hints = || {
        (
            super::prefetch::WRITE_HINTS.with(std::cell::Cell::get),
            super::prefetch::READ_HINTS.with(std::cell::Cell::get),
        )
    };
    let counted = |ahead: u32| {
        let (writes, reads) = hints();
        storage.prefetch_past_hand(live, ahead);
        let (after_writes, after_reads) = hints();
        (after_writes - writes, after_reads - reads)
    };
    // The older member's `prev` names the newer one; the newest has none.
    assert_eq!(live.records()[older].prev(), newer as u32);
    assert_eq!(counted(older as u32), (0, 4));
    assert_eq!(counted(newer as u32), (0, 3));
    assert_eq!(counted(POLICY_NONE), (0, 0));
}

/// Selection and commit both call `prefetch_retirement` for the victim. A victim with a tail-side neighbour adds one write hint for that neighbour's record, which unlink updates through `set_prev`. The step-end read hints are four when a member lies past the hand and three when the hand rests on the head.
#[test]
fn a_selection_hints_the_victims_retirement_lines_and_its_tail_side_neighbour() {
    let step = |storage: &Storage<TestPlatform>| {
        let hints = || {
            (
                super::prefetch::WRITE_HINTS.with(std::cell::Cell::get),
                super::prefetch::READ_HINTS.with(std::cell::Cell::get),
            )
        };
        let (writes, reads) = hints();
        let report = evict(storage);
        let (after_writes, after_reads) = hints();
        (victim(&report), after_writes - writes, after_reads - reads)
    };
    let (retirement_lines, retirement_entries, link, bucket) = (2, 7, 1, 3);
    let selection = retirement_lines + retirement_entries + link;
    let commit = bucket + 2 + retirement_entries;
    let tail_victim = selection + bucket + commit + 2;
    let (selection_reads, commit_reads) = (2, 1);
    let reads = |step_end: usize| selection_reads + commit_reads + step_end;
    let storage = ready(8);
    let oldest = publish(&storage, 1);
    publish(&storage, 2);
    publish(&storage, 3);
    assert_eq!(step(&storage), (Some(oldest), tail_victim, reads(4)));
    let storage = ready(8);
    publish(&storage, 1);
    let second = publish(&storage, 2);
    publish(&storage, 3);
    let mut reader = storage.register().unwrap();
    drop(lookup(&mut reader, &key(1), RETRIES).unwrap());
    assert_eq!(step(&storage), (Some(second), tail_victim + 1, reads(3)));
}

/// Members 1, 2 and 3 published in order into slots 0, 1 and 2, so slot 0,
/// the oldest, is at the hand, and each of `hits` looked up once.
fn hand_layout(hits: &[u8]) -> Storage<TestPlatform> {
    let storage = ready(8);
    let slots: Vec<usize> = (1..=3).map(|n| publish(&storage, n)).collect();
    assert_eq!(slots, [0, 1, 2]);
    for &n in hits {
        hit(&storage, n);
    }
    storage
}

/// A selection whose visit panics under the pool gate poisons it (module
/// doc, "A word with a reserved bit set panics under the gate and poisons
/// it"), on a thread that is not unwinding and from a destructor that
/// catches the panic while its thread unwinds from another: the guard, taken
/// during the unwind, would release open on drop. Slot 1 sits inside a run
/// of held members with a reserved bit set.
#[test]
fn a_reserved_bit_poisons_the_walk_even_during_unwinding() {
    use super::word::{REF, RESERVED};
    struct EvictsOnDrop<'a> {
        storage: &'a Storage<TestPlatform>,
        panicked: &'a std::cell::Cell<bool>,
    }
    impl Drop for EvictsOnDrop<'_> {
        fn drop(&mut self) {
            let storage = self.storage;
            let stepped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                storage.evict_step(&mut generous(), |_, _| true).map(|_| ())
            }));
            self.panicked.set(stepped.is_err());
        }
    }
    for unwinding in [false, true] {
        let storage = hand_layout(&[]);
        let live = storage.live_pool().unwrap();
        for slot in 0..3 {
            live.edit_word(slot, |word| word + REF);
        }
        live.edit_word(1, |word| word | 1 << RESERVED.trailing_zeros());
        let panicked = std::cell::Cell::new(false);
        if unwinding {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _evictor = EvictsOnDrop {
                    storage: &storage,
                    panicked: &panicked,
                };
                panic!("an unrelated panic with a live evictor");
            }));
            assert!(outcome.is_err());
        } else {
            drop(EvictsOnDrop {
                storage: &storage,
                panicked: &panicked,
            });
        }
        assert!(
            panicked.get(),
            "premise: the selection panicked, unwinding={unwinding}"
        );
        assert!(
            matches!(live.try_lock_quiet(), Err(GateError::Poisoned)),
            "the visit's panic poisons the gate, unwinding={unwinding}"
        );
    }
}
