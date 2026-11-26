//! The scalar lookup's witness and prepayment, checked against ledgers the
//! engine does not keep: the primitive observer against the budget, a
//! history of every identity offered under a key against every lease,
//! and independently counted rights against the slot counts.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Barrier, Mutex};

use super::budget::WorkBudget;
use super::lookup::{ACQUISITION, GUARD_STEPS, LookupError, Pause};
use super::lookup_tests::{
    body, key, lookup, paused, pinned, publish, ready, remove, reserved, samples, ticks,
};
use super::probe;
use super::publish_tests::{RETRIES, TRIES, budget, refs};
use super::test_platform::TestPlatform;
use super::{ExtentLease, Registration};
use crate::index::{HASH_CHARGE, Key};

/// A deadline 100 seconds into the engine's nanosecond timeline.
const DEADLINE: u64 = 100 * 1_000_000_000;

/// The prepaid scan bound of the `ready` geometry, `D = 1`: two visits and
/// `14 (1 + D) + 2` comparisons.
const BOUND: usize = 2 + 30;
/// One candidate's identity check and fingerprint comparison.
const CANDIDATE: usize = 2;
/// The credit's and the right's compare-exchange.
const RESERVE: usize = 2;
/// The whole charge of one uncontended hit on one candidate.
const HIT: usize = GUARD_STEPS + HASH_CHARGE + BOUND + CANDIDATE + ACQUISITION + RESERVE;
/// The guard bundle's deciding loads: the era, the record's pin and the
/// cutoff.
const GUARD_LOADS: usize = 3;

fn intervals(
    storage: &super::owner::Storage<TestPlatform>,
    reader: &Registration<'_, TestPlatform>,
) -> u64 {
    storage
        .registration_report(reader.index())
        .unwrap()
        .intervals
}

/// Every primitive the observer counted has a charge of its kind: loads are
/// comparisons or visits, compare-exchanges are coordination attempts,
/// stores and read-modify-writes are updates. The observer counts what the
/// call did, the budget what it charged; the call never did more.
fn charged_covers_observed(spent: &WorkBudget, observed: probe::Counts, label: &str) {
    let charged = spent.counters();
    assert!(
        observed.loads <= charged.comparisons + charged.visits,
        "{label}: {observed:?} loads over {charged:?}"
    );
    assert!(
        observed.cas <= charged.coordination_attempts,
        "{label}: {observed:?} compare-exchanges over {charged:?}"
    );
    assert!(
        observed.stores + observed.rmws <= charged.updates,
        "{label}: {observed:?} updates over {charged:?}"
    );
    assert_eq!(observed.gate_attempts(), 0, "{label}: a lookup took a gate");
}

/// Every allowance from zero to one past a hit, against one published key:
/// below the guard bundle nothing is pinned, hashed or read past the
/// administrative cutoff and the allowance is left as it was; below the
/// hash charge the pin is the only work; below the scan bound the hash is
/// paid and no bucket is read; below the acquisition's bundle the candidate
/// is compared and the rest of the allowance is left as it was; below the
/// two reservation attempts whatever was reserved comes back and no sample
/// is taken; at the hit the one sample is taken, the lease arrives with the
/// allowance spent to zero, and one unit over is left over. At every
/// allowance the observer's primitives are within the charge by kind, and
/// the pin is cleared.
#[test]
#[cfg_attr(miri, ignore = "weak compare-exchange fails spuriously under Miri")]
fn every_allowance_stops_at_a_stage_boundary_with_primitives_within_the_charge() {
    let storage = ready(8);
    let id = publish(&storage, key(0x51), DEADLINE, &body(0x51));
    let mut reader = storage.register().unwrap();
    let mut pins = 0;
    let mut taken = 0;
    for allowance in 0..=HIT + 1 {
        ticks(&storage, &[Some(1)]);
        let mut spent = WorkBudget::new(allowance);
        probe::arm();
        let outcome = reader.lookup(&key(0x51), RETRIES, &mut spent);
        probe::disarm();
        let observed = probe::counts();
        let label = format!("allowance {allowance}");
        charged_covers_observed(&spent, observed, &label);
        assert_eq!(pinned(&storage, &reader), None, "{label}");
        let paid = spent.counters();
        if allowance < GUARD_STEPS {
            // The guard bundle's preflight refuses: nothing is charged,
            // pinned or hashed, and the allowance stands.
            assert_eq!(
                outcome.as_ref().err(),
                Some(&LookupError::Contended),
                "{label}"
            );
            assert_eq!(paid, WorkBudget::new(0).counters(), "{label}");
            assert_eq!(spent.remaining(), allowance, "{label}");
            assert_eq!(observed, probe::Counts::default(), "{label}");
        } else {
            pins += 1;
            assert!(paid.comparisons >= 3 && paid.updates >= 3, "{label}");
        }
        assert_eq!(intervals(&storage, &reader), pins, "{label}");
        let after_guard = allowance.saturating_sub(GUARD_STEPS);
        if allowance >= GUARD_STEPS && after_guard < HASH_CHARGE {
            // The hash charge drained the rest; no pass ran, no bucket read.
            assert_eq!(
                outcome.as_ref().err(),
                Some(&LookupError::Contended),
                "{label}"
            );
            assert_eq!(spent.remaining(), 0, "{label}");
            assert_eq!(paid.visits, 0, "{label}");
            assert_eq!(observed.loads, GUARD_LOADS, "{label}");
        }
        let after_hash = after_guard.saturating_sub(HASH_CHARGE);
        if after_guard >= HASH_CHARGE && after_hash < BOUND {
            // The bound's preflight refused before the first sequence load,
            // leaving the rest of the allowance.
            assert_eq!(
                outcome.as_ref().err(),
                Some(&LookupError::Contended),
                "{label}"
            );
            assert_eq!(paid.hashes, HASH_CHARGE, "{label}");
            assert_eq!(paid.visits, 0, "{label}");
            assert_eq!(spent.remaining(), after_hash, "{label}");
            assert_eq!(observed.loads, GUARD_LOADS, "{label}");
        }
        let after_bound = after_hash.saturating_sub(BOUND);
        if after_hash >= BOUND && after_bound < CANDIDATE {
            // The scan runs; the candidate's checks cannot be paid. The scan
            // read the sequence twice, the chain summary and one bucket; a
            // paid identity check is one more load, recorded whether or not
            // the key's follows.
            const SCAN_LOADS: usize = 4;
            assert_eq!(
                outcome.as_ref().err(),
                Some(&LookupError::Contended),
                "{label}"
            );
            assert_eq!(paid.visits, 2, "{label}");
            assert_eq!(spent.remaining(), 0, "{label}");
            assert_eq!(paid.coordination_attempts, 0, "{label}");
            assert_eq!(
                observed.loads,
                GUARD_LOADS + SCAN_LOADS + after_bound,
                "{label}"
            );
        }
        let after_candidate = after_bound.saturating_sub(CANDIDATE);
        if after_bound >= CANDIDATE && after_candidate < ACQUISITION {
            // The acquisition's preflight refused: nothing reserved, no
            // sample, and the rest of the allowance untouched.
            assert_eq!(
                outcome.as_ref().err(),
                Some(&LookupError::Contended),
                "{label}"
            );
            assert_eq!(spent.remaining(), after_candidate, "{label}");
            assert_eq!(paid.coordination_attempts, 0, "{label}");
            assert_eq!(observed.rmws, 0, "{label}");
        }
        let after_reserve = after_candidate.saturating_sub(ACQUISITION);
        if after_candidate >= ACQUISITION && after_reserve < RESERVE {
            // A reservation attempt could not be paid: a credit reserved
            // before the right's attempt came back, one read-modify-write
            // for one paid attempt, and no sample was taken since a budget
            // refusal is not a limit.
            assert_eq!(
                outcome.as_ref().err(),
                Some(&LookupError::Contended),
                "{label}"
            );
            assert_eq!(spent.remaining(), 0, "{label}");
            assert_eq!(paid.coordination_attempts, after_reserve, "{label}");
            assert_eq!(observed.rmws, after_reserve, "{label}");
        }
        if after_reserve >= RESERVE {
            let lease = outcome.unwrap_or_else(|error| panic!("{label}: {error:?}"));
            taken += 1;
            assert_eq!(lease.id(), id, "{label}");
            assert_eq!(spent.remaining(), allowance - HIT, "{label}");
            assert_eq!(refs(&storage, id), 2, "{label}");
            drop(lease);
        }
        assert_eq!(samples(&storage), taken, "{label}");
        assert_eq!(refs(&storage, id), 1, "{label}");
        assert_eq!(reserved(&storage), 0, "{label}");
    }
    assert_eq!(taken, samples(&storage));
}

/// A failed reservation compare-exchange is charged like a successful one:
/// the observer's compare-exchange count, plus the one unconditional
/// subtract that takes a credit idle in the record, equals the coordination
/// attempts charged, on the uncontended hit and when a right is stolen once.
#[test]
#[cfg_attr(miri, ignore = "weak compare-exchange fails spuriously under Miri")]
fn failed_reservation_attempts_are_charged_one_for_one() {
    fn steal(slot_word: &std::sync::atomic::AtomicU64) {
        slot_word.fetch_add(super::word::REF, Ordering::Relaxed);
    }
    let storage = ready(8);
    ticks(&storage, &[Some(1)]);
    let id = publish(&storage, key(0x52), DEADLINE, &body(0x52));
    let mut reader = storage.register().unwrap();
    for stolen in [false, true] {
        if stolen {
            super::lease::INTERPOSE_BEFORE_RETAIN.with(|hook| hook.set(Some(steal)));
        }
        let mut spent = budget();
        probe::arm();
        let lease = reader.lookup(&key(0x52), RETRIES, &mut spent).unwrap();
        probe::disarm();
        let observed = probe::counts();
        charged_covers_observed(&spent, observed, "hit");
        // The first lookup borrows its credit with a compare-exchange on the
        // engine-wide counter; the second takes one of the borrowed credits
        // idle in the record with one subtract.
        let from_record = usize::from(stolen);
        assert_eq!(
            observed.cas + from_record,
            spent.counters().coordination_attempts
        );
        // The credit, the right, and the retry of a stolen right.
        assert_eq!(
            spent.counters().coordination_attempts,
            2 + usize::from(stolen)
        );
        drop(lease);
        if stolen {
            let pool = storage.live_pool().unwrap();
            pool.set_refs(id.slot_index(), pool.refs(id.slot_index()) - 1);
        }
        assert_eq!(refs(&storage, id), 1);
    }
}

/// Absence is confirmed only under an unchanged, open copy. With the search
/// complete and the bracket pending: a close yields `Closed`; a publication
/// of the key moves the sequence, and a second attempt finds the new object
/// while a single attempt is `Contended`; a removal of another key on the
/// same chain moves the sequence too, and the second attempt confirms the
/// absence the first could not.
#[test]
fn absence_is_confirmed_only_under_an_unchanged_open_copy() {
    // Close between the search and the bracket.
    let storage = ready(8);
    ticks(&storage, &[Some(1)]);
    let mut reader = storage.register().unwrap();
    let outcome = paused(
        &storage,
        Pause::Missing,
        |storage| storage.close(),
        || lookup(&mut reader, &key(0x53), 2).err(),
    );
    assert_eq!(outcome, Some(LookupError::Closed));
    assert_eq!(pinned(&storage, &reader), None);

    // The key arrives between the search and the bracket.
    let storage = ready(8);
    ticks(&storage, &[Some(1), Some(1)]);
    let mut reader = storage.register().unwrap();
    let published = std::sync::OnceLock::new();
    let lease = paused(
        &storage,
        Pause::Missing,
        |storage| {
            let id = publish(storage, key(0x54), DEADLINE, &body(0x54));
            published.set(id).unwrap();
        },
        || lookup(&mut reader, &key(0x54), 2).unwrap(),
    );
    assert_eq!(Some(&lease.id()), published.get());
    drop(lease);
    remove_all(&storage, key(0x54));
    let outcome = paused(
        &storage,
        Pause::Missing,
        |storage| {
            publish(storage, key(0x54), DEADLINE, &body(0x54));
        },
        || lookup(&mut reader, &key(0x54), 1).err(),
    );
    assert_eq!(outcome, Some(LookupError::Contended));

    // Another key of the same chain is removed between the search and the
    // bracket: the copy is stale, the attempt is spent, the next confirms.
    let storage = ready(8);
    ticks(&storage, &[Some(1)]);
    let mut storage = storage;
    super::publish_tests::install_seam(&mut storage, super::publish_tests::one_chain);
    let other = publish(&storage, key(0x55), DEADLINE, &body(0x55));
    let mut reader = storage.register().unwrap();
    let mut spent = budget();
    let outcome = paused(
        &storage,
        Pause::Missing,
        |storage| remove(storage, &key(0x55), other),
        || reader.lookup(&key(0x56), 2, &mut spent).err(),
    );
    assert_eq!(outcome, Some(LookupError::Missing));
    // The guard bundle's three checks, then two attempts, each with its
    // prepaid bound and the bracket that confirms absence; the first
    // compared the one candidate, the second found the chain empty.
    assert_eq!(spent.counters().visits, 2 * 2);
    assert_eq!(spent.counters().comparisons, 3 + 2 * (30 + 2) + 2);
    let outcome = paused(
        &storage,
        Pause::Missing,
        |storage| {
            publish(storage, key(0x57), DEADLINE, &body(0x57));
        },
        || lookup(&mut reader, &key(0x56), 1).err(),
    );
    assert_eq!(outcome, Some(LookupError::Contended));
    assert_eq!(reserved(&storage), 0);
}

fn remove_all(storage: &super::owner::Storage<TestPlatform>, key: Key) {
    let mut reader = storage.register().unwrap();
    let id = lookup(&mut reader, &key, RETRIES).unwrap().id();
    remove(storage, &key, id);
}

/// Readers hold every lease of a round while a writer publishes, replaces
/// and invalidates under four keys of one chain and one tag: every lease
/// names an object the writer offered under that lease's own key, by a
/// history of identities the writer keeps; between rounds the engine's reserved count equals the leases held
/// and every slot's count is the rights held on it plus an anchor of zero
/// or one.
#[test]
fn concurrent_hits_match_the_key_history_and_the_rights_ledger() {
    const ROUNDS: usize = 40;
    const READERS: usize = 2;
    let mut storage = ready(16);
    super::publish_tests::install_seam(&mut storage, super::publish_tests::one_chain);
    let storage = storage;
    ticks(&storage, &[Some(1)]);
    let keys = [key(0xA1), key(0xA2), key(0xA3), key(0xA4)];
    // Every identity offered under a key, appended before the offer, so a
    // lease's identity is in the history when it is checked; a refused offer
    // leaves an entry no lease can match.
    let history: Mutex<Vec<(Key, super::AllocationId)>> = Mutex::new(Vec::new());
    let record = |key: Key, id: super::AllocationId| history.lock().unwrap().push((key, id));
    for (n, key) in keys.iter().enumerate() {
        offer(&storage, *key, &body(0xA1 + n as u8), false, &record);
    }
    let held_count = AtomicUsize::new(0);
    let held_ids: Mutex<Vec<super::AllocationId>> = Mutex::new(Vec::new());
    let checkpoint = Barrier::new(READERS + 1);
    let released = Barrier::new(READERS + 1);
    let hits = AtomicUsize::new(0);
    // The first panic of any thread; every thread still reaches each round's
    // barriers, so a failed assertion ends the test instead of stalling it.
    let failed = Mutex::new(None);
    std::thread::scope(|scope| {
        for _ in 0..READERS {
            let (storage, history, held_count, held_ids, checkpoint, released, hits, failed) = (
                &storage,
                &history,
                &held_count,
                &held_ids,
                &checkpoint,
                &released,
                &hits,
                &failed,
            );
            scope.spawn(move || {
                let mut reader = storage.register().unwrap();
                for _ in 0..ROUNDS {
                    let mut held: Vec<ExtentLease<'_, TestPlatform>> = Vec::new();
                    guarded(failed, || {
                        for key in &keys {
                            match reader.lookup(key, 4, &mut budget()) {
                                Ok(lease) => {
                                    let known = history
                                        .lock()
                                        .unwrap()
                                        .iter()
                                        .any(|(k, id)| k == key && *id == lease.id());
                                    assert!(
                                        known,
                                        "a lease on an object never published under its key"
                                    );
                                    hits.fetch_add(1, Ordering::Relaxed);
                                    held_count.fetch_add(1, Ordering::Relaxed);
                                    held_ids.lock().unwrap().push(lease.id());
                                    held.push(lease);
                                }
                                Err(
                                    LookupError::Missing
                                    | LookupError::Contended
                                    | LookupError::Closed
                                    | LookupError::LeaseLimit
                                    | LookupError::RetainLimit,
                                ) => {}
                                Err(error) => panic!("{error:?}"),
                            }
                        }
                    });
                    checkpoint.wait();
                    released.wait();
                    for lease in held.drain(..) {
                        held_count.fetch_sub(1, Ordering::Relaxed);
                        drop(lease);
                    }
                }
            });
        }
        for round in 0..ROUNDS {
            guarded(&failed, || {
                for (n, key) in keys.iter().enumerate() {
                    let turn = (round + n) % 4;
                    if turn == 0 {
                        let _ = storage.invalidate(key, TRIES, &mut budget());
                    } else if turn == 1 {
                        let body = vec![0xB0 + round as u8; 20 + n];
                        offer(&storage, *key, &body, false, &record);
                    } else if turn == 2 {
                        let body = vec![0xC0 + round as u8; 20 + n];
                        offer(&storage, *key, &body, true, &record);
                    }
                    let _ = storage.certify(&mut WorkBudget::new(400));
                    let _ = storage.service(&mut WorkBudget::new(400));
                }
            });
            checkpoint.wait();
            // Quiescent: the readers hold their leases and the writer is
            // here. The engine's reserved count is the leases held, and each
            // slot's count is its held rights plus at most one anchor.
            guarded(&failed, || {
                let held = held_count.load(Ordering::SeqCst);
                assert_eq!(reserved(&storage), held, "round {round}");
                let ids = std::mem::take(&mut *held_ids.lock().unwrap());
                assert_eq!(ids.len(), held, "round {round}");
                let pool = storage.live_pool().unwrap();
                for slot in 0..16 {
                    let rights = ids.iter().filter(|id| id.slot_index() == slot).count();
                    let count = pool.refs(slot);
                    assert!(
                        count == rights || count == rights + 1,
                        "round {round}: slot {slot} counts {count} with {rights} rights held"
                    );
                }
            });
            released.wait();
        }
    });
    if let Some(panic) = failed.into_inner().unwrap() {
        std::panic::resume_unwind(panic);
    }
    assert!(hits.load(Ordering::Relaxed) > 0);
    assert_eq!(reserved(&storage), 0);
    let pool = storage.live_pool().unwrap();
    for slot in 0..16 {
        let count = pool.refs(slot);
        assert!(count <= 1, "slot {slot} holds {count}");
    }
}

/// Runs `step`, keeping the first panic of the test in `failed` instead of
/// unwinding, so the caller still reaches its round's barriers.
fn guarded(failed: &Mutex<Option<Box<dyn std::any::Any + Send>>>, step: impl FnOnce()) {
    if let Err(panic) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(step)) {
        failed.lock().unwrap().get_or_insert(panic);
    }
}

/// Offers `body` under `key`, as a replacement when `replace` is set and as
/// a publication otherwise, after passing the reservation's identity to
/// `record`, so the history holds every identity a reader can see; a
/// refused offer returns its allocation.
fn offer(
    storage: &super::owner::Storage<TestPlatform>,
    key: Key,
    body: &[u8],
    replace: bool,
    record: &impl Fn(Key, super::AllocationId),
) {
    let Ok(mut allocation) = storage.reserve(Some(4), Some(body.len()), &mut budget()) else {
        return;
    };
    record(key, allocation.id());
    allocation.mark_written();
    let Ok(owner) = allocation.complete(key, DEADLINE, &mut budget()) else {
        return;
    };
    let refused = if replace {
        owner.replace(TRIES, &mut budget()).err()
    } else {
        owner.publish(TRIES, &mut budget()).err()
    };
    if let Some((owner, _)) = refused {
        let _ = storage.return_allocation(owner.release(), &mut budget());
    }
}
