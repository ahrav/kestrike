//! Batch lookup against independent expectations: every structural refusal
//! with keys and outputs byte-identical, the prepaid overhead, repeated keys,
//! mixed outcomes matched element by element against scalar lookups in the
//! same state, close and invalidation between elements, one pin per element
//! with none active when a result is stored, the scalar scratch footprint,
//! and zero allocation on every path, on the heap-backed platform.

use std::sync::{Arc, Barrier};

use super::batch::{BatchError, BatchSlot};
use super::budget::WorkBudget;
use super::free::WINDOW_LINES;
use super::lookup::{ACQUISITION, GUARD_STEPS, INTERPOSE, LookupError, Pause};
use super::lookup_tests::{hit_key, place_record, replace};
use super::lookup_tests::{paused, paused_with};
use super::owner::Storage;
use super::prefetch::{READ_HINTS, WRITE_HINTS};
use super::prepare::{DEPTH, STAGE};
use super::publish_tests::{
    BATCH_MAX, RETRIES, TRIES, budget, index_config, install_seam, refs, spread, storage,
    storage_config, storage_from,
};
use super::test_platform::TestPlatform;
use super::volume_fixture::{Device, arena};
use super::{AllocationId, Registration, RetireOutcome};
use crate::index::{DERIVATIONS, HASH_CHARGE, Key};

/// A deadline 100 seconds into the engine's nanosecond timeline.
const DEADLINE: u64 = 100 * 1_000_000_000;
const PAGE: usize = super::publish_tests::PAGE;
/// The charge of one hit on the `ready` geometry, `D = 1`: the guard bundle,
/// the hash, the prepaid chain bound of two visits and `14 (1 + D) + 2`
/// comparisons, the matching candidate's identity and fingerprint checks, the
/// acquisition's bundle and the two reservation attempts.
const HIT: usize = GUARD_STEPS + HASH_CHARGE + (2 + 30) + 2 + ACQUISITION + 2;

pub(super) fn ready() -> Storage<TestPlatform> {
    ready_wide(BATCH_MAX)
}

/// An indexed storage under the spreading seam, so each test key has its
/// own bucket and the exact charges below hold whatever the process's keyed
/// state would have placed.
fn ready_wide(batch_max: usize) -> Storage<TestPlatform> {
    let slot_count = 16;
    let limits = [16usize];
    let index = crate::index::IndexConfig {
        batch_max,
        ..index_config(&limits, (1, 1), 1)
    };
    let mut storage = storage(slot_count, &index);
    install_seam(&mut storage, spread);
    storage
}

pub(super) fn key(n: u8) -> Key {
    [n; 32]
}

fn body(n: u8) -> Vec<u8> {
    vec![n; 20 + usize::from(n % 7)]
}

pub(super) fn publish(
    storage: &Storage<TestPlatform>,
    key: Key,
    deadline: u64,
    body: &[u8],
) -> AllocationId {
    let mut allocation = storage
        .reserve(Some(4), Some(body.len()), &mut budget())
        .unwrap();
    allocation.mark_written();
    allocation
        .complete(key, deadline, &mut budget())
        .ok()
        .unwrap()
        .publish(TRIES, &mut budget())
        .unwrap()
}

fn reserved(storage: &Storage<TestPlatform>) -> usize {
    storage.lease_report().unwrap().reserved
}

fn intervals(storage: &Storage<TestPlatform>, reader: &Registration<'_, TestPlatform>) -> u64 {
    storage
        .registration_report(reader.index())
        .unwrap()
        .intervals
}

fn pinned(storage: &Storage<TestPlatform>, reader: &Registration<'_, TestPlatform>) -> Option<u64> {
    storage
        .registration_report(reader.index())
        .unwrap()
        .pinned_era
}

fn ticks(storage: &Storage<TestPlatform>, samples: &[Option<u64>]) {
    storage.platform.ticks(samples);
}

fn samples(storage: &Storage<TestPlatform>) -> usize {
    storage.platform.samples_taken()
}

/// Derivations on this thread since the last call; publishing derives too,
/// so a test clears the count right before the batch it measures.
fn derivations() -> usize {
    DERIVATIONS.with(|count| count.replace(0))
}

/// Write hints on this thread since the last call: the batch's are the
/// placement-window hints, [`WINDOW_LINES`] per route staged with a
/// summary that admits its tag, and one record hint per candidate an
/// element validates.
fn write_hints() -> usize {
    WRITE_HINTS.with(|count| count.replace(0))
}

/// Read hints on this thread since the last call: the batch's are one
/// summary line per route derived ahead; both bucket lines and the
/// generation and version lines of the placement window's first and last
/// slots per route staged with a summary that admits its tag; and, from
/// the batch's third key on, one record line per route whose base bucket,
/// read one lookup ahead, holds a pair that carries its tag and names a
/// slot of the pool.
fn read_hints() -> usize {
    READ_HINTS.with(|count| count.replace(0))
}

/// Room for a whole batch of hits, and for Miri's spurious weak failures.
fn generous() -> WorkBudget {
    WorkBudget::new(if cfg!(miri) { 4096 } else { 1024 })
}

fn empty<'s>(n: usize) -> Vec<BatchSlot<'s, TestPlatform>> {
    std::iter::repeat_with(|| None).take(n).collect()
}

/// The refusal variant of every slot, `None` for a lease or an empty slot.
fn refusals(outputs: &[BatchSlot<'_, TestPlatform>]) -> Vec<Option<LookupError>> {
    outputs
        .iter()
        .map(|slot| match slot {
            Some(Err(error)) => Some(*error),
            _ => None,
        })
        .collect()
}

fn hits(outputs: &[BatchSlot<'_, TestPlatform>]) -> usize {
    outputs
        .iter()
        .filter(|slot| matches!(slot, Some(Ok(_))))
        .count()
}

/// Widths 0, 1, `BatchMax` and `BatchMax + 1`, a wrong output length and an
/// occupied slot: every structural refusal reads no key, writes no output,
/// drops no lease, pins nothing and hashes nothing; the empty open batch
/// succeeds without a pin or a hash; the empty batch after close is `Closed`.
#[test]
fn structural_refusals_touch_neither_keys_nor_outputs() {
    let storage = ready();
    ticks(&storage, &[Some(1)]);
    let keys: Vec<Key> = (0..=BATCH_MAX as u8).map(|n| key(0x10 + n)).collect();
    for k in &keys {
        publish(&storage, *k, DEADLINE, &body(k[0]));
    }
    let mut reader = storage.register().unwrap();
    let keys_before = keys.clone();
    let mut none: Vec<BatchSlot<'_, TestPlatform>> = Vec::new();
    let mut one = empty(1);
    let mut full = empty(BATCH_MAX);
    let allocations = crate::instrument::allocations();

    // Width 0: success, no hash, no pin, no sample.
    let mut spent = budget();
    assert_eq!(
        reader.lookup_batch(&[], &mut none, RETRIES, &mut spent),
        Ok(())
    );
    assert_eq!(spent.counters(), WorkBudget::new(0).counters());
    assert_eq!(intervals(&storage, &reader), 0);
    assert_eq!(samples(&storage), 0);

    // Width 1 and BatchMax: one lease per key.
    assert_eq!(
        reader.lookup_batch(&keys[..1], &mut one, RETRIES, &mut generous()),
        Ok(())
    );
    assert_eq!(hits(&one), 1);
    assert_eq!(
        reader.lookup_batch(&keys[..BATCH_MAX], &mut full, RETRIES, &mut generous()),
        Ok(())
    );
    assert_eq!(hits(&full), BATCH_MAX);
    assert_eq!(intervals(&storage, &reader), 1 + BATCH_MAX as u64);
    assert_eq!(crate::instrument::allocations(), allocations);

    // BatchMax + 1: refused before anything, outputs untouched.
    let mut wide = empty(BATCH_MAX + 1);
    let mut spent = budget();
    assert_eq!(
        reader.lookup_batch(&keys, &mut wide, RETRIES, &mut spent),
        Err(BatchError::TooWide {
            width: BATCH_MAX + 1,
            max: BATCH_MAX
        })
    );
    assert!(wide.iter().all(Option::is_none));
    assert_eq!(spent.counters(), WorkBudget::new(0).counters());

    // Lengths differ, both ways.
    let mut short = empty(BATCH_MAX - 1);
    assert_eq!(
        reader.lookup_batch(&keys[..BATCH_MAX], &mut short, RETRIES, &mut generous()),
        Err(BatchError::LengthMismatch {
            keys: BATCH_MAX,
            outputs: BATCH_MAX - 1
        })
    );
    assert!(short.iter().all(Option::is_none));
    let mut long = empty(2);
    assert_eq!(
        reader.lookup_batch(&keys[..1], &mut long, RETRIES, &mut generous()),
        Err(BatchError::LengthMismatch {
            keys: 1,
            outputs: 2
        })
    );
    assert!(long.iter().all(Option::is_none));

    // An occupied slot: the lease it holds is neither dropped nor replaced,
    // the empty slots stay empty, and the overhead was the only charge.
    let held = one.pop().unwrap().unwrap().unwrap();
    let held_id = held.id();
    let mut occupied = empty(3);
    occupied[1] = Some(Ok(held));
    let reserved_before = reserved(&storage);
    let mut spent = budget();
    assert_eq!(
        reader.lookup_batch(&keys[..3], &mut occupied, RETRIES, &mut spent),
        Err(BatchError::Occupied { index: 1 })
    );
    assert_eq!(spent.counters().comparisons, 3);
    assert_eq!(spent.counters().updates, 0);
    assert_eq!(spent.counters().hashes, 0);
    assert!(occupied[0].is_none() && occupied[2].is_none());
    let still_held = occupied[1].take().unwrap().unwrap();
    assert_eq!(still_held.id(), held_id);
    assert_eq!(reserved(&storage), reserved_before);
    assert_eq!(intervals(&storage, &reader), 1 + BATCH_MAX as u64);
    assert_eq!(keys, keys_before);
    assert_eq!(pinned(&storage, &reader), None);
    drop(still_held);
    drop(full);

    // After close: the empty batch and every non-empty one are Closed
    // before any element, and the earlier leases were released normally.
    storage.close();
    let mut none: Vec<BatchSlot<'_, TestPlatform>> = Vec::new();
    assert_eq!(
        reader.lookup_batch(&[], &mut none, RETRIES, &mut generous()),
        Err(BatchError::Closed)
    );
    let mut two = empty(2);
    let mut spent = budget();
    assert_eq!(
        reader.lookup_batch(&keys[..2], &mut two, RETRIES, &mut spent),
        Err(BatchError::Closed)
    );
    assert!(two.iter().all(Option::is_none));
    assert_eq!(spent.counters(), WorkBudget::new(0).counters());
    assert_eq!(reserved(&storage), 0);
}

/// The prepaid overhead is one comparison per slot check and one update per
/// result write: a budget short of it refuses with the outputs untouched; a
/// budget of exactly the overhead fills every slot with `Contended` through
/// the prepaid writes, hashing nothing and pinning nothing.
#[test]
fn prepaid_overhead_is_refused_short_and_fills_contended_when_exact() {
    let storage = ready();
    ticks(&storage, &[Some(1)]);
    let keys = [key(0x21), key(0x22), key(0x23)];
    for k in &keys {
        publish(&storage, *k, DEADLINE, &body(k[0]));
    }
    let mut reader = storage.register().unwrap();
    let mut outputs = empty(3);
    let allocations = crate::instrument::allocations();

    let mut short = WorkBudget::new(5);
    derivations();
    assert_eq!(
        reader.lookup_batch(&keys, &mut outputs, RETRIES, &mut short),
        Err(BatchError::BudgetExhausted)
    );
    assert_eq!(short.remaining(), 0);
    assert!(outputs.iter().all(Option::is_none));
    assert_eq!(intervals(&storage, &reader), 0);
    assert_eq!(derivations(), 0);

    let mut exact = WorkBudget::new(6);
    write_hints();
    assert_eq!(
        reader.lookup_batch(&keys, &mut outputs, RETRIES, &mut exact),
        Ok(())
    );
    assert_eq!(crate::instrument::allocations(), allocations);
    assert_eq!(exact.remaining(), 0);
    assert_eq!(refusals(&outputs), vec![Some(LookupError::Contended); 3]);
    // Each element refused at the guard bundle's preflight: no pin, no
    // route derived, no charged hash pass, no probe, no sample, nothing
    // reserved.
    assert_eq!(exact.counters().hashes, 0);
    assert_eq!((derivations(), write_hints()), (0, 0));
    assert_eq!(intervals(&storage, &reader), 0);
    assert_eq!(samples(&storage), 0);
    assert_eq!(reserved(&storage), 0);
}

/// Once the shared budget is spent mid-batch the remaining slots are filled
/// through the prepaid writes: `Contended` while admission is open, `Closed`
/// once it has closed. The budgets are exact charges, which Miri's spurious
/// weak failures break, so the test is a native one.
#[test]
#[cfg_attr(miri, ignore = "weak compare-exchange fails spuriously under Miri")]
fn a_spent_budget_fills_the_remaining_slots() {
    let storage = ready();
    ticks(&storage, &[Some(1)]);
    let keys = [key(0x21), key(0x22), key(0x23)];
    for k in &keys {
        publish(&storage, *k, DEADLINE, &body(k[0]));
    }
    let mut reader = storage.register().unwrap();
    let mut one_hit = empty(3);

    // Overhead plus one whole element: the first key hits, the rest are
    // Contended once the budget is gone.
    let mut roomy = WorkBudget::new(6 + HIT);
    let allocations = crate::instrument::allocations();
    derivations();
    assert_eq!(
        reader.lookup_batch(&keys, &mut one_hit, RETRIES, &mut roomy),
        Ok(())
    );
    assert_eq!(crate::instrument::allocations(), allocations);
    assert_eq!(
        refusals(&one_hit),
        vec![
            None,
            Some(LookupError::Contended),
            Some(LookupError::Contended)
        ]
    );
    assert_eq!(
        hit_key(one_hit[0].as_ref().unwrap().as_ref().unwrap()),
        key(0x21)
    );
    // The prologue derives all three routes before charging budget; only
    // the first route consumes budget, and only the hit pins: the two
    // refused after it cannot pay their guard bundle.
    assert_eq!(intervals(&storage, &reader), 1);
    assert_eq!(roomy.counters().hashes, 1);
    assert_eq!(derivations(), 3);

    // Once admission closes, the spent-budget fill is Closed: the close
    // lands inside the first element's final bracket, which spends the last
    // of the budget refunding, and the remaining slots are written as Closed
    // without a pin.
    drop(one_hit);
    let mut closing = empty(3);
    let mut roomy = WorkBudget::new(6 + HIT);
    paused(
        &storage,
        Pause::FinalBracket,
        |storage| storage.close(),
        || {
            reader
                .lookup_batch(&keys, &mut closing, RETRIES, &mut roomy)
                .unwrap();
        },
    );
    assert_eq!(refusals(&closing), vec![Some(LookupError::Closed); 3]);
    assert_eq!(roomy.remaining(), 0);
    // The first element pinned; the two after it were refused at the cutoff
    // before pinning.
    assert_eq!(intervals(&storage, &reader), 2);
    assert_eq!(reserved(&storage), 0);
}

/// Repeated keys produce distinct rights and distinct leases: `n`
/// reservations, `n` rights and one payload charge; each lease reads the
/// object's payload back through the volume.
#[test]
fn repeated_keys_acquire_distinct_rights_on_one_payload() {
    let storage = ready();
    ticks(&storage, &[Some(1)]);
    let id = publish(&storage, key(0x31), DEADLINE, &body(0x31));
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let payload = place_record(&storage, &dev, key(0x31), id, &body(0x31));
    let mut reader = storage.register().unwrap();
    let ledger_before = storage.pool_report().unwrap().ledger.unwrap();
    let keys = [key(0x31); BATCH_MAX];
    let mut outputs = empty(BATCH_MAX);
    let allocations = crate::instrument::allocations();
    assert_eq!(
        reader.lookup_batch(&keys, &mut outputs, RETRIES, &mut generous()),
        Ok(())
    );
    assert_eq!(crate::instrument::allocations(), allocations);
    assert_eq!(hits(&outputs), BATCH_MAX);
    assert_eq!(refs(&storage, id), BATCH_MAX + 1);
    assert_eq!(reserved(&storage), BATCH_MAX);
    assert_eq!(
        storage.pool_report().unwrap().ledger.unwrap(),
        ledger_before
    );
    assert_eq!(intervals(&storage, &reader), BATCH_MAX as u64);
    // Each lease is its own right: dropping one releases exactly one.
    for expected in (0..BATCH_MAX).rev() {
        let lease = outputs.pop().unwrap().unwrap().unwrap();
        assert_eq!(hit_key(&lease), key(0x31));
        assert_eq!(dev.read(&lease), payload);
        drop(lease);
        assert_eq!(refs(&storage, id), expected + 1);
        assert_eq!(reserved(&storage), expected);
    }
}

/// Mixed outcomes across one batch match the scalar outcomes taken in the
/// same state, element by element, and earlier hits stay readable after
/// later refusals.
#[test]
fn mixed_outcomes_match_scalar_results_and_keep_earlier_hits() {
    let keys = [
        key(0x41), // hit
        key(0x44), // missing
        key(0x42), // expired
        key(0x43), // second right on `limited`: hit, the third credit
        key(0x43), // RetainLimit: C = 2 reached, the credit refunded
        key(0x41), // second right on `hit`: hit, the fourth credit
        key(0x41), // LeaseLimit: L = 4 reached
    ];
    // L = 4, C = 2, and a batch limit as wide as the case list.
    let slot_count = 16;
    let limits = [16usize];
    let storage = storage_from(
        &super::config::StorageConfig {
            lease_limit: 4,
            object_rights: 2,
            ..storage_config(slot_count)
        },
        &crate::index::IndexConfig {
            batch_max: keys.len(),
            ..index_config(&limits, (1, 1), 1)
        },
        TestPlatform::heap(PAGE),
    );
    ticks(&storage, &[Some(50)]);
    let hit = publish(&storage, key(0x41), DEADLINE, &body(0x41));
    let expired = publish(&storage, key(0x42), 50, &body(0x42));
    let limited = publish(&storage, key(0x43), DEADLINE, &body(0x43));
    let mut reader = storage.register().unwrap();
    // A scalar lease on `limited` takes one of its two rights and one of
    // the four credits.
    let outside = reader.lookup(&key(0x43), RETRIES, &mut budget()).unwrap();

    // The scalar expectation, from a second registration in the same
    // state, every lease held until the end as the batch holds its own, so
    // the limits fall on the same elements.
    let mut scalar = storage.register().unwrap();
    let held: Vec<_> = keys
        .iter()
        .map(|k| scalar.lookup(k, RETRIES, &mut budget()))
        .collect();
    let expected: Vec<Option<LookupError>> = held
        .iter()
        .map(|outcome| outcome.as_ref().err().copied())
        .collect();
    assert_eq!(
        expected,
        vec![
            None,
            Some(LookupError::Missing),
            Some(LookupError::Expired),
            None,
            Some(LookupError::RetainLimit),
            None,
            Some(LookupError::LeaseLimit),
        ]
    );
    drop(held);
    drop(scalar);
    assert_eq!((refs(&storage, hit), refs(&storage, limited)), (1, 2));
    let mut outputs = empty(keys.len());
    let allocations = crate::instrument::allocations();
    assert_eq!(
        reader.lookup_batch(&keys, &mut outputs, RETRIES, &mut WorkBudget::new(512)),
        Ok(())
    );
    assert_eq!(crate::instrument::allocations(), allocations);
    assert_eq!(refusals(&outputs), expected);
    assert_eq!(hits(&outputs), 3);
    assert_eq!(intervals(&storage, &reader), 1 + keys.len() as u64);
    assert_eq!(pinned(&storage, &reader), None);
    // Earlier hits read after the later refusals; the ledgers hold the
    // batch's three rights, the outside lease's one and four credits.
    let first = outputs[0].as_ref().unwrap().as_ref().unwrap();
    assert_eq!(hit_key(first), key(0x41));
    let fourth = outputs[3].as_ref().unwrap().as_ref().unwrap();
    assert_eq!(hit_key(fourth), key(0x43));
    assert_eq!(refs(&storage, hit), 3);
    assert_eq!(refs(&storage, expired), 1);
    assert_eq!(refs(&storage, limited), 3);
    assert_eq!(reserved(&storage), 4);
    assert_eq!(hit_key(&outside), key(0x43));
    drop(outputs);
    drop(outside);
    assert_eq!(reserved(&storage), 0);
}

/// Close between elements returns `Closed` for the remainder while the
/// earlier lease still reads; invalidation between elements yields `Missing`
/// for the invalidated key and leaves the earlier result untouched.
#[test]
fn close_and_invalidation_between_elements_affect_only_later_elements() {
    let storage = ready();
    ticks(&storage, &[Some(1)]);
    let keys = [key(0x51), key(0x52), key(0x53)];
    for k in &keys {
        publish(&storage, *k, DEADLINE, &body(k[0]));
    }
    let mut reader = storage.register().unwrap();

    // Paused before the second element: invalidate its key. The pause hook
    // re-arms itself on the heap, so no allocation count is taken here.
    let mut outputs = empty(3);
    paused_at_element(
        &storage,
        1,
        |storage| {
            let invalidated = storage.invalidate(&keys[1], TRIES, &mut budget()).unwrap();
            assert_eq!(
                invalidated.removed.map(|(_, outcome)| outcome),
                Some(RetireOutcome::Recorded)
            );
        },
        || {
            reader
                .lookup_batch(&keys, &mut outputs, RETRIES, &mut generous())
                .unwrap();
        },
    );
    assert_eq!(
        refusals(&outputs),
        vec![None, Some(LookupError::Missing), None]
    );
    assert_eq!(
        hit_key(outputs[0].as_ref().unwrap().as_ref().unwrap()),
        key(0x51)
    );
    assert_eq!(
        hit_key(outputs[2].as_ref().unwrap().as_ref().unwrap()),
        key(0x53)
    );
    drop(outputs);

    // Paused before the second element: close. The first lease reads, the
    // rest are Closed before any pin, and nothing stays reserved for them.
    publish(&storage, keys[1], DEADLINE, &body(keys[1][0]));
    let mut outputs = empty(3);
    let before = intervals(&storage, &reader);
    paused_at_element(
        &storage,
        1,
        |storage| storage.close(),
        || {
            reader
                .lookup_batch(&keys, &mut outputs, RETRIES, &mut generous())
                .unwrap();
        },
    );
    assert_eq!(
        refusals(&outputs),
        vec![None, Some(LookupError::Closed), Some(LookupError::Closed)]
    );
    assert_eq!(intervals(&storage, &reader), before + 1);
    assert_eq!(
        hit_key(outputs[0].as_ref().unwrap().as_ref().unwrap()),
        key(0x51)
    );
    assert_eq!(reserved(&storage), 1);
    assert_eq!(pinned(&storage, &reader), None);
    drop(outputs);
    assert_eq!(reserved(&storage), 0);
}

/// Runs `batch` on this thread paused before element `element` begins, while
/// `action` runs on another thread.
fn paused_at_element(
    storage: &Storage<TestPlatform>,
    element: usize,
    action: impl FnOnce(&Storage<TestPlatform>) + Send,
    batch: impl FnOnce(),
) {
    paused_with(
        storage,
        |start, done| arm(start, done, element),
        action,
        batch,
    );
}

/// Arms the pause before the next batch element; the first `skip` elements
/// pass through and re-arm, the one after them waits on the barriers.
fn arm(start: Arc<Barrier>, done: Arc<Barrier>, skip: usize) {
    INTERPOSE.with(|hook| {
        hook.set(Some((
            Pause::Element,
            Box::new(move || {
                if skip == 0 {
                    start.wait();
                    done.wait();
                } else {
                    arm(start, done, skip - 1);
                }
            }),
        )));
    });
}

/// `WIDE` exceeds the prologue's `DEPTH` routes, exercising post-prologue
/// lookahead.
const WIDE: usize = DEPTH + 4;

/// The derivations a `WIDE` batch makes once it has asked for its first
/// `asked` elements: the batch derives fingerprints in aligned groups of the
/// hasher's lane width, so every group an ask reaches is derived whole.
fn derived_through(storage: &Storage<TestPlatform>, asked: usize) -> usize {
    let width = storage.index().unwrap().hasher.lane_width();
    asked.div_ceil(width).saturating_mul(width).min(WIDE)
}

fn wide() -> (Storage<TestPlatform>, Vec<Key>) {
    let storage = ready_wide(WIDE);
    ticks(&storage, &[Some(1)]);
    let keys: Vec<Key> = (0..WIDE as u8).map(|n| key(0x70 + n)).collect();
    for k in &keys {
        publish(&storage, *k, DEADLINE, &body(k[0]));
    }
    (storage, keys)
}

/// Miri can spuriously fail weak compare-exchange, invalidating exact budget charges.
#[test]
#[cfg_attr(miri, ignore = "weak compare-exchange fails spuriously under Miri")]
fn a_spent_budget_stops_the_lookahead() {
    let (storage, keys) = wide();
    let mut reader = storage.register().unwrap();

    let mut funded = empty(WIDE);
    derivations();
    write_hints();
    assert_eq!(
        reader.lookup_batch(&keys, &mut funded, RETRIES, &mut generous()),
        Ok(())
    );
    assert_eq!(hits(&funded), WIDE);
    // Every key is present, so every route derived ahead is staged once,
    // by the prologue, the second iteration's catch-up or a later
    // iteration's one step, and hints its bucket and placement window; each
    // hit's validation hints its record.
    assert_eq!(
        (derivations(), write_hints()),
        (WIDE, WINDOW_LINES * WIDE + WIDE)
    );
    drop(funded);

    let mut one_hit = empty(WIDE);
    let mut roomy = WorkBudget::new(2 * WIDE + HIT);
    let allocations = crate::instrument::allocations();
    assert_eq!(
        reader.lookup_batch(&keys, &mut one_hit, RETRIES, &mut roomy),
        Ok(())
    );
    assert_eq!(crate::instrument::allocations(), allocations);
    let mut expected = vec![Some(LookupError::Contended); WIDE];
    expected[0] = None;
    assert_eq!(refusals(&one_hit), expected);
    assert_eq!(
        hit_key(one_hit[0].as_ref().unwrap().as_ref().unwrap()),
        key(0x70)
    );
    assert_eq!(roomy.remaining(), 0);
    assert_eq!(roomy.counters().hashes, HASH_CHARGE);
    // The prologue asks for the first `DEPTH` elements and stages the first
    // `STAGE`; the first iteration asks for one more and stages nothing, and
    // its hit spends the rest of the budget. Each ask derives the whole group
    // holding it.
    let prologue_and_first_iteration = DEPTH + 1;
    assert_eq!(
        (derivations(), write_hints()),
        (
            derived_through(&storage, prologue_and_first_iteration),
            WINDOW_LINES * STAGE + 1
        )
    );
    // The hit pinned; the elements refused after it could not pay their
    // guard bundle and pinned nothing.
    assert_eq!(intervals(&storage, &reader), WIDE as u64 + 1);
}

/// A budget that the prepaid writes leave short of one element's guard
/// bundle and route charge cannot carry any element to its hash charge, so
/// the prologue derives and hints nothing.
#[test]
#[cfg_attr(miri, ignore = "weak compare-exchange fails spuriously under Miri")]
fn a_budget_the_prepaid_writes_exhaust_derives_no_route() {
    let (storage, keys) = wide();
    let mut reader = storage.register().unwrap();

    let mut none = empty(WIDE);
    let mut short = WorkBudget::new(2 * WIDE + GUARD_STEPS + HASH_CHARGE - 1);
    derivations();
    write_hints();
    assert_eq!(
        reader.lookup_batch(&keys, &mut none, RETRIES, &mut short),
        Ok(())
    );
    assert_eq!(refusals(&none), vec![Some(LookupError::Contended); WIDE]);
    assert_eq!(short.remaining(), 0);
    assert_eq!((derivations(), write_hints()), (0, 0));
}

/// A key whose chain summary excludes its tag costs the lookahead its
/// summary hint alone: its base bucket and placement window stay unhinted,
/// and its element still reports `Missing` through its own search.
#[test]
fn an_excluding_summary_ends_the_lookahead_at_the_summary() {
    let storage = ready_wide(WIDE);
    ticks(&storage, &[Some(1)]);
    // Nothing is published, so every summary is empty and excludes every tag.
    let keys: Vec<Key> = (0..WIDE as u8).map(|n| key(0x70 + n)).collect();
    let mut reader = storage.register().unwrap();
    let mut outputs = empty(WIDE);
    derivations();
    write_hints();
    read_hints();
    assert_eq!(
        reader.lookup_batch(&keys, &mut outputs, RETRIES, &mut generous()),
        Ok(())
    );
    assert_eq!(refusals(&outputs), vec![Some(LookupError::Missing); WIDE]);
    assert_eq!(
        (derivations(), read_hints(), write_hints()),
        (WIDE, WIDE, 0)
    );
}

#[test]
fn a_close_stops_the_lookahead() {
    let (storage, keys) = wide();
    let mut reader = storage.register().unwrap();
    let mut outputs = empty(WIDE);
    derivations();
    write_hints();
    paused_at_element(
        &storage,
        1,
        |storage| storage.close(),
        || {
            reader
                .lookup_batch(&keys, &mut outputs, RETRIES, &mut generous())
                .unwrap();
        },
    );
    let mut expected = vec![Some(LookupError::Closed); WIDE];
    expected[0] = None;
    assert_eq!(refusals(&outputs), expected);
    // The close occurs at the second iteration's start. That iteration's
    // ask for one more element and the catch-up's two stagings are the last
    // lookahead work; its element then reports `Closed`. The first
    // element's hit validation hints its record.
    let prologue_and_two_iterations = DEPTH + 2;
    assert_eq!(
        (derivations(), write_hints()),
        (
            derived_through(&storage, prologue_and_two_iterations),
            WINDOW_LINES * (STAGE + 2) + 1
        )
    );
    assert_eq!(intervals(&storage, &reader), 1);
    assert_eq!(reserved(&storage), 1);
    drop(outputs);
    assert_eq!(reserved(&storage), 0);
}

/// Exactly one pin per element and none active when a result is stored: a
/// pause before every element observes the registration unpinned with one
/// more completed interval each time, and never a second interval; the
/// index scratch is the scalar footprint whatever `BatchMax` is.
#[test]
fn one_pin_per_element_and_the_scalar_scratch_footprint() {
    let storage = ready();
    ticks(&storage, &[Some(1)]);
    let keys: Vec<Key> = (0..BATCH_MAX as u8).map(|n| key(0x60 + n)).collect();
    for k in &keys {
        publish(&storage, *k, DEADLINE, &body(k[0]));
    }
    let mut reader = storage.register().unwrap();
    let reader_index = reader.index();
    let observed = std::sync::Mutex::new(Vec::new());
    let start = Arc::new(Barrier::new(2));
    let done = Arc::new(Barrier::new(2));
    let mut outputs = empty(BATCH_MAX);
    std::thread::scope(|scope| {
        let (start_observer, done_observer) = (Arc::clone(&start), Arc::clone(&done));
        let storage = &storage;
        let observed = &observed;
        scope.spawn(move || {
            for _ in 0..BATCH_MAX {
                start_observer.wait();
                let report = storage.registration_report(reader_index).unwrap();
                observed
                    .lock()
                    .unwrap()
                    .push((report.pinned_era, report.intervals));
                done_observer.wait();
            }
        });
        arm_every(start, done, BATCH_MAX);
        reader
            .lookup_batch(&keys, &mut outputs, RETRIES, &mut generous())
            .unwrap();
    });
    assert!(INTERPOSE.with(|hook| hook.take().is_none()));
    let observed = observed.into_inner().unwrap();
    let expected: Vec<(Option<u64>, u64)> = (0..BATCH_MAX as u64).map(|n| (None, n)).collect();
    assert_eq!(observed, expected);
    assert_eq!(hits(&outputs), BATCH_MAX);
    assert_eq!(intervals(&storage, &reader), BATCH_MAX as u64);
    drop(outputs);

    // The scratch inventory is `R * 14 * (1 + D)` identities, with no term
    // in `BatchMax`: the same for a batch limit of 1 and of 64.
    let slot_count = 16;
    let limits = [16usize];
    let narrow = crate::index::IndexConfig {
        batch_max: 1,
        ..index_config(&limits, (1, 1), 1)
    };
    let wide = crate::index::IndexConfig {
        batch_max: 64,
        ..index_config(&limits, (1, 1), 1)
    };
    let config = storage_config(slot_count).validate().unwrap();
    let narrow = narrow.validate(&config).unwrap();
    let wide = wide.validate(&config).unwrap();
    assert_eq!(narrow.inventory(), wide.inventory());
    assert_eq!(
        narrow.inventory().scratch_identities,
        14 * (1 + narrow.depth())
    );
    assert_eq!((narrow.batch_max(), wide.batch_max()), (1, 64));

    // The pool descriptor and the volume's control mapping are laid out from
    // the storage configuration, which carries no batch limit: storages
    // built with either limit lay out the same pool.
    let built = |batch_max| {
        let index = crate::index::IndexConfig {
            batch_max,
            ..index_config(&limits, (1, 1), 1)
        };
        let report = super::publish_tests::storage(slot_count, &index)
            .pool_report()
            .unwrap();
        (report.descriptor, report.control_extent)
    };
    assert_eq!(built(1), built(64));
}

/// Arms a pause before every one of the next `count` elements, each waiting
/// on the barriers once.
fn arm_every(start: Arc<Barrier>, done: Arc<Barrier>, count: usize) {
    if count == 0 {
        return;
    }
    INTERPOSE.with(|hook| {
        hook.set(Some((
            Pause::Element,
            Box::new(move || {
                start.wait();
                done.wait();
                arm_every(start, done, count - 1);
            }),
        )));
    });
}

/// Without an index the batch width is zero: the empty batch succeeds and
/// any key is too wide, before anything else.
#[test]
fn a_storage_without_an_index_refuses_every_batch() {
    let slot_count = 4;
    let config = storage_config(slot_count).validate().unwrap();
    let placement = super::placement::PlacementConfig { control_home: 0 };
    let storage = Storage::initialize(&config, &placement, TestPlatform::heap(PAGE)).unwrap();
    let mut reader = storage.register().unwrap();
    let mut none: Vec<BatchSlot<'_, TestPlatform>> = Vec::new();
    assert_eq!(
        reader.lookup_batch(&[], &mut none, RETRIES, &mut budget()),
        Ok(())
    );
    let mut one = empty(1);
    assert_eq!(
        reader.lookup_batch(&[key(1)], &mut one, RETRIES, &mut budget()),
        Err(BatchError::TooWide { width: 1, max: 0 })
    );
    assert!(one[0].is_none());
    assert_eq!(
        reader.lookup(&key(1), RETRIES, &mut budget()).err(),
        Some(LookupError::Contended)
    );
    assert_eq!(pinned(&storage, &reader), None);
}

/// Each prepayment and slot refusal on its own reachable case, in precedence
/// order:
/// a budget short of the slot comparisons refuses before an occupied slot
/// is found; a budget that pays the comparisons and not the result writes
/// reports the occupied slot before it reaches the writes; with every slot
/// empty the same budget refuses at the writes. The two refusals over the
/// occupied slot keep its lease by identity, and every refusal writes no
/// output, pins nothing, hashes nothing, reserves nothing and spends
/// exactly the steps its prepayment reached.
#[test]
fn each_structural_refusal_has_its_own_witness() {
    let storage = ready();
    ticks(&storage, &[Some(1)]);
    let keys = [key(0x81), key(0x82), key(0x83)];
    for k in &keys {
        publish(&storage, *k, DEADLINE, &body(k[0]));
    }
    let mut reader = storage.register().unwrap();
    let held = reader.lookup(&keys[0], RETRIES, &mut budget()).unwrap();
    let held_id = held.id();
    let mut occupied = empty(3);
    occupied[2] = Some(Ok(held));
    let reserved_before = reserved(&storage);
    let intervals_before = intervals(&storage, &reader);
    derivations();
    let unchanged = |outputs: &mut Vec<BatchSlot<'_, TestPlatform>>| {
        assert!(outputs[0].is_none() && outputs[1].is_none());
        let lease = outputs[2].as_ref().unwrap().as_ref().unwrap();
        assert_eq!(lease.id(), held_id);
    };

    // Comparison-short: two steps for three slot checks.
    let mut short = WorkBudget::new(2);
    assert_eq!(
        reader.lookup_batch(&keys, &mut occupied, RETRIES, &mut short),
        Err(BatchError::BudgetExhausted)
    );
    unchanged(&mut occupied);
    assert_eq!(short.remaining(), 0);
    assert_eq!(
        (short.counters().comparisons, short.counters().updates),
        (2, 0)
    );

    // Occupied: the comparisons are paid and the writes would not be.
    let mut writes_short = WorkBudget::new(4);
    assert_eq!(
        reader.lookup_batch(&keys, &mut occupied, RETRIES, &mut writes_short),
        Err(BatchError::Occupied { index: 2 })
    );
    unchanged(&mut occupied);
    assert_eq!(
        (
            writes_short.counters().comparisons,
            writes_short.counters().updates
        ),
        (3, 0)
    );

    // Update-short: every slot empty, one step for three writes.
    let mut free = empty(3);
    let mut update_short = WorkBudget::new(4);
    assert_eq!(
        reader.lookup_batch(&keys, &mut free, RETRIES, &mut update_short),
        Err(BatchError::BudgetExhausted)
    );
    assert!(free.iter().all(Option::is_none));
    assert_eq!(update_short.remaining(), 0);
    assert_eq!(
        (
            update_short.counters().comparisons,
            update_short.counters().updates
        ),
        (3, 1)
    );

    for spent in [short, writes_short, update_short] {
        assert_eq!(spent.counters().hashes, 0);
    }
    assert_eq!(derivations(), 0);
    assert_eq!(intervals(&storage, &reader), intervals_before);
    assert_eq!(reserved(&storage), reserved_before);
    assert_eq!(samples(&storage), 1);
    assert_eq!(pinned(&storage, &reader), None);
}

/// A route prepared for a key before a replacement or an expiry authorizes
/// nothing: the element whose key was replaced while it waited acquires the
/// replacing object, also when the replacement lands inside its final
/// bracket, the one whose key expired is `Expired`, and an earlier element's
/// lease on the same key keeps the version it acquired. Every element's
/// route was derived by the prologue, before the mutation.
#[test]
fn replacement_and_expiry_between_elements_govern_only_later_elements() {
    let storage = ready();
    ticks(&storage, &[Some(1)]);
    let replaced = key(0x91);
    let old = publish(&storage, replaced, DEADLINE, &body(0x91));
    let mut reader = storage.register().unwrap();

    // Paused before the second element: replace the key both elements ask
    // for.
    let mut outputs = empty(2);
    let mut new = None;
    derivations();
    paused_at_element(
        &storage,
        1,
        |storage| {
            let replacement = replace(storage, replaced, DEADLINE, &body(0x92));
            assert_eq!(replacement.replaced.map(|(id, _)| id), Some(old));
            new = Some(replacement.id);
        },
        || {
            reader
                .lookup_batch(&[replaced; 2], &mut outputs, RETRIES, &mut generous())
                .unwrap();
        },
    );
    let new = new.unwrap();
    assert_ne!(new, old);
    // The prologue derived both elements' routes on this thread and the
    // lookups derived none of their own; the replacement ran on another.
    assert_eq!(derivations(), 2);
    let first = outputs[0].as_ref().unwrap().as_ref().unwrap();
    let second = outputs[1].as_ref().unwrap().as_ref().unwrap();
    assert_eq!((first.id(), second.id()), (old, new));
    assert_eq!((*first.key(), *second.key()), (replaced, replaced));
    // The earlier lease still holds a right on the replaced object: ending
    // it returns exactly one.
    let held = refs(&storage, old);
    drop(outputs.remove(0));
    assert_eq!(refs(&storage, old), held - 1);
    drop(outputs);
    assert_eq!(reserved(&storage), 0);

    // Paused at the prepared element's final bracket, after its candidate
    // was copied and reserved: the replacement moves the sequence, the
    // attempt is spent, and the retry acquires the replacing object.
    let mut outputs = empty(1);
    let mut newer = None;
    paused(
        &storage,
        Pause::FinalBracket,
        |storage| {
            newer = Some(replace(storage, replaced, DEADLINE, &body(0x94)).id);
        },
        || {
            reader
                .lookup_batch(&[replaced], &mut outputs, RETRIES, &mut generous())
                .unwrap();
        },
    );
    let newer = newer.unwrap();
    assert_ne!(newer, new);
    let lease = outputs[0].as_ref().unwrap().as_ref().unwrap();
    assert_eq!((lease.id(), *lease.key()), (newer, replaced));
    drop(outputs);
    assert_eq!(reserved(&storage), 0);

    // Paused before the second element: the clock reaches the deadline.
    let expiring = key(0x93);
    publish(&storage, expiring, DEADLINE, &body(0x93));
    ticks(&storage, &[Some(1)]);
    let mut outputs = empty(2);
    paused_at_element(
        &storage,
        1,
        |storage| ticks(storage, &[Some(DEADLINE)]),
        || {
            reader
                .lookup_batch(&[expiring; 2], &mut outputs, RETRIES, &mut generous())
                .unwrap();
        },
    );
    assert_eq!(refusals(&outputs), vec![None, Some(LookupError::Expired)]);
    let first = outputs[0].as_ref().unwrap().as_ref().unwrap();
    assert_eq!(*first.key(), expiring);
    assert_eq!(reserved(&storage), 1);
    drop(outputs);
    assert_eq!(reserved(&storage), 0);
}

/// A one-key batch charges its element exactly what the scalar lookup of
/// the same key charges, at every allowance from nothing to a whole hit,
/// beside the prepaid comparison and write; below the guard bundle and the
/// hash charge (`AHEAD`) the batch derives no route ahead, and at or above
/// it the one derivation it makes ahead, observed before element 0 begins,
/// replaces the scalar lookup's own.
///
/// Each side runs on its own fresh storage, so no credit or visited bit
/// left by one changes the other's charges. The budgets are exact charges,
/// which Miri's spurious weak failures break, so the test is a native one.
#[test]
#[cfg_attr(miri, ignore = "weak compare-exchange fails spuriously under Miri")]
fn a_batch_element_pays_the_scalar_charges_at_every_allowance() {
    let present = key(0xA1);
    let fresh = || {
        let storage = ready();
        ticks(&storage, &[Some(1)]);
        publish(&storage, present, DEADLINE, &body(0xA1));
        storage
    };
    let allowances = [
        0,
        GUARD_STEPS - 1,
        GUARD_STEPS,
        GUARD_STEPS + HASH_CHARGE - 1,
        GUARD_STEPS + HASH_CHARGE,
        HIT - 1,
        HIT,
    ];
    for allowance in allowances {
        let (alone_storage, batch_storage) = (fresh(), fresh());
        let mut scalar = alone_storage.register().unwrap();
        let mut batch = batch_storage.register().unwrap();
        let mut alone = WorkBudget::new(allowance);
        derivations();
        let expected = scalar
            .lookup(&present, RETRIES, &mut alone)
            .map(|lease| *lease.key());
        let scalar_derivations = derivations();
        let ahead = usize::from(allowance >= GUARD_STEPS + HASH_CHARGE);

        let mut shared = WorkBudget::new(2 + allowance);
        let mut outputs = empty(1);
        // The derivations made before element 0 begins are the prologue's.
        let primed = std::rc::Rc::new(std::cell::Cell::new(usize::MAX));
        let seen = std::rc::Rc::clone(&primed);
        INTERPOSE.with(|hook| {
            hook.set(Some((
                Pause::Element,
                Box::new(move || seen.set(DERIVATIONS.with(std::cell::Cell::get))),
            )));
        });
        batch
            .lookup_batch(&[present], &mut outputs, RETRIES, &mut shared)
            .unwrap();
        assert_eq!(primed.get(), ahead, "{allowance}");
        let outcome = outputs[0].take().unwrap().map(|lease| *lease.key());
        assert_eq!(outcome, expected, "{allowance}");
        assert_eq!(outcome.is_ok(), allowance == HIT, "{allowance}");
        let mut paid = shared.counters();
        paid.comparisons -= 1;
        paid.updates -= 1;
        assert_eq!(paid, alone.counters(), "{allowance}");
        assert_eq!(shared.remaining(), alone.remaining(), "{allowance}");
        assert_eq!(scalar_derivations, ahead, "{allowance}");
        assert_eq!(derivations(), ahead, "{allowance}");
        assert_eq!(
            intervals(&batch_storage, &batch),
            intervals(&alone_storage, &scalar),
            "{allowance}"
        );
        assert_eq!(samples(&batch_storage), samples(&alone_storage));
    }
}
