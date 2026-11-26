//! Registered lookup against independent expectations: exact bytes and
//! ledgers on the uncontended path, every deadline case on deterministic
//! ticks, forced fingerprint collisions, every paused race against removal,
//! replacement, close and expiry, the limits, the fail-closed paths, the pin
//! discipline and the work accounting, on the heap-backed platform.
//!
//! Expected bytes, deadlines, counts and pin states come from the test's own
//! records and from the ledgers the lookup does not write, never from a
//! lookup result recycled as its own oracle.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Barrier, Mutex};

use super::budget::WorkBudget;
use super::grace::ERA_TERMINAL;
use super::init::{InitError, InitPhase};
use super::lease::{
    Credit, CreditError, INTERPOSE_BEFORE_RETAIN, PAUSE_IN_SWEEP, RECORDS_SCANNED, record_credits,
    reserve_credit, return_credit,
};
use super::lookup::{GUARD_STEPS, INTERPOSE, LookupError, Pause, REJECTED_BEFORE_ACCESS};
use super::os::OsCode;
use super::owner::Storage;
use super::publish_tests::{
    PAGE, RETRIES, TRIES, budget, index_config, install_seam, one_chain, refs, storage,
    storage_config, storage_from,
};
use super::tables::{SlotIndex, SlotState};
use super::test_platform::{Fail, Op, TestPlatform};
use super::volume_fixture::{Device, arena, place, record_bytes};
use super::word::ANCHORED;
use super::{AllocationId, ExtentLease, Registration, Replacement, RetireOutcome};
use crate::index::{BucketView, Key, PAIRS, ShardIndex};

/// A deadline 100 seconds into the engine's nanosecond timeline.
const DEADLINE: u64 = 100 * 1_000_000_000;

pub(super) fn ready(slots: usize) -> Storage<TestPlatform> {
    let slot_count = slots;
    let limits = [8usize];
    storage(slot_count, &index_config(&limits, (1, 1), 1))
}

/// An indexed storage with `L = lease_limit` and `C = object_rights`.
fn ready_with(lease_limit: usize, object_rights: usize) -> Storage<TestPlatform> {
    ready_sized(lease_limit, object_rights, 8)
}

fn ready_sized(lease_limit: usize, object_rights: usize, slots: usize) -> Storage<TestPlatform> {
    let slot_count = slots;
    let limits = [8usize];
    let config = super::config::StorageConfig {
        lease_limit,
        object_rights,
        ..storage_config(slot_count)
    };
    storage_from(
        &config,
        &index_config(&limits, (1, 1), 1),
        TestPlatform::heap(PAGE),
    )
}

/// A key whose bytes are all `n`; its body is `n` repeated `len` times.
pub(super) fn key(n: u8) -> Key {
    [n; 32]
}

/// Places `id`'s record, `body` under `key` with the four zero metadata
/// bytes [`completed`] reserves, on `dev`'s device, and returns the payload
/// a read of it delivers.
pub(super) fn place_record(
    storage: &Storage<TestPlatform>,
    dev: &Device<'_, '_>,
    key: Key,
    id: AllocationId,
    body: &[u8],
) -> Vec<u8> {
    let pool = storage.live_pool().unwrap();
    let locator = pool.records()[id.slot_index()].locator();
    // The header carries the session the slot completed under, the one a read of the slot expects.
    let session = pool.generations()[id.slot_index()].load(std::sync::atomic::Ordering::Relaxed);
    let bytes = record_bytes(storage, key, id, session, &[0; 4], body);
    place(storage, &dev.control, locator, &bytes);
    [&[0; 4][..], body].concat()
}

/// The key a hit was taken for, once the object its lease names is checked
/// to carry that key's fingerprint unless it is retired. The key returned is
/// the lookup's own argument, so this checks the fingerprint only; a test
/// that knows the published identity compares `lease.id()` with it. A
/// retirement stamps its era over the fingerprint and then sets the
/// abandonment flag, so a word read between the two waits for the flag, a
/// bounded number of yields. The check's own derivation leaves the thread's
/// derivation count as it was.
pub(super) fn hit_key(lease: &ExtentLease<'_, TestPlatform>) -> Key {
    let storage = lease.storage();
    let pool = storage.live_pool().unwrap();
    let slot = lease.id().slot_index();
    let derivations = crate::index::DERIVATIONS.with(std::cell::Cell::get);
    let fingerprint = storage.route(lease.key()).unwrap().fingerprint();
    crate::index::DERIVATIONS.with(|count| count.set(derivations));
    let bound = (0..1 << 20).any(|_| {
        let matched = pool.records()[slot].fingerprint() == fingerprint
            || pool.word(slot) & super::word::ABANDONED != 0;
        if !matched {
            std::thread::yield_now();
        }
        matched
    });
    assert!(bound, "a hit on another fingerprint");
    *lease.key()
}

pub(super) fn body(n: u8) -> Vec<u8> {
    vec![n; 20 + usize::from(n % 7)]
}

pub(super) fn completed<'s>(
    storage: &'s Storage<TestPlatform>,
    key: Key,
    deadline: u64,
    body: &[u8],
) -> super::Completed<'s, TestPlatform> {
    let mut allocation = storage
        .reserve(Some(4), Some(body.len()), &mut budget())
        .unwrap();
    allocation.mark_written();
    allocation
        .complete(key, deadline, &mut budget())
        .ok()
        .unwrap()
}

pub(super) fn publish(
    storage: &Storage<TestPlatform>,
    key: Key,
    deadline: u64,
    body: &[u8],
) -> AllocationId {
    completed(storage, key, deadline, body)
        .publish(TRIES, &mut budget())
        .unwrap()
}

pub(super) fn replace(
    storage: &Storage<TestPlatform>,
    key: Key,
    deadline: u64,
    body: &[u8],
) -> Replacement {
    completed(storage, key, deadline, body)
        .replace(TRIES, &mut budget())
        .unwrap()
}

pub(super) fn remove(storage: &Storage<TestPlatform>, key: &Key, id: AllocationId) {
    assert_eq!(
        storage.remove(key, id, TRIES, &mut budget()),
        Ok(RetireOutcome::Recorded)
    );
}

pub(super) fn reserved(storage: &Storage<TestPlatform>) -> usize {
    storage.lease_report().unwrap().reserved
}

pub(super) fn pinned(
    storage: &Storage<TestPlatform>,
    reader: &Registration<'_, TestPlatform>,
) -> Option<u64> {
    storage
        .registration_report(reader.index())
        .unwrap()
        .pinned_era
}

pub(super) fn ticks(storage: &Storage<TestPlatform>, samples: &[Option<u64>]) {
    storage.platform.ticks(samples);
}

pub(super) fn samples(storage: &Storage<TestPlatform>) -> usize {
    storage.platform.samples_taken()
}

fn rejected() -> usize {
    REJECTED_BEFORE_ACCESS.with(std::cell::Cell::get)
}

fn sequence(storage: &Storage<TestPlatform>) -> u64 {
    storage.shard_report(ShardIndex(0)).unwrap().sequence
}

pub(super) fn lookup<'s>(
    reader: &mut Registration<'s, TestPlatform>,
    key: &Key,
    retries: usize,
) -> Result<ExtentLease<'s, TestPlatform>, LookupError> {
    reader.lookup(key, retries, &mut budget())
}

/// Runs `lookup` on this thread with the next lookup paused at `at`, while
/// `action` runs on another thread and completes before the lookup resumes.
pub(super) fn paused<R>(
    storage: &Storage<TestPlatform>,
    at: Pause,
    action: impl FnOnce(&Storage<TestPlatform>) + Send,
    lookup: impl FnOnce() -> R,
) -> R {
    paused_with(
        storage,
        move |start, done| {
            INTERPOSE.with(|hook| {
                hook.set(Some((
                    at,
                    Box::new(move || {
                        start.wait();
                        done.wait();
                    }),
                )));
            });
        },
        action,
        lookup,
    )
}

/// Runs `lookup` on this thread after `arm` has installed a pause hook that
/// waits on `start` then `done`, while `action` runs on another thread
/// between the two; asserts the hook fired. A pause that never fires, a
/// panicking lookup and a panicking action each fail the test: the action
/// reaches `done` after a panic, and an unfired pause is released here.
pub(super) fn paused_with<R>(
    storage: &Storage<TestPlatform>,
    arm: impl FnOnce(Arc<Barrier>, Arc<Barrier>),
    action: impl FnOnce(&Storage<TestPlatform>) + Send,
    lookup: impl FnOnce() -> R,
) -> R {
    use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
    let start = Arc::new(Barrier::new(2));
    let done = Arc::new(Barrier::new(2));
    let (outcome, fired) = std::thread::scope(|scope| {
        let (start_paused, done_paused) = (Arc::clone(&start), Arc::clone(&done));
        scope.spawn(move || {
            start_paused.wait();
            let acted = catch_unwind(AssertUnwindSafe(|| action(storage)));
            done_paused.wait();
            if let Err(panic) = acted {
                resume_unwind(panic);
            }
        });
        arm(Arc::clone(&start), Arc::clone(&done));
        let outcome = catch_unwind(AssertUnwindSafe(lookup));
        let fired = INTERPOSE.with(|hook| hook.take().is_none());
        if !fired {
            start.wait();
            done.wait();
        }
        (outcome, fired)
    });
    let outcome = outcome.unwrap_or_else(|panic| resume_unwind(panic));
    assert!(fired, "the armed pause was never reached");
    outcome
}

/// An uncontended, funded lookup returns the published bytes with one credit
/// and one right, allocates nothing on the first and on a steady hit and on
/// release, takes exactly one sample per hit, and leaves the pin cleared;
/// the lease keeps its bytes after the interval and releases both counts.
#[test]
fn a_funded_lookup_returns_exact_bytes_with_no_hidden_work() {
    let storage = ready(8);
    let body = body(0x41);
    let id = publish(&storage, key(0x41), DEADLINE, &body);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let payload = place_record(&storage, &dev, key(0x41), id, &body);
    ticks(&storage, &[Some(DEADLINE - 1)]);
    let mut reader = storage.register().unwrap();
    let ledger_before = storage.pool_report().unwrap().ledger;
    let allocations = crate::instrument::allocations();
    let first = lookup(&mut reader, &key(0x41), RETRIES).unwrap();
    assert_eq!(crate::instrument::allocations(), allocations);
    assert_eq!(refs(&storage, id), 2);
    assert_eq!(reserved(&storage), 1);
    assert_eq!(samples(&storage), 1);
    assert_eq!(pinned(&storage, &reader), None);
    assert_eq!(
        storage
            .registration_report(reader.index())
            .unwrap()
            .intervals,
        1
    );

    // Steady: the same lookup again, then release of both.
    let steady = lookup(&mut reader, &key(0x41), RETRIES).unwrap();
    assert_eq!(crate::instrument::allocations(), allocations);
    assert_eq!(refs(&storage, id), 3);
    assert_eq!(reserved(&storage), 2);
    assert_eq!(samples(&storage), 2);
    assert_eq!(storage.pool_report().unwrap().ledger, ledger_before);
    assert_eq!(dev.read(&first), payload);
    assert_eq!(dev.read(&steady), payload);
    assert_eq!(
        refs(&storage, id),
        3,
        "each read's right ended at its terminal"
    );
    let allocations = crate::instrument::allocations();
    drop(steady);
    drop(first);
    assert_eq!(crate::instrument::allocations(), allocations);
    assert_eq!(refs(&storage, id), 1);
    assert_eq!(reserved(&storage), 0);

    // The lease outlives the interval that acquired it: the registration is
    // gone, the bytes are not.
    let held = lookup(&mut reader, &key(0x41), RETRIES).unwrap();
    drop(reader);
    assert_eq!(dev.read(&held), payload);
    drop(held);
    assert_eq!(reserved(&storage), 0);
}

/// `Missing` needs a stable, complete search of the key's chain. No index
/// attempt (`retries == 0`), a spent budget before the guard bundle, and a
/// budget short of the scan bound all refuse `Contended`, with an
/// independent count of the hash pass and samples showing what each did.
#[test]
fn missing_only_after_a_stable_complete_search_and_exhaustion_is_contended() {
    thread_local! {
        static PASSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }
    fn counting(key: &Key) -> u64 {
        PASSES.with(|passes| passes.set(passes.get() + 1));
        one_chain(key)
    }
    let slot_count = 8;
    let limits = [8usize];
    let mut storage = storage(slot_count, &index_config(&limits, (1, 1), 1));
    install_seam(&mut storage, counting);
    ticks(&storage, &[Some(1)]);
    let published = publish(&storage, key(0x11), DEADLINE, &body(0x11));
    let mut reader = storage.register().unwrap();
    let passes_before = PASSES.with(std::cell::Cell::get);

    // Absent key, same chain as the published one: the one candidate's
    // fingerprint differs, the search completes, and the answer is Missing.
    let mut spent = budget();
    assert_eq!(
        reader.lookup(&key(0x12), RETRIES, &mut spent).err(),
        Some(LookupError::Missing)
    );
    let counters = spent.counters();
    assert_eq!(counters.hashes, 1);
    // The guard bundle's three checks, the prepaid chain bound of `14 (1 + D)`
    // pair comparisons and two sequence validations with `D = 1`, the one
    // candidate's identity check and fingerprint comparison, and the bracket
    // that confirms absence: the cutoff read and the sequence again.
    assert_eq!(counters.comparisons, 3 + 30 + 2 + 2);
    assert_eq!(counters.visits, 2);
    // The guard bundle's pin, clearing and statistics stores.
    assert_eq!(counters.updates, 3);
    assert_eq!(counters.coordination_attempts, 0);
    assert_eq!(PASSES.with(std::cell::Cell::get) - passes_before, 1);
    assert_eq!(samples(&storage), 0);
    assert_eq!(pinned(&storage, &reader), None);

    // An empty chain: the search completes with nothing to compare, and the
    // bound is paid whole all the same.
    let mut spent = budget();
    assert_eq!(
        reader.lookup(&key(0x21), RETRIES, &mut spent).err(),
        Some(LookupError::Missing)
    );
    assert_eq!(spent.counters().comparisons, 3 + 30 + 2);

    // Zero attempts: the guard bundle and the hash pass are paid; no
    // sequence or bucket is read.
    let passes_before = PASSES.with(std::cell::Cell::get);
    let mut spent = budget();
    assert_eq!(
        reader.lookup(&key(0x11), 0, &mut spent).err(),
        Some(LookupError::Contended)
    );
    assert_eq!(spent.counters().hashes, 1);
    assert_eq!(spent.counters().comparisons, 3);
    assert_eq!(spent.counters().visits, 0);
    assert_eq!(PASSES.with(std::cell::Cell::get) - passes_before, 1);

    // Zero budget: no pin, no hash pass, no probe, no sample.
    let passes_before = PASSES.with(std::cell::Cell::get);
    let mut zero = WorkBudget::new(0);
    assert_eq!(
        reader.lookup(&key(0x11), RETRIES, &mut zero).err(),
        Some(LookupError::Contended)
    );
    assert_eq!(zero.counters(), WorkBudget::new(0).counters());
    assert_eq!(PASSES.with(std::cell::Cell::get), passes_before);
    assert_eq!(samples(&storage), 0);

    // The budget ends short of the scan bound: the guard bundle and the hash
    // pass are paid, the bound's preflight refuses before the first
    // sequence read with the rest of the allowance untouched, and the
    // refusal is Contended, never Missing.
    let mut short = WorkBudget::new(GUARD_STEPS + 1 + 4);
    assert_eq!(
        reader.lookup(&key(0x11), RETRIES, &mut short).err(),
        Some(LookupError::Contended)
    );
    assert_eq!(short.remaining(), 4);
    assert_eq!(short.counters().hashes, 1);
    assert_eq!(short.counters().visits, 0);
    assert_eq!(samples(&storage), 0);
    assert_eq!(reserved(&storage), 0);
    assert_eq!(refs(&storage, published), 1);
    assert_eq!(pinned(&storage, &reader), None);

    // Enough for the guard bundle, the hash pass, the scan bound and the
    // identity check, not for the fingerprint comparison: the fingerprint
    // is never read, no credit is taken, and the attempt is Contended. At
    // depth one the bound is two bucket visits, both buckets' pairs and the
    // two sequence validations.
    let scan_bound = 2 + PAIRS * 2 + 2;
    let mut short = WorkBudget::new(GUARD_STEPS + 1 + scan_bound + 1);
    assert_eq!(
        reader.lookup(&key(0x11), RETRIES, &mut short).err(),
        Some(LookupError::Contended)
    );
    assert_eq!(short.counters().visits, 2, "the scan ran");
    assert_eq!(
        short.remaining(),
        0,
        "the identity check spent the last step"
    );
    assert_eq!(short.counters().coordination_attempts, 0);
    assert_eq!(reserved(&storage), 0);
    assert_eq!(refs(&storage, published), 1);
}

/// Only a sample strictly before the deadline of 100 yields a lease; each
/// refusal refunds its reservation exactly once and allocates nothing.
#[test]
fn only_a_sample_strictly_before_the_deadline_acquires() {
    let storage = ready(8);
    let (fresh, stale) = (body(0x51), body(0x52));
    let id = publish(&storage, key(0x51), DEADLINE, &fresh);
    let never = publish(&storage, key(0x52), 0, &stale);
    let mut reader = storage.register().unwrap();

    ticks(&storage, &[Some(DEADLINE - 1)]);
    let before = lookup(&mut reader, &key(0x51), RETRIES).unwrap();
    assert_eq!(samples(&storage), 1);

    let refusals: [(Option<u64>, LookupError); 4] = [
        (Some(DEADLINE), LookupError::Expired),
        (Some(DEADLINE + 1), LookupError::Expired),
        (Some(u64::MAX), LookupError::Expired),
        (None, LookupError::ClockUnavailable),
    ];
    for (sample, expected) in refusals {
        let taken = samples(&storage);
        ticks(&storage, &[sample]);
        let mut spent = budget();
        let allocations = crate::instrument::allocations();
        assert_eq!(
            reader.lookup(&key(0x51), RETRIES, &mut spent).err(),
            Some(expected)
        );
        assert_eq!(crate::instrument::allocations(), allocations);
        assert_eq!(samples(&storage) - taken, 1);
        assert_eq!(spent.counters().coordination_attempts, 2);
        assert_eq!(refs(&storage, id), 2);
        assert_eq!(reserved(&storage), 1);
        assert_eq!(pinned(&storage, &reader), None);
    }
    // A zero deadline is expired for every sample, including zero.
    ticks(&storage, &[Some(0)]);
    assert_eq!(
        lookup(&mut reader, &key(0x52), RETRIES).err(),
        Some(LookupError::Expired)
    );
    assert_eq!(refs(&storage, never), 1);
    // The lease acquired at 99 reads at 101 and beyond; the deadline is the
    // record's and never moves.
    drop(before);
    assert_eq!((refs(&storage, id), reserved(&storage)), (1, 0));
}

/// A clock jump from before an object's deadline to the end of the clock's
/// range expires the object by time alone: lookups report `Expired`, and the
/// retirement era, the shard's sequence and the object's slot identity stay
/// where the jump found them.
#[test]
fn a_clock_jump_expires_by_time_and_advances_no_counter() {
    let storage = ready(8);
    let id = publish(&storage, key(0x61), DEADLINE, &body(0x61));
    let mut reader = storage.register().unwrap();
    ticks(&storage, &[Some(DEADLINE - 1)]);
    drop(lookup(&mut reader, &key(0x61), RETRIES).unwrap());
    let counters = |storage: &Storage<TestPlatform>| {
        let word = storage.live_pool().unwrap().word(id.slot_index());
        (super::grace_tests::era(storage), sequence(storage), word)
    };
    let before = counters(&storage);
    for sample in [DEADLINE, DEADLINE << 20, u64::MAX] {
        ticks(&storage, &[Some(sample)]);
        assert_eq!(
            lookup(&mut reader, &key(0x61), RETRIES).err(),
            Some(LookupError::Expired)
        );
        assert_eq!(counters(&storage), before, "sample {sample}");
    }
}

/// An expired object is reported as `Expired` before lease and retain limits,
/// after the refused attempts and with one sample on the refusal path.
#[test]
fn expiry_is_reported_ahead_of_the_limits() {
    let storage = ready_with(3, 2);
    let id = publish(&storage, key(0x53), DEADLINE, &body(0x53));
    let others = [
        publish(&storage, key(0x54), DEADLINE, &body(0x54)),
        publish(&storage, key(0x55), DEADLINE, &body(0x55)),
        publish(&storage, key(0x56), DEADLINE, &body(0x56)),
    ];
    let mut reader = storage.register().unwrap();
    let mut holder = storage.register().unwrap();

    ticks(&storage, &[Some(1)]);
    let held = [
        lookup(&mut holder, &key(0x54), RETRIES).unwrap(),
        lookup(&mut holder, &key(0x55), RETRIES).unwrap(),
        lookup(&mut holder, &key(0x56), RETRIES).unwrap(),
    ];
    ticks(&storage, &[Some(1)]);
    assert_eq!(
        lookup(&mut reader, &key(0x53), RETRIES).err(),
        Some(LookupError::LeaseLimit)
    );
    ticks(&storage, &[Some(DEADLINE)]);
    let mut spent = budget();
    let taken = samples(&storage);
    assert_eq!(
        reader.lookup(&key(0x53), RETRIES, &mut spent).err(),
        Some(LookupError::Expired)
    );
    assert_eq!(spent.counters().coordination_attempts, 1);
    assert_eq!(samples(&storage) - taken, 1);
    assert_eq!((refs(&storage, id), reserved(&storage)), (1, 3));
    drop(held);

    ticks(&storage, &[Some(1)]);
    let right = [
        lookup(&mut holder, &key(0x53), RETRIES).unwrap(),
        lookup(&mut holder, &key(0x53), RETRIES).unwrap(),
    ];
    ticks(&storage, &[Some(1)]);
    assert_eq!(
        lookup(&mut reader, &key(0x53), RETRIES).err(),
        Some(LookupError::RetainLimit)
    );
    ticks(&storage, &[Some(DEADLINE)]);
    let mut spent = budget();
    let taken = samples(&storage);
    assert_eq!(
        reader.lookup(&key(0x53), RETRIES, &mut spent).err(),
        Some(LookupError::Expired)
    );
    assert_eq!(spent.counters().coordination_attempts, 2);
    assert_eq!(samples(&storage) - taken, 1);
    assert_eq!((refs(&storage, id), reserved(&storage)), (3, 2));
    drop(right);
    for other in others {
        assert_eq!(refs(&storage, other), 1);
    }
    assert_eq!((refs(&storage, id), reserved(&storage)), (1, 0));
}

/// A candidate observed at tick 9 and replaced before its deadline of 10
/// cannot justify `Expired` at tick 10: the moved sequence refunds the
/// reservation and the attempt is spent. With attempts left the replacement
/// is acquired on its own deadline; with none left the call is Contended.
#[test]
fn a_replaced_candidate_is_never_expired_on_its_old_deadline() {
    let storage = ready(8);
    let old = publish(&storage, key(0x61), 10, &body(0x61));
    let mut reader = storage.register().unwrap();
    let replacement = body(0x62);
    let new = Mutex::new(None);

    // Two attempts: the second sees the replacement, whose deadline is far
    // away, at the sticky sample 10.
    ticks(&storage, &[Some(9), Some(10)]);
    let lease = paused(
        &storage,
        Pause::Retain,
        |storage| {
            *new.lock().unwrap() = Some(replace(storage, key(0x61), DEADLINE, &replacement).id);
        },
        || lookup(&mut reader, &key(0x61), 2).unwrap(),
    );
    let new = new.lock().unwrap().unwrap();
    assert_eq!(lease.id(), new, "the lease names the replacement");
    assert_eq!(refs(&storage, new), 2);
    // The old object's tentative right came back; its anchor awaits grace.
    assert_eq!(refs(&storage, old), 1);
    assert_eq!(reserved(&storage), 1);
    assert_eq!(rejected(), 0);
    drop(lease);

    // One attempt: the same race is Contended, never Expired, and every
    // reservation is back; the refund allocates nothing.
    let old = new;
    ticks(&storage, &[Some(9), Some(10)]);
    let third = body(0x63);
    let outcome = paused(
        &storage,
        Pause::Retain,
        |storage| {
            replace(storage, key(0x61), DEADLINE, &third);
        },
        || {
            let allocations = crate::instrument::allocations();
            let outcome = lookup(&mut reader, &key(0x61), 1).err();
            assert_eq!(crate::instrument::allocations(), allocations);
            outcome
        },
    );
    assert_eq!(outcome, Some(LookupError::Contended));
    assert_eq!(refs(&storage, old), 1);
    assert_eq!(reserved(&storage), 0);
    assert_eq!(pinned(&storage, &reader), None);
}

/// A terminal era and a leaked interval refuse every lookup as `Contended`
/// for the guard bundle alone, before any hashing, and leave the
/// registration otherwise usable.
#[test]
fn a_terminal_era_or_a_leaked_interval_refuses_before_any_attempt() {
    let storage = ready(8);
    ticks(&storage, &[Some(1)]);
    publish(&storage, key(0x31), DEADLINE, &body(0x31));
    let mut reader = storage.register().unwrap();
    let mut other = storage.register().unwrap();
    let leaked = other.enter().unwrap();
    std::mem::forget(leaked);
    let mut spent = budget();
    assert_eq!(
        other.lookup(&key(0x31), RETRIES, &mut spent).err(),
        Some(LookupError::Contended)
    );
    // The guard bundle is the only charge: no hash, no visit.
    let paid = spent.counters();
    assert_eq!((paid.hashes, paid.visits), (0, 0));
    assert_eq!(paid.comparisons + paid.updates, GUARD_STEPS);
    assert_eq!(
        hit_key(&lookup(&mut reader, &key(0x31), RETRIES).unwrap()),
        key(0x31)
    );

    storage.eras().era.store(ERA_TERMINAL, Ordering::SeqCst);
    let mut spent = budget();
    assert_eq!(
        reader.lookup(&key(0x31), RETRIES, &mut spent).err(),
        Some(LookupError::Contended)
    );
    let paid = spent.counters();
    assert_eq!((paid.hashes, paid.visits), (0, 0));
    assert_eq!(paid.comparisons + paid.updates, GUARD_STEPS);
    assert_eq!(samples(&storage), 1);
    drop(other);
}

/// A close after the witness overlaps the success: the lease reads and
/// releases normally, and the next lookup is refused before pinning.
#[test]
fn a_close_after_the_witness_leaves_the_lease_valid() {
    let storage = ready(8);
    ticks(&storage, &[Some(1)]);
    let id = publish(&storage, key(0x32), DEADLINE, &body(0x32));
    let mut reader = storage.register().unwrap();
    let lease = lookup(&mut reader, &key(0x32), RETRIES).unwrap();
    storage.close();
    assert_eq!(lease.id(), id);
    assert_eq!((refs(&storage, id), reserved(&storage)), (2, 1));
    let intervals = storage
        .registration_report(reader.index())
        .unwrap()
        .intervals;
    assert_eq!(
        lookup(&mut reader, &key(0x32), RETRIES).err(),
        Some(LookupError::Closed)
    );
    assert_eq!(
        storage
            .registration_report(reader.index())
            .unwrap()
            .intervals,
        intervals
    );
    drop(lease);
    assert_eq!((refs(&storage, id), reserved(&storage)), (1, 0));
}

/// The facade is the request path: a registration and a lease taken
/// through it borrow the storage, so dropping the facade leaves the lease's
/// bytes readable and the registration usable for exit, and closes
/// admission with one store that touches no mapping; the next lookup is
/// refused before pinning. Facade issuance, registration and the lookup
/// allocate nothing.
#[test]
fn a_lease_and_a_registration_outlive_the_facade() {
    let storage = ready(8);
    let log = storage.platform.log();
    ticks(&storage, &[Some(1)]);
    let body = body(0x33);
    let id = publish(&storage, key(0x33), DEADLINE, &body);
    let allocations = crate::instrument::allocations();
    let cache = storage.issue_cache().unwrap();
    let mut reader = cache.register().unwrap();
    let lease = cache
        .lookup(&mut reader, &key(0x33), RETRIES, &mut budget())
        .unwrap();
    assert_eq!(crate::instrument::allocations(), allocations);
    assert_eq!((refs(&storage, id), reserved(&storage)), (2, 1));
    assert_eq!(pinned(&storage, &reader), None);
    assert_eq!(
        storage.issue_cache().err(),
        Some(super::CacheError::AlreadyIssued)
    );

    let calls = log.all().len();
    let allocations = crate::instrument::allocations();
    drop(cache);
    assert_eq!(crate::instrument::allocations(), allocations);
    assert_eq!(log.all().len(), calls);
    assert!(storage.is_closed());
    assert_eq!((refs(&storage, id), reserved(&storage)), (2, 1));
    let taken = samples(&storage);
    assert_eq!(
        lookup(&mut reader, &key(0x33), RETRIES).err(),
        Some(LookupError::Closed)
    );
    assert_eq!(samples(&storage), taken);
    assert_eq!(pinned(&storage, &reader), None);
    assert_eq!(storage.issue_cache().err(), Some(super::CacheError::Closed));
    drop(lease);
    assert_eq!((refs(&storage, id), reserved(&storage)), (1, 0));
    drop(reader);
    assert_eq!(storage.outstanding().registrations, 0);
}

/// Two keys with one forced tag in one chain each return their own object,
/// the second paying one more fingerprint comparison; the all-zero key and a
/// key differing from it in its last byte hit correctly under the production
/// hasher.
#[test]
fn colliding_and_low_entropy_keys_return_their_own_bytes() {
    let slot_count = 8;
    let limits = [8usize];
    let mut storage = storage(slot_count, &index_config(&limits, (1, 1), 1));
    install_seam(&mut storage, one_chain);
    ticks(&storage, &[Some(1)]);
    // Keys 0x10..0x1F share tag and bucket 1 under the seam, each with its
    // own fingerprint.
    let first = publish(&storage, key(0x11), DEADLINE, &body(0x11));
    let second = publish(&storage, key(0x12), DEADLINE, &body(0x12));
    let mut reader = storage.register().unwrap();
    let mut spent_first = budget();
    let a = reader
        .lookup(&key(0x11), RETRIES, &mut spent_first)
        .unwrap();
    let mut spent_second = budget();
    let b = reader
        .lookup(&key(0x12), RETRIES, &mut spent_second)
        .unwrap();
    assert_eq!((a.id(), b.id()), (first, second));
    // Both scans compare two tags; the second key also validates and
    // compares the first candidate's fingerprint before reaching its own.
    assert_eq!(
        spent_second.counters().comparisons,
        spent_first.counters().comparisons + 2
    );
    assert_eq!((refs(&storage, first), refs(&storage, second)), (2, 2));
    drop((a, b));

    // Production hashing: the zero key and its one-byte neighbour.
    let storage = ready(8);
    ticks(&storage, &[Some(1)]);
    let zero = [0u8; 32];
    let mut neighbour = [0u8; 32];
    neighbour[31] = 1;
    publish(&storage, zero, DEADLINE, &[0xA0; 24]);
    publish(&storage, neighbour, DEADLINE, &[0xA1; 24]);
    let mut reader = storage.register().unwrap();
    assert_eq!(hit_key(&lookup(&mut reader, &zero, RETRIES).unwrap()), zero);
    assert_eq!(
        hit_key(&lookup(&mut reader, &neighbour, RETRIES).unwrap()),
        neighbour
    );
    let mut other = [0u8; 32];
    other[0] = 1;
    assert_eq!(
        lookup(&mut reader, &other, RETRIES).err(),
        Some(LookupError::Missing)
    );
}

/// Pausing before the pin, the snapshot, the reservation and the final
/// bracket while another thread removes, replaces or closes: no lease comes
/// of the paused candidate, every reservation is back, the refusal names
/// what happened, and the pin is cleared.
#[test]
fn paused_races_yield_no_lease_and_exact_rollback() {
    let pauses = [
        Pause::Pin,
        Pause::Snapshot,
        Pause::Retain,
        Pause::FinalBracket,
    ];
    for at in pauses {
        // Removal: the candidate is gone; a second attempt proves absence.
        let storage = ready(8);
        ticks(&storage, &[Some(1)]);
        let old = publish(&storage, key(0x81), DEADLINE, &body(0x81));
        let mut reader = storage.register().unwrap();
        let outcome = paused(
            &storage,
            at,
            |storage| remove(storage, &key(0x81), old),
            || lookup(&mut reader, &key(0x81), 2).err(),
        );
        assert_eq!(outcome, Some(LookupError::Missing), "{at:?}");
        assert_eq!(refs(&storage, old), 1, "{at:?}");
        assert_eq!(reserved(&storage), 0, "{at:?}");
        assert_eq!(pinned(&storage, &reader), None, "{at:?}");
        assert_eq!(rejected(), 0, "{at:?}");

        // Removal with one attempt: Contended at the pauses that had
        // already copied the candidate, Missing at those that had not.
        let old = publish(&storage, key(0x82), DEADLINE, &body(0x82));
        let outcome = paused(
            &storage,
            at,
            |storage| remove(storage, &key(0x82), old),
            || lookup(&mut reader, &key(0x82), 1).err(),
        );
        let expected = if matches!(at, Pause::Pin | Pause::Snapshot) {
            LookupError::Missing
        } else {
            LookupError::Contended
        };
        assert_eq!(outcome, Some(expected), "{at:?}");
        assert_eq!((refs(&storage, old), reserved(&storage)), (1, 0), "{at:?}");

        // Replacement: the paused candidate is never the lease; the
        // replacement is, with its own bytes and right.
        let old = publish(&storage, key(0x83), DEADLINE, &body(0x83));
        let new = Mutex::new(None);
        let lease = paused(
            &storage,
            at,
            |storage| {
                *new.lock().unwrap() = Some(replace(storage, key(0x83), DEADLINE, &body(0x84)).id);
            },
            || lookup(&mut reader, &key(0x83), 2).unwrap(),
        );
        let new = new.lock().unwrap().unwrap();
        assert_eq!(lease.id(), new, "{at:?}");
        assert_eq!((refs(&storage, old), refs(&storage, new)), (1, 2), "{at:?}");
        assert_eq!(reserved(&storage), 1, "{at:?}");
        drop(lease);
        assert_eq!(reserved(&storage), 0, "{at:?}");

        // Close: refused Closed wherever the close lands before the
        // witness, with the reservation back if one was taken. A close
        // that lands before the pin is caught by the entry's own cutoff
        // read: the pin is cleared again, no interval is counted, and no
        // sample is taken.
        let before_close = samples(&storage);
        let outcome = paused(
            &storage,
            at,
            |storage| storage.close(),
            || lookup(&mut reader, &key(0x83), 2).err(),
        );
        assert_eq!(outcome, Some(LookupError::Closed), "{at:?}");
        assert_eq!((refs(&storage, new), reserved(&storage)), (1, 0), "{at:?}");
        assert_eq!(pinned(&storage, &reader), None, "{at:?}");
        if at == Pause::Pin {
            assert_eq!(samples(&storage), before_close);
        }
        // After close every lookup refuses before pinning or hashing.
        let taken = samples(&storage);
        let mut spent = budget();
        assert_eq!(
            reader.lookup(&key(0x83), RETRIES, &mut spent).err(),
            Some(LookupError::Closed)
        );
        assert_eq!(spent.counters(), WorkBudget::new(0).counters());
        assert_eq!(samples(&storage), taken);
        let entered = if at == Pause::Pin { 3 } else { 4 };
        assert_eq!(
            storage
                .registration_report(reader.index())
                .unwrap()
                .intervals,
            entered,
            "{at:?}"
        );
    }
}

/// Expiry at the final bracket's sample, under an unchanged mapping,
/// refunds and returns Expired; the same sample with a moved mapping is
/// never Expired, since the deadline it would judge belongs to the mapping
/// that moved.
#[test]
fn expiry_at_the_final_bracket_is_witnessed_only_under_an_unchanged_mapping() {
    let storage = ready(8);
    let id = publish(&storage, key(0x91), 10, &body(0x91));
    let mut reader = storage.register().unwrap();
    ticks(&storage, &[Some(10)]);
    let outcome = paused(
        &storage,
        Pause::FinalBracket,
        |_| {},
        || lookup(&mut reader, &key(0x91), 1).err(),
    );
    assert_eq!(outcome, Some(LookupError::Expired));
    assert_eq!((refs(&storage, id), reserved(&storage)), (1, 0));

    ticks(&storage, &[Some(10)]);
    let outcome = paused(
        &storage,
        Pause::FinalBracket,
        |storage| {
            replace(storage, key(0x91), 10, &body(0x92));
        },
        || lookup(&mut reader, &key(0x91), 1).err(),
    );
    assert_eq!(outcome, Some(LookupError::Contended));
    assert_eq!((refs(&storage, id), reserved(&storage)), (1, 0));
}

/// `L - 1`/`L` and `C - 1`/`C` refuse `LeaseLimit` and `RetainLimit` with
/// exactly one refund each; ten leases on one payload charge ten credits and
/// rights and one record, slot and payload, and the independent credit,
/// right and anchor ledgers agree at every prefix.
#[test]
fn limits_refuse_with_one_refund_and_ten_leases_charge_one_payload() {
    let storage = ready_with(5, 3);
    ticks(&storage, &[Some(1)]);
    let a = publish(&storage, key(0xA1), DEADLINE, &body(0xA1));
    let b = publish(&storage, key(0xA2), DEADLINE, &body(0xA2));
    let mut reader = storage.register().unwrap();

    // C = 3: three leases on `a`, the fourth refused with the credit paid
    // and refunded and the right attempt paid.
    let a1 = lookup(&mut reader, &key(0xA1), RETRIES).unwrap();
    let a2 = lookup(&mut reader, &key(0xA1), RETRIES).unwrap();
    let a3 = lookup(&mut reader, &key(0xA1), RETRIES).unwrap();
    assert_eq!((refs(&storage, a), reserved(&storage)), (4, 3));
    let mut spent = budget();
    let allocations = crate::instrument::allocations();
    assert_eq!(
        reader.lookup(&key(0xA1), RETRIES, &mut spent).err(),
        Some(LookupError::RetainLimit)
    );
    assert_eq!(crate::instrument::allocations(), allocations);
    // One credit attempt and one right attempt, plus the spurious weak
    // failures Miri injects.
    if !cfg!(miri) {
        assert_eq!(spent.counters().coordination_attempts, 2);
    }
    assert_eq!((refs(&storage, a), reserved(&storage)), (4, 3));

    // L = 5: two more on `b` fill the credits; the sixth is refused with
    // one paid attempt and no right touched.
    let _b1 = lookup(&mut reader, &key(0xA2), RETRIES).unwrap();
    let _b2 = lookup(&mut reader, &key(0xA2), RETRIES).unwrap();
    assert_eq!((refs(&storage, b), reserved(&storage)), (3, 5));
    let mut spent = budget();
    let allocations = crate::instrument::allocations();
    assert_eq!(
        reader.lookup(&key(0xA2), RETRIES, &mut spent).err(),
        Some(LookupError::LeaseLimit)
    );
    assert_eq!(crate::instrument::allocations(), allocations);
    if !cfg!(miri) {
        assert_eq!(spent.counters().coordination_attempts, 1);
    }
    assert_eq!((refs(&storage, b), reserved(&storage)), (3, 5));
    drop(a3);
    assert_eq!(reserved(&storage), 4);
    let _b3 = lookup(&mut reader, &key(0xA2), RETRIES).unwrap();
    assert_eq!(refs(&storage, b), 4);
    assert_eq!((a1.id(), a2.id()), (a, a));

    // Ten leases on one payload.
    let storage = ready_with(16, 16);
    ticks(&storage, &[Some(1)]);
    let id = publish(&storage, key(0xA3), DEADLINE, &body(0xA3));
    let mut reader = storage.register().unwrap();
    let ledger_before = storage.pool_report().unwrap().ledger.unwrap();
    let mut leases = Vec::with_capacity(10);
    for n in 1..=10 {
        leases.push(lookup(&mut reader, &key(0xA3), RETRIES).unwrap());
        assert_eq!(refs(&storage, id), n + 1);
        assert_eq!(reserved(&storage), n);
        assert_eq!(
            storage.pool_report().unwrap().ledger.unwrap(),
            ledger_before
        );
    }
    assert_eq!(ledger_before.slots.resident, 1);
    for expected in (0..10).rev() {
        drop(leases.swap_remove((expected * 7) % (expected + 1)));
        assert_eq!(refs(&storage, id), expected + 1);
        assert_eq!(reserved(&storage), expected);
    }
    assert_eq!(
        storage.slot_state(SlotIndex(id.slot_index())),
        Some((SlotState::Resident, id.incarnation()))
    );
}

/// The credits a registered lookup takes stay with its record: the first
/// lookup borrows every credit below `L` at once, later ones take from the
/// record's idle credits with one attempt, a lease returns to the record it
/// was acquired through on whatever thread it drops, a second registration
/// at the limit takes one idle credit from the first with one more attempt,
/// `LeaseLimit` costs one attempt and means every credit backs a lease,
/// dropping a registration gives its idle credits back to the engine-wide
/// count, and a record's late returns wait for its next claimant. The
/// independent count, `L` less what the two words say is idle, matches the
/// report at every step.
#[test]
fn credits_park_in_the_record_and_are_taken_only_at_the_limit() {
    let storage = ready_with(5, 8);
    ticks(&storage, &[Some(1)]);
    publish(&storage, key(0xB1), DEADLINE, &body(0xB1));
    let taken = || storage.leases().reserved.load(Ordering::Relaxed);
    let idle = |index: usize| record_credits(&storage, index, Ordering::Relaxed);
    let mut first = storage.register().unwrap();
    let mut second = storage.register().unwrap();
    let (f, s) = (first.index().0, second.index().0);

    // One lookup borrows all five: one backs the lease, four wait.
    let mut exact = budget();
    let f1 = lookup_with(&mut first, &key(0xB1), &mut exact).unwrap();
    assert_eq!(exact.counters().coordination_attempts, 2);
    assert_eq!(
        (taken(), idle(f), idle(s), reserved(&storage)),
        (5, 4, 0, 1)
    );

    // The second registration finds the count at `L` and takes one of the
    // first's idle credits: the refused borrow and the take are one attempt
    // each, then the right.
    let mut exact = budget();
    let s1 = lookup_with(&mut second, &key(0xB1), &mut exact).unwrap();
    assert_eq!(exact.counters().coordination_attempts, 3);
    assert_eq!(
        (taken(), idle(f), idle(s), reserved(&storage)),
        (5, 3, 0, 2)
    );

    // Its lease returns to its own record, and its next lookup takes from
    // there with one attempt.
    drop(s1);
    assert_eq!((idle(f), idle(s), reserved(&storage)), (3, 1, 1));
    let mut exact = budget();
    let s1 = lookup_with(&mut second, &key(0xB1), &mut exact).unwrap();
    assert_eq!(exact.counters().coordination_attempts, 2);
    assert_eq!((idle(f), idle(s), reserved(&storage)), (3, 0, 2));

    // A lease dropped on another thread returns to the record it came from.
    std::thread::scope(|scope| {
        scope.spawn(move || drop(f1));
    });
    assert_eq!((idle(f), idle(s), reserved(&storage)), (4, 0, 1));

    // Every credit backing a lease: the refusal is one paid attempt on
    // either registration, with the count and the idle words untouched.
    let held: Vec<_> = (0..4)
        .map(|_| lookup(&mut first, &key(0xB1), RETRIES).unwrap())
        .collect();
    assert_eq!(
        (taken(), idle(f), idle(s), reserved(&storage)),
        (5, 0, 0, 5)
    );
    for reader in [&mut first, &mut second] {
        let mut spent = budget();
        assert_eq!(
            lookup_with(reader, &key(0xB1), &mut spent).err(),
            Some(LookupError::LeaseLimit)
        );
        assert_eq!(spent.counters().coordination_attempts, 1);
        assert_eq!(
            (taken(), idle(f), idle(s), reserved(&storage)),
            (5, 0, 0, 5)
        );
    }

    // Dropping the second registration with its lease live gives back
    // nothing, since it holds nothing idle; the lease's later return parks in
    // the unclaimed record, and the next claimant of that record starts
    // with it.
    drop(second);
    assert_eq!((taken(), idle(s), reserved(&storage)), (5, 0, 5));
    drop(s1);
    assert_eq!((taken(), idle(s), reserved(&storage)), (5, 1, 4));
    let mut third = storage.register().unwrap();
    assert_eq!(third.index().0, s);
    let mut exact = budget();
    let t1 = lookup_with(&mut third, &key(0xB1), &mut exact).unwrap();
    assert_eq!(exact.counters().coordination_attempts, 2);
    assert_eq!(
        (taken(), idle(f), idle(s), reserved(&storage)),
        (5, 0, 0, 5)
    );

    // Dropping the first registration returns its idle credits to the count.
    drop(held);
    assert_eq!((taken(), idle(f), reserved(&storage)), (5, 4, 1));
    drop(first);
    assert_eq!((taken(), idle(f), reserved(&storage)), (1, 0, 1));
    drop(t1);
    drop(third);
    assert_eq!(
        (taken(), idle(f), idle(s), reserved(&storage)),
        (0, 0, 0, 0)
    );
    assert_eq!(storage.outstanding().leases, 0);
}

/// Several registered readers at a tight limit, each taking leases on
/// its own thread, handing some to another thread to drop, and giving its
/// registration up and claiming one again mid-run: the credits are
/// conserved, no record word is left holding a credit the engine-wide count
/// does not back or below zero, every refusal is `LeaseLimit` or
/// `Contended`, and once every lease and registration is gone nothing is
/// reserved and nothing is parked.
#[test]
fn concurrent_readers_at_a_tight_limit_conserve_credits() {
    const READERS: usize = 6;
    const ROUNDS: usize = 10_000;
    let config = super::config::StorageConfig {
        lease_limit: 10,
        object_rights: 64,
        reader_limit: READERS,
        ..storage_config(8)
    };
    let storage = storage_from(
        &config,
        &index_config(&[8], (1, 1), 1),
        TestPlatform::heap(PAGE),
    );
    ticks(&storage, &[Some(1)]);
    publish(&storage, key(0xC1), DEADLINE, &body(0xC1));
    let storage = &storage;
    let hits = std::sync::atomic::AtomicUsize::new(0);
    let refusals = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for worker in 0..READERS {
            let hits = &hits;
            let refusals = &refusals;
            scope.spawn(move || {
                let mut seed = 0x9E37_79B9u32 ^ (worker as u32 + 1).wrapping_mul(0x85EB_CA6B);
                let mut next = move || {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    seed
                };
                let mut reader = storage.register().unwrap();
                for round in 0..ROUNDS {
                    let want = 1 + next() as usize % 5;
                    let mut held = Vec::with_capacity(want);
                    for _ in 0..want {
                        match reader.lookup(&key(0xC1), RETRIES, &mut budget()) {
                            Ok(lease) => held.push(lease),
                            Err(LookupError::LeaseLimit | LookupError::Contended) => {
                                refusals.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(error) => panic!("{error:?}"),
                        }
                    }
                    hits.fetch_add(held.len(), Ordering::Relaxed);
                    // Every other round the leases drop on another thread.
                    if round % 2 == 1 {
                        std::thread::scope(|inner| {
                            inner.spawn(move || drop(held));
                        });
                    } else {
                        drop(held);
                    }
                    // Every seventh round the reader gives its record up and
                    // claims one again, so records change hands with
                    // credits parked and leases of the old claimant live.
                    if round % 7 == 6 {
                        drop(reader);
                        reader = storage.register().unwrap();
                    }
                }
            });
        }
    });
    assert!(hits.load(Ordering::Relaxed) >= READERS * ROUNDS);
    let leases = storage.leases();
    assert_eq!(leases.reserved.load(Ordering::SeqCst), 0);
    assert_eq!(storage.lease_report().unwrap().reserved, 0);
    for index in 0..READERS {
        let record = &storage.registrations()[index];
        assert_eq!(record.idle.load(Ordering::SeqCst), 0, "record {index}");
        assert_eq!(
            storage.returns()[index].returned.load(Ordering::SeqCst),
            0,
            "line {index}"
        );
        assert!(!record.claimed.load(Ordering::SeqCst));
    }
    assert_eq!(storage.outstanding().leases, 0);
}

#[test]
fn a_take_from_a_full_pool_trims_only_when_the_budget_pays_for_both_steps() {
    const LIMIT: usize = 100;
    const HELD: usize = 66;
    let storage = ready_with(LIMIT, 8);
    let reader = storage.register().unwrap();
    let r = reader.index().0;
    storage.registrations()[r]
        .idle
        .store(HELD, Ordering::Relaxed);
    storage.leases().reserved.store(HELD, Ordering::Relaxed);
    let taken = || storage.leases().reserved.load(Ordering::Relaxed);
    let idle = || record_credits(&storage, r, Ordering::Relaxed);

    let mut one = WorkBudget::new(1);
    assert_eq!(
        reserve_credit(&storage, LIMIT, Credit::Record(r), &mut one),
        Ok(())
    );
    assert_eq!((taken(), idle()), (HELD, HELD - 1));

    let mut two = WorkBudget::new(2);
    assert_eq!(
        reserve_credit(&storage, LIMIT, Credit::Record(r), &mut two),
        Ok(())
    );
    assert_eq!((taken(), idle()), (17, 15));

    return_credit(&storage, Credit::Record(r));
    return_credit(&storage, Credit::Record(r));
    drop(reader);
    assert_eq!((taken(), idle()), (0, 0));
}

#[test]
fn a_refusal_skips_a_lender_whose_bit_a_sweep_cleared() {
    const LIMIT: usize = 2;
    let storage = ready_with(LIMIT, 8);
    let borrower = storage.register().unwrap();
    let lender = storage.register().unwrap();
    let (b, l) = (borrower.index().0, lender.index().0);
    let scanned = || RECORDS_SCANNED.with(std::cell::Cell::get);
    let reserve =
        |index: usize| reserve_credit(&storage, LIMIT, Credit::Record(index), &mut budget());

    // The lender borrows both credits and parks one; the borrower, at the
    // limit, takes that one and remembers the lender.
    assert_eq!(reserve(l), Ok(()));
    assert_eq!(reserve(b), Ok(()));
    assert_eq!(storage.registrations()[b].lender.load(Ordering::Relaxed), l);

    // The next refusal visits the lender and sweeps its bit clear.
    assert_eq!(reserve(b), Err(CreditError::LeaseLimit));
    let (map, bit) = (&storage.parked()[l / 64].bits, 1u64 << (l % 64));
    assert_eq!(map.load(Ordering::Relaxed) & bit, 0);

    // With the lender's bit clear, the refusal completes after reading the
    // map.
    let before = scanned();
    assert_eq!(reserve(b), Err(CreditError::LeaseLimit));
    assert_eq!(scanned() - before, 0);

    return_credit(&storage, Credit::Record(b));
    return_credit(&storage, Credit::Record(l));
    drop((borrower, lender));
    assert_eq!(storage.leases().reserved.load(Ordering::Relaxed), 0);
}

fn three_words(limit: usize) -> Storage<TestPlatform> {
    let config = super::config::StorageConfig {
        lease_limit: limit,
        object_rights: 8,
        reader_limit: 130,
        ..storage_config(8)
    };
    let storage = storage_from(
        &config,
        &index_config(&[8], (1, 1), 1),
        TestPlatform::heap(PAGE),
    );
    assert_eq!(storage.parked().len(), 3);
    storage.leases().reserved.store(limit, Ordering::Relaxed);
    storage
}

fn map_bits(storage: &Storage<TestPlatform>) -> Vec<u64> {
    storage
        .parked()
        .iter()
        .map(|word| word.bits.load(Ordering::Relaxed))
        .collect()
}

fn sweep_counts(storage: &Storage<TestPlatform>) -> Vec<u64> {
    storage
        .parked()
        .iter()
        .map(|word| word.sweeps.load(Ordering::Relaxed))
        .collect()
}

/// A refusal at the limit pays one visit for the line and one for the pool
/// of every record but its own, sweeps clear the bits it visited and only
/// those, and counts one finished sweep in each map word.
#[test]
fn a_refusal_across_three_map_words_sweeps_every_record_but_its_own() {
    const LIMIT: usize = 4;
    const RECORDS: usize = 130;
    // Bits 2 and 3 of the last word lie beyond RECORDS.
    const PAST: u64 = 0b1100;
    let storage = three_words(LIMIT);
    let scanned = || RECORDS_SCANNED.with(std::cell::Cell::get);
    let own = 70;
    storage.registrations()[own]
        .lender
        .store(own, Ordering::Relaxed);
    for (word, bits) in storage
        .parked()
        .iter()
        .zip([u64::MAX, u64::MAX, 0b11 | PAST])
    {
        word.bits.store(bits, Ordering::Relaxed);
    }

    let mut paid = budget();
    let before = scanned();
    assert_eq!(
        reserve_credit(&storage, LIMIT, Credit::Record(own), &mut paid),
        Err(CreditError::LeaseLimit)
    );
    let others = RECORDS - 1;
    assert_eq!(scanned() - before, 2 * others);
    let counters = paid.counters();
    assert_eq!(counters.visits, 2 * others);
    // The failed reservation on the engine-wide counter costs one
    // coordination attempt.
    assert_eq!(counters.coordination_attempts, 1);
    // Each swept word costs one update per cleared bit plus three updates.
    assert_eq!(counters.updates, (64 + 3) + (63 + 3) + (2 + 3));
    assert_eq!(map_bits(&storage), [0, 1 << (own % 64), PAST]);
    assert_eq!(sweep_counts(&storage), [1 << 32; 3]);
    storage.leases().reserved.store(0, Ordering::Relaxed);
}

/// A take at the limit whose credit waits in the third map word pays for
/// sweeping the two preceding words, takes from the flagged line holding
/// the credit, records that lender and leaves the third word's bits set.
#[test]
fn a_take_at_the_limit_sweeps_earlier_words_and_takes_from_a_later_one() {
    const LIMIT: usize = 4;
    let storage = three_words(LIMIT);
    let scanned = || RECORDS_SCANNED.with(std::cell::Cell::get);
    let (own, last) = (3, 129);
    storage.registrations()[own]
        .lender
        .store(own, Ordering::Relaxed);
    for (word, bits) in storage.parked().iter().zip([u64::MAX, u64::MAX, 0b11]) {
        word.bits.store(bits, Ordering::Relaxed);
    }
    storage.returns()[last].returned.store(1, Ordering::Relaxed);

    let mut paid = budget();
    let before = scanned();
    assert_eq!(
        reserve_credit(&storage, LIMIT, Credit::Record(own), &mut paid),
        Ok(())
    );
    assert_eq!(scanned() - before, 2 * 63 + 2 * 64 + 2);
    let counters = paid.counters();
    assert_eq!(counters.visits, 2 * 63 + 2 * 64 + 2);
    // The failed reservation on the engine-wide counter and the take cost
    // one coordination attempt each.
    assert_eq!(counters.coordination_attempts, 2);
    assert_eq!(counters.updates, (63 + 3) + (64 + 3));
    assert_eq!(map_bits(&storage), [1 << own, 0, 0b11]);
    assert_eq!(sweep_counts(&storage), [1 << 32, 1 << 32, 0]);
    assert_eq!(record_credits(&storage, last, Ordering::Relaxed), 0);
    assert_eq!(
        storage.registrations()[own].lender.load(Ordering::Relaxed),
        last
    );
    assert_eq!(storage.leases().reserved.load(Ordering::Relaxed), LIMIT);
    storage.leases().reserved.store(0, Ordering::Relaxed);
}

#[test]
fn a_budget_spent_inside_a_later_map_word_refuses_with_that_word_unswept() {
    const LIMIT: usize = 4;
    let storage = three_words(LIMIT);
    let scanned = || RECORDS_SCANNED.with(std::cell::Cell::get);
    let own = 3;
    storage.registrations()[own]
        .lender
        .store(own, Ordering::Relaxed);
    for (word, bits) in storage.parked().iter().zip([u64::MAX, u64::MAX, 0b11]) {
        word.bits.store(bits, Ordering::Relaxed);
    }

    let first_word = 2 * 63 + (63 + 3);
    let mut paid = WorkBudget::new(1 + first_word + 10);
    let before = scanned();
    assert_eq!(
        reserve_credit(&storage, LIMIT, Credit::Record(own), &mut paid),
        Err(CreditError::BudgetExhausted)
    );
    assert_eq!(paid.remaining(), 0);
    let counters = paid.counters();
    assert_eq!(counters.coordination_attempts, 1);
    assert_eq!(counters.visits, 2 * 63 + 10);
    assert_eq!(counters.updates, 63 + 3);
    assert_eq!(scanned() - before, 2 * 63 + 10);
    assert_eq!(map_bits(&storage), [1 << own, u64::MAX, 0b11]);
    assert_eq!(sweep_counts(&storage), [1 << 32, 0, 0]);
    storage.leases().reserved.store(0, Ordering::Relaxed);
}

type SweepStep = Box<dyn FnMut(bool)>;

thread_local! {
    static SWEEP_STEP: std::cell::RefCell<Option<SweepStep>> =
        const { std::cell::RefCell::new(None) };
}

fn sweep_step(after_clear: bool) {
    SWEEP_STEP.with(|step| {
        if let Some(step) = step.borrow_mut().as_mut() {
            step(after_clear);
        }
    });
}

/// A return lands on a record whose bit is set just before a sweep clears
/// that bit, and a second borrower reserves while the bit is clear: the
/// credit sits idle on the record's line, so that borrower may not refuse
/// with `LeaseLimit`, and the sweep's reload then finds and takes the
/// credit.
#[test]
fn a_reservation_inside_a_sweep_window_refuses_as_contended() {
    const LIMIT: usize = 2;
    let config = super::config::StorageConfig {
        lease_limit: LIMIT,
        object_rights: 8,
        reader_limit: 3,
        ..storage_config(8)
    };
    let storage: &'static Storage<TestPlatform> = Box::leak(Box::new(storage_from(
        &config,
        &index_config(&[8], (1, 1), 1),
        TestPlatform::heap(PAGE),
    )));
    let scanner = storage.register().unwrap();
    let lender = storage.register().unwrap();
    let borrower = storage.register().unwrap();
    let (a, x, d) = (scanner.index().0, lender.index().0, borrower.index().0);
    let reserve =
        move |index: usize| reserve_credit(storage, LIMIT, Credit::Record(index), &mut budget());

    // The lender borrows both credits and takes the one it parked, which
    // leaves its bit set over an empty record.
    assert_eq!(reserve(x), Ok(()));
    assert_eq!(reserve(x), Ok(()));
    assert_eq!(record_credits(storage, x, Ordering::Relaxed), 0);

    let inside = std::rc::Rc::new(std::cell::Cell::new(None));
    let seen = std::rc::Rc::clone(&inside);
    SWEEP_STEP.with(|step| {
        *step.borrow_mut() = Some(Box::new(move |after_clear| {
            if after_clear {
                seen.set(Some(reserve(d)));
            } else {
                return_credit(storage, Credit::Record(x));
            }
        }));
    });
    PAUSE_IN_SWEEP.with(|hook| hook.set(Some(sweep_step)));
    let outcome = reserve(a);
    SWEEP_STEP.with(|step| step.borrow_mut().take());

    assert_eq!(inside.get(), Some(Err(CreditError::Contended)));
    assert_eq!(outcome, Ok(()));
    assert_eq!(record_credits(storage, x, Ordering::Relaxed), 0);

    return_credit(storage, Credit::Record(a));
    return_credit(storage, Credit::Record(x));
    drop((scanner, lender, borrower));
    assert_eq!(storage.leases().reserved.load(Ordering::Relaxed), 0);
}

fn handed_off<'s>(
    storage: &'s Storage<TestPlatform>,
    n: u8,
    budget: &mut WorkBudget,
) -> (
    super::Resident<'s, TestPlatform>,
    ExtentLease<'s, TestPlatform>,
) {
    completed(storage, key(n), DEADLINE, &body(n))
        .handoff(budget)
        .ok()
        .unwrap()
}

/// A refused reservation visits each flagged record at most once per
/// parking event.
#[test]
fn shared_reservations_take_parked_credits_and_refusals_scan_once() {
    let storage = ready_sized(5, 8, 16);
    ticks(&storage, &[Some(1)]);
    publish(&storage, key(0xB1), DEADLINE, &body(0xB1));
    let taken = || storage.leases().reserved.load(Ordering::Relaxed);
    let idle = |index: usize| record_credits(&storage, index, Ordering::Relaxed);
    let scanned = || RECORDS_SCANNED.with(std::cell::Cell::get);
    let mut first = storage.register().unwrap();
    let f = first.index().0;

    // One lookup borrows all five and parks four in the record.
    let f1 = lookup(&mut first, &key(0xB1), RETRIES).unwrap();
    assert_eq!((taken(), idle(f), reserved(&storage)), (5, 4, 1));

    // The refused handoff visits the flagged record twice, its empty return
    // line and then its pool, and takes from the pool.
    let mut exact = budget();
    let before = scanned();
    let (resident, handed) = handed_off(&storage, 0xB2, &mut exact);
    assert_eq!(exact.counters().coordination_attempts, 2);
    assert_eq!(scanned() - before, 2);
    assert_eq!((taken(), idle(f), reserved(&storage)), (5, 3, 2));

    let mut exact = budget();
    let acquired = resident.acquire(Some(1), &mut exact).unwrap();
    assert_eq!(exact.counters().coordination_attempts, 3);
    assert_eq!((taken(), idle(f), reserved(&storage)), (5, 2, 3));
    drop(acquired);
    drop(handed);
    drop(resident);
    assert_eq!((taken(), idle(f), reserved(&storage)), (3, 2, 1));

    // A late return parks one credit in the unclaimed record.
    drop(first);
    assert_eq!((taken(), idle(f), reserved(&storage)), (1, 0, 1));
    drop(f1);
    assert_eq!((taken(), idle(f), reserved(&storage)), (1, 1, 0));
    let mut held = Vec::new();
    for n in 0..5u8 {
        let mut exact = budget();
        held.push(handed_off(&storage, 0xC0 + n, &mut exact));
        let attempts = if n == 4 { 2 } else { 1 };
        assert_eq!(exact.counters().coordination_attempts, attempts, "{n}");
    }
    assert_eq!((taken(), idle(f), reserved(&storage)), (5, 0, 5));

    // The first refused handoff visits the one record the map still flags,
    // its return line and then its pool, and clears its bit; the second
    // visits none.
    for expected in [2, 0] {
        let mut spent = budget();
        let before = scanned();
        let refused = completed(&storage, key(0xD0), DEADLINE, &body(0xD0))
            .handoff(&mut spent)
            .err()
            .map(|(_, error)| error);
        assert_eq!(refused, Some(super::HandoffError::LeaseLimit));
        assert_eq!(spent.counters().coordination_attempts, 1);
        assert_eq!(scanned() - before, expected);
        assert_eq!((taken(), idle(f), reserved(&storage)), (5, 0, 5));
    }

    drop(held.pop());
    let mut again = storage.register().unwrap();
    assert_eq!(again.index().0, f);
    drop(lookup(&mut again, &key(0xB1), RETRIES).unwrap());
    assert_eq!((taken(), idle(f), reserved(&storage)), (5, 1, 4));
    let mut exact = budget();
    let before = scanned();
    let late = handed_off(&storage, 0xD1, &mut exact);
    assert_eq!(exact.counters().coordination_attempts, 2);
    assert_eq!(scanned() - before, 1);
    assert_eq!((taken(), idle(f), reserved(&storage)), (5, 0, 5));
    drop(late);
    drop(held);
    drop(again);
    assert_eq!((taken(), idle(f), reserved(&storage)), (0, 0, 0));
}

/// A stale identity planted in a bucket and a malformed link each fail
/// closed before any fingerprint read, with the pre-access marker fired,
/// and are never reported as absent. A tag match whose incarnation bits
/// differ is never a lease, even over the slot of the key looked up, and
/// one whose object carries another fingerprint is a miss for that
/// candidate.
#[test]
fn stale_identities_and_corrupt_links_fail_closed_before_the_fingerprint_read() {
    let slot_count = 8;
    let limits = [8usize];
    let mut storage = storage(slot_count, &index_config(&limits, (1, 1), 1));
    install_seam(&mut storage, one_chain);
    ticks(&storage, &[Some(1)]);
    let id = publish(&storage, key(0x11), DEADLINE, &body(0x11));
    let route = storage.route(&key(0x12)).unwrap();
    let published = storage.route(&key(0x11)).unwrap();
    assert_eq!(
        (route.shard(), route.bucket(), route.tag()),
        (published.shard(), published.bucket(), published.tag())
    );
    assert_ne!(route.fingerprint(), published.fingerprint());
    let tag = route.tag();
    let mut reader = storage.register().unwrap();
    let index = storage.index.as_ref().unwrap();
    let shard = index.image.shard(ShardIndex(0)).unwrap();
    // SAFETY: the index mapping is live.
    let buckets = unsafe { shard.buckets(&index.mapping) };
    let bucket = &buckets[route.bucket()];
    assert_eq!(bucket.control(), 1);
    let marker = rejected();

    // The second pair of the chain names the published slot at an
    // incarnation it never had. A lookup of a key that shares the chain
    // passes the published pair on its fingerprint and reaches the planted
    // one: the incarnation check refuses before the fingerprint is read, and
    // the refusal is not Missing.
    let stale = AllocationId::new(SlotIndex(id.slot_index()), id.incarnation() + 1);
    bucket.publish_pair(1, bucket.control(), tag, stale);
    let mut spent = budget();
    assert_eq!(
        reader.lookup(&key(0x12), RETRIES, &mut spent).err(),
        Some(LookupError::Contended)
    );
    assert_eq!(rejected(), marker + 1);
    assert_eq!(samples(&storage), 0);
    assert_eq!(reserved(&storage), 0);
    bucket.clear_pair(1, bucket.control());

    // A slot past the pool: refused before any table is indexed.
    bucket.publish_pair(1, bucket.control(), tag, AllocationId::new(SlotIndex(8), 1));
    assert_eq!(
        lookup(&mut reader, &key(0x12), RETRIES).err(),
        Some(LookupError::Contended)
    );
    assert_eq!(rejected(), marker + 2);
    bucket.clear_pair(1, bucket.control());

    // The published pair alone, rewritten with the right tag and slot but
    // other incarnation bits: the record holds the key's fingerprint, and
    // still no lease is formed and no fingerprint is read.
    bucket.publish_pair(0, 0, tag, stale);
    assert_eq!(
        lookup(&mut reader, &key(0x11), RETRIES).err(),
        Some(LookupError::Contended)
    );
    assert_eq!(rejected(), marker + 3);
    assert_eq!(reserved(&storage), 0);
    bucket.publish_pair(0, 0, tag, id);

    // A second pair naming the live object under the same tag: for the
    // other key its fingerprint differs, so each is a miss for that
    // candidate and the search completes as Missing, with no lease and no
    // refusal.
    bucket.publish_pair(1, bucket.control(), tag, id);
    assert_eq!(
        lookup(&mut reader, &key(0x12), RETRIES).err(),
        Some(LookupError::Missing)
    );
    assert_eq!(rejected(), marker + 3);
    assert_eq!(reserved(&storage), 0);
    bucket.clear_pair(1, bucket.control());

    // With the pair restored the published object hits again.
    assert_eq!(
        hit_key(&lookup(&mut reader, &key(0x11), RETRIES).unwrap()),
        key(0x11)
    );

    // A link out of range under a stable sequence: Corrupt, for exactly the
    // prepaid scan bound and before any fingerprint is read.
    bucket.corrupt(bucket.control(), 7);
    let mut spent = budget();
    assert_eq!(
        reader.lookup(&key(0x11), RETRIES, &mut spent).err(),
        Some(LookupError::Contended)
    );
    assert_eq!(rejected(), marker + 4);
    assert_eq!(spent.counters().visits, 2);
    assert_eq!(pinned(&storage, &reader), None);
    assert_eq!(refs(&storage, id), 1);
}

/// One pin per registration: a lease acquired inside an interval is held
/// after the interval ends and keeps its bytes while the mapping is removed,
/// the era is certified and service runs; the slot is reclaimed only once
/// the lease is gone, after the reader unpinned.
#[test]
fn a_held_lease_outlives_its_interval_and_reclamation_waits_for_it() {
    let storage = ready(8);
    ticks(&storage, &[Some(1)]);
    let id = publish(&storage, key(0xB1), DEADLINE, &body(0xB1));
    let mut reader = storage.register().unwrap();
    let lease = lookup(&mut reader, &key(0xB1), RETRIES).unwrap();
    assert_eq!(pinned(&storage, &reader), None);
    remove(&storage, &key(0xB1), id);
    // Grace can certify: the reader is unpinned. The anchor goes, the
    // right stays, so the slot is held, not returned.
    let certified = storage.certify(&mut WorkBudget::new(400)).unwrap();
    assert!(certified.certified.is_some());
    let report = storage.service(&mut WorkBudget::new(400)).unwrap();
    assert_eq!(report.serviced, 0);
    assert_eq!(refs(&storage, id), 1);
    assert_eq!(lease.id(), id);
    let flag = storage.live_pool().unwrap().flags(id.slot_index());
    assert_eq!(flag & ANCHORED, 0);
    drop(lease);
    assert_eq!(refs(&storage, id), 0);
    let report = storage.service(&mut WorkBudget::new(400)).unwrap();
    assert_eq!(report.serviced, 1);
    assert_eq!(
        storage.slot_state(SlotIndex(id.slot_index())).map(|s| s.0),
        Some(SlotState::Free)
    );
    assert!(storage.outstanding().is_clear() || storage.outstanding().registrations == 1);
    drop(reader);
    assert!(storage.outstanding().is_clear());
}

/// Every reservation attempt is charged: a lost right compare-exchange with
/// no budget left refunds the credit and refuses `Contended`, the same loss
/// with room for a retry succeeds; the failed attempt is counted on the pool.
/// The exact counts assume a weak compare-exchange fails only when it lost,
/// which Miri's spurious failures break, so the test is a native one.
#[test]
#[cfg_attr(miri, ignore = "weak compare-exchange fails spuriously under Miri")]
fn lost_reservation_attempts_are_charged_counted_and_refunded() {
    fn steal(slot_word: &std::sync::atomic::AtomicU64) {
        slot_word.fetch_add(super::word::REF, Ordering::Relaxed);
    }
    let storage = ready(8);
    ticks(&storage, &[Some(1)]);
    let id = publish(&storage, key(0xC1), DEADLINE, &body(0xC1));
    let mut reader = storage.register().unwrap();
    // The uncontended charge, enumerated independently of the counters: the
    // guard bundle 6, hash 1, the prepaid chain bound of 2 visits and 30
    // comparisons, identity 1, fingerprint 1, the acquisition's bundle of the
    // deadline and extents 1, the refund reserve 2 and the final bracket 3,
    // then credit 1 and right 1.
    const TOTAL: usize = GUARD_STEPS + 1 + 32 + 2 + (1 + 2 + 3) + 2;
    let mut exact = budget();
    let held = lookup_with(&mut reader, &key(0xC1), &mut exact).unwrap();
    let paid = exact.counters();
    assert_eq!((paid.hashes, paid.comparisons, paid.visits), (1, 39, 2));
    assert_eq!(paid.updates, 5);
    // The credit and the right.
    assert_eq!(paid.coordination_attempts, 2);
    assert_eq!(budget().remaining() - exact.remaining(), TOTAL);
    assert_eq!(refs(&storage, id), 2);
    assert_eq!(reserved(&storage), 1);
    let total = TOTAL;

    // The right's compare-exchange loses once and the budget cannot pay a
    // retry: the credit comes back, the loss is counted.
    INTERPOSE_BEFORE_RETAIN.with(|hook| hook.set(Some(steal)));
    let mut tight = WorkBudget::new(total);
    assert_eq!(
        lookup_with(&mut reader, &key(0xC1), &mut tight).err(),
        Some(LookupError::Contended)
    );
    assert_eq!(tight.remaining(), 0);
    assert_eq!(storage.pool_report().unwrap().retain_cas_failed, 1);
    // The loss is counted in the reader's own record; the pool's counter,
    // kept for reservations outside any record, stays at zero.
    let own = &storage.registrations()[reader.index().0].retains;
    assert_eq!(own.lost.load(Ordering::Relaxed), 1);
    let pool = &storage.live_pool().unwrap().telemetry().retains;
    assert_eq!(pool.lost.load(Ordering::Relaxed), 0);
    assert_eq!(reserved(&storage), 1);
    // The stolen right stays counted until undone.
    assert_eq!(refs(&storage, id), 3);
    unsteal(&storage, id);

    // With one more step the retry succeeds.
    INTERPOSE_BEFORE_RETAIN.with(|hook| hook.set(Some(steal)));
    let mut roomy = WorkBudget::new(total + 1);
    let lease = lookup_with(&mut reader, &key(0xC1), &mut roomy).unwrap();
    assert_eq!(roomy.remaining(), 0);
    assert_eq!(storage.pool_report().unwrap().retain_cas_failed, 2);
    assert_eq!(refs(&storage, id), 4);
    drop(lease);
    unsteal(&storage, id);
    assert_eq!(refs(&storage, id), 2);
    drop(held);
    assert_eq!((refs(&storage, id), reserved(&storage)), (1, 0));
}

/// Undoes one `steal` on `id`'s counter.
fn unsteal(storage: &Storage<TestPlatform>, id: AllocationId) {
    let pool = storage.live_pool().unwrap();
    pool.set_refs(id.slot_index(), pool.refs(id.slot_index()) - 1);
}

fn lookup_with<'s>(
    reader: &mut Registration<'s, TestPlatform>,
    key: &Key,
    budget: &mut WorkBudget,
) -> Result<ExtentLease<'s, TestPlatform>, LookupError> {
    reader.lookup(key, RETRIES, budget)
}

/// Readers looking up two keys while a writer replaces and invalidates them:
/// each reader first hits its own key before the writer starts, then every
/// outcome is one of the seven, every lease carries the bytes of an object
/// that was published under its key, and the credits and rights return to
/// zero.
#[test]
fn concurrent_lookups_against_mutation_conserve_rights_and_credits() {
    let storage = ready(16);
    ticks(&storage, &[Some(1)]);
    let keys = [key(0xD1), key(0xD2)];
    for (n, key) in keys.iter().enumerate() {
        publish(&storage, *key, DEADLINE, &body(0xD1 + n as u8));
    }
    let hits = std::sync::atomic::AtomicUsize::new(0);
    let (turn, started) = (std::sync::Barrier::new(2), std::sync::Barrier::new(3));
    std::thread::scope(|scope| {
        for own in 0..2 {
            let storage = &storage;
            let hits = &hits;
            let (turn, started) = (&turn, &started);
            scope.spawn(move || {
                let mut reader = storage.register().unwrap();
                // Before any mutation the readers look up their own published keys in sequence, so each lookup finds the credits it needs.
                if own == 1 {
                    turn.wait();
                }
                let first = reader.lookup(&keys[own], 4, &mut WorkBudget::new(64));
                if own == 0 {
                    turn.wait();
                }
                started.wait();
                assert_eq!(hit_key(&first.expect("a hit before mutation")), keys[own]);
                hits.fetch_add(1, Ordering::Relaxed);
                for round in 0..300 {
                    let key = &keys[round % 2];
                    match reader.lookup(key, 4, &mut WorkBudget::new(64)) {
                        Ok(lease) => {
                            hits.fetch_add(1, Ordering::Relaxed);
                            // Every object the writer publishes under a key is bound to it.
                            assert_eq!(hit_key(&lease), *key);
                            drop(lease);
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
        }
        scope.spawn(|| {
            started.wait();
            for round in 0..150u8 {
                let key = keys[usize::from(round % 2)];
                if round % 3 == 0 {
                    let _ = storage.invalidate(&key, TRIES, &mut WorkBudget::new(64));
                } else if let Ok(mut allocation) =
                    storage.reserve(Some(4), Some(20), &mut WorkBudget::new(64))
                {
                    allocation.mark_written();
                    let owner = allocation
                        .complete(key, DEADLINE, &mut WorkBudget::new(64))
                        .ok()
                        .unwrap();
                    if let Err((owner, _)) = owner.replace(TRIES, &mut WorkBudget::new(64)) {
                        let _ =
                            storage.return_allocation(owner.release(), &mut WorkBudget::new(64));
                    }
                }
                let _ = storage.certify(&mut WorkBudget::new(400));
                let _ = storage.service(&mut WorkBudget::new(400));
                std::thread::yield_now();
            }
        });
    });
    assert!(hits.load(Ordering::Relaxed) > 0);
    assert_eq!(reserved(&storage), 0);
    let pool = storage.live_pool().unwrap();
    for slot in 0..16 {
        let count = pool.refs(slot);
        assert!(count <= 1, "slot {slot} holds {count}");
    }
}

/// The clock's resolution is read once at initialization and recorded; a
/// platform that cannot report it refuses initialization before any mapping.
#[test]
fn the_clock_resolution_is_recorded_or_initialization_refuses() {
    let storage = ready(8);
    assert_eq!(storage.root_descriptor().unwrap().clock_resolution_ticks, 1);
    let platform = TestPlatform::heap(PAGE);
    platform.fail_at(Fail {
        op: Op::ClockResolution,
        ordinal: 1,
        code: OsCode(libc::EINVAL),
        region: None,
    });
    let log = platform.log();
    let slot_count = 4;
    let config = storage_config(slot_count).validate().unwrap();
    let placement = super::placement::PlacementConfig { control_home: 0 };
    let failure = Storage::initialize(&config, &placement, platform)
        .err()
        .unwrap();
    assert_eq!(
        failure.error,
        InitError::ClockUnavailable(OsCode(libc::EINVAL))
    );
    assert!(log.calls(Op::Map).is_empty());
    assert!(log.calls(Op::Cut(InitPhase::ControlInit)).is_empty());
}

#[test]
fn a_lookup_hint_requests_the_lookups_first_lines_and_touches_nothing() {
    use super::prefetch::{READ_HINTS, WRITE_HINTS};
    let limits = [8usize];
    let config = index_config(&limits, (1, 1), 1);
    let storage = storage(16, &config);
    let hints = || {
        (
            READ_HINTS.with(std::cell::Cell::get),
            WRITE_HINTS.with(std::cell::Cell::get),
        )
    };
    let sequence_before = storage.shard_report(ShardIndex(0)).unwrap().sequence;
    let (reads, writes) = hints();
    storage.hint_lookup(&key(0x51));
    let (reads_after, writes_after) = hints();
    assert_eq!(reads_after - reads, 7);
    assert_eq!(writes_after - writes, super::free::WINDOW_LINES);
    assert_eq!(
        storage.shard_report(ShardIndex(0)).unwrap().sequence,
        sequence_before
    );
    let mut reader = storage.register().unwrap();
    assert_eq!(
        lookup(&mut reader, &key(0x51), RETRIES).err(),
        Some(LookupError::Missing)
    );
}

/// The sequence the lookup brackets on is the shard's: a lookup that
/// completes leaves it where the publications put it, and no lookup path
/// writes a bucket, a counter or the sequence.
#[test]
fn lookups_write_no_index_state() {
    let storage = ready(8);
    ticks(&storage, &[Some(1)]);
    publish(&storage, key(0xF1), DEADLINE, &body(0xF1));
    let before = storage.shard_report(ShardIndex(0)).unwrap();
    let mut reader = storage.register().unwrap();
    let lease = lookup(&mut reader, &key(0xF1), RETRIES).unwrap();
    assert_eq!(
        lookup(&mut reader, &key(0xF2), RETRIES).err(),
        Some(LookupError::Missing)
    );
    ticks(&storage, &[Some(DEADLINE)]);
    assert_eq!(
        lookup(&mut reader, &key(0xF1), RETRIES).err(),
        Some(LookupError::Expired)
    );
    assert_eq!(storage.shard_report(ShardIndex(0)).unwrap(), before);
    assert_eq!(sequence(&storage), before.sequence);
    drop(lease);
    assert_eq!(storage.shard_report(ShardIndex(0)).unwrap(), before);
}
