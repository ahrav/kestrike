//! Tests of bounded fill authority: the grant, refusal and release cycle of
//! one shard's fill table, the checked serial and its planted maximum, the
//! joint invalidation's flags, refusals and late cutoff, the cleanup of a
//! revoked attempt beside its replacement, the fill tables' extent under the
//! engine ledger with every initialization cut, finalization's fill
//! blockers, the close service's fill stage, budgets, the primitive observer,
//! the allocation audit, and the refusal each keyed operation gives when no
//! shard is enabled, on the heap-backed platform.
//!
//! Expected states are spelled out from the protocol's rules, never read
//! back from a production counter.

use std::sync::atomic::Ordering;

use super::attempt::{BeginError, FILL_SERVICE_PER_RECORD, FillAttempt, FillServiceError};
use super::budget::WorkBudget;
use super::closing::CloseStage;
use super::fill::{self, FillSerial, Record, SERIAL_MAX};
use super::finalize::{Blockers, Finalization, FinalizeError};
use super::image::NO_RECORD;
use super::init::{Cleanup, InitPhase};
use super::lookup_tests::hit_key;
use super::mapping::Region;
use super::os::OsCode;
use super::owner::Storage;
use super::placement::PlacementConfig;
use super::probe;
use super::publish_tests::{
    PAGE, RETRIES, TRIES, budget, candidates, completed, index_config, install_seam, key,
    one_fingerprint, report, storage_config, storage_from,
};
use super::remove::{INTERPOSE_BEFORE_CUTOFF, RemoveError};
use super::test_platform::{Fail, Op, TestPlatform, blocked, finalize};
use super::{
    AllocationId, CacheVersion, EraReport, InvalidateError, Invalidation, JoinError, LeaseReport,
    LookupError, PoolReport, RegistrationIndex, RegistrationReport, ShardReport, WorkCounters,
};
use crate::index::{
    HASH_CHARGE, IndexConfig, Key, KeyHasher, Prefetch, RouteError, ShardIndex, TERMINAL,
};

const SHARD: ShardIndex = ShardIndex(0);

fn config<'a>(limits: &'a [usize], fills: &'a [usize]) -> IndexConfig<'a> {
    IndexConfig {
        fills,
        ..index_config(limits, (1, 1), 1)
    }
}

/// One shard of eight keys with `fills` records, on the heap platform.
pub(super) fn ready(fills: usize) -> Storage<TestPlatform> {
    ready_on(fills, TestPlatform::heap(PAGE))
}

fn ready_on(fills: usize, platform: TestPlatform) -> Storage<TestPlatform> {
    let slot_count = 8;
    let storage = storage_from(
        &storage_config(slot_count),
        &config(&[8], &[fills]),
        platform,
    );
    storage.platform.ticks(&[Some(1)]);
    storage
}

pub(super) fn begin<'s>(
    storage: &'s Storage<TestPlatform>,
    key: &Key,
) -> Result<FillAttempt<'s, TestPlatform>, BeginError> {
    storage.begin_fill(key, crate::storage::CacheVersion(0), TRIES, &mut budget())
}

pub(super) fn invalidate(
    storage: &Storage<TestPlatform>,
    key: &Key,
) -> Result<Invalidation, InvalidateError> {
    storage.invalidate(key, TRIES, &mut budget())
}

pub(super) fn service(storage: &Storage<TestPlatform>) -> super::FillServiceReport {
    storage.service_fills(SHARD, TRIES, &mut budget()).unwrap()
}

/// Every record of shard zero's table, decoded against its next serial.
pub(super) fn records(storage: &Storage<TestPlatform>) -> Vec<Record> {
    let table = storage.root_image.fills[0].as_ref().unwrap();
    // SAFETY: the root mapping is live and only atomics are read.
    let (states, control) = unsafe {
        (
            table.states.as_slice(&storage.root),
            &table.control.as_slice(&storage.root)[0],
        )
    };
    let next = control.next_serial.load();
    states
        .iter()
        .map(|state| fill::decode(state.load(Ordering::Acquire), next).unwrap())
        .collect()
}

pub(super) fn next_serial(storage: &Storage<TestPlatform>) -> u64 {
    let table = storage.root_image.fills[0].as_ref().unwrap();
    // SAFETY: as for `records`.
    unsafe { &table.control.as_slice(&storage.root)[0] }
        .next_serial
        .load()
}

fn cursor(storage: &Storage<TestPlatform>) -> usize {
    let table = storage.root_image.fills[0].as_ref().unwrap();
    // SAFETY: as for `records`.
    unsafe { &table.control.as_slice(&storage.root)[0] }
        .cursor
        .load(Ordering::Relaxed)
}

pub(super) fn plant_serial(storage: &Storage<TestPlatform>, value: u64) {
    let table = storage.root_image.fills[0].as_ref().unwrap();
    // SAFETY: as for `records`; no writer runs.
    unsafe { &table.control.as_slice(&storage.root)[0] }
        .next_serial
        .set_for_test(value);
}

fn plant_custody(storage: &Storage<TestPlatform>, record: usize) {
    let table = storage.root_image.fills[0].as_ref().unwrap();
    // SAFETY: as for `records`; no writer runs.
    unsafe { &table.custody.as_slice(&storage.root)[0] }
        .record
        .store(record, Ordering::Relaxed);
}

/// A serial within the representable range of a fill record.
pub(super) fn fill_serial(value: u64) -> FillSerial {
    FillSerial::new(value).expect("test fill serial out of range")
}

pub(super) fn live(serial: u64) -> Record {
    Record::Occupied {
        serial: fill_serial(serial),
        departed: false,
        revoked: false,
    }
}

pub(super) fn departed(serial: u64, revoked: bool) -> Record {
    Record::Occupied {
        serial: fill_serial(serial),
        departed: true,
        revoked,
    }
}

pub(super) fn revoked(serial: u64) -> Record {
    Record::Occupied {
        serial: fill_serial(serial),
        departed: false,
        revoked: true,
    }
}

/// The shard gate of shard zero, for tests that hold or poison it.
pub(super) fn gate(storage: &Storage<TestPlatform>) -> &super::gate::Gate {
    let index = storage.index.as_ref().unwrap();
    // SAFETY: the index mapping is live.
    unsafe { index.image.shard(SHARD).unwrap().gate(&index.mapping) }
}

pub(super) fn shard_control(storage: &Storage<TestPlatform>) -> &super::shards::ShardControl {
    let index = storage.index.as_ref().unwrap();
    // SAFETY: the index mapping is live.
    unsafe { index.image.shard(SHARD).unwrap().control(&index.mapping) }
}

#[test]
fn two_keys_begin_a_third_is_full_and_a_duplicate_is_in_progress_until_service() {
    let storage = ready(2);
    let (k1, k2, k3) = (key(1), key(2), key(3));
    let a = begin(&storage, &k1).unwrap();
    let b = begin(&storage, &k2).unwrap();
    assert_eq!((a.serial(), b.serial()), (1, 2));
    assert_eq!((a.shard(), a.key()), (SHARD, &k1));
    assert_eq!(begin(&storage, &k3).err(), Some(BeginError::FillSlotsFull));
    assert_eq!(begin(&storage, &k1).err(), Some(BeginError::InProgress));
    assert_eq!(records(&storage), [live(1), live(2)]);

    // Abort departs at once, and the record stays the key's association
    // until a funded pass frees it.
    a.abort();
    assert_eq!(records(&storage), [departed(1, false), live(2)]);
    assert_eq!(begin(&storage, &k1).err(), Some(BeginError::InProgress));
    assert_eq!(begin(&storage, &k3).err(), Some(BeginError::FillSlotsFull));
    let pass = service(&storage);
    assert_eq!((pass.examined, pass.released, pass.retained), (2, 1, 1));
    assert!(!pass.budget_exhausted);
    assert_eq!(records(&storage), [Record::Free, live(2)]);
    let again = begin(&storage, &k1).unwrap();
    assert_eq!(again.serial(), 3);
    assert_eq!(records(&storage), [live(3), live(2)]);
    assert_eq!(next_serial(&storage), 4);
    drop(again);
    drop(b);
    assert_eq!(records(&storage), [departed(3, false), departed(2, false)]);
    assert_eq!(service(&storage).released, 2);
    assert_eq!(records(&storage), [Record::Free, Record::Free]);
    // The serial never resets when the table empties.
    assert_eq!(begin(&storage, &k3).unwrap().serial(), 4);
}

/// Two keys the seam gives one fingerprint are two attempts: full-key
/// identity, not fingerprint identity, decides `InProgress`.
#[test]
fn a_colliding_fingerprint_unequal_key_is_a_separate_attempt() {
    // Two keys equal in every byte but the last, and two equal in every
    // byte but the first: only a comparison of all 32 bytes separates each
    // pair.
    let mut k2 = key(0x10);
    k2[31] ^= 1;
    for (k1, k2) in [(key(0x10), k2), (key(0x10), key(0x11))] {
        let mut storage = ready(2);
        install_seam(&mut storage, one_fingerprint);
        assert_eq!(
            storage.route(&k1).unwrap().fingerprint(),
            storage.route(&k2).unwrap().fingerprint()
        );
        let a = begin(&storage, &k1).unwrap();
        let b = begin(&storage, &k2).unwrap();
        assert_eq!((a.serial(), b.serial()), (1, 2));
        assert_eq!(begin(&storage, &k1).err(), Some(BeginError::InProgress));
        assert_eq!(begin(&storage, &k2).err(), Some(BeginError::InProgress));
        // Invalidating one leaves the other's association current.
        assert_eq!(invalidate(&storage, &k1).unwrap().revoked, Some(1));
        assert_eq!(records(&storage), [revoked(1), live(2)]);
        assert_eq!(begin(&storage, &k2).err(), Some(BeginError::InProgress));
    }
}

/// A shard without a table, and a storage without an index, grant nothing
/// and decide nothing, each with its own refusal.
#[test]
fn a_shard_without_a_table_refuses_full_and_services_nothing() {
    let storage = ready(0);
    assert_eq!(
        begin(&storage, &key(1)).err(),
        Some(BeginError::FillSlotsFull)
    );
    assert_eq!(service(&storage), super::FillServiceReport::default());
    assert!(storage.root_image.fills.iter().all(Option::is_none));
    assert_eq!(storage.root_extent(), PAGE);

    let slot_count = 8;
    let plain = Storage::initialize(
        &storage_config(slot_count).validate().unwrap(),
        &PlacementConfig { control_home: 0 },
        TestPlatform::heap(PAGE),
    )
    .unwrap();
    assert_eq!(begin(&plain, &key(1)).err(), Some(BeginError::NoIndex));
    assert_eq!(
        plain.service_fills(SHARD, TRIES, &mut budget()).err(),
        Some(FillServiceError::NoIndex)
    );
}

/// Plants the serial maximum, takes the last serial for `k1` through `issue`, and asserts that `issue` then refuses `k2` and `k1` again `AttemptExhausted` with the counter one past the maximum; returns the attempt holding the last serial.
fn the_last_serial_issues_once<'s>(
    storage: &'s Storage<TestPlatform>,
    (k1, k2): (&Key, &Key),
    issue: impl Fn(&'s Storage<TestPlatform>, &Key) -> Result<FillAttempt<'s, TestPlatform>, BeginError>,
) -> FillAttempt<'s, TestPlatform> {
    plant_serial(storage, SERIAL_MAX);
    let last = issue(storage, k1).unwrap();
    assert_eq!(last.serial(), SERIAL_MAX);
    assert_eq!(issue(storage, k2).err(), Some(BeginError::AttemptExhausted));
    assert_eq!(issue(storage, k1).err(), Some(BeginError::AttemptExhausted));
    assert_eq!(next_serial(storage), SERIAL_MAX + 1);
    last
}

/// A valid header requires a nonzero serial counter.
#[test]
fn a_zero_serial_counter_refuses_corrupt_and_poisons_the_gate() {
    let storage = ready(2);
    plant_serial(&storage, 0);
    assert_eq!(begin(&storage, &key(1)).err(), Some(BeginError::Corrupt));
    assert!(gate(&storage).is_poisoned());
    assert_eq!(records(&storage), [Record::Free, Record::Free]);
    assert_eq!(next_serial(&storage), 0);
}

#[test]
fn a_planted_serial_maximum_exhausts_issuance_permanently_but_not_cleanup() {
    let storage = ready(2);
    let (k1, k2) = (key(1), key(2));
    let last = the_last_serial_issues_once(&storage, (&k1, &k2), begin);

    // Invalidation, abort and service keep working on the exhausted shard.
    let resident = completed(&storage, k1)
        .publish(TRIES, &mut budget())
        .unwrap();
    let ended = invalidate(&storage, &k1).unwrap();
    assert_eq!(ended.removed.map(|(id, _)| id), Some(resident));
    assert_eq!(ended.revoked, Some(SERIAL_MAX));
    assert_eq!(records(&storage), [revoked(SERIAL_MAX), Record::Free]);
    last.abort();
    assert_eq!(
        records(&storage),
        [departed(SERIAL_MAX, true), Record::Free]
    );
    assert_eq!(service(&storage).released, 1);
    assert_eq!(records(&storage), [Record::Free, Record::Free]);
    // An empty table resets nothing: issuance stays refused, and the old
    // owner's serial no longer authenticates against the freed record.
    assert_eq!(
        begin(&storage, &k2).err(),
        Some(BeginError::AttemptExhausted)
    );
    assert_eq!(next_serial(&storage), SERIAL_MAX + 1);
    let state = storage.fill_state(SHARD, 0);
    assert!(!fill::depart(state, fill_serial(SERIAL_MAX)));
    assert_eq!(state.load(Ordering::Relaxed), fill::FREE);
}

/// An issuer whose counter wraps: where `begin` refuses `AttemptExhausted` it returns the counter to the first serial and begins again.
fn wrapping_begin<'s>(
    storage: &'s Storage<TestPlatform>,
    key: &Key,
) -> Result<FillAttempt<'s, TestPlatform>, BeginError> {
    match begin(storage, key) {
        Err(BeginError::AttemptExhausted) => {
            plant_serial(storage, fill::FIRST_SERIAL);
            begin(storage, key)
        }
        issued => issued,
    }
}

/// Planted defect: `wrapping_begin` issues in place of `begin`. Past the last serial it restarts the counter at the
/// first serial; the live attempt's record then carries a serial at or past the counter, so the wrapped begin reads the
/// table as `Corrupt`, where the exhaustion check of `the_last_serial_issues_once` expects the exact refusal
/// `AttemptExhausted`.
#[test]
#[should_panic(expected = "left: Some(Corrupt)\n right: Some(AttemptExhausted)")]
fn negative_control_a_serial_counter_that_wraps_after_its_maximum_loses_the_exact_refusal() {
    let storage = ready(2);
    let (k1, k2) = (key(1), key(2));
    the_last_serial_issues_once(&storage, (&k1, &k2), wrapping_begin).abort();
}

#[test]
fn invalidate_reports_resident_and_attempt_flags_exactly_and_repeats_end_nothing() {
    let storage = ready(2);
    let (k1, k2, k3, k4) = (key(1), key(2), key(3), key(4));
    let era = || storage.era_report().unwrap().era;
    let first_era = era();

    // Resident only: an existing lease keeps its bytes through the removal.
    let r1 = completed(&storage, k1)
        .publish(TRIES, &mut budget())
        .unwrap();
    let mut reader = storage.register().unwrap();
    let lease = reader.lookup(&k1, 3, &mut budget()).unwrap();
    let before = report(&storage, 0).sequence;
    let ended = invalidate(&storage, &k1).unwrap();
    assert_eq!(ended.removed.map(|(id, _)| id), Some(r1));
    assert_eq!(ended.revoked, None);
    assert_eq!(ended.sequence, before + 2);
    assert_eq!(hit_key(&lease), k1);
    assert!(candidates(&storage, &k1).is_empty());
    drop(lease);

    // Attempt only.
    let a2 = begin(&storage, &k2).unwrap();
    let ended = invalidate(&storage, &k2).unwrap();
    assert_eq!((ended.removed, ended.revoked), (None, Some(1)));
    assert_eq!(records(&storage), [revoked(1), Record::Free]);

    // Both, atomically under one sequence step.
    let r3 = completed(&storage, k3)
        .publish(TRIES, &mut budget())
        .unwrap();
    let a3 = begin(&storage, &k3).unwrap();
    let before = report(&storage, 0).sequence;
    let ended = invalidate(&storage, &k3).unwrap();
    assert_eq!(ended.removed.map(|(id, _)| id), Some(r3));
    assert_eq!(ended.revoked, Some(2));
    assert_eq!(
        (ended.sequence, report(&storage, 0).sequence),
        (before + 2, before + 2)
    );
    assert_eq!(records(&storage), [revoked(1), revoked(2)]);

    // Neither, and a repeat: both absent, the ordering point still moves,
    // and no retirement is recorded twice.
    for k in [k4, k3, k1] {
        let before = report(&storage, 0).sequence;
        let ended = invalidate(&storage, &k).unwrap();
        assert_eq!(
            (ended.removed, ended.revoked, ended.sequence),
            (None, None, before + 2)
        );
    }
    assert_eq!(era(), first_era + 2);
    assert_eq!(
        storage.pool_report().unwrap().ledger.unwrap().slots.retired,
        2
    );

    // Revocation is not release: the records stay occupied while their
    // owners live, a same-key attempt needs another Free record, and only
    // service after departure frees them.
    assert_eq!(begin(&storage, &k2).err(), Some(BeginError::FillSlotsFull));
    let pass = service(&storage);
    assert_eq!((pass.released, pass.retained), (0, 2));
    a2.abort();
    drop(a3);
    assert_eq!(records(&storage), [departed(1, true), departed(2, true)]);
    assert_eq!(service(&storage).released, 2);
    assert_eq!(begin(&storage, &k2).unwrap().serial(), 3);
}

/// A revoked attempt's late abort, drop or service reaches only its own
/// record; the replacement attempt on the same key keeps its association,
/// serial and record.
#[test]
fn late_cleanup_of_a_revoked_attempt_leaves_its_replacement_intact() {
    for late_drop in [false, true] {
        let storage = ready(2);
        let k = key(9);
        let old = begin(&storage, &k).unwrap();
        assert_eq!(invalidate(&storage, &k).unwrap().revoked, Some(1));
        let replacement = begin(&storage, &k).unwrap();
        assert_eq!(replacement.serial(), 2);
        assert_eq!(records(&storage), [revoked(1), live(2)]);
        // Service before the old owner departs frees nothing.
        assert_eq!(service(&storage).released, 0);
        if late_drop {
            drop(old);
        } else {
            old.abort();
        }
        assert_eq!(records(&storage), [departed(1, true), live(2)]);
        let pass = service(&storage);
        assert_eq!((pass.released, pass.retained), (1, 1));
        assert_eq!(records(&storage), [Record::Free, live(2)]);
        assert_eq!(begin(&storage, &k).err(), Some(BeginError::InProgress));
        assert_eq!(replacement.serial(), 2);
        replacement.abort();
        assert_eq!(records(&storage), [Record::Free, departed(2, false)]);
    }
}

/// Everything an invalidation refusal must leave unchanged: the sequence,
/// the visible count, the key's candidates, the fill records, the era, the
/// retired slots and the pending marks.
type Observable = (
    u64,
    usize,
    Vec<super::AllocationId>,
    Vec<Record>,
    u64,
    usize,
    usize,
);

fn observable(storage: &Storage<TestPlatform>, key: &Key) -> Observable {
    let report = report(storage, 0);
    let pool = storage.pool_report().unwrap();
    (
        report.sequence,
        report.visible,
        candidates(storage, key),
        records(storage),
        storage.era_report().unwrap().era,
        pool.ledger.unwrap().slots.retired,
        pool.pending_marks,
    )
}

#[test]
fn invalidate_refusals_before_inhibition_change_nothing() {
    let storage = ready(2);
    let k = key(5);
    completed(&storage, k)
        .publish(TRIES, &mut budget())
        .unwrap();
    let _attempt = begin(&storage, &k).unwrap();
    let baseline = observable(&storage, &k);
    assert_eq!(baseline.3, [live(1), Record::Free]);

    // A held gate, and zero tries.
    let held = gate(&storage).try_lock().unwrap();
    assert_eq!(
        invalidate(&storage, &k).err(),
        Some(InvalidateError::Contended)
    );
    held.release();
    assert_eq!(
        storage.invalidate(&k, 0, &mut budget()).err(),
        Some(InvalidateError::Contended)
    );
    assert_eq!(observable(&storage, &k), baseline);

    // Every budget cut: the hash pass, the gate try, the walk and the fill
    // scan each refuse before the inhibition. The full charge is bounded by
    // the hash, one attempt, one bucket visit with its pair and fingerprint
    // comparisons, and the two-record scan with one comparison.
    let most = crate::index::HASH_CHARGE + 1 + 3 + 3;
    let mut full = None;
    for cuts in 0..=most {
        let mut budget = WorkBudget::new(cuts);
        match storage.invalidate(&k, TRIES, &mut budget) {
            Err(InvalidateError::BudgetExhausted) => {
                assert_eq!(observable(&storage, &k), baseline, "{cuts}");
            }
            Ok(ended) => {
                assert!(ended.removed.is_some() && ended.revoked == Some(1));
                full = Some(cuts);
                break;
            }
            other => panic!("{other:?}"),
        }
    }
    assert!(full.is_some_and(|full| full > 4), "{full:?}");
    assert_eq!(records(&storage), [revoked(1), Record::Free]);

    // A poisoned gate refuses as contended and changes nothing either, with
    // a resident and a current attempt in place.
    let storage = ready(2);
    completed(&storage, k)
        .publish(TRIES, &mut budget())
        .unwrap();
    let _attempt = begin(&storage, &k).unwrap();
    let baseline = observable(&storage, &k);
    gate(&storage).try_lock().unwrap().poison();
    assert_eq!(
        invalidate(&storage, &k).err(),
        Some(InvalidateError::Contended)
    );
    assert_eq!(
        storage.service_fills(SHARD, TRIES, &mut budget()).err(),
        Some(FillServiceError::Poisoned)
    );
    assert_eq!(begin(&storage, &key(6)).err(), Some(BeginError::Contended));
    assert_eq!(observable(&storage, &k), baseline);
}

/// A cutoff read closed inside the inhibition commits a fresh even value and
/// ends nothing; a near-terminal shard writes the terminal value first; an
/// already terminal shard still clears and revokes under the held cutoff.
#[test]
fn late_closed_commits_a_fresh_even_and_terminal_shards_keep_their_argument() {
    let storage = ready(2);
    let k = key(5);
    let resident = completed(&storage, k)
        .publish(TRIES, &mut budget())
        .unwrap();
    let _attempt = begin(&storage, &k).unwrap();
    let before = report(&storage, 0).sequence;
    INTERPOSE_BEFORE_CUTOFF.with(|hook| {
        hook.set(Some(|flag| flag.store(true, Ordering::SeqCst)));
    });
    assert_eq!(
        invalidate(&storage, &k).err(),
        Some(InvalidateError::Closed)
    );
    assert!(storage.is_closed());
    // The sequence moved by one full step with nothing else stored: the
    // mapping is still counted and the association still current.
    assert_eq!(report(&storage, 0).sequence, before + 2);
    assert_eq!(report(&storage, 0).visible, 1);
    assert_eq!(records(&storage), [live(1), Record::Free]);
    assert_eq!(begin(&storage, &k).err(), Some(BeginError::Closed));
    // Closed before the gate: nothing moves at all.
    assert_eq!(
        invalidate(&storage, &k).err(),
        Some(InvalidateError::Closed)
    );
    assert_eq!(report(&storage, 0).sequence, before + 2);
    // The resident is still mapped: exact removal, permitted after close,
    // finds it and commits its own step.
    assert!(storage.remove(&k, resident, TRIES, &mut budget()).is_ok());
    assert_eq!(report(&storage, 0).sequence, before + 4);

    // Near-terminal, open: the terminal store precedes the cutoff read, then
    // the mapping ends and the attempt is revoked without a bracket.
    let storage = ready(2);
    let resident = completed(&storage, k)
        .publish(TRIES, &mut budget())
        .unwrap();
    let _attempt = begin(&storage, &k).unwrap();
    shard_control(&storage)
        .sequence
        .store(TERMINAL - 2, Ordering::SeqCst);
    let ended = invalidate(&storage, &k).unwrap();
    assert_eq!(ended.sequence, TERMINAL);
    assert_eq!(ended.removed.map(|(id, _)| id), Some(resident));
    assert_eq!(ended.revoked, Some(1));
    assert!(report(&storage, 0).terminal);
    assert_eq!(report(&storage, 0).lost_capacity, 8);
    // Already terminal: the held cutoff is read, the value is shared.
    let again = begin(&storage, &key(6)).unwrap();
    assert_eq!(again.serial(), 2);
    let ended = invalidate(&storage, &key(6)).unwrap();
    assert_eq!(
        (ended.sequence, ended.removed, ended.revoked),
        (TERMINAL, None, Some(2))
    );

    // Near-terminal, closed inside: the sequence is consumed and nothing
    // is removed or revoked.
    let storage = ready(2);
    let resident = completed(&storage, k)
        .publish(TRIES, &mut budget())
        .unwrap();
    let _attempt = begin(&storage, &k).unwrap();
    shard_control(&storage)
        .sequence
        .store(TERMINAL - 2, Ordering::SeqCst);
    INTERPOSE_BEFORE_CUTOFF.with(|hook| {
        hook.set(Some(|flag| flag.store(true, Ordering::SeqCst)));
    });
    assert_eq!(
        invalidate(&storage, &k).err(),
        Some(InvalidateError::Closed)
    );
    assert!(report(&storage, 0).terminal);
    // The resident stays counted, so the lost capacity is `N - V` with it.
    let after = report(&storage, 0);
    assert_eq!((after.visible, after.lost_capacity), (1, 8 - 1));
    assert!(storage.remove(&k, resident, TRIES, &mut budget()).is_ok());
    assert_eq!(records(&storage), [live(1), Record::Free]);
}

/// Every root field and fill-table array in declaration order, placed by
/// hand: each array starts at the next multiple of its element alignment and
/// spans its count times its element size. Control sizes come from
/// `size_of`. The descriptor's alignment comes from `align_of`; every other
/// control's alignment is its `repr(align)` value, 128 bytes for the lease
/// controls, parked words and gate and 64 for the other control lines. Each
/// flag is one byte, and each fill-table record holds an 8-byte state, a
/// 32-byte key at alignment 1, an 8-byte fingerprint, an 8-byte place word
/// and a 32-byte row at alignment 8. One parked word
/// covers 64 readers. `omit` drops the named field to model a layout that
/// lacks it. Returns each field's name, offset and count, and the unrounded
/// end.
fn root_fields(
    readers: usize,
    fills: &[usize],
    omit: Option<&str>,
) -> (Vec<(&'static str, usize, usize)>, usize) {
    use super::gate::Gate;
    use super::image::{
        EraControls, FillControl, FillCustody, GraceCursor, LeaseControls, ParkedWord,
        RegistrationRecord, ReturnLine, RootDescriptor,
    };
    let mut fields = Vec::new();
    let mut end = 0usize;
    let mut place = |name: &'static str, size: usize, align: usize, count: usize| {
        if omit == Some(name) {
            return;
        }
        let offset = end.next_multiple_of(align);
        fields.push((name, offset, count));
        end = offset + size * count;
    };
    place(
        "descriptor",
        size_of::<RootDescriptor>(),
        align_of::<RootDescriptor>(),
        1,
    );
    place("closed", 1, 1, 1);
    place("issued", 1, 1, 1);
    place("attached", 1, 1, 1);
    place("leases", size_of::<LeaseControls>(), 128, 1);
    place("parked", size_of::<ParkedWord>(), 128, readers.div_ceil(64));
    place("returns", size_of::<ReturnLine>(), 64, readers);
    place("eras", size_of::<EraControls>(), 64, 1);
    place("maintenance", size_of::<Gate>(), 128, 1);
    place("grace", size_of::<GraceCursor>(), 64, 1);
    place(
        "registrations",
        size_of::<RegistrationRecord>(),
        64,
        readers,
    );
    for &records in fills.iter().filter(|&&records| records > 0) {
        place("fill control", size_of::<FillControl>(), 64, 1);
        place("fill custody", size_of::<FillCustody>(), 64, 1);
        place("fill states", 8, 8, records);
        place("fill keys", 32, 1, records);
        place("fill fingerprints", 8, 8, records);
        place("fill places", 8, 8, records);
        place("fill rows", 32, 8, records);
    }
    (fields, end)
}

/// `end` rounded up to a whole page, at least one: the extent of a root
/// whose fields end there.
fn rounded(end: usize) -> usize {
    end.next_multiple_of(PAGE).max(PAGE)
}

/// The page-rounded root extent of [`root_fields`] with every field present.
fn root_oracle(readers: usize, fills: &[usize]) -> usize {
    rounded(root_fields(readers, fills, None).1)
}

/// The production root layout's fields in declaration order, each as its
/// name, offset and count, and the unrounded end its last field reaches. The
/// image is destructured without `..`, so a field added to `RootImage` fails
/// to compile until this pattern names it; the comparison with
/// [`root_fields`] catches a bound field left out of the returned list.
fn laid_out(image: &super::image::RootImage) -> (Vec<(&'static str, usize, usize)>, usize) {
    use super::image::{FillImage, RootImage};
    fn at<T>(name: &'static str, field: super::control::Field<T>) -> (&'static str, usize, usize) {
        (name, field.offset(), field.len())
    }
    let RootImage {
        descriptor,
        closed,
        issued,
        attached,
        leases,
        parked,
        returns,
        eras,
        maintenance,
        grace,
        registrations,
        fills,
        any_fills: _,
        extent: _,
    } = image;
    let mut fields = vec![
        at("descriptor", *descriptor),
        at("closed", *closed),
        at("issued", *issued),
        at("attached", *attached),
        at("leases", *leases),
        at("parked", *parked),
        at("returns", *returns),
        at("eras", *eras),
        at("maintenance", *maintenance),
        at("grace", *grace),
        at("registrations", *registrations),
    ];
    let mut end = registrations.offset()
        + registrations.len() * size_of::<super::image::RegistrationRecord>();
    for &FillImage {
        control,
        custody,
        states,
        keys,
        fingerprints,
        places,
        rows,
    } in fills.iter().flatten()
    {
        fields.extend([
            at("fill control", control),
            at("fill custody", custody),
            at("fill states", states),
            at("fill keys", keys),
            at("fill fingerprints", fingerprints),
            at("fill places", places),
            at("fill rows", rows),
        ]);
        end = rows.offset() + rows.len() * size_of::<super::row::FillRow>();
    }
    (fields, end)
}

/// The root layout places every field where the hand placement does, at 0,
/// 64 and 65 readers, with no fill table and with a 65-record table: each
/// field's offset and count, the unrounded end and the rounded extent. The
/// field comparison catches a missing field that page rounding masks: the
/// one-byte `attached` flag sits in the padding before the 128-byte-aligned
/// lease controls, so a layout without it has the same rounded extent.
#[test]
fn the_root_layout_places_every_field_where_the_hand_placement_does() {
    for readers in [0, 64, 65] {
        for fills in [&[0usize, 0][..], &[65, 0]] {
            let image = super::image::RootImage::layout(PAGE, readers, fills).unwrap();
            assert_eq!(
                laid_out(&image),
                root_fields(readers, fills, None),
                "{readers} readers, {fills:?}"
            );
            assert_eq!(image.extent, root_oracle(readers, fills));
            assert_eq!(
                rounded(root_fields(readers, fills, Some("attached")).1),
                image.extent,
                "an omitted flag hides under page rounding"
            );
        }
    }
}

#[test]
fn fill_tables_are_charged_once_in_the_root_extent_and_every_cut_rolls_back() {
    let slot_count = 8;
    let limits = [3usize, 0, 5];
    let readers = super::publish_tests::READERS;
    let plain = storage_from(
        &storage_config(slot_count),
        &config(&limits, &[0, 0, 0]),
        TestPlatform::heap(PAGE),
    );
    assert_eq!(plain.root_extent(), PAGE);
    assert_eq!(plain.root_extent(), root_oracle(readers, &[0, 0, 0]));

    // Enough records to push the root past one page.
    let fills = [40usize, 0, 100];
    let platform = TestPlatform::heap(PAGE);
    let log = platform.log();
    let allocations = crate::instrument::allocations();
    let storage = storage_from(
        &storage_config(slot_count),
        &config(&limits, &fills),
        platform,
    );
    let expected = root_oracle(readers, &fills);
    assert!(expected > PAGE);
    assert_eq!(storage.root_extent(), expected);
    assert_eq!(log.ranges(Op::Map)[0].1, expected);
    assert_eq!(
        storage.engine_used() - plain.engine_used(),
        expected - PAGE,
        "the tables are charged once, as root extent"
    );
    assert_eq!(storage.init_peak() - storage.engine_used(), 1024);
    // Initialization allocated the pool handles and the index and fill
    // placement records; nothing on the fill paths afterwards.
    let _ = allocations;
    let fresh: Vec<Record> = records(&storage);
    assert_eq!(fresh, vec![Record::Free; 40]);
    assert_eq!(next_serial(&storage), 1);
    let pass = service(&storage);
    assert_eq!((pass.examined, pass.released), (40, 0));
    let pass = storage
        .service_fills(ShardIndex(2), TRIES, &mut budget())
        .unwrap();
    assert_eq!((pass.examined, pass.released), (100, 0));
    assert_eq!(
        storage
            .service_fills(ShardIndex(1), TRIES, &mut budget())
            .unwrap()
            .examined,
        0
    );
    assert!(storage.root_image.fills[1].is_none());

    // Every cut that lands with the root mapped rolls the tables back with
    // the rest, exactly once.
    let code = OsCode(12);
    let cuts = [
        Fail {
            op: Op::Map,
            ordinal: 2,
            code,
            region: None,
        },
        Fail {
            op: Op::Cut(InitPhase::ControlInit),
            ordinal: 0,
            code,
            region: Some(Region::Root),
        },
        Fail {
            op: Op::Cut(InitPhase::ControlInit),
            ordinal: 0,
            code,
            region: Some(Region::Index),
        },
        Fail {
            op: Op::Cut(InitPhase::Transfer),
            ordinal: 0,
            code,
            region: Some(Region::Root),
        },
    ];
    for fail in cuts {
        let platform = TestPlatform::heap(PAGE);
        let log = platform.log();
        platform.fail_at(fail);
        let validated = storage_config(slot_count).validate().unwrap();
        let index = config(&limits, &fills).validate(&validated).unwrap();
        let failure = Storage::initialize_indexed(
            &validated,
            index,
            &PlacementConfig { control_home: 0 },
            platform,
        )
        .err()
        .unwrap();
        assert!(matches!(failure.cleanup, Cleanup::Complete), "{fail:?}");
        let mapped = log.ranges(Op::Map);
        assert_eq!(mapped[0].1, expected, "{fail:?}");
        let mut released = log.ranges(Op::Unmap);
        released.reverse();
        assert_eq!(released, mapped, "{fail:?}");
    }
}

#[test]
fn the_charge_query_names_what_a_multi_shard_initialization_charges() {
    let (limits, fills) = ([3usize, 0, 5], [40usize, 0, 100]);
    let validated = storage_config(8).validate().unwrap();
    let index = config(&limits, &fills).validate(&validated).unwrap();
    let charges = super::StorageCharges::of(&validated, Some(&index)).unwrap();
    let storage = storage_from(
        &storage_config(8),
        &config(&limits, &fills),
        TestPlatform::heap(PAGE),
    );
    assert_eq!(charges.root, storage.root_extent());
    assert_eq!(
        storage.engine_used(),
        charges.root + charges.control + charges.index
    );
    assert_eq!(charges.total(), Some(storage.init_peak()));
}

#[test]
fn finalization_blocks_on_forgotten_attempts_departed_records_custody_and_poison() {
    // A forgotten owner blocks until the process ends: the record stays
    // occupied and undeparted.
    let mut storage = ready(2);
    std::mem::forget(begin(&storage, &key(1)).unwrap());
    assert_eq!(
        blocked(&mut storage),
        Blockers {
            fills: 1,
            ..Blockers::default()
        }
    );

    // A departed record blocks until service frees it; ended owners plus
    // one funded pass then drain.
    let mut storage = ready(2);
    begin(&storage, &key(1)).unwrap().abort();
    drop(begin(&storage, &key(2)).unwrap());
    assert_eq!(
        blocked(&mut storage),
        Blockers {
            pending_fills: 2,
            ..Blockers::default()
        }
    );
    assert!(storage.is_closed());
    assert_eq!(begin(&storage, &key(3)).err(), Some(BeginError::Closed));
    assert_eq!(service(&storage).released, 2);
    assert_eq!(finalize(&mut storage), Ok(Finalization::Drained));

    // A custody reference blocks as a held record.
    let mut storage = ready(2);
    plant_custody(&storage, 1);
    assert_eq!(
        blocked(&mut storage),
        Blockers {
            custody: 1,
            ..Blockers::default()
        }
    );
    plant_custody(&storage, NO_RECORD);
    assert_eq!(finalize(&mut storage), Ok(Finalization::Drained));

    // A poisoned shard gate is an error, never a blocker service could
    // clear.
    let mut storage = ready(2);
    gate(&storage).try_lock().unwrap().poison();
    assert_eq!(
        finalize(&mut storage),
        Err(FinalizeError::ShardPoisoned { shard: SHARD })
    );
}

/// An inspection stopped for its allowance after the fill records were
/// found clean cannot be followed by a grant on that shard: the first call
/// closed admission, so the resumed inspection reports drained truthfully.
#[test]
fn a_resumed_inspection_cannot_miss_an_attempt_begun_between_calls() {
    let mut storage = ready(3);
    let readers = super::publish_tests::READERS;
    let slots = 8;
    // Records, the credit count, the pool's gate and slots, the shard's gate
    // and records: the whole inspection, with nothing left for a release.
    let inspection = readers + 1 + 1 + slots + 1 + 3;
    let mut exact = WorkBudget::new(inspection);
    assert_eq!(
        storage.finalize(&mut exact),
        Err(FinalizeError::BudgetExhausted)
    );
    assert_eq!(exact.remaining(), 0);
    assert_eq!(begin(&storage, &key(1)).err(), Some(BeginError::Closed));
    assert_eq!(records(&storage), vec![Record::Free; 3]);
    assert_eq!(finalize(&mut storage), Ok(Finalization::Drained));
}

#[test]
fn budgets_bound_every_fill_path_and_the_observer_stays_within_the_charge() {
    let storage = ready(3);
    let k = key(7);
    let failed_tries = || report(&storage, 0).failed_tries;

    // Zero: no gate attempt, no visit, no cursor movement.
    let mut zero = WorkBudget::new(0);
    assert_eq!(
        storage
            .begin_fill(&k, crate::storage::CacheVersion(0), TRIES, &mut zero)
            .err(),
        Some(BeginError::BudgetExhausted)
    );
    assert_eq!(
        storage.service_fills(SHARD, TRIES, &mut zero).err(),
        Some(FillServiceError::BudgetExhausted)
    );
    assert_eq!(
        storage.invalidate(&k, TRIES, &mut zero).err(),
        Some(InvalidateError::BudgetExhausted)
    );
    assert_eq!(zero.counters(), super::WorkCounters::default());
    assert_eq!(
        (failed_tries(), cursor(&storage), next_serial(&storage)),
        (0, 0, 1)
    );

    // The grant: the hash, one attempt, three visits, no comparison on an
    // empty table, one update.
    probe::arm();
    let mut charged = WorkBudget::new(64);
    let attempt = storage
        .begin_fill(&k, crate::storage::CacheVersion(0), TRIES, &mut charged)
        .unwrap();
    let counters = charged.counters();
    assert_eq!(counters.hashes, crate::index::HASH_CHARGE);
    assert_eq!(counters.coordination_attempts, 1);
    assert_eq!(
        (counters.visits, counters.comparisons, counters.updates),
        (3, 0, 1)
    );
    let counts = probe::counts();
    assert!(counts.loads <= counters.visits);
    assert!(counts.stores <= counters.updates);
    assert_eq!(counts.gate_taken, 1);
    // One more attempt on the same key pays one comparison for the match.
    let mut charged = WorkBudget::new(64);
    assert_eq!(
        storage
            .begin_fill(&k, crate::storage::CacheVersion(0), TRIES, &mut charged)
            .err(),
        Some(BeginError::InProgress)
    );
    assert_eq!(charged.counters().comparisons, 1);
    // A cut one short of the grant: every step but the update paid, no
    // record changed.
    let mut short = WorkBudget::new(crate::index::HASH_CHARGE + 1 + 3);
    assert_eq!(
        storage
            .begin_fill(&key(8), crate::storage::CacheVersion(0), TRIES, &mut short)
            .err(),
        Some(BeginError::BudgetExhausted)
    );
    assert_eq!(records(&storage), [live(1), Record::Free, Record::Free]);
    attempt.abort();

    // Service: the gate attempt, then whole record bundles; a bundle short
    // stops in front of its record with the cursor on it.
    probe::arm();
    let mut one = WorkBudget::new(1 + FILL_SERVICE_PER_RECORD);
    let pass = storage.service_fills(SHARD, TRIES, &mut one).unwrap();
    assert_eq!((pass.first, pass.examined, pass.released), (0, 1, 1));
    assert!(pass.budget_exhausted);
    assert_eq!(one.remaining(), 0);
    assert_eq!(cursor(&storage), 1);
    let counts = probe::counts();
    assert!(counts.loads <= 1 && counts.cas <= 1 && counts.gate_taken == 1);
    // A Free record needs a whole bundle affordable but charges its visit
    // alone; one step short of the third bundle stops in front of it.
    let mut short = WorkBudget::new(1 + 2 * FILL_SERVICE_PER_RECORD - 1);
    let pass = storage.service_fills(SHARD, TRIES, &mut short).unwrap();
    assert_eq!((pass.first, pass.examined), (1, 2));
    assert!(pass.budget_exhausted);
    assert_eq!(short.remaining(), 1);
    assert_eq!(cursor(&storage), 0);
    let mut gate_only = WorkBudget::new(1);
    let pass = storage.service_fills(SHARD, TRIES, &mut gate_only).unwrap();
    assert_eq!((pass.first, pass.examined), (0, 0));
    assert!(pass.budget_exhausted);
    assert_eq!(cursor(&storage), 0);
    let pass = service(&storage);
    assert_eq!((pass.first, pass.examined), (0, 3));
    assert!(!pass.budget_exhausted);
    assert_eq!(cursor(&storage), 0);
}

#[test]
fn fill_paths_allocate_nothing() {
    let storage = ready(3);
    let k = key(7);
    completed(&storage, k)
        .publish(TRIES, &mut budget())
        .unwrap();
    let allocations = crate::instrument::allocations();
    let attempt = begin(&storage, &k).unwrap();
    assert_eq!(begin(&storage, &k).err(), Some(BeginError::InProgress));
    let ended = invalidate(&storage, &k).unwrap();
    assert!(ended.removed.is_some() && ended.revoked == Some(1));
    attempt.abort();
    drop(begin(&storage, &key(8)).unwrap());
    let pass = service(&storage);
    assert_eq!(pass.released, 2);
    storage.close();
    storage.close_service(&mut budget()).unwrap();
    assert_eq!(crate::instrument::allocations(), allocations);
}

/// At every budget cut, a grant and an `InProgress` refusal leave the
/// budget exactly as one debit per step would: the hash, the gate try,
/// then per record in table order one visit and, for a current association,
/// one comparison right after it, then the grant's update. The table mixes
/// live, departed, revoked and Free records so the comparisons fall
/// between the visits.
#[test]
fn every_budget_cut_charges_the_scan_as_one_debit_per_step() {
    use super::budget::WorkKind;
    let storage = ready(6);
    // Records: live 1 (revoked below), live 2, Free, departed 4, live 5, Free.
    let first = begin(&storage, &key(1)).unwrap();
    let _second = begin(&storage, &key(2)).unwrap();
    let third = begin(&storage, &key(3)).unwrap();
    let fourth = begin(&storage, &key(4)).unwrap();
    let _fifth = begin(&storage, &key(5)).unwrap();
    third.abort();
    service(&storage);
    fourth.abort();
    assert_eq!(invalidate(&storage, &key(1)).unwrap().revoked, Some(1));
    let table = records(&storage);
    assert_eq!(
        table,
        [
            revoked(1),
            live(2),
            Record::Free,
            departed(4, false),
            live(5),
            Record::Free
        ]
    );
    // The reference: the same steps, one debit each, stopping at the first
    // refusal; `granting` adds the update a grant pays.
    let reference = |cuts: usize, granting: bool| {
        let mut budget = WorkBudget::new(cuts);
        let mut steps = || {
            budget.debit_n(WorkKind::Hash, crate::index::HASH_CHARGE)?;
            budget.debit(WorkKind::CoordinationAttempt)?;
            for record in &table {
                budget.debit(WorkKind::Visit)?;
                if record.is_associated() {
                    budget.debit(WorkKind::Comparison)?;
                }
            }
            if granting {
                budget.debit(WorkKind::Update)?;
            }
            Ok::<(), super::budget::BudgetExhausted>(())
        };
        let exhausted = steps().is_err();
        (budget, exhausted)
    };
    let full = crate::index::HASH_CHARGE + 1 + 6 + 3 + 1;
    for cuts in 0..=full {
        // A fresh key: a grant on the first Free record, or a refusal.
        let mut charged = WorkBudget::new(cuts);
        let outcome = storage.begin_fill(
            &key(9),
            crate::storage::CacheVersion(0),
            TRIES,
            &mut charged,
        );
        let (expected, exhausted) = reference(cuts, true);
        assert_eq!(charged, expected, "grant at {cuts}");
        assert_eq!(outcome.is_err(), exhausted, "grant at {cuts}");
        if let Ok(attempt) = outcome {
            assert_eq!(records(&storage)[2], live(attempt.serial()));
            attempt.abort();
            service(&storage);
            assert_eq!(records(&storage)[2], Record::Free);
            assert_eq!(records(&storage)[3], Record::Free);
        }
        // The departed record, once freed, no longer costs a comparison.
        let table = records(&storage);
        let reference = |cuts: usize| {
            let mut budget = WorkBudget::new(cuts);
            let mut steps = || {
                budget.debit_n(WorkKind::Hash, crate::index::HASH_CHARGE)?;
                budget.debit(WorkKind::CoordinationAttempt)?;
                for record in &table {
                    budget.debit(WorkKind::Visit)?;
                    if record.is_associated() {
                        budget.debit(WorkKind::Comparison)?;
                    }
                }
                Ok::<(), super::budget::BudgetExhausted>(())
            };
            let exhausted = steps().is_err();
            (budget, exhausted)
        };
        // The live key: `InProgress` once every step is paid.
        let mut charged = WorkBudget::new(cuts);
        let outcome = storage.begin_fill(
            &key(5),
            crate::storage::CacheVersion(0),
            TRIES,
            &mut charged,
        );
        let (expected, exhausted) = reference(cuts);
        assert_eq!(charged, expected, "refusal at {cuts}");
        assert_eq!(
            outcome.err(),
            Some(if exhausted {
                BeginError::BudgetExhausted
            } else {
                BeginError::InProgress
            }),
            "refusal at {cuts}"
        );
    }
    drop(first);
}

/// The failed-try counter saturates at its maximum and decides nothing.
#[test]
fn failed_tries_saturates_at_the_maximum_and_changes_no_outcome() {
    let storage = ready(2);
    let control = shard_control(&storage);
    control
        .failed_tries
        .store(usize::MAX - 1, Ordering::Relaxed);
    let held = gate(&storage).try_lock().unwrap();
    assert_eq!(
        storage
            .begin_fill(&key(1), crate::storage::CacheVersion(0), 1, &mut budget())
            .err(),
        Some(BeginError::Contended)
    );
    assert_eq!(control.failed_tries.load(Ordering::Relaxed), usize::MAX);
    assert_eq!(
        storage
            .begin_fill(&key(1), crate::storage::CacheVersion(0), 3, &mut budget())
            .err(),
        Some(BeginError::Contended)
    );
    assert_eq!(
        storage.service_fills(SHARD, 2, &mut budget()).err(),
        Some(FillServiceError::Contended)
    );
    assert_eq!(control.failed_tries.load(Ordering::Relaxed), usize::MAX);
    held.release();
    assert_eq!(begin(&storage, &key(1)).unwrap().serial(), 1);
    assert_eq!(control.failed_tries.load(Ordering::Relaxed), usize::MAX);
}

#[test]
fn the_close_service_runs_the_fill_stage_and_credits_only_records_its_own_calls_examined() {
    let storage = ready(4);
    for n in 1..=4 {
        begin(&storage, &key(n)).unwrap().abort();
    }
    let _live = begin(&storage, &key(5));
    assert_eq!(
        begin(&storage, &key(5)).err(),
        Some(BeginError::FillSlotsFull)
    );
    storage.close();
    let report = storage.close_service(&mut budget()).unwrap();
    assert_eq!(report.started_in, CloseStage::Index);
    assert_eq!(
        (
            report.fill_calls,
            report.fills_visited,
            report.fills_released
        ),
        (1, 4, 4)
    );
    assert!(report.complete);
    assert_eq!(records(&storage), vec![Record::Free; 4]);

    // A pass spread over calls, with an ordinary service call moving the
    // cursor in between: the pass counts only what its own calls examined
    // from where they left the cursor, and the stage still ends.
    let storage = ready(4);
    for n in 1..=4 {
        begin(&storage, &key(n)).unwrap().abort();
    }
    storage.close();
    // The index stage: the cursor gate, one shard gate and every position.
    let positions = {
        let index = storage.index.as_ref().unwrap();
        // SAFETY: the index mapping is live and no publisher runs.
        let tables = unsafe { index.image.shard(SHARD).unwrap().tables(&index.mapping) };
        tables.buckets.len() * crate::index::PAIRS
    };
    let report = storage
        .close_service(&mut WorkBudget::new(1 + 1 + positions))
        .unwrap();
    assert!(
        report.budget_exhausted && report.fill_calls == 0,
        "{report:?}"
    );
    let report = storage
        .close_service(&mut WorkBudget::new(1 + 1 + 2 * FILL_SERVICE_PER_RECORD))
        .unwrap();
    assert_eq!(report.started_in, CloseStage::Fills);
    assert_eq!((report.fills_visited, report.fills_released), (2, 2));
    assert!(report.budget_exhausted);
    // Another caller examines one record, so the pass's next call finds
    // the cursor moved and starts its count over.
    let pass = storage
        .service_fills(
            SHARD,
            TRIES,
            &mut WorkBudget::new(1 + FILL_SERVICE_PER_RECORD),
        )
        .unwrap();
    assert_eq!((pass.first, pass.examined, pass.released), (2, 1, 1));
    let report = storage.close_service(&mut budget()).unwrap();
    assert_eq!(report.started_in, CloseStage::Fills);
    assert_eq!((report.fills_visited, report.fills_released), (4, 1));
    assert!(report.complete, "{report:?}");
    assert_eq!(records(&storage), vec![Record::Free; 4]);

    // A busy shard gate is counted and the stage moves on; the table's own
    // cursor keeps its place.
    let storage = ready(2);
    storage.close();
    let held = gate(&storage).try_lock().unwrap();
    let report = storage.close_service(&mut budget()).unwrap();
    assert!(report.shards_busy >= 1 && !report.complete, "{report:?}");
    held.release();
}

/// The order inside the inhibition, from the primitive observer's log: the
/// odd or terminal store, the cutoff read, then the clearing and the
/// revocation, then the even store, then the retirement's removal of the
/// resident from its policy domain; a cutoff read closed skips straight to
/// the even store.
#[test]
fn the_inhibition_orders_its_cutoff_read_between_the_odd_and_even_stores() {
    use super::probe::Event;
    let storage = ready(2);
    let k = key(5);
    let resident = completed(&storage, k)
        .publish(TRIES, &mut budget())
        .unwrap();
    let attempt = begin(&storage, &k).unwrap();
    let before = report(&storage, 0).sequence;
    probe::arm();
    let ended = invalidate(&storage, &k).unwrap();
    let log = probe::events();
    assert!(!log.overflowed);
    assert_eq!(
        log.events,
        [
            Event::Inhibit {
                sequence: before + 1
            },
            Event::Cutoff { closed: false },
            Event::Cleared {
                slot: resident.slot_index()
            },
            Event::Revoked { serial: 1 },
            Event::Committed {
                sequence: before + 2
            },
            Event::Detached {
                slot: resident.slot_index()
            },
        ]
    );
    assert_eq!(ended.sequence, before + 2);
    attempt.abort();

    // Late closed: nothing between the cutoff read and the even store.
    let storage = ready(2);
    completed(&storage, k)
        .publish(TRIES, &mut budget())
        .unwrap();
    let _attempt = begin(&storage, &k).unwrap();
    let before = report(&storage, 0).sequence;
    INTERPOSE_BEFORE_CUTOFF.with(|hook| {
        hook.set(Some(|flag| flag.store(true, Ordering::SeqCst)));
    });
    probe::arm();
    assert_eq!(
        invalidate(&storage, &k).err(),
        Some(InvalidateError::Closed)
    );
    assert_eq!(
        probe::events().events,
        [
            Event::Inhibit {
                sequence: before + 1
            },
            Event::Cutoff { closed: true },
            Event::Committed {
                sequence: before + 2
            },
        ]
    );

    // Near-terminal: the terminal store is the inhibition and precedes the
    // cutoff read; the value never moves again.
    let storage = ready(2);
    let resident = completed(&storage, k)
        .publish(TRIES, &mut budget())
        .unwrap();
    let _attempt = begin(&storage, &k).unwrap();
    shard_control(&storage)
        .sequence
        .store(TERMINAL - 2, Ordering::SeqCst);
    probe::arm();
    invalidate(&storage, &k).unwrap();
    assert_eq!(
        probe::events().events,
        [
            Event::Inhibit { sequence: TERMINAL },
            Event::Cutoff { closed: false },
            Event::Cleared {
                slot: resident.slot_index()
            },
            Event::Revoked { serial: 1 },
            Event::Committed { sequence: TERMINAL },
            Event::Detached {
                slot: resident.slot_index()
            },
        ]
    );
    probe::disarm();
}

/// A departed record the shard's custody names is skipped by service, not
/// freed, until custody lets go.
#[test]
fn service_skips_a_departed_record_under_custody() {
    let storage = ready(1);
    let k = key(3);
    begin(&storage, &k).unwrap().abort();
    plant_custody(&storage, 0);
    let pass = service(&storage);
    assert_eq!((pass.examined, pass.released, pass.retained), (1, 0, 1));
    assert_eq!(records(&storage), [departed(1, false)]);
    assert_eq!(begin(&storage, &k).err(), Some(BeginError::InProgress));
    plant_custody(&storage, NO_RECORD);
    let pass = service(&storage);
    assert_eq!((pass.examined, pass.released, pass.retained), (1, 1, 0));
    assert_eq!(begin(&storage, &k).unwrap().serial(), 2);
}

/// A close that lands between a grant's entry check and its read under the
/// gate is caught by the read under the gate: `Closed`, and no record,
/// serial or cursor changed.
#[test]
fn a_close_between_the_entry_check_and_the_gate_refuses_the_grant() {
    let storage = ready(2);
    super::attempt::INTERPOSE_BEFORE_GRANT_CUTOFF.with(|hook| {
        hook.set(Some(|flag| flag.store(true, Ordering::SeqCst)));
    });
    let mut charged = WorkBudget::new(64);
    assert_eq!(
        storage
            .begin_fill(
                &key(1),
                crate::storage::CacheVersion(0),
                TRIES,
                &mut charged
            )
            .err(),
        Some(BeginError::Closed)
    );
    assert!(storage.is_closed());
    assert_eq!(charged.counters().visits, 0);
    assert_eq!(records(&storage), [Record::Free, Record::Free]);
    assert_eq!((next_serial(&storage), cursor(&storage)), (1, 0));
    assert_eq!(report(&storage, 0).sequence, 0);
}

/// A malformed word poisons the gate: the records released before it stay
/// Free, the cursor did not move, and every later hold refuses.
#[test]
fn a_malformed_word_poisons_the_gate_after_the_releases_before_it() {
    let storage = ready(2);
    begin(&storage, &key(1)).unwrap().abort();
    let table = storage.root_image.fills[0].as_ref().unwrap();
    // SAFETY: the root mapping is live; no writer runs.
    let states = unsafe { table.states.as_slice(&storage.root) };
    // A serial the shard never issued.
    states[1].store(fill::occupied(fill_serial(9)), Ordering::Relaxed);
    let progress = super::FillServiceReport {
        first: 0,
        examined: 2,
        released: 1,
        retained: 0,
        budget_exhausted: false,
    };
    assert_eq!(
        storage.service_fills(SHARD, TRIES, &mut budget()).err(),
        Some(FillServiceError::Corrupt(progress))
    );
    assert_eq!(states[0].load(Ordering::Relaxed), fill::FREE);
    assert_eq!(
        states[1].load(Ordering::Relaxed),
        fill::occupied(fill_serial(9))
    );
    assert_eq!(cursor(&storage), 0);
    assert_eq!(
        storage.service_fills(SHARD, TRIES, &mut budget()).err(),
        Some(FillServiceError::Poisoned)
    );
    assert_eq!(begin(&storage, &key(2)).err(), Some(BeginError::Contended));

    // The close service carries the same progress into its report beside
    // the poisoned gate.
    let storage = ready(2);
    begin(&storage, &key(1)).unwrap().abort();
    let table = storage.root_image.fills[0].as_ref().unwrap();
    // SAFETY: as above.
    let states = unsafe { table.states.as_slice(&storage.root) };
    states[1].store(fill::occupied(fill_serial(9)), Ordering::Relaxed);
    storage.close();
    let report = storage.close_service(&mut budget()).unwrap();
    assert_eq!(
        (
            report.fill_calls,
            report.fills_visited,
            report.fills_released
        ),
        (1, 2, 1)
    );
    assert_eq!(report.blockers.poisoned_gates, 1);
    assert!(!report.complete);

    // The grant meets the malformed word first and poisons the gate itself.
    let storage = ready(2);
    let table = storage.root_image.fills[0].as_ref().unwrap();
    // SAFETY: as above.
    let states = unsafe { table.states.as_slice(&storage.root) };
    states[0].store(fill::occupied(fill_serial(9)), Ordering::Relaxed);
    assert_eq!(begin(&storage, &key(2)).err(), Some(BeginError::Corrupt));
    assert_eq!(begin(&storage, &key(2)).err(), Some(BeginError::Contended));
    assert_eq!(
        invalidate(&storage, &key(2)).err(),
        Some(InvalidateError::Contended)
    );
}

/// A funded pass observes records in runs of four: a malformed word inside a
/// run still ends the pass with the run's records before it released, and
/// every record the run loaded counts as examined; an under-funded pass over
/// the same table stops at the malformed record itself. Both leave the gate
/// poisoned and the cursor where it was.
#[test]
fn a_malformed_word_inside_a_funded_run_ends_the_pass_after_the_run() {
    let progress = |examined| super::FillServiceReport {
        first: 0,
        examined,
        released: 1,
        retained: 0,
        budget_exhausted: false,
    };
    // Record 0 departed, record 1 malformed, records 2 and 3 Free, 4 and 5
    // Free beyond the first run: the funded pass loads the whole first run.
    let storage = ready(6);
    begin(&storage, &key(1)).unwrap().abort();
    let table = storage.root_image.fills[0].as_ref().unwrap();
    // SAFETY: the root mapping is live; no writer runs.
    let states = unsafe { table.states.as_slice(&storage.root) };
    states[1].store(fill::occupied(fill_serial(9)), Ordering::Relaxed);
    assert_eq!(
        storage.service_fills(SHARD, TRIES, &mut budget()).err(),
        Some(FillServiceError::Corrupt(progress(4)))
    );
    assert_eq!(states[0].load(Ordering::Relaxed), fill::FREE);
    assert_eq!(
        states[1].load(Ordering::Relaxed),
        fill::occupied(fill_serial(9))
    );
    assert_eq!(cursor(&storage), 0);
    assert_eq!(
        storage.service_fills(SHARD, TRIES, &mut budget()).err(),
        Some(FillServiceError::Poisoned)
    );

    // One bundle short of funding every record: the one-record steps stop
    // at the malformed record.
    let storage = ready(6);
    begin(&storage, &key(1)).unwrap().abort();
    let table = storage.root_image.fills[0].as_ref().unwrap();
    // SAFETY: as above.
    let states = unsafe { table.states.as_slice(&storage.root) };
    states[1].store(fill::occupied(fill_serial(9)), Ordering::Relaxed);
    let mut short = WorkBudget::new(1 + 6 * FILL_SERVICE_PER_RECORD - 1);
    assert_eq!(
        storage.service_fills(SHARD, TRIES, &mut short).err(),
        Some(FillServiceError::Corrupt(progress(2)))
    );
    assert_eq!(states[0].load(Ordering::Relaxed), fill::FREE);
    assert_eq!(cursor(&storage), 0);
}

/// A funded pass and an under-funded pass release the same records and
/// leave the same cursor: with a departed record in every position of a
/// table longer than one run, the observation in runs decides as the
/// one-record steps do.
#[test]
fn a_funded_pass_releases_what_the_one_record_steps_release() {
    let mut cursors = Vec::new();
    for funded in [true, false] {
        let storage = ready(6);
        // Records 0, 2 and 5 departed; 1, 3 and 4 live.
        let mut held = Vec::new();
        for k in 0..6u8 {
            let attempt = begin(&storage, &key(k)).unwrap();
            if k == 0 || k == 2 || k == 5 {
                attempt.abort();
            } else {
                held.push(attempt);
            }
        }
        let allowance = 1 + 6 * FILL_SERVICE_PER_RECORD - usize::from(!funded);
        let mut budget = WorkBudget::new(allowance);
        let pass = storage.service_fills(SHARD, TRIES, &mut budget).unwrap();
        assert_eq!((pass.examined, pass.released, pass.retained), (6, 3, 3));
        assert!(!pass.budget_exhausted);
        assert_eq!(
            records(&storage),
            [
                Record::Free,
                live(2),
                Record::Free,
                live(4),
                live(5),
                Record::Free
            ]
        );
        cursors.push(cursor(&storage));
        drop(held);
    }
    assert_eq!(cursors[0], cursors[1]);
}

/// A live owner's record survives the first close pass and is revisited
/// once it departs; a busy gate met on the way is retried by the next call.
#[test]
fn the_close_service_revisits_a_record_whose_owner_ended_after_its_first_pass() {
    let mut storage = ready(2);
    let owner = begin(&storage, &key(1)).unwrap();
    begin(&storage, &key(2)).unwrap().abort();
    storage.close();
    let held = gate(&storage).try_lock().unwrap();
    let report = storage.close_service(&mut budget()).unwrap();
    assert!(report.shards_busy >= 1 && !report.complete, "{report:?}");
    assert_eq!(report.fills_released, 0);
    held.release();
    let report = storage.close_service(&mut budget()).unwrap();
    assert!(report.complete, "{report:?}");
    assert_eq!((report.fills_released, report.blockers.live_fills), (1, 1));
    assert_eq!(records(&storage), [live(1), Record::Free]);
    owner.abort();
    let report = storage.close_service(&mut budget()).unwrap();
    assert!(report.complete, "{report:?}");
    assert_eq!((report.fills_released, report.blockers.live_fills), (1, 0));
    let report = storage.close_service(&mut budget()).unwrap();
    assert_eq!((report.fills_visited, report.fills_released), (2, 0));
    assert_eq!(finalize(&mut storage), Ok(Finalization::Drained));
}

/// The invalidation's observed primitives stay within its charge, and a
/// registered hit beside live and departed records reads its bytes without
/// touching a record, a cursor or the heap.
#[test]
fn invalidation_stays_within_its_charge_and_the_hit_path_ignores_the_table() {
    let storage = ready(3);
    let (k, other) = (key(5), key(6));
    completed(&storage, k)
        .publish(TRIES, &mut budget())
        .unwrap();
    let hit = completed(&storage, other)
        .publish(TRIES, &mut budget())
        .unwrap();
    let _attempt = begin(&storage, &k).unwrap();
    begin(&storage, &key(7)).unwrap().abort();
    probe::arm();
    let mut charged = WorkBudget::new(64);
    let ended = storage.invalidate(&k, TRIES, &mut charged).unwrap();
    assert!(ended.removed.is_some() && ended.revoked == Some(1));
    let counts = probe::counts();
    let counters = charged.counters();
    // Three record visits beside the bucket visits; the walk's own loads are
    // not observed, so the observer's loads are the scan's alone.
    assert!(counts.loads <= counters.visits, "{counts:?} {counters:?}");
    assert_eq!(counters.coordination_attempts, 1);
    probe::disarm();

    let before = records(&storage);
    let allocations = crate::instrument::allocations();
    let mut reader = storage.register().unwrap();
    let lease = reader.lookup(&other, 3, &mut budget()).unwrap();
    assert_eq!(hit_key(&lease), other);
    assert_eq!(lease.id(), hit);
    drop(lease);
    assert_eq!(crate::instrument::allocations(), allocations);
    assert_eq!(records(&storage), before);
    assert_eq!(cursor(&storage), 0);
}

/// Every cut on the enlarged root and after it: the exact error, complete
/// rollback and each mapped range unmapped once, most recent first.
#[test]
fn every_initialization_cut_with_fill_tables_reports_its_step_and_rolls_back() {
    let slot_count = 8;
    let limits = [3usize, 0, 5];
    let fills = [40usize, 0, 100];
    let expected_root = root_oracle(super::publish_tests::READERS, &fills);
    let code = OsCode(12);
    let os = |phase, region| super::init::InitError::Os {
        phase,
        region,
        code,
    };
    let plain = |op, ordinal| Fail {
        op,
        ordinal,
        code,
        region: None,
    };
    let cut = |phase, region| Fail {
        op: Op::Cut(phase),
        ordinal: 0,
        code,
        region: Some(region),
    };
    // Ordinals count calls of one kind in acquisition order: root, control,
    // index; the third element is how many mappings exist at the cut.
    let cases = [
        (plain(Op::Map, 1), os(InitPhase::Map, Region::Root), 0),
        (
            plain(Op::AdviseHuge, 1),
            os(InitPhase::PagePolicy, Region::Root),
            1,
        ),
        (
            plain(Op::AdviseNormal, 1),
            os(InitPhase::PagePolicy, Region::Root),
            1,
        ),
        (
            plain(Op::Bind, 1),
            os(InitPhase::Placement, Region::Root),
            1,
        ),
        (
            plain(Op::Protect, 1),
            os(InitPhase::Protect, Region::Root),
            1,
        ),
        (
            plain(Op::Populate, 1),
            os(InitPhase::Populate, Region::Root),
            1,
        ),
        (
            plain(Op::Residency, 1),
            os(InitPhase::VerifyPopulation, Region::Root),
            1,
        ),
        (
            plain(Op::CheckBound, 1),
            os(InitPhase::VerifyPlacement, Region::Root),
            1,
        ),
        (plain(Op::Map, 3), os(InitPhase::Map, Region::Index), 2),
        (
            cut(InitPhase::ControlInit, Region::Root),
            os(InitPhase::ControlInit, Region::Root),
            3,
        ),
        (
            cut(InitPhase::ControlInit, Region::Index),
            os(InitPhase::ControlInit, Region::Index),
            3,
        ),
        (
            cut(InitPhase::Transfer, Region::Root),
            os(InitPhase::Transfer, Region::Root),
            3,
        ),
    ];
    for (fail, expected, mapped) in cases {
        let platform = TestPlatform::heap(PAGE);
        let log = platform.log();
        platform.fail_at(fail);
        let validated = storage_config(slot_count).validate().unwrap();
        let index = config(&limits, &fills).validate(&validated).unwrap();
        let failure = Storage::initialize_indexed(
            &validated,
            index,
            &PlacementConfig { control_home: 0 },
            platform,
        )
        .err()
        .unwrap();
        assert_eq!(failure.error, expected, "{fail:?}");
        assert!(matches!(failure.cleanup, Cleanup::Complete), "{fail:?}");
        let ranges = log.ranges(Op::Map);
        assert_eq!(ranges.len(), mapped, "{fail:?}");
        if mapped > 0 {
            assert_eq!(ranges[0].1, expected_root, "{fail:?}");
        }
        let mut released = log.ranges(Op::Unmap);
        released.reverse();
        assert_eq!(released, ranges, "{fail:?}");
    }
}

/// Blockers found before a budget cut survive the resume: over three shards
/// with tables of two, none and three records, a forgotten owner on the
/// first and a departed one on the last are reported together whatever the
/// cut, no extent is released while either stands, and servicing the
/// departed one leaves the forgotten one.
#[test]
fn blockers_found_before_a_cut_survive_the_resumed_inspection() {
    let slot_count = 24;
    let limits = [8usize, 8, 8];
    let fills = [2usize, 0, 3];
    let platform = TestPlatform::heap(PAGE);
    let log = platform.log();
    let mut storage = storage_from(
        &storage_config(slot_count),
        &config(&limits, &fills),
        platform,
    );
    install_seam(&mut storage, super::publish_tests::spread);
    // Keys route by their first byte: 0 to shard 0, 3 to shard 1, 7 to
    // shard 2.
    assert_eq!(storage.route(&key(3)).unwrap().shard(), ShardIndex(1));
    assert_eq!(
        begin(&storage, &key(3)).err(),
        Some(BeginError::FillSlotsFull)
    );
    std::mem::forget(begin(&storage, &key(0)).unwrap());
    let departed_on_two = begin(&storage, &key(7)).unwrap();
    assert_eq!(departed_on_two.shard(), ShardIndex(2));
    departed_on_two.abort();
    let expected = Blockers {
        fills: 1,
        pending_fills: 1,
        ..Blockers::default()
    };
    // The whole inspection: two records, the credit count, the pool's gate
    // and its slots, then shard zero's gate and two records, shard one's
    // paid step, shard two's gate and three records.
    let inspection = 2 + 1 + 1 + 24 + 1 + 2 + 1 + 1 + 3;
    for cut in 0..=inspection {
        match storage.finalize(&mut WorkBudget::new(cut)) {
            Err(FinalizeError::BudgetExhausted) => {
                assert_eq!(blocked(&mut storage), expected, "{cut}");
            }
            Ok(Finalization::Blocked(found)) => assert_eq!(found, expected, "{cut}"),
            other => panic!("{cut}: {other:?}"),
        }
        assert!(log.ranges(Op::Unmap).is_empty(), "{cut}");
    }
    assert_eq!(
        storage
            .service_fills(ShardIndex(2), TRIES, &mut budget())
            .unwrap()
            .released,
        1
    );
    assert_eq!(
        blocked(&mut storage),
        Blockers {
            fills: 1,
            ..Blockers::default()
        }
    );
    assert!(log.ranges(Op::Unmap).is_empty());
}

/// Owners abort and drop on other threads while this one grants and
/// services the same shard: every record ends Free, every serial was issued
/// once, and no departure marked another owner's record.
#[test]
fn cross_thread_departures_race_grants_and_service_without_losing_a_record() {
    let storage = ready(3);
    let rounds = if cfg!(miri) { 4 } else { 200 };
    let granted = std::sync::atomic::AtomicU64::new(0);
    std::thread::scope(|scope| {
        for worker in 0..3u8 {
            let (storage, granted) = (&storage, &granted);
            scope.spawn(move || {
                for round in 0..rounds {
                    let k = key(worker + 3 * (round % 2) as u8);
                    match storage.begin_fill(&k, crate::storage::CacheVersion(0), 4, &mut budget())
                    {
                        Ok(attempt) => {
                            granted.fetch_add(1, Ordering::Relaxed);
                            assert_eq!(attempt.key(), &k);
                            if round % 2 == 0 {
                                attempt.abort();
                            } else {
                                drop(attempt);
                            }
                        }
                        Err(
                            BeginError::InProgress
                            | BeginError::FillSlotsFull
                            | BeginError::Contended,
                        ) => {}
                        Err(other) => panic!("{other:?}"),
                    }
                    if round % 3 == 0 {
                        let _ = storage.service_fills(SHARD, 4, &mut budget());
                    }
                }
            });
        }
    });
    // Every owner has ended; one funded pass frees whatever remains.
    let mut passes = 0;
    while records(&storage)
        .iter()
        .any(|record| *record != Record::Free)
    {
        service(&storage);
        passes += 1;
        assert!(passes <= 2, "{:?}", records(&storage));
    }
    assert_eq!(next_serial(&storage), 1 + granted.load(Ordering::Relaxed));
    assert!(granted.load(Ordering::Relaxed) >= 3);
    assert_eq!(
        begin(&storage, &key(9)).unwrap().serial(),
        next_serial(&storage) - 1
    );
}

/// A shard gate word left held by a holder that never released it blocks
/// finalization with its own error, without a Rust borrow to prove it.
#[test]
fn a_held_shard_gate_word_is_reported_not_inspected() {
    let mut storage = ready(2);
    std::mem::forget(gate(&storage).try_lock().unwrap());
    assert_eq!(
        finalize(&mut storage),
        Err(FinalizeError::ShardGateHeld { shard: SHARD })
    );
    assert_eq!(
        storage.service_fills(SHARD, TRIES, &mut budget()).err(),
        Some(FillServiceError::Contended)
    );
}

/// Six records: live attempts on keys 1, 3 and 4, a revoked one on key 2,
/// and two Free records, so a scan visits six records and compares three.
fn mixed() -> Storage<TestPlatform> {
    let storage = ready(6);
    for n in 1..=4 {
        std::mem::forget(begin(&storage, &key(n)).unwrap());
    }
    assert_eq!(invalidate(&storage, &key(2)).unwrap().revoked, Some(2));
    assert_eq!(
        records(&storage),
        [
            live(1),
            revoked(2),
            live(3),
            live(4),
            Record::Free,
            Record::Free
        ]
    );
    storage
}

/// An absent-key invalidation charges the same steps with an allowance that
/// covers every record's visit and comparison and with one that covers only
/// the steps it takes, so its scan runs in both the funded and the bounded
/// form.
#[test]
fn an_invalidation_scan_charges_the_same_funded_or_bounded() {
    let storage = mixed();
    let mut funded = budget();
    let absent = storage.invalidate(&key(9), TRIES, &mut funded).unwrap();
    assert_eq!((absent.removed, absent.revoked), (None, None));
    assert_eq!(funded.counters().comparisons, 3);
    let mut bounded = WorkBudget::new(1024 - funded.remaining());
    let absent = storage.invalidate(&key(9), TRIES, &mut bounded).unwrap();
    assert_eq!((absent.removed, absent.revoked), (None, None));
    assert_eq!(bounded.counters(), funded.counters());
    assert_eq!(bounded.remaining(), 0);
}

/// At a malformed word the grant's scan charges the records it reached, the
/// visits up to and including it and the comparisons before it, with a
/// funded allowance and with one that covers exactly those steps.
#[test]
fn a_scan_charges_the_records_reached_at_a_malformed_word() {
    for tight in [false, true] {
        let storage = mixed();
        let table = storage.root_image.fills[0].as_ref().unwrap();
        // SAFETY: the root mapping is live; no writer runs.
        let states = unsafe { table.states.as_slice(&storage.root) };
        // Record 3 carries a serial the shard never issued.
        states[3].store(fill::occupied(fill_serial(9)), Ordering::Relaxed);
        let reached = super::WorkCounters {
            comparisons: 2,
            coordination_attempts: 1,
            visits: 4,
            updates: 0,
            hashes: crate::index::HASH_CHARGE,
        };
        let mut charged = if tight {
            WorkBudget::new(crate::index::HASH_CHARGE + 1 + 4 + 2)
        } else {
            budget()
        };
        assert_eq!(
            storage
                .begin_fill(
                    &key(5),
                    crate::storage::CacheVersion(0),
                    TRIES,
                    &mut charged
                )
                .err(),
            Some(BeginError::Corrupt)
        );
        assert_eq!(charged.counters(), reached, "tight: {tight}");
        assert_eq!(begin(&storage, &key(5)).err(), Some(BeginError::Contended));
    }
}

/// A service pass with a bundle for every record and one with one step
/// less, which still funds the whole pass, free the same records, report the
/// same, charge the same and leave the cursor where they found it.
#[test]
fn a_service_pass_charges_the_same_funded_or_just_funded() {
    for funded in [true, false] {
        let storage = ready(6);
        let attempts: Vec<_> = (1..=6).map(|n| begin(&storage, &key(n)).unwrap()).collect();
        let mut attempts = attempts.into_iter();
        // Records 0 and 3 depart; 1, 2, 4 and 5 stay live.
        attempts.next().unwrap().abort();
        let kept: Vec<_> = attempts.by_ref().take(2).collect();
        attempts.next().unwrap().abort();
        let rest: Vec<_> = attempts.collect();
        let mut charged = if funded {
            WorkBudget::new(1 + 6 * FILL_SERVICE_PER_RECORD)
        } else {
            WorkBudget::new(6 * FILL_SERVICE_PER_RECORD)
        };
        let pass = storage.service_fills(SHARD, TRIES, &mut charged).unwrap();
        assert_eq!(
            (pass.first, pass.examined, pass.released, pass.retained),
            (0, 6, 2, 4)
        );
        assert!(!pass.budget_exhausted);
        assert_eq!(
            charged.counters(),
            super::WorkCounters {
                coordination_attempts: 1,
                visits: 6,
                updates: 2,
                ..super::WorkCounters::default()
            }
        );
        assert_eq!(cursor(&storage), 0);
        assert_eq!(
            records(&storage),
            [
                Record::Free,
                live(2),
                live(3),
                Record::Free,
                live(5),
                live(6)
            ]
        );
        drop((kept, rest));
    }
}

#[test]
fn a_funded_pass_from_any_cursor_decides_what_the_one_record_steps_decide() {
    const RECORDS: usize = 18;
    let freed = [2, 6, 12, 14];
    let departed = [0, 10, 11, 17];
    for first in 0..RECORDS {
        for funded in [true, false] {
            let storage = ready(RECORDS);
            let mut attempts: Vec<_> = (0..RECORDS as u8)
                .map(|k| Some(begin(&storage, &key(k)).unwrap()))
                .collect();
            for record in freed {
                attempts[record].take().unwrap().abort();
            }
            assert_eq!(service(&storage).released, freed.len());
            for record in departed {
                attempts[record].take().unwrap().abort();
            }
            let table = storage.root_image.fills[0].as_ref().unwrap();
            // SAFETY: the root mapping is live; no writer runs.
            unsafe { &table.control.as_slice(&storage.root)[0] }
                .cursor
                .store(first, Ordering::Relaxed);
            let allowance = 1 + RECORDS * FILL_SERVICE_PER_RECORD - usize::from(!funded);
            let mut charged = WorkBudget::new(allowance);
            let pass = storage.service_fills(SHARD, TRIES, &mut charged).unwrap();
            assert_eq!(
                pass,
                super::FillServiceReport {
                    first,
                    examined: RECORDS,
                    released: departed.len(),
                    retained: RECORDS - freed.len() - departed.len(),
                    budget_exhausted: false,
                },
                "first {first}, funded {funded}"
            );
            assert_eq!(
                charged.counters(),
                super::WorkCounters {
                    coordination_attempts: 1,
                    visits: RECORDS,
                    updates: departed.len(),
                    ..super::WorkCounters::default()
                }
            );
            assert_eq!(cursor(&storage), first);
            let expected: Vec<_> = (0..RECORDS)
                .map(|record| match attempts[record] {
                    Some(_) => live(record as u64 + 1),
                    None => Record::Free,
                })
                .collect();
            assert_eq!(
                records(&storage),
                expected,
                "first {first}, funded {funded}"
            );
        }
    }
}

/// A departure whose word was revoked after the grant sets its flag on the
/// revoked word, and a departure against another serial's word writes
/// nothing, through the production departure on the mapped word.
#[test]
fn a_departure_expecting_the_granted_word_follows_a_revocation() {
    let storage = ready(2);
    let k = key(4);
    let old = begin(&storage, &k).unwrap();
    assert_eq!(invalidate(&storage, &k).unwrap().revoked, Some(1));
    old.abort();
    assert_eq!(records(&storage), [departed(1, true), Record::Free]);
    let state = storage.fill_state(SHARD, 0);
    let word = state.load(Ordering::Relaxed);
    assert!(!fill::depart(state, fill_serial(1)));
    assert!(!fill::depart(state, fill_serial(2)));
    assert_eq!(state.load(Ordering::Relaxed), word);
}

/// "Dropping it releases the gate, poisoned when the drop unwinds from a
/// panic that began after the gate was taken" (`GateGuard`), for the fill
/// shard's gate under a close-service call made from a destructor on a
/// thread already unwinding. The departed record's published row names a
/// retained right on a slot past the slot table, so the refund's
/// `release_right` panics while the pass holds the shard gate. Both the
/// cursor gate and the shard gate read poisoned afterwards, as they do when
/// the same call is made on a thread that is not unwinding.
#[test]
fn a_fill_stage_panic_poisons_the_shard_gate_also_during_unwinding() {
    use super::closing::CloseError;
    use super::{AllocationId, SlotIndex};

    fn call(storage: &Storage<TestPlatform>) {
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = storage.close_service(&mut WorkBudget::new(1 << 20));
        }));
        assert!(panicked.is_err(), "premise: the fill stage panics");
    }
    struct CallOnDrop<'a>(&'a Storage<TestPlatform>);
    impl Drop for CallOnDrop<'_> {
        fn drop(&mut self) {
            assert!(std::thread::panicking());
            call(self.0);
        }
    }

    for unwinding in [false, true] {
        let storage = ready(2);
        begin(&storage, &key(2)).unwrap().abort();
        let slots = storage.live_pool().unwrap().records().len();
        let table = storage.fill_table(SHARD).unwrap();
        // SAFETY: the storage is live and only atomics are written; no gate
        // holder runs.
        let view = unsafe { storage.fill_view(table) };
        let (metadata_len, body_len) = view.rows[0].lengths();
        view.rows[0].mark_ready(
            AllocationId::new(SlotIndex(slots), 0).record_tag(),
            metadata_len,
            body_len,
        );
        view.rows[0].plant_terminal(super::row::published(u32::MAX, true));
        storage.close();

        if unwinding {
            let outer = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _call = CallOnDrop(&storage);
                panic!("an unrelated panic");
            }));
            assert!(outer.is_err());
        } else {
            call(&storage);
        }

        assert_eq!(
            storage.close_service(&mut budget()).err(),
            Some(CloseError::Poisoned),
            "premise, unwinding {unwinding}: the cursor gate is poisoned"
        );
        let index = storage.index().unwrap();
        let shard = index.image.shard(SHARD).unwrap();
        // SAFETY: the index mapping is live while the storage is.
        let gate = unsafe { shard.gate(&index.mapping) };
        assert_eq!(
            gate.try_lock().map(|hold| hold.release()),
            Err(super::gate::GateError::Poisoned),
            "unwinding {unwinding}: the shard gate after the fill stage's panic"
        );
    }
}

/// The record count of the shard's fill table.
const RECORDS: usize = 6;

/// A table of [`RECORDS`] records whose record `free` is its first Free
/// record and whose other records up to record `free + 4` hold the live
/// attempts of the keys `1 + record`; returns those attempts by record.
fn table_with_free_at(
    storage: &Storage<TestPlatform>,
    free: usize,
) -> Vec<Option<FillAttempt<'_, TestPlatform>>> {
    let mut attempts: Vec<_> = (0..=free + 4)
        .map(|record| Some(begin(storage, &key(1 + record as u8)).unwrap()))
        .collect();
    attempts[free].take().unwrap().abort();
    assert_eq!(service(storage).released, 1);
    let table = records(storage);
    assert_eq!(table.len(), RECORDS);
    for (record, state) in table.iter().enumerate() {
        let expected = match record {
            at if at == free || at > free + 4 => Record::Free,
            at => live(1 + at as u64),
        };
        assert_eq!(
            *state, expected,
            "record {record} with the Free record at {free}"
        );
    }
    attempts
}

/// A funded `begin_fill` refuses `InProgress` for a key whose current
/// attempt lies behind the shard's first Free record, at each place of the
/// whole run of four records that follows it, whether the attempt's owner is
/// live or has departed, and the refusal leaves every record as it was: the
/// record is that key's attempt until service frees it, and the key then
/// begins again on the first Free record.
#[test]
fn a_keys_attempt_in_the_run_of_four_behind_the_first_free_record_refuses_in_progress() {
    for free in [0, 1] {
        for behind in 1..=4 {
            let storage = ready(RECORDS);
            let mut attempts = table_with_free_at(&storage, free);
            let at = free + behind;
            let same = key(1 + at as u8);
            let before = records(&storage);
            assert_eq!(
                begin(&storage, &same).err(),
                Some(BeginError::InProgress),
                "a live attempt at record {at} behind the Free record {free}"
            );
            assert_eq!(records(&storage), before, "the refusal changes no record");

            // The owner departs and service has not run: the record is still
            // the key's attempt.
            attempts[at].take().unwrap().abort();
            let mut gone = before.clone();
            gone[at] = departed(1 + at as u64, false);
            assert_eq!(records(&storage), gone);
            assert_eq!(
                begin(&storage, &same).err(),
                Some(BeginError::InProgress),
                "a departed attempt at record {at} behind the Free record {free}"
            );
            assert_eq!(records(&storage), gone, "the refusal changes no record");

            // Once service frees the record, the key begins again on the
            // first Free record.
            assert_eq!(service(&storage).released, 1);
            let again = begin(&storage, &same).unwrap();
            assert_eq!(records(&storage)[free], live(again.serial()));
            assert_eq!(records(&storage)[at], Record::Free);
        }
    }
}

/// The same refusal when the key's attempt is the only occupied record of
/// its run: the three other attempts of the run of four behind the first
/// Free record are aborted and freed, so the run holds one occupied word,
/// at each of its four places in turn. A funded `begin_fill` of that
/// record's key refuses `InProgress`, whether the attempt's owner is live
/// or has departed, and changes no record.
#[test]
fn a_keys_attempt_alone_in_the_run_of_four_behind_the_first_free_record_refuses_in_progress() {
    for free in [0, 1] {
        for behind in 1..=4 {
            let storage = ready(RECORDS);
            let mut attempts = table_with_free_at(&storage, free);
            let at = free + behind;
            for other in (free + 1..=free + 4).filter(|other| *other != at) {
                attempts[other].take().unwrap().abort();
            }
            assert_eq!(service(&storage).released, 3);
            let before = records(&storage);
            for (record, state) in before.iter().enumerate() {
                let expected = match record {
                    held if held == at || held < free => live(1 + held as u64),
                    _ => Record::Free,
                };
                assert_eq!(
                    *state, expected,
                    "record {record} with the Free record at {free}"
                );
            }
            let same = key(1 + at as u8);
            assert_eq!(
                begin(&storage, &same).err(),
                Some(BeginError::InProgress),
                "a live attempt alone at record {at} behind the Free record {free}"
            );
            assert_eq!(records(&storage), before, "the refusal changes no record");

            attempts[at].take().unwrap().abort();
            let mut gone = before.clone();
            gone[at] = departed(1 + at as u64, false);
            assert_eq!(records(&storage), gone);
            assert_eq!(
                begin(&storage, &same).err(),
                Some(BeginError::InProgress),
                "a departed attempt alone at record {at} behind the Free record {free}"
            );
            assert_eq!(records(&storage), gone, "the refusal changes no record");
        }
    }
}

/// A key with no attempt is granted the first Free record of the table
/// [`table_with_free_at`] builds, so an `InProgress` refusal on that table is
/// the same-key record's doing.
#[test]
fn a_key_with_no_attempt_takes_the_first_free_record() {
    for free in [0, 1] {
        let storage = ready(RECORDS);
        let _attempts = table_with_free_at(&storage, free);
        let fresh = begin(&storage, &key(100)).unwrap();
        assert_eq!(records(&storage)[free], live(fresh.serial()));
    }
}

const SLOTS: usize = 8;
/// Both shards carry a key limit of zero, which disables them.
const LIMITS: [usize; 2] = [0, 0];
const KEY: Key = [0x5A; 32];

/// The storage's pool, lease, era and shard reports, whether the key has a
/// route, and whether admission is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Seen {
    pool: Option<PoolReport>,
    leases: Option<LeaseReport>,
    era: Option<EraReport>,
    shards: [Option<ShardReport>; 2],
    route: bool,
    closed: bool,
}

fn seen(storage: &Storage<TestPlatform>) -> Seen {
    Seen {
        pool: storage.pool_report(),
        leases: storage.lease_report(),
        era: storage.era_report(),
        shards: [0, 1].map(|shard| storage.shard_report(ShardIndex(shard))),
        route: storage.route(&KEY).is_some(),
        closed: storage.is_closed(),
    }
}

/// On an open storage whose two-shard index has both shards disabled, each
/// of five keyed operations refuses for the cause its documentation gives to
/// an index with no enabled shard, debits no hash step, and leaves every
/// field of [`Seen`] as it was: `begin_fill`, `join_fill`, `invalidate`, exact
/// removal and `lookup` return `Contended`, and the lookup's registration
/// ends unpinned. A key's route and a fingerprint's reroute return
/// `NoEnabledShard`, the refusal each of those five operations reports as
/// `Contended`.
#[test]
fn every_keyed_operation_refuses_and_changes_nothing_when_no_shard_is_enabled() {
    let storage = storage_from(
        &storage_config(SLOTS),
        &index_config(&LIMITS, (1, 1), 1),
        TestPlatform::heap(PAGE),
    );
    let geometry = storage.index_geometry().expect("the storage is indexed");
    assert_eq!(geometry.shards().len(), 2, "a two-shard index");
    assert!(geometry.enabled().is_empty(), "no shard is enabled");
    let mut reader = storage.register().expect("a lookup registration");
    let record: RegistrationIndex = reader.index();
    let registration = |storage: &Storage<TestPlatform>| -> RegistrationReport {
        storage.registration_report(record).unwrap()
    };

    let before = seen(&storage);
    assert!(!before.closed, "the storage is open");
    assert!(before.pool.is_some() && before.leases.is_some());
    assert_eq!(
        before.shards,
        [None, None],
        "a disabled shard reports nothing"
    );
    assert!(!before.route, "no key has a route");
    let unpinned = registration(&storage);
    assert_eq!((unpinned.claimed, unpinned.pinned_era), (true, None));

    // begin_fill: an index with no enabled shard is one of the causes of
    // `Contended`; a `BeginError` grants no authority and leaves every record
    // as it was.
    let mut spent = budget();
    let begun = storage.begin_fill(&KEY, CacheVersion(1), TRIES, &mut spent);
    assert_eq!(
        begun.err(),
        Some(BeginError::Contended),
        "begin_fill with no enabled shard refuses Contended"
    );
    assert_eq!(spent.counters(), WorkCounters::default());
    assert_eq!(seen(&storage), before, "begin_fill changed nothing");

    // join_fill: no `JoinError` joins or changes a record.
    let mut spent = budget();
    let joined = storage.join_fill(&KEY, u64::MAX, TRIES, &mut spent);
    assert_eq!(joined.err(), Some(JoinError::Contended));
    assert_eq!(spent.counters(), WorkCounters::default());
    assert_eq!(seen(&storage), before, "join_fill changed nothing");

    // invalidate: no mapping, association or count changed.
    let mut spent = budget();
    let invalidated = storage.invalidate(&KEY, TRIES, &mut spent);
    assert_eq!(invalidated.err(), Some(InvalidateError::Contended));
    assert_eq!(spent.counters(), WorkCounters::default());
    assert_eq!(seen(&storage), before, "invalidate changed nothing");

    // Exact removal: no mapping changes.
    let mut spent = budget();
    let removed = storage.remove(&KEY, AllocationId::of_record_tag(1), TRIES, &mut spent);
    assert_eq!(removed.err(), Some(RemoveError::Contended));
    assert_eq!(spent.counters().hashes, 0);
    assert_eq!(seen(&storage), before, "exact removal changed nothing");

    // lookup: every reservation the call made was refunded and its protected
    // interval ended before the error was returned.
    let mut spent = budget();
    let looked = reader.lookup(&KEY, RETRIES, &mut spent);
    assert_eq!(looked.err(), Some(LookupError::Contended));
    assert_eq!(spent.counters().hashes, 0, "the route debits nothing");
    let after = registration(&storage);
    assert_eq!(
        (after.claimed, after.pinned_era),
        (true, None),
        "the lookup's interval ended"
    );
    assert_eq!(seen(&storage), before, "lookup changed nothing");

    // A key's route and a fingerprint's reroute return `NoEnabledShard`
    // against a geometry with no enabled shard, and debit nothing.
    for hasher in [KeyHasher::with_key_pair(1, 2), KeyHasher::with_seam(|_| 7)] {
        let mut exact = WorkBudget::new(HASH_CHARGE);
        assert_eq!(
            hasher.route(&KEY, geometry, &mut exact).err(),
            Some(RouteError::NoEnabledShard)
        );
        assert_eq!(
            hasher
                .reroute_prefetching(7, geometry, &mut exact, Prefetch::NONE)
                .err(),
            Some(RouteError::NoEnabledShard)
        );
        assert_eq!(exact.remaining(), HASH_CHARGE, "nothing is debited");
        assert_eq!(exact.counters(), WorkCounters::default());
    }
}
