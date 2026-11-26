//! Tests derive expected state from protocol rules; byte checks read the simulated device and compare against records the test builds.

use std::cell::Cell;
use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::exact_child;

use super::admission::{Admitted, Decision};
use super::attempt_tests::{
    begin, departed, gate, invalidate, live, ready, records, revoked, service,
};
use super::budget::{BudgetDimension, BudgetShort, WorkBudget};
use super::claim_exit_tests::{
    FREE, PARKED, PARKED_RESIDENT, RETIRED, conserved_after_service, conserved_at,
};
use super::config::StorageConfig;
use super::device::sim::{Event, Fault, QuiesceMode, SimControl, Unwind};
use super::device::{CommandToken, DeviceStatus, IO_UNIT, Operation, RefusalReason, SubmitRefusal};
use super::extent::ExtentLocator;
use super::fill::Record;
use super::finalize::{Finalization, FinalizeError};
use super::layout::{LayoutError, ObjectGeometry};
use super::ledger::SlotPartition;
use super::lookup_tests::lookup;
use super::owner::{Pool, Storage};
use super::owner_fixture::write_tokens;
use super::prefetch::{RMW_WAITS_FOR_HINTS, WRITE_HINTS};
use super::probe;
use super::publish_tests::{
    PAGE, RETRIES, TRIES, budget, candidates, index_config, key, report, storage_config,
    storage_from,
};
use super::record::{
    Crc32c, ExpectedHeader, ExtentPosition, RecordIdentity, header_bytes, verify_header,
};
use super::reserve::INTERPOSE_AFTER_OPEN_READ;
use super::seeded::SplitMix64;
use super::tables::{SlotIndex, SlotState};
use super::test_platform::{TestPlatform, blocked, finalize};
use super::volume_fixture::{
    BUFFER, Device, SESSION, ample_io, arena, arena_with, attach_with, extent, place, record_bytes,
    settle, step,
};
use super::word::ABANDONED;
use super::writable::INTERPOSE_BEFORE_REVALIDATION;
use super::{FillPublishError, FillReserveError, ReceiveError, WritableFill};
use crate::index::{IndexConfig, Key};
use crate::sim::round::turn_until;

/// One reserved bit of a slot word. A word carrying it is malformed, so a
/// gate holder's read of it through `word::checked` panics under the gate.
pub(super) const RESERVED_BIT: u64 = 1 << 43;
const _: () = assert!(RESERVED_BIT & super::word::RESERVED == RESERVED_BIT);

/// Payload bytes of the (4, 20) objects most tests reserve.
const SMALL: usize = 24;
/// Visits the first extent reservation of a fixture's fresh volume makes:
/// the root summary, the one indexed run and the only chunk's bitmap word.
const WORK: usize = 3;

/// The extent work limit a reservation preflights on `storage`.
fn search(storage: &Storage<TestPlatform>) -> usize {
    storage.reserve_minimum() - 4
}
/// The record-aligned window length of every fixture.
const CHUNK: u64 = 8192;

pub(super) fn admit(storage: &Storage<TestPlatform>, metadata: usize, body: usize) -> Admitted {
    match storage.decide_admission(Some(metadata), Some(body)) {
        Decision::Admit(admitted) => admitted,
        other => panic!("expected Admit, got {other:?}"),
    }
}

/// Units `storage` charges an object of `metadata` and `body` bytes: every extent's local header and payload, in whole units.
pub(super) fn charge(storage: &Storage<TestPlatform>, metadata: usize, body: usize) -> u64 {
    ObjectGeometry::new((metadata + body) as u64, &storage.record)
        .expect("a payload within the object limit")
        .total_units()
}

pub(crate) fn reserve<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    key: &Key,
    metadata: usize,
    body: usize,
) -> Result<WritableFill<'s, 'a, TestPlatform>, FillReserveError> {
    reserve_at(
        storage,
        key,
        crate::storage::CacheVersion(0),
        metadata,
        body,
    )
}

pub(crate) fn reserve_at<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    key: &Key,
    version: crate::storage::CacheVersion,
    metadata: usize,
    body: usize,
) -> Result<WritableFill<'s, 'a, TestPlatform>, FillReserveError> {
    let attempt = storage
        .begin_fill(key, version, TRIES, &mut budget())
        .unwrap();
    let admitted = admit(storage, metadata, body);
    attempt.reserve_storage(admitted, Some(metadata), Some(body), TRIES, &mut budget())
}

/// [`reserve_at`] that returns `None` when the storage refuses the fill's begin or its reservation, dropping the
/// attempt, so a caller moves on or begins again later.
pub(crate) fn try_reserve_at<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    key: &Key,
    metadata: usize,
    body: usize,
) -> Option<WritableFill<'s, 'a, TestPlatform>> {
    let version = crate::storage::CacheVersion(0);
    let attempt = storage
        .begin_fill(key, version, TRIES, &mut budget())
        .ok()?;
    let admitted = admit(storage, metadata, body);
    (attempt.reserve_storage(admitted, Some(metadata), Some(body), TRIES, &mut budget())).ok()
}

pub(super) fn partition(storage: &Storage<TestPlatform>) -> (super::RawPartition, SlotPartition) {
    let ledger = storage.pool_report().unwrap().ledger.unwrap();
    (ledger.raw, ledger.slots)
}

fn slot_incarnation(storage: &Storage<TestPlatform>, slot: usize) -> u32 {
    storage.slot_state(SlotIndex(slot)).unwrap().1
}

fn drain_pool(storage: &Storage<TestPlatform>) {
    storage.service(&mut WorkBudget::new(1 << 10)).unwrap();
}

/// The slot the next claim for `k` takes: the lowest free slot of the key's
/// placement window, or the first free slot after it.
pub(super) fn next_slot(storage: &Storage<TestPlatform>, k: &Key) -> usize {
    let fingerprint = storage.route(k).unwrap().fingerprint();
    storage
        .live_pool()
        .unwrap()
        .claim_order(Some(fingerprint), 1)[0]
}

/// The slot the next claim for `k` takes, as [`next_slot`] predicts, and
/// the incarnation that claim installs on it.
pub(super) fn next_claim(storage: &Storage<TestPlatform>, k: &Key) -> (usize, u32) {
    let slot = next_slot(storage, k);
    (slot, slot_incarnation(storage, slot) + 1)
}

/// Asserts that the claim [`next_claim`] predicted ran and returned: its
/// slot's incarnation is the one the claim installed, the holdings pass the
/// conservation judge, and the slot is `Free`.
#[track_caller]
pub(super) fn returned_claim(storage: &Storage<TestPlatform>, (slot, claimed): (usize, u32)) {
    assert_eq!(
        slot_incarnation(storage, slot),
        claimed,
        "premise: the claim"
    );
    conserved_at(storage, slot, FREE);
}

/// Exhausts the incarnation of the first `count` slots a claim for `key(1)`
/// visits and returns the slot it then takes.
fn plant_exhausted(storage: &Storage<TestPlatform>, count: usize) -> usize {
    let fingerprint = storage.route(&key(1)).unwrap().fingerprint();
    let live_pool = storage.live_pool().unwrap();
    let order = live_pool.claim_order(Some(fingerprint), count + 1);
    let _held = live_pool.lock().unwrap();
    for &slot in &order[..count] {
        live_pool.set_incarnation(slot, u32::MAX);
    }
    order[count]
}

fn refused(
    storage: &Storage<TestPlatform>,
    lengths: (Option<usize>, Option<usize>),
    admitted: Admitted,
    budget: &mut WorkBudget,
    expected: FillReserveError,
) {
    let before = partition(storage);
    // The claims: the shard's additional-key count and the lease credits.
    let claims = |storage: &Storage<TestPlatform>| {
        let credits = storage.lease_report().unwrap().reserved;
        (super::publish_tests::report(storage, 0).reserved, credits)
    };
    let claimed = claims(storage);
    let head = next_slot(storage, &key(1));
    let attempt = begin(storage, &key(1)).unwrap();
    let serial = attempt.serial();
    let record = records(storage)
        .iter()
        .position(|record| *record == live(serial))
        .unwrap();
    let error = attempt
        .reserve_storage(admitted, lengths.0, lengths.1, TRIES, budget)
        .err();
    assert_eq!(error, Some(expected));
    conserved_at(storage, head, FREE);
    assert_eq!(records(storage)[record], departed(serial, false));
    assert_eq!(partition(storage), before);
    assert_eq!(claims(storage), claimed, "a refusal holds no claim");
    assert_eq!(service(storage).released, 1);
    assert_eq!(records(storage)[record], Record::Free);
}

#[test]
fn input_refusals_and_forged_decisions_consume_the_attempt_and_spend_nothing() {
    let storage = ready(4);
    let admitted = admit(&storage, 4, 20);
    let mut wider = storage_config(8);
    wider.volume.record.chunk_len *= 2;
    let wider = Storage::initialize(
        &wider.validate().unwrap(),
        &super::placement::PlacementConfig { control_home: 0 },
        TestPlatform::heap(super::publish_tests::PAGE),
    )
    .unwrap();
    let wider = admit(&wider, 4, 20);
    let mut zero = WorkBudget::new(0);
    type Lengths = (Option<usize>, Option<usize>);
    let cases: [(Lengths, Admitted, FillReserveError); 7] = [
        (
            (None, Some(20)),
            admitted,
            FillReserveError::Layout(LayoutError::UnknownLength),
        ),
        (
            (Some(4), None),
            admitted,
            FillReserveError::Layout(LayoutError::UnknownLength),
        ),
        (
            (Some(17), Some(20)),
            admitted,
            FillReserveError::Layout(LayoutError::MetadataTooLarge { len: 17, cap: 16 }),
        ),
        (
            (Some(4), Some(201)),
            admitted,
            FillReserveError::Layout(LayoutError::BodyTooLarge { len: 201, cap: 200 }),
        ),
        ((Some(4), Some(21)), admitted, FillReserveError::Superseded),
        (
            (Some(4), Some(20)),
            admit(&storage, 16, 100),
            FillReserveError::Superseded,
        ),
        ((Some(4), Some(20)), wider, FillReserveError::Superseded),
    ];
    for (lengths, forged, expected) in cases {
        refused(&storage, lengths, forged, &mut zero, expected);
    }
    assert_eq!(zero.counters(), super::WorkCounters::default());
}

/// The body of the two-extent object [`two_extents`] admits beside four metadata bytes.
const TWO_EXTENT_BODY: usize = super::geometry::EXTENT_PAYLOAD as usize + 1000;

/// A storage with one sequence arena root and one fill record whose caps admit [`TWO_EXTENT_BODY`], under a record format of `chunk_len`-byte windows.
fn two_extents(chunk_len: u32) -> Storage<TestPlatform> {
    let fills = [1];
    let index = crate::index::IndexConfig {
        fills: &fills,
        ..super::publish_tests::index_config(&[8], (1, 1), 1)
    };
    let mut volume = crate::storage::test_volume(256 * crate::storage::IO_UNIT, 8);
    volume.block_roots = 1;
    volume.record.chunk_len = chunk_len;
    super::publish_tests::storage_from(
        &super::StorageConfig {
            body_cap: TWO_EXTENT_BODY,
            volume,
            ..super::publish_tests::storage_config(8)
        },
        &index,
        TestPlatform::heap(super::publish_tests::PAGE),
    )
}

/// Admission admits an object of two extents, and the fill reservation
/// claims its whole charge through a promise: the escrow holds none
/// of it once every extent is placed, and the abort returns every extent,
/// the block and the slot.
#[test]
fn a_multi_extent_object_is_reserved_through_a_promise_and_aborted_whole() {
    let body = TWO_EXTENT_BODY;
    let storage = two_extents(CHUNK as u32);
    let before = partition(&storage);
    let admitted = admit(&storage, 4, body);
    assert_eq!(admitted.extents(), 2);
    let fill = begin(&storage, &key(1))
        .unwrap()
        .reserve_storage(admitted, Some(4), Some(body), TRIES, &mut budget())
        .unwrap();
    let report = storage.pool_report().unwrap();
    assert_eq!(report.escrow_units, 0, "every extent placed");
    let held = before.0.free - report.ledger.unwrap().raw.free;
    assert_eq!(held as u64, charge(&storage, 4, body) * IO_UNIT as u64);
    fill.abort();
    assert_eq!(service(&storage).released, 1);
    assert_eq!(partition(&storage), before);
}

/// A decision's own lengths select the claim of one extent or the promise of
/// several, and each verifies the decision before it takes a gate: a
/// decision made for other lengths, of either extent count, or under another
/// record format refuses `Superseded`, leaves the escrow at zero and the
/// budget's counters at their defaults.
#[test]
fn a_forged_decision_for_a_multi_extent_object_is_superseded_on_either_path() {
    let body = TWO_EXTENT_BODY;
    let storage = two_extents(CHUNK as u32);
    let wider = two_extents(2 * CHUNK as u32);
    let two = admit(&storage, 4, body);
    let one = admit(&storage, 4, 20);
    assert_eq!((two.extents(), one.extents()), (2, 1));
    let mut zero = WorkBudget::new(0);
    for (lengths, forged) in [
        ((4, body), admit(&storage, 4, body - 1)),
        ((4, body), one),
        ((4, 20), two),
        ((4, body), admit(&wider, 4, body)),
    ] {
        refused(
            &storage,
            (Some(lengths.0), Some(lengths.1)),
            forged,
            &mut zero,
            FillReserveError::Superseded,
        );
        assert_eq!(storage.pool_report().unwrap().escrow_units, 0);
    }
    assert_eq!(zero.counters(), super::WorkCounters::default());
}

#[test]
fn every_budget_gate_and_capacity_refusal_consumes_the_attempt_and_returns_its_claims_once() {
    let storage = ready(4);
    let k = key(1);
    let before = partition(&storage);
    let admitted = admit(&storage, 4, 20);

    let mut whole = budget();
    let fill = begin(&storage, &k)
        .unwrap()
        .reserve_storage(admitted, Some(4), Some(20), TRIES, &mut whole)
        .unwrap();
    let bundle = budget().remaining() - whole.remaining();
    let counters = whole.counters();
    // The pool and shard gate attempts and the one compare-exchange that
    // reserves both credits; the take; the slot, the record and the chain's
    // one bucket; the hash pass of the place's route.
    assert_eq!(counters.coordination_attempts, 3);
    assert_eq!(counters.updates, 1);
    assert_eq!(counters.visits, 3 + WORK);
    assert_eq!(counters.hashes, 1);
    assert_eq!(bundle, counters.comparisons + 3 + 1 + 3 + WORK + 1);
    fill.abort();
    assert_eq!(service(&storage).released, 1);
    // The extent search preflights its whole limit and the give-back,
    // then debits only its visits. The first funded budget is the spent
    // bundle less the search's visits and the six steps after the extent claim,
    // plus the limit and the give-back; every smaller budget refuses.
    for steps in 0..bundle + search(&storage) - WORK - 5 {
        let mut short = WorkBudget::new(steps);
        refused(
            &storage,
            (Some(4), Some(20)),
            admitted,
            &mut short,
            FillReserveError::BudgetExhausted,
        );
        assert_eq!(short.remaining(), 0, "budget of {steps}");
    }

    {
        let attempt = begin(&storage, &k).unwrap();
        let serial = attempt.serial();
        let held = storage.live_pool().unwrap().lock().unwrap();
        let mut spent = budget();
        assert_eq!(
            attempt
                .reserve_storage(admitted, Some(4), Some(20), TRIES, &mut spent)
                .err(),
            Some(FillReserveError::Contended)
        );
        assert_eq!(spent.counters().coordination_attempts, 1);
        assert_eq!((spent.counters().visits, spent.counters().updates), (0, 0));
        drop(held);
        assert_eq!(partition(&storage), before);
        assert_eq!(records(&storage)[0], departed(serial, false));
        assert_eq!(service(&storage).released, 1);
    }
    {
        let attempt = begin(&storage, &k).unwrap();
        let serial = attempt.serial();
        let claim = next_claim(&storage, &k);
        let held = gate(&storage).lock().unwrap();
        let mut spent = budget();
        assert_eq!(
            attempt
                .reserve_storage(admitted, Some(4), Some(20), TRIES, &mut spent)
                .err(),
            Some(FillReserveError::Contended)
        );
        returned_claim(&storage, claim);
        assert_eq!(spent.counters().coordination_attempts, 1 + TRIES);
        assert_eq!(partition(&storage), before);
        drop(held);
        assert_eq!(records(&storage)[0], departed(serial, false));
        assert_eq!(service(&storage).released, 1);
    }

    // Eight holders fill every slot and every unit but the one-unit clean
    // reserve, which the check under the gate refuses before the slot take.
    let holders: Vec<_> = (0..8)
        .map(|_| storage.reserve(Some(1), Some(1), &mut budget()).unwrap())
        .collect();
    let full = partition(&storage);
    {
        let attempt = begin(&storage, &k).unwrap();
        let serial = attempt.serial();
        let mut spent = budget();
        assert_eq!(
            attempt
                .reserve_storage(admitted, Some(4), Some(20), TRIES, &mut spent)
                .err(),
            Some(FillReserveError::CleanReserve)
        );
        assert_eq!(spent.counters().visits, 0);
        assert_eq!(partition(&storage), full);
        assert_eq!(records(&storage)[0], departed(serial, false));
        assert_eq!(service(&storage).released, 1);
    }
    for holder in holders {
        storage
            .return_allocation(holder.release(), &mut budget())
            .unwrap();
    }
    assert_eq!(partition(&storage), before);

    let fills = [1];
    let index = crate::index::IndexConfig {
        fills: &fills,
        ..super::publish_tests::index_config(&[8], (1, 1), 1)
    };
    // Sixteen units for eight slots: with every slot held, a fill clears
    // the reserve and refuses `ObjectSlotsFull`.
    let roomy = super::publish_tests::storage_from(
        &super::StorageConfig {
            volume: crate::storage::test_volume(16 * crate::storage::IO_UNIT, 8),
            ..super::publish_tests::storage_config(8)
        },
        &index,
        TestPlatform::heap(super::publish_tests::PAGE),
    );
    roomy.platform.ticks(&[Some(1)]);
    let holders: Vec<_> = (0..8)
        .map(|_| roomy.reserve(Some(1), Some(1), &mut budget()).unwrap())
        .collect();
    let full = partition(&roomy);
    let attempt = begin(&roomy, &k).unwrap();
    let mut spent = budget();
    assert_eq!(
        attempt
            .reserve_storage(admit(&roomy, 4, 20), Some(4), Some(20), TRIES, &mut spent)
            .err(),
        Some(FillReserveError::ObjectSlotsFull)
    );
    assert_eq!(spent.counters().visits, 0);
    assert_eq!(partition(&roomy), full);
    drop(holders);

    // Five units for eight slots, holders at units 1 and 3: three free units
    // in separate runs clear the reserve for a two-unit layout, whose
    // extent claim refuses `PayloadFull` with slots to spare.
    let narrow = super::publish_tests::storage_from(
        &super::StorageConfig {
            body_cap: crate::storage::IO_UNIT,
            volume: crate::storage::test_volume(5 * crate::storage::IO_UNIT, 8),
            ..super::publish_tests::storage_config(8)
        },
        &index,
        TestPlatform::heap(super::publish_tests::PAGE),
    );
    let mut held: Vec<_> = (0..4)
        .map(|_| narrow.reserve(Some(1), Some(1), &mut budget()).unwrap())
        .collect();
    assert_eq!(held.remove(2).cancel(), Ok(()));
    assert_eq!(held.remove(0).cancel(), Ok(()));
    let drained = partition(&narrow);
    assert_eq!(drained.0.free, 3 * crate::storage::IO_UNIT);
    let large = admit(&narrow, 16, crate::storage::IO_UNIT);
    assert_eq!(charge(&narrow, 16, crate::storage::IO_UNIT), 2);
    let head = next_slot(&narrow, &key(1));
    // A refused claim restores the slot with its `Free` word, so its
    // incarnation does not move.
    let head_incarnation = slot_incarnation(&narrow, head);
    let mut spent = budget();
    refused(
        &narrow,
        (Some(16), Some(crate::storage::IO_UNIT)),
        large,
        &mut spent,
        FillReserveError::PayloadFull,
    );
    assert_eq!(slot_incarnation(&narrow, head), head_incarnation);
    assert_eq!(partition(&narrow), drained);

    let mut one_short = WorkBudget::new(1 + 1 + 1);
    refused(
        &narrow,
        (Some(16), Some(crate::storage::IO_UNIT)),
        large,
        &mut one_short,
        FillReserveError::BudgetExhausted,
    );
    assert_eq!(one_short.remaining(), 0);
    assert_eq!(one_short.counters().visits, 1);
    assert_eq!(slot_incarnation(&narrow, head), head_incarnation);
    assert_eq!(partition(&narrow), drained);

    let mut after_take = WorkBudget::new(1 + 1 + super::reserve::TAKE_BUNDLE);
    refused(
        &narrow,
        (Some(16), Some(crate::storage::IO_UNIT)),
        large,
        &mut after_take,
        FillReserveError::BudgetExhausted,
    );
    assert_eq!(after_take.remaining(), 0);
    assert_eq!(
        after_take.counters().visits,
        2,
        "premise: the refusal followed the take, whose visit and the give-back's are the two"
    );
    assert_eq!(slot_incarnation(&narrow, head), head_incarnation);
    assert_eq!(partition(&narrow), drained);
    drop(held);
}

/// A fill reservation that claimed its slot and extent and then finds its
/// shard gate poisoned refuses `Contended`, and one whose tries outlast its
/// budget at a busy shard gate refuses `BudgetExhausted`. The route's hash
/// and the slot's advanced incarnation show the refusal followed the claim.
/// Both refusals return the slot and the extent: the ledgers are as before,
/// the tables pass the conservation judge and the claimed slot is `Free`.
#[test]
fn a_fill_reservation_refused_at_its_shard_gate_returns_its_slot_and_extent() {
    let k = key(1);
    for poisoned in [true, false] {
        let storage = ready(2);
        let before = partition(&storage);
        let admitted = admit(&storage, 4, 20);
        let claim = next_claim(&storage, &k);
        let attempt = begin(&storage, &k).unwrap();
        let held = if poisoned {
            gate(&storage).try_lock().unwrap().poison();
            None
        } else {
            Some(gate(&storage).lock().unwrap())
        };
        let (tries, expected) = if poisoned {
            (TRIES, FillReserveError::Contended)
        } else {
            (usize::MAX, FillReserveError::BudgetExhausted)
        };
        let mut spent = budget();
        assert_eq!(
            attempt
                .reserve_storage(admitted, Some(4), Some(20), tries, &mut spent)
                .err(),
            Some(expected)
        );
        assert_eq!(spent.counters().hashes, 1, "premise: the route was hashed");
        returned_claim(&storage, claim);
        assert_eq!(partition(&storage), before);
        drop(held);
    }
}

thread_local! {
    /// Whether [`lose`] last raised the counter it moved.
    static RAISED: Cell<bool> = const { Cell::new(false) };
}

/// Moves `counter` one step off the value its next compare-exchange
/// expects, alternately up and down, and arms itself for the exchange after
/// that one, so every exchange of a bounded credit update on this thread
/// loses until [`stop_losing`] clears the hook.
fn lose(counter: &std::sync::atomic::AtomicUsize) {
    if RAISED.replace(!RAISED.get()) {
        counter.fetch_sub(1, Ordering::Relaxed);
    } else {
        counter.fetch_add(1, Ordering::Relaxed);
    }
    super::lease::INTERPOSE_BEFORE_CAS.with(|hook| hook.set(Some(lose)));
}

/// Clears [`lose`]'s hook and lowers `counter` again when its last move
/// raised it, so the counter holds the value no hook moved.
fn stop_losing(counter: &std::sync::atomic::AtomicUsize) {
    super::lease::INTERPOSE_BEFORE_CAS.with(|hook| hook.set(None));
    if RAISED.take() {
        counter.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A fill reservation whose every credit exchange loses to another writer
/// until its budget runs out refuses `Contended` after its slot and extent
/// claim, holding no credit, and returns the slot and the extent: the tables
/// pass the conservation judge and the claimed slot is `Free`.
#[test]
fn a_fill_reservation_whose_credit_exchanges_all_lose_returns_its_slot_and_extent() {
    let storage = ready(2);
    let before = partition(&storage);
    let k = key(1);
    let admitted = admit(&storage, 4, 20);
    let claim = next_claim(&storage, &k);
    let attempt = begin(&storage, &k).unwrap();
    INTERPOSE_BEFORE_REVALIDATION.with(|hook| {
        hook.set(Some(|_| {
            super::lease::INTERPOSE_BEFORE_CAS.with(|hook| hook.set(Some(lose)));
        }));
    });
    let mut spent = budget();
    let refused = attempt
        .reserve_storage(admitted, Some(4), Some(20), TRIES, &mut spent)
        .err();
    stop_losing(&storage.leases().reserved);
    assert_eq!(refused, Some(FillReserveError::Contended));
    assert_eq!(spent.remaining(), 0);
    let leases = storage.lease_report().unwrap();
    assert!(leases.cas_failed > 1, "{leases:?}");
    assert_eq!(leases.reserved, 0, "the refusal holds no credit");
    returned_claim(&storage, claim);
    assert_eq!(partition(&storage), before);
}

/// An odd sequence on the shard, which only a writer inside its bracket
/// leaves, is a malformed table under the shard gate: a fill reservation that
/// claimed its slot and extent refuses `Corrupt` at its place claim and
/// poisons the shard gate. The refusal returns the slot and the extent: the
/// tables pass the conservation judge and the claimed slot is `Free`.
#[test]
fn a_fill_reservation_over_an_odd_shard_sequence_refuses_corrupt_and_returns_its_slot() {
    let storage = ready(2);
    let before = partition(&storage);
    let k = key(1);
    let admitted = admit(&storage, 4, 20);
    let claim = next_claim(&storage, &k);
    let attempt = begin(&storage, &k).unwrap();
    let sequence = &super::attempt_tests::shard_control(&storage).sequence;
    sequence.store(sequence.load(Ordering::SeqCst) | 1, Ordering::SeqCst);
    assert_eq!(
        attempt
            .reserve_storage(admitted, Some(4), Some(20), TRIES, &mut budget())
            .err(),
        Some(FillReserveError::Corrupt)
    );
    assert!(gate(&storage).is_poisoned());
    returned_claim(&storage, claim);
    assert_eq!(partition(&storage), before);
}

#[test]
fn a_newer_attempt_on_the_same_key_survives_the_older_ones_refusal() {
    let storage = ready(3);
    let k = key(1);
    let before = partition(&storage);

    let first = begin(&storage, &k).unwrap();
    assert_eq!(first.serial(), 1);
    assert_eq!(invalidate(&storage, &k).unwrap().revoked, Some(1));
    let second = begin(&storage, &k).unwrap();
    assert_eq!(second.serial(), 2);
    assert_eq!(records(&storage), [revoked(1), live(2), Record::Free]);

    let admitted = admit(&storage, 4, 20);
    let claim = next_claim(&storage, &k);
    assert_eq!(
        first
            .reserve_storage(admitted, Some(4), Some(20), TRIES, &mut budget())
            .err(),
        Some(FillReserveError::Superseded)
    );
    returned_claim(&storage, claim);
    assert_eq!(partition(&storage), before);
    assert_eq!(
        records(&storage),
        [departed(1, true), live(2), Record::Free]
    );

    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let mut fill = second
        .reserve_storage(admitted, Some(4), Some(20), TRIES, &mut budget())
        .unwrap();
    assert_eq!(fill.serial(), 2);
    assert_eq!(
        fill.receive(&mut dev.volume, &[7; 20], &mut ample_io()),
        Ok(20)
    );
    assert_eq!(
        records(&storage),
        [departed(1, true), live(2), Record::Free]
    );
    fill.abort();
    assert_eq!(
        records(&storage),
        [departed(1, true), departed(2, false), Record::Free]
    );
    // Nothing was submitted, so the abort returned the extent at once.
    assert_eq!(service(&storage).released, 2);
    assert_eq!(partition(&storage), before);
}

/// A count planted on the claimed slot after its claim makes the refused
/// reservation's rollback refuse: the slot is abandoned in place with its
/// right still counted, the gate stays usable, and finalization blocks on
/// the held slot instead of poisoning.
#[test]
fn a_refused_attempts_reservation_abandons_a_slot_that_counts_a_right() {
    let mut storage = ready(2);
    let k = key(1);
    let attempt = begin(&storage, &k).unwrap();
    assert_eq!(invalidate(&storage, &k).unwrap().revoked, Some(1));
    let admitted = admit(&storage, 4, 20);
    let head = next_slot(&storage, &k);
    let live_pool = storage.live_pool().unwrap();
    // The claimed slot's count is zero, so `REF` gives it a count of one.
    plant_before_revalidation(live_pool, head, super::word::REF);
    let refused = attempt
        .reserve_storage(admitted, Some(4), Some(20), TRIES, &mut budget())
        .err();
    assert_eq!(refused, Some(FillReserveError::Superseded));
    assert_eq!(records(&storage), [departed(1, true), Record::Free]);
    assert!(live_pool.try_lock_quiet().is_ok());
    assert_eq!(refs(&storage, head), 1);
    assert_ne!(live_pool.flags(head) & ABANDONED, 0);
    assert_eq!(service(&storage).released, 1);
    assert!(matches!(
        finalize(&mut storage),
        Ok(Finalization::Blocked(_))
    ));
    assert_eq!(records(&storage), [Record::Free, Record::Free]);
}

/// A reserved bit planted on the claimed slot makes the refused
/// reservation's rollback panic under the pool gate: the record stays
/// occupied, the gate stays poisoned, and finalization returns `Poisoned`.
#[test]
fn a_panicking_rollback_keeps_the_refused_attempts_record_occupied() {
    let mut storage = ready(2);
    let k = key(1);
    let attempt = begin(&storage, &k).unwrap();
    assert_eq!(invalidate(&storage, &k).unwrap().revoked, Some(1));
    let admitted = admit(&storage, 4, 20);
    let head = next_slot(&storage, &k);
    let live_pool = storage.live_pool().unwrap();
    plant_before_revalidation(live_pool, head, RESERVED_BIT);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        attempt.reserve_storage(admitted, Some(4), Some(20), TRIES, &mut budget())
    }));
    assert!(outcome.is_err());
    drop(outcome);
    assert_eq!(records(&storage), [revoked(1), Record::Free]);
    assert!(live_pool.try_lock_quiet().is_err());
    assert_eq!(service(&storage).released, 0);
    assert_eq!(finalize(&mut storage), Err(FinalizeError::Poisoned));
    assert_eq!(records(&storage), [revoked(1), Record::Free]);
}

/// A reserved bit planted on the slot the claim takes next makes the
/// reservation's extent claim panic under the pool gate: the record stays
/// occupied, the gate stays poisoned, service releases nothing, and
/// finalization returns `Poisoned`.
#[test]
fn a_panicking_claim_keeps_the_attempts_record_occupied() {
    let mut storage = ready(2);
    let k = key(1);
    let attempt = begin(&storage, &k).unwrap();
    let admitted = admit(&storage, 4, 20);
    let head = next_slot(&storage, &k);
    let live_pool = storage.live_pool().unwrap();
    live_pool.edit_word(head, |word| word | RESERVED_BIT);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        attempt.reserve_storage(admitted, Some(4), Some(20), TRIES, &mut budget())
    }));
    assert!(outcome.is_err());
    drop(outcome);
    assert!(live_pool.try_lock_quiet().is_err());
    assert_eq!(records(&storage), [live(1), Record::Free]);
    assert_eq!(service(&storage).released, 0);
    assert_eq!(finalize(&mut storage), Err(FinalizeError::Poisoned));
    assert_eq!(records(&storage), [live(1), Record::Free]);
}

/// The hook runs once after the next reservation claims `head` and before
/// its record's revalidation, oring `bits` into `head`'s word.
fn plant_before_revalidation(live_pool: &Pool, head: usize, bits: u64) {
    thread_local! {
        static PLANTED: Cell<Option<(&'static std::sync::atomic::AtomicU64, u64)>> =
            const { Cell::new(None) };
    }
    // SAFETY: the word lives in the storage, which outlives the hook's one
    // run inside the reservation the caller makes next.
    let word: &'static std::sync::atomic::AtomicU64 =
        unsafe { &*std::ptr::from_ref(&live_pool.records()[head].ident) };
    PLANTED.with(|planted| planted.set(Some((word, bits))));
    INTERPOSE_BEFORE_REVALIDATION.with(|hook| {
        hook.set(Some(|_| {
            let (word, bits) = PLANTED.with(Cell::take).unwrap();
            word.fetch_or(bits, Ordering::Relaxed);
        }));
    });
}

#[test]
fn revocation_refuses_receives_and_keeps_the_owner_s_extent_and_record() {
    let storage = ready(2);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let k = key(1);
    let mut fill = reserve(&storage, &k, 4, 20).unwrap();
    assert_eq!(
        fill.receive(&mut dev.volume, &[1, 2], &mut ample_io()),
        Ok(2)
    );
    assert_eq!(invalidate(&storage, &k).unwrap().revoked, Some(1));
    assert_eq!(records(&storage), [revoked(1), Record::Free]);
    assert_eq!(
        fill.receive(&mut dev.volume, &[3, 4], &mut ample_io()),
        Err(ReceiveError::Revoked)
    );
    assert_eq!(fill.received(), 2);
    assert_eq!(partition(&storage).0.reserved, SMALL);
    let newer = begin(&storage, &k).unwrap();
    assert_eq!(newer.serial(), 2);
    fill.abort();
    assert_eq!(records(&storage), [departed(1, true), live(2)]);
    newer.abort();
}

#[test]
fn close_refuses_new_writes_and_every_reservation_cut_but_frees_nothing() {
    let storage = ready(3);
    let k = key(1);
    let before = partition(&storage);
    let admitted = admit(&storage, 4, 20);

    INTERPOSE_BEFORE_REVALIDATION.with(|hook| {
        hook.set(Some(|closed| {
            closed.store(true, Ordering::SeqCst);
        }));
    });
    let attempt = begin(&storage, &k).unwrap();
    let claim = next_claim(&storage, &k);
    assert_eq!(
        attempt
            .reserve_storage(admitted, Some(4), Some(20), TRIES, &mut budget())
            .err(),
        Some(FillReserveError::Closed)
    );
    returned_claim(&storage, claim);
    assert!(storage.is_closed());
    assert_eq!(partition(&storage), before);
    assert_eq!(records(&storage)[0], departed(1, false));
    assert_eq!(service(&storage).released, 1);

    let storage = ready(3);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let mut open = reserve(&storage, &key(2), 4, 20).unwrap();
    assert_eq!(
        open.receive(&mut dev.volume, &[1, 2], &mut ample_io()),
        Ok(2)
    );
    let attempt = begin(&storage, &k).unwrap();
    storage.close();
    let mut zero = WorkBudget::new(0);
    assert_eq!(
        attempt
            .reserve_storage(admitted, Some(4), Some(20), TRIES, &mut zero)
            .err(),
        Some(FillReserveError::Closed)
    );
    assert_eq!(zero.counters(), super::WorkCounters::default());
    assert_eq!(begin(&storage, &k).err(), Some(super::BeginError::Closed));

    assert_eq!(
        open.receive(&mut dev.volume, &[3], &mut ample_io()),
        Err(ReceiveError::Closed)
    );
    assert_eq!(
        open.receive(&mut dev.volume, &[], &mut ample_io()),
        Err(ReceiveError::Closed)
    );
    assert_eq!(open.received(), 2);
    assert_eq!(dev.volume.report().writes_submitted, 0);
    assert_eq!(partition(&storage).0.reserved, SMALL);
    // Nothing was submitted, so the abort returns the extent at once.
    open.abort();
    assert_eq!(
        (
            partition(&storage).0.reserved,
            partition(&storage).0.retired
        ),
        (0, 0)
    );
    assert_eq!(records(&storage)[0], departed(1, false));

    let storage = ready(3);
    let admitted = admit(&storage, 4, 20);
    let attempt = begin(&storage, &k).unwrap();
    INTERPOSE_AFTER_OPEN_READ.with(|hook| {
        hook.set(Some(|closed| {
            closed.store(true, Ordering::SeqCst);
        }));
    });
    let mut spent = budget();
    assert_eq!(
        attempt
            .reserve_storage(admitted, Some(4), Some(20), TRIES, &mut spent)
            .err(),
        Some(FillReserveError::Closed)
    );
    assert_eq!((spent.counters().visits, spent.counters().updates), (0, 0));
    assert_eq!(partition(&storage), before);
    assert_eq!(records(&storage)[0], departed(1, false));

    let storage = ready(3);
    let admitted = admit(&storage, 4, 20);
    let attempt = begin(&storage, &k).unwrap();
    storage.close();
    assert_eq!(
        attempt
            .reserve_storage(admitted, None, Some(20), TRIES, &mut zero)
            .err(),
        Some(FillReserveError::Layout(LayoutError::UnknownLength))
    );

    // The volume's own close refuses receives with admission still open.
    let storage = ready(3);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let mut open = reserve(&storage, &key(2), 4, 20).unwrap();
    assert_eq!(
        open.receive(&mut dev.volume, &[1, 2], &mut ample_io()),
        Ok(2)
    );
    let _ = dev.volume.close();
    assert!(!storage.is_closed());
    assert_eq!(
        open.receive(&mut dev.volume, &[3], &mut ample_io()),
        Err(ReceiveError::Closed)
    );
    assert_eq!(open.received(), 2);
    open.abort();
}

#[test]
fn abort_and_drop_dispose_of_the_block_before_the_record_departs() {
    let storage = ready(2);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let before = partition(&storage);

    let mut fill = reserve(&storage, &key(1), 4, 20).unwrap();
    let slot = fill.id().slot_index();
    let incarnation = slot_incarnation(&storage, slot);
    assert_eq!(fill.receive(&mut dev.volume, &[], &mut ample_io()), Ok(0));
    fill.abort();
    conserved_at(&storage, slot, FREE);
    assert_eq!(partition(&storage), before);
    assert_eq!(
        storage.slot_state(SlotIndex(slot)),
        Some((SlotState::Free, incarnation))
    );
    assert_eq!(records(&storage), [departed(1, false), Record::Free]);
    conserved_after_service(&storage, slot, FREE);
    assert_eq!(service(&storage).released, 1);

    // A written record: the drop, and the abort whose rollback is refused,
    // abandon the extent to service.
    for (serial, abort) in [(2, false), (3, true)] {
        let mut fill = reserve(&storage, &key(1), 4, 20).unwrap();
        let slot = fill.id().slot_index();
        dev.fill(&mut fill, &[1; SMALL]);
        if abort {
            fill.abort();
        } else {
            drop(fill);
        }
        conserved_at(&storage, slot, RETIRED);
        assert_eq!(partition(&storage).0.retired, SMALL, "abort {abort}");
        assert_eq!(
            records(&storage),
            [departed(serial, false), Record::Free],
            "abort {abort}"
        );
        conserved_after_service(&storage, slot, FREE);
        assert_eq!(service(&storage).released, 1, "abort {abort}");
        assert_eq!(partition(&storage), before, "abort {abort}");
    }

    // With the pool gate busy, the drop and the abort park the slot.
    for (serial, abort) in [(4, false), (5, true)] {
        let fill = reserve(&storage, &key(1), 4, 20).unwrap();
        let slot = fill.id().slot_index();
        let held = storage.live_pool().unwrap().lock().unwrap();
        if abort {
            fill.abort();
        } else {
            drop(fill);
        }
        assert_eq!(
            records(&storage),
            [departed(serial, false), Record::Free],
            "abort {abort}"
        );
        drop(held);
        conserved_at(&storage, slot, PARKED);
        conserved_after_service(&storage, slot, FREE);
        assert_eq!(service(&storage).released, 1, "abort {abort}");
        assert_eq!(partition(&storage), before, "abort {abort}");
    }
}

/// A slot that counts a right at disposal is abandoned in place, by a drop
/// or an abort alike: the record departs, the slot keeps its right and its
/// abandonment flag, the gate stays usable, and finalization blocks on the
/// held slot instead of poisoning.
#[test]
fn a_disposal_of_a_fill_whose_slot_counts_a_right_abandons_in_place() {
    for drops in [false, true] {
        let mut storage = ready(2);
        let fill = reserve(&storage, &key(1), 4, 20).unwrap();
        let slot = fill.id().slot_index();
        let live_pool = storage.live_pool().unwrap();
        live_pool.set_refs(slot, 1);
        if drops {
            drop(fill);
        } else {
            fill.abort();
        }
        assert_eq!(
            records(&storage),
            [departed(1, false), Record::Free],
            "drops {drops}"
        );
        assert!(live_pool.try_lock_quiet().is_ok(), "drops {drops}");
        assert_eq!(refs(&storage, slot), 1, "drops {drops}");
        assert_ne!(live_pool.flags(slot) & ABANDONED, 0, "drops {drops}");
        assert_eq!(service(&storage).released, 1, "drops {drops}");
        assert!(
            matches!(finalize(&mut storage), Ok(Finalization::Blocked(_))),
            "drops {drops}"
        );
    }
}

/// A reserved bit planted on the fill's slot makes the reservation's
/// rollback panic under the pool gate, leaving the record occupied and the
/// gate poisoned; finalization returns `Poisoned`.
#[test]
fn a_panicking_disposal_keeps_the_record_occupied_and_blocks_finalization() {
    for drops in [false, true] {
        let mut storage = ready(2);
        let fill = reserve(&storage, &key(1), 4, 20).unwrap();
        let slot = fill.id().slot_index();
        let live_pool = storage.live_pool().unwrap();
        live_pool.edit_word(slot, |word| word | RESERVED_BIT);
        probe::arm();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if drops {
                drop(fill);
            } else {
                fill.abort();
            }
        }));
        assert!(outcome.is_err(), "drops {drops}");
        drop(outcome);
        assert_eq!(
            probe::events()
                .events
                .contains(&probe::Event::Parked { slot }),
            drops,
            "drops {drops}: only the drop's unwinding reservation parks"
        );
        assert_eq!(records(&storage), [live(1), Record::Free], "drops {drops}");
        assert!(live_pool.try_lock_quiet().is_err(), "drops {drops}");
        assert_eq!(live_pool.flags(slot) & ABANDONED, 0, "drops {drops}");
        assert_eq!(
            finalize(&mut storage),
            Err(FinalizeError::Poisoned),
            "drops {drops}"
        );
        assert_eq!(records(&storage), [live(1), Record::Free], "drops {drops}");
    }
}

#[test]
fn a_panic_in_the_revalidation_leaves_the_block_charged_and_the_record_occupied() {
    let mut storage = ready(2);
    let attempt = begin(&storage, &key(1)).unwrap();
    let admitted = admit(&storage, 4, 20);
    INTERPOSE_BEFORE_REVALIDATION
        .with(|hook| hook.set(Some(|_| panic!("unwind before the revalidation"))));
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        attempt.reserve_storage(admitted, Some(4), Some(20), TRIES, &mut budget())
    }));
    assert!(outcome.is_err());
    drop(outcome);
    assert_eq!(records(&storage), [live(1), Record::Free]);
    assert_eq!(partition(&storage).0.reserved, SMALL);
    let blockers = blocked(&mut storage);
    assert_eq!(blockers.fills, 1);
    assert_eq!(blockers.held_slots, 1);
}

#[test]
fn a_forgotten_fill_blocks_finalization_and_stays_charged() {
    let mut storage = ready(2);
    let fill = reserve(&storage, &key(1), 4, 20).unwrap();
    std::mem::forget(fill);
    assert_eq!(partition(&storage).0.reserved, SMALL);
    let blockers = blocked(&mut storage);
    assert_eq!(blockers.fills, 1);
    assert_eq!(blockers.held_slots, 1);
    assert_eq!(partition(&storage).0.reserved, SMALL);
}

fn observe_takes(
    storage: &Storage<TestPlatform>,
    admitted: Admitted,
    exhausted: usize,
    steps: usize,
) -> (Result<usize, FillReserveError>, usize) {
    let head = plant_exhausted(storage, exhausted);
    let head_incarnation = slot_incarnation(storage, head);
    let quarantined = partition(storage).1.quarantined;
    let attempt = begin(storage, &key(1)).unwrap();
    let mut spent = WorkBudget::new(steps);
    let outcome = attempt
        .reserve_storage(admitted, Some(4), Some(20), TRIES, &mut spent)
        .map(|fill| {
            let slot = fill.id().slot_index();
            fill.abort();
            slot
        });
    let issued = usize::from(slot_incarnation(storage, head) > head_incarnation);
    let takes = partition(storage).1.quarantined - quarantined + issued;
    assert_eq!(service(storage).released, 1);
    drain_pool(storage);
    (outcome, takes)
}

#[test]
fn the_take_observer_equals_quarantine_delta_plus_the_issued_slot_at_every_budget() {
    let storage = ready(4);
    let admitted = admit(&storage, 4, 20);

    let head = plant_exhausted(&storage, 2);
    let head_incarnation = slot_incarnation(&storage, head);
    probe::arm();
    let mut whole = budget();
    let attempt = begin(&storage, &key(1)).unwrap();
    let after_begin = probe::counts();
    let fill = attempt
        .reserve_storage(admitted, Some(4), Some(20), TRIES, &mut whole)
        .unwrap();
    assert_eq!(fill.id().slot_index(), head);
    assert_eq!(partition(&storage).1.quarantined, 2);
    assert_eq!(slot_incarnation(&storage, head), head_incarnation + 1);
    // The takes, the record and the chain's one bucket, whose walk notes
    // no record load.
    assert_eq!(whole.counters().visits, 3 + 1 + 1 + WORK);
    assert_eq!(probe::counts().loads - after_begin.loads, 3 + 1);
    let bundle = budget().remaining() - whole.remaining();
    fill.abort();
    assert_eq!(service(&storage).released, 1);
    // With one exhausted slot ahead, the first funded budget is the spent
    // bundle less one take, the search's visits and the six steps after
    // the extent claim, plus the limit and the give-back. One step less refuses at
    // the extent search's preflight, after the quarantine, and restores the
    // taken slot.
    let bundle_one = bundle - 6 + search(&storage) - WORK;

    for steps in [0, 1] {
        let (outcome, takes) = observe_takes(&storage, admitted, 1, steps);
        assert_eq!(outcome, Err(FillReserveError::BudgetExhausted));
        assert_eq!(takes, 0);
    }
    let (outcome, takes) = observe_takes(&storage, admitted, 1, bundle_one - 1);
    assert_eq!(outcome, Err(FillReserveError::BudgetExhausted));
    assert_eq!(takes, 1);
    for steps in [bundle_one, usize::MAX] {
        let (outcome, takes) = observe_takes(&storage, admitted, 1, steps);
        assert!(outcome.is_ok());
        assert_eq!(takes, 2);
    }
    // The two refusals before any take left their planted slot exhausted
    // and free; the three funded claims quarantined one slot each.
    assert_eq!(partition(&storage).1.quarantined, 2 + 3);
}

#[test]
fn a_fill_hints_its_placement_window_and_its_bucket_before_revalidation() {
    const CLAIM_HINTS: usize = 5;
    const BUCKET_HINTS: usize = 3;
    thread_local! {
        static AT_REVALIDATION: Cell<usize> = const { Cell::new(0) };
    }
    fn arm() {
        INTERPOSE_BEFORE_REVALIDATION.with(|hook| {
            hook.set(Some(|_| {
                AT_REVALIDATION.with(|at| at.set(WRITE_HINTS.with(Cell::get)));
            }));
        });
    }
    let storage = ready(2);
    for (metadata, body) in [(4, 20), (16, 200)] {
        let before = WRITE_HINTS.with(Cell::get);
        arm();
        let fill = reserve(&storage, &key(1), metadata, body).unwrap();
        let before_revalidation = AT_REVALIDATION.with(Cell::get) - before;
        let hinted = WRITE_HINTS.with(Cell::get) - before;
        assert_eq!(
            before_revalidation,
            CLAIM_HINTS + BUCKET_HINTS + if RMW_WAITS_FOR_HINTS { 0 } else { CLAIM_HINTS }
        );
        assert_eq!(hinted, before_revalidation);
        fill.abort();
        assert_eq!(service(&storage).released, 1);
    }
    let fills = [2];
    let small = super::publish_tests::storage(
        3,
        &IndexConfig {
            fills: &fills,
            ..super::publish_tests::index_config(&[3], (1, 1), 1)
        },
    );
    let before = WRITE_HINTS.with(Cell::get);
    arm();
    let fill = reserve(&small, &key(1), 4, 20).unwrap();
    assert_eq!(AT_REVALIDATION.with(Cell::get) - before, BUCKET_HINTS);
    assert_eq!(WRITE_HINTS.with(Cell::get) - before, BUCKET_HINTS);
    fill.abort();
}

#[test]
fn reserve_receive_and_abort_allocate_nothing() {
    let storage = ready(2);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let k = key(1);
    let body = [3u8; 20];
    let allocations = crate::instrument::allocations();
    let attempt = begin(&storage, &k).unwrap();
    let admitted = admit(&storage, 4, 20);
    let mut fill = attempt
        .reserve_storage(admitted, Some(4), Some(20), TRIES, &mut budget())
        .unwrap();
    assert_eq!(
        fill.receive(&mut dev.volume, &[1, 2, 3, 4], &mut ample_io()),
        Ok(4)
    );
    assert_eq!(
        fill.receive(&mut dev.volume, &body[..10], &mut ample_io()),
        Ok(10)
    );
    assert_eq!(
        fill.receive(&mut dev.volume, &[1; 11], &mut ample_io()),
        Err(ReceiveError::LengthExceeded)
    );
    assert_eq!(
        fill.receive(&mut dev.volume, &body[10..], &mut ample_io()),
        Ok(10)
    );
    fill.abort();
    assert_eq!(service(&storage).released, 1);
    let refused = begin(&storage, &k).unwrap();
    assert_eq!(
        refused
            .reserve_storage(admitted, Some(4), Some(21), TRIES, &mut budget())
            .err(),
        Some(FillReserveError::Superseded)
    );
    assert_eq!(crate::instrument::allocations(), allocations);
}

/// An indexed storage of eight slots whose objects hold up to three
/// receive-write buffers of body, over a 128-unit volume, with `fills` fill
/// records and `object_rights` rights per object.
pub(super) fn wide(fills: usize, object_rights: usize) -> Storage<TestPlatform> {
    let fill_records = [fills];
    let index = IndexConfig {
        fills: &fill_records,
        ..index_config(&[8], (1, 1), 1)
    };
    let config = StorageConfig {
        body_cap: 3 * BUFFER as usize,
        metadata_cap: Some(64),
        object_rights,
        volume: crate::storage::test_volume(128 * IO_UNIT, 8),
        ..storage_config(8)
    };
    let storage = storage_from(&config, &index, TestPlatform::heap(PAGE));
    storage.platform.ticks(&[Some(1)]);
    storage
}

/// `len` bytes from `seed`: 32 generator words fill the first 256-byte
/// line. Each later line starts with the generator's next word and copies
/// its remaining bytes from the corresponding positions in the first line,
/// so a shorter payload is a prefix of a longer one.
pub(super) fn bytes(len: usize, seed: u64) -> Vec<u8> {
    const LINE: usize = 256;
    let mut rng = SplitMix64::new(seed);
    let mut first = [0; LINE];
    for word in first.as_chunks_mut::<8>().0 {
        *word = rng.next_u64().to_le_bytes();
    }
    let mut out = vec![0; len.next_multiple_of(LINE)];
    if let Some((head, rest)) = out.as_chunks_mut::<LINE>().0.split_first_mut() {
        *head = first;
        for line in rest {
            *line = first;
            line[..8].copy_from_slice(&rng.next_u64().to_le_bytes());
        }
    }
    out.truncate(len);
    out
}

#[test]
fn bytes_fill_the_first_line_eight_bytes_per_draw() {
    let mut rng = SplitMix64::new(7);
    let (first, second) = (rng.next_u64().to_le_bytes(), rng.next_u64().to_le_bytes());
    assert_eq!(bytes(13, 7), [&first[..], &second[..5]].concat());
    assert_eq!(bytes(8, 7), first);
    assert!(bytes(0, 7).is_empty());
}

#[test]
fn bytes_repeat_the_first_line_under_later_line_words_and_keep_prefixes() {
    let mut rng = SplitMix64::new(7);
    let words: Vec<_> = (0..33).map(|_| rng.next_u64().to_le_bytes()).collect();
    let payload = bytes(600, 7);
    assert_eq!(payload[..256], words[..32].concat());
    assert_eq!(payload[256..264], words[32]);
    assert_eq!(payload[264..512], payload[8..256]);
    assert_eq!(bytes(300, 7), payload[..300]);
}

/// The extent `fill` holds.
fn locator_of(
    storage: &Storage<TestPlatform>,
    fill: &WritableFill<'_, '_, TestPlatform>,
) -> ExtentLocator {
    storage.live_pool().unwrap().records()[fill.id().slot_index()].locator()
}

fn refs(storage: &Storage<TestPlatform>, slot: usize) -> usize {
    storage.live_pool().unwrap().refs(slot)
}

/// Executes each of `tokens` in turn and returns the unit-rounded span of
/// `locator`'s extent each one changed, as offsets from the extent's start:
/// the extent holds `0xEE` before, and every command writes a whole
/// segment whose first and last units hold a byte other than `0xEE`.
fn landed(
    storage: &Storage<TestPlatform>,
    control: &SimControl,
    locator: ExtentLocator,
    tokens: &[CommandToken],
) -> Vec<(usize, usize)> {
    let unit = IO_UNIT;
    tokens
        .iter()
        .map(|&token| {
            let before = extent(storage, control, locator);
            control.execute(token);
            let after = extent(storage, control, locator);
            let changed: Vec<usize> = (0..after.len())
                .filter(|&at| after[at] != before[at])
                .collect();
            let first = changed[0] / unit * unit;
            let end = (changed[changed.len() - 1] + 1).next_multiple_of(unit);
            (first, end - first)
        })
        .collect()
}

fn queue_full() -> SubmitRefusal {
    SubmitRefusal {
        reason: RefusalReason::QueueFull,
        code: None,
    }
}

/// Retires what the tests left and returns every extent: invalidation of
/// `keys`, grace and service, then the fill records.
fn retire_all(storage: &Storage<TestPlatform>, keys: &[Key]) {
    for key in keys {
        let _ = invalidate(storage, key);
    }
    for _ in 0..4 {
        let _ = storage.certify(&mut WorkBudget::new(1 << 12)).unwrap();
        storage.service(&mut WorkBudget::new(1 << 12)).unwrap();
    }
    service(storage);
}

/// A record built from independent metadata and body streams through
/// `receive` in pieces of several sizes, publishes, and reads back through
/// `Volume::read`, from the publisher's lease and from a lookup's, equal to
/// the bytes the test built, at and around unit, window and buffer
/// boundaries of the record.
#[test]
fn received_records_read_back_equal_at_unit_window_and_buffer_boundaries() {
    let storage = wide(2, 8);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let mut lengths = vec![0, 1, 13];
    for boundary in [
        IO_UNIT,
        2 * IO_UNIT,
        CHUNK as usize,
        BUFFER as usize,
        2 * BUFFER as usize,
    ] {
        for delta in [-1i64, 0, 1] {
            let record = (boundary as i64 + delta) as u64;
            // The payload whose header and payload end nearest `record`.
            let payload = (0..=record)
                .rev()
                .find(|&p| header_bytes(p, CHUNK) + p <= record)
                .unwrap();
            lengths.push(payload as usize);
        }
    }
    for (index, &len) in lengths.iter().enumerate() {
        for piece in [1, 997, 1 << 20] {
            if piece == 1 && len > 20_000 {
                continue;
            }
            let k = key(index as u8 + 1);
            let metadata = len.min(64).min(index * 5);
            let payload = bytes(len, (index * 7 + piece) as u64);
            let mut fill = reserve(&storage, &k, metadata, len - metadata).unwrap();
            super::volume_fixture::receive_all(
                &mut fill,
                &mut dev.volume,
                &dev.control,
                &payload,
                piece,
            );
            settle(&mut dev.volume, &dev.control);
            assert!(fill.is_ready(&dev.volume), "len {len} piece {piece}");
            let lease = fill
                .publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
                .unwrap();
            let delivered = super::volume_fixture::read_back(&mut dev.volume, &dev.control, &lease);
            assert_eq!(delivered.status, super::ReadStatus::Complete, "len {len}");
            assert_eq!(delivered.bytes, payload, "len {len} piece {piece}");
            let mut reader = storage.register().unwrap();
            let hit = lookup(&mut reader, &k, RETRIES).unwrap();
            assert_eq!(dev.read(&hit), payload, "len {len} piece {piece}");
            drop((hit, lease, reader));
            retire_all(&storage, &[k]);
        }
    }
}

/// The payload offset where the first chunk of a `len`-byte payload ends: the first record window less the header.
/// Later chunks end at that offset plus `n * CHUNK`, up to the payload's length. A segment holds two windows, so the chunk ends at odd `n` are segment ends.
fn first_chunk_end(len: usize) -> usize {
    (CHUNK - header_bytes(len as u64, CHUNK)) as usize
}

/// Streams `bytes` into `fill` through `receive`, ticking the device after each call until the fill took them all.
pub(super) fn receive_plain<'s, 'a>(
    dev: &mut Device<'s, 'a>,
    fill: &mut WritableFill<'s, 'a, TestPlatform>,
    bytes: &[u8],
) {
    let mut out = Vec::with_capacity(16);
    let mut taken = 0;
    for _ in 0..64 {
        if taken == bytes.len() {
            return;
        }
        match fill.receive(&mut dev.volume, &bytes[taken..], &mut ample_io()) {
            Ok(count) => taken += count,
            Err(ReceiveError::TableFull | ReceiveError::PoolExhausted) => {}
            Err(error) => panic!("receive refused {error:?}"),
        }
        step(&mut dev.volume, &dev.control, &mut out);
        out.clear();
    }
    panic!("the fill took {taken} of {} bytes", bytes.len());
}

/// Streams `payload` into `fill` and drives every write to its terminal.
/// The bytes from each `(start, end)` of `verified`, in order, go to `receive_verified` in one call under their crc32c, and every other byte goes through `receive`.
/// The device is idle at each verified call, so the volume has a buffer and a command for every segment the input completes and takes the input whole.
fn fill_verified<'s, 'a>(
    dev: &mut Device<'s, 'a>,
    fill: &mut WritableFill<'s, 'a, TestPlatform>,
    payload: &[u8],
    verified: &[(usize, usize)],
) {
    let crc = Crc32c::detect();
    let mut at = 0;
    for &(start, end) in verified {
        receive_plain(dev, fill, &payload[at..start]);
        settle(&mut dev.volume, &dev.control);
        let input = &payload[start..end];
        assert_eq!(
            fill.receive_verified(&mut dev.volume, input, crc.checksum(input), &mut ample_io()),
            Ok(input.len()),
            "the volume takes the input at {start}..{end} whole"
        );
        at = end;
    }
    super::volume_fixture::receive_all(
        fill,
        &mut dev.volume,
        &dev.control,
        &payload[at..],
        BUFFER as usize,
    );
    settle(&mut dev.volume, &dev.control);
}

/// The offset of the first byte at which the extent `fill` holds on the device differs from the record the header encoder builds for `payload`, a body with no metadata, or `None` when the device holds exactly that record.
/// The encoder computes each chunk's crc32c over that chunk's bytes alone.
fn first_difference_from_the_encoded_record(
    storage: &Storage<TestPlatform>,
    dev: &Device<'_, '_>,
    fill: &WritableFill<'_, '_, TestPlatform>,
    key: Key,
    payload: &[u8],
) -> Option<usize> {
    let built = record_bytes(storage, key, fill.id(), SESSION, &[], payload);
    let stored = extent(storage, &dev.control, locator_of(storage, fill));
    assert_eq!(stored.len(), built.len());
    stored
        .iter()
        .zip(&built)
        .position(|(stored, built)| stored != built)
}

/// A record whose bytes arrived through `receive_verified` is, byte for byte, the record the header encoder builds from the payload, so every chunk checksum the fill derived from an input's crc32c is the crc32c of that chunk's bytes; the published record then reads back whole.
/// Each row's inputs meet the record's chunk ends in another way: inside one chunk, with the longer, the shorter or an equal part before a chunk end, ending at one, covering one whole chunk, across a segment's end, across several chunk ends, as the whole payload, and as inputs that follow one another.
#[test]
fn verified_inputs_store_the_record_the_encoder_builds_wherever_chunk_ends_fall() {
    let storage = wide(2, 8);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let len = 2 * BUFFER as usize + 6000;
    let (cut, chunk) = (first_chunk_end(len), CHUNK as usize);
    let rows = [
        ("inside one chunk", vec![(cut + 1000, cut + 5096)]),
        (
            "the longer part before a chunk end",
            vec![(cut - 6000, cut + 2000)],
        ),
        (
            "the shorter part before a chunk end",
            vec![(cut - 2000, cut + 6000)],
        ),
        (
            "equal parts around a chunk end",
            vec![(cut - 4096, cut + 4096)],
        ),
        ("ending at a chunk end", vec![(cut - 4096, cut)]),
        ("one whole chunk", vec![(cut, cut + chunk)]),
        (
            "the longer part before a segment end",
            vec![(cut + chunk - 6000, cut + chunk + 2000)],
        ),
        (
            "the shorter part before a segment end",
            vec![(cut + chunk - 2000, cut + chunk + 6000)],
        ),
        (
            "across three chunk ends",
            vec![(cut - 1000, cut + 2 * chunk + 3000)],
        ),
        ("the whole payload", vec![(0, len)]),
        (
            "inputs that follow one another",
            vec![(0, chunk), (chunk, 2 * chunk), (2 * chunk, 3 * chunk)],
        ),
    ];
    for (n, (row, verified)) in rows.iter().enumerate() {
        let k = key(n as u8 + 1);
        let payload = bytes(len, 40 + n as u64);
        let mut fill = reserve(&storage, &k, 0, len).unwrap();
        fill_verified(&mut dev, &mut fill, &payload, verified);
        assert_eq!(
            first_difference_from_the_encoded_record(&storage, &dev, &fill, k, &payload),
            None,
            "{row}"
        );
        let lease = fill
            .publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
            .unwrap();
        assert!(dev.read(&lease) == payload, "{row}");
        drop(lease);
        retire_all(&storage, &[k]);
    }
}

/// A submit the device refuses at a segment's end ends a verified input there: the call returns the bytes before the segment end, and the bytes after it, which the input's crc32c also covers, then arrive through `receive`.
/// The device still holds the record the header encoder builds, both when the bytes the call took are the longer part of the input and when they are the shorter.
#[test]
fn a_verified_input_ended_by_a_refused_submit_stores_the_record_the_encoder_builds() {
    let storage = wide(2, 8);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let crc = Crc32c::detect();
    let len = 2 * BUFFER as usize + 6000;
    // The second segment's end: the first that submits a command as the fill reaches it.
    let end = first_chunk_end(len) + 3 * CHUNK as usize;
    for (n, (before, after)) in [(4000, 2000), (2000, 4000)].into_iter().enumerate() {
        let k = key(n as u8 + 1);
        let payload = bytes(len, 60 + n as u64);
        let mut fill = reserve(&storage, &k, 0, len).unwrap();
        receive_plain(&mut dev, &mut fill, &payload[..end - before]);
        settle(&mut dev.volume, &dev.control);
        dev.control.refuse_next(queue_full());
        let input = &payload[end - before..end + after];
        assert_eq!(
            fill.receive_verified(&mut dev.volume, input, crc.checksum(input), &mut ample_io()),
            Ok(before),
            "the refused submit ends the call at the segment end"
        );
        super::volume_fixture::receive_all(
            &mut fill,
            &mut dev.volume,
            &dev.control,
            &payload[end..],
            BUFFER as usize,
        );
        settle(&mut dev.volume, &dev.control);
        assert_eq!(
            first_difference_from_the_encoded_record(&storage, &dev, &fill, k, &payload),
            None,
            "{before} bytes taken, {after} left"
        );
        drop(
            fill.publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
                .unwrap(),
        );
        retire_all(&storage, &[k]);
    }
}

/// A verified input under the crc32c of other bytes never reads back as the bytes the fill took.
/// The input's shorter part ends the first chunk and is folded as it is copied; its longer part begins the second chunk, whose checksum the fill derives from the input's.
/// A debug build stops at the fill's assertion, which compares that derived part with a fold of its bytes.
/// A release build stores the record, and a read hands off the first chunk and refuses the second.
#[test]
fn a_verified_input_under_another_checksum_is_refused_by_the_assertion_or_by_the_read() {
    let storage = wide(2, 8);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let len = 2 * BUFFER as usize + 6000;
    let cut = first_chunk_end(len);
    let payload = bytes(len, 70);
    let mut fill = reserve(&storage, &key(1), 0, len).unwrap();
    receive_plain(&mut dev, &mut fill, &payload[..cut - 2000]);
    settle(&mut dev.volume, &dev.control);
    let input = &payload[cut - 2000..cut + 6000];
    let other = Crc32c::detect().checksum(input) ^ 1;
    let read = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_eq!(
            fill.receive_verified(&mut dev.volume, input, other, &mut ample_io()),
            Ok(input.len())
        );
        super::volume_fixture::receive_all(
            &mut fill,
            &mut dev.volume,
            &dev.control,
            &payload[cut + 6000..],
            BUFFER as usize,
        );
        settle(&mut dev.volume, &dev.control);
        let lease = fill
            .publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
            .unwrap();
        super::volume_fixture::read_back(&mut dev.volume, &dev.control, &lease)
    }));
    assert_eq!(
        read.is_err(),
        cfg!(debug_assertions),
        "a debug build stops the call and a release build stores the record"
    );
    match read {
        Err(panic) => {
            let message = panic.downcast_ref::<String>().expect("a panic message");
            assert!(
                message.contains("a checksum of other bytes than the input's"),
                "{message}"
            );
        }
        Ok(delivered) => {
            assert_eq!(
                delivered.status,
                super::ReadStatus::ChunkMismatch { index: 1 }
            );
            assert!(delivered.bytes == payload[..cut], "the first chunk alone");
        }
    }
}

/// A-3: a record whose units fit one buffer and one maximum transfer is
/// written by exactly one command, counted by the volume and the device; a
/// record of three segments is written by three commands that tile its
/// extent once from its start, and the one holding the header comes last.
#[test]
fn one_buffer_is_one_write_and_a_longer_record_submits_its_header_last() {
    let storage = wide(2, 8);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let mut fill = reserve(&storage, &key(1), 4, 100).unwrap();
    let before = (
        dev.volume.report().writes_submitted,
        super::volume_fixture::writes(&dev.control),
    );
    assert_eq!(
        fill.receive(&mut dev.volume, &bytes(104, 1), &mut ample_io()),
        Ok(104)
    );
    assert_eq!(dev.volume.report().writes_submitted, before.0 + 1);
    assert_eq!(super::volume_fixture::writes(&dev.control), before.1 + 1);
    settle(&mut dev.volume, &dev.control);
    drop(
        fill.publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
            .unwrap(),
    );

    let len = 2 * BUFFER as usize + 1000;
    let payload = bytes(len, 2);
    let mut fill = reserve(&storage, &key(2), 16, len - 16).unwrap();
    let locator = locator_of(&storage, &fill);
    assert_eq!(locator.len_units(), 9);
    place(&storage, &dev.control, locator, &vec![0xEE; 9 * IO_UNIT]);
    let tokens = write_tokens(&dev.control).len();
    for piece in payload.chunks(5000) {
        assert_eq!(
            fill.receive(&mut dev.volume, piece, &mut ample_io()),
            Ok(piece.len())
        );
    }
    let submitted = &write_tokens(&dev.control)[tokens..];
    assert_eq!(submitted.len(), 3);
    let buffer = BUFFER as usize;
    assert_eq!(
        landed(&storage, &dev.control, locator, submitted),
        [
            (buffer, buffer),
            (2 * buffer, 9 * IO_UNIT - 2 * buffer),
            (0, buffer)
        ]
    );
    settle(&mut dev.volume, &dev.control);
    let lease = fill
        .publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
        .unwrap();
    assert_eq!(dev.read(&lease), payload);
}

/// `s4n-header-after-payload`, `s4n-command-split-and-staging`: under
/// one-byte receives each later segment submits in the call that fills it,
/// so the fill holds at most its first buffer and the one being filled; the
/// command holding the header is submitted only by the call that takes the
/// last payload byte, after every other segment, and the header it carries
/// verifies with a checksum for every chunk.
#[test]
fn the_header_submits_after_the_last_payload_byte_under_fragmented_receives() {
    let storage = wide(2, 8);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let len = 2 * BUFFER as usize + 3000;
    let payload = bytes(len, 3);
    let mut fill = reserve(&storage, &key(1), 7, len - 7).unwrap();
    let locator = locator_of(&storage, &fill);
    place(
        &storage,
        &dev.control,
        locator,
        &vec![0xEE; locator.len_units() as usize * IO_UNIT],
    );
    let tokens = write_tokens(&dev.control).len();
    for (at, byte) in payload.iter().enumerate() {
        assert_eq!(
            fill.receive(&mut dev.volume, std::slice::from_ref(byte), &mut ample_io()),
            Ok(1)
        );
        let submitted = write_tokens(&dev.control).len() - tokens;
        let expected = if at + 1 == len {
            3
        } else {
            usize::from(at + 1 + header_bytes(len as u64, CHUNK) as usize >= 2 * BUFFER as usize)
        };
        assert_eq!(submitted, expected, "byte {at}");
    }
    let submitted = &write_tokens(&dev.control)[tokens..];
    assert_eq!(submitted.len(), 3);
    let spans = landed(&storage, &dev.control, locator, submitted);
    assert_eq!(spans[2].0, 0, "the header's command comes last");
    let bytes_on_device = extent(&storage, &dev.control, locator);
    let expected = ExpectedHeader {
        position: ExtentPosition::FIRST,
        identity: RecordIdentity {
            key: key(1),
            allocation: fill.id().record_tag(),
            session: SESSION,
            version: 0,
        },
        reader: SESSION,
        len_units: locator.len_units(),
        lengths: None,
    };
    let crc = Crc32c::detect();
    let verified = verify_header(crc, &storage.record, &bytes_on_device, &expected).unwrap();
    let layout = storage.record.layout(7, (len - 7) as u32);
    let header = layout.header_bytes();
    for index in 0..layout.chunk_count() {
        let range = layout.chunk(index).unwrap();
        let chunk = &bytes_on_device[header + range.start as usize..header + range.end as usize];
        assert_eq!(verified.verify_chunk(crc, index, chunk), Ok(()));
    }
    settle(&mut dev.volume, &dev.control);
    fill.abort();
}

/// With a maximum transfer below the buffer length, every command carries at
/// most one maximum transfer in whole units, the commands tile the record
/// once, and the header's comes last; a record that fits one buffer but not
/// one transfer takes two commands.
#[test]
fn commands_tile_the_record_within_a_max_transfer_below_the_buffer_length() {
    let storage = wide(2, 8);
    let buffers = arena();
    let (volume, control) = attach_with(&storage, &buffers, 8192);
    let mut dev = Device { volume, control };
    for (len, commands) in [(12_000usize, 2usize), (30_000, 4)] {
        let payload = bytes(len, len as u64);
        let k = key(len as u8);
        let mut fill = reserve(&storage, &k, 0, len).unwrap();
        let locator = locator_of(&storage, &fill);
        let extent_len = locator.len_units() as usize * IO_UNIT;
        place(&storage, &dev.control, locator, &vec![0xEE; extent_len]);
        let tokens = write_tokens(&dev.control).len();
        assert_eq!(
            fill.receive(&mut dev.volume, &payload, &mut ample_io()),
            Ok(len)
        );
        let submitted = write_tokens(&dev.control)[tokens..].to_vec();
        assert_eq!(submitted.len(), commands, "len {len}");
        let mut spans = landed(&storage, &dev.control, locator, &submitted);
        assert_eq!(spans.last().unwrap().0, 0, "len {len}");
        assert!(
            spans
                .iter()
                .all(|&(_, span)| span <= 8192 && span.is_multiple_of(IO_UNIT))
        );
        spans.sort_unstable();
        let mut next = 0;
        for (start, span) in spans {
            assert_eq!(start, next, "len {len}");
            next += span;
        }
        assert_eq!(next, extent_len, "len {len}");
        settle(&mut dev.volume, &dev.control);
        let lease = fill
            .publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
            .unwrap();
        assert_eq!(dev.read(&lease), payload);
    }
}

/// `s4n-refused-owns-nothing` (receive part): a submit the table refuses
/// leaves its buffer staged, copies nothing past its segment, and leaves the
/// set's submitted units, the table and the slot's count as they were; the
/// next call retries it first, and a refusal there takes no byte.
#[test]
fn a_refused_submit_stays_staged_and_copies_nothing_further() {
    let storage = wide(2, 8);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let len = 2 * BUFFER as usize;
    let payload = bytes(len, 5);
    let mut fill = reserve(&storage, &key(1), 0, len).unwrap();
    let slot = fill.id().slot_index();
    let first = BUFFER as usize - header_bytes(len as u64, CHUNK) as usize;
    assert_eq!(
        fill.receive(&mut dev.volume, &payload[..first], &mut ample_io()),
        Ok(first)
    );
    let table = dev.volume.table_report();
    dev.control.refuse_next(queue_full());
    // Segment 1 fills and its submit is refused: the call stops there.
    assert_eq!(
        fill.receive(&mut dev.volume, &payload[first..], &mut ample_io()),
        Ok(BUFFER as usize)
    );
    let taken = first + BUFFER as usize;
    assert_eq!(fill.received(), taken as u64);
    assert_eq!(fill.progress(&dev.volume).submitted_units, 0);
    assert_eq!(dev.volume.table_report(), table);
    assert_eq!(dev.volume.report().writes_submitted, 0);
    assert_eq!(refs(&storage, slot), 0);
    // The retry's prepaid command remains spent after refusal.
    dev.control.refuse_next(queue_full());
    let mut turn = ample_io();
    assert_eq!(
        fill.receive(&mut dev.volume, &payload[taken..], &mut turn),
        Err(ReceiveError::TableFull)
    );
    assert_eq!(
        (turn.operations_used(), turn.bytes_used()),
        (1, BUFFER as usize)
    );
    assert_eq!(fill.progress(&dev.volume).outstanding_units, 0);
    assert_eq!(fill.received(), taken as u64);
    assert_eq!(refs(&storage, slot), 0);
    // Then it submits, and the rest follows.
    assert_eq!(
        fill.receive(&mut dev.volume, &payload[taken..], &mut ample_io()),
        Ok(len - taken)
    );
    assert_eq!(refs(&storage, slot), 1);
    settle(&mut dev.volume, &dev.control);
    assert_eq!(refs(&storage, slot), 0);
    let lease = fill
        .publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
        .unwrap();
    assert_eq!(dev.read(&lease), payload);
}

/// `s4n-ready-gate`, `s4n-completed-on-success-only`: publication
/// refuses `Incomplete`, with the index and the shard's sequence unchanged,
/// while the header's command is held, after its completion is dropped, and
/// after a short, torn or failed payload command.
#[test]
fn publication_refuses_incomplete_while_a_write_is_outstanding_or_failed() {
    let storage = wide(8, 8);
    let buffers = arena_with(4, 9);
    let mut dev = Device::new(&storage, &buffers);
    let unchanged = |storage: &Storage<TestPlatform>, k: &Key, sequence: u64| {
        assert!(candidates(storage, k).is_empty());
        assert_eq!(report(storage, 0).visible, 0);
        assert_eq!(report(storage, 0).sequence, sequence);
    };
    // The header's command held.
    let mut fill = reserve(&storage, &key(1), 4, 100).unwrap();
    assert_eq!(
        fill.receive(&mut dev.volume, &bytes(104, 1), &mut ample_io()),
        Ok(104)
    );
    let header = *write_tokens(&dev.control).last().unwrap();
    dev.control.hold(header);
    let mut out = Vec::with_capacity(4);
    step(&mut dev.volume, &dev.control, &mut out);
    let progress = fill.progress(&dev.volume);
    assert_eq!((progress.submitted_units, progress.completed_units), (1, 0));
    assert_eq!(progress.outstanding_units, 1, "the held header counts");
    assert!(!fill.is_ready(&dev.volume));
    let sequence = report(&storage, 0).sequence;
    assert_eq!(
        fill.publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
            .err(),
        Some(FillPublishError::Incomplete)
    );
    unchanged(&storage, &key(1), sequence);
    dev.control.release(header);
    settle(&mut dev.volume, &dev.control);

    // The header's completion dropped: the command never reaches a terminal.
    let mut fill = reserve(&storage, &key(2), 4, 100).unwrap();
    assert_eq!(
        fill.receive(&mut dev.volume, &bytes(104, 2), &mut ample_io()),
        Ok(104)
    );
    let header = *write_tokens(&dev.control).last().unwrap();
    dev.control.fault(header, Fault::DropCompletion);
    for _ in 0..4 {
        step(&mut dev.volume, &dev.control, &mut out);
    }
    assert!(!fill.is_ready(&dev.volume));
    assert_eq!(
        fill.publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
            .err(),
        Some(FillPublishError::Incomplete)
    );
    unchanged(&storage, &key(2), sequence);

    // A payload command that ends short, torn or failed fails the set.
    let len = 2 * BUFFER as usize + 1000;
    for (n, fault) in [
        Fault::Short { units: 1 },
        Fault::TornWrite { sectors: 1 },
        Fault::Status(DeviceStatus::Kernel(-5)),
    ]
    .into_iter()
    .enumerate()
    {
        let k = key(3 + n as u8);
        let mut fill = reserve(&storage, &k, 0, len).unwrap();
        let tokens = write_tokens(&dev.control).len();
        assert_eq!(
            fill.receive(&mut dev.volume, &bytes(len, 3), &mut ample_io()),
            Ok(len)
        );
        dev.control.fault(write_tokens(&dev.control)[tokens], fault);
        settle(&mut dev.volume, &dev.control);
        let slot = fill.id().slot_index();
        assert_eq!(
            refs(&storage, slot),
            0,
            "{fault:?}: the right ends with the set's last terminal"
        );
        let progress = fill.progress(&dev.volume);
        assert!(progress.failed, "{fault:?}");
        assert_eq!(progress.outstanding_units, 0, "{fault:?}");
        assert_eq!(progress.submitted_units, progress.len_units, "{fault:?}");
        // The faulted command's four units never count as complete.
        assert_eq!(
            progress.completed_units,
            progress.len_units - 4,
            "{fault:?}"
        );
        assert!(!fill.is_ready(&dev.volume));
        assert_eq!(
            fill.publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
                .err(),
            Some(FillPublishError::Incomplete),
            "{fault:?}"
        );
        unchanged(&storage, &k, sequence);
    }
}

/// `s4n-padding-zeroed`: with the receive-write buffers reused from an
/// earlier fill of `0xFF` bytes and the device holding `0xEE` where the
/// record goes, every byte of the extent outside the header and the payload
/// reads zero: the device holds exactly the record the test builds, for a
/// record of one segment and one of three.
#[test]
fn every_byte_outside_the_header_and_payload_reads_zero_on_the_device() {
    let storage = wide(4, 8);
    let buffers = arena_with(4, 5);
    let mut dev = Device::new(&storage, &buffers);
    let dirty = vec![0xFF; 3 * BUFFER as usize];
    let mut stale = reserve(&storage, &key(9), 64, dirty.len() - 64).unwrap();
    dev.fill(&mut stale, &dirty);
    drop(stale);
    for (n, (metadata, body)) in [(5usize, 99usize), (64, 2 * BUFFER as usize + 777)]
        .into_iter()
        .enumerate()
    {
        let k = key(n as u8 + 1);
        let meta = bytes(metadata, 11 + n as u64);
        let body = bytes(body, 12 + n as u64);
        let mut fill = reserve(&storage, &k, meta.len(), body.len()).unwrap();
        let locator = locator_of(&storage, &fill);
        place(
            &storage,
            &dev.control,
            locator,
            &vec![0xEE; locator.len_units() as usize * IO_UNIT],
        );
        let payload: Vec<u8> = meta.iter().chain(&body).copied().collect();
        dev.fill(&mut fill, &payload);
        let expected = record_bytes(&storage, k, fill.id(), SESSION, &meta, &body);
        assert_eq!(
            extent(&storage, &dev.control, locator),
            expected,
            "metadata {metadata}"
        );
        fill.abort();
    }
}

/// `s4n-abort-holds-extent`, `s4n-right-before-first-submit`,
/// `s4n-right-released-last-terminal`, D8: the fill's right is counted from
/// its first submit to its last terminal. An owner that ends with its write
/// held, whether the drop takes the pool gate or parks behind it, leaves
/// the abandonment flag set and the count at one; service holds the slot,
/// `Filling`-parked or retired, and no reservation receives its extent,
/// until the write's terminal releases the right and service returns it.
#[test]
fn an_abandoned_fill_with_a_write_in_flight_is_held_until_its_last_terminal() {
    for parked in [false, true] {
        let storage = wide(4, 8);
        let buffers = arena_with(4, 5);
        let mut dev = Device::new(&storage, &buffers);
        // Three commands; the two payload ones complete while the header's
        // is held, and the right stays counted through them.
        let len = 2 * BUFFER as usize + 100;
        let mut fill = reserve(&storage, &key(1), 4, len - 4).unwrap();
        let slot = fill.id().slot_index();
        let locator = locator_of(&storage, &fill);
        assert_eq!(refs(&storage, slot), 0);
        assert_eq!(
            fill.receive(&mut dev.volume, &bytes(len, 1), &mut ample_io()),
            Ok(len)
        );
        assert_eq!(
            refs(&storage, slot),
            1,
            "the right precedes the first submit"
        );
        let header = *write_tokens(&dev.control).last().unwrap();
        dev.control.hold(header);
        let mut out = Vec::with_capacity(4);
        turn_until(|| {
            step(&mut dev.volume, &dev.control, &mut out);
            fill.progress(&dev.volume).completed_units > 0
        });
        assert_eq!(
            fill.progress(&dev.volume).completed_units,
            locator.len_units() - 4
        );
        assert_eq!(refs(&storage, slot), 1, "held to the last terminal");
        let held = parked.then(|| storage.live_pool().unwrap().lock().unwrap());
        fill.abort();
        drop(held);
        let live = storage.live_pool().unwrap();
        assert_ne!(live.flags(slot) & ABANDONED, 0);
        let state = if parked {
            SlotState::Filling
        } else {
            SlotState::Retired
        };
        assert_eq!(storage.slot_state(SlotIndex(slot)).unwrap().0, state);
        let pass = storage.service(&mut WorkBudget::new(1 << 12)).unwrap();
        assert_eq!((pass.serviced, pass.held), (0, 1), "parked {parked}");
        assert_eq!(refs(&storage, slot), 1);
        // No reservation receives the held extent while its write is in flight.
        let mut others = Vec::new();
        while let Ok(other) = storage.reserve(Some(0), Some(IO_UNIT), &mut budget()) {
            let other_locator = other.locator();
            let overlap = other_locator.start_unit()
                < locator.start_unit() + u64::from(locator.len_units())
                && locator.start_unit()
                    < other_locator.start_unit() + u64::from(other_locator.len_units());
            assert!(
                !overlap,
                "parked {parked}: a reservation reused the extent under a write"
            );
            others.push(other);
        }
        drop(others);
        assert_eq!(dev.volume.write_sets(), 1, "the set outlives its fill");
        dev.control.release(header);
        settle(&mut dev.volume, &dev.control);
        assert_eq!(refs(&storage, slot), 0, "released at the last terminal");
        assert_eq!(dev.volume.write_sets(), 0, "freed at the last terminal");
        storage.service(&mut WorkBudget::new(1 << 12)).unwrap();
        assert_eq!(
            storage.slot_state(SlotIndex(slot)).unwrap().0,
            SlotState::Free
        );
    }
}

/// A fill's first write submit installs the slot's right before the driver
/// call, so a submit that unwinds leaves the right counted with nothing
/// marked written. Aborting or dropping that fill abandons the extent in
/// place: the slot keeps its right and its `ABANDONED` flag, the pool gate
/// stays usable, and the proven stop fails the unwound set, releases the
/// right and frees the slot.
#[test]
fn a_fill_whose_first_submit_unwound_is_abandoned_until_the_proven_stop() {
    for drops in [false, true] {
        let mut storage = wide(2, 8);
        let buffers = arena();
        let mut dev = Device::new(&storage, &buffers);
        let mut fill = reserve(&storage, &key(1), 4, 100).unwrap();
        let slot = fill.id().slot_index();
        dev.control.unwind_next(Some(Unwind::Submit));
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fill.receive(&mut dev.volume, &bytes(104, 1), &mut ample_io())
        }))
        .is_err();
        dev.control.unwind_next(None);
        assert!(unwound, "drops {drops}");
        assert!(dev.volume.is_lost(), "drops {drops}");
        let progress = fill.progress(&dev.volume);
        assert_eq!(
            (progress.submitted_units, progress.outstanding_commands),
            (0, 1),
            "drops {drops}: the unwound submit stays counted"
        );
        assert_eq!(refs(&storage, slot), 1, "drops {drops}");
        if drops {
            drop(fill);
        } else {
            fill.abort();
        }
        let live_pool = storage.live_pool().unwrap();
        assert!(
            live_pool.try_lock_quiet().is_ok(),
            "drops {drops}: the gate stays usable"
        );
        assert_eq!(
            refs(&storage, slot),
            1,
            "drops {drops}: the right outlives the fill"
        );
        assert_ne!(live_pool.flags(slot) & ABANDONED, 0, "drops {drops}");
        assert_eq!(
            records(&storage),
            [departed(1, false), Record::Free],
            "drops {drops}"
        );
        dev.control.set_quiesce(QuiesceMode::Reset);
        let _ = dev.volume.close();
        settle(&mut dev.volume, &dev.control);
        assert_eq!(
            refs(&storage, slot),
            0,
            "drops {drops}: released at the proven stop"
        );
        assert_eq!(dev.volume.write_sets(), 0, "drops {drops}");
        storage.service(&mut WorkBudget::new(1 << 12)).unwrap();
        assert_eq!(
            storage.slot_state(SlotIndex(slot)).unwrap().0,
            SlotState::Free,
            "drops {drops}"
        );
        drop(dev);
        assert_eq!(service(&storage).released, 1, "drops {drops}");
        let finalized = finalize(&mut storage);
        assert!(
            matches!(
                finalized,
                Ok(Finalization::Drained | Finalization::Closing(_))
            ),
            "drops {drops}: {finalized:?}"
        );
    }
}

/// A fill dropped by the unwind of its own frame, after its first write
/// submit unwound, abandons its extent in place during that unwind, so the
/// unwind reaches its catch and the process keeps running. The case runs in
/// a fresh child: a disposal that panicked while the frame unwinds would
/// abort the process.
#[test]
fn a_fill_dropped_by_its_frame_s_unwind_abandons_without_aborting() {
    exact_child::run(
        "storage::writable_tests::a_fill_dropped_by_its_frame_s_unwind_abandons_without_aborting",
        Duration::from_secs(60),
        || {
            let storage = wide(2, 8);
            let buffers = arena();
            let mut dev = Device::new(&storage, &buffers);
            let slot = std::cell::Cell::new(None);
            let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut fill = reserve(&storage, &key(1), 4, 100).unwrap();
                slot.set(Some(fill.id().slot_index()));
                dev.control.unwind_next(Some(Unwind::Submit));
                let _ = fill.receive(&mut dev.volume, &bytes(104, 1), &mut ample_io());
            }))
            .is_err();
            dev.control.unwind_next(None);
            assert!(unwound);
            let slot = slot.get().expect("the fill was reserved");
            let live_pool = storage.live_pool().unwrap();
            assert!(live_pool.try_lock_quiet().is_ok());
            assert_eq!(refs(&storage, slot), 1);
            assert_ne!(live_pool.flags(slot) & ABANDONED, 0);
            assert_eq!(records(&storage), [departed(1, false), Record::Free]);
        },
    );
}

/// `s4n-read-share-and-ops`, fill part: with reads holding every one of
/// the volume's `read_ops` table slots, a fill still submits, completes and
/// publishes.
#[test]
fn with_reads_holding_every_read_slot_a_fill_still_publishes() {
    let storage = wide(4, 8);
    let buffers = arena_with(4, 5);
    let mut dev = Device::new(&storage, &buffers);
    let mut leases = Vec::new();
    for n in [1u8, 2, 9] {
        let mut fill = reserve(&storage, &key(n), 4, 100).unwrap();
        dev.fill(&mut fill, &bytes(104, u64::from(n)));
        leases.push(
            fill.publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
                .unwrap(),
        );
    }
    let third = leases.pop().unwrap();
    let reads: Vec<_> = leases
        .iter()
        .map(|lease| {
            let op = dev.volume.read(lease.duplicate(), u64::MAX).unwrap();
            let token = dev
                .control
                .events()
                .iter()
                .rev()
                .find_map(|event| match event {
                    Event::Submitted(token, Operation::Read) => Some(*token),
                    _ => None,
                })
                .unwrap();
            dev.control.hold(token);
            (op, token)
        })
        .collect();
    let refused = dev.volume.read(third, u64::MAX).unwrap_err();
    assert_eq!(
        refused.refusal,
        super::ReadRefusal::OpsExhausted,
        "the two reads hold every read slot"
    );
    assert!(
        refused.lease.is_some(),
        "a refusal before admission returns the lease"
    );
    let payload = bytes(104, 3);
    let mut fill = reserve(&storage, &key(3), 4, 100).unwrap();
    assert_eq!(
        fill.receive(&mut dev.volume, &payload, &mut ample_io()),
        Ok(104)
    );
    let mut out = Vec::with_capacity(4);
    for _ in 0..8 {
        step(&mut dev.volume, &dev.control, &mut out);
    }
    assert!(out.is_empty(), "the held reads deliver nothing");
    assert!(fill.is_ready(&dev.volume));
    let lease = fill
        .publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
        .unwrap();
    for (_, token) in reads {
        dev.control.release(token);
    }
    settle(&mut dev.volume, &dev.control);
    assert_eq!(dev.read(&lease), payload);
}

/// A write set whose fill ended with nothing outstanding is reclaimed when
/// the array is full: with one fill record the array holds `1 + depth`
/// sets, and many more fills that each begin a set and abort still each
/// get one.
#[test]
fn write_sets_of_ended_fills_are_reclaimed_when_the_array_is_full() {
    let storage = wide(1, 8);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    for n in 0..3 * u32::from(super::volume_fixture::DEPTH) {
        let mut fill = reserve(&storage, &key(1), 0, 100).unwrap();
        assert_eq!(
            fill.receive(&mut dev.volume, &[n as u8; 10], &mut ample_io()),
            Ok(10),
            "fill {n}"
        );
        fill.abort();
        service(&storage);
    }
}

/// A fill driven through another storage's volume touches nothing there:
/// `receive` refuses `ForeignVolume`, `progress` reports nothing submitted,
/// and `publish` refuses `ForeignVolume` before any shard gate, so the foreign
/// volume's own set at the same array slot is neither read as this fill's
/// readiness nor ended, and its fill still publishes.
#[test]
fn a_fill_refuses_another_storage_s_volume() {
    let (storage, other) = (wide(2, 8), wide(2, 8));
    let (buffers, other_buffers) = (arena(), arena());
    let mut dev = Device::new(&storage, &buffers);
    let mut foreign = Device::new(&other, &other_buffers);
    let payload = bytes(3 * 8192, 1);
    let mut stranger = reserve(&other, &key(2), 0, payload.len()).unwrap();
    foreign.fill(&mut stranger, &payload);
    let mut fill = reserve(&storage, &key(1), 0, payload.len()).unwrap();
    dev.fill(&mut fill, &payload);
    assert!(fill.is_ready(&dev.volume));
    let before = foreign.volume.report();
    assert_eq!(
        fill.receive(&mut foreign.volume, &[], &mut ample_io()),
        Err(ReceiveError::ForeignVolume)
    );
    assert_eq!(fill.progress(&foreign.volume).submitted_units, 0);
    assert!(!fill.is_ready(&foreign.volume));
    assert_eq!(
        fill.publish(&mut foreign.volume, u64::MAX, TRIES, &mut budget())
            .err(),
        Some(FillPublishError::ForeignVolume)
    );
    assert_eq!(foreign.volume.report(), before);
    assert_eq!(report(&storage, 0).visible, 0, "nothing published here");
    let lease = stranger
        .publish(&mut foreign.volume, u64::MAX, TRIES, &mut budget())
        .unwrap();
    assert_eq!(foreign.read(&lease), payload);
}

/// Attach refuses a receive-write pool below `sum(F[s]) + 1` buffers, since
/// each live fill keeps its first segment's buffer until its last payload
/// byte; at `sum(F[s]) + 1`, `sum(F[s])` fills of three segments each,
/// received in turn a unit at a time, all become ready and publish.
#[test]
fn receive_buffers_cover_every_fill_s_first_segment_and_one_more() {
    use super::volume::{AttachError, Volume};
    use super::volume_fixture::{DEPTH, TICK, device_with};
    let storage = wide(3, 8);
    let short = arena_with(4, 3);
    let (disk, _control) = device_with(7, BUFFER);
    let mut charge = super::ledger::EngineBudget::new(1 << 24);
    let refused = Volume::attach(
        &storage,
        &short,
        disk,
        crate::storage::portable::scripted::ScriptedClock::trusted(),
        crate::storage::ServingAuthority::fixture(),
        DEPTH,
        TICK,
        &mut charge,
    );
    assert_eq!(
        refused.err().map(|(error, _)| error),
        Some(AttachError::ReceiveBuffersBelowFills {
            buffers: 3,
            needed: 4
        })
    );
    let buffers = arena_with(4, 4);
    let mut dev = Device::new(&storage, &buffers);
    let payload = bytes(2 * BUFFER as usize + 100, 5);
    let mut fills: Vec<_> = (1..=3)
        .map(|n| reserve(&storage, &key(n), 0, payload.len()).unwrap())
        .collect();
    let mut taken = [0; 3];
    let mut out = Vec::with_capacity(16);
    for _ in 0..256 {
        for (fill, taken) in fills.iter_mut().zip(&mut taken) {
            let end = (*taken + IO_UNIT).min(payload.len());
            if let Ok(count) = fill.receive(&mut dev.volume, &payload[*taken..end], &mut ample_io())
            {
                *taken += count;
            }
        }
        step(&mut dev.volume, &dev.control, &mut out);
        out.clear();
        if fills.iter().all(|fill| fill.is_ready(&dev.volume)) {
            break;
        }
    }
    for fill in fills {
        let lease = fill
            .publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
            .unwrap();
        assert_eq!(dev.read(&lease), payload);
    }
}

/// A refused submit on the call that takes the last payload byte: the call
/// still takes every byte and returns them, the refused segment stays
/// staged with the header's segment behind it, and `progress` shows nothing
/// submitted; `receive(&[])` retries the staged segments, the header's last,
/// until `submitted_units` covers the record. Both for a final later
/// segment and for a record whose header segment is its only one.
#[test]
fn a_refused_final_submit_is_retried_by_an_empty_receive() {
    let storage = wide(2, 8);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    for (n, len) in [(1u8, BUFFER as usize + 1000), (2, 1000)] {
        let payload = bytes(len, u64::from(n));
        let mut fill = reserve(&storage, &key(n), 0, len).unwrap();
        let locator = locator_of(&storage, &fill);
        place(
            &storage,
            &dev.control,
            locator,
            &vec![0xEE; locator.len_units() as usize * IO_UNIT],
        );
        let tokens = write_tokens(&dev.control).len();
        dev.control.refuse_next(queue_full());
        dev.control.refuse_next(queue_full());
        assert_eq!(
            fill.receive(&mut dev.volume, &payload, &mut ample_io()),
            Ok(len)
        );
        assert_eq!(fill.received(), len as u64);
        assert_eq!(fill.progress(&dev.volume).submitted_units, 0);
        assert_eq!(write_tokens(&dev.control).len(), tokens);
        let mut retries = 0;
        while let Err(refusal) = fill.receive(&mut dev.volume, &[], &mut ample_io()) {
            assert_eq!(refusal, ReceiveError::TableFull);
            assert_eq!(fill.progress(&dev.volume).submitted_units, 0);
            retries += 1;
            assert!(retries <= 2, "two refusals were queued");
        }
        let progress = fill.progress(&dev.volume);
        assert_eq!(progress.submitted_units, progress.len_units);
        let spans = landed(
            &storage,
            &dev.control,
            locator,
            &write_tokens(&dev.control)[tokens..],
        );
        assert_eq!(spans.len(), 1 + usize::from(n == 1));
        assert_eq!(
            spans.last().unwrap().0,
            0,
            "the header's command comes last"
        );
        settle(&mut dev.volume, &dev.control);
        let lease = fill
            .publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
            .unwrap();
        assert_eq!(dev.read(&lease), payload);
    }
}

/// A reservation counts as written only once a submit was accepted: a fill
/// whose one submit was refused and that then aborts cancels its extent at
/// once, as an unwritten one, with no abandonment left for service.
#[test]
fn a_fill_whose_every_submit_was_refused_cancels_as_unwritten() {
    let storage = wide(2, 8);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let mut fill = reserve(&storage, &key(1), 0, 1000).unwrap();
    let slot = fill.id().slot_index();
    dev.control.refuse_next(queue_full());
    assert_eq!(
        fill.receive(&mut dev.volume, &bytes(1000, 1), &mut ample_io()),
        Ok(1000)
    );
    assert_eq!(fill.progress(&dev.volume).submitted_units, 0);
    fill.abort();
    assert_eq!(
        storage.slot_state(SlotIndex(slot)).unwrap().0,
        SlotState::Free
    );
    assert_eq!(partition(&storage).1.filling, 0);
}

#[test]
fn every_segment_submit_debits_one_command_and_its_bytes() {
    let storage = wide(2, 8);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let len = BUFFER as usize + 1000;
    let payload = bytes(len, 7);
    for (n, dimension) in [
        (1u8, BudgetDimension::Operations),
        (2, BudgetDimension::Bytes),
    ] {
        let mut short = match dimension {
            BudgetDimension::Operations => WorkBudget::with_io(0, 0, usize::MAX),
            _ => WorkBudget::with_io(0, usize::MAX, 0),
        };
        let mut fill = reserve(&storage, &key(n), 0, len).unwrap();
        let tokens = write_tokens(&dev.control).len();
        assert_eq!(fill.receive(&mut dev.volume, &payload, &mut short), Ok(len));
        assert_eq!(fill.progress(&dev.volume).submitted_units, 0);
        assert_eq!(write_tokens(&dev.control).len(), tokens);
        assert_eq!((short.operations_used(), short.bytes_used()), (0, 0));
        assert_eq!(
            fill.receive(&mut dev.volume, &[], &mut short),
            Err(ReceiveError::Budget(BudgetShort { dimension }))
        );
        let mut one = WorkBudget::with_io(0, 1, usize::MAX);
        assert_eq!(
            fill.receive(&mut dev.volume, &[], &mut one),
            Err(ReceiveError::Budget(BudgetShort {
                dimension: BudgetDimension::Operations
            })),
            "the header waits for a second command"
        );
        let progress = fill.progress(&dev.volume);
        assert!(progress.submitted_units > 0 && progress.submitted_units < progress.len_units);
        assert_eq!(one.operations_used(), 1);
        assert_eq!(
            one.bytes_used(),
            progress.submitted_units as usize * IO_UNIT
        );
        assert_eq!(fill.receive(&mut dev.volume, &[], &mut ample_io()), Ok(0));
        let progress = fill.progress(&dev.volume);
        assert_eq!(progress.submitted_units, progress.len_units);
        let spans = landed(
            &storage,
            &dev.control,
            locator_of(&storage, &fill),
            &write_tokens(&dev.control)[tokens..],
        );
        assert_eq!(
            spans.last().unwrap().0,
            0,
            "the header's command comes last"
        );
        settle(&mut dev.volume, &dev.control);
        let lease = fill
            .publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
            .unwrap();
        assert_eq!(dev.read(&lease), payload);
    }
}

#[test]
fn an_empty_object_primes_its_header_under_the_command_budget() {
    let storage = wide(2, 8);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let mut fill = reserve(&storage, &key(1), 0, 0).unwrap();
    let mut none = WorkBudget::with_io(0, 0, 0);
    assert_eq!(
        fill.receive(&mut dev.volume, &[], &mut none),
        Err(ReceiveError::Budget(BudgetShort {
            dimension: BudgetDimension::Operations
        }))
    );
    assert_eq!(fill.progress(&dev.volume).submitted_units, 0);
    assert_eq!(dev.volume.report().writes_submitted, 0);
    let mut one = WorkBudget::with_io(0, 1, usize::MAX);
    assert_eq!(fill.receive(&mut dev.volume, &[], &mut one), Ok(0));
    let progress = fill.progress(&dev.volume);
    assert_eq!(progress.submitted_units, progress.len_units);
    assert_eq!(progress.outstanding_units, progress.len_units);
    assert_eq!(one.operations_used(), 1);
    assert_eq!(one.bytes_used(), progress.len_units as usize * IO_UNIT);
    assert!(
        !fill.is_ready(&dev.volume),
        "readiness waits for the terminal"
    );
    settle(&mut dev.volume, &dev.control);
    let progress = fill.progress(&dev.volume);
    assert_eq!(progress.outstanding_units, 0);
    assert!(fill.is_ready(&dev.volume));
    let lease = fill
        .publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
        .unwrap();
    assert!(dev.read(&lease).is_empty());
}

crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
    a_fill_refuses_another_storage_s_volume,
    a_refused_final_submit_is_retried_by_an_empty_receive,
    a_refused_submit_stays_staged_and_copies_nothing_further,
    abort_and_drop_dispose_of_the_block_before_the_record_departs,
    an_abandoned_fill_with_a_write_in_flight_is_held_until_its_last_terminal,
    an_empty_object_primes_its_header_under_the_command_budget,
    commands_tile_the_record_within_a_max_transfer_below_the_buffer_length,
    every_byte_outside_the_header_and_payload_reads_zero_on_the_device,
    every_segment_submit_debits_one_command_and_its_bytes,
    one_buffer_is_one_write_and_a_longer_record_submits_its_header_last,
    received_records_read_back_equal_at_unit_window_and_buffer_boundaries,
    the_header_submits_after_the_last_payload_byte_under_fragmented_receives,
    with_reads_holding_every_read_slot_a_fill_still_publishes,
);

/// A reserved bit planted on a promised placement's slot makes
/// `PlacingFill::end`'s cancel panic under the pool gate: the record stays
/// occupied, as it does for a fill's panicking disposal, the gate stays
/// poisoned, and service releases no record.
#[test]
fn a_panicking_cancel_keeps_the_ended_placements_record_occupied() {
    let fills = [1];
    let index = crate::index::IndexConfig {
        fills: &fills,
        ..super::publish_tests::index_config(&[8], (1, 1), 1)
    };
    let body = super::geometry::EXTENT_PAYLOAD as usize + 1000;
    let mut volume = crate::storage::test_volume(256 * crate::storage::IO_UNIT, 8);
    volume.block_roots = 1;
    let mut storage = super::publish_tests::storage_from(
        &super::StorageConfig {
            body_cap: body,
            volume,
            ..super::publish_tests::storage_config(8)
        },
        &index,
        TestPlatform::heap(super::publish_tests::PAGE),
    );
    let admitted = admit(&storage, 4, body);
    let placing = begin(&storage, &key(1))
        .unwrap()
        .promise_storage(admitted, Some(4), Some(body), &mut budget())
        .unwrap();
    assert_eq!(placing.placed(), 0);
    let live_pool = storage.live_pool().unwrap();
    let slots: Vec<usize> = (0..8)
        .filter(|&slot| live_pool.gate_state(slot).0 == SlotState::Filling)
        .collect();
    assert_eq!(slots.len(), 1, "the promise holds one slot");
    live_pool.edit_word(slots[0], |word| word | RESERVED_BIT);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| placing.end()));
    assert!(outcome.is_err());
    drop(outcome);
    assert!(live_pool.try_lock_quiet().is_err());
    assert_eq!(records(&storage), [live(1)]);
    assert_eq!(service(&storage).released, 0);
    assert_eq!(records(&storage), [live(1)]);
    assert_eq!(finalize(&mut storage), Err(FinalizeError::Poisoned));
}

/// A reserved bit planted on a promised placement's slot makes the park of
/// the placement's end leave the word unchanged, as a park of a malformed
/// word does, so the slot is never disposed of: the record must stay
/// occupied and undeparted while that slot is still charged, whether the
/// placement is dropped with no extent placed, dropped with every extent
/// placed, or ended while the pool gate is busy.
#[test]
fn a_dropped_placement_over_a_malformed_slot_keeps_its_record() {
    for end in ["drop", "place then drop", "end under a busy gate"] {
        let fills = [1];
        let index = crate::index::IndexConfig {
            fills: &fills,
            ..super::publish_tests::index_config(&[8], (1, 1), 1)
        };
        let body = super::geometry::EXTENT_PAYLOAD as usize + 1000;
        let mut volume = crate::storage::test_volume(256 * crate::storage::IO_UNIT, 8);
        volume.block_roots = 1;
        let storage = super::publish_tests::storage_from(
            &super::StorageConfig {
                body_cap: body,
                volume,
                ..super::publish_tests::storage_config(8)
            },
            &index,
            TestPlatform::heap(super::publish_tests::PAGE),
        );
        let admitted = admit(&storage, 4, body);
        let mut placing = begin(&storage, &key(1))
            .unwrap()
            .promise_storage(admitted, Some(4), Some(body), &mut budget())
            .unwrap();
        let live_pool = storage.live_pool().unwrap();
        let slots: Vec<usize> = (0..8)
            .filter(|&slot| live_pool.gate_state(slot).0 == SlotState::Filling)
            .collect();
        assert_eq!(slots.len(), 1, "{end}: the promise holds one slot");
        live_pool.edit_word(slots[0], |word| word | RESERVED_BIT);
        match end {
            "drop" => drop(placing),
            "place then drop" => {
                assert!(matches!(placing.place(&mut budget()), Ok(true)), "{end}");
                drop(placing);
            }
            _ => {
                let held = live_pool.lock().unwrap();
                placing.end();
                drop(held);
            }
        }
        assert_ne!(
            live_pool.word(slots[0]) & RESERVED_BIT,
            0,
            "{end}: premise: the park leaves a malformed word malformed"
        );
        service(&storage);
        assert!(
            matches!(
                records(&storage)[..],
                [Record::Occupied {
                    departed: false,
                    ..
                }]
            ),
            "{end}: the record must stay occupied while its slot is still charged: {:?}",
            records(&storage)
        );
    }
}

/// Retires one receive-write buffer of `arena`, which holds `count`: every
/// buffer starts at its last incarnation, one is taken and dropped, and the
/// others return to incarnation one. Premise: the pool then reports one
/// retired buffer and `count - 1` free.
fn retire_one_receive_buffer(arena: &super::device::BufferArena<TestPlatform>, count: usize) {
    use super::device::PoolKind;
    for index in 0..count {
        arena
            .pools()
            .set_incarnation(PoolKind::ReceiveWrite, index, u64::MAX);
    }
    drop(arena.acquire(PoolKind::ReceiveWrite).unwrap());
    for index in 0..count {
        arena
            .pools()
            .set_incarnation(PoolKind::ReceiveWrite, index, 1);
    }
    let pool = arena.report(PoolKind::ReceiveWrite);
    assert_eq!(
        (pool.retired, pool.free),
        (1, count as u32 - 1),
        "premise: one receive-write buffer retired"
    );
}

/// Attach counts only receive-write buffers that have not retired against
/// `sum(F[s]) + 1`: a retired buffer never returns to the free stack, so with
/// three fill records a pool of four buffers, one retired, leaves no buffer
/// for a later segment and attach refuses it. A pool of five, one retired,
/// attaches.
#[test]
fn a_retired_receive_buffer_counts_against_the_fill_bound_at_attach() {
    use super::volume::{AttachError, Volume};
    use super::volume_fixture::{DEPTH, TICK, device_with};
    let storage = wide(3, 8);
    for (count, refusal) in [
        (
            4,
            Some(AttachError::ReceiveBuffersBelowFills {
                buffers: 3,
                needed: 4,
            }),
        ),
        (5, None),
    ] {
        let buffers = arena_with(4, count);
        retire_one_receive_buffer(&buffers, count as usize);
        let (disk, _control) = device_with(7, BUFFER);
        let mut charge = super::ledger::EngineBudget::new(1 << 24);
        let attached = Volume::attach(
            &storage,
            &buffers,
            disk,
            crate::storage::portable::scripted::ScriptedClock::trusted(),
            crate::storage::ServingAuthority::fixture(),
            DEPTH,
            TICK,
            &mut charge,
        );
        assert_eq!(
            attached.err().map(|(error, _)| error),
            refusal,
            "{count} buffers, one retired"
        );
    }
}

/// The hook runs once after the next reservation claims `head` and before its record's revalidation: it ors
/// `bits` into `head`'s word and takes the pool gate, which [`release_gate_held_before_revalidation`] releases.
fn hold_gate_before_revalidation(live_pool: &Pool, head: usize, bits: u64) {
    // SAFETY: the pool lives in the storage, which outlives the hook's one run inside the reservation the
    // caller makes next and the hold the caller releases before the storage ends.
    let pool: &'static Pool = unsafe { &*std::ptr::from_ref(live_pool) };
    GATE_PLANT.with(|plant| plant.set(Some((pool, head, bits))));
    INTERPOSE_BEFORE_REVALIDATION.with(|hook| {
        hook.set(Some(|_| {
            let (pool, head, bits) = GATE_PLANT.with(Cell::take).unwrap();
            pool.edit_word(head, |word| word | bits);
            GATE_HELD.with(|held| held.replace(pool.lock()));
        }));
    });
}

/// Releases the pool gate the hook of [`hold_gate_before_revalidation`] took, and returns whether it held one.
fn release_gate_held_before_revalidation() -> bool {
    GATE_HELD.with(|held| held.take()).is_some()
}

thread_local! {
    static GATE_PLANT: Cell<Option<(&'static Pool, usize, u64)>> = const { Cell::new(None) };
    static GATE_HELD: std::cell::RefCell<Option<super::tables::PoolAccess<'static>>> =
        const { std::cell::RefCell::new(None) };
}

/// Clears every hook and plant the busy-gate fixtures arm and releases any pool gate a hook holds, when
/// dropped. A test declares it right after its storage, so it drops first on a return and on an unwind,
/// and no hold or pool reference a hook keeps outlives that storage.
struct HookCleanup;

impl Drop for HookCleanup {
    fn drop(&mut self) {
        INTERPOSE_BEFORE_REVALIDATION.with(|hook| hook.set(None));
        drop(super::publication::AFTER_BIND.with(|hook| hook.borrow_mut().take()));
        GATE_PLANT.with(Cell::take);
        MOVE_PLANT.with(Cell::take);
        drop(GATE_HELD.with(|held| held.take()));
        drop(MOVE_HELD.with(|held| held.take()));
    }
}

/// A one-extent fill's end with the pool gate busy abandons its slot through a park, and a park leaves a
/// word with a reserved bit unchanged, so the slot is never disposed of: the record must stay occupied and
/// undeparted while that slot is still charged, whether the fill is aborted, dropped, refused by its
/// revalidation, refused by its publication's completion, or refused after it with the block completed.
#[test]
fn a_fill_ended_under_a_busy_gate_over_a_malformed_slot_keeps_its_record() {
    let mut freed = Vec::new();
    for end in [
        "abort",
        "drop",
        "refused revalidation",
        "refused publication",
        "refused installation",
    ] {
        let storage = ready(2);
        let _cleanup = HookCleanup;
        let live_pool = storage.live_pool().unwrap();
        let k = key(1);
        let slot = if end == "refused installation" {
            let buffers = arena();
            let mut dev = Device::new(&storage, &buffers);
            let mut fill = reserve(&storage, &k, 4, 20).unwrap();
            let slot = fill.id().slot_index();
            dev.fill(&mut fill, &[1; SMALL]);
            assert!(fill.is_ready(&dev.volume), "{end}");
            // SAFETY: the pool and the closed flag live in the storage, which outlives the hook's one run
            // inside the publication below and the hold released before the storage ends.
            let (pool, closed): (&'static Pool, &'static std::sync::atomic::AtomicBool) = unsafe {
                (
                    &*std::ptr::from_ref(live_pool),
                    &*std::ptr::from_ref(storage.closed()),
                )
            };
            super::publication::AFTER_BIND.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    pool.edit_word(slot, |word| word | RESERVED_BIT);
                    closed.store(true, Ordering::SeqCst);
                    GATE_HELD.with(|held| held.replace(pool.lock()));
                }));
            });
            let refused = fill
                .publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
                .err();
            let held = release_gate_held_before_revalidation();
            assert_eq!(refused, Some(FillPublishError::Closed), "{end}");
            assert!(held, "{end}");
            slot
        } else if end == "refused publication" {
            let buffers = arena();
            let mut dev = Device::new(&storage, &buffers);
            let mut fill = reserve(&storage, &k, 4, 20).unwrap();
            let slot = fill.id().slot_index();
            dev.fill(&mut fill, &[1; SMALL]);
            assert!(fill.is_ready(&dev.volume), "{end}");
            live_pool.edit_word(slot, |word| word | RESERVED_BIT);
            let held = live_pool.lock().unwrap();
            let refused = fill
                .publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
                .err();
            assert_eq!(refused, Some(FillPublishError::Contended), "{end}");
            drop(held);
            slot
        } else if end == "refused revalidation" {
            let attempt = begin(&storage, &k).unwrap();
            assert_eq!(invalidate(&storage, &k).unwrap().revoked, Some(1));
            let admitted = admit(&storage, 4, 20);
            let head = next_slot(&storage, &k);
            hold_gate_before_revalidation(live_pool, head, RESERVED_BIT);
            let refused = attempt
                .reserve_storage(admitted, Some(4), Some(20), TRIES, &mut budget())
                .err();
            let held = release_gate_held_before_revalidation();
            assert_eq!(refused, Some(FillReserveError::Superseded), "{end}");
            assert!(held, "{end}");
            head
        } else {
            let fill = reserve(&storage, &k, 4, 20).unwrap();
            let slot = fill.id().slot_index();
            live_pool.edit_word(slot, |word| word | RESERVED_BIT);
            let held = live_pool.lock().unwrap();
            if end == "drop" {
                drop(fill);
            } else {
                fill.abort();
            }
            drop(held);
            slot
        };
        let word = live_pool.word(slot);
        let state = if end == "refused installation" {
            SlotState::Resident
        } else {
            SlotState::Filling
        };
        assert_eq!(
            word & (RESERVED_BIT | ABANDONED | super::word::STATE),
            RESERVED_BIT | state.bits(),
            "{end}: premise: the park leaves a malformed word unchanged, in its state and unflagged: {word:#x}"
        );
        service(&storage);
        if !matches!(
            records(&storage)[..],
            [
                Record::Occupied {
                    departed: false,
                    ..
                },
                Record::Free
            ]
        ) {
            freed.push((end, records(&storage)));
        }
    }
    assert!(
        freed.is_empty(),
        "the record must stay occupied while its slot is still charged: {freed:?}"
    );
}

/// Revalidation holds the shard gate across the first credit exchange after the extent claim. A panic at that
/// exchange poisons the gate even when a destructor acquired it during an earlier unwind.
#[test]
fn a_revalidation_panic_poisons_the_shard_gate_even_during_unwinding() {
    struct RunsOnDrop<F: FnMut()>(F);
    impl<F: FnMut()> Drop for RunsOnDrop<F> {
        fn drop(&mut self) {
            (self.0)();
        }
    }
    for unwinding in [false, true] {
        let storage = ready(2);
        let admitted = admit(&storage, 4, 20);
        let mut attempt = Some(begin(&storage, &key(1)).unwrap());
        INTERPOSE_BEFORE_REVALIDATION.with(|hook| {
            hook.set(Some(|_| {
                super::lease::INTERPOSE_BEFORE_CAS.with(|hook| {
                    hook.set(Some(|_| {
                        panic!("a panic before the place claim's first credit exchange")
                    }));
                });
            }));
        });
        let panicked = Cell::new(false);
        let mut reserve = || {
            let attempt = attempt.take().unwrap();
            let reserved = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                drop(attempt.reserve_storage(admitted, Some(4), Some(20), TRIES, &mut budget()));
            }));
            panicked.set(reserved.is_err());
        };
        if unwinding {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _reserver = RunsOnDrop(&mut reserve);
                panic!("an unrelated panic with a live reserver");
            }));
            assert!(outcome.is_err());
        } else {
            reserve();
        }
        assert!(
            panicked.get(),
            "premise: the revalidation panicked, unwinding={unwinding}"
        );
        assert!(
            gate(&storage).is_poisoned(),
            "the revalidation's panic poisons the shard gate, unwinding={unwinding}"
        );
    }
}

/// The slot word of a one-extent fill names another incarnation when the fill
/// ends, with the pool gate free or busy. Neither the gated retirement nor the park changes a word that names
/// another incarnation, so the slot is never disposed of, and the record must stay occupied and undeparted while
/// that slot is still charged (obligation writable-disposal-closes-before-departure: a departed record was
/// disposed of). The arm with the word intact ends the same ways, and service frees its record.
#[test]
fn a_fill_ended_over_a_slot_word_naming_another_incarnation_keeps_its_record() {
    let mut freed = Vec::new();
    for moved in [false, true] {
        for (end, busy) in [
            ("abort", false),
            ("drop", false),
            ("abort", true),
            ("drop", true),
        ] {
            let storage = ready(2);
            let live_pool = storage.live_pool().unwrap();
            let fill = reserve(&storage, &key(1), 4, 20).unwrap();
            let slot = fill.id().slot_index();
            let reserved = live_pool.word(slot);
            if moved {
                live_pool.edit_word(slot, |word| word.wrapping_add(1));
            }
            let planted = live_pool.word(slot);
            let held = busy.then(|| live_pool.lock().unwrap());
            if end == "drop" {
                drop(fill);
            } else {
                fill.abort();
            }
            drop(held);
            let context = format!("{end}, gate busy {busy}, word moved {moved}");
            if !moved {
                service(&storage);
                assert_eq!(
                    records(&storage),
                    [Record::Free, Record::Free],
                    "{context}: sibling: an intact slot is disposed of and its record freed"
                );
                continue;
            }
            assert_eq!(
                (planted as u32, planted >> 32),
                ((reserved as u32).wrapping_add(1), reserved >> 32),
                "{context}: premise: only the incarnation was moved"
            );
            assert_eq!(
                live_pool.word(slot),
                planted,
                "{context}: premise: the end leaves a word that names another incarnation unchanged"
            );
            service(&storage);
            if !matches!(
                records(&storage)[..],
                [
                    Record::Occupied {
                        departed: false,
                        ..
                    },
                    Record::Free
                ]
            ) {
                freed.push((context, records(&storage)));
            }
        }
    }
    assert!(
        freed.is_empty(),
        "the record must stay occupied while its slot is still charged: {freed:#?}"
    );
}

thread_local! {
    /// The pool, the slot and whether to take the pool gate, for the hook of [`move_incarnation_before_revalidation`].
    static MOVE_PLANT: Cell<Option<(&'static Pool, usize, bool, bool)>> = const { Cell::new(None) };
    /// The pool gate a hook took, released by [`release_moved_gate`].
    static MOVE_HELD: std::cell::RefCell<Option<super::tables::PoolAccess<'static>>> =
        const { std::cell::RefCell::new(None) };
    /// The slot word as a hook left it.
    static MOVE_WORD: Cell<u64> = const { Cell::new(0) };
}

/// Adds one to the incarnation half of `slot`'s word when `moved`, records the word, and takes the pool gate when `busy`.
fn move_incarnation(pool: &'static Pool, slot: usize, moved: bool, busy: bool) {
    if moved {
        pool.edit_word(slot, |word| word.wrapping_add(1));
    }
    MOVE_WORD.with(|word| word.set(pool.word(slot)));
    if busy {
        MOVE_HELD.with(|held| held.replace(pool.lock()));
    }
}

/// The hook runs once after the next reservation claims `head` and before its record's revalidation, as [`move_incarnation`].
fn move_incarnation_before_revalidation(live_pool: &Pool, head: usize, moved: bool, busy: bool) {
    // SAFETY: the pool lives in the storage, which outlives the hook's one run inside the reservation the caller makes next and the hold the caller releases before the storage ends.
    let pool: &'static Pool = unsafe { &*std::ptr::from_ref(live_pool) };
    MOVE_PLANT.with(|plant| plant.set(Some((pool, head, moved, busy))));
    INTERPOSE_BEFORE_REVALIDATION.with(|hook| {
        hook.set(Some(|_| {
            let (pool, head, moved, busy) = MOVE_PLANT.with(Cell::take).unwrap();
            move_incarnation(pool, head, moved, busy);
        }));
    });
}

/// Releases the pool gate a hook took, and returns whether it held one.
fn release_moved_gate() -> bool {
    MOVE_HELD.with(|held| held.take()).is_some()
}

/// The slot word of a one-extent fill names another incarnation when the fill is refused: by its revalidation, by its publication's completion, or after the completion with the block bound. Neither the gated retirement nor the park changes a word that names another incarnation, so the slot is never disposed of, and the record must stay occupied and undeparted while that slot is still charged. The siblings with the word intact are refused the same ways: each passes the conservation judge with its slot returned, retired or parked at the refusal and again after one service pass, and service frees their records.
#[test]
fn a_refused_fill_over_a_slot_word_naming_another_incarnation_keeps_its_record() {
    /// Where the fill is refused.
    #[derive(Debug, Clone, Copy)]
    enum Exit {
        /// By its revalidation, which a revocation refuses `Superseded`.
        Revalidation,
        /// By its publication's bind.
        Publication,
        /// After its bind, by a close the bind's hook makes.
        Installation,
    }
    let mut freed = Vec::new();
    for (exit, busy, moved) in [
        (Exit::Revalidation, false, false),
        (Exit::Revalidation, true, false),
        (Exit::Publication, true, false),
        (Exit::Installation, false, false),
        (Exit::Installation, true, false),
        (Exit::Revalidation, false, true),
        (Exit::Revalidation, true, true),
        (Exit::Publication, false, true),
        (Exit::Publication, true, true),
        (Exit::Installation, false, true),
        (Exit::Installation, true, true),
    ] {
        let context = format!("refused {exit:?}, gate busy {busy}, word moved {moved}");
        let storage = ready(2);
        let _cleanup = HookCleanup;
        let live_pool = storage.live_pool().unwrap();
        // SAFETY: the pool lives in the storage, which outlives every hook run and every hold below.
        let pool: &'static Pool = unsafe { &*std::ptr::from_ref(live_pool) };
        let k = key(1);
        let (slot, reserved) = match exit {
            Exit::Installation => {
                let buffers = arena();
                let mut dev = Device::new(&storage, &buffers);
                let mut fill = reserve(&storage, &k, 4, 20).unwrap();
                let slot = fill.id().slot_index();
                let reserved = live_pool.word(slot);
                dev.fill(&mut fill, &[1; SMALL]);
                assert!(fill.is_ready(&dev.volume), "{context}");
                // SAFETY: the closed flag lives in the storage, which outlives the hook's one run inside the publication below.
                let closed: &'static std::sync::atomic::AtomicBool =
                    unsafe { &*std::ptr::from_ref(storage.closed()) };
                super::publication::AFTER_BIND.with(|hook| {
                    *hook.borrow_mut() = Some(Box::new(move || {
                        closed.store(true, Ordering::SeqCst);
                        move_incarnation(pool, slot, moved, busy);
                    }));
                });
                let refused = fill
                    .publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
                    .err();
                let held = release_moved_gate();
                assert_eq!(refused, Some(FillPublishError::Closed), "{context}");
                assert_eq!(held, busy, "{context}");
                assert!(
                    storage.is_closed(),
                    "{context}: premise: the bind ran its hook"
                );
                (slot, reserved)
            }
            Exit::Publication => {
                let buffers = arena();
                let mut dev = Device::new(&storage, &buffers);
                let mut fill = reserve(&storage, &k, 4, 20).unwrap();
                let slot = fill.id().slot_index();
                let reserved = live_pool.word(slot);
                dev.fill(&mut fill, &[1; SMALL]);
                assert!(fill.is_ready(&dev.volume), "{context}");
                move_incarnation(pool, slot, moved, busy);
                let mut spent = budget();
                let refused = fill
                    .publish(&mut dev.volume, u64::MAX, TRIES, &mut spent)
                    .err();
                let held = release_moved_gate();
                let expected = if busy {
                    FillPublishError::Contended
                } else {
                    FillPublishError::Superseded
                };
                assert_eq!(refused, Some(expected), "{context}");
                assert_eq!(held, busy, "{context}");
                assert_eq!(
                    spent.counters().hashes,
                    0,
                    "{context}: premise: the bind refused before the route's hash"
                );
                (slot, reserved)
            }
            Exit::Revalidation => {
                let attempt = begin(&storage, &k).unwrap();
                assert_eq!(invalidate(&storage, &k).unwrap().revoked, Some(1));
                let admitted = admit(&storage, 4, 20);
                let (head, claimed) = next_claim(&storage, &k);
                move_incarnation_before_revalidation(live_pool, head, moved, busy);
                let refused = attempt
                    .reserve_storage(admitted, Some(4), Some(20), TRIES, &mut budget())
                    .err();
                let held = release_moved_gate();
                assert_eq!(refused, Some(FillReserveError::Superseded), "{context}");
                assert_eq!(held, busy, "{context}");
                assert_eq!(
                    slot_incarnation(&storage, head),
                    claimed + u32::from(moved),
                    "{context}: premise: the refusal follows the claim"
                );
                (head, 0)
            }
        };
        if !moved {
            // An intact slot under a free pool gate returns or retires at the
            // refusal, and one service pass frees it. Under a busy gate it
            // parks, and one pass frees a parked `Filling` slot and retires a
            // parked `Resident` one.
            let (at_exit, after_service) = match (exit, busy) {
                (Exit::Revalidation, false) => (FREE, FREE),
                (Exit::Revalidation | Exit::Publication, true) => (PARKED, FREE),
                (Exit::Publication, false) => {
                    unreachable!("{context}: an intact bind under a free gate publishes")
                }
                (Exit::Installation, false) => (RETIRED, FREE),
                (Exit::Installation, true) => (PARKED_RESIDENT, RETIRED),
            };
            conserved_at(&storage, slot, at_exit);
            conserved_after_service(&storage, slot, after_service);
            service(&storage);
            assert_eq!(
                records(&storage),
                [Record::Free, Record::Free],
                "{context}: sibling: an intact slot is disposed of and its record freed"
            );
            continue;
        }
        let planted = MOVE_WORD.with(Cell::get);
        if reserved != 0 {
            assert_eq!(
                planted as u32,
                (reserved as u32).wrapping_add(1),
                "{context}: premise: the incarnation was moved by one"
            );
        }
        let state = match exit {
            Exit::Installation => SlotState::Resident,
            Exit::Revalidation | Exit::Publication => SlotState::Filling,
        };
        let word = live_pool.word(slot);
        assert_eq!(
            (
                word as u32,
                word & (ABANDONED | super::word::STATE),
                live_pool.gate_state(slot).0
            ),
            (planted as u32, state.bits(), state),
            "{context}: premise: the refusal leaves the word naming the other incarnation, in its state and unflagged: {word:#x}, planted {planted:#x}"
        );
        service(&storage);
        if !matches!(
            records(&storage)[..],
            [
                Record::Occupied {
                    departed: false,
                    ..
                },
                Record::Free
            ]
        ) {
            freed.push((context, records(&storage)));
        }
    }
    assert!(
        freed.is_empty(),
        "the record must stay occupied while its slot is still charged: {freed:#?}"
    );
}

/// The slot word of a promised placement names another incarnation when the placement ends. The cancel's gated return finds the slot no longer describing the builder and the park changes no word that names another incarnation, so the slot is never disposed of: the record must stay occupied and undeparted while that slot is still charged, whether the placement is dropped or ended, with the pool gate free or busy. The siblings with the word intact end the same ways, and service frees their records.
#[test]
fn a_placement_ended_over_a_slot_word_naming_another_incarnation_keeps_its_record() {
    let mut freed = Vec::new();
    for moved in [false, true] {
        for (end, busy) in [
            ("drop", false),
            ("end", false),
            ("drop", true),
            ("end", true),
        ] {
            let context = format!("{end}, gate busy {busy}, word moved {moved}");
            let fills = [1];
            let index = crate::index::IndexConfig {
                fills: &fills,
                ..super::publish_tests::index_config(&[8], (1, 1), 1)
            };
            let body = super::geometry::EXTENT_PAYLOAD as usize + 1000;
            let mut volume = crate::storage::test_volume(256 * crate::storage::IO_UNIT, 8);
            volume.block_roots = 1;
            let storage = super::publish_tests::storage_from(
                &super::StorageConfig {
                    body_cap: body,
                    volume,
                    ..super::publish_tests::storage_config(8)
                },
                &index,
                TestPlatform::heap(super::publish_tests::PAGE),
            );
            let admitted = admit(&storage, 4, body);
            let placing = begin(&storage, &key(1))
                .unwrap()
                .promise_storage(admitted, Some(4), Some(body), &mut budget())
                .unwrap();
            let live_pool = storage.live_pool().unwrap();
            let slots: Vec<usize> = (0..8)
                .filter(|&slot| live_pool.gate_state(slot).0 == SlotState::Filling)
                .collect();
            assert_eq!(slots.len(), 1, "{context}: the promise holds one slot");
            let promised = live_pool.word(slots[0]);
            if moved {
                live_pool.edit_word(slots[0], |word| word.wrapping_add(1));
            }
            let planted = live_pool.word(slots[0]);
            let held = busy.then(|| live_pool.lock().unwrap());
            if end == "drop" {
                drop(placing);
            } else {
                placing.end();
            }
            drop(held);
            if !moved {
                service(&storage);
                assert_eq!(
                    records(&storage),
                    [Record::Free],
                    "{context}: sibling: an intact slot is disposed of and its record freed"
                );
                continue;
            }
            assert_eq!(
                (planted as u32, planted >> 32),
                ((promised as u32).wrapping_add(1), promised >> 32),
                "{context}: premise: only the incarnation was moved"
            );
            assert_eq!(
                (live_pool.word(slots[0]), live_pool.gate_state(slots[0]).0),
                (planted, SlotState::Filling),
                "{context}: premise: the end leaves a word that names another incarnation unchanged and filling"
            );
            service(&storage);
            if !matches!(
                records(&storage)[..],
                [Record::Occupied {
                    departed: false,
                    ..
                }]
            ) {
                freed.push((context, records(&storage)));
            }
        }
    }
    assert!(
        freed.is_empty(),
        "the record must stay occupied while its slot is still charged: {freed:#?}"
    );
}
