//! The clean reserve at the claim: equality passes and one unit short
//! refuses on both claim paths with nothing changed, charged units include
//! the record header and padding, projected retirement funds no claim, a
//! returned extent funds one later claim, the domain report shows the
//! reserve and the claimable units, and at the structural floor the
//! promises of every PUT pass with `T - 1` retired units in flight.

use super::admission::Decision;
use super::attempt_tests::{begin, service};
use super::budget::WorkBudget;
use super::config::StorageConfig;
use super::extent::RawPartition;
use super::geometry::EXTENT_PAYLOAD;
use super::owner::Storage;
use super::owner_fixture::{floor_marks, largest_charge};
use super::publish_tests::{PAGE, TRIES, index_config, key, storage_config, storage_from};
use super::reserve::ReserveError;
use super::tables::PoolState;
use super::test_platform::TestPlatform;
use super::writable::FillReserveError;
use crate::storage::IO_UNIT;

const SLOTS: usize = 8;
/// The clean reserve `R` every fixture uses, in units.
const RESERVE: u64 = 1;
/// A body that, with the fixtures' 4 metadata bytes, makes a 4,092-byte
/// payload: it fits one unit's bytes while its header pushes the charged
/// record to two units.
const TWO_UNIT_BODY: usize = IO_UNIT - 8;

/// An indexed storage of `units` units and eight slots with the fixtures'
/// one-unit reserve.
fn storage(units: usize) -> Storage<TestPlatform> {
    storage_reserving(units, RESERVE)
}

/// An indexed storage of `units` units and eight slots with a clean reserve
/// of `reserve` units, admitting bodies up to one unit, with headroom
/// watermarks so the domain report is available: `T = Cmax` and
/// `low_units` the structural floor of zero promises, `R + T`.
fn storage_reserving(units: usize, reserve: u64) -> Storage<TestPlatform> {
    let mut volume = crate::storage::test_volume(units * IO_UNIT, SLOTS);
    volume.reserve_units = reserve;
    let mut config = StorageConfig {
        body_cap: IO_UNIT,
        volume,
        ..storage_config(SLOTS)
    };
    let largest = largest_charge(&config);
    config.volume.maintenance = Some(floor_marks(&config, 0, largest));
    indexed(&config)
}

/// A storage over `config` with one index shard of eight slots and two
/// fill records, its clock reading tick 1.
fn indexed(config: &StorageConfig) -> Storage<TestPlatform> {
    let limits = [SLOTS];
    let fills = [2usize];
    let index = crate::index::IndexConfig {
        fills: &fills,
        ..index_config(&limits, (1, 1), 1)
    };
    let storage = storage_from(config, &index, TestPlatform::heap(PAGE));
    storage.platform.ticks(&[Some(1)]);
    storage
}

fn budget() -> WorkBudget {
    WorkBudget::new(1 << 12)
}

/// Every word a claim could mutate, read under the pool gate: the pool
/// state with the slot ledger and the claim cursor, the raw ledger,
/// the free runs the extent bitmap holds, and every slot's word.
#[derive(Debug, PartialEq)]
struct Snapshot {
    state: PoolState,
    raw: RawPartition,
    free_runs: Vec<(u64, u64)>,
    words: Vec<u64>,
}

fn snapshot(storage: &Storage<TestPlatform>) -> Snapshot {
    let live = storage.live_pool().unwrap();
    let mut access = live.lock().unwrap();
    let mut tables = access.tables();
    let state = *tables.state;
    let extents = tables.extents();
    let (raw, free_runs) = (extents.ledger(), extents.free_set());
    drop(access);
    let words = (0..SLOTS).map(|slot| live.word(slot)).collect();
    Snapshot {
        state,
        raw,
        free_runs,
        words,
    }
}

fn free_units(storage: &Storage<TestPlatform>) -> u64 {
    storage.domain_report().unwrap().free_units
}

/// Holds one-unit allocations until `free` units remain.
fn hold_until(
    storage: &Storage<TestPlatform>,
    free: u64,
) -> Vec<super::ExtentReservation<'_, TestPlatform>> {
    let mut held = Vec::new();
    while free_units(storage) > free {
        held.push(storage.reserve(Some(1), Some(1), &mut budget()).unwrap());
    }
    held
}

fn admitted(storage: &Storage<TestPlatform>, body: usize) -> super::Admitted {
    match storage.decide_admission(Some(4), Some(body)) {
        Decision::Admit(admitted) => admitted,
        other => panic!("expected Admit, got {other:?}"),
    }
}

/// Both claim paths, at `free == C + R` with a fitting run and a free slot,
/// succeed and leave exactly `R` free. `C` is the full charged record: a
/// payload that fits one unit's bytes charges two units with its header, so
/// the claim needs `C + R` free units counted over the whole charged record.
#[test]
fn equality_passes_on_both_claim_paths_and_leaves_the_reserve() {
    let direct = storage(4);
    let held = hold_until(&direct, 2 + RESERVE);
    let claim = direct
        .reserve(Some(4), Some(TWO_UNIT_BODY), &mut budget())
        .unwrap();
    assert_eq!(claim.locator().len_units(), 2);
    assert_eq!(free_units(&direct), RESERVE);
    drop((claim, held));

    let writable = storage(4);
    let held = hold_until(&writable, 2 + RESERVE);
    let fill = begin(&writable, &key(1))
        .unwrap()
        .reserve_storage(
            admitted(&writable, TWO_UNIT_BODY),
            Some(4),
            Some(TWO_UNIT_BODY),
            TRIES,
            &mut budget(),
        )
        .unwrap();
    assert_eq!(free_units(&writable), RESERVE);
    fill.abort();
    drop(held);
}

/// One unit short of `C + R`, both claim paths refuse `CleanReserve` with
/// the slot words, the free set, the extent bitmap and both ledgers
/// unchanged. The direct claim spends only the gate attempt and the update,
/// and the fill's claim makes no visit. The fill attempt is consumed and its
/// record departs.
#[test]
fn one_unit_short_refuses_on_both_claim_paths_and_changes_nothing() {
    let storage = storage(4);
    let held = hold_until(&storage, 2 + RESERVE - 1);
    // Two free units cover the one-unit payload and fall one short of C + R.
    assert_eq!(free_units(&storage), 2);
    let before = snapshot(&storage);
    let mut spent = budget();
    assert_eq!(
        storage
            .reserve(Some(4), Some(TWO_UNIT_BODY), &mut spent)
            .err(),
        Some(ReserveError::CleanReserve)
    );
    assert_eq!(snapshot(&storage), before);
    let counters = spent.counters();
    assert_eq!(
        (
            counters.coordination_attempts,
            counters.updates,
            counters.visits
        ),
        (1, 1, 0)
    );

    let attempt = begin(&storage, &key(2)).unwrap();
    let before = snapshot(&storage);
    let mut spent = budget();
    assert_eq!(
        attempt
            .reserve_storage(
                admitted(&storage, TWO_UNIT_BODY),
                Some(4),
                Some(TWO_UNIT_BODY),
                TRIES,
                &mut spent,
            )
            .err(),
        Some(FillReserveError::CleanReserve)
    );
    assert_eq!(snapshot(&storage), before);
    assert_eq!(spent.counters().visits, 0);
    assert_eq!(service(&storage).released, 1);
    // A one-unit claim still fits beside the reserve.
    let small = storage.reserve(Some(1), Some(1), &mut budget()).unwrap();
    assert_eq!(free_units(&storage), RESERVE);
    drop((small, held));
}

/// An evicted extent held in flight by a pinned reader counts toward the
/// headroom predicate but funds no claim: a claim that actual free units
/// refuse stays refused. Once the extent returns, the same claim succeeds,
/// and further service credits nothing more, so the next one refuses.
#[test]
fn projected_retirement_funds_no_claim_and_a_return_funds_one() {
    let storage = storage(4);
    for n in 1..=3 {
        super::lookup_tests::publish(&storage, key(n), u64::MAX, &[n; 20]);
    }
    assert_eq!(free_units(&storage), RESERVE);
    let mut pinned = storage.register().unwrap();
    let protected = pinned.enter().unwrap();
    let report = storage.evict_step(&mut budget(), |_, _| true).unwrap();
    assert!(report.commit.is_some(), "{report:?}");
    let _ = storage.certify(&mut budget()).unwrap();
    let _ = storage.service(&mut budget()).unwrap();
    let domain = storage.domain_report().unwrap();
    assert_eq!((domain.free_units, domain.in_flight_units), (RESERVE, 1));
    let before = snapshot(&storage);
    assert_eq!(
        storage.reserve(Some(1), Some(1), &mut budget()).err(),
        Some(ReserveError::CleanReserve)
    );
    assert_eq!(snapshot(&storage), before);

    drop(protected);
    let mut calls = 0;
    while storage.domain_report().unwrap().in_flight_units != 0 {
        let _ = storage.certify(&mut budget()).unwrap();
        let _ = storage.service(&mut budget()).unwrap();
        calls += 1;
        assert!(calls < 8, "the evicted extent never returned");
    }
    assert_eq!(free_units(&storage), RESERVE + 1);
    let claim = storage.reserve(Some(1), Some(1), &mut budget()).unwrap();
    let _ = storage.certify(&mut budget()).unwrap();
    assert_eq!(storage.service(&mut budget()).unwrap().serviced, 0);
    assert_eq!(free_units(&storage), RESERVE);
    assert_eq!(
        storage.reserve(Some(1), Some(1), &mut budget()).err(),
        Some(ReserveError::CleanReserve)
    );
    drop(claim);
}

/// The domain report carries `R` and the claimable units, `free - R`
/// saturating at zero, after setup, after claims and after a refusal.
#[test]
fn the_domain_report_shows_the_reserve_and_the_claimable_units() {
    let storage = storage(4);
    let check = |storage: &Storage<TestPlatform>| {
        let domain = storage.domain_report().unwrap();
        assert_eq!(domain.reserve_units, RESERVE);
        assert_eq!(
            domain.claimable_units,
            domain.free_units.saturating_sub(RESERVE)
        );
        domain
    };
    assert_eq!(check(&storage).claimable_units, 3);
    let held = hold_until(&storage, RESERVE);
    assert_eq!(check(&storage).claimable_units, 0);
    assert_eq!(
        storage.reserve(Some(1), Some(1), &mut budget()).err(),
        Some(ReserveError::CleanReserve)
    );
    assert_eq!(check(&storage).claimable_units, 0);
    drop(held);
}

/// The configured reserve `R` decides: with `R = 2`, a
/// two-unit claim passes at `free == 4`, leaving two free, and refuses at
/// three with nothing changed, and the domain report carries the same `R`.
#[test]
fn the_configured_reserve_decides_the_claim_and_the_report() {
    let reserve = 2;
    let storage = storage_reserving(5, reserve);
    let domain = storage.domain_report().unwrap();
    assert_eq!((domain.reserve_units, domain.claimable_units), (2, 3));
    let held = hold_until(&storage, 2 + reserve);
    let claim = storage
        .reserve(Some(4), Some(TWO_UNIT_BODY), &mut budget())
        .unwrap();
    let domain = storage.domain_report().unwrap();
    assert_eq!((domain.free_units, domain.claimable_units), (reserve, 0));
    assert_eq!(claim.cancel(), Ok(()));
    let more = hold_until(&storage, 2 + reserve - 1);
    let before = snapshot(&storage);
    assert_eq!(
        storage
            .reserve(Some(4), Some(TWO_UNIT_BODY), &mut budget())
            .err(),
        Some(ReserveError::CleanReserve)
    );
    assert_eq!(snapshot(&storage), before);
    let domain = storage.domain_report().unwrap();
    assert_eq!((domain.reserve_units, domain.claimable_units), (2, 1));
    drop((held, more));
}

/// The body of the largest object of [`floored`]: one full extent and 1,000
/// more bytes, two extents charging `Cmax = 64` units beside its 16
/// metadata bytes.
const TWO_EXTENTS: usize = EXTENT_PAYLOAD as usize + 1000;

/// PUTs whose promises the floor of [`floored`] covers.
const PUTS: u32 = 2;

/// Builds the floor fixture on [`UNITS_OF_FLOORED`] units: one sequence
/// arena root, [`TWO_EXTENTS`] as the largest object, `T = Cmax`, and
/// `low_units` `below` units under the structural floor of [`PUTS`] PUTs,
/// `R + 3 × Cmax`.
fn floored(below: u64) -> Storage<TestPlatform> {
    let units = UNITS_OF_FLOORED as usize;
    let mut volume = crate::storage::test_volume(units * IO_UNIT, SLOTS);
    volume.alloc_search_words = crate::storage::work_bound(units as u64, SLOTS, 64);
    volume.block_roots = 1;
    let mut config = StorageConfig {
        engine_budget: 1 << 26,
        body_cap: TWO_EXTENTS,
        volume,
        ..storage_config(SLOTS)
    };
    let largest = largest_charge(&config);
    let mut marks = floor_marks(&config, PUTS, largest);
    marks.low_units -= below;
    config.volume.maintenance = Some(marks);
    indexed(&config)
}

/// Publishes one full-extent object, `Cmax - 1` units, and evicts it into
/// flight, where a reader the caller pinned beforehand holds it, then
/// holds one-unit claims until the free units less the escrow, plus the
/// in-flight units, equal `low_units`: a raw read exactly at the watermark,
/// with `in_flight_units = retired_units = T - 1`.
fn at_the_watermark(
    storage: &Storage<TestPlatform>,
) -> Vec<super::ExtentReservation<'_, TestPlatform>> {
    let past = (UNITS_OF_FLOORED - FLOOR_OF_FLOORED) as usize;
    let pad = storage
        .reserve(Some(0), Some(past * IO_UNIT - 2048), &mut budget())
        .unwrap();
    assert_eq!(free_units(storage), FLOOR_OF_FLOORED);
    let body = vec![7; EXTENT_PAYLOAD as usize - 4];
    super::lookup_tests::publish(storage, key(1), u64::MAX, &body);
    let report = storage.evict_step(&mut budget(), |_, _| true).unwrap();
    assert!(report.commit.is_some(), "{report:?}");
    let _ = storage.certify(&mut budget()).unwrap();
    let _ = storage.service(&mut budget()).unwrap();
    let domain = storage.domain_report().unwrap();
    let mut held = hold_until(storage, domain.low_units - domain.in_flight_units);
    held.push(pad);
    let domain = storage.domain_report().unwrap();
    assert_eq!(domain.retired_limit, LARGEST_OF_FLOORED, "{domain:?}");
    assert_eq!(
        (domain.in_flight_units, domain.retired_units),
        (LARGEST_OF_FLOORED - 1, LARGEST_OF_FLOORED - 1),
        "{domain:?}"
    );
    assert_eq!(
        domain.free_units - domain.escrow_units + domain.in_flight_units,
        domain.low_units,
        "{domain:?}"
    );
    held
}

/// [`TWO_EXTENTS`] with its 16 metadata bytes charges `Cmax`: a full
/// extent's 63 units and one more for the rest.
const LARGEST_OF_FLOORED: u64 = 64;

/// The structural floor of [`PUTS`] PUTs over [`floored`], whose retired
/// allowance is one largest charge.
const FLOOR_OF_FLOORED: u64 = RESERVE + (PUTS as u64 + 1) * LARGEST_OF_FLOORED;

const UNITS_OF_FLOORED: u64 = FLOOR_OF_FLOORED.div_ceil(63) * 63;

/// At `low_units` equal to the structural floor `R + 2 × Cmax + T` of two
/// PUTs, read exactly at the watermark with `T - 1` retired units in
/// flight, two promises of `Cmax` pass and their placements, `2 × Cmax`
/// units, pass with no maintenance call between them.
#[test]
fn every_promise_and_its_placements_pass_at_the_floor_with_the_allowance_less_one_in_flight() {
    let storage = floored(0);
    assert_eq!(storage.domain_report().unwrap().low_units, FLOOR_OF_FLOORED);
    let mut pinned = storage.register().unwrap();
    let protected = pinned.enter().unwrap();
    let held = at_the_watermark(&storage);
    let mut builders: Vec<_> = (0..PUTS)
        .map(|_| {
            storage
                .promise(Some(16), Some(TWO_EXTENTS), &mut budget())
                .unwrap()
        })
        .collect();
    for builder in &builders {
        assert_eq!(builder.remaining(), LARGEST_OF_FLOORED);
    }
    for builder in &mut builders {
        while !builder.is_complete() {
            assert!(builder.place(&mut budget()).unwrap(), "{builder:?}");
        }
    }
    let domain = storage.domain_report().unwrap();
    assert_eq!(domain.escrow_units, 0, "{domain:?}");
    assert_eq!(domain.claimable_units, 1, "{domain:?}");
    drop((builders, held, protected));
}

/// Two units under the floor, `low_units = R + 2 × Cmax + T - 2`, read
/// exactly at the watermark with `T - 1` retired units in flight, leave
/// `2 × Cmax - 1` units claimable: the first promise of `Cmax` passes and
/// the last refuses `CleanReserve`.
#[test]
fn two_units_under_the_floor_the_last_promise_refuses_on_the_clean_reserve() {
    let storage = floored(2);
    assert_eq!(
        storage.domain_report().unwrap().low_units,
        FLOOR_OF_FLOORED - 2
    );
    let mut pinned = storage.register().unwrap();
    let protected = pinned.enter().unwrap();
    let held = at_the_watermark(&storage);
    let first = storage
        .promise(Some(16), Some(TWO_EXTENTS), &mut budget())
        .unwrap();
    assert_eq!(
        storage
            .promise(Some(16), Some(TWO_EXTENTS), &mut budget())
            .err(),
        Some(super::PromiseError::Reserve(ReserveError::CleanReserve))
    );
    drop((first, held, protected));
}

/// `record_units` includes both extents: 63 units for the first and one for the remainder.
#[test]
fn the_owner_s_floor_terms_of_a_two_extent_object_carry_its_whole_charge() {
    let storage = floored(0);
    let terms = storage.floor_terms().expect("a live storage");
    assert_eq!(terms.record_units, LARGEST_OF_FLOORED);
    assert_eq!(terms.floor(PUTS), Ok(FLOOR_OF_FLOORED));
}
