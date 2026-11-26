//! Budgeted maintenance through the public surface: recovery of usable
//! capacity after `CleanReserve`, the in-flight bound while grace is blocked,
//! the minimum and zero budgets, the single holder, poisoning, stage
//! fairness, closed-storage delegation, watermark validation, the in-flight
//! unit count, and honest reports.

use std::cell::Cell;

use super::budget::{BudgetDimension, WorkBudget};
use super::closing::ClosingReport;
use super::config::StorageConfig;
use super::evict::Commit;
use super::geometry::EXTENT_PAYLOAD;
use super::lookup_tests::{key, lookup};
use super::maintain::{
    INTERPOSE_BEFORE_HEADROOM_SELECT, INTERPOSE_BEFORE_STAGE, MaintainError, MaintainReport,
    MaintainStage,
};
use super::owner::Storage;
use super::placement::PlacementConfig;
use super::publish_tests::{PAGE, RETRIES, index_config, storage_config};
use super::reserve::ReserveError;
use super::test_platform::TestPlatform;
use super::volume::VolumeWatermarks;
use super::{ConfigError, Finalization, Maintained};
use crate::index::{IndexConfig, ShardIndex};

const SLOTS: usize = 40;
/// Units of the volume: every published object below spans one, so fifteen
/// objects fill it beside the reserve while slots remain free.
const UNITS: usize = 16;
/// The fixture volume's one-unit clean reserve, in bytes: a full volume
/// keeps this many free.
const RESERVE: usize = crate::storage::IO_UNIT;

fn watermarks(low_units: u64, min_free_slots: usize) -> VolumeWatermarks {
    VolumeWatermarks {
        low_units,
        min_free_slots,
        retired_units: u64::MAX,
    }
}

/// An indexed storage of `units` units and `SLOTS` slots with the given
/// maintenance watermarks.
fn storage_with(marks: Option<VolumeWatermarks>) -> Storage<TestPlatform> {
    storage_on(UNITS, marks)
}

fn storage_on(units: usize, marks: Option<VolumeWatermarks>) -> Storage<TestPlatform> {
    storage_capped(units, marks, storage_config(SLOTS).body_cap)
}

/// As [`storage_on`], admitting bodies of up to `body_cap` bytes.
fn storage_capped(
    units: usize,
    marks: Option<VolumeWatermarks>,
    body_cap: usize,
) -> Storage<TestPlatform> {
    storage_sharded(units, marks, body_cap, 1)
}

fn storage_sharded(
    units: usize,
    marks: Option<VolumeWatermarks>,
    body_cap: usize,
    shards: usize,
) -> Storage<TestPlatform> {
    storage_arena(units, marks, body_cap, shards, 0, SLOTS)
}

/// As [`storage_sharded`], with `block_roots` sequence arena roots and a
/// search allowance that funds the largest extent, so the storage promises
/// objects of several extents.
fn storage_arena(
    units: usize,
    marks: Option<VolumeWatermarks>,
    body_cap: usize,
    shards: usize,
    block_roots: usize,
    slots: usize,
) -> Storage<TestPlatform> {
    let limits = vec![slots / shards; shards];
    let fills = vec![2usize; shards];
    let index = IndexConfig {
        fills: &fills,
        ..index_config(&limits, (1, 1), 1)
    };
    let mut volume = crate::storage::test_volume(units * crate::storage::IO_UNIT, slots);
    volume.maintenance = marks;
    volume.block_roots = block_roots;
    if block_roots > 0 {
        volume.alloc_search_words = crate::storage::work_bound(units as u64, slots, 64);
    }
    let config = StorageConfig {
        lease_limit: 64,
        body_cap,
        volume,
        ..storage_config(slots)
    };
    let validated = config.validate().unwrap();
    let index = index.validate(&validated).unwrap();
    let placement = PlacementConfig { control_home: 0 };
    let storage =
        Storage::initialize_indexed(&validated, index, &placement, TestPlatform::heap(PAGE))
            .unwrap();
    storage.platform.ticks(&[Some(1)]);
    storage
}

/// A storage whose headroom keeps `low_units` free units and one free slot.
fn ready(low_units: u64) -> Storage<TestPlatform> {
    storage_with(Some(watermarks(low_units, 1)))
}

fn generous() -> WorkBudget {
    WorkBudget::new(1 << 16)
}

fn open(result: Result<Maintained, MaintainError>) -> MaintainReport {
    match result {
        Ok(Maintained::Open(report)) => report,
        other => panic!("expected an open report, got {other:?}"),
    }
}

fn maintain(storage: &Storage<TestPlatform>) -> MaintainReport {
    open(storage.maintain(&mut generous()))
}

/// A one-unit object for key `n`.
fn publish_big(storage: &Storage<TestPlatform>, n: u8) -> usize {
    super::lookup_tests::publish(storage, key(n), u64::MAX, &[n; 100]).slot_index()
}

fn reserve_big(storage: &Storage<TestPlatform>) -> Result<(), ReserveError> {
    storage
        .reserve(Some(4), Some(100), &mut generous())
        .map(drop)
}

/// Returns every evicted extent, then publishes fresh keys from `next` until
/// the volume is full again.
fn refill(storage: &Storage<TestPlatform>, next: &mut u8) {
    let _ = storage.certify(&mut generous()).unwrap();
    storage.service(&mut generous()).unwrap();
    while storage.pool_report().unwrap().ledger.unwrap().raw.free != RESERVE {
        publish_big(storage, *next);
        *next += 1;
    }
}

/// Fills the volume with published objects and returns their keys.
fn fill_big(storage: &Storage<TestPlatform>) -> Vec<u8> {
    let mut keys = Vec::new();
    while storage.pool_report().unwrap().ledger.unwrap().raw.free != RESERVE {
        let n = keys.len() as u8 + 1;
        publish_big(storage, n);
        keys.push(n);
    }
    keys
}

/// A volume full of unleased residents refuses `CleanReserve`; funded calls,
/// which run grace and service themselves, make the next same-size
/// reservation succeed. The same witness with every resident leased, the
/// reject-everything control, never recovers and reports blocked.
#[test]
fn funded_maintenance_recovers_a_full_volume() {
    let storage = ready(2);
    fill_big(&storage);
    assert_eq!(reserve_big(&storage), Err(ReserveError::CleanReserve));
    let mut calls = 0;
    while reserve_big(&storage).is_err() {
        maintain(&storage);
        calls += 1;
        assert!(calls < 100, "maintenance never recovered the volume");
    }
    assert!(storage.maintain_totals().evicted >= 1);

    let control = ready(2);
    let keys = fill_big(&control);
    let mut reader = control.register().unwrap();
    let leases: Vec<_> = keys
        .iter()
        .map(|&n| lookup(&mut reader, &key(n), RETRIES).unwrap())
        .collect();
    let mut blocked = false;
    for _ in 0..100 {
        blocked |= maintain(&control).blocked_by_readers_or_io;
    }
    assert!(reserve_big(&control).is_err(), "the control recovered");
    assert!(blocked);
    assert_eq!(control.maintain_totals().evicted, 0);
    drop(leases);
}

/// Retired extents held by leases do not come back, so maintenance keeps
/// evicting unleased residents until a reservation succeeds.
#[test]
fn held_retired_capacity_is_recovered_from_unleased_residents() {
    let storage = ready(2);
    let keys = fill_big(&storage);
    let mut reader = storage.register().unwrap();
    let held: Vec<_> = keys[..4]
        .iter()
        .map(|&n| {
            let lease = lookup(&mut reader, &key(n), RETRIES).unwrap();
            let ended = super::attempt_tests::invalidate(&storage, &key(n)).unwrap();
            (lease, ended.removed.unwrap().0)
        })
        .collect();
    let mut calls = 0;
    while reserve_big(&storage).is_err() {
        maintain(&storage);
        calls += 1;
        assert!(calls < 100);
    }
    for (_, id) in &held {
        assert_eq!(
            storage.slot_state(id.slot()).unwrap().0,
            super::tables::SlotState::Retired,
            "a held extent never returns while its lease is out"
        );
    }
    assert!(storage.domain_report().unwrap().detached >= 4);
    drop(held);
}

/// Grace blocked by a pinned reader and no leases: calls stop evicting once
/// `placeable_units + in_flight_units`, which at this fixture's one-unit
/// charge equals `free_units + in_flight_units`, reaches `low_units`, not
/// before and not at it, in flight stays within the watermarks' bound, and
/// with no claimable unit the report says blocked.
#[test]
fn a_blocked_grace_bounds_eviction_by_the_targets() {
    let target = 3;
    let storage = ready(target);
    fill_big(&storage);
    let mut pinned = storage.register().unwrap();
    let protected = pinned.enter().unwrap();
    let mut last = MaintainReport::default();
    for _ in 0..60 {
        last = maintain(&storage);
        let domain = storage.domain_report().unwrap();
        // The unit watermark, the slot watermark and one call's victim.
        assert!(domain.in_flight as u64 <= target + 1 + 1, "{domain:?}");
    }
    let domain = storage.domain_report().unwrap();
    // The full volume keeps its one-unit reserve free, which counts toward
    // the target beside the units in flight.
    assert_eq!((domain.free_units, domain.claimable_units), (1, 0));
    assert_eq!(domain.in_flight_units, target - 1);
    assert_eq!(domain.in_flight as u64, target - 1);
    // In-flight and detached capacity is never reservable.
    assert!(matches!(
        reserve_big(&storage),
        Err(ReserveError::CleanReserve)
    ));
    let before = storage.maintain_totals().evicted;
    for _ in 0..10 {
        last = maintain(&storage);
    }
    assert_eq!(
        storage.maintain_totals().evicted,
        before,
        "eviction stopped at target"
    );
    if last.domain.is_some() {
        assert!(last.blocked_by_readers_or_io);
    }
    let mut saw_blocked = false;
    for _ in 0..10 {
        let report = maintain(&storage);
        saw_blocked |= report.blocked_by_readers_or_io && report.domain.is_some();
    }
    assert!(saw_blocked);
    drop(protected);
}

/// Budgets 0, 1 and one short of the minimum refuse before the root gate
/// with nothing debited and no cursor moved; the minimum runs the stage the
/// cursor stands in, from every starting stage, and the cursor moves past
/// what ran; a large budget runs every stage once.
#[test]
fn the_minimum_runs_one_stage_and_less_runs_none() {
    let storage = ready(2);
    fill_big(&storage);
    let minimum = storage.maintain_minimum();
    for allowance in [0, 1, minimum - 1] {
        let mut spent = WorkBudget::new(allowance);
        assert_eq!(
            storage.maintain(&mut spent),
            Err(MaintainError::BudgetExhausted)
        );
        assert_eq!(spent.counters(), WorkBudget::new(0).counters());
    }
    let mut stage = MaintainStage::Fills;
    for _ in 0..5 {
        let report = open(storage.maintain(&mut WorkBudget::new(minimum)));
        assert_eq!(report.started_in, stage);
        let ran = stages_ran(&report);
        // The starting stage decided; the call stops in front of the first
        // stage it cannot fund, where the next call starts, or after one
        // pass over all five, which leaves the cursor where it started.
        assert!(ran[stage as usize], "{report:?}");
        assert!(
            report.budget_exhausted && report.more_work || ran.iter().all(|&ran| ran),
            "{report:?}"
        );
        let mut next = stage as usize;
        while ran[next % 5] && next < stage as usize + 5 {
            next += 1;
        }
        stage = MaintainStage::ALL[next % 5];
    }
    // Every stage as the starting one decides at the minimum, from a full
    // volume with nothing in flight, so headroom has a victim to give.
    let mut next_key = 100;
    for start in MaintainStage::ALL {
        refill(&storage, &mut next_key);
        storage
            .maintain
            .stage
            .store(start as usize, std::sync::atomic::Ordering::Relaxed);
        let report = open(storage.maintain(&mut WorkBudget::new(minimum)));
        assert_eq!(report.started_in, start);
        let stages = [
            report.fills,
            report.certify,
            report.reclaim,
            report.expiry,
            report.headroom,
        ];
        // The starting stage made at least one decision: a stage minimum
        // short of what one decision needs would stop it before any.
        let stage = stages[start as usize];
        assert!(stage.ran, "{start:?}: {report:?}");
        match start {
            MaintainStage::Fills | MaintainStage::Reclaim | MaintainStage::Expiry => {
                assert!(stage.visited > 0 || stage.done, "{start:?}: {report:?}");
            }
            MaintainStage::Certify => {}
            MaintainStage::Headroom => {
                assert_eq!(
                    report.evicted, 1,
                    "the full volume gave a victim: {report:?}"
                );
            }
        }
    }
    let report = open(storage.maintain(&mut WorkBudget::new(usize::MAX)));
    assert!(report.fills.ran && report.headroom.ran && !report.budget_exhausted);
    let report = maintain(&storage);
    assert!(
        report.fills.ran
            && report.reclaim.ran
            && report.certify.ran
            && report.expiry.ran
            && report.headroom.ran
    );
}

/// A second caller finds the root gate held: `Contended`, one attempt
/// charged, nothing else.
#[test]
fn a_second_caller_is_contended_for_one_attempt() {
    let storage = ready(2);
    let guard = storage.maintain.gate.try_lock().unwrap();
    let mut spent = generous();
    let stage = storage
        .maintain
        .stage
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(storage.maintain(&mut spent), Err(MaintainError::Contended));
    assert_eq!(
        storage
            .maintain
            .stage
            .load(std::sync::atomic::Ordering::Relaxed),
        stage
    );
    assert_eq!(spent.counters().coordination_attempts, 1);
    assert_eq!(spent.remaining(), (1 << 16) - 1);
    drop(guard);
    maintain(&storage);
}

thread_local! {
    static AT: Cell<Option<MaintainStage>> = const { Cell::new(None) };
    static STORAGE: Cell<Option<&'static Storage<TestPlatform>>> = const { Cell::new(None) };
}

/// Bounds outside the storage module use this count because `MaintainStage::ALL` is private.
pub(crate) const MAINTAIN_STAGES: usize = MaintainStage::ALL.len();

/// While `f` runs, maintenance calls on this thread reset `storage`'s saved stage cursor to `MaintainStage::Expiry` before `MaintainStage::Reclaim`.
/// The hook and the storage reference clear when `f` returns or unwinds.
pub(crate) fn with_restarting_stage_cursor<T>(
    storage: &'static Storage<TestPlatform>,
    f: impl FnOnce() -> T,
) -> T {
    struct Clear;
    impl Drop for Clear {
        fn drop(&mut self) {
            INTERPOSE_BEFORE_STAGE.with(|hook| hook.set(None));
            STORAGE.with(|cell| cell.set(None));
        }
    }
    assert!(
        INTERPOSE_BEFORE_STAGE.with(Cell::get).is_none(),
        "no other stage hook is installed on this thread"
    );
    STORAGE.with(|cell| cell.set(Some(storage)));
    INTERPOSE_BEFORE_STAGE.with(|hook| {
        hook.set(Some(|stage| {
            if stage == MaintainStage::Reclaim
                && let Some(storage) = STORAGE.with(Cell::get)
            {
                storage.maintain.stage.store(
                    MaintainStage::Expiry as usize,
                    std::sync::atomic::Ordering::Relaxed,
                );
            }
        }))
    });
    let _clear = Clear;
    f()
}

/// A panic inside a call poisons the root gate: later calls refuse
/// `Poisoned`, while reservation, close and the close service's drain keep
/// working through to a drained finalization.
#[test]
fn a_panic_inside_maintenance_poisons_only_maintenance() {
    let mut storage = ready(2);
    publish_big(&storage, 1);
    INTERPOSE_BEFORE_STAGE.with(|hook| {
        hook.set(Some(|stage| {
            if stage == MaintainStage::Certify {
                panic!("a stage panicked");
            }
        }))
    });
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        storage.maintain(&mut generous())
    }));
    INTERPOSE_BEFORE_STAGE.with(|hook| hook.set(None));
    assert!(unwound.is_err());
    assert_eq!(
        storage.maintain(&mut generous()),
        Err(MaintainError::Poisoned)
    );
    assert!(reserve_big(&storage).is_ok());
    storage.close();
    drain_closed(&storage);
    let domain = storage.domain_report().unwrap();
    assert_eq!(
        (domain.members, domain.detached, domain.in_flight),
        (0, 0, 0)
    );
    assert_eq!(
        super::test_platform::finalize(&mut storage),
        Ok(Finalization::Drained)
    );
}

/// A panic inside a call poisons the root gate (module doc, "A panic under
/// the root gate poisons it: later calls refuse `Poisoned`"), on a thread
/// that is not unwinding and from a destructor that catches the panic while
/// its thread unwinds from another: the guard, taken during the unwind,
/// would release open on drop.
#[test]
fn a_panic_inside_maintenance_poisons_the_root_gate_even_during_unwinding() {
    struct MaintainsOnDrop<'a> {
        storage: &'a Storage<TestPlatform>,
        panicked: &'a Cell<bool>,
    }
    impl Drop for MaintainsOnDrop<'_> {
        fn drop(&mut self) {
            let storage = self.storage;
            let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                storage.maintain(&mut generous()).map(|_| ())
            }));
            self.panicked.set(unwound.is_err());
        }
    }
    for unwinding in [false, true] {
        let storage = ready(2);
        publish_big(&storage, 1);
        INTERPOSE_BEFORE_STAGE.with(|hook| {
            hook.set(Some(|stage| {
                if stage == MaintainStage::Certify {
                    panic!("a stage panicked");
                }
            }))
        });
        let panicked = Cell::new(false);
        if unwinding {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _maintainer = MaintainsOnDrop {
                    storage: &storage,
                    panicked: &panicked,
                };
                panic!("an unrelated panic with a live maintainer");
            }));
            assert!(outcome.is_err());
        } else {
            drop(MaintainsOnDrop {
                storage: &storage,
                panicked: &panicked,
            });
        }
        INTERPOSE_BEFORE_STAGE.with(|hook| hook.set(None));
        assert!(
            panicked.get(),
            "premise: the call panicked, unwinding={unwinding}"
        );
        assert_eq!(
            storage.maintain(&mut generous()),
            Err(MaintainError::Poisoned),
            "unwinding={unwinding}"
        );
    }
}

/// Runs close service through maintenance until a call completes a pass.
fn drain_closed(storage: &Storage<TestPlatform>) -> ClosingReport {
    for _ in 0..20 {
        match storage.maintain(&mut generous()) {
            Ok(Maintained::Closed(report))
                if report.complete && report.blockers.held_slots == 0 =>
            {
                return report;
            }
            Ok(Maintained::Closed(_)) => {}
            other => panic!("expected the close service's report, got {other:?}"),
        }
    }
    panic!("close service never completed");
}

/// Interleaved ordinary service and certification, which share the
/// underlying cursors, never starve a stage: across funded minimum calls
/// every stage runs repeatedly.
///
/// Bound: the maintenance minimum covers the root attempt and the largest
/// stage minimum, so each call funded with at least it, here `minimum + 3`,
/// runs at least the stage at the cursor, and the cursor moves to the
/// next stage after each stage it runs whatever the other callers did. The
/// service and certification calls leave the persisted cursor where the
/// previous maintenance call left it, and each maintenance call starts
/// there. The stages therefore run in cycle order, each within one run of
/// every other, and `ROUNDS` calls run each of the five stages at least
/// `ROUNDS / 5` times.
#[test]
fn interleaved_callers_do_not_starve_any_stage() {
    interleaved_callers_starve_no_stage(Storage::maintain);
}

/// A maintenance call that does not start at the persisted cursor: it puts
/// the stage cursor back on Fills and then runs production maintenance.
fn maintain_from_the_first_stage(
    storage: &Storage<TestPlatform>,
    budget: &mut WorkBudget,
) -> Result<Maintained, MaintainError> {
    storage.maintain.stage.store(
        MaintainStage::Fills as usize,
        std::sync::atomic::Ordering::Relaxed,
    );
    storage.maintain(budget)
}

#[test]
#[should_panic(expected = "round 1: the call started away from the persisted cursor")]
fn negative_control_a_maintenance_call_that_ignores_the_persisted_cursor_fails_the_start_check() {
    interleaved_callers_starve_no_stage(maintain_from_the_first_stage);
}

/// The interleaved-callers test's history and checks, with `maintain` the
/// call under test: production [`Storage::maintain`] in the record test, the
/// call that ignores the cursor in its control.
fn interleaved_callers_starve_no_stage(
    maintain: impl Fn(&Storage<TestPlatform>, &mut WorkBudget) -> Result<Maintained, MaintainError>,
) {
    const ROUNDS: usize = 50;
    let storage = ready(2);
    fill_big(&storage);
    let minimum = storage.maintain_minimum();
    let mut runs = [0usize; MaintainStage::ALL.len()];
    let mut expected = persisted(&storage);
    for round in 0..ROUNDS {
        storage.service(&mut generous()).unwrap();
        let _ = storage.certify(&mut generous()).unwrap();
        assert_eq!(
            persisted(&storage),
            expected,
            "round {round}: the other callers moved the stage cursor"
        );
        let report = open(maintain(&storage, &mut WorkBudget::new(minimum + 3)));
        assert_eq!(
            report.started_in, expected,
            "round {round}: the call started away from the persisted cursor"
        );
        let (next, _) = contiguous_run(expected, &report);
        for (count, ran) in runs.iter_mut().zip(stages_ran(&report)) {
            *count += usize::from(ran);
        }
        expected = next;
        assert_eq!(persisted(&storage), expected, "round {round}");
    }
    let (low, high) = (runs.iter().min().unwrap(), runs.iter().max().unwrap());
    assert!(
        high - low <= 1,
        "the stages ran out of cycle order: {runs:?}"
    );
    let bound = ROUNDS / MaintainStage::ALL.len();
    for (stage, &count) in MaintainStage::ALL.iter().zip(&runs) {
        assert!(
            count >= bound,
            "{stage:?} ran {count} times, below {bound}: {runs:?}"
        );
    }
}

/// Closing at each stage boundary stops the call with its open report and
/// `more_work`; the next call returns the close service's report without
/// taking the root gate, and drains to `Drained` with every domain empty.
#[test]
fn a_close_at_each_stage_delegates_the_next_call() {
    for stage in MaintainStage::ALL {
        let storage: &'static Storage<TestPlatform> = Box::leak(Box::new(ready(2)));
        publish_big(storage, 1);
        // A retired, uncertified record is pending when close lands.
        publish_big(storage, 2);
        super::attempt_tests::invalidate(storage, &key(2)).unwrap();
        let free_before = storage.pool_report().unwrap().ledger.unwrap().raw.free;
        STORAGE.with(|cell| cell.set(Some(storage)));
        AT.with(|cell| cell.set(Some(stage)));
        INTERPOSE_BEFORE_STAGE.with(|hook| {
            hook.set(Some(|stage| {
                if AT.with(Cell::get) == Some(stage) {
                    STORAGE.with(Cell::get).unwrap().close();
                }
            }))
        });
        let report = maintain(storage);
        INTERPOSE_BEFORE_STAGE.with(|hook| hook.set(None));
        assert!(report.more_work, "{stage:?}");
        // The cursor stays at the boundary the close landed on.
        assert_eq!(persisted(storage), stage);
        // The call started at the first stage: every stage before the
        // boundary ran, and none from it on.
        let ran = stages_ran(&report);
        for (index, &ran) in ran.iter().enumerate() {
            assert_eq!(ran, index < stage as usize, "{stage:?}: {report:?}");
        }
        assert!(storage.is_closed());
        // The root gate is held: a delegated call must not try it.
        let guard = storage.maintain.gate.try_lock().unwrap();
        assert!(matches!(
            storage.maintain(&mut generous()),
            Ok(Maintained::Closed(_))
        ));
        drop(guard);
        drain_closed(storage);
        let domain = storage.domain_report().unwrap();
        assert_eq!(
            (domain.members, domain.detached, domain.in_flight),
            (0, 0, 0)
        );
        // The pending record's custody passed to the close service, which
        // returned its extent.
        let pool = storage.pool_report().unwrap();
        assert_eq!(pool.pending_marks, 0, "{stage:?}");
        let ledger = pool.ledger.unwrap();
        assert_eq!(ledger.slots.retired, 0, "{stage:?}");
        assert!(ledger.raw.free > free_before, "{stage:?}");
        assert_eq!(
            ledger.raw.free,
            UNITS * crate::storage::IO_UNIT,
            "{stage:?}"
        );
    }
}

/// Watermarks are validated with no default: `low_units` below the reserve
/// plus the largest record (here one unit each) or above the volume's units
/// and `min_free_slots` of zero or `O` are refused before any mapping. A storage without watermarks refuses maintenance.
#[test]
fn watermarks_are_required_and_checked() {
    let check = |marks: VolumeWatermarks| {
        let mut config = storage_config(SLOTS);
        config.volume.raw_bytes =
            (UNITS + crate::storage::TEST_METADATA_UNITS as usize) * crate::storage::IO_UNIT;
        config.volume.maintenance = Some(marks);
        config.validate().err()
    };
    for low_units in [0, 1, UNITS as u64 + 1] {
        assert_eq!(
            check(watermarks(low_units, 1)),
            Some(ConfigError::LowUnitsOutOfRange { low_units })
        );
    }
    for slots in [0, SLOTS] {
        assert_eq!(
            check(watermarks(2, slots)),
            Some(ConfigError::MinFreeSlotsOutOfRange {
                min_free_slots: slots
            })
        );
    }
    assert_eq!(check(watermarks(2, 1)), None);
    assert_eq!(check(watermarks(UNITS as u64, SLOTS - 1)), None);
    let unconfigured = storage_with(None);
    assert_eq!(
        unconfigured.maintain(&mut generous()),
        Err(MaintainError::NotConfigured)
    );
}

/// A storage without watermarks has no headroom domain to read:
/// `domain_report` is `None`, and the read leaves the pool gate usable for
/// reservations.
#[test]
fn a_storage_without_watermarks_reports_no_domain() {
    let storage = storage_with(None);
    assert_eq!(storage.domain_report(), None);
    assert!(reserve_big(&storage).is_ok());
}

/// The headroom step runs while `placeable_units + in_flight_units <
/// low_units` with members present, and not once the sum reaches
/// `low_units`; at this fixture's one-unit charge the placeable units equal
/// the free units, so with `low_units` free units left there is no
/// eviction, and one fewer draws one.
#[test]
fn headroom_runs_below_the_unit_watermark_and_not_at_it() {
    let low = 4;
    let storage = ready(low);
    for n in 1..=(UNITS as u64 - low) as u8 {
        publish_big(&storage, n);
    }
    let at = storage.domain_report().unwrap();
    assert_eq!((at.free_units, at.in_flight_units), (low, 0));
    for _ in 0..20 {
        maintain(&storage);
    }
    assert_eq!(
        storage.maintain_totals().evicted,
        0,
        "evicted at the watermark"
    );
    publish_big(&storage, 100);
    let below = storage.domain_report().unwrap();
    assert_eq!(below.free_units, low - 1);
    let mut calls = 0;
    while storage.maintain_totals().evicted == 0 {
        maintain(&storage);
        calls += 1;
        assert!(calls < 20, "no eviction below the watermark");
    }
    // One eviction's unit in flight or returned brings the sum back to the
    // watermark, and no second eviction follows.
    for _ in 0..20 {
        maintain(&storage);
    }
    assert_eq!(storage.maintain_totals().evicted, 1);
    let after = storage.domain_report().unwrap();
    assert_eq!(after.free_units + after.in_flight_units, low);
    // With no reader pinned, grace and service return the victim: its units
    // leave `in_flight_units` exactly when they rejoin the free units.
    assert_eq!((after.in_flight, after.in_flight_units), (0, 0));
    assert_eq!(after.free_units, low);
}

/// A promise of every claimable unit refuses direct claims, and maintenance
/// evicts while the promise holds, so the volume recovers claimable units
/// beside it. The volume's one 65-unit free run counts one 63-unit charge,
/// so it reads short before the promise as well.
#[test]
fn maintenance_recovers_claimable_units_while_a_promise_holds() {
    // A two-extent object, the largest the storage admits: 63 units and 1.
    let two = EXTENT_PAYLOAD as usize + 1000;
    // Seven units of record behind the four metadata bytes `publish` adds.
    let seven = 7 * crate::storage::IO_UNIT - 300;
    // The one-unit reserve plus the largest object's charge.
    let low = 65;
    let storage = storage_arena(135, Some(watermarks(low, 1)), two, 1, 1, SLOTS);
    for n in 1..=10 {
        super::lookup_tests::publish(&storage, key(n), u64::MAX, &vec![n; seven]);
    }
    let at = storage.domain_report().unwrap();
    assert_eq!((at.free_units, at.claimable_units), (low, low - 1));
    let builder = storage
        .promise(Some(0), Some(two), &mut generous())
        .unwrap();
    assert_eq!(builder.remaining(), low - 1);
    let promised = storage.domain_report().unwrap();
    assert_eq!((promised.free_units, promised.claimable_units), (low, 0));
    assert_eq!(reserve_big(&storage), Err(ReserveError::CleanReserve));
    let mut calls = 0;
    while storage.maintain_totals().evicted == 0 {
        maintain(&storage);
        calls += 1;
        assert!(calls < 20, "no eviction with every claimable unit promised");
    }
    // The victim's units return with no reader pinned, and a direct claim
    // passes again beside the promise.
    for _ in 0..20 {
        maintain(&storage);
    }
    assert!(storage.domain_report().unwrap().claimable_units > 0);
    reserve_big(&storage).unwrap();
    drop(builder);
}

/// Under a pinned reader the evicted extent stays in flight: its units count
/// in `in_flight_units` from the mark until its return, and only then move
/// to the free units. The victim, the oldest resident, spans two units, so
/// the unit count differs from the extent count. The reserve's free unit
/// holds no two-unit charge, so a four-unit target takes the victim and the
/// two one-unit residents after it, and their returned units form one
/// four-unit run at the watermark.
#[test]
fn in_flight_units_count_an_evicted_extent_until_its_return() {
    let storage = storage_capped(UNITS, Some(watermarks(4, 1)), crate::storage::IO_UNIT + 1);
    let wide = vec![0; crate::storage::IO_UNIT + 1];
    super::lookup_tests::publish(&storage, key(200), u64::MAX, &wide);
    fill_big(&storage);
    let mut pinned = storage.register().unwrap();
    let protected = pinned.enter().unwrap();
    let mut calls = 0;
    while storage.domain_report().unwrap().in_flight_units == 0 {
        maintain(&storage);
        calls += 1;
        assert!(calls < 40, "no eviction reached its mark");
    }
    for _ in 0..10 {
        maintain(&storage);
    }
    let held = storage.domain_report().unwrap();
    assert_eq!(
        (held.in_flight, held.in_flight_units, held.free_units),
        (3, 4, 1)
    );
    drop(protected);
    let mut calls = 0;
    while storage.domain_report().unwrap().in_flight_units != 0 {
        maintain(&storage);
        calls += 1;
        assert!(calls < 40, "the return never cleared the in-flight units");
    }
    let returned = storage.domain_report().unwrap();
    assert_eq!(
        (
            returned.in_flight,
            returned.in_flight_units,
            returned.free_units
        ),
        (0, 0, 5)
    );
}

/// Reports are this call's exact counts and flags come from exact state: a
/// planted maximum in the evicted, short-stage and evicted-unit totals
/// saturates each and leaves the reports of an identical history equal.
#[test]
fn a_saturated_total_changes_no_report() {
    let run = |planted: bool| {
        let mut storage = ready(2);
        storage.install_hasher(crate::index::KeyHasher::with_key_pair(
            0x5eed_0001,
            0x5eed_0002,
        ));
        fill_big(&storage);
        if planted {
            let cursor = &storage.maintain;
            for total in [&cursor.evicted, &cursor.short_stages, &cursor.evicted_units] {
                total.store(u64::MAX, std::sync::atomic::Ordering::Relaxed);
            }
        }
        let reports: Vec<_> = (0..12).map(|_| maintain(&storage)).collect();
        (reports, storage.maintain_totals())
    };
    let (plain, totals) = run(false);
    let (planted, saturated) = run(true);
    assert_eq!(plain, planted);
    let evicted = totals.evicted;
    assert!(evicted > 0);
    assert!(totals.short_stages >= evicted && totals.evicted_units >= evicted);
    assert_eq!(
        (
            saturated.evicted,
            saturated.short_stages,
            saturated.evicted_units
        ),
        (u64::MAX, u64::MAX, u64::MAX)
    );
    assert_eq!(
        plain
            .iter()
            .map(|report| report.evicted as u64)
            .sum::<u64>(),
        evicted
    );
}

/// A busy inner gate is counted and skipped, never waited on: with the pool
/// gate held, the slot, expiry and headroom stages each count it and the
/// cursor still moves past every stage. The expiry stage tries the gate
/// because a resident's deadline has passed; with no deadline at or below
/// the sample it needs no gate and is done without an attempt.
#[test]
fn a_busy_inner_gate_is_counted_and_skipped() {
    let storage = ready(2);
    super::lookup_tests::publish(&storage, key(200), 5, &[9; 100]);
    fill_big(&storage);
    storage.platform.ticks(&[Some(5)]);
    let live = storage.live_pool().unwrap();
    let guard = live.try_lock().unwrap();
    let report = maintain(&storage);
    drop(guard);
    assert!(report.contended >= 3, "{report:?}");
    assert!(report.reclaim.ran && report.expiry.ran && report.headroom.ran);
    assert!(!report.reclaim.done && !report.expiry.done && !report.headroom.done);
    assert_eq!(
        storage
            .maintain
            .stage
            .load(std::sync::atomic::Ordering::Relaxed),
        MaintainStage::Fills as usize,
        "the cursor passed every stage"
    );

    let undated = ready(2);
    fill_big(&undated);
    let live = undated.live_pool().unwrap();
    let guard = live.try_lock().unwrap();
    let report = maintain(&undated);
    drop(guard);
    assert_eq!(report.contended, 2, "{report:?}");
    assert!(report.expiry.ran && report.expiry.done, "{report:?}");
    assert!(!report.reclaim.done && !report.headroom.done);
}

/// A poisoned grace maintenance gate closes admission as certification
/// does: the call reports the stall, and the next call delegates to the
/// close service.
#[test]
fn a_poisoned_grace_gate_closes_admission_and_the_next_call_delegates() {
    let storage = ready(2);
    storage.maintenance_gate().try_lock().unwrap().poison();
    let report = maintain(&storage);
    assert_eq!(
        report.certify_stall,
        Some(super::maintain::CertifyStall::Poisoned)
    );
    assert!(storage.is_closed());
    assert!(matches!(
        storage.maintain(&mut generous()),
        Ok(Maintained::Closed(_))
    ));
}

/// A caller that funds calls only while `more_work` is set still recovers
/// the short volume, whichever stage the cursor starts in.
#[test]
fn funding_while_more_work_recovers_the_short_volume() {
    for start in MaintainStage::ALL {
        let storage = ready(2);
        storage
            .maintain
            .stage
            .store(start as usize, std::sync::atomic::Ordering::Relaxed);
        fill_big(&storage);
        let mut calls = 0;
        while maintain(&storage).more_work {
            calls += 1;
            assert!(calls < 200, "more_work never cleared");
        }
        assert!(reserve_big(&storage).is_ok(), "start {start:?}");
    }
}

/// Funding while `more_work` is set restores reservable capacity at the
/// smallest watermark, the reserve plus the largest record.
#[test]
fn funding_while_more_work_recovers_a_single_unit() {
    let storage = ready(2);
    fill_big(&storage);
    assert!(reserve_big(&storage).is_err());
    let mut calls = 0;
    while maintain(&storage).more_work {
        calls += 1;
        assert!(calls < 200, "more_work never cleared");
    }
    assert!(reserve_big(&storage).is_ok());
}

/// The grace-blocked reading holds at the minimum budget too, where a call
/// runs about one stage: the flag reads the last certification call's
/// outcome, not only this call's.
#[test]
fn a_blocked_grace_is_reported_to_a_minimally_funded_caller() {
    let storage = ready(3);
    fill_big(&storage);
    let mut pinned = storage.register().unwrap();
    let protected = pinned.enter().unwrap();
    for _ in 0..60 {
        maintain(&storage);
    }
    let minimum = storage.maintain_minimum();
    let mut saw = false;
    for _ in 0..40 {
        let report = open(storage.maintain(&mut WorkBudget::new(minimum)));
        saw |= report.headroom.ran && report.domain.is_some() && report.blocked_by_readers_or_io;
    }
    assert!(saw);
    drop(protected);
}

/// Every eviction and expiry a report counts is one extent newly in flight:
/// with grace held by a pinned reader nothing returns, so the domain's
/// in-flight count, read independently under the pool gate, rises by
/// exactly the report's removals on every call. Removals stop at the
/// target less the reserve unit the full volume keeps free.
#[test]
fn report_counts_equal_the_in_flight_the_ledger_shows() {
    let storage = ready(6);
    fill_big(&storage);
    let mut pinned = storage.register().unwrap();
    let protected = pinned.enter().unwrap();
    let mut removed = 0;
    for _ in 0..30 {
        let before = storage.domain_report().unwrap().in_flight;
        let report = maintain(&storage);
        let after = storage.domain_report().unwrap().in_flight;
        assert_eq!(
            after - before,
            report.evicted + report.expired,
            "{report:?}"
        );
        removed += report.evicted;
    }
    assert!(removed >= 5);
    drop(protected);
}

/// With the era at the certificate, the certify stage decides from its
/// reads and leaves the grace gate alone, so a held gate goes unnoticed;
/// once a retirement raises the era, the stage tries the gate and records
/// it busy.
#[test]
fn certification_at_the_certificate_tries_no_gate() {
    let storage = ready(2);
    let id = super::lookup_tests::publish(&storage, key(1), u64::MAX, &[1; 20]);
    while maintain(&storage).more_work {}
    let grace = storage.maintenance_gate().try_lock().unwrap();
    let report = maintain(&storage);
    assert_eq!(
        (report.certify_stall, report.contended, report.certify.done),
        (Some(super::maintain::CertifyStall::NoProgress), 0, true),
        "{report:?}"
    );
    super::lookup_tests::remove(&storage, &key(1), id);
    let report = maintain(&storage);
    assert_eq!(
        (report.certify_stall, report.contended, report.certify.done),
        (Some(super::maintain::CertifyStall::Busy), 1, false),
        "{report:?}"
    );
    drop(grace);
    let report = maintain(&storage);
    assert_eq!(report.certify_stall, None, "the pass certifies: {report:?}");
}

/// A held shard gate and a held grace gate are counted and skipped: fill
/// service and certification record the busy attempt, and the cursor moves
/// on to the next stage.
#[test]
fn busy_shard_and_grace_gates_are_counted_and_skipped() {
    let storage = ready(2);
    // A live attempt occupies a record, so the table needs its gated pass.
    let attempt = super::attempt_tests::begin(&storage, &key(1)).unwrap();
    let shard = super::attempt_tests::gate(&storage).try_lock().unwrap();
    let grace = storage.maintenance_gate().try_lock().unwrap();
    let report = maintain(&storage);
    drop((shard, grace));
    assert!(report.fills.ran && !report.fills.done);
    assert_eq!(report.fill_tables, 1);
    assert_eq!(
        report.certify_stall,
        Some(super::maintain::CertifyStall::Busy)
    );
    assert!(report.contended >= 2, "{report:?}");
    assert!(report.headroom.ran, "the stages after them still ran");
    attempt.abort();
}

/// Slot pressure under blocked grace: with free slots below the watermark,
/// headroom evicts until free plus in-flight slots reach it and then stops,
/// within the watermarks' bound.
#[test]
fn slot_pressure_evicts_up_to_the_slot_watermark_and_stops() {
    let min_free_slots = SLOTS - 10;
    let storage = storage_with(Some(watermarks(2, min_free_slots)));
    let published = fill_big(&storage).len();
    assert!(SLOTS - published < min_free_slots);
    let mut pinned = storage.register().unwrap();
    let protected = pinned.enter().unwrap();
    for _ in 0..80 {
        maintain(&storage);
        let domain = storage.domain_report().unwrap();
        assert!(domain.in_flight <= 1 + 1 + min_free_slots + 1, "{domain:?}");
    }
    let domain = storage.domain_report().unwrap();
    assert!(
        domain.free_slots + domain.in_flight >= min_free_slots,
        "{domain:?}"
    );
    let stopped = storage.maintain_totals().evicted;
    for _ in 0..10 {
        maintain(&storage);
    }
    assert_eq!(storage.maintain_totals().evicted, stopped);
    drop(protected);
}

/// The blocked reading clears once grace moves: with the pinned reader gone,
/// certification advances, the in-flight extents return, and no later call
/// reports blocked.
#[test]
fn the_blocked_reading_clears_once_grace_moves() {
    let storage = ready(3);
    fill_big(&storage);
    let mut pinned = storage.register().unwrap();
    let protected = pinned.enter().unwrap();
    for _ in 0..40 {
        maintain(&storage);
    }
    drop(protected);
    for _ in 0..20 {
        maintain(&storage);
    }
    for _ in 0..10 {
        assert!(!maintain(&storage).blocked_by_readers_or_io);
    }
    assert!(reserve_big(&storage).is_ok());
}

/// A poisoned pool gate is counted and skipped for good: a caller that funds
/// while `more_work` is set stops after a clean run instead of spinning.
#[test]
fn a_poisoned_pool_gate_does_not_hold_more_work_forever() {
    let storage = ready(2);
    let live = storage.live_pool().unwrap();
    // A holder that panics poisons the gate.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = live.try_lock().unwrap();
        panic!("a holder panicked");
    }));
    assert!(live.try_lock().is_err());
    let mut calls = 0;
    while maintain(&storage).more_work {
        calls += 1;
        assert!(calls < 50, "more_work never cleared");
    }
}

/// After a quiet stretch reported done, a volume that falls short is found
/// again: each "done" starts a new run, so a caller that funds after
/// `CleanReserve` and while `more_work` is set reaches the short domain.
#[test]
fn a_volume_short_after_a_quiet_stretch_is_recovered() {
    for start in 0..2 {
        let storage = ready(2);
        let mut calls = 0;
        while maintain(&storage).more_work {
            calls += 1;
            assert!(calls < 50);
        }
        fill_big(&storage);
        assert!(reserve_big(&storage).is_err());
        let mut calls = 0;
        while maintain(&storage).more_work {
            calls += 1;
            assert!(calls < 200);
        }
        assert!(reserve_big(&storage).is_ok(), "start {start}");
    }
}

/// A short volume whose candidates sit in a poisoned shard never commits: the
/// refusal is counted, and a caller funding while `more_work` is set stops.
#[test]
fn a_poisoned_shard_gate_does_not_hold_more_work_forever() {
    let storage = ready(2);
    fill_big(&storage);
    super::attempt_tests::gate(&storage)
        .try_lock()
        .unwrap()
        .poison();
    let mut calls = 0;
    let mut contended = 0;
    loop {
        let report = maintain(&storage);
        contended += report.contended;
        if !report.more_work {
            break;
        }
        calls += 1;
        assert!(calls < 50, "more_work never cleared");
    }
    assert!(contended > 0);
    assert_eq!(storage.maintain_totals().evicted, 0);
}

/// Headroom reaches a healthy shard's members when a poisoned shard of two
/// holds the two oldest: a caller funding while `more_work` is set evicts
/// one of them before `more_work` clears.
#[test]
fn a_poisoned_shard_leaves_more_work_while_a_healthy_shard_can_evict() {
    let storage = storage_sharded(
        UNITS,
        Some(watermarks(2, 1)),
        storage_config(SLOTS).body_cap,
        2,
    );
    let poisoned = |n: u8| storage.route(&key(n)).unwrap().shard() == ShardIndex(0);
    let oldest: Vec<u8> = (1..=u8::MAX).filter(|&n| poisoned(n)).take(2).collect();
    for &n in &oldest {
        publish_big(&storage, n);
    }
    let mut healthy = 0;
    let mut next = 1;
    while storage.pool_report().unwrap().ledger.unwrap().raw.free != RESERVE {
        if !oldest.contains(&next) {
            publish_big(&storage, next);
            healthy += usize::from(!poisoned(next));
        }
        next += 1;
    }
    assert!(
        healthy > 0,
        "the fill placed no member in the healthy shard"
    );
    super::attempt_tests::gate(&storage)
        .try_lock()
        .unwrap()
        .poison();
    let mut calls = 0;
    while maintain(&storage).more_work {
        calls += 1;
        assert!(calls < 50, "more_work never cleared");
    }
    assert!(
        storage.maintain_totals().evicted >= 1,
        "maintenance reported no work while a healthy shard's member could evict"
    );
}

/// A headroom commit refused by a poisoned shard still reports what its
/// selection retained: the counts equal those of the same selection over a
/// healthy shard, where the commit evicts.
#[test]
fn a_poisoned_commit_reports_its_selections_counts() {
    let first_big_eviction = |poison: bool| {
        let storage = ready(2);
        let keys = fill_big(&storage);
        let mut reader = storage.register().unwrap();
        let (_, older) = keys.split_last().unwrap();
        let leases: Vec<_> = older
            .iter()
            .map(|&n| lookup(&mut reader, &key(n), RETRIES).unwrap())
            .collect();
        if poison {
            super::attempt_tests::gate(&storage)
                .try_lock()
                .unwrap()
                .poison();
        }
        let report = (0..8)
            .map(|_| maintain(&storage))
            .find(|report| report.headroom.visited > 0 && report.domain.is_some())
            .expect("headroom selects in the short volume");
        drop(leases);
        report
    };
    let counts = |report: &MaintainReport| {
        (
            report.held,
            report.unpublished,
            report.detached_seen,
            report.stale_marks,
        )
    };
    let healthy = first_big_eviction(false);
    let poisoned = first_big_eviction(true);
    assert_eq!((healthy.evicted, poisoned.evicted), (1, 0));
    assert!(healthy.held > 0);
    assert_eq!(counts(&poisoned), counts(&healthy));
}

/// An expiry commit refused `Corrupt` counts as contended, as a headroom
/// commit's does, and leaves the stage unfinished: the report says the shard
/// was poisoned and nothing was expired.
#[test]
fn a_corrupt_expiry_commit_is_counted() {
    let storage = ready(2);
    // Deadline 1 at the sticky sample 1: expired by equality.
    super::lookup_tests::publish(&storage, key(1), 1, &[1; 100]);
    // A found pair with `V` zero refuses removal `Corrupt`.
    super::attempt_tests::shard_control(&storage)
        .visible
        .store(0, std::sync::atomic::Ordering::Relaxed);
    let report = maintain(&storage);
    assert!(report.expiry.visited > 0, "{report:?}");
    assert_eq!(report.expired, 0, "{report:?}");
    assert!(report.contended > 0, "{report:?}");
    assert!(!report.expiry.done, "{report:?}");
}

/// A headroom commit that finds the shard gate busy counts as contended and
/// leaves the stage unfinished.
#[test]
fn a_contended_headroom_commit_leaves_the_stage_unfinished() {
    let storage = ready(2);
    fill_big(&storage);
    storage.maintain.stage.store(
        MaintainStage::Headroom as usize,
        std::sync::atomic::Ordering::Relaxed,
    );
    let shard = super::attempt_tests::gate(&storage).try_lock().unwrap();
    let report = open(storage.maintain(&mut WorkBudget::new(storage.maintain_minimum())));
    drop(shard);
    assert!(
        report.headroom.ran && report.headroom.visited > 0,
        "{report:?}"
    );
    assert_eq!(report.evicted, 0, "{report:?}");
    assert!(report.contended > 0 && !report.headroom.done, "{report:?}");
}

/// Headroom's predicate is charged only once its pool gate opens: a busy
/// gate costs the attempt alone, as every inner gate does. The call is
/// closed at the next stage so nothing else is charged.
#[test]
fn a_busy_pool_gate_charges_headroom_only_the_attempt() {
    let storage: &'static Storage<TestPlatform> = Box::leak(Box::new(ready(2)));
    storage.maintain.stage.store(
        MaintainStage::Headroom as usize,
        std::sync::atomic::Ordering::Relaxed,
    );
    STORAGE.with(|cell| cell.set(Some(storage)));
    AT.with(|cell| cell.set(Some(MaintainStage::Fills)));
    INTERPOSE_BEFORE_STAGE.with(|hook| {
        hook.set(Some(|stage| {
            if AT.with(Cell::get) == Some(stage) {
                STORAGE.with(Cell::get).unwrap().close();
            }
        }))
    });
    let live = storage.live_pool().unwrap();
    let held = live.lock().unwrap();
    let mut spent = generous();
    let report = open(storage.maintain(&mut spent));
    drop(held);
    INTERPOSE_BEFORE_STAGE.with(|hook| hook.set(None));
    assert_eq!(
        (report.started_in, report.contended),
        (MaintainStage::Headroom, 1),
        "{report:?}"
    );
    // The root gate's attempt and the pool gate's.
    assert_eq!(
        spent.counters().coordination_attempts,
        2,
        "{:?}",
        spent.counters()
    );
    assert_eq!(spent.counters().comparisons, 0, "{:?}", spent.counters());
}

/// One volume and one shard: `cover` is one, so one clean call
/// reports done. An expiry candidate invalidated between selection and
/// commit is `Absent`, and the sweep stopped at it, so the call still has
/// work: the expired resident behind it is unvisited.
#[test]
fn an_absent_expiry_commit_keeps_more_work() {
    let storage: &'static Storage<TestPlatform> =
        Box::leak(Box::new(storage_on(4, Some(watermarks(2, 1)))));
    super::lookup_tests::publish(storage, key(1), 10 * 1_000_000_000, &[1; 100]);
    super::lookup_tests::publish(storage, key(2), 10 * 1_000_000_000, &[2; 100]);
    // Settle every other stage before the deadline passes.
    let mut calls = 0;
    while maintain(storage).more_work {
        calls += 1;
        assert!(calls < 50, "more_work never cleared");
    }
    storage.platform.ticks(&[Some(10 * 1_000_000_000)]);
    STORAGE.with(|cell| cell.set(Some(storage)));
    super::evict::INTERPOSE_BEFORE_COMMIT.with(|hook| {
        hook.set(Some(|| {
            let storage = STORAGE.with(Cell::get).unwrap();
            super::attempt_tests::invalidate(storage, &key(1)).unwrap();
        }))
    });
    let report = maintain(storage);
    assert_eq!(report.expired, 0, "{report:?}");
    assert!(report.more_work, "{report:?}");
}

/// Extents returned between headroom's call and its selection hold satisfy
/// the watermark first: the stage decides from the state its selection
/// holds, so no resident is evicted.
#[test]
fn headroom_decides_from_the_state_its_selection_holds() {
    let storage: &'static Storage<TestPlatform> = Box::leak(Box::new(ready(2)));
    fill_big(storage);
    storage.maintain.stage.store(
        MaintainStage::Headroom as usize,
        std::sync::atomic::Ordering::Relaxed,
    );
    STORAGE.with(|cell| cell.set(Some(storage)));
    INTERPOSE_BEFORE_HEADROOM_SELECT.with(|hook| {
        hook.set(Some(|| {
            let storage = STORAGE.with(Cell::get).unwrap();
            for n in [1, 2] {
                super::attempt_tests::invalidate(storage, &key(n)).unwrap();
            }
            let _ = storage.certify(&mut generous()).unwrap();
            storage.service(&mut generous()).unwrap();
        }))
    });
    let report = maintain(storage);
    assert!(report.headroom.ran && report.domain.is_some(), "{report:?}");
    assert_eq!(report.evicted, 0, "{report:?}");
}

/// The minimum is a property of the configuration: it reads no mapping, so
/// a drained owner still answers it, with the value it gave while live.
#[test]
fn the_minimum_survives_finalization() {
    let mut storage = ready(2);
    let minimum = storage.maintain_minimum();
    storage.close();
    drain_closed(&storage);
    assert_eq!(
        super::test_platform::finalize(&mut storage),
        Ok(Finalization::Drained)
    );
    assert_eq!(storage.maintain_minimum(), minimum);
}

/// A stale pending mark applied by headroom's selection hold is counted even
/// when the domain meets its watermarks and no victim is chosen.
#[test]
fn a_stale_mark_is_counted_on_satisfied_headroom() {
    let storage = ready(2);
    storage.maintain.stage.store(
        MaintainStage::Headroom as usize,
        std::sync::atomic::Ordering::Relaxed,
    );
    // A mark for an incarnation slot 0 never had: stale when applied.
    storage.live_pool().unwrap().pending_mark().set(0, u32::MAX);
    let report = open(storage.maintain(&mut WorkBudget::new(storage.maintain_minimum())));
    assert_eq!(report.started_in, MaintainStage::Headroom);
    assert!(report.headroom.done && report.evicted == 0, "{report:?}");
    assert_eq!(report.stale_marks, 1, "{report:?}");
}

fn persisted(storage: &Storage<TestPlatform>) -> MaintainStage {
    MaintainStage::ALL[storage
        .maintain
        .stage
        .load(std::sync::atomic::Ordering::Relaxed)]
}

fn stages_ran(report: &MaintainReport) -> [bool; 5] {
    [
        report.fills.ran,
        report.certify.ran,
        report.reclaim.ran,
        report.expiry.ran,
        report.headroom.ran,
    ]
}

fn contiguous_run(start: MaintainStage, report: &MaintainReport) -> (MaintainStage, usize) {
    let ran = stages_ran(report);
    let mut next = start as usize;
    let mut count = 0;
    while count < 5 && ran[next % 5] {
        next += 1;
        count += 1;
    }
    assert!(count >= 1, "{start:?}: {report:?}");
    assert_eq!(
        ran.iter().filter(|&&r| r).count(),
        count,
        "{start:?}: a stage outside the run ran: {report:?}"
    );
    (MaintainStage::ALL[next % 5], count)
}

/// From every persisted start, calls funded at the maintenance minimum run
/// a contiguous run of stages in the cycle Fills, Certify, Reclaim, Expiry,
/// Headroom, stop in front of the first they cannot fund with CPU named as
/// the short dimension, and persist that stage, where the next call starts;
/// within five calls every stage runs.
#[test]
fn every_start_visits_every_stage_in_cycle_order() {
    for start in MaintainStage::ALL {
        let storage = ready(2);
        fill_big(&storage);
        let minimum = storage.maintain_minimum();
        storage
            .maintain
            .stage
            .store(start as usize, std::sync::atomic::Ordering::Relaxed);
        let mut visited = [false; 5];
        let mut expected = start;
        for call in 0..5 {
            assert_eq!(persisted(&storage), expected, "{start:?} call {call}");
            let report = open(storage.maintain(&mut WorkBudget::new(minimum)));
            assert_eq!(report.started_in, expected);
            let (next, count) = contiguous_run(expected, &report);
            for position in 0..count {
                visited[(expected as usize + position) % 5] = true;
            }
            if count < 5 {
                assert_eq!(report.stopped_by, Some(BudgetDimension::Cpu), "{report:?}");
                assert!(
                    report.budget_exhausted && report.more_work,
                    "DEBUG {minimum} {:?} {report:?}",
                    storage.stage_minima()
                );
            }
            expected = next;
            assert_eq!(persisted(&storage), expected, "{start:?} call {call}");
        }
        assert!(visited.iter().all(|&v| v), "{start:?}: {visited:?}");
    }
}

/// A call that returns extents reports their full charged bytes, header,
/// payload and padding, computed here from each record's layout, and debits
/// no operation and no transfer byte from an allowance that has both.
#[test]
fn reclaimed_bytes_are_the_full_extents_returned_and_no_io_is_debited() {
    let storage = storage_capped(UNITS, Some(watermarks(3, 1)), crate::storage::IO_UNIT + 1);
    // The last body's 4,092-byte payload fits one unit while its header
    // pushes the record to two, so payload-only rounding falls short.
    let bodies = [
        vec![1u8; 100],
        vec![2u8; crate::storage::IO_UNIT + 1],
        vec![3u8; 3000],
        vec![4u8; crate::storage::IO_UNIT - 8],
    ];
    let (mut expected, mut payloads, mut payload_units) = (0, 0, 0);
    for (n, body) in bodies.iter().enumerate() {
        let k = key(50 + n as u8);
        super::lookup_tests::publish(&storage, k, u64::MAX, body);
        let payload = 4 + body.len();
        payloads += payload;
        payload_units += payload.div_ceil(crate::storage::IO_UNIT) * crate::storage::IO_UNIT;
        let header = 108 + 4 * (payload.div_ceil(8192) + 1);
        expected += (header + payload).div_ceil(crate::storage::IO_UNIT) * crate::storage::IO_UNIT;
        super::attempt_tests::invalidate(&storage, &k).unwrap();
    }
    let mut budget = WorkBudget::with_io(1 << 16, 8, 1 << 20);
    let report = open(storage.maintain(&mut budget));
    assert!(report.certify.ran && report.reclaim.ran);
    assert_eq!(report.reclaimed_bytes, expected, "{report:?}");
    assert!(expected > payloads, "header and padding count");
    assert!(
        expected > payload_units,
        "the header counts toward the units"
    );
    assert_eq!((report.operations, report.transfer_bytes), (0, 0));
    assert_eq!((budget.operations_used(), budget.bytes_used()), (0, 0));
    assert_eq!(report.evicted, 0);
    assert_eq!(settled_without_io(&storage), (0, 0));
    // Nothing is left to return.
    assert_eq!(maintain(&storage).reclaimed_bytes, 0);
}

/// Each call starts with an allowance of eight storage commands and twice the volume's bytes, so the
/// zero-debit assertions distinguish a stage that debits nothing from an exhausted allowance.
fn settled_without_io(storage: &Storage<TestPlatform>) -> (usize, usize) {
    let (mut evicted, mut reclaimed) = (0, 0);
    for call in 0..64 {
        let mut budget = WorkBudget::with_io(1 << 16, 8, 2 * UNITS * crate::storage::IO_UNIT);
        let report = open(storage.maintain(&mut budget));
        assert_eq!(
            (report.operations, report.transfer_bytes),
            (0, 0),
            "call {call}: {report:?}"
        );
        assert_eq!(
            (budget.operations_used(), budget.bytes_used()),
            (0, 0),
            "call {call}: {report:?}"
        );
        evicted += report.evicted;
        reclaimed += report.reclaimed_bytes;
        if !report.more_work {
            return (evicted, reclaimed);
        }
    }
    panic!("maintenance still reports more work after 64 calls");
}

/// The run starts at `RESERVE` free bytes under `ready(3)`, so Headroom evicts residents and Reclaim
/// returns their extents by the time maintenance settles, which can take several calls.
#[test]
fn headroom_eviction_and_its_reclaim_debit_no_io() {
    let storage = ready(3);
    fill_big(&storage);
    let free = || storage.pool_report().unwrap().ledger.unwrap().raw.free;
    let before = free();
    assert_eq!(before, RESERVE);
    let (evicted, reclaimed) = settled_without_io(&storage);
    assert!(evicted > 0, "Headroom evicted a resident");
    assert!(reclaimed > 0, "Reclaim returned an evicted extent");
    assert_eq!(reclaimed, free() - before);
}

/// Grace held by a pinned reader keeps evicted extents in flight. With the
/// eight-unit target above the seven free units nine one-unit objects
/// leave, and the 35-slot target above their 31 free slots, the first
/// in-flight unit meets the unit target while the slot target stays short;
/// each headroom stage commits at most one victim, and once free plus
/// in-flight slots reach the target, further calls remove nothing. Expiry
/// then retires an expired member although both targets are met.
#[test]
fn headroom_commits_one_victim_per_stage_and_expiry_runs_past_the_targets() {
    let min_free_slots = SLOTS - 5;
    let storage = storage_with(Some(watermarks(8, min_free_slots)));
    for n in 1..=8u8 {
        super::lookup_tests::publish(&storage, key(n), u64::MAX, &[n; 100]);
    }
    super::lookup_tests::publish(&storage, key(99), 5 * 1_000_000_000, &[9; 100]);
    let mut pinned = storage.register().unwrap();
    let protected = pinned.enter().unwrap();
    let mut evictions = 0;
    for _ in 0..60 {
        let report = maintain(&storage);
        assert!(report.evicted <= 1, "{report:?}");
        evictions += report.evicted;
    }
    // The first victim meets the unit target; the slot target takes four.
    let domain = storage.domain_report().unwrap();
    assert_eq!(evictions, 4, "{domain:?}");
    assert_eq!((domain.in_flight, domain.in_flight_units), (4, 4));
    assert_eq!(domain.free_units + domain.in_flight_units, 11);
    assert_eq!(domain.free_slots + domain.in_flight, min_free_slots);
    let before = storage.maintain_totals().evicted;
    for _ in 0..10 {
        assert_eq!(maintain(&storage).evicted, 0);
    }
    assert_eq!(storage.maintain_totals().evicted, before);
    // Past key 99's deadline, expiry removes it whatever the targets say.
    storage.platform.ticks(&[Some(6 * 1_000_000_000)]);
    let mut expired = 0;
    for _ in 0..10 {
        expired += maintain(&storage).expired;
    }
    assert_eq!(expired, 1);
    drop(protected);
}

/// With `p` members held at the tail and each headroom stage funded for
/// `v < p + 1` visits, the first eligible member is committed within
/// `ceil((p + 1) / v)` funded headroom stages; after the holds end, a
/// contention-free run of funded calls returns every retired extent within
/// a bound derived from the volume.
#[test]
fn a_funded_headroom_stage_passes_a_held_prefix_within_the_call_bound() {
    for extra in [0usize, 1, 2] {
        let storage = ready(2);
        let keys = fill_big(&storage);
        // The maintenance minimum funds every stage, so a headroom stage
        // funded at least that far affords `v` visits; `p` exceeds it.
        let headroom = storage.stage_minima()[MaintainStage::Headroom as usize];
        let per_visit = super::evict::SELECT_PER_VISIT;
        let funded = storage.maintain_minimum() + extra * per_visit;
        let v = (funded - 1 - headroom) / per_visit + 1;
        let p = v + 1 + extra;
        assert!(p < keys.len(), "the fixture holds {} members", keys.len());
        let mut reader = storage.register().unwrap();
        let held: Vec<_> = keys[..p]
            .iter()
            .map(|&n| lookup(&mut reader, &key(n), RETRIES).unwrap())
            .collect();
        let bound = (p + 1).div_ceil(v);
        let mut stages = 0;
        loop {
            storage.maintain.stage.store(
                MaintainStage::Headroom as usize,
                std::sync::atomic::Ordering::Relaxed,
            );
            let report = open(storage.maintain(&mut WorkBudget::new(funded)));
            assert!(report.headroom.ran);
            stages += 1;
            if report.evicted == 1 {
                break;
            }
            assert!(stages < bound, "p {p} v {v}: past {bound} stages");
        }
        assert!(stages <= bound, "p {p} v {v}: {stages} > {bound}");
        // The victim is the first member behind the held prefix.
        assert!(lookup(&mut reader, &key(keys[p]), RETRIES).is_err());
        drop(lookup(&mut reader, &key(keys[p + 1]), RETRIES).unwrap());
        drop(held);
        // Recovery: every slot is serviced within two full passes of
        // funded calls once nothing holds a right.
        let limit = 2 * MaintainStage::ALL.len() * (SLOTS + 1);
        let mut calls = 0;
        while storage.pool_report().unwrap().ledger.unwrap().slots.retired != 0 {
            maintain(&storage);
            calls += 1;
            assert!(calls <= limit, "p {p} v {v}: recovery past {limit} calls");
        }
    }
}

/// A sixteen-shard volume with nothing parked, retired or filling. One
/// funded call covers every shard's fill table and reports no more work on
/// its own, so the caller may rest; the first call may certify first.
#[test]
fn a_funded_call_covers_every_shard_and_reports_no_more_work() {
    const WIDE: usize = 1024;
    let storage = wide_storage(WIDE, 4);
    let fund = storage.maintain_minimum().max(1 << 12);
    let mut done_at = None;
    for call in 0..4 {
        let report = open(storage.maintain(&mut WorkBudget::new(fund)));
        assert_eq!(report.fill_tables, 16, "{report:?}");
        assert_eq!(report.fills.visited, 16 * 4, "every record sighted");
        assert!(report.fills.done, "{report:?}");
        assert_eq!(report.contended, 0, "no gate was tried: {report:?}");
        assert!(
            report.reclaim.visited < WIDE,
            "each call walks only part of the slot table"
        );
        if !report.more_work {
            done_at = Some(call);
            break;
        }
    }
    assert!(done_at.is_some_and(|at| at <= 1), "{done_at:?}");
    // Each done starts a new run: the next funded call reports done again.
    let report = open(storage.maintain(&mut WorkBudget::new(fund)));
    assert!(!report.more_work, "{report:?}");
}

/// An allowance that funds part of the Fills run covers a prefix of the
/// shards per call and leaves the cursor on the next, so the calls report
/// more work until their coverage since the last done reaches every shard.
#[test]
fn a_run_cut_short_covers_the_shards_over_consecutive_calls() {
    let storage = wide_storage(1024, 4);
    // Settle the first certification with a full allowance.
    let mut calls = 0;
    while open(storage.maintain(&mut WorkBudget::new(1 << 12))).more_work {
        calls += 1;
        assert!(calls < 4);
    }
    // Room past the maintenance minimum for a few sighted tables of four
    // records, each charged one visit per record.
    let fund = storage.maintain_minimum() + 6 * 4 + 16;
    let mut covered = 0;
    let mut dones = 0;
    for call in 0..40 {
        let report = open(storage.maintain(&mut WorkBudget::new(fund)));
        assert!(
            (1..16).contains(&report.fill_tables),
            "call {call} covered {} tables: {report:?}",
            report.fill_tables
        );
        assert_eq!(report.fills.visited, 4 * report.fill_tables, "{report:?}");
        covered += report.fill_tables;
        assert_eq!(
            report.more_work,
            covered < 16,
            "call {call} covered {covered} since the last done: {report:?}"
        );
        if !report.more_work {
            covered = 0;
            dones += 1;
        }
    }
    assert!(dones >= 2, "{dones} dones in forty calls");
}

/// The sighting leaves a table with an occupied record to its gated pass:
/// a live attempt is retained, and once it departs the pass releases it.
#[test]
fn an_occupied_table_takes_its_gated_pass_and_a_departed_record_is_released() {
    let storage = wide_storage(1024, 4);
    let fund = 1 << 12;
    while open(storage.maintain(&mut WorkBudget::new(fund))).more_work {}
    let k = key(9);
    let attempt = super::attempt_tests::begin(&storage, &k).unwrap();
    let shard = storage.route(&k).unwrap().shard();
    let report = open(storage.maintain(&mut WorkBudget::new(fund)));
    assert_eq!(report.fill_tables, 16);
    // The sighting that found the occupied word is charged; the pass that
    // follows counts the records.
    assert_eq!(report.fills.visited, 16 * 4, "{report:?}");
    assert_eq!(report.contended, 0, "{report:?}");
    assert!(report.fills.done && !report.more_work, "{report:?}");
    assert_eq!(fill_records(&storage, shard).len(), 4);
    assert_eq!(
        fill_records(&storage, shard)
            .iter()
            .filter(|record| **record != super::fill::Record::Free)
            .count(),
        1,
        "the live attempt stays"
    );
    attempt.abort();
    let report = open(storage.maintain(&mut WorkBudget::new(fund)));
    assert_eq!(report.fills.visited, 16 * 4, "{report:?}");
    assert!(
        fill_records(&storage, shard)
            .iter()
            .all(|record| *record == super::fill::Record::Free),
        "the departed record was released"
    );
    let report = open(storage.maintain(&mut WorkBudget::new(fund)));
    assert_eq!(report.fills.visited, 16 * 4, "every table is sighted again");
}

#[test]
fn every_allowance_that_funds_a_full_cycle_reaches_done() {
    let storage = wide_storage(1024, 32);
    let cycle: usize = storage.stage_minima().iter().sum();
    for fund in cycle..cycle + 512 {
        let reached =
            (0..4 * 16).any(|_| !open(storage.maintain(&mut WorkBudget::new(fund))).more_work);
        assert!(reached, "allowance {fund} never reported done");
    }
}

/// Each shard without a fill table costs the Fills run one visit.
#[test]
fn a_shard_without_a_fill_table_is_charged_to_the_run() {
    let storage = wide_storage(1024, 0);
    let minima = storage.stage_minima();
    let reserve: usize = minima[MaintainStage::Fills as usize + 1..].iter().sum();
    let report = open(storage.maintain(&mut WorkBudget::new(1 + reserve + 3)));
    assert_eq!(report.started_in, MaintainStage::Fills);
    assert_eq!(report.fill_tables, 3, "{report:?}");
    assert!(report.fills.done && report.reclaim.ran, "{report:?}");
    assert_eq!(report.fills.visited, 0, "no record was examined");
}

fn wide_storage(slots: usize, records: usize) -> Storage<TestPlatform> {
    use super::publish_tests::storage_from;
    let limits = [64; 16];
    let fills = [records; 16];
    let index = IndexConfig {
        fills: &fills,
        ..index_config(&limits, (1, 1), 1)
    };
    let mut volume = crate::storage::test_volume(1 << 30, slots);
    volume.maintenance = Some(VolumeWatermarks {
        low_units: 64,
        min_free_slots: 1,
        retired_units: u64::MAX,
    });
    let config = StorageConfig {
        metadata_cap: Some(64),
        engine_budget: 1 << 30,
        volume,
        ..storage_config(slots)
    };
    let storage = storage_from(&config, &index, TestPlatform::heap(PAGE));
    storage.platform.ticks(&[Some(1)]);
    storage
}

/// Every record of `shard`'s fill table, decoded against its next serial.
fn fill_records(storage: &Storage<TestPlatform>, shard: ShardIndex) -> Vec<super::fill::Record> {
    let table = storage.root_image.fills[shard.0].as_ref().unwrap();
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
        .map(|state| {
            super::fill::decode(state.load(std::sync::atomic::Ordering::Acquire), next).unwrap()
        })
        .collect()
}

/// The retired allowance `T` equal to the largest object's charge
/// validates, and one unit short refuses.
#[test]
fn a_retired_allowance_of_the_largest_charge_validates_and_one_unit_short_refuses() {
    let cmax = storage_config(SLOTS)
        .validate()
        .unwrap()
        .largest_geometry()
        .total_units();
    let config = |retired_units| {
        let mut volume = crate::storage::test_volume(UNITS * crate::storage::IO_UNIT, SLOTS);
        volume.maintenance = Some(VolumeWatermarks {
            low_units: 2,
            min_free_slots: 1,
            retired_units,
        });
        StorageConfig {
            volume,
            ..storage_config(SLOTS)
        }
    };
    assert!(config(cmax).validate().is_ok());
    assert_eq!(
        config(cmax - 1).validate().err(),
        Some(ConfigError::RetiredUnitsBelowLargest {
            retired_units: cmax - 1,
            record_units: cmax,
        })
    );
}

/// A reservation like [`reserve_big`]'s, cancelled so it retires nothing.
fn claim_big(storage: &Storage<TestPlatform>) -> Result<(), ReserveError> {
    storage
        .reserve(Some(4), Some(100), &mut generous())
        .map(|owner| owner.cancel().unwrap())
}

/// A storage whose headroom keeps two free units and one slot and whose
/// retired allowance is the largest object's charge.
fn allowance() -> Storage<TestPlatform> {
    let cmax = storage_config(SLOTS)
        .validate()
        .unwrap()
        .largest_geometry()
        .total_units();
    storage_with(Some(VolumeWatermarks {
        low_units: 2,
        min_free_slots: 1,
        retired_units: cmax,
    }))
}

/// The retired charge the domain counts, and the units every retired
/// slot's extents hold, counted from the records.
fn retired_census(storage: &Storage<TestPlatform>) -> (u64, u64) {
    let live = storage.live_pool().unwrap();
    let mut access = live.lock().unwrap();
    let mut tables = access.tables();
    let counted = tables.domain.retired_units;
    let held = (0..SLOTS)
        .filter(|&slot| live.gate_state(slot).0 == super::tables::SlotState::Retired)
        .map(|slot| u64::from(tables.held_units(slot)))
        .sum();
    (counted, held)
}

/// Mandatory removal passes the allowance: invalidating every resident
/// retires them all, past `T`, while each claim refuses `RetiredPressure`
/// with nothing changed; funded maintenance returns the retired charge,
/// after which a claim succeeds. The retired census matches at every step.
#[test]
fn mass_invalidation_passes_the_allowance_and_funded_return_restores_claims() {
    let storage = allowance();
    let keys = fill_big(&storage);
    for &n in &keys {
        super::attempt_tests::invalidate(&storage, &key(n)).unwrap();
        let (counted, held) = retired_census(&storage);
        assert_eq!(counted, held, "the retired census");
    }
    let (retired, _) = retired_census(&storage);
    let limit = storage.domain_report().unwrap().retired_limit;
    assert!(
        retired > limit,
        "mandatory removal passes the allowance: {retired} of {limit}"
    );
    let before = storage.pool_report().unwrap().ledger;
    assert_eq!(
        before.unwrap().raw.free,
        RESERVE,
        "the clean reserve is short too"
    );
    assert_eq!(claim_big(&storage), Err(ReserveError::RetiredPressure));
    assert_eq!(storage.pool_report().unwrap().ledger, before);
    let mut calls = 0;
    while claim_big(&storage).is_err() {
        maintain(&storage);
        let (counted, held) = retired_census(&storage);
        assert_eq!(counted, held, "the retired census");
        calls += 1;
        assert!(calls < 100, "funded return never restored claims");
    }
    assert!(retired_census(&storage).0 < limit);
}

/// With only the largest unexpired objects and no blockers, headroom
/// eviction retires one victim within the allowance at a time, refuses
/// the next while it waits for return, and funded maintenance restores
/// capacity so a new object publishes and reads back by lookup.
#[test]
fn headroom_evicts_within_the_allowance_and_restores_capacity_for_a_new_object() {
    let storage = allowance();
    fill_big(&storage);
    let limit = storage.domain_report().unwrap().retired_limit;
    let mut calls = 0;
    while claim_big(&storage).is_err() {
        maintain(&storage);
        let (retired, held) = retired_census(&storage);
        assert_eq!(retired, held, "the retired census");
        assert!(retired <= limit, "eviction stays within the allowance");
        calls += 1;
        assert!(calls < 200, "headroom never restored capacity");
    }
    assert!(storage.maintain_totals().evicted >= 1);
    let fresh = 200;
    publish_big(&storage, fresh);
    let mut reader = storage.register().unwrap();
    assert!(lookup(&mut reader, &key(fresh), RETRIES).is_ok());
}

/// A body cap that makes `Cmax` exceed a one-unit object's charge.
const WIDE_BODY: usize = 3 * crate::storage::IO_UNIT;

fn one_retired_beside(wide: bool) -> (Storage<TestPlatform>, u64, usize, u64) {
    let cmax = StorageConfig {
        body_cap: WIDE_BODY,
        ..storage_config(SLOTS)
    }
    .validate()
    .unwrap()
    .largest_geometry()
    .total_units();
    let marks = VolumeWatermarks {
        low_units: 1 + cmax,
        min_free_slots: 1,
        retired_units: cmax,
    };
    let storage = storage_capped(UNITS, Some(marks), WIDE_BODY);
    publish_big(&storage, 1);
    let body = if wide {
        vec![2; WIDE_BODY]
    } else {
        vec![2; 100]
    };
    let victim = super::lookup_tests::publish(&storage, key(2), u64::MAX, &body).slot_index();
    super::attempt_tests::invalidate(&storage, &key(1)).unwrap();
    assert_eq!(retired_census(&storage), (1, 1));
    let units = {
        let mut access = storage.live_pool().unwrap().lock().unwrap();
        u64::from(access.tables().held_units(victim))
    };
    (storage, cmax, victim, units)
}

/// A victim's own charge decides its fit: with `T = Cmax` and one unit
/// retired, less than `Cmax` remains, and a one-unit victim still fits and
/// is committed, leaving the retired charge within `T`.
#[test]
fn a_victim_below_the_largest_charge_fits_beside_a_retired_charge_within_the_allowance() {
    let (storage, cmax, victim, units) = one_retired_beside(false);
    assert!(units < cmax, "the victim fits beside one retired unit");
    let report = storage.evict_step(&mut generous(), |_, _| true).unwrap();
    assert!(!report.beyond_allowance);
    assert!(matches!(
        report.commit,
        Some(Commit::Evicted { victim: id, .. }) if id.slot_index() == victim
    ));
    assert_eq!(retired_census(&storage), (1 + units, 1 + units));
}

/// A victim of `Cmax` units beside one retired unit would take the retired
/// charge past `T = Cmax`, so the step refuses it and commits nothing.
#[test]
fn a_largest_victim_beside_one_retired_unit_is_refused() {
    let (storage, cmax, _, units) = one_retired_beside(true);
    assert_eq!(units, cmax, "the victim charges the largest object's units");
    let report = storage.evict_step(&mut generous(), |_, _| true).unwrap();
    assert!(report.beyond_allowance);
    assert!(report.commit.is_none());
    assert_eq!(retired_census(&storage), (1, 1));
}

/// A retired object a lease still reads stays counted in the retired
/// charge after grace releases its anchor, until its extents return.
#[test]
fn a_reader_held_retired_object_keeps_its_charge_after_the_anchor_release() {
    let storage = allowance();
    let keys = fill_big(&storage);
    let mut reader = storage.register().unwrap();
    let lease = lookup(&mut reader, &key(keys[0]), RETRIES).unwrap();
    super::attempt_tests::invalidate(&storage, &key(keys[0])).unwrap();
    for _ in 0..4 {
        let _ = storage.certify(&mut generous()).unwrap();
        storage.service(&mut generous()).unwrap();
    }
    let (counted, held) = retired_census(&storage);
    assert_eq!(counted, held);
    assert!(counted >= 1, "the reader-held extent stays counted");
    assert_eq!(claim_big(&storage), Err(ReserveError::RetiredPressure));
    drop(lease);
    storage.service(&mut generous()).unwrap();
    assert_eq!(retired_census(&storage), (0, 0));
    assert_eq!(claim_big(&storage), Ok(()));
}

/// The planted control: the retired charge lowered by the units of a
/// projected return, as if a return still pending funded a claim. The
/// claim passes the pressure check, and the retired census rejects the
/// history.
#[test]
#[should_panic(expected = "the retired census")]
fn negative_control_a_projected_return_funding_a_claim_fails_the_census() {
    let storage = allowance();
    // Room for more claims beside one retired object at the allowance.
    publish_big(&storage, 1);
    super::attempt_tests::invalidate(&storage, &key(1)).unwrap();
    assert_eq!(claim_big(&storage), Err(ReserveError::RetiredPressure));
    {
        let live = storage.live_pool().unwrap();
        let mut access = live.lock().unwrap();
        access.tables().domain.retired_units = 0;
    }
    assert_eq!(
        claim_big(&storage),
        Ok(()),
        "the planted charge funds the claim"
    );
    let (counted, held) = retired_census(&storage);
    assert_eq!(counted, held, "the retired census");
}

/// A replacement fill at the allowance refuses `RetiredPressure` before it
/// claims anything, and the incumbent stays current and readable.
#[test]
fn a_replacement_at_the_allowance_refuses_and_keeps_the_incumbent() {
    let storage = allowance();
    let keys = fill_big(&storage);
    super::attempt_tests::invalidate(&storage, &key(keys[0])).unwrap();
    let incumbent = keys[1];
    let mut reader = storage.register().unwrap();
    let before = lookup(&mut reader, &key(incumbent), RETRIES).unwrap().id();
    let ledger = storage.pool_report().unwrap().ledger;
    let refused = super::attempt_tests::begin(&storage, &key(incumbent))
        .unwrap()
        .reserve_storage(
            super::writable_tests::admit(&storage, 4, 100),
            Some(4),
            Some(100),
            super::publish_tests::TRIES,
            &mut generous(),
        )
        .err();
    assert_eq!(refused, Some(super::FillReserveError::RetiredPressure));
    assert_eq!(storage.pool_report().unwrap().ledger, ledger);
    assert_eq!(
        lookup(&mut reader, &key(incumbent), RETRIES).unwrap().id(),
        before
    );
}

#[test]
fn a_clean_report_leaves_only_stages_its_observations_name_as_skipped() {
    for case in ["healthy", "pool", "shard", "clock"] {
        let storage = ready(2);
        match case {
            "healthy" => {}
            "pool" => crate::storage::owner_fixture::poison_pool(&storage),
            "shard" => {
                fill_big(&storage);
                crate::storage::owner_fixture::poison_shard(&storage);
            }
            _ => storage.platform.ticks(&[None]),
        }
        let mut clean = 0;
        for _ in 0..50 {
            let Ok(Maintained::Open(report)) = storage.maintain(&mut WorkBudget::new(1 << 16))
            else {
                panic!("{case}: an open call");
            };
            if report.more_work {
                continue;
            }
            clean += 1;
            let done = [
                report.fills.done,
                report.certify.done,
                report.reclaim.done,
                report.expiry.done,
                report.headroom.done,
            ];
            let (expected, contended, clock) = match case {
                "healthy" => ([true; 5], 0, false),
                "pool" => ([true, true, false, true, false], 2, false),
                "shard" => ([true, true, true, true, false], 1, false),
                _ => ([true, true, true, false, true], 0, true),
            };
            assert_eq!(done, expected, "{case}: {report:?}");
            assert_eq!(report.contended, contended, "{case}: {report:?}");
            assert_eq!(report.clock_unavailable, clock, "{case}: {report:?}");
        }
        assert!(clean > 0, "{case}: a call reported no more work");
    }
}

/// The body of a three-extent object, the largest the run-wait fixtures admit.
const THREE: usize = 2 * EXTENT_PAYLOAD as usize + 1000;
/// Units of the run-wait fixtures' volume.
const RUN_UNITS: usize = 1024;
const RUN_CEILING: u64 = RUN_UNITS as u64 - RUN_UNITS as u64 % 63;
const RUN_SLOTS: usize = 160;
/// The reproducer's watermark: eight 16-unit holes beside the volume's free
/// tail cover a three-extent charge plus the clean reserve.
const FRAGMENTED_LOW: u64 = 144;

/// A publishable body whose record charges `units` units.
fn resident(units: usize) -> Vec<u8> {
    vec![7; units * crate::storage::IO_UNIT - 300]
}

/// A storage of [`RUN_UNITS`] units and [`RUN_SLOTS`] slots admitting
/// three-extent objects, with watermarks `low_units` and `retired_units`.
fn run_storage(low_units: u64, retired_units: u64) -> Storage<TestPlatform> {
    storage_arena(
        RUN_UNITS,
        Some(VolumeWatermarks {
            low_units,
            min_free_slots: 1,
            retired_units,
        }),
        THREE,
        1,
        1,
        RUN_SLOTS,
    )
}

/// The charge of the largest object, a three-extent one, from a promise on
/// a storage of its own.
fn largest() -> u64 {
    let storage = run_storage(200, u64::MAX);
    let builder = storage
        .promise(Some(0), Some(THREE), &mut generous())
        .unwrap();
    builder.remaining()
}

fn fill_residents(storage: &Storage<TestPlatform>, sizes: &[usize]) -> Vec<(u8, u64)> {
    let mut residents = Vec::new();
    loop {
        let units = sizes[residents.len() % sizes.len()];
        if storage.domain_report().unwrap().claimable_units < units as u64 {
            return residents;
        }
        let n = residents.len() as u8 + 1;
        super::lookup_tests::publish(storage, key(n), u64::MAX, &resident(units));
        residents.push((n, units as u64));
    }
}

/// The fragmentation reproducer with a retired allowance of
/// `retired_units`: a full volume of 16-unit residents, the ones `visited`
/// selects read since their publication, then headroom until the free units
/// reach the watermark, whose SIEVE victims are unread residents first. A
/// victim may still be in flight.
fn fragmented_with(visited: impl Fn(u8) -> bool, retired_units: u64) -> Storage<TestPlatform> {
    let storage = run_storage(FRAGMENTED_LOW, retired_units);
    let keys = fill_residents(&storage, &[16]);
    let mut reader = storage.register().unwrap();
    for &(n, _) in keys.iter().filter(|&&(n, _)| visited(n)) {
        drop(lookup(&mut reader, &key(n), RETRIES).unwrap());
    }
    drop(reader);
    for _ in 0..4000 {
        if storage.domain_report().unwrap().free_units >= FRAGMENTED_LOW {
            return storage;
        }
        maintain(&storage);
    }
    panic!("headroom never freed the watermark's units");
}

/// [`fragmented_with`] under an unbounded retired allowance.
fn fragmented(visited: impl Fn(u8) -> bool) -> Storage<TestPlatform> {
    fragmented_with(visited, u64::MAX)
}

/// Runs maintenance until the placeable units reach the watermark with no
/// eviction in flight, checking that no call evicts more than one victim,
/// and returns the victims evicted.
fn until_placeable(storage: &Storage<TestPlatform>) -> u64 {
    let before = storage.maintain_totals().evicted;
    for _ in 0..4000 {
        let domain = storage.domain_report().unwrap();
        if domain.placeable_units >= domain.low_units && domain.in_flight == 0 {
            return storage.maintain_totals().evicted - before;
        }
        let report = maintain(storage);
        assert!(report.evicted <= 1, "one victim per call: {report:?}");
    }
    panic!(
        "the placeable units never reached the watermark: {:?}",
        storage.domain_report()
    );
}

/// Every other resident read: SIEVE's first victims are the unread
/// residents, so when the free units reach the watermark they sit in 16-unit
/// holes between read residents beside a shorter free tail. The free units
/// less the escrow cover a three-extent charge plus the clean reserve while
/// no free run holds a 63-unit charge, so the placeable units are zero. With
/// no builder waiting, headroom reads the volume short and evicts, one victim
/// per call, until the placeable units reach the watermark with nothing in
/// flight; twenty calls after that evict nothing, and a three-extent object
/// places without waiting.
#[test]
fn a_fragmented_watermark_evicts_with_no_waiter_until_placeable_units_reach_it() {
    let storage = fragmented(|n| n % 2 == 0);
    let at = storage.domain_report().unwrap();
    assert!(
        at.free_units - at.escrow_units >= largest() + at.reserve_units,
        "{at:?}"
    );
    assert!(
        at.free_units >= at.low_units && at.placeable_units == 0,
        "{at:?}"
    );
    assert!(
        until_placeable(&storage) > 0,
        "the fragmented volume read short"
    );
    assert_eq!(
        evicted_by(&storage, 20),
        0,
        "placeable units at the watermark evict nothing"
    );
    let mut builder = storage
        .promise(Some(0), Some(THREE), &mut generous())
        .unwrap();
    assert!(builder.place(&mut generous()).unwrap());
    builder.cancel();
}

/// A three-extent builder promised on the fragmented reproducer refuses
/// `PayloadFull` and waits, since no free run holds a 63-unit extent.
/// Funded calls alternate with its retries: each call evicts at most one
/// victim, and the same builder places every extent once headroom forms the
/// runs, with the escrow back to zero.
#[test]
fn a_waiting_builder_completes_through_placeable_headroom() {
    let storage = fragmented(|n| n % 2 == 0);
    let mut builder = storage
        .promise(Some(0), Some(THREE), &mut generous())
        .unwrap();
    assert_eq!(
        builder.place(&mut generous()).err(),
        Some(super::PromiseError::Reserve(ReserveError::PayloadFull))
    );
    assert!(builder.waiting());
    for _ in 0..4000 {
        let report = maintain(&storage);
        assert!(report.evicted <= 1, "one victim per call: {report:?}");
        match builder.retry(&mut generous()) {
            Ok(true) => {
                assert!(builder.is_complete() && !builder.waiting());
                assert_eq!(storage.domain_report().unwrap().escrow_units, 0);
                builder.cancel();
                return;
            }
            Ok(false) | Err(super::PromiseError::Reserve(ReserveError::PayloadFull)) => {}
            Err(error) => panic!("placement refused: {error:?}"),
        }
    }
    panic!("headroom never completed the waiting builder");
}

/// With no resident read, or every resident read, headroom's victims at the
/// watermark are address neighbours, so a free run holds the object and its
/// placement completes without waiting.
#[test]
fn an_unread_or_fully_read_volume_places_the_object_without_waiting() {
    for visited in [false, true] {
        let storage = fragmented(|_| visited);
        assert!(
            storage.domain_report().unwrap().longest_run >= 64,
            "visited {visited}"
        );
        let mut builder = storage
            .promise(Some(0), Some(THREE), &mut generous())
            .unwrap();
        assert!(builder.place(&mut generous()).unwrap(), "visited {visited}");
        assert!(!builder.waiting(), "visited {visited}");
        builder.cancel();
    }
}

/// Returns blocked by a pinned reader: on the fragmented reproducer headroom
/// evicts with no waiter until the in-flight units cover the placeable
/// shortfall and stops there, at most one 16-unit victim past it. When the
/// reader leaves, the returns land in 16-unit holes between read residents,
/// so the placeable units stay short, and the call whose Reclaim lands the
/// first return reads the volume short again and evicts.
#[test]
fn placeable_eviction_stops_at_the_in_flight_credit_and_resumes_when_a_return_lands() {
    let storage = fragmented(|n| n % 2 == 0);
    let mut pinned = storage.register().unwrap();
    let protected = pinned.enter().unwrap();
    for _ in 0..400 {
        maintain(&storage);
    }
    assert_eq!(
        evicted_by(&storage, 20),
        0,
        "a call at the in-flight credit evicted"
    );
    let blocked = storage.domain_report().unwrap();
    let credit = blocked.low_units - blocked.placeable_units;
    assert!(
        blocked.in_flight_units >= credit && blocked.in_flight_units < credit + 16,
        "{blocked:?}"
    );
    drop(protected);
    drop(pinned);
    for _ in 0..40 {
        let (free, evicted) = (
            storage.domain_report().unwrap().free_units,
            storage.maintain_totals().evicted,
        );
        maintain(&storage);
        let domain = storage.domain_report().unwrap();
        if domain.free_units > free {
            assert!(domain.placeable_units < domain.low_units, "{domain:?}");
            assert_eq!(
                storage.maintain_totals().evicted,
                evicted + 1,
                "the call that landed a return read the volume short"
            );
            return;
        }
    }
    panic!("no return landed after the reader left");
}

/// On the fragmented reproducer a three-extent promise escrows 127 units
/// against zero placeable units, so the escrow term clamps at zero. With
/// returns blocked, headroom evicts until the in-flight units alone meet
/// the watermark, at most one 16-unit victim past it.
#[test]
fn an_escrow_above_the_placeable_units_leaves_the_in_flight_units_to_meet_the_watermark() {
    let storage = fragmented(|n| n % 2 == 0);
    let builder = storage
        .promise(Some(0), Some(THREE), &mut generous())
        .unwrap();
    let mut pinned = storage.register().unwrap();
    let protected = pinned.enter().unwrap();
    for _ in 0..400 {
        maintain(&storage);
    }
    let domain = storage.domain_report().unwrap();
    assert!(domain.escrow_units > domain.placeable_units, "{domain:?}");
    assert!(
        domain.in_flight_units >= domain.low_units
            && domain.in_flight_units < domain.low_units + 16,
        "{domain:?}"
    );
    drop(protected);
    drop(pinned);
    builder.cancel();
}

/// With returns blocked and the retired allowance at the largest object's
/// charge, headroom on the fragmented reproducer stops once the next victim
/// would take the retired charge past it, short of the in-flight credit, and
/// the step names the refused victim as beyond the allowance.
#[test]
fn placeable_eviction_stops_at_the_retired_allowance() {
    let cmax = largest();
    // The allowance binds before the in-flight credit of the watermark.
    assert!(cmax < FRAGMENTED_LOW, "largest charge {cmax}");
    let storage = fragmented_with(|n| n % 2 == 0, cmax);
    let mut pinned = storage.register().unwrap();
    let protected = pinned.enter().unwrap();
    for _ in 0..400 {
        maintain(&storage);
    }
    let domain = storage.domain_report().unwrap();
    assert!(domain.retired_units <= cmax && domain.retired_units + 16 > cmax);
    assert!(
        domain.placeable_units + domain.in_flight_units < domain.low_units,
        "the allowance stopped eviction first: {domain:?}"
    );
    let step = storage.evict_step(&mut generous(), |_, _| true).unwrap();
    assert!(step.beyond_allowance && step.commit.is_none());
    // The refusal leaves the hand on the refused member, so the next step
    // refuses the same slot.
    let hand = || {
        storage
            .live_pool()
            .unwrap()
            .lock()
            .unwrap()
            .tables()
            .domain
            .hand
    };
    let refused = hand();
    let again = storage.evict_step(&mut generous(), |_, _| true).unwrap();
    assert!(again.beyond_allowance && again.commit.is_none());
    assert_eq!(hand(), refused, "the hand stays on the refused slot");
    drop(protected);
    drop(pinned);
}

/// When every resident of the fragmented reproducer is leased, headroom
/// evicts nothing and reports the readers-or-I/O block.
#[test]
fn placeable_eviction_stops_when_every_member_is_leased() {
    let storage = fragmented(|n| n % 2 == 0);
    let mut reader = storage.register().unwrap();
    let leases: Vec<_> = (1..=u8::MAX)
        .filter_map(|n| lookup(&mut reader, &key(n), RETRIES).ok())
        .collect();
    let evicted = storage.maintain_totals().evicted;
    let mut blocked = false;
    for _ in 0..40 {
        blocked |= maintain(&storage).blocked_by_readers_or_io;
    }
    assert_eq!(
        storage.maintain_totals().evicted,
        evicted,
        "every member is leased"
    );
    assert!(blocked, "the stop reports readers or I/O");
    drop(leases);
}

/// Fills the empty `storage` with a 16-unit resident at the volume's start
/// and a held filler, then one-unit walls that cut the rest of the free
/// space into `holes` in address order; the last hole joins the clean
/// reserve's free unit at the volume's end. Returns the claims that stay
/// held.
fn walled<'s>(
    storage: &'s Storage<TestPlatform>,
    holes: &[u64],
) -> Vec<super::ExtentReservation<'s, TestPlatform>> {
    let payload = storage.domain_report().unwrap().free_units;
    let count = holes.len() as u64;
    let filler = payload - 16 - holes.iter().sum::<u64>() - count + 1;
    super::lookup_tests::publish(storage, key(1), u64::MAX, &resident(16));
    // Claims of at most 62 units, each one extent, that cover `units` units
    // in address order.
    let claim = |mut units: u64| {
        let mut claims = Vec::new();
        while units > 0 {
            let piece = units.min(62);
            let body = piece as usize * crate::storage::IO_UNIT - 2048;
            claims.push(
                storage
                    .reserve(Some(0), Some(body), &mut generous())
                    .unwrap(),
            );
            units -= piece;
        }
        claims
    };
    let mut held = claim(filler);
    let mut cut = Vec::new();
    for (index, &units) in holes.iter().enumerate() {
        if index + 1 == holes.len() {
            cut.extend(claim(units - 1));
        } else {
            cut.extend(claim(units));
            held.extend(claim(1));
        }
    }
    assert_eq!(storage.domain_report().unwrap().free_units, 1);
    for hole in cut {
        hole.cancel().unwrap();
    }
    let runs = super::boundary_tests::free_runs(storage);
    assert_eq!(
        runs.iter().map(|&(_, len)| len).collect::<Vec<_>>(),
        holes,
        "{runs:?}"
    );
    held
}

/// The victims `calls` maintenance calls evict.
fn evicted_by(storage: &Storage<TestPlatform>, calls: usize) -> u64 {
    let before = storage.maintain_totals().evicted;
    for _ in 0..calls {
        maintain(storage);
    }
    storage.maintain_totals().evicted - before
}

/// The volume fits `n` holes of a 63-unit charge, each but the last
/// followed by a one-unit wall. When every hole holds exactly one charge,
/// the placeable units equal the free units at a watermark of `63 * n` and
/// twenty calls evict nothing. Moving one wall a unit keeps the free units at the
/// watermark but leaves a 62-unit hole, which counts zero, beside a
/// 64-unit one, which counts one charge, so the placeable units fall a
/// charge short and headroom evicts.
#[test]
fn a_volume_of_63_unit_holes_is_not_short_and_a_62_unit_hole_is() {
    let n = (RUN_UNITS as u64 - 16 + 1) / 64;
    let low = 63 * n;
    let storage = run_storage(low, u64::MAX);
    let held = walled(&storage, &vec![63; n as usize]);
    let domain = storage.domain_report().unwrap();
    assert_eq!(
        (domain.placeable_units, domain.free_units),
        (low, low),
        "{domain:?}"
    );
    assert_eq!(
        evicted_by(&storage, 20),
        0,
        "63-unit holes cover the watermark"
    );
    drop(held);
    let mut holes = vec![62, 64];
    holes.resize(n as usize, 63);
    let storage = run_storage(low, u64::MAX);
    let held = walled(&storage, &holes);
    let domain = storage.domain_report().unwrap();
    assert_eq!(domain.free_units, low, "{domain:?}");
    assert_eq!(domain.placeable_units + 63, low, "{domain:?}");
    assert!(
        evicted_by(&storage, 20) > 0,
        "the 62-unit hole leaves the volume short"
    );
    drop(held);
}

/// Four 63-unit holes hold 252 placeable units, above a 128-unit watermark,
/// so twenty calls evict nothing. A three-extent promise escrows 127 units,
/// and the next call reads `252 - 127 < 128` and evicts. Placing the
/// builder lowers the placeable units by at most its charge plus one charge
/// less a unit. This layout reaches that bound: the two full extents take
/// two holes and the one-unit tail leaves a 62-unit hole that counts zero,
/// so one whole hole stays placeable.
#[test]
fn the_escrow_counts_against_placeable_units_and_bounds_their_drop() {
    let storage = run_storage(128, u64::MAX);
    let held = walled(&storage, &[63; 4]);
    assert_eq!(storage.domain_report().unwrap().placeable_units, 252);
    assert_eq!(evicted_by(&storage, 20), 0, "252 placeable units cover 128");
    let mut builder = storage
        .promise(Some(0), Some(THREE), &mut generous())
        .unwrap();
    let charge = builder.remaining();
    assert_eq!(charge, 127);
    assert_eq!(
        evicted_by(&storage, 1),
        1,
        "the escrow leaves the volume short"
    );
    let domain = storage.domain_report().unwrap();
    assert_eq!(
        (domain.placeable_units, domain.in_flight_units),
        (252, 16),
        "the 16-unit victim is still in flight beside the four holes"
    );
    let before = domain.placeable_units;
    assert!(builder.place(&mut generous()).unwrap());
    let after = storage.domain_report().unwrap().placeable_units;
    assert_eq!(
        (before - after, after),
        (charge + 62, 63),
        "the tail leaves a 62-unit hole"
    );
    builder.cancel();
    drop(held);
}

/// The 63-unit charge leaves a 16-unit remainder in the 1,024-unit volume,
/// so a watermark at the 1,008-unit placeable ceiling holds residents within
/// that remainder.
#[test]
fn a_watermark_at_the_placeable_ceiling_keeps_residents_within_the_remainder() {
    assert_eq!(RUN_CEILING, 1008);
    let storage = run_storage(RUN_CEILING, u64::MAX);
    assert_eq!(
        storage.domain_report().unwrap().placeable_units,
        RUN_CEILING
    );
    super::lookup_tests::publish(&storage, key(1), u64::MAX, &resident(8));
    let domain = storage.domain_report().unwrap();
    assert_eq!(
        (domain.free_units, domain.placeable_units),
        (1016, RUN_CEILING)
    );
    assert_eq!(
        evicted_by(&storage, 20),
        0,
        "the ceiling covers the watermark"
    );
    super::lookup_tests::publish(&storage, key(2), u64::MAX, &resident(9));
    let domain = storage.domain_report().unwrap();
    assert_eq!((domain.free_units, domain.placeable_units), (1007, 945));
    assert_eq!(evicted_by(&storage, 1), 1, "945 placeable units fall short");
}

/// A storage whose headroom keeps `low_units` free units, one free slot and
/// a retired allowance of `retired_units`, full of one-unit residents behind
/// a two-unit one, and the keys of the one-unit residents.
fn behind_wide(low_units: u64, retired_units: u64) -> (Storage<TestPlatform>, Vec<u8>) {
    let marks = VolumeWatermarks {
        low_units,
        min_free_slots: 1,
        retired_units,
    };
    let storage = storage_capped(UNITS, Some(marks), crate::storage::IO_UNIT + 1);
    let wide = vec![0; crate::storage::IO_UNIT + 1];
    super::lookup_tests::publish(&storage, key(200), u64::MAX, &wide);
    let keys = fill_big(&storage);
    (storage, keys)
}

/// The totals after `calls` funded calls, each running its headroom stage,
/// with a reader pinned so every evicted extent stays in flight.
fn totals_pinned(storage: &Storage<TestPlatform>, calls: usize) -> super::MaintainTotals {
    let mut pinned = storage.register().unwrap();
    let protected = pinned.enter().unwrap();
    for _ in 0..calls {
        assert!(maintain(storage).headroom.ran);
    }
    drop(protected);
    storage.maintain_totals()
}

thread_local! {
    static COMMITS: std::cell::RefCell<Vec<Commit>> = const { std::cell::RefCell::new(Vec::new()) };
}

fn record_commit(_: super::allocation::AllocationId, commit: Option<Commit>) {
    if let Some(commit) = commit {
        COMMITS.with(|commits| commits.borrow_mut().push(commit));
    }
}

/// Runs `f` and returns its result with every commit a removal step on this thread made while it ran, in order.
fn commits_during<T>(f: impl FnOnce() -> T) -> (T, Vec<Commit>) {
    COMMITS.with(|commits| commits.borrow_mut().clear());
    super::evict::OBSERVE_COMMIT.with(|cell| cell.set(Some(record_commit)));
    let result = f();
    super::evict::OBSERVE_COMMIT.with(|cell| cell.set(None));
    (result, COMMITS.with(|commits| commits.take()))
}

fn three_extents(storage: &Storage<TestPlatform>, id: super::allocation::AllocationId) -> u64 {
    super::sequence_tests::published_sequence(storage, id, 3)
        .extents
        .iter()
        .map(|extent| u64::from(extent.len_units()))
        .sum()
}

#[test]
fn a_sequence_victim_adds_every_extent_s_units() {
    let storage = run_storage(RUN_CEILING, u64::MAX);
    let id = super::lookup_tests::publish(&storage, key(1), u64::MAX, &[1; 100]);
    assert_eq!(three_extents(&storage, id), 127);
    let totals = totals_pinned(&storage, 1);
    assert_eq!(
        (totals.evicted, totals.short_stages, totals.evicted_units),
        (1, 1, 127)
    );
}

/// The 127-unit sequence victim exceeds the 126 units remaining in the allowance after the one-unit eviction.
#[test]
fn the_allowance_prices_a_sequence_victim_at_every_extent() {
    assert_eq!(largest(), 127, "a three-extent object charges 127 units");
    let storage = run_storage(RUN_CEILING, 127);
    super::lookup_tests::publish(&storage, key(1), u64::MAX, &[1; 100]);
    let id = super::lookup_tests::publish(&storage, key(2), u64::MAX, &[2; 100]);
    assert_eq!(three_extents(&storage, id), 127);
    let (totals, commits) = commits_during(|| totals_pinned(&storage, 2));
    assert!(
        matches!(commits[..], [Commit::Evicted { .. }]),
        "{commits:?}"
    );
    assert_eq!(
        (totals.evicted, totals.short_stages, totals.evicted_units),
        (1, 2, 1)
    );
}

/// A victim's units count in the evicting call even when its retirement parks behind a busy pool gate.
#[test]
fn a_parked_victim_s_units_count_in_the_evicting_call() {
    let storage: &'static Storage<TestPlatform> = Box::leak(Box::new(behind_wide(4, u64::MAX).0));
    storage.maintain.stage.store(
        MaintainStage::Headroom as usize,
        std::sync::atomic::Ordering::Relaxed,
    );
    let mut pinned = storage.register().unwrap();
    let protected = pinned.enter().unwrap();
    let holder = super::evict_tests::hold_pool_gate_during_commit(storage);
    let report = open(storage.maintain(&mut WorkBudget::new(storage.maintain_minimum())));
    let counted = storage.maintain_totals();
    let pending = storage.live_pool().unwrap().pending_mark().is_pending();
    super::evict_tests::release_holder(holder);
    assert_eq!(
        (report.started_in, report.evicted),
        (MaintainStage::Headroom, 1),
        "{report:?}"
    );
    assert!(pending, "the retirement parked behind the held gate");
    assert_eq!(
        (counted.evicted, counted.short_stages, counted.evicted_units),
        (1, 1, 2)
    );
    maintain(storage);
    assert!(!storage.live_pool().unwrap().pending_mark().is_pending());
    let totals = storage.maintain_totals();
    assert_eq!(
        (totals.evicted, totals.short_stages, totals.evicted_units),
        (2, 2, 3)
    );
    drop(protected);
}

/// A headroom stage that evicts counts one short stage and adds its victim's
/// own units: the first victim, the oldest resident, spans two units and the
/// second one unit, so the units total is 3, the victims' own units, above
/// the victim count, 2. The reserve's free unit holds no two-unit charge, so
/// with both victims in flight under a pinned reader their three units meet
/// the three-unit watermark, and both totals keep their values through the
/// stages after them.
#[test]
fn an_evicting_headroom_stage_counts_a_short_stage_and_its_victim_s_units() {
    let (storage, _) = behind_wide(3, u64::MAX);
    let totals = totals_pinned(&storage, 12);
    assert_eq!(
        (totals.evicted, totals.short_stages, totals.evicted_units),
        (2, 2, 3)
    );
}

/// The grace reading counts placeable units. The largest object charges two
/// units, so the reserve's one free unit is placeable as nothing, and with a
/// pinned reader no report reads blocked while the in-flight units, two
/// after the wide victim, fall short of the three-unit watermark. Once the
/// next victim brings them to three, eviction stops, and a later call's
/// report reads blocked with no claimable unit.
#[test]
fn the_grace_reading_waits_for_in_flight_units_to_cover_the_placeable_shortfall() {
    let (storage, _) = behind_wide(3, u64::MAX);
    let mut pinned = storage.register().unwrap();
    let protected = pinned.enter().unwrap();
    let mut blocked_at = None;
    let mut short_at_two = false;
    for _ in 0..60 {
        let report = maintain(&storage);
        let Some(domain) = report.domain else {
            continue;
        };
        assert_eq!((domain.free_units, domain.placeable_units), (1, 0));
        if report.blocked_by_readers_or_io {
            assert_eq!(domain.in_flight_units, 3, "{report:?}");
            blocked_at = Some(domain);
        } else if domain.in_flight_units == 2 && domain.claimable_units == 0 {
            short_at_two = true;
        }
    }
    assert!(short_at_two, "no unblocked read at two in-flight units");
    let domain = blocked_at.expect("a call read grace blocked");
    assert_eq!(domain.claimable_units, 0, "{domain:?}");
    assert_eq!(storage.maintain_totals().evicted, 2);
    drop(protected);
}

/// A victim invalidated between its selection and its commit ends `Absent`:
/// the stage read the volume short, so it counts, and the units total stays
/// at zero.
#[test]
fn an_absent_headroom_commit_counts_the_stage_and_no_units() {
    let storage: &'static Storage<TestPlatform> = Box::leak(Box::new(behind_wide(3, u64::MAX).0));
    storage.maintain.stage.store(
        MaintainStage::Headroom as usize,
        std::sync::atomic::Ordering::Relaxed,
    );
    STORAGE.with(|cell| cell.set(Some(storage)));
    super::evict::INTERPOSE_BEFORE_COMMIT.with(|hook| {
        hook.set(Some(|| {
            let storage = STORAGE.with(Cell::get).unwrap();
            super::attempt_tests::invalidate(storage, &key(200)).unwrap();
        }))
    });
    let report = open(storage.maintain(&mut WorkBudget::new(storage.maintain_minimum())));
    assert!(
        super::evict::INTERPOSE_BEFORE_COMMIT
            .with(Cell::take)
            .is_none(),
        "the commit hook ran"
    );
    assert_eq!(report.started_in, MaintainStage::Headroom);
    assert_eq!(
        (report.evicted, report.contended, report.replacing),
        (0, 0, 0),
        "{report:?}"
    );
    let totals = storage.maintain_totals();
    assert_eq!(
        (totals.evicted, totals.short_stages, totals.evicted_units),
        (0, 1, 0)
    );
}

/// A stage that reads the volume short and commits zero victims counts the
/// short stage and adds no units: with every member leased, selection retains
/// every member and chooses none; with the shard gate poisoned every commit
/// refuses; with the retired allowance at the largest charge the first victim
/// fills it, adding its 2 units, and every later victim lies beyond it.
#[test]
fn a_short_stage_without_a_victim_counts_the_stage_and_no_units() {
    let calls = 6;
    let (leased, leased_commits) = {
        let (storage, keys) = behind_wide(3, u64::MAX);
        let mut reader = storage.register().unwrap();
        let leases: Vec<_> = [200]
            .iter()
            .chain(&keys)
            .map(|&n| lookup(&mut reader, &key(n), RETRIES).unwrap())
            .collect();
        let totals = commits_during(|| totals_pinned(&storage, calls));
        drop(leases);
        totals
    };
    assert!(leased_commits.is_empty(), "{leased_commits:?}");
    let (poisoned, poisoned_commits) = {
        let (storage, _) = behind_wide(3, u64::MAX);
        super::attempt_tests::gate(&storage)
            .try_lock()
            .unwrap()
            .poison();
        commits_during(|| totals_pinned(&storage, calls))
    };
    assert!(
        !poisoned_commits.is_empty() && poisoned_commits.iter().all(|&c| c == Commit::Poisoned),
        "{poisoned_commits:?}"
    );
    let cmax = StorageConfig {
        body_cap: crate::storage::IO_UNIT + 1,
        ..storage_config(SLOTS)
    }
    .validate()
    .unwrap()
    .largest_geometry()
    .total_units();
    assert_eq!(cmax, 2, "the two-unit resident is the largest charge");
    let (beyond, beyond_commits) = commits_during(|| totals_pinned(&behind_wide(8, cmax).0, calls));
    assert!(
        matches!(beyond_commits[..], [Commit::Evicted { .. }]),
        "{beyond_commits:?}"
    );
    for (name, totals, evicted) in [
        ("leased", leased, (0, 0)),
        ("poisoned", poisoned, (0, 0)),
        ("beyond the allowance", beyond, (1, 2)),
    ] {
        assert_eq!(
            (totals.evicted, totals.evicted_units),
            evicted,
            "{name}: {totals:?}"
        );
        assert_eq!(totals.short_stages, calls as u64, "{name}: {totals:?}");
    }
}

/// A headroom stage that finds the pool gate busy returns before the
/// selection hold reads the domain, so both totals stay at zero until a stage
/// takes the gate.
#[test]
fn a_busy_pool_gate_adds_to_neither_total() {
    let storage = ready(2);
    fill_big(&storage);
    let live = storage.live_pool().unwrap();
    let guard = live.try_lock().unwrap();
    let report = maintain(&storage);
    drop(guard);
    assert!(report.headroom.ran && report.domain.is_none(), "{report:?}");
    let totals = storage.maintain_totals();
    assert_eq!((totals.short_stages, totals.evicted_units), (0, 0));
    maintain(&storage);
    assert_eq!(storage.maintain_totals().short_stages, 1);
}

/// On the fragmentation reproducer the free units sit in 16-unit holes, so
/// every hole is shorter than a 63-unit charge and the placeable units are
/// zero; with
/// every resident unread or read, the free units hold full extents beside a
/// remainder. In every case the domain report's count equals the sum of each
/// free run's whole charges over the allocator's runs, below the free units.
#[test]
fn placeable_units_count_each_hole_s_whole_extents() {
    let alternate: fn(u8) -> bool = |n| n.is_multiple_of(2);
    for (visited, fragments) in [(alternate, true), (|_| false, false), (|_| true, false)] {
        let storage = fragmented(visited);
        let holes = super::boundary_tests::free_runs(&storage);
        let domain = storage.domain_report().unwrap();
        assert_eq!(
            domain.placeable_units,
            holes.iter().map(|&(_, len)| len / 63 * 63).sum::<u64>(),
            "{holes:?}"
        );
        assert_eq!(
            domain.free_units,
            holes.iter().map(|&(_, len)| len).sum::<u64>()
        );
        assert!(domain.placeable_units < domain.free_units, "{domain:?}");
        assert_eq!(domain.placeable_units == 0, fragments, "{domain:?}");
    }
}

/// A storage whose largest object is one one-unit extent charges one unit
/// per full extent, so every free unit is placeable: one published object
/// leaves a 15-unit run, and the report counts all 15 units placeable.
#[test]
fn a_one_extent_largest_object_makes_every_free_unit_placeable() {
    let storage = ready(2);
    publish_big(&storage, 1);
    let live = storage.domain_report().unwrap();
    assert_eq!((live.placeable_units, live.free_units), (15, 15));
}

#[test]
fn a_two_unit_largest_object_counts_whole_two_unit_charges() {
    let storage = storage_capped(UNITS, Some(watermarks(3, 1)), crate::storage::IO_UNIT + 1);
    publish_big(&storage, 1);
    let domain = storage.domain_report().unwrap();
    assert_eq!((domain.placeable_units, domain.free_units), (14, 15));
}

/// `domain_report` returns `None` once the owner leaves the `Live` phase, as
/// after finalization drains it.
#[test]
fn a_finalized_storage_reports_no_domain() {
    let mut storage = ready(2);
    assert!(storage.domain_report().is_some());
    storage.close();
    drain_closed(&storage);
    assert_eq!(
        super::test_platform::finalize(&mut storage),
        Ok(Finalization::Drained)
    );
    assert_eq!(storage.domain_report(), None);
}

/// `domain_report` holds the pool gate while it reads the domain, so a
/// read that panics poisons the gate (storage/gate.rs module doc: "A holder
/// that panics poisons the gate on release"). A root whose level count is
/// zero makes the longest-run read panic. The report runs on a thread that
/// is not unwinding and from a destructor that catches the panic while its
/// thread unwinds from another; a guard taken during the unwind would
/// release open on drop.
#[test]
fn a_panicking_domain_read_poisons_the_pool_gate_even_during_unwinding() {
    use crate::storage::gate::GateError;
    struct ReportsOnDrop<'a> {
        storage: &'a Storage<TestPlatform>,
        panicked: &'a Cell<bool>,
    }
    impl Drop for ReportsOnDrop<'_> {
        fn drop(&mut self) {
            let storage = self.storage;
            let reported =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| storage.domain_report()));
            self.panicked.set(reported.is_err());
        }
    }
    for unwinding in [false, true] {
        let storage = storage_with(Some(watermarks(2, 1)));
        let live = storage.live_pool().unwrap();
        {
            let mut access = live.lock().unwrap();
            access.tables().extents().plant_levels(0);
            access.release();
        }
        let panicked = Cell::new(false);
        let reporter = ReportsOnDrop {
            storage: &storage,
            panicked: &panicked,
        };
        if unwinding {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _reporter = reporter;
                panic!("an unrelated panic with a live reporter");
            }));
            assert!(outcome.is_err());
        } else {
            drop(reporter);
        }
        assert!(
            panicked.get(),
            "premise: the domain read panicked, unwinding={unwinding}"
        );
        let poisoned = matches!(live.try_lock_quiet(), Err(GateError::Poisoned));
        // The planted root is malformed whatever the verdict; the storage's
        // own teardown must not read it.
        std::mem::forget(storage);
        assert!(
            poisoned,
            "the domain read's panic poisons the pool gate, unwinding={unwinding}"
        );
    }
}

#[test]
fn every_removed_member_has_exact_fingerprint_and_incarnation_in_stage_order() {
    let storage = ready(4);
    let expired = super::lookup_tests::publish(&storage, key(1), 2_000_000, &[1; 100]);
    let headroom = super::lookup_tests::publish(&storage, key(2), u64::MAX, &[2; 100]);
    for n in 3..=15 {
        publish_big(&storage, n);
    }
    let expired_fp = storage.route(&key(1)).unwrap().fingerprint();
    let headroom_fp = storage.route(&key(2)).unwrap().fingerprint();
    storage.platform.ticks(&[Some(3_000_000)]);
    storage.maintain.stage.store(
        MaintainStage::Expiry as usize,
        std::sync::atomic::Ordering::Relaxed,
    );
    let before = crate::instrument::allocations();
    let report = maintain(&storage);
    assert_eq!(crate::instrument::allocations(), before);
    assert_eq!((report.expired, report.evicted), (1, 1));
    assert_eq!(
        report.removed,
        [
            Some(super::RemovedMember {
                fingerprint: expired_fp,
                allocation: expired
            }),
            Some(super::RemovedMember {
                fingerprint: headroom_fp,
                allocation: headroom
            }),
        ]
    );
    let mut reader = storage.register().unwrap();
    for n in [1, 2] {
        assert!(matches!(
            lookup(&mut reader, &key(n), RETRIES),
            Err(super::LookupError::Missing)
        ));
    }
    for n in 3..=15 {
        assert!(lookup(&mut reader, &key(n), RETRIES).is_ok());
    }
}

#[test]
fn maintenance_reports_the_exact_successor_after_reclaim_and_slot_reuse() {
    let mut config = storage_config(2);
    config.volume.maintenance = Some(watermarks(2, 1));
    let limits = [2];
    let storage = super::publish_tests::storage_from(
        &config,
        &index_config(&limits, (1, 1), 1),
        TestPlatform::heap(PAGE),
    );
    storage.platform.ticks(&[Some(1)]);
    let old = super::lookup_tests::publish(&storage, key(1), u64::MAX, &[1; 100]);
    let survivor = super::lookup_tests::publish(&storage, key(2), u64::MAX, &[2; 100]);
    storage
        .invalidate(&key(1), RETRIES, &mut generous())
        .unwrap();
    for _ in 0..8 {
        let _ = storage.certify(&mut generous()).unwrap();
        storage.service(&mut generous()).unwrap();
        let word = storage.live_pool().unwrap().records()[old.slot_index()]
            .ident
            .load(std::sync::atomic::Ordering::Relaxed);
        if super::word::state(word) == super::SlotState::Free {
            break;
        }
    }
    let word = storage.live_pool().unwrap().records()[old.slot_index()]
        .ident
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(super::word::state(word), super::SlotState::Free);
    let successor = super::lookup_tests::publish(&storage, key(1), u64::MAX, &[3; 100]);
    assert_eq!(successor.slot_index(), old.slot_index());
    assert!(successor.incarnation() > old.incarnation());
    assert!(successor.incarnation() > 1);
    let fingerprint = storage.route(&key(1)).unwrap().fingerprint();
    let mut reader = storage.register().unwrap();
    let retained = lookup(&mut reader, &key(2), RETRIES).unwrap();
    assert_eq!(retained.id(), survivor);
    storage.maintain.stage.store(
        MaintainStage::Headroom as usize,
        std::sync::atomic::Ordering::Relaxed,
    );
    let before = crate::instrument::allocations();
    let report = maintain(&storage);
    assert_eq!(crate::instrument::allocations(), before);
    assert_eq!(report.started_in, MaintainStage::Headroom);
    assert_eq!((report.evicted, report.expired), (1, 0));
    assert_eq!(report.held, 1);
    assert_eq!(
        report.removed,
        [
            Some(super::RemovedMember {
                fingerprint,
                allocation: successor
            }),
            None,
        ]
    );
    assert!(matches!(
        lookup(&mut reader, &key(1), RETRIES),
        Err(super::LookupError::Missing)
    ));
    assert_eq!(
        lookup(&mut reader, &key(2), RETRIES).unwrap().id(),
        survivor
    );
    drop(retained);
}

/// `maintain_into` writes its caller's report on an open call alone. Over
/// identical histories that evict, the reports it writes equal the ones
/// `maintain` returns, removal identities included. A call refused
/// `BudgetExhausted` or `NotConfigured` and a call on closed storage leave
/// the caller's report as it arrived.
#[test]
fn maintain_into_writes_the_callers_report_on_an_open_call_alone() {
    let history = |in_place: bool| {
        let mut storage = ready(2);
        storage.install_hasher(crate::index::KeyHasher::with_key_pair(
            0x5eed_0001,
            0x5eed_0002,
        ));
        fill_big(&storage);
        (0..12)
            .map(|_| {
                if !in_place {
                    return maintain(&storage);
                }
                let mut report = MaintainReport::default();
                assert_eq!(
                    storage.maintain_into(&mut generous(), &mut report),
                    Ok(None)
                );
                report
            })
            .collect::<Vec<_>>()
    };
    let (by_value, in_place) = (history(false), history(true));
    assert!(by_value.iter().any(|report| report.evicted > 0));
    assert_eq!(by_value, in_place);

    let storage = ready(2);
    let mut report = MaintainReport::default();
    assert_eq!(
        storage.maintain_into(&mut WorkBudget::new(0), &mut report),
        Err(MaintainError::BudgetExhausted)
    );
    assert_eq!(report, MaintainReport::default());
    assert_eq!(
        storage_with(None).maintain_into(&mut generous(), &mut report),
        Err(MaintainError::NotConfigured)
    );
    assert_eq!(report, MaintainReport::default());
    storage.close();
    assert!(matches!(
        storage.maintain_into(&mut generous(), &mut report),
        Ok(Some(_))
    ));
    assert_eq!(report, MaintainReport::default());
}
