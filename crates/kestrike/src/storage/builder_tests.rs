//! Escrowed placement against two independent censuses: the promise
//! census sums each builder's remaining charge against the escrow and the
//! free units, and the physical census sums the free set against the units
//! the test knows are placed or claimed. Cases: exact and one-short
//! promises, refused promises and placements, direct claims beside
//! promised units, every cancellation cut of two- and three-extent objects
//! beside a second live builder, two builders interleaving, and a planted
//! defect that drops one promise's charge from the escrow, so a second
//! promise spends the same free units and the census rejects it.

use std::sync::atomic::Ordering;

use super::budget::WorkBudget;
use super::builder::{Builder, PromiseError};
use super::claim_exit_tests::{FILLING, FREE, PARKED, conserved_after_service, conserved_at};
use super::config::StorageConfig;
use super::gate::GateError;
use super::geometry::EXTENT_PAYLOAD;
use super::layout::IO_UNIT;
use super::owner::Storage;
use super::placement::PlacementConfig;
use super::reserve::ReserveError;
use super::test_platform::TestPlatform;

mod escrow_replay;

/// The body of a two-extent object.
const TWO: usize = EXTENT_PAYLOAD as usize + 1000;
/// The body of a three-extent object, the largest the storage admits.
const THREE: usize = 2 * EXTENT_PAYLOAD as usize + 1000;
const SLOTS: usize = 6;

/// A storage of `units` units with `block_roots` arena roots, whose
/// largest body is `body_cap` bytes.
fn storage_with(units: usize, block_roots: usize, body_cap: usize) -> Storage<TestPlatform> {
    let mut volume = crate::storage::test_volume(units * IO_UNIT, SLOTS);
    volume.alloc_search_words = crate::storage::work_bound(units as u64, SLOTS, 64);
    volume.block_roots = block_roots;
    let config = StorageConfig {
        page_size: 4096,
        engine_budget: 1 << 26,
        body_cap,
        metadata_cap: Some(0),
        lease_limit: 16,
        object_rights: 8,
        reader_limit: 2,
        volume,
    };
    Storage::initialize(
        &config.validate().unwrap(),
        &PlacementConfig { control_home: 0 },
        TestPlatform::heap(4096),
    )
    .unwrap()
}

/// A storage of `units` units whose largest object has three extents.
fn storage(units: usize) -> Storage<TestPlatform> {
    storage_with(units, 1, THREE)
}

/// A storage of `units` units whose largest object has two extents.
fn small(units: usize) -> Storage<TestPlatform> {
    storage_with(units, 1, TWO)
}

fn budget() -> WorkBudget {
    WorkBudget::new(1 << 20)
}

/// A budget that funds one placement of `builder`.
fn one(builder: &Builder<'_, TestPlatform>) -> WorkBudget {
    WorkBudget::new(builder.place_steps())
}

fn promise(
    storage: &Storage<TestPlatform>,
    body: usize,
) -> Result<Builder<'_, TestPlatform>, PromiseError> {
    storage.promise(Some(0), Some(body), &mut budget())
}

/// The charge of an object of `body` bytes, from a promise on a roomy
/// storage.
fn charge(body: usize) -> u64 {
    let storage = storage(1024);
    promise(&storage, body).unwrap().remaining()
}

/// A builder and the charge it promised.
type Owned<'a, 's> = (&'a Builder<'s, TestPlatform>, u64);

/// The escrow, the free units and the units claimable, read under the gate.
fn counts(storage: &Storage<TestPlatform>) -> (u64, u64, u64) {
    let live = storage.live_pool().unwrap();
    let mut access = live.lock().unwrap();
    let mut tables = access.tables();
    let escrow = live.telemetry().escrow();
    let free = tables.free_units();
    (
        escrow,
        free,
        super::reserve::claimable_units(&mut tables, live),
    )
}

/// The promise census: the escrow is the builders' remaining charge, the
/// units promised and not placed fit in the free units, and the report
/// shows the same escrow.
fn census(storage: &Storage<TestPlatform>, builders: &[Owned<'_, '_>]) -> Result<(), String> {
    let (escrow, free, _) = counts(storage);
    let remaining: u64 = builders
        .iter()
        .map(|(builder, _)| builder.remaining())
        .sum();
    if remaining > free {
        return Err(format!(
            "promised units exceed the free units: {remaining} of {free}"
        ));
    }
    if escrow != remaining {
        return Err(format!(
            "the escrow {escrow} is not the builders' remaining {remaining}"
        ));
    }
    let reported = storage.pool_report().unwrap().escrow_units;
    if reported != escrow {
        return Err(format!("the report shows escrow {reported}, not {escrow}"));
    }
    Ok(())
}

/// The physical census: each builder's block holds its placed extents,
/// the free set sums to the free units, and those plus the builders'
/// placed units and `direct` claimed units are the volume.
fn physical(
    storage: &Storage<TestPlatform>,
    units: usize,
    direct: u64,
    builders: &[Owned<'_, '_>],
) {
    let live = storage.live_pool().unwrap();
    let mut access = live.lock().unwrap();
    let mut tables = access.tables();
    let free = tables.free_units();
    let set: u64 = tables.extents().free_set().iter().map(|(_, len)| len).sum();
    assert_eq!(set, free, "the free set sums to the free units");
    for (builder, _) in builders {
        let slot = builder.id().slot().0;
        let (block, count, owner) = tables.sequence(slot).unwrap();
        let prefix = tables.blocks().prefix(block, owner, count).unwrap().len();
        assert_eq!(
            prefix,
            builder.placed() as usize,
            "the block holds every placed extent"
        );
    }
    let placed: u64 = builders
        .iter()
        .map(|(builder, charge)| charge - builder.remaining())
        .sum();
    assert_eq!(free + placed + direct, units as u64, "units are conserved");
}

/// Every unit and slot is free, the arena is whole and nothing is promised.
fn assert_whole(storage: &Storage<TestPlatform>, units: usize) {
    let live = storage.live_pool().unwrap();
    let mut access = live.lock().unwrap();
    let mut tables = access.tables();
    assert_eq!(tables.extents().free_set(), [(0, units as u64)]);
    assert_eq!(tables.state.ledger.free, SLOTS);
    assert_eq!(tables.blocks().free_bytes(), 32_768);
    assert_eq!(live.telemetry().escrow(), 0);
}

/// The slot ledger's free and filling counts, the free set and the arena's
/// free bytes, read under the gate.
fn snapshot(storage: &Storage<TestPlatform>) -> (usize, usize, Vec<(u64, u64)>, u64) {
    let live = storage.live_pool().unwrap();
    let mut access = live.lock().unwrap();
    let mut tables = access.tables();
    let ledger = tables.state.ledger;
    let set = tables.extents().free_set();
    (
        ledger.free,
        ledger.filling,
        set,
        tables.blocks().free_bytes(),
    )
}

/// Service calls until one returns nothing; each visit returns one extent,
/// so a three-extent object takes at most three.
fn serve_out(storage: &Storage<TestPlatform>) {
    for _ in 0..4 {
        let report = storage.service(&mut budget()).unwrap();
        if report.partial == 0 && report.serviced == 0 {
            return;
        }
    }
    panic!("service kept returning past three extents");
}

fn two_short_runs(storage: &Storage<TestPlatform>) -> super::ExtentReservation<'_, TestPlatform> {
    let first = direct(storage, 40);
    let pin = direct(storage, 1);
    let second = direct(storage, 40);
    first.cancel().unwrap();
    second.cancel().unwrap();
    assert_eq!(snapshot(storage).2, [(0, 40), (41, 41)]);
    pin
}

/// A direct object of `units` units.
fn direct(
    storage: &Storage<TestPlatform>,
    units: usize,
) -> super::ExtentReservation<'_, TestPlatform> {
    storage
        .reserve(Some(0), Some(units * IO_UNIT - 2048), &mut budget())
        .unwrap()
}

/// With the free units exactly the charge plus the clean reserve the
/// promise succeeds; one unit fewer refuses `CleanReserve` with the slots,
/// the free set, the arena and the escrow unchanged.
#[test]
fn an_exact_promise_succeeds_and_one_unit_short_refuses_with_no_change() {
    let charge = charge(TWO);
    let units = charge as usize + 1 + 1;
    let storage = small(units);
    let first = direct(&storage, 1);
    let second = direct(&storage, 1);
    let before = (counts(&storage), snapshot(&storage));
    assert_eq!(before.0, (0, charge, charge - 1));
    assert_eq!(
        promise(&storage, TWO).err(),
        Some(PromiseError::Reserve(ReserveError::CleanReserve))
    );
    assert_eq!((counts(&storage), snapshot(&storage)), before);
    second.cancel().unwrap();
    let builder = promise(&storage, TWO).unwrap();
    assert_eq!(counts(&storage), (charge, charge + 1, 0));
    census(&storage, &[(&builder, charge)]).unwrap();
    physical(&storage, units, 1, &[(&builder, charge)]);
    drop((builder, first));
}

#[test]
fn a_promise_refuses_bootstrapping_below_live_and_closed_after_withdrawal_changing_nothing() {
    use super::readiness::Event;
    let storage = storage(1024);
    storage.readiness.apply(Event::Attach).unwrap();
    let before = (counts(&storage), snapshot(&storage));
    assert_eq!(
        promise(&storage, TWO).err(),
        Some(PromiseError::Reserve(ReserveError::Bootstrapping))
    );
    assert_eq!((counts(&storage), snapshot(&storage)), before);
    storage.readiness.apply(Event::LoadComplete).unwrap();
    storage
        .readiness
        .apply(Event::BeginReplay {
            matches: true,
            rows: 0,
        })
        .unwrap();
    let builder = promise(&storage, TWO).unwrap();
    assert_eq!(storage.withdraw(), super::readiness::State::Withheld);
    let held = (counts(&storage), snapshot(&storage));
    assert_eq!(
        promise(&storage, TWO).err(),
        Some(PromiseError::Reserve(ReserveError::Closed))
    );
    assert_eq!((counts(&storage), snapshot(&storage)), held);
    drop(builder);
}

/// A one-extent object promises nothing; the reservation claims it.
#[test]
fn a_one_extent_object_promises_nothing() {
    let storage = storage(1024);
    assert_eq!(promise(&storage, 100).err(), Some(PromiseError::OneExtent));
    assert_eq!(counts(&storage).0, 0);
}

/// An arena with no block for the sequence refuses `Blocks` and restores
/// the taken slot: nothing changes, the gate is free, and the next claim
/// takes the same slot.
/// The restored slot is `Free` and the tables pass the conservation judge.
#[test]
fn a_refused_block_restores_the_slot_and_changes_nothing() {
    let storage = storage_with(1024, 0, THREE);
    let before = (counts(&storage), snapshot(&storage));
    assert_eq!(promise(&storage, TWO).err(), Some(PromiseError::Blocks));
    conserved_at(&storage, 0, FREE);
    assert_eq!((counts(&storage), snapshot(&storage)), before);
    let claimed = direct(&storage, 1);
    assert_eq!(claimed.id().slot().0, 0);
}

/// A budget that funds the gate try, the update and the slot take but not
/// the block allocation refuses `BudgetExhausted`, restores the slot, pays
/// the give-back, spends the rest and changes nothing else.
/// The restored slot is `Free` and the tables pass the conservation judge.
#[test]
fn an_unfunded_block_allocation_restores_the_slot_and_spends_the_rest() {
    let storage = storage(1024);
    let before = (counts(&storage), snapshot(&storage));
    let steps = 1 + 1 + super::reserve::TAKE_BUNDLE + super::blocks::BlockArena::ALLOCATE_STEPS - 1;
    let mut short = WorkBudget::new(steps);
    assert_eq!(
        storage.promise(Some(0), Some(TWO), &mut short).err(),
        Some(PromiseError::Reserve(ReserveError::BudgetExhausted))
    );
    conserved_at(&storage, 0, FREE);
    assert_eq!(short.remaining(), 0);
    assert_eq!((counts(&storage), snapshot(&storage)), before);
    assert_eq!(direct(&storage, 1).id().slot().0, 0);
}

/// A direct claim spends only units outside the escrow: with one builder's
/// charge promised and nothing placed, a direct claim of the units left
/// beyond the clean reserve succeeds and one more refuses.
#[test]
fn a_direct_claim_leaves_promised_units_alone() {
    let charge = charge(TWO);
    let units = charge as usize + 1 + 1;
    let storage = small(units);
    let builder = promise(&storage, TWO).unwrap();
    let claimed = direct(&storage, 1);
    assert_eq!(
        storage.reserve(Some(0), Some(100), &mut budget()).err(),
        Some(ReserveError::CleanReserve)
    );
    census(&storage, &[(&builder, charge)]).unwrap();
    physical(&storage, units, 1, &[(&builder, charge)]);
    drop((claimed, builder));
}

/// Every placement refusal preserves the storage's tables and the builder's
/// placement; only a no-run refusal sets the waiting flag, and progress
/// clears it.
#[test]
fn a_refused_placement_preserves_placement_and_sets_the_waiting_flag() {
    // Runs of 40 and 41 units hold the charge in total and no full extent.
    let units = 82;
    let storage = small(units);
    let pin = two_short_runs(&storage);
    let charge = charge(TWO);
    let mut builder = promise(&storage, TWO).unwrap();
    let live = storage.live_pool().unwrap();
    let state = |builder: &Builder<'_, TestPlatform>| {
        (
            counts(&storage),
            snapshot(&storage),
            builder.remaining(),
            builder.placed(),
        )
    };
    let before = state(&builder);
    let slot = builder.id().slot_index();
    // A fresh builder's gate and budget refusals leave it not waiting.
    let held = live.lock().unwrap();
    assert!(matches!(
        builder.place(&mut budget()).err(),
        Some(PromiseError::Reserve(ReserveError::Gate(_)))
    ));
    drop(held);
    conserved_at(&storage, slot, FILLING);
    assert_eq!(
        builder.place(&mut WorkBudget::new(0)).err(),
        Some(PromiseError::Reserve(ReserveError::BudgetExhausted))
    );
    conserved_at(&storage, slot, FILLING);
    assert_eq!(
        (state(&builder), builder.waiting()),
        (before.clone(), false)
    );
    // The no-run refusal changes no table, placement or escrow state and
    // sets the waiting flag.
    assert_eq!(
        builder.place(&mut budget()).err(),
        Some(PromiseError::Reserve(ReserveError::PayloadFull))
    );
    conserved_at(&storage, slot, FILLING);
    assert_eq!((state(&builder), builder.waiting()), (before.clone(), true));
    assert_eq!(
        builder.place(&mut budget()).err(),
        Some(PromiseError::Reserve(ReserveError::PayloadFull))
    );
    conserved_at(&storage, slot, FILLING);
    assert_eq!((state(&builder), builder.waiting()), (before.clone(), true));
    // An unfunded placement refuses at its preflight, before the gate.
    assert_eq!(
        builder.place(&mut WorkBudget::new(0)).err(),
        Some(PromiseError::Reserve(ReserveError::BudgetExhausted))
    );
    conserved_at(&storage, slot, FILLING);
    assert_eq!(state(&builder), before);
    let held = live.lock().unwrap();
    assert!(matches!(
        builder.place(&mut budget()).err(),
        Some(PromiseError::Reserve(ReserveError::Gate(_)))
    ));
    drop(held);
    conserved_at(&storage, slot, FILLING);
    assert_eq!((state(&builder), builder.waiting()), (before.clone(), true));
    pin.cancel().unwrap();
    assert!(!builder.place(&mut one(&builder)).unwrap());
    assert!(!builder.waiting(), "progress clears the waiting flag");
    census(&storage, &[(&builder, charge)]).unwrap();
    physical(&storage, units, 0, &[(&builder, charge)]);
    drop(builder);
}

#[derive(Debug, Clone, Copy)]
enum End {
    Cancel,
    CancelBusy,
    Drop,
}

/// Every cancellation cut: a builder of two or three extents ends after
/// each count of placements by a cancel with the gate free, a cancel with
/// the gate busy or a drop, while a second builder holds its own promise.
/// The ending refunds exactly the remaining charge once: the escrow is the
/// other builder's remaining after the end, after the gate frees and after
/// service. Placement completes the builder only at its last extent.
/// Right after each end and after one service pass the tables pass the
/// conservation judge: a cancel with the gate free leaves the slot `Free`, a
/// cancel with the gate busy and a drop park it as `Filling` with `ABANDONED`,
/// and one service pass frees a parked slot that holds at most one placed
/// extent.
#[test]
fn every_cancellation_cut_refunds_once_and_service_returns_the_rest() {
    let units = 1024;
    for body in [TWO, THREE] {
        let charge = charge(body);
        let extents = 2 + usize::from(body == THREE);
        for placed in 0..=extents {
            for end in [End::Cancel, End::CancelBusy, End::Drop] {
                let case = format!("body {body}, {placed} placed, {end:?}");
                let storage = storage(units);
                let mut other = promise(&storage, TWO).unwrap();
                other.place(&mut one(&other)).unwrap();
                let other_charge = self::charge(TWO);
                let mut builder = promise(&storage, body).unwrap();
                for index in 0..placed {
                    let complete = builder.place(&mut one(&builder)).unwrap();
                    assert_eq!(complete, index + 1 == extents, "{case}");
                    assert_eq!(builder.is_complete(), complete, "{case}");
                    census(&storage, &[(&builder, charge), (&other, other_charge)]).unwrap();
                    physical(
                        &storage,
                        units,
                        0,
                        &[(&builder, charge), (&other, other_charge)],
                    );
                }
                assert!(!builder.waiting(), "{case}: a builder that never waited");
                let live = storage.live_pool().unwrap();
                let escrow = || live.telemetry().escrow();
                let slot = builder.id().slot_index();
                match end {
                    End::Cancel => {
                        builder.cancel();
                        // A free gate returns the builder at once.
                        assert_eq!(snapshot(&storage).1, 1, "{case}");
                    }
                    End::CancelBusy => {
                        let held = live.lock().unwrap();
                        builder.cancel();
                        assert_eq!(escrow(), other.remaining(), "{case}");
                        drop(held);
                    }
                    End::Drop => drop(builder),
                }
                assert_eq!(escrow(), other.remaining(), "{case}");
                // One service pass returns one placed extent of a parked slot.
                let (at_exit, after_service) = match (end, placed) {
                    (End::Cancel, _) => (FREE, FREE),
                    (_, 0 | 1) => (PARKED, FREE),
                    _ => (PARKED, PARKED),
                };
                conserved_at(&storage, slot, at_exit);
                let (_, free_before, _) = counts(&storage);
                conserved_after_service(&storage, slot, after_service);
                if after_service == PARKED {
                    let (_, free_after, _) = counts(&storage);
                    assert!(
                        free_after > free_before,
                        "{case}: the pass returned an extent"
                    );
                }
                serve_out(&storage);
                census(&storage, &[(&other, other_charge)]).unwrap();
                physical(&storage, units, 0, &[(&other, other_charge)]);
                other.cancel();
                serve_out(&storage);
                assert_whole(&storage, units);
            }
        }
    }
}

/// A waiting builder refunds its whole charge once on every exit: a cancel
/// with the gate free, a cancel that finds it busy and refunds without it,
/// and a drop. Each case starts from the 40- and 41-unit runs of a
/// two-extent object's refused placement, so the builder waits before the
/// exit, and service then leaves the storage whole beside the pin.
#[test]
fn a_waiting_builder_refunds_once_on_every_exit() {
    for end in [End::Cancel, End::CancelBusy, End::Drop] {
        let units = 82;
        let storage = small(units);
        let pin = two_short_runs(&storage);
        let mut builder = promise(&storage, TWO).unwrap();
        assert!(!builder.waiting(), "{end:?}");
        assert_eq!(
            builder.place(&mut budget()).err(),
            Some(PromiseError::Reserve(ReserveError::PayloadFull))
        );
        assert!(builder.waiting(), "{end:?}");
        let live = storage.live_pool().unwrap();
        let escrow = || live.telemetry().escrow();
        match end {
            End::Cancel => {
                builder.cancel();
            }
            End::CancelBusy => {
                let held = live.lock().unwrap();
                builder.cancel();
                assert_eq!(escrow(), 0, "the gate-free refund");
                drop(held);
            }
            End::Drop => drop(builder),
        }
        assert_eq!(escrow(), 0, "{end:?}");
        serve_out(&storage);
        assert_eq!(snapshot(&storage).2, [(0, 40), (41, 41)], "{end:?}");
        pin.cancel().unwrap();
        assert_whole(&storage, units);
    }
}

fn run_bound(storage: &Storage<TestPlatform>) -> (u64, u64) {
    let live = storage.live_pool().unwrap();
    let mut access = live.lock().unwrap();
    let longest = access.tables().extents().longest_free_run();
    let bound = live.telemetry().run_bound();
    access.release();
    (bound, longest)
}

/// A placement on a root summary shorter than the extent refuses after the
/// gate try and one visit. While the run bound stays below the waited
/// extent, a retry refuses `PayloadFull` even with the gate held, where a
/// placement refuses `Gate`, and preserves the escrow, the free set, the
/// slots, the builder's placement and its waiting flag. An unfunded retry
/// refuses `BudgetExhausted` at that proof's preflight, and the builder's
/// slot stays `Filling` with the tables passing the conservation judge. A
/// return that leaves every run shorter than the waited extent preserves
/// that refusal; the pin's return joins the runs, and the retry places.
#[test]
fn a_waiting_retry_refuses_without_the_gate_until_a_return_joins_a_run() {
    let units = 82;
    let storage = small(units);
    let pin = two_short_runs(&storage);
    let charge = charge(TWO);
    let mut builder = promise(&storage, TWO).unwrap();
    let live = storage.live_pool().unwrap();
    let state = |builder: &Builder<'_, TestPlatform>| {
        (
            counts(&storage),
            snapshot(&storage),
            builder.remaining(),
            builder.placed(),
        )
    };
    let mut first = budget();
    let funded = first.remaining();
    assert_eq!(
        builder.place(&mut first).err(),
        Some(PromiseError::Reserve(ReserveError::PayloadFull))
    );
    assert_eq!(
        funded - first.remaining(),
        2,
        "the gate try and the root read"
    );
    let before = state(&builder);
    let held = live.lock().unwrap();
    assert_eq!(
        builder.retry(&mut budget()).err(),
        Some(PromiseError::Reserve(ReserveError::PayloadFull)),
        "the bound proves the refusal without the gate"
    );
    assert!(matches!(
        builder.place(&mut budget()).err(),
        Some(PromiseError::Reserve(ReserveError::Gate(_)))
    ));
    drop(held);
    assert!(
        builder.waiting() && storage.proves_no_run(builder.wait_units()),
        "premise: the retry refuses at its no-run preflight"
    );
    assert_eq!(
        builder.retry(&mut WorkBudget::new(0)).err(),
        Some(PromiseError::Reserve(ReserveError::BudgetExhausted))
    );
    conserved_at(&storage, builder.id().slot_index(), FILLING);
    assert_eq!((state(&builder), builder.waiting()), (before.clone(), true));
    direct(&storage, 1).cancel().unwrap();
    assert_eq!(run_bound(&storage), (41, 41));
    let held = live.lock().unwrap();
    assert_eq!(
        builder.retry(&mut budget()).err(),
        Some(PromiseError::Reserve(ReserveError::PayloadFull))
    );
    drop(held);
    assert_eq!((state(&builder), builder.waiting()), (before, true));
    pin.cancel().unwrap();
    assert_eq!(run_bound(&storage), (82, 82));
    assert!(!builder.retry(&mut one(&builder)).unwrap());
    assert!(!builder.waiting(), "progress clears the waiting flag");
    census(&storage, &[(&builder, charge)]).unwrap();
    physical(&storage, units, 0, &[(&builder, charge)]);
    drop(builder);
    serve_out(&storage);
}

/// The run bound equals the longest free run after every return and bounds
/// it from above after every claim.
#[test]
fn the_run_bound_tracks_returns_and_covers_the_longest_run_after_claims() {
    let units = 512;
    let storage = small(units);
    assert_eq!(run_bound(&storage).0, u64::MAX, "no return yet");
    let mut held = Vec::new();
    let mut seed = 0x9E37_79B9_7F4A_7C15_u64;
    for _ in 0..400 {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let pick = (seed >> 33) as usize;
        if held.is_empty() || !pick.is_multiple_of(3) {
            if let Ok(claim) = storage.reserve(
                Some(0),
                Some((1 + pick % 40) * IO_UNIT - 2048),
                &mut budget(),
            ) {
                held.push(claim);
            }
            let (bound, longest) = run_bound(&storage);
            assert!(bound >= longest, "after a claim: {bound} < {longest}");
        } else {
            held.swap_remove(pick % held.len()).cancel().unwrap();
            let (bound, longest) = run_bound(&storage);
            assert_eq!(bound, longest, "after a return");
        }
    }
    for claim in held {
        claim.cancel().unwrap();
    }
    assert_eq!(run_bound(&storage), (units as u64, units as u64));
}

#[test]
fn a_run_bound_below_the_units_proves_no_run_and_a_join_ends_the_proof() {
    let storage = small(82);
    assert!(!storage.proves_no_run(u64::MAX), "no return yet");
    let pin = two_short_runs(&storage);
    assert_eq!(run_bound(&storage), (41, 41));
    assert!(storage.proves_no_run(42) && !storage.proves_no_run(41));
    pin.cancel().unwrap();
    assert!(storage.proves_no_run(83) && !storage.proves_no_run(82));
}

#[test]
fn a_waiting_retry_places_when_the_longest_run_equals_the_waited_extent() {
    let units = 138;
    let storage = storage(units);
    let first = storage
        .reserve(Some(0), Some(EXTENT_PAYLOAD as usize), &mut budget())
        .unwrap();
    let pin = direct(&storage, 1);
    let second = direct(&storage, 62);
    let wall = direct(&storage, 1);
    let third = direct(&storage, 10);
    for claimed in [first, second, third] {
        claimed.cancel().unwrap();
    }
    let mut builder = promise(&storage, THREE).unwrap();
    assert!(!builder.place(&mut budget()).unwrap());
    assert_eq!(
        run_bound(&storage),
        (63, 62),
        "a claim leaves the bound high"
    );
    assert_eq!(
        builder.retry(&mut budget()).err(),
        Some(PromiseError::Reserve(ReserveError::PayloadFull))
    );
    assert!(builder.waiting());
    assert_eq!(
        run_bound(&storage),
        (62, 62),
        "the refusal under the gate lowers the bound to the longest run"
    );
    let held = storage.live_pool().unwrap().lock().unwrap();
    assert_eq!(
        builder.retry(&mut budget()).err(),
        Some(PromiseError::Reserve(ReserveError::PayloadFull)),
        "the lowered bound refuses the next retry without the gate"
    );
    drop(held);
    conserved_at(&storage, builder.id().slot_index(), FILLING);
    pin.cancel().unwrap();
    assert_eq!(run_bound(&storage), (63, 63));
    assert!(builder.retry(&mut budget()).unwrap());
    assert!(!builder.waiting());
    builder.cancel();
    drop(wall);
    serve_out(&storage);
}

#[test]
fn a_service_return_of_a_sequence_s_last_extent_sets_the_run_bound() {
    let storage = storage(1024);
    let mut builder = promise(&storage, THREE).unwrap();
    assert!(builder.place(&mut budget()).unwrap());
    let slot = builder.id().slot().0;
    drop(builder);
    assert_eq!(run_bound(&storage).0, u64::MAX, "no return yet");
    let live = storage.live_pool().unwrap();
    let mut access = live.lock().unwrap();
    let mut tables = access.tables();
    let (block, count, _) = tables.sequence(slot).unwrap();
    let before = tables.extents().longest_free_run();
    let returned = super::reserve::return_last(
        &mut tables,
        live,
        slot,
        (block, count),
        super::extent::HeldPhase::Reserved,
    );
    assert!(returned.is_some());
    let longest = tables.extents().longest_free_run();
    let bound = live.telemetry().run_bound();
    access.release();
    assert!(longest > before, "the extent joins the free tail");
    assert_eq!(bound, longest);
    serve_out(&storage);
}

/// Two builders interleave placement and cancel; both censuses hold at
/// every step.
#[test]
fn two_builders_interleave_placement_and_cancel_and_reconcile() {
    let units = 1024;
    let storage = storage(units);
    let (two, three) = (charge(TWO), charge(THREE));
    let mut first = promise(&storage, THREE).unwrap();
    let mut second = promise(&storage, TWO).unwrap();
    let check = |owned: &[Owned<'_, '_>]| {
        census(&storage, owned).unwrap();
        physical(&storage, units, 0, owned);
    };
    check(&[(&first, three), (&second, two)]);
    first.place(&mut one(&first)).unwrap();
    check(&[(&first, three), (&second, two)]);
    second.place(&mut one(&second)).unwrap();
    first.place(&mut one(&first)).unwrap();
    check(&[(&first, three), (&second, two)]);
    second.cancel();
    check(&[(&first, three)]);
    assert!(first.place(&mut one(&first)).unwrap());
    check(&[(&first, three)]);
    first.cancel();
    assert_whole(&storage, units);
}

#[test]
fn a_funded_placement_places_every_extent_in_one_hold() {
    let units = 1024;
    let storage = storage(units);
    let three = charge(THREE);
    let mut builder = promise(&storage, THREE).unwrap();
    assert!(!builder.place(&mut one(&builder)).unwrap());
    assert_eq!(builder.placed(), 1);
    assert!(builder.place(&mut budget()).unwrap());
    assert_eq!((builder.placed(), builder.remaining()), (3, 0));
    census(&storage, &[(&builder, three)]).unwrap();
    physical(&storage, units, 0, &[(&builder, three)]);
    builder.cancel();
    assert_whole(&storage, units);
}

#[test]
fn a_later_extent_without_a_run_ends_the_hold_after_the_earlier_ones() {
    // Of the free runs of 63, 62 and 11 units, the 63-unit run alone holds
    // a full extent; cancelling `pin` joins its unit to the 62-unit run,
    // which then holds the second.
    let units = 138;
    let storage = storage(units);
    let first = storage
        .reserve(Some(0), Some(EXTENT_PAYLOAD as usize), &mut budget())
        .unwrap();
    let pin = direct(&storage, 1);
    let second = direct(&storage, 62);
    let wall = direct(&storage, 1);
    let third = direct(&storage, 10);
    for claimed in [first, second, third] {
        claimed.cancel().unwrap();
    }
    assert_eq!(snapshot(&storage).2, [(0, 63), (64, 62), (127, 11)]);
    let three = charge(THREE);
    let mut builder = promise(&storage, THREE).unwrap();
    assert!(!builder.place(&mut budget()).unwrap());
    assert_eq!((builder.placed(), builder.waiting()), (1, false));
    census(&storage, &[(&builder, three)]).unwrap();
    physical(&storage, units, 2, &[(&builder, three)]);
    let before = (counts(&storage), snapshot(&storage), builder.remaining());
    assert_eq!(
        builder.place(&mut budget()).err(),
        Some(PromiseError::Reserve(ReserveError::PayloadFull))
    );
    conserved_at(&storage, builder.id().slot_index(), FILLING);
    assert_eq!(
        (counts(&storage), snapshot(&storage), builder.remaining()),
        before
    );
    assert!(builder.waiting(), "a builder with placed extents waits too");
    pin.cancel().unwrap();
    assert!(builder.place(&mut budget()).unwrap());
    assert!(!builder.waiting());
    census(&storage, &[(&builder, three)]).unwrap();
    physical(&storage, units, 1, &[(&builder, three)]);
    // The return joins the two full extents and leaves `wall`'s unit
    // between them and the last extent held.
    builder.cancel();
    assert_eq!(snapshot(&storage).2, [(0, 126), (127, 11)]);
    wall.cancel().unwrap();
    assert_whole(&storage, units);
}

/// A body of whole extents makes the last extent as long as the others,
/// so one funded call places every extent.
#[test]
fn an_object_of_whole_extents_places_its_last_extent_with_the_run() {
    let units = 1024;
    for extents in [2, 3] {
        let storage = storage_with(units, 1, 3 * EXTENT_PAYLOAD as usize);
        let body = extents * EXTENT_PAYLOAD as usize;
        let mut builder = promise(&storage, body).unwrap();
        let charge = builder.remaining();
        assert_eq!(charge, 63 * extents as u64);
        assert!(builder.place(&mut budget()).unwrap());
        census(&storage, &[(&builder, charge)]).unwrap();
        physical(&storage, units, 0, &[(&builder, charge)]);
        builder.cancel();
        assert_whole(&storage, units);
    }
}

#[test]
fn a_budget_of_two_placements_bounds_the_hold() {
    let units = 1024;
    let storage = storage(units);
    let three = charge(THREE);
    let mut builder = promise(&storage, THREE).unwrap();
    let mut two = WorkBudget::new(2 * builder.place_steps());
    builder.place(&mut two).unwrap();
    assert!(builder.placed() >= 2);
    assert!(builder.is_complete() || two.remaining() < builder.place_steps());
    census(&storage, &[(&builder, three)]).unwrap();
    physical(&storage, units, 0, &[(&builder, three)]);
    while !builder.is_complete() {
        builder.place(&mut one(&builder)).unwrap();
    }
    builder.cancel();
    assert_whole(&storage, units);
}

/// A complete builder places nothing more.
#[test]
#[should_panic(expected = "a complete builder places nothing")]
fn a_complete_builder_refuses_another_placement() {
    let storage = storage(1024);
    let mut builder = promise(&storage, TWO).unwrap();
    while !builder.place(&mut budget()).unwrap() {}
    let _ = builder.place(&mut budget());
}

/// A promise whose charge leaves the escrow lets a second promise spend
/// the same free units, and the census fails.
#[test]
fn negative_control_a_duplicate_promise_spends_the_same_free_units() {
    let charge = charge(TWO);
    let units = charge as usize + 1 + 2;
    let storage = small(units);
    let first = promise(&storage, TWO).unwrap();
    // The planted defect: the first promise's charge leaves the escrow.
    let live = storage.live_pool().unwrap();
    live.telemetry().refund(charge);
    let second = promise(&storage, TWO).unwrap();
    let verdict = census(&storage, &[(&first, charge), (&second, charge)]);
    assert!(
        verdict
            .as_ref()
            .is_err_and(|v| v.starts_with("promised units exceed the free units")),
        "{verdict:?}"
    );
    live.telemetry()
        .refunded
        .fetch_sub(charge, Ordering::Relaxed);
    drop((first, second));
}

/// A placement that panics under the gate poisons it even when a destructor
/// runs it, and catches its panic, while the thread unwinds from another
/// panic (`place`, "# Panics"): the guard, taken during the unwind, would
/// release open on drop. The block is planted already full, so the panic
/// comes after the allocator reserved the run.
#[test]
fn a_placement_panic_during_unwinding_poisons_the_gate() {
    struct PlacesOnDrop<'a, 's> {
        builder: &'a mut Builder<'s, TestPlatform>,
        panicked: &'a std::cell::Cell<bool>,
    }
    impl Drop for PlacesOnDrop<'_, '_> {
        fn drop(&mut self) {
            let mut funded = one(self.builder);
            let builder = &mut *self.builder;
            let placed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                builder.place(&mut funded)
            }));
            self.panicked.set(placed.is_err());
        }
    }
    let storage = storage(1024);
    let mut builder = promise(&storage, TWO).unwrap();
    let live = storage.live_pool().unwrap();
    let count = u64::from(builder.extents());
    let header = builder.block().0 as usize * 4;
    let mut access = live.lock().unwrap();
    access
        .tables()
        .blocks()
        .plant_word(header + 1, count | count << 32);
    access.release();
    let panicked = std::cell::Cell::new(false);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _placer = PlacesOnDrop {
            builder: &mut builder,
            panicked: &panicked,
        };
        panic!("an unrelated panic with a live placer");
    }));
    assert!(outcome.is_err());
    assert!(panicked.get(), "premise: the placement panicked");
    assert!(
        matches!(live.try_lock_quiet(), Err(GateError::Poisoned)),
        "the placement's panic poisons the gate"
    );
}

/// A promise whose slot take panics under the gate poisons it, on a thread
/// that is not unwinding and from a destructor that catches the panic while
/// its thread unwinds from another (`take_slot`, "# Panics": the caller
/// holds the gate, so the panic poisons it). Slot 0 is free with a counted
/// word; the take has removed it from the free set when it panics.
#[test]
fn a_promise_whose_take_panics_poisons_the_gate_even_during_unwinding() {
    struct PromisesOnDrop<'a> {
        storage: &'a Storage<TestPlatform>,
        panicked: &'a std::cell::Cell<bool>,
    }
    impl Drop for PromisesOnDrop<'_> {
        fn drop(&mut self) {
            let storage = self.storage;
            let promised = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                promise(storage, TWO).map(|builder| builder.id())
            }));
            self.panicked.set(promised.is_err());
        }
    }
    for unwinding in [false, true] {
        let storage = storage(1024);
        let live = storage.live_pool().unwrap();
        {
            let _held = live.lock().unwrap();
            live.set_refs(0, 1);
        }
        let panicked = std::cell::Cell::new(false);
        if unwinding {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _promiser = PromisesOnDrop {
                    storage: &storage,
                    panicked: &panicked,
                };
                panic!("an unrelated panic with a live promiser");
            }));
            assert!(outcome.is_err());
        } else {
            drop(PromisesOnDrop {
                storage: &storage,
                panicked: &panicked,
            });
        }
        assert!(
            panicked.get(),
            "premise: the promise panicked, unwinding={unwinding}"
        );
        assert!(
            matches!(live.try_lock_quiet(), Err(GateError::Poisoned)),
            "the take's panic poisons the gate, unwinding={unwinding}"
        );
    }
}

/// Runs `step` from a destructor that catches its panic, directly or while
/// the thread unwinds from an unrelated panic, and returns whether the step
/// panicked.
fn panics_in_a_destructor(unwinding: bool, step: impl FnOnce()) -> bool {
    struct StepsOnDrop<'a, F: FnOnce()> {
        step: Option<F>,
        panicked: &'a std::cell::Cell<bool>,
    }
    impl<F: FnOnce()> Drop for StepsOnDrop<'_, F> {
        fn drop(&mut self) {
            let step = self.step.take().unwrap();
            let stepped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(step));
            self.panicked.set(stepped.is_err());
        }
    }
    let panicked = std::cell::Cell::new(false);
    let stepper = StepsOnDrop {
        step: Some(step),
        panicked: &panicked,
    };
    if unwinding {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _stepper = stepper;
            panic!("an unrelated panic with a live stepper");
        }));
        assert!(outcome.is_err());
    } else {
        drop(stepper);
    }
    panicked.get()
}

/// The lowest reserved bit of a slot word.
fn reserved_bit(word: u64) -> u64 {
    word | 1 << super::word::RESERVED.trailing_zeros()
}

/// A builder's cancel checks its slot's word under the gate, refuses a
/// reserved bit, and the panic poisons the pool gate (`Pool::gate_state`,
/// "# Panics": "the caller holds the gate, so the panic poisons it"), on a
/// thread that is not unwinding and from a destructor that cancels while its
/// thread unwinds from another panic: the guard, taken during the unwind,
/// would release open on drop.
#[test]
fn a_reserved_bit_poisons_the_builder_s_cancel_even_during_unwinding() {
    for unwinding in [false, true] {
        let storage = storage(1024);
        let mut builder = promise(&storage, TWO).unwrap();
        assert!(!builder.place(&mut one(&builder)).unwrap());
        let live = storage.live_pool().unwrap();
        live.edit_word(builder.id().slot().0, reserved_bit);
        let panicked = panics_in_a_destructor(unwinding, || {
            builder.cancel();
        });
        assert!(
            panicked,
            "premise: the cancel panicked, unwinding={unwinding}"
        );
        assert!(
            matches!(live.try_lock_quiet(), Err(GateError::Poisoned)),
            "the check's panic poisons the gate, unwinding={unwinding}"
        );
    }
}

/// A reservation's cancel makes the same check under the gate, and its
/// panic poisons the pool gate also during unwinding. The owner drops as the
/// panic leaves the cancel; under a gate left open its abandonment would
/// read the same word under a second hold and panic inside the destructor.
#[test]
fn a_reserved_bit_poisons_the_owner_s_cancel_even_during_unwinding() {
    for unwinding in [false, true] {
        let storage = storage(1024);
        let owner = storage.reserve(Some(0), Some(100), &mut budget()).unwrap();
        let live = storage.live_pool().unwrap();
        live.edit_word(owner.id().slot().0, reserved_bit);
        let panicked = panics_in_a_destructor(unwinding, || {
            let _ = owner.cancel();
        });
        assert!(
            panicked,
            "premise: the cancel panicked, unwinding={unwinding}"
        );
        assert!(
            matches!(live.try_lock_quiet(), Err(GateError::Poisoned)),
            "the check's panic poisons the gate, unwinding={unwinding}"
        );
    }
}

/// A reservation's completion makes the same check under the gate before it
/// binds the record, and its panic poisons the pool gate also during
/// unwinding; the owner drops as for the cancel.
#[test]
fn a_reserved_bit_poisons_the_owner_s_completion_even_during_unwinding() {
    for unwinding in [false, true] {
        let storage = storage(1024);
        let mut owner = storage.reserve(Some(0), Some(100), &mut budget()).unwrap();
        let live = storage.live_pool().unwrap();
        live.edit_word(owner.id().slot().0, reserved_bit);
        let panicked = panics_in_a_destructor(unwinding, || {
            owner.mark_written();
            let _ = owner.complete(
                super::lookup_tests::key(0x67),
                100_000_000_000,
                &mut budget(),
            );
        });
        assert!(
            panicked,
            "premise: the completion panicked, unwinding={unwinding}"
        );
        assert!(
            matches!(live.try_lock_quiet(), Err(GateError::Poisoned)),
            "the check's panic poisons the gate, unwinding={unwinding}"
        );
    }
}

/// The park's marks on `slot`: the pending-mark counter, the word's flags
/// and the slot's bit in the parked set.
fn marks(storage: &Storage<TestPlatform>, slot: usize) -> (usize, u64, bool) {
    let live = storage.live_pool().unwrap();
    (
        live.telemetry().pending_marks.load(Ordering::Acquire),
        live.flags(slot),
        live.parked_slots()[slot / 64].load(Ordering::Acquire) & (1 << (slot % 64)) != 0,
    )
}

/// What [`snapshot`] reads: the ledger's free and filling slot counts, the
/// free set and the arena's free bytes.
type Snapshot = (usize, usize, Vec<(u64, u64)>, u64);

/// A three-extent builder on an empty storage with its first extent placed
/// and charge remaining, and the empty storage's snapshot.
fn partly_placed(storage: &Storage<TestPlatform>) -> (Builder<'_, TestPlatform>, Snapshot) {
    let empty = snapshot(storage);
    let mut builder = promise(storage, THREE).unwrap();
    let charge = builder.remaining();
    assert!(!builder.place(&mut one(&builder)).unwrap());
    assert_eq!(builder.placed(), 1);
    assert!(0 < builder.remaining() && builder.remaining() < charge);
    let escrow = storage.live_pool().unwrap().telemetry().escrow();
    assert_eq!(escrow, builder.remaining());
    (builder, empty)
}

/// The slot keeps the builder's incarnation and a well-formed word but is
/// `Resident`, so the hold's check does not find the builder. The cancel
/// takes the free gate: the escrow falls by the whole remaining charge,
/// the ledger, the free set and the arena stay as the placement left them,
/// and the park counts one pending mark, flags the word and sets the slot's
/// parked bit, all before any service. With the state restored, service
/// finds the park and returns the placed extent, the block and the slot.
#[test]
fn a_gate_held_cancel_over_a_slot_in_another_state_refunds_and_parks_it_for_service() {
    use super::tables::SlotState;
    use super::word::ABANDONED;

    let storage = storage(1024);
    let live = storage.live_pool().unwrap();
    let (builder, empty) = partly_placed(&storage);
    let (slot, incarnation) = (builder.id().slot_index(), builder.id().incarnation());
    let placed = snapshot(&storage);
    assert_ne!(placed, empty);
    assert_eq!(marks(&storage, slot), (0, 0, false));

    live.set_state(slot, SlotState::Resident);
    assert_eq!(
        storage.slot_state(builder.id().slot()),
        Some((SlotState::Resident, incarnation))
    );
    builder.cancel();

    assert_eq!(
        live.telemetry().refunded.load(Ordering::Acquire),
        0,
        "the cancel took the gate"
    );
    assert_eq!(live.telemetry().escrow(), 0, "the hold refunds the charge");
    assert_eq!(snapshot(&storage), placed, "the hold returns nothing");
    assert_eq!(live.gate_state(slot), (SlotState::Resident, incarnation));
    assert_eq!(
        marks(&storage, slot),
        (1, ABANDONED, true),
        "a slot the hold does not return goes to the park"
    );

    live.set_state(slot, SlotState::Filling);
    serve_out(&storage);
    assert_eq!(snapshot(&storage), empty, "service returns the parked slot");
    assert_eq!(marks(&storage, slot), (0, 0, false));
    assert_eq!(live.telemetry().escrow(), 0);
}

/// The slot names a later incarnation than the builder's. The cancel takes
/// the free gate and refunds the charge, leaves the ledger, the free set
/// and the arena as the placement left them, and hands the slot and the
/// builder's incarnation to the park once; the park leaves a word that
/// names another incarnation unmarked.
#[test]
fn a_gate_held_cancel_over_a_slot_of_another_incarnation_refunds_and_parks_without_a_mark() {
    use super::probe;
    use super::tables::SlotState;

    let storage = storage(1024);
    let live = storage.live_pool().unwrap();
    let (builder, _) = partly_placed(&storage);
    let (slot, incarnation) = (builder.id().slot_index(), builder.id().incarnation());
    let placed = snapshot(&storage);

    live.set_incarnation(slot, incarnation + 1);
    probe::arm();
    builder.cancel();
    probe::disarm();

    let log = probe::events();
    assert!(!log.overflowed);
    assert_eq!(
        live.telemetry().refunded.load(Ordering::Acquire),
        0,
        "the cancel took the gate"
    );
    assert_eq!(live.telemetry().escrow(), 0, "the hold refunds the charge");
    assert_eq!(snapshot(&storage), placed, "the hold returns nothing");
    assert_eq!(
        log.events
            .iter()
            .filter(|event| **event == probe::Event::Parked { slot })
            .count(),
        1,
        "a slot the hold does not return goes to the park"
    );
    assert_eq!(live.gate_state(slot), (SlotState::Filling, incarnation + 1));
    assert_eq!(marks(&storage, slot), (0, 0, false));
}
