//! Slots that own extent sequences: the dual locator encoding over every
//! direct value and generated tagged values, a census of sequence objects
//! built through storage-level setup, whole-sequence returns by cancel and
//! extent-by-extent returns by service, stale and wrong-owner refusals
//! beside a successor, and a planted cleanup that names its block through
//! a reused slot.

use std::sync::atomic::Ordering;

use super::allocation::{AllocationId, ExtentReservation};
use super::block_order::ROOT_BYTES;
use super::blocks::{ArenaError, Block, BlockArena};
use super::budget::WorkBudget;
use super::config::StorageConfig;
use super::extent::{ExtentLocator, HeldPhase, LOCATOR_LEN_LIMIT, LOCATOR_START_LIMIT};
use super::geometry::EXTENT_PAYLOAD;
use super::held::{DIRECT_UNITS, Held};
use super::layout::IO_UNIT;
use super::owner::Storage;
use super::placement::PlacementConfig;
use super::record::RecordConfig;
use super::seeded::SplitMix64;
use super::tables::{SlotState, release_extent};
use super::test_platform::TestPlatform;

const UNITS: usize = 512;
const SLOTS: usize = 4;

/// A storage of 512 units and `slots` slots whose largest object fits one
/// extent, with one arena root.
fn storage_of(slots: usize) -> Storage<TestPlatform> {
    storage_sized(UNITS, slots)
}

fn storage_sized(units: usize, slots: usize) -> Storage<TestPlatform> {
    storage_built(units, slots, None)
}

/// As [`storage_of`], with headroom watermarks `maintenance`, which
/// maintenance needs.
pub(super) fn storage_with(
    slots: usize,
    maintenance: Option<super::volume::VolumeWatermarks>,
) -> Storage<TestPlatform> {
    storage_built(UNITS, slots, maintenance)
}

/// A storage of `units` units and `slots` slots with one arena root and
/// headroom watermarks `maintenance`.
fn storage_built(
    units: usize,
    slots: usize,
    maintenance: Option<super::volume::VolumeWatermarks>,
) -> Storage<TestPlatform> {
    let mut volume = crate::storage::test_volume(units * IO_UNIT, slots);
    volume.alloc_search_words = crate::storage::work_bound(units as u64, slots, 64);
    volume.block_roots = 1;
    volume.maintenance = maintenance;
    let config = StorageConfig {
        page_size: 4096,
        engine_budget: 1 << 26,
        body_cap: 200_000,
        metadata_cap: Some(64),
        lease_limit: 64,
        object_rights: 8,
        reader_limit: 4,
        volume,
    };
    Storage::initialize(
        &config.validate().unwrap(),
        &PlacementConfig { control_home: 0 },
        TestPlatform::heap(4096),
    )
    .unwrap()
}

pub(super) fn storage() -> Storage<TestPlatform> {
    storage_of(SLOTS)
}

pub(super) fn budget() -> WorkBudget {
    WorkBudget::new(1 << 20)
}

/// Units of one full extent: a record of [`EXTENT_PAYLOAD`] bytes.
fn full_units() -> u32 {
    let config = RecordConfig { chunk_len: 8192 }.validate().unwrap();
    config.layout(0, EXTENT_PAYLOAD as u32).record_units() as u32
}

/// One owned object as the test built it: its owner, its block for
/// `count` extents, the held extents in order, and their payload bytes.
pub(super) struct Object {
    pub(super) owner: AllocationId,
    pub(super) block: Block,
    pub(super) count: u32,
    pub(super) extents: Vec<ExtentLocator>,
    pub(super) payload: usize,
}

/// The block order for `count` locators behind the 16-byte header, by
/// doubling from 32 bytes.
fn order_of(count: u32) -> u32 {
    (0..=10)
        .find(|&order| 32 << order >= 16 + 8 * count)
        .unwrap()
}

/// Turns `reservation`'s one extent into the last extent of a sequence of
/// `count`: under the gate it takes a block, reserves the `count - 1` full
/// extents before the last, appends all `count` in order and stores the
/// sequence handle in the slot's record, as a producer of a multi-extent
/// object does.
pub(super) fn sequence(
    storage: &Storage<TestPlatform>,
    reservation: &ExtentReservation<'_, TestPlatform>,
    count: u32,
) -> Object {
    built(storage, reservation, count, count)
}

/// As [`sequence`], with only the first `held` of the `count` extents
/// reserved and appended; a partial prefix gives the reservation's own
/// extent back, since every extent of it carries a full extent's payload.
pub(super) fn built(
    storage: &Storage<TestPlatform>,
    reservation: &ExtentReservation<'_, TestPlatform>,
    count: u32,
    held: u32,
) -> Object {
    built_for(storage, reservation.id(), count, held)
}

/// `published_sequence` models a published multi-extent object by holding every extent and publishing the full extents' payload.
pub(super) fn published_sequence(
    storage: &Storage<TestPlatform>,
    owner: AllocationId,
    count: u32,
) -> Object {
    let object = built_for(storage, owner, count, count);
    let live = storage.live_pool().unwrap();
    let mut access = live.lock().unwrap();
    access
        .tables()
        .publish_payload((count as usize - 1) * EXTENT_PAYLOAD as usize);
    access.release();
    object
}

/// As [`built`], for the object `owner` names, whatever owner holds it;
/// the extents it adds carry reserved payload.
pub(super) fn built_for(
    storage: &Storage<TestPlatform>,
    owner: AllocationId,
    count: u32,
    held: u32,
) -> Object {
    let live = storage.live_pool().unwrap();
    let mut access = live.lock().unwrap();
    let mut tables = access.tables();
    let slot = owner.slot_index();
    let last = tables.held_locator(slot);
    let payload = live.held_charge(&mut tables, slot).0;
    let mut budget = budget();
    let block = tables.blocks().allocate(owner, count, &mut budget).unwrap();
    let mut extents = Vec::new();
    for _ in 1..count.min(held + 1) {
        let units = full_units();
        let limit = live.image.extent_bound;
        let extent = tables
            .extents()
            .reserve(units, EXTENT_PAYLOAD as usize, limit, &mut budget)
            .unwrap();
        extents.push(extent);
    }
    let payload = if held == count {
        extents.push(last);
        payload + (count as usize - 1) * EXTENT_PAYLOAD as usize
    } else {
        release_extent(&mut tables.extents(), last, HeldPhase::Reserved, payload);
        held as usize * EXTENT_PAYLOAD as usize
    };
    for &extent in &extents {
        tables
            .blocks()
            .open(block, owner, count)
            .and_then(|mut prefix| prefix.push(extent))
            .unwrap();
    }
    live.records()[slot].set_locator(Held::Sequence { block, count }.locator());
    Object {
        owner,
        block,
        count,
        extents,
        payload,
    }
}

/// Each returned sequence has separated extents, so returning the
/// sequence takes one allocator run per extent.
fn interleaved(
    storage: &Storage<TestPlatform>,
    reservations: [&ExtentReservation<'_, TestPlatform>; 2],
    count: u32,
) -> [Object; 2] {
    let live = storage.live_pool().unwrap();
    let mut access = live.lock().unwrap();
    let mut tables = access.tables();
    let mut budget = budget();
    let units = full_units();
    let limit = live.image.extent_bound;
    let mut objects = reservations.map(|reservation| {
        let owner = reservation.id();
        let slot = owner.slot_index();
        Object {
            owner,
            block: tables.blocks().allocate(owner, count, &mut budget).unwrap(),
            count,
            extents: Vec::new(),
            payload: live.held_charge(&mut tables, slot).0
                + (count as usize - 1) * EXTENT_PAYLOAD as usize,
        }
    });
    for _ in 1..count {
        for object in &mut objects {
            let extent = tables
                .extents()
                .reserve(units, EXTENT_PAYLOAD as usize, limit, &mut budget)
                .unwrap();
            object.extents.push(extent);
        }
    }
    for object in &mut objects {
        let slot = object.owner.slot_index();
        object.extents.push(tables.held_locator(slot));
        for &extent in &object.extents {
            tables
                .blocks()
                .open(object.block, object.owner, count)
                .and_then(|mut prefix| prefix.push(extent))
                .unwrap();
        }
        let handle = Held::Sequence {
            block: object.block,
            count,
        };
        live.records()[slot].set_locator(handle.locator());
    }
    objects
}

/// Checks the owned objects `objects` against the tables: each slot's
/// record names its sequence, whose block holds exactly its extents in
/// order; the units and payload the gate holder derives are the objects';
/// the arena's free bytes and the objects' blocks fill its root; no two
/// of the objects' extents share a unit and none lies in a free run; each object's payload sits in
/// the ledger phase of its slot's state, `others`, the payload of the direct
/// objects also owned, sits in the reserved phase, and the raw-byte ledger sums to the volume.
pub(super) fn census(
    storage: &Storage<TestPlatform>,
    objects: &[&Object],
    others: usize,
) -> Result<(), String> {
    let live = storage.live_pool().unwrap();
    let mut access = live.lock().unwrap();
    let mut tables = access.tables();
    let mut owned: Vec<(u64, u64)> = Vec::new();
    let mut arena_bytes = 0;
    for object in objects {
        let slot = object.owner.slot_index();
        let count = object.count;
        let named = Held::Sequence {
            block: object.block,
            count,
        };
        if tables.held(slot) != named || tables.owner(slot) != object.owner {
            return Err(format!("slot {slot} names another object"));
        }
        let arena = tables.blocks();
        let bits: Vec<u64> = object.extents.iter().map(|extent| extent.bits()).collect();
        match arena.prefix(object.block, object.owner, count) {
            Ok(prefix) if prefix == &bits[..] => {}
            Ok(_) => return Err(format!("slot {slot} lost an extent of its prefix")),
            Err(_) => {
                return Err(format!(
                    "a live object lost its sequence block at slot {slot}"
                ));
            }
        }
        owned.extend(
            object
                .extents
                .iter()
                .map(|e| (e.start_unit(), u64::from(e.len_units()))),
        );
        arena_bytes += 32 << order_of(count);
        let units: u32 = object.extents.iter().map(|extent| extent.len_units()).sum();
        if tables.held_units(slot) != units
            || live.held_charge(&mut tables, slot) != (object.payload, units)
        {
            return Err(format!("slot {slot} derives other units or payload"));
        }
    }
    if tables.blocks().free_bytes() + arena_bytes != ROOT_BYTES {
        return Err("the arena's free bytes and the objects' blocks miss the root".into());
    }
    owned.extend(tables.extents().free_set());
    owned.sort_unstable();
    if owned
        .windows(2)
        .any(|pair| pair[0].0 + pair[0].1 > pair[1].0)
    {
        return Err("two extents or an extent and a free run share a unit".into());
    }
    let ledger = tables.extents().ledger();
    // Each object's payload sits in the phase of its slot's state; the
    // direct objects in `others` are filling.
    let mut phases = [others, 0, 0];
    for object in objects {
        match live.gate_state(object.owner.slot_index()).0 {
            SlotState::Filling => phases[0] += object.payload,
            SlotState::Resident => phases[1] += object.payload,
            SlotState::Retired => phases[2] += object.payload,
            state => return Err(format!("an object in state {state:?}")),
        }
    }
    let total = ledger.free + ledger.reserved + ledger.resident + ledger.retired + ledger.waste;
    if [ledger.reserved, ledger.resident, ledger.retired] != phases || total != UNITS * IO_UNIT {
        let payload = phases;
        return Err(format!(
            "the ledger {ledger:?} misses the objects' filling, resident and retired payload {payload:?}"
        ));
    }
    Ok(())
}

/// Whether the volume is whole again: every unit free, every slot free and
/// the arena's root listed whole.
pub(super) fn whole(storage: &Storage<TestPlatform>) -> bool {
    let live = storage.live_pool().unwrap();
    let mut access = live.lock().unwrap();
    let mut tables = access.tables();
    tables.extents().free_set() == [(0, UNITS as u64)]
        && tables.state.ledger.free == live.records().len()
        && tables.blocks().free_bytes() == 32_768
}

#[test]
fn every_direct_locator_decodes_unchanged_and_invalid_tags_fail_closed() {
    let starts = [0, 1, 4095, 1 << 32, LOCATOR_START_LIMIT - 1];
    for len in 0..=DIRECT_UNITS {
        for start in starts {
            let direct = ExtentLocator::new(start, len).unwrap();
            for record_len in [0, 1, 512, 4097, u64::from(len) * 4096] {
                let ended = direct.ending_at(record_len);
                assert_eq!(
                    Held::decode(ended),
                    Some(Held::Direct(ended)),
                    "{len} {start}"
                );
                assert_eq!(Held::Direct(ended).locator(), ended);
            }
        }
    }
    let mut rng = SplitMix64::new(0x5eed);
    for _ in 0..10_000 {
        let held = Held::Sequence {
            block: Block(rng.next_u64() as u32),
            count: 2 + rng.below(2114) as u32,
        };
        assert_eq!(Held::decode(held.locator()), Some(held));
    }
    for (block, count) in [(0, 2), (0, 2115), (u32::MAX, 2), (u32::MAX, 2115)] {
        let held = Held::Sequence {
            block: Block(block),
            count,
        };
        assert_eq!(Held::decode(held.locator()), Some(held));
    }
    let tagged = |start: u64, len: u32| ExtentLocator::new(start, len).unwrap();
    for invalid in [
        tagged(1 << 32, DIRECT_UNITS + 2115),
        tagged(0, DIRECT_UNITS + 1),
        tagged(0, DIRECT_UNITS + 2116),
        tagged(0, LOCATOR_LEN_LIMIT - 1),
        tagged(1 << 32, DIRECT_UNITS + 2),
        tagged(0, DIRECT_UNITS + 2).ending_at(u64::from(DIRECT_UNITS + 1) * 4096 + 1),
    ] {
        assert_eq!(Held::decode(invalid), None, "{invalid:?}");
    }
    for _ in 0..100_000 {
        let bits = ExtentLocator::from_bits(rng.next_u64());
        if let Some(held) = Held::decode(bits) {
            assert_eq!(
                held.locator(),
                bits,
                "a decoded locator encodes back to itself"
            );
        }
    }
}

/// Two sequence objects and a direct one pass the census; cancelling the
/// direct one leaves both sequences intact; cancelling a sequence returns
/// its extents, block and slot within its return's work bound and leaves
/// the other sequence intact.
#[test]
fn a_cancelled_sequence_returns_every_extent_its_block_and_its_slot_once() {
    let storage = storage();
    let small = storage
        .reserve(Some(10), Some(1000), &mut budget())
        .unwrap();
    let second = storage.reserve(Some(0), Some(300), &mut budget()).unwrap();
    let direct = storage.reserve(Some(0), Some(5000), &mut budget()).unwrap();
    let object = sequence(&storage, &small, 3);
    let other = sequence(&storage, &second, 2);
    census(&storage, &[&object, &other], 5000).unwrap();
    direct.cancel().unwrap();
    census(&storage, &[&object, &other], 0).unwrap();
    let live = storage.live_pool().unwrap();
    let work = live.held_work(live.records()[small.id().slot_index()].locator());
    assert_eq!(
        work,
        3 * (1 + live.image.extent_bound) + BlockArena::FREE_STEPS
    );
    super::reserve::take_return_visits();
    small.cancel().unwrap();
    let visits = super::reserve::take_return_visits();
    assert!(visits >= 3 && visits <= work, "{visits} of {work}");
    census(&storage, &[&other], 0).unwrap();
    second.cancel().unwrap();
    census(&storage, &[], 0).unwrap();
    assert!(whole(&storage));
}

/// Sequences whose extents interleave return only their own extents:
/// the first return leaves the other sequence's extents held between the
/// freed runs, with return visits from 3 through `held_work`; the second
/// joins every run back into the free volume.
#[test]
fn interleaved_sequences_return_only_their_own_extents() {
    let storage = storage();
    let first = storage.reserve(Some(0), Some(100), &mut budget()).unwrap();
    let second = storage.reserve(Some(0), Some(300), &mut budget()).unwrap();
    let [one, two] = interleaved(&storage, [&first, &second], 3);
    for object in [&one, &two] {
        for pair in object.extents.windows(2) {
            let end = pair[0].start_unit() + u64::from(pair[0].len_units());
            assert_ne!(end, pair[1].start_unit(), "extents of one sequence adjoin");
            let end = pair[1].start_unit() + u64::from(pair[1].len_units());
            assert_ne!(end, pair[0].start_unit(), "extents of one sequence adjoin");
        }
    }
    census(&storage, &[&one, &two], 0).unwrap();
    let live = storage.live_pool().unwrap();
    for (reservation, other) in [(first, Some(&two)), (second, None)] {
        let work = live.held_work(live.records()[reservation.id().slot_index()].locator());
        super::reserve::take_return_visits();
        reservation.cancel().unwrap();
        let visits = super::reserve::take_return_visits();
        assert!(visits >= 3 && visits <= work, "{visits} of {work}");
        census(&storage, other.as_slice(), 0).unwrap();
    }
    assert!(whole(&storage));
}

/// A run of adjoining extents requires every unit to be held before it
/// returns: with the middle full extent already free, the run's return
/// fails closed and poisons the gate.
#[test]
fn a_run_with_a_free_unit_fails_closed() {
    let storage = storage();
    let reservation = storage.reserve(Some(0), Some(100), &mut budget()).unwrap();
    let object = sequence(&storage, &reservation, 3);
    let freed = object.extents[1];
    let adjoining = object.extents[0].start_unit() + u64::from(object.extents[0].len_units());
    assert_eq!(adjoining, freed.start_unit(), "the full extents adjoin");
    {
        let live = storage.live_pool().unwrap();
        let mut access = live.lock().unwrap();
        let mut tables = access.tables();
        release_extent(
            &mut tables.extents(),
            freed,
            HeldPhase::Reserved,
            EXTENT_PAYLOAD as usize,
        );
    }
    super::slot_tests::poisons(&storage, super::tables::EXTENT_REFUSED, || {
        let _ = reservation.cancel();
    });
}

/// Cancellation poisons the gate when the sequence holds an empty extent
/// or a 10-unit extent beside 62 adjoining full extents.
#[test]
fn a_run_admits_only_extents_whose_own_returns_pass() {
    for odd_units in [0, 10] {
        let storage = storage_sized(8192, SLOTS);
        let others: Vec<_> = (0..2)
            .map(|_| {
                storage
                    .reserve(Some(0), Some(200_000), &mut budget())
                    .unwrap()
            })
            .collect();
        let reservation = storage.reserve(Some(0), Some(100), &mut budget()).unwrap();
        {
            let live = storage.live_pool().unwrap();
            let mut access = live.lock().unwrap();
            let mut tables = access.tables();
            let (owner, slot) = (reservation.id(), reservation.id().slot_index());
            let mut budget = budget();
            let block = tables.blocks().allocate(owner, 64, &mut budget).unwrap();
            let units = full_units();
            let mut end = None;
            for _ in 0..62 {
                let extent = tables
                    .extents()
                    .reserve(
                        units,
                        EXTENT_PAYLOAD as usize,
                        live.image.extent_bound,
                        &mut budget,
                    )
                    .unwrap();
                assert!(end.is_none_or(|end| end == extent.start_unit()));
                end = Some(extent.start_unit() + u64::from(extent.len_units()));
                tables
                    .blocks()
                    .open(block, owner, 64)
                    .and_then(|mut prefix| prefix.push(extent))
                    .unwrap();
            }
            let end = end.unwrap();
            let odd = if odd_units == 0 {
                ExtentLocator::new(end, 0).unwrap()
            } else {
                let limit = live.image.extent_bound;
                let payload = odd_units as usize * IO_UNIT;
                tables
                    .extents()
                    .reserve(odd_units, payload, limit, &mut budget)
                    .unwrap()
            };
            assert_eq!(odd.start_unit(), end, "the odd extent adjoins the run");
            let last = tables.held_locator(slot);
            for extent in [odd, last] {
                tables
                    .blocks()
                    .open(block, owner, 64)
                    .and_then(|mut prefix| prefix.push(extent))
                    .unwrap();
            }
            let handle = Held::Sequence { block, count: 64 };
            live.records()[slot].set_locator(handle.locator());
        }
        super::slot_tests::poisons(&storage, super::tables::EXTENT_REFUSED, || {
            let _ = reservation.cancel();
        });
        std::mem::forget(others);
    }
}

/// A partial prefix, none or two of three extents appended, returns the
/// full extents it holds and its block, restoring the full free volume.
#[test]
fn a_partial_prefix_returns_exactly_what_it_holds() {
    for held in [0, 2] {
        let storage = storage();
        let reservation = storage.reserve(Some(0), Some(100), &mut budget()).unwrap();
        let object = built(&storage, &reservation, 3, held);
        census(&storage, &[&object], 0).unwrap();
        reservation.cancel().unwrap();
        census(&storage, &[], 0).unwrap();
        assert!(whole(&storage));
    }
}

/// What a return preflights: the extent work bound for a direct extent, a
/// sequence's pops, bounds and block steps, and the bound for a locator of
/// neither form.
#[test]
fn the_return_work_covers_each_form() {
    let storage = storage();
    let live = storage.live_pool().unwrap();
    let direct = ExtentLocator::new(5, 7).unwrap();
    assert_eq!(live.held_work(direct), live.image.extent_bound);
    let handle = Held::Sequence {
        block: Block(0),
        count: 9,
    };
    let per = 1 + live.image.extent_bound;
    assert_eq!(
        live.held_work(handle.locator()),
        9 * per + BlockArena::FREE_STEPS
    );
    let neither = ExtentLocator::new(0, DIRECT_UNITS + 1).unwrap();
    assert_eq!(live.held_work(neither), live.image.extent_bound);
    let bound = storage.pool_report().unwrap().extent_bound;
    for units in 0..=DIRECT_UNITS {
        let direct = ExtentLocator::new(5, units).unwrap();
        assert!(live.held_work(direct) <= bound, "{units} units");
    }
    assert!(live.held_work(neither) <= bound);
    assert!(live.held_work(handle.locator()) > bound);
    // The configuration limits state a sequence visit's steps.
    assert_eq!(super::release::SEQUENCE_VISIT, 22);
}

/// An abandoned sequence object returns one extent per service call funded
/// at the minimum, which covers one extent's return and the final block
/// cleanup: the first call returns the last held extent and leaves the
/// slot pending, the second returns the rest, the block and the slot.
#[test]
fn service_returns_an_abandoned_sequence_one_extent_per_visit() {
    let storage = storage();
    let reservation = storage.reserve(Some(0), Some(100), &mut budget()).unwrap();
    let mut object = sequence(&storage, &reservation, 2);
    let units: u32 = object.extents.iter().map(|extent| extent.len_units()).sum();
    census(&storage, &[&object], 0).unwrap();
    drop(reservation);
    let mut minimum = WorkBudget::new(storage.service_minimum());
    let report = storage.service(&mut minimum).unwrap();
    assert_eq!((report.serviced, report.partial), (0, 1), "{report:?}");
    // The last extent carries the object's own payload past the full ones.
    let last = object.extents.pop().unwrap();
    object.payload = EXTENT_PAYLOAD as usize;
    assert_eq!(report.reclaimed_bytes, last.len_units() as usize * IO_UNIT);
    census(&storage, &[&object], 0).unwrap();
    let mut minimum = WorkBudget::new(storage.service_minimum());
    let report = storage.service(&mut minimum).unwrap();
    assert_eq!((report.serviced, report.partial), (1, 0), "{report:?}");
    assert_eq!(
        report.reclaimed_bytes,
        (units - last.len_units()) as usize * IO_UNIT
    );
    census(&storage, &[], 0).unwrap();
    assert!(whole(&storage));
}

/// A returned sequence's slot keeps the handle in its record until the
/// next claim. A stale parked bit on that free slot is sized as a free
/// slot's visit, so a call funded at the minimum clears it and reaches the
/// parked obligation behind it.
#[test]
fn a_stale_park_on_a_freed_sequence_slot_costs_a_free_slot_visit() {
    let storage = storage();
    let reservation = storage.reserve(Some(0), Some(100), &mut budget()).unwrap();
    let object = sequence(&storage, &reservation, 2);
    let slot = object.owner.slot_index();
    drop(reservation);
    // One extent per visit: the second call's visit returns the rest.
    assert_eq!(storage.service(&mut budget()).unwrap().partial, 1);
    assert_eq!(storage.service(&mut budget()).unwrap().serviced, 1);
    let live = storage.live_pool().unwrap();
    let state = |slot| super::service_tests::state(&storage, slot);
    assert_eq!(state(slot), SlotState::Free);
    assert!(
        matches!(
            Held::decode(live.records()[slot].locator()),
            Some(Held::Sequence { .. })
        ),
        "the freed record keeps its sequence handle"
    );
    // A park whose bit landed after its retirement absorbed it.
    super::pending::mark_parked::<_, super::pending::Published>(
        live.parked_slots(),
        live.parked_summary(),
        slot,
    );
    // A parked obligation behind the stale bit keeps the park pass running.
    let direct = storage.reserve(Some(0), Some(100), &mut budget()).unwrap();
    let parked = direct.id().slot_index();
    assert!(parked > slot);
    assert_eq!(
        storage.return_allocation(direct.release(), &mut WorkBudget::new(0)),
        Ok(super::release::ReturnOutcome::PendingBudget)
    );
    let report = storage
        .service(&mut WorkBudget::new(storage.service_minimum()))
        .unwrap();
    assert_eq!(report.skipped, 1, "{report:?}");
    assert_eq!(
        live.parked_slots()[slot / 64].load(Ordering::Relaxed) & (1 << (slot % 64)),
        0,
        "the stale bit is cleared"
    );
    let mut calls = 0;
    while state(parked) != SlotState::Free {
        calls += 1;
        assert!(calls <= 4, "the parked direct object never returned");
        storage
            .service(&mut WorkBudget::new(storage.service_minimum()))
            .unwrap();
    }
    assert_eq!(live.telemetry().pending_marks.load(Ordering::Relaxed), 0);
}

/// A stale parked bit on a retired sequence's slot is the park pass's to
/// clear on a slot bundle alone, so a call funded at the minimum clears the
/// bit and reaches the parked obligation behind it, while the retired pass
/// returns the sequence one extent per call.
#[test]
fn a_stale_park_on_a_retired_sequence_slot_costs_a_slot_bundle() {
    let storage = storage();
    let reservation = storage.reserve(Some(0), Some(100), &mut budget()).unwrap();
    let object = sequence(&storage, &reservation, 2);
    let slot = object.owner.slot_index();
    drop(reservation);
    let live = storage.live_pool().unwrap();
    let state = |slot| super::service_tests::state(&storage, slot);
    assert_eq!(state(slot), SlotState::Retired);
    super::pending::mark_parked::<_, super::pending::Published>(
        live.parked_slots(),
        live.parked_summary(),
        slot,
    );
    let direct = storage.reserve(Some(0), Some(100), &mut budget()).unwrap();
    let parked = direct.id().slot_index();
    assert!(parked > slot);
    assert_eq!(
        storage.return_allocation(direct.release(), &mut WorkBudget::new(0)),
        Ok(super::release::ReturnOutcome::PendingBudget)
    );
    let report = storage
        .service(&mut WorkBudget::new(storage.service_minimum()))
        .unwrap();
    assert_eq!(report.skipped, 1, "{report:?}");
    assert_eq!(report.partial, 1, "{report:?}");
    assert_eq!(state(slot), SlotState::Retired, "{report:?}");
    assert_eq!(
        live.parked_slots()[slot / 64].load(Ordering::Relaxed) & (1 << (slot % 64)),
        0,
        "the stale bit is cleared"
    );
    let mut calls = 0;
    while state(parked) != SlotState::Free || state(slot) != SlotState::Free {
        calls += 1;
        assert!(
            calls <= 4,
            "the parked direct object or the sequence never returned"
        );
        storage
            .service(&mut WorkBudget::new(storage.service_minimum()))
            .unwrap();
    }
    assert_eq!(live.telemetry().pending_marks.load(Ordering::Relaxed), 0);
    assert!(whole(&storage));
}

#[test]
fn a_parked_sequence_returns_beside_held_retired_objects_under_the_minimum() {
    const HELD: usize = 60;
    let storage = storage_sized(1024, HELD + 1);
    let mut leases = Vec::new();
    for slot in 0..HELD {
        let (resident, lease) = super::service_tests::resident_at(&storage, slot);
        drop(resident);
        leases.push(lease);
    }
    let live = storage.live_pool().unwrap();
    live.claim_next(HELD);
    let reservation = storage.reserve(Some(0), Some(100), &mut budget()).unwrap();
    assert_eq!(reservation.id().slot_index(), HELD);
    sequence(&storage, &reservation, 6);
    let gate = live.lock().unwrap();
    drop(reservation);
    drop(gate);
    let state = |slot| super::service_tests::state(&storage, slot);
    assert_eq!(state(HELD), SlotState::Filling, "the sequence is parked");
    // Six extents, one per minimum-funded call, beside the held retired
    // objects the retired pass spends its allowance on.
    let mut calls = 0;
    while state(HELD) != SlotState::Free {
        calls += 1;
        assert!(calls <= 6, "the parked sequence never returned");
        let report = storage
            .service(&mut WorkBudget::new(storage.service_minimum()))
            .unwrap();
        assert!(report.held > 0, "{report:?}");
        assert_eq!(report.partial + report.serviced, 1, "{report:?}");
        assert!((0..HELD).all(|slot| state(slot) == SlotState::Retired));
    }
    assert_eq!(calls, 6);
    assert_eq!(live.telemetry().pending_marks.load(Ordering::Relaxed), 0);
    drop(leases);
}

/// After a sequence returns and a successor takes its slot, a pop, an
/// append and a free under the old identity refuse with the successor
/// intact:
/// `Owner` where the successor's block starts at the old block, and
/// `NotLive` where the old block lies inside the successor's larger one.
#[test]
fn stale_and_wrong_owner_operations_refuse_with_the_successor_intact() {
    for (spacer, count) in [(false, 2), (true, 6)] {
        let storage = storage_of(1);
        let first = storage.reserve(Some(0), Some(100), &mut budget()).unwrap();
        let live = storage.live_pool().unwrap();
        let held = AllocationId::new(super::tables::SlotIndex(9), 1);
        let spacer_block = spacer.then(|| {
            let mut access = live.lock().unwrap();
            let block = access.tables().blocks().allocate(held, 2, &mut budget());
            block.unwrap()
        });
        let old = sequence(&storage, &first, 2);
        first.cancel().unwrap();
        if let Some(block) = spacer_block {
            let mut access = live.lock().unwrap();
            access
                .tables()
                .blocks()
                .free(block, held, 2, &mut budget())
                .unwrap();
        }
        let successor = storage.reserve(Some(0), Some(100), &mut budget()).unwrap();
        assert_eq!(
            successor.id().slot_index(),
            old.owner.slot_index(),
            "the slot is reused"
        );
        let new = sequence(&storage, &successor, count);
        census(&storage, &[&new], 0).unwrap();
        let expected = if spacer {
            assert_ne!(new.block, old.block);
            ArenaError::NotLive { block: old.block }
        } else {
            assert_eq!(new.block, old.block);
            ArenaError::Owner {
                expected: old.owner.record_tag(),
                found: new.owner.record_tag(),
            }
        };
        {
            let mut access = live.lock().unwrap();
            let mut tables = access.tables();
            let mut arena = tables.blocks();
            assert_eq!(
                arena
                    .open(old.block, old.owner, 2)
                    .map(|mut prefix| prefix.pop()),
                Err(expected)
            );
            assert_eq!(
                arena
                    .open(old.block, old.owner, 2)
                    .and_then(|mut prefix| prefix.push(new.extents[0])),
                Err(expected)
            );
            assert_eq!(
                arena.free(old.block, old.owner, 2, &mut budget()),
                Err(expected)
            );
        }
        census(&storage, &[&new], 0).unwrap();
        successor.cancel().unwrap();
        assert!(whole(&storage));
    }
}

/// A cleanup that names its block through the slot, as an early slot
/// return would leave it, reaches the successor's block once the slot is
/// reused, and the census fails; the cleanup holding its own identity
/// refuses, as `stale_and_wrong_owner_operations_refuse_with_the_successor_intact`
/// shows.
#[test]
fn negative_control_an_early_slot_free_lets_stale_cleanup_free_the_successor() {
    let storage = storage_of(1);
    let first = storage.reserve(Some(0), Some(100), &mut budget()).unwrap();
    let slot = first.id().slot_index();
    sequence(&storage, &first, 2);
    first.cancel().unwrap();
    let successor = storage.reserve(Some(0), Some(100), &mut budget()).unwrap();
    let new = sequence(&storage, &successor, 2);
    {
        let live = storage.live_pool().unwrap();
        let mut access = live.lock().unwrap();
        let mut tables = access.tables();
        let Held::Sequence { block, count } = tables.held(slot) else {
            panic!("the successor holds a sequence");
        };
        // The planted cleanup: the slot's current identity, not its own.
        let owner = tables.owner(slot);
        let mut arena = tables.blocks();
        let mut prefix = arena.open(block, owner, count).unwrap();
        while prefix.pop().is_some() {}
        arena.free(block, owner, count, &mut budget()).unwrap();
    }
    assert_eq!(
        census(&storage, &[&new], 0),
        Err(format!(
            "a live object lost its sequence block at slot {slot}"
        ))
    );
    std::mem::forget(successor);
}
