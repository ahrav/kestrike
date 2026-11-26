//! The write guard at the payload write gate: the pure overlap rule, and armed and unarmed writes through
//! `Volume::write_at` over the volume fixture with caller-supplied locators.

use super::super::blocks::Block;
use super::super::device::sim::Captured;
use super::super::device::{BufferArena, DeviceRange, IO_UNIT, Operation, PoolKind};
use super::super::evict_tests::drain;
use super::super::extent::ExtentLocator;
use super::super::held::{DIRECT_UNITS, Held};
use super::super::lenses::HeldExtent;
use super::super::owner_fixture::{
    Device, arena, invalidate, publish, publish_sequence, sequence_storage, storage,
};
use super::super::publish_tests::key;
use super::super::tables::SlotIndex;
use super::super::test_platform::TestPlatform;
use super::super::volume_fixture::settle;
use super::super::word;
use super::super::word::SlotState;
use super::super::{AllocationId, ExtentReservation, Storage, WorkBudget};
use super::volume_tests::{ATTEMPT, ATTEMPT_SERIAL};
use super::write::WriteSet;
use super::write_guard::{Conflict, Guarded, W1, arm, conflict, take};

const META: usize = 16;

fn held(storage: &Storage<TestPlatform>) -> (Vec<HeldExtent>, u64) {
    let mut held = Vec::new();
    let skipped = storage.held_extents_into(&mut held).expect("a live pool");
    (held, skipped)
}

fn id(slot: usize, incarnation: u32) -> AllocationId {
    AllocationId::new(SlotIndex(slot), incarnation)
}

fn range(start: u64, len: u32) -> DeviceRange {
    DeviceRange::new(start, len).expect("an aligned range")
}

fn extent(holder: AllocationId, bytes: std::ops::Range<u64>) -> HeldExtent {
    HeldExtent { holder, bytes }
}

/// Reserves a slot and begins its fill over `locator` or, with `None`, over the slot's own extent. Returns the
/// reservation, which keeps the slot `Filling`, and the set.
fn begin<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    device: &mut Device<'s, 'a>,
    locator: Option<ExtentLocator>,
) -> (ExtentReservation<'s, TestPlatform>, WriteSet) {
    let reservation = storage
        .reserve(Some(0), Some(64), &mut WorkBudget::new(1 << 16))
        .expect("an extent");
    let locator = locator.unwrap_or(reservation.locator());
    let set = device
        .volume
        .begin_fill(
            reservation.id(),
            locator,
            locator.len_units(),
            &ATTEMPT,
            ATTEMPT_SERIAL,
        )
        .expect("a set");
    (reservation, set)
}

/// `write` measures `offset` in extent units and settles the volume before returning. It returns the device range
/// the simulated device captured for the submitted write when the volume accepted it.
fn write<'s, 'a>(
    device: &mut Device<'s, 'a>,
    arena: &'a BufferArena<TestPlatform>,
    set: WriteSet,
    offset: u32,
) -> Option<DeviceRange> {
    let before = device.control.capture().events.len();
    let buffer = arena.acquire(PoolKind::ReceiveWrite).expect("free");
    let written = device.volume.write_at(set, buffer, offset).is_ok();
    let submitted =
        device.control.capture().events[before..]
            .iter()
            .find_map(|event| match event {
                Captured::Submitted {
                    operation: Operation::Write,
                    device: submitted,
                    ..
                } => Some(*submitted),
                _ => None,
            });
    settle(&mut device.volume, &device.control);
    written.then(|| submitted.expect("the accepted write reached the device"))
}

/// The locator of the slot of `extent`.
fn locator_of(storage: &Storage<TestPlatform>, extent: &HeldExtent) -> ExtentLocator {
    storage.live_pool().expect("live").records()[extent.holder.slot_index()].locator()
}

#[test]
fn a_range_inside_another_slots_extent_is_named_and_an_adjacent_one_is_not() {
    let held = [
        extent(id(0, 3), 8192..16384),
        extent(id(1, 5), 16384..24576),
    ];
    let named = conflict(&held, id(1, 5), range(12288, 8192));
    assert_eq!(
        named,
        Some(Conflict {
            rule: W1,
            writer: id(1, 5),
            holder: id(0, 3),
            range: range(12288, 8192),
        })
    );
    assert_eq!(conflict(&held, id(1, 5), range(16384, 8192)), None);
    assert_eq!(conflict(&held, id(2, 1), range(24576, 4096)), None);
    assert_eq!(conflict(&held, id(2, 1), range(4096, 4096)), None);
    let first = conflict(&held, id(2, 1), range(8192, 16384)).map(|found| found.holder);
    assert_eq!(first, Some(id(0, 3)));

    // A write that starts below every held extent and ends inside one names that extent's slot.
    let below = conflict(&held, id(2, 1), range(4096, 8192));
    assert_eq!(below.map(|found| found.holder), Some(id(0, 3)));
    // When a write crosses from the writer's extent into the next slot's extent, W1 names the next slot as the
    // holder.
    let overrun = conflict(&held, id(0, 3), range(12288, 8192));
    assert_eq!(
        overrun.map(|found| (found.holder, found.range)),
        Some((id(1, 5), range(12288, 8192)))
    );

    // W1 skips a zero-length extent strictly inside the write and names the next overlapping foreign extent's holder.
    let empty = extent(id(3, 1), 10240..10240);
    assert_eq!(
        conflict(std::slice::from_ref(&empty), id(2, 1), range(8192, 8192)),
        None
    );
    let behind_empty = [empty, extent(id(0, 3), 8192..16384)];
    let named = conflict(&behind_empty, id(2, 1), range(8192, 8192));
    assert_eq!(named.map(|found| found.holder), Some(id(0, 3)));
}

#[test]
fn a_write_over_another_slots_extent_is_named() {
    let w1 = "a payload write overlapped an extent another slot holds";
    assert_eq!(w1, W1);
    let storage = storage(8);
    let arena = arena(4);
    let mut device = Device::new(&storage, &arena);
    publish(&storage, &mut device, &key(1), META, &[7; 8192]);
    publish(&storage, &mut device, &key(2), META, &[8; 8192]);
    let (published, skipped) = held(&storage);
    assert_eq!((published.len(), skipped), (2, 0), "two published objects");
    let units = |extent: &HeldExtent| (extent.bytes.end - extent.bytes.start) / IO_UNIT as u64;
    assert!(units(&published[0]) >= 2, "a multi-unit extent");
    let (filling, open) = begin(&storage, &mut device, None);
    let (listed, _) = held(&storage);
    let filling_extent = listed.iter().find(|extent| extent.holder == filling.id());
    let filling_extent = filling_extent
        .expect("the lens lists a Filling slot")
        .clone();
    // The guard must retain the first conflict's submitted range across both checks.
    let prior = arm(true);
    let mut writers = Vec::new();
    let mut submitted = Vec::new();
    for (over, offset) in [(&published[0], 1), (&published[1], 0)] {
        let (reservation, set) = begin(&storage, &mut device, Some(locator_of(&storage, over)));
        let range = write(&mut device, &arena, set, offset);
        submitted.push(range.expect("the guard records and the overlapping write is accepted"));
        device.volume.end_fill(set);
        writers.push(reservation);
    }
    arm(prior);
    let seen = take();
    let recorded = seen.first.expect("W1 recorded");
    assert_eq!(
        (recorded.rule, recorded.writer, recorded.holder),
        (w1, writers[0].id(), published[0].holder),
        "the first conflict is kept"
    );
    assert_eq!(
        recorded.range, submitted[0],
        "the range the device was given"
    );
    let unit = IO_UNIT as u64;
    assert_eq!(
        (recorded.range.start(), submitted[1].start()),
        (published[0].bytes.start + unit, published[1].bytes.start),
        "each write starts at its offset from the lens extent's first byte"
    );
    assert!(recorded.range.end() <= published[0].bytes.end);
    assert_eq!((seen.skipped, seen.checked), (0, 2));
    assert!(!seen.clean(), "a conflict alone makes the record unclean");

    let prior = arm(true);
    let (reservation, set) = begin(
        &storage,
        &mut device,
        Some(locator_of(&storage, &filling_extent)),
    );
    assert!(write(&mut device, &arena, set, 0).is_some());
    device.volume.end_fill(set);
    arm(prior);
    let recorded = take().first.expect("W1 recorded over a Filling slot");
    assert_eq!(
        (recorded.writer, recorded.holder),
        (reservation.id(), filling.id())
    );
    device.volume.end_fill(open);
}

#[test]
fn own_free_and_sequence_slots_raise_nothing() {
    let storage = sequence_storage();
    let arena = arena(4);
    let mut device = Device::new(&storage, &arena);
    publish_sequence(&storage, &mut device, &key(2), 3, 0, None);
    publish(&storage, &mut device, &key(1), META, &[7; 4096]);
    let slot = held(&storage).0[0].holder.slot_index();
    invalidate(&storage, &key(1)).expect("the invalidation");
    let retired = held(&storage).0;
    assert!(
        retired
            .iter()
            .any(|extent| extent.holder.slot_index() == slot),
        "a retired slot still holds its extent"
    );
    device.persist_journal();
    drain(&storage);
    let (after, skipped) = held(&storage);
    assert!(
        after
            .iter()
            .all(|extent| extent.holder.slot_index() != slot),
        "the freed slot is absent"
    );
    assert_eq!(skipped, 1, "the sequence owner is skipped and counted");
    // Both checks skip the same sequence owner, so the per-write maximum stays at 1.
    let prior = arm(true);
    let mut reservations = Vec::new();
    for _ in 0..2 {
        let (reservation, set) = begin(&storage, &mut device, None);
        assert!(write(&mut device, &arena, set, 0).is_some());
        device.volume.end_fill(set);
        reservations.push(reservation);
    }
    arm(prior);
    let seen = take();
    assert_eq!(
        (seen.first, seen.skipped, seen.checked),
        (None, 1, 2),
        "the skip count is the per-write maximum"
    );
    assert!(
        !seen.clean(),
        "a skipped slot alone makes the record unclean"
    );
}

#[test]
fn a_held_slot_the_lens_cannot_read_is_counted() {
    let storage = storage(8);
    let arena = arena(4);
    let mut device = Device::new(&storage, &arena);
    publish(&storage, &mut device, &key(1), META, &[7; 4096]);
    let (listed, skipped) = held(&storage);
    assert_eq!((listed.len(), skipped), (1, 0));
    let slot = listed[0].holder.slot_index();
    let pool = storage.live_pool().expect("live");
    let (clean_word, clean_locator) = (pool.word(slot), pool.records()[slot].locator());

    let undecodable = ExtentLocator::new(0, DIRECT_UNITS + 1).expect("a locator");
    pool.records()[slot].set_locator(undecodable);
    assert_eq!(held(&storage), (Vec::new(), 1), "an undecodable locator");
    // One armed record: the first write skips the planted slot, the second skips nothing, and the maximum stays 1.
    let prior = arm(true);
    let mut reservations = Vec::new();
    for restore in [false, true] {
        if restore {
            pool.records()[slot].set_locator(clean_locator);
        }
        let (reservation, set) = begin(&storage, &mut device, None);
        assert!(write(&mut device, &arena, set, 0).is_some());
        device.volume.end_fill(set);
        reservations.push(reservation);
    }
    arm(prior);
    let seen = take();
    assert_eq!((seen.first, seen.skipped, seen.checked), (None, 1, 2));
    assert!(!seen.clean());

    let payload_units = pool.descriptor().geometry.payload_units();
    let outside = [
        ExtentLocator::new(clean_locator.start_unit(), 0).expect("a locator"),
        ExtentLocator::new(payload_units, 1).expect("a locator"),
    ];
    for planted in outside {
        pool.records()[slot].set_locator(planted);
        let (listed, skipped) = held(&storage);
        let absent = listed.iter().all(|held| held.holder.slot_index() != slot);
        assert!(absent && skipped == 1, "the locator {planted:?}");
    }
    pool.records()[slot].set_locator(clean_locator);

    let unknown = clean_word & !word::STATE | 5 << word::STATE_SHIFT;
    for planted in [clean_word | 1 << 43, unknown] {
        pool.edit_word(slot, |_| planted);
        let (listed, skipped) = held(&storage);
        let absent = listed.iter().all(|held| held.holder.slot_index() != slot);
        assert!(absent && skipped == 1, "the word {planted:#x}");
        pool.edit_word(slot, |_| clean_word);
    }
    assert_eq!(held(&storage).1, 0, "the restored slot is listed again");
}

#[test]
fn idle_slots_count_nothing_whatever_their_locator() {
    let storage = storage(8);
    let arena = arena(4);
    let mut device = Device::new(&storage, &arena);
    publish(&storage, &mut device, &key(1), META, &[7; 4096]);
    let slot = held(&storage).0[0].holder.slot_index();
    let pool = storage.live_pool().expect("live");
    let (clean_word, clean_locator) = (pool.word(slot), pool.records()[slot].locator());
    let incarnation = u64::from(word::incarnation(clean_word));
    let sequence = Held::Sequence {
        block: Block(1),
        count: 2,
    }
    .locator();
    let undecodable = ExtentLocator::new(0, DIRECT_UNITS + 1).expect("a locator");
    for idle in [SlotState::Free, SlotState::Quarantined] {
        pool.edit_word(slot, |_| incarnation | idle.bits());
        for locator in [sequence, undecodable] {
            pool.records()[slot].set_locator(locator);
            assert_eq!(held(&storage), (Vec::new(), 0), "{idle:?} over {locator:?}");
        }
    }
    pool.records()[slot].set_locator(clean_locator);
    pool.edit_word(slot, |_| clean_word);
    assert_eq!(
        held(&storage).0.len(),
        1,
        "the restored slot is listed again"
    );
}

#[test]
fn an_unarmed_thread_records_nothing() {
    let storage = storage(8);
    let arena = arena(4);
    let mut device = Device::new(&storage, &arena);
    publish(&storage, &mut device, &key(1), META, &[7; 4096]);
    let first = held(&storage).0[0].clone();
    let outer = arm(true);
    assert!(!outer, "a test thread starts unarmed");
    let nested = arm(false);
    assert!(nested, "the nested disarm returns the outer armed state");
    let (_reservation, set) = begin(&storage, &mut device, Some(locator_of(&storage, &first)));
    assert!(write(&mut device, &arena, set, 0).is_some());
    device.volume.end_fill(set);
    let seen = take();
    assert_eq!(seen, Guarded::default());
    assert!(seen.clean(), "an empty record is clean");
    assert!(
        !arm(nested),
        "restoring the outer state returns the disarmed state"
    );
    assert!(
        arm(outer),
        "restoring the start state returns the armed state"
    );
}
