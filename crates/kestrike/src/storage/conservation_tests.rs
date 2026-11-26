//! Edited snapshots, each failing the judge by its own fault, and live
//! storages whose tables pass or fail the conservation rule.

use super::super::SlotState;
use super::super::claim_exit_tests::judged as rule;
use super::super::extent::ExtentLocator;
use super::super::held::DIRECT_UNITS;
use super::super::owner_fixture::{
    Device, arena, clear_abandoned, edit_tables, invalidate, leak_unit, poison_pool, publish,
    publish_sequence, sequence_storage, set_state, storage, with_pool_held,
};
use super::super::publish_tests::key;
use super::super::test_platform::TestPlatform;
use super::super::word::{ABANDONED, REF, RESERVED, STATE};
use super::super::{Storage, sequence_tests};
use super::{Binding, Extent, Fault, GATE, Holdings, LOCATOR, NOT_LIVE, SEQUENCE, UNTAKEN};
use crate::index::Identity;

fn word(state: SlotState, refs: u64) -> u64 {
    1 | state.bits() | (refs * REF)
}

fn bound(slot: u32) -> Binding {
    Binding {
        shard: 0,
        identity: Identity {
            tag: 0,
            incarnation_low: 1,
            slot,
        },
    }
}

fn clean() -> (Holdings, Vec<Binding>) {
    let mut holdings = Holdings {
        unreadable: None,
        payload_units: 16,
        words: vec![
            word(SlotState::Resident, 1),
            word(SlotState::Retired, 0),
            word(SlotState::Filling, 1),
            word(SlotState::Free, 0),
            word(SlotState::Quarantined, 0),
            word(SlotState::Resident, 0),
        ],
        extents: vec![
            Extent {
                start: 0,
                len: 2,
                slot: 0,
            },
            Extent {
                start: 2,
                len: 1,
                slot: 1,
            },
            Extent {
                start: 13,
                len: 3,
                slot: 2,
            },
            Extent {
                start: 8,
                len: 1,
                slot: 5,
            },
        ],
        free_slots: vec![false, false, false, true, false, false],
        free_runs: vec![(3, 5), (9, 4)],
        ..Holdings::default()
    };
    holdings.slots.free = 1;
    holdings.slots.filling = 1;
    holdings.slots.resident = 2;
    holdings.slots.retired = 1;
    holdings.slots.quarantined = 1;
    holdings.raw.free = 9 * super::IO_UNIT;
    (holdings, vec![bound(0)])
}

type Edit = fn(&mut Holdings, &mut Vec<Binding>);

fn judged(edit: impl FnOnce(&mut Holdings, &mut Vec<Binding>)) -> Result<(), Fault> {
    let (mut holdings, mut bindings) = clean();
    edit(&mut holdings, &mut bindings);
    holdings.judge(&bindings)
}

/// A clean snapshot passes: two adjacent extents, a third ending at the
/// volume's last unit, a word in every state, and an unbound resident with
/// a zero count, whose publication has not installed its anchor. An
/// `ABANDONED` resident passes with or without a binding: the flag marks a
/// retirement awaiting service.
#[test]
fn a_clean_snapshot_and_an_abandoned_resident_pass() {
    assert_eq!(judged(|_, _| {}), Ok(()));
    assert_eq!(
        judged(|holdings, bindings| {
            holdings.words[0] |= ABANDONED;
            bindings.clear();
        }),
        Ok(())
    );
    assert_eq!(judged(|holdings, _| holdings.words[0] |= ABANDONED), Ok(()));
}

/// Each edited snapshot fails by its own fault, with every check before it
/// passing.
#[test]
fn each_edited_snapshot_fails_by_its_own_fault() {
    let cases: [(&str, Edit, Fault); 34] = [
        (
            "an unreadable snapshot",
            |holdings, _| holdings.unreadable = Some(GATE),
            Fault::Unreadable(GATE),
        ),
        (
            "a malformed word",
            |holdings, _| holdings.words[3] |= 1 << 43,
            Fault::Malformed { slot: 3 },
        ),
        (
            "a state encoding past Quarantined",
            |holdings, _| holdings.words[3] |= 5 << super::word::STATE_SHIFT,
            Fault::Malformed { slot: 3 },
        ),
        (
            "a malformed word beside free runs that differ",
            |holdings, _| {
                holdings.words[3] |= 1 << 43;
                holdings.free_runs.clear();
            },
            Fault::Malformed { slot: 3 },
        ),
        (
            "an extent past the volume",
            |holdings, _| {
                holdings.extents[2] = Extent {
                    start: 14,
                    len: 3,
                    slot: 2,
                }
            },
            Fault::PastVolume { slot: 2 },
        ),
        (
            "two extents sharing a unit",
            |holdings, _| {
                holdings.extents[1] = Extent {
                    start: 1,
                    len: 1,
                    slot: 1,
                }
            },
            Fault::Overlap { slot: 1 },
        ),
        (
            "a unit held by no slot and absent from the free runs",
            |holdings, _| holdings.free_runs[0] = (3, 4),
            Fault::FreeRuns,
        ),
        (
            "a free run over a held unit",
            |holdings, _| holdings.free_runs[0] = (2, 6),
            Fault::FreeRuns,
        ),
        (
            "a free run past the last unheld run",
            |holdings, _| holdings.free_runs.push((13, 3)),
            Fault::FreeRuns,
        ),
        (
            "a slot count off by one",
            |holdings, _| {
                holdings.slots.free = 0;
                holdings.slots.resident = 3;
            },
            Fault::SlotCounts,
        ),
        (
            "a quarantined slot counted as free",
            |holdings, _| {
                holdings.slots.quarantined = 0;
                holdings.slots.free = 2;
            },
            Fault::SlotCounts,
        ),
        (
            "a free slot missing from the free-slot set",
            |holdings, _| holdings.free_slots[3] = false,
            Fault::FreeSlots { slot: 3 },
        ),
        (
            "a free-slot set of the right size with a wrong member",
            |holdings, _| holdings.free_slots = vec![true, false, false, false, false, false],
            Fault::FreeSlots { slot: 0 },
        ),
        (
            "a raw free term off by one unit",
            |holdings, _| holdings.raw.free -= super::IO_UNIT,
            Fault::RawFree,
        ),
        (
            "a duplicate binding",
            |_, bindings| bindings.push(bound(0)),
            Fault::DuplicateBinding { slot: 0 },
        ),
        (
            "a binding to a retired slot with the slot ledger edited to match",
            |holdings, _| {
                holdings.words[0] = word(SlotState::Retired, 1);
                holdings.slots.resident = 1;
                holdings.slots.retired = 2;
            },
            Fault::NotResident { slot: 0 },
        ),
        (
            "a binding at another incarnation",
            |_, bindings| bindings[0].identity.incarnation_low = 2,
            Fault::NotResident { slot: 0 },
        ),
        (
            "an unbound resident",
            |_, bindings| bindings.clear(),
            Fault::UnboundResident { slot: 0 },
        ),
        (
            "a binding to a zero-count resident beside an unbound resident",
            |_, bindings| bindings[0].identity.slot = 5,
            Fault::NotResident { slot: 5 },
        ),
        (
            "an overlap beside an unbound resident",
            |holdings, bindings| {
                bindings.clear();
                holdings.extents[1].start = 1;
            },
            Fault::Overlap { slot: 1 },
        ),
        (
            "a free-slot bit past the last slot",
            |holdings, _| holdings.free_slots.extend([false, true]),
            Fault::FreeSlots { slot: 7 },
        ),
        (
            "a free slot missing beside a bit past the last slot",
            |holdings, _| {
                holdings.free_slots[3] = false;
                holdings.free_slots.push(true);
            },
            Fault::FreeSlots { slot: 3 },
        ),
        (
            "a slot count off by one beside a free-slot bit past the last slot",
            |holdings, _| {
                holdings.slots.free = 0;
                holdings.slots.resident = 3;
                holdings.free_slots.push(true);
            },
            Fault::SlotCounts,
        ),
        (
            "a free-slot bit past the last slot beside a raw free term off by one unit",
            |holdings, _| {
                holdings.free_slots.push(true);
                holdings.raw.free -= super::IO_UNIT;
            },
            Fault::FreeSlots { slot: 6 },
        ),
        (
            "a free-slot copy shorter than the slot table",
            |holdings, _| holdings.free_slots.truncate(5),
            Fault::FreeSlots { slot: 5 },
        ),
        (
            "a binding to a slot past the slot table",
            |_, bindings| bindings.push(bound(6)),
            Fault::NotResident { slot: 6 },
        ),
        (
            "an unreadable snapshot beside an extent past the volume",
            |holdings, _| {
                holdings.unreadable = Some(GATE);
                holdings.extents[2].start = 14;
            },
            Fault::Unreadable(GATE),
        ),
        (
            "an extent past the volume beside an overlap",
            |holdings, _| {
                holdings.extents[2].start = 14;
                holdings.extents[1].start = 1;
            },
            Fault::PastVolume { slot: 2 },
        ),
        (
            "an overlap beside a short free run",
            |holdings, _| {
                holdings.extents[1].start = 1;
                holdings.free_runs[0] = (3, 4);
            },
            Fault::Overlap { slot: 1 },
        ),
        (
            "a short free run beside a slot count off by one",
            |holdings, _| {
                holdings.free_runs[0] = (3, 4);
                holdings.slots.free = 0;
                holdings.slots.resident = 3;
            },
            Fault::FreeRuns,
        ),
        (
            "a slot count off by one beside a missing free slot",
            |holdings, _| {
                holdings.slots.free = 0;
                holdings.slots.resident = 3;
                holdings.free_slots[3] = false;
            },
            Fault::SlotCounts,
        ),
        (
            "a missing free slot beside a raw free term off by one unit",
            |holdings, _| {
                holdings.free_slots[3] = false;
                holdings.raw.free -= super::IO_UNIT;
            },
            Fault::FreeSlots { slot: 3 },
        ),
        (
            "a raw free term off by one unit beside a duplicate binding",
            |holdings, bindings| {
                holdings.raw.free -= super::IO_UNIT;
                bindings.push(bound(0));
            },
            Fault::RawFree,
        ),
        (
            "a duplicate binding to a retired slot with the slot ledger edited to match",
            |holdings, bindings| {
                holdings.words[0] = word(SlotState::Retired, 1);
                holdings.slots.resident = 1;
                holdings.slots.retired = 2;
                bindings.push(bound(0));
            },
            Fault::DuplicateBinding { slot: 0 },
        ),
    ];
    for (name, edit, fault) in cases {
        assert_eq!(judged(edit), Err(fault), "{name}");
    }
}

fn bound_slot(storage: &Storage<TestPlatform>) -> usize {
    let mut bindings = Vec::new();
    storage.bindings_into(&mut bindings).unwrap();
    bindings[0].identity.slot as usize
}

/// A published object passes. With its slot's word set to `Free` the judge
/// reports the free runs, which precede every ledger check, and it passes
/// once the word is restored. A leaked unit fails the free-run check, and
/// the storage keeps publishing and servicing with the unit leaked.
#[test]
fn a_freed_word_and_a_leaked_unit_fail_the_free_runs_of_a_live_storage() {
    let storage = storage(8);
    let buffers = arena(8);
    let mut device = Device::new(&storage, &buffers);
    publish(&storage, &mut device, &key(1), 0, &[1; 3000]);
    assert_eq!(rule(&storage), Ok(()));
    let slot = bound_slot(&storage);
    set_state(&storage, slot, SlotState::Free);
    assert_eq!(rule(&storage), Err(Fault::FreeRuns));
    set_state(&storage, slot, SlotState::Resident);
    assert_eq!(rule(&storage), Ok(()), "restored");
    assert!(leak_unit(&storage), "premise: a unit leaked");
    assert_eq!(rule(&storage), Err(Fault::FreeRuns));
    publish(&storage, &mut device, &key(2), 0, &[2; 3000]);
    storage
        .service(&mut super::super::publish_tests::budget())
        .unwrap();
    assert_eq!(rule(&storage), Err(Fault::FreeRuns));
}

/// The reserved bits, and a state encoding past `Quarantined`, in the bound
/// slot's word of a live storage each fail the rule as that slot's
/// malformed word, and the restored word passes.
#[test]
fn a_malformed_word_of_a_live_storage_fails_by_its_slot() {
    let storage = storage(8);
    let buffers = arena(8);
    let mut device = Device::new(&storage, &buffers);
    publish(&storage, &mut device, &key(1), 0, &[1; 3000]);
    let slot = bound_slot(&storage);
    let live = storage.live_pool().unwrap();
    let held = live.word(slot);
    for malformed in [held | RESERVED, held | STATE] {
        live.edit_word(slot, |_| malformed);
        assert_eq!(
            rule(&storage),
            Err(Fault::Malformed { slot: slot as u32 }),
            "{malformed:#x}"
        );
        live.edit_word(slot, |_| held);
        assert_eq!(rule(&storage), Ok(()), "restored");
    }
}

/// The free-slot set of a live storage fails the rule by membership alone,
/// with the words, the slot ledger and the extents unchanged: a free slot
/// swapped for the bound slot keeps the set's size and fails at the lower
/// of the two, and a bit set past the last slot fails at that bit. With the
/// set restored, a raw free term one unit short fails as the raw free term.
#[test]
fn the_free_slot_set_and_the_raw_free_term_of_a_live_storage_fail_by_their_own_fault() {
    let storage = storage(8);
    let buffers = arena(8);
    let mut device = Device::new(&storage, &buffers);
    publish(&storage, &mut device, &key(1), 0, &[1; 3000]);
    assert_eq!(rule(&storage), Ok(()));
    let held = bound_slot(&storage);
    let slots = storage.live_pool().unwrap().records().len();
    let free = edit_tables(&storage, |tables| {
        let mut set = tables.free_slots();
        let free = (0..slots)
            .find(|&slot| set.contains(slot))
            .expect("a free slot");
        set.take(free);
        set.give(held);
        free
    });
    assert_eq!(
        rule(&storage),
        Err(Fault::FreeSlots {
            slot: held.min(free) as u32
        })
    );
    edit_tables(&storage, |tables| {
        let mut set = tables.free_slots();
        set.take(held);
        set.give(free);
    });
    assert_eq!(rule(&storage), Ok(()), "restored");
    assert_ne!(
        slots % 64,
        0,
        "premise: level 0 has bits past the last slot"
    );
    edit_tables(&storage, |tables| tables.free_slots().give(slots));
    assert_eq!(rule(&storage), Err(Fault::FreeSlots { slot: slots as u32 }));
    edit_tables(&storage, |tables| tables.free_slots().take(slots));
    assert_eq!(rule(&storage), Ok(()), "restored");
    let was = edit_tables(&storage, |tables| {
        let mut extents = tables.extents();
        let was = extents.ledger().free;
        extents.plant_ledger_free(was - super::IO_UNIT);
        was
    });
    assert_eq!(rule(&storage), Err(Fault::RawFree));
    edit_tables(&storage, |tables| tables.extents().plant_ledger_free(was));
    assert_eq!(rule(&storage), Ok(()), "restored");
    edit_tables(&storage, |tables| {
        tables.state.ledger.free -= 1;
        tables.state.ledger.quarantined += 1;
    });
    assert_eq!(rule(&storage), Err(Fault::SlotCounts));
    edit_tables(&storage, |tables| {
        tables.state.ledger.free += 1;
        tables.state.ledger.quarantined -= 1;
    });
    assert_eq!(rule(&storage), Ok(()), "restored");
}

fn sized(slots: usize) -> Storage<TestPlatform> {
    let config = super::super::publish_tests::storage_config(slots);
    let limits = [slots];
    let index = super::super::publish_tests::index_config(&limits, (1, 1), 1);
    super::super::publish_tests::storage_from(
        &config,
        &index,
        TestPlatform::heap(super::super::publish_tests::PAGE),
    )
}

#[test]
fn the_free_slot_copy_covers_level_0_of_a_64_and_a_65_slot_set() {
    let whole = sized(64);
    let mut holdings = Holdings::default();
    whole.holdings_into(&mut holdings);
    assert_eq!(holdings.judge(&[]), Ok(()));
    assert_eq!(holdings.free_slots.len(), 64, "no padding");
    let padded = sized(65);
    padded.holdings_into(&mut holdings);
    assert_eq!(holdings.judge(&[]), Ok(()));
    assert_eq!(holdings.free_slots.len(), 128, "one padded word");
    for bit in [65, 127] {
        edit_tables(&padded, |tables| tables.free_slots().give(bit));
        padded.holdings_into(&mut holdings);
        assert_eq!(
            holdings.judge(&[]),
            Err(Fault::FreeSlots { slot: bit as u32 }),
            "bit {bit}"
        );
        edit_tables(&padded, |tables| tables.free_slots().take(bit));
        padded.holdings_into(&mut holdings);
        assert_eq!(holdings.judge(&[]), Ok(()), "bit {bit} restored");
    }
}

/// The judge accepts a published three-extent sequence beside a direct
/// object, and a filling sequence whose held extents are all three or a
/// two-extent prefix.
#[test]
fn sequences_whole_and_partly_held_pass() {
    let storage = sequence_storage();
    let buffers = arena(8);
    let mut device = Device::new(&storage, &buffers);
    publish(&storage, &mut device, &key(2), 0, &[2; 3000]);
    publish_sequence(&storage, &mut device, &key(1), 3, 0, None);
    assert_eq!(rule(&storage), Ok(()));
    let mut holdings = Holdings::default();
    storage.holdings_into(&mut holdings);
    assert_eq!(
        holdings.extents.len(),
        4,
        "premise: a direct object and three extents"
    );
    for held in [3, 2] {
        let storage = sequence_tests::storage();
        let reservation = storage
            .reserve(Some(0), Some(100), &mut sequence_tests::budget())
            .unwrap();
        let object = sequence_tests::built(&storage, &reservation, 3, held);
        assert_eq!(object.extents.len(), held as usize, "premise: the prefix");
        let mut holdings = Holdings::default();
        storage.holdings_into(&mut holdings);
        assert_eq!(holdings.judge(&[]), Ok(()), "{held} of 3 held");
        assert_eq!(holdings.extents.len(), held as usize);
    }
}

/// An object removed while the pool gate is held parks its retirement: the
/// slot stays `Resident`, unbound, with `ABANDONED`, and passes. With the
/// flag cleared the same tables fail as an unbound resident.
#[test]
fn an_object_removed_under_a_held_pool_gate_passes_until_its_flag_is_cleared() {
    let storage = storage(8);
    let buffers = arena(8);
    let mut device = Device::new(&storage, &buffers);
    publish(&storage, &mut device, &key(1), 0, &[1; 3000]);
    let slot = bound_slot(&storage);
    let removed = with_pool_held(&storage, || invalidate(&storage, &key(1)));
    assert!(removed.is_ok(), "{removed:?}");
    let live = storage.live_pool().unwrap();
    assert_ne!(
        live.flags(slot) & ABANDONED,
        0,
        "premise: the retirement parked"
    );
    assert_eq!(rule(&storage), Ok(()));
    clear_abandoned(&storage, slot);
    assert_eq!(
        rule(&storage),
        Err(Fault::UnboundResident { slot: slot as u32 })
    );
}

/// A held or poisoned pool gate leaves the snapshot unreadable, and a
/// buffer no snapshot filled is unreadable by its own reason.
#[test]
fn a_held_or_poisoned_pool_gate_is_unreadable() {
    let storage = storage(8);
    let mut holdings = Holdings::default();
    assert_eq!(holdings.judge(&[]), Err(Fault::Unreadable(UNTAKEN)));
    with_pool_held(&storage, || storage.holdings_into(&mut holdings));
    assert_eq!(holdings.judge(&[]), Err(Fault::Unreadable(GATE)));
    storage.holdings_into(&mut holdings);
    assert_eq!(holdings.judge(&[]), Ok(()), "released");
    poison_pool(&storage);
    storage.holdings_into(&mut holdings);
    assert_eq!(holdings.judge(&[]), Err(Fault::Unreadable(GATE)));
}

/// A held locator of neither form, a sequence block that refuses the slot's
/// incarnation, and a storage past its `Live` phase each leave the snapshot
/// unreadable by name.
#[test]
fn an_undecodable_slot_or_a_finalized_storage_is_unreadable() {
    let storage = sequence_tests::storage();
    let reservation = storage
        .reserve(Some(0), Some(100), &mut sequence_tests::budget())
        .unwrap();
    let slot = reservation.id().slot_index();
    let live = storage.live_pool().unwrap();
    let handle = live.records()[slot].locator();
    sequence_tests::built(&storage, &reservation, 3, 3);
    let sequence = live.records()[slot].locator();
    let mut holdings = Holdings::default();
    live.records()[slot].set_locator(ExtentLocator::new(0, DIRECT_UNITS + 1).unwrap());
    storage.holdings_into(&mut holdings);
    assert_eq!(holdings.judge(&[]), Err(Fault::Unreadable(LOCATOR)));
    live.records()[slot].set_locator(sequence);
    storage.holdings_into(&mut holdings);
    assert_eq!(holdings.judge(&[]), Ok(()), "restored");
    live.edit_word(slot, |held| held + 1);
    storage.holdings_into(&mut holdings);
    assert_eq!(holdings.judge(&[]), Err(Fault::Unreadable(SEQUENCE)));
    live.edit_word(slot, |held| held - 1);
    assert_ne!(
        handle, sequence,
        "premise: the slot holds a sequence handle"
    );
    drop(reservation);
    let mut finalized = sequence_tests::storage();
    assert_eq!(
        finalized.finalize(&mut sequence_tests::budget()),
        Ok(super::super::Finalization::Drained),
        "premise: a drained storage"
    );
    finalized.holdings_into(&mut holdings);
    assert_eq!(holdings.judge(&[]), Err(Fault::Unreadable(NOT_LIVE)));
}

/// The free-run reader yields the maximal runs of units no reservation
/// holds, computed from the reservations kept, over a volume that
/// reservations fragmented, and agrees with the allocator's own free set.
#[test]
fn the_free_run_reader_matches_the_allocators_free_set_on_a_fragmented_volume() {
    let storage = sequence_tests::storage();
    let live = storage.live_pool().unwrap();
    let mut access = live.lock().unwrap();
    let mut tables = access.tables();
    let mut extents = tables.extents();
    let limit = live.image.extent_bound;
    let mut budget = sequence_tests::budget();
    let placed: Vec<_> = (1..=6)
        .map(|units| extents.reserve(units, 0, limit, &mut budget).unwrap())
        .collect();
    for locator in placed.iter().step_by(2) {
        super::super::tables::release_extent(
            &mut extents,
            *locator,
            super::super::extent::HeldPhase::Reserved,
            0,
        );
    }
    let mut runs = Vec::new();
    extents.free_runs_into(&mut runs);
    let mut kept: Vec<(u64, u64)> = placed
        .iter()
        .skip(1)
        .step_by(2)
        .map(|locator| (locator.start_unit(), u64::from(locator.len_units())))
        .collect();
    kept.sort_unstable();
    let payload_units = live.descriptor().geometry.payload_units();
    let mut expected = Vec::new();
    let mut cursor = 0;
    for (start, len) in kept.into_iter().chain([(payload_units, 0)]) {
        if start > cursor {
            expected.push((cursor, start - cursor));
        }
        cursor = start + len;
    }
    assert!(runs.len() >= 3, "premise: a fragmented volume: {runs:?}");
    assert_eq!(runs, expected);
    assert_eq!(runs, extents.free_set());
    access.release();
}
