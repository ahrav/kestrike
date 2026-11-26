//! A damaged slot loses only the entries with a row on a unit that failed its check or its read; a torn or stale
//! unit raises the stale-write alarm, a failed or short read the unreadable alarm, a failed check outranks a
//! failed read, and no intact entry is evicted.
//! Kept entries that share a slot load cold with `LoadRefusal::Slot`.
//!
//! Every test decodes one encoded checkpoint slot of unit 0 and six data units through `SlotDecode`, one unit per
//! window, as `checkpoint_tests::Fed` lands them. A torn unit has its last sector overwritten, a stale unit is the
//! unit at the same index of the capture before, and a failed read lands as a window of no bytes. The sibling
//! decodes the same slot in the same arrival orders with no unit damaged.

use crate::storage::record::Crc32c;

use super::capture::CaptureEntry;
use super::checkpoint::{Damage, UNIT_LEN, UnitDamage, encode};
use super::checkpoint_tests::{
    Fed, canonical, checkpoint, damaged, entries, loaded, outside, whole,
};
use super::{GuardedLoad, LoadRefusal};

/// The capture `Fed` decodes.
const CAPTURE: u32 = 5;
/// Entries of the slot: 240 rows, which fill six data units of 41 rows short of six rows.
const ENTRIES: usize = 120;
/// Units of the slot: unit 0 and six data units.
const UNITS: usize = 7;
/// The unit whose read fails in the mixed cases, below `TORN`.
const UNREAD: usize = 2;
/// The unit that fails its check in the mixed cases.
const TORN: usize = 4;

fn slot(capture: u32, entries: &[CaptureEntry]) -> Vec<Box<[u8; UNIT_LEN]>> {
    let units = encode(Crc32c::detect(), checkpoint(capture), entries, u32::MAX).unwrap();
    assert_eq!(
        units.len(),
        UNITS,
        "premise: the slot is unit 0 and six data units"
    );
    units
}

/// `units` with the last sector of unit `unit` overwritten, as a write torn before its last sector leaves it.
fn torn(units: &[Box<[u8; UNIT_LEN]>], unit: usize) -> Vec<Box<[u8; UNIT_LEN]>> {
    let mut units = units.to_vec();
    units[unit][UNIT_LEN - 512..].fill(0xA5);
    units
}

/// The arrival orders of the seven units: in unit order, in reverse, and two that land the torn unit before and
/// after the unit whose read fails with other units between them.
fn orders() -> [[usize; UNITS]; 4] {
    [
        [0, 1, 2, 3, 4, 5, 6],
        [6, 5, 4, 3, 2, 1, 0],
        [4, 6, 0, 2, 5, 1, 3],
        [3, 2, 6, 1, 0, 4, 5],
    ]
}

/// The decode of `units` landed in `order`, with each unit of `unread` landed as a failed read.
fn decode(units: &[Box<[u8; UNIT_LEN]>], order: &[usize], unread: &[usize]) -> Fed {
    let mut fed = Fed::new(units.len(), 4);
    for &at in order {
        let bytes = if unread.contains(&at) {
            &[][..]
        } else {
            &units[at][..]
        };
        fed.land(at, bytes);
    }
    fed
}

/// The entries of `entries` with no row on any unit of `lost`.
fn off(entries: &[CaptureEntry], lost: &[usize]) -> Vec<CaptureEntry> {
    let mut kept = entries.to_vec();
    for &unit in lost {
        let outside = outside(entries, unit);
        kept.retain(|entry| outside.contains(entry));
    }
    kept
}

/// Judges one damaged decode: the load is warm with exactly `kept`, and the damage lists `failed` and `unread`.
fn judge_loss(
    case: &str,
    damage: &Damage,
    load: GuardedLoad,
    kept: &[CaptureEntry],
    failed: &[u32],
    unread: &[u32],
) {
    assert_eq!(
        load,
        GuardedLoad::Warm(kept.to_vec()),
        "{case}: the load is the entries off the lost units"
    );
    assert_eq!(
        damage.failed, failed,
        "{case}: the units that failed their check"
    );
    assert_eq!(damage.unread, unread, "{case}: the units whose read failed");
}

#[test]
fn a_torn_or_stale_unit_loses_its_entries_and_raises_the_stale_write_alarm() {
    let entries = entries(ENTRIES);
    let units = slot(CAPTURE, &entries);
    let earlier = slot(CAPTURE - 1, &entries);
    for unit in 1..UNITS {
        let kept = outside(&entries, unit);
        assert!(
            !kept.is_empty() && kept.len() < entries.len(),
            "premise: unit {unit} holds some entries, not all"
        );
        let mut stale = units.clone();
        stale[unit] = earlier[unit].clone();
        for (case, damaged_units) in [("torn", torn(&units, unit)), ("stale", stale)] {
            for order in orders() {
                let case = format!("{case} unit {unit}, order {order:?}");
                let (damage, load) = damaged(decode(&damaged_units, &order, &[]).finish());
                judge_loss(&case, &damage, load, &kept, &[unit as u32], &[]);
                assert!(
                    !matches!(damage.first, UnitDamage::Unread { .. }),
                    "{case}: {:?}",
                    damage.first
                );
                assert_eq!(damage.alarm(), LoadRefusal::StaleWrite, "{case}");
            }
        }
    }
}

#[test]
fn a_failed_read_loses_its_entries_and_raises_the_unreadable_alarm() {
    let entries = entries(ENTRIES);
    let units = slot(CAPTURE, &entries);
    for unit in 1..UNITS {
        let kept = outside(&entries, unit);
        for order in orders() {
            let case = format!("unread unit {unit}, order {order:?}");
            let slot = decode(&units, &order, &[unit]).finish();
            assert!(
                !slot.installable(),
                "{case}: a later read may still load the unit"
            );
            let (damage, load) = damaged(slot);
            judge_loss(&case, &damage, load, &kept, &[], &[unit as u32]);
            assert_eq!(
                damage.first,
                UnitDamage::Unread { unit: unit as u32 },
                "{case}"
            );
            assert_eq!(damage.alarm(), LoadRefusal::Unreadable, "{case}");
        }
    }
}

#[test]
fn a_failed_check_outranks_a_failed_read_at_a_lower_unit() {
    let entries = entries(ENTRIES);
    let units = torn(&slot(CAPTURE, &entries), TORN);
    let kept = off(&entries, &[UNREAD, TORN]);
    assert!(!kept.is_empty(), "premise: some entries lie off both units");
    let mut torn_first = 0;
    for order in orders() {
        let place = |unit| order.iter().position(|&at| at == unit).unwrap();
        torn_first += usize::from(place(TORN) < place(UNREAD));
        let case = format!("unread unit {UNREAD} below torn unit {TORN}, order {order:?}");
        let (damage, load) = damaged(decode(&units, &order, &[UNREAD]).finish());
        judge_loss(
            &case,
            &damage,
            load,
            &kept,
            &[TORN as u32],
            &[UNREAD as u32],
        );
        assert_eq!(
            damage.first,
            UnitDamage::Chunk { unit: TORN as u32 },
            "{case}: the first damage is the failed check, not the failed read"
        );
        assert_eq!(damage.alarm(), LoadRefusal::StaleWrite, "{case}");
    }
    assert!(
        (1..orders().len()).contains(&torn_first),
        "premise: the torn unit lands before the unread unit in some orders and after it in others"
    );
}

#[test]
fn a_failed_check_at_a_lower_unit_stays_the_first_damage_beside_a_failed_read() {
    let entries = entries(ENTRIES);
    let units = torn(&slot(CAPTURE, &entries), UNREAD);
    let kept = off(&entries, &[UNREAD, TORN]);
    for order in orders() {
        let case = format!("torn unit {UNREAD} below unread unit {TORN}, order {order:?}");
        let (damage, load) = damaged(decode(&units, &order, &[TORN]).finish());
        judge_loss(
            &case,
            &damage,
            load,
            &kept,
            &[UNREAD as u32],
            &[TORN as u32],
        );
        assert_eq!(
            damage.first,
            UnitDamage::Chunk {
                unit: UNREAD as u32
            },
            "{case}"
        );
        assert_eq!(damage.alarm(), LoadRefusal::StaleWrite, "{case}");
    }
}

/// An intact unit 0 that records another unit count than the store names loads the slot cold in every arrival
/// order: the damage names the recorded and the named count, lists unit 0 alone as failed and raises the
/// stale-write alarm.
#[test]
fn a_unit_0_naming_another_unit_count_reports_both_counts_and_loads_cold_in_every_arrival_order() {
    let entries = entries(ENTRIES);
    let mut units = slot(CAPTURE, &entries);
    let longer = encode(
        Crc32c::detect(),
        checkpoint(CAPTURE),
        &self::entries(ENTRIES + 60),
        u32::MAX,
    )
    .unwrap();
    assert!(
        longer.len() > UNITS,
        "premise: the longer encoding names another unit count"
    );
    units[0] = longer[0].clone();
    for order in orders() {
        let (damage, load) = damaged(decode(&units, &order, &[]).finish());
        assert!(
            matches!(damage.first, UnitDamage::Units { recorded, named } if recorded as usize == longer.len() && named as usize == UNITS),
            "order {order:?}: {damage:?}"
        );
        assert_eq!(damage.failed, [0], "order {order:?}");
        assert_eq!(damage.alarm(), LoadRefusal::StaleWrite, "order {order:?}");
        assert!(
            matches!(
                load,
                GuardedLoad::Cold {
                    refusal: LoadRefusal::StaleWrite,
                    ..
                }
            ),
            "order {order:?}: {load:?}"
        );
    }
}

#[test]
fn kept_entries_that_share_a_slot_load_cold_by_the_guard_beside_a_lost_unit() {
    let mut entries = entries(ENTRIES);
    entries[1].allocation = entries[0].allocation;
    let units = slot(CAPTURE, &entries);
    let kept = outside(&entries, TORN);
    assert!(
        kept.starts_with(&entries[..2]) && kept.len() < entries.len(),
        "premise: both entries of the shared slot lie off unit {TORN}, which holds others"
    );
    let cold = GuardedLoad::Cold {
        entries: canonical(kept),
        refusal: LoadRefusal::Slot,
    };
    for order in orders() {
        let (damage, load) = damaged(decode(&torn(&units, TORN), &order, &[]).finish());
        assert_eq!(load, cold, "torn unit {TORN}, order {order:?}");
        assert_eq!(
            (damage.failed.as_slice(), damage.unread.as_slice()),
            ([TORN as u32].as_slice(), [].as_slice()),
            "torn unit {TORN}, order {order:?}"
        );
        let (damage, load) = damaged(decode(&units, &order, &[TORN]).finish());
        assert_eq!(load, cold, "unread unit {TORN}, order {order:?}");
        assert_eq!(
            (damage.failed.as_slice(), damage.unread.as_slice()),
            ([].as_slice(), [TORN as u32].as_slice()),
            "unread unit {TORN}, order {order:?}"
        );
    }
}

/// The sibling: the same slot in the same arrival orders with every unit intact decodes whole and loads warm with
/// every entry, so each loss and alarm above follows from its damaged unit.
#[test]
fn the_undamaged_slot_loads_every_entry_in_every_order() {
    let entries = entries(ENTRIES);
    let units = slot(CAPTURE, &entries);
    for order in orders() {
        let slot = decode(&units, &order, &[]).finish();
        assert!(slot.installable(), "order {order:?}");
        let load = whole(slot);
        assert!(
            matches!(load, GuardedLoad::Warm(_)),
            "order {order:?}: {load:?}"
        );
        assert_eq!(loaded(load), entries, "order {order:?}");
    }
}
