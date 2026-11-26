use super::{GeometryRefusal, VolumeGeometry};
use crate::failover::poll::{Reads, Verdict, fresh, poll};
use crate::failover::poll_tests::{
    listed, own_entry, own_pair, owner, report_of, serving, volume, wide,
};
use crate::failover::records::{Layout, LayoutRefusal, VolumeState, prefix_floor, slot_units};
use crate::failover::retire::{Retirement, Role, Target, Trigger};
use crate::storage::store_tests::record;

/// Units of an 8 TiB volume of 4 KiB units.
const VOLUME_UNITS: u64 = 1 << 31;

#[test]
fn below_floor_refuses_and_retires() {
    let floor = prefix_floor(3, 1 << 25).expect("a floor");
    assert_eq!(floor, 2_455_207);
    let at_floor = Layout {
        units: floor,
        slots: 3,
        slot_units: 818_402,
        entries: 1 << 25,
    };
    let below = Layout {
        units: floor - 1,
        ..at_floor
    };
    let refusal = LayoutRefusal::BelowFloor {
        units: floor - 1,
        floor,
    };
    assert_eq!(
        VolumeGeometry::recorded(&below, VOLUME_UNITS),
        Err(GeometryRefusal::Layout(refusal))
    );
    let geometry = VolumeGeometry::recorded(&at_floor, VOLUME_UNITS).expect("the floor admits");
    assert_eq!(
        (geometry.metadata_units(), geometry.payload_units()),
        (floor, VOLUME_UNITS - floor)
    );
    let holder = owner();
    let own = listed(&[holder.instance.as_str()]);
    let recorded = |layout| {
        let mut record = volume(VolumeState::Active, holder.host);
        record.layout = layout;
        record
    };
    let (kept, refused) = (recorded(at_floor), recorded(below));
    let retired = |target| {
        Verdict::Retire(
            Retirement::new(
                holder.volume,
                Role::Active,
                target,
                Trigger::Layout(refusal),
            )
            .expect("a retirement"),
        )
    };
    let acquiring = record();
    let fresh_reads = |volume| Reads {
        shard: Some(&acquiring),
        volume: Some(volume),
        listed: Some(&own),
        peers: &[],
    };
    assert_eq!(fresh(&holder, &fresh_reads(&kept)), Verdict::Continue);
    assert_eq!(
        fresh(&holder, &fresh_reads(&refused)),
        retired(Target::of(&acquiring))
    );
    let serving_record = serving();
    let target = Target::of(&serving_record);
    let poll_reads = |volume| Reads {
        shard: Some(&serving_record),
        volume: Some(volume),
        listed: Some(&own),
        peers: &[],
    };
    let held = [own_entry()];
    let held = report_of(&held);
    assert_eq!(
        poll(
            &holder,
            target,
            own_pair(),
            Ok(&held),
            &poll_reads(&kept),
            &wide()
        ),
        Verdict::Continue
    );
    assert_eq!(
        poll(
            &holder,
            target,
            own_pair(),
            Ok(&held),
            &poll_reads(&refused),
            &wide()
        ),
        retired(target)
    );
}

#[test]
fn recorded_geometry_refuses_each_bound_and_admits_its_edges() {
    let floor = prefix_floor(3, 1 << 25).expect("a floor");
    let at_floor = Layout {
        units: floor,
        slots: 3,
        slot_units: 818_402,
        entries: 1 << 25,
    };
    for (layout, refused) in [
        (
            Layout {
                slots: 2,
                ..at_floor
            },
            LayoutRefusal::TooFewSlots { slots: 2 },
        ),
        (
            Layout {
                slot_units: 818_403,
                ..at_floor
            },
            LayoutRefusal::SlotUnits {
                recorded: 818_403,
                required: 818_402,
            },
        ),
        (
            Layout {
                slot_units: 818_401,
                ..at_floor
            },
            LayoutRefusal::SlotUnits {
                recorded: 818_401,
                required: 818_402,
            },
        ),
    ] {
        assert_eq!(
            VolumeGeometry::recorded(&layout, VOLUME_UNITS),
            Err(GeometryRefusal::Layout(refused))
        );
    }
    assert_eq!(
        VolumeGeometry::recorded(&at_floor, floor),
        Err(GeometryRefusal::PastVolume {
            units: floor,
            volume: floor,
        })
    );
    assert_eq!(
        VolumeGeometry::recorded(&at_floor, (1 << 37) + 1),
        Err(GeometryRefusal::VolumeTooLarge {
            volume: (1 << 37) + 1
        })
    );
    assert_eq!(
        VolumeGeometry::recorded(&at_floor, floor - 1),
        Err(GeometryRefusal::PastVolume {
            units: floor,
            volume: floor - 1,
        })
    );
    for (volume_units, payload) in [(floor + 1, 1), (1 << 37, (1 << 37) - floor)] {
        let geometry = VolumeGeometry::recorded(&at_floor, volume_units).expect("a payload unit");
        assert_eq!(
            (geometry.metadata_units(), geometry.payload_units()),
            (floor, payload)
        );
    }
}

#[test]
fn the_floor_follows_the_entry_cap_at_every_multiple_of_41_and_each_slot_count() {
    for (entries, units) in [
        (0, 1),
        (1, 2),
        (40, 2),
        (41, 2),
        (42, 3),
        (81, 3),
        (82, 3),
        (83, 4),
        (1 << 25, 818_402),
    ] {
        assert_eq!(slot_units(entries), units, "{entries} entries");
    }
    for (entries, slots, slot, floor) in [
        (0, 3, 1, 4),
        (41, 3, 2, 7),
        (42, 4, 3, 13),
        (82, 5, 3, 16),
        (83, 3, 4, 13),
        (64, 7, 3, 22),
    ] {
        let layout = Layout {
            units: floor,
            slots,
            slot_units: slot,
            entries,
        };
        assert_eq!(
            prefix_floor(u64::from(slots), u64::from(entries)),
            Some(floor)
        );
        assert_eq!(layout.check_floor(), Ok(()), "{layout:?}");
        assert_eq!(
            Layout {
                units: floor - 1,
                ..layout
            }
            .check_floor(),
            Err(LayoutRefusal::BelowFloor {
                units: floor - 1,
                floor
            })
        );
        for recorded in [slot - 1, slot + 1] {
            assert_eq!(
                Layout {
                    slot_units: recorded,
                    ..layout
                }
                .check_floor(),
                Err(LayoutRefusal::SlotUnits {
                    recorded,
                    required: u64::from(slot)
                })
            );
        }
    }
}
