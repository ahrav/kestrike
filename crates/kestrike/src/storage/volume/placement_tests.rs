use super::placement::{PlacementRefusal, place};
use crate::failover::records::{Layout, LayoutRefusal};

#[test]
fn unplaceable_capture_refused_before_submit() {
    let cap = 100;
    for slots in 2..=4u32 {
        let layout = Layout {
            units: 1 << 20,
            slots,
            slot_units: 4,
            entries: cap,
        };
        for mask in 0..1u32 << slots {
            let possible: Vec<u32> = (0..slots).filter(|slot| mask & 1 << slot != 0).collect();
            for entries in [0, 1, u64::from(cap), u64::from(cap) + 1, u64::MAX] {
                let placed = place(&layout, &possible, entries);
                if slots == 2 {
                    assert_eq!(
                        placed,
                        Err(PlacementRefusal::Layout(LayoutRefusal::TooFewSlots {
                            slots
                        }))
                    );
                } else if entries > u64::from(cap) {
                    assert_eq!(placed, Err(PlacementRefusal::Entries { entries, cap }));
                } else if possible.len() == slots as usize {
                    assert_eq!(placed, Err(PlacementRefusal::NoFreeSlot));
                } else {
                    let slot = placed.expect("a free slot");
                    assert!(slot < slots && !possible.contains(&slot));
                    assert_eq!((0..slot).find(|free| !possible.contains(free)), None);
                }
            }
        }
    }
    let valid = Layout {
        units: 13,
        slots: 3,
        slot_units: 4,
        entries: cap,
    };
    for (layout, refusal) in [
        (
            Layout {
                slot_units: 3,
                ..valid
            },
            LayoutRefusal::SlotUnits {
                recorded: 3,
                required: 4,
            },
        ),
        (
            Layout { units: 12, ..valid },
            LayoutRefusal::BelowFloor {
                units: 12,
                floor: 13,
            },
        ),
    ] {
        assert_eq!(
            place(&layout, &[0], 1),
            Err(PlacementRefusal::Layout(refusal))
        );
    }
    assert_eq!(place(&valid, &[0], 1), Ok(1));
}

/// Steps the device until the staged unit command ends and returns its result.
fn finish(dev: &mut super::super::volume_fixture::Device<'_, '_>) -> super::checkpoint::UnitDone {
    (0..1000)
        .find_map(|_| {
            super::super::volume_fixture::step(
                &mut dev.volume,
                &dev.control,
                &mut Vec::with_capacity(16),
            );
            dev.volume.take_unit()
        })
        .expect("the unit command ends")
}

/// The device byte ranges every write the device accepted inside the metadata prefix starts at.
fn prefix_writes(dev: &super::super::volume_fixture::Device<'_, '_>) -> Vec<u64> {
    use super::super::device::Operation;
    use super::super::device::sim::Captured;
    let metadata = super::super::TEST_METADATA_UNITS * super::super::IO_UNIT as u64;
    dev.control
        .capture()
        .events
        .iter()
        .filter_map(|event| match event {
            Captured::Submitted {
                operation: Operation::Write,
                device,
                ..
            } if device.start() < metadata => Some(device.start()),
            _ => None,
        })
        .collect()
}

/// The device bytes of slot `slot` under `layout`.
fn slot_range(layout: &Layout, slot: u32) -> std::ops::Range<u64> {
    let unit = super::super::IO_UNIT as u64;
    let first = (1 + u64::from(slot) * u64::from(layout.slot_units)) * unit;
    first..first + u64::from(layout.slot_units) * unit
}

fn checkpoint(capture: u32) -> super::super::checkpoint::Checkpoint {
    super::super::checkpoint::Checkpoint {
        shard: crate::net::ownership::Shard::new(7).unwrap(),
        session: 2,
        capture,
    }
}

/// Stages `entries` as capture `capture` under `possible` with an unlimited engine budget.
fn staged_capture(
    possible: &mut super::super::checkpoint::PossiblyNamed,
    capture: u32,
    entries: &[crate::storage::recovery::CaptureEntry],
) -> Result<super::super::checkpoint::StagedCheckpoint, super::super::checkpoint::StageRefusal> {
    super::super::checkpoint::StagedCheckpoint::new(
        super::super::record::Crc32c::detect(),
        possible,
        (checkpoint(capture), entries),
        &crate::storage::EngineBudget::unlimited(),
    )
}

/// Fifty one-extent entries of incarnation 2.
fn fifty() -> Vec<crate::storage::recovery::CaptureEntry> {
    (0..50)
        .map(|at| crate::storage::recovery::capture_tests::entry(at, 2, 8 * at as u64))
        .collect()
}

pub(super) fn test_layout() -> Layout {
    Layout {
        units: 16,
        slots: 3,
        slot_units: 4,
        entries: 3 * crate::failover::records::UNIT_ENTRIES as u32,
    }
}

#[test]
fn checkpoint_units_only_to_unnamed_slots() {
    use super::super::checkpoint::PossiblyNamed;
    use super::super::volume_fixture::{Device, step};
    use super::checkpoint::{UnitDone, UnitRefused};
    use super::journal_tests::{poll, published, storage_with};
    use crate::failover::records::NamedCheckpoint;

    let storage = storage_with(|volume| volume.metadata_commands = 2);
    let buffers = super::bootstrap_tests::arena_maintaining(2, 4096);
    let mut dev = Device::new(&storage, &buffers);
    dev.control.clear_capture();
    published(&storage, &mut dev, 1..=3);
    let layout = test_layout();
    let named = NamedCheckpoint {
        slot: 1,
        session: 2,
        capture: 1,
        units: 2,
    };
    let mut possible = PossiblyNamed::new(
        (crate::net::ownership::Shard::new(7).unwrap(), 2),
        layout,
        Some(named),
    );
    possible.submit(Some(2));
    let entries = fifty();
    let mut stage = staged_capture(&mut possible, 2, &entries).unwrap();
    let slot = stage.slot();
    assert_eq!(slot, 0, "slots 1 and 2 are possibly named");
    assert_eq!(
        dev.volume.stage_unit_write(
            &PossiblyNamed::new(
                (crate::net::ownership::Shard::new(7).unwrap(), 2),
                layout,
                None
            ),
            &mut stage,
            0
        ),
        Err(UnitRefused::Unreserved),
        "a set that holds no reservation for the stage refuses its unit"
    );
    let mut out = Vec::with_capacity(16);
    for unit in 0..stage.units().len() as u32 {
        dev.volume
            .stage_unit_write(&possible, &mut stage, unit)
            .unwrap();
        assert_eq!(
            dev.volume.stage_unit_write(&possible, &mut stage, unit),
            Err(UnitRefused::Busy)
        );
        let done = finish(&mut dev);
        assert_eq!(done, UnitDone::Written { slot, unit });
        dev.volume.stage_unit_read(&possible, (slot, unit)).unwrap();
        let done = finish_for(&mut dev, &mut stage);
        assert_eq!(done, UnitDone::Read { slot, unit });
    }
    assert!(stage.verified(), "every unit reads back its staged bytes");
    assert_eq!(
        dev.volume.stage_unit_write(&possible, &mut stage, 4),
        Err(UnitRefused::Range),
        "a unit past the stage's units"
    );
    for _ in 0..32 {
        poll(&mut dev);
        step(&mut dev.volume, &dev.control, &mut out);
    }
    let writes = prefix_writes(&dev);
    assert_eq!(
        writes.len(),
        stage.units().len(),
        "only the unit writes reach the prefix"
    );
    assert!(
        writes
            .iter()
            .all(|start| slot_range(&layout, slot).contains(start)),
        "{writes:?}"
    );
    let protected = |possible: &PossiblyNamed| {
        let mut slots = possible.slots();
        slots.extend(possible.quarantined());
        slots
    };
    let flagged = |writes: &[u64], slots: &[u32]| {
        writes.iter().any(|start| {
            slots
                .iter()
                .any(|named| slot_range(&layout, *named).contains(start))
        })
    };
    assert!(!flagged(&writes, &protected(&possible)));
    let mut incomplete = PossiblyNamed::new(
        (crate::net::ownership::Shard::new(7).unwrap(), 2),
        layout,
        None,
    );
    incomplete.submit(Some(0));
    let mut injected = staged_capture(&mut incomplete, 3, &entries).unwrap();
    assert_eq!(injected.slot(), 1, "a set that forgets the named slot");
    dev.volume
        .stage_unit_write(&incomplete, &mut injected, 0)
        .unwrap();
    let done = finish(&mut dev);
    assert_eq!(done, UnitDone::Written { slot: 1, unit: 0 });
    assert!(
        flagged(&prefix_writes(&dev), &protected(&possible)),
        "an injected write to a named slot is flagged"
    );
    let _ = dev
        .volume
        .authority_event(crate::failover::serving::Event::Withdraw(
            crate::failover::serving::Cause::Planned,
        ));
    assert_eq!(
        dev.volume.stage_unit_write(&possible, &mut stage, 0),
        Err(UnitRefused::Unadmitted),
        "a withdrawn tenure stages no unit"
    );
}

/// Steps the device until the staged unit command ends and returns its result, with a read-back recorded in `stage`.
fn finish_for(
    dev: &mut super::super::volume_fixture::Device<'_, '_>,
    stage: &mut super::super::checkpoint::StagedCheckpoint,
) -> super::checkpoint::UnitDone {
    (0..1000)
        .find_map(|_| {
            super::super::volume_fixture::step(
                &mut dev.volume,
                &dev.control,
                &mut Vec::with_capacity(16),
            );
            dev.volume.take_unit_for(stage)
        })
        .expect("the unit command ends")
}

/// Every attempt of a unit carries the bytes the stage retains: a first write the device fails leaves the unit
/// unverified, and the retry writes and verifies the retained bytes. New content needs a new
/// capture number: a second stage at the same `(session, capture)` refuses, and the next capture takes another slot,
/// since the abandoned stage's write exposed its own.
#[test]
fn a_retried_unit_write_submits_the_staged_bytes_and_changed_content_needs_a_new_capture() {
    use super::super::checkpoint::{PossiblyNamed, ReserveRefusal, StageRefusal};
    use super::super::device::sim::Fault;
    use super::super::device::{DeviceStatus, Operation};
    use super::super::volume_fixture::Device;
    use super::bootstrap_tests::submitted;
    use super::checkpoint::UnitDone;
    use super::journal_tests::{poll, published, storage_with};

    let storage = storage_with(|volume| volume.metadata_commands = 2);
    let buffers = super::bootstrap_tests::arena_maintaining(2, 4096);
    let mut dev = Device::new(&storage, &buffers);
    published(&storage, &mut dev, 1..=3);
    let layout = test_layout();
    let mut possible = PossiblyNamed::new(
        (crate::net::ownership::Shard::new(7).unwrap(), 2),
        layout,
        None,
    );
    let entries = fifty();
    let mut stage = staged_capture(&mut possible, 2, &entries).unwrap();
    let slot = stage.slot();
    let start = slot_range(&layout, slot).start as usize;
    let staged = stage.units()[0].to_vec();

    dev.volume
        .stage_unit_write(&possible, &mut stage, 0)
        .unwrap();
    poll(&mut dev);
    let (token, _) = *submitted(&dev.control, Operation::Write).last().unwrap();
    dev.control
        .fault(token, Fault::Status(DeviceStatus::Kernel(-5)));
    assert_eq!(finish(&mut dev), UnitDone::Failed { slot, unit: 0 });
    dev.volume.stage_unit_read(&possible, (slot, 0)).unwrap();
    assert_eq!(
        finish_for(&mut dev, &mut stage),
        UnitDone::Read { slot, unit: 0 }
    );
    assert_ne!(
        dev.control.device(start, staged.len()),
        staged,
        "the failed write moved no byte"
    );
    for unit in 1..stage.units().len() as u32 {
        dev.volume
            .stage_unit_write(&possible, &mut stage, unit)
            .unwrap();
        finish(&mut dev);
        dev.volume.stage_unit_read(&possible, (slot, unit)).unwrap();
        finish_for(&mut dev, &mut stage);
    }
    assert!(
        !stage.verified(),
        "every other unit read back equal, so the failed write's unit alone is unverified"
    );

    dev.volume
        .stage_unit_write(&possible, &mut stage, 0)
        .unwrap();
    assert_eq!(finish(&mut dev), UnitDone::Written { slot, unit: 0 });
    assert_eq!(
        dev.control.device(start, staged.len()),
        staged,
        "the retry writes the retained bytes"
    );
    dev.volume.stage_unit_read(&possible, (slot, 0)).unwrap();
    finish_for(&mut dev, &mut stage);
    assert!(
        stage.verified(),
        "every unit reads back equal after the retry"
    );

    let mut changed = entries.clone();
    changed.pop();
    assert_eq!(
        staged_capture(&mut possible, 3, &changed).map(|_| ()),
        Err(StageRefusal::Reserve(ReserveRefusal::Busy)),
        "one stage holds the reservation"
    );
    stage.abandon(&mut possible);
    assert_eq!(possible.quarantined(), [slot]);
    assert_eq!(
        staged_capture(&mut possible, 2, &changed).map(|_| ()),
        Err(StageRefusal::Reserve(ReserveRefusal::Capture)),
        "changed content at the same capture number refuses"
    );
    let next = staged_capture(&mut possible, 3, &changed).unwrap();
    assert_ne!(
        next.slot(),
        slot,
        "the next capture avoids the exposed slot"
    );
}

/// A unit write whose completion is lost lands its bytes with no terminal; its stage stays unverified, the volume's
/// end fails the command once, and abandoning the stage quarantines the slot the attempt reached, so no later capture
/// of the tenure writes it.
#[test]
fn a_unit_write_whose_completion_is_lost_quarantines_its_slot() {
    use super::super::checkpoint::PossiblyNamed;
    use super::super::device::sim::{Fault, QuiesceMode};
    use super::super::device::{Operation, QuiesceProgress};
    use super::super::volume_fixture::{Device, step};
    use super::bootstrap_tests::submitted;
    use super::checkpoint::{UnitDone, UnitRefused};
    use super::journal_tests::{poll, published, storage_with};

    let storage = storage_with(|volume| volume.metadata_commands = 2);
    let buffers = super::bootstrap_tests::arena_maintaining(2, 4096);
    let mut dev = Device::new(&storage, &buffers);
    published(&storage, &mut dev, 1..=3);
    let layout = test_layout();
    let mut possible = PossiblyNamed::new(
        (crate::net::ownership::Shard::new(7).unwrap(), 2),
        layout,
        None,
    );
    let entries = fifty();
    let mut stage = staged_capture(&mut possible, 2, &entries).unwrap();
    let slot = stage.slot();
    dev.volume
        .stage_unit_write(&possible, &mut stage, 0)
        .unwrap();
    poll(&mut dev);
    let (token, _) = *submitted(&dev.control, Operation::Write).last().unwrap();
    dev.control.fault(token, Fault::DropCompletion);
    let mut ended = Vec::new();
    for _ in 0..64 {
        step(&mut dev.volume, &dev.control, &mut Vec::with_capacity(16));
        ended.extend(dev.volume.take_unit_for(&mut stage));
    }
    assert_eq!(ended, [], "the completion never arrives");
    assert_eq!(
        dev.volume.stage_unit_write(&possible, &mut stage, 1),
        Err(UnitRefused::Busy),
        "the lost command holds the cell"
    );
    let start = slot_range(&layout, slot).start as usize;
    assert_eq!(
        dev.control.device(start, super::super::IO_UNIT),
        stage.units()[0][..],
        "the attempt landed"
    );
    assert!(!stage.verified());
    dev.control.set_quiesce(QuiesceMode::Reset);
    let mut progress = dev.volume.close();
    for _ in 0..4 {
        poll(&mut dev);
        ended.extend(dev.volume.take_unit_for(&mut stage));
        progress = dev.volume.close();
    }
    assert!(
        matches!(progress, QuiesceProgress::Quiesced(_)),
        "{progress:?}"
    );
    assert_eq!(
        ended,
        [UnitDone::Failed { slot, unit: 0 }],
        "the volume's end fails the command once"
    );
    assert!(!stage.verified(), "a lost write never verifies");
    stage.abandon(&mut possible);
    assert_eq!(possible.quarantined(), [slot]);
    let next = staged_capture(&mut possible, 3, &entries).unwrap();
    assert_ne!(
        next.slot(),
        slot,
        "no later capture of the tenure reuses the exposed slot"
    );
}

/// A unit command runs once: a refused submit, a device failure or a refused read-back each yield `UnitDone::Failed`,
/// submit nothing again, and leave the metadata open for the next unit; a delivered result not yet taken, a slot or
/// unit outside the layout, and a prefix unit past the metadata area each refuse at staging.
#[test]
fn a_failed_unit_command_ends_once_and_leaves_the_metadata_open() {
    use super::super::checkpoint::{PossiblyNamed, StagedCheckpoint};
    use super::super::device::sim::Fault;
    use super::super::device::{DeviceStatus, Operation, RefusalReason, SubmitRefusal};
    use super::super::volume_fixture::{Device, step};
    use super::bootstrap_tests::submitted;
    use super::checkpoint::{UnitDone, UnitRefused};
    use super::journal_tests::{poll, published, storage_with};

    let storage = storage_with(|volume| volume.metadata_commands = 2);
    let buffers = super::bootstrap_tests::arena_maintaining(2, 4096);
    let mut dev = Device::new(&storage, &buffers);
    published(&storage, &mut dev, 1..=3);
    let layout = test_layout();
    let mut possible = PossiblyNamed::new(
        (crate::net::ownership::Shard::new(7).unwrap(), 2),
        layout,
        None,
    );
    let mut stage = StagedCheckpoint::reserved_at(
        &mut possible,
        checkpoint(2),
        0,
        vec![Box::new([0x5A; super::super::recovery::checkpoint::UNIT_LEN]); 5],
    );
    let refused = SubmitRefusal {
        reason: RefusalReason::InvalidRange,
        code: None,
    };

    let before = submitted(&dev.control, Operation::Write).len();
    dev.control.refuse_next(refused);
    dev.volume
        .stage_unit_write(&possible, &mut stage, 0)
        .unwrap();
    assert_eq!(finish(&mut dev), UnitDone::Failed { slot: 0, unit: 0 });
    assert_eq!(
        dev.volume.metadata_outcome(),
        super::super::MetadataOutcome::Open,
        "a refused unit write leaves the metadata open"
    );
    assert_eq!(
        submitted(&dev.control, Operation::Write).len(),
        before,
        "the refused write is not resubmitted"
    );

    dev.volume
        .stage_unit_write(&possible, &mut stage, 1)
        .unwrap();
    poll(&mut dev);
    let (token, _) = *submitted(&dev.control, Operation::Write).last().unwrap();
    dev.control
        .fault(token, Fault::Status(DeviceStatus::Kernel(-5)));
    assert_eq!(finish(&mut dev), UnitDone::Failed { slot: 0, unit: 1 });
    let writes = submitted(&dev.control, Operation::Write).len();
    for _ in 0..16 {
        poll(&mut dev);
        dev.control.tick(64);
    }
    assert_eq!(
        submitted(&dev.control, Operation::Write).len(),
        writes,
        "a failed unit write runs once"
    );
    assert_eq!(
        dev.volume.metadata_outcome(),
        super::super::MetadataOutcome::Open
    );

    dev.control.refuse_next(refused);
    dev.volume.stage_unit_read(&possible, (0, 0)).unwrap();
    assert_eq!(finish(&mut dev), UnitDone::Failed { slot: 0, unit: 0 });

    dev.volume
        .stage_unit_write(&possible, &mut stage, 2)
        .unwrap();
    for _ in 0..1000 {
        if dev.volume.metadata.unit.is_some() {
            break;
        }
        step(&mut dev.volume, &dev.control, &mut Vec::with_capacity(16));
    }
    assert!(
        dev.volume.metadata.unit.is_some(),
        "the third unit write ends"
    );
    assert_eq!(
        dev.volume.stage_unit_write(&possible, &mut stage, 3),
        Err(UnitRefused::Busy),
        "a delivered result not yet taken holds the cell"
    );
    assert_eq!(
        dev.volume.take_unit(),
        Some(UnitDone::Written { slot: 0, unit: 2 })
    );
    let writes = submitted(&dev.control, Operation::Write).len();
    assert_eq!(
        dev.volume.stage_unit_write(&possible, &mut stage, 4),
        Err(UnitRefused::Range),
        "a unit past the slot"
    );
    let mut past = StagedCheckpoint::reserved_at(
        &mut possible,
        checkpoint(3),
        3,
        vec![Box::new([0; super::super::recovery::checkpoint::UNIT_LEN])],
    );
    assert_eq!(
        dev.volume.stage_unit_write(&possible, &mut past, 0),
        Err(UnitRefused::Range),
        "a slot past the layout"
    );
    let mut beyond = PossiblyNamed::new(
        (crate::net::ownership::Shard::new(7).unwrap(), 2),
        Layout {
            units: 1 + 3 * 64,
            slot_units: 64,
            entries: 63 * crate::failover::records::UNIT_ENTRIES as u32,
            ..layout
        },
        None,
    );
    let mut far = StagedCheckpoint::reserved_at(
        &mut beyond,
        checkpoint(2),
        2,
        vec![Box::new([0; super::super::recovery::checkpoint::UNIT_LEN])],
    );
    assert_eq!(
        dev.volume.stage_unit_write(&beyond, &mut far, 0),
        Err(UnitRefused::Range),
        "a prefix unit past the metadata area"
    );
    poll(&mut dev);
    assert_eq!(
        submitted(&dev.control, Operation::Write).len(),
        writes,
        "a refused staging submits nothing"
    );
}

/// A staged unit write or read-back that a lost device, a withdrawal or a volume close reaches before its submission
/// ends once as `UnitDone::Failed` and submits nothing, and staging then refuses.
#[test]
fn a_staged_unit_command_fails_once_on_loss_withdrawal_or_close() {
    use super::super::checkpoint::{PossiblyNamed, StagedCheckpoint};
    use super::super::device::{Operation, RefusalReason, SubmitRefusal};
    use super::super::volume_fixture::Device;
    use super::bootstrap_tests::submitted;
    use super::checkpoint::{UnitDone, UnitRefused};
    use super::journal_tests::{poll, published, storage_with};

    let layout = test_layout();
    let mut possible = PossiblyNamed::new(
        (crate::net::ownership::Shard::new(7).unwrap(), 2),
        layout,
        None,
    );
    let mut stage = StagedCheckpoint::reserved_at(
        &mut possible,
        checkpoint(2),
        0,
        vec![Box::new([0x5A; super::super::recovery::checkpoint::UNIT_LEN]); 5],
    );
    for case in ["lost", "withdrawn", "storage withdrawn", "closed"] {
        for read in [false, true] {
            let storage = storage_with(|volume| volume.metadata_commands = 2);
            let buffers = super::bootstrap_tests::arena_maintaining(2, 4096);
            let mut dev = Device::new(&storage, &buffers);
            published(&storage, &mut dev, 1..=3);
            let before = submitted(&dev.control, Operation::Write).len()
                + submitted(&dev.control, Operation::Read).len();
            let mut command = |dev: &mut Device<'_, '_>| {
                if read {
                    dev.volume.stage_unit_read(&possible, (0, 0))
                } else {
                    dev.volume.stage_unit_write(&possible, &mut stage, 0)
                }
            };
            command(&mut dev).unwrap();
            match case {
                "lost" => {
                    dev.control.refuse_next(SubmitRefusal {
                        reason: RefusalReason::DeviceGone,
                        code: Some(-19),
                    });
                    poll(&mut dev);
                }
                "withdrawn" => {
                    let _ = dev
                        .volume
                        .authority_event(crate::failover::serving::Event::Withdraw(
                            crate::failover::serving::Cause::Planned,
                        ));
                }
                "storage withdrawn" => {
                    let _ = storage.withdraw();
                    poll(&mut dev);
                }
                _ => {
                    let _ = dev.volume.close();
                }
            }
            assert_eq!(
                dev.volume.take_unit(),
                Some(UnitDone::Failed { slot: 0, unit: 0 }),
                "{case}, read-back {read}"
            );
            for _ in 0..8 {
                poll(&mut dev);
            }
            assert_eq!(
                dev.volume.take_unit(),
                None,
                "{case}: the command ends once"
            );
            let after = submitted(&dev.control, Operation::Write).len()
                + submitted(&dev.control, Operation::Read).len();
            assert_eq!(
                after, before,
                "{case}: the staged command is never submitted"
            );
            assert!(
                matches!(command(&mut dev), Err(UnitRefused::Unadmitted)),
                "{case}: staging refuses"
            );
        }
    }
}

/// A unit write or read-back whose submit unwinds inside the driver call reaches no terminal the volume maps, so the
/// volume's loss ends it once as `UnitDone::Failed`; the command stays ended through the proven stop.
#[test]
fn a_unit_command_whose_submit_unwinds_fails_once() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::super::checkpoint::{PossiblyNamed, StagedCheckpoint};
    use super::super::device::QuiesceProgress;
    use super::super::device::sim::{QuiesceMode, Unwind};
    use super::super::volume_fixture::Device;
    use super::checkpoint::{UnitDone, UnitRefused};
    use super::journal_tests::{poll, published, storage_with};

    let layout = test_layout();
    let mut possible = PossiblyNamed::new(
        (crate::net::ownership::Shard::new(7).unwrap(), 2),
        layout,
        None,
    );
    let mut stage = StagedCheckpoint::reserved_at(
        &mut possible,
        checkpoint(2),
        0,
        vec![Box::new([0x5A; super::super::recovery::checkpoint::UNIT_LEN]); 5],
    );
    for read in [false, true] {
        let storage = storage_with(|volume| volume.metadata_commands = 2);
        let buffers = super::bootstrap_tests::arena_maintaining(2, 4096);
        let mut dev = Device::new(&storage, &buffers);
        published(&storage, &mut dev, 1..=3);
        if read {
            dev.volume.stage_unit_read(&possible, (0, 0)).unwrap();
        } else {
            dev.volume
                .stage_unit_write(&possible, &mut stage, 0)
                .unwrap();
        }
        dev.control.unwind_next(Some(Unwind::Submit));
        let mut out = Vec::with_capacity(16);
        let unwound = catch_unwind(AssertUnwindSafe(|| dev.volume.poll_storage(0, &mut out)));
        dev.control.unwind_next(None);
        assert!(unwound.is_err(), "read-back {read}: the submit unwinds");
        let mut ended = Vec::new();
        for _ in 0..4 {
            poll(&mut dev);
            ended.extend(dev.volume.take_unit());
        }
        assert!(dev.volume.is_lost(), "read-back {read}");
        assert_eq!(
            ended,
            [UnitDone::Failed { slot: 0, unit: 0 }],
            "read-back {read}: the lost volume ends the unwound command once"
        );
        assert!(
            matches!(
                dev.volume.stage_unit_read(&possible, (0, 1)),
                Err(UnitRefused::Unadmitted)
            ),
            "read-back {read}: a lost volume stages no unit"
        );
        dev.control.set_quiesce(QuiesceMode::Reset);
        let mut progress = dev.volume.close();
        for _ in 0..4 {
            poll(&mut dev);
            ended.extend(dev.volume.take_unit());
            progress = dev.volume.close();
        }
        assert!(
            matches!(progress, QuiesceProgress::Quiesced(_)),
            "read-back {read}: {progress:?}"
        );
        assert_eq!(
            ended.len(),
            1,
            "read-back {read}: the command ends once through the proven stop"
        );
    }
}

/// The owner exits while a unit write of the next capture is outstanding and its completion never arrives. The
/// write was admitted only to the stage's reserved slot, so the named slot holds the bytes its own stage verified,
/// the store names the same checkpoint, the exposed slot is quarantined, and a reader over the device's prefix loads
/// every entry of the named checkpoint. A placement over no unavailable slot takes the named slot, which the
/// named-slot byte comparison guards.
#[test]
fn an_owner_exit_with_a_unit_write_outstanding_keeps_the_named_checkpoint() {
    use super::super::checkpoint::tests::{Inline, SESSION, entry, load_limits};
    use super::super::checkpoint::{PossiblyNamed, SlotReader, StagedCheckpoint, publish};
    use super::super::device::sim::{Fault, QuiesceMode};
    use super::super::device::{Operation, QuiesceProgress};
    use super::super::record::Crc32c;
    use super::super::recovery::checkpoint_tests::{routing, whole};
    use super::super::recovery::{Capture, CaptureEpoch, GuardedLoad, SideCap};
    use super::super::store::Key;
    use super::super::store_tests::{OWNER, client, record, shard, stored};
    use super::super::volume_fixture::{Device, step};
    use super::bootstrap_tests::submitted;
    use super::checkpoint::UnitDone;
    use super::journal_tests::{poll, published, storage_with};
    use crate::failover::records::{Host, ShardRecord};
    use crate::failover::retire::Target;
    use crate::storage::EngineBudget;

    let storage = storage_with(|volume| volume.metadata_commands = 2);
    let buffers = super::bootstrap_tests::arena_maintaining(2, 4096);
    let mut dev = Device::new(&storage, &buffers);
    published(&storage, &mut dev, 1..=3);
    let layout = test_layout();
    let store = super::super::store::sim::Shared::new();
    // The tenure of `SESSION`: generation 3 and one consumed attempt.
    let seeded = ShardRecord {
        attempts: 1,
        ..record()
    };
    client(&store).create_shard(seeded).unwrap();
    let mut host = client(&store);
    let own = Target {
        generation: seeded.generation,
        owner: Host::new(OWNER).unwrap(),
        attempts: 1,
    };
    let mut possible = PossiblyNamed::new((shard(), SESSION), layout, None);
    let entries: Vec<_> = (0..50).map(|at| entry(at, 2, 8 * at as u64)).collect();
    let stage_of = |possible: &mut PossiblyNamed, capture| {
        let checkpoint = super::super::checkpoint::Checkpoint {
            shard: shard(),
            session: SESSION,
            capture,
        };
        let budget = EngineBudget::unlimited();
        StagedCheckpoint::new(Crc32c::detect(), possible, (checkpoint, &entries), &budget).unwrap()
    };
    let mut first = stage_of(&mut possible, 1);
    let slot = first.slot();
    for unit in 0..first.units().len() as u32 {
        dev.volume
            .stage_unit_write(&possible, &mut first, unit)
            .unwrap();
        assert_eq!(finish(&mut dev), UnitDone::Written { slot, unit });
        dev.volume.stage_unit_read(&possible, (slot, unit)).unwrap();
        assert_eq!(
            finish_for(&mut dev, &mut first),
            UnitDone::Read { slot, unit }
        );
    }
    let written: Vec<u8> = first
        .units()
        .iter()
        .flat_map(|unit| unit.to_vec())
        .collect();
    let mut pass = Capture::at_counter(0);
    let cap = SideCap {
        entries: 1,
        words: 1,
    };
    pass.start((1, CaptureEpoch::default()), 1, 0, 1, true, cap)
        .unwrap();
    pass.advance(1).unwrap();
    let proof = pass
        .intact((shard(), SESSION), CaptureEpoch::default())
        .unwrap();
    let current = host.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    publish(
        &mut host,
        &mut possible,
        &current,
        (own, None),
        (&proof, CaptureEpoch::default()),
        &mut first,
    )
    .unwrap();
    let named = first.named();
    let recorded = stored(&store);

    assert_eq!(
        super::place(&layout, &[], 50),
        Ok(slot),
        "control: a placement over no unavailable slot takes the named slot"
    );
    let mut next = stage_of(&mut possible, 2);
    assert_ne!(
        next.slot(),
        slot,
        "the next stage reserves around the named slot"
    );
    dev.volume
        .stage_unit_write(&possible, &mut next, 0)
        .unwrap();
    poll(&mut dev);
    let (token, _) = *submitted(&dev.control, Operation::Write).last().unwrap();
    dev.control.fault(token, Fault::DropCompletion);
    for _ in 0..64 {
        step(&mut dev.volume, &dev.control, &mut Vec::with_capacity(16));
        assert_eq!(dev.volume.take_unit_for(&mut next), None);
    }
    dev.control.set_quiesce(QuiesceMode::Reset);
    let (mut ended, mut progress) = (Vec::new(), dev.volume.close());
    for _ in 0..4 {
        poll(&mut dev);
        ended.extend(dev.volume.take_unit_for(&mut next));
        progress = dev.volume.close();
    }
    assert!(
        matches!(progress, QuiesceProgress::Quiesced(_)),
        "{progress:?}"
    );
    let exposed = next.slot();
    assert_eq!(
        ended,
        [UnitDone::Failed {
            slot: exposed,
            unit: 0
        }]
    );
    next.abandon(&mut possible);
    assert_eq!(possible.slots(), [slot]);
    assert_eq!(possible.quarantined(), [exposed]);
    assert_eq!(
        crate::failover::report::Pressure::unresolved(&possible),
        crate::failover::report::Gauge::known(1, u64::from(layout.slots)),
        "the quarantined slot is the one unresolved slot"
    );
    assert_eq!(stored(&store), recorded, "the exit wrote no record");
    let named_range = slot_range(&layout, slot);
    assert!(
        dev.control
            .device(named_range.start as usize, written.len())
            == written,
        "the outstanding write left the named slot's bytes"
    );
    let prefix = dev
        .control
        .device(0, layout.units as usize * super::super::IO_UNIT);
    let mut reader = SlotReader::new(
        Crc32c::detect(),
        &layout,
        shard(),
        (named, 0, &[]),
        SESSION,
        (load_limits(50), &EngineBudget::unlimited()),
        routing(4),
    )
    .unwrap();
    while let Some(range) = reader.next_read() {
        let start = range.start() as usize;
        reader.complete(range, &prefix[start..start + range.byte_len() as usize]);
    }
    assert_eq!(whole(reader.load()), GuardedLoad::Warm(entries));
}

/// Checkpoint-unit commands under a recovery I/O share of two units per ten ticks, whose bucket holds one unit of
/// bulk room beside the suffix reserve: the write of a unit takes the bulk room as it is submitted, its read-back
/// stays staged with no device submission for the five ticks the write's bytes take to drain, and each later command
/// waits the same way, so the stage still verifies every unit with the bytes it staged.
#[test]
fn checkpoint_units_wait_for_the_recovery_io_share_and_still_verify() {
    use super::super::checkpoint::PossiblyNamed;
    use super::checkpoint::UnitDone;
    use super::journal_tests::{published, storage_with};

    let storage = storage_with(|volume| {
        volume.metadata_commands = 2;
        volume.recovery.io = super::super::recovery::HostShare {
            bytes: 2 * super::super::IO_UNIT as u64,
            interval: 10,
            owners: 1,
        };
    });
    let buffers = super::bootstrap_tests::arena_maintaining(2, 4096);
    let mut dev = super::super::volume_fixture::Device::new(&storage, &buffers);
    published(&storage, &mut dev, 1..=3);
    let mut possible = PossiblyNamed::new(
        (crate::net::ownership::Shard::new(7).unwrap(), 2),
        test_layout(),
        None,
    );
    let entries = fifty();
    let mut stage = staged_capture(&mut possible, 2, &entries).unwrap();
    let slot = stage.slot();
    let mut now = 1_000;
    // Polls at `now` until the staged unit command ends.
    let finish_at = |dev: &mut super::super::volume_fixture::Device<'_, '_>,
                     stage: &mut super::super::checkpoint::StagedCheckpoint,
                     now: u64| {
        (0..1000)
            .find_map(|_| {
                dev.control.tick(64);
                let _ = dev.volume.poll_storage(now, &mut Vec::with_capacity(16));
                dev.volume.take_unit_for(stage)
            })
            .expect("the unit command ends")
    };
    let _ = dev.volume.poll_storage(now, &mut Vec::with_capacity(16));
    let mut refusals = 0;
    for unit in 0..stage.units().len() as u32 {
        dev.volume
            .stage_unit_write(&possible, &mut stage, unit)
            .unwrap();
        assert_eq!(
            finish_at(&mut dev, &mut stage, now),
            UnitDone::Written { slot, unit }
        );
        dev.volume.stage_unit_read(&possible, (slot, unit)).unwrap();
        let submitted = dev.volume.report().metadata_submitted;
        for _ in 0..5 {
            dev.control.tick(64);
            let _ = dev.volume.poll_storage(now, &mut Vec::with_capacity(16));
            assert_eq!(
                (
                    dev.volume.take_unit(),
                    dev.volume.report().metadata_submitted
                ),
                (None, submitted),
                "the read-back waits staged while the bucket holds the write's bytes"
            );
            refusals += 1;
            now += 1;
        }
        assert_eq!(
            finish_at(&mut dev, &mut stage, now),
            UnitDone::Read { slot, unit }
        );
        now += 10;
        let _ = dev.volume.poll_storage(now, &mut Vec::with_capacity(16));
    }
    assert!(stage.verified(), "every deferred unit reads back its bytes");
    // A suffix block charges the same share: once it takes the bulk room, a unit command at that tick waits.
    let layout = Layout {
        units: test_layout().units + 8,
        ..test_layout()
    };
    let mut log = super::super::recovery::suffix::SuffixLog::default();
    let limits = super::super::recovery::suffix::SuffixLimits {
        flush_ns: 1,
        queue_blocks: 4,
        oldest_ns: 1 << 40,
        uncertified: 1 << 40,
    };
    let recorded = crate::failover::records::Suffix {
        session: 2,
        start: 0,
        certified: 0,
        end: 8,
    };
    let shard = crate::net::ownership::Shard::new(7).unwrap();
    let crc = super::super::record::Crc32c::detect();
    assert!(log.open((crc, shard), (limits, &layout), recorded, 0));
    let record = super::super::recovery::delta::Record::Insert(entries[0].clone());
    log.append(0, &record).unwrap();
    log.seal_cut();
    let (share, tick) = dev.volume.recovery_io();
    assert_eq!(tick, now);
    let mut unit = [0; super::super::recovery::delta::UNIT_LEN];
    let lsn = log
        .take_within(share, tick, &mut unit)
        .expect("the bucket is empty");
    log.written(lsn);
    dev.volume.stage_unit_read(&possible, (slot, 0)).unwrap();
    let submitted = dev.volume.report().metadata_submitted;
    dev.control.tick(64);
    let _ = dev.volume.poll_storage(now, &mut Vec::with_capacity(16));
    assert_eq!(
        (
            dev.volume.take_unit(),
            dev.volume.report().metadata_submitted
        ),
        (None, submitted),
        "the suffix block took the bulk room"
    );
    let report = dev.volume.recovery_report();
    assert_eq!(
        (report.io_peak_bytes, report.io_saturated_windows),
        (
            2 * super::super::IO_UNIT as u64,
            stage.units().len() as u64 + 1
        ),
        "{refusals} waiting polls in one saturated window per unit, which holds its write and read-back, and the \
         suffix block's window"
    );
}

/// A checkpoint whose unit writes and read-backs take all the bulk room of the recovery I/O share competes with a
/// suffix log that appends a record every tick and seals one block per interval: a staged unit command waits until
/// the bucket drained, while the suffix reserve holds each sealed block as it is offered, so no append refuses
/// `Stalled` with unit commands pending. With the reserve planted away the unit commands take the room first at
/// every tick and the appends stall.
#[test]
fn suffix_blocks_keep_their_reserve_while_checkpoint_units_take_the_bulk_room() {
    use super::super::checkpoint::PossiblyNamed;
    use super::super::recovery::delta::Record;
    use super::super::recovery::io_share::NO_RESERVE;
    use super::super::recovery::suffix::{SuffixLimits, SuffixLog, SuffixRefusal};
    use super::checkpoint::UnitDone;
    use super::journal_tests::{published, storage_with};

    let run = || -> (u64, u64, u64) {
        let storage = storage_with(|volume| {
            volume.metadata_commands = 2;
            volume.recovery.io = super::super::recovery::HostShare {
                bytes: 2 * super::super::IO_UNIT as u64,
                interval: 10,
                owners: 1,
            };
        });
        let buffers = super::bootstrap_tests::arena_maintaining(2, 4096);
        let mut dev = super::super::volume_fixture::Device::new(&storage, &buffers);
        published(&storage, &mut dev, 1..=3);
        let mut possible = PossiblyNamed::new(
            (crate::net::ownership::Shard::new(7).unwrap(), 2),
            test_layout(),
            None,
        );
        let entries = fifty();
        let mut stage = staged_capture(&mut possible, 2, &entries).unwrap();
        let slot = stage.slot();
        let region = Layout {
            units: test_layout().units + 1000,
            ..test_layout()
        };
        let mut log = SuffixLog::default();
        // The log seals one block per interval, a rate the reserve holds.
        let limits = SuffixLimits {
            flush_ns: 10,
            queue_blocks: 4,
            oldest_ns: 30,
            uncertified: 1 << 40,
        };
        let recorded = crate::failover::records::Suffix {
            session: 2,
            start: 0,
            certified: 0,
            end: 1000,
        };
        let shard = crate::net::ownership::Shard::new(7).unwrap();
        let crc = super::super::record::Crc32c::detect();
        assert!(log.open((crc, shard), (limits, &region), recorded, 0));
        let (mut busy, mut write) = (false, true);
        let (mut stalls, mut units) = (0, 0);
        for now in 1_000..1_300u64 {
            dev.control.tick(64);
            let _ = dev.volume.poll_storage(now, &mut Vec::with_capacity(16));
            if let Some(done) = dev.volume.take_unit_for(&mut stage) {
                assert!(matches!(
                    done,
                    UnitDone::Written { .. } | UnitDone::Read { .. }
                ));
                (busy, write, units) = (false, !write, units + 1);
            }
            if !busy {
                let staged = if write {
                    dev.volume.stage_unit_write(&possible, &mut stage, 0)
                } else {
                    dev.volume.stage_unit_read(&possible, (slot, 0))
                };
                match staged {
                    Ok(()) => busy = true,
                    Err(other) => panic!("tick {now}: {other:?}"),
                }
            }
            let entry = entries[(now % 50) as usize].clone();
            match log.append(now, &Record::Insert(entry)) {
                Err(SuffixRefusal::Stalled) => stalls += 1,
                Ok(_) | Err(SuffixRefusal::Queue) => {}
                Err(other) => panic!("tick {now}: {other:?}"),
            }
            log.flush_due(now);
            let (share, tick) = dev.volume.recovery_io();
            let mut unit = [0; super::super::recovery::delta::UNIT_LEN];
            if let Some(lsn) = log.take_within(share, tick, &mut unit) {
                log.written(lsn);
            }
        }
        let refused = dev.volume.recovery_report().io_saturated_windows;
        (stalls, units, refused)
    };
    let (stalls, units, refused) = run();
    assert_eq!(
        stalls, 0,
        "the reserve holds each suffix block the log seals"
    );
    assert!(
        units > 10 && refused > 0,
        "{units} unit commands, {refused} windows that refused a charge"
    );
    NO_RESERVE.with(|plant| plant.set(true));
    let (planted, ..) = run();
    NO_RESERVE.with(|plant| plant.set(false));
    assert!(
        planted > 0,
        "control: with no reserve the unit commands starve the suffix blocks"
    );
}

/// A unit command that finds no maintenance buffer charges nothing to the recovery I/O share: with every buffer held
/// elsewhere, a hundred offers refuse `Buffer` and the share's peak and saturated windows stay zero, and the next
/// offer once a buffer returns stages the unit, whose submission charges its bytes.
#[test]
fn a_unit_command_with_no_buffer_charges_no_share() {
    use super::super::checkpoint::PossiblyNamed;
    use super::super::device::PoolKind;
    use super::checkpoint::UnitRefused;
    use super::journal_tests::{published, storage_with};

    let storage = storage_with(|volume| {
        volume.metadata_commands = 2;
        volume.recovery.io = super::super::recovery::HostShare {
            bytes: 2 * super::super::IO_UNIT as u64,
            interval: 10,
            owners: 1,
        };
    });
    let buffers = super::bootstrap_tests::arena_maintaining(2, 4096);
    let mut dev = super::super::volume_fixture::Device::new(&storage, &buffers);
    published(&storage, &mut dev, 1..=3);
    let mut possible = PossiblyNamed::new(
        (crate::net::ownership::Shard::new(7).unwrap(), 2),
        test_layout(),
        None,
    );
    let entries = fifty();
    let mut stage = staged_capture(&mut possible, 2, &entries).unwrap();
    let held: Vec<_> = std::iter::from_fn(|| buffers.acquire(PoolKind::Maintenance).ok()).collect();
    assert!(!held.is_empty());
    for _ in 0..100 {
        assert_eq!(
            dev.volume.stage_unit_write(&possible, &mut stage, 0),
            Err(UnitRefused::Buffer)
        );
    }
    let report = dev.volume.recovery_report();
    assert_eq!((report.io_peak_bytes, report.io_saturated_windows), (0, 0));
    drop(held);
    dev.volume
        .stage_unit_write(&possible, &mut stage, 0)
        .unwrap();
    assert_eq!(
        dev.volume.recovery_report().io_peak_bytes,
        0,
        "staging charges nothing"
    );
    dev.control.tick(64);
    let _ = dev.volume.poll_storage(1_000, &mut Vec::with_capacity(16));
    assert_eq!(
        dev.volume.recovery_report().io_peak_bytes,
        super::super::IO_UNIT as u64
    );
}

/// A read-back the device reports whole while it moved no byte leaves its unit unverified, even when the buffer the
/// read takes is the one its unit's write just returned; a read that moves the bytes then verifies the unit.
#[test]
fn a_read_back_that_moves_no_bytes_leaves_its_unit_unverified() {
    use super::super::checkpoint::PossiblyNamed;
    use super::super::device::sim::Fault;
    use super::super::device::{DeviceStatus, Operation};
    use super::super::volume_fixture::Device;
    use super::bootstrap_tests::submitted;
    use super::checkpoint::UnitDone;
    use super::journal_tests::{poll, published, storage_with};

    let storage = storage_with(|volume| volume.metadata_commands = 1);
    let buffers = super::bootstrap_tests::arena_maintaining(1, 4096);
    let mut dev = Device::new(&storage, &buffers);
    published(&storage, &mut dev, 1..=3);
    let mut possible = PossiblyNamed::new(
        (crate::net::ownership::Shard::new(7).unwrap(), 2),
        test_layout(),
        None,
    );
    let entries = fifty();
    let mut stage = staged_capture(&mut possible, 2, &entries).unwrap();
    let slot = stage.slot();
    let whole = DeviceStatus::Kernel(super::super::recovery::checkpoint::UNIT_LEN as i32);

    dev.volume
        .stage_unit_write(&possible, &mut stage, 0)
        .unwrap();
    assert_eq!(finish(&mut dev), UnitDone::Written { slot, unit: 0 });
    dev.volume.stage_unit_read(&possible, (slot, 0)).unwrap();
    poll(&mut dev);
    let (token, _) = *submitted(&dev.control, Operation::Read).last().unwrap();
    dev.control.fault(token, Fault::Status(whole));
    assert_eq!(
        finish_for(&mut dev, &mut stage),
        UnitDone::Read { slot, unit: 0 }
    );
    assert!(
        !stage.unit_verified(0),
        "a read that moved nothing compares unequal"
    );

    dev.volume.stage_unit_read(&possible, (slot, 0)).unwrap();
    finish_for(&mut dev, &mut stage);
    assert!(
        stage.unit_verified(0),
        "a read that moved the bytes verifies"
    );
}

/// A discard frees what an ended pass holds on the capture pool's helper: the calling thread frees none of the
/// units' bytes and the helper's terminal releases the job. A pool whose bound holds one job keeps it for the
/// tenure's encode, so there the calling thread frees the units itself.
#[test]
fn a_discard_frees_an_ended_stages_units_off_the_calling_thread() {
    use super::super::checkpoint::PossiblyNamed;
    use super::super::volume_fixture::Device;
    use super::checkpoint::Leftovers;
    use super::journal_tests::storage_with;
    use crate::instrument::deallocated_bytes;

    let leftovers = || {
        let mut possible = PossiblyNamed::new(
            (crate::net::ownership::Shard::new(7).unwrap(), 2),
            test_layout(),
            None,
        );
        let mut stage = staged_capture(&mut possible, 2, &fifty()).unwrap();
        let units = stage.take_units();
        stage.abandon(&mut possible);
        Leftovers {
            saved: fifty(),
            units,
        }
    };
    let unit_bytes = 3 * super::super::IO_UNIT;

    let storage = storage_with(|volume| volume.metadata_commands = 2);
    let buffers = super::bootstrap_tests::arena_maintaining(2, 4096);
    let mut dev = Device::new(&storage, &buffers);
    let held = leftovers();
    assert_eq!(held.units.len() * super::super::IO_UNIT, unit_bytes);
    let before = deallocated_bytes();
    let accepted = dev.volume.discard(held);
    let here = deallocated_bytes().wrapping_sub(before);
    assert!(accepted, "the pool accepts the discard");
    assert!(
        here < super::super::IO_UNIT,
        "{here} bytes freed by the caller"
    );
    let live = |dev: &Device<'_, '_>| dev.volume.metadata.helpers.as_ref().unwrap().held().0;
    assert_eq!(
        live(&dev),
        1,
        "the discard holds one job until its terminal"
    );
    // The next discard adopts the first one's terminal, which the test pool waits for.
    dev.volume.discard(leftovers());
    assert_eq!(live(&dev), 1);
    assert!(!dev.volume.discard(Leftovers::default()));
    assert_eq!(live(&dev), 1, "an empty discard dispatches nothing");
    assert!(dev.volume.discarded(), "the accepted discards completed");
    assert_eq!(live(&dev), 0, "their terminals released their jobs");

    let storage = storage_with(|volume| {
        volume.metadata_commands = 2;
        (volume.recovery.helpers, volume.recovery.jobs) = (1, 1);
    });
    let buffers = super::bootstrap_tests::arena_maintaining(2, 4096);
    let mut dev = Device::new(&storage, &buffers);
    let held = leftovers();
    let before = deallocated_bytes();
    let accepted = dev.volume.discard(held);
    let here = deallocated_bytes().wrapping_sub(before);
    assert!(!accepted, "the calling thread dropped the leftovers");
    assert!(here >= unit_bytes, "{here} bytes freed by the caller");
    assert_eq!(live(&dev), 0, "the pool's one job stays for the encode");
}
