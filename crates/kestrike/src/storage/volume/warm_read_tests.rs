//! The warm bootstrap's read wiring over simulated media a running writer left: a tenure captures its entries and
//! writes them as a checkpoint through its own unit commands, a successor attaches with the warm source its record
//! names, reads the slot and the suffix blocks through the metadata cells on the recovery helpers, and installs the
//! load with no probe or root write; every failure keeps the media and the record.

use std::rc::Rc;

use super::super::super::checkpoint::{PossiblyNamed, READ_LEN, StagedCheckpoint};
use super::super::super::device::Operation;
use super::super::super::device::sim::{Media, SimControl, media};
use super::super::super::ledger::EngineBudget;
use super::super::super::lookup::LookupError;
use super::super::super::lookup_tests::lookup;
use super::super::super::portable::scripted::ScriptedClock;
use super::super::super::publish_tests::key;
use super::super::super::readiness::State;
use super::super::super::record::Crc32c;
use super::super::super::recovery::capture_tests::drain;
use super::super::super::recovery::checkpoint::{Checkpoint, UnitDamage};
use super::super::super::recovery::delta::{Cause, Record, UNIT_LEN};
use super::super::super::recovery::delta_tests::packed_as;
use super::super::super::recovery::{CaptureEntry, LoadRefusal};
use super::super::super::store_tests::{record, shard};
use super::super::super::test_platform::TestPlatform;
use super::super::super::volume_fixture::fenced;
use super::super::super::volume_fixture::{
    BUFFER, DEPTH, Device, TICK, TestVolume, arena_with, config_for, facts, read_back,
};
use super::super::super::{IO_UNIT, MetadataOutcome, ReadStatus, Storage, Volume};
use super::super::bootstrap_tests::{arena_maintaining, read_starts, submitted};
use super::super::helpers::PARK;
use super::super::journal_tests::storage_with;
use super::tests::{live, resident, served, units, writes};
use super::{WarmSource, read_len};
use crate::failover::records::{Ancestry, Layout, NamedCheckpoint, ShardRecord, Suffix};
use crate::storage::device::sim::sim_attached;

/// The narrow storage whose recovery limits hold a job for every read window and destination, as attach requires of a
/// warm source.
pub(super) fn sourced() -> Storage<TestPlatform> {
    storage_with(|volume| {
        volume.recovery.jobs = (super::super::super::checkpoint::WINDOWS + 1) as u32;
        volume.recovery.adopt = volume.recovery.jobs;
    })
}

/// The records layout over the test prefix of sixteen units: three slots of `slot_units`, the rest the delta region.
fn layout(slot_units: u32) -> Layout {
    Layout {
        units: super::super::TEST_METADATA_UNITS,
        slots: 3,
        slot_units,
        entries: (slot_units - 1) * crate::failover::records::UNIT_ENTRIES as u32,
    }
}

/// A tenure's media: `count` published objects, their entries captured and written as checkpoint 9 into the slot the
/// tenure's possibly-named set reserved, through the tenure's own unit commands; the writer's session and its free and
/// placeable units.
fn checkpointed(
    count: u8,
) -> (
    Media,
    Vec<CaptureEntry>,
    NamedCheckpoint,
    Layout,
    u64,
    (u64, u64),
) {
    let store = media(super::super::super::volume_fixture::MEDIA);
    let storage = storage_with(|volume| volume.metadata_commands = 2);
    let buffers = arena_maintaining(2, 4096);
    let mut dev = Device::over(&storage, &buffers, Rc::clone(&store));
    for n in 1..=count {
        drop(
            super::super::super::publication_tests::publish(&storage, &mut dev, &key(n), &[n; 40])
                .unwrap(),
        );
        let mut budget = super::super::super::budget::WorkBudget::new(1 << 20);
        storage
            .service_fills(crate::index::ShardIndex(0), 8, &mut budget)
            .unwrap();
    }
    storage.start_capture(1024, true, 1024).unwrap();
    let entries = drain(&storage);
    assert_eq!(entries.len(), usize::from(count));
    let session = dev.volume.authority.session().get();
    let layout = layout(2);
    let mut possible = PossiblyNamed::new((shard(), session), layout, None);
    let checkpoint = Checkpoint {
        shard: shard(),
        session,
        capture: 9,
    };
    let mut stage = StagedCheckpoint::new(
        Crc32c::detect(),
        &mut possible,
        (checkpoint, &entries),
        &EngineBudget::unlimited(),
    )
    .unwrap();
    assert!(stage.units().len() <= 2, "the entries fit the slot");
    for unit in 0..stage.units().len() as u32 {
        dev.volume
            .stage_unit_write(&possible, &mut stage, unit)
            .unwrap();
        let mut out = Vec::with_capacity(16);
        let done = (0..1000)
            .find_map(|_| {
                super::super::super::volume_fixture::step(&mut dev.volume, &dev.control, &mut out);
                dev.volume.take_unit()
            })
            .expect("the unit write ends");
        assert_eq!(
            done,
            super::super::checkpoint::UnitDone::Written {
                slot: stage.slot(),
                unit
            }
        );
    }
    let named = stage.named();
    let before = units(&storage);
    (store, entries, named, layout, session, before)
}

/// The shard record naming `named` at `cut` with `ancestry`, under the test shard at the fixture generation.
fn manifest(named: NamedCheckpoint, cut: u64, ancestry: &[Suffix], generation: u64) -> ShardRecord {
    ShardRecord {
        generation: crate::net::ownership::ShardGeneration::new(generation).unwrap(),
        checkpoint: Some(named),
        cut,
        ancestry: Ancestry::new(ancestry).unwrap(),
        ..record()
    }
}

/// Relaunches `store` on a fresh narrow storage whose attach carries the warm source `source` builds from the
/// record it is given and the attach's session, over an arena of `maintenance` maintenance buffers, and runs
/// `body`. The helpers park, so each job spans a tick.
fn relaunch_sourced<R>(
    store: &Media,
    maintenance: u32,
    source: impl FnOnce(&crate::storage::Session) -> Option<WarmSource>,
    body: impl for<'s> FnOnce(&'s Storage<TestPlatform>, &mut TestVolume<'s, '_>, &SimControl) -> R,
) -> R {
    relaunch_sourced_on(sourced(), store, maintenance, source, body)
}

/// [`relaunch_sourced`] on `storage`.
fn relaunch_sourced_on<R>(
    storage: Storage<TestPlatform>,
    store: &Media,
    maintenance: u32,
    source: impl FnOnce(&crate::storage::Session) -> Option<WarmSource>,
    body: impl for<'s> FnOnce(&'s Storage<TestPlatform>, &mut TestVolume<'s, '_>, &SimControl) -> R,
) -> R {
    let buffers = if maintenance == 1 {
        arena_with(4, 9)
    } else {
        arena_maintaining(maintenance, 4096)
    };
    let mut authority = crate::storage::ServingAuthority::fixture();
    authority.warm = source(&authority.session).map(Box::new);
    let (mut volume, control) =
        super::super::super::volume_fixture::attach_under(&storage, &buffers, store, authority)
            .expect("attach");
    PARK.with(|park| park.set(true));
    let result = body(&storage, &mut volume, &control);
    PARK.with(|park| park.set(false));
    result
}

/// The device byte ranges of every read the device accepted, inside the metadata prefix or past it, so a read past
/// the named slot shows in the trace.
fn prefix_reads(control: &SimControl) -> Vec<(u64, u32)> {
    use super::super::super::device::sim::Captured;
    control
        .capture()
        .events
        .iter()
        .filter_map(|event| match event {
            Captured::Submitted {
                operation: Operation::Read,
                device,
                ..
            } => Some((device.start(), device.byte_len())),
            _ => None,
        })
        .collect()
}

/// Ticks `volume` through its warm read and install, at most 128 ticks.
fn load(volume: &mut TestVolume<'_, '_>, control: &SimControl) {
    for _ in 0..128 {
        if !volume.readiness().initializing() {
            return;
        }
        super::tests::tick(volume, control);
    }
}

/// A successor whose record names the checkpoint reads the slot's units through the metadata cells, each read inside
/// the layout's units and one unit long under the test's one-unit maintenance buffers, writes nothing to the device,
/// and serves every captured entry at `Live` with the writer's free units; the recovery report counts the installed
/// entries and no loss, an opened adoption phase that adopted at least one helper terminal, helper peaks above zero
/// and within the attach's recovery limits, and held units equal to the payload units the restored extents take.
#[test]
fn a_warm_source_reads_the_named_slot_through_the_metadata_cells_and_writes_nothing() {
    let (store, entries, named, layout, _, writer) = checkpointed(3);
    let before = store.borrow().clone();
    relaunch_sourced(
        &store,
        1,
        |session| {
            WarmSource::new(
                &manifest(named, 0, &[], session.generation().get()),
                layout,
                session,
                &fenced(&[]),
            )
        },
        |storage, volume, control| {
            load(volume, control);
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
            assert_eq!(volume.readiness(), State::Loaded);
            assert_eq!(writes(control), 0, "the warm path writes no device unit");
            let reads = prefix_reads(control);
            let slot = (1 + u64::from(named.slot) * u64::from(layout.slot_units)) * IO_UNIT as u64;
            assert_eq!(
                reads,
                (0..u64::from(named.units))
                    .map(|unit| (slot + unit * IO_UNIT as u64, IO_UNIT as u32))
                    .collect::<Vec<_>>(),
                "one read per named unit, each inside the slot, none of unit 0"
            );
            assert_eq!(units(storage), writer);
            assert_eq!(resident(storage), entries.len());
            let report = volume.recovery_report().warm;
            assert_eq!(
                (
                    report.installed,
                    report.omitted,
                    report.failed_units,
                    report.unread_units
                ),
                (3, 0, 0, 0)
            );
            let recovery = volume.recovery_report();
            let limits = storage.recovery;
            assert!(
                (1..=limits.jobs).contains(&recovery.peak_jobs),
                "{recovery:?}"
            );
            assert!(
                (IO_UNIT as u64..=limits.input_bytes as u64).contains(&recovery.peak_input_bytes),
                "{recovery:?}"
            );
            assert!(
                (1..=limits.output_bytes as u64).contains(&recovery.peak_output_bytes),
                "{recovery:?}"
            );
            let adoption = recovery.phase(super::super::RecoveryPhase::Adoption);
            assert!(
                adoption.start.is_some() && adoption.operations >= 1,
                "{adoption:?}"
            );
            let payload = storage.pool().descriptor().geometry.payload_units();
            assert_eq!(recovery.held_units, payload - units(storage).0);
            assert_eq!(volume.certified(), None, "no predecessor suffix");
            live(storage, volume);
            for n in 1..=3 {
                assert_eq!(
                    served(storage, volume, control, n),
                    [&key(n)[..4], &[n; 40][..]].concat()
                );
            }
            assert_eq!(
                store.borrow()[..16 * IO_UNIT],
                before[..16 * IO_UNIT],
                "the prefix is unchanged"
            );
        },
    );
}

/// A read window is the largest power of two of whole units the maintenance buffer and the device transfer admit, at
/// most [`READ_LEN`]; with two 4096-byte maintenance buffers two reads are outstanding at once and the load is the
/// same.
#[test]
fn a_short_maintenance_buffer_shortens_the_reads_and_the_load_is_unchanged() {
    assert_eq!(read_len(4096, 1 << 20), IO_UNIT as u64);
    assert_eq!(read_len(16384, 1 << 20), 16384);
    assert_eq!(read_len(12288, 1 << 20), 8192);
    assert_eq!(read_len(1 << 20, 1 << 20), READ_LEN);
    assert_eq!(read_len(1 << 20, 6144), 4096);
    assert_eq!(read_len(512, 512), IO_UNIT as u64, "the floor is one unit");
    let (store, entries, named, layout, _, writer) = checkpointed(3);
    relaunch_sourced(
        &store,
        2,
        |session| {
            WarmSource::new(
                &manifest(named, 0, &[], session.generation().get()),
                layout,
                session,
                &fenced(&[]),
            )
        },
        |storage, volume, control| {
            load(volume, control);
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
            assert_eq!(prefix_reads(control).len(), named.units as usize);
            assert_eq!(units(storage), writer);
            assert_eq!(resident(storage), entries.len());
        },
    );
}

/// A device that fails a slot read, or a stop during the read, leaves the unit unread: the load installs nothing,
/// the attempt ends `Unloadable(Unreadable)` with the media and the pool unchanged and no device write, and a later
/// attach over the same media loads warm.
#[test]
fn a_failed_slot_read_counts_as_unread_and_installs_nothing() {
    use super::super::super::device::DeviceStatus;
    use super::super::super::device::sim::Fault;
    let (store, entries, named, layout, _, writer) = checkpointed(3);
    let before = store.borrow().clone();
    relaunch_sourced(
        &store,
        1,
        |session| {
            WarmSource::new(
                &manifest(named, 0, &[], session.generation().get()),
                layout,
                session,
                &fenced(&[]),
            )
        },
        |storage, volume, control| {
            let mut out = Vec::with_capacity(16);
            let mut faulted = false;
            for _ in 0..128 {
                if !volume.readiness().initializing() {
                    break;
                }
                if !faulted && let Some(&(token, _)) = submitted(control, Operation::Read).first() {
                    control.fault(token, Fault::Status(DeviceStatus::Kernel(-5)));
                    faulted = true;
                }
                control.tick(64);
                let _ = volume.poll_storage(0, &mut out);
                if let Some((ran, released)) = volume
                    .metadata
                    .helpers
                    .as_mut()
                    .and_then(|helpers| helpers.parked())
                {
                    released.extend(ran.drain(..));
                }
            }
            assert!(faulted, "a read was faulted");
            assert_eq!(
                volume.metadata_outcome(),
                MetadataOutcome::Unloadable(LoadRefusal::Unreadable)
            );
            assert_eq!(volume.readiness(), State::Withheld);
            assert_eq!(writes(control), 0);
            assert_eq!(resident(storage), 0, "nothing installed");
            assert_eq!(
                volume.recovery_report().warm.unread_units,
                1,
                "the loss record names the unread unit"
            );
            assert_eq!(store.borrow()[..], before[..], "the media are unchanged");
        },
    );
    relaunch_sourced(
        &store,
        1,
        |session| {
            WarmSource::new(
                &manifest(named, 0, &[], session.generation().get()),
                layout,
                session,
                &fenced(&[]),
            )
        },
        |storage, volume, control| {
            load(volume, control);
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
            assert_eq!(units(storage), writer);
            assert_eq!(resident(storage), entries.len());
        },
    );
}

/// A device status fault on the read at each position of a warm attach over a three-object checkpoint and one planted
/// suffix block leaves that unit or block unread: the attempt ends `Unloadable(Unreadable)` with no device write, no
/// resident entry and the media unchanged, and a clean attach after it loads warm. The faulted attach retries no read,
/// issues every other read of the clean attach, and reports the one unit or block unread. The attach with no fault
/// submits the suffix block's read, then one read per slot unit, so the sweep faults each of those reads once.
#[test]
fn a_failed_read_at_each_position_of_a_warm_attach_installs_nothing() {
    use super::super::super::device::DeviceStatus;
    use super::super::super::device::sim::Fault;
    let (store, entries, named, layout, session, _) = checkpointed(3);
    let removed = entries
        .iter()
        .find(|entry| entry.key == key(2))
        .expect("key 2 was captured");
    let block = super::super::super::recovery::delta::Block {
        shard: shard(),
        session,
        lsn: 0,
    };
    let records = [Record::Remove {
        identity: super::super::super::recovery::delta::identity_of(removed),
        cause: Cause::Invalidate,
    }];
    plant_suffix(&store, &layout, 0, &packed_as(block, &records));
    let suffix = Suffix {
        session,
        start: 0,
        certified: 1,
        end: 1,
    };
    let source = |session: &crate::storage::Session| {
        WarmSource::new(
            &manifest(named, 0, &[suffix], session.generation().get()),
            layout,
            session,
            &fenced(&[]),
        )
    };
    let before = store.borrow().clone();
    let clean = || {
        relaunch_sourced(&store, 1, source, |storage, volume, control| {
            load(volume, control);
            let reads = read_starts(control);
            assert_eq!(writes(control), 0, "the clean attach writes nothing");
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
            assert_eq!(
                resident(storage),
                entries.len() - 1,
                "the suffix removes key 2"
            );
            live(storage, volume);
            let mut reader = storage.register().unwrap();
            assert!(
                matches!(lookup(&mut reader, &key(2), 4), Err(LookupError::Missing)),
                "the suffix removes key 2"
            );
            for n in [1, 3] {
                assert_eq!(
                    served(storage, volume, control, n),
                    [&key(n)[..4], &[n; 40][..]].concat()
                );
            }
            reads
        })
    };
    let reads = clean();
    assert_eq!(reads.len(), 3, "the suffix block, then each slot unit");
    let region =
        (layout.units - super::super::super::recovery::delta::blocks(&layout)) * IO_UNIT as u64;
    let slot = (1 + u64::from(named.slot) * u64::from(layout.slot_units)) * IO_UNIT as u64;
    assert_eq!(
        reads[0], region,
        "the suffix block is read first: {reads:?}"
    );
    assert_eq!(
        reads[1..],
        (0..u64::from(named.units))
            .map(|unit| slot + unit * IO_UNIT as u64)
            .collect::<Vec<_>>(),
        "then one read per named unit of the slot"
    );
    let mut faulted = Vec::new();
    for n in 1..=reads.len() {
        relaunch_sourced(&store, 1, source, |storage, volume, control| {
            let mut fault = None;
            for _ in 0..128 {
                if !volume.readiness().initializing() {
                    break;
                }
                if fault.is_none()
                    && let Some(&(token, start)) = submitted(control, Operation::Read).get(n - 1)
                {
                    control.fault(token, Fault::Status(DeviceStatus::Kernel(-5)));
                    fault = Some(start);
                }
                super::tests::tick(volume, control);
            }
            let fault = fault.expect("the read is submitted and faulted");
            faulted.push(fault);
            assert_eq!(
                read_starts(control),
                reads,
                "read {n}: the failed read is not retried and every later read is issued"
            );
            let report = volume.recovery_report().warm;
            let expected = if fault >= region {
                (0, 1, None)
            } else {
                let unit = ((fault - slot) / IO_UNIT as u64) as u32;
                (1, 0, Some(UnitDamage::Unread { unit }))
            };
            assert_eq!(
                (
                    report.unread_units,
                    report.suffix_unread,
                    report.first_damage
                ),
                expected,
                "read {n}: the faulted unit or block alone is unread"
            );
            assert_eq!(
                volume.metadata_outcome(),
                MetadataOutcome::Unloadable(LoadRefusal::Unreadable),
                "read {n}"
            );
            assert_eq!(volume.readiness(), State::Withheld, "read {n}");
            assert_eq!(writes(control), 0, "read {n}");
            assert_eq!(resident(storage), 0, "read {n}: nothing installed");
        });
        assert!(
            *store.borrow() == before,
            "read {n}: the media are unchanged"
        );
        assert_eq!(clean(), reads, "after read {n}, a clean attach loads warm");
        assert!(
            *store.borrow() == before,
            "after read {n}: the clean attach leaves the media unchanged"
        );
    }
    assert_eq!(
        faulted, reads,
        "the sweep faults every read of the clean attach once"
    );
}

/// A device that refuses a slot read's submit for good leaves the unit unread: the refusal returns the read's charge
/// and clears its cell, the attempt ends `Unloadable(Unreadable)` with no device write, no restored entry, the media
/// unchanged and the pool holding no job or charge once its terminals landed, and a later attach over the same media
/// loads warm.
#[test]
fn a_slot_read_refused_for_good_at_submit_counts_as_unread_and_installs_nothing() {
    use super::super::super::device::{RefusalReason, SubmitRefusal};
    let (store, entries, named, layout, _, writer) = checkpointed(3);
    let before = store.borrow().clone();
    let source = |session: &crate::storage::Session| {
        WarmSource::new(
            &manifest(named, 0, &[], session.generation().get()),
            layout,
            session,
            &fenced(&[]),
        )
    };
    relaunch_sourced(&store, 1, source, |storage, volume, control| {
        control.refuse_next(SubmitRefusal {
            reason: RefusalReason::InvalidRange,
            code: None,
        });
        let _ = volume.poll_storage(0, &mut Vec::with_capacity(16));
        assert!(volume.metadata.reading.is_some(), "the warm read began");
        assert_eq!(
            volume.report.metadata_refused, 1,
            "the slot read's submit was refused"
        );
        assert!(
            prefix_reads(control).is_empty(),
            "the refused read never reached the device"
        );
        load(volume, control);
        assert_eq!(
            volume.metadata_outcome(),
            MetadataOutcome::Unloadable(LoadRefusal::Unreadable)
        );
        assert_eq!(volume.readiness(), State::Withheld);
        assert_eq!(volume.recovery_report().warm.unread_units, 1);
        assert_eq!(writes(control), 0);
        assert_eq!(resident(storage), 0, "nothing installed");
        assert!(
            volume.metadata.commands.iter().all(Option::is_none),
            "no cell holds the refused read"
        );
        let held = (volume.metadata.helpers.as_ref()).map(super::super::helpers::Helpers::held);
        assert!(
            held.is_none_or(|(jobs, charge)| jobs == 0 && charge == Default::default()),
            "the pool holds no job or charge: {held:?}"
        );
    });
    assert_eq!(store.borrow()[..], before[..], "the media are unchanged");
    relaunch_sourced(&store, 1, source, |storage, volume, control| {
        load(volume, control);
        assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
        assert_eq!(units(storage), writer);
        assert_eq!(resident(storage), entries.len());
    });
}

/// A helper that panics on a slot job fails the decode: the attempt ends `MetadataFailed` with the readiness
/// `Withheld`, installs nothing, writes nothing, and the media and the record stay for a later attach, which loads
/// warm.
#[test]
fn a_panicking_slot_job_fails_the_warm_load_closed_and_keeps_the_media() {
    let (store, entries, named, layout, _, writer) = checkpointed(3);
    let before = store.borrow().clone();
    super::super::helpers::PANIC.with(|panic| panic.set(true));
    relaunch_sourced(
        &store,
        1,
        |session| {
            WarmSource::new(
                &manifest(named, 0, &[], session.generation().get()),
                layout,
                session,
                &fenced(&[]),
            )
        },
        |storage, volume, control| {
            load(volume, control);
            super::super::helpers::PANIC.with(|panic| panic.set(false));
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::MetadataFailed);
            assert_eq!(volume.readiness(), State::Withheld);
            assert_eq!(writes(control), 0);
            assert_eq!(resident(storage), 0);
            assert_eq!(store.borrow()[..], before[..]);
        },
    );
    super::super::helpers::PANIC.with(|panic| panic.set(false));
    relaunch_sourced(
        &store,
        1,
        |session| {
            WarmSource::new(
                &manifest(named, 0, &[], session.generation().get()),
                layout,
                session,
                &fenced(&[]),
            )
        },
        |storage, volume, control| {
            load(volume, control);
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
            assert_eq!(units(storage), writer);
            assert_eq!(resident(storage), entries.len());
        },
    );
}

/// A warm attach through the production attach whose helper CPU set the kernel refuses fails the read pool's start:
/// the attempt ends `MetadataFailed` with no pool, no slot read, no restored entry and the media unchanged.
#[test]
#[cfg(not(loom))]
fn a_refused_helper_placement_ends_a_sourced_warm_attach_before_any_slot_read() {
    let (store, _, named, layout, _, _) = checkpointed(3);
    let before = store.borrow().clone();
    let allowed = super::super::CpuSet::current().unwrap();
    let outside = (0..super::super::MAX_CPUS)
        .rev()
        .find(|&cpu| !allowed.contains(cpu))
        .expect("some CPU index lies outside the allowed set");
    let storage = storage_with(|volume| {
        volume.recovery.jobs = (super::super::super::checkpoint::WINDOWS + 1) as u32;
        volume.recovery.adopt = volume.recovery.jobs;
        volume.recovery.cpus = super::super::CpuSet::from_cpus(&[outside]).unwrap();
    });
    let source = |session: &crate::storage::Session| {
        WarmSource::new(
            &manifest(named, 0, &[], session.generation().get()),
            layout,
            session,
            &fenced(&[]),
        )
    };
    relaunch_sourced_on(storage, &store, 1, source, |storage, volume, control| {
        load(volume, control);
        assert_eq!(volume.metadata_outcome(), MetadataOutcome::MetadataFailed);
        assert!(volume.metadata.helpers.is_none(), "no pool started");
        assert_eq!(prefix_reads(control), [], "no slot read reached the device");
        assert_eq!(writes(control), 0);
        assert_eq!(resident(storage), 0);
    });
    assert!(*store.borrow() == before, "the media is unchanged");
}

/// A withdrawal while a sourced warm attach's slot read is at the device cancels the read pool, so its threads end
/// while the withdrawn volume lives on, nothing installs and the media keep the predecessor's bytes.
#[test]
#[cfg(not(loom))]
fn a_withdrawal_with_a_slot_read_in_flight_ends_the_read_helpers() {
    let (store, _, named, layout, _, _) = checkpointed(3);
    let before = store.borrow().clone();
    let source = |session: &crate::storage::Session| {
        WarmSource::new(
            &manifest(named, 0, &[], session.generation().get()),
            layout,
            session,
            &fenced(&[]),
        )
    };
    relaunch_sourced_on(sourced(), &store, 1, source, |storage, volume, control| {
        let ended = |volume: &TestVolume<'_, '_>| {
            (volume.metadata.helpers.as_ref()).is_some_and(super::super::helpers::Helpers::ended)
        };
        let _ = volume.poll_storage(0, &mut Vec::with_capacity(16));
        assert_eq!(
            prefix_reads(control).len(),
            1,
            "the first slot read is at the device"
        );
        assert!(volume.metadata.reading.is_some(), "the read is in flight");
        assert!(
            volume.metadata.helpers.is_some(),
            "the attach started its read pool"
        );
        assert!(!ended(volume), "the read helpers run until the withdrawal");
        assert_eq!(storage.withdraw(), State::Withheld);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline && !ended(volume) {
            super::tests::tick(volume, control);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(ended(volume), "the withdrawn attempt's read helpers ended");
        assert_eq!(
            resident(storage),
            0,
            "the withdrawn attempt installed nothing"
        );
        assert_eq!(writes(control), 0);
    });
    assert!(*store.borrow() == before, "the media is unchanged");
}

/// Writes `units` as the suffix blocks from LSN `first` of `layout`'s delta region into `store`.
fn plant_suffix(store: &Media, layout: &Layout, first: u64, units: &[Box<[u8; UNIT_LEN]>]) {
    let region = super::super::super::recovery::delta::blocks(layout);
    let base = layout.units - region;
    for (at, unit) in units.iter().enumerate() {
        let prefix = (base + (first + at as u64) % region) as usize * IO_UNIT;
        store.borrow_mut()[prefix..prefix + IO_UNIT].copy_from_slice(&unit[..]);
    }
}

/// The predecessor's suffix removes one checkpoint entry: the suffix blocks are read first, the removed entry misses
/// at `Live` with its units free, the others serve, and a tail hole certifies the suffix to the hole; a suffix already
/// certified to that end raises nothing, and a damaged suffix block below the certified end refuses `StaleWrite` with
/// nothing installed.
#[test]
fn a_suffix_remove_reaches_the_warm_load_and_the_predecessor_suffix_is_certified_to_its_hole() {
    let (store, entries, named, layout, session, writer) = checkpointed(3);
    let removed = entries
        .iter()
        .find(|entry| entry.key == key(2))
        .expect("key 2 was captured");
    let block = super::super::super::recovery::delta::Block {
        shard: shard(),
        session,
        lsn: 0,
    };
    let records = [Record::Remove {
        identity: super::super::super::recovery::delta::identity_of(removed),
        cause: Cause::Invalidate,
    }];
    let blocks = packed_as(block, &records);
    assert_eq!(blocks.len(), 1);
    plant_suffix(&store, &layout, 0, &blocks);
    let removed_units = u64::from(super::ExtentLocator::from_bits(removed.extents[0]).len_units());
    let suffix = Suffix {
        session,
        start: 0,
        certified: 0,
        end: 3,
    };
    let source = |named, ancestry: Vec<Suffix>| {
        move |session: &crate::storage::Session| {
            WarmSource::new(
                &manifest(named, 0, &ancestry, session.generation().get()),
                layout,
                session,
                &fenced(&[]),
            )
        }
    };
    relaunch_sourced(
        &store,
        1,
        source(named, vec![suffix]),
        |storage, volume, control| {
            load(volume, control);
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
            let reads = prefix_reads(control);
            let region_start = (layout.units
                - super::super::super::recovery::delta::blocks(&layout))
                * IO_UNIT as u64;
            assert!(
                reads[..3].iter().all(|(start, _)| *start >= region_start),
                "the suffix blocks are read first: {reads:?}"
            );
            assert_eq!(reads.len(), 3 + named.units as usize);
            assert_eq!(resident(storage), 2);
            assert_eq!(
                units(storage).0,
                writer.0 + removed_units,
                "the removed entry's units are free"
            );
            assert_eq!(
                volume.certified(),
                Some(vec![(session, 1)]),
                "blocks 1 and 2 are the unflushed tail, so the suffix certifies to the first hole"
            );
            assert_eq!(volume.certified(), None, "taken once");
            let report = volume.recovery_report().warm;
            assert_eq!(
                (report.suffix_tails, report.suffix_damage, report.installed),
                (1, 0, 2)
            );
            live(storage, volume);
            let mut reader = storage.register().unwrap();
            assert!(matches!(
                lookup(&mut reader, &key(2), 4),
                Err(LookupError::Missing)
            ));
            for n in [1, 3] {
                assert_eq!(
                    served(storage, volume, control, n),
                    [&key(n)[..4], &[n; 40][..]].concat()
                );
            }
        },
    );
    let whole = Suffix {
        certified: 1,
        end: 1,
        ..suffix
    };
    relaunch_sourced(
        &store,
        1,
        source(named, vec![whole]),
        |storage, volume, control| {
            load(volume, control);
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
            assert_eq!(resident(storage), 2);
            assert_eq!(
                volume.certified(),
                None,
                "a suffix already certified to its end raises nothing"
            );
        },
    );
    let damaged = Suffix {
        certified: 1,
        ..suffix
    };
    let mut torn = blocks[0].clone();
    torn[UNIT_LEN / 2] ^= 0xFF;
    plant_suffix(&store, &layout, 0, &[torn]);
    let before = store.borrow().clone();
    relaunch_sourced(
        &store,
        1,
        source(named, vec![damaged]),
        |storage, volume, control| {
            load(volume, control);
            assert_eq!(
                volume.metadata_outcome(),
                MetadataOutcome::Unloadable(LoadRefusal::StaleWrite),
                "a hole below the certified end is damage"
            );
            assert_eq!(resident(storage), 0);
            assert_eq!(writes(control), 0);
            assert_eq!(volume.recovery_report().warm.suffix_damage, 1);
            assert_eq!(store.borrow()[..], before[..]);
        },
    );
}

/// A record naming no checkpoint yields no source. A source whose layout spans more or fewer units than the metadata
/// prefix refuses `NamedSlot`, since its payload locators count from the end of the layout's units; recovery limits below one read window's charge, below one destination guard's bytes, or with fewer
/// jobs than the reader's windows and destinations refuse `RecoveryLimits`, each before any command; limits exactly at
/// each bound attach.
#[test]
fn attach_refuses_a_warm_source_the_prefix_or_the_recovery_limits_cannot_hold() {
    use super::super::super::checkpoint::WINDOWS;
    use super::super::AttachError;
    let (_, _, named, layout, _, _) = checkpointed(1);
    let session = crate::storage::ServingAuthority::fixture().session;
    assert!(
        WarmSource::new(&record(), layout, &session, &fenced(&[])).is_none(),
        "no checkpoint, no source"
    );
    let manifest = manifest(named, 0, &[], session.generation().get());
    let source = |layout| WarmSource::new(&manifest, layout, &session, &fenced(&[])).unwrap();
    let attach = |storage: &Storage<TestPlatform>, layout: Layout| {
        let buffers = arena_with(4, 9);
        let capacity = (storage.pool().descriptor().geometry.volume_units() * IO_UNIT as u64)
            .max(super::super::super::volume_fixture::MEDIA);
        let config = super::super::super::device::sim::SimConfig {
            capacity,
            ..config_for(7)
        };
        let (disk, _) = sim_attached(
            config,
            media(capacity),
            super::super::super::volume_fixture::facts_for(capacity, BUFFER),
        );
        let mut authority = crate::storage::ServingAuthority::fixture();
        authority.warm = Some(Box::new(source(layout)));
        Volume::attach(
            storage,
            &buffers,
            disk,
            ScriptedClock::trusted(),
            authority,
            DEPTH,
            TICK,
            &mut EngineBudget::new(1 << 30),
        )
        .map(|_| ())
        .map_err(|(error, _)| error)
    };
    let wide = Layout {
        units: 64,
        ..layout
    };
    assert_eq!(
        attach(&sourced(), wide),
        Err(AttachError::NamedSlot {
            units: 64,
            metadata_units: 16
        })
    );
    let short = Layout { units: 8, ..layout };
    assert_eq!(
        attach(&sourced(), short),
        Err(AttachError::NamedSlot {
            units: 8,
            metadata_units: 16
        }),
        "a layout shorter than the prefix refuses too"
    );
    let refused = |result| matches!(result, Err(AttachError::RecoveryLimits { .. }));
    let jobs = (WINDOWS + 1) as u32;
    let with = |edit: &dyn Fn(&mut super::super::helpers::RecoveryLimits)| {
        storage_with(|volume| {
            (volume.recovery.jobs, volume.recovery.adopt) = (jobs, jobs);
            edit(&mut volume.recovery);
        })
    };
    let window = super::super::helpers::Charge::decode(IO_UNIT);
    let at_bounds =
        with(&|limits| (limits.input_bytes, limits.output_bytes) = (window.input, window.output));
    assert_eq!(
        attach(&at_bounds, layout),
        Ok(()),
        "limits at one window and the jobs bound attach"
    );
    // Over 8192-byte maintenance buffers the read window spans two metadata blocks, so limits one byte short of the
    // window pass the one-block floor every attach checks and only the warm window check refuses them, with the
    // window's length as `unit`.
    let attach_wide = |storage: &Storage<TestPlatform>| {
        let buffers = arena_maintaining(2, 8192);
        let mut authority = crate::storage::ServingAuthority::fixture();
        authority.warm = Some(Box::new(source(layout)));
        let store = media(super::super::super::volume_fixture::MEDIA);
        super::super::super::volume_fixture::attach_under(storage, &buffers, &store, authority)
            .map(|_| ())
    };
    let wide = super::super::helpers::Charge::decode(8192);
    for (input, output) in [(wide.input - 1, wide.output), (wide.input, wide.output - 1)] {
        let short = with(&|limits| (limits.input_bytes, limits.output_bytes) = (input, output));
        assert_eq!(
            attach_wide(&short),
            Err(AttachError::RecoveryLimits { unit: 8192 }),
            "a window's input {input} or output {output} below its charge refuses at the warm check"
        );
    }
    let exact =
        with(&|limits| (limits.input_bytes, limits.output_bytes) = (wide.input, wide.output));
    assert_eq!(
        attach_wide(&exact),
        Ok(()),
        "limits at the wide window's charge attach"
    );
    let few_jobs = with(&|limits| (limits.jobs, limits.adopt) = (jobs - 1, jobs - 1));
    assert!(
        refused(attach(&few_jobs, layout)),
        "fewer jobs than the windows and the destination refuses"
    );
    // Slots enough that one destination's guard bitmaps outgrow a window, so the guard sets the input bound.
    let slots = 40 * 1024;
    let large = |input: usize| {
        let config = super::super::super::config::StorageConfig {
            lease_limit: 16,
            volume: super::super::super::volume::VolumeConfig {
                recovery: super::super::helpers::RecoveryLimits {
                    jobs,
                    adopt: jobs,
                    input_bytes: input,
                    output_bytes: window.output,
                    ..super::super::test_recovery()
                },
                ..super::super::test_volume_with(IO_UNIT * 64, 10_400, slots)
            },
            ..super::super::super::publish_tests::storage_config(slots)
        };
        let limits = [slots];
        let index = super::super::super::publish_tests::index_config(&limits, (1, 1), 1);
        let index = crate::index::IndexConfig {
            fills: &[2],
            ..index
        };
        let storage = super::super::super::publish_tests::storage_from(
            &config,
            &index,
            TestPlatform::heap(super::super::super::publish_tests::PAGE),
        );
        storage.platform.ticks(&[Some(1)]);
        storage
    };
    // The large storage's prefix is 10,400 units, so its source's layout spans them.
    let spanning = Layout {
        units: 10_400,
        ..layout
    };
    let probe = large(usize::MAX / 2);
    let guard = super::Planned::of(&probe, (IO_UNIT as u32, BUFFER), &source(spanning))
        .unwrap()
        .charges()
        .1;
    assert!(
        guard > window.input,
        "the guard {guard} outgrows the window"
    );
    let short = attach(&large(guard - 1), spanning);
    assert!(
        refused(short),
        "input bytes one short of the guard refuse: {short:?}"
    );
    assert_eq!(
        attach(&large(guard), spanning),
        Ok(()),
        "input bytes at the guard attach"
    );
}

/// The conversion's expiry contract is the shard's configured clock contract: the captured pairs the writer encoded
/// under it convert to live deadlines and every entry installs, and an attach whose clock names another scale refuses
/// `ClockScale` before any command, so no checkpoint of a shard is read under another scale.
#[test]
fn a_warm_load_converts_expiry_under_the_shards_configured_contract() {
    use super::super::super::portable::ClockScale;
    let (store, entries, named, layout, _, _) = checkpointed(2);
    relaunch_sourced(
        &store,
        1,
        |session| {
            WarmSource::new(
                &manifest(named, 0, &[], session.generation().get()),
                layout,
                session,
                &fenced(&[]),
            )
        },
        |storage, volume, control| {
            load(volume, control);
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
            assert_eq!(resident(storage), entries.len());
            assert_eq!(
                volume.recovery_report().warm.omitted,
                0,
                "every pair converts"
            );
            live(storage, volume);
            let mut reader = storage.register().unwrap();
            let lease = lookup(&mut reader, &key(1), 4).expect("served");
            assert_eq!(
                read_back(volume, control, &lease).status,
                ReadStatus::Complete
            );
        },
    );
    let storage = storage_with(|volume| {
        volume.clock.scale = ClockScale::UtcStepped;
        let jobs = (super::super::super::checkpoint::WINDOWS + 1) as u32;
        (volume.recovery.jobs, volume.recovery.adopt) = (jobs, jobs);
    });
    let buffers = arena_with(4, 9);
    let mut authority = crate::storage::ServingAuthority::fixture();
    let session = &authority.session;
    let source = WarmSource::new(
        &manifest(named, 0, &[], session.generation().get()),
        layout,
        session,
        &fenced(&[]),
    )
    .unwrap();
    authority.warm = Some(Box::new(source));
    let refused =
        super::super::super::volume_fixture::attach_under(&storage, &buffers, &store, authority)
            .map(|_| ());
    assert!(
        matches!(refused, Err(super::super::AttachError::ClockScale { .. })),
        "{refused:?}"
    );
}

/// Each staged slot read holds one window's charge and each destination job the decode's guard bytes on the helpers,
/// so the live charge observed across the read's ticks reaches a window and, beside it, exactly the guard; a source
/// whose named checkpoint spans more units than the layout's slot refuses at the stage `Unloadable(Limits)` with the
/// readiness withheld, no device command and the media unchanged.
#[test]
fn every_slot_read_holds_a_window_charge_and_every_destination_job_a_guard_charge() {
    let (store, _, named, layout, _, _) = checkpointed(3);
    let source = WarmSource::new(
        &manifest(named, 0, &[], 1),
        layout,
        &crate::storage::ServingAuthority::fixture().session,
        &fenced(&[]),
    )
    .unwrap();
    let guard = super::Planned::of(&sourced(), (IO_UNIT as u32, BUFFER), &source)
        .unwrap()
        .charges()
        .1;
    assert!(guard > 0 && guard < IO_UNIT);
    relaunch_sourced(
        &store,
        1,
        |session| {
            WarmSource::new(
                &manifest(named, 0, &[], session.generation().get()),
                layout,
                session,
                &fenced(&[]),
            )
        },
        |_, volume, control| {
            let mut out = Vec::with_capacity(16);
            let mut seen = Vec::new();
            for _ in 0..128 {
                if !volume.readiness().initializing() {
                    break;
                }
                control.tick(64);
                let _ = volume.poll_storage(0, &mut out);
                if let Some(helpers) = volume.metadata.helpers.as_mut() {
                    seen.push(helpers.held().1.input);
                    if let Some((ran, released)) = helpers.parked() {
                        released.extend(ran.drain(..));
                    }
                }
            }
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
            assert!(
                seen.iter().any(|&input| input >= IO_UNIT),
                "a staged read holds a window: {seen:?}"
            );
            assert!(
                seen.iter()
                    .all(|&input| [0, guard].contains(&(input % IO_UNIT))),
                "every live charge is whole windows and at most one destination guard: {seen:?}"
            );
            assert!(
                seen.iter().any(|&input| input % IO_UNIT == guard),
                "a destination job holds the guard bytes {guard}: {seen:?}"
            );
        },
    );
    let before = store.borrow().clone();
    let oversized = NamedCheckpoint {
        units: layout.slot_units + 1,
        ..named
    };
    relaunch_sourced(
        &store,
        1,
        |session| {
            WarmSource::new(
                &manifest(oversized, 0, &[], session.generation().get()),
                layout,
                session,
                &fenced(&[]),
            )
        },
        |storage, volume, control| {
            load(volume, control);
            assert_eq!(
                volume.metadata_outcome(),
                MetadataOutcome::Unloadable(LoadRefusal::Limits)
            );
            assert_eq!(volume.readiness(), State::Withheld);
            assert_eq!(prefix_reads(control).len(), 0);
            assert!(
                !volume.warm_decided(),
                "a refusal before the stage records no account"
            );
            assert_eq!(writes(control), 0);
            assert_eq!(resident(storage), 0);
            assert_eq!(store.borrow()[..], before[..]);
        },
    );
}

#[test]
fn a_covered_key_in_the_sources_coverage_is_omitted_and_an_invalidation_after_the_commit_removes_a_restored_key()
 {
    let (store, entries, named, layout, _, writer) = checkpointed(3);
    let units_of = |n: u8| {
        let entry = entries.iter().find(|entry| entry.key == key(n)).unwrap();
        u64::from(super::ExtentLocator::from_bits(entry.extents[0]).len_units())
    };
    relaunch_sourced(
        &store,
        1,
        |session| {
            WarmSource::new(
                &manifest(named, 0, &[], session.generation().get()),
                layout,
                session,
                &fenced(&[key(2)]),
            )
        },
        |storage, volume, control| {
            load(volume, control);
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
            assert_eq!(volume.recovery_report().warm.omitted, 1);
            assert_eq!(resident(storage), 2);
            assert_eq!(
                units(storage).0,
                writer.0 + units_of(2),
                "the covered entry's units are free"
            );
            let mut budget = super::super::super::budget::WorkBudget::new(1 << 20);
            // The warm load requires the tenure's suffix, so the invalidation is recorded once the log opens.
            super::suffix_sim_tests::record_changes(
                storage,
                volume.authority.session().get(),
                &layout,
            );
            storage
                .invalidate(&key(3), 4, &mut budget)
                .expect("the restored binding is published");
            live(storage, volume);
            let mut reader = storage.register().unwrap();
            for n in [2, 3] {
                assert!(
                    matches!(lookup(&mut reader, &key(n), 4), Err(LookupError::Missing)),
                    "key {n} misses"
                );
            }
            assert_eq!(
                served(storage, volume, control, 1),
                [&key(1)[..4], &[1; 40][..]].concat()
            );
        },
    );
}

#[test]
fn an_attach_carrying_a_warm_source_restores_from_the_attach_to_the_commit() {
    let (store, _, named, layout, _, _) = checkpointed(3);
    relaunch_sourced(
        &store,
        1,
        |session| {
            WarmSource::new(
                &manifest(named, 0, &[], session.generation().get()),
                layout,
                session,
                &fenced(&[]),
            )
        },
        |_, volume, control| {
            let mut seen = [false; 3];
            for _ in 0..128 {
                if !volume.readiness().initializing() {
                    break;
                }
                let metadata = &volume.metadata;
                let phase = [
                    metadata.warm_source.is_some(),
                    metadata.reading.is_some(),
                    metadata.warm.is_some(),
                ];
                assert!(
                    volume.warms(),
                    "source pending, slot read, load staged: {phase:?}"
                );
                for (seen, at) in seen.iter_mut().zip(phase) {
                    *seen |= at;
                }
                super::tests::tick(volume, control);
            }
            assert_eq!(volume.readiness(), State::Loaded);
            assert_eq!(seen, [true; 3], "the run passed through every phase");
        },
    );
    relaunch_sourced(
        &store,
        1,
        |_| None,
        |_, volume, control| {
            assert!(!volume.warms());
            super::tests::tick(volume, control);
            assert!(!volume.warms(), "a cold attach restores nothing");
        },
    );
}

/// Attach charges a warm source's envelope, the reader's estimate plus the warm estimate of the layout's entries, to
/// the caller's engine budget beside its own arrays, and the volume's share of the budget is that envelope: a budget
/// one byte short of the total refuses `Envelope` before any command, and the attempt charges its actual estimates
/// within the share.
#[test]
fn attach_charges_the_warm_envelope_to_the_engine_budget() {
    let (store, entries, named, layout, _, _) = checkpointed(3);
    let storage = sourced();
    let buffers = arena_with(4, 9);
    let source = |session: &crate::storage::Session| {
        WarmSource::new(
            &manifest(named, 0, &[], session.generation().get()),
            layout,
            session,
            &fenced(&[]),
        )
    };
    let authority = |warm: bool| {
        let mut authority = crate::storage::ServingAuthority::fixture();
        authority.warm = warm
            .then(|| source(&authority.session).map(Box::new))
            .flatten();
        authority
    };
    let charge = |warm: bool| {
        let (disk, _) = sim_attached(config_for(7), Rc::clone(&store), facts(BUFFER));
        let clock = ScriptedClock::trusted();
        Volume::attach_charge(
            &storage,
            &buffers,
            &disk,
            &*clock,
            &authority(warm),
            DEPTH,
            TICK,
        )
        .unwrap()
    };
    let envelope = super::Planned::of(
        &storage,
        (IO_UNIT as u32, BUFFER),
        &source(&authority(false).session).unwrap(),
    )
    .unwrap()
    .envelope;
    assert_eq!(
        charge(true) - charge(false),
        envelope,
        "the envelope is charged beside the arrays"
    );
    let attach = |limit: usize| {
        let (disk, control) = sim_attached(config_for(7), Rc::clone(&store), facts(BUFFER));
        let mut budget = EngineBudget::new(limit);
        let attached = Volume::attach(
            &storage,
            &buffers,
            disk,
            ScriptedClock::trusted(),
            authority(true),
            DEPTH,
            TICK,
            &mut budget,
        );
        (attached.map_err(|(error, _)| error), budget, control)
    };
    let (refused, budget, _) = attach(charge(true) - 1);
    assert!(
        matches!(refused, Err(super::super::AttachError::Envelope(_))),
        "a budget one byte short refuses"
    );
    assert_eq!(budget.used(), 0, "a refused attach charges nothing");
    let (attached, budget, control) = attach(charge(true));
    let mut volume = attached.expect("the exact budget attaches");
    assert_eq!(budget.used(), charge(true));
    assert_eq!(
        volume.budget.limit(),
        envelope,
        "the volume's share is the envelope"
    );
    PARK.with(|park| park.set(true));
    load(&mut volume, &control);
    PARK.with(|park| park.set(false));
    assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
    assert_eq!(resident(&storage), entries.len());
    assert!(volume.budget.used() <= envelope);
}

#[test]
fn the_warm_envelope_holds_the_tables_of_the_sources_coverage_copy() {
    let (_, entries, named, layout, _, _) = checkpointed(3);
    let storage = sourced();
    let session = crate::storage::ServingAuthority::fixture().session;
    let record = manifest(named, 0, &[], session.generation().get());
    let keys: Vec<[u8; 32]> = entries.iter().map(|entry| entry.key).collect();
    let planned = |covered: &[[u8; 32]]| {
        let source = WarmSource::new(&record, layout, &session, &fenced(covered)).unwrap();
        let planned = super::Planned::of(&storage, (IO_UNIT as u32, BUFFER), &source).unwrap();
        (planned.envelope, source.coverage.heap_bytes())
    };
    let ((cold, bare), (held, tables)) = (planned(&[]), planned(&keys));
    assert!(tables > bare, "held intervals grow the copy's tables");
    assert_eq!(
        held - cold,
        tables - bare,
        "the envelope grows by the bytes the copy's tables grew"
    );
}

#[test]
fn a_warm_load_frees_its_coverage_copy_once_every_conversion_landed() {
    let (store, entries, named, layout, _, _) = checkpointed(3);
    let covered = entries[1].key;
    relaunch_sourced(
        &store,
        1,
        |session| {
            WarmSource::new(
                &manifest(named, 0, &[], session.generation().get()),
                layout,
                session,
                &fenced(&[covered]),
            )
        },
        |storage, volume, control| {
            super::tests::reach(volume, control, super::Stage::Convert);
            let warm = volume.metadata.warm.as_ref().unwrap();
            let copy = std::sync::Arc::downgrade(warm.coverage.as_ref().unwrap());
            load(volume, control);
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
            assert_eq!(
                resident(storage),
                entries.len() - 1,
                "the conversions judged the covered entry by the copy"
            );
            assert!(
                copy.upgrade().is_none(),
                "the open volume keeps no copy of the coverage"
            );
            assert!(volume.budget.used() <= volume.budget.limit());
        },
    );
}

#[test]
fn the_plan_and_the_reader_count_the_same_bytes_for_a_suffix() {
    let (_, _, named, layout, writer, _) = checkpointed(3);
    let storage = sourced();
    let session = crate::storage::ServingAuthority::fixture().session;
    let suffix = Suffix {
        session: writer,
        start: 0,
        certified: 0,
        end: 3,
    };
    let index = storage.index().unwrap();
    let counted = |ancestry: &[Suffix]| {
        let record = manifest(named, 0, ancestry, session.generation().get());
        let source = WarmSource::new(&record, layout, &session, &fenced(&[])).unwrap();
        let planned = super::Planned::of(&storage, (IO_UNIT as u32, BUFFER), &source).unwrap();
        let reader = super::super::super::checkpoint::SlotReader::with_read_len(
            Crc32c::detect(),
            &layout,
            shard(),
            (named, 0, ancestry),
            session.get(),
            (planned.limits, &EngineBudget::unlimited()),
            (index.hasher.clone(), planned.destinations),
            planned.read_len,
        )
        .unwrap();
        (planned.envelope, reader.bytes())
    };
    let ((bare, slot), (suffixed, replayed)) = (counted(&[]), counted(&[suffix]));
    assert!(
        replayed > slot,
        "the suffix's blocks grow the reader's bytes"
    );
    assert_eq!(
        suffixed - bare,
        replayed - slot,
        "the plan charges the suffix what the reader counts for it"
    );
}

/// A slot that starts inside a read window touches one window more than its length in windows, a suffix adds one
/// live chunk per destination, and an entry stitched across a boundary between two windows adds one chunk, so the
/// attach envelope holds a load of the layout's entries in one chunk per window the reader actually reads, plus one,
/// per destination, and one per boundary between those windows.
#[test]
fn the_warm_envelope_holds_a_chunk_for_every_window_the_slot_touches_and_the_suffix() {
    let (_, _, named, layout, _, _) = checkpointed(3);
    let storage = sourced();
    let session = crate::storage::ServingAuthority::fixture().session;
    let record = manifest(named, 0, &[], session.generation().get());
    let source = WarmSource::new(&record, layout, &session, &fenced(&[])).unwrap();
    let read_len = 2 * IO_UNIT as u64;
    let planned = super::Planned::of(&storage, (read_len as u32, BUFFER), &source).unwrap();
    assert_eq!(planned.read_len, read_len);
    let index = storage.index().unwrap();
    let mut reader = super::super::super::checkpoint::SlotReader::with_read_len(
        Crc32c::detect(),
        &layout,
        shard(),
        (named, 0, &[]),
        session.get(),
        (planned.limits, &EngineBudget::unlimited()),
        (index.hasher.clone(), planned.destinations),
        read_len,
    )
    .unwrap();
    let mut reads = 0;
    while reader.next_read().is_some() {
        reads += 1;
    }
    let slot_bytes = u64::from(named.units) * IO_UNIT as u64;
    assert_eq!(
        reads,
        slot_bytes.div_ceil(read_len) as usize + 1,
        "the slot starts inside a window"
    );
    let destinations = planned.destinations;
    let lanes = storage.recovery.helpers.max(1) as usize;
    let payload_units = storage.pool().descriptor().geometry.payload_units();
    let load = (
        layout.entries as usize,
        (reads + 1) * destinations + (reads - 1),
        destinations,
    );
    let groups = super::groups_of(&index.geometry).1;
    let warm = super::warm_estimate(
        load,
        payload_units,
        (lanes, groups, index.geometry.inventory().geometry_bytes),
    )
    .unwrap();
    assert!(
        planned.envelope >= reader.bytes() + warm,
        "envelope {} below the reader's {} and the warm {warm}",
        planned.envelope,
        reader.bytes()
    );
}

/// Each predecessor suffix certifies to the lowest hole inside its own LSN range, or to its recorded end when none
/// lies there, and a suffix already certified to that end raises nothing: a tail hole in the earlier suffix leaves the
/// later certified to its end, a hole in the later leaves the earlier at its end, and a cut above a suffix's start
/// reads it from the cut.
#[test]
fn each_suffix_certifies_to_its_own_first_hole_or_its_end() {
    use super::super::super::recovery::delta::BlockHole;
    use super::super::super::recovery::delta_replay::{Hole, SuffixReport};
    let (first, second) = (
        crate::net::ownership::session_of(7, 2),
        crate::net::ownership::session_of(7, 4),
    );
    let ancestry = Ancestry::new(&[
        Suffix {
            session: first,
            start: 0,
            certified: 1,
            end: 4,
        },
        Suffix {
            session: second,
            start: 4,
            certified: 4,
            end: 8,
        },
    ])
    .unwrap();
    let layout = layout(2);
    let tail = |lsn| SuffixReport {
        tails: vec![Hole {
            lsn,
            cause: BlockHole::Chunk,
        }],
        ..SuffixReport::default()
    };
    let cases = [
        (SuffixReport::default(), 0, vec![(first, 4), (second, 8)]),
        (tail(2), 0, vec![(first, 2), (second, 8)]),
        (tail(6), 0, vec![(first, 4), (second, 6)]),
        (tail(1), 0, vec![(second, 8)]),
        (
            SuffixReport {
                unread: vec![5],
                ..SuffixReport::default()
            },
            0,
            vec![(first, 4), (second, 5)],
        ),
        (tail(2), 3, vec![(first, 4), (second, 8)]),
    ];
    for (report, cut, raised) in cases {
        assert_eq!(
            super::certified(&ancestry, cut, &layout, &report),
            raised,
            "{report:?} from cut {cut}"
        );
    }
}

/// A slot read still at the device when the attempt ends lands on a cancelled pool: its late terminal copies no byte
/// into the abandoned reader, and the ended attempt writes nothing.
#[test]
fn a_slot_read_landing_after_the_attempt_ended_copies_nothing() {
    use super::super::super::checkpoint::COPIES;
    let (store, _, named, layout, _, _) = checkpointed(3);
    relaunch_sourced(
        &store,
        1,
        |session| {
            WarmSource::new(
                &manifest(named, 0, &[], session.generation().get()),
                layout,
                session,
                &fenced(&[]),
            )
        },
        |_, volume, control| {
            // A tick runs the device before the volume's poll, so the poll that first submits a slot read leaves it
            // at the device.
            for _ in 0..16 {
                super::tests::tick(volume, control);
                if !submitted(control, Operation::Read).is_empty() {
                    break;
                }
            }
            assert_eq!(
                control.delivered(Operation::Read),
                0,
                "the read is in flight"
            );
            volume.end(MetadataOutcome::MetadataFailed);
            let copies = COPIES.with(std::cell::Cell::get);
            for _ in 0..16 {
                super::tests::tick(volume, control);
            }
            assert!(control.delivered(Operation::Read) > 0, "the read landed");
            assert_eq!(
                COPIES.with(std::cell::Cell::get),
                copies,
                "the late terminal copies nothing"
            );
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::MetadataFailed);
            assert_eq!(writes(control), 0);
        },
    );
}

/// A warm load through the production attach whose slot reads exceed a recovery I/O share of two units per ten
/// ticks, whose bucket holds one unit of bulk room beside the suffix reserve, with two maintenance buffers that would
/// carry two reads at once: each slot read reaches the device no sooner than five ticks, one unit's drain, after the
/// read before it, and a run whose device completes nothing for 35 ticks issues every read its buffers carry, since
/// the bucket drains with the clock whatever completed. Each slot unit is read once, and the load serves every
/// captured entry at `Live` with the writer's units. With the share ignored the spacing fails.
#[test]
fn a_warm_load_above_the_recovery_io_share_defers_its_slot_reads_and_installs_every_entry() {
    use super::super::super::recovery::io_share::IGNORE;
    const INTERVAL: u64 = 10;
    // The ticks one unit takes to drain from a bucket whose part is two units per interval.
    const DRAIN: u64 = INTERVAL / 2;
    let (store, entries, named, layout, _, writer) = checkpointed(3);
    assert!(named.units >= 2, "the slot spans more than one read");
    let run = |stall: u64| -> Result<(), String> {
        let storage = storage_with(|volume| {
            volume.metadata_commands = 2;
            volume.recovery.jobs = (super::super::super::checkpoint::WINDOWS + 1) as u32;
            volume.recovery.adopt = volume.recovery.jobs;
            volume.recovery.io = super::super::super::recovery::HostShare {
                bytes: 2 * IO_UNIT as u64,
                interval: INTERVAL,
                owners: 1,
            };
        });
        let source = |session: &crate::storage::Session| {
            WarmSource::new(
                &manifest(named, 0, &[], session.generation().get()),
                layout,
                session,
                &fenced(&[]),
            )
        };
        relaunch_sourced_on(storage, &store, 2, source, |storage, volume, control| {
            let (mut last, mut seen) = (None::<u64>, 0usize);
            for now in 1..=2_000u64 {
                if !volume.readiness().initializing() {
                    break;
                }
                if now > stall {
                    control.tick(64);
                }
                let _ = volume.poll_storage(now, &mut Vec::with_capacity(16));
                if let Some((ran, released)) = volume
                    .metadata
                    .helpers
                    .as_mut()
                    .and_then(|helpers| helpers.parked())
                {
                    released.extend(ran.drain(..));
                }
                for _ in seen..prefix_reads(control).len() {
                    if let Some(last) = last.filter(|last| now - last < DRAIN) {
                        return Err(format!(
                            "tick {now}: a slot read {} ticks after the read before it",
                            now - last
                        ));
                    }
                    last = Some(now);
                }
                seen = prefix_reads(control).len();
                // The bucket drains with the clock whether or not a read completed.
                if stall > 0 && now == stall && seen != named.units as usize {
                    return Err(format!(
                        "tick {now}: {seen} reads issued with nothing completed"
                    ));
                }
            }
            let report = volume.recovery_report();
            if report.io_peak_bytes > 2 * IO_UNIT as u64 || report.io_saturated_windows == 0 {
                return Err(format!("{report:?}"));
            }
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
            let mut reads = prefix_reads(control);
            assert_eq!(
                reads.len(),
                named.units as usize,
                "each slot unit is read once"
            );
            reads.dedup();
            assert_eq!(reads.len(), named.units as usize);
            assert_eq!(units(storage), writer);
            assert_eq!(
                resident(storage),
                entries.len(),
                "every captured entry installs"
            );
            assert_eq!(
                volume.recovery_report().warm.installed,
                entries.len() as u64
            );
            Ok(())
        })
    };
    assert_eq!(run(0), Ok(()));
    assert_eq!(
        run(35),
        Ok(()),
        "a device that completes nothing for 35 ticks"
    );
    IGNORE.with(|plant| plant.set(true));
    let ignored = run(0);
    IGNORE.with(|plant| plant.set(false));
    assert!(
        ignored
            .as_ref()
            .is_err_and(|error| error.contains("ticks after the read before it")),
        "control: an ignored share issues a slot read before the bucket drained: {ignored:?}"
    );
}

/// Slot reads take the recovery I/O share as they reach the device: while the device turns every submit away as full
/// for five intervals from the attach's first tick, both slot reads wait staged in the two metadata cells and each
/// refusal returns its charge, so both cells' submits reach the device at every tick of the span. The tick after the
/// last scripted refusal is consumed, the first read reaches the device, and the second waits until the first read's
/// bytes drain from the share's bucket, which holds one slot read beside the suffix reserve, so the two staged reads
/// never land together. The load installs every captured entry with the writer's units.
#[test]
fn slot_reads_staged_behind_a_full_device_queue_keep_the_share_s_spacing() {
    use super::super::super::device::sim::Origin;
    use super::super::super::device::{RefusalReason, SubmitRefusal};
    const INTERVAL: u64 = 10;
    let (store, entries, named, layout, _, writer) = checkpointed(3);
    assert_eq!(named.units, 2, "the slot spans two one-unit reads");
    let storage = storage_with(|volume| {
        volume.metadata_commands = 2;
        volume.recovery.jobs = (super::super::super::checkpoint::WINDOWS + 1) as u32;
        volume.recovery.adopt = volume.recovery.jobs;
        volume.recovery.io = super::super::super::recovery::HostShare {
            bytes: 2 * IO_UNIT as u64,
            interval: INTERVAL,
            owners: 1,
        };
    });
    let source = |session: &crate::storage::Session| {
        WarmSource::new(
            &manifest(named, 0, &[], session.generation().get()),
            layout,
            session,
            &fenced(&[]),
        )
    };
    let full = SubmitRefusal {
        reason: RefusalReason::QueueFull,
        code: None,
    };
    relaunch_sourced_on(storage, &store, 2, source, |storage, volume, control| {
        let (mut ticks, mut queued, mut reopened) = (Vec::new(), 0usize, None);
        for now in 1..=2_000u64 {
            if !volume.readiness().initializing() {
                break;
            }
            let consumed = control.refused(Origin::Script);
            if now < 1 + 5 * INTERVAL {
                // Two refusals queued at each tick's start refuse both staged cells' submits of that tick.
                while queued < consumed + 2 {
                    control.refuse_next(full);
                    queued += 1;
                }
            } else if reopened.is_none() && consumed == queued {
                reopened = Some(now);
            }
            control.tick(64);
            let _ = volume.poll_storage(now, &mut Vec::with_capacity(16));
            if let Some((ran, released)) = volume
                .metadata
                .helpers
                .as_mut()
                .and_then(|helpers| helpers.parked())
            {
                released.extend(ran.drain(..));
            }
            ticks.resize(prefix_reads(control).len(), now);
            if now == 5 * INTERVAL {
                assert!(
                    ticks.is_empty(),
                    "the device accepted no slot read while full"
                );
                assert!(
                    volume.metadata.commands.iter().flatten().count() >= 2,
                    "both slot reads wait staged behind the full queue"
                );
            }
        }
        assert!(
            control.refused(Origin::Script) >= 10 * INTERVAL as usize - 2,
            "the device refused both staged reads at every tick of the full span"
        );
        let reopened = reopened.expect("the scripted refusals were consumed");
        assert_eq!(
            ticks[0], reopened,
            "the first read reaches the device once it accepts again: {ticks:?}"
        );
        assert!(
            ticks[1] - ticks[0] >= INTERVAL / 2,
            "the second staged read waits one read's drain from the share's bucket: {ticks:?}"
        );
        assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
        assert_eq!(
            ticks.len(),
            named.units as usize,
            "each slot unit is read once"
        );
        assert_eq!(units(storage), writer);
        assert_eq!(
            resident(storage),
            entries.len(),
            "every captured entry installs"
        );
    });
}

/// A warm source whose slot read and the suffix reserve exceed the owner's part of the recovery I/O share refuses the
/// attach, since a bucket of that part could not hold the read.
#[test]
fn attach_refuses_a_warm_source_whose_slot_read_exceeds_the_recovery_io_share() {
    let (store, _, named, layout, _, _) = checkpointed(3);
    let storage = storage_with(|volume| {
        volume.recovery.jobs = (super::super::super::checkpoint::WINDOWS + 1) as u32;
        volume.recovery.adopt = volume.recovery.jobs;
        volume.recovery.io = super::super::super::recovery::HostShare {
            bytes: 2 * IO_UNIT as u64 + 8192,
            interval: 1,
            owners: 2,
        };
    });
    let buffers = arena_maintaining(2, 8192);
    let mut authority = crate::storage::ServingAuthority::fixture();
    authority.warm = WarmSource::new(
        &manifest(named, 0, &[], authority.session.generation().get()),
        layout,
        &authority.session,
        &fenced(&[]),
    )
    .map(Box::new);
    let refused =
        super::super::super::volume_fixture::attach_under(&storage, &buffers, &store, authority)
            .map(|_| ());
    assert_eq!(
        refused,
        Err(crate::storage::AttachError::RecoveryLimits { unit: 8192 }),
        "an 8 KiB slot read plus the reserve exceeds each of two owners' 8 KiB part of a 16 KiB share"
    );
}

/// A warm load through the production attach whose helper pool holds one read window beside the guard charge the
/// reader's first job takes, and whose helper terminals never return for 500 ticks: the pool issues one slot read,
/// then holds exactly its input-byte bound with the slot's next read waiting, reserves nothing past the bound at any
/// tick, writes nothing and stays in its load; once the terminals return it installs every captured entry. The
/// `OVER_RESERVE` plant, a reservation that ignores the bounds, fails the bound check.
#[test]
fn a_warm_load_whose_helpers_stall_fills_its_helper_bound_and_installs_every_entry() {
    let (store, entries, named, layout, _, writer) = checkpointed(3);
    let source = |session: &crate::storage::Session| {
        WarmSource::new(
            &manifest(named, 0, &[], session.generation().get()),
            layout,
            session,
            &fenced(&[]),
        )
    };
    // The window charge and guard bytes of the reader attach builds for this source.
    let (window, guard) = relaunch_sourced(&store, 2, source, |_, volume, _| {
        let _ = volume.poll_storage(1, &mut Vec::with_capacity(16));
        let reading = volume
            .metadata
            .reading
            .as_mut()
            .expect("the warm read began");
        (reading.window.input, reading.reader.decode().guard_bytes())
    });
    assert!(
        named.units >= 2 && window >= guard,
        "the slot spans a second read, which the bound below refuses"
    );
    let storage = sourced();
    let mut limits = storage.recovery;
    limits.input_bytes = window + guard;
    let storage = storage_with(|volume| volume.recovery = limits);
    let stall = |storage, store: &Media| {
        relaunch_sourced_on(storage, store, 2, source, |storage, volume, control| {
            let mut reached = None;
            for now in 1..=500u64 {
                control.tick(64);
                let _ = volume.poll_storage(now, &mut Vec::with_capacity(16));
                let (jobs, held) = volume
                    .metadata
                    .helpers
                    .as_ref()
                    .map_or((0, Default::default()), |h| h.held());
                assert!(
                    jobs <= limits.jobs && held.input <= limits.input_bytes,
                    "tick {now}: {jobs} jobs and {} input bytes",
                    held.input
                );
                let reads = prefix_reads(control).len();
                assert!(reads <= 1, "tick {now}: {reads} slot reads issued");
                if held.input == limits.input_bytes {
                    reached = reached.or(Some(now));
                }
                if let Some(at) = reached {
                    assert_eq!(
                        (held.input, reads),
                        (limits.input_bytes, 1),
                        "tick {now}: the pool reached its bound at tick {at} and holds it with one slot read issued"
                    );
                }
                assert!(
                    volume.readiness().initializing(),
                    "tick {now}: the load waits"
                );
                assert_eq!(writes(control), 0);
            }
            assert!(
                reached.is_some(),
                "the stalled pool reaches its input-byte bound"
            );
            load(volume, control);
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
            assert_eq!(units(storage), writer);
            assert_eq!(resident(storage), entries.len());
        });
    };
    stall(storage, &store);
    super::super::helpers::OVER_RESERVE.with(|plant| plant.set(true));
    let over = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        stall(storage_with(|volume| volume.recovery = limits), &store)
    }));
    super::super::helpers::OVER_RESERVE.with(|plant| plant.set(false));
    PARK.with(|park| park.set(false));
    let message = over
        .err()
        .and_then(|payload| payload.downcast::<String>().ok());
    assert!(
        message
            .as_deref()
            .is_some_and(|m| m.contains("input bytes")),
        "control: a pool that ignores its bounds passes its input-byte bound: {message:?}"
    );
}
