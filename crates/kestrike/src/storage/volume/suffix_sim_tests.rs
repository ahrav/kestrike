//! The production simulation of a tenure's mutation suffix over one shard's store double and one volume's simulated
//! media: every membership change of an open suffix is recorded before it moves a membership word or is refused
//! before its acknowledgment, the volume's delta writer lands each sealed block at its prefix unit ahead of the
//! checkpoint-unit commands, a removed slot waits for its REMOVE block's persistence, a pass whose snapshot members
//! left through recorded removals publishes, and the next takeover replays the checkpoint with the suffix over it,
//! then certifies the predecessor's suffix and opens its own.

use super::super::super::checkpoint::{
    PossiblyNamed, StagedCheckpoint, SuffixBounds, SuffixDue, SuffixLimits, open_suffix,
    suffix_step,
};
use super::super::super::claim_exit_tests::{FREE, RETIRED, conserved_after_service, conserved_at};
use super::super::super::device::sim::{Fault, SimControl, media};
use super::super::super::device::{DeviceStatus, Disk, Operation};
use super::super::super::ledger::EngineBudget;
use super::super::super::lookup::LookupError;
use super::super::super::lookup_tests::lookup;
use super::super::super::publication::FillPublishError;
use super::super::super::publication_tests::drain as serve;
use super::super::super::publish_tests::key;
use super::super::super::record::Crc32c;
use super::super::super::recovery::capture_tests::drain;
use super::super::super::recovery::checkpoint::Checkpoint;
use super::super::super::recovery::delta::{Block, Cause, Record, decode};
use super::super::super::recovery::delta_tests::fed;
use super::super::super::recovery::suffix::SuffixLog;
use super::super::super::recovery::suffix_tests::take;
use super::super::super::store_tests::{client, shard};
use super::super::super::test_platform::TestPlatform;
use super::super::super::volume_fixture::{
    Device, MEDIA, arena_with, attach_under, bootstrap, read_back,
};
use super::super::super::{IO_UNIT, MetadataOutcome, ReadStatus, Storage};
use super::super::bootstrap_tests::submitted;
use super::super::checkpoint::{UnitDone, UnitRefused};
use super::super::metadata::{JOURNAL, Target};
use super::sim_tests::{PREFIX, layout, load, predecessor_session, storage, takeover};
use super::tests::{live, tick, units};
use crate::failover::records::{
    Ancestry, Layout, NamedCheckpoint, ShardRecord, Suffix, VolumeRecord,
};
use crate::failover::restart::tests as restart_tests;
use crate::failover::retire::Target as Own;
use crate::failover::takeover::tests::{
    Card, a_holds_c_registered, c_host, c_pair, stored_c, with_c,
};
use crate::storage::budget::WorkBudget;
use crate::storage::store::sim::{Arm, Shared};

/// A block seals at the next delta stage, and under the fixture's one-sample clock no record stalls.
const LIMITS: SuffixLimits = SuffixLimits {
    flush_ns: 0,
    queue_blocks: 8,
    oldest_ns: 1 << 40,
    uncertified: 16,
};

/// The first prefix unit of [`layout`]'s delta region: `1 + K·S`.
const DELTA: u64 = 1 + 3 * 3;

/// A cold tenure of the predecessor's session over fresh media with its suffix open over `[0, end)`.
fn tenure<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    buffers: &'a super::super::super::device::BufferArena<TestPlatform>,
    end: u64,
) -> Device<'s, 'a> {
    let dev = cold(storage, buffers);
    let own = Suffix {
        session: predecessor_session().get(),
        start: 0,
        certified: 0,
        end,
    };
    let opened = storage
        .with_suffix(|log| log.open((Crc32c::detect(), shard()), (LIMITS, &layout()), own, 0));
    assert_eq!(opened, Ok(true));
    dev
}

/// Opens `storage`'s suffix log under `session` over `[0, 16)` of `layout`'s delta region, as a tenure does once its
/// store records that suffix, so the changes a required log refuses are recorded.
pub(super) fn record_changes(storage: &Storage<TestPlatform>, session: u64, layout: &Layout) {
    let own = Suffix {
        session,
        start: 0,
        certified: 0,
        end: 16,
    };
    let open = (LIMITS, layout);
    let opened = storage.with_suffix(|log| log.open((Crc32c::detect(), shard()), open, own, 0));
    assert_eq!(opened, Ok(true));
}

/// A cold tenure of the predecessor's session over fresh media whose suffix never opened.
fn cold<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    buffers: &'a super::super::super::device::BufferArena<TestPlatform>,
) -> Device<'s, 'a> {
    let store = media(MEDIA);
    let authority = crate::storage::ServingAuthority::fixture_under(predecessor_session());
    let (mut volume, control) = attach_under(storage, buffers, &store, authority).expect("attach");
    bootstrap(&mut volume, &control);
    Device { volume, control }
}

/// Ticks until the suffix holds no record and its last write's result was given to the log.
fn settle<D: Disk>(
    storage: &Storage<TestPlatform>,
    volume: &mut super::super::Volume<'_, '_, TestPlatform, D>,
    control: &SimControl,
) {
    for _ in 0..256 {
        // Read under the mutex directly, so the probe republishes no due time the stage should have published.
        let idle = storage.pool().capture_lock().unwrap().suffix.idle();
        if idle && volume.metadata.delta.is_none() {
            return;
        }
        tick(volume, control);
    }
    panic!("the suffix drains");
}

/// The bytes `key` serves, or `None` when it misses.
fn served<'s, D: Disk>(
    storage: &'s Storage<TestPlatform>,
    volume: &mut super::super::Volume<'s, '_, TestPlatform, D>,
    control: &SimControl,
    key: &[u8; 32],
) -> Option<Vec<u8>> {
    let mut reader = storage.register().unwrap();
    match lookup(&mut reader, key, 4) {
        Ok(lease) => {
            let delivered = read_back(volume, control, &lease);
            assert_eq!(delivered.status, ReadStatus::Complete);
            Some(delivered.bytes)
        }
        Err(LookupError::Missing) => None,
        Err(other) => panic!("{other:?}"),
    }
}

/// Publishes a fill of `key` with `body`, then services both shards' fill tables so departed fills free their rows
/// whichever shard the key routes to.
fn publish<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    dev: &mut Device<'s, 'a>,
    key: &[u8; 32],
    body: &[u8],
) -> Result<super::super::super::lease::ExtentLease<'s, TestPlatform>, FillPublishError> {
    let published = super::super::super::publication_tests::publish(storage, dev, key, body);
    for shard in 0..2 {
        let mut budget = WorkBudget::new(1 << 20);
        storage
            .service_fills(crate::index::ShardIndex(shard), 8, &mut budget)
            .unwrap();
    }
    published
}

/// The bytes a fill of `key` with `body` stores.
fn bytes(key: &[u8; 32], body: &[u8]) -> Vec<u8> {
    [&key[..4], body].concat()
}

/// The device starts of the delta writes `control` saw, as prefix units.
fn delta_units(control: &SimControl) -> Vec<u64> {
    (submitted(control, Operation::Write).into_iter())
        .map(|(_, start)| start / IO_UNIT as u64)
        .filter(|unit| (DELTA..PREFIX).contains(unit))
        .collect()
}

/// The records of the block of LSN `lsn` as the media holds it under the predecessor's session.
fn block_records(device: &SimControl, lsn: u64) -> Vec<Record> {
    let media = device.shared_media();
    let media = media.borrow();
    let at = (DELTA + lsn) as usize * IO_UNIT;
    let unit = &media[at..at + IO_UNIT];
    let expected = Block {
        shard: shard(),
        session: predecessor_session().get(),
        lsn,
    };
    let parts = decode(
        Crc32c::detect(),
        expected,
        expected.session,
        unit,
        Vec::new(),
    )
    .expect("a written block decodes");
    let mut assembler = super::super::super::recovery::delta::Assembler::default();
    assembler.admit(&parts).unwrap();
    (parts.into_iter())
        .filter_map(|part| fed(&mut assembler, part).unwrap())
        .collect()
}

/// Publishes a fill of `key(n)` whose deadline is `expires` ticks, then services the fill tables.
fn expiring<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    dev: &mut Device<'s, 'a>,
    n: u8,
    expires: u64,
) -> super::super::super::lease::ExtentLease<'s, TestPlatform> {
    use super::super::super::publish_tests::{TRIES, budget};
    let fill = super::super::super::publication_tests::filled(storage, dev, &key(n), &[n; 40]);
    let lease = fill
        .publish(&mut dev.volume, expires, TRIES, &mut budget())
        .unwrap();
    serve(storage);
    lease
}

/// Ticks until the block of LSN `lsn` is submitted, then faults that first write.
fn fail_first_write(dev: &mut Device<'_, '_>, lsn: u64) {
    for _ in 0..8 {
        tick(&mut dev.volume, &dev.control);
        let staged = dev.volume.metadata.commands[JOURNAL]
            .as_ref()
            .map(|c| c.target);
        if staged == Some(Target::Delta(lsn)) {
            let (token, _) = *submitted(&dev.control, Operation::Write).last().unwrap();
            return dev
                .control
                .fault(token, Fault::Status(DeviceStatus::Kernel(-5)));
        }
    }
    panic!("the block of LSN {lsn} was submitted");
}

/// The shard's store: the record names the predecessor owner with C as standby, the predecessor's first checkpoint
/// [`named`] at cut 0 and its suffix `own`; the volume record enrolls the predecessor and C under the test layout.
fn suffix_store(own: Suffix) -> Shared {
    let shard = ShardRecord {
        checkpoint: Some(named()),
        ancestry: Ancestry::new(&[own]).unwrap(),
        standby: Some(c_host()),
        ..restart_tests::shard_record(4)
    };
    let volume = VolumeRecord {
        layout: layout(),
        ..with_c()
    };
    restart_tests::store(shard, volume)
}

/// REFUSE-BEFORE-ACK on the fill and removal paths: a fill whose record the suffix refuses at its reserved end
/// returns `History`, which followers see as object pressure, and publishes nothing, moves no membership word and
/// leaves the log as it was; a removal the suffix refuses returns `History` and the entry still serves; an
/// extension admits both. The refused fill's slot is retired with `ABANDONED`, the tables pass the
/// conservation judge, and one service pass frees the slot.
#[test]
fn a_refused_append_refuses_the_fill_or_removal_before_acknowledgment_and_changes_nothing() {
    let storage = storage(1);
    let buffers = arena_with(4, 9);
    let mut dev = tenure(&storage, &buffers, 1);
    drop(publish(&storage, &mut dev, &key(1), &[1; 40]).unwrap());
    settle(&storage, &mut dev.volume, &dev.control);
    let pool = storage.pool();
    let words = || {
        (
            pool.insert_step.load(std::sync::atomic::Ordering::Relaxed),
            pool.eligible.load(std::sync::atomic::Ordering::Relaxed),
            pool.suffix_tail.load(std::sync::atomic::Ordering::Relaxed),
            format!("{:?}", storage.with_suffix(|log| log.recorded())),
            storage.with_suffix(|log| (log.head(), log.idle(), log.pending(), log.durable())),
        )
    };
    let before = words();
    let slot = super::super::super::writable_tests::next_slot(&storage, &key(2));
    assert_eq!(
        publish(&storage, &mut dev, &key(2), &[2; 40]).err(),
        Some(FillPublishError::History)
    );
    assert_eq!(words(), before, "the refused fill changed nothing");
    conserved_at(&storage, slot, RETIRED);
    assert_eq!(
        served(&storage, &mut dev.volume, &dev.control, &key(2)),
        None
    );
    conserved_after_service(&storage, slot, FREE);
    let mut budget = WorkBudget::new(1 << 20);
    assert_eq!(
        storage.invalidate(&key(1), 4, &mut budget).err(),
        Some(super::super::super::InvalidateError::History)
    );
    assert_eq!(words(), before, "the refused removal changed nothing");
    storage.with_suffix(|log| log.extend(4)).unwrap();
    // With no clock sample the record cannot take its time, so the removal refuses `History` and changes nothing.
    storage.platform.ticks(&[None]);
    let before = words();
    assert_eq!(
        storage.invalidate(&key(1), 4, &mut budget).err(),
        Some(super::super::super::InvalidateError::History)
    );
    assert_eq!(words(), before, "the clockless removal changed nothing");
    storage.platform.ticks(&[Some(1)]);
    assert_eq!(
        served(&storage, &mut dev.volume, &dev.control, &key(1)),
        Some(bytes(&key(1), &[1; 40])),
        "the entry whose removal was refused still serves"
    );
    drop(publish(&storage, &mut dev, &key(2), &[2; 40]).unwrap());
    assert!(
        storage
            .invalidate(&key(1), 4, &mut budget)
            .unwrap()
            .removed
            .is_some()
    );
    assert_eq!(
        served(&storage, &mut dev.volume, &dev.control, &key(1)),
        None
    );
}

/// HOLD-UNTIL-DURABLE: the delta writer lands each sealed block at its prefix unit ahead of a checkpoint-unit
/// command, a block sealed by a capture start between ticks takes the journal cell before the capture's own unit
/// writes, a failed write keeps its block and the next stage resends it to the same unit, and an invalidated slot's
/// units return only once its REMOVE block persisted and the tick published the durable prefix.
#[test]
fn a_removed_slot_returns_only_after_its_remove_block_persisted_and_a_failed_write_resends_it() {
    let storage = storage(1);
    let buffers = arena_with(4, 9);
    let mut dev = tenure(&storage, &buffers, 16);
    drop(publish(&storage, &mut dev, &key(1), &[1; 40]).unwrap());
    settle(&storage, &mut dev.volume, &dev.control);
    serve(&storage);
    let written = delta_units(&dev.control);
    assert!(!written.is_empty(), "the insert's block was written");
    assert_eq!(
        written,
        (0..written.len() as u64)
            .map(|lsn| DELTA + lsn)
            .collect::<Vec<_>>()
    );
    let durable = storage.with_suffix(|log| log.durable()).unwrap();
    assert_eq!(durable, written.len() as u64);
    let prefix = || (dev.volume.journal_words.prefix).load(std::sync::atomic::Ordering::Acquire);
    assert_eq!(prefix(), durable, "the tick published the durable prefix");
    let free = units(&storage).0;

    // The REMOVE's block: its first write fails and the next stage resends it.
    let mut budget = WorkBudget::new(1 << 20);
    assert!(
        storage
            .invalidate(&key(1), 4, &mut budget)
            .unwrap()
            .removed
            .is_some()
    );
    let remove = durable;
    fail_first_write(&mut dev, remove);
    // Until the resent block persists, service keeps the slot and the prefix stays below the REMOVE's LSN.
    let mut held = 0;
    while prefix() == remove {
        serve(&storage);
        assert_eq!(
            units(&storage).0,
            free,
            "the slot waits for its REMOVE block"
        );
        held += 1;
        assert!(held < 64, "the resent block persists");
        tick(&mut dev.volume, &dev.control);
    }
    assert!(
        held >= 2,
        "service ran while the block failed and while it was resent"
    );
    settle(&storage, &mut dev.volume, &dev.control);
    let units_written = delta_units(&dev.control);
    assert_eq!(
        units_written[written.len()..],
        [DELTA + remove, DELTA + remove],
        "the failed block was resent to its own unit"
    );
    let records = block_records(&dev.control, remove);
    assert!(
        matches!(records[..], [Record::Remove { identity, cause: Cause::Invalidate }] if identity.key == key(1)),
        "{records:?}"
    );
    assert_eq!(prefix(), remove + 1);
    serve(&storage);
    assert!(
        units(&storage).0 > free,
        "the slot returned once its block persisted"
    );

    // A FILL replacing a live key records one REPLACE; the incumbent's units wait for that block, whose
    // first write fails, and return once it persisted.
    drop(publish(&storage, &mut dev, &key(3), &[3; 40]).unwrap());
    settle(&storage, &mut dev.volume, &dev.control);
    serve(&storage);
    let replace = storage.with_suffix(|log| log.head()).unwrap();
    drop(publish(&storage, &mut dev, &key(3), &[0x33; 40]).unwrap());
    serve(&storage);
    let replaced = units(&storage).0;
    fail_first_write(&mut dev, replace);
    for pass in 0.. {
        if prefix() > replace {
            break;
        }
        assert!(pass < 64, "the resent REPLACE block persists");
        serve(&storage);
        assert_eq!(
            units(&storage).0,
            replaced,
            "the incumbent waits for its REPLACE block"
        );
        tick(&mut dev.volume, &dev.control);
    }
    assert!(matches!(
        block_records(&dev.control, replace)[..],
        [Record::Replace { old, .. }] if old.key == key(3)
    ));
    serve(&storage);
    assert!(
        units(&storage).0 > replaced,
        "the incumbent returned once its block persisted"
    );

    // A capture start seals the open block between ticks; the capture's unit write waits behind it.
    drop(publish(&storage, &mut dev, &key(2), &[2; 40]).unwrap());
    storage.start_capture(1024, true, 1024).unwrap();
    let entries = drain(&storage);
    let session = predecessor_session().get();
    let mut possible = PossiblyNamed::new((shard(), session), layout(), None);
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
    // Read under the mutex directly, so no accessor republishes the due time the capture start stored.
    assert!(storage.pool().capture_lock().unwrap().suffix.pending());
    assert_eq!(
        dev.volume.stage_unit_write(&possible, &mut stage, 0),
        Err(UnitRefused::Busy),
        "a sealed block goes before a checkpoint-unit write"
    );
    settle(&storage, &mut dev.volume, &dev.control);
    dev.volume
        .stage_unit_write(&possible, &mut stage, 0)
        .unwrap();
    let done = (0..64).find_map(|_| {
        tick(&mut dev.volume, &dev.control);
        dev.volume.take_unit()
    });
    assert_eq!(
        done,
        Some(UnitDone::Written {
            slot: stage.slot(),
            unit: 0
        })
    );
}

/// A pass whose snapshot member left through a recorded
/// invalidation stays publishable and its checkpoint names the member; after host loss the takeover's warm load
/// replays the checkpoint with the suffix over it, so the invalidated entry misses, the replaced key serves its new
/// bytes, a fill after the pass serves and an untouched member serves. The successor then certifies the
/// predecessor's suffix to the end its load read whole, records its own suffix from the predecessor's end and opens
/// its log, and a removal it records persists and is certified by the store step; its warm install required the
/// log, so a removal before the open refuses `History`. With a suffix the tenure never required, the same
/// invalidation makes the pass unpublishable.
#[test]
fn a_pass_with_a_recorded_removal_publishes_and_the_takeover_replays_the_suffix_over_it() {
    let storage = storage(1);
    let buffers = arena_with(4, 9);
    let mut dev = tenure(&storage, &buffers, 16);
    let store = dev.control.shared_media();
    for n in 1..=3 {
        drop(publish(&storage, &mut dev, &key(n), &[n; 40]).unwrap());
    }
    let session = predecessor_session().get();
    storage.start_capture(1024, true, 1024).unwrap();
    let counter = storage.pool().capture_lock().unwrap().counter();
    let mut budget = WorkBudget::new(1 << 20);
    assert!(
        storage
            .invalidate(&key(2), 4, &mut budget)
            .unwrap()
            .removed
            .is_some()
    );
    let entries = drain(&storage);
    assert_eq!(entries.len(), 3, "the side list keeps the removed member");
    let proof = storage
        .cut_intact((shard(), session), counter)
        .expect("a recorded removal keeps the pass publishable");
    let cut = proof.cut();
    assert!(cut > 0, "the inserts lie below the cut");
    drop(publish(&storage, &mut dev, &key(4), &[4; 40]).unwrap());
    let replaced = publish(&storage, &mut dev, &key(1), &[0x11; 40]).unwrap();
    drop(replaced);
    assert_eq!(
        (storage.cut_intact((shard(), session), counter)).map(|proof| proof.cut()),
        Ok(cut),
        "a recorded replacement of a snapshot member keeps the pass publishable"
    );
    settle(&storage, &mut dev.volume, &dev.control);
    let durable = storage.with_suffix(|log| log.durable()).unwrap();
    assert!(durable > cut);
    let after: Vec<Record> = (cut..durable)
        .flat_map(|lsn| block_records(&dev.control, lsn))
        .collect();
    assert!(
        after.iter().any(|record| matches!(record,
            Record::Replace { old, new, .. } if old.key == key(1) && new.key == key(1))),
        "the replacement is one REPLACE record: {after:?}"
    );
    assert!(
        after.iter().any(|record| matches!(record,
            Record::Remove { identity, cause: Cause::Invalidate } if identity.key == key(2))),
        "{after:?}"
    );
    let mut possible = PossiblyNamed::new((shard(), session), layout(), Some(named()));
    let checkpoint = Checkpoint {
        shard: shard(),
        session,
        capture: counter,
    };
    let mut stage = StagedCheckpoint::new(
        Crc32c::detect(),
        &mut possible,
        (checkpoint, &entries),
        &EngineBudget::unlimited(),
    )
    .unwrap();
    for unit in 0..stage.units().len() as u32 {
        dev.volume
            .stage_unit_write(&possible, &mut stage, unit)
            .unwrap();
        let done = (0..64).find_map(|_| {
            tick(&mut dev.volume, &dev.control);
            dev.volume.take_unit()
        });
        let slot = stage.slot();
        assert_eq!(done, Some(UnitDone::Written { slot, unit }));
        dev.volume.stage_unit_read(&possible, (slot, unit)).unwrap();
        let done = (0..64).find_map(|_| {
            tick(&mut dev.volume, &dev.control);
            dev.volume.take_unit_for(&mut stage)
        });
        assert_eq!(done, Some(UnitDone::Read { slot, unit }));
    }
    let predecessor = Suffix {
        session,
        start: 0,
        certified: 0,
        end: 16,
    };
    // The predecessor publishes the pass over its record: the cut is the proof's and its suffix, ending above the
    // cut, stays in the ancestry.
    let records = suffix_store(predecessor);
    let mut host = client(&records);
    let read = host
        .read::<ShardRecord>(super::super::super::store::Key::Shard(shard()))
        .unwrap();
    let target = Own::of(read.value());
    let published = super::super::super::checkpoint::publish(
        &mut host,
        &mut possible,
        &read,
        (target, Some(named())),
        (&proof, storage.capture_epoch()),
        &mut stage,
    )
    .expect("a pass whose snapshot member left through a recorded removal publishes");
    assert_eq!(
        (published.value().cut, published.value().ancestry.as_slice()),
        (cut, &[predecessor][..])
    );
    assert_eq!(published.value().checkpoint, Some(stage.named()));
    let named = stage.named();
    drop(dev);
    let mut card = Card::new(c_pair(), &a_holds_c_registered());
    takeover(
        &records,
        &store,
        (c_host(), &mut card, &stored_c()),
        |storage, volume, control| {
            load(volume, control);
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
            live(storage, volume);
            let hit = |volume: &mut _, n: u8| served(storage, volume, control, &key(n));
            let mut budget = WorkBudget::new(1 << 20);
            assert_eq!(
                storage.invalidate(&key(3), 4, &mut budget).err(),
                Some(super::super::super::InvalidateError::History),
                "the required suffix refuses a removal before it opens"
            );
            assert_eq!(
                hit(volume, 1),
                Some(bytes(&key(1), &[0x11; 40])),
                "the REPLACE applies"
            );
            assert_eq!(
                hit(volume, 2),
                None,
                "the recorded REMOVE excludes the checkpoint's member"
            );
            assert_eq!(hit(volume, 3), Some(bytes(&key(3), &[3; 40])));
            assert_eq!(
                hit(volume, 4),
                Some(bytes(&key(4), &[4; 40])),
                "the INSERT after the cut applies"
            );

            // The successor certifies the predecessor's suffix, records its own and opens its log.
            let ends = volume.certified().unwrap_or_default();
            assert_eq!(
                ends,
                [(session, durable)],
                "the load read the predecessor's blocks whole to its hole"
            );
            let successor = volume.authority.session().get();
            let mut host = client(&records);
            let mut possible = PossiblyNamed::new((shard(), successor), layout(), Some(named));
            let read = host
                .read::<ShardRecord>(super::super::super::store::Key::Shard(shard()))
                .unwrap();
            let own = Own::of(read.value());
            let bounds = SuffixBounds {
                limits: LIMITS,
                step: 2,
                margin: 1,
            };
            let (read, opened) = open_suffix(
                &mut host,
                &mut possible,
                (read, own),
                (storage, &ends),
                bounds,
            )
            .unwrap();
            assert!(opened);
            let mine = Suffix {
                session: successor,
                start: 16,
                certified: 16,
                end: 18,
            };
            assert_eq!(
                read.value().ancestry.as_slice(),
                [
                    Suffix {
                        certified: durable,
                        ..predecessor
                    },
                    mine
                ]
            );
            assert_eq!(storage.with_suffix(|log| log.recorded()), Ok(mine));

            // A removal in the successor's tenure is recorded, written at its unit and certified by the store step.
            let mut budget = WorkBudget::new(1 << 20);
            assert!(
                storage
                    .invalidate(&key(3), 4, &mut budget)
                    .unwrap()
                    .removed
                    .is_some()
            );
            settle(storage, volume, control);
            assert_eq!(storage.with_suffix(|log| log.durable()), Ok(17));
            assert!(
                delta_units(control).contains(&(DELTA + 16)),
                "LSN 16 lies at unit 16 mod 22 of the region"
            );
            let (read, due) = suffix_step(&mut host, &mut possible, (read, own), storage, bounds);
            let read = read.unwrap();
            assert_eq!(due, Some(SuffixDue::default()));
            assert_eq!(read.value().ancestry.as_slice()[1].certified, 17);
            // The head near the reserved end: the store records the extension first, and the log admits only up to
            // what the store committed.
            let identity = |n: u8| super::super::super::recovery::delta::Identity {
                key: key(n),
                allocation: 1,
                session: successor,
                version: 1,
            };
            storage
                .with_suffix(|log| {
                    let remove = Record::Remove {
                        identity: identity(9),
                        cause: Cause::Evict,
                    };
                    log.append(1, &remove).unwrap();
                    log.seal_cut();
                    assert!(log.needs_extension(bounds.margin));
                })
                .unwrap();
            let head = storage.with_suffix(|log| log.head()).unwrap();
            let read = suffix_step(&mut host, &mut possible, (read, own), storage, bounds)
                .0
                .unwrap();
            assert_eq!(read.value().ancestry.as_slice()[1].end, head + bounds.step);
            assert_eq!(
                storage.with_suffix(|log| log.recorded().end),
                Ok(head + bounds.step),
                "the log's reserved end is the store's"
            );
        },
    );

    // The control: the same pass with a suffix the tenure never required is unpublishable.
    let storage = super::sim_tests::storage(1);
    let buffers = arena_with(4, 9);
    let mut dev = cold(&storage, &buffers);
    for n in 1..=2 {
        drop(publish(&storage, &mut dev, &key(n), &[n; 40]).unwrap());
    }
    storage.start_capture(1024, true, 1024).unwrap();
    let counter = storage.pool().capture_lock().unwrap().counter();
    let mut budget = WorkBudget::new(1 << 20);
    assert!(
        storage
            .invalidate(&key(2), 4, &mut budget)
            .unwrap()
            .removed
            .is_some()
    );
    let _ = drain(&storage);
    assert_eq!(
        storage.cut_intact((shard(), session), counter).err(),
        Some(super::super::super::recovery::CaptureError::Released),
        "with a suffix the tenure never required, the invalidation of a snapshot member makes the pass unpublishable"
    );
}

/// A recorded removal keeps its pass publishable only under the capture epoch the pass started in: the proof publishes
/// under that epoch and refuses `Replaced` at a Publish under a later one, naming nothing, and once a wholesale
/// replacement advances the storage's epoch the same pass refuses `Replaced` at its proof, whatever the suffix recorded.
#[test]
fn a_recorded_removal_keeps_its_pass_publishable_only_under_the_capture_epoch_it_started_in() {
    use super::super::super::checkpoint::tests::{SESSION, published_capture};
    use super::super::super::checkpoint::{CaptureEpoch, WriteRefused};
    use super::super::super::recovery::CaptureError;
    let storage = storage(1);
    let buffers = arena_with(4, 9);
    let mut dev = tenure(&storage, &buffers, 16);
    for n in 1..=3 {
        drop(publish(&storage, &mut dev, &key(n), &[n; 40]).unwrap());
    }
    let tenure = (shard(), SESSION);
    let counter = storage.start_capture(1024, true, 1024).unwrap();
    let mut budget = WorkBudget::new(1 << 20);
    assert!(
        storage
            .invalidate(&key(2), 4, &mut budget)
            .unwrap()
            .removed
            .is_some()
    );
    let entries = drain(&storage);
    assert_eq!(entries.len(), 3, "the side list keeps the removed member");
    let proof = storage
        .cut_intact(tenure, counter)
        .expect("a recorded removal keeps the pass publishable");
    let epoch = storage.capture_epoch();
    assert_eq!(proof.epoch(), epoch);
    assert_eq!(
        published_capture(&entries, (&proof, CaptureEpoch(epoch.0 + 1))),
        (Err(WriteRefused::Replaced), None),
        "a proof of an earlier epoch publishes nothing though its removal was recorded"
    );
    let (published, named) = published_capture(&entries, (&proof, epoch));
    assert_eq!(published, Ok(()));
    assert_eq!(named.map(|ck| ck.capture), Some(counter));
    // A recorded removal of a member the walk already passed keeps the pass provable.
    assert!(
        storage
            .invalidate(&key(3), 4, &mut budget)
            .unwrap()
            .removed
            .is_some()
    );
    assert_eq!(
        storage.cut_intact(tenure, counter).map(|again| again.cut()),
        Ok(proof.cut())
    );
    storage.pool().replaced();
    assert_eq!(
        storage.cut_intact(tenure, counter),
        Err(CaptureError::Replaced),
        "a replacement after the start leaves the pass unprovable though its removal was recorded"
    );
    drop(dev);
}

/// A checkpoint of the predecessor's session at slot 0 below every pass counter, which the store step tests'
/// records name.
fn named() -> NamedCheckpoint {
    NamedCheckpoint {
        slot: 0,
        session: predecessor_session().get(),
        capture: 0,
        units: 1,
    }
}

/// The store of the predecessor's record naming [`named`] at cut 0, and the set that knows it.
fn named_store() -> (Shared, PossiblyNamed) {
    let shard = ShardRecord {
        checkpoint: Some(named()),
        ..restart_tests::shard_record(4)
    };
    let possible = PossiblyNamed::new(
        (
            super::super::super::store_tests::shard(),
            predecessor_session().get(),
        ),
        layout(),
        Some(named()),
    );
    (
        restart_tests::store(shard, restart_tests::volume_record()),
        possible,
    )
}

/// The successor's log opens only over the suffix the store committed; a record naming no checkpoint, which
/// restart and takeover refuse beside a suffix, gets no reservation and leaves the log closed; an outage of the
/// reservation's write leaves the log closed, and a later call opens it.
#[test]
fn open_suffix_opens_the_log_only_over_a_committed_reservation() {
    let storage = storage(1);
    let session = predecessor_session().get();
    let bounds = SuffixBounds {
        limits: LIMITS,
        step: 4,
        margin: 1,
    };
    let bare = restart_tests::store(
        restart_tests::shard_record(4),
        restart_tests::volume_record(),
    );
    let mut host = client(&bare);
    let record = super::super::super::store::Key::Shard(shard());
    let read = host.read::<ShardRecord>(record).unwrap();
    let version = read.version();
    let own = Own::of(read.value());
    let mut possible = PossiblyNamed::new((shard(), session), layout(), None);
    let (read, opened) = open_suffix(
        &mut host,
        &mut possible,
        (read, own),
        (&storage, &[]),
        bounds,
    )
    .unwrap();
    assert!(!opened, "a record naming no checkpoint opens no suffix");
    assert_eq!(read.version(), version, "and records none");
    assert_eq!(host.read::<ShardRecord>(record).unwrap().version(), version);
    let (records, mut possible) = named_store();
    let mut host = client(&records);
    let read = host.read::<ShardRecord>(record).unwrap();
    records.schedule(Arm::Unavailable);
    assert!(
        open_suffix(
            &mut host,
            &mut possible,
            (read, own),
            (&storage, &[]),
            bounds
        )
        .is_err()
    );
    assert_eq!(storage.with_suffix(|log| log.is_open()), Ok(false));
    // A busy capture mutex leaves the log closed after the reservation committed; the next call opens
    // over that reservation and reserves nothing more.
    let read = host
        .read::<ShardRecord>(super::super::super::store::Key::Shard(shard()))
        .unwrap();
    let held = storage.pool().capture_lock().unwrap();
    let (read, opened) = open_suffix(
        &mut host,
        &mut possible,
        (read, own),
        (&storage, &[]),
        bounds,
    )
    .unwrap();
    drop(held);
    assert!(!opened, "a busy mutex leaves the log closed");
    let reserved = read.value().ancestry.as_slice().to_vec();
    let (read, opened) = open_suffix(
        &mut host,
        &mut possible,
        (read, own),
        (&storage, &[]),
        bounds,
    )
    .unwrap();
    assert!(opened);
    assert_eq!(
        read.value().ancestry.as_slice(),
        reserved,
        "the retry reserved nothing more"
    );
    assert_eq!(
        read.value().ancestry.as_slice(),
        [Suffix {
            session,
            start: 0,
            certified: 0,
            end: 4
        }]
    );
}

/// While the open block waits its flush interval the tick is not ready and the writer takes
/// no capture-mutex try on any call; once the interval passes the tick wakes with no other work, seals and writes
/// the block with one try per stage, and an idle log leaves the tick idle.
#[test]
fn an_open_block_wakes_the_tick_once_its_flush_interval_passes_and_no_earlier_call_tries_the_mutex()
{
    let storage = storage(1);
    let buffers = arena_with(4, 9);
    let mut dev = tenure(&storage, &buffers, 16);
    let limits = SuffixLimits {
        flush_ns: 10,
        ..LIMITS
    };
    let own = Suffix {
        session: predecessor_session().get(),
        start: 0,
        certified: 0,
        end: 16,
    };
    let mut log = super::super::super::recovery::suffix::SuffixLog::default();
    assert!(log.open((Crc32c::detect(), shard()), (limits, &layout()), own, 0));
    storage.with_suffix(|current| *current = log).unwrap();
    storage.platform.ticks(&[Some(1)]);
    drop(publish(&storage, &mut dev, &key(1), &[1; 40]).unwrap());
    let tries = || super::super::checkpoint::DELTA_TRIES.with(std::cell::Cell::get);
    let before = tries();
    for _ in 0..8 {
        assert!(
            !dev.volume.metadata_ready(),
            "the open block's flush time has not passed"
        );
        tick(&mut dev.volume, &dev.control);
        dev.volume.stage_delta();
    }
    assert_eq!(
        tries(),
        before,
        "no call tried the capture mutex before the flush time"
    );
    assert!(
        delta_units(&dev.control).is_empty(),
        "the interval has not passed"
    );
    storage.platform.ticks(&[Some(20)]);
    assert!(dev.volume.metadata_ready(), "the flush time wakes the tick");
    settle(&storage, &mut dev.volume, &dev.control);
    assert!(
        tries() - before <= 3,
        "seal and stage, then the result: {}",
        tries() - before
    );
    assert_eq!(delta_units(&dev.control), [DELTA]);
    assert!(
        !dev.volume.metadata_ready(),
        "an idle log leaves the tick idle"
    );
    // With every maintenance buffer taken, a sealed block waits one flush interval between tries.
    let mut taken = Vec::new();
    while let Ok(buffer) = buffers.acquire(super::super::super::device::PoolKind::Maintenance) {
        taken.push(buffer);
    }
    drop(publish(&storage, &mut dev, &key(2), &[2; 40]).unwrap());
    storage.platform.ticks(&[Some(40)]);
    let before = tries();
    for _ in 0..8 {
        tick(&mut dev.volume, &dev.control);
        dev.volume.stage_delta();
    }
    assert_eq!(
        tries() - before,
        1,
        "one try, then the block waits the flush interval"
    );
    drop(taken);
    storage.platform.ticks(&[Some(60)]);
    settle(&storage, &mut dev.volume, &dev.control);
    assert_eq!(delta_units(&dev.control), [DELTA, DELTA + 1]);
}

/// The close's drain ends every mapping without recording a removal, so a successor's replay of the suffix keeps
/// the drained entries.
#[test]
fn the_close_drain_records_no_removal() {
    let storage = storage(1);
    let buffers = arena_with(4, 9);
    let mut dev = tenure(&storage, &buffers, 16);
    drop(publish(&storage, &mut dev, &key(1), &[1; 40]).unwrap());
    settle(&storage, &mut dev.volume, &dev.control);
    storage.close();
    let removed: usize = (0..16)
        .map(|_| {
            storage
                .close_service(&mut WorkBudget::new(1 << 16))
                .map_or(0, |report| report.removed)
        })
        .sum();
    assert_eq!(removed, 1, "the drain ended the mapping");
    let pool = storage.pool();
    assert_eq!(
        pool.suffix_tail.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "no removal was recorded"
    );
    assert!(
        pool.capture_lock().unwrap().suffix.idle(),
        "the suffix holds no record"
    );
}

/// An eviction and an expiry of an open suffix each record one REMOVE with their own cause before
/// the mapping clears, and the removed slot's units wait until that block persisted; with the log at its reserved
/// end, an expiry the suffix refuses keeps the entry a member, though new lookups no longer hit it, and maintenance
/// counts it as a suffix refusal, done until the suffix advances.
#[test]
fn an_eviction_and_an_expiry_record_their_removes_and_hold_their_slots_until_durable() {
    use super::super::super::evict::Commit;
    use super::super::super::evict_tests::generous;
    const SECOND: u64 = 1_000_000_000;
    let storage = storage(1);
    let buffers = arena_with(4, 9);
    let mut dev = tenure(&storage, &buffers, 16);
    drop(expiring(&storage, &mut dev, 1, u64::MAX));
    let leased = expiring(&storage, &mut dev, 2, 5 * SECOND);
    settle(&storage, &mut dev.volume, &dev.control);
    serve(&storage);
    let removal = |dev: &mut Device<'_, '_>, commit: Option<Commit>, cause: Cause, n: u8| {
        assert!(matches!(commit, Some(Commit::Evicted { .. })), "{commit:?}");
        let lsn = storage.with_suffix(|log| log.head()).unwrap();
        serve(&storage);
        let free = units(&storage).0;
        fail_first_write(dev, lsn);
        for pass in 0.. {
            let prefix =
                (dev.volume.journal_words.prefix).load(std::sync::atomic::Ordering::Acquire);
            if prefix > lsn {
                break;
            }
            assert!(pass < 64, "the resent {cause:?} block persists");
            serve(&storage);
            assert_eq!(
                units(&storage).0,
                free,
                "the {cause:?} slot waits for its REMOVE block"
            );
            tick(&mut dev.volume, &dev.control);
        }
        assert!(
            matches!(block_records(&dev.control, lsn)[..],
                [Record::Remove { identity, cause: recorded }] if identity.key == key(n) && recorded == cause),
            "{:?}",
            block_records(&dev.control, lsn)
        );
        serve(&storage);
        assert!(
            units(&storage).0 > free,
            "the {cause:?} slot returned once its block persisted"
        );
    };
    // The lease keeps key 2 resident, so the hand's victim is key 1.
    let evicted = (0..4)
        .find_map(|_| {
            storage
                .evict_step(&mut generous(), |_, _| true)
                .unwrap()
                .commit
        })
        .filter(|commit| matches!(commit, Commit::Evicted { .. }));
    removal(&mut dev, evicted, Cause::Evict, 1);
    drop(leased);
    serve(&storage);
    storage.platform.ticks(&[Some(10 * SECOND)]);
    let expired = storage.expire_step(&mut generous()).unwrap().commit;
    removal(&mut dev, expired, Cause::Expire, 2);

    // At the reserved end the expiry is refused, the entry stays a member and maintenance counts the refusal.
    let marks = super::super::config::VolumeWatermarks {
        low_units: 4,
        min_free_slots: 1,
        retired_units: u64::MAX,
    };
    let storage = super::sim_tests::storage_with(1, Some(marks));
    let buffers = arena_with(4, 9);
    let mut dev = tenure(&storage, &buffers, 1);
    drop(expiring(&storage, &mut dev, 3, 5 * SECOND));
    settle(&storage, &mut dev.volume, &dev.control);
    serve(&storage);
    let tail = storage
        .pool()
        .suffix_tail
        .load(std::sync::atomic::Ordering::Relaxed);
    storage.platform.ticks(&[Some(10 * SECOND)]);
    assert_eq!(
        storage.expire_step(&mut generous()).unwrap().commit,
        Some(Commit::History)
    );
    let maintained = storage.maintain(&mut WorkBudget::new(1 << 20)).unwrap();
    let super::super::super::Maintained::Open(report) = maintained else {
        panic!("{maintained:?}")
    };
    assert_eq!(report.suffix_refused, 1);
    assert!(
        report.expiry.done,
        "a suffix refusal is no contention to retry"
    );
    assert_eq!(
        storage
            .pool()
            .suffix_tail
            .load(std::sync::atomic::Ordering::Relaxed),
        tail
    );
    let mut reader = storage.register().unwrap();
    assert!(
        lookup(&mut reader, &key(3), 4).is_err(),
        "an expired entry no longer hits"
    );
    assert_eq!(
        storage
            .pool()
            .eligible
            .load(std::sync::atomic::Ordering::Relaxed),
        1,
        "it stays a member"
    );
}

/// The waiting set: a retired slot that no right holds and that waits only for its unwritten block is visited once
/// and then left unvisited while the durable prefix stands; a slot a lease holds is visited by every call, a new
/// retirement is the only slot the next call visits, every call still reports each waiting slot, and once the block
/// persists one pass visits and returns them all.
#[test]
fn a_retired_slot_waiting_for_its_block_is_visited_once_until_the_prefix_moves() {
    let storage = storage(1);
    let buffers = arena_with(4, 9);
    let mut dev = tenure(&storage, &buffers, 16);
    for n in 1..=3 {
        drop(publish(&storage, &mut dev, &key(n), &[n; 40]).unwrap());
    }
    settle(&storage, &mut dev.volume, &dev.control);
    serve(&storage);
    let free = units(&storage).0;
    let slots = storage.pool().records().len();
    let invalidate = |n: u8| {
        let ended = storage.invalidate(&key(n), 4, &mut WorkBudget::new(1 << 20));
        assert!(ended.unwrap().removed.is_some());
    };
    let service = || storage.service(&mut WorkBudget::new(1 << 10)).unwrap();
    // The REMOVE records wait in the open block, which no tick has sealed. A lease holds key 1's retired slot by a
    // right, so every call visits that slot; key 2's slot waits for the block alone and is visited once.
    let mut reader = storage.register().unwrap();
    let lease = lookup(&mut reader, &key(1), 4).unwrap();
    invalidate(1);
    invalidate(2);
    serve(&storage);
    for _ in 0..2 {
        let walked = service();
        assert_eq!((walked.visited, walked.held), (1, 1), "{walked:?}");
        assert_eq!(walked.awaiting_journal, 1);
    }
    // With the lease gone key 1's slot waits for the block too, and after the visit that finds it no call visits
    // either slot.
    drop(lease);
    serve(&storage);
    for _ in 0..3 {
        let idle = service();
        assert_eq!((idle.visited, idle.awaiting_journal), (0, 2), "{idle:?}");
        assert!(idle.pending && !idle.budget_exhausted);
        assert_eq!((idle.covered, idle.park_covered), (slots, slots));
    }
    assert_eq!(units(&storage).0, free, "no waiting slot returned");

    // A third retirement is the one slot the next calls visit, until it waits for the block as well.
    invalidate(3);
    let walked = service();
    assert_eq!((walked.visited, walked.serviced), (1, 0), "{walked:?}");
    serve(&storage);
    let idle = service();
    assert_eq!((idle.visited, idle.awaiting_journal), (0, 3));

    // The block persists and the prefix moves: the next pass visits the three slots and returns them.
    settle(&storage, &mut dev.volume, &dev.control);
    let returned = service();
    assert_eq!(
        (
            returned.visited,
            returned.serviced,
            returned.awaiting_journal
        ),
        (3, 3, 0),
        "{returned:?}"
    );
    assert!(units(&storage).0 > free);
    assert!(!service().pending, "nothing is left to return");
}

/// The store step clamps every extension to the log's capacity, so the store never refuses one; the
/// durable prefix is certified whatever the extension does, and the handoff signal rises once the head nears
/// `start + J`.
#[test]
fn suffix_step_clamps_its_extension_to_the_capacity_and_certifies_up_to_the_handoff() {
    let storage = storage(1);
    let (records, mut possible) = named_store();
    let mut host = client(&records);
    let record = super::super::super::store::Key::Shard(shard());
    let read = host.read::<ShardRecord>(record).unwrap();
    let own = Own::of(read.value());
    let session = predecessor_session().get();
    let bounds = SuffixBounds {
        limits: LIMITS,
        step: 5,
        margin: 2,
    };
    let (mut read, opened) = open_suffix(
        &mut host,
        &mut possible,
        (read, own),
        (&storage, &[]),
        bounds,
    )
    .unwrap();
    assert!(opened);
    let identity = super::super::super::recovery::delta::Identity {
        key: key(1),
        allocation: 1,
        session,
        version: 1,
    };
    let remove = Record::Remove {
        identity,
        cause: Cause::Evict,
    };
    let mut due = SuffixDue::default();
    for _ in 0..64 {
        // One block per round, written at once, so the durable prefix follows the head.
        let appended = storage
            .with_suffix(|log| {
                let appended = log.append(1, &remove).is_ok();
                log.seal_cut();
                if let Some((lsn, _)) = take(log) {
                    log.written(lsn);
                }
                appended
            })
            .unwrap();
        let stepped = suffix_step(&mut host, &mut possible, (read, own), &storage, bounds);
        read = stepped.0.expect("the store admits every clamped extension");
        due = stepped.1.expect("the step sampled the log");
        if !appended && due.handoff {
            break;
        }
    }
    let ancestry = read.value().ancestry.as_slice();
    let capacity = storage.with_suffix(|log| log.capacity()).unwrap();
    assert_eq!(capacity, 22, "J of the layout from start 0 and floor 0");
    assert_eq!(
        ancestry[0].end, capacity,
        "the reserved end stops at the capacity"
    );
    assert_eq!(
        ancestry[0].certified,
        storage.with_suffix(|log| log.durable()).unwrap(),
        "the durable prefix is certified"
    );
    assert!(due.handoff, "the head nears start + J");
    assert!(
        !due.publication,
        "the capacity is the tenure's bound, which a publish does not raise"
    );
}

/// A block whose writes keep failing ends the metadata `MetadataFailed` once its failures pass
/// `metadata_retries`, which closes admission, rather than resubmitting it on every turn; an earlier block's failure
/// followed by its persistence leaves the next block its whole retry budget.
#[test]
fn a_delta_block_that_keeps_failing_ends_the_metadata_after_its_retries() {
    let storage = storage(1);
    let buffers = arena_with(4, 9);
    let mut dev = tenure(&storage, &buffers, 16);
    drop(publish(&storage, &mut dev, &key(1), &[1; 40]).unwrap());
    // The INSERT's block fails once and persists on its resend, which resets the failure count.
    fail_first_write(&mut dev, 0);
    settle(&storage, &mut dev.volume, &dev.control);
    let lsn = storage.with_suffix(|log| log.head()).unwrap();
    let mut budget = WorkBudget::new(1 << 20);
    assert!(
        storage
            .invalidate(&key(1), 4, &mut budget)
            .unwrap()
            .removed
            .is_some()
    );
    let retries = dev.volume.metadata.retries;
    // Every write of the REMOVE's block is faulted while pending.
    let (mut faulted, mut seen) = (0, 0);
    for _ in 0..256 {
        if dev.volume.metadata_outcome() != MetadataOutcome::Open {
            break;
        }
        tick(&mut dev.volume, &dev.control);
        let writes: Vec<_> = (submitted(&dev.control, Operation::Write).into_iter())
            .filter(|&(_, start)| start / IO_UNIT as u64 == DELTA + lsn)
            .collect();
        for &(token, _) in &writes[seen..] {
            dev.control
                .fault(token, Fault::Status(DeviceStatus::Kernel(-5)));
            faulted += 1;
        }
        seen = writes.len();
    }
    assert_eq!(
        faulted,
        retries as usize + 1,
        "one attempt and its retries, each failed"
    );
    assert_eq!(
        dev.volume.metadata_outcome(),
        MetadataOutcome::MetadataFailed
    );
    assert!(storage.is_closed(), "the failed suffix closes admission");
}

/// After a panic poisons the capture mutex the log closes, its sealed blocks drain to their units and the tick
/// publishes their prefix, the closed log stays required, so a fill and a removal refuse `History`, and a
/// checkpoint-unit command is admitted once no sealed block waits; the priority check takes no mutex.
#[test]
fn a_poisoned_capture_drains_its_blocks_and_then_admits_checkpoint_units() {
    let storage = storage(1);
    let buffers = arena_with(4, 9);
    let mut dev = tenure(&storage, &buffers, 16);
    drop(publish(&storage, &mut dev, &key(1), &[1; 40]).unwrap());
    storage.start_capture(1024, true, 1024).unwrap();
    let sealed = storage.with_suffix(|log| log.head()).unwrap();
    assert!(sealed > 0, "the capture start sealed the insert's block");
    let entries = drain(&storage);
    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = storage.pool().capture_lock().unwrap();
        panic!("a panic under the capture mutex");
    }));
    assert!(poisoned.is_err());
    settle_poisoned(&storage, &mut dev);
    assert_eq!(
        delta_units(&dev.control),
        (0..sealed).map(|lsn| DELTA + lsn).collect::<Vec<_>>(),
        "every sealed block landed at its unit"
    );
    assert_eq!(
        (dev.volume.journal_words.prefix).load(std::sync::atomic::Ordering::Acquire),
        sealed,
        "the tick published the drained prefix"
    );
    // The closed log stays required: a fill and a removal refuse `History` and change nothing.
    refused(&storage, &mut dev);
    let session = predecessor_session().get();
    let mut possible = PossiblyNamed::new((shard(), session), layout(), None);
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
    assert_eq!(
        dev.volume.stage_unit_write(&possible, &mut stage, 0),
        Ok(())
    );
}

/// Ticks a volume whose capture mutex is poisoned until its sealed blocks drained.
fn settle_poisoned(storage: &Storage<TestPlatform>, dev: &mut Device<'_, '_>) {
    for _ in 0..64 {
        tick(&mut dev.volume, &dev.control);
        let idle = storage
            .pool()
            .suffix_due
            .load(std::sync::atomic::Ordering::Relaxed)
            == u64::MAX;
        if idle
            && dev.volume.metadata.delta.is_none()
            && dev.volume.metadata.commands[JOURNAL].is_none()
        {
            return;
        }
    }
    panic!("the poisoned log drains");
}

/// A suffix the tenure required before it opened refuses every fill and removal `History`, changing nothing, and
/// an open with invalid limits keeps it required; once it opens, both are recorded.
#[test]
fn a_required_suffix_refuses_every_change_until_it_opens() {
    let storage = storage(1);
    let buffers = arena_with(4, 9);
    let mut dev = cold(&storage, &buffers);
    drop(publish(&storage, &mut dev, &key(1), &[1; 40]).unwrap());
    storage.require_suffix().unwrap();
    refused(&storage, &mut dev);
    let own = Suffix {
        session: predecessor_session().get(),
        start: 0,
        certified: 0,
        end: 16,
    };
    let open = |limits: SuffixLimits| {
        let open = (limits, &layout());
        (storage.with_suffix(|log| log.open((Crc32c::detect(), shard()), open, own, 0))).unwrap()
    };
    let invalid = SuffixLimits {
        uncertified: 0,
        ..LIMITS
    };
    assert!(!open(invalid));
    refused(&storage, &mut dev);
    assert!(open(LIMITS));
    drop(publish(&storage, &mut dev, &key(2), &[2; 40]).unwrap());
    let mut budget = WorkBudget::new(1 << 20);
    assert!(
        storage
            .invalidate(&key(1), 4, &mut budget)
            .unwrap()
            .removed
            .is_some()
    );
    settle(&storage, &mut dev.volume, &dev.control);
    let records: Vec<Record> = (0..storage.with_suffix(|log| log.durable()).unwrap())
        .flat_map(|lsn| block_records(&dev.control, lsn))
        .collect();
    assert!(
        matches!(records[..], [Record::Insert(ref insert), Record::Remove { identity, .. }]
            if insert.key == key(2) && identity.key == key(1)),
        "{records:?}"
    );
}

/// A fill and a removal of `key(1)`'s entry each refuse `History` and change no membership word or log state, and
/// the entry still serves.
fn refused<'s>(storage: &'s Storage<TestPlatform>, dev: &mut Device<'s, '_>) {
    let pool = storage.pool();
    let words = || {
        (
            pool.insert_step.load(std::sync::atomic::Ordering::Relaxed),
            pool.eligible.load(std::sync::atomic::Ordering::Relaxed),
            pool.suffix_tail.load(std::sync::atomic::Ordering::Relaxed),
            storage.with_suffix(|log| (log.head(), log.idle(), log.required())),
        )
    };
    let before = words();
    assert_eq!(
        publish(storage, dev, &key(2), &[2; 40]).err(),
        Some(FillPublishError::History)
    );
    let mut budget = WorkBudget::new(1 << 20);
    assert_eq!(
        storage.invalidate(&key(1), 4, &mut budget).err(),
        Some(super::super::super::InvalidateError::History)
    );
    assert_eq!(words(), before, "the refused changes changed nothing");
    assert_eq!(
        served(storage, &mut dev.volume, &dev.control, &key(1)),
        Some(bytes(&key(1), &[1; 40]))
    );
}

/// A Publish whose cut reached the reserved end drops the tenure's suffix from the record; the next store step
/// records a continuation from the cut, certifies and extends it, and the log admits again.
#[test]
fn a_publish_at_the_reserved_end_is_followed_by_a_continuation_of_the_suffix() {
    use super::super::super::checkpoint::tests::published_over;
    let storage = storage(1);
    let (records, mut possible) = named_store();
    let mut host = client(&records);
    let record = super::super::super::store::Key::Shard(shard());
    let read = host.read::<ShardRecord>(record).unwrap();
    let own = Own::of(read.value());
    let session = predecessor_session().get();
    let bounds = SuffixBounds {
        limits: LIMITS,
        step: 2,
        margin: 1,
    };
    let (read, opened) = open_suffix(
        &mut host,
        &mut possible,
        (read, own),
        (&storage, &[]),
        bounds,
    )
    .unwrap();
    assert!(opened);
    let remove = |n: u8| Record::Remove {
        identity: super::super::super::recovery::delta::Identity {
            key: super::super::super::publish_tests::key(n),
            allocation: 1,
            session,
            version: 1,
        },
        cause: Cause::Evict,
    };
    let append = |n: u8| {
        storage
            .with_suffix(|log| {
                let appended = log.append(1, &remove(n));
                log.seal_cut();
                if let Some((lsn, _)) = take(log) {
                    log.written(lsn);
                }
                appended.map(|_| ())
            })
            .unwrap()
    };
    assert_eq!((append(1), append(2)), (Ok(()), Ok(())));
    assert_eq!(
        append(3),
        Err(super::super::super::recovery::suffix::SuffixRefusal::Reserved)
    );
    let counter = storage.start_capture(1024, true, 1024).unwrap();
    let entries = drain(&storage);
    let proof = storage.cut_intact((shard(), session), counter).unwrap();
    assert_eq!(
        proof.cut(),
        2,
        "the pass sealed its cut at the reserved end"
    );
    let read = published_over(
        (&mut host, &mut possible),
        (&read, own, Some(named())),
        (&proof, storage.capture_epoch()),
        &entries,
    )
    .unwrap();
    assert_eq!(
        (read.value().cut, read.value().ancestry.as_slice()),
        (2, &[][..]),
        "the cut dropped the tenure's suffix"
    );
    let commits = || records.0.borrow().commit_count(&record);
    let before = commits();
    records.schedule(Arm::Pass);
    records.schedule(Arm::Unavailable);
    let (stepped, _) = suffix_step(&mut host, &mut possible, (read, own), &storage, bounds);
    records.0.borrow_mut().unschedule();
    let read = stepped.expect("the step needs no write after the continuation's");
    let continued = Suffix {
        session,
        start: 2,
        certified: 2,
        end: 4,
    };
    assert_eq!(read.value().ancestry.as_slice(), [continued]);
    assert_eq!(
        commits() - before,
        1,
        "the continuation's one write records its certified and reserved ends"
    );
    let recorded = storage.with_suffix(|log| log.recorded()).unwrap();
    assert_eq!(
        (recorded.certified, recorded.end),
        (2, 4),
        "the log holds the ends the continuation recorded"
    );
    assert_eq!(append(3), Ok(()), "the continued suffix admits again");
}

/// A Publish whose cut reached the tenure's bound of `J` blocks from its start drops the tenure's suffix; the next
/// store step writes nothing, keeps the handoff due and leaves the record's chain empty, so a successor's suffix
/// starts at the cut with all `J` blocks before it.
#[test]
fn a_publish_at_the_tenure_bound_is_followed_by_no_continuation() {
    use super::super::super::checkpoint::suffix_start;
    use super::super::super::checkpoint::tests::published_over;
    use super::super::super::recovery::suffix::SuffixRefusal;
    let storage = storage(1);
    let (records, mut possible) = named_store();
    let mut host = client(&records);
    let record = super::super::super::store::Key::Shard(shard());
    let read = host.read::<ShardRecord>(record).unwrap();
    let own = Own::of(read.value());
    let session = predecessor_session().get();
    let bounds = SuffixBounds {
        limits: LIMITS,
        step: 2,
        margin: 1,
    };
    let (mut read, opened) = open_suffix(
        &mut host,
        &mut possible,
        (read, own),
        (&storage, &[]),
        bounds,
    )
    .unwrap();
    assert!(opened);
    let start = storage.with_suffix(|log| log.recorded().start).unwrap();
    let bound = start + layout().units - DELTA;
    let remove = |n: u8| Record::Remove {
        identity: super::super::super::recovery::delta::Identity {
            key: super::super::super::publish_tests::key(n),
            allocation: 1,
            session,
            version: 1,
        },
        cause: Cause::Evict,
    };
    let append = |n: u8| {
        storage
            .with_suffix(|log| {
                let appended = log.append(1, &remove(n));
                log.seal_cut();
                if let Some((lsn, _)) = take(log) {
                    log.written(lsn);
                }
                appended.map(|_| ())
            })
            .unwrap()
    };
    // J appends, each refused at most once before a step extends or certifies past it.
    let mut n = 0;
    for attempt in 0.. {
        assert!(attempt < 64, "the log reaches its bound");
        match append(n) {
            Ok(()) => n += 1,
            Err(SuffixRefusal::Exhausted) => break,
            Err(SuffixRefusal::Reserved | SuffixRefusal::Uncertified) => {
                let (stepped, _) =
                    suffix_step(&mut host, &mut possible, (read, own), &storage, bounds);
                read = stepped.unwrap();
            }
            Err(refused) => panic!("{refused:?}"),
        }
    }
    assert_eq!(storage.with_suffix(|log| log.head()).unwrap(), bound);
    let counter = storage.start_capture(1024, true, 1024).unwrap();
    let entries = drain(&storage);
    let proof = storage.cut_intact((shard(), session), counter).unwrap();
    assert_eq!(proof.cut(), bound, "the pass sealed its cut at the bound");
    let read = published_over(
        (&mut host, &mut possible),
        (&read, own, Some(named())),
        (&proof, storage.capture_epoch()),
        &entries,
    )
    .unwrap();
    assert_eq!(
        (read.value().cut, read.value().ancestry.as_slice()),
        (bound, &[][..]),
        "the cut dropped the tenure's suffix"
    );
    let commits = || records.0.borrow().commit_count(&record);
    let before = commits();
    let (stepped, due) = suffix_step(&mut host, &mut possible, (read, own), &storage, bounds);
    let read = stepped.expect("the step writes nothing");
    assert_eq!(commits(), before, "no continuation past the bound");
    assert!(due.is_some_and(|due| due.handoff), "the handoff stays due");
    assert_eq!(read.value().ancestry.as_slice(), &[][..]);
    assert_eq!(
        suffix_start(read.value()),
        bound,
        "a successor's suffix starts at the cut"
    );
}

/// A headroom eviction the suffix refuses leaves its victim serving, and maintenance counts the refusal and ends the
/// stage with no more work, so the owner rests instead of retrying a removal no record fits.
#[test]
fn a_headroom_eviction_the_suffix_refuses_ends_the_stage_with_no_more_work() {
    let marks = super::super::config::VolumeWatermarks {
        low_units: 4,
        min_free_slots: 63,
        retired_units: u64::MAX,
    };
    let storage = super::sim_tests::storage_with(1, Some(marks));
    let buffers = arena_with(4, 9);
    let mut dev = tenure(&storage, &buffers, 16);
    for n in 1..=2 {
        drop(publish(&storage, &mut dev, &key(n), &[n; 40]).unwrap());
    }
    settle(&storage, &mut dev.volume, &dev.control);
    serve(&storage);
    // A closed log stays required, so it refuses every removal record.
    storage.with_suffix(SuffixLog::close).unwrap();
    let maintained = storage.maintain(&mut WorkBudget::new(1 << 20)).unwrap();
    let super::super::super::Maintained::Open(report) = maintained else {
        panic!("{maintained:?}")
    };
    assert_eq!(report.suffix_refused, 1, "{report:?}");
    assert!(report.headroom.done, "{report:?}");
    assert!(!report.more_work, "{report:?}");
    assert_eq!(
        served(&storage, &mut dev.volume, &dev.control, &key(1)),
        Some(bytes(&key(1), &[1; 40])),
        "the refused victim still serves"
    );
    assert_eq!(
        served(&storage, &mut dev.volume, &dev.control, &key(2)),
        Some(bytes(&key(2), &[2; 40]))
    );
}

/// A block write's terminal that arrives while a membership change holds the capture mutex stays parked, with the
/// durable prefix and the published prefix word unchanged, and the next stage after the mutex is free gives the same
/// result to the log.
#[test]
fn a_delta_terminal_parked_behind_a_held_capture_mutex_is_applied_once_the_mutex_is_free() {
    let storage = storage(1);
    let buffers = arena_with(4, 9);
    let mut dev = tenure(&storage, &buffers, 16);
    drop(publish(&storage, &mut dev, &key(1), &[1; 40]).unwrap());
    let lsn = storage.with_suffix(|log| log.head()).unwrap();
    storage.with_suffix(SuffixLog::seal_cut).unwrap();
    assert_eq!(
        (storage.pool().suffix_due).load(std::sync::atomic::Ordering::Relaxed),
        0,
        "the accessor publishes the sealed block's due time"
    );
    let staged = |dev: &Device<'_, '_>| {
        (dev.volume.metadata.commands[JOURNAL].as_ref()).map(|command| command.target)
    };
    for _ in 0..8 {
        if staged(&dev) == Some(Target::Delta(lsn)) {
            break;
        }
        tick(&mut dev.volume, &dev.control);
    }
    assert_eq!(staged(&dev), Some(Target::Delta(lsn)));
    let prefix = || (dev.volume.journal_words.prefix).load(std::sync::atomic::Ordering::Acquire);
    let before = prefix();
    let held = storage.pool().capture_lock().unwrap();
    for _ in 0..4 {
        tick(&mut dev.volume, &dev.control);
    }
    assert_eq!(
        dev.volume.metadata.delta,
        Some((lsn, true)),
        "the terminal is parked"
    );
    let possible = PossiblyNamed::new((shard(), predecessor_session().get()), layout(), None);
    assert_eq!(
        dev.volume.stage_unit_read(&possible, (0, 0)),
        Err(UnitRefused::Busy),
        "a checkpoint unit waits behind the parked result"
    );
    assert_eq!(prefix(), before, "no stage gave the log the result");
    assert_eq!(held.suffix.durable(), lsn);
    drop(held);
    settle(&storage, &mut dev.volume, &dev.control);
    assert_eq!(storage.with_suffix(|log| log.durable()), Ok(lsn + 1));
    assert_eq!(prefix(), lsn + 1);
}

/// A delta write the device refuses for good while it stays live parks a failed result: the metadata stays open, the
/// durable prefix stays put and the removed slot stays held, and the next stage resends the retained block to its
/// own unit, whose persistence then returns the slot.
#[test]
fn a_delta_write_the_device_refuses_keeps_its_block_and_the_next_stage_resends_it() {
    use super::super::super::device::{RefusalReason, SubmitRefusal};
    let storage = storage(1);
    let buffers = arena_with(4, 9);
    let mut dev = tenure(&storage, &buffers, 16);
    drop(publish(&storage, &mut dev, &key(1), &[1; 40]).unwrap());
    settle(&storage, &mut dev.volume, &dev.control);
    serve(&storage);
    let free = units(&storage).0;
    let remove = storage.with_suffix(|log| log.head()).unwrap();
    let mut budget = WorkBudget::new(1 << 20);
    assert!(
        storage
            .invalidate(&key(1), 4, &mut budget)
            .unwrap()
            .removed
            .is_some()
    );
    dev.control.refuse_next(SubmitRefusal {
        reason: RefusalReason::InvalidRange,
        code: None,
    });
    let prefix = || (dev.volume.journal_words.prefix).load(std::sync::atomic::Ordering::Acquire);
    for _ in 0..8 {
        if dev.volume.metadata.delta == Some((remove, false)) {
            break;
        }
        tick(&mut dev.volume, &dev.control);
    }
    assert_eq!(
        dev.volume.metadata.delta,
        Some((remove, false)),
        "the refusal parked a failed result"
    );
    assert_eq!(dev.volume.metadata_outcome(), MetadataOutcome::Open);
    assert_eq!(prefix(), remove);
    serve(&storage);
    assert_eq!(
        units(&storage).0,
        free,
        "the slot waits for its REMOVE block"
    );
    settle(&storage, &mut dev.volume, &dev.control);
    assert_eq!(prefix(), remove + 1);
    assert_eq!(
        delta_units(&dev.control)
            .iter()
            .filter(|&&unit| unit == DELTA + remove)
            .count(),
        1,
        "the refused submit wrote nothing and the resend wrote the block once"
    );
    assert!(matches!(
        block_records(&dev.control, remove)[..],
        [Record::Remove { identity, cause: Cause::Invalidate }] if identity.key == key(1)
    ));
    serve(&storage);
    assert!(
        units(&storage).0 > free,
        "the slot returned once its block persisted"
    );
}

/// The recovery I/O share counts a suffix block once for each time the log hands it out for writing: a delta write
/// the device refuses for good keeps its block's bytes in the share window, and the resend charges the block again,
/// so the window's peak reads three blocks where the device accepted two. Every poll of the fixture reads tick 0, so
/// the three charges fall in the share's first window.
#[test]
fn a_delta_block_the_device_refuses_counts_in_the_share_window_once_for_each_take() {
    use super::super::super::device::{RefusalReason, SubmitRefusal};
    const BLOCK: u64 = IO_UNIT as u64;
    let storage = storage(1);
    let buffers = arena_with(4, 9);
    let mut dev = tenure(&storage, &buffers, 16);
    drop(publish(&storage, &mut dev, &key(1), &[1; 40]).unwrap());
    settle(&storage, &mut dev.volume, &dev.control);
    let window = |dev: &Device<'_, '_>| {
        let report = dev.volume.recovery_report();
        (report.io_peak_bytes, report.io_saturated_windows)
    };
    let commands = |dev: &Device<'_, '_>| {
        let report = &dev.volume.report;
        (report.metadata_refused, report.metadata_submitted)
    };
    assert_eq!(window(&dev), (BLOCK, 0), "the INSERT's block");
    let (refused, submitted) = commands(&dev);
    let remove = storage.with_suffix(|log| log.head()).unwrap();
    let mut budget = WorkBudget::new(1 << 20);
    assert!(
        storage
            .invalidate(&key(1), 4, &mut budget)
            .unwrap()
            .removed
            .is_some()
    );
    dev.control.refuse_next(SubmitRefusal {
        reason: RefusalReason::InvalidRange,
        code: None,
    });
    for _ in 0..8 {
        if dev.volume.metadata.delta == Some((remove, false)) {
            break;
        }
        tick(&mut dev.volume, &dev.control);
    }
    assert_eq!(dev.volume.metadata.delta, Some((remove, false)));
    assert_eq!(commands(&dev), (refused + 1, submitted));
    assert_eq!(
        window(&dev),
        (2 * BLOCK, 0),
        "the refused write keeps its block's charge"
    );
    settle(&storage, &mut dev.volume, &dev.control);
    assert_eq!(commands(&dev), (refused + 1, submitted + 1));
    assert_eq!(
        window(&dev),
        (3 * BLOCK, 0),
        "the resend charges the block again"
    );
    assert_eq!(
        delta_units(&dev.control),
        [DELTA + remove - 1, DELTA + remove],
        "the device accepted one write of each block"
    );
}

/// The store step moves the log only after the store committed: with certification and extension both due, a
/// certification the store leaves unknown moves neither of the log's ends, an extension it leaves unknown leaves the
/// reserved end where it was while the committed certification reaches the log, each step still returns its
/// handoff signal, and a later step extends both.
#[test]
fn a_store_step_whose_extension_the_store_refuses_leaves_the_log_at_the_committed_end() {
    let storage = storage(1);
    let (records, mut possible) = named_store();
    let mut host = client(&records);
    let record = super::super::super::store::Key::Shard(shard());
    let read = host.read::<ShardRecord>(record).unwrap();
    let own = Own::of(read.value());
    let session = predecessor_session().get();
    let bounds = SuffixBounds {
        limits: LIMITS,
        step: 2,
        margin: 21,
    };
    let (read, opened) = open_suffix(
        &mut host,
        &mut possible,
        (read, own),
        (&storage, &[]),
        bounds,
    )
    .unwrap();
    assert!(opened);
    let remove = Record::Remove {
        identity: super::super::super::recovery::delta::Identity {
            key: key(1),
            allocation: 1,
            session,
            version: 1,
        },
        cause: Cause::Evict,
    };
    storage
        .with_suffix(|log| {
            log.append(1, &remove).unwrap();
            log.seal_cut();
            let (lsn, _) = take(log).unwrap();
            log.written(lsn);
            assert!(log.needs_extension(bounds.margin));
        })
        .unwrap();
    let before = storage.with_suffix(|log| log.recorded()).unwrap();
    // A certification the store leaves unknown moves neither of the log's ends, and the step keeps its signals.
    records.schedule(Arm::Unavailable);
    let (refused, due) = suffix_step(&mut host, &mut possible, (read, own), &storage, bounds);
    assert!(refused.is_err(), "the certification's write is unknown");
    assert_eq!(storage.with_suffix(|log| log.recorded()), Ok(before));
    assert_eq!(
        due,
        Some(SuffixDue {
            handoff: true,
            publication: false
        }),
        "head 1 lies within the margin 21 of start + J = 22"
    );
    let read = host.read::<ShardRecord>(record).unwrap();
    records.schedule(Arm::Pass);
    records.schedule(Arm::Unavailable);
    let (refused, due) = suffix_step(&mut host, &mut possible, (read, own), &storage, bounds);
    assert!(refused.is_err(), "the extension's write is unknown");
    assert_eq!(
        due,
        Some(SuffixDue {
            handoff: true,
            publication: false
        }),
        "a refused write keeps the signals"
    );
    let after = storage.with_suffix(|log| log.recorded()).unwrap();
    assert_eq!(
        after.end, before.end,
        "the log admits nothing the store did not commit"
    );
    assert_eq!(
        after.certified, 1,
        "the committed certification reached the log"
    );

    let read = host.read::<ShardRecord>(record).unwrap();
    let read = suffix_step(&mut host, &mut possible, (read, own), &storage, bounds)
        .0
        .unwrap();
    assert_eq!(read.value().ancestry.as_slice()[0].end, 3);
    assert_eq!(storage.with_suffix(|log| log.recorded().end), Ok(3));
}

/// A store step that finds the capture mutex held samples nothing: it returns its read with no store write and no
/// signal, where the next step over the same log samples it and returns the due handoff. A log that never opened is
/// sampled, and its step returns the clear signal.
#[test]
fn a_store_step_that_finds_the_capture_mutex_held_returns_no_signal() {
    let storage = storage(1);
    let (records, mut possible) = named_store();
    let mut host = client(&records);
    let record = super::super::super::store::Key::Shard(shard());
    let read = host.read::<ShardRecord>(record).unwrap();
    let own = Own::of(read.value());
    let bounds = SuffixBounds {
        limits: LIMITS,
        step: 2,
        margin: 21,
    };
    let (unopened, due) = suffix_step(&mut host, &mut possible, (read, own), &storage, bounds);
    let read = unopened.unwrap();
    assert_eq!(due, Some(SuffixDue::default()), "a sampled closed log");
    let (read, opened) = open_suffix(
        &mut host,
        &mut possible,
        (read, own),
        (&storage, &[]),
        bounds,
    )
    .unwrap();
    assert!(opened);
    let remove = Record::Remove {
        identity: super::super::super::recovery::delta::Identity {
            key: key(1),
            allocation: 1,
            session: predecessor_session().get(),
            version: 1,
        },
        cause: Cause::Evict,
    };
    storage
        .with_suffix(|log| {
            log.append(1, &remove).unwrap();
            log.seal_cut();
            let (lsn, _) = take(log).unwrap();
            log.written(lsn);
        })
        .unwrap();
    let commits = || records.0.borrow().commit_count(&record);
    let (version, before) = (read.version(), commits());
    let held = storage.pool().capture_lock().unwrap();
    let (stepped, due) = suffix_step(&mut host, &mut possible, (read, own), &storage, bounds);
    drop(held);
    let read = stepped.expect("a step that samples nothing refuses nothing");
    assert_eq!((read.version(), commits()), (version, before));
    assert_eq!(due, None, "a step that sampled nothing returns no signal");
    let (_, due) = suffix_step(&mut host, &mut possible, (read, own), &storage, bounds);
    assert_eq!(
        due,
        Some(SuffixDue {
            handoff: true,
            publication: false
        }),
        "head 1 lies within the margin 21 of start + J = 22"
    );
}

/// While a Publish of unknown outcome keeps a second slot possibly named, the floor is unsettled, so open_suffix over
/// the tenure's committed suffix writes nothing and leaves the log closed; a write of the tenure's own that settles
/// the set lets it open.
#[test]
fn open_suffix_leaves_the_log_closed_while_another_slot_stays_possibly_named() {
    use super::super::super::checkpoint::tests::published_over;
    use super::super::super::checkpoint::{WriteRefused, confirm, settled_floor};
    use super::super::super::store::StoreError;
    let storage = storage(1);
    let (records, mut possible) = named_store();
    let mut host = client(&records);
    let record = super::super::super::store::Key::Shard(shard());
    let read = host.read::<ShardRecord>(record).unwrap();
    let own = Own::of(read.value());
    let session = predecessor_session().get();
    let bounds = SuffixBounds {
        limits: LIMITS,
        step: 2,
        margin: 1,
    };
    // A busy mutex leaves the log closed over the committed reservation.
    let held = storage.pool().capture_lock().unwrap();
    let (read, opened) = open_suffix(
        &mut host,
        &mut possible,
        (read, own),
        (&storage, &[]),
        bounds,
    )
    .unwrap();
    drop(held);
    assert!(!opened);
    let counter = storage.start_capture(1024, true, 1024).unwrap();
    let entries = drain(&storage);
    let proof = storage.cut_intact((shard(), session), counter).unwrap();
    records.schedule(Arm::Hold);
    assert_eq!(
        published_over(
            (&mut host, &mut possible),
            (&read, own, Some(named())),
            (&proof, storage.capture_epoch()),
            &entries,
        )
        .map(|_| ()),
        Err(WriteRefused::Store(StoreError::Unknown))
    );
    let read = host.read::<ShardRecord>(record).unwrap();
    assert_eq!(settled_floor(&possible, read.value()), None);
    let version = read.version();
    let (read, opened) = open_suffix(
        &mut host,
        &mut possible,
        (read, own),
        (&storage, &[]),
        bounds,
    )
    .unwrap();
    assert!(!opened, "an unsettled floor leaves the log closed");
    assert_eq!(read.version(), version, "and writes nothing");
    assert_eq!(storage.with_suffix(|log| log.is_open()), Ok(false));
    let read = confirm(&mut host, &mut possible, &read, own).unwrap();
    let (_, opened) = open_suffix(
        &mut host,
        &mut possible,
        (read, own),
        (&storage, &[]),
        bounds,
    )
    .unwrap();
    assert!(opened, "the confirm settled the set");
    records.release();
}

/// A fill the publication's verdict refuses `Expired`, and an invalidation whose cutoff reads closed inside its
/// bracket, are refused before the suffix append: the open suffix records nothing and no tail rises.
#[test]
fn a_change_another_check_refuses_records_nothing_in_the_open_suffix() {
    use super::super::super::publish_tests::{TRIES, budget};
    use super::super::super::remove::INTERPOSE_BEFORE_CUTOFF;
    const SECOND: u64 = 1_000_000_000;
    let storage = storage(1);
    let buffers = arena_with(4, 9);
    let mut dev = tenure(&storage, &buffers, 16);
    drop(publish(&storage, &mut dev, &key(1), &[1; 40]).unwrap());
    settle(&storage, &mut dev.volume, &dev.control);
    let pool = storage.pool();
    let words = || {
        (
            pool.suffix_tail.load(std::sync::atomic::Ordering::Relaxed),
            storage.with_suffix(|log| (log.head(), log.idle(), log.durable())),
        )
    };
    let before = words();
    let fill =
        super::super::super::publication_tests::filled(&storage, &mut dev, &key(2), &[2; 40]);
    storage.platform.ticks(&[Some(11 * SECOND)]);
    assert_eq!(
        fill.publish(&mut dev.volume, 10 * SECOND, TRIES, &mut budget())
            .err(),
        Some(FillPublishError::Expired)
    );
    assert_eq!(words(), before, "an expired fill records nothing");
    INTERPOSE_BEFORE_CUTOFF.with(|hook| {
        hook.set(Some(|flag| {
            flag.store(true, std::sync::atomic::Ordering::SeqCst)
        }));
    });
    let mut budget = WorkBudget::new(1 << 20);
    assert_eq!(
        storage.invalidate(&key(1), 4, &mut budget).err(),
        Some(super::super::super::InvalidateError::Closed)
    );
    assert_eq!(
        words(),
        before,
        "an invalidation closed at its cutoff records nothing"
    );
}

/// A sealed block whose prefix unit lies outside the metadata area ends the metadata `MetadataFailed` at once, whatever
/// `metadata_retries` allows, with nothing submitted and the journal cell empty, which closes admission.
#[test]
fn a_delta_block_the_area_cannot_hold_ends_the_metadata_whatever_the_retries() {
    let storage = storage(1);
    let buffers = arena_with(4, 9);
    let mut dev = cold(&storage, &buffers);
    dev.volume.metadata.retries = u32::MAX;
    // A layout whose delta region starts past the test area's units.
    let beyond = Layout {
        units: 1 + 1000 + 4,
        slots: 1,
        slot_units: 1000,
        ..layout()
    };
    let own = Suffix {
        session: predecessor_session().get(),
        start: 0,
        certified: 0,
        end: 4,
    };
    let open = (LIMITS, &beyond);
    let opened = storage.with_suffix(|log| log.open((Crc32c::detect(), shard()), open, own, 0));
    assert_eq!(opened, Ok(true));
    drop(publish(&storage, &mut dev, &key(1), &[1; 40]).unwrap());
    for _ in 0..8 {
        if dev.volume.metadata_outcome() != MetadataOutcome::Open {
            break;
        }
        tick(&mut dev.volume, &dev.control);
    }
    assert_eq!(
        dev.volume.metadata_outcome(),
        MetadataOutcome::MetadataFailed
    );
    let beyond_units = (submitted(&dev.control, Operation::Write).into_iter())
        .filter(|&(_, start)| (1001..1005).contains(&(start / IO_UNIT as u64)))
        .count();
    assert_eq!(
        beyond_units, 0,
        "no block was submitted to the layout's delta region"
    );
    assert!(dev.volume.metadata.commands[JOURNAL].is_none());
    assert!(storage.is_closed(), "the failed suffix closes admission");
}

thread_local! {
    /// The barrier a retirement hook shares with its pool-gate holder. Per thread, so tests running in parallel
    /// never share one.
    static RETIREMENT_BARRIER: std::cell::RefCell<Option<std::sync::Arc<std::sync::Barrier>>> =
        const { std::cell::RefCell::new(None) };
}

/// Holds the pool gate on another thread from this thread's next retirement, after the commit's removal record was
/// appended under the gate, until the third wait on [`RETIREMENT_BARRIER`], so the retirement parks.
fn hold_pool_gate_from_the_retirement(
    storage: &'static Storage<TestPlatform>,
) -> std::thread::JoinHandle<()> {
    use super::super::super::lease::INTERPOSE_BEFORE_TERMINAL_CLOSE;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    RETIREMENT_BARRIER.with(|cell| *cell.borrow_mut() = Some(std::sync::Arc::clone(&barrier)));
    let holder = std::thread::spawn(move || {
        barrier.wait();
        let guard = storage.live_pool().unwrap().lock().unwrap();
        barrier.wait();
        barrier.wait();
        drop(guard);
    });
    INTERPOSE_BEFORE_TERMINAL_CLOSE.with(|hook| {
        hook.set(Some(|_| {
            let barrier = RETIREMENT_BARRIER.with(|cell| cell.borrow().clone().unwrap());
            barrier.wait();
            barrier.wait();
        }))
    });
    holder
}

/// What one eviction history over an open suffix saw: the in-flight count, units and pending flag once the
/// eviction's mark applied, and the domain's members after the maintenance calls that followed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EvictionSeen {
    in_flight: (usize, u64, bool),
    members_after: usize,
}

/// Two one-unit objects published and their blocks persisted, with `low_units` at `low`, then one eviction whose
/// REMOVE block stays unwritten. With `parked`, another thread holds the pool gate from the commit on, so the
/// retirement parks and the mark stays pending. Certification and service run until the slot awaits its block with
/// no anchor and no right, a selection hold that chooses nothing applies any pending mark, and eight maintenance
/// calls follow with no tick.
fn eviction_awaiting_its_block(parked: bool, low: u64) -> EvictionSeen {
    use super::super::super::allocation::RetireOutcome;
    use super::super::super::evict::Commit;
    use super::super::super::evict_tests::generous;
    use super::super::super::word;
    let marks = super::super::config::VolumeWatermarks {
        low_units: low,
        min_free_slots: 1,
        retired_units: u64::MAX,
    };
    let storage: &'static Storage<TestPlatform> =
        Box::leak(Box::new(super::sim_tests::storage_with(1, Some(marks))));
    let buffers = arena_with(4, 9);
    let mut dev = tenure(storage, &buffers, 16);
    for n in 1..=2 {
        drop(publish(storage, &mut dev, &key(n), &[n; 40]).unwrap());
    }
    settle(storage, &mut dev.volume, &dev.control);
    serve(storage);
    let holder = parked.then(|| hold_pool_gate_from_the_retirement(storage));
    let report = storage.evict_step(&mut generous(), |_, _| true).unwrap();
    if let Some(holder) = holder {
        RETIREMENT_BARRIER
            .with(|cell| cell.borrow().clone().unwrap())
            .wait();
        holder.join().unwrap();
    }
    let Some(Commit::Evicted {
        victim, retirement, ..
    }) = report.commit
    else {
        panic!("the step evicts: {report:?}");
    };
    let expected = match parked {
        true => RetireOutcome::Parked,
        false => retirement,
    };
    assert_eq!((retirement, report.mark_pending), (expected, parked));
    let slot = victim.slot_index();
    let mut awaiting = 0;
    for _ in 0..4 {
        let _ = storage.certify(&mut generous()).unwrap();
        awaiting = storage.service(&mut generous()).unwrap().awaiting_journal;
    }
    let current = storage.live_pool().unwrap().word(slot);
    assert_eq!(
        (awaiting, word::refs(current), current & word::ANCHORED),
        (1, 0, 0),
        "the slot awaits its block with no anchor and no right"
    );
    let applied = storage.evict_step(&mut generous(), |_, _| false).unwrap();
    assert_eq!((applied.stale_marks, applied.mark_pending), (0, false));
    let domain = storage.domain_report().unwrap();
    let in_flight = (
        domain.in_flight,
        domain.in_flight_units,
        domain.pending_mark,
    );
    for _ in 0..8 {
        let _ = storage.maintain(&mut WorkBudget::new(1 << 20)).unwrap();
    }
    EvictionSeen {
        in_flight,
        members_after: storage.domain_report().unwrap().members,
    }
}

/// A slot held only for its journal block keeps its eviction in flight whether the retirement recorded the mark
/// under the gate or parked and left it pending, so headroom short by one unit evicts one object either way.
#[test]
fn an_eviction_awaiting_its_block_stays_in_flight_when_its_mark_applies_late() {
    let low = {
        let marks = super::super::config::VolumeWatermarks {
            low_units: 4,
            min_free_slots: 1,
            retired_units: u64::MAX,
        };
        let storage = super::sim_tests::storage_with(1, Some(marks));
        let buffers = arena_with(4, 9);
        let mut dev = tenure(&storage, &buffers, 16);
        for n in 1..=2 {
            drop(publish(&storage, &mut dev, &key(n), &[n; 40]).unwrap());
        }
        settle(&storage, &mut dev.volume, &dev.control);
        serve(&storage);
        storage.domain_report().unwrap().placeable_units + 1
    };
    let recorded = eviction_awaiting_its_block(false, low);
    assert_eq!(
        recorded,
        EvictionSeen {
            in_flight: (1, 1, false),
            members_after: 1
        },
        "the gate-recorded eviction"
    );
    assert_eq!(
        eviction_awaiting_its_block(true, low),
        recorded,
        "the parked eviction"
    );
}

thread_local! {
    /// The storage a commit hook looks its victim up in, and the lease that lookup took.
    static READER_SCENE: std::cell::Cell<Option<&'static Storage<TestPlatform>>> =
        const { std::cell::Cell::new(None) };
    static READER_LEASE: std::cell::RefCell<
        Option<super::super::super::lease::ExtentLease<'static, TestPlatform>>,
    > = const { std::cell::RefCell::new(None) };
}

/// The eviction of [`eviction_awaiting_its_block`] with a lease taken on the victim between selection and commit,
/// which [`READER_LEASE`] keeps. Certification and service run until the anchor is released and the lease's right
/// alone holds the victim, whose REMOVE block stays unwritten; with `parked`, a selection hold that chooses nothing
/// then applies the pending mark. Returns the storage, its device and the victim's slot.
fn eviction_a_reader_holds(
    parked: bool,
    low: u64,
) -> (
    &'static Storage<TestPlatform>,
    Device<'static, 'static>,
    usize,
) {
    use super::super::super::evict::{Commit, INTERPOSE_BEFORE_COMMIT};
    use super::super::super::evict_tests::generous;
    use super::super::super::word;
    let marks = super::super::config::VolumeWatermarks {
        low_units: low,
        min_free_slots: 1,
        retired_units: u64::MAX,
    };
    let storage: &'static Storage<TestPlatform> =
        Box::leak(Box::new(super::sim_tests::storage_with(1, Some(marks))));
    let buffers = Box::leak(Box::new(arena_with(4, 9)));
    let mut dev = tenure(storage, buffers, 16);
    for n in 1..=2 {
        drop(publish(storage, &mut dev, &key(n), &[n; 40]).unwrap());
    }
    settle(storage, &mut dev.volume, &dev.control);
    serve(storage);
    READER_SCENE.with(|cell| cell.set(Some(storage)));
    INTERPOSE_BEFORE_COMMIT.with(|hook| {
        hook.set(Some(|| {
            let storage = READER_SCENE.with(std::cell::Cell::get).unwrap();
            let mut reader = storage.register().unwrap();
            let lease = lookup(&mut reader, &key(1), 4).unwrap();
            READER_LEASE.with(|cell| *cell.borrow_mut() = Some(lease));
        }))
    });
    let holder = parked.then(|| hold_pool_gate_from_the_retirement(storage));
    let report = storage.evict_step(&mut generous(), |_, _| true).unwrap();
    if let Some(holder) = holder {
        RETIREMENT_BARRIER
            .with(|cell| cell.borrow().clone().unwrap())
            .wait();
        holder.join().unwrap();
    }
    let Some(Commit::Evicted { victim, .. }) = report.commit else {
        panic!("the step evicts: {report:?}");
    };
    assert_eq!(report.mark_pending, parked);
    let slot = victim.slot_index();
    for _ in 0..4 {
        let _ = storage.certify(&mut generous()).unwrap();
        let _ = storage.service(&mut generous()).unwrap();
    }
    let current = storage.live_pool().unwrap().word(slot);
    assert_eq!(
        (word::refs(current), current & word::ANCHORED),
        (1, 0),
        "premise: the reader's right alone holds the victim"
    );
    if parked {
        let applied = storage.evict_step(&mut generous(), |_, _| false).unwrap();
        assert_eq!((applied.stale_marks, applied.mark_pending), (0, false));
    }
    (storage, dev, slot)
}

/// [`eviction_a_reader_holds`], then the lease is dropped and the slot awaits its unwritten REMOVE block with no
/// anchor and no right, as the eviction without a reader does.
fn eviction_awaiting_its_block_after_a_reader(parked: bool, low: u64) -> EvictionSeen {
    use super::super::super::evict_tests::generous;
    use super::super::super::word;
    let (storage, _dev, slot) = eviction_a_reader_holds(parked, low);
    drop(READER_LEASE.with(|cell| cell.borrow_mut().take()).unwrap());
    let mut awaiting = 0;
    for _ in 0..4 {
        awaiting = storage.service(&mut generous()).unwrap().awaiting_journal;
    }
    let current = storage.live_pool().unwrap().word(slot);
    assert_eq!(
        (awaiting, word::refs(current), current & word::ANCHORED),
        (1, 0, 0),
        "the slot awaits its block with no anchor and no right"
    );
    let domain = storage.domain_report().unwrap();
    let in_flight = (
        domain.in_flight,
        domain.in_flight_units,
        domain.pending_mark,
    );
    for _ in 0..8 {
        let _ = storage.maintain(&mut WorkBudget::new(1 << 20)).unwrap();
    }
    EvictionSeen {
        in_flight,
        members_after: storage.domain_report().unwrap().members,
    }
}

/// The low watermark one unit above what two published one-unit objects leave placeable.
fn low_one_unit_short() -> u64 {
    let marks = super::super::config::VolumeWatermarks {
        low_units: 4,
        min_free_slots: 1,
        retired_units: u64::MAX,
    };
    let storage = super::sim_tests::storage_with(1, Some(marks));
    let buffers = arena_with(4, 9);
    let mut dev = tenure(&storage, &buffers, 16);
    for n in 1..=2 {
        drop(publish(&storage, &mut dev, &key(n), &[n; 40]).unwrap());
    }
    settle(&storage, &mut dev.volume, &dev.control);
    serve(&storage);
    storage.domain_report().unwrap().placeable_units + 1
}

/// A slot held only for its journal block keeps its eviction in flight when a reader's right outlived the anchor
/// and was released before the block persisted, so headroom short by one unit evicts one object, as it does with
/// no reader, whether the retirement recorded the mark under the gate or parked and its mark applied while the
/// right remained.
#[test]
fn an_eviction_awaiting_its_block_stays_in_flight_after_a_reader_releases_its_right() {
    let low = low_one_unit_short();
    let recorded = eviction_awaiting_its_block(false, low);
    assert_eq!(
        eviction_awaiting_its_block_after_a_reader(false, low),
        recorded,
        "the eviction a reader held past its anchor"
    );
    assert_eq!(
        eviction_awaiting_its_block_after_a_reader(true, low),
        recorded,
        "the parked eviction a reader held past its anchor"
    );
}

/// An evicted slot whose anchor is released while a reader's right remains stays in flight while its REMOVE block
/// is unwritten, and leaves flight at the first service call after the block persists: from then the right alone
/// holds the extent. The slot returns once the right is released.
#[test]
fn an_evicted_slot_a_reader_holds_leaves_flight_once_its_block_is_durable() {
    use super::super::super::evict_tests::generous;
    use super::super::super::word;
    let in_flight = |storage: &Storage<TestPlatform>| {
        let domain = storage.domain_report().unwrap();
        (domain.in_flight, domain.in_flight_units)
    };
    for parked in [false, true] {
        let (storage, mut dev, slot) = eviction_a_reader_holds(parked, low_one_unit_short());
        assert_eq!(
            in_flight(storage),
            (1, 1),
            "parked {parked}: block unwritten"
        );
        settle(storage, &mut dev.volume, &dev.control);
        let _ = storage.service(&mut generous()).unwrap();
        let current = storage.live_pool().unwrap().word(slot);
        assert_eq!(
            (in_flight(storage), word::refs(current)),
            ((0, 0), 1),
            "parked {parked}: the right alone holds the extent"
        );
        drop(READER_LEASE.with(|cell| cell.borrow_mut().take()).unwrap());
        let report = storage.service(&mut generous()).unwrap();
        let current = storage.live_pool().unwrap().word(slot);
        assert_eq!(
            (
                in_flight(storage),
                report.awaiting_journal,
                word::refs(current),
                word::state(current)
            ),
            ((0, 0), 0, 0, super::super::super::tables::SlotState::Free),
            "parked {parked}: the slot returned"
        );
    }
}

/// Drives the delta writer to a sealed block it cannot stage for want of a buffer: one try at 40, then a
/// try at 55 whose second sample is `second`. Returns the writer's capture-mutex tries at a third stage at 56.
fn tries_after_a_stage_whose_clock_sample_was(second: Option<u64>) -> usize {
    let storage = storage(1);
    let buffers = arena_with(4, 9);
    let mut dev = tenure(&storage, &buffers, 16);
    let limits = SuffixLimits {
        flush_ns: 10,
        ..LIMITS
    };
    let own = Suffix {
        session: predecessor_session().get(),
        start: 0,
        certified: 0,
        end: 16,
    };
    let mut log = super::super::super::recovery::suffix::SuffixLog::default();
    assert!(log.open((Crc32c::detect(), shard()), (limits, &layout()), own, 0));
    storage.with_suffix(|current| *current = log).unwrap();
    storage.platform.ticks(&[Some(1)]);
    drop(publish(&storage, &mut dev, &key(1), &[1; 40]).unwrap());
    storage.platform.ticks(&[Some(20)]);
    settle(&storage, &mut dev.volume, &dev.control);
    assert_eq!(delta_units(&dev.control), [DELTA]);
    let mut taken = Vec::new();
    while let Ok(buffer) = buffers.acquire(super::super::super::device::PoolKind::Maintenance) {
        taken.push(buffer);
    }
    drop(publish(&storage, &mut dev, &key(2), &[2; 40]).unwrap());
    let tries = || super::super::checkpoint::DELTA_TRIES.with(std::cell::Cell::get);
    storage.platform.ticks(&[Some(40)]);
    let before = tries();
    dev.volume.stage_delta();
    assert_eq!(tries() - before, 1, "the first try at 40");
    storage.platform.ticks(&[Some(45)]);
    dev.volume.stage_delta();
    assert_eq!(tries() - before, 1, "45 lies inside the flush interval");
    storage.platform.ticks(&[Some(55), second]);
    dev.volume.stage_delta();
    assert_eq!(tries() - before, 2, "the second try at 55");
    storage.platform.ticks(&[Some(56)]);
    let at_56 = tries();
    dev.volume.stage_delta();
    drop(taken);
    tries() - at_56
}

/// Sibling: with every sample served, the try at 55 sets the next try one flush interval later, so a stage at 56
/// takes no capture-mutex try (stage_delta: "A block it cannot stage for want of a buffer ... waits one flush
/// interval before the next try").
#[test]
fn a_served_clock_keeps_the_flush_interval_between_unstaged_tries() {
    assert_eq!(tries_after_a_stage_whose_clock_sample_was(Some(55)), 0);
}

/// When the try at 55 reads no second clock sample (`now_ticks` is `None`), stage_delta paces from the wake's sample,
/// 55, so the stage at 56 still lies inside the flush interval and takes no capture-mutex try.
#[test]
fn a_failed_clock_sample_keeps_the_flush_interval_between_unstaged_tries() {
    assert_eq!(tries_after_a_stage_whose_clock_sample_was(None), 0);
}

#[path = "suffix_entry_cap_tests.rs"]
mod entry_cap;
