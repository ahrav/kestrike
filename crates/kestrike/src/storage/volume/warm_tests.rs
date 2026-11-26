//! The warm bootstrap over simulated media a running writer left: a named slot's load of the writer's entries,
//! decoded by the slot reader under the relaunched storage's routing, installs on the pool, publishes into the index
//! and commits readiness in one pool-gate hold; restored entries grant nothing until `Live`, fills refuse until then,
//! and every refusal, withdrawal or crash before the commit leaves the media and the predecessor's evidence as they were.

use std::rc::Rc;

use super::super::super::checkpoint::tests::{Inline, slot_image_under};
use super::super::super::config::StorageConfig;
use super::super::super::device::Operation;
use super::super::super::device::sim::{Media, SimControl, media};
use super::super::super::ledger::EngineBudget;
use super::super::super::lookup::LookupError;
use super::super::super::lookup_tests::lookup;
use super::super::super::publication_tests::publish;
use super::super::super::publish_tests::key;
use super::super::super::publish_tests::{PAGE, index_config, storage_config, storage_from};
use super::super::super::readiness::{Event, State};
use super::super::super::record::Crc32c;
use super::super::super::recovery::capture_tests::drain;
use super::super::super::recovery::checkpoint::{Chunk, SlotLoad};
use super::super::super::recovery::{CaptureEntry, LoadLimits, LoadRefusal};
use super::super::super::store_tests::shard;
use super::super::super::test_platform::TestPlatform;
use super::super::super::volume_fixture::{
    Device, MEDIA, TestVolume, arena_with, attach_over, fenced, fenced_over, read_back,
};
use super::super::super::{MetadataOutcome, ReadStatus, ReserveError, Storage};
use super::super::bootstrap_tests::submitted;
use super::super::helpers::PARK;
use super::super::journal_tests::storage_with;
use super::Stage;
use crate::index::IndexConfig;
use crate::storage::checkpoint::SlotReader;

/// The storage the writer and each relaunch run: eight slots over one index shard.
pub(super) fn narrow() -> Storage<TestPlatform> {
    storage_with(|_| {})
}

/// A storage of 64 slots over two index shards and records of up to three units, so a slot of its entries spans two
/// data units and two destinations.
fn wide() -> Storage<TestPlatform> {
    two_shards([32, 32])
}

/// [`wide`] with visible limits of four and six keys on its two index shards.
fn tight() -> Storage<TestPlatform> {
    two_shards([4, 6])
}

/// Under `PAIR`, each shard of [`two_shards`] receives at most 32 of keys 1 through 44.
const PAIR: (u64, u64) = (0x5eed_0001, 0x5eed_0002);

/// A storage of 64 slots over two index shards of `visible` keys under [`PAIR`], records of up to three units.
fn two_shards(visible: [usize; 2]) -> Storage<TestPlatform> {
    let fills = [4, 4];
    let index = IndexConfig {
        fills: &fills,
        ..index_config(&visible, (1, 1), 1)
    };
    let config = StorageConfig {
        lease_limit: 16,
        volume: super::super::test_volume_with(65 * super::super::super::IO_UNIT, 32, 64),
        body_cap: 3 * super::super::super::IO_UNIT,
        ..storage_config(64)
    };
    let mut storage = storage_from(&config, &index, TestPlatform::heap(PAGE));
    storage.install_hasher(crate::index::KeyHasher::with_key_pair(PAIR.0, PAIR.1));
    let placed = |count: u8| {
        let owner = storage.index().unwrap();
        let mut placed = [0usize; 2];
        for n in 1..=count {
            let route = (owner.hasher)
                .route_unpaid(&key(n), &owner.geometry, crate::index::Prefetch::NONE)
                .unwrap();
            placed[route.position()] += 1;
        }
        placed
    };
    assert!(
        placed(44).iter().all(|&count| count <= 32),
        "{:?}",
        placed(44)
    );
    storage.platform.ticks(&[Some(1)]);
    storage
}

/// A restored set that routes more keys to an index shard than that shard's own visible limit refuses `Limits` at the
/// marks, before the allocator's hold and any slot install or publication, and keeps the media, though the set fits the
/// index's total; a set holding exactly each shard's limit opens and serves every key.
#[test]
fn a_restored_set_past_a_shards_visible_limit_refuses_before_any_table_write() {
    let (store, entries, _) = written_in(wide, 30);
    let by_shard = |storage: &Storage<TestPlatform>| {
        let index = storage.index().unwrap();
        let mut routed: [Vec<(CaptureEntry, u64)>; 2] = [Vec::new(), Vec::new()];
        for entry in entries.iter().cloned() {
            let mut words = [0; crate::index::LANES];
            (index.hasher).fingerprints(std::slice::from_ref(&entry.key), &mut words);
            routed[crate::index::reduce(words[0], 2)].push((entry, words[0]));
        }
        assert!(
            routed.iter().all(|shard| shard.len() >= 7),
            "30 keys over two shards"
        );
        routed
    };
    // Shard 0 holds four keys and shard 1 six: one key past shard 0's limit refuses though it fits shard 1's, one key
    // past shard 1's limit refuses, and each shard exactly at its limit opens.
    for (counts, refuses) in [([5, 1], true), ([1, 7], true), ([4, 6], false)] {
        let served: Vec<[u8; 32]> = (0..2)
            .flat_map(|shard| by_shard(&wide())[shard][..counts[shard]].to_vec())
            .map(|(entry, _)| entry.key)
            .collect();
        relaunch_in(
            tight,
            &store,
            &[],
            |storage, _| {
                let routed = by_shard(storage);
                let chunks = (0..2)
                    .map(|shard| {
                        let held = &routed[shard][..counts[shard]];
                        held.iter()
                            .map(|held| Chunk::holding(std::slice::from_ref(held)))
                            .collect()
                    })
                    .collect();
                SlotLoad::handed(chunks)
            },
            |storage, volume, control| {
                let before = pristine(storage);
                settle(volume, control);
                if refuses {
                    return refused(
                        storage,
                        volume,
                        control,
                        (MetadataOutcome::Unloadable(LoadRefusal::Limits), before),
                    );
                }
                assert_eq!(
                    volume.metadata_outcome(),
                    MetadataOutcome::Open,
                    "{counts:?}"
                );
                live(storage, volume);
                let mut reader = storage.register().unwrap();
                for key in &served {
                    drop(lookup(&mut reader, key, 4).expect("every restored key maps"));
                }
            },
        );
    }
}

/// Media holding `count` published objects, the writer's captured entries and its free and placeable units.
pub(super) fn written(count: u8) -> (Media, Vec<CaptureEntry>, (u64, u64)) {
    written_in(narrow, count)
}

fn written_in(
    make: fn() -> Storage<TestPlatform>,
    count: u8,
) -> (Media, Vec<CaptureEntry>, (u64, u64)) {
    written_bodies(make, &vec![40; usize::from(count)])
}

/// Media holding one published object of `len` body bytes per entry of `lens`, keys from 1, written on `make`'s
/// storage, with the writer's captured entries and its free and placeable units.
fn written_bodies(
    make: fn() -> Storage<TestPlatform>,
    lens: &[usize],
) -> (Media, Vec<CaptureEntry>, (u64, u64)) {
    let store = media(MEDIA);
    let storage = make();
    let buffers = arena_with(4, 9);
    let mut dev = Device::over(&storage, &buffers, Rc::clone(&store));
    for (n, &len) in (1..).zip(lens) {
        drop(publish(&storage, &mut dev, &key(n), &vec![n; len]).unwrap());
        for shard in 0..storage.index().unwrap().geometry.enabled().len() {
            let mut budget = super::super::super::budget::WorkBudget::new(1 << 20);
            storage
                .service_fills(crate::index::ShardIndex(shard), 8, &mut budget)
                .unwrap();
        }
    }
    storage.start_capture(1024, true, 1024).unwrap();
    let entries = drain(&storage);
    assert_eq!(entries.len(), lens.len());
    (store, entries, units(&storage))
}

/// The allocator's free and placeable units and the slot ledger's resident count, read in one pool-gate hold.
pub(super) fn units(storage: &Storage<TestPlatform>) -> (u64, u64) {
    let pool = storage.live_pool().unwrap();
    let mut access = pool.lock().unwrap();
    let mut tables = access.tables();
    let units = (tables.free_units(), tables.placeable_units());
    access.release();
    units
}

pub(super) fn resident(storage: &Storage<TestPlatform>) -> usize {
    let pool = storage.live_pool().unwrap();
    let access = pool.lock().unwrap();
    let mut access = access;
    let resident = access.tables().state.ledger.resident;
    access.release();
    resident
}

/// The destinations the slot reader routes entries over, more than the index has shards.
const DESTINATIONS: usize = 3;

/// The limits the relaunched storage's slot reader checks entries against.
fn limits(storage: &Storage<TestPlatform>) -> LoadLimits {
    let descriptor = storage.pool().descriptor();
    LoadLimits {
        payload_start: 0,
        payload_end: descriptor.geometry.payload_units(),
        reserve_units: 0,
        slot_count: descriptor.slot_count,
        n_max: 1024,
        record_chunk_len: storage.record.chunk_len(),
    }
}

/// The load of `entries` a slot reader decodes under `storage`'s hasher and index geometry for the reader session
/// `reader`, with the slot's last unit torn when `tear`.
fn decoded(
    storage: &Storage<TestPlatform>,
    entries: &[CaptureEntry],
    reader: u64,
    tear: bool,
) -> SlotLoad {
    let (layout, ck, bytes) = slot_image_under(entries, tear, entries[0].session);
    let index = storage.index().unwrap();
    let mut slot = SlotReader::new(
        Crc32c::detect(),
        &layout,
        shard(),
        (ck, 0, &[]),
        reader,
        (limits(storage), &EngineBudget::unlimited()),
        (index.hasher.clone(), DESTINATIONS),
    )
    .unwrap();
    while !slot.done() {
        let range = slot
            .next_read()
            .expect("a reader that is not done issues a read");
        let start = range.start() as usize;
        slot.complete(range, &bytes[start..start + range.byte_len() as usize]);
    }
    slot.load()
}

/// A load that names `entries` with their fingerprints under `storage`'s hasher, routed to their destinations, as a
/// guard that accepted them would hand it over.
fn handed(storage: &Storage<TestPlatform>, entries: Vec<CaptureEntry>) -> SlotLoad {
    let mut shards: Vec<Vec<Chunk>> = vec![Vec::new(); DESTINATIONS];
    for held in printed(storage, &entries) {
        let destination = crate::index::reduce(held.1, DESTINATIONS);
        shards[destination].push(Chunk::holding(&[held]));
    }
    SlotLoad::handed(shards)
}

/// `entries`, each with its key's routing fingerprint under `storage`'s hasher.
fn printed(storage: &Storage<TestPlatform>, entries: &[CaptureEntry]) -> Vec<(CaptureEntry, u64)> {
    let index = storage.index().unwrap();
    let printed = entries.iter().map(|entry| {
        let mut words = [0; crate::index::LANES];
        (index.hasher).fingerprints(std::slice::from_ref(&entry.key), &mut words);
        (entry.clone(), words[0])
    });
    printed.collect()
}

/// Takes every entry of `load`'s destinations as one chunk whose entries all carry the first entry's fingerprint.
fn collided(load: &mut SlotLoad) -> Chunk {
    let chunks = load.shards.iter_mut().flat_map(std::mem::take);
    let held: Vec<(CaptureEntry, u64)> = chunks.flat_map(|chunk| chunk.captured()).collect();
    let print = held[0].1;
    let collided: Vec<_> = held.into_iter().map(|(entry, _)| (entry, print)).collect();
    Chunk::holding(&collided)
}

/// Relaunches `store` on a fresh storage whose volume assumes a warm bootstrap of the load `of` builds from the
/// storage and the tenure's session, and runs `body`.
fn relaunch<R>(
    store: &Media,
    of: impl FnOnce(&Storage<TestPlatform>, u64) -> SlotLoad,
    body: impl for<'s> FnOnce(&'s Storage<TestPlatform>, &mut TestVolume<'s, '_>, &SimControl) -> R,
) -> R {
    relaunch_covered(store, &[], of, body)
}

fn relaunch_covered<R>(
    store: &Media,
    covered: &[[u8; 32]],
    of: impl FnOnce(&Storage<TestPlatform>, u64) -> SlotLoad,
    body: impl for<'s> FnOnce(&'s Storage<TestPlatform>, &mut TestVolume<'s, '_>, &SimControl) -> R,
) -> R {
    relaunch_in(narrow, store, covered, of, body)
}

fn relaunch_in<R>(
    make: fn() -> Storage<TestPlatform>,
    store: &Media,
    covered: &[[u8; 32]],
    of: impl FnOnce(&Storage<TestPlatform>, u64) -> SlotLoad,
    body: impl for<'s> FnOnce(&'s Storage<TestPlatform>, &mut TestVolume<'s, '_>, &SimControl) -> R,
) -> R {
    relaunch_under(make, store, fenced(covered), of, body)
}

/// [`relaunch_in`] under the tenure's fenced coverage `coverage`.
fn relaunch_under<R>(
    make: fn() -> Storage<TestPlatform>,
    store: &Media,
    coverage: super::super::super::cache::coverage::Coverage,
    of: impl FnOnce(&Storage<TestPlatform>, u64) -> SlotLoad,
    body: impl for<'s> FnOnce(&'s Storage<TestPlatform>, &mut TestVolume<'s, '_>, &SimControl) -> R,
) -> R {
    let storage = make();
    let buffers = arena_with(4, 9);
    let (mut volume, control) = attach_over(&storage, &buffers, store).unwrap();
    let load = of(&storage, volume.authority.session().get());
    volume.assume_warm(load, coverage).unwrap();
    PARK.with(|park| park.set(true));
    let result = body(&storage, &mut volume, &control);
    PARK.with(|park| park.set(false));
    result
}

/// One tick of `volume`, after which the parked helpers release the terminals of the jobs they ran, so the next tick
/// adopts them and a conversion spans at least one tick.
pub(super) fn tick<D: super::super::super::device::Disk>(
    volume: &mut super::super::Volume<'_, '_, TestPlatform, D>,
    control: &SimControl,
) {
    let mut out = Vec::with_capacity(16);
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

/// The warm bootstrap's stage, `None` before it staged.
pub(super) fn stage(volume: &TestVolume<'_, '_>) -> Option<Stage> {
    volume.metadata.warm.as_ref().map(|warm| warm.stage)
}

/// Ticks `volume` until its warm bootstrap reaches `at`, and fails after 64 ticks.
pub(super) fn reach(volume: &mut TestVolume<'_, '_>, control: &SimControl, at: Stage) {
    for _ in 0..64 {
        if stage(volume) == Some(at) {
            return;
        }
        tick(volume, control);
    }
    panic!(
        "the warm bootstrap never reached {at:?}: {:?}",
        stage(volume)
    );
}

/// Ticks `volume` until its readiness leaves `Detached` and `Loading`, or 64 ticks pass.
pub(super) fn settle(volume: &mut TestVolume<'_, '_>, control: &SimControl) {
    for _ in 0..64 {
        if !volume.readiness().initializing() {
            return;
        }
        tick(volume, control);
    }
}

/// Each lane's install merge and the pairs each destination published.
fn progress(volume: &TestVolume<'_, '_>) -> (Vec<super::Merge>, Vec<usize>) {
    let warm = volume.metadata.warm.as_ref().unwrap();
    (warm.merges.clone(), warm.published.clone())
}

/// The lanes `storage`'s warm bootstrap splits over and the index geometry its publication groups follow.
fn split(storage: &Storage<TestPlatform>) -> (usize, &crate::index::ValidatedIndex) {
    let index = storage.index().unwrap();
    (storage.recovery.helpers as usize, &index.geometry)
}

/// The stages before the commit lands, in their order.
const STAGES: [Stage; 6] = [
    Stage::Convert,
    Stage::Mark,
    Stage::Hold,
    Stage::Install,
    Stage::Publish,
    Stage::Commit,
];

pub(super) fn writes(control: &SimControl) -> usize {
    submitted(control, Operation::Write).len()
}

/// Serves `key(n)` at `Live` and returns the delivered bytes.
pub(super) fn served<'s>(
    storage: &'s Storage<TestPlatform>,
    volume: &mut TestVolume<'s, '_>,
    control: &SimControl,
    n: u8,
) -> Vec<u8> {
    let mut reader = storage.register().unwrap();
    let lease = lookup(&mut reader, &key(n), 4).expect("served at Live");
    let delivered = read_back(volume, control, &lease);
    assert_eq!(delivered.status, ReadStatus::Complete, "key {n}");
    delivered.bytes
}

/// Brings a loaded volume to `Live` through replay of its restored rows; a load that restored none is live at once.
pub(super) fn live<D: super::super::super::device::Disk>(
    storage: &Storage<TestPlatform>,
    volume: &mut super::super::Volume<'_, '_, TestPlatform, D>,
) {
    match volume.begin_replay(storage.feed_contract(), 0) {
        Ok(State::Replaying) => assert_eq!(volume.complete_replay(), Ok(State::Live)),
        Ok(State::Live) => assert_eq!(
            volume.metadata.warm.as_ref().map(|warm| warm.rows()),
            Some(0)
        ),
        began => panic!("{began:?}"),
    }
}

/// A `Live` volume over restored bindings submits no metadata write: the warm load requires the tenure's suffix, so an
/// invalidation of a restored key refuses `History` before the log opens, 96 polls stage no root block or checkpoint
/// unit, and the metadata stays open.
#[test]
fn a_live_warm_volume_writes_no_metadata_block() {
    let (store, entries, _) = written(3);
    relaunch(
        &store,
        |storage, reader| decoded(storage, &entries, reader, false),
        |storage, volume, control| {
            settle(volume, control);
            live(storage, volume);
            assert_eq!(volume.readiness(), State::Live);
            let metadata =
                volume.metadata.area.layout().metadata_units * super::super::super::IO_UNIT as u64;
            let prefix = |control: &SimControl| {
                submitted(control, Operation::Write)
                    .into_iter()
                    .filter(|(_, start)| *start < metadata)
                    .count()
            };
            let before = prefix(control);
            assert_eq!(
                super::super::super::attempt_tests::invalidate(storage, &key(1)).err(),
                Some(super::super::super::InvalidateError::History)
            );
            for _ in 0..96 {
                tick(volume, control);
            }
            assert_eq!(
                prefix(control),
                before,
                "a Live volume submits no metadata write"
            );
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
            assert_eq!(volume.readiness(), State::Live);
            assert!(
                volume.metadata.commands[super::super::metadata::JOURNAL].is_none(),
                "no journal block is staged"
            );
        },
    );
}

/// A warm bootstrap opens with every restored entry refusing its grant until `Live`, then serves each entry's exact
/// bytes; the allocator holds exactly the restored extents, so its free and placeable units equal the writer's, and
/// the attempt writes no device unit. A withdrawal after `Live` refuses the grants again.
#[test]
fn a_recovered_entry_misses_before_live_and_serves_exact_bytes_at_live() {
    let (store, entries, writer) = written(3);
    relaunch(
        &store,
        |storage, reader| decoded(storage, &entries, reader, false),
        |storage, volume, control| {
            settle(volume, control);
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
            assert_eq!(volume.readiness(), State::Loaded);
            assert_eq!(writes(control), 0, "the warm path writes no device unit");
            assert_eq!(
                units(storage),
                writer,
                "the allocator holds exactly the restored extents"
            );
            assert_eq!(resident(storage), 3);
            let mut reader = storage.register().unwrap();
            assert!(
                matches!(lookup(&mut reader, &key(1), 4), Err(LookupError::Contended)),
                "no grant at Loaded"
            );
            assert_eq!(
                volume.begin_replay(storage.feed_contract(), 0),
                Ok(State::Replaying)
            );
            assert!(
                matches!(lookup(&mut reader, &key(1), 4), Err(LookupError::Contended)),
                "no grant while replay runs"
            );
            assert_eq!(volume.complete_replay(), Ok(State::Live));
            let report = volume.recovery_report();
            let readiness = report.phase(super::super::report::RecoveryPhase::RetainedReadiness);
            assert_eq!(
                readiness.rows, 3,
                "the report counts the restored rows at Live"
            );
            for n in 1..=3 {
                assert_eq!(
                    served(storage, volume, control, n),
                    [&key(n)[..4], &[n; 40][..]].concat()
                );
            }
            assert_eq!(storage.withdraw(), State::Withheld);
            assert!(
                matches!(lookup(&mut reader, &key(1), 4), Err(LookupError::Contended)),
                "no grant after the withdrawal"
            );
        },
    );
}

/// A fill reservation at every stage of the warm bootstrap, the commit's own tick included, refuses
/// `Bootstrapping` and changes no table, and no payload write is submitted; the first reservation after `Live`
/// succeeds and takes no unit a restored extent holds.
#[test]
fn a_reservation_at_every_warm_stage_refuses_and_writes_nothing() {
    let (store, entries, writer) = written(3);
    relaunch(
        &store,
        |storage, reader| decoded(storage, &entries, reader, false),
        |storage, volume, control| {
            let mut seen = Vec::new();
            while volume.readiness().initializing() {
                if let Some(at) = stage(volume)
                    && seen.last() != Some(&at)
                {
                    seen.push(at);
                }
                let before = (units(storage), resident(storage));
                let mut budget = super::super::super::budget::WorkBudget::new(1 << 20);
                let reserved = storage.reserve(Some(0), Some(100), &mut budget);
                assert_eq!(
                    reserved.err(),
                    Some(ReserveError::Bootstrapping),
                    "{:?}",
                    stage(volume)
                );
                assert_eq!(
                    (units(storage), resident(storage)),
                    before,
                    "{:?}",
                    stage(volume)
                );
                tick(volume, control);
                assert!(seen.len() < 16, "the load ends");
            }
            assert_eq!(seen, STAGES, "every stage ran under a refused reservation");
            assert_eq!(writes(control), 0);
            live(storage, volume);
            let mut budget = super::super::super::budget::WorkBudget::new(1 << 20);
            let reservation = storage
                .reserve(Some(0), Some(100), &mut budget)
                .expect("fills open at Live");
            let (start, len) = (
                reservation.locator().start_unit(),
                u64::from(reservation.locator().len_units()),
            );
            let taken = |entry: &CaptureEntry| {
                let locator = super::ExtentLocator::from_bits(entry.extents[0]);
                let held =
                    locator.start_unit()..locator.start_unit() + u64::from(locator.len_units());
                held.start < start + len && start < held.end
            };
            assert!(
                !entries.iter().any(taken),
                "the fill takes no restored unit"
            );
            assert_eq!(units(storage).0, writer.0 - len);
        },
    );
}

/// A load decoded from the writer's entries.
fn whole(entries: &[CaptureEntry]) -> impl FnOnce(&Storage<TestPlatform>, u64) -> SlotLoad + '_ {
    move |storage, reader| decoded(storage, entries, reader, false)
}

/// `entry` copied under `key(n)` and slot `slot`, at incarnation 1.
fn named(entry: &CaptureEntry, n: u8, slot: u64) -> CaptureEntry {
    CaptureEntry {
        key: key(n),
        allocation: slot << 32 | 1,
        ..entry.clone()
    }
}

/// Asserts that the attempt ended before its commit with `outcome`, the pool as the relaunch found it and no device
/// command, and that a stale `LoadComplete` reopens nothing.
fn refused(
    storage: &Storage<TestPlatform>,
    volume: &TestVolume<'_, '_>,
    control: &SimControl,
    (outcome, before): (MetadataOutcome, (u64, u64)),
) {
    assert_eq!(volume.metadata_outcome(), outcome);
    assert_eq!(volume.readiness(), State::Withheld);
    assert_eq!(
        (units(storage), resident(storage)),
        (before, 0),
        "no table write"
    );
    assert_eq!(control.capture().events.len(), 0, "no device command");
    assert_eq!(
        storage.readiness.apply(Event::LoadComplete),
        Ok(State::Withheld)
    );
}

/// The free and placeable units of the relaunched pool before any load.
fn pristine(storage: &Storage<TestPlatform>) -> (u64, u64) {
    units(storage)
}

/// A withdrawal at every stage before the commit ends the attempt `Withheld`, whether the tick's stop check or the
/// stage's own read under the pool gate or a publisher's read of the word observes it: no later hold writes a table and
/// no lane's install or publication cursor moves, so the
/// allocator's units and the installed slots stay as the withdrawal found them and every installed slot keeps its
/// extent; the commit never lands, a stale `LoadComplete` changes nothing, and nothing is written to the device.
#[test]
fn a_withdrawal_at_every_warm_stage_ends_withheld_and_frees_no_extent() {
    let (store, entries, _) = written(3);
    for at in STAGES {
        relaunch(&store, whole(&entries), |storage, volume, control| {
            reach(volume, control, at);
            let before = (units(storage), resident(storage));
            let cursors = progress(volume);
            assert_eq!(storage.withdraw(), State::Withheld, "{at:?}");
            // A withdrawal landing after a tick's stop check: the stage itself reads `Withheld` under the gate.
            for _ in 0..4 {
                volume.warm_step();
            }
            for _ in 0..8 {
                tick(volume, control);
            }
            assert_eq!(volume.readiness(), State::Withheld, "{at:?}");
            assert_ne!(volume.metadata_outcome(), MetadataOutcome::Open, "{at:?}");
            assert_eq!(
                (units(storage), resident(storage)),
                before,
                "{at:?}: no table write after the withdrawal"
            );
            assert_eq!(
                progress(volume),
                cursors,
                "{at:?}: no install or index publication after the withdrawal"
            );
            assert_eq!(
                storage.readiness.apply(Event::LoadComplete),
                Ok(State::Withheld),
                "{at:?}"
            );
            assert!(
                volume
                    .metadata
                    .helpers
                    .as_ref()
                    .is_none_or(|helpers| !helpers.accepting()),
                "{at:?}: the conversions are cancelled"
            );
            assert_eq!(writes(control), 0, "{at:?}");
        });
    }
}

/// A crash at every stage before the commit leaves the media byte for byte as the writer left it, and the next
/// relaunch loads the same entries warm and serves them.
#[test]
fn a_crash_at_every_warm_stage_relaunches_to_the_same_set() {
    let (store, entries, writer) = written(3);
    let image = store.borrow().clone();
    for at in STAGES {
        relaunch(&store, whole(&entries), |_, volume, control| {
            reach(volume, control, at)
        });
        assert!(
            *store.borrow() == image,
            "{at:?}: the crashed attempt wrote nothing"
        );
        relaunch(&store, whole(&entries), |storage, volume, control| {
            settle(volume, control);
            assert_eq!(units(storage), writer, "{at:?}");
            live(storage, volume);
            assert_eq!(
                served(storage, volume, control, 2),
                [&key(2)[..4], &[2; 40][..]].concat()
            );
        });
    }
}

/// A conversion that panics on its helper closes the attempt `MetadataFailed` with no device command, which keeps the
/// media as recovery evidence, and a relaunch over the same media loads warm.
#[test]
fn a_conversion_panic_closes_the_attempt_and_a_relaunch_loads_warm() {
    let (store, entries, _) = written(3);
    super::PANIC.with(|panic| panic.set(true));
    relaunch(&store, whole(&entries), |storage, volume, control| {
        let before = pristine(storage);
        settle(volume, control);
        assert_eq!(volume.readiness(), State::Closed);
        assert_eq!(volume.metadata_outcome(), MetadataOutcome::MetadataFailed);
        assert!(
            volume.warm_decided(),
            "a failure after the stage decides the account"
        );
        assert_eq!((units(storage), resident(storage)), (before, 0));
        assert_eq!(control.capture().events.len(), 0, "no device command");
    });
    super::PANIC.with(|panic| panic.set(false));
    relaunch(&store, whole(&entries), |storage, volume, control| {
        settle(volume, control);
        live(storage, volume);
        assert_eq!(
            served(storage, volume, control, 1),
            [&key(1)[..4], &[1; 40][..]].concat()
        );
    });
}

/// A slot whose entries overlap gets the guard's refusal, and the attempt ends `Unloadable(Overlap)` with no table
/// write and no device command; the same media relaunched with the writer's own load serves.
#[test]
fn a_guard_refused_load_installs_nothing_and_keeps_the_media() {
    let (store, mut entries, _) = written(3);
    let mut planted = entries.clone();
    planted.push(named(&entries[0], 9, 7));
    relaunch(
        &store,
        |storage, reader| {
            let load = decoded(storage, &planted, reader, false);
            assert_eq!(load.verdict, Err(LoadRefusal::Overlap));
            load
        },
        |storage, volume, control| {
            let before = pristine(storage);
            settle(volume, control);
            refused(
                storage,
                volume,
                control,
                (MetadataOutcome::Unloadable(LoadRefusal::Overlap), before),
            );
        },
    );
    entries.sort_by_key(|entry| entry.key);
    relaunch(&store, whole(&entries), |storage, volume, control| {
        settle(volume, control);
        live(storage, volume);
        assert_eq!(
            served(storage, volume, control, 3),
            [&key(3)[..4], &[3; 40][..]].concat()
        );
    });
}

/// Two restored extents sharing a unit, in a load no guard judged, fail the held bitmap on their helpers, and the
/// attempt ends `Unloadable(Overlap)` before the allocator's hold.
#[test]
fn an_overlapping_restored_extent_refuses_before_any_table_write() {
    let (store, entries, _) = written(3);
    let mut planted = entries.clone();
    planted.push(named(&entries[0], 9, 7));
    relaunch(
        &store,
        |storage, _| handed(storage, planted),
        |storage, volume, control| {
            let before = pristine(storage);
            settle(volume, control);
            refused(
                storage,
                volume,
                control,
                (MetadataOutcome::Unloadable(LoadRefusal::Overlap), before),
            );
        },
    );
}

/// Two restored entries naming one slot over disjoint extents install the first and refuse the second `NotFree`, so
/// the attempt ends `Unloadable(Slot)` before the commit: the readiness never reads `Loaded`, and the installed slot
/// keeps its extent.
#[test]
fn a_duplicate_slot_ends_the_attempt_before_commit() {
    let (store, entries, _) = written(3);
    let mut planted = entries.clone();
    let mut twin = named(&entries[0], 9, 0);
    twin.allocation = entries[0].allocation;
    twin.extents = vec![super::ExtentLocator::new(8, 1).unwrap().bits()];
    planted.push(twin);
    relaunch(
        &store,
        |storage, _| handed(storage, planted),
        |storage, volume, control| {
            settle(volume, control);
            assert_eq!(
                volume.metadata_outcome(),
                MetadataOutcome::Unloadable(LoadRefusal::Slot)
            );
            assert_eq!(volume.readiness(), State::Withheld);
            assert!(resident(storage) >= 1, "the installed slots stay");
            assert_eq!(units(storage).0, 9 - 4, "every restored extent stays held");
            assert_eq!(
                storage.readiness.apply(Event::LoadComplete),
                Ok(State::Withheld)
            );
            assert_eq!(writes(control), 0);
        },
    );
}

/// A slot two ascending entries name refuses in the install tick that reaches it, whether one destination's run holds
/// both entries or two destinations' runs hold one each: the entries of lower rank in the window stay resident, the
/// refused entry's run keeps it and the marked entries behind it, the attempt ends `Unloadable(Slot)` before the
/// commit with every restored extent held, and no device command is issued.
#[test]
fn a_slot_two_ascending_entries_name_refuses_in_the_tick_that_reaches_it() {
    let (store, entries, _) = written(3);
    assert!(entries.is_sorted_by_key(CaptureEntry::slot));
    let mut twin = named(&entries[0], 9, 0);
    twin.allocation = entries[0].allocation;
    twin.extents = vec![super::ExtentLocator::new(8, 1).unwrap().bits()];
    let planted = [
        entries[0].clone(),
        twin,
        entries[1].clone(),
        entries[2].clone(),
    ];
    // One run holds the twin behind its slot's first entry, then the twin alone is a second destination's run.
    for (apart, installed) in [(false, 1), (true, 3)] {
        relaunch(
            &store,
            |storage, _| {
                let mut held = printed(storage, &planted);
                let shards = match apart {
                    false => vec![vec![Chunk::holding(&held)]],
                    true => {
                        let twin = held.remove(1);
                        vec![vec![Chunk::holding(&[twin])], vec![Chunk::holding(&held)]]
                    }
                };
                SlotLoad::handed(shards)
            },
            |storage, volume, control| {
                reach(volume, control, Stage::Install);
                let warm = volume.metadata.warm.as_ref().unwrap();
                let runs: Vec<(usize, usize)> = (warm.converted.iter())
                    .map(|converted| (converted.placed.len(), converted.late.len()))
                    .collect();
                let expected: &[(usize, usize)] = if apart { &[(3, 0), (1, 0)] } else { &[(4, 0)] };
                assert_eq!(runs, expected, "the slot's first entry leads the first run");
                tick(volume, control);
                assert_eq!(
                    volume.metadata_outcome(),
                    MetadataOutcome::Unloadable(LoadRefusal::Slot),
                    "apart {apart}"
                );
                assert_eq!(volume.readiness(), State::Withheld);
                assert_eq!(resident(storage), installed, "apart {apart}");
                let taken: &[usize] = if apart { &[3, 0, 0, 0] } else { &[1, 0] };
                assert_eq!(progress(volume).0[0].taken, taken, "apart {apart}");
                assert_eq!(units(storage).0, 9 - 4, "every restored extent stays held");
                assert_eq!(writes(control), 0);
            },
        );
    }
}

/// A slot two late entries of one run name refuses at the second in the install tick that reaches it: the first stays
/// resident, the late run keeps the second and the ascending run keeps the entry the window had marked, the attempt
/// ends `Unloadable(Slot)` before the commit with every restored extent held, and no device command is issued.
#[test]
fn a_slot_two_late_entries_name_refuses_at_the_second() {
    let (store, entries, _) = written(3);
    assert!(entries.is_sorted_by_key(CaptureEntry::slot));
    let mut twin = named(&entries[0], 9, 0);
    twin.allocation = entries[0].allocation;
    twin.extents = vec![super::ExtentLocator::new(8, 1).unwrap().bits()];
    let planted = [
        entries[2].clone(),
        entries[0].clone(),
        twin,
        entries[1].clone(),
    ];
    relaunch(
        &store,
        |storage, _| SlotLoad::handed(vec![vec![Chunk::holding(&printed(storage, &planted))]]),
        |storage, volume, control| {
            reach(volume, control, Stage::Install);
            let converted = &volume.metadata.warm.as_ref().unwrap().converted[0];
            assert_eq!((converted.placed.len(), converted.late.len()), (1, 3));
            tick(volume, control);
            assert_eq!(
                volume.metadata_outcome(),
                MetadataOutcome::Unloadable(LoadRefusal::Slot)
            );
            assert_eq!(volume.readiness(), State::Withheld);
            assert_eq!(resident(storage), 1);
            assert_eq!(progress(volume).0[0].taken, [0, 1]);
            assert_eq!(units(storage).0, 9 - 4, "every restored extent stays held");
            assert_eq!(writes(control), 0);
        },
    );
}

/// A late entry's refusal stops the tick: a later piece's late entry below the bound stays uninstalled, each run keeps
/// the entries the tick did not install, and the attempt ends `Unloadable(Slot)` with every restored extent held.
#[test]
fn a_refused_late_entry_stops_the_tick_before_a_later_run_installs() {
    let (store, entries, _) = written(4);
    assert!(entries.is_sorted_by_key(CaptureEntry::slot));
    let mut twin = named(&entries[0], 9, 0);
    twin.allocation = entries[0].allocation;
    twin.extents = vec![super::ExtentLocator::new(8, 1).unwrap().bits()];
    // The first piece's late entries name one slot twice; the second piece's late entry lies below the same bound.
    let first = [entries[2].clone(), entries[0].clone(), twin];
    let second = [entries[3].clone(), entries[1].clone()];
    relaunch(
        &store,
        |storage, _| {
            let chunk = |planted: &[CaptureEntry]| vec![Chunk::holding(&printed(storage, planted))];
            SlotLoad::handed(vec![chunk(&second), chunk(&first)])
        },
        |storage, volume, control| {
            reach(volume, control, Stage::Install);
            let warm = volume.metadata.warm.as_ref().unwrap();
            let runs: Vec<(usize, usize)> = (warm.converted.iter())
                .map(|converted| (converted.placed.len(), converted.late.len()))
                .collect();
            assert_eq!(runs, [(1, 2), (1, 1)], "the twins' piece leads");
            tick(volume, control);
            assert_eq!(
                volume.metadata_outcome(),
                MetadataOutcome::Unloadable(LoadRefusal::Slot)
            );
            assert_eq!(volume.readiness(), State::Withheld);
            assert_eq!(resident(storage), 1, "the later piece's late entry waits");
            assert_eq!(progress(volume).0[0].taken, [0, 1, 0, 0]);
            assert_eq!(units(storage).0, 9 - 5, "every restored extent stays held");
            assert_eq!(writes(control), 0);
        },
    );
}

/// A lane's range of a run holds exactly the entries whose slots the lane holds, its first and last slots included,
/// over a run ascending by slot and over a run ordered by lane whose slots descend within each lane.
#[test]
fn a_lane_takes_the_entries_of_its_slot_range_from_a_run() {
    let placed = |slot: u32| super::Placed {
        slot,
        expires_at_s: 0,
        locator: super::ExtentLocator::new(0, 1).unwrap(),
        chunk: 0,
        at: 0,
        print: 0,
    };
    let slots = |run: &[super::Placed]| run.iter().map(|placed| placed.slot).collect::<Vec<_>>();
    let ascending = [0, 127, 128, 255, 256, 383].map(placed);
    let by_lane = [127, 0, 255, 128, 383, 256].map(placed);
    for (lane, held) in [[0, 127], [128, 255], [256, 383]].into_iter().enumerate() {
        let range = (lane * 128, (lane + 1) * 128);
        assert_eq!(slots(super::within(&ascending, range)), held);
        assert_eq!(slots(super::within(&by_lane, range)), [held[1], held[0]]);
    }
    assert_eq!(super::within(&ascending, (384, 512)), []);
}

/// Two restored keys with the same fingerprint in one destination cause `Collided` before any table write, including
/// when conversion splits their chunks into separate pieces.
#[test]
fn a_fingerprint_collision_ends_collided_before_any_table_write() {
    let (store, entries, _) = written(2);
    for (split, at) in [(false, 0), (true, 0), (false, DESTINATIONS - 1)] {
        relaunch(
            &store,
            |storage, _| {
                let mut load = handed(storage, entries.clone());
                let collided = collided(&mut load);
                load.shards[at] = if split {
                    let entries = collided.captured().into_iter();
                    entries.map(|pair| Chunk::holding(&[pair])).collect()
                } else {
                    vec![collided]
                };
                load
            },
            |storage, volume, control| {
                let before = pristine(storage);
                reach(volume, control, Stage::Mark);
                let warm = volume.metadata.warm.as_ref().expect("staged");
                let pieces = (warm.converted.iter()).filter(|piece| piece.destination == at);
                assert!(
                    !split || pieces.count() > 1,
                    "destination 0 lands in two pieces"
                );
                assert!(
                    at == 0 || at >= warm.split.lanes,
                    "a later round deals destination {at}"
                );
                settle(volume, control);
                refused(
                    storage,
                    volume,
                    control,
                    (MetadataOutcome::Collided, before),
                );
                assert!(volume.warm_decided(), "the collision decides the account");
            },
        );
    }
}

/// The conversion counts a covered entry before the marks' collision check, so the recovery report keeps one
/// omission for a load that ends `Collided` and installs no entry.
#[test]
fn a_load_refused_at_the_marks_keeps_its_omitted_count() {
    let (store, entries, _) = written(3);
    relaunch_covered(
        &store,
        &[key(2)],
        |storage, _| {
            let mut load = handed(storage, entries.clone());
            let collided = collided(&mut load);
            load.shards[0] = vec![collided];
            load
        },
        |storage, volume, control| {
            let before = pristine(storage);
            reach(volume, control, Stage::Mark);
            let warm = volume.metadata.warm.as_ref().expect("staged");
            assert_eq!(warm.omitted, 1, "the conversion omitted the covered entry");
            settle(volume, control);
            refused(
                storage,
                volume,
                control,
                (MetadataOutcome::Collided, before),
            );
            assert!(volume.warm_decided(), "the collision decides the account");
            let retention = crate::failover::report::Retention::of(&volume.recovery_report());
            assert_eq!((retention.installed, retention.omitted), (0, 1));
        },
    );
}

/// Two keys of one fingerprint in a publication group above the first, the highest group of 64 spread fingerprints,
/// refuse the conversion `Collided`, so the collision check covers every group and not only the first.
#[test]
fn a_fingerprint_collision_in_a_later_publication_group_ends_collided() {
    let (store, entries, _) = written_in(many, 1);
    relaunch_in(many, &store, &[], whole(&entries), |storage, volume, _| {
        let index = storage.index().unwrap();
        let offsets = super::groups_of(&index.geometry).0;
        let group = |print: u64| {
            let route = index.hasher.reroute_unpaid(print, &index.geometry);
            let route = route.unwrap();
            offsets[route.position()] + (route.bucket() >> super::RUN_BITS)
        };
        let prints: Vec<u64> = (0u64..64).map(|n| n.wrapping_mul(SPREAD) | 1).collect();
        let at = (0..prints.len()).max_by_key(|&n| group(prints[n])).unwrap();
        assert!(group(prints[at]) > 0);
        let mut held = planted(&entries[0], 64, false, prints.iter().copied());
        held[(at + 1) % prints.len()].1 = prints[at];
        let (converted, _, _, _) = measured(storage, volume, &held);
        assert_eq!(converted.refusal, Some(MetadataOutcome::Collided));
    });
}

/// An entry whose `(key, version)` the tenure's coverage covers and an entry whose deadline lies below the earliest
/// bound of the load's reading are omitted: their keys miss at `Live`, their units are free, so the allocator's free
/// units exceed the writer's by theirs, and the conversion counts them; the other entry serves.
#[test]
fn a_covered_or_expired_entry_is_omitted_and_its_units_stay_free() {
    let (store, mut entries, writer) = written(3);
    let expired = entries
        .iter_mut()
        .find(|entry| entry.key == key(3))
        .unwrap();
    expired.deadline_ns = u64::from(expired.lifetime_ms) * 1_000_000 + 1;
    relaunch_covered(
        &store,
        &[key(2)],
        whole(&entries),
        |storage, volume, control| {
            settle(volume, control);
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
            let warm = volume.metadata.warm.as_ref().unwrap();
            assert_eq!((warm.rows(), warm.omitted), (1, 2));
            assert_eq!(units(storage).0, writer.0 + 2);
            live(storage, volume);
            let mut reader = storage.register().unwrap();
            for n in [2, 3] {
                assert!(
                    matches!(lookup(&mut reader, &key(n), 4), Err(LookupError::Missing)),
                    "key {n}"
                );
            }
            assert_eq!(
                served(storage, volume, control, 1),
                [&key(1)[..4], &[1; 40][..]].concat()
            );
        },
    );
}

/// A chunk that dropped its first entry, as a seal drops a superseded one, names each entry it holds by the entry's
/// place in the run: the places skip the dropped one and each reads its own entry back. The load installs the held
/// entries from those places, so the dropped key misses at `Live` and each held key serves its own bytes.
#[test]
fn a_chunk_that_dropped_an_entry_installs_the_held_entries_from_their_own_places() {
    let (store, entries, writer) = written(3);
    relaunch(
        &store,
        |storage, _| {
            let chunk = Chunk::holding(&printed(storage, &entries)).without(&[0]);
            assert_eq!(chunk.len(), 2);
            let places: Vec<usize> = chunk.placed().map(|(at, _, _)| at).collect();
            assert_eq!(places, [1, 2]);
            for (at, entry, _) in chunk.placed() {
                assert_eq!(chunk.at(at), entry);
                assert_eq!(entry.identity.key, entries[at].key);
            }
            SlotLoad::handed(vec![vec![chunk]])
        },
        |storage, volume, control| {
            settle(volume, control);
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
            assert_eq!(
                units(storage).0,
                writer.0 + 1,
                "the dropped entry's unit is free"
            );
            live(storage, volume);
            let dropped = entries[0].key;
            let mut reader = storage.register().unwrap();
            assert!(matches!(
                lookup(&mut reader, &dropped, 4),
                Err(LookupError::Missing)
            ));
            drop(reader);
            for entry in &entries[1..] {
                let n = entry.key[0];
                assert_eq!(
                    served(storage, volume, control, n),
                    [&key(n)[..4], &[n; 40][..]].concat()
                );
            }
        },
    );
}

/// Entries that name each other's extents restore, but each read finds the other record's header at residency and
/// refuses it, so no byte of the wrong object is exposed.
#[test]
fn a_reused_payload_unit_fails_identity_at_residency() {
    let (store, mut entries, _) = written(2);
    let (first, second) = (entries[0].extents.clone(), entries[1].extents.clone());
    (entries[0].extents, entries[1].extents) = (second, first);
    relaunch(&store, whole(&entries), |storage, volume, control| {
        settle(volume, control);
        live(storage, volume);
        let mut reader = storage.register().unwrap();
        for n in [1, 2] {
            let lease = lookup(&mut reader, &key(n), 4).expect("the index maps the restored key");
            let delivered = read_back(volume, control, &lease);
            assert!(
                matches!(delivered.status, ReadStatus::HeaderMismatch(_)),
                "key {n}: {:?}",
                delivered.status
            );
            assert!(delivered.bytes.is_empty(), "key {n}");
        }
    });
}

/// A planted edit of a decoded load.
type Edit = fn(&mut SlotLoad);

/// A slot torn in its last data unit loads the entries of its intact units only with its loss record: the damage
/// names the failed unit and raises the stale-write alarm, the survivors serve, the lost entries miss and their units
/// are free. A load whose verdict refuses installs nothing, an unread unit or suffix block refuses
/// `Unreadable`, damaged suffix history refuses `StaleWrite`, and so does damage that leaves no entry of the slot,
/// each with no table write.
#[test]
fn a_damaged_load_installs_its_survivors_only_with_its_loss_record() {
    let (store, entries, writer) = written_in(wide, 44);
    let lost: Vec<[u8; 32]> = entries[41..].iter().map(|entry| entry.key).collect();
    relaunch_in(
        wide,
        &store,
        &[],
        |storage, reader| decoded(storage, &entries, reader, true),
        |storage, volume, control| {
            settle(volume, control);
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
            let warm = volume.metadata.warm.as_ref().unwrap();
            let report = volume.recovery_report().warm;
            assert_eq!(
                (
                    report.failed_units,
                    report.unread_units,
                    report.first_damage.map(|first| matches!(
                        first,
                        super::super::super::recovery::checkpoint::UnitDamage::Chunk { unit: 2 }
                    )),
                    report.omitted,
                    report.installed
                ),
                (1, 0, Some(true), 0, 41),
                "the loss record names the torn unit and the installed count"
            );
            // The committed load decides the report entry's retention account, which names the same loss.
            assert!(volume.warm_decided(), "the commit decides the account");
            let full = volume.recovery_report();
            let retention = crate::failover::report::Retention::of(&full);
            assert_eq!(
                (
                    retention.failed_units,
                    retention.unread_units,
                    retention.first_damage,
                    retention.installed,
                    retention.omitted,
                    retention.held_units,
                ),
                (
                    1,
                    0,
                    Some(crate::failover::report::Damage::Chunk),
                    41,
                    0,
                    full.held_units,
                ),
                "{retention:?}"
            );
            assert_eq!(warm.rows(), 41);
            assert_eq!(
                units(storage).0,
                writer.0 + lost.len() as u64,
                "the lost entries' units are free"
            );
            live(storage, volume);
            let mut reader = storage.register().unwrap();
            for key in &lost {
                assert!(matches!(
                    lookup(&mut reader, key, 4),
                    Err(LookupError::Missing)
                ));
            }
            let survivor = entries[0].key;
            let lease = lookup(&mut reader, &survivor, 4).expect("a survivor serves");
            assert_eq!(
                read_back(volume, control, &lease).status,
                ReadStatus::Complete
            );
        },
    );
    let refusals: [(Edit, LoadRefusal); 4] = [
        (
            |load| load.verdict = Err(LoadRefusal::StaleWrite),
            LoadRefusal::StaleWrite,
        ),
        (|load| load.suffix.unread.push(5), LoadRefusal::Unreadable),
        (
            |load| {
                load.suffix
                    .damage
                    .push(super::super::super::recovery::delta_replay::Hole {
                        lsn: 5,
                        cause: super::super::super::recovery::delta::BlockHole::Chunk,
                    })
            },
            LoadRefusal::StaleWrite,
        ),
        (
            |load| {
                let withheld = super::super::super::recovery::delta::identity_of(
                    &load.shards[0][0].captured()[0].0,
                );
                load.suffix.withheld.push(withheld);
            },
            LoadRefusal::Unrestorable,
        ),
    ];
    for (edit, refusal) in refusals {
        relaunch_in(
            wide,
            &store,
            &[],
            |storage, reader| {
                let mut load = decoded(storage, &entries, reader, true);
                edit(&mut load);
                load
            },
            |storage, volume, control| {
                let before = pristine(storage);
                settle(volume, control);
                let outcome = volume.metadata_outcome();
                assert_eq!(
                    crate::failover::report::Metadata::from(&outcome),
                    crate::failover::report::Metadata::Unloadable,
                    "{refusal:?}"
                );
                assert!(
                    volume.warm_decided(),
                    "{refusal:?}: a refused load keeps its recorded account"
                );
                refused(
                    storage,
                    volume,
                    control,
                    (MetadataOutcome::Unloadable(refusal), before),
                );
            },
        );
    }
    relaunch_in(
        wide,
        &store,
        &[],
        |storage, reader| {
            let (layout, ck, bytes) = super::super::super::checkpoint::tests::slot_image_under(
                &entries,
                false,
                entries[0].session,
            );
            let index = storage.index().unwrap();
            let mut slot = SlotReader::new(
                Crc32c::detect(),
                &layout,
                shard(),
                (ck, 0, &[]),
                reader,
                (limits(storage), &EngineBudget::unlimited()),
                (index.hasher.clone(), DESTINATIONS),
            )
            .unwrap();
            let _ = bytes;
            while !slot.done() {
                let range = slot.next_read().unwrap();
                slot.fail_read(range);
            }
            slot.load()
        },
        |storage, volume, control| {
            let before = pristine(storage);
            settle(volume, control);
            refused(
                storage,
                volume,
                control,
                (MetadataOutcome::Unloadable(LoadRefusal::Unreadable), before),
            );
        },
    );
    // Every unit of the slot fails its check, so the damage leaves no entry of the slot: committing would replace the
    // retained set with the suffix's entries alone, and the attempt refuses `StaleWrite` with the loss recorded and no
    // table write.
    relaunch_in(
        wide,
        &store,
        &[],
        |storage, reader| {
            let (layout, ck, bytes) = super::super::super::checkpoint::tests::slot_image_under(
                &entries,
                false,
                entries[0].session,
            );
            let index = storage.index().unwrap();
            let mut slot = SlotReader::new(
                Crc32c::detect(),
                &layout,
                shard(),
                (ck, 0, &[]),
                reader,
                (limits(storage), &EngineBudget::unlimited()),
                (index.hasher.clone(), DESTINATIONS),
            )
            .unwrap();
            while !slot.done() {
                let range = slot.next_read().unwrap();
                let start = range.start() as usize;
                let mut torn = bytes[start..start + range.byte_len() as usize].to_vec();
                torn.iter_mut().for_each(|byte| *byte ^= 0x5a);
                slot.complete(range, &torn);
            }
            let mut load = slot.load();
            assert_eq!(load.slot_found, 0, "every unit of the slot failed");
            // A live suffix entry beside the lost slot leaves the load nonempty, and the attempt still refuses.
            let index = storage.index().unwrap();
            let mut words = [0; crate::index::LANES];
            (index.hasher).fingerprints(std::slice::from_ref(&entries[0].key), &mut words);
            load.shards[0].push(Chunk::holding(&[(entries[0].clone(), words[0])]));
            load
        },
        |storage, volume, control| {
            let before = pristine(storage);
            settle(volume, control);
            assert!(
                volume.recovery_report().warm.failed_units > 0,
                "the loss is recorded"
            );
            refused(
                storage,
                volume,
                control,
                (MetadataOutcome::Unloadable(LoadRefusal::StaleWrite), before),
            );
        },
    );
    // An empty checkpoint is unit 0 alone, which holds only counts: its damage loses no entry, so the load opens with
    // the suffix's entry and the damage in the report.
    relaunch_in(
        wide,
        &store,
        &[],
        |storage, reader| {
            let (layout, ck, bytes) = super::super::super::checkpoint::tests::slot_image_under(
                &[],
                false,
                entries[0].session,
            );
            assert_eq!(ck.units, 1, "an empty checkpoint is one unit");
            let index = storage.index().unwrap();
            let mut slot = SlotReader::new(
                Crc32c::detect(),
                &layout,
                shard(),
                (ck, 0, &[]),
                reader,
                (limits(storage), &EngineBudget::unlimited()),
                (index.hasher.clone(), DESTINATIONS),
            )
            .unwrap();
            while !slot.done() {
                let range = slot.next_read().unwrap();
                let start = range.start() as usize;
                let mut torn = bytes[start..start + range.byte_len() as usize].to_vec();
                torn.iter_mut().for_each(|byte| *byte ^= 0x5a);
                slot.complete(range, &torn);
            }
            let mut load = slot.load();
            assert!(load.damage.is_some(), "unit 0 failed");
            let mut words = [0; crate::index::LANES];
            (index.hasher).fingerprints(std::slice::from_ref(&entries[0].key), &mut words);
            load.shards[0].push(Chunk::holding(&[(entries[0].clone(), words[0])]));
            load
        },
        |storage, volume, control| {
            settle(volume, control);
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
            assert_eq!(volume.recovery_report().warm.failed_units, 1);
            assert_eq!(resident(storage), 1, "the suffix's entry installs");
        },
    );
}

/// The warm bootstrap reads and writes no device unit, so a foreign tenure's activation record at unit 0 neither
/// reaches the load nor changes: the slot's entries serve and unit 0 keeps the foreign bytes.
#[test]
fn a_foreign_unit_zero_record_changes_no_warm_load() {
    use super::super::super::recovery::session_at;
    use super::super::activation::{Activation, RECORD_LEN};
    let (store, entries, _) = written(2);
    let mut record = [0; RECORD_LEN];
    Activation::of(
        crate::failover::records::VolumeId::new("vol-0fedcba9876543210").unwrap(),
        &session_at(7, 2),
    )
    .encode(Crc32c::detect(), &mut record);
    store.borrow_mut()[..RECORD_LEN].copy_from_slice(&record);
    relaunch(&store, whole(&entries), |storage, volume, control| {
        settle(volume, control);
        assert_eq!(
            control.capture().events.len(),
            0,
            "the warm bootstrap submits no device command"
        );
        live(storage, volume);
        assert_eq!(
            served(storage, volume, control, 1),
            [&key(1)[..4], &[1; 40][..]].concat()
        );
    });
    assert_eq!(store.borrow()[..RECORD_LEN], record[..]);
}

/// An install worker that panics, here at a free slot whose word carries a flag, leaves the pool gate poisoned, so
/// tables the other lanes wrote and no fold completed admit no holder, and ends the attempt `MetadataFailed` with no
/// device command and no commit: a reservation refuses `Closed`, as the ended attempt closed admission, the media stay
/// as the writer left them, and a relaunch loads the same entries warm.
#[test]
fn a_panicking_install_worker_poisons_the_gate_and_fails_the_attempt_closed() {
    let (store, entries, writer) = written(3);
    let image = store.borrow().clone();
    relaunch(&store, whole(&entries), |storage, volume, control| {
        reach(volume, control, Stage::Install);
        // `Lane::install` panics at a free slot whose word carries a flag, before it writes the slot.
        let slot = entries[1].slot();
        storage.live_pool().unwrap().records()[slot]
            .ident
            .store(u64::MAX, std::sync::atomic::Ordering::Relaxed);
        tick(volume, control);
        assert_eq!(volume.metadata_outcome(), MetadataOutcome::MetadataFailed);
        assert_ne!(volume.readiness(), State::Loaded);
        let live = storage.live_pool().unwrap();
        assert!(
            matches!(
                live.try_lock_quiet(),
                Err(super::super::super::gate::GateError::Poisoned)
            ),
            "the gate stays poisoned"
        );
        let mut budget = super::super::super::budget::WorkBudget::new(1 << 20);
        // The ended attempt closed admission, so the reservation refuses before it reaches the poisoned gate.
        assert!(matches!(
            storage.reserve(Some(0), Some(100), &mut budget),
            Err(ReserveError::Closed)
        ));
        assert_eq!(control.capture().events.len(), 0, "no device command");
    });
    assert!(*store.borrow() == image);
    relaunch(&store, whole(&entries), |storage, volume, control| {
        settle(volume, control);
        assert_eq!(units(storage), writer);
        live(storage, volume);
        assert_eq!(
            served(storage, volume, control, 3),
            [&key(3)[..4], &[3; 40][..]].concat()
        );
    });
}

/// Mark bands of one word each: an extent crossing from the first band into the second spills its bits past the first
/// band's words, and the holder finds a unit the second band marked, or marks the spilled units once when no other
/// extent holds them; disjoint extents on either side of the edge mark without an overlap.
#[test]
fn an_overlap_across_a_mark_band_edge_is_found_by_the_holder() {
    let pack = |start: u64, units: u32| super::ExtentLocator::new(start, units).unwrap().bits();
    let cases = [
        (vec![pack(63, 2)], vec![pack(64, 1)], true, [1 << 63, 1]),
        (vec![pack(63, 2)], vec![pack(65, 1)], false, [1 << 63, 0b11]),
        (
            vec![pack(10, 2)],
            vec![pack(64, 3)],
            false,
            [0b11 << 10, 0b111],
        ),
    ];
    for (first, second, overlap, words) in cases {
        let mut held = vec![0; 2];
        let bands = [first, second];
        let (low, high) = held.split_at_mut(1);
        let marks = [
            super::mark(low, 0, bands[0].iter()),
            super::mark(high, 1, bands[1].iter()),
        ];
        assert_eq!(super::overlapped(&mut held, marks), overlap, "{bands:?}");
        if !overlap {
            assert_eq!(held, words, "{bands:?}");
        }
    }
}

/// The same band edge on a volume: on the wide storage's two mark bands, one bitmap word each, a two-unit extent from
/// unit 63 and a one-unit extent at unit 64 refuse the attempt `Overlap` before any table write.
#[test]
fn an_overlap_across_a_mark_band_edge_refuses_before_any_table_write() {
    let (store, entries, _) = written_in(wide, 2);
    let mut crossing = entries[0].clone();
    crossing.extents = vec![super::ExtentLocator::new(63, 2).unwrap().bits()];
    let mut inside = named(&entries[1], 9, 40);
    inside.extents = vec![super::ExtentLocator::new(64, 1).unwrap().bits()];
    relaunch_in(
        wide,
        &store,
        &[],
        |storage, _| handed(storage, vec![crossing, inside]),
        |storage, volume, control| {
            let before = pristine(storage);
            settle(volume, control);
            assert_eq!(volume.metadata.warm.as_ref().unwrap().split.band, 1);
            refused(
                storage,
                volume,
                control,
                (MetadataOutcome::Unloadable(LoadRefusal::Overlap), before),
            );
        },
    );
}

/// A storage of 512 slots over four index shards whose warm bootstrap runs four lanes of 128 slots each.
fn many() -> Storage<TestPlatform> {
    let fills = [2, 2, 2, 2];
    let index = IndexConfig {
        fills: &fills,
        ..index_config(&[128, 128, 128, 128], (1, 1), 1)
    };
    let mut volume = super::super::test_volume_with(513 * super::super::super::IO_UNIT, 256, 512);
    volume.recovery.helpers = 4;
    volume.recovery.jobs = 8;
    let config = StorageConfig {
        lease_limit: 16,
        volume,
        ..storage_config(512)
    };
    let storage = storage_from(&config, &index, TestPlatform::heap(PAGE));
    storage.platform.ticks(&[Some(1)]);
    storage
}

/// Over four lanes of 128 slots and runs of 16 entries a lane a tick, a load of 200 entries spread over the lanes and
/// the four index shards installs in several ticks with more than one lane holding entries, publishes nothing until
/// every install tick ran, then publishes in several ticks, and serves every key at `Live` with the writer's free and
/// placeable units and one resident slot per entry.
#[test]
fn a_load_over_four_lanes_and_many_ticks_serves_every_key_at_live() {
    let (store, entries, writer) = written_in(many, 200);
    relaunch_in(
        many,
        &store,
        &[],
        whole(&entries),
        |storage, volume, control| {
            let lanes = |volume: &TestVolume<'_, '_>| {
                let warm = volume.metadata.warm.as_ref().unwrap();
                let lane = warm.split.lane;
                let used: std::collections::BTreeSet<usize> =
                    entries.iter().map(|entry| entry.slot() / lane).collect();
                (warm.split.lanes, used.len())
            };
            let (mut installs, mut publishes, mut rounds) = (0, 0, 0);
            let published = |volume: &TestVolume<'_, '_>| {
                (volume.metadata.warm.as_ref())
                    .map_or(0, |warm| warm.published.iter().sum::<usize>())
            };
            let mut reader = storage.register().unwrap();
            while volume.readiness().initializing() {
                let at = stage(volume);
                installs += usize::from(at == Some(Stage::Install));
                publishes += usize::from(at == Some(Stage::Publish));
                if at == Some(Stage::Publish) {
                    assert_eq!(
                        resident(storage),
                        entries.len(),
                        "publication follows every install"
                    );
                }
                tick(volume, control);
                if at == Some(Stage::Install) {
                    assert_eq!(published(volume), 0, "no pair publishes beside an install");
                    assert!(
                        (entries.iter()).all(|entry| matches!(
                            lookup(&mut reader, &entry.key, 4),
                            Err(LookupError::Missing)
                        )),
                        "no restored key maps in the index after an install tick"
                    );
                }
                rounds += 1;
                assert!(rounds < 256, "the load ends");
            }
            let (count, used) = lanes(volume);
            assert_eq!(count, 4);
            assert!(used > 1, "entries reach {used} lanes");
            assert!(
                installs > 1 && publishes > 1,
                "{installs} install and {publishes} publication ticks"
            );
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
            assert_eq!((units(storage), resident(storage)), (writer, entries.len()));
            live(storage, volume);
            for n in (1..).take(entries.len()) {
                assert_eq!(
                    served(storage, volume, control, n),
                    [&key(n)[..4], &[n; 40][..]].concat(),
                    "key {n}"
                );
            }
        },
    );
}

/// A publication tick whose index shard gate another holder keeps retries within the tick and leaves the rest to a
/// later tick; once the gate is free the load completes and every key serves.
#[test]
fn a_held_shard_gate_defers_publication_to_a_later_tick() {
    let (store, entries, _) = written(3);
    relaunch(&store, whole(&entries), |storage, volume, control| {
        reach(volume, control, Stage::Publish);
        let gate = super::super::super::attempt_tests::gate(storage);
        let held = gate.try_lock().unwrap();
        tick(volume, control);
        assert_eq!(
            stage(volume),
            Some(Stage::Publish),
            "the held gate defers the run"
        );
        held.release();
        settle(volume, control);
        assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
        live(storage, volume);
        for n in 1..=3 {
            assert_eq!(
                served(storage, volume, control, n),
                [&key(n)[..4], &[n; 40][..]].concat()
            );
        }
    });
}

/// The insertion step of each of `slots`, read in one hold of the capture lock.
fn steps(storage: &Storage<TestPlatform>, slots: impl Iterator<Item = usize>) -> Vec<(usize, u64)> {
    let pool = storage.live_pool().unwrap();
    let capture = pool.capture_lock().unwrap();
    slots
        .map(|slot| (slot, pool.capture_step(&capture, slot)))
        .collect()
}

/// A load whose entries ascend by slot over three destinations installs each lane's slots in slot order, whatever
/// destination holds an entry and across the ticks a lane takes: within a lane the insertion steps ascend with the
/// slots.
#[test]
fn an_ascending_load_installs_each_lane_in_slot_order_across_destinations_and_ticks() {
    let (store, entries, _) = written_in(many, 200);
    assert!(entries.is_sorted_by_key(CaptureEntry::slot));
    relaunch_in(
        many,
        &store,
        &[],
        |storage, _| handed(storage, entries.clone()),
        |storage, volume, control| {
            reach(volume, control, Stage::Install);
            let warm = volume.metadata.warm.as_ref().unwrap();
            let lane = warm.split.lane;
            let sources = (warm.converted.iter())
                .filter(|converted| !converted.placed.is_empty())
                .count();
            assert!(sources > 1, "{sources} destinations hold entries");
            assert!(
                warm.converted
                    .iter()
                    .all(|converted| converted.late.is_empty())
            );
            let mut installs = 0;
            while stage(volume) == Some(Stage::Install) {
                tick(volume, control);
                installs += 1;
                assert!(installs < 64, "the installs end");
            }
            assert!(installs > 1, "{installs} install ticks");
            let installed = steps(storage, entries.iter().map(CaptureEntry::slot));
            assert!(installed.iter().all(|&(_, step)| step > 0));
            for pair in installed.windows(2) {
                let ((low, before), (high, after)) = (pair[0], pair[1]);
                assert!(
                    low / lane != high / lane || before < after,
                    "slot {low} at step {before}, slot {high} at step {after}"
                );
            }
        },
    );
}

/// A load whose entries descend by slot holds one ascending entry a conversion piece and every other entry late, and the
/// load opens with one resident slot an entry and serves every key's exact bytes at `Live`.
#[test]
fn a_load_in_descending_slot_order_installs_its_late_entries_and_serves_every_key() {
    let (store, entries, writer) = written_in(many, 200);
    let reversed: Vec<CaptureEntry> = entries.iter().rev().cloned().collect();
    relaunch_in(
        many,
        &store,
        &[],
        |storage, _| handed(storage, reversed),
        |storage, volume, control| {
            reach(volume, control, Stage::Install);
            let warm = volume.metadata.warm.as_ref().unwrap();
            let (ascending, late): (usize, usize) = (warm.converted.iter())
                .map(|converted| (converted.placed.len(), converted.late.len()))
                .fold((0, 0), |sum, held| (sum.0 + held.0, sum.1 + held.1));
            assert_eq!(ascending + late, entries.len());
            let pieces = warm.converted.len();
            assert!(
                ascending <= pieces,
                "{ascending} ascending entries over {pieces} pieces"
            );
            settle(volume, control);
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
            assert_eq!((units(storage), resident(storage)), (writer, entries.len()));
            live(storage, volume);
            for n in (1..).take(entries.len()) {
                assert_eq!(
                    served(storage, volume, control, n),
                    [&key(n)[..4], &[n; 40][..]].concat(),
                    "key {n}"
                );
            }
        },
    );
}

/// A scoped worker the OS refuses to start ends the attempt `MetadataFailed` at the marks, the install and the
/// publication, with no device command: the install's refusal leaves the pool gate poisoned, since the workers that
/// ran left unfolded lanes, and a relaunch over the same media loads warm.
#[test]
fn a_refused_worker_start_fails_the_attempt_closed_at_every_parallel_stage() {
    let (store, entries, _) = written(3);
    for at in [Stage::Mark, Stage::Install, Stage::Publish] {
        relaunch(&store, whole(&entries), |storage, volume, control| {
            reach(volume, control, at);
            super::SPAWN_REFUSED.with(|refused| refused.set(true));
            tick(volume, control);
            super::SPAWN_REFUSED.with(|refused| refused.set(false));
            assert_eq!(
                volume.metadata_outcome(),
                MetadataOutcome::MetadataFailed,
                "{at:?}"
            );
            assert_ne!(volume.readiness(), State::Loaded, "{at:?}");
            let gate = storage
                .live_pool()
                .unwrap()
                .try_lock_quiet()
                .map(|access| access.release());
            let expected = match at == Stage::Install {
                true => Err(super::super::super::gate::GateError::Poisoned),
                false => Ok(()),
            };
            assert_eq!(gate, expected, "{at:?}");
            assert_eq!(
                control.capture().events.len(),
                0,
                "{at:?}: no device command"
            );
        });
    }
    relaunch(&store, whole(&entries), |storage, volume, control| {
        settle(volume, control);
        live(storage, volume);
        assert_eq!(
            served(storage, volume, control, 2),
            [&key(2)[..4], &[2; 40][..]].concat()
        );
    });
}

/// The `Bounds` rule runs before the omission rules: an extent past the payload refuses the attempt even on an entry
/// whose deadline passed, and so does a slot at the slot count, each with no table write.
#[test]
fn an_out_of_bounds_extent_or_slot_refuses_bounds_whatever_its_expiry() {
    let (store, entries, _) = written(2);
    let mut past = entries[0].clone();
    past.extents = vec![super::ExtentLocator::new(9, 1).unwrap().bits()];
    past.deadline_ns = u64::from(past.lifetime_ms) * 1_000_000 + 1;
    let slot = named(&entries[1], 9, 8);
    for planted in [past, slot] {
        relaunch(
            &store,
            |storage, _| handed(storage, vec![planted]),
            |storage, volume, control| {
                let before = pristine(storage);
                settle(volume, control);
                refused(
                    storage,
                    volume,
                    control,
                    (MetadataOutcome::Unloadable(LoadRefusal::Bounds), before),
                );
            },
        );
    }
}

/// The stage refuses `Memory` when the engine budget holds one byte less than [`warm_bytes`](super::warm_bytes), with
/// no table write, and loads warm when it holds exactly that; the structures the attempt keeps after the marks, its
/// places, pairs, packed extents and held bitmap, fit the estimate.
#[test]
fn a_budget_one_byte_short_of_the_warm_bytes_refuses_memory() {
    let (store, entries, writer) = written(3);
    for short in [true, false] {
        relaunch(&store, whole(&entries), |storage, volume, control| {
            let assumed = volume.metadata.assumed.as_mut().unwrap();
            let payload_units = storage.pool().descriptor().geometry.payload_units();
            let bytes = super::warm_bytes(
                &assumed.load,
                payload_units,
                split(storage),
                &assumed.coverage,
            )
            .unwrap();
            volume.budget = EngineBudget::new(bytes - usize::from(short));
            if short {
                let before = pristine(storage);
                settle(volume, control);
                return refused(
                    storage,
                    volume,
                    control,
                    (MetadataOutcome::Unloadable(LoadRefusal::Memory), before),
                );
            }
            reach(volume, control, Stage::Hold);
            let warm = volume.metadata.warm.as_ref().unwrap();
            let kept: usize = (warm.converted.iter())
                .map(|converted| {
                    let extents: usize = converted.extents.iter().map(Vec::capacity).sum();
                    (converted.placed.capacity() + converted.late.capacity())
                        * size_of::<super::Placed>()
                        + extents * size_of::<u64>()
                })
                .sum::<usize>()
                + (warm.pairs.iter()).map(Vec::capacity).sum::<usize>() * size_of::<(u64, u64)>()
                + warm.held.len() * size_of::<u64>();
            assert!(kept <= bytes, "kept {kept} of {bytes} estimated bytes");
            settle(volume, control);
            assert_eq!(units(storage), writer);
        });
    }
}

/// A restored entry whose deadline passes after `Live` refuses its lookup `Expired` at residency.
#[test]
fn a_restored_entry_past_its_deadline_at_residency_is_expired() {
    let (store, entries, _) = written(1);
    relaunch(&store, whole(&entries), |storage, volume, control| {
        settle(volume, control);
        live(storage, volume);
        let mut reader = storage.register().unwrap();
        drop(lookup(&mut reader, &key(1), 4).expect("served before its deadline"));
        storage.platform.ticks(&[Some(u64::MAX / 2)]);
        assert!(matches!(
            lookup(&mut reader, &key(1), 4),
            Err(LookupError::Expired)
        ));
    });
}

/// A planted edit of a captured entry, given the payload's unit count.
type Planted = fn(&mut CaptureEntry, u64);

/// An admitted entry the install can neither restore nor show left the retained set refuses the attempt with no table
/// write, so its units are never offered to a fill: a sequence entry, a record wider than the unit cap, a record of
/// another session epoch, a pair whose earliest bound lies past the reading, and a malformed pair, a zero lifetime or
/// a zero deadline beside a nonzero lifetime, refuse `Unrestorable`, and a zero-unit extent and a tail of a whole unit
/// refuse `Bounds`. Expiry, the absent pair and coverage evidence precede the capability refusals: a sequence entry
/// whose deadline lies below the reading's earliest bound, an entry whose pair is `PortableExpiry::ABSENT`, a
/// live-only binding's, and a covered record wider than the unit cap are omitted beside a survivor that serves.
#[test]
fn an_unrestorable_entry_refuses_the_attempt_and_frees_no_unit() {
    let (store, entries, _) = written(2);
    let payload_units = narrow().pool().descriptor().geometry.payload_units();
    let planted = |edit: Planted| {
        let mut entry = entries[0].clone();
        edit(&mut entry, payload_units);
        vec![entry, entries[1].clone()]
    };
    fn at(start: u64, units: u32) -> Vec<u64> {
        vec![super::ExtentLocator::new(start, units).unwrap().bits()]
    }
    let cases: [(Planted, LoadRefusal); 8] = [
        (|entry, _| entry.lifetime_ms = 0, LoadRefusal::Unrestorable),
        (|entry, _| entry.deadline_ns = 0, LoadRefusal::Unrestorable),
        (
            |entry, _| entry.extents.push(entry.extents[0]),
            LoadRefusal::Unrestorable,
        ),
        (
            |entry, units| entry.extents = at(units - 2, 2),
            LoadRefusal::Unrestorable,
        ),
        (
            |entry, _| entry.session += 1 << 32,
            LoadRefusal::Unrestorable,
        ),
        (
            |entry, _| entry.deadline_ns = u64::MAX / 2,
            LoadRefusal::Unrestorable,
        ),
        (|entry, _| entry.extents = at(5, 0), LoadRefusal::Bounds),
        (
            |entry, _| entry.tail = super::IO_UNIT as u16,
            LoadRefusal::Bounds,
        ),
    ];
    for (edit, refusal) in cases {
        let load = planted(edit);
        relaunch(
            &store,
            |storage, _| handed(storage, load),
            |storage, volume, control| {
                assert!(
                    volume.max_units < 2,
                    "a two-unit record passes the unit cap"
                );
                let before = pristine(storage);
                settle(volume, control);
                refused(
                    storage,
                    volume,
                    control,
                    (MetadataOutcome::Unloadable(refusal), before),
                );
            },
        );
    }
    let expired: Planted = |entry, _| {
        entry.extents.push(entry.extents[0]);
        entry.deadline_ns = u64::from(entry.lifetime_ms) * 1_000_000 + 1;
    };
    let absent: Planted = |entry, _| (entry.deadline_ns, entry.lifetime_ms) = (0, 0);
    let wide: Planted = |entry, units| entry.extents = at(units - 2, 2);
    let omitted = [
        (expired, &[][..]),
        (absent, &[][..]),
        (wide, &[entries[0].key][..]),
    ];
    for (edit, covered) in omitted {
        let load = planted(edit);
        relaunch_covered(
            &store,
            covered,
            |storage, _| handed(storage, load),
            |storage, volume, control| {
                settle(volume, control);
                assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
                let warm = volume.metadata.warm.as_ref().unwrap();
                assert_eq!((warm.rows(), warm.omitted), (1, 1));
                live(storage, volume);
                let n = entries[1].key[0];
                assert_eq!(
                    served(storage, volume, control, n),
                    [&key(n)[..4], &[n; 40][..]].concat()
                );
            },
        );
    }
}

/// The omission of an entry whose pair is `PortableExpiry::ABSENT` is read from its stored pair and holds at any
/// reading the load accepts. Under a trusted reading at the writer's time and under one an hour past the other
/// entry's deadline, the absent-pair entry is omitted, its units stay free and its key misses at `Live`; the other
/// entry's fate follows the reading: it restores and serves under the first and is omitted as expired under the
/// second.
#[test]
fn an_absent_pair_is_omitted_at_either_of_two_clock_readings() {
    use super::super::super::portable::scripted::{ScriptedClock, TEST_EARLIEST};
    let (store, mut entries, writer) = written(2);
    (entries[0].deadline_ns, entries[0].lifetime_ms) = (0, 0);
    let past = entries[1].deadline_ns + 3_600 * 1_000_000_000;
    let (absent, other) = (entries[0].key[0], entries[1].key[0]);
    for (earliest, restored) in [(TEST_EARLIEST, true), (past, false)] {
        relaunch(&store, whole(&entries), |storage, volume, control| {
            let (clock, script) = ScriptedClock::with_script();
            script.trusted(earliest, earliest + 2_000_000);
            volume.clock = super::super::clock::Clock::new(clock);
            settle(volume, control);
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
            let warm = volume.metadata.warm.as_ref().unwrap();
            let expected = if restored { (1, 1) } else { (0, 2) };
            assert_eq!((warm.rows(), warm.omitted), expected, "at {earliest}");
            let freed = if restored { 1 } else { 2 };
            assert_eq!(units(storage).0, writer.0 + freed, "at {earliest}");
            live(storage, volume);
            let mut reader = storage.register().unwrap();
            assert!(
                matches!(
                    lookup(&mut reader, &key(absent), 4),
                    Err(LookupError::Missing)
                ),
                "at {earliest}"
            );
            if restored {
                assert_eq!(
                    served(storage, volume, control, other),
                    [&key(other)[..4], &[other; 40][..]].concat()
                );
            } else {
                assert!(matches!(
                    lookup(&mut reader, &key(other), 4),
                    Err(LookupError::Missing)
                ));
            }
        });
    }
}

/// An entry the slot decode withholds, here one of another session epoch whose pair has also expired, leaves the load's
/// verdict `Ok`; the stage refuses it `Unrestorable` with no table write, since the load keeps no expiry or coverage
/// evidence for it and its units would otherwise be freed.
#[test]
fn a_slot_entry_the_decode_withholds_refuses_the_stage() {
    let (store, mut entries, _) = written(3);
    entries[1].session += 1 << 32;
    entries[1].deadline_ns = u64::from(entries[1].lifetime_ms) * 1_000_000 + 1;
    relaunch(&store, whole(&entries), |storage, volume, control| {
        let assumed = volume.metadata.assumed.as_ref().unwrap();
        assert_eq!(
            (assumed.load.verdict, assumed.load.slot_withheld),
            (Ok(()), 1)
        );
        let before = pristine(storage);
        settle(volume, control);
        refused(
            storage,
            volume,
            control,
            (
                MetadataOutcome::Unloadable(LoadRefusal::Unrestorable),
                before,
            ),
        );
    });
}

/// A clock the recovery cannot trust withholds every pair, so the stage refuses `Unrestorable` before any helper
/// starts, with no table write, where an omission of every entry would open an empty cache.
#[test]
fn a_mismatched_clock_contract_refuses_the_stage_and_opens_no_empty_cache() {
    let (store, entries, _) = written(3);
    relaunch(&store, whole(&entries), |storage, volume, control| {
        volume.clock = super::super::clock::Clock::new(
            super::super::super::portable::scripted::ScriptedClock::untrusted(),
        );
        let before = pristine(storage);
        settle(volume, control);
        assert!(volume.metadata.helpers.is_none(), "no helper started");
        refused(
            storage,
            volume,
            control,
            (
                MetadataOutcome::Unloadable(LoadRefusal::Unrestorable),
                before,
            ),
        );
    });
}

/// A load of no destination and a load whose every entry the coverage covers each commit an empty restored set: the
/// volume opens with no resident slot and pristine units, and replay of zero rows reaches `Live`.
#[test]
fn a_load_with_nothing_to_restore_opens_empty_and_reaches_live() {
    let (store, entries, _) = written(2);
    let keys = [entries[0].key, entries[1].key];
    for (covered, empty) in [(&[][..], true), (&keys[..], false)] {
        relaunch_covered(
            &store,
            covered,
            |storage, reader| match empty {
                true => handed(storage, Vec::new()),
                false => decoded(storage, &entries, reader, false),
            },
            |storage, volume, control| {
                if empty {
                    volume
                        .metadata
                        .assumed
                        .as_mut()
                        .unwrap()
                        .load
                        .shards
                        .clear();
                }
                let before = pristine(storage);
                settle(volume, control);
                assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open, "{empty}");
                assert_eq!((units(storage), resident(storage)), (before, 0), "{empty}");
                assert_eq!(
                    volume.begin_replay(storage.feed_contract(), 0),
                    Ok(State::Live),
                    "{empty}"
                );
            },
        );
    }
}

/// The install's insertion-clock preflight lets the clock reach `u64::MAX`, as the one-at-a-time install does, and
/// refuses `Slot` with no table write only when the reservation would pass it.
#[test]
fn an_install_reaching_the_last_insertion_step_loads_and_one_past_it_refuses() {
    let (store, entries, _) = written(3);
    for (clock, loads) in [(u64::MAX - 3, true), (u64::MAX - 2, false)] {
        relaunch(&store, whole(&entries), |storage, volume, control| {
            reach(volume, control, Stage::Install);
            let pool = storage.live_pool().unwrap();
            pool.insert_step
                .store(clock, std::sync::atomic::Ordering::Relaxed);
            let before = units(storage);
            settle(volume, control);
            if loads {
                assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
                assert_eq!(
                    pool.insert_step.load(std::sync::atomic::Ordering::Relaxed),
                    u64::MAX
                );
            } else {
                assert_eq!(
                    volume.metadata_outcome(),
                    MetadataOutcome::Unloadable(LoadRefusal::Slot)
                );
                assert_eq!((units(storage), resident(storage)), (before, 0));
            }
        });
    }
}

/// A poisoned index shard gate never reopens, so publication ends the attempt `MetadataFailed` within a bounded number
/// of ticks instead of retrying every tick, with fills closed and no device command.
#[test]
fn a_poisoned_shard_gate_ends_publication_metadata_failed() {
    let (store, entries, _) = written(3);
    relaunch(&store, whole(&entries), |storage, volume, control| {
        reach(volume, control, Stage::Publish);
        super::super::super::attempt_tests::gate(storage)
            .try_lock()
            .unwrap()
            .poison();
        for _ in 0..4 {
            tick(volume, control);
        }
        assert_eq!(volume.metadata_outcome(), MetadataOutcome::MetadataFailed);
        assert_ne!(volume.readiness(), State::Loaded);
        assert_eq!(control.capture().events.len(), 0, "no device command");
    });
}

/// Records of one, two and three units restore on the wide storage: the allocator's free and placeable units equal
/// the writer's, one slot is resident per entry, and each key serves its exact bytes at `Live`.
#[test]
fn records_spanning_several_units_restore_their_exact_bytes() {
    let lens = [40, 5000, 9000];
    let (store, entries, writer) = written_bodies(wide, &lens);
    assert!(
        entries
            .iter()
            .any(|entry| { super::ExtentLocator::from_bits(entry.extents[0]).len_units() == 3 })
    );
    relaunch_in(
        wide,
        &store,
        &[],
        whole(&entries),
        |storage, volume, control| {
            settle(volume, control);
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
            assert_eq!((units(storage), resident(storage)), (writer, 3));
            live(storage, volume);
            for (n, len) in (1..).zip(lens) {
                assert_eq!(
                    served(storage, volume, control, n),
                    [&key(n)[..4], &vec![n; len][..]].concat(),
                    "key {n}"
                );
            }
        },
    );
}

/// Coverage omits an entry only at a covered version: entries at version 5 are omitted, their units free, under an
/// interval holding 5, and restore at version 5 under intervals that end below it or start above it. An entry at
/// version 0 is judged by key as FILL admission judges it, so any interval of its key omits it.
#[test]
fn coverage_omits_an_entry_only_at_a_covered_version() {
    let (store, mut entries, writer) = written(2);
    let keys = [entries[0].key, entries[1].key];
    let cases = [
        (5, (4, 6), true),
        (5, (0, 4), false),
        (5, (6, 9), false),
        (0, (5, 9), true),
    ];
    for (version, interval, covered) in cases {
        for entry in &mut entries {
            entry.version = version;
        }
        let load = entries.clone();
        relaunch_under(
            narrow,
            &store,
            fenced_over(&keys, interval),
            |storage, _| handed(storage, load),
            |storage, volume, control| {
                settle(volume, control);
                assert_eq!(
                    volume.metadata_outcome(),
                    MetadataOutcome::Open,
                    "{interval:?}"
                );
                let warm = volume.metadata.warm.as_ref().unwrap();
                let restored = if covered { 0 } else { 2 };
                assert_eq!(
                    (warm.rows(), warm.omitted),
                    (restored, 2 - restored),
                    "{interval:?}"
                );
                let freed = if covered { 2 } else { 0 };
                assert_eq!(units(storage).0, writer.0 + freed, "{interval:?}");
                if covered {
                    return;
                }
                live(storage, volume);
                storage.start_capture(1024, true, 1024).unwrap();
                let versions: Vec<u64> = drain(storage).iter().map(|entry| entry.version).collect();
                assert_eq!(
                    versions,
                    vec![version; restored as usize],
                    "{interval:?}: the installed version"
                );
            },
        );
    }
}

/// A capture of a warm-loaded volume at `Live` drains the entries the writer captured, field for field, and a
/// relaunch from that capture serves them again; the warm load requires the tenure's suffix, so an invalidation of a
/// restored key refuses `History` before the log opens and the key still serves.
#[test]
fn a_warm_loaded_volume_captures_the_entries_it_restored() {
    let (store, mut entries, _) = written(3);
    let fields = |entry: &CaptureEntry| {
        (
            entry.key,
            entry.allocation,
            entry.session,
            entry.version,
            (entry.deadline_ns, entry.lifetime_ms, entry.tail),
            entry.extents.clone(),
        )
    };
    let mut recaptured = relaunch(&store, whole(&entries), |storage, volume, control| {
        settle(volume, control);
        live(storage, volume);
        storage.start_capture(1024, true, 1024).unwrap();
        drain(storage)
    });
    entries.sort_by_key(|entry| entry.key);
    recaptured.sort_by_key(|entry| entry.key);
    assert_eq!(
        recaptured.iter().map(fields).collect::<Vec<_>>(),
        entries.iter().map(fields).collect::<Vec<_>>()
    );
    relaunch(&store, whole(&recaptured), |storage, volume, control| {
        settle(volume, control);
        live(storage, volume);
        assert_eq!(
            served(storage, volume, control, 2),
            [&key(2)[..4], &[2; 40][..]].concat()
        );
        let mut budget = super::super::super::budget::WorkBudget::new(1 << 20);
        assert_eq!(
            storage.invalidate(&key(2), 4, &mut budget).err(),
            Some(super::super::super::InvalidateError::History)
        );
        assert_eq!(
            served(storage, volume, control, 2),
            [&key(2)[..4], &[2; 40][..]].concat()
        );
    });
}

/// A pool gate another holder keeps at the hold, an install or the commit, and a capture lock another holder keeps at
/// an install, leave the stage, the lane cursors and the tables as they were for the tick; once released the load
/// opens. A poisoned capture lock ends the install `MetadataFailed` with no slot installed.
#[test]
fn a_held_pool_gate_or_capture_lock_defers_the_stage_and_a_poisoned_lock_fails_it() {
    let (store, entries, writer) = written(3);
    for (at, capture) in [
        (Stage::Hold, false),
        (Stage::Install, false),
        (Stage::Commit, false),
        (Stage::Install, true),
    ] {
        relaunch(&store, whole(&entries), |storage, volume, control| {
            reach(volume, control, at);
            let pool = storage.live_pool().unwrap();
            let before = (units(storage), resident(storage));
            let cursors = progress(volume);
            if capture {
                let held = pool.capture_lock().unwrap();
                volume.warm_step();
                drop(held);
            } else {
                let held = pool.try_lock_quiet().unwrap();
                volume.warm_step();
                held.release();
            }
            assert_eq!(stage(volume), Some(at), "{at:?} {capture}");
            assert_eq!(
                (units(storage), resident(storage)),
                before,
                "{at:?} {capture}"
            );
            assert_eq!(progress(volume), cursors);
            settle(volume, control);
            assert_eq!(
                volume.metadata_outcome(),
                MetadataOutcome::Open,
                "{at:?} {capture}"
            );
            assert_eq!(units(storage), writer);
        });
    }
    relaunch(&store, whole(&entries), |storage, volume, control| {
        reach(volume, control, Stage::Install);
        let pool = storage.live_pool().unwrap();
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = pool.capture_lock().unwrap();
            panic!("a planted capture-lock holder panic");
        }));
        assert!(poisoned.is_err());
        let before = units(storage);
        volume.warm_step();
        assert_eq!(volume.metadata_outcome(), MetadataOutcome::MetadataFailed);
        assert_eq!((units(storage), resident(storage)), (before, 0));
    });
}

/// The volume's helpers run unparked: the conversions and the commit's free jobs run on helper threads, the load
/// opens and serves, and dropping the volume waits for the free jobs.
#[test]
fn unparked_helpers_convert_and_free_a_warm_load() {
    let (store, entries, writer) = written(3);
    relaunch(&store, whole(&entries), |storage, volume, control| {
        PARK.with(|park| park.set(false));
        for _ in 0..256 {
            if !volume.readiness().initializing() {
                break;
            }
            control.tick(64);
            let _ = volume.poll_storage(0, &mut Vec::with_capacity(16));
            std::thread::yield_now();
        }
        assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
        assert_eq!(units(storage), writer);
        live(storage, volume);
        assert_eq!(
            served(storage, volume, control, 1),
            [&key(1)[..4], &[1; 40][..]].concat()
        );
    });
}

/// A withdrawal whose compare-and-swap lands inside the commit's hold, after the hold read `Loading`, leaves the word
/// `Withheld`: the commit's `LoadComplete` changes nothing, the volume does not open, and a stale `LoadComplete`
/// reopens nothing.
#[test]
fn a_withdrawal_landing_inside_the_commit_hold_keeps_the_attempt_withheld() {
    let (store, entries, _) = written(3);
    relaunch(&store, whole(&entries), |storage, volume, control| {
        reach(volume, control, Stage::Commit);
        assert!(
            !volume.warm_decided(),
            "a staged load awaiting its commit has no deciding result"
        );
        super::WITHDRAW_AT_COMMIT.with(|at| at.set(true));
        volume.warm_step();
        super::WITHDRAW_AT_COMMIT.with(|at| at.set(false));
        assert!(
            !volume.warm_decided(),
            "a load the withdrawal stopped at its commit has no deciding result"
        );
        assert_eq!(volume.readiness(), State::Withheld);
        assert_ne!(volume.metadata_outcome(), MetadataOutcome::Open);
        assert_eq!(
            storage.readiness.apply(Event::LoadComplete),
            Ok(State::Withheld)
        );
        assert_eq!(writes(control), 0);
    });
}

/// The resident slots the pool's slot words name, counted word by word.
fn resident_words(storage: &Storage<TestPlatform>) -> usize {
    let resident = super::super::super::tables::SlotState::Resident.bits();
    (storage.live_pool().unwrap().records().iter())
        .filter(|record| {
            record.ident.load(std::sync::atomic::Ordering::Relaxed) & resident == resident
        })
        .count()
}

/// On four lanes: a duplicate slot in lane 1 refuses `Slot` while the other lanes install, and the folded ledger
/// counts exactly the slot words that read resident; a worker of lane 2 that panics poisons the gate while the other
/// lanes complete; and two keys of one fingerprint in lanes 0 and 2 of one destination end `Collided` before any
/// table write.
#[test]
fn failures_in_one_lane_of_several_fold_or_fail_closed() {
    let (store, entries, _) = written_in(many, 200);
    let lane = |entry: &CaptureEntry| entry.slot() / 128;
    let in_lane = |k: usize| {
        entries
            .iter()
            .find(|entry| lane(entry) == k)
            .unwrap()
            .clone()
    };
    let mut twin = named(&in_lane(1), 250, 0);
    twin.allocation = in_lane(1).allocation;
    twin.extents = vec![super::ExtentLocator::new(500, 1).unwrap().bits()];
    let mut planted = entries.clone();
    planted.push(twin);
    relaunch_in(
        many,
        &store,
        &[],
        |storage, _| handed(storage, planted),
        |storage, volume, control| {
            settle(volume, control);
            assert_eq!(
                volume.metadata_outcome(),
                MetadataOutcome::Unloadable(LoadRefusal::Slot)
            );
            let installed = resident(storage);
            assert!(installed > 1, "the other lanes installed");
            assert_eq!(
                installed,
                resident_words(storage),
                "the fold counts every installed slot"
            );
        },
    );
    relaunch_in(
        many,
        &store,
        &[],
        whole(&entries),
        |storage, volume, control| {
            reach(volume, control, Stage::Install);
            let slot = in_lane(2).slot();
            storage.live_pool().unwrap().records()[slot]
                .ident
                .store(u64::MAX, std::sync::atomic::Ordering::Relaxed);
            // The planted slot's lane reaches it within a few install runs.
            for _ in 0..16 {
                if volume.metadata_outcome() != MetadataOutcome::Bootstrapping {
                    break;
                }
                tick(volume, control);
            }
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::MetadataFailed);
            assert!(matches!(
                storage.live_pool().unwrap().try_lock_quiet(),
                Err(super::super::super::gate::GateError::Poisoned)
            ));
            assert_eq!(control.capture().events.len(), 0, "no device command");
        },
    );
    let (first, third) = (in_lane(0), in_lane(2));
    relaunch_in(
        many,
        &store,
        &[],
        |storage, _| {
            let mut load = handed(storage, vec![first, third]);
            load.shards[0] = vec![collided(&mut load)];
            load
        },
        |storage, volume, control| {
            let before = pristine(storage);
            settle(volume, control);
            refused(
                storage,
                volume,
                control,
                (MetadataOutcome::Collided, before),
            );
        },
    );
}

/// [`wide`] under the deterministic seam that routes keys by their first byte, so a load's shard populations repeat.
fn wide_spread() -> Storage<TestPlatform> {
    let mut storage = wide();
    super::super::super::publish_tests::install_seam(
        &mut storage,
        super::super::super::publish_tests::spread,
    );
    storage
}

/// On two index shards, three destinations and two lanes, publication ticks that meet the second shard's gate in
/// another holder's hands publish each destination's pairs of the first shard, which lead its grouped pairs, and leave
/// the destination's cursor at its first pair of the held shard, inside the pairs of a destination that holds both
/// shards', with the stage at the publication: a destination waiting on the gate keeps no other from its worker. Once
/// the gate is free the workers resume from those cursors and every key serves at `Live`.
#[test]
fn a_publication_worker_stops_at_a_held_shard_gate_and_resumes_from_its_cursor() {
    let (store, entries, _) = written_in(wide_spread, 12);
    relaunch_in(
        wide_spread,
        &store,
        &[],
        whole(&entries),
        |storage, volume, control| {
            reach(volume, control, Stage::Publish);
            let index = storage.index().unwrap();
            let second = crate::index::ShardIndex(1);
            let shard = index.image.shard(second).unwrap();
            // SAFETY: the index mapping is live while the storage is.
            let held = unsafe { shard.gate(&index.mapping) }.try_lock().unwrap();
            // A tick starts a worker for as many pending destinations as lanes, from one destination later each tick.
            for _ in 0..DESTINATIONS {
                tick(volume, control);
                assert_eq!(stage(volume), Some(Stage::Publish));
            }
            let warm = volume.metadata.warm.as_ref().unwrap();
            let stops: Vec<(usize, usize)> = (warm.pairs.iter())
                .map(|pairs| {
                    let free = |pair: &&super::Pair| {
                        let route = index
                            .hasher
                            .reroute_unpaid(pair.fingerprint, &index.geometry);
                        route.map(|route| route.shard()) != Some(second)
                    };
                    let stop = pairs.iter().take_while(free).count();
                    (stop, pairs.len())
                })
                .collect();
            let cursors: Vec<usize> = stops.iter().map(|stop| stop.0).collect();
            assert_eq!(
                warm.published, cursors,
                "each cursor stops at the held shard"
            );
            assert!(
                stops.iter().any(|&(stop, pairs)| 0 < stop && stop < pairs),
                "{stops:?}: a cursor stops inside a destination's pairs"
            );
            held.release();
            settle(volume, control);
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
            live(storage, volume);
            for n in (1..).take(entries.len()) {
                assert_eq!(
                    served(storage, volume, control, n),
                    [&key(n)[..4], &[n; 40][..]].concat(),
                    "key {n}"
                );
            }
        },
    );
}

/// The odd multiplier the fabricated fingerprints spread by.
const SPREAD: u64 = 0x9E37_79B9_7F4A_7C15;

/// `count` copies of `entry` under distinct keys and one-unit extents, at slots ascending from 0 or descending to 0,
/// the `n`th with the `n`th of `prints`.
fn planted(
    entry: &CaptureEntry,
    count: u64,
    descending: bool,
    prints: impl Iterator<Item = u64>,
) -> Vec<(CaptureEntry, u64)> {
    let planted = (0..count).zip(prints).map(|(n, print)| {
        let slot = if descending { count - 1 - n } else { n };
        let mut entry = entry.clone();
        entry.key[..8].copy_from_slice(&n.to_le_bytes());
        entry.allocation = slot << 32 | 1;
        entry.extents = vec![super::ExtentLocator::new(n, 1).unwrap().bits()];
        (entry, print)
    });
    planted.collect()
}

/// The conversion of one destination holding `held` in two chunks, the second starting a quarter in, and the
/// destination's collision check, run inline on the measuring thread over 4,096 slots and payload units: the
/// conversion, the destination's publication pairs, the bytes the two allocated at their peak and the
/// [`warm_bytes`](super::warm_bytes) of its load.
fn measured(
    storage: &Storage<TestPlatform>,
    volume: &mut TestVolume<'_, '_>,
    held: &[(CaptureEntry, u64)],
) -> (super::Converted, super::Pairs, usize, usize) {
    let (first, second) = held.split_at(held.len() / 4);
    let chunks = vec![Chunk::holding(first), Chunk::holding(second)];
    let one = SlotLoad::handed(vec![chunks.clone()]);
    let (slots, payload_units): (usize, u64) = (4096, 4096);
    let lanes = storage.recovery.helpers as usize;
    let index = storage.index().unwrap();
    let job = super::Convert {
        destination: 0,
        chunks,
        split: super::Split {
            lane: super::super::super::tables::lane_len(slots, lanes),
            band: (payload_units.div_ceil(64) as usize).div_ceil(lanes),
            lanes,
            payload_units,
            slots,
        },
        coverage: std::sync::Arc::new(fenced(&[])),
        contracts: (storage.clock.encode(), storage.clock),
        sample: volume.recovery_sample(),
        record: storage.record,
        max_units: u64::from(volume.max_units),
        writer: volume.authority.session().get(),
    };
    let routing = (index.hasher.clone(), index.geometry.clone());
    let groups = super::groups_of(&index.geometry);
    let bytes = super::warm_bytes(&one, payload_units, split(storage), &job.coverage).unwrap();
    let live = crate::instrument::live_bytes();
    crate::instrument::reset_peak();
    let converted = super::convert(job);
    let (pairs, collided) =
        super::destination_pairs(std::slice::from_ref(&converted), (&routing, &groups), 0);
    let peak = crate::instrument::peak_bytes().wrapping_sub(live);
    let mut converted = converted;
    if collided {
        converted.refusal = Some(MetadataOutcome::Collided);
    }
    (converted, pairs, peak, bytes)
}

/// The conversion of one destination of 2,048 entries in two chunks over four lanes and its collision check allocate
/// at most [`warm_bytes`](super::warm_bytes) of its load at their peak, the places, packed extents, publication pairs
/// and the check's scratch included, whether the entries ascend by slot, so every place joins the ascending run, or
/// descend, so every place after the first is late under one reservation of exactly their count; the late places
/// leave by lane and, within a lane, in the load's order across the chunks, and the pairs leave grouped by index
/// shard and bucket run over more groups than shards.
#[test]
fn a_conversion_peak_fits_the_warm_bytes_estimate() {
    let (store, entries, _) = written_in(many, 1);
    relaunch_in(many, &store, &[], whole(&entries), |storage, volume, _| {
        for descending in [false, true] {
            let prints = (0u64..).map(|n| n.wrapping_mul(SPREAD) | 1);
            let held = planted(&entries[0], 2048, descending, prints);
            let (converted, pairs, peak, bytes) = measured(storage, volume, &held);
            assert_eq!(converted.refusal, None);
            assert!(
                peak <= bytes,
                "peak {peak} of {bytes} estimated bytes, descending {descending}"
            );
            let ascending = converted.placed.len();
            assert_eq!(ascending, if descending { 1 } else { 2048 });
            let late = (converted.late.len(), converted.late.capacity());
            assert_eq!(late, (2048 - ascending, 2048 - ascending));
            assert!(converted.placed.is_sorted_by_key(|placed| placed.slot));
            // The load's order within a lane is descending slots here.
            let lane = 4096 / storage.recovery.helpers as usize;
            let order = |placed: &super::Placed| {
                (placed.slot as usize / lane, std::cmp::Reverse(placed.slot))
            };
            assert!(converted.late.is_sorted_by_key(order));
            let index = storage.index().unwrap();
            let (offsets, groups) = super::groups_of(&index.geometry);
            let routing = (index.hasher.clone(), index.geometry.clone());
            let group = |pair: &super::Pair| super::group_of(&routing, &offsets, pair.fingerprint);
            assert_eq!(pairs.len(), 2048);
            assert!(pairs.is_sorted_by_key(group));
            let held: std::collections::BTreeSet<usize> = pairs.iter().map(group).collect();
            assert!(
                held.len() > index.geometry.enabled().len() && held.len() <= groups,
                "{} of {groups} groups hold pairs",
                held.len()
            );
        }
    });
}

/// A scoped warm worker runs on the CPU set `spread` gives it, apart from the owner's CPU, whatever set the owner
/// thread runs on.
#[test]
#[cfg(not(loom))]
fn scoped_workers_of_a_pinned_owner_run_on_the_given_cpus() {
    use super::super::CpuSet;
    let allowed = CpuSet::current().unwrap();
    let mut cpus = allowed.cpus();
    let (Some(owner), Some(_)) = (cpus.next(), cpus.next()) else {
        panic!("the test needs two allowed CPUs, found {allowed:?}");
    };
    let mut apart = allowed;
    apart.remove(owner);
    // SAFETY: `pthread_self` reads the calling thread's handle.
    let this = unsafe { libc::pthread_self() };
    // SAFETY: `this` names the calling thread, which stays live for each call.
    unsafe { CpuSet::from_cpus(&[owner]).unwrap().apply(this) }.unwrap();
    let placed = super::spread(
        vec![(), ()],
        |_| true,
        &apart,
        |_, ()| CpuSet::current().unwrap(),
    );
    // SAFETY: as above.
    unsafe { allowed.apply(this) }.unwrap();
    assert!(placed.iter().all(|set| *set == Some(apart)), "{placed:?}");
}

/// A share that holds no work runs on the thread that called `spread`, on that thread's CPU, while a share that holds
/// work runs on a scoped worker on the given CPU set; a share with no work that panics yields `None` beside the other
/// shares' results, as a worker's panic does.
#[test]
#[cfg(not(loom))]
fn a_share_with_no_work_runs_on_the_calling_thread_and_its_panic_is_contained() {
    use super::super::CpuSet;
    let allowed = CpuSet::current().unwrap();
    let mut cpus = allowed.cpus();
    let (Some(owner), Some(_)) = (cpus.next(), cpus.next()) else {
        panic!("the test needs two allowed CPUs, found {allowed:?}");
    };
    let (mut apart, pinned) = (allowed, CpuSet::from_cpus(&[owner]).unwrap());
    apart.remove(owner);
    // SAFETY: `pthread_self` reads the calling thread's handle.
    let this = unsafe { libc::pthread_self() };
    // SAFETY: `this` names the calling thread, which stays live for each call.
    unsafe { pinned.apply(this) }.unwrap();
    let caller = std::thread::current().id();
    let ran = super::spread(
        vec![0, 1, 2],
        |k| k == 1,
        &apart,
        |k, share| {
            assert_eq!(k, share, "a share runs under its own position");
            (
                std::thread::current().id() == caller,
                CpuSet::current().unwrap(),
            )
        },
    );
    let contained = super::spread(
        vec![0, 1],
        |k| k == 1,
        &apart,
        |_, share| {
            assert_ne!(share, 0, "a planted panic in the share with no work");
            share
        },
    );
    // SAFETY: as above.
    unsafe { allowed.apply(this) }.unwrap();
    assert_eq!(
        ran,
        [
            Some((true, pinned)),
            Some((false, apart)),
            Some((true, pinned))
        ]
    );
    assert_eq!(contained, [None, Some(1)]);
}

/// A share whose panic payload panics again when dropped yields `None`, on the calling thread and from a scoped
/// worker's join alike, and `spread` returns: each payload's destructor ran once and the second panic ended inside
/// `spread`. On the calling thread `contain` caught the share's panic and forgets the destructor's payload; at the
/// join it caught the destructor's panic and drops that payload, whose destructor records `fuse`.
#[test]
#[cfg(not(loom))]
fn a_share_whose_panic_payload_panics_on_drop_yields_none_on_the_caller_and_from_a_join() {
    use crate::storage::{Bomb, Dropped};
    let cpus = super::super::CpuSet::current().unwrap();
    let dropped = Dropped::default();
    let bombs = vec![
        Some(Bomb(std::sync::Arc::clone(&dropped))),
        Some(Bomb(std::sync::Arc::clone(&dropped))),
        None,
    ];
    let results = super::spread(
        bombs,
        |k| k == 1,
        &cpus,
        |k, bomb| {
            if let Some(bomb) = bomb {
                std::panic::panic_any(bomb);
            }
            k
        },
    );
    assert_eq!(results, [None, None, Some(2)]);
    assert_eq!(*dropped.lock().unwrap(), ["bomb", "bomb", "fuse"]);
}

/// The control of the payload disposal: with a caught payload dropped bare (`BARE_PAYLOAD`), the destructor's panic
/// unwinds out of `spread`, from the share on the calling thread and from the worker's join alike.
#[test]
#[cfg(not(loom))]
fn a_bare_drop_of_a_panic_payload_that_panics_unwinds_out_of_spread() {
    use crate::storage::{Bomb, Dropped};
    let cpus = super::super::CpuSet::current().unwrap();
    super::BARE_PAYLOAD.with(|bare| bare.set(true));
    let unwound = [false, true].map(|busy| {
        let dropped = Dropped::default();
        let bomb = Bomb(std::sync::Arc::clone(&dropped));
        let spread = std::panic::AssertUnwindSafe(|| {
            super::spread(
                vec![bomb],
                |_| busy,
                &cpus,
                |_, bomb| -> () { std::panic::panic_any(bomb) },
            )
        });
        let unwound = std::panic::catch_unwind(spread).is_err();
        (unwound, dropped.lock().unwrap().clone())
    });
    super::BARE_PAYLOAD.with(|bare| bare.set(false));
    assert_eq!(
        unwound,
        [(true, vec!["bomb", "fuse"]), (true, vec!["bomb", "fuse"])]
    );
}

/// A conversion stops at its first refusal: an entry of two extents in the first chunk refuses `Unrestorable`, the
/// job consumes that chunk alone, and nothing of the second chunk joins its places or pairs.
#[test]
fn a_conversion_stops_at_its_first_refusal_and_consumes_no_later_chunk() {
    let (store, entries, _) = written_in(many, 1);
    relaunch_in(many, &store, &[], whole(&entries), |storage, volume, _| {
        let prints = (0u64..).map(|n| n.wrapping_mul(SPREAD) | 1);
        let mut held = planted(&entries[0], 8, false, prints);
        let second = super::ExtentLocator::new(4000, 1).unwrap().bits();
        held[0].0.extents.push(second);
        let (converted, _, _, _) = measured(storage, volume, &held);
        assert_eq!(
            converted.refusal,
            Some(MetadataOutcome::Unloadable(LoadRefusal::Unrestorable))
        );
        assert_eq!(
            converted.chunks.len(),
            1,
            "the second chunk is not consumed"
        );
        assert!(converted.placed.is_empty() && converted.late.is_empty());
    });
}

/// A destination of 2,049 entries that descend by slot and whose fingerprints share one publication group holds every
/// per-entry term of the estimate at once: the ascending run's room, the late reservation, the packed extents, the
/// publication pairs and a probe table of four words an entry. The peak of its conversion and collision check stays
/// within [`warm_bytes`](super::warm_bytes) and within one place an entry of it.
#[test]
fn a_conversion_of_late_entries_in_one_group_peaks_within_one_place_an_entry_of_the_estimate() {
    let (store, entries, _) = written_in(many, 1);
    relaunch_in(many, &store, &[], whole(&entries), |storage, volume, _| {
        let index = storage.index().unwrap();
        let offsets = super::groups_of(&index.geometry).0;
        let first = |print: &u64| {
            let route = index.hasher.reroute_unpaid(*print, &index.geometry);
            route.is_some_and(|route| {
                offsets[route.position()] + (route.bucket() >> super::RUN_BITS) == 0
            })
        };
        let prints = (1u64..).map(|n| n.wrapping_mul(SPREAD) | 1).filter(first);
        let held = planted(&entries[0], 2049, true, prints);
        let (converted, _, peak, bytes) = measured(storage, volume, &held);
        assert_eq!(converted.refusal, None);
        let places = (converted.placed.len(), converted.late.capacity());
        assert_eq!(places, (1, 2048));
        assert!(peak <= bytes, "peak {peak} of {bytes} estimated bytes");
        assert!(
            peak > bytes - 2049 * size_of::<super::Placed>(),
            "peak {peak} of {bytes} estimated bytes"
        );
    });
}

/// A capture pass refuses to start while the attach gate runs and while the warm load runs, so no pass can take a
/// `t0` below the restored slots' insertion steps; the install ticks and the commit each advance the capture epoch;
/// after the commit a pass starts and drains every restored entry.
#[test]
fn a_capture_start_during_the_warm_load_refuses_and_the_first_after_names_every_entry() {
    use super::super::super::recovery::CaptureError;
    let (store, entries, _) = written(3);
    relaunch(&store, whole(&entries), |storage, volume, control| {
        assert_eq!(
            storage.readiness.state_and_attach_gate(),
            (State::Detached, true)
        );
        assert_eq!(
            storage.start_capture(1024, true, 1024).err(),
            Some(CaptureError::Unavailable),
            "the attach gate runs"
        );
        let mut epochs = Vec::new();
        for at in [Stage::Convert, Stage::Install, Stage::Publish] {
            reach(volume, control, at);
            assert_eq!(
                storage.start_capture(1024, true, 1024).err(),
                Some(CaptureError::Unavailable),
                "{at:?}"
            );
            epochs.push(storage.capture_epoch().0);
        }
        settle(volume, control);
        epochs.push(storage.capture_epoch().0);
        assert!(
            epochs[0] == epochs[1] && epochs[1] < epochs[2] && epochs[2] < epochs[3],
            "the install ticks and the commit advance the epoch: {epochs:?}"
        );
        storage.start_capture(1024, true, 1024).unwrap();
        assert_eq!(drain(storage).len(), entries.len());
    });
}

/// A withdrawal the tick observes while a warm attempt loads cancels the attempt's helpers, so the pool's threads end
/// while the withdrawn volume lives on, and the media keep the predecessor's bytes.
#[test]
#[cfg(not(loom))]
fn a_withdrawal_during_a_warm_load_ends_the_helpers() {
    let (store, entries, _) = written(3);
    let before = store.borrow().clone();
    let storage = narrow();
    let buffers = arena_with(4, 9);
    let (mut volume, control) = attach_over(&storage, &buffers, &store).unwrap();
    let load = decoded(&storage, &entries, volume.authority.session().get(), false);
    volume.assume_warm(load, fenced(&[])).unwrap();
    PARK.with(|park| park.set(true));
    reach(&mut volume, &control, Stage::Convert);
    PARK.with(|park| park.set(false));
    assert!(
        volume.metadata.helpers.is_some(),
        "the warm attempt started its pool"
    );
    let ended = |volume: &TestVolume<'_, '_>| {
        (volume.metadata.helpers.as_ref()).is_some_and(super::super::helpers::Helpers::ended)
    };
    assert!(
        !ended(&volume),
        "the helper threads run until the withdrawal"
    );
    assert_eq!(storage.withdraw(), State::Withheld);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline && !ended(&volume) {
        tick(&mut volume, &control);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(
        ended(&volume),
        "the withdrawn attempt's helper threads ended"
    );
    assert_eq!(
        resident(&storage),
        0,
        "the withdrawn attempt installed nothing"
    );
    assert!(*store.borrow() == before, "the media is unchanged");
}

/// A CPU set the kernel refuses for the helpers fails the warm attempt's pool start: the attempt ends
/// `MetadataFailed` with no pool, no restored entry and the media unchanged.
#[test]
#[cfg(not(loom))]
fn a_refused_helper_placement_ends_the_warm_attempt_with_no_write() {
    let (store, entries, _) = written(3);
    let before = store.borrow().clone();
    let allowed = super::super::CpuSet::current().unwrap();
    let outside = (0..super::super::MAX_CPUS)
        .rev()
        .find(|&cpu| !allowed.contains(cpu))
        .expect("some CPU index lies outside the allowed set");
    let storage = storage_with(|volume| {
        volume.recovery.cpus = super::super::CpuSet::from_cpus(&[outside]).unwrap();
    });
    let buffers = arena_with(4, 9);
    let (mut volume, control) = attach_over(&storage, &buffers, &store).unwrap();
    let load = decoded(&storage, &entries, volume.authority.session().get(), false);
    volume.assume_warm(load, fenced(&[])).unwrap();
    for _ in 0..64 {
        tick(&mut volume, &control);
    }
    assert_eq!(volume.metadata_outcome(), MetadataOutcome::MetadataFailed);
    assert!(volume.metadata.helpers.is_none(), "no pool started");
    assert_eq!(
        resident(&storage),
        0,
        "the failed attempt installed nothing"
    );
    drop(volume);
    assert!(*store.borrow() == before, "the media is unchanged");
}

/// ENDED-HOLDS: a warm attempt withdrawn at its publication leaves its installed, unpublished slots anchored, so after
/// the volume quiesces and releases, the storage's finalization reports them blocked and releases no extent.
#[test]
fn a_storage_after_an_ended_warm_attempt_finalizes_blocked() {
    use super::super::super::publication_tests::drain;
    use super::super::super::test_platform::blocked;
    let (store, entries, _) = written(3);
    let mut storage = narrow();
    let buffers = arena_with(4, 9);
    {
        let (mut volume, control) = attach_over(&storage, &buffers, &store).unwrap();
        let load = decoded(&storage, &entries, volume.authority.session().get(), false);
        volume.assume_warm(load, fenced(&[])).unwrap();
        PARK.with(|park| park.set(true));
        reach(&mut volume, &control, Stage::Publish);
        PARK.with(|park| park.set(false));
        assert_eq!(resident(&storage), entries.len());
        let held = units(&storage);
        assert_eq!(storage.withdraw(), State::Withheld);
        let mut out = Vec::with_capacity(16);
        for _ in 0..64 {
            if matches!(
                volume.close(),
                super::super::super::QuiesceProgress::Quiesced(_)
            ) {
                break;
            }
            control.tick(64);
            let _ = volume.poll_storage(0, &mut out);
            out.clear();
        }
        assert!(volume.release().is_ok());
        assert_eq!(units(&storage), held, "the ended attempt frees no extent");
        storage.close();
        drain(&storage);
    }
    assert_eq!(
        blocked(&mut storage),
        super::super::super::Blockers {
            held_slots: entries.len(),
            ..Default::default()
        }
    );
}

/// A pool that already carries an object when the hold runs, here a fill reserved before the attach, refuses the
/// allocator's rebuild: the attempt ends `MetadataFailed` with the units the reservation left and no device command;
/// and a pool gate poisoned at the hold, the install or the commit ends the attempt `MetadataFailed` there.
#[test]
fn a_hold_over_a_used_pool_or_a_poisoned_gate_fails_the_attempt() {
    let (store, entries, _) = written(3);
    let storage = narrow();
    let mut budget = super::super::super::budget::WorkBudget::new(1 << 20);
    let reserved = storage.reserve(Some(0), Some(100), &mut budget).unwrap();
    let buffers = arena_with(4, 9);
    let (mut volume, control) = attach_over(&storage, &buffers, &store).unwrap();
    let load = decoded(&storage, &entries, volume.authority.session().get(), false);
    volume.assume_warm(load, fenced(&[])).unwrap();
    PARK.with(|park| park.set(true));
    reach(&mut volume, &control, Stage::Hold);
    let before = units(&storage);
    tick(&mut volume, &control);
    PARK.with(|park| park.set(false));
    assert_eq!(volume.metadata_outcome(), MetadataOutcome::MetadataFailed);
    assert_eq!(units(&storage), before);
    assert_eq!(control.capture().events.len(), 0, "no device command");
    drop(reserved);
    for at in [Stage::Hold, Stage::Install, Stage::Commit] {
        relaunch(&store, whole(&entries), |storage, volume, control| {
            reach(volume, control, at);
            storage
                .live_pool()
                .unwrap()
                .try_lock_quiet()
                .unwrap()
                .poison();
            volume.warm_step();
            assert_eq!(
                volume.metadata_outcome(),
                MetadataOutcome::MetadataFailed,
                "{at:?}"
            );
            assert_ne!(volume.readiness(), State::Loaded, "{at:?}");
        });
    }
}

/// A destination split into many conversion pieces holds one set of lane vectors per piece, and over 64 lanes those
/// vectors outweigh the load's entries: converting every piece of a 128-chunk destination and keeping every result
/// allocates at most [`warm_bytes`](super::warm_bytes), which charges each piece [`pieces`](super::pieces) adds.
#[test]
fn every_conversion_piece_s_vectors_fit_the_warm_bytes_estimate() {
    let (store, entries, _) = written_in(many, 1);
    relaunch_in(many, &store, &[], whole(&entries), |storage, volume, _| {
        let lanes = 64;
        let chunks: Vec<Chunk> = (0..128u64)
            .map(|n| {
                let mut entry = entries[0].clone();
                entry.key[..8].copy_from_slice(&n.to_le_bytes());
                entry.allocation = n << 32 | 1;
                entry.extents = vec![super::ExtentLocator::new(2 * n, 1).unwrap().bits()];
                Chunk::holding(&[(entry, n.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)])
            })
            .collect();
        let (slots, payload_units): (usize, u64) = (4096, 4096);
        let load = SlotLoad::handed(vec![chunks.clone()]);
        let index = storage.index().unwrap();
        let groups = super::groups_of(&index.geometry);
        let coverage = std::sync::Arc::new(fenced(&[]));
        let bytes =
            super::warm_bytes(&load, payload_units, (lanes, &index.geometry), &coverage).unwrap();
        let pieces = super::pieces(vec![chunks], lanes);
        assert_eq!(
            pieces.len(),
            2 * lanes,
            "one destination splits into 2 * lanes pieces"
        );
        let routing = (index.hasher.clone(), index.geometry.clone());
        let split = super::Split {
            lane: slots.div_ceil(lanes),
            band: (payload_units.div_ceil(64) as usize).div_ceil(lanes),
            lanes,
            payload_units,
            slots,
        };
        let live = crate::instrument::live_bytes();
        crate::instrument::reset_peak();
        let mut converted = Vec::with_capacity(pieces.len());
        for (destination, chunks) in pieces {
            converted.push(super::convert(super::Convert {
                destination,
                chunks,
                split,
                coverage: std::sync::Arc::clone(&coverage),
                contracts: (storage.clock.encode(), storage.clock),
                sample: volume.recovery_sample(),
                record: storage.record,
                max_units: u64::from(volume.max_units),
                writer: volume.authority.session().get(),
            }));
        }
        let (_, collided) = super::destination_pairs(&converted, (&routing, &groups), 0);
        let peak = crate::instrument::peak_bytes().wrapping_sub(live);
        assert!(!collided);
        assert!(converted.iter().all(|piece| piece.refusal.is_none()));
        assert!(peak <= bytes, "peak {peak} of {bytes} estimated bytes");
    });
}

/// A capture pass started before the attach, while readiness reads `Detached`, takes a `t0` below every restored
/// slot's insertion step; the warm install abandons it, so it can publish no cut that omits the restored entries, and
/// the first pass after the commit names every entry.
#[test]
fn a_capture_pass_started_before_the_attach_is_abandoned_by_the_install() {
    let (store, entries, _) = written(3);
    let storage = narrow();
    let counter = storage.start_capture(1024, true, 1024).unwrap();
    let buffers = arena_with(4, 9);
    let (mut volume, control) = attach_over(&storage, &buffers, &store).unwrap();
    let load = decoded(&storage, &entries, volume.authority.session().get(), false);
    volume.assume_warm(load, fenced(&[])).unwrap();
    PARK.with(|park| park.set(true));
    settle(&mut volume, &control);
    PARK.with(|park| park.set(false));
    assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
    assert_eq!(
        storage.capture_next(counter).err(),
        Some(super::super::super::recovery::CaptureError::Abandoned)
    );
    let _ = storage.pool().capture_lock().unwrap().finish();
    storage.start_capture(1024, true, 1024).unwrap();
    assert_eq!(drain(&storage).len(), entries.len());
}

/// A capture proof taken before the attach, over the empty pool, refuses `Replaced` at its Publish after the warm
/// commit, with no checkpoint named, so it cannot replace the restored set with the pre-attach membership; a pass
/// started before the attach and proven after it refuses `Replaced` at its proof; and a proof taken after the commit,
/// under the current epoch, publishes a checkpoint of every restored entry.
#[test]
fn a_proof_minted_before_the_warm_commit_refuses_at_publish_and_one_after_publishes() {
    use super::super::super::checkpoint::WriteRefused;
    use super::super::super::checkpoint::tests::{SESSION, published_capture};
    use super::super::super::recovery::CaptureError;
    let (store, entries, _) = written(3);
    let storage = narrow();
    let tenure = (shard(), SESSION);
    let before = storage.start_capture(1024, true, 1024).unwrap();
    assert_eq!(drain(&storage), Vec::new());
    let early = storage.cut_intact(tenure, before).unwrap();
    let _ = storage.pool().capture_lock().unwrap().finish();
    let spanning = storage.start_capture(1024, true, 1024).unwrap();
    assert_eq!(drain(&storage), Vec::new());
    let buffers = arena_with(4, 9);
    let (mut volume, control) = attach_over(&storage, &buffers, &store).unwrap();
    let load = decoded(&storage, &entries, volume.authority.session().get(), false);
    volume.assume_warm(load, fenced(&[])).unwrap();
    PARK.with(|park| park.set(true));
    reach(&mut volume, &control, Stage::Convert);
    assert_eq!(
        storage.cut_intact(tenure, spanning),
        Err(CaptureError::Replaced),
        "a pass from before the attach proves nothing after it"
    );
    settle(&mut volume, &control);
    PARK.with(|park| park.set(false));
    assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
    assert_eq!(
        published_capture(&[], (&early, storage.capture_epoch())),
        (Err(WriteRefused::Replaced), None),
        "a proof of the pre-attach membership publishes nothing"
    );
    let _ = storage.pool().capture_lock().unwrap().finish();
    let after = storage.start_capture(1024, true, 1024).unwrap();
    let captured = drain(&storage);
    assert_eq!(captured.len(), entries.len());
    let proof = storage.cut_intact(tenure, after).unwrap();
    let (published, named) = published_capture(&captured, (&proof, storage.capture_epoch()));
    assert_eq!(published, Ok(()));
    assert_eq!(named.map(|ck| ck.capture), Some(after));
}

/// A record of version 0 is judged by its key as FILL admission judges it: coverage over an
/// interval that excludes 0 still omits the entry, its units free, and the other entry serves.
#[test]
fn a_version_zero_entry_under_any_interval_of_its_key_is_omitted() {
    let (store, entries, writer) = written(2);
    relaunch_under(
        narrow,
        &store,
        fenced_over(&[entries[0].key], (5, 9)),
        whole(&entries),
        |storage, volume, control| {
            settle(volume, control);
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
            let warm = volume.metadata.warm.as_ref().unwrap();
            assert_eq!((warm.rows(), warm.omitted), (1, 1));
            assert_eq!(units(storage).0, writer.0 + 1);
            live(storage, volume);
            let mut reader = storage.register().unwrap();
            assert!(matches!(
                lookup(&mut reader, &entries[0].key, 4),
                Err(LookupError::Missing)
            ));
            let n = entries[1].key[0];
            assert_eq!(
                served(storage, volume, control, n),
                [&key(n)[..4], &[n; 40][..]].concat()
            );
        },
    );
}

/// A withdrawal that completes just before a stage's pool-gate try-lock is seen by the stage's read under the gate:
/// at the hold, an install and the commit the stage writes no table, moves no cursor and does not open.
#[test]
fn a_withdrawal_before_a_stage_s_gate_is_read_under_the_gate() {
    let (store, entries, _) = written(3);
    for at in [Stage::Hold, Stage::Install, Stage::Commit] {
        relaunch(&store, whole(&entries), |storage, volume, control| {
            reach(volume, control, at);
            let before = (units(storage), resident(storage));
            let cursors = progress(volume);
            super::WITHDRAW_BEFORE_GATE.with(|at| at.set(true));
            volume.warm_step();
            super::WITHDRAW_BEFORE_GATE.with(|at| at.set(false));
            assert_eq!(volume.readiness(), State::Withheld, "{at:?}");
            assert_ne!(volume.metadata_outcome(), MetadataOutcome::Open, "{at:?}");
            assert_eq!((units(storage), resident(storage)), before, "{at:?}");
            assert_eq!(progress(volume), cursors, "{at:?}");
            assert_eq!(writes(control), 0, "{at:?}");
        });
    }
}

/// `repeated` finds a repeat exactly when two words are equal, for words sharing their high bits, their low bits, or
/// neither, the word 0 included, at lengths around the empty and single-word cases, reusing one table across calls.
#[test]
fn repeated_finds_exactly_the_equal_words() {
    let mut rng = super::super::super::seeded::SplitMix64::new(1151);
    let mut table = Vec::new();
    for round in 0..600 {
        let len = match round % 5 {
            0 => rng.below(3) as usize,
            _ => rng.below(3000) as usize,
        };
        let mut words: Vec<u64> = (0..len)
            .map(|_| match round % 3 {
                0 => rng.next_u64(),
                1 => rng.below(1 << 20) << 44,
                _ => rng.below(1 << 12),
            })
            .collect();
        if round % 2 == 0 && len >= 2 {
            let (from, to) = (
                rng.below(len as u64) as usize,
                rng.below(len as u64) as usize,
            );
            words[to] = words[from];
        }
        let mut sorted = words.clone();
        sorted.sort_unstable();
        let expected = sorted.windows(2).any(|pair| pair[0] == pair[1]);
        assert_eq!(
            super::repeated(words.iter().copied(), &mut table),
            expected,
            "round {round}"
        );
    }
    for (words, expected) in [
        (&[0, 7, 9][..], false),
        (&[5, 0, 3, 0][..], true),
        (&[0][..], false),
        (&[0, 0][..], true),
        (&[4, 0, 8][..], false),
    ] {
        assert_eq!(
            super::repeated(words.iter().copied(), &mut table),
            expected,
            "words {words:?}"
        );
    }
}

/// What a storage's finalization returned.
type Finalized = Result<super::super::super::Finalization, super::super::super::FinalizeError>;

/// Runs a warm attempt of three entries to its commit stage, after every pair was published and before
/// `LoadComplete`, then either ends it there by withdrawal or, with `commit`, lets it commit; releases the volume and
/// closes admission. With `sweep`, the close service then runs to a complete report twice, with certification and
/// slot service after each call. Returns the units free after the release and after the service, the finalization's
/// result and the unmap count.
fn closed_after_its_publication(
    commit: bool,
    sweep: bool,
) -> ((u64, u64), (u64, u64), Finalized, usize) {
    use super::super::super::budget::WorkBudget;
    use super::super::super::publication_tests::drain;
    use super::super::super::test_platform::Op;
    let (store, entries, _) = written(3);
    let mut storage = narrow();
    let platform_log = storage.platform.log();
    let buffers = arena_with(4, 9);
    let (held, serviced) = {
        let (mut volume, control) = attach_over(&storage, &buffers, &store).unwrap();
        let load = decoded(&storage, &entries, volume.authority.session().get(), false);
        volume.assume_warm(load, fenced(&[])).unwrap();
        PARK.with(|park| park.set(true));
        reach(&mut volume, &control, Stage::Commit);
        PARK.with(|park| park.set(false));
        assert_eq!(
            progress(&volume).1.iter().sum::<usize>(),
            entries.len(),
            "premise: every pair is published"
        );
        assert_eq!(volume.readiness(), State::Loading, "premise: no commit");
        assert_eq!(resident(&storage), entries.len());
        if commit {
            reach(&mut volume, &control, Stage::Done);
            assert_eq!(volume.readiness(), State::Loaded, "premise: the commit");
        } else {
            assert_eq!(storage.withdraw(), State::Withheld);
        }
        let mut out = Vec::with_capacity(16);
        for _ in 0..64 {
            if matches!(
                volume.close(),
                super::super::super::QuiesceProgress::Quiesced(_)
            ) {
                break;
            }
            control.tick(64);
            let _ = volume.poll_storage(0, &mut out);
            out.clear();
        }
        assert!(volume.release().is_ok());
        let held = units(&storage);
        storage.close();
        drain(&storage);
        if sweep {
            for _ in 0..2 {
                let report = storage
                    .close_service(&mut WorkBudget::new(1 << 16))
                    .unwrap();
                assert!(report.complete, "premise: {report:?}");
                drain(&storage);
            }
        }
        (held, units(&storage))
    };
    let ended = storage.finalize(&mut WorkBudget::new(1 << 16));
    (held, serviced, ended, platform_log.ranges(Op::Unmap).len())
}

/// ENDED-HOLDS past the publication: a warm attempt withdrawn after it published every pair and before its commit
/// leaves its installed slots anchored, so the storage's finalization reports them blocked and releases no extent.
#[test]
fn a_storage_after_a_warm_attempt_ended_past_its_publication_finalizes_blocked() {
    let (held, serviced, ended, unmaps) = closed_after_its_publication(false, false);
    assert_eq!(serviced, held, "the ended attempt frees no extent");
    assert_eq!(
        ended,
        Ok(super::super::super::Finalization::Blocked(
            super::super::super::Blockers {
                held_slots: 3,
                ..Default::default()
            }
        ))
    );
    assert_eq!(unmaps, 0);
}

/// ENDED-HOLDS under the close service: the storage of a warm attempt that ended after its publication and before its
/// commit keeps the attempt's installed slots until it drops, so the close service frees none of their extents and
/// the finalization after it reports them blocked and unmaps nothing.
#[test]
fn the_close_service_frees_no_slot_of_a_warm_attempt_ended_past_its_publication() {
    let (held, serviced, ended, unmaps) = closed_after_its_publication(false, true);
    assert_eq!(serviced, held, "the ended attempt frees no extent");
    assert_eq!(
        ended,
        Ok(super::super::super::Finalization::Blocked(
            super::super::super::Blockers {
                held_slots: 3,
                ..Default::default()
            }
        ))
    );
    assert_eq!(unmaps, 0);
}

/// The hold ends at the commit: the close service removes every pair of a warm attempt that committed and returns its
/// extents, so the storage's finalization drains.
#[test]
fn the_close_service_returns_the_slots_of_a_committed_warm_attempt() {
    let (held, serviced, ended, _) = closed_after_its_publication(true, true);
    assert_eq!(
        (serviced.0, serviced.1),
        (held.0 + 3, held.1 + 3),
        "each restored extent returns"
    );
    assert_eq!(ended, Ok(super::super::super::Finalization::Drained));
}

/// A finalization call whose allowance ends after a clean inspection closes admission and keeps that inspection, so
/// no warm attempt may install a slot behind it: either the attach is refused `Closed` and the next call drains, or
/// the slots an ended attempt left installed are reported blocked with no extent released.
#[test]
fn a_clean_inspection_is_never_followed_by_a_warm_install_it_misses() {
    use super::super::super::budget::WorkBudget;
    use super::super::super::test_platform::{Op, blocked, finalize};
    use super::super::super::{Finalization, FinalizeError, Phase};
    // The largest allowance that pays the whole inspection of a `narrow` storage and no release position.
    let mut inspection = 0;
    while narrow().finalize(&mut WorkBudget::new(inspection + 1))
        == Err(FinalizeError::BudgetExhausted)
    {
        inspection += 1;
    }
    let (store, entries, _) = written(3);
    let mut storage = narrow();
    let platform_log = storage.platform.log();
    assert_eq!(
        storage.finalize(&mut WorkBudget::new(inspection)),
        Err(FinalizeError::BudgetExhausted)
    );
    assert!(storage.is_closed());
    assert_eq!(storage.phase(), Phase::Live);
    let buffers = arena_with(4, 9);
    let installed = match attach_over(&storage, &buffers, &store) {
        Err(refusal) => {
            assert_eq!(refusal, super::super::AttachError::Closed);
            false
        }
        Ok((mut volume, control)) => {
            let load = decoded(&storage, &entries, volume.authority.session().get(), false);
            volume.assume_warm(load, fenced(&[])).unwrap();
            PARK.with(|park| park.set(true));
            reach(&mut volume, &control, Stage::Publish);
            PARK.with(|park| park.set(false));
            assert_eq!(storage.withdraw(), State::Withheld);
            let mut out = Vec::with_capacity(16);
            for _ in 0..64 {
                if matches!(
                    volume.close(),
                    super::super::super::QuiesceProgress::Quiesced(_)
                ) {
                    break;
                }
                control.tick(64);
                let _ = volume.poll_storage(0, &mut out);
                out.clear();
            }
            assert!(volume.release().is_ok());
            true
        }
    };
    assert_eq!(
        resident(&storage),
        if installed { entries.len() } else { 0 }
    );
    if installed {
        assert_eq!(
            blocked(&mut storage),
            super::super::super::Blockers {
                held_slots: entries.len(),
                ..Default::default()
            }
        );
        assert!(platform_log.ranges(Op::Unmap).is_empty());
    } else {
        assert_eq!(finalize(&mut storage), Ok(Finalization::Drained));
    }
}

/// Reaches the install stage over a written set of three, plants a domain head past the slot table so the install's
/// fold indexes past the records under the capture hold, runs `call` on the volume, and returns the capture mutex's
/// state after it.
fn capture_after_a_fold_panic(
    call: impl FnOnce(&mut TestVolume<'_, '_>, &SimControl),
) -> Result<(), super::super::super::gate::GateError> {
    let (store, entries, _) = written(3);
    relaunch(&store, whole(&entries), |storage, volume, control| {
        reach(volume, control, Stage::Install);
        assert!(
            storage.pool().capture_lock().is_ok(),
            "premise: capture serialization is free and sound before the install"
        );
        let mut access = storage.pool().try_lock_quiet().unwrap();
        access.tables().domain.head = storage.pool().records().len() as u32 + 5;
        access.release();
        call(volume, control);
        storage.pool().capture_lock().map(drop)
    })
}

/// Capture serialization's poison rule (`Pool::capture_lock`, "# Errors": "`GateError::Poisoned` if a holder
/// panicked while holding it"): the warm install's fold panics on a malformed domain head while the tick holds the
/// capture mutex, and capture serialization is terminal after it.
#[test]
fn a_panicking_install_fold_poisons_capture_serialization() {
    use super::super::super::gate::GateError;
    let capture = capture_after_a_fold_panic(|volume, control| {
        let caught =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| tick(volume, control)));
        assert!(caught.is_err(), "premise: the install's fold panics");
    });
    assert_eq!(capture, Err(GateError::Poisoned));
}

/// The same tick made by a destructor of a thread that is already unwinding, its panic caught there: capture
/// serialization is terminal after it, as on a thread that is not unwinding (`Capture::poison`: "Each runs it itself
/// because a mutex guard taken by a thread that was already unwinding leaves its mutex unpoisoned on drop").
#[test]
fn a_panicking_install_fold_poisons_capture_serialization_even_during_unwinding() {
    use super::super::super::gate::GateError;
    let capture = capture_after_a_fold_panic(|volume, control| {
        struct TicksOnDrop<'v, 'a, 'b>(&'v mut TestVolume<'a, 'b>, &'v SimControl);
        impl Drop for TicksOnDrop<'_, '_, '_> {
            fn drop(&mut self) {
                assert!(std::thread::panicking());
                let (volume, control) = (&mut *self.0, self.1);
                let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    tick(volume, control)
                }));
                assert!(caught.is_err(), "premise: the install's fold panics");
            }
        }
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ticker = TicksOnDrop(volume, control);
            panic!("an unrelated panic with a live ticker");
        }));
        assert!(outcome.is_err());
    });
    assert_eq!(capture, Err(GateError::Poisoned));
}

/// The install's hold folds each lane's sublist onto the policy list on the thread that ticks; a list head outside the slot records panics that fold under the pool gate, and the panic poisons the gate (`gate.rs`: "A holder that panics poisons the gate on release"), also in a tick made by a destructor while its thread unwinds from another panic: the guard, taken during the unwind, would release open on drop.
#[test]
fn an_install_fold_over_a_malformed_policy_head_poisons_the_gate_even_during_unwinding() {
    struct CallsOnDrop<'c, F: FnMut()> {
        call: F,
        panicked: &'c std::cell::Cell<bool>,
    }
    impl<F: FnMut()> Drop for CallsOnDrop<'_, F> {
        fn drop(&mut self) {
            let called = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (self.call)()));
            self.panicked.set(called.is_err());
        }
    }
    for unwinding in [false, true] {
        let (store, entries, _) = written(3);
        relaunch(&store, whole(&entries), |storage, volume, control| {
            reach(volume, control, Stage::Install);
            let live = storage.live_pool().unwrap();
            let mut access = live.lock().unwrap();
            access.tables().domain.head = live.records().len() as u32;
            access.release();
            let panicked = std::cell::Cell::new(false);
            let caller = CallsOnDrop {
                call: || tick(volume, control),
                panicked: &panicked,
            };
            if unwinding {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _caller = caller;
                    panic!("an unrelated panic with a live caller");
                }));
                assert!(outcome.is_err());
            } else {
                drop(caller);
            }
            assert!(
                panicked.get(),
                "premise: the install's fold panicked, unwinding={unwinding}"
            );
            assert!(
                matches!(
                    live.try_lock_quiet(),
                    Err(super::super::super::gate::GateError::Poisoned)
                ),
                "the fold's panic poisons the gate, unwinding={unwinding}"
            );
        });
    }
}

/// The conservation snapshot reads a storage inside a warm load as
/// unreadable: an attempt withdrawn at its install stage, before its commit,
/// keeps its hold for the storage's life. A load that committed and went
/// live restores tables and bindings the judge passes.
#[test]
fn the_conservation_snapshot_refuses_an_uncommitted_warm_load_and_passes_a_committed_one() {
    use super::super::super::conservation::{Fault, Holdings};
    let (store, entries, _) = written(3);
    relaunch(&store, whole(&entries), |storage, volume, control| {
        reach(volume, control, Stage::Install);
        assert_eq!(storage.withdraw(), State::Withheld);
        for _ in 0..8 {
            tick(volume, control);
        }
        assert_ne!(volume.metadata_outcome(), MetadataOutcome::Open);
        let mut holdings = Holdings::default();
        storage.holdings_into(&mut holdings);
        assert_eq!(
            holdings.judge(&[]),
            Err(Fault::Unreadable("the storage is inside a warm load"))
        );
    });
    relaunch(&store, whole(&entries), |storage, volume, control| {
        settle(volume, control);
        live(storage, volume);
        assert_eq!(resident(storage), entries.len(), "premise: restored slots");
        let mut bindings = Vec::new();
        storage.bindings_into(&mut bindings).unwrap();
        assert_eq!(bindings.len(), entries.len(), "premise: restored bindings");
        let mut holdings = Holdings::default();
        storage.holdings_into(&mut holdings);
        assert_eq!(holdings.judge(&bindings), Ok(()));
    });
}
