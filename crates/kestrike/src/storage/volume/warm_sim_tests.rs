//! The production deterministic simulation of warm recovery over one shard's store double, control-plane doubles and
//! one volume's simulated media: a tenure fills, captures and writes its checkpoint through its own unit commands;
//! host loss drops it without quiesce; the record's standby takes the volume over by its own compare-and-swap and
//! loads warm, so the recoverable set survives host loss (P4) and no fill after `Live` takes a restored unit (P6);
//! owner-and-standby loss and a successor crash before its preempt keep the volume and its evidence for the next
//! takeover, and no outcome RESETs or requests replacement (P9).

use std::rc::Rc;

use super::super::super::checkpoint::{
    PLANT, Plant, PossiblyNamed, StagedCheckpoint, SuffixLimits,
};
use super::super::super::device::Operation;
use super::super::super::device::sim::{Media, SimControl, media, sim_attached};
use super::super::super::ledger::EngineBudget;
use super::super::super::lookup::LookupError;
use super::super::super::lookup_tests::lookup;
use super::super::super::portable::PhysicalClock;
use super::super::super::portable::scripted::{ScriptedClock, TEST_EARLIEST};
use super::super::super::publication_tests::{payload, reserved};
use super::super::super::publish_tests::{TRIES, budget, key};
use super::super::super::record::Crc32c;
use super::super::super::recovery::CaptureEntry;
use super::super::super::recovery::capture_tests::drain;
use super::super::super::recovery::checkpoint::{Checkpoint, encode};
pub(crate) use super::super::super::recovery::delta_replay::{
    PLANT as REPLAY_PLANT, Plant as ReplayPlant,
};
pub(crate) use super::super::super::recovery::suffix::FLOORLESS;
use super::super::super::recovery::{LoadRefusal, session_at};
use super::super::super::store_tests::{client, shard};
use super::super::super::test_platform::TestPlatform;
use super::super::super::volume_fixture::{
    BUFFER, DEPTH, Device, MEDIA, TICK, arena_with, bootstrap, config_for, facts, read_back,
    receive_all, settle,
};
use super::super::super::{
    CacheVersion, IO_UNIT, MetadataOutcome, ReadStatus, ReserveError, Storage, Volume,
};
use super::super::bootstrap_tests::submitted;
use super::super::clock_tests::pair_of;
use super::super::gate_fixture::{self, Reserving, ZeroClock};
use super::super::helpers::PARK;
use super::tests::{live, tick, units};
pub(crate) use super::{HOLD_SKIPS_RESTORE, REFUSE_ABSENT, RETAIN_ABSENT};
use crate::failover::fresh::tests::registrant;
use crate::failover::records::{Layout, NamedCheckpoint, ShardRecord, Suffix, VolumeRecord};
use crate::failover::restart::tests as restart_tests;
use crate::failover::takeover::tests::{
    Card, a_holds_c_registered, b_host, b_pair, c_host, c_pair, designate, stored_b, stored_c,
    takeover_of, with_c, with_c_and_b,
};
use crate::storage::budget::WorkBudget;
use crate::storage::store::sim::Shared;

/// The predecessor's tenure: generation 3 at `E = 4`, so its session is `(3, 8)` and a takeover's `(3, 10)`.
pub(super) fn predecessor_session() -> crate::storage::Session {
    session_at(3, 3)
}

/// The metadata prefix of [`storage`]'s volume, in units.
pub(crate) const PREFIX: u64 = 32;

/// The records layout over the prefix: three slots of three units, so a slot's entries span two data units, and the
/// rest the delta region.
pub(crate) fn layout() -> Layout {
    Layout {
        units: PREFIX,
        slots: 3,
        slot_units: 3,
        entries: 2 * crate::failover::records::UNIT_ENTRIES as u32,
    }
}

/// A storage of the shard's shape: 64 slots over two index shards, `commands` metadata commands, four read
/// operations and read commands, which an owner's four request slots need, and recovery limits that hold a job for
/// every read window and destination.
pub(crate) fn storage(commands: u32) -> Storage<TestPlatform> {
    storage_with(commands, None)
}

/// [`storage`] with maintenance under `maintenance`'s watermarks.
pub(super) fn storage_with(
    commands: u32,
    maintenance: Option<super::super::config::VolumeWatermarks>,
) -> Storage<TestPlatform> {
    storage_shaped(commands, maintenance, None, (65, [32, 32]), |_| {})
}

/// [`storage`] whose owner's recovery runs under the host's recovery I/O share `io`.
pub(crate) fn storage_shared(
    commands: u32,
    io: super::super::super::recovery::HostShare,
) -> Storage<TestPlatform> {
    storage_shaped(commands, None, Some(io), (65, [32, 32]), |_| {})
}

pub(crate) fn share_of(
    storage: &Storage<TestPlatform>,
) -> super::super::super::recovery::HostShare {
    storage.recovery.io
}

/// [`storage`] of one metadata command over a pool of `slots` slots whose two index shards hold `shards` keys.
pub(crate) fn storage_of(slots: usize, shards: [usize; 2]) -> Storage<TestPlatform> {
    storage_shaped(1, None, None, (65, shards), |config| {
        config.volume.slot_count = slots;
        config.volume.alloc_search_words = super::super::super::extent::work_bound(65, slots, 1);
    })
}

/// The payload units of [`sequence_storage`].
const SEQUENCE_UNITS: u64 = 256;

/// [`storage`] over [`SEQUENCE_UNITS`] payload units with a sequence arena of one root and a body cap one unit past
/// [`EXTENT_PAYLOAD`](super::super::super::EXTENT_PAYLOAD), so a FILL whose body passes one extent's payload is
/// admitted as an object of two extents.
pub(crate) fn sequence_storage() -> Storage<TestPlatform> {
    storage_shaped(
        1,
        None,
        None,
        (SEQUENCE_UNITS as usize, [32, 32]),
        |config| {
            config.volume.block_roots = 1;
            config.volume.alloc_search_words =
                super::super::super::extent::work_bound(SEQUENCE_UNITS, 64, 64);
            config.body_cap = super::super::super::EXTENT_PAYLOAD as usize + IO_UNIT;
        },
    )
}

/// [`sequence_storage`] with no sequence arena: a FILL whose body passes one extent's payload refuses
/// `Layout(MultipleExtents)`.
pub(crate) fn wide_storage() -> Storage<TestPlatform> {
    storage_shaped(
        1,
        None,
        None,
        (SEQUENCE_UNITS as usize, [32, 32]),
        |config| {
            config.body_cap = super::super::super::EXTENT_PAYLOAD as usize + IO_UNIT;
        },
    )
}

/// [`storage_with`] over `payload_units` payload units and two index shards that hold `shards` keys, under the
/// recovery I/O share `io`, or the test volume's own share when `None`, its configuration changed by `shape`.
fn storage_shaped(
    commands: u32,
    maintenance: Option<super::super::config::VolumeWatermarks>,
    io: Option<super::super::super::recovery::HostShare>,
    (payload_units, shards): (usize, [usize; 2]),
    shape: impl FnOnce(&mut super::super::super::config::StorageConfig),
) -> Storage<TestPlatform> {
    use super::super::super::config::StorageConfig;
    use super::super::super::publish_tests::{PAGE, index_config, storage_config, storage_from};
    let fills = [4, 4];
    let index = crate::index::IndexConfig {
        fills: &fills,
        ..index_config(&shards, (1, 1), 1)
    };
    let mut volume = super::super::test_volume_with(payload_units * IO_UNIT, PREFIX, 64);
    volume.metadata_commands = commands;
    (volume.read_ops, volume.read_commands) = (4, 4);
    volume.maintenance = maintenance;
    let jobs = (super::super::super::checkpoint::WINDOWS + 2) as u32;
    (volume.recovery.jobs, volume.recovery.adopt) = (jobs, jobs);
    if let Some(io) = io {
        volume.recovery.io = io;
    }
    let mut config = StorageConfig {
        lease_limit: 16,
        volume,
        ..storage_config(64)
    };
    shape(&mut config);
    let mut storage = storage_from(&config, &index, TestPlatform::heap(PAGE));
    storage.install_hasher(crate::index::KeyHasher::with_key_pair(PAIR.0, PAIR.1));
    let owner = storage.index().expect("an indexed storage");
    let mut placed = [0usize; 2];
    for n in 1..=KEYS {
        let route = (owner.hasher)
            .route_unpaid(&key(n), &owner.geometry, crate::index::Prefetch::NONE)
            .expect("an enabled shard");
        placed[route.shard().0] += 1;
    }
    assert!(
        placed.iter().all(|&count| count <= 32),
        "keys 1..={KEYS} route {placed:?} under the fixed pair, past a 32-key shard"
    );
    storage.platform.ticks(&[Some(1)]);
    storage
}

/// The most keys a test of this module publishes.
const KEYS: u8 = 50;

/// The index key pair of every storage here, under which keys `1..=KEYS` place at most 32 in either shard, so the
/// writer's publication and the successor's restored publication fit the shards' visible limits on every run.
const PAIR: (u64, u64) = (0x5eed_0001, 0x5eed_0002);

/// Tenure A over fresh media: `count` published objects, captured and written as checkpoint 9 through A's unit
/// commands. Returns the media, the entries, the named checkpoint and A's free and placeable units; A's volume drops
/// without quiesce, the host loss.
fn tenure_a(count: u8) -> (Media, Vec<CaptureEntry>, NamedCheckpoint, (u64, u64)) {
    let a = tenure_a_with(count, |n| [&key(n)[..4], &[n; 40][..]].concat());
    (a.media, a.entries, a.named, a.writer)
}

/// What tenure A left behind at its host loss.
pub(crate) struct TenureA {
    pub(crate) media: Media,
    pub(crate) entries: Vec<CaptureEntry>,
    pub(crate) named: NamedCheckpoint,
    /// A's free and placeable units after its capture.
    pub(crate) writer: (u64, u64),
    /// Every write A's device executed, in order: its payload fills, then its checkpoint units.
    pub(crate) attempts: Vec<super::super::super::device::sim::Attempt>,
}

/// [`tenure_a`] whose object `n` holds `content(n)`, four metadata bytes then the body, with A's write attempts.
pub(crate) fn tenure_a_with(count: u8, content: impl Fn(u8) -> Vec<u8>) -> TenureA {
    tenure_replacing(predecessor_session(), count, content, None).0
}

/// [`tenure_a_with`] for `shard`: the checkpoint and its unit identities name `shard`.
pub(crate) fn tenure_a_on(
    shard: crate::net::ownership::Shard,
    count: u8,
    content: impl Fn(u8) -> Vec<u8>,
) -> TenureA {
    tenure_on(shard, predecessor_session(), count, content, None).0
}

/// Publishes `payload`, four metadata bytes then the body, as object `n` through `dev` and services both shards'
/// fills.
fn publish_object<'s>(
    storage: &'s Storage<TestPlatform>,
    dev: &mut Device<'s, '_>,
    n: u8,
    payload: &[u8],
) {
    use super::super::super::publication_tests::{DEADLINE, reserved};
    use super::super::super::publish_tests::{TRIES, budget};
    let mut fill = reserved(storage, &key(n), &payload[4..]).unwrap();
    dev.fill(&mut fill, payload);
    drop(
        fill.publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
            .unwrap(),
    );
    for shard in 0..2 {
        let mut budget = super::super::super::budget::WorkBudget::new(1 << 20);
        storage
            .service_fills(crate::index::ShardIndex(shard), 8, &mut budget)
            .unwrap();
    }
}

/// [`tenure_a_with`] for a tenure of `session` that, after its checkpoint is written, publishes `replaced.1` over
/// object `replaced.0`, and
/// returns the suffix record of that replacement: the captured entry leaves and the new publication's entry, read
/// from a second capture pass, enters. The tenure writes the new record's payload; it writes no suffix block.
pub(crate) fn tenure_replacing(
    session: crate::storage::Session,
    count: u8,
    content: impl Fn(u8) -> Vec<u8>,
    replaced: Option<(u8, Vec<u8>)>,
) -> (
    TenureA,
    Option<super::super::super::recovery::delta::Record>,
) {
    tenure_on(shard(), session, count, content, replaced)
}

fn tenure_on(
    shard: crate::net::ownership::Shard,
    session: crate::storage::Session,
    count: u8,
    content: impl Fn(u8) -> Vec<u8>,
    replaced: Option<(u8, Vec<u8>)>,
) -> (
    TenureA,
    Option<super::super::super::recovery::delta::Record>,
) {
    let store = media(super::super::super::volume_fixture::MEDIA);
    let storage = storage(1);
    let buffers = super::super::super::volume_fixture::arena_with(4, 9);
    let wrote = session.get();
    let authority = crate::storage::ServingAuthority::fixture_under(session);
    let (mut volume, control) =
        super::super::super::volume_fixture::attach_under(&storage, &buffers, &store, authority)
            .expect("attach");
    bootstrap(&mut volume, &control);
    control.record_attempts();
    let mut dev = Device { volume, control };
    for n in 1..=count {
        publish_object(&storage, &mut dev, n, &content(n));
    }
    let pass = storage.start_capture(1024, true, 1024).unwrap();
    let entries = drain(&storage);
    assert_eq!(entries.len(), usize::from(count));
    let session = dev.volume.authority.session().get();
    assert_eq!(session, wrote);
    let mut possible = PossiblyNamed::new((shard, session), layout(), None);
    let checkpoint = Checkpoint {
        shard,
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
    let writer = units(&storage);
    let record = replaced.map(|(n, payload)| {
        use super::super::super::recovery::delta::{Cause, Record, identity_of};
        publish_object(&storage, &mut dev, n, &payload);
        // The checkpoint's pass ends before the pass that reads the replacement's entry starts.
        super::super::super::recovery::capture_tests::finish(&storage, pass).unwrap();
        storage.start_capture(1024, true, 1024).unwrap();
        let later = drain(&storage);
        let of = |entries: &[CaptureEntry]| {
            let entry = entries.iter().find(|entry| entry.key == key(n));
            entry.expect("the object is published").clone()
        };
        let (old, new) = (of(&entries), of(&later));
        assert_ne!(
            old.extents, new.extents,
            "the replacement holds its own units"
        );
        Record::Replace {
            old: identity_of(&old),
            cause: Cause::Evict,
            new,
        }
    });
    let a = TenureA {
        media: store,
        entries,
        named,
        writer,
        attempts: dev.control.attempts(),
    };
    (a, record)
}

/// A suffix record.
type SuffixRecord = super::super::super::recovery::delta::Record;

/// The suffix record of `entry`'s eviction.
pub(crate) fn removal_of(entry: &CaptureEntry) -> SuffixRecord {
    use super::super::super::recovery::delta::{Cause, Record, identity_of};
    Record::Remove {
        identity: identity_of(entry),
        cause: Cause::Evict,
    }
}

/// The INSERT of the new entry of `record`, a REPLACE, bound live-only: its pair is `PortableExpiry::ABSENT`, as a FILL
/// published under an untrusted clock reading binds it.
pub(crate) fn live_only_insert(record: &SuffixRecord) -> SuffixRecord {
    use super::super::super::recovery::delta::Record;
    match record {
        Record::Replace { new, .. } => Record::Insert(CaptureEntry {
            deadline_ns: 0,
            lifetime_ms: 0,
            ..new.clone()
        }),
        other => panic!("{other:?}"),
    }
}

/// The device unit of the payload a replacement record's new entry names.
pub(crate) fn replacement_unit(record: &SuffixRecord) -> u32 {
    match record {
        super::super::super::recovery::delta::Record::Replace { new, .. } => payload_unit(new),
        other => panic!("{other:?}"),
    }
}

/// The slot and the units of a checkpoint of `entries` that the tenure whose record names `named` stages under
/// `named`'s own capture identity, or the stage's refusal. The set is the tenure's at that record, so it found
/// `named` named.
pub(crate) fn restaged(
    named: NamedCheckpoint,
    entries: &[CaptureEntry],
) -> Result<(u32, Vec<Vec<u8>>), super::super::super::checkpoint::StageRefusal> {
    let mut possible = PossiblyNamed::new((shard(), named.session), layout(), Some(named));
    let checkpoint = Checkpoint {
        shard: shard(),
        session: named.session,
        capture: named.capture,
    };
    let budget = EngineBudget::unlimited();
    let stage = StagedCheckpoint::new(
        Crc32c::detect(),
        &mut possible,
        (checkpoint, entries),
        &budget,
    )?;
    let units = stage.units().iter().map(|unit| unit.to_vec()).collect();
    Ok((stage.slot(), units))
}

/// What the owner's suffix writer did in [`append_suffix`].
pub(crate) struct Appended {
    /// Why the store recorded no suffix, when it refused: a chain at its cap before any request, or the store
    /// client's own refusal.
    pub(crate) unreserved: Option<super::super::super::checkpoint::WriteRefused>,
    /// The block each appended record sealed, with its LSN, in order: the records' prefix up to the first the log
    /// refused before any change, so `blocks[i]` holds `records[i]`; empty when the store refused.
    pub(crate) blocks: Vec<(u64, Vec<u8>)>,
}

/// The owner the shard record names records a suffix of `records.len()` blocks from `start` through
/// `checkpoint::reserve_suffix`, opens its `SuffixLog` over the record's floor, and appends each record as one sealed
/// block, stopping at the first the log refuses. With `certify` it then takes every block as written and certifies the suffix to its durable end through
/// `checkpoint::certify`. The caller lands the blocks' bytes on the media.
pub(crate) fn append_suffix(
    store: &Shared,
    start: u64,
    records: &[SuffixRecord],
    certify: bool,
) -> Appended {
    use super::super::super::checkpoint::{
        certify as certify_suffix, reserve_suffix, settled_floor,
    };
    use super::super::super::recovery::suffix::{SuffixLimits, SuffixLog};
    use crate::failover::records::Suffix;
    use crate::failover::retire::Target;
    let mut client = client(store);
    let read = client
        .read::<ShardRecord>(crate::storage::store::Key::Shard(shard()))
        .unwrap();
    let record = *read.value();
    let session =
        crate::net::ownership::session_of(record.generation.get() as u32, record.attempts * 2);
    let mut possible = PossiblyNamed::new((shard(), session), layout(), record.checkpoint);
    let own = Target::of(&record);
    let suffix = Suffix {
        session,
        start,
        certified: start,
        end: start + records.len() as u64,
    };
    let mut appended = Appended {
        unreserved: None,
        blocks: Vec::new(),
    };
    let reserved = match reserve_suffix(&mut client, &mut possible, (&read, own), suffix) {
        Ok(reserved) => reserved,
        Err(refused) => {
            appended.unreserved = Some(refused);
            return appended;
        }
    };
    let floor =
        settled_floor(&possible, reserved.value()).expect("the reservation settled the set");
    let limits = SuffixLimits {
        flush_ns: 1,
        queue_blocks: 8,
        oldest_ns: 1 << 40,
        uncertified: 1 << 40,
    };
    let mut log = SuffixLog::default();
    assert!(log.open(
        (Crc32c::detect(), shard()),
        (limits, &layout()),
        suffix,
        floor
    ));
    for record in records {
        if log.append(0, record).is_err() {
            break;
        }
        log.seal_cut();
        let mut unit = [0; super::super::super::recovery::delta::UNIT_LEN];
        let lsn = log.take(&mut unit).expect("the sealed block");
        appended.blocks.push((lsn, unit.to_vec()));
        log.written(lsn);
    }
    if certify {
        let end = (session, log.durable());
        certify_suffix(&mut client, &mut possible, (&reserved, own), end).unwrap();
    }
    appended
}

/// The delta blocks of the layout.
pub(crate) fn region() -> u64 {
    super::super::super::recovery::delta::blocks(&layout())
}

/// The device unit of delta block `lsn`.
pub(crate) fn block_unit(lsn: u64) -> u32 {
    let region = super::super::super::recovery::delta::blocks(&layout());
    (layout().units - region + lsn % region) as u32
}

/// The delta block of `session` at `lsn` holding `records`, which must fit one block.
pub(crate) fn suffix_block(
    session: u64,
    lsn: u64,
    records: &[super::super::super::recovery::delta::Record],
) -> Vec<u8> {
    let block = super::super::super::recovery::delta::Block {
        shard: shard(),
        session,
        lsn,
    };
    let blocks = super::super::super::recovery::delta_tests::packed_as(block, records);
    assert_eq!(blocks.len(), 1);
    blocks[0].to_vec()
}

/// The storage key of object `n`.
pub(crate) fn object_key(n: u8) -> [u8; 32] {
    key(n)
}

/// The device unit that holds the slot row of the entry at `index` of `named`'s capture order: a slot of one-extent
/// entries holds [`UNIT_ENTRIES`](crate::failover::records::UNIT_ENTRIES) rows a data unit, after its unit 0.
pub(crate) fn row_unit(named: NamedCheckpoint, index: usize) -> u32 {
    let data = 1 + index / crate::failover::records::UNIT_ENTRIES as usize;
    1 + named.slot * layout().slot_units + data as u32
}

/// The device unit of `entry`'s one payload unit.
pub(crate) fn payload_unit(entry: &CaptureEntry) -> u32 {
    let locator = super::ExtentLocator::from_bits(entry.extents[0]);
    assert_eq!((entry.extents.len(), locator.len_units()), (1, 1));
    (PREFIX + locator.start_unit()) as u32
}

/// The shard's store: the record names A owner at `E = 4` with C as standby, the checkpoint `named` at cut 0 and no
/// suffix; the volume record enrolls A, C and, when `with_b`, B, under the test layout.
pub(crate) fn shard_store(named: NamedCheckpoint, with_b: bool) -> Shared {
    shard_store_with(named, with_b, 4, (0, &[]))
}

/// [`shard_store`] whose record names A owner at `E = attempts`, the cut `cut` and the suffixes `ancestry`.
pub(crate) fn shard_store_with(
    named: NamedCheckpoint,
    with_b: bool,
    attempts: u32,
    (cut, ancestry): (u64, &[crate::failover::records::Suffix]),
) -> Shared {
    let shard = ShardRecord {
        checkpoint: Some(named),
        cut,
        ancestry: crate::failover::records::Ancestry::new(ancestry).unwrap(),
        standby: Some(c_host()),
        ..restart_tests::shard_record(attempts)
    };
    let volume = VolumeRecord {
        layout: layout(),
        ..if with_b { with_c_and_b() } else { with_c() }
    };
    restart_tests::store(shard, volume)
}

pub(crate) type Manifest = (
    crate::net::ownership::ShardGeneration,
    crate::failover::records::VolumeId,
    Option<NamedCheckpoint>,
    u64,
    crate::failover::records::Ancestry,
);

/// The shard record's manifest: generation, volume, checkpoint, cut and ancestry.
pub(crate) fn manifest(store: &Shared) -> Manifest {
    let record = restart_tests::shard_now(store);
    (
        record.generation,
        record.active,
        record.checkpoint,
        record.cut,
        record.ancestry,
    )
}

/// A successor's volume: over the reserving driver, whose registry shows the successor's pair holding the type-2
/// reservation, so the authority's Report issues the serving token.
pub(crate) type Successor<'s, 'a> = Volume<'s, 'a, TestPlatform, Reserving>;

/// The successor `host` takes the volume over through the store and `card`, and attaches a fresh storage over
/// `store`'s media with the capability, running `body` under parked helpers.
pub(super) fn takeover<R>(
    records: &Shared,
    store: &Media,
    (host, card, local): (
        crate::failover::records::Host,
        &mut Card,
        &restart_tests::Stored,
    ),
    body: impl for<'s> FnOnce(&'s Storage<TestPlatform>, &mut Successor<'s, '_>, &SimControl) -> R,
) -> R {
    let path = takeover_of(records, host);
    let taken = path
        .run(&mut client(records), local, card)
        .expect("the takeover");
    assert!(taken.warm().is_some(), "the record names the checkpoint");
    let own = taken.fenced().own();
    // `takeover_of` runs under the gate fixture's limits.
    let bounds = super::super::gate_fixture::bounds_of(super::super::gate_fixture::limits());
    let (authority, fencing) =
        crate::storage::ServingAuthority::restarted(bounds, Box::new(ZeroClock), taken);
    assert!(fencing.coverage().is_some(), "every page is fenced");
    let storage = storage(1);
    let buffers = super::super::gate_fixture::arena_with(4, 9);
    let (mut volume, control, _) = attach_successor(&storage, &buffers, store, authority, own);
    PARK.with(|park| park.set(true));
    let result = body(&storage, &mut volume, &control);
    PARK.with(|park| park.set(false));
    result
}

/// Attaches `storage`'s volume over `store`'s media under `authority`, behind the reserving driver whose registry
/// shows the successor's pair `own` holding the type-2 reservation, so the authority's Report issues the serving
/// token. Returns the volume, the device's control and the registry, the tenure's Report table.
pub(crate) fn attach_successor<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    buffers: &'a super::super::super::device::BufferArena<TestPlatform>,
    store: &Media,
    authority: crate::storage::ServingAuthority,
    own: crate::failover::evidence::Pair,
) -> (
    Successor<'s, 'a>,
    SimControl,
    super::super::gate_fixture::Control,
) {
    let clock = ScriptedClock::trusted();
    attach_successor_with(storage, buffers, store, (authority, own), clock)
}

/// [`attach_successor`] under the physical clock `clock`.
pub(crate) fn attach_successor_with<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    buffers: &'a super::super::super::device::BufferArena<TestPlatform>,
    store: &Media,
    (authority, own): (
        crate::storage::ServingAuthority,
        crate::failover::evidence::Pair,
    ),
    clock: Box<dyn PhysicalClock>,
) -> (
    Successor<'s, 'a>,
    SimControl,
    super::super::gate_fixture::Control,
) {
    let (disk, control) = sim_attached(config_for(7), Rc::clone(store), facts(BUFFER));
    let registry = gate_fixture::registry();
    let disk = gate_fixture::reserving_as(disk, &registry, own, 2);
    {
        let mut registry = registry.borrow_mut();
        registry.entries.push(registrant(own, 2, true));
        registry.rtype = 2;
    }
    let volume = Volume::attach(
        storage,
        buffers,
        disk,
        clock,
        authority,
        DEPTH,
        TICK,
        &mut EngineBudget::new(1 << 25),
    )
    .map_err(|(error, _)| error)
    .expect("attach");
    (volume, control, registry)
}

/// Ticks `volume` through its warm bootstrap, at most 128 ticks.
pub(super) fn load(volume: &mut Successor<'_, '_>, control: &SimControl) {
    for _ in 0..128 {
        if !volume.readiness().initializing() {
            return;
        }
        super::tests::tick(volume, control);
    }
}

/// The clocks one warm load samples: the volume's physical clock, which reads the trusted instant `physical_ns`
/// with zero width on every read, and the storage platform's monotonic sample `monotonic_ns`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LoadClock {
    /// Nanoseconds since the Unix epoch.
    pub(crate) physical_ns: u64,
    /// Nanoseconds on the storage platform's monotonic clock.
    pub(crate) monotonic_ns: u64,
}

/// Attaches `storage`'s volume over `media` warm under the fixture authority of `session`, from the checkpoint
/// `record` names under `layout`, and drives at most 1024 bootstrap ticks, whose helper-pool jobs run inline on the
/// calling thread; busy mark, install and publication shares run on scoped workers, and a refused worker start can end
/// the load `MetadataFailed`. A load that
/// ends `Open` is brought to `Live` and its control rebased; a load with any other outcome, or one still initializing
/// after the bound, returns its device as the load left it, short of `Live`. Under `clock` the load samples its two
/// readings; with `None` the volume reads `ScriptedClock::trusted()` and the platform's samples stay as the caller
/// left them. The load checks restored entries against `coverage`, the fenced coverage of the tenure's stored pages,
/// and against a fenced coverage that holds no entry under `None`. The calling thread's fixture sessions continue
/// above a generation-1 `session`, so a later fixture attach on this thread writes a higher session. Returns `None`
/// when `WarmSource::new` returns `None` or the attach returns `Err`.
///
/// # Panics
///
/// When an `Open` load's replay does not reach `Live`, or when the device holds a pending command or a posted
/// completion as its control rebases.
pub(crate) fn warm_device<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    buffers: &'a super::super::super::device::BufferArena<TestPlatform>,
    media: &Media,
    (record, layout, session): (&ShardRecord, Layout, crate::storage::Session),
    clock: Option<LoadClock>,
    coverage: Option<&crate::storage::page_coverage::Coverage>,
) -> Option<Device<'s, 'a>> {
    session.continue_fixture_sequence();
    let mut authority = crate::storage::ServingAuthority::fixture_under(session);
    let empty = crate::storage::volume_fixture::fenced(&[]);
    let coverage = coverage.unwrap_or(&empty);
    let source = super::WarmSource::new(record, layout, authority.session(), coverage)?;
    authority.warm = Some(Box::new(source));
    let physical = match clock {
        Some(clock) => {
            storage.platform.ticks(&[Some(clock.monotonic_ns)]);
            let (physical, script) = ScriptedClock::with_script();
            script.trusted(clock.physical_ns, clock.physical_ns);
            physical
        }
        None => ScriptedClock::trusted(),
    };
    let attached = crate::storage::volume_fixture::attach_under_clock(
        storage, buffers, media, authority, physical,
    );
    let (mut volume, control) = attached.ok()?;
    inline(|| {
        let mut out = Vec::with_capacity(16);
        for _ in 0..1024 {
            if !volume.readiness().initializing() {
                break;
            }
            control.tick(64);
            let _ = volume.poll_storage(0, &mut out);
            volume.release_parked();
            out.clear();
        }
    });
    if volume.metadata_outcome() == MetadataOutcome::Open {
        live(storage, &mut volume);
        control.rebase();
    }
    Some(Device { volume, control })
}

/// Runs `body` with the calling thread's inline-recovery flag set, so recovery helper jobs run on this thread, and
/// restores the flag's prior value when `body` returns or unwinds.
fn inline<R>(body: impl FnOnce() -> R) -> R {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            crate::storage::INLINE_RECOVERY.with(|cell| cell.set(self.0));
        }
    }
    let _restore = Restore(crate::storage::INLINE_RECOVERY.with(|cell| cell.replace(true)));
    body()
}

/// Whether the capture lock was taken and the storage's suffix log holds no open block and no sealed block awaiting
/// durability; `false` when the lock is refused.
pub(crate) fn suffix_idle(storage: &Storage<TestPlatform>) -> bool {
    let pool = storage.pool();
    pool.capture_lock()
        .is_ok_and(|capture| capture.suffix.idle())
}

pub(crate) fn release_capture(storage: &Storage<TestPlatform>) -> bool {
    let pool = storage.pool();
    pool.capture_lock()
        .map(|mut capture| capture.left(1, false))
        .is_ok()
}

/// The keys of `entries` that serve at `Live`, with every other key missing.
fn hits<'s>(
    storage: &'s Storage<TestPlatform>,
    volume: &mut Successor<'s, '_>,
    control: &SimControl,
    entries: &[CaptureEntry],
) -> Vec<[u8; 32]> {
    let mut reader = storage.register().unwrap();
    let mut hits = Vec::new();
    for entry in entries {
        match lookup(&mut reader, &entry.key, 4) {
            Ok(lease) => {
                let delivered = read_back(volume, control, &lease);
                assert_eq!(delivered.status, ReadStatus::Complete);
                let n = (1..=u8::MAX)
                    .find(|&n| key(n) == entry.key)
                    .expect("a published key");
                assert_eq!(delivered.bytes, [&key(n)[..4], &[n; 40][..]].concat());
                hits.push(entry.key);
            }
            Err(LookupError::Missing) => {}
            Err(other) => panic!("{other:?}"),
        }
    }
    hits
}

/// The payload units of `store` that hold a written record: the units of S.
fn units_of(store: &Media) -> usize {
    let media = store.borrow();
    (16..media.len() / IO_UNIT)
        .filter(|unit| {
            media[unit * IO_UNIT..unit * IO_UNIT + 8]
                .iter()
                .any(|byte| *byte != 0)
        })
        .count()
}

/// The named slot's `unit` overwritten with that unit of a checkpoint of `entries` the predecessor encoded as its
/// capture 8: a delayed predecessor landing on the recovery evidence.
pub(crate) fn stale_landing(
    store: &Media,
    named: NamedCheckpoint,
    entries: &[CaptureEntry],
    unit: u32,
) {
    let earlier = Checkpoint {
        shard: shard(),
        session: predecessor_session().get(),
        capture: 8,
    };
    let units = encode(Crc32c::detect(), earlier, entries, layout().slot_units).unwrap();
    let prefix = (1 + named.slot as usize * layout().slot_units as usize + unit as usize) * IO_UNIT;
    store.borrow_mut()[prefix..prefix + IO_UNIT].copy_from_slice(&units[unit as usize][..]);
}

/// The entries of `entries` with their row on data unit `unit` of the slot: a slot of one-extent entries holds one row
/// per entry, [`UNIT_ENTRIES`](crate::failover::records::UNIT_ENTRIES) rows a data unit, in capture order.
fn on_unit(entries: &[CaptureEntry], unit: usize) -> Vec<[u8; 32]> {
    let per = crate::failover::records::UNIT_ENTRIES as usize;
    (entries.iter().skip((unit - 1) * per).take(per))
        .map(|entry| entry.key)
        .collect()
}

/// Records that the predecessor acknowledged an INVALIDATE of `key` at version 0 on its coverage page, fenced under
/// its session.
pub(crate) fn acknowledged_invalidation(records: &Shared, key: [u8; 32]) {
    use crate::storage::page_coverage::{Interval, Limits, merged, page_of};
    let record = restart_tests::shard_now(records);
    let interval = Interval::new(CacheVersion(0), CacheVersion(0)).unwrap();
    let limits = Limits {
        intervals: 4,
        page_bytes: record.page_cap.get() as usize,
    };
    let at = crate::storage::store::Key::Page(shard(), page_of(&key, record.pages));
    let mut client = client(records);
    let read = client
        .read::<crate::failover::records::CoveragePage>(at)
        .unwrap();
    let page = crate::failover::records::CoveragePage {
        fence: predecessor_session().get(),
        ..read.value().clone()
    };
    let page = merged(&page, (key, interval), limits).unwrap();
    client.replace(&read, page).unwrap();
}

/// P4: after host loss the named standby takes the same volume over by its compare-and-swap and loads the whole
/// recoverable set warm, with no device write and the record's manifest kept; an INVALIDATE the predecessor
/// acknowledged on a coverage page excludes its entry. A delayed predecessor landing on one data unit of the named
/// slot, applied at rest before the attach or while the successor's read of it is in flight, loses exactly the
/// entries with a row on that unit, the rest of S serving; the same landing on unit 0 loses nothing. The
/// total-eviction control, which refuses the whole load on any damage, ends the load `Unloadable(StaleWrite)` on
/// either arm and retains nothing of S.
#[test]
fn warm_takeover_on_the_same_volume_after_host_loss_retains_s_under_delayed_predecessor_landings() {
    let count = 50;
    let (store, entries, named, writer) = tenure_a(count);
    assert_eq!(named.units, 3, "unit 0 and two data units");
    let records = shard_store(named, false);
    let invalidated = entries[7].key;
    acknowledged_invalidation(&records, invalidated);
    let before = manifest(&records);
    let prefix = store.borrow()[..PREFIX as usize * IO_UNIT].to_vec();
    let mut card = Card::new(c_pair(), &a_holds_c_registered());
    takeover(
        &records,
        &store,
        (c_host(), &mut card, &stored_c()),
        |storage, volume, control| {
            load(volume, control);
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
            assert_eq!(submitted(control, Operation::Write).len(), 0);
            assert_eq!(
                volume.recovery_report().warm.omitted,
                1,
                "the invalidated entry is omitted"
            );
            assert!(units(storage).0 > writer.0, "its units are free");
            live(storage, volume);
            let served = hits(storage, volume, control, &entries);
            assert_eq!(
                served.len(),
                entries.len() - 1,
                "every other entry of S serves"
            );
            assert!(!served.contains(&invalidated));
            assert_eq!(
                store.borrow()[..PREFIX as usize * IO_UNIT],
                prefix[..],
                "the prefix is unchanged"
            );
        },
    );
    assert_eq!(
        manifest(&records),
        before,
        "the manifest survives the takeover"
    );
    let taken = restart_tests::shard_now(&records);
    assert_eq!(
        (taken.owner, taken.standby, taken.attempts),
        (c_host(), None, 5)
    );

    // A landing on data unit 2, at rest or in flight, and on unit 0, each under the reader and under the control.
    for (unit, in_flight, control_arm) in [
        (2, false, false),
        (2, true, false),
        (0, false, false),
        (2, false, true),
        (0, false, true),
    ] {
        let (store, entries, named, _) = tenure_a(count);
        let lost = on_unit(&entries, 2);
        assert!(!lost.is_empty() && lost.len() < entries.len());
        if !in_flight {
            stale_landing(&store, named, &entries, unit);
        }
        let records = shard_store(named, false);
        let mut card = Card::new(c_pair(), &a_holds_c_registered());
        PLANT.with(|plant| plant.set(control_arm.then_some(Plant::AllOrNothing)));
        let served = takeover(
            &records,
            &store,
            (c_host(), &mut card, &stored_c()),
            |storage, volume, control| {
                if in_flight {
                    // A tick runs the device before the volume's poll, so the poll that first submits slot reads leaves
                    // them unexecuted, and the landing reaches the media before any of them reads it.
                    for _ in 0..16 {
                        super::tests::tick(volume, control);
                        if !submitted(control, Operation::Read).is_empty() {
                            break;
                        }
                    }
                    assert!(
                        !submitted(control, Operation::Read).is_empty(),
                        "the reads are in flight"
                    );
                    assert_eq!(
                        control.delivered(Operation::Read),
                        0,
                        "no read has executed"
                    );
                    stale_landing(&store, named, &entries, unit);
                }
                load(volume, control);
                PLANT.with(|plant| plant.set(None));
                assert_eq!(submitted(control, Operation::Write).len(), 0);
                let outcome = volume.metadata_outcome();
                if outcome != MetadataOutcome::Open {
                    return (outcome, Vec::new());
                }
                live(storage, volume);
                (outcome, hits(storage, volume, control, &entries))
            },
        );
        PLANT.with(|plant| plant.set(None));
        let (outcome, served) = served;
        let arm = format!(
            "unit {unit}, in flight {in_flight}, control {control_arm}, outcome {outcome:?}"
        );
        let expected: Vec<[u8; 32]> = match (control_arm, unit) {
            (true, _) => Vec::new(),
            (false, 0) => entries.iter().map(|entry| entry.key).collect(),
            (false, _) => (entries.iter().map(|entry| entry.key))
                .filter(|key| !lost.contains(key))
                .collect(),
        };
        let (mut served, mut expected) = (served, expected);
        served.sort();
        expected.sort();
        if control_arm {
            assert_eq!(
                outcome,
                MetadataOutcome::Unloadable(LoadRefusal::StaleWrite),
                "{arm}: the total-eviction control refuses the whole load"
            );
        }
        assert_eq!(served, expected, "{arm}");
        if !control_arm {
            assert!(!served.is_empty(), "{arm}: the retained set is not empty");
        }
    }
}

/// P6: after a warm takeover reaches `Live`, every fill reservation until the payload is full takes units outside
/// the restored extents, so one owner holds each unit.
#[test]
fn fills_after_a_warm_takeover_never_reserve_a_restored_unit() {
    let (store, entries, named, _) = tenure_a(3);
    let records = shard_store(named, false);
    let mut card = Card::new(c_pair(), &a_holds_c_registered());
    takeover(
        &records,
        &store,
        (c_host(), &mut card, &stored_c()),
        |storage, volume, control| {
            load(volume, control);
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
            live(storage, volume);
            let held: Vec<(u64, u64)> = entries
                .iter()
                .map(|entry| {
                    let locator = super::ExtentLocator::from_bits(entry.extents[0]);
                    (
                        locator.start_unit(),
                        locator.start_unit() + u64::from(locator.len_units()),
                    )
                })
                .collect();
            let mut reservations = Vec::new();
            loop {
                let mut budget = super::super::super::budget::WorkBudget::new(1 << 20);
                match storage.reserve(Some(0), Some(100), &mut budget) {
                    Ok(reservation) => {
                        let locator = reservation.locator();
                        let (start, end) = (
                            locator.start_unit(),
                            locator.start_unit() + u64::from(locator.len_units()),
                        );
                        assert!(
                            !held.iter().any(|&(s, e)| s < end && start < e),
                            "a fill took a restored unit"
                        );
                        reservations.push(reservation);
                    }
                    Err(
                        ReserveError::PayloadFull
                        | ReserveError::ObjectSlotsFull
                        | ReserveError::CleanReserve,
                    ) => break,
                    Err(other) => panic!("{other:?}"),
                }
                assert!(reservations.len() < 64, "the payload fills");
            }
            assert!(!reservations.is_empty(), "fills open at Live");
            assert_eq!(
                hits(storage, volume, control, &entries).len(),
                entries.len(),
                "S serves beside the fills"
            );
        },
    );
}

/// P9: owner and standby loss leaves the volume active with its manifest, prefix and payload unchanged and no
/// retirement; the function outside the hosts names a new standby and its takeover loads S warm. A successor that
/// crashes after its compare-and-swap and before its preempt leaves the record naming it with no standby, the
/// predecessor's registration holding and the media unchanged; the predecessor's restart refuses `Deposed` with no
/// flip. A later named standby admits the predecessor's registration, whose tenure its write superseded through the
/// crashed successor's, preempts it and loads S warm with the manifest unchanged (SUPERSEDED-TENURE-PREEMPT). No arm
/// writes the device or RESETs.
#[test]
fn owner_and_standby_loss_and_a_successor_crash_before_preempt_keep_the_volume_and_load_warm_later()
{
    let (store, entries, named, writer) = tenure_a(3);
    let records = shard_store(named, true);
    let before = manifest(&records);
    let prefix = store.borrow()[..PREFIX as usize * IO_UNIT].to_vec();
    // Owner and standby lost: nothing ran on the volume. The function outside the hosts names B.
    designate(&records, Some(b_host()));
    assert_eq!(manifest(&records), before);
    assert_eq!(store.borrow()[..PREFIX as usize * IO_UNIT], prefix[..]);
    let reservation = a_holds_c_registered();
    reservation
        .borrow_mut()
        .entries
        .push(crate::failover::fresh::tests::registrant(
            b_pair(),
            3,
            false,
        ));
    let mut card = Card::new(b_pair(), &reservation);
    takeover(
        &records,
        &store,
        (b_host(), &mut card, &stored_b()),
        |storage, volume, control| {
            load(volume, control);
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
            assert_eq!(submitted(control, Operation::Write).len(), 0);
            assert_eq!(units(storage), writer);
            live(storage, volume);
            assert_eq!(
                hits(storage, volume, control, &entries).len(),
                entries.len()
            );
        },
    );
    assert_eq!(manifest(&records), before);

    // Successor C crashes after its compare-and-swap, before its preempt.
    let (store, entries, named, writer) = tenure_a(3);
    let records = shard_store(named, true);
    let prefix = store.borrow()[..PREFIX as usize * IO_UNIT].to_vec();
    let reservation = a_holds_c_registered();
    reservation
        .borrow_mut()
        .entries
        .push(crate::failover::fresh::tests::registrant(
            b_pair(),
            3,
            false,
        ));
    let mut card_c = Card::new(c_pair(), &reservation);
    card_c.stop_at = Some(3);
    let refused = takeover_of(&records, c_host())
        .run(&mut client(&records), &stored_c(), &mut card_c)
        .unwrap_err();
    assert!(matches!(
        refused.check,
        crate::failover::takeover::Check::FirstReport(_)
    ));
    let crashed = restart_tests::shard_now(&records);
    assert_eq!(
        (crashed.owner, crashed.standby, crashed.attempts),
        (c_host(), None, 5)
    );
    assert_eq!(
        manifest(&records),
        before,
        "the manifest survives the crash"
    );
    assert_eq!(store.borrow()[..PREFIX as usize * IO_UNIT], prefix[..]);
    let mut restarting = restart_tests::Card::new();
    restarting.entries = reservation.borrow().entries.clone();
    let refused = restart_tests::restart()
        .run(
            &mut client(&records),
            &restart_tests::sample(),
            &mut restarting,
        )
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.flip),
        (crate::failover::restart::Check::Deposed, None),
        "the predecessor's restart requests no replacement"
    );
    designate(&records, Some(b_host()));
    let mut card_b = Card::new(b_pair(), &reservation);
    takeover(
        &records,
        &store,
        (b_host(), &mut card_b, &stored_b()),
        |storage, volume, control| {
            load(volume, control);
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
            assert_eq!(submitted(control, Operation::Write).len(), 0);
            assert_eq!(units(storage), writer);
            live(storage, volume);
            assert_eq!(
                hits(storage, volume, control, &entries).len(),
                entries.len()
            );
        },
    );
    assert_eq!(
        card_b.log,
        restart_tests::FULL,
        "the named standby preempts the superseded holder"
    );
    let holders: Vec<_> = reservation
        .borrow()
        .entries
        .iter()
        .filter(|e| e.holder)
        .map(|e| e.pair)
        .collect();
    assert_eq!(holders, [b_pair()]);
    assert_eq!(
        manifest(&records),
        before,
        "the takeover keeps the manifest"
    );
    assert_eq!(
        store.borrow()[..PREFIX as usize * IO_UNIT],
        prefix[..],
        "no RESET, no prefix write"
    );
    assert_eq!(
        units_of(&store),
        entries.len(),
        "every payload unit of S holds its record"
    );
}

/// One second in nanoseconds.
const SECOND: u64 = 1_000_000_000;
/// True time at the cold tenure's monotonic zero, in nanoseconds after `TEST_EARLIEST`.
const START: u64 = 2000 * SECOND;
/// The fill's deadline on the cold tenure's monotonic clock: its tenth whole second.
const EXPIRES: u64 = 10 * SECOND + SECOND / 2;
/// The body of the object the cold tenure publishes under key 5.
const BODY: [u8; 40] = [0x5a; 40];
/// The body of the fill of key 6, whose publication is refused.
const OTHER: [u8; 40] = [0xa5; 40];

/// A trusted physical clock on the smeared scale whose every reading holds the true instant `truth`, in nanoseconds
/// after `TEST_EARLIEST`: its earliest bound lies `below` under it and its latest bound `above` over it.
fn wall(truth: u64, (below, above): (u64, u64)) -> Box<dyn PhysicalClock> {
    let (clock, script) = ScriptedClock::with_script();
    let at = TEST_EARLIEST + truth;
    script.trusted(at - below, at + above);
    clock
}

/// The checkpoint the bootstrap leaves at slot 0, which the stored record names.
fn named() -> NamedCheckpoint {
    NamedCheckpoint {
        slot: 0,
        session: predecessor_session().get(),
        capture: 0,
        units: 1,
    }
}

/// A fill's refusal: its reservation's or its publication's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FillRefused {
    Reserve(crate::storage::FillReserveError),
    Publish(crate::storage::FillPublishError),
}

/// Whether `filled` is the `History` refusal of a fill's publication, which a tenure that opened no suffix gives
/// a fill no record names.
pub(crate) fn refused_unrecorded(filled: &Result<(), FillRefused>) -> bool {
    *filled
        == Err(FillRefused::Publish(
            crate::storage::FillPublishError::History,
        ))
}

/// A fill of `k` with `body` and the deadline `expires`, driven to its publication; `Err` names the refusal.
fn fill<'s, 'a, D: crate::storage::device::Disk>(
    storage: &'s Storage<TestPlatform>,
    volume: &mut crate::storage::Volume<'s, 'a, TestPlatform, D>,
    control: &SimControl,
    k: &[u8; 32],
    body: &[u8],
    expires: u64,
) -> Result<(), FillRefused> {
    let mut fill = reserved(storage, k, body).map_err(FillRefused::Reserve)?;
    receive_all(&mut fill, volume, control, &payload(k, body), 4096);
    settle(volume, control);
    let published = fill.publish(volume, expires, TRIES, &mut budget());
    for shard in 0..2 {
        storage
            .service_fills(
                crate::index::ShardIndex(shard),
                8,
                &mut WorkBudget::new(1 << 20),
            )
            .unwrap();
    }
    published.map(drop).map_err(FillRefused::Publish)
}

/// The error a lookup of `held` on `storage` ends in, `None` for a hit and for a refused reader registration, then
/// the outcome of a fill of `filled` with `body` and no deadline, driven to its publication on `volume`.
pub(crate) fn fill_beside<'s, 'a, D: crate::storage::device::Disk>(
    storage: &'s Storage<TestPlatform>,
    volume: &mut crate::storage::Volume<'s, 'a, TestPlatform, D>,
    control: &SimControl,
    held: &[u8; 32],
    (filled, body): (&[u8; 32], &[u8]),
) -> (Option<LookupError>, Result<(), FillRefused>) {
    let looked = storage
        .register()
        .ok()
        .and_then(|mut reader| lookup(&mut reader, held, 4).err());
    let filled = fill(storage, volume, control, filled, body, u64::MAX);
    (looked, filled)
}

fn unrecorded_fill<'s>(
    storage: &'s Storage<TestPlatform>,
    volume: &mut Successor<'s, '_>,
    control: &SimControl,
) -> Option<LookupError> {
    let (looked, refused) = fill_beside(storage, volume, control, &key(5), (&key(6), &OTHER));
    assert!(
        matches!(looked, Some(LookupError::Missing | LookupError::Expired)),
        "premise: key 5's lookup ends Expired or Missing in the first restart's tenure, {looked:?}"
    );
    assert!(
        refused_unrecorded(&refused),
        "premise: with no suffix open the fill of key 6 is written and its publication refused, {refused:?}"
    );
    looked
}

/// The judgment after the second restart, whose load ended `Open`: the load restored key 5 alive, and at `Live` its
/// read delivers the object's exact bytes.
fn serves_exact_bytes<'s>(
    storage: &'s Storage<TestPlatform>,
    volume: &mut Successor<'s, '_>,
    control: &SimControl,
) {
    let mut reader = storage.register().unwrap();
    let lease =
        lookup(&mut reader, &key(5), 4).expect("the second restart's load restores key 5 alive");
    let delivered = read_back(volume, control, &lease);
    assert_eq!(
        (delivered.status, delivered.bytes),
        (ReadStatus::Complete, payload(&key(5), &BODY)),
        "key 5 delivers the object's exact bytes at Live after the second restart's load restored it alive"
    );
}

/// The cold tenure: it publishes key 5 with its deadline and every record lands. Returns the store double of its
/// record and the media.
/// The third tuple element is key 5's persisted portable deadline in nanoseconds after `TEST_EARLIEST`, the origin
/// of [`wall`]'s `truth`.
fn cold_tenure() -> (Shared, Media, u64) {
    let storage = storage(1);
    storage.platform.ticks(&[Some(1)]);
    let buffers = arena_with(4, 9);
    let store = media(MEDIA);
    let authority = crate::storage::ServingAuthority::fixture_under(predecessor_session());
    let (disk, control) = crate::storage::device::sim::sim_attached(
        config_for(7),
        std::rc::Rc::clone(&store),
        facts(BUFFER),
    );
    let mut volume = crate::storage::Volume::attach(
        &storage,
        &buffers,
        disk,
        wall(START + 1, (0, 0)),
        authority,
        DEPTH,
        TICK,
        &mut EngineBudget::new(1 << 25),
    )
    .map_err(|(error, _)| error)
    .expect("attach");
    bootstrap(&mut volume, &control);
    let mut dev = Device { volume, control };
    let session = predecessor_session().get();
    let limits = SuffixLimits {
        flush_ns: 0,
        queue_blocks: 8,
        oldest_ns: 1 << 40,
        uncertified: 16,
    };
    let own = Suffix {
        session,
        start: 0,
        certified: 0,
        end: 8,
    };
    let opened = storage
        .with_suffix(|log| log.open((Crc32c::detect(), shard()), (limits, &layout()), own, 0));
    assert_eq!(opened, Ok(true), "the cold tenure's suffix opens");
    fill(
        &storage,
        &mut dev.volume,
        &dev.control,
        &key(5),
        &BODY,
        EXPIRES,
    )
    .expect("the cold tenure publishes key 5");
    let mut rested = false;
    for _ in 0..256 {
        if storage.with_suffix(|log| log.idle()).unwrap_or(false)
            && dev.volume.metadata.delta.is_none()
        {
            rested = true;
            break;
        }
        tick(&mut dev.volume, &dev.control);
    }
    assert!(rested, "every record of the cold tenure lands");
    assert_eq!(dev.volume.metadata_outcome(), MetadataOutcome::Open);
    let recorded = {
        let live = storage.live_pool().unwrap();
        let capture = live.capture_membership_lock().unwrap();
        capture.suffix.recorded()
    };
    let predecessor = Suffix {
        session,
        start: 0,
        certified: recorded.certified,
        end: recorded.end,
    };
    let mut reader = storage.register().unwrap();
    let lease = lookup(&mut reader, &key(5), 4).expect("the cold tenure serves key 5");
    // `wall` adds `TEST_EARLIEST` to its `truth`. Subtracting that offset expresses the deadline on that scale.
    let deadline = pair_of(&storage, lease)
        .deadline_ns
        .checked_sub(TEST_EARLIEST)
        .expect("key 5's slot holds a portable pair");
    let media = dev.control.shared_media();
    let records = shard_store_with(named(), true, 4, (0, &[predecessor]));
    (records, media, deadline)
}

/// The owner restarts on its own record under the physical clock `clock`, its monotonic clock reading `mono`, and
/// loads warm. After a load that ends `Open` it reaches Live and runs `body`; any other load's outcome is the
/// error, and that tenure writes nothing.
fn restarted<R>(
    records: &Shared,
    store: &Media,
    (clock, mono): (Box<dyn PhysicalClock>, u64),
    body: impl for<'s> FnOnce(&'s Storage<TestPlatform>, &mut Successor<'s, '_>, &SimControl) -> R,
) -> Result<R, MetadataOutcome> {
    let mut card = restart_tests::Card::new();
    let taken = restart_tests::restart()
        .run(&mut client(records), &restart_tests::sample(), &mut card)
        .unwrap_or_else(|refused| panic!("the restart: {:?}", refused.check));
    assert!(taken.warm().is_some(), "the record names the checkpoint");
    let own = taken.fenced().own();
    let bounds = gate_fixture::bounds_of(gate_fixture::limits());
    let (authority, fencing) =
        crate::storage::ServingAuthority::restarted(bounds, Box::new(ZeroClock), taken);
    assert!(fencing.coverage().is_some(), "every page is fenced");
    let storage = storage(1);
    storage.platform.ticks(&[Some(mono)]);
    let buffers = gate_fixture::arena_with(4, 9);
    let (mut volume, control, _) =
        attach_successor_with(&storage, &buffers, store, (authority, own), clock);
    crate::storage::volume::helpers::PARK.with(|park| park.set(true));
    load(&mut volume, &control);
    let result = match volume.metadata_outcome() {
        MetadataOutcome::Open => {
            live(&storage, &mut volume);
            Ok(body(&storage, &mut volume, &control))
        }
        other => Err(other),
    };
    crate::storage::volume::helpers::PARK.with(|park| park.set(false));
    result
}

/// A cold tenure publishes key 5 with a deadline ten seconds ahead and every record lands; the owner then restarts
/// twice on its own record, both times before that deadline, with no fault and under trusted clocks of zero width.
/// The first load has 0.6 s of the object's life left at a sample 0.1 s into a monotonic second, so the rounded local
/// deadline falls in the sample's own second and the load reads the pair expired. That tenure opens no suffix: a fill
/// of key 6 writes its payload and its publication is refused, so no record names the write. The second load has
/// 0.5 s left at a sample 0.8 s into a second and reads the same pair alive. It restores key 5, which serves the
/// object's exact bytes at `Live`: an entry that one load reads expired and a later load reads alive keeps its units
/// through the tenure between them.
#[test]
fn an_entry_an_earlier_load_reads_expired_serves_its_exact_bytes_when_a_later_load_restores_it() {
    let (records, store, deadline) = cold_tenure();

    // The first restart: 0.6 s of life left, 0.1 s into a monotonic second. The load reads the pair expired.
    let first = (
        wall(deadline - 6 * SECOND / 10, (0, 0)),
        100 * SECOND + SECOND / 10,
    );
    let looked = restarted(&records, &store, first, unrecorded_fill)
        .expect("premise: the first restart's warm load ends Open");

    // The second restart: 0.5 s of life left, 0.8 s into a monotonic second.
    let second = (
        wall(deadline - 5 * SECOND / 10, (0, 0)),
        200 * SECOND + 8 * SECOND / 10,
    );
    let loaded = restarted(&records, &store, second, serves_exact_bytes);
    assert_eq!(loaded, Ok(()), "the second restart's warm load ends Open");
    assert_eq!(
        looked,
        Some(LookupError::Expired),
        "the first restart's load kept key 5 as an entry that reads expired"
    );
}

/// The same two restarts with the first load's monotonic sample past `u32::MAX` whole seconds, where no 32-bit second
/// names the sample. That load reads the pair expired, has no second to give its entry and refuses `Unrestorable`, so
/// its tenure writes nothing; the second load restores key 5, which serves the object's exact bytes at `Live`.
#[test]
fn an_entry_read_expired_at_a_sample_past_32_bits_of_seconds_serves_its_exact_bytes_when_a_later_load_restores_it()
 {
    let (records, store, deadline) = cold_tenure();

    // The first restart: 0.6 s of life left, 0.1 s into a monotonic second that 32 bits cannot name. The load reads
    // the pair expired and keeps its entry, which has no local second to take, so the load refuses.
    let past = (u64::from(u32::MAX) + 100) * SECOND + SECOND / 10;
    let first = (wall(deadline - 6 * SECOND / 10, (0, 0)), past);
    let loaded = restarted(&records, &store, first, |_, _, _| ());
    assert_eq!(
        loaded,
        Err(MetadataOutcome::Unloadable(LoadRefusal::Unrestorable)),
        "the first restart's warm load refuses"
    );

    // The second restart: 0.5 s of life left, 0.8 s into a monotonic second.
    let second = (
        wall(deadline - 5 * SECOND / 10, (0, 0)),
        200 * SECOND + 8 * SECOND / 10,
    );
    let loaded = restarted(&records, &store, second, serves_exact_bytes);
    assert_eq!(loaded, Ok(()), "the second restart's warm load ends Open");
}

/// The same two restarts with the first load reading the pair expired through its reading's width alone: 2 ms of the
/// object's life are left and the reading's latest bound lies 0.5 ms past the deadline, while the whole-second
/// rounding at that sample would keep the pair. The second load has 1 ms left under a reading of zero width, reads
/// the pair alive and restores key 5, which serves the object's exact bytes at `Live`.
#[test]
fn an_entry_read_expired_under_a_reading_whose_width_reaches_past_its_deadline_serves_its_exact_bytes_when_a_later_load_restores_it()
 {
    const MILLI: u64 = SECOND / 1000;
    let (records, store, deadline) = cold_tenure();

    // The first restart: 2 ms of life left, under a reading 3.5 ms wide whose latest bound lies 0.5 ms past the
    // deadline. Its monotonic sample lies 0.5 ms before a whole second, so the rounding alone would keep a
    // pair with 2 ms left.
    let wide = wall(deadline - 2 * MILLI, (MILLI, 5 * MILLI / 2));
    let first = (wide, 101 * SECOND - MILLI / 2);
    let looked = restarted(&records, &store, first, unrecorded_fill)
        .expect("premise: the first restart's warm load ends Open");

    // The second restart: 1 ms of life left, under a reading of zero width, 0.5 ms before a whole second.
    let second = (wall(deadline - MILLI, (0, 0)), 201 * SECOND - MILLI / 2);
    let loaded = restarted(&records, &store, second, serves_exact_bytes);
    assert_eq!(loaded, Ok(()), "the second restart's warm load ends Open");
    assert_eq!(
        looked,
        Some(LookupError::Expired),
        "the first restart's load kept key 5 as an entry that reads expired"
    );
}

/// Runs `body` at the transfer target C, `Live` on `media`: the owner A transfers the shard to its standby C over
/// the record its own bump committed, where `named` is the checkpoint the record names; C's restart takes the
/// lineage arm, preempts A's key, passes Report #2 and fences every coverage page, then attaches and loads warm to
/// `Live`.
fn at_the_live_transfer_target<R>(
    media: &Media,
    named: NamedCheckpoint,
    body: impl for<'s, 'a> FnOnce(&'s Storage<TestPlatform>, &mut Successor<'s, 'a>, &SimControl) -> R,
) -> R {
    use crate::failover::reconcile::StandbyGate;
    use crate::storage::Session;
    use crate::storage::store::{Key, Outgoing};
    let records = shard_store(named, false);
    let mut owner = client(&records);
    let read = owner.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    let session = Session::activate(owner.bump(&read).unwrap()).unwrap();
    let read = owner.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    owner
        .transfer(
            &StandbyGate::qualified(),
            &read,
            &Outgoing::of(&session),
            c_host(),
        )
        .expect("the transfer commits");
    let mut card = restart_tests::Card::new();
    card.entries = vec![restart_tests::holder(restart_tests::own(), 1)];
    let restarted = restart_tests::restart_of(
        shard(),
        crate::failover::takeover::tests::holder_of(c_host()),
    )
    .run(&mut client(&records), &stored_c(), &mut card)
    .expect("C's restart reaches its fencing boundary");
    assert!(restarted.lineage(), "C's restart took the lineage arm");
    assert_eq!(card.preempted, [restart_tests::own().key]);
    let bounds = super::super::gate_fixture::bounds_of(super::super::gate_fixture::limits());
    let (authority, fencing) =
        crate::storage::ServingAuthority::restarted(bounds, Box::new(ZeroClock), restarted);
    assert!(fencing.coverage().is_some(), "every page is fenced");
    let storage = storage(1);
    let buffers = super::super::gate_fixture::arena_with(4, 9);
    let (mut volume, control, _) = attach_successor(&storage, &buffers, media, authority, c_pair());
    PARK.with(|park| park.set(true));
    load(&mut volume, &control);
    live(&storage, &mut volume);
    let out = body(&storage, &mut volume, &control);
    PARK.with(|park| park.set(false));
    out
}

/// A write of the outgoing owner A that lands after the transfer target's fencing boundary. A transfers the shard to
/// its standby C over the record its own bump committed; C's restart takes the lineage arm, preempts A's key, passes
/// Report #2 and fences every coverage page, then attaches and loads warm to `Live`. Only then does A's held write
/// land on C's media: the payload unit of one retained object takes the checked bytes A wrote for another object.
/// The landed object's read runs and its header check refuses the unit before any byte is delivered, and every other
/// retained object serves its own bytes.
#[test]
fn a_predecessor_write_landing_after_the_transfer_target_s_fence_reads_as_a_miss() {
    let count = 50;
    let (store, entries, named, _) = tenure_a(count);
    at_the_live_transfer_target(&store, named, |storage, volume, control| {
        let (landed, source) = (&entries[3], &entries[11]);
        let (to, from) = (payload_unit(landed) as usize, payload_unit(source) as usize);
        let stale = store.borrow()[from * IO_UNIT..(from + 1) * IO_UNIT].to_vec();
        assert_ne!(
            store.borrow()[to * IO_UNIT..(to + 1) * IO_UNIT],
            stale[..],
            "the landing changes the unit"
        );
        store.borrow_mut()[to * IO_UNIT..(to + 1) * IO_UNIT].copy_from_slice(&stale);
        let mut reader = storage.register().unwrap();
        let n_of = |entry: &CaptureEntry| (1..=u8::MAX).find(|&n| key(n) == entry.key).unwrap();
        let own_bytes = |n: u8| [&key(n)[..4], &[n; 40][..]].concat();
        let mut landed_status = None;
        for entry in &entries {
            let n = n_of(entry);
            let lease = match lookup(&mut reader, &entry.key, 4) {
                Ok(lease) => lease,
                Err(LookupError::Missing) if entry.key == landed.key => continue,
                Err(other) => panic!("{n}: {other:?}"),
            };
            let delivered = read_back(volume, control, &lease);
            if entry.key == landed.key {
                // The landed object is one unit, so its header check runs before any byte is delivered.
                landed_status = Some(delivered.status);
                assert!(
                    delivered.bytes.is_empty(),
                    "no byte of the landed unit surfaces: {:?}",
                    delivered.bytes
                );
            } else {
                assert_eq!(delivered.status, ReadStatus::Complete, "{n}");
                assert_eq!(delivered.bytes, own_bytes(n), "{n}: its own bytes");
            }
        }
        assert!(
            matches!(landed_status, Some(ReadStatus::HeaderMismatch(_))),
            "the landed object was read and its header check refused the other object's unit: {landed_status:?}"
        );
    });
}

/// When the held write of [`a_write_the_owner_issued_before_its_withdrawal`] lands at the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lands {
    /// While the target holds the unit free, before the target's own fill takes it.
    OnAFreeUnit,
    /// After the target's own fill took the unit and published its object there.
    OverTheTargetsFill,
    /// Never: the target's fill attempt lands a second time in its place, the sibling with no foreign write.
    OwnAgain,
}

/// The object of the target's own fill, which no object of A names.
const TARGETS: u8 = 60;
/// The object A replaced with a write it never acknowledged.
const REPLACED: u8 = 3;

/// A write the outgoing owner A issued before its withdrawal that the device holds and lands after the target's
/// fencing boundary: A publishes twelve objects and captures them, then issues the write of a replacement of
/// one object, which no record of the certified cut names. The write is held: the unit keeps its earlier bytes
/// through the transfer. C's restart takes the lineage arm, preempts A's key, fences coverage and loads warm to
/// `Live`, opens its suffix and publishes an object of its own, whose fill takes the unit A's write names. A's
/// recorded attempt then lands at its own address as `lands` says. Returns each read that failed its rule: a
/// retained object delivers its own bytes, the replaced object the bytes of the cut and never the replacement's,
/// and the target's object its own bytes, or, once A's write lies over it, no byte and a header refusal.
fn a_write_the_owner_issued_before_its_withdrawal(lands: Lands) -> Vec<String> {
    let old = |n: u8| [&key(n)[..4], &[n; 40][..]].concat();
    let (a, replacement) = tenure_replacing(
        predecessor_session(),
        12,
        old,
        Some((REPLACED, [&key(REPLACED)[..4], &[0xee; 40][..]].concat())),
    );
    let unit = replacement_unit(&replacement.expect("the replacement's record"));
    let at = unit as usize * IO_UNIT;
    let held = (a.attempts.iter())
        .rfind(|attempt| attempt.covers(u64::from(unit)))
        .expect("A's device recorded the replacement's write")
        .clone();
    assert_eq!(
        (held.start, held.bytes.len()),
        (at as u64, IO_UNIT),
        "the held attempt is the one unit of the replacement"
    );
    // The device holds the write: the unit keeps the bytes it held before A issued it.
    a.media.borrow_mut()[at..at + IO_UNIT].fill(0);
    let media = a.media.clone();
    at_the_live_transfer_target(&media, a.named, |storage, volume, control| {
        let mut failures = Vec::new();
        if lands == Lands::OnAFreeUnit {
            held.land(&media);
        }
        let own = Suffix {
            session: volume.authority.session().get(),
            start: 0,
            certified: 0,
            end: 8,
        };
        let limits = SuffixLimits {
            flush_ns: 0,
            queue_blocks: 8,
            oldest_ns: 1 << 40,
            uncertified: 16,
        };
        let opened = storage
            .with_suffix(|log| log.open((Crc32c::detect(), shard()), (limits, &layout()), own, 0));
        assert_eq!(opened, Ok(true), "the target's suffix opens");
        control.record_attempts();
        fill(
            storage,
            volume,
            control,
            &key(TARGETS),
            &[TARGETS; 40],
            u64::MAX,
        )
        .expect("the target publishes its own object");
        let own_attempt = (control.attempts().into_iter())
            .find(|attempt| attempt.covers(u64::from(unit)))
            .expect("premise: the target's fill takes the unit A's held write names");
        assert_ne!(own_attempt.bytes, held.bytes);
        match lands {
            Lands::OnAFreeUnit => {}
            Lands::OverTheTargetsFill => held.land(&media),
            Lands::OwnAgain => own_attempt.land(&media),
        }
        let mut reader = storage.register().unwrap();
        for entry in &a.entries {
            let n = (1..=u8::MAX).find(|&n| key(n) == entry.key).unwrap();
            match lookup(&mut reader, &entry.key, 4) {
                Ok(lease) => {
                    let delivered = read_back(volume, control, &lease);
                    if (delivered.status, &delivered.bytes) != (ReadStatus::Complete, &old(n)) {
                        failures.push(format!(
                            "object {n} of the cut read {:?} with {:?}",
                            delivered.status, delivered.bytes
                        ));
                    }
                }
                Err(other) => failures.push(format!("object {n} of the cut: {other:?}")),
            }
        }
        let lease = lookup(&mut reader, &key(TARGETS), 4).expect("the target's object is indexed");
        let delivered = read_back(volume, control, &lease);
        let covered = lands == Lands::OverTheTargetsFill;
        let refused = matches!(delivered.status, ReadStatus::HeaderMismatch(_));
        let own_bytes = [&key(TARGETS)[..4], &[TARGETS; 40][..]].concat();
        let ruled = match covered {
            true => refused && delivered.bytes.is_empty(),
            false => delivered.status == ReadStatus::Complete && delivered.bytes == own_bytes,
        };
        if !ruled {
            failures.push(format!(
                "the target's object read {:?} with {:?}",
                delivered.status, delivered.bytes
            ));
        }
        failures
    })
}

/// `NoPredecessorEffectAfterFB` for the transfer target, for a write the predecessor issued before its withdrawal
/// that the device holds and lands after the target's fencing boundary: the write lands at its own address as A's device recorded it. Landing on a
/// unit the target holds free, it changes nothing the target serves, and the target's later fill of that unit
/// serves its own bytes. Landing over the target's published fill, it makes that object's read refuse at the
/// header check before any byte is delivered, and every object of the cut keeps its own bytes: the replacement A
/// never acknowledged is served under no key. The sibling that lands the target's own attempt again serves it.
#[test]
fn a_write_the_owner_issued_before_its_withdrawal_lands_after_the_target_s_fence_as_a_miss_or_no_change()
 {
    for lands in [
        Lands::OnAFreeUnit,
        Lands::OverTheTargetsFill,
        Lands::OwnAgain,
    ] {
        let failures = a_write_the_owner_issued_before_its_withdrawal(lands);
        assert!(failures.is_empty(), "{lands:?}: {failures:#?}");
    }
}

/// A panic inside `inline` leaves the inline-recovery flag at its value before the call, false here, and a flag that
/// was already set stays set after a normal return.
#[test]
fn the_warm_bootstrap_restores_the_inline_flag_on_unwind() {
    let flag = || crate::storage::INLINE_RECOVERY.with(std::cell::Cell::get);
    let before = crate::storage::INLINE_RECOVERY.with(|cell| cell.replace(false));
    assert!(inline(flag), "the body runs with the flag set");
    assert!(!flag(), "a normal return restores the cleared flag");
    let inside = std::cell::Cell::new(false);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        inline(|| {
            inside.set(flag());
            panic!("a bootstrap tick panics")
        })
    }));
    assert!(unwound.is_err());
    assert!(inside.get(), "the panicking body ran with the flag set");
    assert!(!flag());
    crate::storage::INLINE_RECOVERY.with(|cell| cell.set(true));
    assert!(inline(flag));
    assert!(flag());
    crate::storage::INLINE_RECOVERY.with(|cell| cell.set(before));
}

/// After a warm tenure takes a generation-1 session ahead of the thread's fixture sequence, the next fixture session
/// is strictly above it; a session at a later generation leaves the sequence where it stood.
#[test]
fn a_fixture_attach_after_a_warm_tenure_takes_a_higher_session() {
    let _restarted = crate::storage::restart_sessions();
    let first = crate::storage::next_session().get();
    let warm = session_at(1, 3);
    assert!(crate::storage::upcoming_session() <= warm.get());
    warm.continue_fixture_sequence();
    let cold = crate::storage::next_session().get();
    assert!(
        first < warm.get() && warm.get() < cold,
        "{first} {warm:?} {cold}"
    );
    let upcoming = crate::storage::upcoming_session();
    session_at(2, 0).continue_fixture_sequence();
    session_at(1, 1).continue_fixture_sequence();
    assert_eq!(crate::storage::upcoming_session(), upcoming);
    let jump = session_at(1, 1 << 20);
    jump.continue_fixture_sequence();
    assert!(crate::storage::upcoming_session() > jump.get());
    session_at(1, crate::failover::records::ATTEMPTS_MAX - 1).continue_fixture_sequence();
}

/// `warm_device` continues the calling thread's fixture sequence above a session 4096 attempts ahead of it and draws
/// no fixture session on the way, so an attach costs the same however far ahead its session lies. The record names no
/// checkpoint, so `warm_device` returns `None` once the sequence has moved.
#[test]
fn warm_device_continues_the_fixture_sequence_without_drawing_a_session() {
    let _restarted = crate::storage::restart_sessions();
    let storage = storage(1);
    let buffers = arena_with(4, 9);
    let store = media(MEDIA);
    let record = crate::storage::store_tests::record();
    let far = session_at(1, 1 << 12);
    let ahead = far.get();
    assert!(crate::storage::upcoming_session() < ahead);
    let drawn = crate::storage::Session::fixture_draws();
    let attached = warm_device(
        &storage,
        &buffers,
        &store,
        (&record, layout(), far),
        None,
        None,
    );
    assert!(attached.is_none(), "the record names no checkpoint");
    assert_eq!(
        crate::storage::Session::fixture_draws(),
        drawn,
        "the warm attach drew a fixture session"
    );
    assert!(crate::storage::upcoming_session() > ahead);
}
