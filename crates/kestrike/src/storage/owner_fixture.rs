//! A simulated storage stack for network-owner tests: an indexed storage whose objects span several fragments, a buffer arena with read-response buffers for each request slot, an attached volume over a seeded simulated disk, and published objects.

use super::AllocationId;
use super::SlotState;
use super::StorageCharges;
use super::StorageConfig;
use super::completed::Completed;
use super::device::sim::Event;
use super::device::{BufferArena, CommandToken, Operation};
use super::layout::IO_UNIT;
use super::owner::Storage;
use super::publish_tests::{TRIES, budget, index_config, storage_config, storage_from};
use super::record::{Crc32c, ExtentPosition, RecordIdentity, encode_header, framing};
use super::remove::{InvalidateError, Invalidation};
use super::volume_fixture::arena_with;
pub(crate) use super::writable::INTERPOSE_BEFORE_REVALIDATION;
pub(crate) use super::writable_tests::{reserve, reserve_at, try_reserve_at};
use crate::index::IndexConfig;
use crate::index::Key;
use crate::index::{Bucket, Identity};

pub(crate) use super::device::sim::{Fault, QuiesceMode, SimControl, SimDisk, Unwind};
pub(crate) use super::evict::Commit;
pub(crate) use super::extent::work_bound;
pub(crate) use super::sequence_read_tests::{LAST as SEQUENCE_LAST, Plant};
pub(crate) use super::test_platform::TestPlatform;
pub(crate) use super::volume_fixture::{
    BUFFER, DEPTH, Device, MEDIA, SESSION, TICK, attach_shaped, device_with, open_polled,
    read_back, writes,
};

/// A storage of eight slots with four read operation records, whose objects hold up to three buffers of body and 64 bytes of metadata, each with up to `object_rights` rights.
pub(crate) fn storage(object_rights: usize) -> Storage<TestPlatform> {
    storage_with(object_rights, CHUNK_LEN)
}

/// Record chunk length of [`storage`].
pub(crate) const CHUNK_LEN: u32 = 8192;

/// Body cap of [`storage`]'s objects: three read buffers.
pub(crate) const BODY_CAP: u32 = 3 * BUFFER;

/// [`storage`] whose volume reads one command ahead: a read may hold a second command outstanding, from its first command on.
pub(crate) fn storage_reading_ahead(object_rights: usize) -> Storage<TestPlatform> {
    storage_reading_ahead_by(object_rights, 1)
}

/// [`storage`] whose volume reads `read_ahead` commands ahead of a read's current one.
pub(crate) fn storage_reading_ahead_by(
    object_rights: usize,
    read_ahead: u8,
) -> Storage<TestPlatform> {
    storage_configured(object_rights, 8192, read_ahead)
}

/// [`storage`] with a record chunk of `chunk_len` bytes.
fn storage_with(object_rights: usize, chunk_len: u32) -> Storage<TestPlatform> {
    storage_configured(object_rights, chunk_len, 0)
}

fn storage_configured(
    object_rights: usize,
    chunk_len: u32,
    read_ahead: u8,
) -> Storage<TestPlatform> {
    storage_shaped(object_rights, chunk_len, read_ahead, 64)
}

/// [`storage`] whose objects carry up to `metadata_cap` metadata bytes.
pub(crate) fn storage_with_metadata(metadata_cap: usize) -> Storage<TestPlatform> {
    storage_shaped(8, 8192, 0, metadata_cap)
}

/// [`storage_with_metadata`] over 512 units with one sequence arena root,
/// so an object whose metadata spans several extents is placed as a
/// sequence.
pub(crate) fn sequence_storage_with_metadata(metadata_cap: usize) -> Storage<TestPlatform> {
    sequence_storage_shaped(
        metadata_cap,
        Shape {
            units: 512,
            slots: 8,
        },
    )
}

/// As [`sequence_storage_with_metadata`], with the volume's units and slots
/// set by `shape`.
pub(crate) fn sequence_storage_shaped(metadata_cap: usize, shape: Shape) -> Storage<TestPlatform> {
    let config = sequence_config(metadata_cap, shape);
    indexed(&config, super::publish_tests::BATCH_MAX, shape.slots)
}

/// A storage over `shape` with one sequence arena root whose objects carry
/// up to `body_cap` body bytes and 64 bytes of metadata, so an object whose
/// body spans several extents is placed as a sequence. Its watermarks are
/// [`floor_marks`] of the largest such object.
pub(crate) fn sequence_storage_with_body(body_cap: usize, shape: Shape) -> Storage<TestPlatform> {
    let mut config = sequence_config(64, shape);
    config.body_cap = body_cap;
    config.volume.maintenance = None;
    let largest = largest_charge(&config);
    config.volume.maintenance = Some(floor_marks(&config, PUTS, largest));
    indexed(&config, super::publish_tests::BATCH_MAX, shape.slots)
}

/// [`sequence_storage_with_body`] whose one index shard keeps `fills` fill records, so the volume holds two receive-write buffers for each.
pub(crate) fn sequence_storage_filling(
    body_cap: usize,
    shape: Shape,
    fills: usize,
) -> Storage<TestPlatform> {
    let mut config = sequence_config(64, shape);
    config.body_cap = body_cap;
    config.volume.maintenance = None;
    let largest = largest_charge(&config);
    config.volume.maintenance = Some(floor_marks(&config, PUTS, largest));
    sharded(
        &config,
        super::publish_tests::BATCH_MAX,
        &[shape.slots],
        &[fills],
    )
}

fn sequence_config(metadata_cap: usize, shape: Shape) -> StorageConfig {
    let mut config = sized_config((8, CHUNK_LEN, 0, metadata_cap), 4, shape);
    config.volume.block_roots = 1;
    config
}

/// [`sequence_storage_shaped`] over two index shards that split the slots evenly and keep `fills` fill records each, so one shard's records can run out while the other's stay free.
pub(crate) fn two_shard_sequence_storage(
    metadata_cap: usize,
    shape: Shape,
    fills: usize,
) -> Storage<TestPlatform> {
    let config = sequence_config(metadata_cap, shape);
    sharded(
        &config,
        super::publish_tests::BATCH_MAX,
        &[shape.slots / 2; 2],
        &[fills; 2],
    )
}

fn storage_shaped(
    object_rights: usize,
    chunk_len: u32,
    read_ahead: u8,
    metadata_cap: usize,
) -> Storage<TestPlatform> {
    storage_sized(
        (object_rights, chunk_len, read_ahead, metadata_cap),
        super::publish_tests::BATCH_MAX,
        4,
        FIXTURE,
    )
}

/// A storage's volume units and object slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Shape {
    pub(crate) units: usize,
    pub(crate) slots: usize,
}

/// The shape of [`storage`]: 128 units and eight slots.
pub(crate) const FIXTURE: Shape = Shape {
    units: 128,
    slots: 8,
};

/// [`storage`] over `shape`'s units and slots with records chunked every
/// `chunk_len` bytes.
pub(crate) fn storage_shaped_as(shape: Shape, chunk_len: u32) -> Storage<TestPlatform> {
    storage_sized(
        (8, chunk_len, 0, 64),
        super::publish_tests::BATCH_MAX,
        4,
        shape,
    )
}

/// [`storage_shaped_as`] whose recovery limits admit a warm attach: a warm read holds `checkpoint::WINDOWS` live jobs
/// plus one job per destination, so `volume.recovery.jobs` is `WINDOWS + 2`, which covers the fixture's one destination
/// and one more job, and `volume.recovery.adopt` lets one tick receive the terminals of that many jobs.
pub(crate) fn storage_warm_as(shape: Shape, chunk_len: u32) -> Storage<TestPlatform> {
    let mut config = sized_config((8, chunk_len, 0, 64), 4, shape);
    let jobs = (super::checkpoint::WINDOWS + 2) as u32;
    (config.volume.recovery.jobs, config.volume.recovery.adopt) = (jobs, jobs);
    indexed(&config, super::publish_tests::BATCH_MAX, shape.slots)
}

/// [`storage_shaped_as`] whose volume keeps one read command, so a read
/// that holds it leaves every other read of the volume waiting.
pub(crate) fn storage_reading_one_command(shape: Shape, chunk_len: u32) -> Storage<TestPlatform> {
    let mut config = sized_config((8, chunk_len, 0, 64), 4, shape);
    config.volume.read_commands = 1;
    indexed(&config, super::publish_tests::BATCH_MAX, shape.slots)
}

/// [`storage`] whose index admits batches of `batch_max` keys and whose
/// volume keeps `read_ops` read operation records and
/// `min(read_ops, DEPTH - 2)` read commands, so at least two of the fixture
/// device's `DEPTH` queue slots stay with writes.
pub(crate) fn storage_windowed(batch_max: usize, read_ops: u32) -> Storage<TestPlatform> {
    storage_sized((8, 8192, 0, 64), batch_max, read_ops, FIXTURE)
}

fn storage_sized(
    object: (usize, u32, u8, usize),
    batch_max: usize,
    read_ops: u32,
    shape: Shape,
) -> Storage<TestPlatform> {
    indexed(
        &sized_config(object, read_ops, shape),
        batch_max,
        shape.slots,
    )
}

pub(crate) fn storage_leasing(lease_limit: usize) -> Storage<TestPlatform> {
    let config = StorageConfig {
        lease_limit,
        ..sized_config((8, CHUNK_LEN, 0, 64), 4, FIXTURE)
    };
    indexed(&config, super::publish_tests::BATCH_MAX, FIXTURE.slots)
}

fn sized_config(
    (object_rights, chunk_len, read_ahead, metadata_cap): (usize, u32, u8, usize),
    read_ops: u32,
    shape: Shape,
) -> StorageConfig {
    let mut volume = crate::storage::test_volume(shape.units * super::IO_UNIT, shape.slots);
    volume.read_ops = read_ops;
    // Two queue slots stay with writes, one for each peer's PUT; the one metadata slot comes out of the read share.
    volume.read_commands = read_ops.min(u32::from(DEPTH) - 2) - 1;
    volume.read_ahead = read_ahead;
    volume.record = super::record::RecordConfig { chunk_len };
    let mut config = StorageConfig {
        body_cap: BODY_CAP as usize,
        metadata_cap: Some(metadata_cap),
        object_rights,
        volume,
        ..storage_config(shape.slots)
    };
    let largest = largest_charge(&config);
    config.volume.maintenance = Some(floor_marks(&config, PUTS, largest));
    config
}

/// The PUTs the default fixtures cover: their `low_units` is the structural
/// floor of this many promises, [`storage`]'s index grants this many fill
/// records, and the owner tests' `OWNER.put.puts` equals it.
pub(crate) const PUTS: u32 = 2;

/// Watermarks for `config` whose retired allowance `T` is `retired_units`
/// and whose `low_units` is the structural floor of `puts` PUTs;
/// `min_free_slots` is one.
///
/// # Panics
///
/// If `config` with those watermarks fails validation, or the floor is
/// undefined.
pub(crate) fn floor_marks(
    config: &StorageConfig,
    puts: u32,
    retired_units: u64,
) -> super::VolumeWatermarks {
    let mut probe = *config;
    probe.volume.maintenance = None;
    let mut marks = super::VolumeWatermarks {
        low_units: probe
            .validate()
            .expect("a valid configuration")
            .placeable_ceiling(),
        min_free_slots: 1,
        retired_units,
    };
    probe.volume.maintenance = Some(marks);
    marks.low_units = probe
        .validate()
        .expect("a valid configuration")
        .structural_floor(puts)
        .expect("a floor within the payload units");
    marks
}

/// The charged units of `config`'s largest object, record headers and padding included, as validation computes them.
pub(crate) fn largest_charge(config: &StorageConfig) -> u64 {
    config
        .validate()
        .expect("a valid configuration")
        .largest_geometry()
        .total_units()
}

/// [`storage`] over `units` units whose clean reserve `reserve` derives from the charged units of the largest object; `T` is that charge and `low_units` the structural floor of [`PUTS`] PUTs.
pub(crate) fn storage_marked(
    units: usize,
    reserve: impl FnOnce(u64) -> u64,
) -> Storage<TestPlatform> {
    let shape = Shape { units, ..FIXTURE };
    let mut config = sized_config((8, CHUNK_LEN, 0, 64), 4, shape);
    let largest = largest_charge(&config);
    config.volume.reserve_units = reserve(largest);
    config.volume.maintenance = Some(floor_marks(&config, PUTS, largest));
    indexed(&config, super::publish_tests::BATCH_MAX, shape.slots)
}

/// The default watermarks use the largest object's validated charge and the structural floor for [`PUTS`] PUTs; returning `None` disables watermark maintenance.
pub(crate) fn storage_watched(
    marks: impl FnOnce(super::VolumeWatermarks) -> Option<super::VolumeWatermarks>,
) -> Storage<TestPlatform> {
    let mut config = sized_config((8, CHUNK_LEN, 0, 64), 4, FIXTURE);
    config.volume.maintenance = config.volume.maintenance.and_then(marks);
    indexed(&config, super::publish_tests::BATCH_MAX, FIXTURE.slots)
}

/// The engine charges of [`storage`]'s configuration, and that storage
/// initialized with its engine budget at `engine` bytes, ticked as
/// [`storage`] ticks.
pub(crate) fn storage_budgeted(
    engine: impl FnOnce(StorageCharges) -> usize,
) -> (
    StorageCharges,
    Result<Storage<TestPlatform>, super::InitFailure>,
) {
    let mut config = sized_config((8, CHUNK_LEN, 0, 64), 4, FIXTURE);
    let (fill_records, shards) = ([PUTS as usize], [FIXTURE.slots]);
    let index = IndexConfig {
        fills: &fill_records,
        batch_max: super::publish_tests::BATCH_MAX,
        ..index_config(&shards, (1, 1), 1)
    };
    let validated = config.validate().unwrap();
    let geometry = index.validate(&validated).unwrap();
    let charges = StorageCharges::of(&validated, Some(&geometry)).unwrap();
    config.engine_budget = engine(charges);
    let validated = config.validate().unwrap();
    let geometry = index.validate(&validated).unwrap();
    let placement = super::PlacementConfig { control_home: 0 };
    let platform = TestPlatform::heap(super::publish_tests::PAGE);
    let storage = Storage::initialize_indexed(&validated, geometry, &placement, platform);
    (charges, storage.map(ticked))
}

/// [`storage_windowed`] at the fixture's batch size whose one index shard
/// keeps `fills` fill records, so that many fills of distinct keys are in
/// progress at once.
pub(crate) fn storage_filling(read_ops: u32, fills: usize) -> Storage<TestPlatform> {
    let config = sized_config((8, CHUNK_LEN, 0, 64), read_ops, FIXTURE);
    sharded(
        &config,
        super::publish_tests::BATCH_MAX,
        &[FIXTURE.slots],
        &[fills],
    )
}

/// [`storage_filling`] at `read_ops` read records whose index keeps a fill record for each of `puts` PUTs and whose
/// `low_units` is the structural floor of `puts` promises, for an owner whose PUT cap passes [`PUTS`].
pub(crate) fn storage_for_puts(read_ops: u32, puts: u32) -> Storage<TestPlatform> {
    let mut config = sized_config((8, CHUNK_LEN, 0, 64), read_ops, FIXTURE);
    let largest = largest_charge(&config);
    config.volume.maintenance = Some(floor_marks(&config, puts, largest));
    sharded(
        &config,
        super::publish_tests::BATCH_MAX,
        &[FIXTURE.slots],
        &[puts as usize],
    )
}

fn indexed(config: &StorageConfig, batch_max: usize, slots: usize) -> Storage<TestPlatform> {
    sharded(config, batch_max, &[slots], &[PUTS as usize])
}

/// A storage over `config` whose index shard `s` holds `slots[s]` slots and
/// `fills[s]` fill records, its clock reading tick 1.
fn sharded(
    config: &StorageConfig,
    batch_max: usize,
    slots: &[usize],
    fills: &[usize],
) -> Storage<TestPlatform> {
    let index = IndexConfig {
        fills,
        batch_max,
        ..index_config(slots, (1, 1), 1)
    };
    storage_from_configs(config, &index)
}

pub(crate) fn unindexed(slot_count: usize) -> Storage<TestPlatform> {
    let validated = super::publish_tests::storage_config(slot_count)
        .validate()
        .unwrap();
    let placement = super::PlacementConfig { control_home: 0 };
    let platform = TestPlatform::heap(super::publish_tests::PAGE);
    Storage::initialize(&validated, &placement, platform).unwrap()
}

/// A storage over heap memory built from `config` and `index`, its clock always reading tick 1, for a test that derives every limit itself.
///
/// # Panics
///
/// If either configuration fails validation or the storage fails to initialize.
pub(crate) fn storage_from_configs(
    config: &StorageConfig,
    index: &IndexConfig<'_>,
) -> Storage<TestPlatform> {
    ticked(storage_from(
        config,
        index,
        TestPlatform::heap(super::publish_tests::PAGE),
    ))
}

/// An arena of `read` read-response buffers and four receive-write buffers.
pub(crate) fn arena(read: u32) -> BufferArena<TestPlatform> {
    arena_with(read, 4)
}

/// Publishes `payload` under `key`, its first `metadata` bytes as metadata, through `device`, dropping the publisher's lease.
pub(crate) fn publish<'s>(
    storage: &'s Storage<TestPlatform>,
    device: &mut Device<'s, '_>,
    key: &Key,
    metadata: usize,
    payload: &[u8],
) {
    publish_until(storage, device, key, metadata, payload, u64::MAX);
}

pub(crate) fn publish_until<'s>(
    storage: &'s Storage<TestPlatform>,
    device: &mut Device<'s, '_>,
    key: &Key,
    metadata: usize,
    payload: &[u8],
    deadline: u64,
) {
    let mut fill = reserve(storage, key, metadata, payload.len() - metadata).expect("a fill");
    device.fill(&mut fill, payload);
    let lease = fill
        .publish(&mut device.volume, deadline, TRIES, &mut budget())
        .expect("published");
    drop(lease);
    device.persist_journal();
}

pub(crate) fn expiry_cursor(storage: &Storage<TestPlatform>) -> usize {
    let live = storage.live_pool().unwrap();
    let mut access = live.lock().unwrap();
    access.tables().state.cursor_expiry
}

pub(crate) fn residents(storage: &Storage<TestPlatform>) -> usize {
    storage
        .pool_report()
        .unwrap()
        .ledger
        .unwrap()
        .slots
        .resident
}

/// Publishes under `key` an object of `count` extents through `device`:
/// a fill of its last [`SEQUENCE_LAST`] bytes, so the index names the
/// object, then the extents before it placed and every extent's record
/// written by the fixture, `plant` writing one extent differently. Returns
/// the object's payload, metadata first.
pub(crate) fn publish_sequence<'s>(
    storage: &'s Storage<TestPlatform>,
    device: &mut Device<'s, '_>,
    key: &Key,
    count: u32,
    metadata: usize,
    plant: Option<Plant>,
) -> Vec<u8> {
    let mut fill = reserve(storage, key, metadata, SEQUENCE_LAST - metadata).expect("a fill");
    device.fill(&mut fill, &[0; SEQUENCE_LAST]);
    let lease = fill
        .publish(&mut device.volume, u64::MAX, TRIES, &mut budget())
        .expect("published");
    let id = lease.id();
    drop(lease);
    super::sequence_read_tests::plant_sequence(
        storage,
        &device.control,
        id,
        *key,
        count,
        metadata,
        plant,
    )
}

pub(crate) fn set_clock(storage: &Storage<TestPlatform>, samples: &[Option<u64>]) {
    storage.platform.ticks(samples);
}

/// Holds shard 0's gate until the guard drops, so its next try refuses `Contended`.
pub(crate) fn hold_shard(storage: &Storage<TestPlatform>) -> impl Drop + '_ {
    super::attempt_tests::gate(storage).try_lock().unwrap()
}

/// Poisons shard 0's gate, as an unwinding holder would.
pub(crate) fn poison_shard(storage: &Storage<TestPlatform>) {
    super::attempt_tests::gate(storage)
        .try_lock()
        .unwrap()
        .poison();
}

pub(crate) fn poison_pool(storage: &Storage<TestPlatform>) {
    let live = storage.live_pool().unwrap();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = live.try_lock().unwrap();
        panic!("a holder panicked");
    }));
}

pub(crate) fn with_pool_held<R>(storage: &Storage<TestPlatform>, during: impl FnOnce() -> R) -> R {
    let held = storage.live_pool().unwrap().try_lock().unwrap();
    let out = during();
    held.release();
    out
}

/// Leaves one payload unit reserved in the extent allocator, recorded in no
/// slot, and returns whether it did: `false` when the storage is past its
/// `Live` phase, the pool gate is held or poisoned, or the allocator
/// refuses.
pub(crate) fn leak_unit(storage: &Storage<TestPlatform>) -> bool {
    let Some(live) = storage.live_pool() else {
        return false;
    };
    let Ok(mut access) = live.try_lock_quiet() else {
        return false;
    };
    let limit = live.image.extent_bound;
    let leaked = access
        .tables()
        .extents()
        .reserve(1, 0, limit, &mut budget())
        .is_ok();
    access.release();
    leaked
}

/// Panics when the storage is past `Live` or the pool gate is held.
pub(crate) fn edit_tables<R>(
    storage: &Storage<TestPlatform>,
    edit: impl FnOnce(&mut super::tables::Tables<'_>) -> R,
) -> R {
    let live = storage.live_pool().expect("a live pool");
    let mut access = live.try_lock_quiet().expect("a free pool gate");
    let out = edit(&mut access.tables());
    access.release();
    out
}

pub(crate) fn with_maintenance_held<R>(
    storage: &Storage<TestPlatform>,
    during: impl FnOnce() -> R,
) -> R {
    let _held = storage.maintain.gate.try_lock().unwrap();
    during()
}

/// Poisons the root's maintenance gate, as an unwinding maintenance call would.
pub(crate) fn poison_maintenance(storage: &Storage<TestPlatform>) {
    storage.maintenance_gate().try_lock().unwrap().poison();
}

pub(crate) fn cut_next_publication() {
    super::publication::CUT.with(|cut| cut.set(Some(super::publication::Cut::AfterEvenPreSettle)));
}

pub(crate) fn arena_sized(read: u32, read_len: u32) -> BufferArena<TestPlatform> {
    super::volume_fixture::arena_sized(read, read_len, 4)
}

/// Clock samples `storage`'s platform has handed out so far.
pub(crate) fn samples_taken(storage: &Storage<TestPlatform>) -> usize {
    storage.platform.samples_taken()
}

pub(crate) fn last_sample(storage: &Storage<TestPlatform>) -> Option<u64> {
    storage.platform.last_sample()
}

/// Invalidates `key`'s object.
pub(crate) fn invalidate(
    storage: &Storage<TestPlatform>,
    key: &Key,
) -> Result<Invalidation, InvalidateError> {
    super::attempt_tests::invalidate(storage, key)
}

/// The token of the last read command the device accepted, if any.
pub(crate) fn last_read(control: &SimControl) -> Option<CommandToken> {
    control.events().iter().rev().find_map(|event| match event {
        Event::Submitted(token, Operation::Read) => Some(*token),
        _ => None,
    })
}

/// Write tokens the device accepted, in submission order.
pub(crate) fn write_tokens(control: &SimControl) -> Vec<CommandToken> {
    control
        .events()
        .iter()
        .filter_map(|event| match event {
            Event::Submitted(token, Operation::Write) => Some(*token),
            _ => None,
        })
        .collect()
}

/// Write tokens the device accepted at or past byte `from`, in submission order: with `from` the payload's first byte, the payload writes alone.
pub(crate) fn writes_from(control: &SimControl, from: u64) -> Vec<CommandToken> {
    control
        .capture()
        .events
        .iter()
        .filter_map(|event| match *event {
            super::device::sim::Captured::Submitted {
                token,
                operation: Operation::Write,
                device,
                ..
            } if device.start() >= from => Some(token),
            _ => None,
        })
        .collect()
}

pub(crate) fn read_tokens(control: &SimControl) -> Vec<CommandToken> {
    control
        .events()
        .iter()
        .filter_map(|event| match event {
            Event::Submitted(token, Operation::Read) => Some(*token),
            _ => None,
        })
        .collect()
}

/// A storage like [`storage`] whose record chunk is `chunk_len` bytes, and an arena of `read` read-response buffers of `read_len` bytes.
pub(crate) fn narrow(
    chunk_len: u32,
    read: u32,
    read_len: u32,
) -> (Storage<TestPlatform>, BufferArena<TestPlatform>) {
    (
        storage_with(8, chunk_len),
        super::volume_fixture::arena_sized(read, read_len, 4),
    )
}

/// A storage like [`storage`] over 768 units and four slots whose largest
/// object has three extents, the shape [`publish_sequence`] plants into.
pub(crate) fn sequence_storage() -> Storage<TestPlatform> {
    let units = 768;
    let slots = 4;
    let (fill_records, shards) = ([PUTS as usize], [slots]);
    let index = IndexConfig {
        fills: &fill_records,
        batch_max: super::publish_tests::BATCH_MAX,
        ..index_config(&shards, (1, 1), 1)
    };
    let mut volume = crate::storage::test_volume(units * super::IO_UNIT, slots);
    volume.alloc_search_words = super::extent::work_bound(units as u64, 4, 64);
    volume.block_roots = 1;
    volume.read_ops = 4;
    volume.read_commands = 4u32.min(u32::from(DEPTH) - 3);
    volume.record = super::record::RecordConfig {
        chunk_len: CHUNK_LEN,
    };
    let mut config = StorageConfig {
        engine_budget: 1 << 26,
        body_cap: 2 * super::geometry::EXTENT_PAYLOAD as usize + SEQUENCE_LAST,
        metadata_cap: Some(40),
        lease_limit: 8,
        object_rights: 8,
        volume,
        ..storage_config(slots)
    };
    // The floor of `PUTS` PUTs lies below the units a three-extent object
    // leaves free, so no GET triggers a reclaim.
    let largest = largest_charge(&config);
    config.volume.maintenance = Some(floor_marks(&config, PUTS, largest));
    let storage = storage_from(
        &config,
        &index,
        TestPlatform::heap(super::publish_tests::PAGE),
    );
    storage.platform.ticks(&[Some(1)]);
    storage
}

/// A storage like [`storage`] whose keys share one hash chain, so a forged fingerprint makes a lookup find another key's object.
pub(crate) fn one_chain_storage() -> Storage<TestPlatform> {
    let mut storage = storage(8);
    super::publish_tests::install_seam(&mut storage, super::publish_tests::one_chain);
    storage
}

/// Gives `owner`'s published object the fingerprint of `stranger`, so a lookup of `stranger` finds it and its read ends with a key mismatch.
pub(crate) fn forge(storage: &Storage<TestPlatform>, owner: &Key, stranger: &Key) {
    let mut reader = storage.register().expect("a registration");
    let lease = reader
        .lookup(owner, TRIES, &mut budget())
        .expect("the owner's object");
    let slot = lease.id().slot_index();
    drop(lease);
    drop(reader);
    let fingerprint = storage.route(stranger).expect("a route").fingerprint();
    storage.live_pool().expect("a live pool").records()[slot].set_fingerprint(fingerprint);
}

/// Replaces slot `slot`'s identity word with `word` and returns the word it
/// held, for a test that plants a binding to a slot holding nothing and
/// restores it.
pub(crate) fn swap_ident(storage: &Storage<TestPlatform>, slot: usize, word: u64) -> u64 {
    let records = storage.live_pool().expect("a live pool").records();
    records[slot]
        .ident
        .swap(word, std::sync::atomic::Ordering::AcqRel)
}

/// `set_state` preserves the slot's incarnation, flags and count so tests
/// can plant a binding to a retired slot.
pub(crate) fn set_state(storage: &Storage<TestPlatform>, slot: usize, state: SlotState) {
    storage
        .live_pool()
        .expect("a live pool")
        .set_state(slot, state);
}

/// Moves slot `holder` to `Filling` over the direct extent slot `of` holds,
/// so two slots hold one extent while every index binding stays as it was.
/// The caller passes an `of` that holds a direct locator.
pub(crate) fn hold_extent_of(storage: &Storage<TestPlatform>, holder: usize, of: usize) {
    let live = storage.live_pool().expect("a live pool");
    let records = live.records();
    records[holder].set_locator(records[of].locator());
    live.set_state(holder, SlotState::Filling);
}

/// Clears `ABANDONED` from slot `slot`'s word.
pub(crate) fn clear_abandoned(storage: &Storage<TestPlatform>, slot: usize) {
    let live = storage.live_pool().expect("a live pool");
    live.edit_word(slot, |held| held & !super::word::ABANDONED);
}

pub(crate) fn with_duplicate_binding<R>(
    storage: &Storage<TestPlatform>,
    key: &Key,
    planted: impl FnOnce() -> R,
) -> R {
    let (bucket, _) = key_bucket(storage, key);
    let identity = bucket.identities().next().expect("a bound bucket");
    with_planted(bucket, identity, planted)
}

pub(crate) fn with_shadow_binding<R>(
    storage: &Storage<TestPlatform>,
    key: &Key,
    id: AllocationId,
    planted: impl FnOnce() -> R,
) -> R {
    let (bucket, tag) = key_bucket(storage, key);
    with_planted(bucket, Identity::new(tag, id), planted)
}

fn key_bucket<'s>(storage: &'s Storage<TestPlatform>, key: &Key) -> (&'s Bucket, u16) {
    let route = storage.route(key).expect("a route");
    let index = storage.index().expect("an index");
    let shard = index.image.shard(route.shard()).expect("a shard");
    // SAFETY: the index mapping is owned and initialized while the storage is live, which `index` checked.
    let bucket = &unsafe { shard.buckets(&index.mapping) }[route.bucket()];
    (bucket, route.tag())
}

fn with_planted<R>(bucket: &Bucket, identity: Identity, planted: impl FnOnce() -> R) -> R {
    let pair = bucket.plant(identity).expect("an unfilled bucket");
    let result = planted();
    bucket.clear(pair);
    result
}

pub(crate) fn shadow_resident<'s>(
    storage: &'s Storage<TestPlatform>,
    control: &SimControl,
    key: &Key,
    payload: &[u8],
    session: u64,
) -> Completed<'s, TestPlatform> {
    let mut allocation = storage
        .reserve(Some(0), Some(payload.len()), &mut budget())
        .expect("a reservation");
    allocation.mark_written();
    let Ok(completed) = allocation.complete_under(
        *key,
        u64::MAX,
        super::tables::Naming {
            session,
            version: 0,
        },
        &mut budget(),
    ) else {
        panic!("a completed owner");
    };
    let id = completed.id();
    let bytes = super::volume_fixture::record_bytes(storage, *key, id, session, &[], payload);
    let locator = storage.live_pool().expect("a live pool").records()[id.slot_index()].locator();
    control.write_device(super::volume_fixture::device_byte(storage, locator), &bytes);
    set_refs(storage, id.slot_index(), 1);
    completed
}

pub(crate) fn set_refs(storage: &Storage<TestPlatform>, slot: usize, refs: usize) {
    storage
        .live_pool()
        .expect("a live pool")
        .set_refs(slot, refs);
}

/// Rewrites `key`'s record header with `session`, its first `metadata`
/// payload bytes framed as metadata and the rest as body, and recomputed
/// checksums, while preserving its key, allocation, payload length and
/// payload bytes.
pub(crate) fn reseal(
    storage: &Storage<TestPlatform>,
    control: &SimControl,
    key: &Key,
    session: u64,
    metadata: u32,
) {
    let mut reader = storage.register().expect("a registration");
    let lease = reader
        .lookup(key, TRIES, &mut budget())
        .expect("the key's object");
    let id = lease.id();
    drop(lease);
    drop(reader);
    let locator = storage.live_pool().expect("a live pool").records()[id.slot_index()].locator();
    let start = super::volume_fixture::device_byte(storage, locator);
    let mut bytes = control.device(start, locator.len_units() as usize * IO_UNIT);
    let (_, _, was_metadata, was_body) = framing(&bytes).expect("a framed record");
    let layout = storage
        .record
        .layout(metadata, was_metadata + was_body - metadata);
    let version = storage.live_pool().expect("a live pool").versions()[id.slot_index()]
        .load(std::sync::atomic::Ordering::Relaxed);
    let identity = RecordIdentity {
        key: *key,
        allocation: id.record_tag(),
        session,
        version,
    };
    encode_header(
        Crc32c::detect(),
        &layout,
        &identity,
        ExtentPosition::FIRST,
        &mut bytes,
    )
    .expect("encodes");
    control.write_device(start, &bytes[..layout.header_bytes()]);
}

/// Reads `key`'s object through `device` and keeps its first verified chunk, which holds one read-response buffer while it lives.
pub(crate) fn held_chunk<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    device: &mut Device<'s, 'a>,
    key: &Key,
) -> super::ValidatedChunk<'a> {
    let mut reader = storage.register().expect("a registration");
    let lease = reader
        .lookup(key, TRIES, &mut budget())
        .expect("the object");
    let op = device.volume.read(lease, u64::MAX).expect("a read");
    let mut out = Vec::with_capacity(16);
    let mut held = None;
    for _ in 0..64 {
        super::volume_fixture::step(&mut device.volume, &device.control, &mut out);
        for event in out.drain(..) {
            match event {
                super::ReadEvent::Chunk { op: of, chunk, .. } if of == op && held.is_none() => {
                    held = Some(chunk)
                }
                _ => {}
            }
        }
    }
    held.expect("a chunk")
}

/// A storage over `platform` whose one index shard holds `keys` visible keys, so a test can fill the index before the volume.
fn storage_keyed(
    platform: TestPlatform,
    (payload_bytes, metadata_units): (usize, u64),
    body_cap: usize,
    metadata_cap: usize,
    (keys, lease_limit): (usize, usize),
) -> Storage<TestPlatform> {
    let (fill_records, limits) = ([4], [keys]);
    let index = IndexConfig {
        fills: &fill_records,
        ..index_config(&limits, (1, 1), 1)
    };
    let mut volume = crate::storage::test_volume_with(payload_bytes, metadata_units, 8);
    volume.read_ops = 4;
    volume.read_commands = 4;
    let mut config = StorageConfig {
        body_cap,
        metadata_cap: Some(metadata_cap),
        lease_limit,
        volume,
        ..storage_config(8)
    };
    let largest = largest_charge(&config);
    // A retired allowance of two largest charges holds the versions a key
    // refilled in place retires before service returns them.
    config.volume.maintenance = Some(floor_marks(&config, PUTS, 2 * largest));
    ticked(storage_from(&config, &index, platform))
}

pub(crate) fn heap_storage_on(payload_bytes: usize, body_cap: usize) -> Storage<TestPlatform> {
    heap_storage_with_metadata_on(payload_bytes, body_cap, 64)
}

/// `storage_over` uses [`heap_storage_on`]'s configuration with a supplied
/// platform so tests can inspect its log or arm failures before construction.
pub(crate) fn storage_over(
    platform: TestPlatform,
    payload_bytes: usize,
    body_cap: usize,
) -> Storage<TestPlatform> {
    let limits = (8, storage_config(8).lease_limit);
    storage_keyed(
        platform,
        (payload_bytes, crate::storage::TEST_METADATA_UNITS),
        body_cap,
        64,
        limits,
    )
}

/// The metadata prefix of a storage a hardware test attaches over an EBS volume: two root slots and six more blocks of the 16 KiB atomic unit the EBS profile derives.
pub(crate) const HARDWARE_METADATA_UNITS: u64 = 32;

/// The EBS profile's atomic unit in bytes.
pub(crate) const HARDWARE_UNIT: u32 = 16384;

/// [`heap_storage_with_metadata_on`] whose metadata prefix is [`HARDWARE_METADATA_UNITS`] long, for a test that attaches an EBS volume.
pub(crate) fn hardware_storage_on(
    payload_bytes: usize,
    body_cap: usize,
    metadata_cap: usize,
) -> Storage<TestPlatform> {
    let platform = TestPlatform::heap(super::publish_tests::PAGE);
    let limits = (8, storage_config(8).lease_limit);
    storage_keyed(
        platform,
        (payload_bytes, HARDWARE_METADATA_UNITS),
        body_cap,
        metadata_cap,
        limits,
    )
}

pub(crate) fn heap_storage_with_metadata_on(
    payload_bytes: usize,
    body_cap: usize,
    metadata_cap: usize,
) -> Storage<TestPlatform> {
    let platform = TestPlatform::heap(super::publish_tests::PAGE);
    let limits = (8, storage_config(8).lease_limit);
    storage_keyed(
        platform,
        (payload_bytes, crate::storage::TEST_METADATA_UNITS),
        body_cap,
        metadata_cap,
        limits,
    )
}

pub(crate) fn heap_storage_limited_on(
    payload_bytes: usize,
    body_cap: usize,
    keys: usize,
    lease_limit: usize,
) -> Storage<TestPlatform> {
    let platform = TestPlatform::heap(super::publish_tests::PAGE);
    storage_keyed(
        platform,
        (payload_bytes, crate::storage::TEST_METADATA_UNITS),
        body_cap,
        64,
        (keys, lease_limit),
    )
}

/// `storage` with its clock reading tick 1 from now on.
fn ticked(storage: Storage<TestPlatform>) -> Storage<TestPlatform> {
    storage.platform.ticks(&[Some(1)]);
    storage
}

pub(crate) fn arena_on<P: super::os::Platform>(
    platform: P,
    read: u32,
    receive: u32,
) -> BufferArena<P> {
    super::volume_fixture::pools_on(platform, (read, BUFFER), (receive, BUFFER), HARDWARE_UNIT)
}

/// Registration records of `storage`, each of which a certification pass visits.
pub(crate) fn registration_records(storage: &Storage<TestPlatform>) -> usize {
    storage.registrations().len()
}

/// Whether the allocator's bitmap holds every unit of `units`, a first unit and a count, free, read under one pool hold.
pub(crate) fn units_free(storage: &Storage<TestPlatform>, (start, len): (u64, u32)) -> bool {
    let pool = storage.live_pool().expect("a live storage");
    let mut access = pool.lock().expect("the pool gate");
    let free = access.tables().extents().free_set();
    access.release();
    let end = start + u64::from(len);
    free.iter().any(|&(at, run)| at <= start && end <= at + run)
}

/// The units the one-extent member `id` holds: its extent's first unit and its unit count, read under one pool hold.
pub(crate) fn held_units(storage: &Storage<TestPlatform>, id: AllocationId) -> (u64, u32) {
    let pool = storage.live_pool().expect("a live storage");
    let mut access = pool.lock().expect("the pool gate");
    let locator = access.tables().held_locator(id.slot_index());
    access.release();
    (locator.start_unit(), locator.len_units())
}
