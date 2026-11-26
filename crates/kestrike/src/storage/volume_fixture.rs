//! A simulated device and an attached volume for storage tests: a small buffer arena, a volume over a seeded simulated disk, and helpers that stream a record through `receive`, drive writes to their terminals, place a record on the device directly and read an object back through `Volume::read`.

use std::ops::Range;

use super::allocation::AllocationId;
use super::budget::WorkBudget;
use super::device::identify_fixture::{EBS, Fields, facts_sized};
use super::device::sim::{
    Media, Mode, SimConfig, SimControl, SimDisk, StatusForm, media, sim_attached,
};
use super::device::{
    AttachFacts, BufferArena, BufferConfig, IO_UNIT, Operation, PoolKind, PoolSpec, TransferLimits,
};
use super::extent::ExtentLocator;
use super::lease::ExtentLease;
use super::ledger::EngineBudget;
use super::os::HugepageSize;
use super::owner::Storage;
use super::placement::NodeMask;
use super::portable::PhysicalClock;
use super::portable::scripted::ScriptedClock;
use super::record::{Crc32c, ExtentPosition, RecordIdentity, encode_header};
use super::recovery::MetadataOutcome;
use super::test_platform::TestPlatform;
use super::volume::{ReadEvent, ReadOp, ReadStatus, TickConfig, VerifiedReadInfo, Volume};
use super::writable::WritableFill;
use crate::sim::round::{Act, Actor, round};

/// The session of the first fixture authority a thread draws after its sequence starts or restarts; each later
/// fixture authority on the thread holds a higher session, which a test reads from its volume's `session()`.
pub(crate) const SESSION: u64 = (1 << 32) | 2;

pub(crate) fn fixture_format(drawn: &mut [u8; 16]) -> Result<(), crate::entropy::EntropyError> {
    *drawn = [
        0, 0, 0, 0, 0, 0, 0, 0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8,
    ];
    Ok(())
}

/// Receive-write and read-response buffer length.
pub(crate) const BUFFER: u32 = 16384;
/// Command table depth.
pub(crate) const DEPTH: u16 = 8;

pub(crate) const TICK: TickConfig = TickConfig {
    submit_burst: 8,
    terminal_burst: 8,
    validate_bytes: 1 << 20,
};

pub(crate) type TestVolume<'s, 'a> = Volume<'s, 'a, TestPlatform, SimDisk>;

/// The command allowance exceeds the budget required by each fixture write.
pub(crate) fn ample_io() -> WorkBudget {
    WorkBudget::with_io(0, usize::MAX, usize::MAX)
}

/// An arena of `read` read-response and `receive` receive-write buffers of [`BUFFER`] bytes.
pub(crate) fn arena_with(read: u32, receive: u32) -> BufferArena<TestPlatform> {
    arena_sized(read, BUFFER, receive)
}

/// An arena of `read` read-response buffers of `read_len` bytes, `receive` receive-write buffers of [`BUFFER`] bytes and one maintenance buffer of [`unit`] bytes.
pub(crate) fn arena_sized(read: u32, read_len: u32, receive: u32) -> BufferArena<TestPlatform> {
    arena_sized_on(TestPlatform::heap(4096), read, read_len, receive)
}

/// [`arena_sized`] over `platform`, with a maintenance buffer of [`unit`] bytes.
pub(crate) fn arena_sized_on<P: super::os::Platform>(
    platform: P,
    read: u32,
    read_len: u32,
    receive: u32,
) -> BufferArena<P> {
    pools_on(platform, (read, read_len), (receive, BUFFER), unit())
}

/// An arena of four read-response and four receive-write buffers of
/// `max(BUFFER, chunk_len)` bytes and one 4096-byte maintenance buffer. A
/// volume whose records chunk every `chunk_len` bytes passes attach's
/// buffer-divisibility check when `chunk_len` divides [`BUFFER`] or
/// exceeds it, so each receive-write buffer holds whole chunks.
pub(crate) fn arena_for_chunk(chunk_len: u32) -> BufferArena<TestPlatform> {
    let len = BUFFER.max(chunk_len);
    pools_on(TestPlatform::heap(4096), (4, len), (4, len), 4096)
}

pub(crate) fn pools_on<P: super::os::Platform>(
    platform: P,
    read: (u32, u32),
    receive: (u32, u32),
    maintenance_len: u32,
) -> BufferArena<P> {
    pools_with(platform, read, receive, maintenance_len, 0)
}

pub(crate) fn pools_with<P: super::os::Platform>(
    platform: P,
    (read, read_len): (u32, u32),
    (receive, receive_len): (u32, u32),
    maintenance_len: u32,
    reservation: u32,
) -> BufferArena<P> {
    let mut pools = vec![
        PoolSpec {
            kind: PoolKind::ReadResponse,
            count: read,
            buffer_len: read_len,
        },
        PoolSpec {
            kind: PoolKind::ReceiveWrite,
            count: receive,
            buffer_len: receive_len,
        },
        PoolSpec {
            kind: PoolKind::Maintenance,
            count: 1,
            buffer_len: maintenance_len,
        },
    ];
    if reservation > 0 {
        pools.push(PoolSpec {
            kind: PoolKind::Reservation,
            count: reservation,
            buffer_len: 4096,
        });
    }
    let validated = BufferConfig {
        hugepage: HugepageSize::TwoMiB,
        nodes: NodeMask::from_nodes(&[0]).expect("node 0"),
        pools: &pools,
    }
    .validate()
    .expect("valid");
    BufferArena::initialize(&validated, platform, &mut EngineBudget::new(usize::MAX))
        .expect("arena")
}

pub(crate) fn arena() -> BufferArena<TestPlatform> {
    arena_with(4, 4)
}

/// A simulated disk of 4 MiB over fresh media whose maximum transfer is `max_transfer`, reporting [`facts`].
pub(crate) fn device_with(seed: u64, max_transfer: u32) -> (SimDisk, SimControl) {
    attached(config(seed, max_transfer))
}

/// A simulated disk built from `config` over fresh media, reporting the [`facts_for`] its capacity and largest transfer.
pub(crate) fn attached(config: SimConfig) -> (SimDisk, SimControl) {
    let facts = facts_for(config.capacity, config.max_transfer);
    sim_attached(config, media(config.capacity), facts)
}

/// [`facts_for`] a device of [`MEDIA`] bytes.
pub(crate) fn facts(max_transfer: u32) -> AttachFacts {
    facts_for(MEDIA, max_transfer)
}

/// The attach facts of a `capacity`-byte device with 512-byte sectors, a device-wide atomic unit of [`unit`] bytes and a `max_transfer`-byte command limit.
pub(crate) fn facts_for(capacity: u64, max_transfer: u32) -> AttachFacts {
    let fields = Fields {
        awupf: u16::try_from(unit() / 512 - 1).expect("a unit of at most BUFFER bytes"),
        nsfeat: 0,
        nawupf: 0,
        nabo: 0,
        nabspf: 0,
        vendor: None,
        limits: TransferLimits {
            namespace_max: max_transfer,
            boundary: 0,
            command: max_transfer,
        },
        ..EBS
    };
    facts_sized(fields, capacity / 512)
}

thread_local! {
    /// The device unit a [`Unit`] guard holds on the calling thread, in bytes; `None` while no guard is held.
    static UNIT: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
}

/// A guard over the calling thread's device unit: [`Unit::hold`] sets the unit [`unit`] returns, and dropping the
/// guard, on return or unwind, returns the thread to the 4096-byte default.
#[must_use = "the unit returns to 4096 once the guard drops"]
pub(crate) struct Unit(std::marker::PhantomData<*const ()>);

impl Unit {
    /// Sets the calling thread's device unit to `bytes`, a power of two from 4096 to [`BUFFER`].
    ///
    /// # Panics
    ///
    /// When `bytes` is outside that range, or when the thread already holds a guard, whatever its unit.
    pub(crate) fn hold(bytes: u32) -> Self {
        assert!(bytes.is_power_of_two() && (4096..=BUFFER).contains(&bytes));
        assert_eq!(UNIT.get(), None, "the device unit is held once");
        UNIT.set(Some(bytes));
        Self(std::marker::PhantomData)
    }
}

impl Drop for Unit {
    fn drop(&mut self) {
        UNIT.set(None);
    }
}

/// The calling thread's device unit in bytes: the atomic unit [`facts_for`] reports and the maintenance buffer
/// length [`arena_sized_on`] gives. It is the held [`Unit`]'s, or 4096 while the thread holds none.
pub(crate) fn unit() -> u32 {
    UNIT.get().unwrap_or(4096)
}

/// Polls `volume`, over a driver whose commands progress on its own polls, until both RESET roots are persisted, formatting a volume whose root slots both decode invalid.
///
/// # Panics
///
/// When the bootstrap refuses or stays unfinished for `polls` polls.
pub(crate) fn open_polled<P: super::os::Platform, D: super::device::Disk>(
    volume: &mut Volume<'_, '_, P, D>,
    polls: usize,
) {
    let mut out = Vec::with_capacity(16);
    open_stepping(
        volume,
        |ticks| ticks < polls,
        |volume| {
            let _ = volume.poll_storage(0, &mut out);
            out.clear();
        },
    );
}

/// [`open_polled`] with the device advanced by `step` after each bootstrap tick, while `more`, given the ticks so
/// far, allows another tick.
///
/// # Panics
///
/// If the bootstrap refuses, or `more(ticks)` returns `false` before this function observes
/// `MetadataOutcome::Open`.
pub(crate) fn open_stepping<'s, 'a, P: super::os::Platform, D: super::device::Disk>(
    volume: &mut Volume<'s, 'a, P, D>,
    mut more: impl FnMut(usize) -> bool,
    mut step: impl FnMut(&mut Volume<'s, 'a, P, D>),
) {
    let mut ticks = 0;
    loop {
        match volume.metadata_outcome() {
            MetadataOutcome::Open => {
                let feed = volume.storage().feed;
                let begun = volume.begin_replay(feed, 0);
                assert_eq!(
                    volume.readiness(),
                    super::readiness::State::Live,
                    "{begun:?}"
                );
                return;
            }
            MetadataOutcome::Unformatted => volume.format().expect("a disposable volume formats"),
            MetadataOutcome::Bootstrapping => {}
            outcome => panic!("the bootstrap ended {outcome:?}"),
        }
        assert!(
            more(ticks),
            "the bootstrap stayed unfinished for {ticks} polls"
        );
        step(volume);
        ticks += 1;
    }
}

pub(crate) fn close_and_release<'s, 'a, P: super::os::Platform, D: super::device::Disk>(
    mut volume: Volume<'s, 'a, P, D>,
    mut more: impl FnMut(usize) -> bool,
    mut step: impl FnMut(&mut Volume<'s, 'a, P, D>),
) -> (super::Quiesced, D) {
    let mut ticks = 0;
    let quiesced = loop {
        if let super::QuiesceProgress::Quiesced(quiesced) = volume.close() {
            break quiesced;
        }
        assert!(
            more(ticks),
            "the volume stayed unquiesced for {ticks} polls"
        );
        step(&mut volume);
        ticks += 1;
    };
    let (_proof, disk) = volume
        .release_driver()
        .map_err(|_| "quiesced")
        .expect("released");
    (quiesced, disk)
}

/// Tests use [`JUMP`] to schedule a clock change between readings.
pub(crate) struct ServingTime(pub(crate) std::rc::Rc<std::cell::Cell<u64>>);

thread_local! {
    /// `Some((reads, to))` makes [`ServingTime`] set its clock to `to` on reading `reads + 1`.
    pub(crate) static JUMP: std::cell::Cell<Option<(u32, u64)>> = const { std::cell::Cell::new(None) };
}

impl super::ServingClock for ServingTime {
    fn now_us(&self) -> Option<u64> {
        match JUMP.get() {
            Some((0, to)) => {
                JUMP.set(None);
                self.0.set(to);
            }
            Some((reads, to)) => JUMP.set(Some((reads - 1, to))),
            None => {}
        }
        Some(self.0.get())
    }
}

/// Ticks `volume`'s bootstrap until both RESET roots are persisted, formatting the media when both root slots decode invalid, then rebases `control` so its counts, log and capture start after the bootstrap.
///
/// # Panics
///
/// When the bootstrap refuses or stays unfinished after 64 rounds; the outcome is read once more after the last.
pub(crate) fn bootstrap(volume: &mut TestVolume<'_, '_>, control: &SimControl) {
    let mut out = Vec::with_capacity(16);
    for round in 0..=ROUNDS {
        match volume.metadata_outcome() {
            MetadataOutcome::Open => {
                let feed = volume.storage().feed;
                let begun = volume.begin_replay(feed, 0);
                assert_eq!(
                    volume.readiness(),
                    super::readiness::State::Live,
                    "{begun:?}"
                );
                control.rebase();
                return;
            }
            MetadataOutcome::Unformatted => volume
                .format_from(fixture_format)
                .expect("fresh media formats"),
            MetadataOutcome::Bootstrapping => {}
            outcome => panic!("the bootstrap ended {outcome:?}\n{}", control.describe()),
        }
        if round == ROUNDS {
            break;
        }
        // Outside the controller's rounds, so a test's generated schedule orders the same rounds with or without the bootstrap before them.
        control.tick(64);
        let _ = volume.poll_storage(0, &mut out);
        out.clear();
    }
    panic!("the bootstrap never opened\n{}", control.describe());
}

/// The device rounds a bootstrap or a probe ticks before it reports an unfinished attach.
const ROUNDS: u32 = 64;

pub(crate) fn config_for(seed: u64) -> SimConfig {
    config(seed, BUFFER)
}

fn config(seed: u64, max_transfer: u32) -> SimConfig {
    SimConfig {
        seed,
        capacity: MEDIA,
        queue_depth: u32::from(DEPTH),
        max_transfer,
        form: StatusForm::Kernel,
        mode: Mode::Direct,
        script: crate::storage::device::sim::SCRIPT,
    }
}

/// Bytes of a fixture device's media.
pub(crate) const MEDIA: u64 = 1 << 22;

/// Attaches `storage`'s volume over a fresh simulated disk.
pub(crate) fn attach<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    arena: &'a BufferArena<TestPlatform>,
) -> (TestVolume<'s, 'a>, SimControl) {
    attach_with(storage, arena, BUFFER)
}

pub(crate) fn attach_with<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    arena: &'a BufferArena<TestPlatform>,
    max_transfer: u32,
) -> (TestVolume<'s, 'a>, SimControl) {
    let (disk, control) = device_with(7, max_transfer);
    (attach_disk(storage, arena, disk, &control), control)
}

/// Attaches `storage`'s volume over a fresh simulated disk of queue depth `depth` and largest transfer `max_transfer`, with a command table of the same depth and tick bursts of that depth, and bootstraps it, or returns attach's refusal.
pub(crate) fn attach_shaped<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    arena: &'a BufferArena<TestPlatform>,
    depth: u16,
    max_transfer: u32,
) -> Result<(TestVolume<'s, 'a>, SimControl), super::volume::AttachError> {
    let (disk, control) = sim_attached(
        SimConfig {
            queue_depth: u32::from(depth),
            ..config(7, max_transfer)
        },
        media(MEDIA),
        facts(max_transfer),
    );
    let tick = TickConfig {
        submit_burst: u32::from(depth),
        terminal_burst: u32::from(depth),
        ..TICK
    };
    let mut budget = EngineBudget::new(1 << 25);
    let mut volume = Volume::attach(
        storage,
        arena,
        disk,
        ScriptedClock::trusted(),
        crate::storage::ServingAuthority::fixture(),
        depth,
        tick,
        &mut budget,
    )
    .map_err(|(error, _)| error)?;
    bootstrap(&mut volume, &control);
    Ok((volume, control))
}

/// Attaches `storage`'s volume over `store` on a simulated disk under the fixture authority, unbootstrapped, or returns
/// attach's refusal.
pub(crate) fn attach_over<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    arena: &'a BufferArena<TestPlatform>,
    store: &Media,
) -> Result<(TestVolume<'s, 'a>, SimControl), super::volume::AttachError> {
    attach_under(
        storage,
        arena,
        store,
        crate::storage::ServingAuthority::fixture(),
    )
}

/// Attaches `storage`'s volume over `store` on a simulated disk under `authority`, unbootstrapped, with a 32 MiB engine
/// budget, or returns attach's refusal.
pub(crate) fn attach_under<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    arena: &'a BufferArena<TestPlatform>,
    store: &Media,
    authority: crate::storage::ServingAuthority,
) -> Result<(TestVolume<'s, 'a>, SimControl), super::volume::AttachError> {
    attach_under_clock(storage, arena, store, authority, ScriptedClock::trusted())
}

/// [`attach_under`] whose volume reads `clock`.
pub(crate) fn attach_under_clock<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    arena: &'a BufferArena<TestPlatform>,
    store: &Media,
    authority: crate::storage::ServingAuthority,
    clock: Box<dyn PhysicalClock>,
) -> Result<(TestVolume<'s, 'a>, SimControl), super::volume::AttachError> {
    let (disk, control) = sim_attached(config_for(7), std::rc::Rc::clone(store), facts(BUFFER));
    let volume = Volume::attach(
        storage,
        arena,
        disk,
        clock,
        authority,
        DEPTH,
        TICK,
        &mut EngineBudget::new(1 << 25),
    )
    .map_err(|(error, _)| error)?;
    Ok((volume, control))
}

/// What a probe attach saw: its first outcome other than `Bootstrapping`, its last outcome, and one entry for each
/// write its own device executed over either root block, in execution order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Probe {
    pub first: MetadataOutcome,
    pub last: MetadataOutcome,
    /// The generation a write of one whole root block at its slot's start decodes to; `None` for a root write that
    /// covers part of a block or does not decode.
    pub root_writes: Vec<Option<u64>>,
}

/// Attaches `storage`'s volume over `store` under the fixture authority of `session`, arms
/// [`Plant::GenerationReuse`](super::volume::Plant::GenerationReuse) for the probing loop when `reissue` holds, and
/// ticks the probe's own device for at most 64 rounds, reading the outcome before each round and once after the last.
/// When the first outcome other than `Bootstrapping` is `Unformatted`, the probe calls
/// `volume.format_from(fixture_format)` and ticks on, and a refused format returns its outcome as the last; a probe
/// that runs out of rounds returns `Bootstrapping` for the outcome it did not reach. The probe's device records every
/// write it executes from the attach on, and [`Probe::root_writes`] decodes those over the root blocks at the
/// thread's [`unit`]. The volume drops before the return.
///
/// # Errors
///
/// Attach's refusal.
///
/// # Panics
///
/// When `store` is shorter than [`MEDIA`] bytes, the capacity of the probe's simulated device.
pub(crate) fn attach_probing(
    storage: &Storage<TestPlatform>,
    arena: &BufferArena<TestPlatform>,
    store: &Media,
    session: super::recovery::Session,
    reissue: bool,
) -> Result<Probe, super::volume::AttachError> {
    probe_within(ROUNDS, storage, arena, store, (session, reissue))
}

/// [`attach_probing`] with a budget of `rounds` device rounds.
fn probe_within(
    rounds: u32,
    storage: &Storage<TestPlatform>,
    arena: &BufferArena<TestPlatform>,
    store: &Media,
    (session, reissue): (super::recovery::Session, bool),
) -> Result<Probe, super::volume::AttachError> {
    struct Armed;
    impl Drop for Armed {
        fn drop(&mut self) {
            super::volume::PLANT.set(None);
        }
    }
    let authority = crate::storage::ServingAuthority::fixture_under(session);
    let (mut volume, control) = attach_under(storage, arena, store, authority)?;
    control.record_attempts();
    let _armed = reissue.then(|| {
        super::volume::PLANT.set(Some(super::volume::Plant::GenerationReuse));
        Armed
    });
    let mut out = Vec::with_capacity(16);
    let mut first = MetadataOutcome::Bootstrapping;
    let mut last = MetadataOutcome::Bootstrapping;
    for round in 0..=rounds {
        let outcome = volume.metadata_outcome();
        match (first, outcome) {
            (_, MetadataOutcome::Bootstrapping) => {}
            (MetadataOutcome::Bootstrapping, MetadataOutcome::Unformatted) => {
                first = outcome;
                if let Err(refused) = volume.format_from(fixture_format) {
                    last = refused;
                    break;
                }
            }
            (MetadataOutcome::Bootstrapping, _) => {
                (first, last) = (outcome, outcome);
                break;
            }
            _ => {
                last = outcome;
                break;
            }
        }
        if round == rounds {
            break;
        }
        control.tick(64);
        let _ = volume.poll_storage(0, &mut out);
        out.clear();
    }
    drop(volume);
    let root_writes = root_writes(&control.attempts(), unit());
    Ok(Probe {
        first,
        last,
        root_writes,
    })
}

/// The root-block layout at `unit`, over the [`TEST_METADATA_UNITS`](super::TEST_METADATA_UNITS)-unit prefix.
fn root_layout(unit: u32) -> super::recovery::Layout {
    super::recovery::Layout {
        unit,
        metadata_units: super::TEST_METADATA_UNITS,
    }
}

/// One entry for each of `attempts` that wrote a byte of either root block at `unit`: the generation it decodes to
/// when it wrote the whole block from the block's start, or `None`.
fn root_writes(attempts: &[super::device::sim::Attempt], unit: u32) -> Vec<Option<u64>> {
    use super::recovery::{Slot, decode};
    let len = u64::from(unit);
    let mut writes = Vec::new();
    for attempt in attempts {
        let end = attempt.start.saturating_add(attempt.bytes.len() as u64);
        for slot in [Slot::A, Slot::B] {
            let at = slot.block().saturating_mul(len);
            if attempt.start >= at.saturating_add(len) || end <= at {
                continue;
            }
            let whole = attempt.start == at && attempt.bytes.len() as u64 == len;
            let decoded = whole
                .then(|| decode(Crc32c::detect(), root_layout(unit), &attempt.bytes, slot).ok())
                .flatten();
            writes.push(decoded.map(|(_, root)| root.generation));
        }
    }
    writes
}

/// Each root slot of `store` decoded under `layout`, or `None` for a slot that does not decode, whose block the
/// store does not hold whole, or whose unit is below 4096 bytes or other than a power of two.
pub(crate) fn decoded_roots(
    store: &Media,
    layout: super::recovery::Layout,
) -> [Option<(super::recovery::FormatId, super::recovery::Root)>; 2] {
    use super::recovery::{Slot, decode};
    let unit = layout.unit;
    let media = store.borrow();
    [Slot::A, Slot::B].map(|slot| {
        if !(unit.is_power_of_two() && unit >= 4096) {
            return None;
        }
        let at = usize::try_from(slot.block())
            .ok()?
            .checked_mul(unit as usize)?;
        let block = media.get(at..at.checked_add(unit as usize)?)?;
        decode(Crc32c::detect(), layout, block, slot).ok()
    })
}

/// The generation each root slot of `store` decodes to, for blocks of `unit` bytes over a
/// [`TEST_METADATA_UNITS`](super::TEST_METADATA_UNITS)-unit prefix, or `None` as [`decoded_roots`] gives it.
pub(crate) fn root_generations(store: &Media, unit: u32) -> [Option<u64>; 2] {
    decoded_roots(store, root_layout(unit)).map(|root| root.map(|(_, root)| root.generation))
}

/// A tenure's fenced coverage holding version 0 of each key of `covered`.
pub(crate) fn fenced(covered: &[[u8; 32]]) -> super::cache::coverage::Coverage {
    fenced_over(covered, (0, 0))
}

/// A tenure's fenced coverage holding versions `low` through `high` of each key of `covered`.
pub(crate) fn fenced_over(
    covered: &[[u8; 32]],
    (low, high): (u64, u64),
) -> super::cache::coverage::Coverage {
    use super::cache::coverage::{Coverage, Interval, Limits, merged};
    let limits = Limits {
        intervals: 4,
        page_bytes: 1 << 16,
    };
    let interval = Interval::new(super::CacheVersion(low), super::CacheVersion(high)).unwrap();
    let page = (covered.iter()).fold(
        crate::failover::records::CoveragePage::default(),
        |page, key| merged(&page, (*key, interval), limits).unwrap(),
    );
    Coverage::of_pages(std::num::NonZeroU16::MIN, &[page])
}

/// `storage`'s volume over `disk`, bootstrapped.
fn attach_disk<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    arena: &'a BufferArena<TestPlatform>,
    disk: SimDisk,
    control: &SimControl,
) -> TestVolume<'s, 'a> {
    attach_clocked(storage, arena, disk, control, ScriptedClock::trusted())
}

/// `storage`'s volume over `disk` reading `clock`, bootstrapped.
fn attach_clocked<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    arena: &'a BufferArena<TestPlatform>,
    disk: SimDisk,
    control: &SimControl,
    clock: Box<dyn PhysicalClock>,
) -> TestVolume<'s, 'a> {
    let mut budget = EngineBudget::new(1 << 25);
    let mut volume = Volume::attach(
        storage,
        arena,
        disk,
        clock,
        crate::storage::ServingAuthority::fixture(),
        DEPTH,
        TICK,
        &mut budget,
    )
    .map_err(|(error, _)| error)
    .expect("attach");
    bootstrap(&mut volume, control);
    volume
}

/// One disk tick and one volume poll as one controller round, with room for
/// every event a tick pushes.
pub(crate) fn step<'a, D: super::device::Disk>(
    volume: &mut Volume<'_, 'a, TestPlatform, D>,
    control: &SimControl,
    out: &mut Vec<ReadEvent<'a>>,
) {
    let mut tick = || control.tick(64);
    let mut poll = || {
        let _ = volume.poll_storage(0, out);
    };
    round(&mut [
        Act::new(Actor::Disk(0), &mut tick),
        Act::new(Actor::Volume(0), &mut poll),
    ]);
}

/// Ticks until the device holds no command.
pub(crate) fn settle<D: super::device::Disk>(
    volume: &mut Volume<'_, '_, TestPlatform, D>,
    control: &SimControl,
) {
    let mut out = Vec::with_capacity(16);
    for _ in 0..64 {
        step(volume, control, &mut out);
        out.clear();
        if control.outstanding() == 0 {
            step(volume, control, &mut out);
            return;
        }
    }
    panic!("the device kept a command\n{}", control.describe());
}

/// Ticks until every staged metadata command settled and the device holds no command.
pub(crate) fn persist_journal(volume: &mut TestVolume<'_, '_>, control: &SimControl) {
    if !tick_journal(volume, control, 64) {
        panic!("a metadata command stayed staged\n{}", control.describe());
    }
}

/// Ticks at most `rounds` times, stopping once every staged metadata command settled and the device holds no command; returns whether it stopped there.
pub(crate) fn tick_journal(
    volume: &mut TestVolume<'_, '_>,
    control: &SimControl,
    rounds: usize,
) -> bool {
    let mut out = Vec::with_capacity(16);
    for _ in 0..rounds {
        step(volume, control, &mut out);
        out.clear();
        if volume.journal_settled() && control.outstanding() == 0 {
            return true;
        }
    }
    false
}

/// Streams all of `payload` into `fill` in `piece`-byte calls, ticking whenever the volume refuses, then submits the rest.
pub(crate) fn receive_all<'s, 'a, D: super::device::Disk>(
    fill: &mut WritableFill<'s, 'a, TestPlatform>,
    volume: &mut Volume<'s, 'a, TestPlatform, D>,
    control: &SimControl,
    payload: &[u8],
    piece: usize,
) {
    let mut out = Vec::with_capacity(16);
    let mut taken = 0;
    let mut last = None;
    for _ in 0..(4096 + payload.len()) {
        let end = (taken + piece.max(1)).min(payload.len());
        match fill.receive(volume, &payload[taken..end], &mut ample_io()) {
            Ok(count) => taken += count,
            Err(error) => {
                last = Some(error);
                step(volume, control, &mut out);
                out.clear();
                continue;
            }
        }
        let progress = fill.progress(volume);
        if taken == payload.len() && progress.submitted_units == progress.len_units {
            return;
        }
        if taken == payload.len() {
            step(volume, control, &mut out);
            out.clear();
        }
    }
    panic!(
        "the fill never submitted its record: {taken} of {} bytes taken, last refusal {last:?}, {:?}\n{}",
        payload.len(),
        fill.progress(volume),
        control.describe()
    );
}

/// The record `layout` names for `key`, `id` and `session`: header, payload and zero tail.
pub(crate) fn record_bytes(
    storage: &Storage<TestPlatform>,
    key: [u8; 32],
    id: AllocationId,
    session: u64,
    metadata: &[u8],
    body: &[u8],
) -> Vec<u8> {
    let identity = RecordIdentity {
        key,
        allocation: id.record_tag(),
        session,
        version: 0,
    };
    identity_bytes(storage, &identity, metadata, body)
}

pub(crate) fn identity_bytes(
    storage: &Storage<TestPlatform>,
    identity: &RecordIdentity,
    metadata: &[u8],
    body: &[u8],
) -> Vec<u8> {
    let layout = storage
        .record
        .layout(metadata.len() as u32, body.len() as u32);
    let mut bytes = vec![0; layout.record_units() as usize * IO_UNIT];
    let header = layout.header_bytes();
    bytes[header..header + metadata.len()].copy_from_slice(metadata);
    bytes[header + metadata.len()..][..body.len()].copy_from_slice(body);
    encode_header(
        Crc32c::detect(),
        &layout,
        identity,
        ExtentPosition::FIRST,
        &mut bytes,
    )
    .expect("encodes");
    bytes
}

/// Writes `bytes` at `locator`'s first unit on the device.
pub(crate) fn place(
    storage: &Storage<TestPlatform>,
    control: &SimControl,
    locator: ExtentLocator,
    bytes: &[u8],
) {
    control.write_device(device_byte(storage, locator), bytes);
}

/// The bytes of `locator`'s extent on the device.
pub(crate) fn extent(
    storage: &Storage<TestPlatform>,
    control: &SimControl,
    locator: ExtentLocator,
) -> Vec<u8> {
    control.device(
        device_byte(storage, locator),
        locator.len_units() as usize * IO_UNIT,
    )
}

/// The device byte where `locator`'s first payload unit begins, past `storage`'s metadata prefix.
pub(crate) fn device_byte(storage: &Storage<TestPlatform>, locator: ExtentLocator) -> usize {
    let metadata = storage.pool().descriptor().geometry.metadata_units();
    (metadata + locator.start_unit()) as usize * IO_UNIT
}

/// What a read delivered: the verified payload bytes in order, their ranges, and the outcome.
#[derive(Debug)]
pub(crate) struct Delivered {
    pub(crate) bytes: Vec<u8>,
    pub(crate) ranges: Vec<Range<u64>>,
    /// The verified header's information the read's events carried, `None` when its header never verified.
    pub(crate) info: Option<VerifiedReadInfo>,
    pub(crate) status: ReadStatus,
}

/// Ticks the read `op` to its `Done`, collecting its chunks and granting its next command after each one.
pub(crate) fn drive<D: super::device::Disk>(
    volume: &mut Volume<'_, '_, TestPlatform, D>,
    control: &SimControl,
    op: ReadOp,
) -> Delivered {
    drive_from(volume, control, op, 0)
}

/// [`drive`] for a read whose chunks before payload byte `start` were already taken.
pub(crate) fn drive_from<D: super::device::Disk>(
    volume: &mut Volume<'_, '_, TestPlatform, D>,
    control: &SimControl,
    op: ReadOp,
    start: u64,
) -> Delivered {
    let mut delivered = Delivered {
        bytes: Vec::new(),
        ranges: Vec::new(),
        info: None,
        status: ReadStatus::Quiesced,
    };
    let mut out = Vec::with_capacity(8);
    for _ in 0..64 {
        step(volume, control, &mut out);
        for event in out.drain(..) {
            match event {
                ReadEvent::Chunk {
                    op: of,
                    info,
                    range,
                    chunk,
                } => {
                    assert_eq!(of, op);
                    assert!(delivered.info.is_none_or(|seen| seen == info), "one header");
                    delivered.info = Some(info);
                    // Each later command needs its own grant.
                    let _ = volume.grant_read(op);
                    let next = start + delivered.bytes.len() as u64;
                    assert_eq!(range.start, next, "in order");
                    assert_eq!(chunk.bytes().len() as u64, range.end - range.start);
                    delivered.bytes.extend_from_slice(chunk.bytes());
                    delivered.ranges.push(range);
                }
                ReadEvent::Done {
                    op: of,
                    info,
                    status,
                } => {
                    assert_eq!(of, op);
                    assert!(
                        delivered.info.is_none() || info == delivered.info,
                        "Done carries the chunks' header"
                    );
                    delivered.info = info;
                    delivered.status = status;
                    return delivered;
                }
            }
        }
    }
    panic!("no Done\n{}", control.describe());
}

/// Reads the object `lease` names through the volume to its `Done`.
pub(crate) fn read_back<'s, D: super::device::Disk>(
    volume: &mut Volume<'s, '_, TestPlatform, D>,
    control: &SimControl,
    lease: &ExtentLease<'s, TestPlatform>,
) -> Delivered {
    let op = volume.read(lease.duplicate(), u64::MAX).expect("admitted");
    drive(volume, control, op)
}

/// Write commands the device accepted.
pub(crate) fn writes(control: &SimControl) -> usize {
    control.accepted(Operation::Write)
}

/// A storage's volume over a simulated disk and the disk's control handle.
pub(crate) struct Device<'s, 'a> {
    pub(crate) volume: TestVolume<'s, 'a>,
    pub(crate) control: SimControl,
}

impl<'s, 'a> Device<'s, 'a> {
    pub(crate) fn new(
        storage: &'s Storage<TestPlatform>,
        arena: &'a BufferArena<TestPlatform>,
    ) -> Self {
        let (volume, control) = attach(storage, arena);
        Self { volume, control }
    }

    /// `storage`'s volume, bootstrapped, over a fresh simulated disk whose
    /// commands move bytes in `media`, which other incarnations share: the
    /// first incarnation formats the media and each later one RESETs it
    /// under the thread's next, higher, fixture session.
    pub(crate) fn over(
        storage: &'s Storage<TestPlatform>,
        arena: &'a BufferArena<TestPlatform>,
        media: Media,
    ) -> Self {
        let (disk, control) = sim_attached(config(7, BUFFER), media, facts(BUFFER));
        let volume = attach_disk(storage, arena, disk, &control);
        Self { volume, control }
    }

    /// `storage`'s volume, bootstrapped, reading `clock`.
    pub(crate) fn clocked(
        storage: &'s Storage<TestPlatform>,
        arena: &'a BufferArena<TestPlatform>,
        clock: Box<dyn PhysicalClock>,
    ) -> Self {
        let (disk, control) = device_with(7, BUFFER);
        let volume = attach_clocked(storage, arena, disk, &control, clock);
        Self { volume, control }
    }

    /// Loses the volume through a storage poll whose driver call unwinds. The poll gets output room and the device is not advanced.
    pub(crate) fn lose(&mut self) {
        self.control
            .unwind_next(Some(super::device::sim::Unwind::Pick));
        let mut out = Vec::with_capacity(4);
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.volume.poll_storage(0, &mut out)
        }));
        assert!(unwound.is_err(), "the poll unwound");
        assert!(self.volume.is_lost(), "the unwound poll lost the volume");
    }

    /// Streams `payload` into `fill` and drives every write to its terminal.
    pub(crate) fn fill(&mut self, fill: &mut WritableFill<'s, 'a, TestPlatform>, payload: &[u8]) {
        receive_all(fill, &mut self.volume, &self.control, payload, 4096);
        settle(&mut self.volume, &self.control);
    }

    /// [`tick_journal`] over this device.
    pub(crate) fn tick_journal(&mut self, rounds: usize) -> bool {
        tick_journal(&mut self.volume, &self.control, rounds)
    }

    /// Ticks until every staged metadata command settled.
    pub(crate) fn persist_journal(&mut self) {
        persist_journal(&mut self.volume, &self.control);
    }

    /// The payload `lease`'s object reads back as, after its read completed.
    pub(crate) fn read(&mut self, lease: &ExtentLease<'s, TestPlatform>) -> Vec<u8> {
        let delivered = read_back(&mut self.volume, &self.control, lease);
        assert_eq!(delivered.status, ReadStatus::Complete);
        delivered.bytes
    }
}

#[cfg(test)]
mod probe_tests {
    use std::cell::Cell;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::super::owner_fixture::{CHUNK_LEN, FIXTURE, arena, storage_shaped_as};
    use super::super::recovery::{FormatId, Root, Slot, encode, session_at};
    use super::*;

    #[test]
    #[should_panic(expected = "the device unit is held once")]
    fn a_second_unit_guard_over_the_default_unit_panics() {
        let _held = Unit::hold(4096);
        let _second = Unit::hold(BUFFER);
    }

    #[test]
    fn a_refused_second_guard_keeps_the_first_and_a_later_guard_holds() {
        let held = Unit::hold(4096);
        assert!(catch_unwind(|| Unit::hold(BUFFER)).is_err());
        assert_eq!(unit(), 4096);
        drop(held);
        let _wide = Unit::hold(BUFFER);
        assert_eq!(unit(), BUFFER);
    }

    #[test]
    fn a_unit_guard_returns_the_thread_to_4096_bytes_on_unwind() {
        let seen = Cell::new(0);
        let unwound = catch_unwind(AssertUnwindSafe(|| {
            let _held = Unit::hold(BUFFER);
            seen.set(unit());
            panic!("unwinding through the guard");
        }));
        let payload = unwound.expect_err("the closure panics");
        assert_eq!(
            payload.downcast_ref::<&str>(),
            Some(&"unwinding through the guard")
        );
        assert_eq!(seen.get(), BUFFER);
        assert_eq!(unit(), 4096);
    }

    fn probed(rounds: u32) -> Probe {
        let storage = storage_shaped_as(FIXTURE, CHUNK_LEN);
        let arena = arena(16);
        probe_within(
            rounds,
            &storage,
            &arena,
            &media(MEDIA),
            (session_at(1, 0), false),
        )
        .expect("attached")
    }

    #[test]
    fn a_probe_reads_the_outcome_its_last_round_produced() {
        let rounds = {
            let storage = storage_shaped_as(FIXTURE, CHUNK_LEN);
            let arena = arena(16);
            let store = media(MEDIA);
            let authority = crate::storage::ServingAuthority::fixture_under(session_at(1, 0));
            let (mut volume, control) =
                attach_under(&storage, &arena, &store, authority).expect("attached");
            let mut out = Vec::with_capacity(16);
            let mut rounds = 0;
            while volume.metadata_outcome() == MetadataOutcome::Bootstrapping {
                assert!(
                    rounds < ROUNDS,
                    "the attach reads its roots within its rounds"
                );
                control.tick(64);
                let _ = volume.poll_storage(0, &mut out);
                out.clear();
                rounds += 1;
            }
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::Unformatted);
            rounds
        };
        assert!(rounds >= 1);
        let at = probed(rounds);
        assert_eq!(
            (at.first, at.last),
            (MetadataOutcome::Unformatted, MetadataOutcome::Bootstrapping)
        );
        let short = probed(rounds - 1);
        assert_eq!(
            (short.first, short.last),
            (
                MetadataOutcome::Bootstrapping,
                MetadataOutcome::Bootstrapping
            )
        );
        let full = probed(ROUNDS);
        assert_eq!(
            (full.first, full.last),
            (MetadataOutcome::Unformatted, MetadataOutcome::Open)
        );
        assert!(
            full.root_writes.contains(&Some(session_at(1, 0).get())),
            "{full:?}"
        );
        assert!(full.root_writes.iter().all(Option::is_some), "{full:?}");
    }

    #[test]
    fn root_generations_reads_a_short_or_partial_store_as_undecoded() {
        let root = Root::reset(
            5,
            crate::storage::TEST_CLOCK.encode(),
            crate::storage::TEST_FEED.encode(),
        );
        let mut block = vec![0; BUFFER as usize];
        encode(
            Crc32c::detect(),
            root_layout(BUFFER),
            FormatId([0x42; 16]),
            &root,
            Slot::A,
            &mut block,
        );
        let at = |slot: Slot| slot.block() as usize * BUFFER as usize;
        for len in [
            at(Slot::B) + BUFFER as usize - 1,
            at(Slot::B),
            MEDIA as usize,
        ] {
            let store = media(len as u64);
            store.borrow_mut()[at(Slot::A)..at(Slot::A) + BUFFER as usize].copy_from_slice(&block);
            assert_eq!(
                root_generations(&store, BUFFER),
                [Some(root.generation), None],
                "{len}"
            );
            assert_eq!(root_generations(&store, 0), [None, None], "{len}");
        }
        assert_eq!(root_generations(&media(0), BUFFER), [None, None]);
    }
}
