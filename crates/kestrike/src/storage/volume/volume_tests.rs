use super::super::config::{ConfigError, StorageConfig};
use super::super::device::sim::{
    Event, Fault, Mode, QuiesceMode, SimConfig, SimControl, SimDisk, StatusForm,
};
use super::super::device::{
    BufferArena, BufferConfig, CommandToken, Completion, DeviceStatus, IO_UNIT, Operation,
    PoolKind, PoolSpec, QuiesceProgress, Quiesced, Refusal, RefusalReason, Released, SECTOR,
    SubmitRefusal, TableError,
};
use std::sync::atomic::AtomicU64;

use super::super::ExtentReservation;
use super::super::budget::WorkBudget;
use super::super::device::Buffer;
use super::super::extent::ExtentLocator;
use super::super::fill::FillSerial;
use super::super::ledger::EngineBudget;
use super::super::os::HugepageSize;
use super::super::owner::Storage;
use super::super::placement::{NodeMask, PlacementConfig};
use super::super::record::{
    Crc32c, ExtentPosition, HeaderMismatch, RecordConfig, RecordConfigError, RecordIdentity,
    RecordLayout, encode_header,
};
use super::super::seeded::SplitMix64;
use super::super::test_platform::TestPlatform;
use super::super::volume_fixture::{attached, bootstrap, drive, drive_from};
use super::ready::SlotSet;
use super::{
    AttachError, ControlRefusal, MAX_READ_AHEAD, RawRead, ReadEvent, ReadOp, ReadRefusal,
    ReadStatus, TickConfig, TickReport, Volume, VolumeConfig, WriteSet,
};
use crate::sim::round::{Act, Actor, round, turn_until};

pub(super) const PAGE: usize = 4096;
pub(super) const BUFFER: u32 = 16384;
pub(super) const CHUNK: u32 = 8192;
pub(super) const DEPTH: u16 = 8;
pub(super) use super::super::volume_fixture::SESSION;
pub(super) const KEY: [u8; 32] = [0x4B; 32];
pub(super) const CAPACITY: u64 = 1 << 22;

pub(super) const TICK: TickConfig = TickConfig {
    submit_burst: 8,
    terminal_burst: 8,
    validate_bytes: 1 << 20,
};

pub(super) type TestVolume<'s, 'a> = Volume<'s, 'a, TestPlatform, SimDisk>;

/// Metadata cap of every storage here; the test records use at most 100 bytes.
const METADATA_CAP: usize = 128;

/// Body cap of the default storage, above every test record's body.
const BODY_CAP: usize = 6 * CHUNK as usize;

pub(super) fn storage_with(
    read_ops: u32,
    record: RecordConfig,
) -> Result<Storage<TestPlatform>, ConfigError> {
    storage_sized(read_ops, record, BODY_CAP)
}

/// A storage whose largest admissible record has `body_cap` body bytes, on
/// a volume one unit larger than that record.
pub(super) fn storage_sized(
    read_ops: u32,
    record: RecordConfig,
    body_cap: usize,
) -> Result<Storage<TestPlatform>, ConfigError> {
    // Room past every placed record's start for the reservations writes take.
    let units = sized_units(record, body_cap);
    storage_on(units * IO_UNIT, (read_ops, read_ops, 0), record, body_cap)
}

pub(super) fn sized_units(record: RecordConfig, body_cap: usize) -> usize {
    (largest_units(record, body_cap) + 1).max(VOLUME_FLOOR)
}

pub(super) fn default_units() -> usize {
    sized_units(RecordConfig { chunk_len: CHUNK }, BODY_CAP)
}

/// The default storage with `read_ops` read records whose reads hold at most `read_commands` table slots together.
pub(super) fn storage_shared(read_ops: u32, read_commands: u32) -> Storage<TestPlatform> {
    let record = RecordConfig { chunk_len: CHUNK };
    let units = (largest_units(record, BODY_CAP) + 1).max(VOLUME_FLOOR);
    storage_on(
        units * IO_UNIT,
        (read_ops, read_commands, 0),
        record,
        BODY_CAP,
    )
    .expect("valid")
}

/// The default storage with `read_ops` read records and a read share of `read_ops` table slots, whose reads hold a second command ahead of their current one, before or after the header verified.
pub(super) fn storage_reading_ahead(read_ops: u32) -> Storage<TestPlatform> {
    let record = RecordConfig { chunk_len: CHUNK };
    let units = (largest_units(record, BODY_CAP) + 1).max(VOLUME_FLOOR);
    storage_on(units * IO_UNIT, (read_ops, read_ops, 1), record, BODY_CAP).expect("valid")
}

/// A storage whose reads may hold `ahead` commands ahead of their current one, with bodies up to twelve chunks, so a record spans more commands than a read holds.
pub(super) fn storage_reading_ahead_by(read_ops: u32, ahead: u8) -> Storage<TestPlatform> {
    let record = RecordConfig { chunk_len: CHUNK };
    let body_cap = 12 * CHUNK as usize;
    let units = (largest_units(record, body_cap) + 1).max(VOLUME_FLOOR);
    storage_on(
        units * IO_UNIT,
        (read_ops, read_ops.max(u32::from(ahead) + 1), ahead),
        record,
        body_cap,
    )
    .expect("valid")
}

/// Units of the largest admissible record with `body_cap` body bytes.
fn largest_units(record: RecordConfig, body_cap: usize) -> usize {
    record.validate().map_or(1, |valid| {
        valid
            .layout(METADATA_CAP as u32, body_cap as u32)
            .record_units() as usize
    })
}

fn storage_on(
    payload_bytes: usize,
    shares: (u32, u32, u8),
    record: RecordConfig,
    body_cap: usize,
) -> Result<Storage<TestPlatform>, ConfigError> {
    storage_edited(payload_bytes, shares, record, body_cap, |_| {})
}

/// The default storage of `read_ops` read records whose volume configuration `edit` changes before validation.
pub(super) fn storage_changed(
    read_ops: u32,
    edit: impl FnOnce(&mut VolumeConfig),
) -> Result<Storage<TestPlatform>, ConfigError> {
    let record = RecordConfig { chunk_len: CHUNK };
    let units = sized_units(record, BODY_CAP);
    storage_edited(
        units * IO_UNIT,
        (read_ops, read_ops, 0),
        record,
        BODY_CAP,
        edit,
    )
}

fn storage_edited(
    payload_bytes: usize,
    (read_ops, read_commands, read_ahead): (u32, u32, u8),
    record: RecordConfig,
    body_cap: usize,
    edit: impl FnOnce(&mut VolumeConfig),
) -> Result<Storage<TestPlatform>, ConfigError> {
    let mut config = StorageConfig {
        page_size: PAGE,
        engine_budget: usize::MAX,
        body_cap,
        metadata_cap: Some(METADATA_CAP),
        lease_limit: 2,
        object_rights: 2,
        reader_limit: 1,
        volume: VolumeConfig {
            read_ops,
            read_commands,
            read_ahead,
            record,
            alloc_search_words: crate::storage::extent::work_bound(
                (payload_bytes / IO_UNIT) as u64,
                8,
                largest_units(record, body_cap) as u64,
            ),
            ..crate::storage::test_volume(payload_bytes, 8)
        },
    };
    edit(&mut config.volume);
    let validated = config.validate()?;
    let placement = PlacementConfig { control_home: 0 };
    Ok(Storage::initialize(&validated, &placement, TestPlatform::heap(PAGE)).expect("storage"))
}

pub(super) fn storage(read_ops: u32) -> Storage<TestPlatform> {
    storage_with(read_ops, RecordConfig { chunk_len: CHUNK }).expect("valid")
}

pub(super) fn arena_with(read: u32, receive: u32) -> BufferArena<TestPlatform> {
    let pools = [
        PoolSpec {
            kind: PoolKind::ReadResponse,
            count: read,
            buffer_len: BUFFER,
        },
        PoolSpec {
            kind: PoolKind::ReceiveWrite,
            count: receive,
            buffer_len: BUFFER,
        },
        PoolSpec {
            kind: PoolKind::Maintenance,
            count: 1,
            buffer_len: 4096,
        },
    ];
    let validated = BufferConfig {
        hugepage: HugepageSize::TwoMiB,
        nodes: NodeMask::from_nodes(&[0]).expect("node 0"),
        pools: &pools,
    }
    .validate()
    .expect("valid");
    BufferArena::initialize(
        &validated,
        TestPlatform::heap(4096),
        &mut EngineBudget::new(usize::MAX),
    )
    .expect("arena")
}

pub(super) fn arena() -> BufferArena<TestPlatform> {
    arena_with(4, 4)
}

pub(super) fn device(seed: u64) -> (SimDisk, SimControl) {
    device_sized(seed, CAPACITY)
}

fn device_sized(seed: u64, capacity: u64) -> (SimDisk, SimControl) {
    attached(SimConfig {
        seed,
        capacity,
        queue_depth: u32::from(DEPTH),
        max_transfer: BUFFER,
        form: StatusForm::Kernel,
        mode: Mode::Direct,
        script: crate::storage::device::sim::SCRIPT,
    })
}

pub(super) fn attach<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    arena: &'a BufferArena<TestPlatform>,
    tick: TickConfig,
) -> (TestVolume<'s, 'a>, SimControl) {
    let (disk, control) = device(7);
    let mut budget = EngineBudget::new(1 << 24);
    let mut volume = Volume::attach(
        storage,
        arena,
        disk,
        crate::storage::portable::scripted::ScriptedClock::trusted(),
        crate::storage::ServingAuthority::fixture(),
        DEPTH,
        tick,
        &mut budget,
    )
    .map_err(|(error, _)| error)
    .expect("attach");
    bootstrap(&mut volume, &control);
    (volume, control)
}

/// One inline record: its header, payload and zero tail as the device holds
/// them, and the read that names it.
pub(super) struct Record {
    pub(super) bytes: Vec<u8>,
    pub(super) payload: Vec<u8>,
    pub(super) layout: RecordLayout,
    pub(super) read: RawRead,
}

/// Placed records start this many units in, past every extent a reservation takes.
pub(super) const PLACED: u64 = 100;
const VOLUME_FLOOR: usize = 256;

pub(super) fn record(
    start_unit: u64,
    metadata_len: u32,
    body_len: u32,
    session: u64,
    seed: u64,
) -> Record {
    record_at(PLACED + start_unit, metadata_len, body_len, session, seed)
}

pub(super) fn record_at(
    start_unit: u64,
    metadata_len: u32,
    body_len: u32,
    session: u64,
    seed: u64,
) -> Record {
    let layout = RecordConfig { chunk_len: CHUNK }
        .validate()
        .expect("valid")
        .layout(metadata_len, body_len);
    let mut rng = SplitMix64::new(seed);
    let payload: Vec<u8> = (0..layout.payload_len())
        .map(|_| rng.next_u64() as u8)
        .collect();
    let mut bytes = vec![0; layout.record_units() as usize * IO_UNIT];
    bytes[layout.header_bytes()..][..payload.len()].copy_from_slice(&payload);
    let identity = RecordIdentity {
        key: KEY,
        allocation: seed,
        session,
        version: 0,
    };
    encode_header(
        Crc32c::detect(),
        &layout,
        &identity,
        ExtentPosition::FIRST,
        &mut bytes,
    )
    .expect("encodes");
    Record {
        read: RawRead {
            locator: ExtentLocator::new(start_unit, layout.record_units() as u32)
                .expect("fits")
                .ending_at(layout.record_len()),
            key: KEY,
            allocation: seed,
            session: SESSION,
            version: 0,
        },
        bytes,
        payload,
        layout,
    }
}

pub(super) fn place(storage: &Storage<TestPlatform>, control: &SimControl, record: &Record) {
    control.write_device(
        crate::storage::volume_fixture::device_byte(storage, record.read.locator),
        &record.bytes,
    );
}

pub(super) const ATTEMPT_SERIAL: FillSerial = FillSerial::new(1).unwrap();

/// A live fill attempt word, serial 1, for write sets the tests begin directly.
pub(super) static ATTEMPT: AtomicU64 = AtomicU64::new(ATTEMPT_SERIAL.get() << 2);

/// Reserves an extent of `units` units and begins its write set; the reservation keeps the slot filling, so the set's right can be installed.
pub(super) fn write_set<'s>(
    storage: &'s Storage<TestPlatform>,
    volume: &mut TestVolume<'s, '_>,
    units: u32,
) -> (ExtentReservation<'s, TestPlatform>, WriteSet) {
    // The shortest body whose record fills `units` units.
    let body = (0..BODY_CAP)
        .find(|&body| storage.record.layout(0, body as u32).record_units() == u64::from(units))
        .expect("a body of that many units");
    let reservation = storage
        .reserve(Some(0), Some(body), &mut WorkBudget::new(64))
        .expect("an extent");
    assert_eq!(reservation.locator().len_units(), units);
    let set = volume
        .begin_fill(
            reservation.id(),
            reservation.locator(),
            reservation.locator().len_units(),
            &ATTEMPT,
            ATTEMPT_SERIAL,
        )
        .expect("a set");
    (reservation, set)
}

/// One device step of up to `max` commands, then one tick at time zero, as
/// one controller round; returns the tick's report.
fn turn<'a>(
    volume: &mut TestVolume<'_, 'a>,
    control: &SimControl,
    max: u32,
    out: &mut Vec<ReadEvent<'a>>,
) -> TickReport {
    let mut report = None;
    let mut tick = || control.tick(max);
    let mut poll = || report = Some(volume.poll_storage(0, out));
    round(&mut [
        Act::new(Actor::Disk(0), &mut tick),
        Act::new(Actor::Volume(0), &mut poll),
    ]);
    report.expect("the round polled the volume")
}

/// Reserves an extent for `metadata_len` and `body_len` bytes, writes the record `record_at` builds there through a write set in buffer-sized commands, ticks until every command succeeded and ends the set.
fn write_record<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    volume: &mut TestVolume<'s, 'a>,
    arena: &'a BufferArena<TestPlatform>,
    control: &SimControl,
    metadata_len: u32,
    body_len: u32,
    seed: u64,
) -> (Record, ExtentReservation<'s, TestPlatform>) {
    let reservation = storage
        .reserve(
            Some(metadata_len as usize),
            Some(body_len as usize),
            &mut WorkBudget::new(64),
        )
        .expect("an extent");
    let record = record_at(
        reservation.locator().start_unit(),
        metadata_len,
        body_len,
        SESSION,
        seed,
    );
    let set = volume
        .begin_fill(
            reservation.id(),
            reservation.locator(),
            reservation.locator().len_units(),
            &ATTEMPT,
            ATTEMPT_SERIAL,
        )
        .expect("a set");
    let mut offset = 0;
    let mut out = Vec::with_capacity(8);
    while offset < record.bytes.len() {
        let Ok(mut buffer) = arena.acquire(PoolKind::ReceiveWrite) else {
            turn(volume, control, 8, &mut out);
            continue;
        };
        let len = (record.bytes.len() - offset).min(buffer.capacity());
        buffer.bytes_mut()[..len].copy_from_slice(&record.bytes[offset..offset + len]);
        let written =
            write(volume, set, buffer, (offset / IO_UNIT) as u32).map_err(|(_, refusal)| refusal);
        assert_eq!(written, Ok(len as u32));
        offset += len;
    }
    for _ in 0..32 {
        if volume.write_progress(set).expect("live").is_ready() {
            volume.end_fill(set);
            return (record, reservation);
        }
        turn(volume, control, 8, &mut out);
    }
    panic!("the set never became ready\n{}", control.describe());
}

/// Submits `buffer` at `offset` units of the set's extent and returns the bytes the command carries.
pub(super) fn write<'a>(
    volume: &mut TestVolume<'_, 'a>,
    set: WriteSet,
    buffer: Buffer<'a>,
    offset: u32,
) -> Result<u32, (Buffer<'a>, Refusal)> {
    let before = volume.write_progress(set).expect("live").submitted_units;
    volume.write_at(set, buffer, offset)?;
    Ok((volume.write_progress(set).expect("live").submitted_units - before) * IO_UNIT as u32)
}

pub(super) fn last_submitted(control: &SimControl) -> CommandToken {
    control
        .events()
        .iter()
        .rev()
        .find_map(|event| match event {
            Event::Submitted(token, _) => Some(*token),
            _ => None,
        })
        .expect("a submit")
}

pub(super) fn submits(control: &SimControl) -> usize {
    control.accepted(Operation::Read) + control.accepted(Operation::Write)
}

pub(super) fn queue_full() -> SubmitRefusal {
    SubmitRefusal {
        reason: RefusalReason::QueueFull,
        code: None,
    }
}

#[test]
fn s1_a_write_set_is_ready_only_after_every_write_succeeded() {
    let storage = storage(2);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let (reservation, set) = write_set(&storage, &mut volume, 8);
    let start = crate::storage::volume_fixture::device_byte(&storage, reservation.locator());
    let mut tokens = Vec::new();
    for (offset, fill) in [(0, 0x11u8), (4, 0x22)] {
        let mut buffer = arena.acquire(PoolKind::ReceiveWrite).expect("free");
        buffer.bytes_mut().fill(fill);
        let written = write(&mut volume, set, buffer, offset).map_err(|(_, refusal)| refusal);
        assert_eq!(written, Ok(BUFFER));
        tokens.push(last_submitted(&control));
    }
    control.hold(tokens[1]);
    let mut out = Vec::with_capacity(2);
    turn_until(|| {
        turn(&mut volume, &control, 8, &mut out);
        volume.write_progress(set).expect("live").completed_units > 0
    });
    let progress = volume.write_progress(set).expect("live");
    assert_eq!((progress.completed_units, progress.is_ready()), (4, false));
    control.release(tokens[1]);
    turn_until(|| {
        turn(&mut volume, &control, 8, &mut out);
        volume.write_progress(set).expect("live").is_ready()
    });
    assert!(volume.write_progress(set).expect("live").is_ready());
    let len = BUFFER as usize;
    assert_eq!(control.device(start, len), vec![0x11; len]);
    assert_eq!(control.device(start + len, len), vec![0x22; len]);
    volume.end_fill(set);
    assert_eq!(volume.write_progress(set), None);
    assert!(out.is_empty());
    drop(reservation);
}

#[test]
fn s2_a_hit_read_delivers_verified_chunks_then_complete() {
    let storage = storage(2);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let record = record(3, 100, 2 * CHUNK + 5, SESSION, 1);
    place(&storage, &control, &record);
    let op = volume.read_raw(&record.read, u64::MAX).expect("admitted");
    let delivered = drive(&mut volume, &control, op);
    assert_eq!(delivered.status, ReadStatus::Complete);
    assert_eq!(delivered.bytes, record.payload);
    assert_eq!(
        delivered.ranges.len(),
        2,
        "two chunks with the header in two windows, then one"
    );
    assert_eq!(submits(&control), 2);
    let report = volume.report();
    let reads = (
        report.reads_submitted,
        report.reads_done,
        report.reads_failed,
    );
    assert_eq!(reads, (2, 2, 0));
    assert_eq!(arena.report(PoolKind::ReadResponse).free, 4);
}

/// A read's end is its locator's record end rounded up to the device block, within the extent: a 512-byte device reads to the record's last sector, a 4 KiB device to the record's last unit, and a locator without a tail reads the whole extent.
#[test]
fn a_read_s_end_rounds_the_record_end_to_the_device_block() {
    const UNIT: u64 = IO_UNIT as u64;
    let extent = ExtentLocator::new(7, 3).unwrap();
    let ended = extent.ending_at(2 * UNIT + 700);
    assert_eq!(super::attach::read_end(ended, 512), 2 * UNIT + 1024);
    assert_eq!(super::attach::read_end(ended, 4096), 3 * UNIT);
    assert_eq!(super::attach::read_end(extent, 512), 3 * UNIT);
    assert_eq!(
        super::attach::read_end(extent.ending_at(3 * UNIT), 512),
        3 * UNIT
    );
}

/// A read ends at its record's last sector: a record whose bytes end inside its last unit moves its bytes rounded up to the device's 512-byte block and delivers every payload byte, and a locator whose tail falls short of the header's lengths ends the read with a length mismatch before any payload byte.
#[test]
fn a_read_ends_at_its_record_s_last_sector_and_a_short_tail_mismatches_its_lengths() {
    let storage = storage(2);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let moved = |control: &SimControl| -> u64 {
        control
            .events()
            .iter()
            .filter_map(|event| match event {
                Event::Executed { len, .. } => Some(*len as u64),
                _ => None,
            })
            .sum()
    };
    let whole = record(3, 100, 2 * CHUNK + 2_000, SESSION, 1);
    let record_len = whole.layout.record_len();
    let last_unit = (whole.layout.record_units() - 1) * IO_UNIT as u64;
    assert!(
        record_len > last_unit + SECTOR as u64
            && record_len.next_multiple_of(SECTOR as u64) < last_unit + IO_UNIT as u64,
        "the record ends past its last unit's first sector and short of its last"
    );
    place(&storage, &control, &whole);
    let op = volume.read_raw(&whole.read, u64::MAX).expect("admitted");
    let delivered = drive(&mut volume, &control, op);
    assert_eq!(delivered.status, ReadStatus::Complete);
    assert_eq!(delivered.bytes, whole.payload);
    assert_eq!(moved(&control), record_len.next_multiple_of(SECTOR as u64));

    let mut short = record(3, 100, 2 * CHUNK + 2_000, SESSION, 2);
    short.read.locator = short.read.locator.ending_at(last_unit + 1);
    place(&storage, &control, &short);
    let before = moved(&control);
    let op = volume.read_raw(&short.read, u64::MAX).expect("admitted");
    let delivered = drive(&mut volume, &control, op);
    assert_eq!(
        delivered.status,
        ReadStatus::HeaderMismatch(HeaderMismatch::Lengths {
            metadata_len: 100,
            body_len: 2 * CHUNK + 2_000,
        })
    );
    assert!(delivered.bytes.is_empty());
    assert!(
        moved(&control) - before <= last_unit + SECTOR as u64,
        "the read stopped at the short tail"
    );
}

#[test]
fn s3_cancel_holds_the_record_and_buffer_until_the_real_terminal_while_a_write_proceeds() {
    let storage = storage(1);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let record = record(0, 0, CHUNK, SESSION, 2);
    place(&storage, &control, &record);
    let op = volume.read_raw(&record.read, u64::MAX).expect("admitted");
    let read_token = last_submitted(&control);
    let (_reservation, set) = write_set(&storage, &mut volume, 1);
    let buffer = arena.acquire(PoolKind::ReceiveWrite).expect("free");
    write(&mut volume, set, buffer, 0).expect("submitted");
    control.hold(read_token);
    assert_eq!(volume.cancel_read(op), Ok(()));
    assert_eq!(volume.cancel_read(op), Err(ControlRefusal::Stale));
    let mut out = Vec::with_capacity(4);
    turn_until(|| {
        turn(&mut volume, &control, 8, &mut out);
        !out.is_empty() && volume.write_progress(set).expect("live").is_ready()
    });
    let done: Vec<_> = out
        .drain(..)
        .map(|event| match event {
            ReadEvent::Done { op, status, .. } => (op, status),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(done, [(op, ReadStatus::Cancelled)]);
    assert_eq!(volume.report().cancelled, 1);
    assert!(volume.write_progress(set).expect("live").is_ready());
    assert_eq!(arena.report(PoolKind::ReadResponse).quarantined, 1);
    assert_eq!(
        volume.read_raw(&record.read, u64::MAX),
        Err(ReadRefusal::OpsExhausted)
    );
    control.release(read_token);
    for _ in 0..4 {
        turn(&mut volume, &control, 8, &mut out);
    }
    assert!(out.is_empty(), "the late terminal frees silently");
    assert_eq!(arena.report(PoolKind::ReadResponse).free, 4);
    assert_eq!(volume.cancel_read(op), Err(ControlRefusal::Stale));
    let again = volume
        .read_raw(&record.read, u64::MAX)
        .expect("the record is free again");
    assert_ne!(again, op, "a reused slot carries a new generation");
}

#[test]
fn s4_shutdown_releases_only_after_a_proven_stop() {
    for proven in [false, true] {
        let storage = storage(2);
        let arena = arena();
        let (mut volume, control) = attach(&storage, &arena, TICK);
        let record = record(0, 0, CHUNK, SESSION, 3);
        let op = volume.read_raw(&record.read, u64::MAX).expect("admitted");
        control.fault(last_submitted(&control), Fault::DropCompletion);
        let (_reservation, set) = write_set(&storage, &mut volume, 4);
        let buffer = arena.acquire(PoolKind::ReceiveWrite).expect("free");
        write(&mut volume, set, buffer, 0).expect("submitted");
        control.fault(last_submitted(&control), Fault::DropCompletion);
        control.tick(8);
        let mode = if proven {
            QuiesceMode::Reset
        } else {
            QuiesceMode::Unproven
        };
        control.set_quiesce(mode);
        let first = volume.close();
        assert_eq!(
            matches!(first, QuiesceProgress::Quiesced(_)),
            proven,
            "{first:?}"
        );
        assert_eq!(
            volume.read_raw(&record.read, u64::MAX),
            Err(ReadRefusal::Closed)
        );
        assert_eq!(volume.cancel_read(op), Err(ControlRefusal::Closed));
        match volume.release() {
            Ok(proof) => {
                assert!(proven);
                assert_eq!(proof, Quiesced::DeviceStopped);
            }
            Err(held) => {
                let (mut volume, progress) = *held;
                assert!(!proven);
                let unproven = matches!(
                    progress,
                    QuiesceProgress::Draining { .. } | QuiesceProgress::Unproven { .. }
                );
                assert!(unproven, "{progress:?}");
                let mut out = Vec::with_capacity(4);
                volume.poll_storage(0, &mut out);
                assert!(
                    out.is_empty(),
                    "nothing ends while the device may touch its buffers"
                );
                let draining = volume.write_progress(set).expect("live");
                assert!(!draining.is_ready());
                assert!(
                    draining.outstanding_units > 0,
                    "the unproven write stays outstanding"
                );
                drop(out);
                let mut volume = match volume.release() {
                    Err(held) => held.0,
                    Ok(_) => panic!("still unproven"),
                };
                control.set_quiesce(QuiesceMode::Reset);
                let progress = volume.close();
                assert_eq!(progress, QuiesceProgress::Quiesced(Quiesced::DeviceStopped));
                let mut out = Vec::with_capacity(4);
                volume.poll_storage(0, &mut out);
                let done: Vec<_> = out
                    .drain(..)
                    .map(|event| match event {
                        ReadEvent::Done { op, status, .. } => (op, status),
                        other => panic!("{other:?}"),
                    })
                    .collect();
                assert_eq!(done, [(op, ReadStatus::Quiesced)]);
                let quiesced = volume.write_progress(set).expect("live");
                assert!(quiesced.failed);
                assert_eq!(
                    quiesced.outstanding_units, 0,
                    "the quiesced write cleared its units"
                );
                drop(out);
                assert_eq!(
                    volume.release().map_err(|_| ()),
                    Ok(Quiesced::DeviceStopped)
                );
            }
        }
        assert!(
            arena.release().is_ok(),
            "a proven stop returns every buffer"
        );
    }
}

#[test]
fn a_proven_stop_ends_each_operation_once_and_fails_outstanding_writes() {
    let storage = storage(2);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let record = record(0, 0, CHUNK, SESSION, 3);
    let op = volume.read_raw(&record.read, u64::MAX).expect("admitted");
    control.hold(last_submitted(&control));
    let (_reservation, set) = write_set(&storage, &mut volume, 4);
    let buffer = arena.acquire(PoolKind::ReceiveWrite).expect("free");
    write(&mut volume, set, buffer, 0).expect("submitted");
    control.hold(last_submitted(&control));
    control.set_quiesce(QuiesceMode::Reset);
    let mut progress = volume.close();
    let mut out = Vec::with_capacity(4);
    let mut done = Vec::new();
    for _ in 0..4 {
        volume.poll_storage(0, &mut out);
        done.extend(out.drain(..).map(|event| match event {
            ReadEvent::Done { op, status, .. } => (op, status),
            other => panic!("{other:?}"),
        }));
        progress = volume.close();
    }
    assert_eq!(progress, QuiesceProgress::Quiesced(Quiesced::DeviceStopped));
    assert_eq!(done, [(op, ReadStatus::Quiesced)]);
    let written = volume.write_progress(set).expect("live");
    assert!(written.failed && !written.is_ready());
    assert_eq!(
        volume.release().map_err(|_| ()),
        Ok(Quiesced::DeviceStopped)
    );
    drop(out);
    assert_eq!(arena.release().map_err(|_| ()), Ok(Released::Complete));
}

#[test]
fn s5_a_held_command_does_not_block_another_operation() {
    let storage = storage(3);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let first = record(0, 0, CHUNK, SESSION, 4);
    let second = record(10, 0, CHUNK, SESSION, 5);
    place(&storage, &control, &first);
    place(&storage, &control, &second);
    let held = volume.read_raw(&first.read, u64::MAX).expect("admitted");
    let token = last_submitted(&control);
    control.hold(token);
    let other = volume.read_raw(&second.read, u64::MAX).expect("admitted");
    let delivered = drive(&mut volume, &control, other);
    assert_eq!(delivered.status, ReadStatus::Complete);
    assert_eq!(delivered.bytes, second.payload);
    assert_eq!(volume.table_report().pending, 1);
    control.release(token);
    let delivered = drive(&mut volume, &control, held);
    assert_eq!(delivered.status, ReadStatus::Complete);
    assert_eq!(delivered.bytes, first.payload);
}

#[test]
fn seeded_records_round_trip_at_unit_chunk_and_buffer_boundaries() {
    let storage = storage(2);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let sizes = [
        (0, 0),
        (0, 1),
        (1, 0),
        (0, 4095),
        (0, 4096),
        (0, 4097),
        (3, CHUNK - 3),
        (0, CHUNK + 1),
        (100, 2 * CHUNK - 100),
        (0, 3 * CHUNK),
        (7, 5 * CHUNK + 11),
    ];
    for (index, &(metadata, body)) in sizes.iter().enumerate() {
        let (record, reservation) = write_record(
            &storage,
            &mut volume,
            &arena,
            &control,
            metadata,
            body,
            index as u64 + 10,
        );
        let before = submits(&control);
        let op = volume.read_raw(&record.read, u64::MAX).expect("admitted");
        let delivered = drive(&mut volume, &control, op);
        assert_eq!(delivered.status, ReadStatus::Complete, "{metadata}+{body}");
        assert_eq!(delivered.bytes, record.payload, "{metadata}+{body}");
        if record.layout.record_len() <= u64::from(BUFFER) {
            assert_eq!(submits(&control) - before, 1, "one device round trip");
        }
        assert!(
            storage
                .return_allocation(reservation.release(), &mut WorkBudget::new(64))
                .is_ok()
        );
    }
}

#[test]
fn a_flipped_chunk_byte_hands_off_only_earlier_chunks_and_an_unfinished_buffer_exposes_nothing() {
    let storage = storage(2);
    let arena = arena();
    let tick = TickConfig {
        validate_bytes: 3000,
        ..TICK
    };
    let (mut volume, control) = attach(&storage, &arena, tick);
    let record = record(0, 0, 4 * CHUNK, SESSION, 6);
    let mut forged = record.bytes.clone();
    forged[record.layout.header_bytes() + 2 * CHUNK as usize + 100] ^= 0x01;
    control.write_device(
        crate::storage::volume_fixture::device_byte(&storage, record.read.locator),
        &forged,
    );
    let op = volume.read_raw(&record.read, u64::MAX).expect("admitted");
    let mut out = Vec::with_capacity(8);
    let (mut exposed, mut status) = (Vec::new(), None);
    for _ in 0..64 {
        let tick = turn(&mut volume, &control, 8, &mut out);
        assert!(tick.validated_bytes <= 3000);
        for event in out.drain(..) {
            match event {
                ReadEvent::Chunk {
                    op: of,
                    range,
                    chunk,
                    ..
                } => {
                    assert_eq!(of, op);
                    let expected = &record.payload[range.start as usize..range.end as usize];
                    assert_eq!(chunk.bytes(), expected);
                    exposed.push(range);
                    volume.grant_read(op).expect("live");
                }
                ReadEvent::Done { status: ended, .. } => status = Some(ended),
            }
        }
        if status.is_some() {
            break;
        }
    }
    assert_eq!(status, Some(ReadStatus::ChunkMismatch { index: 2 }));
    // The first command's two windows hand off chunks 0 and 1 together.
    let chunk = |index| record.layout.chunk(index).expect("in range");
    assert_eq!(exposed.len(), 1);
    assert_eq!(exposed[0], chunk(0).start..chunk(1).end);
    assert_eq!(arena.report(PoolKind::ReadResponse).free, 4);
    let report = volume.report();
    assert_eq!((report.chunk_mismatch, report.header_mismatch), (1, 0));
}

/// Hint counting excludes the checksum paths: a byte budget of 320 keeps every folded piece under the x86 streaming mechanism's 384-byte threshold, and that mechanism is the one checksum path that hints.
#[test]
fn an_arrived_read_command_hints_its_first_two_lines_and_a_failed_one_hints_nothing() {
    let hints = || super::super::prefetch::READ_HINTS.with(std::cell::Cell::get);
    let storage = storage(2);
    let arena = arena();
    let tick = TickConfig {
        validate_bytes: 320,
        ..TICK
    };
    let (mut volume, control) = attach(&storage, &arena, tick);
    let two = record(3, 100, 2 * CHUNK + 5, SESSION, 1);
    place(&storage, &control, &two);
    let op = volume.read_raw(&two.read, u64::MAX).expect("admitted");
    let before = hints();
    let mut out = Vec::with_capacity(8);
    let mut status = None;
    for _ in 0..256 {
        turn(&mut volume, &control, 8, &mut out);
        for event in out.drain(..) {
            match event {
                ReadEvent::Chunk { op: of, .. } => {
                    assert_eq!(of, op);
                    // The last chunk's grant finds the operation ended.
                    let _ = volume.grant_read(op);
                }
                ReadEvent::Done { status: ended, .. } => status = Some(ended),
            }
        }
        if status.is_some() {
            break;
        }
    }
    assert_eq!(status, Some(ReadStatus::Complete));
    assert_eq!(submits(&control), 2);
    assert_eq!(hints() - before, 2 * 2, "two lines per arrived command");
    let failed = record(0, 0, CHUNK, SESSION, 7);
    place(&storage, &control, &failed);
    let op = volume.read_raw(&failed.read, u64::MAX).expect("admitted");
    control.fault(
        last_submitted(&control),
        Fault::Status(DeviceStatus::Kernel(-5)),
    );
    let before = hints();
    assert_eq!(
        drive(&mut volume, &control, op).status,
        ReadStatus::DeviceError
    );
    assert_eq!(hints() - before, 0);
}

#[test]
fn failed_and_short_reads_expose_nothing() {
    for (fault, expected) in [
        (Fault::Short { units: 1 }, ReadStatus::Short),
        (
            Fault::PartialReadFailure { sectors: 9 },
            ReadStatus::DeviceError,
        ),
        (
            Fault::Status(DeviceStatus::Kernel(-5)),
            ReadStatus::DeviceError,
        ),
    ] {
        let storage = storage(2);
        let arena = arena();
        let (mut volume, control) = attach(&storage, &arena, TICK);
        let record = record(0, 0, CHUNK, SESSION, 7);
        place(&storage, &control, &record);
        let op = volume.read_raw(&record.read, u64::MAX).expect("admitted");
        control.fault(last_submitted(&control), fault);
        let delivered = drive(&mut volume, &control, op);
        assert_eq!(delivered.status, expected, "{fault:?}");
        assert!(delivered.bytes.is_empty(), "{fault:?}");
        let report = volume.report();
        assert_eq!(report.reads_failed, 1);
        assert_eq!(report.short, u64::from(expected == ReadStatus::Short));
    }
}

#[test]
fn header_identity_mismatches_end_the_read_with_no_chunk() {
    let storage = storage(2);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let stale = record(0, 0, CHUNK, SESSION + 1, 8);
    place(&storage, &control, &stale);
    let op = volume.read_raw(&stale.read, u64::MAX).expect("admitted");
    let delivered = drive(&mut volume, &control, op);
    let session = HeaderMismatch::Session {
        expected: SESSION,
        found: SESSION + 1,
    };
    assert_eq!(delivered.status, ReadStatus::HeaderMismatch(session));
    assert!(delivered.bytes.is_empty());
    assert_eq!(volume.report().lookup_false_positives, 0);
    let current = record(0, 0, CHUNK, SESSION, 8);
    place(&storage, &control, &current);
    let other_key = RawRead {
        key: [0; 32],
        ..current.read
    };
    let op = volume.read_raw(&other_key, u64::MAX).expect("admitted");
    let delivered = drive(&mut volume, &control, op);
    assert_eq!(
        delivered.status,
        ReadStatus::HeaderMismatch(HeaderMismatch::Key)
    );
    assert!(delivered.bytes.is_empty());
    assert_eq!(volume.report().lookup_false_positives, 1);
    // A locator one unit short of the header's lengths fails on them.
    let short = RawRead {
        locator: ExtentLocator::new(PLACED, current.read.locator.len_units() - 1).expect("fits"),
        ..current.read
    };
    let op = volume.read_raw(&short, u64::MAX).expect("admitted");
    let delivered = drive(&mut volume, &control, op);
    assert_eq!(
        delivered.status,
        ReadStatus::HeaderMismatch(HeaderMismatch::Lengths {
            metadata_len: 0,
            body_len: CHUNK
        })
    );
    assert!(delivered.bytes.is_empty());
    let report = volume.report();
    assert_eq!(report.lookup_false_positives, 1);
    // Every header variant counts, the key one also as a false positive.
    assert_eq!((report.header_mismatch, report.chunk_mismatch), (3, 0));
}

/// Forged lengths that fill the locator's units end the read at the header,
/// with no chunk: a chunk count the lengths do not derive fails
/// `ChunkParameters`, and a body length that grows the chunk table moves the
/// crc span and, its verified length moved with it past `ExtentLength`,
/// fails `HeaderCrc`. A header longer than the first
/// command cannot arise here: attach sizes the command for the largest
/// header, and the read refuses a locator past the largest record.
#[test]
fn forged_header_lengths_end_the_read_before_any_payload_byte() {
    const BODY_LEN: usize = 76;
    const CHUNK_COUNT: usize = 84;
    const EXTENT_LEN: usize = 92;
    let storage = storage(2);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let mut counted = record(0, 0, CHUNK, SESSION, 9);
    let chunks = counted.layout.chunk_count() + 1;
    counted.bytes[CHUNK_COUNT..CHUNK_COUNT + 4].copy_from_slice(&chunks.to_le_bytes());
    let mut moved = record(8, 10, 3 * CHUNK - 11, SESSION, 10);
    moved.bytes[BODY_LEN..BODY_LEN + 4].copy_from_slice(&(3 * CHUNK - 9).to_le_bytes());
    moved.bytes[EXTENT_LEN..EXTENT_LEN + 4].copy_from_slice(&(3 * CHUNK + 1).to_le_bytes());
    for (forged, parameters) in [(&counted, true), (&moved, false)] {
        place(&storage, &control, forged);
        let op = volume.read_raw(&forged.read, u64::MAX).expect("admitted");
        let delivered = drive(&mut volume, &control, op);
        let status = delivered.status;
        if parameters {
            assert_eq!(
                status,
                ReadStatus::HeaderMismatch(HeaderMismatch::ChunkParameters {
                    chunk_len: CHUNK,
                    chunk_count: chunks
                })
            );
        } else {
            assert!(
                matches!(
                    status,
                    ReadStatus::HeaderMismatch(HeaderMismatch::HeaderCrc { .. })
                ),
                "{status:?}"
            );
        }
        assert!(delivered.bytes.is_empty());
    }
}

#[test]
fn one_tick_stays_within_every_burst_and_the_byte_budget_and_allocates_nothing() {
    let storage = storage(6);
    let arena = arena_with(8, 4);
    let tick = TickConfig {
        submit_burst: 2,
        terminal_burst: 3,
        validate_bytes: 10_000,
    };
    let (mut volume, control) = attach(&storage, &arena, tick);
    let records: Vec<Record> = (0..6)
        .map(|index| record(index * 16, 0, 3 * CHUNK, SESSION, 20 + index))
        .collect();
    let mut ops = Vec::new();
    for record in &records {
        place(&storage, &control, record);
        ops.push(volume.read_raw(&record.read, u64::MAX).expect("admitted"));
    }
    let mut out = Vec::with_capacity(32);
    let (mut done, mut validated) = (0, 0);
    // Ticks whose verification spent the whole byte budget, the witness that it binds.
    let mut spent = 0;
    for _ in 0..200 {
        let mut tick = || control.tick(8);
        let mut poll = || {
            let submitted_before = submits(&control);
            let allocations = crate::instrument::allocations();
            let ended_before = volume.report().reads_done + volume.report().reads_failed;
            let report = volume.poll_storage(0, &mut out);
            assert_eq!(crate::instrument::allocations(), allocations);
            let ended = volume.report().reads_done + volume.report().reads_failed - ended_before;
            assert!(ended <= 3, "{ended} terminals applied in one tick");
            assert!(report.submitted <= 2 && report.terminals <= 3);
            assert!(report.validated_bytes <= 10_000);
            spent += usize::from(report.validated_bytes == 10_000);
            validated += report.validated_bytes as u64;
            assert_eq!(volume.report().validated_bytes, validated);
            assert_eq!(
                submits(&control) - submitted_before,
                report.submitted as usize
            );
        };
        round(&mut [
            Act::new(Actor::Disk(0), &mut tick),
            Act::new(Actor::Volume(0), &mut poll),
        ]);
        for event in out.drain(..) {
            match event {
                // The last chunk's `Done` follows it in this output, which makes that grant stale.
                ReadEvent::Chunk { op, .. } => {
                    let _ = volume.grant_read(op);
                }
                ReadEvent::Done { status, .. } => {
                    assert_eq!(status, ReadStatus::Complete);
                    done += 1;
                }
            }
        }
        if done == ops.len() {
            // Every header byte and every payload chunk was folded once.
            let folded: u64 = records
                .iter()
                .map(|record| (record.layout.header_bytes() + record.payload.len()) as u64)
                .sum();
            assert_eq!(validated, folded);
            assert!(spent > 0, "a tick spent the whole byte budget");
            return;
        }
    }
    panic!("reads did not finish\n{}", control.describe());
}

/// The burst-binding witness for the tick allowances: six reads, each granted while its first command is outstanding, so the tick that verifies a command submits the next one from the kept grant. With a byte budget above three commands, the first tick after the device returns them applies a whole terminal burst, and submits a whole submit burst, all in the one call.
#[test]
fn one_tick_applies_a_whole_terminal_burst_and_submits_a_whole_submit_burst() {
    let storage = storage(6);
    let arena = arena_with(8, 4);
    let tick = TickConfig {
        submit_burst: 2,
        terminal_burst: 3,
        validate_bytes: 1 << 20,
    };
    let (mut volume, control) = attach(&storage, &arena, tick);
    for index in 0..6 {
        let placed = record(index * 16, 0, 3 * CHUNK, SESSION, 30 + index);
        place(&storage, &control, &placed);
        let op = volume.read_raw(&placed.read, u64::MAX).expect("admitted");
        volume.grant_read(op).expect("live");
    }
    let mut out = Vec::with_capacity(32);
    let report = turn(&mut volume, &control, 8, &mut out);
    assert_eq!(
        (report.terminals, report.submitted),
        (tick.terminal_burst, tick.submit_burst),
        "{report:?}"
    );
    assert!(report.validated_bytes <= tick.validate_bytes);
}

#[test]
fn an_output_with_fewer_than_two_spare_slots_takes_no_terminal() {
    let storage = storage(2);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let record = record(0, 0, CHUNK, SESSION, 9);
    place(&storage, &control, &record);
    let op = volume.read_raw(&record.read, u64::MAX).expect("admitted");
    let mut narrow = Vec::with_capacity(1);
    let report = turn(&mut volume, &control, 8, &mut narrow);
    assert_eq!((report.terminals, narrow.capacity()), (0, 1));
    assert_eq!(
        volume.table_report().pending,
        1,
        "the terminal stays with the table"
    );
    let delivered = drive(&mut volume, &control, op);
    assert_eq!(delivered.status, ReadStatus::Complete);
}

fn completed(out: &[ReadEvent<'_>]) -> Vec<ReadOp> {
    out.iter()
        .filter_map(|event| match event {
            ReadEvent::Done {
                op,
                status: ReadStatus::Complete,
                ..
            } => Some(*op),
            _ => None,
        })
        .collect()
}

#[test]
fn each_tick_serves_operations_from_a_cursor_that_moves_only_on_a_call_that_serves() {
    let storage = storage(4);
    let arena = arena();
    let (first, second) = (
        record(0, 0, 100, SESSION, 51),
        record(2, 0, 100, SESSION, 52),
    );
    // The budget verifies exactly one of the two records per tick.
    let one = first.layout.header_bytes() + first.layout.payload_len() as usize;
    let tick = TickConfig {
        validate_bytes: one,
        ..TICK
    };
    let (mut volume, control) = attach(&storage, &arena, tick);
    place(&storage, &control, &first);
    place(&storage, &control, &second);
    let (a, b) = (
        volume.read_raw(&first.read, u64::MAX).expect("admitted"),
        volume.read_raw(&second.read, u64::MAX).expect("admitted"),
    );
    assert_eq!((a.slot, b.slot), (0, 1));
    let mut narrow = Vec::with_capacity(1);
    let mut tick = || control.tick(8);
    let mut poll = || assert_eq!(volume.poll_storage(0, &mut narrow), TickReport::default());
    round(&mut [
        Act::new(Actor::Disk(0), &mut tick),
        Act::new(Actor::Volume(0), &mut poll),
    ]);
    assert!(narrow.is_empty());
    assert_eq!(volume.cursor, 0, "the call without room kept the cursor");
    // The call that serves starts at slot 0, so slot 0 takes the whole budget.
    let mut out = Vec::with_capacity(8);
    let report = volume.poll_storage(0, &mut out);
    assert_eq!((report.terminals, report.validated_bytes), (2, one));
    assert_eq!(completed(&out), [a]);
    assert_eq!(out.len(), 2, "slot 1 hands off nothing");
    assert_eq!(volume.cursor, 1);
    out.clear();
    // The next call starts at slot 1.
    volume.poll_storage(0, &mut out);
    assert_eq!(completed(&out), [b]);
}

#[test]
fn held_chunks_exhaust_the_response_pool_and_a_live_read_waits_without_failing() {
    let storage = storage(2);
    let arena = arena_with(2, 2);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let first = record(0, 0, 5 * CHUNK, SESSION, 11);
    place(&storage, &control, &first);
    let op = volume.read_raw(&first.read, u64::MAX).expect("admitted");
    let mut out = Vec::with_capacity(8);
    let mut held = Vec::new();
    for _ in 0..8 {
        turn(&mut volume, &control, 8, &mut out);
        held.extend(out.drain(..).map(|event| match event {
            ReadEvent::Chunk { chunk, .. } => {
                volume.grant_read(op).expect("live");
                chunk
            }
            other => panic!("{other:?}"),
        }));
    }
    assert_eq!(held.len(), 2, "both buffers are held as chunks");
    assert_eq!(arena.report(PoolKind::ReadResponse).held_high_water, 2);
    assert_eq!(
        volume.read_raw(&first.read, u64::MAX),
        Err(ReadRefusal::PoolExhausted)
    );
    let (_reservation, set) = write_set(&storage, &mut volume, 1);
    let buffer = arena.acquire(PoolKind::ReceiveWrite).expect("free");
    write(&mut volume, set, buffer, 0).expect("a write submits while the read waits");
    drop(held);
    // Each held buffer carries two windows: chunks 0 and 1, then 2 and 3.
    let start = first.layout.chunk(3).expect("in range").end;
    let delivered = drive_from(&mut volume, &control, op, start);
    assert_eq!(delivered.status, ReadStatus::Complete);
    assert_eq!(delivered.bytes, first.payload[start as usize..]);
}

#[test]
fn attach_refuses_each_invalid_input_distinctly_and_attaches_once() {
    let arena = arena();
    let refuse = |storage: &Storage<TestPlatform>, depth: u16, tick: TickConfig| {
        // A device every storage here fits, so the geometry checks past the
        // device's capacity are the ones refused.
        let (disk, _control) = device_sized(1, 1 << 30);
        let mut budget = EngineBudget::new(1 << 24);
        let before = budget;
        let refused = Volume::attach(
            storage,
            &arena,
            disk,
            crate::storage::portable::scripted::ScriptedClock::trusted(),
            crate::storage::ServingAuthority::fixture(),
            depth,
            tick,
            &mut budget,
        )
        .err()
        .map(|(error, _)| error);
        assert_eq!(budget, before);
        refused
    };
    let storage = storage(2);
    for zero in [
        TickConfig {
            submit_burst: 0,
            ..TICK
        },
        TickConfig {
            terminal_burst: 0,
            ..TICK
        },
        TickConfig {
            validate_bytes: 0,
            ..TICK
        },
    ] {
        assert_eq!(
            refuse(&storage, DEPTH, zero),
            Some(AttachError::ZeroTickField),
            "{zero:?}"
        );
    }
    assert_eq!(
        refuse(&storage, 0, TICK),
        Some(AttachError::Table(TableError::ZeroDepth))
    );
    assert_eq!(
        refuse(&storage, 4, TICK),
        Some(AttachError::BurstAboveDepth { burst: 8, depth: 4 })
    );
    let small = TickConfig {
        submit_burst: 2,
        terminal_burst: 2,
        ..TICK
    };
    assert_eq!(
        refuse(&storage, 2, small),
        Some(AttachError::ReadCommandsOutOfRange {
            read_commands: 2,
            depth: 2
        })
    );
    let far = storage_reading_ahead_by(2, MAX_READ_AHEAD + 1);
    assert_eq!(
        refuse(&far, DEPTH, TICK),
        Some(AttachError::ReadAheadOutOfRange {
            read_ahead: MAX_READ_AHEAD + 1
        })
    );
    let wide = RecordConfig {
        chunk_len: 3 * 4096,
    };
    let wide = storage_with(2, wide).expect("valid");
    assert_eq!(
        refuse(&wide, DEPTH, TICK),
        Some(AttachError::ChunkLenNotDividingBuffer {
            chunk_len: 3 * 4096,
            buffer_len: BUFFER
        })
    );
    // Read-response buffers of half a window cannot hold the window that
    // carries the local header and the first payload chunk.
    let (disk, _control) = device_sized(1, 1 << 30);
    let mut budget = EngineBudget::new(1 << 24);
    let half_reads = arena_with_read_len(CHUNK / 2);
    let refused = Volume::attach(
        &storage,
        &half_reads,
        disk,
        crate::storage::portable::scripted::ScriptedClock::trusted(),
        crate::storage::ServingAuthority::fixture(),
        DEPTH,
        TICK,
        &mut budget,
    );
    assert_eq!(
        refused.err().map(|(error, _)| error),
        Some(AttachError::ReadCommandFit {
            needed: u64::from(CHUNK),
            limit: u64::from(CHUNK / 2)
        })
    );
    assert_eq!(budget, EngineBudget::new(1 << 24));
    let (disk, _control) = device(1);
    let mut tight = EngineBudget::new(64);
    let refused = Volume::attach(
        &storage,
        &arena,
        disk,
        crate::storage::portable::scripted::ScriptedClock::trusted(),
        crate::storage::ServingAuthority::fixture(),
        DEPTH,
        TICK,
        &mut tight,
    );
    let refused = refused.err().map(|(error, _)| error);
    assert!(matches!(refused, Some(AttachError::Envelope(_))));
    assert_eq!(tight.used(), 0);
    let (volume, _control) = attach(&storage, &arena, TICK);
    assert_eq!(
        refuse(&storage, DEPTH, TICK),
        Some(AttachError::AlreadyAttached)
    );
    assert_eq!(volume.release().map_err(|_| ()), Ok(Quiesced::AllReturned));
    assert_eq!(
        refuse(&storage, DEPTH, TICK),
        Some(AttachError::AlreadyAttached)
    );
    assert!(
        storage.volume_attached(),
        "a released volume leaves the bit set"
    );
    let mut storage = storage;
    assert_eq!(
        super::super::test_platform::finalize(&mut storage),
        Ok(super::super::finalize::Finalization::Drained)
    );
    assert!(
        !storage.volume_attached(),
        "a drained storage reports no attach"
    );
}

#[test]
fn attach_refuses_a_volume_larger_than_the_device() {
    let arena = arena();
    let record = RecordConfig { chunk_len: CHUNK };
    let refuse = |storage: &Storage<TestPlatform>, capacity: u64, depth: u16| {
        let (disk, _control) = device_sized(1, capacity);
        let mut budget = EngineBudget::new(1 << 24);
        let before = budget;
        let refused = Volume::attach(
            storage,
            &arena,
            disk,
            crate::storage::portable::scripted::ScriptedClock::trusted(),
            crate::storage::ServingAuthority::fixture(),
            depth,
            TICK,
            &mut budget,
        )
        .err()
        .map(|(error, disk)| {
            assert_eq!(
                super::super::device::Disk::geometry(&disk).capacity,
                capacity,
                "the refusal returns the driver"
            );
            error
        });
        assert_eq!(budget, before);
        refused
    };
    let over = CAPACITY as usize + IO_UNIT;
    let oversized = storage_on(
        over - crate::storage::TEST_METADATA_UNITS as usize * IO_UNIT,
        (2, 2, 0),
        record,
        BODY_CAP,
    )
    .expect("valid");
    assert_eq!(
        refuse(&oversized, CAPACITY, 0),
        Some(AttachError::Table(TableError::ZeroDepth))
    );
    let exceeds = Some(AttachError::VolumeExceedsDevice {
        raw_bytes: over as u64,
        capacity: CAPACITY,
    });
    assert_eq!(refuse(&oversized, CAPACITY, 4), exceeds);
    assert_eq!(refuse(&oversized, CAPACITY, DEPTH), exceeds);
    let (disk, _control) = device_sized(1, over as u64);
    let mut budget = EngineBudget::new(1 << 24);
    let volume = Volume::attach(
        &oversized,
        &arena,
        disk,
        crate::storage::portable::scripted::ScriptedClock::trusted(),
        crate::storage::ServingAuthority::fixture(),
        DEPTH,
        TICK,
        &mut budget,
    )
    .map_err(|(error, _)| error)
    .expect("a device of exactly the volume's bytes attaches");
    assert_eq!(volume.release().map_err(|_| ()), Ok(Quiesced::AllReturned));
}

/// The window that carries the largest local header and the first payload
/// chunk must fit one read command: a device whose largest transfer is half
/// a window refuses at attach, since the local header of a full extent lies
/// in its first window; a transfer of one window attaches.
#[test]
fn the_first_window_must_fit_one_read_command_at_attach() {
    let arena = arena_with(4, 4);
    let record = RecordConfig { chunk_len: CHUNK };
    let storage = storage_sized(2, record, 200_000).expect("valid");
    let attach_with = |max_transfer: u32| {
        let (disk, _control) = attached(SimConfig {
            seed: 1,
            capacity: 1 << 30,
            queue_depth: u32::from(DEPTH),
            max_transfer,
            form: StatusForm::Kernel,
            mode: Mode::Direct,
            script: crate::storage::device::sim::SCRIPT,
        });
        let mut budget = EngineBudget::new(1 << 24);
        Volume::attach(
            &storage,
            &arena,
            disk,
            crate::storage::portable::scripted::ScriptedClock::trusted(),
            crate::storage::ServingAuthority::fixture(),
            DEPTH,
            TICK,
            &mut budget,
        )
        .map_err(|(error, _)| error)
    };
    assert_eq!(
        attach_with(CHUNK / 2).err(),
        Some(AttachError::ReadCommandFit {
            needed: u64::from(CHUNK),
            limit: u64::from(CHUNK / 2)
        })
    );
    let volume = attach_with(CHUNK).expect("one window fits one command");
    assert_eq!(volume.release().map_err(|_| ()), Ok(Quiesced::AllReturned));
}

pub(super) fn arena_with_read_len(read_len: u32) -> BufferArena<TestPlatform> {
    arena_with_reads(2, read_len)
}

/// A buffer arena of `count` read-response buffers of `read_len` bytes.
pub(super) fn arena_with_reads(count: u32, read_len: u32) -> BufferArena<TestPlatform> {
    let pools = [
        PoolSpec {
            kind: PoolKind::ReadResponse,
            count,
            buffer_len: read_len,
        },
        PoolSpec {
            kind: PoolKind::ReceiveWrite,
            count: 2,
            buffer_len: BUFFER,
        },
        PoolSpec {
            kind: PoolKind::Maintenance,
            count: 1,
            buffer_len: 4096,
        },
    ];
    let validated = BufferConfig {
        hugepage: HugepageSize::TwoMiB,
        nodes: NodeMask::from_nodes(&[0]).expect("node 0"),
        pools: &pools,
    }
    .validate()
    .expect("valid");
    BufferArena::initialize(
        &validated,
        TestPlatform::heap(4096),
        &mut EngineBudget::new(usize::MAX),
    )
    .expect("arena")
}

#[test]
fn storage_validation_refuses_a_zero_read_share_and_each_record_error() {
    let refusal = |read_ops, chunk_len| storage_with(read_ops, RecordConfig { chunk_len }).err();
    assert_eq!(refusal(0, CHUNK), Some(ConfigError::ZeroReadOps));
    assert_eq!(
        refusal(1, 0),
        Some(ConfigError::Record(RecordConfigError::ZeroChunkLen))
    );
    assert_eq!(
        refusal(1, 100),
        Some(ConfigError::Record(
            RecordConfigError::ChunkLenNotUnitMultiple { chunk_len: 100 }
        ))
    );
}

#[test]
fn a_refused_read_or_write_owns_nothing() {
    let storage = storage(1);
    let arena = arena_with(1, 1);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let record = record(0, 0, CHUNK, SESSION, 12);
    for len_units in [0, 14] {
        let wrong_len = RawRead {
            locator: ExtentLocator::new(0, len_units).expect("fits"),
            ..record.read
        };
        assert_eq!(
            volume.read_raw(&wrong_len, u64::MAX),
            Err(ReadRefusal::Layout)
        );
    }
    control.refuse_next(SubmitRefusal {
        reason: RefusalReason::InvalidRange,
        code: None,
    });
    assert!(matches!(
        volume.read_raw(&record.read, u64::MAX),
        Err(ReadRefusal::Submit(_))
    ));
    assert_eq!(arena.report(PoolKind::ReadResponse).free, 1);
    assert_eq!(volume.table_report().pending, 0);
    volume
        .read_raw(&record.read, u64::MAX)
        .expect("the record and buffer were free");
    assert_eq!(
        volume.read_raw(&record.read, u64::MAX),
        Err(ReadRefusal::PoolExhausted)
    );
    let (reservation, set) = write_set(&storage, &mut volume, 1);
    let slot = reservation.id().slot_index();
    control.refuse_next(queue_full());
    let buffer = arena.acquire(PoolKind::ReceiveWrite).expect("free");
    let (buffer, refusal) = write(&mut volume, set, buffer, 0).expect_err("refused");
    assert!(matches!(refusal, Refusal::Device(_)));
    assert_eq!(volume.write_progress(set).expect("live").submitted_units, 0);
    assert_eq!(
        storage.live_pool().unwrap().refs(slot),
        0,
        "the right round-trips"
    );
    assert_eq!(volume.table_report().pending, 1);
    let report = volume.report();
    assert_eq!((report.reads_refused, report.writes_refused), (1, 1));
    assert_eq!((report.reads_submitted, report.writes_submitted), (1, 0));
    drop(buffer);
}

#[test]
fn an_unmapped_terminal_is_counted_stale_and_changes_nothing() {
    let storage = storage(2);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let record = record(0, 0, CHUNK, SESSION, 13);
    place(&storage, &control, &record);
    let op = volume.read_raw(&record.read, u64::MAX).expect("admitted");
    let token = last_submitted(&control);
    control.fault(token, Fault::DropCommand);
    let mut out = Vec::with_capacity(4);
    let mut tick = || control.tick(8);
    let inject = || {
        control.inject(
            Completion {
                token: CommandToken::from_raw(token.raw() + (1 << 16)),
                status: DeviceStatus::Kernel(4096),
            },
            super::super::device::sim::Injection::Foreign,
        )
    };
    let mut poll = || {
        inject();
        let _ = volume.poll_storage(0, &mut out);
    };
    round(&mut [
        Act::new(Actor::Disk(0), &mut tick),
        Act::new(Actor::Volume(0), &mut poll),
    ]);
    assert!(out.is_empty());
    assert_eq!(volume.report().stale, 1);
    assert_eq!(volume.table_report().pending, 1);
    let stale = ReadOp {
        generation: op.generation + 1,
        ..op
    };
    assert_eq!(volume.cancel_read(stale), Err(ControlRefusal::Stale));
    assert_eq!(volume.cancel_read(op), Ok(()));
}

#[test]
fn write_faults_fail_the_set_and_never_count_as_complete() {
    for fault in [
        Fault::Short { units: 1 },
        Fault::TornWrite { sectors: 3 },
        Fault::Status(DeviceStatus::Kernel(-5)),
    ] {
        let storage = storage(2);
        let arena = arena();
        let (mut volume, control) = attach(&storage, &arena, TICK);
        let (_reservation, set) = write_set(&storage, &mut volume, 4);
        let buffer = arena.acquire(PoolKind::ReceiveWrite).expect("free");
        write(&mut volume, set, buffer, 0).expect("submitted");
        control.fault(last_submitted(&control), fault);
        let mut out = Vec::with_capacity(2);
        turn_until(|| {
            turn(&mut volume, &control, 8, &mut out);
            volume.write_progress(set).expect("live").failed
        });
        let progress = volume.write_progress(set).expect("live");
        assert!(progress.failed, "{fault:?}");
        assert_eq!(progress.completed_units, 0, "{fault:?}");
        assert!(!progress.is_ready(), "{fault:?}");
        assert_eq!(volume.report().writes_failed, 1);
    }
}

#[test]
fn seeded_ticks_conserve_the_table_the_pools_and_every_command() {
    for seed in 0..8 {
        let storage = storage(3);
        let arena = arena_with(4, 3);
        let tick = TickConfig {
            submit_burst: 2,
            terminal_burst: 2,
            validate_bytes: 6000,
        };
        let (mut volume, control) = attach(&storage, &arena, tick);
        let mut rng = SplitMix64::new(seed);
        let records: Vec<Record> = (0..4)
            .map(|index| {
                let body = (1 + rng.below(4) as u32) * CHUNK - 7;
                record(index * 16, 0, body, SESSION, seed * 10 + index)
            })
            .collect();
        for record in &records {
            place(&storage, &control, record);
        }
        let mut live: Vec<ReadOp> = Vec::new();
        let mut out = Vec::with_capacity(8);
        let mut chunks = Vec::new();
        for step in 0..400 {
            let at = format!("seed {seed} step {step}");
            match rng.below(6) {
                0 | 1 if step < 300 => {
                    let record = &records[rng.below(4) as usize];
                    if let Ok(op) = volume.read_raw(&record.read, u64::MAX) {
                        live.push(op);
                    }
                }
                2 if !live.is_empty() => {
                    let op = live[rng.below(live.len() as u64) as usize];
                    let _ = volume.cancel_read(op);
                }
                3 if step < 300 => {
                    // A reservation whose write set submits one command and
                    // ends; its drop abandons the extent, which service
                    // returns once the command's terminal released the right.
                    let _ = storage.service(&mut WorkBudget::new(1 << 10));
                    if let Ok(reservation) =
                        storage.reserve(Some(0), Some(IO_UNIT), &mut WorkBudget::new(64))
                        && let Some(set) = volume.begin_fill(
                            reservation.id(),
                            reservation.locator(),
                            reservation.locator().len_units(),
                            &ATTEMPT,
                            ATTEMPT_SERIAL,
                        )
                    {
                        if let Ok(buffer) = arena.acquire(PoolKind::ReceiveWrite) {
                            let _ = volume.write_at(set, buffer, 0);
                        }
                        volume.end_fill(set);
                        drop(reservation);
                    }
                }
                _ => chunks.clear(),
            }
            turn(&mut volume, &control, 1 + rng.below(4) as u32, &mut out);
            for event in out.drain(..) {
                match event {
                    ReadEvent::Chunk { op, chunk, .. } => {
                        assert!(live.contains(&op), "a Chunk after its Done, {at}");
                        chunks.push(chunk);
                    }
                    ReadEvent::Done { op, .. } => {
                        assert!(live.contains(&op), "a second Done, {at}");
                        live.retain(|live| *live != op);
                    }
                }
            }
            let table = volume.table_report();
            let slots = table.free_slots + table.pending + table.abandoned + table.retired;
            assert_eq!(slots, u32::from(DEPTH), "{at}");
            let (mut storage, mut quarantined) = (0, 0);
            for kind in [PoolKind::ReadResponse, PoolKind::ReceiveWrite] {
                let pool = arena.report(kind);
                let census = pool.free + pool.application + pool.storage + pool.quarantined;
                assert_eq!(census, pool.count, "{at}");
                storage += pool.storage;
                quarantined += pool.quarantined;
            }
            assert_eq!(
                table.pending + table.abandoned,
                storage + quarantined,
                "{at}"
            );
            assert_eq!(table.abandoned, quarantined, "{at}");
            let held = arena.report(PoolKind::ReadResponse).application;
            assert!(chunks.len() as u32 <= held, "{at}");
            let report = volume.report();
            let reads = (
                control.accepted(Operation::Read),
                control.delivered(Operation::Read),
            );
            let writes = (
                control.accepted(Operation::Write),
                control.delivered(Operation::Write),
            );
            assert_eq!(report.reads_submitted as usize, reads.0, "{at}");
            let reads_ended = (report.reads_done + report.reads_failed) as usize;
            assert_eq!(reads_ended, reads.1, "{at}");
            assert_eq!(report.writes_submitted as usize, writes.0, "{at}");
            let writes_ended = (report.writes_done + report.writes_failed) as usize;
            assert_eq!(writes_ended, writes.1, "{at}");
            assert!(
                reads.0 - reads.1 <= 3,
                "reads hold at most read_ops slots, {at}"
            );
        }
        assert!(
            live.is_empty(),
            "every admitted read ended once, seed {seed}"
        );
    }
}

#[test]
fn commands_stay_within_a_max_transfer_below_the_buffer_length() {
    let storage = storage(2);
    let arena = arena();
    let (disk, control) = attached(SimConfig {
        seed: 3,
        capacity: 1 << 22,
        queue_depth: u32::from(DEPTH),
        max_transfer: 12288,
        form: StatusForm::Kernel,
        mode: Mode::Direct,
        script: crate::storage::device::sim::SCRIPT,
    });
    let mut budget = EngineBudget::new(1 << 24);
    let mut volume = Volume::attach(
        &storage,
        &arena,
        disk,
        crate::storage::portable::scripted::ScriptedClock::trusted(),
        crate::storage::ServingAuthority::fixture(),
        DEPTH,
        TICK,
        &mut budget,
    )
    .map_err(|(error, _)| error)
    .expect("attach");
    bootstrap(&mut volume, &control);
    let layout = storage.record.layout(0, 3 * CHUNK + 5);
    let reservation = storage
        .reserve(
            Some(0),
            Some(3 * CHUNK as usize + 5),
            &mut WorkBudget::new(64),
        )
        .expect("an extent");
    let record = record_at(
        reservation.locator().start_unit(),
        0,
        3 * CHUNK + 5,
        SESSION,
        31,
    );
    assert_eq!(record.read.locator, reservation.locator());
    assert_eq!(record.layout, layout);
    let set = volume
        .begin_fill(
            reservation.id(),
            reservation.locator(),
            reservation.locator().len_units(),
            &ATTEMPT,
            ATTEMPT_SERIAL,
        )
        .expect("a set");
    let mut offset = 0;
    let mut out = Vec::with_capacity(8);
    while offset < record.bytes.len() {
        let mut buffer = arena.acquire(PoolKind::ReceiveWrite).expect("free");
        let len = (record.bytes.len() - offset).min(buffer.capacity());
        buffer.bytes_mut()[..len].copy_from_slice(&record.bytes[offset..offset + len]);
        let written = write(&mut volume, set, buffer, (offset / IO_UNIT) as u32)
            .map_err(|(_, refusal)| refusal);
        let expected = (record.bytes.len() - offset).min(12288) as u32;
        assert_eq!(written, Ok(expected));
        offset += expected as usize;
        turn_until(|| {
            turn(&mut volume, &control, 8, &mut out);
            volume.write_progress(set).expect("live").outstanding_units == 0
        });
    }
    assert!(volume.write_progress(set).expect("live").is_ready());
    let op = volume.read_raw(&record.read, u64::MAX).expect("admitted");
    let delivered = drive(&mut volume, &control, op);
    assert_eq!(delivered.status, ReadStatus::Complete);
    assert_eq!(delivered.bytes, record.payload);
    assert_eq!(delivered.ranges.len(), 4, "one chunk per 12 KiB command");
}

/// WRITE-ROOM: with no metadata command staged, writes hold every slot of the write share,
/// `depth - read_commands - metadata_commands`, and the metadata slot, then
/// refuse the next write `TableFull` with its buffer back and the set
/// unchanged, while the table still has the read share free.
#[test]
fn a_full_write_room_refuses_a_write_with_its_buffer_back() {
    let storage = storage(2);
    let arena = arena_with(2, 9);
    let (mut volume, _control) = attach(&storage, &arena, TICK);
    assert_eq!(volume.write_share(), u32::from(DEPTH) - 3);
    assert_eq!(
        volume.write_room(),
        u32::from(DEPTH) - 2,
        "the write share and the unclaimed metadata slot"
    );
    let (_first, set) = write_set(&storage, &mut volume, 13);
    for offset in 0..3 {
        let buffer = arena.acquire(PoolKind::ReceiveWrite).expect("free");
        write(&mut volume, set, buffer, offset * 4).expect("a free table slot");
    }
    let mut others = Vec::new();
    // Two read commands leave the writes `DEPTH - 2` slots while no metadata command claims its slot.
    for _ in 3..DEPTH - 2 {
        let (reservation, other) = write_set(&storage, &mut volume, 1);
        let buffer = arena.acquire(PoolKind::ReceiveWrite).expect("free");
        write(&mut volume, other, buffer, 0).expect("a free table slot");
        others.push(reservation);
    }
    let before = volume.write_progress(set).expect("live");
    assert_eq!(
        before.outstanding_units, 12,
        "three outstanding commands of four units"
    );
    let buffer = arena.acquire(PoolKind::ReceiveWrite).expect("free");
    let (buffer, refusal) = write(&mut volume, set, buffer, 12).expect_err("full");
    assert_eq!(refusal, Refusal::TableFull { abandoned: 0 });
    assert_eq!(volume.write_progress(set).expect("live"), before);
    assert_eq!(arena.report(PoolKind::ReceiveWrite).application, 1);
    assert_eq!(volume.write_room(), 0);
    assert_eq!(
        volume.table_report().free_slots,
        2,
        "the read share stays free"
    );
    drop(buffer);
}

/// WRITE-ROOM: a unit command staged while writes hold the metadata slot
/// lowers the write room at once and stays staged, with the read share free,
/// until a write reaches its terminal; the tick that applies that terminal
/// submits the command, and the writes take the slot again only after the
/// command ended.
#[test]
fn a_staged_metadata_command_takes_its_slot_back_at_a_write_terminal() {
    use super::super::checkpoint::PossiblyNamed;
    use super::super::volume_fixture::step;
    use super::checkpoint::UnitDone;

    let storage = storage(2);
    let arena = arena_with(2, 9);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let (_first, set) = write_set(&storage, &mut volume, 13);
    let mut held = Vec::new();
    for offset in 0..3 {
        let buffer = arena.acquire(PoolKind::ReceiveWrite).expect("free");
        write(&mut volume, set, buffer, offset * 4).expect("a free table slot");
        held.push(last_submitted(&control));
    }
    let mut others = Vec::new();
    for _ in 3..DEPTH - 2 {
        let (reservation, other) = write_set(&storage, &mut volume, 1);
        let buffer = arena.acquire(PoolKind::ReceiveWrite).expect("free");
        write(&mut volume, other, buffer, 0).expect("a free table slot");
        held.push(last_submitted(&control));
        others.push(reservation);
    }
    for token in &held {
        control.hold(*token);
    }
    assert_eq!(volume.write_room(), 0, "the writes hold the metadata slot");
    let possible = PossiblyNamed::new(
        (crate::net::ownership::Shard::new(7).unwrap(), 2),
        super::placement_tests::test_layout(),
        None,
    );
    volume.stage_unit_read(&possible, (0, 0)).expect("staged");
    let submitted = volume.report().metadata_submitted;
    let mut out = Vec::with_capacity(16);
    step(&mut volume, &control, &mut out);
    assert_eq!(
        volume.report().metadata_submitted,
        submitted,
        "a write holds the command's slot"
    );
    assert_eq!(
        volume.table_report().free_slots,
        2,
        "the read share stays free while the command waits"
    );
    control.release(held.pop().expect("a held write"));
    step(&mut volume, &control, &mut out);
    assert_eq!(
        volume.report().metadata_submitted,
        submitted + 1,
        "the command takes the slot the write's terminal freed"
    );
    assert_eq!(volume.write_room(), 0, "a claimed slot admits no write");
    let (_late, late) = write_set(&storage, &mut volume, 1);
    let buffer = arena.acquire(PoolKind::ReceiveWrite).expect("free");
    let (buffer, refusal) = write(&mut volume, late, buffer, 0).expect_err("claimed");
    assert_eq!(refusal, Refusal::TableFull { abandoned: 0 });
    let done = (0..100).find_map(|_| {
        step(&mut volume, &control, &mut out);
        volume.take_unit()
    });
    assert_eq!(done, Some(UnitDone::Read { slot: 0, unit: 0 }));
    assert_eq!(
        volume.write_room(),
        1,
        "the ended command returns its slot to the writes"
    );
    write(&mut volume, late, buffer, 0).expect("the returned slot");
}

#[test]
fn corrupted_bytes_in_a_later_command_end_the_read_at_its_first_chunk() {
    let storage = storage(2);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let record = record(0, 0, 3 * CHUNK, SESSION, 32);
    place(&storage, &control, &record);
    let op = volume.read_raw(&record.read, u64::MAX).expect("admitted");
    let mut out = Vec::with_capacity(8);
    turn_until(|| {
        turn(&mut volume, &control, 8, &mut out);
        !out.is_empty()
    });
    assert_eq!(out.len(), 1, "the first command's chunk was handed off");
    volume.grant_read(op).expect("live");
    control.fault(last_submitted(&control), Fault::CorruptSuccess);
    // The first command's two windows held chunks 0 and 1.
    let start = record.layout.chunk(1).expect("in range").end;
    let delivered = drive_from(&mut volume, &control, op, start);
    assert_eq!(delivered.status, ReadStatus::ChunkMismatch { index: 2 });
    assert!(
        delivered.bytes.is_empty(),
        "nothing of the corrupted command is exposed"
    );
}

#[test]
fn a_permanent_device_refusal_of_a_later_command_ends_the_read() {
    let storage = storage(2);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let record = record(0, 0, 3 * CHUNK, SESSION, 33);
    place(&storage, &control, &record);
    let op = volume.read_raw(&record.read, u64::MAX).expect("admitted");
    control.refuse_next(SubmitRefusal {
        reason: RefusalReason::InvalidRange,
        code: None,
    });
    let delivered = drive(&mut volume, &control, op);
    assert_eq!(delivered.status, ReadStatus::DeviceError);
    let first = record.layout.chunk(1).expect("in range").end as usize;
    assert_eq!(delivered.bytes, record.payload[..first]);
}

#[test]
fn a_full_device_queue_ends_the_ticks_submit_attempts() {
    let storage = storage(4);
    let arena = arena_with(8, 4);
    let tick = TickConfig {
        submit_burst: 1,
        ..TICK
    };
    let (mut volume, control) = attach(&storage, &arena, tick);
    let records: Vec<_> = (0..4)
        .map(|index| record(index * 16, 0, 2 * CHUNK, SESSION, 40 + index))
        .collect();
    for record in &records {
        place(&storage, &control, record);
    }
    let ops: Vec<_> = records
        .iter()
        .map(|record| volume.read_raw(&record.read, u64::MAX).expect("admitted"))
        .collect();
    // Grants made while each first command is outstanding admit the second.
    for op in &ops {
        volume.grant_read(*op).expect("live");
    }
    let refused = |control: &SimControl| {
        control
            .events()
            .iter()
            .filter(|event| matches!(event, Event::Refused { .. }))
            .count()
    };
    let mut out = Vec::with_capacity(8);
    let (mut before, mut report, mut armed) = (0, None, false);
    turn_until(|| {
        let mut tick = || control.tick(8);
        let mut poll = || {
            if !armed {
                for _ in &records {
                    control.refuse_next(queue_full());
                }
                armed = true;
            }
            before = refused(&control);
            report = Some(volume.poll_storage(0, &mut out));
        };
        round(&mut [
            Act::new(Actor::Disk(0), &mut tick),
            Act::new(Actor::Volume(0), &mut poll),
        ]);
        refused(&control) > before
    });
    let report = report.expect("the round polled the volume");
    assert_eq!(report.submitted, 0);
    assert_eq!(
        refused(&control) - before,
        1,
        "once the device queue refuses a command, the tick attempts no further submit"
    );
    let mut payloads = vec![Vec::new(); ops.len()];
    let mut statuses = vec![None; ops.len()];
    for _ in 0..64 {
        for event in out.drain(..) {
            match event {
                ReadEvent::Chunk { op, chunk, .. } => {
                    let at = ops.iter().position(|of| *of == op).expect("a live op");
                    payloads[at].extend_from_slice(chunk.bytes());
                }
                ReadEvent::Done { op, status, .. } => {
                    let at = ops.iter().position(|of| *of == op).expect("a live op");
                    assert_eq!(statuses[at].replace(status), None, "one Done per op");
                }
            }
        }
        if statuses.iter().all(Option::is_some) {
            break;
        }
        turn(&mut volume, &control, 8, &mut out);
    }
    for (at, record) in records.iter().enumerate() {
        assert_eq!(statuses[at], Some(ReadStatus::Complete), "read {at}");
        assert_eq!(payloads[at], record.payload, "read {at}");
    }
}

#[test]
fn the_ready_set_counts_its_members_and_finds_the_lowest_in_any_range() {
    let mut rng = SplitMix64::new(41);
    for count in [1u32, 5, 64, 65, 130] {
        let mut ready = SlotSet::new(count);
        let mut model = vec![false; count as usize];
        assert!(!ready.any(), "count {count}");
        for step in 0..400 {
            let slot = rng.below(u64::from(count)) as u32;
            let member = rng.below(2) == 0;
            ready.set(slot, member);
            model[slot as usize] = member;
            let from = rng.below(u64::from(count) + 1) as u32;
            let end = from + rng.below(u64::from(count - from) + 1) as u32;
            let expected = (from..end).find(|&slot| model[slot as usize]);
            assert_eq!(ready.next(from, end), expected, "count {count} step {step}");
            let members = model.iter().filter(|&&member| member).count() as u32;
            assert_eq!(ready.members(), members, "count {count} step {step}");
            assert_eq!(ready.any(), members != 0, "count {count} step {step}");
        }
        let mut order: Vec<u32> = (0..count).collect();
        for at in (1..order.len()).rev() {
            order.swap(at, rng.below(at as u64 + 1) as usize);
        }
        for slot in order {
            for _ in 0..2 {
                ready.set(slot, false);
                model[slot as usize] = false;
                let members = model.iter().filter(|&&member| member).count() as u32;
                assert_eq!(ready.members(), members, "count {count} clear {slot}");
                assert_eq!(ready.any(), members != 0, "count {count} clear {slot}");
            }
        }
        assert_eq!(ready.next(0, count), None, "count {count}");
    }
}

/// A write set's slot must index the volume's own slot table: `begin_fill`
/// refuses an identity past it, the bound every later write and terminal of
/// the set relies on.
#[test]
#[should_panic(expected = "a fill's slot outside the volume's storage")]
fn a_write_set_outside_the_storage_s_slot_table_is_refused() {
    use super::super::allocation::AllocationId;
    use super::super::tables::SlotIndex;
    let storage = storage(2);
    let arena = arena();
    let (mut volume, _control) = attach(&storage, &arena, TICK);
    let slots = storage.live_pool().unwrap().records().len();
    let locator = ExtentLocator::new(0, 1).expect("fits");
    let _ = volume.begin_fill(
        AllocationId::new(SlotIndex(slots), 1),
        locator,
        locator.len_units(),
        &ATTEMPT,
        ATTEMPT_SERIAL,
    );
}

crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
    a_flipped_chunk_byte_hands_off_only_earlier_chunks_and_an_unfinished_buffer_exposes_nothing,
    a_full_device_queue_ends_the_ticks_submit_attempts,
    a_permanent_device_refusal_of_a_later_command_ends_the_read,
    a_read_ends_at_its_record_s_last_sector_and_a_short_tail_mismatches_its_lengths,
    an_arrived_read_command_hints_its_first_two_lines_and_a_failed_one_hints_nothing,
    an_output_with_fewer_than_two_spare_slots_takes_no_terminal,
    an_unmapped_terminal_is_counted_stale_and_changes_nothing,
    commands_stay_within_a_max_transfer_below_the_buffer_length,
    corrupted_bytes_in_a_later_command_end_the_read_at_its_first_chunk,
    each_tick_serves_operations_from_a_cursor_that_moves_only_on_a_call_that_serves,
    failed_and_short_reads_expose_nothing,
    forged_header_lengths_end_the_read_before_any_payload_byte,
    header_identity_mismatches_end_the_read_with_no_chunk,
    held_chunks_exhaust_the_response_pool_and_a_live_read_waits_without_failing,
    one_tick_stays_within_every_burst_and_the_byte_budget_and_allocates_nothing,
    s1_a_write_set_is_ready_only_after_every_write_succeeded,
    s2_a_hit_read_delivers_verified_chunks_then_complete,
    s3_cancel_holds_the_record_and_buffer_until_the_real_terminal_while_a_write_proceeds,
    s5_a_held_command_does_not_block_another_operation,
    seeded_records_round_trip_at_unit_chunk_and_buffer_boundaries,
    seeded_ticks_conserve_the_table_the_pools_and_every_command,
    write_faults_fail_the_set_and_never_count_as_complete,
);

/// The recovery times take their origin from the attach's first tick: a volume closed before any tick stamps its
/// initialization start at the recorder's default clock, a time no tick gave, and keeps no origin after a later poll;
/// one polled first at tick 0 has its origin at 0.
#[test]
fn a_close_before_the_first_tick_leaves_the_times_without_an_origin() {
    for first in [None, Some(0)] {
        let storage = storage(2);
        let arena = arena();
        let (disk, _control) = device(7);
        let mut volume = Volume::attach(
            &storage,
            &arena,
            disk,
            crate::storage::portable::scripted::ScriptedClock::trusted(),
            crate::storage::ServingAuthority::fixture(),
            DEPTH,
            TICK,
            &mut EngineBudget::new(1 << 24),
        )
        .map_err(|(error, _)| error)
        .expect("attach");
        if let Some(now) = first {
            let _ = volume.poll_storage(now, &mut Vec::with_capacity(16));
        }
        let _ = volume.close();
        assert_eq!(volume.recovery_timed(), first.is_some(), "{first:?}");
        assert_eq!(
            volume
                .recovery_report()
                .phase(super::RecoveryPhase::Initialization)
                .start,
            Some(0),
            "{first:?}: the start is stamped at 0"
        );
        let _ = volume.poll_storage(500, &mut Vec::with_capacity(16));
        assert_eq!(
            volume.recovery_timed(),
            first.is_some(),
            "{first:?}: a drain poll after the close gives no origin"
        );
    }
}
