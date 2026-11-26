//! Reads of objects of several extents: a published sequence object built
//! by storage-level placement, each extent's record written by the
//! fixture, read through the volume under one right. Cases: exact bytes
//! with and without commands ahead crossing extent boundaries, buffers
//! large enough that a whole extent fits the commands ahead, nonzero
//! metadata, a busy pool gate at a boundary, a checksum-valid later extent
//! naming another context at each later index, a short or failed command
//! at a boundary, first headers whose lengths name another extent count, and a cancel with commands ahead across the boundary
//! that drains device and response-buffer custody separately. A planted
//! extent of other bytes, sealed with valid crcs, shows the exact-bytes
//! oracle rejects substituted payload.

use std::sync::atomic::Ordering;

use super::config::StorageConfig;
use super::device::sim::{Event as SimEvent, Fault, SimControl};
use super::device::{DeviceStatus, Operation, PoolKind, RefusalReason, SubmitRefusal};
use super::geometry::EXTENT_PAYLOAD;
use super::layout::IO_UNIT;
use super::lease::ExtentLease;
use super::owner::Storage;
use super::placement::PlacementConfig;
use super::record::{
    Crc32c, ExtentPosition, HeaderMismatch, RecordConfig, RecordIdentity, encode_header,
};
use super::sequence_tests::{Object, built_for};
use super::test_platform::TestPlatform;
use super::volume::{Grant, ReadEvent, ReadOp, ReadStatus, VerifiedReadInfo};
use super::volume_fixture::{
    BUFFER, Device, SESSION, arena, arena_sized, attach_with, place, settle, step,
};
use super::word;
use super::{AllocationId, ExtentReservation, Resident, WorkBudget};

const KEY: [u8; 32] = [0x3c; 32];
/// The payload of an object's last extent, metadata included.
pub(crate) const LAST: usize = 100;
/// The storage's metadata cap.
pub(crate) const METADATA: usize = 40;

/// A storage of 768 units whose largest object has three extents, with one
/// arena root, `read_ahead` commands ahead per read and a read share of
/// four commands.
pub(crate) fn storage(read_ahead: u8) -> Storage<TestPlatform> {
    storage_of(read_ahead, 2)
}

fn storage_of(read_ahead: u8, read_ops: u32) -> Storage<TestPlatform> {
    let units = 768;
    let mut volume = crate::storage::test_volume(units * IO_UNIT, 4);
    volume.alloc_search_words = crate::storage::work_bound(units as u64, 4, 64);
    volume.block_roots = 1;
    volume.read_ahead = read_ahead;
    volume.read_ops = read_ops;
    // Room for the current command and every command ahead.
    volume.read_commands = 4;
    let config = StorageConfig {
        page_size: 4096,
        engine_budget: 1 << 26,
        body_cap: 2 * EXTENT_PAYLOAD as usize + LAST,
        metadata_cap: Some(METADATA),
        lease_limit: 8,
        object_rights: 8,
        reader_limit: 2,
        volume,
    };
    Storage::initialize(
        &config.validate().unwrap(),
        &PlacementConfig { control_home: 0 },
        TestPlatform::heap(4096),
    )
    .unwrap()
}

pub(crate) fn budget() -> WorkBudget {
    WorkBudget::new(1 << 20)
}

/// The payload of an object of `count` extents, metadata first when it has
/// any: a byte pattern that changes every unit.
fn payload(count: u32) -> Vec<u8> {
    let len = (count as usize - 1) * EXTENT_PAYLOAD as usize + LAST;
    (0..len)
        .map(|at| (at % 251) as u8 ^ (at / 4096) as u8)
        .collect()
}

/// A change to an extent's identity and the mismatch it must produce.
type Change = (fn(&mut RecordIdentity), fn(HeaderMismatch) -> bool);

/// What the fixture writes differently at one extent.
#[derive(Clone, Copy)]
pub(crate) enum Plant {
    /// Seals the extent under the identity `change` makes.
    Identity(u32, fn(&mut RecordIdentity)),
    /// Seals the extent over other payload bytes, with valid crcs.
    Bytes(u32),
    /// Seals the first extent under whole lengths one extent shorter.
    Fewer,
}

/// A published object.
struct Published<'s> {
    resident: Resident<'s, TestPlatform>,
    lease: ExtentLease<'s, TestPlatform>,
    object: Object,
    payload: Vec<u8>,
}

/// A published object of `count` extents with `metadata` bytes of
/// metadata, built by storage-level placement, each extent's record
/// written by [`planted`]; `plant` writes one extent differently.
fn published<'s>(
    storage: &'s Storage<TestPlatform>,
    control: &SimControl,
    count: u32,
    metadata: usize,
    plant: Option<Plant>,
) -> Published<'s> {
    let mut owner: ExtentReservation<'s, TestPlatform> = storage
        .reserve(Some(metadata), Some(LAST - metadata), &mut budget())
        .unwrap();
    owner.mark_written();
    let id = owner.id();
    let completed = owner.complete(KEY, u64::MAX, &mut budget()).ok().unwrap();
    let (resident, lease) = completed.handoff(&mut budget()).ok().unwrap();
    let (object, payload) = planted(storage, control, id, KEY, count, metadata, plant);
    Published {
        resident,
        lease,
        object,
        payload,
    }
}

/// The payload of the object [`planted`] builds for `id`: see there.
pub(crate) fn plant_sequence(
    storage: &Storage<TestPlatform>,
    control: &SimControl,
    id: AllocationId,
    key: [u8; 32],
    count: u32,
    metadata: usize,
    plant: Option<Plant>,
) -> Vec<u8> {
    planted(storage, control, id, key, count, metadata, plant).1
}

/// Extends the published object `id` names under `key`, whose one extent
/// holds the last [`LAST`] bytes of the payload, to `count` extents and
/// writes each extent's record at its locator with its own header: the
/// whole lengths, its index and its offset. `plant` writes one extent
/// differently. Returns the object and its payload, whose first `metadata`
/// bytes are metadata.
fn planted(
    storage: &Storage<TestPlatform>,
    control: &SimControl,
    id: AllocationId,
    key: [u8; 32],
    count: u32,
    metadata: usize,
    plant: Option<Plant>,
) -> (Object, Vec<u8>) {
    let object = built_for(storage, id, count, count);
    {
        let mut access = storage.live_pool().unwrap().lock().unwrap();
        access
            .tables()
            .publish_payload((count as usize - 1) * EXTENT_PAYLOAD as usize);
    }
    let payload = payload(count);
    let config = RecordConfig { chunk_len: 8192 }.validate().unwrap();
    let (m, b) = (metadata as u32, (payload.len() - metadata) as u32);
    for (index, locator) in object.extents.iter().enumerate() {
        let offset = index * EXTENT_PAYLOAD as usize;
        let end = (offset + EXTENT_PAYLOAD as usize).min(payload.len());
        let whole = match plant {
            Some(Plant::Fewer) if index == 0 => b - EXTENT_PAYLOAD as u32,
            _ => b,
        };
        let layout = config.extent_layout(m, whole, (end - offset) as u64);
        let mut bytes = vec![0; layout.record_units() as usize * IO_UNIT];
        let header = layout.header_bytes();
        bytes[header..header + end - offset].copy_from_slice(&payload[offset..end]);
        let mut identity = RecordIdentity {
            key,
            allocation: id.record_tag(),
            session: SESSION,
            version: 0,
        };
        match plant {
            Some(Plant::Identity(at, change)) if at as usize == index => change(&mut identity),
            Some(Plant::Bytes(at)) if at as usize == index => bytes[header] ^= 0xff,
            _ => {}
        }
        let position = ExtentPosition {
            index: index as u32,
            offset: offset as u64,
        };
        encode_header(Crc32c::detect(), &layout, &identity, position, &mut bytes).unwrap();
        place(storage, control, *locator, &bytes);
    }
    (object, payload)
}

/// The rights the object's slot counts.
fn rights(storage: &Storage<TestPlatform>, object: &Object) -> usize {
    let slot = object.owner.slot_index();
    word::refs(
        storage.live_pool().unwrap().records()[slot]
            .ident
            .load(Ordering::Acquire),
    )
}

/// Commands each extent's record needs at `span` bytes a command, for an
/// object of `len` payload bytes with `metadata` bytes of metadata.
pub(crate) fn commands(len: usize, metadata: usize, span: u32) -> Vec<u64> {
    let config = RecordConfig { chunk_len: 8192 }.validate().unwrap();
    let (m, b) = (metadata as u32, (len - metadata) as u32);
    (0..len.div_ceil(EXTENT_PAYLOAD as usize))
        .map(|index| {
            let start = index as u64 * EXTENT_PAYLOAD;
            let payload = (len as u64 - start).min(EXTENT_PAYLOAD);
            let record = config.extent_layout(m, b, payload).record_len();
            record.div_ceil(u64::from(span))
        })
        .collect()
}

/// Commands the first extent's record needs at `span` bytes a command.
fn first_commands(len: usize, metadata: usize, span: u32) -> u64 {
    commands(len, metadata, span)[0]
}

/// What one read through [`read_through`] saw.
struct Seen {
    bytes: Vec<u8>,
    info: Option<VerifiedReadInfo>,
    status: ReadStatus,
    /// The read submitted more commands than the first extent's record
    /// needs while that extent's bytes were still undelivered, which only a
    /// command ahead in the second extent makes.
    crossed: bool,
    /// The most commands the device held at once.
    peak: usize,
}

/// Ticks the read `op`, whose bytes before payload offset `start` were
/// taken, to its `Done`, granting a command after each chunk until a grant
/// reports the read exhausted, and none after, as a network read does: its
/// bytes in order with one whole-object information. A grant reports the
/// read exhausted only once it submitted every command, `total` of them.
/// `commands` is the first extent's command count.
fn read_through(
    device: &mut Device<'_, '_>,
    op: ReadOp,
    start: u64,
    (commands, total): (u64, u64),
) -> Seen {
    let mut out = Vec::with_capacity(16);
    let mut seen = Seen {
        bytes: Vec::new(),
        info: None,
        status: ReadStatus::Quiesced,
        crossed: false,
        peak: 0,
    };
    let mut exhausted = false;
    for _ in 0..512 {
        step(&mut device.volume, &device.control, &mut out);
        seen.peak = seen.peak.max(device.control.outstanding());
        seen.crossed |= seen.bytes.len() < EXTENT_PAYLOAD as usize
            && device.volume.report().reads_submitted > commands;
        for event in out.drain(..) {
            match event {
                ReadEvent::Chunk {
                    info, range, chunk, ..
                } => {
                    assert!(seen.info.is_none_or(|seen| seen == info), "one information");
                    seen.info = Some(info);
                    assert_eq!(range.start, start + seen.bytes.len() as u64, "in order");
                    seen.bytes.extend_from_slice(chunk.bytes());
                    if !exhausted {
                        exhausted = device.volume.grant_read(op) == Ok(Grant::Exhausted);
                        let submitted = device.volume.report().reads_submitted;
                        assert!(
                            !exhausted || submitted >= total,
                            "exhausted at {submitted} of {total} commands"
                        );
                    }
                }
                ReadEvent::Done { status, info, .. } => {
                    assert!(seen.info.is_none() || info == seen.info);
                    seen.info = info;
                    seen.status = status;
                    return seen;
                }
            }
        }
    }
    panic!("no Done");
}

/// Two- and three-extent objects read back their exact bytes under the
/// lease's one right, with the whole lengths in every event and chunks in
/// order across each boundary. Commands ahead cross the boundary exactly
/// when the volume reads ahead, the device holds at most the current
/// command and those ahead, and the read's right ends with its last
/// terminal. Response buffers of 128 KiB, which fit a whole extent in the
/// commands ahead, keep granting until every command is submitted.
#[test]
fn a_sequence_reads_its_exact_bytes_under_one_right_across_every_boundary() {
    for (span, read_ahead, metadata) in [
        (BUFFER, 0, 0),
        (BUFFER, 2, METADATA),
        (BUFFER, 3, 0),
        (128 * 1024, 2, METADATA),
        (128 * 1024, 3, 0),
    ] {
        for count in [2, 3] {
            let case = format!("{span} {read_ahead} {metadata} {count}");
            let storage = storage(read_ahead);
            let buffers = arena_sized(4, span, 4);
            let (volume, control) = attach_with(&storage, &buffers, span);
            let mut device = Device { volume, control };
            let p = published(&storage, &device.control, count, metadata, None);
            let before = rights(&storage, &p.object);
            let op = device.volume.read(p.lease.duplicate(), u64::MAX).unwrap();
            assert_eq!(rights(&storage, &p.object), before + 1, "{case}: one right");
            for _ in 0..read_ahead {
                let _ = device.volume.grant_read(op);
            }
            let all = commands(p.payload.len(), metadata, span);
            let seen = read_through(&mut device, op, 0, (all[0], all.iter().sum()));
            assert_eq!(seen.status, ReadStatus::Complete, "{case}");
            assert!(seen.bytes == p.payload, "{case}: exact bytes");
            let info = seen.info.unwrap();
            let lengths = (metadata as u32, (p.payload.len() - metadata) as u32);
            assert_eq!((info.metadata_len(), info.body_len()), lengths, "{case}");
            assert_eq!(seen.crossed, read_ahead > 0, "{case}: crossing");
            assert!(
                seen.peak <= usize::from(read_ahead) + 1,
                "{case}: {}",
                seen.peak
            );
            assert_eq!(
                rights(&storage, &p.object),
                before,
                "{case}: the right ended"
            );
            drop((p.resident, p.lease));
        }
    }
}

/// The planted control: a later extent sealed over other bytes with valid
/// crcs reads back whole, and the exact-bytes oracle rejects it.
#[test]
#[should_panic(expected = "exact bytes")]
fn negative_control_substituted_later_bytes_fail_the_exact_bytes_oracle() {
    let storage = storage(0);
    let buffers = arena();
    let mut device = Device::new(&storage, &buffers);
    let p = published(&storage, &device.control, 2, 0, Some(Plant::Bytes(1)));
    let op = device.volume.read(p.lease.duplicate(), u64::MAX).unwrap();
    let seen = read_through(&mut device, op, 0, (u64::MAX, 0));
    assert_eq!(seen.status, ReadStatus::Complete);
    assert!(seen.bytes == p.payload, "exact bytes");
}

/// A busy pool gate when the read reaches the next extent keeps the read
/// waiting with no command outstanding; once the gate frees, the read
/// continues and delivers the exact bytes.
#[test]
fn a_busy_gate_at_a_boundary_holds_the_read_until_it_frees() {
    let storage = storage(0);
    let buffers = arena();
    let mut device = Device::new(&storage, &buffers);
    let p = published(&storage, &device.control, 2, 0, None);
    let op = device.volume.read(p.lease.duplicate(), u64::MAX).unwrap();
    let mut out = Vec::with_capacity(16);
    let mut bytes = Vec::new();
    for round in 0.. {
        if bytes.len() >= EXTENT_PAYLOAD as usize {
            break;
        }
        assert!(
            round < 256,
            "the first extent stalled at {} bytes",
            bytes.len()
        );
        step(&mut device.volume, &device.control, &mut out);
        for event in out.drain(..) {
            let ReadEvent::Chunk { chunk, .. } = event else {
                panic!("the first extent ends no read");
            };
            bytes.extend_from_slice(chunk.bytes());
            if bytes.len() < EXTENT_PAYLOAD as usize {
                let _ = device.volume.grant_read(op);
            }
        }
    }
    let held = storage.live_pool().unwrap().lock().unwrap();
    assert_eq!(device.volume.grant_read(op), Ok(Grant::Added));
    for _ in 0..4 {
        step(&mut device.volume, &device.control, &mut out);
        assert!(out.is_empty(), "the read waits for the gate");
        assert_eq!(device.control.outstanding(), 0);
    }
    drop(held);
    let rest = read_through(&mut device, op, EXTENT_PAYLOAD, (u64::MAX, 0));
    assert_eq!(rest.status, ReadStatus::Complete);
    bytes.extend_from_slice(&rest.bytes[..]);
    assert!(
        bytes.len() == p.payload.len() && bytes == p.payload,
        "exact bytes"
    );
    drop((p.resident, p.lease));
}

fn queue_full() -> SubmitRefusal {
    SubmitRefusal {
        reason: RefusalReason::QueueFull,
        code: None,
    }
}

#[test]
fn a_busy_gate_at_a_boundary_holds_only_its_own_read() {
    let storage = storage_of(0, 3);
    let buffers = arena();
    let mut device = Device::new(&storage, &buffers);
    let objects: Vec<_> = (0..3)
        .map(|_| published(&storage, &device.control, 2, 0, None))
        .collect();
    let ops: Vec<_> = objects
        .iter()
        .map(|p| device.volume.read(p.lease.duplicate(), u64::MAX).unwrap())
        .collect();
    let (inside, boundary) = ([ops[0], ops[2]], ops[1]);
    let mut out = Vec::with_capacity(16);
    let mut bytes = Vec::new();
    for round in 0.. {
        if bytes.len() >= EXTENT_PAYLOAD as usize {
            break;
        }
        assert!(round < 256, "the first extent stalled at {}", bytes.len());
        step(&mut device.volume, &device.control, &mut out);
        for event in out.drain(..) {
            match event {
                ReadEvent::Chunk { op, chunk, .. } if op == boundary => {
                    bytes.extend_from_slice(chunk.bytes());
                    if bytes.len() < EXTENT_PAYLOAD as usize {
                        let _ = device.volume.grant_read(boundary);
                    }
                }
                ReadEvent::Chunk { .. } => {}
                ReadEvent::Done { status, .. } => panic!("no read ends: {status:?}"),
            }
        }
    }
    let held = storage.live_pool().unwrap().lock().unwrap();
    assert_eq!(device.volume.grant_read(boundary), Ok(Grant::Added));
    for round in 0..2 {
        for op in inside {
            device.control.refuse_next(queue_full());
            assert_eq!(device.volume.grant_read(op), Ok(Grant::Added));
        }
        let submitted = device.volume.report().reads_submitted;
        step(&mut device.volume, &device.control, &mut out);
        assert_eq!(
            device.volume.report().reads_submitted,
            submitted + 2,
            "round {round}: both reads inside their first extent submit"
        );
        let mut delivered = 0;
        for _ in 0..8 {
            if delivered == 2 {
                break;
            }
            step(&mut device.volume, &device.control, &mut out);
            for event in out.drain(..) {
                let ReadEvent::Chunk { op, .. } = event else {
                    panic!("no read ends");
                };
                assert!(inside.contains(&op), "the held read delivers nothing");
                delivered += 1;
            }
        }
        assert_eq!(delivered, 2, "round {round}");
    }
    drop(held);
    let rest = read_through(&mut device, boundary, EXTENT_PAYLOAD, (u64::MAX, 0));
    assert_eq!(rest.status, ReadStatus::Complete);
    bytes.extend_from_slice(&rest.bytes);
    assert!(bytes == objects[1].payload, "exact bytes");
    for op in inside {
        device.volume.cancel_read(op).unwrap();
    }
    settle(&mut device.volume, &device.control);
    drop(objects);
}

/// A command ahead into the second extent that the device queue refuses
/// keeps the locator it read, so its retry submits while the pool gate is
/// held and the first extent's current command is still on the device.
#[test]
fn a_refused_crossing_retries_with_the_locator_it_read() {
    let storage = storage(1);
    let buffers = arena();
    let mut device = Device::new(&storage, &buffers);
    let p = published(&storage, &device.control, 2, 0, None);
    let commands = first_commands(p.payload.len(), 0, BUFFER);
    let op = device.volume.read(p.lease.duplicate(), u64::MAX).unwrap();
    let mut out = Vec::with_capacity(16);
    let mut bytes = Vec::new();
    // The device holds the first extent's final read and refuses the
    // crossing command, so the retry happens across the extent boundary.
    let mut last = None;
    let arm = |device: &Device<'_, '_>, last: &mut Option<_>| {
        if last.is_none() && device.volume.report().reads_submitted == commands {
            let newest = device
                .control
                .events()
                .into_iter()
                .rev()
                .find_map(|event| match event {
                    SimEvent::Submitted(token, Operation::Read) => Some(token),
                    _ => None,
                })
                .unwrap();
            device.control.hold(newest);
            device.control.refuse_next(queue_full());
            *last = Some(newest);
        }
    };
    let _ = device.volume.grant_read(op);
    arm(&device, &mut last);
    let mut refused = false;
    for _ in 0..256 {
        step(&mut device.volume, &device.control, &mut out);
        arm(&device, &mut last);
        for event in out.drain(..) {
            let ReadEvent::Chunk { chunk, .. } = event else {
                panic!("the first extent ends no read");
            };
            bytes.extend_from_slice(chunk.bytes());
            let _ = device.volume.grant_read(op);
            arm(&device, &mut last);
        }
        refused = device.volume.report().reads_refused > 0;
        if refused {
            break;
        }
    }
    assert!(refused, "the crossing command was refused");
    assert_eq!(device.volume.report().reads_submitted, commands);
    assert_eq!(
        device.control.outstanding(),
        1,
        "the first extent's last command"
    );
    let held = storage.live_pool().unwrap().lock().unwrap();
    for _ in 0..4 {
        step(&mut device.volume, &device.control, &mut out);
        assert!(out.is_empty());
    }
    assert_eq!(
        device.volume.report().reads_submitted,
        commands + 1,
        "the retry submits under the held gate"
    );
    drop(held);
    device.control.release(last.unwrap());
    let rest = read_through(&mut device, op, bytes.len() as u64, (u64::MAX, 0));
    assert_eq!(rest.status, ReadStatus::Complete);
    bytes.extend_from_slice(&rest.bytes);
    assert!(bytes == p.payload, "exact bytes");
    drop((p.resident, p.lease));
}

/// A later extent sealed with valid crcs under one changed identity
/// field, at index 1 or 2, ends the read at that header:
/// every byte before the extent is delivered and none of its own, the Done
/// carries the first extent's information, the read's right ends after
/// its last terminal, and the lookup counts no false positive.
#[test]
fn a_wrong_later_context_ends_the_read_with_none_of_its_bytes() {
    let changes: [Change; 4] = [
        (
            |identity| identity.key[0] ^= 1,
            |m| m == HeaderMismatch::Key,
        ),
        (
            |identity| identity.allocation ^= 1,
            |m| matches!(m, HeaderMismatch::Allocation { .. }),
        ),
        (
            |identity| identity.session ^= 1,
            |m| matches!(m, HeaderMismatch::Session { .. }),
        ),
        (
            |identity| identity.version ^= 1,
            |m| matches!(m, HeaderMismatch::CacheVersion { .. }),
        ),
    ];
    for read_ahead in [0, 3] {
        for index in [1, 2] {
            for (change, expected) in changes {
                let storage = storage(read_ahead);
                let buffers = arena();
                let mut device = Device::new(&storage, &buffers);
                let plant = Plant::Identity(index, change);
                let p = published(&storage, &device.control, 3, 0, Some(plant));
                let before = rights(&storage, &p.object);
                let op = device.volume.read(p.lease.duplicate(), u64::MAX).unwrap();
                for _ in 0..read_ahead {
                    let _ = device.volume.grant_read(op);
                }
                let seen = read_through(&mut device, op, 0, (u64::MAX, 0));
                let ReadStatus::HeaderMismatch(mismatch) = seen.status else {
                    panic!("{read_ahead} {index}: {:?}", seen.status);
                };
                assert!(expected(mismatch), "{mismatch:?}");
                let start = index as usize * EXTENT_PAYLOAD as usize;
                assert!(seen.bytes == p.payload[..start], "only the extents before");
                assert!(seen.info.is_some(), "the first extent's information");
                settle(&mut device.volume, &device.control);
                assert_eq!(rights(&storage, &p.object), before);
                assert_eq!(device.volume.report().lookup_false_positives, 0);
                drop((p.resident, p.lease));
            }
        }
    }
}

/// A first header whose checksum-valid lengths name fewer extents than
/// the object's block holds ends the read at that header with no byte.
#[test]
fn lengths_naming_another_extent_count_end_the_read_at_the_first_header() {
    let storage = storage(0);
    let buffers = arena();
    let mut device = Device::new(&storage, &buffers);
    let p = published(&storage, &device.control, 3, 0, Some(Plant::Fewer));
    let op = device.volume.read(p.lease.duplicate(), u64::MAX).unwrap();
    let seen = read_through(&mut device, op, 0, (u64::MAX, 0));
    assert!(
        matches!(
            seen.status,
            ReadStatus::HeaderMismatch(HeaderMismatch::Lengths { .. })
        ),
        "{:?}",
        seen.status
    );
    assert!(seen.bytes.is_empty() && seen.info.is_none());
    drop((p.resident, p.lease));
}

/// A direct extent whose checksum-valid header claims the lengths of an
/// object of two extents ends the read at that header with no byte.
#[test]
fn a_direct_extent_claiming_two_extents_ends_the_read_at_its_header() {
    let storage = storage(0);
    let buffers = arena();
    let device = Device::new(&storage, &buffers);
    let mut owner: ExtentReservation<'_, TestPlatform> = storage
        .reserve(Some(0), Some(EXTENT_PAYLOAD as usize), &mut budget())
        .unwrap();
    owner.mark_written();
    let id = owner.id();
    let locator = owner.locator();
    let completed = owner.complete(KEY, u64::MAX, &mut budget()).ok().unwrap();
    let (resident, lease) = completed.handoff(&mut budget()).ok().unwrap();
    let config = RecordConfig { chunk_len: 8192 }.validate().unwrap();
    let layout = config.extent_layout(0, EXTENT_PAYLOAD as u32 + 1, EXTENT_PAYLOAD);
    let mut bytes = vec![0; layout.record_units() as usize * IO_UNIT];
    let identity = RecordIdentity {
        key: KEY,
        allocation: id.record_tag(),
        session: SESSION,
        version: 0,
    };
    encode_header(
        Crc32c::detect(),
        &layout,
        &identity,
        ExtentPosition::FIRST,
        &mut bytes,
    )
    .unwrap();
    place(&storage, &device.control, locator, &bytes);
    let mut device = device;
    let op = device.volume.read(lease.duplicate(), u64::MAX).unwrap();
    let seen = read_through(&mut device, op, 0, (u64::MAX, 0));
    assert!(
        matches!(
            seen.status,
            ReadStatus::HeaderMismatch(HeaderMismatch::Lengths { .. })
        ),
        "{:?}",
        seen.status
    );
    assert!(seen.bytes.is_empty() && seen.info.is_none());
    drop((resident, lease));
}

/// Reads to the first command of the second extent, faults it as `fault`
/// before the device executes it, and returns what the read delivered and
/// how it ended.
fn faulted_at_boundary(fault: Fault, read_ahead: u8) -> (Vec<u8>, ReadStatus, usize, usize) {
    let storage = storage(read_ahead);
    let buffers = arena();
    let mut device = Device::new(&storage, &buffers);
    let p = published(&storage, &device.control, 2, 0, None);
    let before = rights(&storage, &p.object);
    let commands = first_commands(p.payload.len(), 0, BUFFER);
    let op = device.volume.read(p.lease.duplicate(), u64::MAX).unwrap();
    for _ in 0..read_ahead {
        let _ = device.volume.grant_read(op);
    }
    let mut out = Vec::with_capacity(16);
    let (mut bytes, mut faulted) = (Vec::new(), false);
    for _ in 0..512 {
        // The newest command is the second extent's first once the read
        // submitted one more than the first extent needs.
        if !faulted && device.volume.report().reads_submitted == commands + 1 {
            let newest = device
                .control
                .events()
                .into_iter()
                .rev()
                .find_map(|event| match event {
                    SimEvent::Submitted(token, Operation::Read) => Some(token),
                    _ => None,
                });
            device.control.fault(newest.unwrap(), fault);
            faulted = true;
        }
        step(&mut device.volume, &device.control, &mut out);
        for event in out.drain(..) {
            match event {
                ReadEvent::Chunk { chunk, .. } => {
                    bytes.extend_from_slice(chunk.bytes());
                    let _ = device.volume.grant_read(op);
                }
                ReadEvent::Done { status, .. } => {
                    settle(&mut device.volume, &device.control);
                    let after = rights(&storage, &p.object);
                    drop((p.resident, p.lease));
                    return (bytes, status, before, after);
                }
            }
        }
    }
    panic!("no Done");
}

/// A short or failed first command of the second extent, submitted as the
/// current command or ahead of the first extent's last, ends the read
/// with its status after every byte of the first extent and none of the
/// second; the right ends after the last terminal.
#[test]
fn a_short_or_failed_command_at_a_boundary_ends_the_read_after_the_first_extent() {
    let faults = [
        (Fault::Short { units: 0 }, ReadStatus::Short),
        (
            Fault::Status(DeviceStatus::Kernel(-5)),
            ReadStatus::DeviceError,
        ),
    ];
    for read_ahead in [0, 3] {
        for (fault, status) in faults {
            let (bytes, ended, before, after) = faulted_at_boundary(fault, read_ahead);
            assert_eq!(ended, status, "{read_ahead}");
            let first = &payload(2)[..EXTENT_PAYLOAD as usize];
            assert!(
                bytes == first,
                "{read_ahead} {status:?}: the first extent exactly"
            );
            assert_eq!(after, before, "the right ended");
        }
    }
}

/// A cancel once a command ahead reached the second extent ends the read:
/// while the device still holds commands after the Done, the read's right
/// stays counted; the commands drain to their terminals, the right then
/// ends, and the chunk the caller holds keeps its response buffer until it
/// drops.
#[test]
fn a_cancel_across_the_boundary_drains_device_and_buffer_custody_separately() {
    let storage = storage(3);
    let buffers = arena();
    let mut device = Device::new(&storage, &buffers);
    let p = published(&storage, &device.control, 2, 0, None);
    let before = rights(&storage, &p.object);
    let free = buffers.report(PoolKind::ReadResponse).free;
    let commands = first_commands(p.payload.len(), 0, BUFFER);
    let op = device.volume.read(p.lease.duplicate(), u64::MAX).unwrap();
    for _ in 0..3 {
        let _ = device.volume.grant_read(op);
    }
    let mut out = Vec::with_capacity(16);
    let (mut kept, mut delivered) = (None, 0);
    for _ in 0..512 {
        if device.volume.report().reads_submitted > commands && kept.is_some() {
            break;
        }
        step(&mut device.volume, &device.control, &mut out);
        for event in out.drain(..) {
            if let ReadEvent::Chunk { chunk, .. } = event {
                delivered += chunk.bytes().len();
                kept = Some(chunk);
                let _ = device.volume.grant_read(op);
            }
        }
    }
    // A second-extent command submitted before the first extent's bytes
    // were all delivered went ahead.
    assert!(
        device.volume.report().reads_submitted > commands && delivered < EXTENT_PAYLOAD as usize,
        "an ahead crossed"
    );
    // Holding every outstanding command keeps the device's custody past
    // the Done.
    let held: Vec<_> = device
        .control
        .ready(super::device::sim::Stage::Execute)
        .into_iter()
        .chain(device.control.ready(super::device::sim::Stage::Post))
        .collect();
    for &token in &held {
        let _ = device.control.try_hold(token);
    }
    device.volume.cancel_read(op).unwrap();
    let mut done = false;
    for _ in 0..8 {
        step(&mut device.volume, &device.control, &mut out);
        done |= out.drain(..).any(|event| {
            matches!(
                event,
                ReadEvent::Done {
                    status: ReadStatus::Cancelled,
                    ..
                }
            )
        });
        if done {
            break;
        }
    }
    assert!(done, "the cancel delivered its Done");
    assert!(
        device.control.outstanding() > 0,
        "held commands stay on the device"
    );
    assert_eq!(
        rights(&storage, &p.object),
        before + 1,
        "the right outlives the Done"
    );
    for &token in &held {
        device.control.release(token);
    }
    settle(&mut device.volume, &device.control);
    assert_eq!(
        rights(&storage, &p.object),
        before,
        "the right ended after the terminals"
    );
    assert_eq!(
        buffers.report(PoolKind::ReadResponse).free,
        free - 1,
        "the held chunk keeps its buffer"
    );
    drop(kept);
    assert_eq!(buffers.report(PoolKind::ReadResponse).free, free);
    drop((p.resident, p.lease));
}

/// Reads a three-extent object whole under the grants and span `root`
/// selects and passes each validated chunk, with the volume that holds its
/// window checksums, to `judge`. Returns the chunks judged.
fn each_chunk(
    root: u64,
    mut judge: impl FnMut(&mut super::seeded::SplitMix64, &Device<'_, '_>, &super::ValidatedChunk<'_>),
) -> usize {
    let mut rng = super::seeded::SplitMix64::new(root);
    let span = [BUFFER, 128 * 1024, 512 * 1024][rng.below(3) as usize];
    let metadata = [0, METADATA][rng.below(2) as usize];
    let read_ahead = rng.below(4) as u8;
    let storage = storage(read_ahead);
    let buffers = arena_sized(4, span, 4);
    let (volume, control) = attach_with(&storage, &buffers, span);
    let mut device = Device { volume, control };
    let p = published(&storage, &device.control, 3, metadata, None);
    let op = device.volume.read(p.lease.duplicate(), u64::MAX).unwrap();
    let mut out = Vec::with_capacity(16);
    let mut chunks = 0;
    for _ in 0..512 {
        step(&mut device.volume, &device.control, &mut out);
        for event in out.drain(..) {
            match event {
                ReadEvent::Chunk { chunk, .. } => {
                    judge(&mut rng, &device, &chunk);
                    chunks += 1;
                    drop(chunk);
                    let _ = device.volume.grant_read(op);
                }
                ReadEvent::Done { status, .. } => {
                    assert_eq!(status, ReadStatus::Complete, "root {root}");
                    settle(&mut device.volume, &device.control);
                    drop((p.resident, p.lease));
                    return chunks;
                }
            }
        }
    }
    panic!("no Done");
}

/// A checksum asked for a range that wraps the chunk's offset back before
/// its bytes, or for a range that runs backwards, panics on the range check
/// rather than returning a checksum, with or without debug assertions.
#[test]
fn a_chunk_s_checksum_of_a_wrapping_or_backward_range_panics() {
    let crc = Crc32c::detect();
    let mut answered = Vec::new();
    let chunks = each_chunk(0, |_, device, chunk| {
        let crcs = device.volume.chunk_crcs(chunk);
        let wrapping = std::ops::Range {
            start: usize::MAX - 7,
            end: 0,
        };
        let backward = std::ops::Range { start: 1, end: 0 };
        for range in [wrapping, backward] {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                chunk.crc(
                    crc,
                    &mut super::record::ZeroRuns::new(),
                    crcs,
                    range.clone(),
                )
            }));
            let refused = outcome.as_ref().is_err_and(|payload| {
                payload.downcast_ref::<&str>() == Some(&"a range inside the chunk")
            });
            if !refused {
                answered.push((range, outcome.ok()));
            }
        }
    });
    assert!(chunks > 0, "no chunk");
    assert!(
        answered.is_empty(),
        "ranges outside the chunk not refused by the range check: {answered:x?}"
    );
}
