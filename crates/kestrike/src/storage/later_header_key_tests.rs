//! A read checks the key of every later extent's header: a checksum-valid later extent that names another key
//! ends the read with none of that extent's bytes.
//!
//! The scenario publishes a three-extent object through storage-level placement and writes each extent's
//! record with the fixture of `storage::sequence_read_tests`. One extent after the first is sealed, with
//! valid header, context and chunk checksums, under a key that differs from the lease's key and under the
//! lease's allocation word, session and cache version. A read under the lease must end
//! `HeaderMismatch(Key)` at that extent, hand out exactly the payload of the extents before it, and carry
//! the first extent's information in every chunk and in `Done`: the lease's key, allocation word, session
//! and cache version with the object's whole lengths. With every extent sealed under the lease's key, a
//! read of the same object returns the whole payload with `ReadStatus::Complete`.
//!
//! Each case decides its facts into a `Seen`, lets the device settle and drops its fixtures, and only
//! then asserts, so a failing case ends in a result line.

use super::ExtentReservation;
use super::geometry::EXTENT_PAYLOAD;
use super::record::{HeaderMismatch, RecordIdentity};
use super::sequence_read_tests::{
    LAST, METADATA, Plant, budget, commands, plant_sequence, storage,
};
use super::test_platform::TestPlatform;
use super::volume::{Grant, ReadEvent, ReadStatus, VerifiedReadInfo};
use super::volume_fixture::{BUFFER, Device, SESSION, arena, settle, step};

/// The key the object is published and leased under.
const KEY: [u8; 32] = [0x3c; 32];
/// Extents of the object.
const EXTENTS: u32 = 3;

/// Read-ahead depth and metadata length of each case: no command ahead, commands ahead that cross
/// the extent boundary before the earlier extent's bytes are delivered, and metadata ahead of the body.
const SHAPES: [(u8, usize); 3] = [(0, 0), (3, 0), (2, METADATA)];

/// The other keys a later extent is sealed under: one that shares no byte with the lease's key, and
/// one that differs from it in the lowest bit of its last byte alone.
const OTHER_KEYS: [fn(&mut RecordIdentity); 2] = [
    |identity| identity.key = [0xc3; 32],
    |identity| identity.key[31] ^= 1,
];

/// What one read under the lease handed out.
struct Seen {
    /// The object's payload as the fixture wrote it, metadata first.
    payload: Vec<u8>,
    /// The bytes of the read's chunks, in the order the chunks arrived.
    bytes: Vec<u8>,
    /// Every chunk began at the payload offset where the chunk before it ended.
    in_order: bool,
    /// The status of the read's `Done`; `None` when no `Done` arrived within the tick bound.
    status: Option<ReadStatus>,
    /// The information `Done` carried.
    info: Option<VerifiedReadInfo>,
    /// Every chunk carried the information `Done` carried.
    one_information: bool,
    /// For each later extent, whether the volume submitted its first command ahead of the read's current
    /// command while bytes of the extents before it were still undelivered.
    crossed: [bool; EXTENTS as usize - 1],
    /// Every unplanted extent uses the same seal identity: the publication's key and allocation word, the
    /// fixture's session, and cache version 0.
    leased: RecordIdentity,
}

/// Publishes a three-extent object with `metadata` bytes of metadata under [`KEY`], writes its
/// extents' records, the one `plant` names sealed differently, and reads it under its lease with
/// `read_ahead` commands ahead, granting a command after each chunk as a network read does.
fn read_object(read_ahead: u8, metadata: usize, plant: Option<Plant>) -> Seen {
    let storage = storage(read_ahead);
    let buffers = arena();
    let mut device = Device::new(&storage, &buffers);
    let mut owner: ExtentReservation<'_, TestPlatform> = storage
        .reserve(Some(metadata), Some(LAST - metadata), &mut budget())
        .expect("premise: the object's last extent reserves");
    owner.mark_written();
    let id = owner.id();
    let completed = owner
        .complete(KEY, u64::MAX, &mut budget())
        .expect("premise: the object completes under its key");
    let (resident, lease) = completed
        .handoff(&mut budget())
        .expect("premise: the object publishes");
    let payload = plant_sequence(&storage, &device.control, id, KEY, EXTENTS, metadata, plant);
    let op = device
        .volume
        .read(lease.duplicate(), u64::MAX)
        .expect("premise: the read is admitted under the lease");
    for _ in 0..read_ahead {
        let _ = device.volume.grant_read(op);
    }
    let mut seen = Seen {
        payload,
        bytes: Vec::new(),
        in_order: true,
        status: None,
        info: None,
        one_information: true,
        crossed: [false; EXTENTS as usize - 1],
        leased: RecordIdentity {
            key: KEY,
            allocation: id.record_tag(),
            session: SESSION,
            version: 0,
        },
    };
    // The commands the read needs through each extent before the last.
    let through: Vec<u64> = commands(seen.payload.len(), metadata, BUFFER)
        .into_iter()
        .take(seen.crossed.len())
        .scan(0, |sum, extent| {
            *sum += extent;
            Some(*sum)
        })
        .collect();
    // The commands the volume had submitted, and those of them ahead, when the last round ended.
    let (mut submitted, mut ahead) = (0, 0);
    let mut chunk_infos = Vec::new();
    let mut exhausted = false;
    let mut out = Vec::with_capacity(16);
    'ticks: for _ in 0..512 {
        step(&mut device.volume, &device.control, &mut out);
        let report = device.volume.report();
        // Every command this round submitted was ahead of the read's current command.
        let all_ahead = report.reads_submitted - submitted == report.reads_ahead - ahead;
        for (later, crossed) in seen.crossed.iter_mut().enumerate() {
            let first_of_later =
                submitted <= through[later] && report.reads_submitted > through[later];
            let boundary = (later + 1) * EXTENT_PAYLOAD as usize;
            *crossed |= first_of_later && all_ahead && seen.bytes.len() < boundary;
        }
        (submitted, ahead) = (report.reads_submitted, report.reads_ahead);
        for event in out.drain(..) {
            match event {
                ReadEvent::Chunk {
                    info, range, chunk, ..
                } => {
                    seen.in_order &= range.start == seen.bytes.len() as u64;
                    chunk_infos.push(info);
                    seen.bytes.extend_from_slice(chunk.bytes());
                    if !exhausted {
                        exhausted = device.volume.grant_read(op) == Ok(Grant::Exhausted);
                    }
                }
                ReadEvent::Done { status, info, .. } => {
                    seen.status = Some(status);
                    seen.info = info;
                    break 'ticks;
                }
            }
        }
    }
    drop(out);
    seen.one_information = chunk_infos.iter().all(|info| Some(*info) == seen.info);
    // The commands ahead of an ended read return before the fixtures drop.
    settle(&mut device.volume, &device.control);
    drop((resident, lease));
    seen
}

fn carried(seen: &Seen) -> Option<(RecordIdentity, u32, u32)> {
    seen.info
        .map(|info| (*info.identity(), info.metadata_len(), info.body_len()))
}

/// The lease's identity with the metadata and body lengths of the object whose payload is `seen.payload`.
fn leased_whole(seen: &Seen, metadata: usize) -> Option<(RecordIdentity, u32, u32)> {
    let body = (seen.payload.len() - metadata) as u32;
    Some((seen.leased, metadata as u32, body))
}

/// A checksum-valid later extent naming another key ends the read with none of its bytes
/// and the first extent's information.
#[test]
fn a_later_extent_sealed_under_another_key_ends_the_read_before_any_of_its_bytes() {
    let mut cases = 0;
    for (read_ahead, metadata) in SHAPES {
        for index in 1..EXTENTS {
            for (which, other_key) in OTHER_KEYS.into_iter().enumerate() {
                let case = format!(
                    "read-ahead {read_ahead}, metadata {metadata}, extent {index}, other key {which}"
                );
                let plant = Plant::Identity(index, other_key);
                let seen = read_object(read_ahead, metadata, Some(plant));
                let before = index as usize * EXTENT_PAYLOAD as usize;
                assert!(
                    seen.crossed[..index as usize]
                        .iter()
                        .all(|&crossed| crossed == (read_ahead > 0)),
                    "{case}: premise: a command ahead crosses into each extent through {index} exactly when \
                     the volume reads ahead, found {:?}",
                    seen.crossed
                );
                assert_eq!(
                    seen.status,
                    Some(ReadStatus::HeaderMismatch(HeaderMismatch::Key)),
                    "{case}: the read ends at the extent's header with the key mismatch"
                );
                assert!(
                    seen.bytes.len() <= before,
                    "{case}: {} bytes handed out, {} of them of extent {index} or later",
                    seen.bytes.len(),
                    seen.bytes.len() - before
                );
                assert!(
                    seen.in_order && seen.bytes == seen.payload[..before],
                    "{case}: the bytes handed out are exactly the payload of the extents before"
                );
                assert_eq!(
                    carried(&seen),
                    leased_whole(&seen, metadata),
                    "{case}: Done carries the first extent's information, under the lease's key"
                );
                assert!(
                    seen.one_information,
                    "{case}: one information in every event"
                );
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 12, "every shape, later extent and other key ran");
}

/// The sibling: the same object with every extent sealed under the lease's key reads whole.
#[test]
fn the_same_object_sealed_under_the_lease_s_key_reads_its_whole_payload() {
    for (read_ahead, metadata) in SHAPES {
        let case = format!("read-ahead {read_ahead}, metadata {metadata}");
        let seen = read_object(read_ahead, metadata, None);
        assert_eq!(
            seen.crossed,
            [read_ahead > 0; EXTENTS as usize - 1],
            "{case}: premise: a command ahead crosses each boundary exactly when the volume reads ahead"
        );
        assert_eq!(seen.status, Some(ReadStatus::Complete), "{case}");
        assert_eq!(
            seen.payload.len(),
            (EXTENTS as usize - 1) * EXTENT_PAYLOAD as usize + LAST,
            "{case}: the object has three extents"
        );
        assert!(
            seen.in_order && seen.bytes == seen.payload,
            "{case}: the bytes handed out are the whole payload"
        );
        assert_eq!(
            carried(&seen),
            leased_whole(&seen, metadata),
            "{case}: Done carries the object's information"
        );
        assert!(
            seen.one_information,
            "{case}: one information in every event"
        );
    }
}
