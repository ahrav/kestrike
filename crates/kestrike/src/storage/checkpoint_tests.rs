//! The possibly-named set under Publish and Confirm outcomes over the store double, its reservation and quarantine, the staged checkpoint's verified Publish, and the named-slot reader's command shape, streamed guard and fault-local damage outcomes over prefix byte images.

use super::*;
use crate::failover::records::{Host, Layout, NamedCheckpoint, ShardRecord, Suffix};
use crate::failover::retire::Target;
use crate::index::{KeyHasher, ValidatedIndex};
use crate::net::ownership::ShardGeneration;
use crate::storage::extent::ExtentLocator;
use crate::storage::recovery::capture_tests::{drain, limits, observed_completed};
use crate::storage::recovery::checkpoint::{Checkpoint, encode, rows, units};
use crate::storage::recovery::checkpoint::{PER_WINDOW, run};
use crate::storage::recovery::checkpoint_tests::{
    canon, canonical, colliding, damaged, loaded, outside, routing, settle, whole,
};
use crate::storage::recovery::delta::Record;
use crate::storage::recovery::{Capture, CutIntact, SideCap};
use crate::storage::recovery::{CaptureEntry, GuardedLoad, LoadRefusal, guarded_load};
use crate::storage::seeded::SplitMix64;
use crate::storage::store::sim::{Arm, MemLog, Shared};
use crate::storage::store::{Key, Outcome, Refusal};
use crate::storage::store_tests::{OWNER, client, record, shard, stored};

/// The tenure session `g·2^32 + 2E` of the seeded record, `g = 3` and `E = 1`.
pub(crate) const SESSION: u64 = (3 << 32) | 2;

/// A reader whose decode jobs run inline as each read completes.
pub(crate) trait Inline {
    fn complete(&mut self, range: DeviceRange, bytes: &[u8]);
    fn fail_read(&mut self, range: DeviceRange);
    fn load(self) -> SlotLoad;
}

impl Inline for SlotReader {
    fn complete(&mut self, range: DeviceRange, bytes: &[u8]) {
        let job = self.completed(range, bytes.to_vec());
        settle(self.decode(), job);
    }

    fn fail_read(&mut self, range: DeviceRange) {
        let job = self.failed(range);
        settle(self.decode(), job);
    }

    fn load(self) -> SlotLoad {
        assert!(self.done(), "every job ran");
        self.finish().expect("no helper failed")
    }
}

fn own() -> Target {
    Target {
        generation: ShardGeneration::new(3).unwrap(),
        owner: Host::new(OWNER).unwrap(),
        attempts: 1,
    }
}

/// A store holding the shard record of the tenure [`own`] names.
fn seeded() -> Shared {
    let store = Shared::new();
    client(&store)
        .create_shard(ShardRecord {
            attempts: own().attempts,
            ..record()
        })
        .unwrap();
    store
}

fn named(slot: u32, capture: u32) -> NamedCheckpoint {
    NamedCheckpoint {
        slot,
        session: SESSION,
        capture,
        units: 1,
    }
}

fn set(named: Option<NamedCheckpoint>) -> PossiblyNamed {
    PossiblyNamed::new((shard(), SESSION), layout(4), named)
}

/// A stage of `ck` holding the reservation for its slot, with every unit read back, for tests of the set's and the
/// Publish's arithmetic.
fn staged(possible: &mut PossiblyNamed, ck: NamedCheckpoint) -> StagedCheckpoint {
    let checkpoint = Checkpoint {
        shard: shard(),
        session: ck.session,
        capture: ck.capture,
    };
    let units = vec![Box::new([0; UNIT_LEN]); ck.units as usize];
    let mut stage = StagedCheckpoint::reserved_at(possible, checkpoint, ck.slot, units);
    for unit in 0..ck.units {
        stage.wrote(unit);
        stage.read_back((ck.slot, unit), &[0; UNIT_LEN]);
    }
    stage
}

/// Publishes `ck` through a fresh stage of it.
fn publish_named(
    host: &mut Client<Shared, MemLog>,
    possible: &mut PossiblyNamed,
    read: &Read<ShardRecord>,
    own: Target,
    known: Option<NamedCheckpoint>,
    ck: NamedCheckpoint,
) -> Result<Read<ShardRecord>, WriteRefused> {
    let mut stage = staged(possible, ck);
    publish(
        host,
        possible,
        read,
        (own, known),
        (&cut(stage.named().capture), CaptureEpoch::default()),
        &mut stage,
    )
}

/// Returns proof that one-slot pass `counter` completed under `(shard(), SESSION)`.
fn cut(counter: u32) -> CutIntact {
    cut_under((shard(), SESSION), counter)
}

/// Returns proof that one-slot pass `counter` completed under `tenure`.
fn cut_under(tenure: (crate::net::ownership::Shard, u64), counter: u32) -> CutIntact {
    let mut capture = Capture::at_counter(u64::from(counter) - 1);
    let cap = SideCap {
        entries: 1,
        words: 1,
    };
    capture
        .start((1, CaptureEpoch::default()), 1, 0, 1, true, cap)
        .unwrap();
    capture.advance(1).unwrap();
    capture.intact(tenure, CaptureEpoch::default()).unwrap()
}

fn read(client: &mut Client<Shared, MemLog>) -> Read<ShardRecord> {
    client.read::<ShardRecord>(Key::Shard(shard())).unwrap()
}

#[test]
fn delayed_publish_after_confirm() {
    // The client maps a timeout and a failure reply to one `StoreError::Unknown`, so one held Publish covers both.
    {
        let reply = "unknown";
        let store = seeded();
        let mut host = client(&store);
        let mut possible = set(None);
        let first = read(&mut host);
        store.schedule(Arm::Hold);
        assert_eq!(
            publish_named(&mut host, &mut possible, &first, own(), None, named(0, 1)).map(|_| ()),
            Err(WriteRefused::Store(StoreError::Unknown)),
            "{reply}: the Publish is delayed and its reply is unknown"
        );
        assert!(
            possible.contains(0),
            "{reply}: an unknown Publish keeps its slot"
        );
        assert_eq!(possible.slots(), vec![0]);
        let current = read(&mut host);
        confirm(&mut host, &mut possible, &current, own()).unwrap();
        assert!(
            !possible.contains(0),
            "{reply}: the Confirm settles every earlier write"
        );
        assert_eq!(
            possible.quarantined(),
            [0],
            "{reply}: the unknown Publish's slot leaves the set for quarantine, not for reuse"
        );
        assert_eq!(possible.free_slot(), Some(1));
        assert_eq!(
            store.release(),
            vec![Outcome::NotCommitted(Refusal::Condition)],
            "{reply}: the delayed Publish fails on the record version"
        );
        assert_eq!(stored(&store).1.checkpoint, None, "{reply}");
    }

    for arm in crate::storage::store_tests::UNKNOWN {
        let store = seeded();
        let mut host = client(&store);
        let mut possible = set(None);
        let first = read(&mut host);
        store.schedule(arm);
        assert_eq!(
            publish_named(&mut host, &mut possible, &first, own(), None, named(1, 1)).map(|_| ()),
            Err(WriteRefused::Store(StoreError::Unknown)),
            "{arm:?}"
        );
        assert_eq!(
            possible.slots(),
            vec![1],
            "{arm:?}: an unknown Publish keeps its slot"
        );
        let committed = stored(&store).1.checkpoint;
        let (Arm::Timeout { commit } | Arm::Failure { commit }) = arm else {
            unreachable!("every unknown arm is a timeout or a failure reply");
        };
        assert_eq!(committed, commit.then(|| named(1, 1)), "{arm:?}");
        let current = read(&mut host);
        let confirmed = confirm(&mut host, &mut possible, &current, own()).unwrap();
        assert_eq!(confirmed.value().checkpoint, committed, "{arm:?}");
        assert_eq!(
            possible.slots(),
            committed.map(|ck| ck.slot).into_iter().collect::<Vec<_>>(),
            "{arm:?}: after the Confirm the set is the slot the store names"
        );
    }

    let store = seeded();
    let mut host = client(&store);
    let mut possible = set(None);
    let first = read(&mut host);
    store.schedule(Arm::Hold);
    let _ = publish_named(&mut host, &mut possible, &first, own(), None, named(2, 1));
    let current = read(&mut host);
    confirm(&mut host, &mut possible, &current, own()).unwrap();
    store.release();
    let mut late = client(&store);
    let stale = read(&mut late);
    store.schedule(Arm::DoubleWin);
    let field_scoped = ShardRecord {
        checkpoint: Some(named(2, 1)),
        ..*stale.value()
    };
    let _ = late.replace(&first, field_scoped);
    let landed = stored(&store).1.checkpoint.map(|ck| ck.slot);
    assert_eq!(landed, Some(2));
    assert!(
        !possible.contains(2),
        "field-scoped control: the store names slot 2 outside the possibly-named set"
    );
}

#[test]
fn a_success_settles_the_set_only_after_every_earlier_write() {
    let version = |at: u64| crate::storage::store::Version::new(at).unwrap();
    let mut possible = set(Some(named(0, 1)));
    let a = possible.submit(Some(1));
    let b = possible.submit(Some(2));
    possible.succeeded(a, Some(named(1, 2)), version(2));
    assert_eq!(
        possible.slots(),
        vec![0, 1, 2],
        "a success with a later write unresolved keeps every slot"
    );
    possible.succeeded(b, Some(named(2, 3)), version(3));
    assert_eq!(possible.slots(), vec![2]);
    assert_eq!(
        possible.quarantined(),
        [1],
        "the slots this tenure wrote that the settling success dropped are quarantined"
    );
    assert_eq!(
        possible.free_slot(),
        Some(0),
        "the slot named at the tenure's start, which no attempt of the tenure reached, goes free"
    );

    let mut possible = set(None);
    let newer = possible.submit(Some(1));
    possible.succeeded(newer, Some(named(1, 2)), version(3));
    let older = possible.submit(Some(0));
    possible.succeeded(older, Some(named(0, 1)), version(2));
    assert_eq!(
        possible.slots(),
        vec![1, 0],
        "a success below the settled version keeps the settled slot"
    );
}

fn layout(slot_units: u32) -> Layout {
    Layout {
        units: 1 + 3 * u64::from(slot_units),
        slots: 3,
        slot_units,
        entries: (slot_units - 1) * crate::failover::records::UNIT_ENTRIES as u32,
    }
}

/// The capture tests' entry of `slot`, `incarnation` and first unit `start`, under the session the slot tests' readers
/// admit, since a slot load withholds an entry of a session its reader does not admit.
pub(crate) fn entry(slot: usize, incarnation: u32, start: u64) -> CaptureEntry {
    CaptureEntry {
        session: SESSION,
        ..crate::storage::recovery::capture_tests::entry(slot, incarnation, start)
    }
}

/// `count` entries of distinct keys, slots and units.
pub(crate) fn entries(count: usize) -> Vec<CaptureEntry> {
    (0..count).map(|at| entry(at, 2, 8 * at as u64)).collect()
}

pub(crate) fn load_limits(count: usize) -> LoadLimits {
    LoadLimits {
        payload_end: 8 * count as u64 + 8,
        slot_count: count + 1,
        n_max: count + 1,
        ..limits()
    }
}

fn prefix(layout: &Layout, slot: u32, units: &[Box<[u8; UNIT_LEN]>]) -> Vec<u8> {
    let mut bytes = vec![0xEE; layout.units as usize * IO_UNIT];
    let start = (1 + slot as usize * layout.slot_units as usize) * IO_UNIT;
    for (at, unit) in units.iter().enumerate() {
        bytes[start + at * IO_UNIT..start + (at + 1) * IO_UNIT].copy_from_slice(&unit[..]);
    }
    bytes
}

/// Over 16 KiB windows of a slot whose first unit is not window-aligned, so the first read is three units and every
/// later one a full window, a reader that copies each read into a spare buffer of a landed window
/// ([`SlotReader::completed_copy`]) reuses spares, never holds a buffer past one window (the reader's debug check),
/// and loads the same slot as one handed a fresh buffer per read.
#[test]
fn a_read_copied_into_a_spare_buffer_decodes_the_same_slot() {
    let read_len = 4 * IO_UNIT as u64;
    let entries = entries(41 * 377);
    let (layout, ck, bytes) = slot_image(&entries, false);
    let first = layout.prefix_unit(ck.slot, 0).unwrap() * IO_UNIT as u64;
    assert_eq!(
        first % read_len,
        IO_UNIT as u64,
        "the slot starts one unit past a window edge"
    );
    let reader = || {
        SlotReader::with_read_len(
            Crc32c::detect(),
            &layout,
            shard(),
            (ck, 0, &[]),
            SESSION,
            (load_limits(entries.len()), &EngineBudget::unlimited()),
            routing(4),
            read_len,
        )
        .unwrap()
    };
    let mut loads = Vec::new();
    for copied in [false, true] {
        let mut reader = reader();
        let (mut lens, mut spares) = (Vec::new(), 0);
        while let Some(range) = reader.next_read() {
            let read = &bytes[range.start() as usize..range.end() as usize];
            lens.push(range.byte_len());
            let job = if copied {
                spares += usize::from(!reader.decode().spares_is_empty());
                reader.completed_copy(range, read)
            } else {
                reader.completed(range, read.to_vec())
            };
            if let Some(job) = job {
                reader.decode().landed(run(job));
            }
            while let Some(job) = reader.decode().work() {
                reader.decode().landed(run(job));
            }
        }
        assert_eq!(
            lens[..2],
            [3 * IO_UNIT as u32, read_len as u32],
            "a short read, then a window"
        );
        assert!(!copied || spares > 0, "spare buffers were reused");
        assert!(reader.done());
        loads.push(reader.finish().unwrap());
    }
    let held: usize = loads[0].shards.iter().flatten().map(Chunk::len).sum();
    assert_eq!(
        (loads[0].verdict, held, loads[0].damage.is_none()),
        (Ok(()), entries.len(), true),
        "the fresh-buffer load holds every entry undamaged"
    );
    assert_eq!(loads[0], loads[1]);
}

/// Issues every read the reader admits, completes the read `pick` names, and runs decode jobs inline in the order
/// `pick` names, at times deferring them past the next completion, until the reader is done.
fn drive(
    reader: &mut SlotReader,
    bytes: &[u8],
    mut pick: impl FnMut(usize) -> usize,
) -> Vec<(DeviceRange, usize)> {
    let (mut issued, mut flight, mut jobs) = (Vec::new(), Vec::new(), Vec::new());
    loop {
        while let Some(range) = reader.next_read() {
            flight.push(range);
            issued.push((range, flight.len()));
        }
        if flight.is_empty() && jobs.is_empty() {
            break;
        }
        if !flight.is_empty() {
            let range = flight.remove(pick(flight.len()));
            let start = range.start() as usize;
            jobs.extend(reader.completed(
                range,
                bytes[start..start + range.byte_len() as usize].to_vec(),
            ));
        }
        loop {
            jobs.extend(std::iter::from_fn(|| reader.decode().work()));
            let at = pick(jobs.len() + 1);
            if jobs.is_empty() || (at == jobs.len() && !flight.is_empty()) {
                break;
            }
            let job = jobs.swap_remove(at.min(jobs.len() - 1));
            reader.decode().landed(run(job));
        }
    }
    assert!(reader.done());
    issued
}

/// The reader shape the obligation states, in literals: every read lies in one 256 KiB-aligned window of the slot,
/// every read but the first and last is a whole window, and at least 16 are outstanding while 16 or more remain.
fn shape(issued: &[(DeviceRange, usize)], slot: (u64, u64)) -> Result<(), String> {
    const WINDOW: u64 = 256 * 1024;
    const DEPTH: usize = 16;
    let mut at = slot.0;
    for (index, (range, flight)) in issued.iter().enumerate() {
        let (start, end) = (range.start(), range.start() + u64::from(range.byte_len()));
        if start != at || end > slot.1 || start / WINDOW != (end - 1) / WINDOW {
            return Err(format!(
                "read {index} at {start}..{end} leaves its window or the slot"
            ));
        }
        let first_or_last = index == 0 || end == slot.1;
        if !first_or_last && (!start.is_multiple_of(WINDOW) || end - start != WINDOW) {
            return Err(format!("read {index} is not a whole window"));
        }
        let remaining = issued.len() - index;
        if remaining >= DEPTH && index >= DEPTH - 1 && *flight < DEPTH {
            return Err(format!("read {index} issued with {flight} outstanding"));
        }
        at = end;
    }
    (at == slot.1)
        .then_some(())
        .ok_or_else(|| "the reads do not cover the slot".to_string())
}

/// Completes every read the reader issues and lands its window inline, and runs destination jobs only once the reader
/// issues no read, so the decode holds as many windows as its cap admits; returns whether the cap was reached.
fn drive_to_the_cap(reader: &mut SlotReader, bytes: &[u8]) -> bool {
    let (mut landed, mut capped) = (0, false);
    while !reader.done() {
        while let Some(range) = reader.next_read() {
            let start = range.start() as usize;
            let job = reader.completed(
                range,
                bytes[start..start + range.byte_len() as usize].to_vec(),
            );
            if let Some(job) = job {
                reader.decode().landed(run(job));
            }
            landed += 1;
        }
        capped |= landed - reader.decode().released() == WINDOWS;
        while let Some(job) = reader.decode().work() {
            reader.decode().landed(run(job));
        }
    }
    capped
}

/// A full slot's decode holds every entry in window storage reserved for exactly the window's openers, never more than
/// the slot's rows, and peaks within the bytes the reader charges while it streams and while it seals, with distinct
/// fingerprints, with every fingerprint colliding, where each seal compares every key, and with every key shared,
/// whether destination jobs run as soon as they exist or wait until the decode holds its window cap.
#[test]
fn a_full_slot_decode_holds_exact_chunks_within_the_charge() {
    let count = 41 * 64 * (WINDOWS + 4);
    let distinct = entries(count);
    let mut shared = distinct.clone();
    for entry in &mut shared {
        entry.key = distinct[0].key;
    }
    let limits = load_limits(count);
    let colliding = colliding(&distinct);
    for (entries, hold) in [
        (&distinct, false),
        (&colliding, false),
        (&distinct, true),
        (&shared, false),
    ] {
        let (layout, ck, bytes) = slot_image(entries, false);
        let charge = |windows| {
            SlotDecode::bytes(ck.units, &limits, 4, (windows, READ_LEN as usize)).unwrap()
        };
        let live = crate::instrument::live_bytes();
        crate::instrument::reset_peak();
        let mut reader = SlotReader::new(
            Crc32c::detect(),
            &layout,
            shard(),
            (ck, 0, &[]),
            SESSION,
            (limits, &EngineBudget::unlimited()),
            routing(4),
        )
        .unwrap();
        if hold {
            assert!(
                drive_to_the_cap(&mut reader, &bytes),
                "the decode holds its window cap"
            );
        } else {
            drive(&mut reader, &bytes, |_| 0);
        }
        let driven = crate::instrument::peak_bytes().wrapping_sub(live);
        crate::instrument::reset_peak();
        let slot = reader.finish().unwrap();
        let verdict = crate::instrument::peak_bytes().wrapping_sub(live);
        let refused = std::ptr::eq(entries, &shared);
        let held: usize = slot.shards.iter().flatten().map(Chunk::len).sum();
        let storage: std::collections::BTreeMap<usize, usize> =
            (slot.shards.iter().flatten().map(Chunk::storage)).collect();
        let reserved: usize = storage.values().sum();
        let expected = if refused {
            Err(LoadRefusal::Key)
        } else {
            Ok(())
        };
        assert_eq!(
            (slot.verdict, held),
            (expected, count),
            "a whole slot loads every entry, refused Key when every key is shared"
        );
        assert!(
            reserved <= (ck.units as usize - 1) * 41,
            "the windows reserve {reserved}"
        );
        let peak = driven.max(verdict);
        assert!(
            peak <= charge(WINDOWS),
            "peak {peak} within {}",
            charge(WINDOWS)
        );
        assert!(
            verdict <= charge(0),
            "verdict {verdict} within {}",
            charge(0)
        );
    }
}

#[test]
fn a_decode_whose_extents_reach_every_destination_holds_its_cap_within_the_charge() {
    let count = 41 * 64 * (WINDOWS + 4);
    let mut entries = entries(count);
    for entry in &mut entries {
        entry.extents = vec![ExtentLocator::new(0, 64).unwrap().bits()];
    }
    let limits = LoadLimits {
        payload_end: 64,
        ..load_limits(count)
    };
    let (layout, ck, bytes) = slot_image(&entries, false);
    let charge = SlotDecode::bytes(ck.units, &limits, 64, (WINDOWS, READ_LEN as usize)).unwrap();
    let live = crate::instrument::live_bytes();
    crate::instrument::reset_peak();
    let mut reader = SlotReader::new(
        Crc32c::detect(),
        &layout,
        shard(),
        (ck, 0, &[]),
        SESSION,
        (limits, &EngineBudget::unlimited()),
        routing(64),
    )
    .unwrap();
    assert!(
        drive_to_the_cap(&mut reader, &bytes),
        "the decode holds its window cap"
    );
    let load = reader.finish().unwrap();
    let peak = crate::instrument::peak_bytes().wrapping_sub(live);
    assert!(load.verdict.is_err(), "{:?}", load.verdict);
    assert!(peak <= charge, "peak {peak} within the charge {charge}");
}

#[test]
fn slot_reader_command_shape() {
    let count = 41 * 2200;
    let entries = entries(count);
    let crc = Crc32c::detect();
    let slot_units = units(rows(&entries)) as u32;
    let layout = layout(slot_units);
    let checkpoint = Checkpoint {
        shard: shard(),
        session: SESSION,
        capture: 4,
    };
    let encoded = encode(crc, checkpoint, &entries, u32::MAX).unwrap();
    let bytes = prefix(&layout, 1, &encoded);
    let ck = NamedCheckpoint {
        slot: 1,
        session: SESSION,
        capture: 4,
        units: slot_units,
    };
    let mut reader = SlotReader::new(
        crc,
        &layout,
        shard(),
        (ck, 0, &[]),
        SESSION,
        (load_limits(count), &EngineBudget::unlimited()),
        routing(4),
    )
    .unwrap();
    let issued = drive(&mut reader, &bytes, |_| 0);
    let start = (1 + u64::from(slot_units)) * IO_UNIT as u64;
    let slot = (start, start + u64::from(slot_units) * IO_UNIT as u64);
    assert!(issued.len() > 2 * READ_DEPTH, "{} reads", issued.len());
    assert_eq!(shape(&issued, slot), Ok(()));
    assert_eq!(whole(reader.load()), GuardedLoad::Warm(entries));

    let serial: Vec<(DeviceRange, usize)> = (slot.0..slot.1)
        .step_by(IO_UNIT)
        .map(|at| (DeviceRange::new(at, IO_UNIT as u32).unwrap(), 1))
        .collect();
    assert_eq!(
        shape(&serial, slot),
        Err("read 1 is not a whole window".to_string()),
        "control: 4 KiB reads at queue depth 1 fail the shape check"
    );
    let shallow: Vec<(DeviceRange, usize)> = issued.iter().map(|(range, _)| (*range, 1)).collect();
    assert_eq!(
        shape(&shallow, slot),
        Err("read 15 issued with 1 outstanding".to_string()),
        "control: whole windows at queue depth 1 fail the depth clause"
    );
}

/// A checkpoint of up to 3000 entries of one to three extents each, with each of an overlap, an extent outside the
/// payload area, a zero-length last extent, a tail past one unit, a last record too short for its header, a shared
/// key, a shared slot, a capacity the extents overrun, an entry cap below the count and invalid limits planted at
/// random.
pub(crate) fn generated(rng: &mut SplitMix64) -> (Vec<CaptureEntry>, LoadLimits) {
    let count = 1 + rng.next_u64() as usize % 3000;
    let mut entries = entries(count);
    for (at, entry) in entries.iter_mut().enumerate() {
        entry.extents = (0..1 + rng.next_u64() % 3)
            .map(|extent| {
                ExtentLocator::new(8 * at as u64 + extent, 1)
                    .unwrap()
                    .bits()
            })
            .collect();
    }
    let pair = |rng: &mut SplitMix64| {
        let (a, b) = (
            rng.next_u64() as usize % count,
            rng.next_u64() as usize % count,
        );
        (a != b).then_some((a, b))
    };
    if rng.next_u64().is_multiple_of(2)
        && let Some((a, b)) = pair(rng)
    {
        entries[b].extents[0] = entries[a].extents[0];
    }
    if rng.next_u64().is_multiple_of(4) {
        let at = rng.next_u64() as usize % count;
        entries[at].extents[0] = ExtentLocator::new(1 << 20, 1).unwrap().bits();
    }
    if rng.next_u64().is_multiple_of(8) {
        let at = rng.next_u64() as usize % count;
        let last = entries[at].extents.len() - 1;
        entries[at].extents[last] = ExtentLocator::new(8 * at as u64 + 6, 0).unwrap().bits();
    }
    if rng.next_u64().is_multiple_of(8) {
        entries[rng.next_u64() as usize % count].tail = IO_UNIT as u16;
    }
    if rng.next_u64().is_multiple_of(8) {
        entries[rng.next_u64() as usize % count].tail = 1;
    }
    if rng.next_u64().is_multiple_of(4) {
        // An extent across the range edge of a destination at four or sixteen destinations, and at times a second
        // extent overlapping it in part.
        let shards = [4, 16][rng.next_u64() as usize % 2];
        let edge = (8 * count as u64 + 8).div_ceil(shards) * (1 + rng.next_u64() % (shards - 1));
        let (at, len) = (
            (edge.saturating_sub(4) / 8) as usize,
            2 + rng.next_u64() % 15,
        );
        if at < count && edge > len / 2 {
            let start = edge - len / 2;
            entries[at].extents = vec![ExtentLocator::new(start, len as u32).unwrap().bits()];
            if rng.next_u64().is_multiple_of(2)
                && let Some((_, b)) = pair(rng).filter(|&(_, b)| b != at)
            {
                entries[b].extents[0] = ExtentLocator::new(start + 1, len as u32).unwrap().bits();
            }
        }
    }
    if rng.next_u64().is_multiple_of(6)
        && let Some((a, b)) = pair(rng)
    {
        entries[b].key = entries[a].key;
    }
    if rng.next_u64().is_multiple_of(6)
        && let Some((a, b)) = pair(rng)
    {
        entries[b].allocation = entries[a].allocation;
    }
    let mut limits = load_limits(count);
    if rng.next_u64().is_multiple_of(4) {
        let total = rows(&entries);
        limits.reserve_units = limits.payload_end - total / 2;
    }
    if count > 1 && rng.next_u64().is_multiple_of(10) {
        limits.n_max = count - 1;
    }
    if rng.next_u64().is_multiple_of(12) {
        limits.reserve_units = limits.payload_end + 1;
    }
    (entries, limits)
}

/// `entries` encoded into slot 2 under capture 9, torn in the last unit when `tear`: the layout, the named checkpoint
/// and the prefix image.
pub(crate) fn slot_image(
    entries: &[CaptureEntry],
    tear: bool,
) -> (Layout, NamedCheckpoint, Vec<u8>) {
    slot_image_under(entries, tear, SESSION)
}

/// [`slot_image`] written by the session `session`.
pub(crate) fn slot_image_under(
    entries: &[CaptureEntry],
    tear: bool,
    session: u64,
) -> (Layout, NamedCheckpoint, Vec<u8>) {
    let slot_units = units(rows(entries)) as u32;
    let layout = layout(slot_units.max(2));
    let checkpoint = Checkpoint {
        shard: shard(),
        session,
        capture: 9,
    };
    let mut encoded = encode(Crc32c::detect(), checkpoint, entries, layout.slot_units).unwrap();
    if tear {
        encoded.last_mut().unwrap()[IO_UNIT - 1] ^= 1;
    }
    let ck = NamedCheckpoint {
        slot: 2,
        session,
        capture: 9,
        units: slot_units,
    };
    (layout, ck, prefix(&layout, 2, &encoded))
}

/// A reader of `ck` under `layout` and `limits` over `shards` destinations.
pub(crate) fn slot_reader(
    layout: &Layout,
    ck: NamedCheckpoint,
    limits: LoadLimits,
    shards: usize,
) -> SlotReader {
    let unlimited = EngineBudget::unlimited();
    SlotReader::new(
        Crc32c::detect(),
        layout,
        shard(),
        (ck, 0, &[]),
        SESSION,
        (limits, &unlimited),
        routing(shards),
    )
    .unwrap()
}

/// The load of `entries`, torn in the last unit when `tear`, through a reader over one, four or sixteen destinations
/// whose reads complete and jobs run in random orders.
fn streamed(
    entries: &[CaptureEntry],
    limits: LoadLimits,
    rng: &mut SplitMix64,
    tear: bool,
) -> SlotLoad {
    let shards = [1, 4, 16][rng.next_u64() as usize % 3];
    streamed_over(entries, limits, rng, tear, shards)
}

/// The load of `entries` through a reader over `shards` destinations, as [`streamed`] states.
fn streamed_over(
    entries: &[CaptureEntry],
    limits: LoadLimits,
    rng: &mut SplitMix64,
    tear: bool,
    shards: usize,
) -> SlotLoad {
    let (layout, ck, bytes) = slot_image(entries, tear);
    let mut reader = slot_reader(&layout, ck, limits, shards);
    drive(&mut reader, &bytes, |len| rng.next_u64() as usize % len);
    reader.load()
}

/// Whether an in-bounds extent of `entries` spans the edge of two destination ranges among `shards` destinations,
/// whose ranges each hold `ceil(payload / shards)` units.
fn spans_an_edge(entries: &[CaptureEntry], limits: LoadLimits, shards: u64) -> bool {
    let per = (limits.payload_end - limits.payload_start).div_ceil(shards);
    entries
        .iter()
        .flat_map(|entry| &entry.extents)
        .any(|&bits| {
            let locator = ExtentLocator::from_bits(bits);
            let (start, len) = (locator.start_unit(), u64::from(locator.len_units()));
            let end = start + len;
            len > 0
                && start >= limits.payload_start
                && end <= limits.payload_end
                && (start - limits.payload_start) / per != (end - 1 - limits.payload_start) / per
        })
}

fn planted<T>(plant: Plant, run: impl FnOnce() -> T) -> T {
    PLANT.with(|cell| cell.set(Some(plant)));
    let load = run();
    PLANT.with(|cell| cell.set(None));
    load
}

#[test]
fn streamed_guard_equals_batch_guard() {
    let mut rng = SplitMix64::new(0x1294);
    let (mut per_window, mut all_or_nothing, mut guarded_torn, mut split) = (false, false, 0, 0);
    let mut verdicts = Vec::new();
    let mut across = entries(3000);
    across[2900].extents = across[0].extents.clone();
    for case in 0..120 {
        let (entries, limits) = if case == 0 {
            (across.clone(), load_limits(3000))
        } else {
            generated(&mut rng)
        };
        let batch = canon(guarded_load(
            entries.clone(),
            limits,
            &EngineBudget::unlimited(),
        ));
        verdicts.push(match batch {
            GuardedLoad::Warm(_) => None,
            GuardedLoad::Cold { refusal, .. } => Some(refusal),
        });
        assert_eq!(
            whole(streamed(&entries, limits, &mut rng, false)),
            batch,
            "case {case}"
        );
        for shards in [4, 16] {
            if spans_an_edge(&entries, limits, shards) {
                split += 1;
                assert_eq!(
                    whole(streamed_over(
                        &entries,
                        limits,
                        &mut rng,
                        false,
                        shards as usize
                    )),
                    batch,
                    "case {case}: a span split over {shards} destinations"
                );
            }
        }
        let last = units(rows(&entries)) as usize - 1;
        let kept = canonical(outside(&entries, last));
        let (damage, load) = damaged(streamed(&entries, limits, &mut rng, true));
        assert_eq!(damage.failed, [last as u32], "case {case}");
        assert_eq!(damage.alarm(), LoadRefusal::StaleWrite, "case {case}");
        assert_eq!(
            loaded(load.clone()),
            kept,
            "case {case}: a torn last unit loses only its own entries"
        );
        // When no entry's rows cross into the torn unit, the guard saw exactly the kept entries' rows, so its verdict
        // is the batch guard's over them.
        let uncut = rows(&kept) == (last as u64 - 1) * crate::failover::records::UNIT_ENTRIES;
        if uncut {
            assert_eq!(
                load,
                canon(guarded_load(
                    kept.clone(),
                    limits,
                    &EngineBudget::unlimited()
                )),
                "case {case}: the intact entries get the batch guard's verdict"
            );
            guarded_torn += usize::from(matches!(load, GuardedLoad::Cold { .. }));
        }
        let passes = matches!(batch, GuardedLoad::Warm(_));
        if passes {
            assert_eq!(
                load,
                GuardedLoad::Warm(kept.clone()),
                "case {case}: the intact entries of a slot that passes whole pass"
            );
        }
        PER_WINDOW.with(|cell| cell.set(true));
        per_window |= whole(streamed(&entries, limits, &mut rng, false)) != batch;
        PER_WINDOW.with(|cell| cell.set(false));
        all_or_nothing |= passes
            && !kept.is_empty()
            && planted(Plant::AllOrNothing, || {
                streamed(&entries, limits, &mut rng, true)
            })
            .load()
                != GuardedLoad::Warm(kept);
    }
    assert!(
        guarded_torn > 0,
        "some torn slot's intact entries are refused by the guard"
    );
    assert!(split > 0, "some case splits a span at a destination edge");
    for verdict in [
        None,
        Some(LoadRefusal::Limits),
        Some(LoadRefusal::Entries),
        Some(LoadRefusal::Overlap),
        Some(LoadRefusal::Bounds),
        Some(LoadRefusal::Key),
        Some(LoadRefusal::Slot),
        Some(LoadRefusal::Units),
    ] {
        assert!(
            verdicts.contains(&verdict),
            "no generated case yields {verdict:?}"
        );
    }
    assert!(
        per_window,
        "control: a guard checking overlap per window only returns another verdict than the batch guard"
    );
    assert!(
        all_or_nothing,
        "control: a reader that loads nothing from a damaged slot loses entries no damaged unit holds"
    );
}

/// A member of an in-progress capture is removed after `t0` and its unit is reused by another key while the cut
/// still names the member on that unit. The capture's publication proof refuses `Released`, so no Publish names the
/// reused unit; a pass in which no member left before the proof publishes the same snapshot and loads it warm. The
/// proof requires the tenure's suffix, so a removal after the proof and before the Publish refuses `History` while
/// the log is unopened and the pass stays intact, and a stale counter refuses `Superseded`.
#[test]
fn evict_reuse_during_capture() {
    use crate::storage::publish_tests::{TRIES, budget, index_config, key, storage};
    use crate::storage::recovery::CaptureError;
    use crate::storage::remove::RemoveError;
    let crc = Crc32c::detect();
    let layout = layout(2);
    let staged = |captured: &[CaptureEntry], possible: &mut PossiblyNamed, bytes: &mut [u8]| {
        let checkpoint = Checkpoint {
            shard: shard(),
            session: SESSION,
            capture: 1,
        };
        let mut stage = StagedCheckpoint::new(
            crc,
            possible,
            (checkpoint, captured),
            &EngineBudget::unlimited(),
        )
        .unwrap();
        land(&layout, &mut stage, bytes);
        stage
    };
    for removed in [true, false] {
        let s = storage(4, &index_config(&[4], (1, 1), 2));
        let (bound, kept) = observed_completed(&s, key(3));
        bound.publish(TRIES, &mut budget()).unwrap();
        let (bound, before) = observed_completed(&s, key(1));
        let a = bound.publish(TRIES, &mut budget()).unwrap();
        let counter = s.start_capture(4, true, 4).unwrap();
        if removed {
            s.remove(&key(1), a, TRIES, &mut budget()).unwrap();
            let _ = s.certify(&mut budget()).unwrap();
            for _ in 0..4 {
                s.service(&mut budget()).unwrap();
            }
            let (bound, after) = observed_completed(&s, key(2));
            bound.publish(TRIES, &mut budget()).unwrap();
            assert_eq!(
                before.extents, after.extents,
                "the evicted entry's unit is reused"
            );
        }
        let mut captured = drain(&s);
        captured.sort_by_key(CaptureEntry::slot);
        let mut expected = vec![before, kept];
        expected.sort_by_key(CaptureEntry::slot);
        assert_eq!(captured, expected, "the cut is the t0 snapshot");
        // The tenure's reader admits only its own generation's sessions, which the test storage's do not share.
        for entry in captured.iter_mut().chain(&mut expected) {
            entry.session = SESSION;
        }
        let store = seeded();
        let mut host = client(&store);
        let mut possible = PossiblyNamed::new((shard(), SESSION), layout, None);
        let mut bytes = vec![0; layout.units as usize * IO_UNIT];
        let mut stage = staged(&captured, &mut possible, &mut bytes);
        let current = read(&mut host);
        assert_eq!(
            s.cut_intact((shard(), SESSION), counter + 1),
            Err(CaptureError::Superseded),
            "a proof names only the current pass"
        );
        let published = s.cut_intact((shard(), SESSION), counter).map(|cut| {
            if !removed {
                assert_eq!(
                    s.remove(&key(1), a, TRIES, &mut budget()).err(),
                    Some(RemoveError::History),
                    "the proof requires the suffix, whose unopened log records no removal"
                );
            }
            publish(
                &mut host,
                &mut possible,
                &current,
                (own(), None),
                (&cut, s.capture_epoch()),
                &mut stage,
            )
        });
        if removed {
            assert_eq!(
                published.map(|_| ()),
                Err(CaptureError::Released),
                "a cut naming a released member's unit does not publish"
            );
            assert_eq!(
                stored(&store).1.checkpoint,
                None,
                "no Publish reached the store"
            );
            assert_eq!(possible.slots(), Vec::<u32>::new());
            assert!(
                !s.pool().capture_lock().unwrap().suffix.required(),
                "a refused proof requires no suffix"
            );
            continue;
        }
        published.unwrap().unwrap();
        assert!(
            s.cut_intact((shard(), SESSION), counter).is_ok(),
            "the refused removal left the pass intact"
        );
        let mut reader = SlotReader::new(
            crc,
            &layout,
            shard(),
            (stage.named(), 0, &[]),
            SESSION,
            (limits(), &EngineBudget::unlimited()),
            routing(4),
        )
        .unwrap();
        drive(&mut reader, &bytes, |_| 0);
        assert_eq!(whole(reader.load()), GuardedLoad::Warm(expected));
    }
}

/// Stages `captured` as capture `proof.counter()` of `(shard(), SESSION)` over a fresh seeded store, lands and reads
/// back every unit, and publishes it under `proof` and the storage epoch `epoch`; returns the Publish's outcome and the
/// checkpoint the store then names.
pub(crate) fn published_capture(
    captured: &[CaptureEntry],
    (proof, epoch): (&CutIntact, CaptureEpoch),
) -> (Result<(), WriteRefused>, Option<NamedCheckpoint>) {
    let store = seeded();
    let mut host = client(&store);
    let mut possible = PossiblyNamed::new((shard(), SESSION), layout(2), None);
    let current = read(&mut host);
    let published = published_over(
        (&mut host, &mut possible),
        (&current, own(), None),
        (proof, epoch),
        captured,
    );
    (published.map(|_| ()), stored(&store).1.checkpoint)
}

/// Stages `captured` as the checkpoint of `proof`'s pass, lands and reads back every unit, then publishes it over
/// `read`, which shows `own` and the `known` checkpoint.
pub(crate) fn published_over(
    (host, possible): (&mut Client<Shared, MemLog>, &mut PossiblyNamed),
    (read, own, known): (&Read<ShardRecord>, Target, Option<NamedCheckpoint>),
    (proof, epoch): (&CutIntact, CaptureEpoch),
    captured: &[CaptureEntry],
) -> Result<Read<ShardRecord>, WriteRefused> {
    let layout = *possible.layout();
    let (shard, session) = proof.tenure();
    let checkpoint = Checkpoint {
        shard,
        session,
        capture: proof.counter(),
    };
    let budget = EngineBudget::unlimited();
    let mut stage =
        StagedCheckpoint::new(Crc32c::detect(), possible, (checkpoint, captured), &budget).unwrap();
    let mut bytes = vec![0; layout.units as usize * IO_UNIT];
    land(&layout, &mut stage, &mut bytes);
    publish(
        host,
        possible,
        read,
        (own, known),
        (proof, epoch),
        &mut stage,
    )
}

/// Writes every unit of `stage` into the prefix image `bytes` and takes each unit's read-back of the image.
fn land(layout: &Layout, stage: &mut StagedCheckpoint, bytes: &mut [u8]) {
    let start = (1 + stage.slot() as usize * layout.slot_units as usize) * IO_UNIT;
    for unit in 0..stage.units().len() {
        let at = start + unit * IO_UNIT;
        stage.wrote(unit as u32);
        bytes[at..at + IO_UNIT].copy_from_slice(&stage.units()[unit][..]);
        let read: [u8; UNIT_LEN] = bytes[at..at + IO_UNIT].try_into().unwrap();
        stage.read_back((stage.slot(), unit as u32), &read);
    }
}

fn published_image(
    (store, arm): (&Shared, Option<Arm>),
    host: &mut Client<Shared, MemLog>,
    possible: &mut PossiblyNamed,
    layout: &Layout,
    bytes: &mut [u8],
    capture: u32,
) -> (NamedCheckpoint, Vec<CaptureEntry>, Result<(), WriteRefused>) {
    let (mut stage, entries) = landed(possible, layout, bytes, capture);
    let current = read(host);
    let known = current.value().checkpoint;
    if let Some(arm) = arm {
        store.schedule(arm);
    }
    let published = publish(
        host,
        possible,
        &current,
        (own(), known),
        (&cut(stage.named().capture), CaptureEpoch::default()),
        &mut stage,
    )
    .map(|_| ());
    (stage.named(), entries, published)
}

fn recovered(
    store: &Shared,
    layout: &Layout,
    bytes: &[u8],
) -> (Option<NamedCheckpoint>, GuardedLoad) {
    let mut host = client(store);
    let mut possible = set(None);
    let current = read(&mut host);
    let confirmed = confirm(&mut host, &mut possible, &current, own()).unwrap();
    let named = confirmed.value().checkpoint;
    assert_eq!(
        possible.slots(),
        named.map(|ck| ck.slot).into_iter().collect::<Vec<_>>(),
        "the Confirm proves which slot is named"
    );
    let Some(ck) = named else {
        return (None, GuardedLoad::Warm(Vec::new()));
    };
    let mut reader = SlotReader::new(
        Crc32c::detect(),
        layout,
        shard(),
        (ck, 0, &[]),
        SESSION,
        (load_limits(50), &EngineBudget::unlimited()),
        routing(4),
    )
    .unwrap();
    drive(&mut reader, bytes, |_| 0);
    (named, whole(reader.load()))
}

#[test]
fn checkpoint_unit_inflight() {
    let layout = layout(4);
    let store = seeded();
    let mut host = client(&store);
    let mut possible = set(None);
    let mut bytes = vec![0; layout.units as usize * IO_UNIT];
    let (first, entries, published) = published_image(
        (&store, None),
        &mut host,
        &mut possible,
        &layout,
        &mut bytes,
        1,
    );
    assert_eq!(published, Ok(()));
    let checkpoint = Checkpoint {
        shard: shard(),
        session: SESSION,
        capture: 2,
    };
    let mut next = StagedCheckpoint::new(
        Crc32c::detect(),
        &mut possible,
        (checkpoint, &entries),
        &EngineBudget::unlimited(),
    )
    .unwrap();
    assert_ne!(next.slot(), first.slot);
    for unit in 0..next.units().len() {
        next.wrote(unit as u32);
        let at = (1 + next.slot() as usize * layout.slot_units as usize + unit) * IO_UNIT;
        bytes[at..at + 512].fill(0x5A);
    }
    let exposed = next.slot();
    next.abandon(&mut possible);
    assert_eq!(
        possible.quarantined(),
        [exposed],
        "the slot a unit write reached is quarantined for the rest of the tenure"
    );
    assert_ne!(possible.free_slot(), Some(exposed));
    drop(host);
    let (named, load) = recovered(&store, &layout, &bytes);
    assert_eq!(
        named,
        Some(first),
        "a crash with a unit in flight leaves the earlier checkpoint named"
    );
    assert_eq!(load, GuardedLoad::Warm(entries));
}

#[test]
fn publish_unacknowledged() {
    for applied in [true, false] {
        let layout = layout(4);
        let store = seeded();
        let mut host = client(&store);
        let mut possible = set(None);
        let mut bytes = vec![0; layout.units as usize * IO_UNIT];
        let (first, first_entries, published) = published_image(
            (&store, None),
            &mut host,
            &mut possible,
            &layout,
            &mut bytes,
            1,
        );
        assert_eq!(published, Ok(()));
        let (_, second_entries, unknown) = published_image(
            (&store, Some(Arm::Hold)),
            &mut host,
            &mut possible,
            &layout,
            &mut bytes,
            2,
        );
        assert_eq!(
            unknown,
            Err(WriteRefused::Store(StoreError::Unknown)),
            "the second Publish's reply is unknown"
        );
        drop(host);
        if applied {
            store.release();
        }
        let (named, load) = recovered(&store, &layout, &bytes);
        let late = store.release();
        if applied {
            assert_eq!(late, Vec::new(), "the applied Publish left nothing held");
            let second = named.expect("the applied Publish names the second checkpoint");
            assert_eq!(second.capture, 2);
            assert_eq!(load, GuardedLoad::Warm(second_entries));
        } else {
            assert_eq!(
                late,
                vec![Outcome::NotCommitted(Refusal::Condition)],
                "the Publish applied after the Confirm fails on the record version"
            );
            assert_eq!(stored(&store).1.checkpoint, Some(first));
            assert_eq!(named, Some(first));
            assert_eq!(load, GuardedLoad::Warm(first_entries));
        }
    }
}

/// A damaged unit of the named slot loses only the entries with a row on it: the load keeps every other entry, names
/// the damaged unit, and raises the stale-write alarm for a failed check and the unreadable alarm for a failed read.
#[test]
fn a_torn_unit_loses_only_its_entries_and_raises_the_stale_write_alarm() {
    let count = 200;
    let entries = entries(count);
    let crc = Crc32c::detect();
    let slot_units = units(rows(&entries)) as u32;
    let layout = layout(slot_units);
    let checkpoint = Checkpoint {
        shard: shard(),
        session: SESSION,
        capture: 6,
    };
    let encoded = encode(crc, checkpoint, &entries, u32::MAX).unwrap();
    let ck = NamedCheckpoint {
        slot: 0,
        session: SESSION,
        capture: 6,
        units: slot_units,
    };
    let reader = || {
        SlotReader::new(
            crc,
            &layout,
            shard(),
            (ck, 0, &[]),
            SESSION,
            (load_limits(count), &EngineBudget::unlimited()),
            routing(4),
        )
        .unwrap()
    };
    for torn in 1..slot_units as usize {
        let mut torn_units = encoded.clone();
        torn_units[torn][IO_UNIT - 1] ^= 1;
        let bytes = prefix(&layout, 0, &torn_units);
        let mut slot = reader();
        drive(&mut slot, &bytes, |_| 0);
        let (damage, load) = damaged(slot.load());
        let lost = 41 * (torn - 1)..41 * torn;
        let kept: Vec<CaptureEntry> = entries
            .iter()
            .enumerate()
            .filter(|(at, _)| !lost.contains(at))
            .map(|(_, entry)| entry.clone())
            .collect();
        assert_eq!(damage.failed, [torn as u32], "unit {torn} torn");
        assert_eq!(damage.alarm(), LoadRefusal::StaleWrite, "unit {torn} torn");
        assert_eq!(load.events().count(), 0, "no intact entry is evicted");
        assert_eq!(
            load,
            GuardedLoad::Warm(kept),
            "unit {torn} torn: every entry of the intact units loads"
        );
    }
    let bytes = prefix(&layout, 0, &encoded);
    let mut slot = reader();
    let first = slot.next_read().unwrap();
    slot.fail_read(first);
    while let Some(range) = slot.next_read() {
        let start = range.start() as usize;
        slot.complete(range, &bytes[start..start + range.byte_len() as usize]);
    }
    let (unread, _) = damaged(slot.load());
    assert_eq!(unread.alarm(), LoadRefusal::Unreadable);
    assert_eq!(unread.unread, (0..slot_units).collect::<Vec<_>>());
}

/// A two-window slot of 41 * 70 single-extent entries under capture 6, its layout and its units.
fn two_windows() -> (
    Vec<CaptureEntry>,
    Layout,
    NamedCheckpoint,
    Vec<Box<[u8; UNIT_LEN]>>,
) {
    let entries = entries(41 * 70);
    let slot_units = units(rows(&entries)) as u32;
    let layout = layout(slot_units);
    let checkpoint = Checkpoint {
        shard: shard(),
        session: SESSION,
        capture: 6,
    };
    let encoded = encode(Crc32c::detect(), checkpoint, &entries, slot_units).unwrap();
    let ck = NamedCheckpoint {
        slot: 0,
        session: SESSION,
        capture: 6,
        units: slot_units,
    };
    (entries, layout, ck, encoded)
}

fn two_window_reader(layout: &Layout, ck: NamedCheckpoint, count: usize) -> SlotReader {
    SlotReader::new(
        Crc32c::detect(),
        layout,
        shard(),
        (ck, 0, &[]),
        SESSION,
        (load_limits(count), &EngineBudget::unlimited()),
        routing(4),
    )
    .unwrap()
}

#[test]
fn a_reader_keeps_at_most_read_depth_reads_outstanding() {
    let entries = entries(41 * 64 * (READ_DEPTH + 4));
    let (layout, ck, bytes) = slot_image(&entries, false);
    let mut reader = slot_reader(&layout, ck, load_limits(entries.len()), 4);
    let issued: Vec<DeviceRange> = std::iter::from_fn(|| reader.next_read()).collect();
    assert_eq!(issued.len(), READ_DEPTH);
    let start = issued[0].start() as usize;
    let job = reader.completed(
        issued[0],
        bytes[start..start + issued[0].byte_len() as usize].to_vec(),
    );
    drop(job);
    assert!(
        reader.next_read().is_some(),
        "a settled read admits one more"
    );
    assert_eq!(reader.next_read(), None);
}

#[test]
fn a_reader_stops_reads_and_jobs_after_a_helper_failure() {
    let entries = entries(41 * 64 * 4);
    let (layout, ck, bytes) = slot_image(&entries, false);
    let mut reader = slot_reader(&layout, ck, load_limits(entries.len()), 4);
    let range = reader.next_read().unwrap();
    let start = range.start() as usize;
    let job = reader.completed(
        range,
        bytes[start..start + range.byte_len() as usize].to_vec(),
    );
    reader.decode().landed(run(job.expect("a slot read")));
    let control = slot_reader(&layout, ck, load_limits(entries.len()), 4);
    assert!(!control.done(), "control: a fresh reader is not done");
    reader.decode().fail();
    assert_eq!(reader.next_read(), None, "no read after the failure");
    assert!(
        reader.decode().work().is_none(),
        "no destination job after the failure"
    );
    assert!(reader.done());
    assert!(reader.finish().is_none(), "a helper failure yields no load");
}

#[test]
fn a_completion_the_reader_did_not_issue_panics_before_it_decodes() {
    let (entries, layout, ck, _) = two_windows();
    let mut both = two_window_reader(&layout, ck, entries.len());
    let (first, second) = (both.next_read().unwrap(), both.next_read().unwrap());
    let unit = IO_UNIT as u32;
    let foreign = [
        (second, "a read not yet issued"),
        (
            DeviceRange::new(first.start() + u64::from(unit), first.byte_len() - unit).unwrap(),
            "the tail of the issued read",
        ),
        (
            DeviceRange::new(first.start() - u64::from(unit), unit).unwrap(),
            "a unit below the slot",
        ),
        (
            DeviceRange::new(first.start(), unit).unwrap(),
            "a short read",
        ),
        (first, "a second completion of the issued read"),
    ];
    for (range, case) in foreign {
        let mut reader = two_window_reader(&layout, ck, entries.len());
        let issued = reader.next_read().unwrap();
        if range == first {
            let _ = reader.completed(issued, Vec::new());
        }
        let completed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = reader.completed(range, Vec::new());
        }));
        assert!(completed.is_err(), "{case}");
        if range != first {
            assert!(!reader.done(), "{case}: the issued read stays outstanding");
            let _ = reader.completed(issued, Vec::new());
        }
        assert_eq!(reader.next_read(), Some(second), "{case}");
    }
}

#[test]
fn a_failed_read_loses_only_its_units_and_a_failed_check_outranks_it() {
    let (entries, layout, ck, encoded) = two_windows();
    let bytes = prefix(&layout, 0, &encoded);
    let mut reader = two_window_reader(&layout, ck, entries.len());
    let (first, second) = (reader.next_read().unwrap(), reader.next_read().unwrap());
    assert_eq!(reader.next_read(), None, "the slot spans two windows");
    let at = first.start() as usize;
    reader.complete(first, &bytes[at..at + first.byte_len() as usize]);
    reader.fail_read(second);
    let decoded = first.byte_len() / IO_UNIT as u32;
    let whole = (decoded as usize - 1) * 41;
    let (unread, load) = damaged(reader.load());
    assert_eq!(unread.alarm(), LoadRefusal::Unreadable);
    assert_eq!(unread.unread, (decoded..ck.units).collect::<Vec<_>>());
    assert_eq!(load, GuardedLoad::Warm(entries[..whole].to_vec()));

    let mut torn = encoded.clone();
    torn[5][IO_UNIT - 1] ^= 1;
    let bytes = prefix(&layout, 0, &torn);
    for failed_first in [false, true] {
        let mut reader = two_window_reader(&layout, ck, entries.len());
        let (first, second) = (reader.next_read().unwrap(), reader.next_read().unwrap());
        let at = first.start() as usize;
        if failed_first {
            reader.fail_read(second);
        }
        reader.complete(first, &bytes[at..at + first.byte_len() as usize]);
        if !failed_first {
            reader.fail_read(second);
        }
        let decoded = first.byte_len() / IO_UNIT as u32;
        let (damage, load) = damaged(reader.load());
        assert_eq!(
            damage.alarm(),
            LoadRefusal::StaleWrite,
            "a stale unit raises the stale-write alarm whether the failed read completes first or last"
        );
        assert_eq!(damage.failed, [5], "failed first {failed_first}");
        assert_eq!(
            damage.unread,
            (decoded..ck.units).collect::<Vec<_>>(),
            "failed first {failed_first}: the unread window may load on a later read"
        );
        let read = &entries[..(decoded as usize - 1) * 41];
        assert_eq!(
            load,
            GuardedLoad::Warm(outside(read, 5)),
            "failed first {failed_first}: the read window's intact entries load"
        );
    }
}

/// An entry whose rows straddle a failed read has a row on an unread unit, so it is lost with that read, as
/// unreadable damage; the whole entries after it load.
#[test]
fn an_entry_straddling_a_failed_read_is_lost_as_unreadable() {
    let mut entries = entries(41 * 70);
    let at = 41 * 62 - 1;
    entries[at].extents = vec![
        ExtentLocator::new(8 * at as u64, 1).unwrap().bits(),
        ExtentLocator::new(8 * at as u64 + 1, 1).unwrap().bits(),
    ];
    let slot_units = units(rows(&entries)) as u32;
    let layout = layout(slot_units);
    let checkpoint = Checkpoint {
        shard: shard(),
        session: SESSION,
        capture: 6,
    };
    let encoded = encode(Crc32c::detect(), checkpoint, &entries, slot_units).unwrap();
    let ck = NamedCheckpoint {
        slot: 0,
        session: SESSION,
        capture: 6,
        units: slot_units,
    };
    let bytes = prefix(&layout, 0, &encoded);
    let mut reader = two_window_reader(&layout, ck, entries.len());
    let (first, second) = (reader.next_read().unwrap(), reader.next_read().unwrap());
    reader.fail_read(first);
    let at = second.start() as usize;
    reader.complete(second, &bytes[at..at + second.byte_len() as usize]);
    let (unread, load) = damaged(reader.load());
    assert_eq!(
        unread.alarm(),
        LoadRefusal::Unreadable,
        "the continuation row after the unread window is the read failure's, not a stale write's"
    );
    let straddling = 41 * 62 - 1;
    assert_eq!(
        load,
        GuardedLoad::Warm(entries[straddling + 1..].to_vec()),
        "the straddling entry is lost and every whole entry of the read window loads"
    );
}

#[test]
fn a_short_completion_counts_its_missing_units_as_unread() {
    let (entries, layout, ck, encoded) = two_windows();
    let bytes = prefix(&layout, 0, &encoded);
    for kept in [0, IO_UNIT, IO_UNIT + 512] {
        let mut reader = two_window_reader(&layout, ck, entries.len());
        let (first, second) = (reader.next_read().unwrap(), reader.next_read().unwrap());
        let at = first.start() as usize;
        reader.complete(first, &bytes[at..at + first.byte_len() as usize]);
        let at = second.start() as usize;
        reader.complete(second, &bytes[at..at + kept]);
        let slot = reader.load();
        assert!(!slot.installable(), "{kept}");
        let (short, load) = damaged(slot);
        assert_eq!(
            short.alarm(),
            LoadRefusal::Unreadable,
            "a completion holding {kept} of the read's bytes"
        );
        let held = (second.start() / IO_UNIT as u64 - 1) as u32 + (kept / IO_UNIT) as u32;
        assert_eq!(short.unread, (held..ck.units).collect::<Vec<_>>(), "{kept}");
        assert_eq!(
            load,
            GuardedLoad::Warm(
                entries[..(held as usize - 1) * crate::failover::records::UNIT_ENTRIES as usize]
                    .to_vec()
            ),
            "{kept}: the whole entries of the units before the first unread unit load"
        );
    }
}

#[test]
fn a_later_tenure_reads_the_checkpoint_and_another_generation_does_not() {
    let (entries, layout, ck, encoded) = two_windows();
    let bytes = prefix(&layout, 0, &encoded);
    let read_as = |reader: u64| {
        let mut slot = SlotReader::new(
            Crc32c::detect(),
            &layout,
            shard(),
            (ck, 0, &[]),
            reader,
            (load_limits(entries.len()), &EngineBudget::unlimited()),
            routing(4),
        )
        .unwrap();
        drive(&mut slot, &bytes, |_| 0);
        slot.load()
    };
    assert_eq!(
        whole(read_as((3 << 32) | 4)),
        GuardedLoad::Warm(entries.clone()),
        "a later tenure of the writer's generation"
    );
    let (foreign, load) = damaged(read_as((4 << 32) | 2));
    assert_eq!(
        (foreign.alarm(), foreign.failed.len(), load),
        (
            LoadRefusal::StaleWrite,
            ck.units as usize,
            GuardedLoad::Warm(Vec::new())
        ),
        "control: a reader of another generation refuses the writer's session"
    );
}

#[test]
fn the_reader_refuses_a_slot_outside_the_layout_or_past_the_budget() {
    let (entries, layout, ck, _) = two_windows();
    let reader = |layout: &Layout, ck: NamedCheckpoint, budget: &EngineBudget| {
        SlotReader::new(
            Crc32c::detect(),
            layout,
            shard(),
            (ck, 0, &[]),
            SESSION,
            (load_limits(entries.len()), budget),
            routing(4),
        )
        .map(|_| ())
    };
    let unlimited = EngineBudget::unlimited();
    let last = NamedCheckpoint {
        slot: layout.slots - 1,
        ..ck
    };
    assert_eq!(
        reader(&layout, last, &unlimited),
        Ok(()),
        "the last slot at its full units"
    );
    for (named, case) in [
        (
            NamedCheckpoint {
                slot: layout.slots,
                ..ck
            },
            "a slot past the layout",
        ),
        (NamedCheckpoint { units: 0, ..ck }, "zero units"),
        (
            NamedCheckpoint {
                units: layout.slot_units + 1,
                ..ck
            },
            "more units than the slot",
        ),
    ] {
        assert_eq!(
            reader(&layout, named, &unlimited),
            Err(ReaderRefusal::Slot),
            "{case}"
        );
    }
    let below = Layout {
        units: layout.units - 1,
        ..layout
    };
    assert_eq!(
        reader(&below, ck, &unlimited),
        Err(ReaderRefusal::Slot),
        "a layout below its floor"
    );
    // A suffix LSN count past `u64` is refused, and so is a layout whose bytes overflow `u64`, before the budget.
    // The layout's bytes fit `u64`, so only the suffix LSN count of 2^14 region-long suffixes overflows.
    let vast = Layout {
        units: 1 << 51,
        ..layout
    };
    let long = |start| Suffix {
        session: SESSION,
        start,
        certified: u64::MAX,
        end: u64::MAX,
    };
    let overflowing: Vec<_> = (0..1 << 14).map(long).collect();
    let suffix_reader = |layout: &Layout, ancestry: &[Suffix], budget: &EngineBudget| {
        SlotReader::new(
            Crc32c::detect(),
            layout,
            shard(),
            (ck, 0, ancestry),
            SESSION,
            (load_limits(entries.len()), budget),
            routing(4),
        )
        .map(|_| ())
    };
    assert_eq!(
        suffix_reader(&vast, &overflowing, &unlimited),
        Err(ReaderRefusal::Slot),
        "a suffix LSN count past u64"
    );
    let wide = Layout {
        units: 1 << 52,
        ..layout
    };
    assert_eq!(
        suffix_reader(&wide, &[], &EngineBudget::new(0)),
        Err(ReaderRefusal::Slot),
        "a layout whose bytes pass u64, before the budget"
    );
    let bytes = SlotDecode::bytes(
        ck.units,
        &load_limits(entries.len()),
        4,
        (WINDOWS, READ_LEN as usize),
    )
    .unwrap();
    let limits = load_limits(entries.len());
    let past = SlotDecode::bytes(ck.units, &limits, 4, (usize::MAX, usize::MAX));
    assert_eq!(past, None, "an estimate past u128 is refused");
    assert_eq!(reader(&layout, ck, &EngineBudget::new(bytes)), Ok(()));
    assert_eq!(
        reader(&layout, ck, &EngineBudget::new(bytes - 1)),
        Err(ReaderRefusal::Memory),
        "a budget one byte short of the decode"
    );
    let refused = SlotReader::new(
        Crc32c::detect(),
        &layout,
        shard(),
        (ck, 0, &[]),
        SESSION,
        (load_limits(entries.len()), &unlimited),
        routing(0),
    );
    assert_eq!(
        refused.map(|_| ()),
        Err(ReaderRefusal::Slot),
        "zero destinations"
    );
    let checkpoint = Checkpoint {
        shard: shard(),
        session: SESSION,
        capture: ck.capture,
    };
    let limits = load_limits(entries.len());
    let decode = SlotDecode::new(
        Crc32c::detect(),
        checkpoint,
        ck.units,
        SESSION,
        limits,
        routing(0),
        (
            crate::storage::recovery::checkpoint_tests::no_suffix(),
            0,
            &[],
        ),
    );
    assert!(decode.is_none(), "a decode needs a destination");
}

#[test]
fn publish_and_confirm_refuse_another_tenure_or_checkpoint_before_any_request() {
    let store = seeded();
    let mut host = client(&store);
    let mut possible = set(Some(named(0, 1)));
    let current = read(&mut host);
    let before = stored(&store);
    let deposed = Target {
        attempts: own().attempts + 1,
        ..own()
    };
    let mut stage = staged(&mut possible, named(1, 2));
    let other = (1..)
        .filter_map(crate::net::ownership::Shard::new)
        .find(|other| *other != shard())
        .unwrap();
    let foreign = |set: &mut PossiblyNamed, shard, session| {
        let mut stage = StagedCheckpoint::reserved_at(
            set,
            Checkpoint {
                shard,
                session,
                capture: 2,
            },
            1,
            vec![Box::new([0; UNIT_LEN])],
        );
        stage.wrote(0);
        stage.read_back((1, 0), &[0; UNIT_LEN]);
        stage
    };
    for (target, known, epoch, expected) in [
        (deposed, None, CaptureEpoch::default(), WriteRefused::Tenure),
        (
            own(),
            Some(named(2, 1)),
            CaptureEpoch::default(),
            WriteRefused::Known,
        ),
        (own(), None, CaptureEpoch(1), WriteRefused::Replaced),
    ] {
        let case = format!("{expected:?}");
        let units = stage.units().to_vec();
        let refused = publish(
            &mut host,
            &mut possible,
            &current,
            (target, known),
            (&cut(2), epoch),
            &mut stage,
        );
        assert_eq!(refused.map(|_| ()), Err(expected), "{case}");
        assert_eq!(stage.units(), units, "{case}: the stage keeps its bytes");
        assert!(
            possible.admits(&stage),
            "{case}: the stage keeps its reservation"
        );
        assert_eq!(
            possible.free_slot(),
            None,
            "{case}: the reserved slot stays unavailable"
        );
    }
    for (stage_shard, session, case) in [
        (other, SESSION, "a stage of another shard"),
        (shard(), SESSION + 2, "a stage of a later session"),
        (shard(), SESSION - 2, "a stage of an earlier session"),
        (
            shard(),
            SESSION + (1 << 32),
            "a stage of another generation",
        ),
    ] {
        let mut other_set = set(Some(named(0, 1)));
        let mut stage = foreign(&mut other_set, stage_shard, session);
        assert_eq!(
            publish(
                &mut host,
                &mut other_set,
                &current,
                (own(), None),
                (
                    &cut_under((stage_shard, session), 2),
                    CaptureEpoch::default()
                ),
                &mut stage
            )
            .map(|_| ()),
            Err(WriteRefused::Tenure),
            "{case} publishes nothing over this tenure's record"
        );
        assert!(other_set.admits(&stage), "{case}");
    }
    assert_eq!(
        confirm(&mut host, &mut possible, &current, deposed).map(|_| ()),
        Err(WriteRefused::Tenure)
    );
    assert_eq!(stored(&store), before, "no refused write reached the store");
    assert_eq!(
        possible.slots(),
        vec![0],
        "no refused write entered the set"
    );
    stage.abandon(&mut possible);
    assert_eq!(
        possible.quarantined(),
        [1],
        "the written slot of the abandoned stage"
    );
}

/// Publish and Confirm write only a record of the set's tenure: another shard's record under the same
/// `(generation, owner, E)` and a record with no activated `E` refuse before any request, and a tenure of another
/// generation and `E` publishes under the session `g·2^32 + 2E` that record derives.
#[test]
fn publish_and_confirm_refuse_a_record_outside_the_sets_tenure() {
    let other = (1..)
        .filter_map(crate::net::ownership::Shard::new)
        .find(|other| *other != shard())
        .unwrap();
    let store = seeded();
    let mut host = client(&store);
    let seeded_record = *read(&mut host).value();
    host.create_shard(ShardRecord {
        shard: other,
        ..seeded_record
    })
    .unwrap();
    let foreign = host.read::<ShardRecord>(Key::Shard(other)).unwrap();
    let mut possible = set(None);
    let mut stage = staged(&mut possible, named(1, 2));
    assert_eq!(
        confirm(&mut host, &mut possible, &foreign, own()).map(|_| ()),
        Err(WriteRefused::Tenure),
        "a Confirm of another shard's record"
    );
    assert_eq!(
        publish(
            &mut host,
            &mut possible,
            &foreign,
            (own(), None),
            (&cut(2), CaptureEpoch::default()),
            &mut stage
        )
        .map(|_| ()),
        Err(WriteRefused::Tenure),
        "a Publish over another shard's record"
    );
    assert!(possible.admits(&stage));
    assert_eq!(
        host.read::<ShardRecord>(Key::Shard(other)).unwrap().value(),
        foreign.value()
    );
    for (generation, attempts, refused) in [(3, 0, true), (4, 2, false)] {
        let store = Shared::new();
        let mut host = client(&store);
        host.create_shard(ShardRecord {
            generation: ShardGeneration::new(generation).unwrap(),
            attempts,
            ..record()
        })
        .unwrap();
        let session = crate::net::ownership::session_of(generation as u32, 2 * attempts);
        let tenure = Target {
            generation: ShardGeneration::new(generation).unwrap(),
            attempts,
            ..own()
        };
        let mut possible = PossiblyNamed::new((shard(), session), layout(4), None);
        let mut stage = StagedCheckpoint::reserved_at(
            &mut possible,
            Checkpoint {
                shard: shard(),
                session,
                capture: 1,
            },
            0,
            vec![Box::new([0; UNIT_LEN])],
        );
        stage.wrote(0);
        stage.read_back((0, 0), &[0; UNIT_LEN]);
        let current = read(&mut host);
        let published = publish(
            &mut host,
            &mut possible,
            &current,
            (tenure, None),
            (&cut_under((shard(), session), 1), CaptureEpoch::default()),
            &mut stage,
        );
        if refused {
            assert_eq!(
                published.map(|_| ()),
                Err(WriteRefused::Tenure),
                "E = 0 has no activated session"
            );
            assert_eq!(stored(&store).1.checkpoint, None);
        } else {
            published.unwrap();
            assert_eq!(stored(&store).1.checkpoint, Some(stage.named()));
        }
    }
}

#[test]
fn a_write_whose_log_fails_after_its_commit_keeps_its_slot_and_withdraws_the_client() {
    for confirming in [false, true] {
        let store = seeded();
        let log = MemLog::default();
        let mut host = Client::open(store.clone(), log.clone()).unwrap();
        let mut possible = set(None);
        if confirming {
            let first = read(&mut host);
            publish_named(&mut host, &mut possible, &first, own(), None, named(1, 1)).unwrap();
        }
        let current = read(&mut host);
        log.fail.set(true);
        let written = if confirming {
            confirm(&mut host, &mut possible, &current, own())
        } else {
            publish_named(&mut host, &mut possible, &current, own(), None, named(1, 1))
        };
        assert_eq!(
            written.map(|_| ()),
            Err(WriteRefused::Store(StoreError::Log))
        );
        assert!(stored(&store).0 > current.version(), "the write committed");
        let expected = vec![1];
        assert_eq!(
            possible.slots(),
            expected,
            "a write that may have committed keeps its slot"
        );
        log.fail.set(false);
        assert_eq!(
            publish_named(
                &mut host,
                &mut possible,
                &current,
                own(),
                current.value().checkpoint,
                named(2, 1)
            )
            .map(|_| ()),
            Err(WriteRefused::Store(StoreError::Withdrawn)),
            "the client withdrew"
        );
        assert_eq!(
            possible.slots(),
            expected,
            "a write refused before any request leaves the set as it was"
        );
    }
}

#[test]
fn a_publish_the_store_refuses_keeps_its_slot() {
    let store = seeded();
    let mut host = client(&store);
    let mut possible = set(None);
    let stale = read(&mut host);
    publish_named(&mut host, &mut possible, &stale, own(), None, named(0, 1)).unwrap();
    assert_eq!(
        publish_named(&mut host, &mut possible, &stale, own(), None, named(1, 2)).map(|_| ()),
        Err(WriteRefused::Store(StoreError::Refused(Refusal::Condition))),
        "a Publish on a stale version fails on the record version"
    );
    assert_eq!(
        possible.slots(),
        vec![0, 1],
        "a refusal after a request keeps the write's slot"
    );
}

/// Unit 0 holds only counts, so a torn unit 0 loses no entry: every entry of the data units loads.
#[test]
fn a_torn_unit_zero_loses_no_entry_and_raises_the_stale_write_alarm() {
    let (entries, layout, ck, encoded) = two_windows();
    let mut torn = encoded.clone();
    torn[0][IO_UNIT - 1] ^= 1;
    let bytes = prefix(&layout, 0, &torn);
    let mut reader = two_window_reader(&layout, ck, entries.len());
    drive(&mut reader, &bytes, |_| 0);
    let (damage, load) = damaged(reader.load());
    assert_eq!(
        (damage.alarm(), damage.failed, load),
        (LoadRefusal::StaleWrite, vec![0], GuardedLoad::Warm(entries))
    );
}

#[test]
fn a_write_refused_before_any_request_leaves_the_set() {
    let store = seeded();
    let mut host = client(&store);
    let mut possible = set(None);
    let first = read(&mut host);
    let published =
        publish_named(&mut host, &mut possible, &first, own(), None, named(0, 5)).unwrap();
    let regressed = publish_named(
        &mut host,
        &mut possible,
        &published,
        own(),
        Some(named(0, 5)),
        named(1, 3),
    );
    assert!(
        matches!(
            regressed,
            Err(WriteRefused::Store(StoreError::Successor(_)))
        ),
        "{regressed:?}"
    );
    assert_eq!(
        possible.slots(),
        vec![0],
        "a Publish the client refused before sending keeps no slot"
    );
    store.schedule(Arm::Timeout { commit: false });
    let unknown = publish_named(
        &mut host,
        &mut possible,
        &published,
        own(),
        Some(named(0, 5)),
        named(2, 6),
    );
    assert_eq!(
        unknown.map(|_| ()),
        Err(WriteRefused::Store(StoreError::Unknown))
    );
    assert_eq!(
        possible.slots(),
        vec![0, 2],
        "an unknown Publish keeps its slot"
    );
}

/// A Publish over a read taken before the store's namespace changed refuses before any request: the client returns
/// `Namespace`, the set keeps only the named slot, and the scheduled arm is left for the next request.
#[test]
fn a_publish_refused_for_another_namespace_leaves_the_set() {
    let store = seeded();
    let mut host = client(&store);
    let mut possible = set(None);
    let first = read(&mut host);
    let published =
        publish_named(&mut host, &mut possible, &first, own(), None, named(0, 5)).unwrap();
    store.0.borrow_mut().namespace = crate::failover::records::Namespace::new([0x22; 16]).unwrap();
    store.schedule(Arm::Unavailable);
    let refused = publish_named(
        &mut host,
        &mut possible,
        &published,
        own(),
        Some(named(0, 5)),
        named(1, 6),
    );
    assert_eq!(
        refused.map(|_| ()),
        Err(WriteRefused::Store(StoreError::Namespace))
    );
    assert_eq!(
        possible.slots(),
        vec![0],
        "a Publish the client refused before sending keeps no slot"
    );
    assert_eq!(
        store.clone().read(&Key::Shard(shard())),
        Err(crate::storage::store::Unavailable),
        "a request consumed the scheduled arm"
    );
}

/// Set arithmetic over stages reserved directly on one slot: a later Publish of that slot that the client refuses
/// before sending keeps the slot an earlier sent Publish may name. An exact retry of one stage is
/// `an_exact_publish_retry_after_an_unknown_outcome_settles_on_the_stage`.
#[test]
fn a_retry_refused_before_sending_keeps_the_slot_an_earlier_sent_write_may_name() {
    let store = seeded();
    let mut host = client(&store);
    let mut possible = set(None);
    let first = read(&mut host);
    let published =
        publish_named(&mut host, &mut possible, &first, own(), None, named(0, 5)).unwrap();
    store.schedule(Arm::Timeout { commit: false });
    let known = Some(named(0, 5));
    let unknown = publish_named(
        &mut host,
        &mut possible,
        &published,
        own(),
        known,
        named(1, 6),
    );
    assert_eq!(
        unknown.map(|_| ()),
        Err(WriteRefused::Store(StoreError::Unknown))
    );
    let regressed = publish_named(
        &mut host,
        &mut possible,
        &published,
        own(),
        known,
        named(1, 3),
    );
    assert!(
        matches!(
            regressed,
            Err(WriteRefused::Store(StoreError::Successor(_)))
        ),
        "{regressed:?}"
    );
    assert_eq!(
        possible.slots(),
        vec![0, 1],
        "the earlier sent Publish still holds its slot"
    );
    store.schedule(Arm::Timeout { commit: false });
    let _ = publish_named(
        &mut host,
        &mut possible,
        &published,
        own(),
        known,
        named(1, 7),
    );
    assert_eq!(possible.slots(), vec![0, 1]);
}

/// A stage of capture `capture`'s 50 entries, landed into `bytes` and read back.
fn landed(
    possible: &mut PossiblyNamed,
    layout: &Layout,
    bytes: &mut [u8],
    capture: u32,
) -> (StagedCheckpoint, Vec<CaptureEntry>) {
    let entries: Vec<CaptureEntry> = (0..50)
        .map(|at| entry(at, capture, 8 * at as u64))
        .collect();
    let checkpoint = Checkpoint {
        shard: shard(),
        session: SESSION,
        capture,
    };
    let mut stage = StagedCheckpoint::new(
        Crc32c::detect(),
        possible,
        (checkpoint, &entries),
        &EngineBudget::unlimited(),
    )
    .unwrap();
    land(layout, &mut stage, bytes);
    (stage, entries)
}

/// A Publish whose reply is unknown is superseded by a later Publish that commits and is acknowledged: the earlier
/// slot leaves the set for quarantine, the next placement skips it, and the delayed Publish fails on the version.
#[test]
fn a_superseded_publish_quarantines_its_slot() {
    let layout = layout(4);
    let store = seeded();
    let mut host = client(&store);
    let mut possible = PossiblyNamed::new((shard(), SESSION), layout, None);
    let mut bytes = vec![0; layout.units as usize * IO_UNIT];
    let (mut first, _) = landed(&mut possible, &layout, &mut bytes, 1);
    let current = read(&mut host);
    store.schedule(Arm::Hold);
    assert_eq!(
        publish(
            &mut host,
            &mut possible,
            &current,
            (own(), None),
            (&cut(first.named().capture), CaptureEpoch::default()),
            &mut first
        )
        .map(|_| ()),
        Err(WriteRefused::Store(StoreError::Unknown))
    );
    let (mut second, _) = landed(&mut possible, &layout, &mut bytes, 2);
    assert_ne!(second.slot(), first.slot());
    let current = read(&mut host);
    publish(
        &mut host,
        &mut possible,
        &current,
        (own(), None),
        (&cut(second.named().capture), CaptureEpoch::default()),
        &mut second,
    )
    .unwrap();
    assert_eq!(possible.slots(), vec![second.slot()]);
    assert_eq!(
        possible.quarantined(),
        [first.slot()],
        "the superseded Publish's slot is quarantined, not freed"
    );
    assert_eq!(
        crate::storage::volume::place(&layout, &possible.slots(), 50),
        Ok(first.slot()),
        "control: placement over the set alone would reuse the superseded slot"
    );
    let third = possible.free_slot().expect("one slot stays free");
    assert!(third != first.slot() && third != second.slot());
    assert_eq!(
        store.release(),
        vec![Outcome::NotCommitted(Refusal::Condition)],
        "the delayed Publish fails on the record version"
    );
    assert_eq!(stored(&store).1.checkpoint, Some(second.named()));
    let current = read(&mut host);
    assert_eq!(
        publish(
            &mut host,
            &mut possible,
            &current,
            (own(), Some(second.named())),
            (&cut(first.named().capture), CaptureEpoch::default()),
            &mut first
        )
        .map(|_| ()),
        Err(WriteRefused::Superseded),
        "a retry of a stage whose slot left the set refuses before any request"
    );
}

/// A tenure that starts with a named checkpoint in a three-slot layout settles three captures, the first freeing the
/// start's slot for the second, and then every slot is named or quarantined: a capture start refuses `NoFreeCheckpointSlot` before its pass begins, the reservation
/// refuses, and neither the record nor any slot changes.
#[test]
fn a_capture_with_no_free_slot_refuses_before_any_unit() {
    use crate::storage::recovery::{CaptureError, SideCap};
    let layout = layout(4);
    let store = seeded();
    let mut host = client(&store);
    let mut earlier = PossiblyNamed::new((shard(), SESSION), layout, None);
    let mut bytes = vec![0; layout.units as usize * IO_UNIT];
    let (mut named, _) = landed(&mut earlier, &layout, &mut bytes, 1);
    let current = read(&mut host);
    publish(
        &mut host,
        &mut earlier,
        &current,
        (own(), None),
        (&cut(named.named().capture), CaptureEpoch::default()),
        &mut named,
    )
    .unwrap();
    let mut possible = PossiblyNamed::new((shard(), SESSION), layout, stored(&store).1.checkpoint);
    for capture in [2, 3, 4] {
        let (mut stage, _) = landed(&mut possible, &layout, &mut bytes, capture);
        let current = read(&mut host);
        let known = current.value().checkpoint;
        publish(
            &mut host,
            &mut possible,
            &current,
            (own(), known),
            (&cut(stage.named().capture), CaptureEpoch::default()),
            &mut stage,
        )
        .unwrap();
    }
    assert_eq!(possible.free_slot(), None);
    let before = (stored(&store), bytes.clone());
    let set_before = (
        possible.highest,
        possible.reserved,
        possible.quarantined().to_vec(),
        possible.slots(),
    );
    let mut capture = crate::storage::recovery::Capture::default();
    let cap = SideCap {
        entries: 4,
        words: 4,
    };
    assert_eq!(
        capture.start(
            (1, CaptureEpoch::default()),
            8,
            2,
            8,
            possible.free_slot().is_some(),
            cap
        ),
        Err(CaptureError::NoFreeCheckpointSlot)
    );
    assert_eq!(capture.check_counter(0), Err(CaptureError::Idle));
    let entries: Vec<CaptureEntry> = (0..50).map(|at| entry(at, 5, 8 * at as u64)).collect();
    let checkpoint = Checkpoint {
        shard: shard(),
        session: SESSION,
        capture: 5,
    };
    assert_eq!(
        StagedCheckpoint::new(
            Crc32c::detect(),
            &mut possible,
            (checkpoint, &entries),
            &EngineBudget::unlimited()
        )
        .map(|_| ()),
        Err(StageRefusal::Reserve(ReserveRefusal::Placement(
            crate::storage::volume::PlacementRefusal::NoFreeSlot
        )))
    );
    assert_eq!(
        (stored(&store), bytes),
        before,
        "the refusal changes neither the record nor the slots"
    );
    assert_eq!(
        (
            possible.highest,
            possible.reserved,
            possible.quarantined().to_vec(),
            possible.slots(),
        ),
        set_before,
        "the refusal reserves nothing and burns no capture number"
    );
}

/// Each `(session, capture)` is reserved at most once and only above the named one, so a unit identity has one
/// encoding; a refusal reserves nothing.
#[test]
fn a_reservation_at_or_below_the_highest_capture_refuses() {
    let checkpoint = |session, capture| Checkpoint {
        shard: shard(),
        session,
        capture,
    };
    let mut possible = set(Some(named(0, 5)));
    for (ck, expected, case) in [
        (
            checkpoint(SESSION, 5),
            ReserveRefusal::Capture,
            "the named capture",
        ),
        (
            checkpoint(SESSION, 4),
            ReserveRefusal::Capture,
            "a capture below it",
        ),
        (
            checkpoint(SESSION - 2, 9),
            ReserveRefusal::Tenure,
            "an earlier session",
        ),
        (
            checkpoint(SESSION + 2, 9),
            ReserveRefusal::Tenure,
            "a later session",
        ),
    ] {
        assert_eq!(possible.reserve(ck, 1), Err(expected), "{case}");
        assert_eq!(possible.free_slot(), Some(1), "{case}: nothing reserved");
    }
    assert_eq!(possible.reserve(checkpoint(SESSION, 6), 1), Ok(1));
    assert_eq!(
        possible.reserve(checkpoint(SESSION, 7), 1),
        Err(ReserveRefusal::Busy)
    );
    possible.reserved = None;
    assert_eq!(
        possible.reserve(checkpoint(SESSION, 6), 1),
        Err(ReserveRefusal::Capture),
        "a released reservation's capture is not reserved again"
    );
}

/// A Publish names a stage only once every unit read back equal: a stage with a unit that never read back, or that
/// read back other bytes, refuses before any request.
#[test]
fn a_publish_of_an_unverified_stage_refuses_before_any_request() {
    let layout = layout(4);
    let store = seeded();
    let mut host = client(&store);
    let mut possible = PossiblyNamed::new((shard(), SESSION), layout, None);
    let mut bytes = vec![0; layout.units as usize * IO_UNIT];
    let (mut stage, _) = landed(&mut possible, &layout, &mut bytes, 1);
    let before = stored(&store);
    let current = read(&mut host);
    stage.wrote(1);
    assert_eq!(
        publish(
            &mut host,
            &mut possible,
            &current,
            (own(), None),
            (&cut(stage.named().capture), CaptureEpoch::default()),
            &mut stage
        )
        .map(|_| ()),
        Err(WriteRefused::Unverified),
        "a rewritten unit awaits its read-back"
    );
    let unit = stage.units()[1].clone();
    stage.read_back((stage.slot(), 1), &unit);
    assert!(stage.verified(), "the staged bytes read back");
    stage.read_back((stage.slot(), 1), &[0x5A; UNIT_LEN]);
    assert!(
        !stage.verified(),
        "a later read-back of other bytes unverifies the unit"
    );
    assert_eq!(
        publish(
            &mut host,
            &mut possible,
            &current,
            (own(), None),
            (&cut(stage.named().capture), CaptureEpoch::default()),
            &mut stage
        )
        .map(|_| ()),
        Err(WriteRefused::Unverified),
        "a read-back of other bytes"
    );
    assert_eq!(stored(&store), before);
    assert_eq!(possible.slots(), Vec::<u32>::new());
    stage.read_back((stage.slot(), 1), &unit);
    publish(
        &mut host,
        &mut possible,
        &current,
        (own(), None),
        (&cut(stage.named().capture), CaptureEpoch::default()),
        &mut stage,
    )
    .unwrap();
    assert_eq!(stored(&store).1.checkpoint, Some(stage.named()));
}

/// The named slot and a slot an unknown Publish may name are both damaged, one by a flipped bit and the other by a
/// delayed landing of another capture's unit. Whether the unknown Publish committed or not, recovery reads only the
/// slot the store names, loses only the entries with a row on that slot's damaged unit, lists that unit as failed,
/// and the record keeps naming the damaged checkpoint.
#[test]
fn both_possibly_named_slots_damaged_lose_only_their_damaged_units() {
    let layout = layout(4);
    let crc = Crc32c::detect();
    let stale = encode(
        crc,
        Checkpoint {
            shard: shard(),
            session: SESSION - 2,
            capture: 9,
        },
        &entries(50),
        u32::MAX,
    )
    .unwrap();
    for commit in [false, true] {
        let store = seeded();
        let mut host = client(&store);
        let mut possible = PossiblyNamed::new((shard(), SESSION), layout, None);
        let mut bytes = vec![0; layout.units as usize * IO_UNIT];
        let (mut first, first_entries) = landed(&mut possible, &layout, &mut bytes, 1);
        let current = read(&mut host);
        publish(
            &mut host,
            &mut possible,
            &current,
            (own(), None),
            (&cut(first.named().capture), CaptureEpoch::default()),
            &mut first,
        )
        .unwrap();
        let (mut second, second_entries) = landed(&mut possible, &layout, &mut bytes, 2);
        let current = read(&mut host);
        store.schedule(Arm::Timeout { commit });
        let known = (own(), Some(first.named()));
        let _ = publish(
            &mut host,
            &mut possible,
            &current,
            known,
            (&cut(second.named().capture), CaptureEpoch::default()),
            &mut second,
        );
        assert_eq!(possible.slots(), vec![first.slot(), second.slot()]);
        let unit_at = |slot: u32, unit: usize| {
            (1 + slot as usize * layout.slot_units as usize + unit) * IO_UNIT
        };
        bytes[unit_at(first.slot(), 2) + IO_UNIT - 1] ^= 1;
        let at = unit_at(second.slot(), 1);
        bytes[at..at + IO_UNIT].copy_from_slice(&stale[1][..]);
        drop(host);
        let mut host = client(&store);
        let current = read(&mut host);
        let confirmed = confirm(&mut host, &mut set(None), &current, own()).unwrap();
        let named = confirmed.value().checkpoint.expect("a checkpoint is named");
        let (expected, entries, torn) = if commit {
            (second.named(), &second_entries, 1)
        } else {
            (first.named(), &first_entries, 2)
        };
        assert_eq!(named, expected, "commit {commit}");
        let mut reader = SlotReader::new(
            crc,
            &layout,
            shard(),
            (named, 0, &[]),
            SESSION,
            (load_limits(50), &EngineBudget::unlimited()),
            routing(4),
        )
        .unwrap();
        drive(&mut reader, &bytes, |_| 0);
        let (damage, load) = damaged(reader.load());
        assert_eq!(damage.failed, [torn as u32], "commit {commit}");
        assert_eq!(damage.alarm(), LoadRefusal::StaleWrite, "commit {commit}");
        assert_eq!(
            load,
            GuardedLoad::Warm(outside(entries, torn)),
            "commit {commit}: every entry of the intact units loads"
        );
        assert_eq!(
            stored(&store).1.checkpoint,
            Some(named),
            "the record keeps naming the damaged checkpoint"
        );
    }
}

/// A named slot the device cannot read loses its entries for that read alone: the record keeps naming the
/// checkpoint, no successor may clear it, and a later read of the same slot loads every entry.
#[test]
fn an_unreadable_named_slot_keeps_the_record_and_a_later_read_loads_it() {
    let layout = layout(4);
    let store = seeded();
    let mut host = client(&store);
    let mut possible = PossiblyNamed::new((shard(), SESSION), layout, None);
    let mut bytes = vec![0; layout.units as usize * IO_UNIT];
    let (mut stage, entries) = landed(&mut possible, &layout, &mut bytes, 1);
    let current = read(&mut host);
    publish(
        &mut host,
        &mut possible,
        &current,
        (own(), None),
        (&cut(stage.named().capture), CaptureEpoch::default()),
        &mut stage,
    )
    .unwrap();
    let reader = || {
        SlotReader::new(
            Crc32c::detect(),
            &layout,
            shard(),
            (stage.named(), 0, &[]),
            SESSION,
            (load_limits(50), &EngineBudget::unlimited()),
            routing(4),
        )
        .unwrap()
    };
    let mut unread = reader();
    while let Some(range) = unread.next_read() {
        unread.fail_read(range);
    }
    let slot = unread.load();
    assert!(
        !slot.installable(),
        "a slot with unread units is reread before any entry is installed"
    );
    let (failed, load) = damaged(slot);
    assert_eq!(
        (failed.alarm(), failed.unread.len(), load),
        (
            LoadRefusal::Unreadable,
            stage.named().units as usize,
            GuardedLoad::Warm(Vec::new())
        )
    );
    let current = read(&mut host);
    let cleared = ShardRecord {
        checkpoint: None,
        ..*current.value()
    };
    assert!(
        matches!(
            host.replace(&current, cleared),
            Err(StoreError::Successor(_))
        ),
        "no record write clears the named checkpoint"
    );
    assert_eq!(stored(&store).1.checkpoint, Some(stage.named()));
    let mut again = reader();
    drive(&mut again, &bytes, |_| 0);
    let again = again.load();
    assert!(again.installable());
    assert_eq!(whole(again), GuardedLoad::Warm(entries));
}

/// Two entries on intact units overlap and a later unit is torn: the guard still judges the intact units' entries
/// and refuses them, so a damaged slot never loads an entry set the guard would refuse.
#[test]
fn a_damaged_slot_loads_its_intact_entries_only_through_the_guard() {
    let count = 41 * 3;
    let mut entries = entries(count);
    entries[1].extents = entries[0].extents.clone();
    let crc = Crc32c::detect();
    let slot_units = units(rows(&entries)) as u32;
    let layout = layout(slot_units);
    let checkpoint = Checkpoint {
        shard: shard(),
        session: SESSION,
        capture: 6,
    };
    let mut encoded = encode(crc, checkpoint, &entries, u32::MAX).unwrap();
    encoded[3][IO_UNIT - 1] ^= 1;
    let bytes = prefix(&layout, 0, &encoded);
    let ck = NamedCheckpoint {
        slot: 0,
        session: SESSION,
        capture: 6,
        units: slot_units,
    };
    let mut reader = SlotReader::new(
        crc,
        &layout,
        shard(),
        (ck, 0, &[]),
        SESSION,
        (load_limits(count), &EngineBudget::unlimited()),
        routing(4),
    )
    .unwrap();
    drive(&mut reader, &bytes, |_| 0);
    let (damage, load) = damaged(reader.load());
    assert_eq!(damage.failed, [3]);
    assert_eq!(
        load,
        GuardedLoad::Cold {
            entries: outside(&entries, 3),
            refusal: LoadRefusal::Overlap
        },
        "the overlap on the intact units is refused"
    );
}

/// A Publish the client refuses before sending removes the stage's slot from the set, and the slot the stage wrote
/// is quarantined: the next reservation skips it, and a retry of the stage refuses `Superseded`.
#[test]
fn a_publish_refused_before_sending_quarantines_the_written_slot() {
    let layout = layout(4);
    let store = seeded();
    let mut host = client(&store);
    let mut possible = PossiblyNamed::new((shard(), SESSION), layout, None);
    let mut bytes = vec![0; layout.units as usize * IO_UNIT];
    let (mut first, _) = landed(&mut possible, &layout, &mut bytes, 1);
    let current = read(&mut host);
    let published = publish(
        &mut host,
        &mut possible,
        &current,
        (own(), None),
        (&cut(first.named().capture), CaptureEpoch::default()),
        &mut first,
    )
    .unwrap();
    let (mut second, _) = landed(&mut possible, &layout, &mut bytes, 2);
    store.0.borrow_mut().namespace = crate::failover::records::Namespace::new([0x22; 16]).unwrap();
    let known = (own(), Some(first.named()));
    assert_eq!(
        publish(
            &mut host,
            &mut possible,
            &published,
            known,
            (&cut(second.named().capture), CaptureEpoch::default()),
            &mut second
        )
        .map(|_| ()),
        Err(WriteRefused::Store(StoreError::Namespace))
    );
    assert_eq!(possible.slots(), vec![first.slot()]);
    assert_eq!(possible.quarantined(), [second.slot()]);
    let free = possible.free_slot().expect("one slot stays free");
    assert!(free != first.slot() && free != second.slot());
    assert_eq!(
        publish(
            &mut host,
            &mut possible,
            &published,
            known,
            (&cut(second.named().capture), CaptureEpoch::default()),
            &mut second
        )
        .map(|_| ()),
        Err(WriteRefused::Superseded)
    );
}

/// An exact retry of a stage after an unknown Publish converges: when the first attempt did not apply, the retry
/// commits the same checkpoint and the held attempt then fails on the version; when it committed, the retry finds
/// the record naming the stage and settles the set with a compare-and-swap of that value. Either way the set holds
/// only the stage's slot and nothing is quarantined.
#[test]
fn an_exact_publish_retry_after_an_unknown_outcome_settles_on_the_stage() {
    for arm in [Arm::Hold, Arm::Timeout { commit: true }] {
        let layout = layout(4);
        let store = seeded();
        let mut host = client(&store);
        let mut possible = PossiblyNamed::new((shard(), SESSION), layout, None);
        let mut bytes = vec![0; layout.units as usize * IO_UNIT];
        let (mut stage, _) = landed(&mut possible, &layout, &mut bytes, 1);
        let current = read(&mut host);
        store.schedule(arm);
        assert_eq!(
            publish(
                &mut host,
                &mut possible,
                &current,
                (own(), None),
                (&cut(stage.named().capture), CaptureEpoch::default()),
                &mut stage
            )
            .map(|_| ()),
            Err(WriteRefused::Store(StoreError::Unknown)),
            "{arm:?}"
        );
        let current = read(&mut host);
        let retried = publish(
            &mut host,
            &mut possible,
            &current,
            (own(), None),
            (&cut(stage.named().capture), CaptureEpoch::default()),
            &mut stage,
        )
        .unwrap_or_else(|refusal| panic!("{arm:?}: {refusal:?}"));
        assert_eq!(retried.value().checkpoint, Some(stage.named()), "{arm:?}");
        assert_eq!(possible.slots(), vec![stage.slot()], "{arm:?}");
        assert!(possible.quarantined().is_empty(), "{arm:?}");
        if arm == Arm::Hold {
            assert_eq!(
                store.release(),
                vec![Outcome::NotCommitted(Refusal::Condition)],
                "the held attempt fails on the version"
            );
        }
        assert_eq!(stored(&store).1.checkpoint, Some(stage.named()), "{arm:?}");
    }
}

/// A read-back verifies a unit only from the stage's own slot: equal bytes read from another slot leave it
/// unverified.
#[test]
fn a_read_back_of_another_slot_verifies_nothing() {
    let layout = layout(4);
    let mut possible = PossiblyNamed::new((shard(), SESSION), layout, None);
    let mut bytes = vec![0; layout.units as usize * IO_UNIT];
    let (mut stage, _) = landed(&mut possible, &layout, &mut bytes, 1);
    stage.wrote(0);
    let unit = stage.units()[0].clone();
    stage.read_back((stage.slot() + 1, 0), &unit);
    assert!(!stage.verified(), "another slot's bytes verify nothing");
    stage.read_back((stage.slot(), 0), &unit);
    assert!(stage.verified());
}

/// The stage's units are charged to the engine budget before they are encoded: a budget one byte short of them
/// refuses `Memory` and reserves nothing.
#[test]
fn a_stage_the_engine_budget_cannot_hold_refuses_before_any_reservation() {
    let layout = layout(4);
    let entries: Vec<CaptureEntry> = (0..50).map(|at| entry(at, 1, 8 * at as u64)).collect();
    let checkpoint = Checkpoint {
        shard: shard(),
        session: SESSION,
        capture: 1,
    };
    let bytes = units(rows(&entries)) as usize * (UNIT_LEN + size_of::<Box<[u8; UNIT_LEN]>>() + 1);
    let mut possible = PossiblyNamed::new((shard(), SESSION), layout, None);
    assert_eq!(
        StagedCheckpoint::new(
            Crc32c::detect(),
            &mut possible,
            (checkpoint, &entries),
            &EngineBudget::new(bytes - 1)
        )
        .map(|_| ()),
        Err(StageRefusal::Memory)
    );
    assert_eq!(possible.free_slot(), Some(0), "nothing is reserved");
    let stage = StagedCheckpoint::new(
        Crc32c::detect(),
        &mut possible,
        (checkpoint, &entries),
        &EngineBudget::new(bytes),
    )
    .unwrap();
    assert_eq!(stage.units().len(), units(rows(&entries)) as usize);
}

/// A cut whose extent rows exceed the slot's rows refuses its reservation, so a published slot never names a subset
/// of its cut; an entry the encoder refuses reserves nothing either, and both leave the capture number reservable.
#[test]
fn a_stage_of_a_cut_the_slot_cannot_hold_or_encode_reserves_nothing() {
    let layout = layout(4);
    let checkpoint = Checkpoint {
        shard: shard(),
        session: SESSION,
        capture: 1,
    };
    let mut wide = entry(0, 1, 0);
    wide.extents = (0..u64::from(layout.entries) + 1)
        .map(|at| ExtentLocator::new(8 * at, 1).unwrap().bits())
        .collect();
    let mut empty = entry(0, 1, 0);
    empty.extents.clear();
    let mut possible = PossiblyNamed::new((shard(), SESSION), layout, None);
    for (cut, expected) in [
        (
            vec![wide],
            StageRefusal::Reserve(ReserveRefusal::Placement(PlacementRefusal::Entries {
                entries: u64::from(layout.entries) + 1,
                cap: layout.entries,
            })),
        ),
        (
            vec![empty],
            StageRefusal::Encode(EncodeRefusal::Extents {
                allocation: entry(0, 1, 0).allocation,
            }),
        ),
    ] {
        assert_eq!(
            StagedCheckpoint::new(
                Crc32c::detect(),
                &mut possible,
                (checkpoint, &cut),
                &EngineBudget::unlimited()
            )
            .map(|_| ()),
            Err(expected)
        );
        assert_eq!(
            (possible.highest, possible.reserved, possible.free_slot()),
            (None, None, Some(0)),
            "{expected:?} reserves nothing"
        );
    }
    let stage = StagedCheckpoint::new(
        Crc32c::detect(),
        &mut possible,
        (checkpoint, &[entry(0, 1, 0)]),
        &EngineBudget::unlimited(),
    )
    .unwrap();
    assert_eq!(stage.slot(), 0);
    stage.abandon(&mut possible);
}

/// A retry of a stage whose Publish reply was lost runs after a later stage reserved and wrote its slot: the retry
/// leaves that reservation in place, so abandoning the later stage still quarantines the slot it exposed. The first
/// submission released the retried stage's unit bytes and the checkpoint it names keeps its unit count.
#[test]
fn a_publish_retry_keeps_a_later_stages_reservation() {
    let layout = layout(4);
    let store = seeded();
    let mut host = client(&store);
    let mut possible = PossiblyNamed::new((shard(), SESSION), layout, None);
    let mut bytes = vec![0; layout.units as usize * IO_UNIT];
    let (mut first, _) = landed(&mut possible, &layout, &mut bytes, 1);
    let named = first.named();
    let current = read(&mut host);
    store.schedule(Arm::Timeout { commit: false });
    assert!(
        publish(
            &mut host,
            &mut possible,
            &current,
            (own(), None),
            (&cut(1), CaptureEpoch::default()),
            &mut first
        )
        .is_err()
    );
    assert!(first.units().is_empty());
    assert_eq!(first.named(), named);
    let (later, _) = landed(&mut possible, &layout, &mut bytes, 2);
    assert!(possible.admits(&later));
    let current = read(&mut host);
    let known = current.value().checkpoint;
    publish(
        &mut host,
        &mut possible,
        &current,
        (own(), known),
        (&cut(1), CaptureEpoch::default()),
        &mut first,
    )
    .unwrap();
    assert_eq!(stored(&store).1.checkpoint, Some(named));
    assert!(
        possible.admits(&later),
        "the retry left the later stage's reservation"
    );
    let slot = later.slot();
    later.abandon(&mut possible);
    assert!(
        possible.quarantined().contains(&slot),
        "the exposed slot is quarantined"
    );
}

/// Random schedules of stages, unit writes, Publishes under every reply arm, Confirms, releases of held writes and
/// abandoned stages, half of them in a tenure that starts with a named checkpoint, keep the retained set: the
/// quarantine only grows and equals the slots this tenure wrote that are neither in the set nor reserved, the free
/// slot lies outside the set, the quarantine and the reservation, a slot a write exposed is never reserved again, and
/// the store names a slot in the set.
#[test]
fn random_schedules_never_reserve_an_exposed_slot() {
    let mut rng = SplitMix64::new(0x1443);
    let arms = [
        None,
        Some(Arm::Hold),
        Some(Arm::Timeout { commit: false }),
        Some(Arm::Timeout { commit: true }),
    ];
    let (mut quarantining, mut refused) = (0, 0);
    for schedule in 0..200 {
        let layout = layout(4);
        let store = seeded();
        let mut host = client(&store);
        let mut bytes = vec![0; layout.units as usize * IO_UNIT];
        let mut capture = 0u32;
        if schedule % 2 == 1 {
            let mut earlier = PossiblyNamed::new((shard(), SESSION), layout, None);
            let (mut named, _) = landed(&mut earlier, &layout, &mut bytes, 1);
            let current = read(&mut host);
            publish(
                &mut host,
                &mut earlier,
                &current,
                (own(), None),
                (&cut(1), CaptureEpoch::default()),
                &mut named,
            )
            .unwrap();
            capture = 1;
        }
        let mut possible =
            PossiblyNamed::new((shard(), SESSION), layout, stored(&store).1.checkpoint);
        let mut stage = None::<StagedCheckpoint>;
        let mut exposed: Vec<u32> = Vec::new();
        for step in 0..30 {
            let before = possible.quarantined().to_vec();
            match (rng.next_u64() % 6, stage.take()) {
                (0, None) => {
                    capture += 1;
                    let entries: Vec<CaptureEntry> =
                        (0..4).map(|at| entry(at, capture, 8 * at as u64)).collect();
                    let checkpoint = Checkpoint {
                        shard: shard(),
                        session: SESSION,
                        capture,
                    };
                    let fresh = StagedCheckpoint::new(
                        Crc32c::detect(),
                        &mut possible,
                        (checkpoint, &entries),
                        &EngineBudget::unlimited(),
                    );
                    refused += usize::from(fresh.is_err());
                    if let Ok(fresh) = fresh {
                        assert!(
                            !exposed.contains(&fresh.slot()),
                            "schedule {schedule} step {step}: exposed slot {} reserved again",
                            fresh.slot()
                        );
                        stage = Some(fresh);
                    }
                }
                (1, Some(mut held)) => {
                    if possible.admits(&held) {
                        land(&layout, &mut held, &mut bytes);
                        exposed.push(held.slot());
                    }
                    stage = Some(held);
                }
                (2, Some(mut held)) => {
                    let current = read(&mut host);
                    let known = current.value().checkpoint;
                    let sends = held.verified()
                        && (possible.admits(&held)
                            || held.published && possible.contains(held.slot));
                    if let Some(arm) = arms[rng.next_u64() as usize % arms.len()].filter(|_| sends)
                    {
                        store.schedule(arm);
                    }
                    let _ = publish(
                        &mut host,
                        &mut possible,
                        &current,
                        (own(), known),
                        (&cut(held.named().capture), CaptureEpoch::default()),
                        &mut held,
                    );
                    stage = Some(held);
                }
                (3, held) => {
                    let current = read(&mut host);
                    let _ = confirm(&mut host, &mut possible, &current, own());
                    stage = held;
                }
                (4, held) => {
                    store.release();
                    stage = held;
                }
                (5, Some(held)) => held.abandon(&mut possible),
                (_, held) => stage = held,
            }
            let quarantined = possible.quarantined();
            assert!(
                before.iter().all(|slot| quarantined.contains(slot)),
                "schedule {schedule} step {step}: the quarantine shrank"
            );
            let reserved = stage
                .as_ref()
                .filter(|held| possible.admits(held))
                .map(StagedCheckpoint::slot);
            let mut model: Vec<u32> = exposed
                .iter()
                .copied()
                .filter(|&slot| !possible.contains(slot) && reserved != Some(slot))
                .collect();
            model.sort_unstable();
            model.dedup();
            let mut actual = quarantined.to_vec();
            actual.sort_unstable();
            assert_eq!(
                actual, model,
                "schedule {schedule} step {step}: the quarantine is the written slots that left the set"
            );
            let mut unavailable = possible.slots();
            unavailable.extend(quarantined);
            unavailable.extend(reserved);
            assert!(
                possible
                    .free_slot()
                    .is_none_or(|free| !unavailable.contains(&free)),
                "schedule {schedule} step {step}"
            );
            if let Some(named) = stored(&store).1.checkpoint {
                assert!(
                    possible.contains(named.slot),
                    "schedule {schedule} step {step}: the store names slot {} outside the set",
                    named.slot
                );
            }
        }
        quarantining += usize::from(!possible.quarantined().is_empty());
        if let Some(held) = stage {
            held.abandon(&mut possible);
        }
    }
    assert!(
        quarantining > 20 && refused > 0,
        "{quarantining} schedules quarantined, {refused} reservations refused"
    );
}

/// A Publish takes only the proof of the pass whose counter the stage encodes as its capture number: a proof of
/// another pass refuses `OtherPass` before any request.
#[test]
fn a_publish_under_another_pass_proof_refuses() {
    let layout = layout(4);
    let store = seeded();
    let mut host = client(&store);
    let mut possible = PossiblyNamed::new((shard(), SESSION), layout, None);
    let mut bytes = vec![0; layout.units as usize * IO_UNIT];
    let (mut stage, _) = landed(&mut possible, &layout, &mut bytes, 1);
    let current = read(&mut host);
    for other in [2, 3] {
        assert_eq!(
            publish(
                &mut host,
                &mut possible,
                &current,
                (own(), None),
                (&cut(other), CaptureEpoch::default()),
                &mut stage
            )
            .map(|_| ()),
            Err(WriteRefused::OtherPass)
        );
    }
    assert_eq!(stored(&store).1.checkpoint, None);
    assert!(possible.admits(&stage), "the refusal keeps the reservation");
    publish(
        &mut host,
        &mut possible,
        &current,
        (own(), None),
        (&cut(1), CaptureEpoch::default()),
        &mut stage,
    )
    .unwrap();
}

/// A tenure of `attempts` attempts over a fresh store holding `chain` beside the checkpoint [`prior`] names, so the
/// record's current session is `3·2^32 + 2·attempts`.
fn tenure(
    attempts: u32,
    chain: &[crate::failover::records::Suffix],
) -> (Shared, Client<Shared, MemLog>, Target) {
    let store = Shared::new();
    let record = ShardRecord {
        attempts,
        checkpoint: Some(prior()),
        ancestry: crate::failover::records::Ancestry::new(chain).unwrap(),
        ..crate::storage::store_tests::record()
    };
    client(&store).create_shard(record).unwrap();
    let own = Target { attempts, ..own() };
    let host = client(&store);
    (store, host, own)
}

/// The set at a tenure's start over a layout of four-unit slots and a 16-block delta region.
fn suffix_set(attempts: u32) -> PossiblyNamed {
    let layout = layout(4);
    PossiblyNamed::new(
        (shard(), (3 << 32) | (2 * u64::from(attempts))),
        Layout {
            units: layout.units + 16,
            ..layout
        },
        None,
    )
}

/// The checkpoint a [`tenure`] record names at slot 0, below every capture a test stages.
fn prior() -> NamedCheckpoint {
    named(0, 0)
}

fn suffix(session: u64, start: u64, certified: u64, end: u64) -> crate::failover::records::Suffix {
    crate::failover::records::Suffix {
        session,
        start,
        certified,
        end,
    }
}

/// A publish writes the proof's cut and keeps every suffix ending above it; once the publish settles the set, the
/// floor it names is the cut, and a publish whose cut reaches a suffix's end drops the suffix. A proof cut below the
/// publishing tenure's first suffix LSN refuses.
#[test]
fn a_publish_writes_the_cut_and_keeps_every_suffix_a_replay_from_it_needs() {
    let (store, mut host, own) = tenure(1, &[]);
    let session = SESSION;
    let mut possible = suffix_set(1);
    let current = read(&mut host);
    reserve_suffix(
        &mut host,
        &mut possible,
        (&current, own),
        suffix(session, 0, 0, 10),
    )
    .unwrap();
    let current = read(&mut host);
    reserve_suffix(
        &mut host,
        &mut possible,
        (&current, own),
        suffix(session, 0, 0, 14),
    )
    .unwrap();
    let current = read(&mut host);
    certify(&mut host, &mut possible, (&current, own), (session, 6)).unwrap();
    assert_eq!(
        stored(&store).1.ancestry.as_slice(),
        &[suffix(session, 0, 6, 14)],
        "reserve_suffix extends the tenure's own last suffix and certify raises its certified end"
    );
    let mut proof = walked_at(1);
    proof.cut_at(8);
    let current = read(&mut host);
    let mut stage = staged(&mut possible, named(1, 1));
    let committed = publish(
        &mut host,
        &mut possible,
        &current,
        (own, Some(prior())),
        (
            &proof
                .intact((shard(), SESSION), CaptureEpoch::default())
                .unwrap(),
            CaptureEpoch::default(),
        ),
        &mut stage,
    )
    .unwrap();
    let record = stored(&store).1;
    assert_eq!(record.cut, 8);
    assert_eq!(
        record.ancestry.as_slice(),
        &[suffix(session, 0, 6, 14)],
        "a suffix ending above the cut is kept"
    );
    assert_eq!((suffix_start(&record), suffix_floor(&record)), (14, 8));
    assert_eq!(settled_floor(&possible, committed.value()), Some(8));
    let other_shard = crate::net::ownership::Shard::new(shard().get() + 1).unwrap();
    for other in [
        ShardRecord {
            shard: other_shard,
            ..*committed.value()
        },
        ShardRecord {
            attempts: committed.value().attempts + 1,
            ..*committed.value()
        },
    ] {
        assert_eq!(
            settled_floor(&possible, &other),
            None,
            "a record of another shard or session names no floor of the set's tenure"
        );
    }
    let mut proof = walked_at(2);
    proof.cut_at(14);
    let current = read(&mut host);
    let mut stage = staged(&mut possible, named(2, 2));
    publish(
        &mut host,
        &mut possible,
        &current,
        (own, Some(named(1, 1))),
        (
            &proof
                .intact((shard(), SESSION), CaptureEpoch::default())
                .unwrap(),
            CaptureEpoch::default(),
        ),
        &mut stage,
    )
    .unwrap();
    let record = stored(&store).1;
    assert_eq!((record.cut, record.ancestry.as_slice()), (14, &[][..]));
    assert_eq!((suffix_start(&record), suffix_floor(&record)), (14, 14));
    // Over a covered predecessor suffix and the publishing tenure's own, the publish keeps exactly its own suffix.
    let (covered, needed) = (
        suffix((3 << 32) | 2, 0, 5, 5),
        suffix((3 << 32) | 4, 5, 5, 12),
    );
    let publish_at = |(attempts, session): (u32, u64), cut: u64| {
        let (chain_store, mut chain_host, chain_own) = tenure(attempts, &[covered, needed]);
        let mut chain_possible = suffix_set(attempts);
        let mut proof = walked_at(1);
        proof.cut_at(cut);
        let current = read(&mut chain_host);
        let ck = NamedCheckpoint {
            session,
            ..named(1, 1)
        };
        let mut stage = staged(&mut chain_possible, ck);
        let published = publish(
            &mut chain_host,
            &mut chain_possible,
            &current,
            (chain_own, Some(prior())),
            (
                &proof
                    .intact((shard(), ck.session), CaptureEpoch::default())
                    .unwrap(),
                CaptureEpoch::default(),
            ),
            &mut stage,
        );
        (published.map(|_| ()), stored(&chain_store).1)
    };
    // A successor's proof cut below the end of every recorded suffix was sealed before its log opened, over a
    // snapshot that already reflects those records, so it refuses before any request.
    let (refused, record) = publish_at((3, (3 << 32) | 6), 8);
    assert_eq!(refused, Err(WriteRefused::Chain));
    assert_eq!(
        record.checkpoint,
        Some(prior()),
        "the refused publish names nothing new"
    );
    // The publishing tenure's own suffix starts at 5, so a proof cut at 3 was sealed before its log opened.
    let (refused, record) = publish_at((2, (3 << 32) | 4), 3);
    assert_eq!(refused, Err(WriteRefused::Chain));
    assert_eq!(record.checkpoint, Some(prior()));
    let (published, record) = publish_at((2, (3 << 32) | 4), 8);
    assert_eq!(published, Ok(()));
    assert_eq!((record.cut, record.ancestry.as_slice()), (8, &[needed][..]));
    assert_eq!((suffix_start(&record), suffix_floor(&record)), (12, 8));
    // A proof whose cut is below the record's refuses before any request, with the stage and its reservation kept.
    let mut proof = walked_at(3);
    proof.cut_at(13);
    let current = read(&mut host);
    let mut stage = staged(&mut possible, named(3, 3));
    let slots = possible.slots();
    assert_eq!(
        publish(
            &mut host,
            &mut possible,
            &current,
            (own, Some(named(2, 2))),
            (
                &proof
                    .intact((shard(), SESSION), CaptureEpoch::default())
                    .unwrap(),
                CaptureEpoch::default()
            ),
            &mut stage,
        )
        .map(|_| ()),
        Err(WriteRefused::Chain)
    );
    assert_eq!(possible.slots(), slots, "the reservation is kept");
    assert!(possible.admits(&stage), "the stage is kept");
    assert_eq!(stored(&store).1.cut, 14);
}

/// A floor is settled only while the set holds the committed checkpoint alone: an unknown Publish of another slot
/// keeps a lower cut possibly named.
#[test]
fn an_unknown_publish_keeps_the_floor_unsettled() {
    let (store, mut host, own) = tenure(1, &[]);
    let mut possible = set(Some(prior()));
    let mut proof = walked_at(1);
    proof.cut_at(3);
    let current = read(&mut host);
    assert_eq!(
        settled_floor(&possible, current.value()),
        Some(0),
        "the floor is settled before the held Publish"
    );
    store.schedule(Arm::Hold);
    let mut stage = staged(&mut possible, named(1, 1));
    let unknown = publish(
        &mut host,
        &mut possible,
        &current,
        (own, Some(prior())),
        (
            &proof
                .intact((shard(), SESSION), CaptureEpoch::default())
                .unwrap(),
            CaptureEpoch::default(),
        ),
        &mut stage,
    );
    assert_eq!(
        unknown.map(|_| ()),
        Err(WriteRefused::Store(StoreError::Unknown))
    );
    let current = read(&mut host);
    assert_eq!(settled_floor(&possible, current.value()), None);
    store.release();
}

/// A capture pass with its cut recorded at `counter`, walked with no member leaving.
fn walked_at(counter: u32) -> Capture {
    let mut capture = Capture::at_counter(u64::from(counter) - 1);
    let cap = SideCap {
        entries: 1,
        words: 1,
    };
    capture
        .start((1, CaptureEpoch::default()), 1, 0, 1, true, cap)
        .unwrap();
    capture.advance(1).unwrap();
    capture
}

/// A full chain refuses a fifth suffix before any request, as does a record naming no checkpoint, certify raises a
/// predecessor's certified end, a store outage keeps the chain while the write is held, and a successor's suffix
/// starts after every recorded suffix.
#[test]
fn a_full_chain_or_store_outage_refuses_the_suffix_write_and_keeps_history() {
    let predecessors: Vec<_> = [(2u64, 0u64), (4, 10), (6, 20)]
        .map(|(epoch, start)| suffix((3 << 32) | epoch, start, start, start + 10))
        .to_vec();
    let (store, mut host, own) = tenure(4, &predecessors);
    // A region of 64 blocks holds the predecessors' 30 blocks of history above the floor and the tenure's suffix.
    let narrow = *suffix_set(4).layout();
    let wide = Layout {
        units: narrow.units + 48,
        ..narrow
    };
    let mut possible = PossiblyNamed::new((shard(), (3 << 32) | 8), wide, None);
    let current = read(&mut host);
    let fifth = suffix((3 << 32) | 10, 40, 40, 50);
    let before = stored(&store);
    assert_eq!(
        reserve_suffix(&mut host, &mut possible, (&current, own), fifth).map(|_| ()),
        Err(WriteRefused::Chain),
        "a suffix of another session than the set's tenure refuses below the cap, before any request"
    );
    assert_eq!(stored(&store), before);
    // A record naming no checkpoint, which restart and takeover refuse beside a suffix, gets no suffix.
    let bare = Shared::new();
    let record = ShardRecord {
        attempts: 1,
        ..crate::storage::store_tests::record()
    };
    client(&bare).create_shard(record).unwrap();
    let mut bare_host = client(&bare);
    let bare_read = read(&mut bare_host);
    let bare_before = stored(&bare);
    assert_eq!(
        reserve_suffix(
            &mut bare_host,
            &mut suffix_set(1),
            (&bare_read, Target::of(bare_read.value())),
            suffix(SESSION, 0, 0, 10)
        )
        .map(|_| ()),
        Err(WriteRefused::Chain),
        "a record naming no checkpoint refuses a suffix before any request"
    );
    assert_eq!(stored(&bare), bare_before);
    let own_suffix = suffix((3 << 32) | 8, 30, 33, 40);
    reserve_suffix(&mut host, &mut possible, (&current, own), own_suffix).unwrap();
    assert_eq!(
        stored(&store).1.ancestry.as_slice()[3],
        suffix((3 << 32) | 8, 30, 30, 40),
        "an appended suffix's certified end is its start"
    );
    let current = read(&mut host);
    let four: Vec<_> = predecessors
        .iter()
        .copied()
        .chain([suffix((3 << 32) | 8, 30, 30, 40)])
        .collect();
    let (full_store, mut full_host, full_own) = tenure(5, &four);
    let full = read(&mut full_host);
    assert_eq!(
        reserve_suffix(&mut full_host, &mut suffix_set(5), (&full, full_own), fifth).map(|_| ()),
        Err(WriteRefused::Chain),
        "a full chain refuses the tenure's own suffix before any request"
    );
    assert_eq!(stored(&full_store).1.ancestry.as_slice(), &four[..]);
    assert_eq!(
        certify(
            &mut host,
            &mut possible,
            (&current, own),
            ((3 << 32) | 12, 1)
        )
        .map(|_| ()),
        Err(WriteRefused::Chain),
        "certify refuses a session the chain does not hold"
    );
    let before = stored(&store);
    let other_shard = crate::net::ownership::Shard::new(shard().get() + 1).unwrap();
    let other_tenure = Target {
        attempts: own.attempts + 1,
        ..own
    };
    let mut foreign = PossiblyNamed::new((other_shard, (3 << 32) | 8), *possible.layout(), None);
    for (possible, tenure, write) in [
        (&mut foreign, (&current, own), "another shard"),
        (&mut possible, (&current, other_tenure), "another tenure"),
    ] {
        assert_eq!(
            reserve_suffix(&mut host, possible, tenure, fifth).map(|_| ()),
            Err(WriteRefused::Tenure),
            "{write}"
        );
        assert_eq!(
            certify(&mut host, possible, tenure, ((3 << 32) | 6, 25)).map(|_| ()),
            Err(WriteRefused::Tenure),
            "{write}"
        );
    }
    assert_eq!(stored(&store), before, "a tenure refusal changes nothing");
    assert_eq!(
        reserve_suffix(
            &mut host,
            &mut possible,
            (&current, own),
            suffix((3 << 32) | 8, 30, 30, 30 + 65)
        )
        .map(|_| ()),
        Err(WriteRefused::Chain),
        "a suffix longer than the delta region refuses"
    );
    assert_eq!(
        reserve_suffix(
            &mut host,
            &mut possible,
            (&current, own),
            suffix((3 << 32) | 8, 30, 30, 65)
        )
        .map(|_| ()),
        Err(WriteRefused::Chain),
        "a suffix ending past the floor plus the delta region refuses"
    );
    let (exact_store, mut exact_host, exact_own) = tenure(1, &[]);
    let exact = read(&mut exact_host);
    reserve_suffix(
        &mut exact_host,
        &mut suffix_set(1),
        (&exact, exact_own),
        suffix(SESSION, 0, 0, 16),
    )
    .unwrap();
    assert_eq!(
        stored(&exact_store).1.ancestry.as_slice(),
        &[suffix(SESSION, 0, 0, 16)],
        "a suffix of exactly the delta region's blocks is recorded"
    );
    let predecessor = suffix((3 << 32) | 2, 0, 4, 10);
    let (behind_store, mut behind_host, behind_own) = tenure(2, &[predecessor]);
    let mut behind = suffix_set(2);
    let own_session = (3 << 32) | 4;
    for end in [12, 15] {
        let current = read(&mut behind_host);
        reserve_suffix(
            &mut behind_host,
            &mut behind,
            (&current, behind_own),
            suffix(own_session, 10, end, end),
        )
        .unwrap();
    }
    assert_eq!(
        stored(&behind_store).1.ancestry.as_slice(),
        &[predecessor, suffix(own_session, 10, 10, 15)],
        "an extension raises only the end of the tenure's own suffix"
    );
    certify(
        &mut host,
        &mut possible,
        (&current, own),
        ((3 << 32) | 6, 25),
    )
    .unwrap();
    assert_eq!(
        stored(&store).1.ancestry.as_slice()[2].certified,
        25,
        "a predecessor's certified end rises"
    );
    let current = read(&mut host);
    let before = stored(&store);
    store.schedule(Arm::Hold);
    assert_eq!(
        certify(
            &mut host,
            &mut possible,
            (&current, own),
            ((3 << 32) | 8, 35)
        )
        .map(|_| ()),
        Err(WriteRefused::Store(StoreError::Unknown)),
        "a store outage leaves the write unknown"
    );
    assert_eq!(
        stored(&store),
        before,
        "the chain is unchanged while the write is held"
    );
    store.release();
    let record = stored(&store).1;
    assert_eq!((suffix_start(&record), suffix_floor(&record)), (40, 0));
}

fn open_bounds() -> SuffixBounds {
    SuffixBounds {
        limits: SuffixLimits {
            flush_ns: 0,
            queue_blocks: 8,
            oldest_ns: 1 << 40,
            uncertified: 16,
        },
        step: 4,
        margin: 1,
    }
}

#[test]
fn a_tenure_over_a_full_chain_publishes_past_it_and_then_opens_its_suffix() {
    use crate::storage::publish_tests::{TRIES, budget, index_config, key, storage};
    let s = storage(4, &index_config(&[4], (1, 1), 2));
    let (bound, _) = observed_completed(&s, key(1));
    bound.publish(TRIES, &mut budget()).unwrap();
    let four: Vec<_> = [(2u64, 0u64), (4, 10), (6, 20), (8, 30)]
        .map(|(epoch, start)| suffix((3 << 32) | epoch, start, start, start + 10))
        .to_vec();
    let (store, mut host, own) = tenure(5, &four);
    let session = (3 << 32) | 10;
    let layout = *suffix_set(5).layout();
    let mut possible = PossiblyNamed::new((shard(), session), layout, Some(prior()));
    let current = read(&mut host);
    assert_eq!(
        open_suffix(
            &mut host,
            &mut possible,
            (current, own),
            (&s, &[]),
            open_bounds()
        )
        .map(|_| ()),
        Err(WriteRefused::Chain),
        "a full chain refuses the tenure's own suffix"
    );
    assert_eq!(stored(&store).1.ancestry.as_slice(), &four[..]);
    assert_eq!(s.with_suffix(|log| log.is_open()), Ok(false));
    let counter = s.start_capture(4, true, 4).unwrap();
    let captured = drain(&s);
    assert_eq!(captured.len(), 1);
    let proof = s.cut_intact((shard(), session), counter).unwrap();
    let current = read(&mut host);
    let published = published_over(
        (&mut host, &mut possible),
        (&current, own, Some(prior())),
        (&proof, s.capture_epoch()),
        &captured,
    )
    .expect("a pass of the unopened log seals its cut at the end of every recorded suffix");
    assert_eq!(
        (published.value().cut, published.value().ancestry.as_slice()),
        (40, &[][..]),
        "the Publish at the chain's end drops every predecessor suffix"
    );
    let (reserved, opened) = open_suffix(
        &mut host,
        &mut possible,
        (published, own),
        (&s, &[]),
        open_bounds(),
    )
    .unwrap();
    assert!(opened, "the emptied chain admits the tenure's suffix");
    let mine = suffix(session, 40, 40, 44);
    assert_eq!(reserved.value().ancestry.as_slice(), &[mine]);
    assert_eq!(s.with_suffix(|log| log.recorded()), Ok(mine));
}

#[test]
fn open_suffix_reserves_up_to_the_last_lsn() {
    use crate::storage::LSN_LIMIT;
    use crate::storage::publish_tests::{index_config, storage};
    let s = storage(4, &index_config(&[4], (1, 1), 2));
    let store = Shared::new();
    let cut = LSN_LIMIT - 1;
    client(&store)
        .create_shard(ShardRecord {
            attempts: 1,
            checkpoint: Some(prior()),
            cut,
            ..record()
        })
        .unwrap();
    let mut host = client(&store);
    let layout = *suffix_set(1).layout();
    let mut possible = PossiblyNamed::new((shard(), SESSION), layout, Some(prior()));
    let current = read(&mut host);
    let (reserved, opened) = open_suffix(
        &mut host,
        &mut possible,
        (current, own()),
        (&s, &[]),
        open_bounds(),
    )
    .expect("a reservation step past the last LSN is cut to the end the record admits");
    assert!(opened);
    let mine = suffix(SESSION, cut, cut, LSN_LIMIT + 1);
    assert_eq!(reserved.value().ancestry.as_slice(), &[mine]);
    assert_eq!(s.with_suffix(|log| log.recorded()), Ok(mine));
}

/// A reader holds at most `WINDOWS` windows from a read's issue until every destination applied the window: with
/// every window decoded but no destination job run, it issues no read even with none outstanding, and it resumes once
/// the destination jobs ran.
#[test]
fn a_reader_issues_no_read_while_it_holds_its_window_cap() {
    let entries = entries(41 * 64 * (WINDOWS + 4));
    let (layout, ck, bytes) = slot_image(&entries, false);
    let mut reader = slot_reader(&layout, ck, load_limits(entries.len()), 4);
    let mut issued = 0;
    while let Some(range) = reader.next_read() {
        issued += 1;
        let start = range.start() as usize;
        let job = reader.completed(
            range,
            bytes[start..start + range.byte_len() as usize].to_vec(),
        );
        reader.decode().landed(run(job.expect("a slot read")));
    }
    assert_eq!(issued, WINDOWS, "the cap stops reads with none outstanding");
    assert!(!reader.done());
    settle(reader.decode(), None);
    assert!(
        reader.next_read().is_some(),
        "reads resume once the windows are applied"
    );
}

/// The reader session of the suffix cases: generation 3, above every suffix session `(3 << 32) | 2·level`.
pub(crate) const SUFFIX_READER: u64 = (3 << 32) | 8;

/// A slot of `entries` beside an ancestry of suffixes, level `k` writing `levels[k]` from the previous level's end
/// under session `(3 << 32) | 2·(k + 1)`, on one prefix image whose delta region holds two spare blocks: the layout,
/// the named checkpoint, the cut, the ancestry and the image. A block of `torn` LSNs has its last payload byte flipped,
/// and the last level certifies only its start when `uncertified`.
pub(crate) fn suffix_image(
    entries: &[CaptureEntry],
    levels: &[Vec<Record>],
    holes: (&[u64], bool),
) -> (Layout, NamedCheckpoint, Vec<Suffix>, Vec<u8>) {
    suffix_image_at(entries, levels, holes, (0, false))
}

/// [`suffix_image`] with the first level starting at LSN `from`, so the blocks wrap the region when `from` is near its
/// end, and with the slot torn in its last unit when `slot_tear`. A torn block LSN counts from `from`.
pub(crate) fn suffix_image_at(
    entries: &[CaptureEntry],
    levels: &[Vec<Record>],
    (torn, uncertified): (&[u64], bool),
    (from, slot_tear): (u64, bool),
) -> (Layout, NamedCheckpoint, Vec<Suffix>, Vec<u8>) {
    use crate::storage::recovery::delta::Block;
    let (mut blocks, mut ancestry) = (Vec::new(), Vec::new());
    for (level, records) in levels.iter().enumerate() {
        let session = (3 << 32) | (2 * level as u64 + 2);
        let start = from + blocks.len() as u64;
        let first = Block {
            shard: shard(),
            session,
            lsn: start,
        };
        blocks.extend(crate::storage::recovery::delta_tests::packed_as(
            first, records,
        ));
        let end = from + blocks.len() as u64;
        let last = uncertified && level + 1 == levels.len();
        ancestry.push(Suffix {
            session,
            start,
            certified: if last { start } else { end },
            end,
        });
    }
    let (slot_image_layout, ck, slot_bytes) = slot_image(entries, slot_tear);
    let region = blocks.len() as u64 + 2;
    let layout = Layout {
        units: slot_image_layout.units + region,
        ..slot_image_layout
    };
    let mut bytes = slot_bytes;
    bytes.resize(layout.units as usize * IO_UNIT, 0xEE);
    for (lsn, block) in (from..).zip(blocks.iter_mut()) {
        if torn.contains(&(lsn - from)) {
            block[UNIT_LEN - 1] ^= 1;
        }
        let at = (slot_image_layout.units + lsn % region) as usize * IO_UNIT;
        bytes[at..at + IO_UNIT].copy_from_slice(&block[..]);
    }
    (layout, ck, ancestry, bytes)
}

/// A suffix entry of serial `serial` over a checkpoint of `count` entries built by [`entries`]: a fresh key, slot
/// and unit past the checkpoint's, or by `kind` a checkpoint entry `of`'s slot, unit or key, a slot past the count of
/// `limits` or a unit past its payload area.
pub(crate) fn suffix_entry(
    serial: usize,
    count: usize,
    kind: u64,
    of: usize,
    limits: &LoadLimits,
) -> CaptureEntry {
    let fresh = count + serial;
    let mut made = entry(fresh, 4, 8 * fresh as u64);
    made.key[16..24].copy_from_slice(&(serial as u64).to_le_bytes());
    let base = entry(of, 2, 8 * of as u64);
    match kind {
        0 => made.allocation = (of as u64) << 32 | 4,
        1 => made.extents = base.extents,
        2 => made.key = base.key,
        3 => made.allocation = (limits.slot_count as u64 + 3) << 32 | 4,
        4 => {
            made.extents = vec![
                ExtentLocator::new(limits.payload_end + 1, 1)
                    .unwrap()
                    .bits(),
            ]
        }
        _ => {}
    }
    made
}

/// Random suffix levels over a checkpoint of `count` entries: inserts of fresh entries and of entries that reuse a
/// checkpoint entry's slot, unit or key, or that leave the limits, REMOVEs and REPLACEs of checkpoint entries and of
/// earlier inserts, and pairs of one level's inserts on one unit.
pub(crate) fn suffix_levels(
    rng: &mut SplitMix64,
    count: usize,
    limits: &LoadLimits,
) -> Vec<Vec<Record>> {
    use crate::storage::recovery::delta::{Cause, identity_of};
    let mut serial = 0;
    let mut inserted: Vec<CaptureEntry> = Vec::new();
    (0..1 + rng.below(3))
        .map(|_| {
            (0..rng.below(24))
                .map(|_| {
                    serial += 1;
                    let of = rng.below(count as u64) as usize;
                    let kind = rng.below(12);
                    let made = suffix_entry(serial, count, kind, of, limits);
                    let record = match rng.below(6) {
                        0 => Record::Remove {
                            identity: identity_of(&entry(of, 2, 8 * of as u64)),
                            cause: Cause::Evict,
                        },
                        1 if !inserted.is_empty() => Record::Remove {
                            identity: identity_of(
                                &inserted[rng.below(inserted.len() as u64) as usize],
                            ),
                            cause: Cause::Invalidate,
                        },
                        2 => Record::Replace {
                            old: identity_of(&entry(of, 2, 8 * of as u64)),
                            cause: Cause::Invalidate,
                            new: suffix_entry(serial, count, 1, of, limits),
                        },
                        3 if !inserted.is_empty() => {
                            let mut twin = made.clone();
                            twin.extents = inserted[inserted.len() - 1].extents.clone();
                            Record::Insert(twin)
                        }
                        _ => Record::Insert(made),
                    };
                    if let Record::Insert(entry) | Record::Replace { new: entry, .. } = &record {
                        inserted.push(entry.clone());
                    }
                    record
                })
                .collect()
        })
        .collect()
}

/// The batch replay of the suffixes on `bytes` over `entries`, as the reader names them.
pub(crate) fn batch_replay(
    limits: (&Layout, &LoadLimits),
    entries: &[CaptureEntry],
    ancestry: &[Suffix],
    bytes: &[u8],
) -> crate::storage::recovery::delta_replay::SuffixLoad {
    batch_replay_from(limits, entries, (0, ancestry), bytes)
}

/// [`batch_replay`] from the cut `cut`.
pub(crate) fn batch_replay_from(
    (layout, limits): (&Layout, &LoadLimits),
    entries: &[CaptureEntry],
    (cut, ancestry): (u64, &[Suffix]),
    bytes: &[u8],
) -> crate::storage::recovery::delta_replay::SuffixLoad {
    let region = crate::storage::recovery::delta::blocks(layout);
    let first = layout.units - region;
    crate::storage::recovery::delta_replay::replay(
        (Crc32c::detect(), shard(), SUFFIX_READER),
        (layout, limits),
        entries.to_vec(),
        cut,
        ancestry,
        |lsn, unit| {
            let at = (first + lsn % region) as usize * IO_UNIT;
            unit.copy_from_slice(&bytes[at..at + IO_UNIT]);
            true
        },
    )
    .expect("valid limits")
}

/// A reader of `ck` and `ancestry` from cut 0 under `layout` and `limits` over `shards` destinations, for the suffix
/// reader session.
pub(crate) fn suffix_reader(
    layout: &Layout,
    (ck, ancestry): (NamedCheckpoint, &[Suffix]),
    limits: LoadLimits,
    routing: (KeyHasher, usize),
) -> SlotReader {
    suffix_reader_from(layout, (ck, 0, ancestry), limits, routing)
}

/// [`suffix_reader`] from the cut `cut`.
pub(crate) fn suffix_reader_from(
    layout: &Layout,
    (ck, cut, ancestry): (NamedCheckpoint, u64, &[Suffix]),
    limits: LoadLimits,
    routing: (KeyHasher, usize),
) -> SlotReader {
    SlotReader::new(
        Crc32c::detect(),
        layout,
        shard(),
        (ck, cut, ancestry),
        SUFFIX_READER,
        (limits, &EngineBudget::unlimited()),
        routing,
    )
    .unwrap()
}

/// Whether `range` lies inside one `READ_LEN`-aligned window.
fn in_one_window(range: DeviceRange) -> bool {
    range.start() / READ_LEN == (range.start() + u64::from(range.byte_len()) - 1) / READ_LEN
}

/// A slot and an ancestry of one to three suffixes, loaded through a reader over one, four or sixteen destinations in
/// random read and job orders, get the verdict of the guard over the checkpoint and, once it passes, of the batch
/// replay of the suffixes over the checkpoint followed by the batch guard over its live entries: the same final
/// entries, the same report of the suffix's entries, and the counts of checkpoint entries the suffix superseded and of
/// checkpoint entries both paths withhold for a session the reader does not admit. The cases reach such entries,
/// exclusion and supersession of checkpoint entries, withheld pairs, damage and tails, every rule the final set can
/// fail, a slot torn in its last unit beside a suffix that changes its kept entries, suffixes that wrap the delta region
/// and a cut inside a suffix. The reader issues its suffix reads first, each inside one window and the delta region.
#[test]
fn a_slot_and_suffix_stream_equals_batch_replay_and_guard() {
    use crate::storage::recovery::checkpoint::KEEP_SUPERSEDED;
    let mut rng = SplitMix64::new(0x1445B);
    let (mut refusals, mut reach, mut keep_superseded) =
        (std::collections::BTreeSet::new(), [0; 10], false);
    for case in 0..300 {
        let (mut entries, mut limits) = match case % 3 {
            0 => generated(&mut rng),
            _ => {
                let count = 1 + rng.below(1500) as usize;
                (entries(count), load_limits(count))
            }
        };
        if case % 5 == 0 {
            // A checkpoint entry of generation 0, which the suffix reader does not admit.
            let at = case as usize % entries.len();
            entries[at].session = 2;
        }
        let count = entries.len();
        limits.slot_count = 2 * count + 1200;
        limits.payload_end = 8 * limits.slot_count as u64;
        match rng.below(4) {
            0 => limits.n_max = count + rng.below(4) as usize,
            1 => {
                limits.reserve_units = limits.payload_end - rows(&entries) - rng.below(8);
                limits.n_max = limits.slot_count;
            }
            _ => limits.n_max = limits.slot_count,
        }
        let mut levels = suffix_levels(&mut rng, count, &limits);
        if case % 4 == 2 {
            // A level of several blocks, so a cut can fall inside it.
            let fresh = (1000..1080).map(|serial| suffix_entry(serial, count, 5, 0, &limits));
            levels[0].extend(fresh.map(Record::Insert));
        }
        let blocks: usize = levels.iter().map(Vec::len).sum::<usize>().div_ceil(20);
        let mut torn: Vec<u64> = (0..rng.below(2))
            .map(|_| rng.below(blocks.max(1) as u64))
            .collect();
        let uncertified = rng.below(4) == 0;
        torn.extend(uncertified.then(|| blocks.saturating_sub(1) as u64));
        let (from, slot_tear) = (rng.below(64), case % 7 == 3);
        let (layout, ck, ancestry, bytes) =
            suffix_image_at(&entries, &levels, (&torn, uncertified), (from, slot_tear));
        let end = ancestry.last().map_or(from, |suffix| suffix.end);
        let cut = match rng.below(2) {
            0 => from + rng.below(end - from + 1),
            _ => 0,
        };
        let region = crate::storage::recovery::delta::blocks(&layout);
        let shards = [1, 4, 16][rng.below(3) as usize];
        let mut reader = suffix_reader_from(&layout, (ck, cut, &ancestry), limits, routing(shards));
        let mut picks = SplitMix64::new(case);
        let issued = drive(&mut reader, &bytes, |len| picks.below(len as u64) as usize);
        let delta =
            (layout.units - crate::storage::recovery::delta::blocks(&layout)) * IO_UNIT as u64;
        let suffix_reads = issued
            .iter()
            .take_while(|(range, _)| range.start() >= delta)
            .count();
        assert!(
            issued.iter().all(|(range, _)| in_one_window(*range))
                && issued[suffix_reads..]
                    .iter()
                    .all(|(range, _)| range.start() < delta),
            "case {case}: suffix reads lead and every read lies in one window"
        );
        let slot = reader.finish().expect("no helper failed");
        // A torn last unit loses only its own entries; when no entry's rows cross into it, the decoded rows are exactly
        // the kept entries' and the oracle runs over them.
        let last = units(rows(&entries)) as usize - 1;
        let entries = match slot_tear {
            true => outside(&entries, last),
            false => entries,
        };
        match slot_tear {
            true => assert_eq!(
                slot.damage.as_ref().map(|damage| &damage.failed[..]),
                Some(&[last as u32][..])
            ),
            false => assert_eq!(slot.damage, None, "case {case}"),
        }
        if slot_tear && rows(&entries) != (last as u64 - 1) * crate::failover::records::UNIT_ENTRIES
        {
            continue;
        }
        let base = guarded_load(entries.clone(), limits, &EngineBudget::unlimited());
        if let GuardedLoad::Cold { refusal, .. } = base {
            assert_eq!(
                slot.verdict,
                Err(refusal),
                "case {case}: the checkpoint's refusal leads"
            );
            continue;
        }
        let batch = batch_replay_from((&layout, &limits), &entries, (cut, &ancestry), &bytes);
        let expected = canon(guarded_load(
            batch.entries.clone(),
            limits,
            &EngineBudget::unlimited(),
        ));
        if let GuardedLoad::Cold { refusal, .. } = &expected {
            refusals.insert(format!("{refusal:?}"));
        }
        assert_eq!(slot.load(), expected, "case {case}");
        let identities: Vec<_> = entries
            .iter()
            .map(crate::storage::recovery::delta::identity_of)
            .collect();
        let mut report = batch.report.clone();
        report.superseded.retain(|id| !identities.contains(id));
        report.withheld.retain(|id| !identities.contains(id));
        let superseded = batch.report.superseded.len() - report.superseded.len();
        let withheld = batch.report.withheld.len() - report.withheld.len();
        assert_eq!(
            (&slot.suffix, slot.slot_superseded, slot.slot_withheld),
            (&report, superseded as u64, withheld as u64),
            "case {case}"
        );
        let excluded = identities
            .iter()
            .filter(|id| report.excluded.contains(id))
            .count();
        for (at, reached) in [
            withheld > 0,
            superseded > 0,
            excluded > 0,
            !report.withheld.is_empty(),
            !report.damage.is_empty(),
            !report.tails.is_empty(),
            matches!(expected, GuardedLoad::Warm(_)) && !levels.iter().all(Vec::is_empty),
            slot_tear && superseded + excluded > 0,
            from % region + (end - from) > region,
            ancestry
                .iter()
                .any(|suffix| suffix.start < cut && cut < suffix.end),
        ]
        .into_iter()
        .enumerate()
        {
            reach[at] += usize::from(reached);
        }
        if superseded > 0 && !keep_superseded {
            KEEP_SUPERSEDED.with(|cell| cell.set(true));
            let mut reader =
                suffix_reader_from(&layout, (ck, cut, &ancestry), limits, routing(shards));
            drive(&mut reader, &bytes, |_| 0);
            keep_superseded = reader.finish().unwrap().load() != expected;
            KEEP_SUPERSEDED.with(|cell| cell.set(false));
        }
    }
    assert!(
        reach.iter().all(|&count| count > 0),
        "every case kind is reached: {reach:?}"
    );
    for refusal in ["Entries", "Units"] {
        assert!(
            refusals.contains(refusal),
            "no final set is refused {refusal}: {refusals:?}"
        );
    }
    assert!(
        keep_superseded,
        "control: a seal that keeps superseded checkpoint entries loads another set than the batch replay"
    );
}

/// An index of `shards` enabled shards, whose key routes a load's destinations follow.
fn index_of(shards: usize) -> ValidatedIndex {
    let storage = crate::storage::StorageConfig {
        page_size: 4096,
        engine_budget: usize::MAX,
        body_cap: 3000,
        metadata_cap: Some(64),
        lease_limit: 8,
        object_rights: 8,
        reader_limit: 2,
        volume: crate::storage::test_volume(2 * 4096, 1 << 20),
    }
    .validate()
    .unwrap();
    let (limits, fills) = (vec![8; shards], vec![0; shards]);
    crate::index::IndexConfig {
        shards: crate::index::ShardLimits::Explicit(&limits),
        load: crate::index::Ratio {
            numerator: 1,
            denominator: 2,
        },
        overflow: crate::index::Ratio {
            numerator: 1,
            denominator: 4,
        },
        depth: 1,
        batch_max: 4,
        fills: &fills,
    }
    .validate(&storage)
    .unwrap()
}

/// Each destination of a slot and suffix load holds exactly the entries whose fingerprint the index routes to its
/// shard, the slot's in unit order and then the suffix's, and every read and job order gives the same destinations.
#[test]
fn entries_reach_their_shard_in_unit_order_whatever_the_job_order() {
    let count = 41 * 64 * 3;
    // One to three extents per entry inside its 8-unit stride, so some entries cross a unit and a window edge and reach
    // their destination as stitched chunks.
    let mut entries = entries(count);
    for (at, entry) in entries.iter_mut().enumerate() {
        entry.extents = (0..1 + at as u64 % 3)
            .map(|extent| {
                ExtentLocator::new(8 * at as u64 + extent, 1)
                    .unwrap()
                    .bits()
            })
            .collect();
    }
    let mut limits = load_limits(count);
    limits.slot_count = 2 * count + 64;
    (limits.payload_end, limits.n_max) = (8 * limits.slot_count as u64, limits.slot_count);
    let inserts: Vec<Record> = (1..200)
        .map(|serial| Record::Insert(suffix_entry(serial, count, 5, 0, &limits)))
        .collect();
    let (layout, ck, ancestry, bytes) = suffix_image(&entries, &[inserts], (&[], false));
    let (hasher, index) = (routing(4).0, index_of(4));
    let mut first = None;
    for seed in 0..8 {
        let mut rng = SplitMix64::new(seed);
        let mut reader = suffix_reader(&layout, (ck, &ancestry), limits, routing(4));
        drive(&mut reader, &bytes, |len| rng.below(len as u64) as usize);
        let slot = reader.finish().unwrap();
        assert_eq!(slot.verdict, Ok(()));
        for (dest, chunks) in slot.shards.iter().enumerate() {
            let mut words = [0; crate::index::LANES];
            let held: Vec<(CaptureEntry, u64)> = chunks.iter().flat_map(Chunk::captured).collect();
            for (entry, print) in &held {
                hasher.fingerprints(std::slice::from_ref(&entry.key), &mut words);
                let routed = hasher
                    .reroute_unpaid(*print, &index)
                    .map(|route| route.position());
                assert_eq!(
                    (words[0], routed),
                    (*print, Some(dest)),
                    "an entry reaches its own shard"
                );
            }
            assert!(
                held.windows(2)
                    .all(|pair| pair[0].0.allocation < pair[1].0.allocation),
                "destination {dest} holds the slot's entries in unit order, then the suffix's"
            );
        }
        let held: usize = slot.shards.iter().flatten().map(Chunk::len).sum();
        assert_eq!(held, count + 199);
        let shards = first.get_or_insert_with(|| slot.shards.clone());
        assert_eq!(&slot.shards, shards, "seed {seed}");
    }
}

/// Densest-record suffixes of one-extent INSERTs, of REMOVEs and of wide INSERTs: the dense suffix fills its blocks
/// with one level of records over `count` fresh slots.
pub(crate) fn dense_levels(kind: u64, count: usize, limits: &LoadLimits) -> Vec<Vec<Record>> {
    use crate::storage::recovery::delta::{Cause, identity_of};
    let records = (1..1 + 2 * count)
        .map(|serial| {
            let mut made = suffix_entry(serial, count, 5, 0, limits);
            match kind {
                0 => Record::Insert(made),
                1 => Record::Remove {
                    identity: identity_of(&made),
                    cause: Cause::Evict,
                },
                _ => {
                    let start = 8 * (count + serial) as u64;
                    made.extents = (0..7)
                        .map(|at| ExtentLocator::new(start + at, 1).unwrap().bits())
                        .collect();
                    Record::Insert(made)
                }
            }
        })
        .collect();
    vec![records]
}

/// A slot and a suffix of the densest records, one-extent INSERTs, REMOVEs or wide INSERTs, load within the bytes the
/// reader charges for the decode and the replay, and a budget one byte below that charge refuses the reader `Memory`.
#[test]
fn the_suffix_charge_covers_a_dense_suffix_and_a_short_budget_refuses_memory() {
    use crate::storage::recovery::delta_replay::bytes as replay_bytes;
    let count = 41 * 64 * 2;
    let mut entries = entries(count);
    // An entry the reader does not admit, so seals withhold it beside the patch's drops.
    entries[count / 2].session = 2;
    let mut limits = load_limits(count);
    limits.slot_count = 8 * count + 64;
    (limits.payload_end, limits.n_max) = (8 * limits.slot_count as u64, limits.slot_count);
    let mut rng = SplitMix64::new(0x1445B);
    for (kind, shards) in (0..3).flat_map(|kind| [(kind, 4), (kind, 64)]) {
        let levels = dense_levels(kind, count, &limits);
        let (layout, ck, ancestry, bytes) = suffix_image(&entries, &levels, (&[], false));
        let blocks = ancestry[0].end;
        let charge = SlotDecode::bytes(ck.units, &limits, shards, (WINDOWS, READ_LEN as usize))
            .unwrap()
            + replay_bytes(blocks).unwrap();
        let reader = |budget: &EngineBudget| {
            SlotReader::new(
                Crc32c::detect(),
                &layout,
                shard(),
                (ck, 0, &ancestry),
                SUFFIX_READER,
                (limits, budget),
                routing(shards),
            )
        };
        assert!(
            matches!(
                reader(&EngineBudget::new(charge - 1)),
                Err(ReaderRefusal::Memory)
            ),
            "kind {kind}: a budget one byte short of the decode and replay"
        );
        // The peak is compared with the charge of only the slot windows the slot spans, so the unreached windows of
        // the reader's charge leave no room for a replay undercharge.
        let first = layout.prefix_unit(ck.slot, 0).unwrap() * IO_UNIT as u64;
        let end = first + u64::from(ck.units) * IO_UNIT as u64;
        let held = ((end - 1) / READ_LEN - first / READ_LEN + 1) as usize;
        assert!(held < WINDOWS, "the slot spans {held} windows");
        let reached = SlotDecode::bytes(ck.units, &limits, shards, (held, READ_LEN as usize))
            .unwrap()
            + replay_bytes(blocks).unwrap();
        // In order, the replay lands before any slot window; at random, between them; with destination jobs held
        // until every read landed, after every slot window, which then reach their seals unclassified.
        for schedule in 0..3 {
            let live = crate::instrument::live_bytes();
            crate::instrument::reset_peak();
            let mut reader = reader(&EngineBudget::new(charge)).unwrap();
            match schedule {
                0 => drop(drive(&mut reader, &bytes, |_| 0)),
                1 => drop(drive(&mut reader, &bytes, |len| {
                    rng.below(len as u64) as usize
                })),
                _ => drop(drive_to_the_cap(&mut reader, &bytes)),
            }
            let slot = reader.finish().unwrap();
            let peak = crate::instrument::peak_bytes().wrapping_sub(live);
            let what = format!("kind {kind}, {shards} shards, schedule {schedule}");
            assert_eq!(
                (slot.verdict, slot.damage, slot.slot_withheld),
                (Ok(()), None, 1),
                "{what}"
            );
            assert!(
                peak <= reached,
                "{what}: peak {peak} within the charge {reached} of the windows the slot spans"
            );
        }
    }
}

/// A suffix that spans more reads than the reader keeps outstanding never takes it past [`READ_DEPTH`] reads, suffix
/// and slot reads together.
#[test]
fn a_reader_keeps_its_read_depth_across_suffix_and_slot_reads() {
    let count = 41 * 64 * 10;
    let entries = entries(count);
    let mut limits = load_limits(count);
    limits.slot_count = 8 * count + 64;
    (limits.payload_end, limits.n_max) = (8 * limits.slot_count as u64, limits.slot_count);
    let levels = dense_levels(0, count, &limits);
    let (layout, ck, ancestry, bytes) = suffix_image(&entries, &levels, (&[], false));
    let delta = (layout.units - crate::storage::recovery::delta::blocks(&layout)) * IO_UNIT as u64;
    let mut reader = suffix_reader(&layout, (ck, &ancestry), limits, routing(4));
    let issued = drive(&mut reader, &bytes, |len| len - 1);
    let suffix_reads = issued
        .iter()
        .filter(|(range, _)| range.start() >= delta)
        .count();
    assert!(
        suffix_reads > READ_DEPTH,
        "the suffix spans {suffix_reads} reads"
    );
    assert!(
        issued
            .iter()
            .all(|&(_, outstanding)| outstanding <= READ_DEPTH),
        "at most {READ_DEPTH} reads are outstanding"
    );
    assert!(
        issued.iter().all(|(range, _)| in_one_window(*range)),
        "every suffix and slot read lies in one window"
    );
    assert_eq!(reader.finish().unwrap().verdict, Ok(()));
}

/// A suffix read that completes short holds one whole block and half of the next: the whole block replays, and every
/// later block of that read is unread, so the load is not installable.
#[test]
fn a_short_suffix_read_leaves_the_blocks_past_its_whole_units_unread() {
    let count = 300;
    let entries = entries(count);
    let mut limits = load_limits(count);
    limits.slot_count = 8 * count + 64;
    (limits.payload_end, limits.n_max) = (8 * limits.slot_count as u64, limits.slot_count);
    let levels = dense_levels(0, count, &limits);
    let (layout, ck, ancestry, bytes) = suffix_image(&entries, &levels, (&[], false));
    let mut reader = suffix_reader(&layout, (ck, &ancestry), limits, routing(4));
    let first = reader.next_read().expect("the first suffix read");
    let blocks = u64::from(first.byte_len()) / IO_UNIT as u64;
    assert!(blocks > 1, "the first suffix read spans {blocks} blocks");
    let start = first.start() as usize;
    reader.complete(first, &bytes[start..start + IO_UNIT + IO_UNIT / 2]);
    while let Some(range) = reader.next_read() {
        let start = range.start() as usize;
        reader.complete(range, &bytes[start..start + range.byte_len() as usize]);
    }
    let slot = reader.load();
    let lsn = ancestry[0].start;
    assert_eq!(
        slot.suffix.unread,
        (lsn + 1..lsn + blocks).collect::<Vec<_>>()
    );
    assert!(!slot.installable());
}

/// A suffix block the device could not read is unread, so the load is not installable until a later read loads it;
/// with every block read the same load is installable.
#[test]
fn an_unread_suffix_block_leaves_the_load_uninstallable() {
    let count = 300;
    let entries = entries(count);
    let mut limits = load_limits(count);
    limits.slot_count = 8 * count + 64;
    (limits.payload_end, limits.n_max) = (8 * limits.slot_count as u64, limits.slot_count);
    let levels = dense_levels(0, count, &limits);
    let (layout, ck, ancestry, bytes) = suffix_image(&entries, &levels, (&[], false));
    let delta = (layout.units - crate::storage::recovery::delta::blocks(&layout)) * IO_UNIT as u64;
    for fail in [true, false] {
        let mut reader = suffix_reader(&layout, (ck, &ancestry), limits, routing(4));
        let mut failed = 0;
        while let Some(range) = reader.next_read() {
            let start = range.start() as usize;
            if fail && failed == 0 && range.start() >= delta {
                failed += 1;
                reader.fail_read(range);
            } else {
                reader.complete(range, &bytes[start..start + range.byte_len() as usize]);
            }
        }
        let slot = reader.load();
        assert_eq!(slot.damage, None);
        assert_eq!(slot.installable(), !fail, "a failed suffix read: {fail}");
        assert_eq!(slot.suffix.unread.is_empty(), !fail);
    }
}

/// Suffix reads lead and release their windows as they land, so a reader holding every slot window it may hold has
/// issued its suffix reads and exactly [`WINDOWS`] slot reads, issues none while no destination job ran, and resumes
/// once they ran.
#[test]
fn a_reader_holds_its_window_cap_across_suffix_and_slot_reads() {
    let count = 41 * 64 * (WINDOWS + 4);
    let entries = entries(count);
    let mut limits = load_limits(count);
    limits.slot_count = 2 * count + 64;
    (limits.payload_end, limits.n_max) = (8 * limits.slot_count as u64, limits.slot_count);
    let levels = vec![dense_levels(0, count, &limits)[0][..8000].to_vec()];
    let (layout, ck, ancestry, bytes) = suffix_image(&entries, &levels, (&[], false));
    let delta = (layout.units - crate::storage::recovery::delta::blocks(&layout)) * IO_UNIT as u64;
    let mut reader = suffix_reader(&layout, (ck, &ancestry), limits, routing(4));
    let (mut suffix_reads, mut slot_reads) = (0, 0);
    while let Some(range) = reader.next_read() {
        let start = range.start() as usize;
        match reader.completed(
            range,
            bytes[start..start + range.byte_len() as usize].to_vec(),
        ) {
            Some(job) => {
                slot_reads += 1;
                reader.decode().landed(run(job));
            }
            None => {
                assert_eq!(slot_reads, 0, "suffix reads lead");
                assert!(range.start() >= delta);
                suffix_reads += 1;
            }
        }
    }
    assert!(suffix_reads > 1, "the suffix spans several reads");
    assert_eq!(
        slot_reads, WINDOWS,
        "the cap stops slot reads with none outstanding"
    );
    assert!(!reader.done());
    settle(reader.decode(), None);
    assert!(
        reader.next_read().is_some(),
        "reads resume once the windows are applied"
    );
}

/// A matching capture number identifies a pass only within its shard and session.
#[test]
fn a_publish_under_the_same_counters_proof_of_another_tenure_refuses() {
    let other = (1..)
        .filter_map(crate::net::ownership::Shard::new)
        .find(|other| *other != shard())
        .unwrap();
    let layout = layout(4);
    let store = seeded();
    let mut host = client(&store);
    let mut possible = PossiblyNamed::new((shard(), SESSION), layout, None);
    let mut bytes = vec![0; layout.units as usize * IO_UNIT];
    let (mut stage, _) = landed(&mut possible, &layout, &mut bytes, 1);
    let current = read(&mut host);
    for (tenure, case) in [
        ((other, SESSION), "another shard's storage"),
        (
            (shard(), SESSION - (1 << 32)),
            "the shard's earlier generation",
        ),
        ((shard(), SESSION + 2), "the generation's next activation"),
        (
            (shard(), SESSION + (1 << 32)),
            "the shard's next generation",
        ),
    ] {
        assert_eq!(
            publish(
                &mut host,
                &mut possible,
                &current,
                (own(), None),
                (&cut_under(tenure, 1), CaptureEpoch::default()),
                &mut stage
            )
            .map(|_| ()),
            Err(WriteRefused::OtherPass),
            "{case}"
        );
        assert_eq!(stored(&store).1.checkpoint, None, "{case}");
        assert!(
            possible.admits(&stage),
            "{case}: the refusal keeps the reservation"
        );
    }
    publish(
        &mut host,
        &mut possible,
        &current,
        (own(), None),
        (&cut_under((shard(), SESSION), 1), CaptureEpoch::default()),
        &mut stage,
    )
    .unwrap();
    assert_eq!(stored(&store).1.checkpoint, Some(stage.named()));
}

/// `certify_suffixes` writes each end in order over the record the previous write committed, skips an end whose
/// session the chain no longer holds, and returns the first other refusal with the earlier writes committed.
#[test]
fn certify_suffixes_writes_in_order_skips_a_missing_suffix_and_stops_at_a_refusal() {
    let (a, b) = ((3 << 32) | 2, (3 << 32) | 4);
    let chain = [suffix(a, 0, 0, 10), suffix(b, 10, 10, 20)];
    let (store, mut host, own) = tenure(3, &chain);
    let mut possible = suffix_set(3);
    let current = read(&mut host);
    let committed = certify_suffixes(
        &mut host,
        &mut possible,
        (current, own),
        &[(a, 6), ((3 << 32) | 12, 9), (b, 15)],
    )
    .unwrap();
    assert_eq!(
        committed.value().ancestry.as_slice(),
        &[suffix(a, 0, 6, 10), suffix(b, 10, 15, 20)],
        "both held suffixes rise; the missing one is skipped"
    );
    assert_eq!(stored(&store).1.ancestry, committed.value().ancestry);
    let current = read(&mut host);
    store.schedule(Arm::Pass);
    store.schedule(Arm::Hold);
    let refused = certify_suffixes(&mut host, &mut possible, (current, own), &[(a, 8), (b, 18)]);
    assert_eq!(
        refused.map(|_| ()),
        Err(WriteRefused::Store(StoreError::Unknown)),
        "the held write's refusal returns"
    );
    assert_eq!(
        stored(&store).1.ancestry.as_slice(),
        &[suffix(a, 0, 8, 10), suffix(b, 10, 15, 20)],
        "the first write committed and the held one did not"
    );
}

/// `slot_found` counts the slot's own whole entries, never the suffix's: beside a live suffix INSERT an intact slot of
/// 41 entries reports 41 with 42 loaded, and the same slot with every unit torn reports 0 while the load still holds
/// the suffix's entry, so a warm stage can tell a lost slot from a suffix-only load.
#[test]
fn slot_found_counts_the_slots_entries_beside_a_live_suffix_insert() {
    let count = 41;
    let entries = entries(count);
    let mut limits = load_limits(count);
    limits.slot_count = 8 * count + 64;
    (limits.payload_end, limits.n_max) = (8 * limits.slot_count as u64, limits.slot_count);
    let levels = vec![vec![Record::Insert(suffix_entry(0, count, 5, 0, &limits))]];
    let (layout, ck, ancestry, bytes) = suffix_image(&entries, &levels, (&[], false));
    let delta = (layout.units - crate::storage::recovery::delta::blocks(&layout)) * IO_UNIT as u64;
    for torn in [false, true] {
        let mut reader = suffix_reader(&layout, (ck, &ancestry), limits, routing(4));
        while let Some(range) = reader.next_read() {
            let start = range.start() as usize;
            let mut read = bytes[start..start + range.byte_len() as usize].to_vec();
            if torn && range.start() < delta {
                read.iter_mut().for_each(|byte| *byte ^= 0x5a);
            }
            reader.complete(range, &read);
        }
        let slot = reader.load();
        let held: usize = slot.shards.iter().flatten().map(Chunk::len).sum();
        let expected = if torn {
            (0, 1)
        } else {
            (count as u64, count + 1)
        };
        assert_eq!((slot.slot_found, held), expected, "torn {torn}");
        assert_eq!(slot.damage.is_some(), torn);
    }
}

#[path = "saturation_tests.rs"]
mod saturation;

/// `WriteRefused::Superseded`: "a later success or a refusal before sending moved its slot out, and the stage can
/// never publish." The tenure starts with slot 0 named. A Publish of slot 1 frees slot 0, a stage reserves it, and
/// its Publish's outcome is unknown. A Confirm's success then settles the set without slot 0 and quarantines it, so
/// the stage can never publish. A Confirm on the tenure's first read, which still names slot 0, fails on the record
/// version before the retry; the retry must still refuse `Superseded`.
#[test]
fn a_superseded_stage_stays_superseded_after_a_refused_stale_confirm() {
    for stale_confirm in [false, true] {
        let store = seeded();
        let mut host = client(&store);
        let first = read(&mut host);
        publish_named(&mut host, &mut set(None), &first, own(), None, named(0, 1)).unwrap();

        let mut possible = set(Some(named(0, 1)));
        let start = read(&mut host);
        let published = publish_named(
            &mut host,
            &mut possible,
            &start,
            own(),
            Some(named(0, 1)),
            named(1, 2),
        )
        .unwrap();
        assert_eq!(
            possible.free_slot(),
            Some(0),
            "premise: the start slot goes free"
        );

        let mut stage = staged(&mut possible, named(0, 3));
        let proof = (&cut(3), CaptureEpoch::default());
        let known = (own(), Some(named(1, 2)));
        store.schedule(Arm::Timeout { commit: false });
        assert_eq!(
            publish(
                &mut host,
                &mut possible,
                &published,
                known,
                proof,
                &mut stage
            )
            .map(|_| ()),
            Err(WriteRefused::Store(StoreError::Unknown))
        );
        let current = read(&mut host);
        confirm(&mut host, &mut possible, &current, own()).unwrap();
        assert_eq!(
            (possible.slots(), possible.quarantined()),
            (vec![1], &[0u32][..]),
            "premise: the settling success drops and quarantines the stage's slot"
        );

        if stale_confirm {
            assert_eq!(
                confirm(&mut host, &mut possible, &start, own()).map(|_| ()),
                Err(WriteRefused::Store(StoreError::Refused(Refusal::Condition))),
                "premise: a Confirm on the first read fails on the record version"
            );
        }
        let current = read(&mut host);
        let retry = publish(&mut host, &mut possible, &current, known, proof, &mut stage);
        assert_eq!(
            (
                retry.map(|_| ()),
                stored(&store).1.checkpoint,
                possible.quarantined()
            ),
            (
                Err(WriteRefused::Superseded),
                Some(named(1, 2)),
                &[0u32][..]
            ),
            "stale confirm {stale_confirm}: the superseded stage publishes nothing"
        );
    }
}

/// Obligation `checkpoint-publication-reserved-quarantined`: "an exact retry after an unknown Publish converges on
/// the stage whether or not the first attempt committed". The tenure starts with slot 0 named, a Publish of slot 1
/// frees it, and a stage reserves it. A Confirm on the tenure's first read, which still names slot 0, fails on the
/// record version, and a Confirm on a fresh read settles the set, both before the stage's first Publish. That Publish's
/// outcome is unknown, and its slot never leaves the set afterwards, so the exact retry converges on the stage, and
/// the reserved slot is never quarantined.
#[test]
fn an_exact_retry_converges_after_a_refused_stale_confirm_named_the_reserved_slot() {
    for (stale_confirm, commit) in [(false, false), (false, true), (true, false), (true, true)] {
        let arm = format!("stale confirm {stale_confirm}, commit {commit}");
        let store = seeded();
        let mut host = client(&store);
        let first = read(&mut host);
        publish_named(&mut host, &mut set(None), &first, own(), None, named(0, 1)).unwrap();

        let mut possible = set(Some(named(0, 1)));
        let start = read(&mut host);
        let known = Some(named(0, 1));
        publish_named(&mut host, &mut possible, &start, own(), known, named(1, 2)).unwrap();
        let mut stage = staged(&mut possible, named(0, 3));
        assert_eq!(
            stage.slot(),
            0,
            "premise: the stage reserves the freed slot"
        );

        if stale_confirm {
            assert_eq!(
                confirm(&mut host, &mut possible, &start, own()).map(|_| ()),
                Err(WriteRefused::Store(StoreError::Refused(Refusal::Condition))),
                "premise: a Confirm on the first read fails on the record version"
            );
        }
        let current = read(&mut host);
        let settled = confirm(&mut host, &mut possible, &current, own()).unwrap();
        assert!(possible.admits(&stage), "{arm}: the stage keeps its slot");
        assert_eq!(
            (possible.slots(), possible.quarantined()),
            (vec![1], &[][..]),
            "{arm}: the settling success drops no slot this tenure wrote"
        );

        let proof = (&cut(3), CaptureEpoch::default());
        let known = (own(), Some(named(1, 2)));
        store.schedule(Arm::Timeout { commit });
        assert_eq!(
            publish(&mut host, &mut possible, &settled, known, proof, &mut stage).map(|_| ()),
            Err(WriteRefused::Store(StoreError::Unknown)),
            "premise: the first Publish's outcome is unknown"
        );
        let current = read(&mut host);
        let retry = publish(&mut host, &mut possible, &current, known, proof, &mut stage);
        assert_eq!(
            (
                retry.map(|_| ()),
                stored(&store).1.checkpoint,
                possible.slots(),
                possible.quarantined()
            ),
            (Ok(()), Some(named(0, 3)), vec![0], &[1u32][..]),
            "{arm}: the exact retry converges on the stage"
        );
    }
}

/// `ReservedBeforeWrite`, `UniqueCapture`: given a reservation and the cut's copy, [`StagedCheckpoint::encode`]
/// produces a stage with the same slot, units and name as [`StagedCheckpoint::new`] over the set and the copied
/// entries, and the set admits the encoded stage's unit writes. While a reservation holds the set's one free slot,
/// a second reservation attempt returns `Busy`. A refused encode returns its reservation; the set's release of that
/// reservation frees the slot, leaves the quarantine empty and keeps the capture number spent.
#[test]
fn a_reserved_stage_encodes_off_the_set_as_one_built_over_it() {
    let crc = Crc32c::detect();
    let entries = crate::storage::recovery::checkpoint_tests::entries(40);
    let mut cut = Cut::new();
    for entry in &entries {
        cut.push(entry, &EngineBudget::unlimited()).unwrap();
    }
    cut.save(Vec::new());
    let checkpoint = |capture| Checkpoint {
        shard: shard(),
        session: SESSION,
        capture,
    };
    let mut over = set(Some(named(0, 1)));
    let built = StagedCheckpoint::new(
        crc,
        &mut over,
        (checkpoint(2), &entries),
        &EngineBudget::unlimited(),
    )
    .unwrap();

    let mut possible = set(Some(named(0, 1)));
    let reservation = possible.reserve_stage(checkpoint(2), &cut).unwrap();
    assert_eq!(possible.free_slot(), None, "the set holds one reservation");
    assert_eq!(
        possible.reserve_stage(checkpoint(3), &cut).err(),
        Some(ReserveRefusal::Busy)
    );
    let staged = StagedCheckpoint::encode(
        crc,
        reservation,
        (&cut, &mut Vec::new()),
        &EngineBudget::unlimited(),
    )
    .unwrap();
    assert!(possible.admits(&staged));
    assert_eq!(staged.slot(), built.slot());
    assert_eq!(staged.named(), built.named());
    assert!(staged.units() == built.units());
    staged.abandon(&mut possible);
    assert_eq!(
        possible.free_slot(),
        Some(1),
        "an unexposed stage frees its slot"
    );

    let reservation = possible.reserve_stage(checkpoint(3), &cut).unwrap();
    let (refusal, reservation) = StagedCheckpoint::encode(
        crc,
        reservation,
        (&cut, &mut Vec::new()),
        &EngineBudget::new(UNIT_LEN),
    )
    .expect_err("the budget holds one unit");
    assert_eq!(refusal, StageRefusal::Memory);
    assert_eq!(
        possible.free_slot(),
        None,
        "a refused encode keeps the reservation"
    );
    possible.release(reservation);
    assert_eq!(possible.free_slot(), Some(1));
    assert!(possible.quarantined().is_empty());
    assert_eq!(
        possible.reserve_stage(checkpoint(3), &cut).err(),
        Some(ReserveRefusal::Capture),
        "a released reservation's capture number stays spent"
    );
    let _ = possible.reserve_stage(checkpoint(4), &cut).unwrap();

    // A refused reservation leaves the set as it was.
    let mut full = set(Some(named(0, 1)));
    for slot in 1..full.layout().slots {
        full.submit(Some(slot));
    }
    let before = (full.slots(), full.free_slot());
    assert_eq!(
        full.reserve_stage(checkpoint(2), &cut).err(),
        Some(ReserveRefusal::Placement(PlacementRefusal::NoFreeSlot))
    );
    assert_eq!((full.slots(), full.free_slot()), before);
}

/// A reserved stage over `cut` in a fresh set, encoded into `kept` under `budget`.
fn staged_into(
    cut: &Cut,
    kept: &mut Units,
    budget: EngineBudget,
) -> Result<StagedCheckpoint, StageRefusal> {
    let checkpoint = Checkpoint {
        shard: shard(),
        session: SESSION,
        capture: 2,
    };
    let mut possible = set(Some(named(0, 1)));
    let reservation = possible.reserve_stage(checkpoint, cut).unwrap();
    StagedCheckpoint::encode(Crc32c::detect(), reservation, (cut, kept), &budget)
        .map_err(|(refusal, _)| refusal)
}

/// A stage takes its units from the kept unit buffers in order and keeps the rest, and the budget counts the kept
/// buffers with the stage's units, [`PER_UNIT`] bytes each: a budget of twice the stage's units keeps a second
/// stage's worth of buffers, a budget of the stage's units alone frees the buffers past them, and one byte less
/// refuses the stage. Kept buffers that number more than twice the stage's units are freed down to the stage's units
/// under any budget, so the stage leaves none. Each stage holds the units of a stage built in fresh buffers.
#[test]
fn a_stage_takes_its_units_from_the_kept_buffers_under_the_budget_with_them() {
    let entries = crate::storage::recovery::checkpoint_tests::entries(40);
    let mut cut = Cut::new();
    for entry in &entries {
        cut.push(entry, &EngineBudget::unlimited()).unwrap();
    }
    cut.save(Vec::new());
    let fresh = staged_into(&cut, &mut Vec::new(), EngineBudget::unlimited()).unwrap();
    let needed = fresh.units().len();
    assert!(needed > 1);
    let scrambled =
        |count: usize| -> Units { (0..count).map(|_| Box::new([0xA5; UNIT_LEN])).collect() };
    let pointers = |units: &[Box<[u8; UNIT_LEN]>]| -> Vec<*const u8> {
        units.iter().map(|unit| unit.as_ptr()).collect()
    };
    for (kept_count, budget, left) in [
        (2 * needed, usize::MAX, needed),
        (2 * needed, 2 * needed * PER_UNIT, needed),
        (2 * needed, 2 * needed * PER_UNIT - 1, 0),
        (2 * needed, needed * PER_UNIT, 0),
        (2 * needed + 1, usize::MAX, 0),
        (needed - 1, needed * PER_UNIT, 0),
    ] {
        let mut kept = scrambled(kept_count);
        let before = pointers(&kept);
        let staged = staged_into(&cut, &mut kept, EngineBudget::new(budget)).unwrap();
        assert!(
            staged.units() == fresh.units(),
            "{kept_count} kept, budget {budget}"
        );
        assert_eq!(kept.len(), left, "{kept_count} kept, budget {budget}");
        let reused = needed.min(kept_count);
        assert_eq!(pointers(staged.units())[..reused], before[..reused]);
        if left > 0 {
            assert_eq!(pointers(&kept), before[needed..needed + left]);
        }
    }
    let mut kept = scrambled(2 * needed);
    assert_eq!(
        staged_into(&cut, &mut kept, EngineBudget::new(needed * PER_UNIT - 1)).err(),
        Some(StageRefusal::Memory)
    );
}
