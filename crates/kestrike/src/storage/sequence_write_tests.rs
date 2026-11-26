//! Writes of objects of several extents through a fill: each extent's
//! record streams through the receive-write buffers and seals its header
//! after its payload, and publication waits for every unit of every extent.
//! Cases: the units a fill counts for an object of one, two and three
//! extents, from its reservation on; two- and three-extent PUTs that
//! publish once and read back their exact bytes by lease and by lookup; a
//! verified input that spans an extent's end, whose object reads back
//! exactly; a
//! failed write at the first, middle or final extent of a replacement,
//! which publishes nothing and leaves the incumbent's bytes, with every
//! extent returned once the fill ends;
//! duplicate completions of the first range standing in for a final range
//! that never completes, which publication refuses; the write share, which
//! several fills saturate while a read still submits, and which frees only
//! at the writes' terminals; and a volume without a sequence arena, which
//! refuses a multi-extent fill.

use super::attempt::CacheVersion;
use super::attempt_tests::{begin, records, service};
use super::claim_exit_tests::{FILLING, FREE, PARKED, conserved_after_service, conserved_at};
use super::config::StorageConfig;
use super::device::sim::{Event, Fault, Injection};
use super::device::{CommandToken, Completion, DeviceStatus, IO_UNIT, Operation};
use super::geometry::EXTENT_PAYLOAD;
use super::lookup_tests::lookup;
use super::owner::Storage;
use super::publish_tests::{
    PAGE, RETRIES, TRIES, budget, index_config, storage_config, storage_from,
};
use super::test_platform::TestPlatform;
use super::volume_fixture::{BUFFER, DEPTH, Device, ample_io, arena_with, read_back, settle, step};
use super::writable_tests::{RESERVED_BIT, admit, bytes, charge, receive_plain};
use super::{FillPublishError, PlacingFill, ReadStatus, ReceiveError, WorkBudget, WritableFill};
use crate::index::{IndexConfig, Key};

const METADATA: usize = 24;

/// An indexed storage of 768 units and eight slots whose largest object has
/// three extents, with one sequence arena root and two fill records.
pub(super) fn storage() -> Storage<TestPlatform> {
    storage_with(1)
}

/// [`storage`] with `block_roots` sequence arena roots.
fn storage_with(block_roots: usize) -> Storage<TestPlatform> {
    let fills = [2usize];
    let index = IndexConfig {
        fills: &fills,
        ..index_config(&[8], (1, 1), 1)
    };
    let units = 768;
    let mut volume = crate::storage::test_volume(units * IO_UNIT, 8);
    volume.alloc_search_words = crate::storage::work_bound(units as u64, 8, 64);
    volume.block_roots = block_roots;
    let config = StorageConfig {
        body_cap: 2 * EXTENT_PAYLOAD as usize + 4096,
        metadata_cap: Some(METADATA),
        object_rights: 8,
        volume,
        ..storage_config(8)
    };
    let storage = storage_from(&config, &index, TestPlatform::heap(PAGE));
    storage.platform.ticks(&[Some(1)]);
    storage
}

fn key(n: u8) -> Key {
    [n; 32]
}

/// A payload of `extents` extents: full extents and a last one of 3,000
/// bytes.
pub(super) fn payload(extents: usize, seed: u64) -> Vec<u8> {
    bytes((extents - 1) * EXTENT_PAYLOAD as usize + 3000, seed)
}

/// A fill reserved for `payload` under `key`, `METADATA` bytes of it metadata.
pub(super) fn reserve<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    key: &Key,
    payload: &[u8],
) -> WritableFill<'s, 'a, TestPlatform> {
    reserve_at(storage, key, CacheVersion(0), payload)
}

fn reserve_at<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    key: &Key,
    version: CacheVersion,
    payload: &[u8],
) -> WritableFill<'s, 'a, TestPlatform> {
    let body = payload.len() - METADATA;
    super::writable_tests::reserve_at(storage, key, version, METADATA, body).unwrap()
}

/// The write tokens the device accepted, newest last; the log keeps the
/// newest events.
fn writes(dev: &Device<'_, '_>) -> Vec<CommandToken> {
    dev.control
        .events()
        .iter()
        .filter_map(|event| match event {
            Event::Submitted(token, Operation::Write) => Some(*token),
            _ => None,
        })
        .collect()
}

/// Streams `payload` into `fill` a buffer at a time, ticking between calls,
/// and calls `submitted` with each write token as its receive returns, before
/// the device executes it; then submits every staged segment and settles.
pub(super) fn stream<'s, 'a>(
    dev: &mut Device<'s, 'a>,
    fill: &mut WritableFill<'s, 'a, TestPlatform>,
    payload: &[u8],
    mut submitted: impl FnMut(&Device<'s, 'a>, usize, CommandToken),
) {
    let mut out = Vec::with_capacity(16);
    let (mut taken, mut count) = (0, 0);
    for _ in 0..4096 {
        let piece = &payload[taken..(taken + BUFFER as usize).min(payload.len())];
        let before = dev.volume.report().writes_submitted;
        match fill.receive(&mut dev.volume, piece, &mut ample_io()) {
            Ok(n) => taken += n,
            Err(ReceiveError::TableFull | ReceiveError::PoolExhausted) => {}
            Err(error) => panic!("receive refused {error:?}"),
        }
        let new = (dev.volume.report().writes_submitted - before) as usize;
        let tokens = writes(dev);
        for token in &tokens[tokens.len() - new..] {
            submitted(dev, count, *token);
            count += 1;
        }
        step(&mut dev.volume, &dev.control, &mut out);
        out.clear();
        let progress = fill.progress(&dev.volume);
        if taken == payload.len() && progress.submitted_units == progress.len_units {
            settle(&mut dev.volume, &dev.control);
            return;
        }
    }
    panic!("the stream never completed");
}

/// Two- and three-extent PUTs publish once and read back exactly, by the
/// publisher's lease and by a lookup. After each publish the slot holds the
/// whole payload, and the raw-byte ledger counts zero reserved bytes and every
/// published payload as resident.
#[test]
fn a_multi_extent_put_publishes_once_and_reads_back_exactly() {
    let storage = storage();
    let buffers = arena_with(4, 4);
    let mut dev = Device::new(&storage, &buffers);
    let mut resident = 0;
    for (n, extents) in [(1, 2), (2, 3)] {
        let payload = payload(extents, n as u64);
        let version = 0x5EED_0000 + u64::from(n);
        let mut fill = reserve_at(&storage, &key(n), CacheVersion(version), &payload);
        stream(&mut dev, &mut fill, &payload, |_, _, _| {});
        assert!(fill.is_ready(&dev.volume), "{extents} extents");
        let lease = fill
            .publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
            .unwrap();
        resident += payload.len();
        let live = storage.live_pool().unwrap();
        assert_eq!(
            live.versions()[lease.id().slot_index()].load(std::sync::atomic::Ordering::Relaxed),
            version,
            "{extents} extents: the index names the fill's cache version"
        );
        let mut access = live.lock().unwrap();
        let mut tables = access.tables();
        let held = live.held_charge(&mut tables, lease.id().slot().0).0;
        let ledger = tables.extents().ledger();
        access.release();
        assert_eq!(held, payload.len(), "{extents} extents: held payload");
        assert_eq!(
            (ledger.reserved, ledger.resident),
            (0, resident),
            "{extents} extents: resident payload"
        );
        let delivered = read_back(&mut dev.volume, &dev.control, &lease);
        assert_eq!(delivered.status, ReadStatus::Complete);
        assert!(delivered.bytes == payload, "{extents} extents: exact bytes");
        let mut reader = storage.register().unwrap();
        let hit = lookup(&mut reader, &key(n), RETRIES).unwrap();
        assert!(
            dev.read(&hit) == payload,
            "{extents} extents: exact bytes by lookup"
        );
        drop((hit, lease, reader));
    }
}

/// When a verified input crosses an extent's end, each extent's record holds the chunk checksums of its own bytes, so the object reads back exactly.
#[test]
fn a_verified_input_across_an_extent_end_reads_back_exactly() {
    let storage = storage();
    let buffers = arena_with(4, 4);
    let mut dev = Device::new(&storage, &buffers);
    let crc = super::record::Crc32c::detect();
    let end = EXTENT_PAYLOAD as usize;
    for (n, (before, after)) in [(4000, 2000), (2000, 4000)].into_iter().enumerate() {
        let payload = bytes(end + 6000, 30 + n as u64);
        // The volume's count of submitted writes once the first extent's record is submitted whole.
        let first_extent =
            dev.volume.report().writes_submitted + extent_writes(&storage, payload.len())[0] as u64;
        let mut fill = reserve(&storage, &key(n as u8 + 1), &payload);
        receive_plain(&mut dev, &mut fill, &payload[..end - before]);
        settle(&mut dev.volume, &dev.control);
        assert!(
            dev.volume.report().writes_submitted < first_extent,
            "the first extent's record waits for its last bytes"
        );
        let input = &payload[end - before..end + after];
        assert_eq!(
            fill.receive_verified(&mut dev.volume, input, crc.checksum(input), &mut ample_io()),
            Ok(input.len())
        );
        assert_eq!(
            dev.volume.report().writes_submitted,
            first_extent,
            "the call submitted the rest of the first extent's commands"
        );
        stream(&mut dev, &mut fill, &payload[end + after..], |_, _, _| {});
        let lease = fill
            .publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
            .unwrap();
        let delivered = read_back(&mut dev.volume, &dev.control, &lease);
        assert_eq!(delivered.status, ReadStatus::Complete);
        assert!(
            delivered.bytes == payload,
            "{before} bytes before the extent end, {after} after"
        );
        drop(lease);
    }
}

/// A fill's `len_units` is the sum of every extent record's
/// `record_units`, before the first `receive` and in the write set that
/// `receive` begins; for an object of one extent the sum equals
/// `layout().units()`. `is_ready` compares `completed_units` with this
/// count, so publication waits for every extent from the reservation on.
#[test]
fn a_fill_counts_every_unit_of_its_object_from_its_reservation() {
    let buffers = arena_with(4, 4);
    for extents in 1..=3 {
        let storage = storage();
        let mut dev = Device::new(&storage, &buffers);
        let payload = payload(extents, extents as u64);
        let (m, b) = (METADATA as u32, (payload.len() - METADATA) as u32);
        let units: u64 = (0..extents as u64)
            .map(|index| {
                let start = index * EXTENT_PAYLOAD;
                let coverage = (payload.len() as u64 - start).min(EXTENT_PAYLOAD);
                storage.record.extent_layout(m, b, coverage).record_units()
            })
            .sum();
        let mut fill = reserve(&storage, &key(extents as u8), &payload);
        if extents == 1 {
            assert_eq!(fill.layout().units() as u64, units);
        }
        let before = fill.progress(&dev.volume);
        assert_eq!(u64::from(before.len_units), units, "{extents} extents");
        assert_eq!(before.submitted_units, 0);
        // 1,000 bytes complete no extent and fill no later segment, so the
        // call submits nothing and only begins the write set.
        let piece = &payload[..1000];
        assert_eq!(
            fill.receive(&mut dev.volume, piece, &mut ample_io()),
            Ok(piece.len())
        );
        let staged = fill.progress(&dev.volume);
        assert_eq!(
            u64::from(staged.len_units),
            units,
            "{extents} extents: write set"
        );
        assert_eq!(staged.submitted_units, 0);
        fill.abort();
    }
}

/// Write commands each extent's record takes, for a payload of `len` bytes.
fn extent_writes(storage: &Storage<TestPlatform>, len: usize) -> Vec<usize> {
    let (m, b) = (METADATA as u32, (len - METADATA) as u32);
    (0..len.div_ceil(EXTENT_PAYLOAD as usize))
        .map(|index| {
            let start = index as u64 * EXTENT_PAYLOAD;
            let coverage = (len as u64 - start).min(EXTENT_PAYLOAD);
            let units = storage.record.extent_layout(m, b, coverage).record_units();
            (units as usize * IO_UNIT).div_ceil(BUFFER as usize)
        })
        .collect()
}

/// A replacement of three extents whose write at the first, middle or final
/// extent fails publishes nothing: publication refuses `Incomplete`, the
/// incumbent's bytes still read back, and once the fill ends and service
/// runs, every unit of the replacement is free again.
#[test]
fn a_failed_write_at_any_extent_publishes_nothing_and_keeps_the_incumbent() {
    for failed in 0..3 {
        let storage = storage();
        let buffers = arena_with(4, 4);
        let mut dev = Device::new(&storage, &buffers);
        let incumbent = payload(2, 9);
        let mut fill = reserve(&storage, &key(1), &incumbent);
        stream(&mut dev, &mut fill, &incumbent, |_, _, _| {});
        let lease = fill
            .publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
            .unwrap();
        let free = storage.domain_report().map(|d| d.free_units);
        let replacement = payload(3, 10);
        let counts = extent_writes(&storage, replacement.len());
        let target: usize = counts[..failed].iter().sum::<usize>() + counts[failed] / 2;
        let mut fill = reserve(&storage, &key(1), &replacement);
        stream(&mut dev, &mut fill, &replacement, |dev, count, token| {
            if count == target {
                dev.control
                    .fault(token, Fault::Status(DeviceStatus::Kernel(-5)));
            }
        });
        assert!(!fill.is_ready(&dev.volume), "extent {failed}");
        assert!(
            fill.progress(&dev.volume).failed,
            "extent {failed}: the set failed"
        );
        assert_eq!(
            fill.publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
                .err(),
            Some(FillPublishError::Incomplete),
            "extent {failed}"
        );
        assert!(
            dev.read(&lease) == incumbent,
            "extent {failed}: the incumbent's bytes"
        );
        let mut reader = storage.register().unwrap();
        let hit = lookup(&mut reader, &key(1), RETRIES).unwrap();
        assert_eq!(
            hit.id(),
            lease.id(),
            "extent {failed}: the incumbent is current"
        );
        drop((hit, reader));
        settle(&mut dev.volume, &dev.control);
        for _ in 0..8 {
            service(&storage);
            let _ = storage.service(&mut budget());
        }
        assert_eq!(
            storage.domain_report().map(|d| d.free_units),
            free,
            "extent {failed}"
        );
        drop(lease);
    }
}

/// Duplicate completions of the first write stand in for a final write
/// whose completion never comes: the volume counts them stale, the fill
/// stays unready, and publication refuses `Incomplete`.
#[test]
fn duplicate_first_completions_never_stand_in_for_a_missing_final_write() {
    let storage = storage();
    let buffers = arena_with(4, 4);
    let mut dev = Device::new(&storage, &buffers);
    let payload = payload(2, 3);
    let total: usize = extent_writes(&storage, payload.len()).iter().sum();
    let mut first = None;
    let mut fill = reserve(&storage, &key(1), &payload);
    let mut out = Vec::with_capacity(16);
    let mut taken = 0;
    for _ in 0..4096 {
        if taken == payload.len() {
            break;
        }
        let piece = &payload[taken..(taken + BUFFER as usize).min(payload.len())];
        let before = dev.volume.report().writes_submitted;
        if let Ok(n) = fill.receive(&mut dev.volume, piece, &mut ample_io()) {
            taken += n;
        }
        let new = (dev.volume.report().writes_submitted - before) as usize;
        let tokens = writes(&dev);
        for (at, token) in tokens[tokens.len() - new..].iter().enumerate() {
            let count = dev.volume.report().writes_submitted as usize - new + at;
            if count == 0 {
                first = Some(*token);
            }
            if count == total - 1 {
                dev.control.fault(*token, Fault::DropCompletion);
            }
        }
        step(&mut dev.volume, &dev.control, &mut out);
        out.clear();
    }
    let _ = fill.receive(&mut dev.volume, &[], &mut ample_io());
    for _ in 0..4 {
        step(&mut dev.volume, &dev.control, &mut out);
        out.clear();
    }
    let stale = dev.volume.report().stale;
    for _ in 0..3 {
        dev.control.inject(
            Completion {
                token: first.unwrap(),
                status: DeviceStatus::Kernel(BUFFER as i32),
            },
            Injection::Duplicate,
        );
        step(&mut dev.volume, &dev.control, &mut out);
        out.clear();
    }
    assert!(
        dev.volume.report().stale >= stale + 3,
        "{:?}",
        dev.volume.report()
    );
    let progress = fill.progress(&dev.volume);
    assert!(
        progress.completed_units < progress.len_units,
        "{progress:?}"
    );
    assert_eq!(
        fill.publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
            .err(),
        Some(FillPublishError::Incomplete)
    );
}

/// Offers `fill` the buffer of `payload` from byte `at`.
fn next_piece<'s, 'a>(
    dev: &mut Device<'s, 'a>,
    fill: &mut WritableFill<'s, 'a, TestPlatform>,
    payload: &[u8],
    at: usize,
) -> Result<usize, ReceiveError> {
    let piece = &payload[at..(at + BUFFER as usize).min(payload.len())];
    fill.receive(&mut dev.volume, piece, &mut ample_io())
}

/// Two fills whose writes the device holds fill the write share,
/// `depth - read_commands - metadata_commands`, and the metadata slot no
/// command claims, and then refuse `TableFull`; a read still submits into
/// the read share. Aborting a fill with its writes held returns none of
/// those slots: the other fill stays refused until the held writes reach
/// their terminals.
#[test]
fn fills_share_the_write_share_and_a_read_keeps_its_own() {
    let storage = storage();
    // Buffers to spare beyond the share, so only the share refuses.
    let buffers = arena_with(4, 12);
    let mut dev = Device::new(&storage, &buffers);
    let small = payload(1, 1);
    let mut fill = reserve(&storage, &key(9), &small);
    stream(&mut dev, &mut fill, &small, |_, _, _| {});
    let lease = fill
        .publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
        .unwrap();
    // The published fill's record frees for the next attempts.
    service(&storage);
    let payloads = [payload(2, 2), payload(2, 3)];
    let mut fills = [
        reserve(&storage, &key(1), &payloads[0]),
        reserve(&storage, &key(2), &payloads[1]),
    ];
    let mut taken = [0usize; 2];
    let mut held = Vec::new();
    for _ in 0..64 {
        for (at, fill) in fills.iter_mut().enumerate() {
            let payload = &payloads[at];
            let piece = &payload[taken[at]..(taken[at] + BUFFER as usize).min(payload.len())];
            let before = dev.volume.report().writes_submitted;
            if let Ok(n) = fill.receive(&mut dev.volume, piece, &mut ample_io()) {
                taken[at] += n;
            }
            let new = (dev.volume.report().writes_submitted - before) as usize;
            let tokens = writes(&dev);
            for token in &tokens[tokens.len() - new..] {
                dev.control.hold(*token);
                held.push(*token);
            }
        }
    }
    // The depth less the read share of 2; no metadata command claims the metadata share of 1.
    let share = usize::from(DEPTH) - 2;
    assert_eq!(
        held.len(),
        share,
        "the writes hold the write share and the metadata slot"
    );
    let table = dev.volume.table_report();
    assert_eq!(table.pending as usize, share);
    assert_eq!(
        next_piece(&mut dev, &mut fills[1], &payloads[1], taken[1]),
        Err(ReceiveError::TableFull),
        "the writes' room is full"
    );
    let reads = dev.volume.report().reads_submitted;
    let op = dev.volume.read(lease.duplicate(), u64::MAX).unwrap();
    assert_eq!(
        dev.volume.report().reads_submitted,
        reads + 1,
        "the read submits"
    );
    let [first, mut second] = fills;
    first.abort();
    assert_eq!(
        next_piece(&mut dev, &mut second, &payloads[1], taken[1]),
        Err(ReceiveError::TableFull),
        "an aborted fill's held writes keep their slots"
    );
    for token in held {
        dev.control.release(token);
    }
    settle(&mut dev.volume, &dev.control);
    stream(
        &mut dev,
        &mut second,
        &payloads[1][taken[1]..],
        |_, _, _| {},
    );
    assert!(second.is_ready(&dev.volume));
    let _ = op;
    drop((second, lease));
}

/// A volume without a sequence arena admits an object of several extents
/// and refuses its fill reservation `MultipleExtents`, claiming nothing.
#[test]
fn a_volume_without_an_arena_refuses_a_multi_extent_fill() {
    let storage = storage_with(0);
    let payload = payload(2, 1);
    let body = payload.len() - METADATA;
    let refused = begin(&storage, &key(1))
        .unwrap()
        .reserve_storage(
            admit(&storage, METADATA, body),
            Some(METADATA),
            Some(body),
            TRIES,
            &mut budget(),
        )
        .err();
    assert_eq!(
        refused,
        Some(super::FillReserveError::Layout(
            super::layout::LayoutError::MultipleExtents { extents: 2 }
        ))
    );
    assert_eq!(
        storage.pool_report().unwrap().ledger.unwrap().slots.filling,
        0
    );
}

/// A fill's progress counts its outstanding write commands: at an extent
/// boundary, with the first extent's short final segment and the second
/// extent's one-unit record both in flight, the count equals the volume's
/// in-flight writes, which the outstanding units rounded up to whole
/// segments understate by one.
#[test]
fn outstanding_commands_count_each_partial_segment_across_an_extent_boundary() {
    let storage = storage();
    let buffers = arena_with(4, 4);
    let mut dev = Device::new(&storage, &buffers);
    let payload = payload(2, 5);
    let counts = extent_writes(&storage, payload.len());
    assert_eq!(counts[1], 1, "the last extent is one short command");
    // The first extent's segments submit in order, the short final one
    // second to last and the header's last; the second extent's one command
    // follows.
    let held_at = [counts[0] - 2, counts[0]];
    let mut fill = reserve(&storage, &key(1), &payload);
    let mut held = Vec::new();
    let mut out = Vec::with_capacity(16);
    let mut taken = 0;
    for _ in 0..4096 {
        let piece = &payload[taken..(taken + BUFFER as usize).min(payload.len())];
        let before = dev.volume.report().writes_submitted as usize;
        if let Ok(n) = fill.receive(&mut dev.volume, piece, &mut ample_io()) {
            taken += n;
        }
        let tokens = writes(&dev);
        let new = dev.volume.report().writes_submitted as usize - before;
        for (at, token) in tokens[tokens.len() - new..].iter().enumerate() {
            if held_at.contains(&(before + at)) {
                dev.control.hold(*token);
                held.push(*token);
            }
        }
        step(&mut dev.volume, &dev.control, &mut out);
        out.clear();
        let progress = fill.progress(&dev.volume);
        if taken == payload.len() && progress.submitted_units == progress.len_units {
            break;
        }
    }
    for _ in 0..4 {
        step(&mut dev.volume, &dev.control, &mut out);
        out.clear();
    }
    assert_eq!(held.len(), 2, "both short segments are held");
    let report = dev.volume.report();
    let inflight = report.writes_submitted - report.writes_done - report.writes_failed;
    assert_eq!(inflight, 2, "{report:?}");
    let progress = fill.progress(&dev.volume);
    let segment_units = BUFFER / IO_UNIT as u32;
    assert_eq!(
        progress.outstanding_units.div_ceil(segment_units),
        1,
        "the two short segments fit one segment's units: {progress:?}"
    );
    assert_eq!(
        u64::from(progress.outstanding_commands),
        inflight,
        "{progress:?}"
    );
    for token in held {
        dev.control.release(token);
    }
    settle(&mut dev.volume, &dev.control);
    assert!(fill.is_ready(&dev.volume));
    fill.abort();
}

/// A storage of `units` units and eight slots with one sequence arena root,
/// whose caps admit an object of `extents` extents.
fn storage_admitting(units: usize, extents: usize) -> Storage<TestPlatform> {
    let fills = [2usize];
    let index = IndexConfig {
        fills: &fills,
        ..index_config(&[8], (1, 1), 1)
    };
    let mut volume = crate::storage::test_volume(units * IO_UNIT, 8);
    volume.block_roots = 1;
    let config = StorageConfig {
        body_cap: extents * EXTENT_PAYLOAD as usize,
        metadata_cap: Some(METADATA),
        object_rights: 8,
        volume,
        ..storage_config(8)
    };
    let storage = storage_from(&config, &index, TestPlatform::heap(PAGE));
    storage.platform.ticks(&[Some(1)]);
    storage
}

/// A placement spans calls, each funded with one extent's `place_steps`
/// and two steps over: every call places exactly one extent, the escrow
/// falls to zero with the last, and the complete placement reserves a fill
/// that streams and publishes every extent. The one-call `reserve_storage`
/// under the first promise's cost plus that budget promises again for fewer
/// steps, so its first placement hold funds more than one extent; it places
/// at least two and fewer than all, then refuses `BudgetExhausted`, and
/// service returns what it placed. The refusal parks its slot as `Filling`
/// with `ABANDONED`; the tables pass the conservation judge before and after
/// one service pass, which returns part of the placement and leaves the
/// slot parked.
#[test]
fn a_placement_spans_calls_each_within_one_extents_work() {
    let extents = 5usize;
    let storage = storage_admitting(64 * 16 - 16, extents);
    let buffers = arena_with(4, 4);
    let mut dev = Device::new(&storage, &buffers);
    let payload = payload(extents, 7);
    let body = payload.len() - METADATA;
    let admitted = admit(&storage, METADATA, body);
    assert_eq!(admitted.extents() as usize, extents);
    let before = storage.pool_report().unwrap().ledger.unwrap().raw;
    let mut promise = budget();
    let mut placing = begin(&storage, &key(1))
        .unwrap()
        .promise_storage(admitted, Some(METADATA), Some(body), &mut promise)
        .unwrap();
    let promise_cost = budget().remaining() - promise.remaining();
    let steps = placing.place_steps();
    // One pass: the preflight passes, the pass debits at least one step, and
    // the budget left is below another pass's.
    let per_call = steps + 2;
    assert_eq!(
        storage.pool_report().unwrap().escrow_units,
        charge(&storage, METADATA, body)
    );
    for call in 1..=extents {
        let mut funds = WorkBudget::new(per_call);
        let complete = placing.place(&mut funds).unwrap();
        assert_eq!(placing.placed() as usize, call, "call {call}");
        assert_eq!(complete, call == extents, "call {call}");
    }
    assert_eq!(storage.pool_report().unwrap().escrow_units, 0);
    let mut fill = placing.reserve_storage(TRIES, &mut budget()).unwrap();
    stream(&mut dev, &mut fill, &payload, |_, _, _| {});
    let lease = fill
        .publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
        .unwrap();
    let live = storage.live_pool().unwrap();
    let mut access = live.lock().unwrap();
    let held = live
        .held_charge(&mut access.tables(), lease.id().slot().0)
        .0;
    access.release();
    assert_eq!(held, payload.len(), "the slot holds every extent's payload");
    drop(lease);

    // The same per-call budget in one call funds the promise and a first
    // hold of more than one extent, then refuses, with every placed extent
    // returned by service.
    let slot = storage.live_pool().unwrap().claim_order(None, 1)[0];
    let refused = begin(&storage, &key(2))
        .unwrap()
        .reserve_storage(
            admit(&storage, METADATA, body),
            Some(METADATA),
            Some(body),
            TRIES,
            &mut WorkBudget::new(promise_cost + per_call),
        )
        .err();
    assert_eq!(refused, Some(super::FillReserveError::BudgetExhausted));
    assert_eq!(storage.pool_report().unwrap().escrow_units, 0);
    conserved_at(&storage, slot, PARKED);
    let held = placed(&storage, slot);
    assert!(
        (2..extents).contains(&held),
        "premise: the refusal placed part of the object, more than one extent: {held}"
    );
    let free = storage.pool_report().unwrap().ledger.unwrap().raw.free;
    conserved_after_service(&storage, slot, PARKED);
    assert!(
        storage.pool_report().unwrap().ledger.unwrap().raw.free > free,
        "the service pass returned an extent"
    );
    for _ in 0..4 {
        service(&storage);
        let _ = storage.service(&mut budget());
    }
    let after = storage.pool_report().unwrap().ledger.unwrap().raw;
    assert_eq!(
        after.free,
        before.free
            - payload.len()
            - (charge(&storage, METADATA, body) as usize * IO_UNIT - payload.len()),
        "only the published object holds units"
    );
}

/// The extents slot `slot`'s sequence block holds, read under the pool gate.
fn placed(storage: &Storage<TestPlatform>, slot: usize) -> usize {
    let live = storage.live_pool().unwrap();
    let mut access = live.lock().unwrap();
    let mut tables = access.tables();
    let (block, count, owner) = tables.sequence(slot).unwrap();
    tables.blocks().prefix(block, owner, count).unwrap().len()
}

/// Promises a three-extent object for `key(1)` and places it within three
/// calls, and returns the slot the promise claimed, `Filling` with the
/// tables passing the conservation judge, and the complete placement.
fn placed_whole(storage: &Storage<TestPlatform>) -> (usize, PlacingFill<'_, TestPlatform>) {
    let payload = payload(3, 9);
    let body = payload.len() - METADATA;
    let admitted = admit(storage, METADATA, body);
    assert_eq!(admitted.extents(), 3);
    let slot = storage.live_pool().unwrap().claim_order(None, 1)[0];
    let mut placing = begin(storage, &key(1))
        .unwrap()
        .promise_storage(admitted, Some(METADATA), Some(body), &mut budget())
        .unwrap();
    assert!(
        (0..3).any(|_| placing.place(&mut budget()).unwrap()),
        "premise: three calls complete the placement"
    );
    conserved_at(storage, slot, FILLING);
    (slot, placing)
}

/// A complete placement whose attempt was revoked before it takes the shard
/// hold refuses `Superseded` at its revalidation. With the pool gate free
/// the refusal returns the placed extents and the slot in one hold: the
/// tables pass the conservation judge and the slot is `Free` before any
/// service pass, and again after one.
#[test]
fn a_complete_placement_refused_at_its_revalidation_returns_every_extent_and_its_slot() {
    let storage = storage();
    let (slot, placing) = placed_whole(&storage);
    let revoked = super::attempt_tests::invalidate(&storage, &key(1)).unwrap();
    assert!(revoked.revoked.is_some(), "premise: the attempt is revoked");
    assert_eq!(
        placing.reserve_storage(TRIES, &mut budget()).err(),
        Some(super::FillReserveError::Superseded)
    );
    conserved_at(&storage, slot, FREE);
    conserved_after_service(&storage, slot, FREE);
}

/// A complete placement's revalidation spends a budget the caller passes
/// after the placement, with nothing preflighted for it. The revalidation
/// costs six steps, one each for the route's hash, the shard gate try, the
/// record visit, the key comparison, the credit attempt and the chain walk,
/// so each budget of zero to five steps refuses `BudgetExhausted` at a
/// different step. Each refusal returns the placed extents and the slot:
/// the tables pass the conservation judge and the slot is `Free`.
#[test]
fn a_complete_placement_refused_for_budget_at_each_revalidation_step_returns_its_slot() {
    let storage = storage();
    // The hashes, coordination attempts, visits and comparisons each budget
    // pays before its next step refuses: the route's hash, the shard gate
    // try, the record visit, the key comparison, the credit attempt, and
    // the chain walk's visit.
    let paid = [
        (0, 0, 0, 0),
        (1, 0, 0, 0),
        (1, 1, 0, 0),
        (1, 1, 1, 0),
        (1, 1, 1, 1),
        (1, 2, 1, 1),
    ];
    for (steps, paid) in paid.into_iter().enumerate() {
        let (slot, placing) = placed_whole(&storage);
        let mut short = WorkBudget::new(steps);
        assert_eq!(
            placing.reserve_storage(TRIES, &mut short).err(),
            Some(super::FillReserveError::BudgetExhausted),
            "budget of {steps}"
        );
        let spent = short.counters();
        assert_eq!(
            (
                (
                    spent.hashes,
                    spent.coordination_attempts,
                    spent.visits,
                    spent.comparisons
                ),
                short.remaining()
            ),
            (paid, 0),
            "premise: the budget of {steps} refused at its own step"
        );
        conserved_at(&storage, slot, FREE);
        assert_eq!(service(&storage).released, 1, "budget of {steps}");
    }
    let (_, placing) = placed_whole(&storage);
    let mut funds = WorkBudget::new(6);
    let fill = placing.reserve_storage(TRIES, &mut funds).unwrap();
    let spent = funds.counters();
    assert_eq!(
        (
            spent.hashes,
            spent.coordination_attempts,
            spent.visits,
            spent.comparisons,
            funds.remaining()
        ),
        (1, 2, 2, 1, 0),
        "premise: the revalidation's six steps"
    );
    fill.abort();
}

/// Aborting a placement with extents placed refunds the unplaced charge at
/// once and returns the placed extents, the block and the slot through
/// service, and the attempt's record departs.
#[test]
fn an_aborted_placement_returns_its_extents_and_departs() {
    let extents = 6usize;
    let storage = storage_admitting(64 * 8, extents);
    let payload = payload(extents, 8);
    let body = payload.len() - METADATA;
    let admitted = admit(&storage, METADATA, body);
    let before = storage.pool_report().unwrap().ledger.unwrap();
    let mut placing = begin(&storage, &key(3))
        .unwrap()
        .promise_storage(admitted, Some(METADATA), Some(body), &mut budget())
        .unwrap();
    let steps = placing.place_steps();
    assert!(
        !placing
            .place(&mut WorkBudget::new(steps + steps / 2))
            .unwrap()
    );
    let placed = placing.placed();
    assert!(placed > 0 && (placed as usize) < extents, "{placed} placed");
    let report = storage.pool_report().unwrap();
    assert_eq!(report.ledger.unwrap().slots.filling, 1);
    assert!(report.escrow_units > 0 && report.escrow_units < charge(&storage, METADATA, body));
    placing.abort();
    assert_eq!(storage.pool_report().unwrap().escrow_units, 0);
    for _ in 0..4 {
        service(&storage);
        let _ = storage.service(&mut budget());
    }
    let after = storage.pool_report().unwrap().ledger.unwrap();
    assert_eq!((after.raw, after.slots), (before.raw, before.slots));
    assert!(
        begin(&storage, &key(3)).is_ok(),
        "the key's record departed, so a new attempt begins"
    );
}

#[test]
fn ending_a_placement_returns_an_unplaced_one_at_once_and_a_placed_one_through_service() {
    let extents = 6usize;
    let storage = storage_admitting(64 * 8, extents);
    let payload = payload(extents, 8);
    let body = payload.len() - METADATA;
    let admitted = admit(&storage, METADATA, body);
    let before = storage.pool_report().unwrap().ledger.unwrap();
    let arena = || {
        let live = storage.live_pool().unwrap();
        let mut access = live.lock().unwrap();
        let free = access.tables().blocks().free_bytes();
        access.release();
        free
    };
    let blocks = arena();
    let promise = |name: u8| {
        begin(&storage, &key(name))
            .unwrap()
            .promise_storage(admitted, Some(METADATA), Some(body), &mut budget())
            .unwrap()
    };
    let unplaced = promise(3);
    let promised = storage.pool_report().unwrap();
    assert_eq!(
        (
            promised.ledger.unwrap().slots.filling,
            promised.escrow_units
        ),
        (1, charge(&storage, METADATA, body))
    );
    assert!(arena() < blocks, "the promise holds a sequence block");
    unplaced.end();
    let ended = storage.pool_report().unwrap();
    let ledger = ended.ledger.unwrap();
    assert_eq!(
        (ledger.raw, ledger.slots, ended.escrow_units, arena()),
        (before.raw, before.slots, 0, blocks),
        "the unplaced placement returned its block and slot in its own hold"
    );
    service(&storage);
    let _ = storage.service(&mut budget());
    let serviced = storage.pool_report().unwrap().ledger.unwrap();
    assert_eq!(
        (serviced.raw, serviced.slots),
        (before.raw, before.slots),
        "service found nothing of it to return"
    );
    assert!(
        begin(&storage, &key(3)).is_ok(),
        "the key's record departed, so a new attempt begins"
    );
    let mut placed = promise(4);
    let steps = placed.place_steps();
    assert!(
        !placed
            .place(&mut WorkBudget::new(steps + steps / 2))
            .unwrap()
    );
    assert!(placed.placed() > 0);
    placed.end();
    let ended = storage.pool_report().unwrap();
    let ledger = ended.ledger.unwrap();
    assert_eq!(ended.escrow_units, 0);
    assert_eq!(
        ledger.slots.filling, 1,
        "the placed extents wait for service"
    );
    assert!(ledger.raw.free < before.raw.free);
    for _ in 0..4 {
        service(&storage);
        let _ = storage.service(&mut budget());
    }
    let serviced = storage.pool_report().unwrap().ledger.unwrap();
    assert_eq!((serviced.raw, serviced.slots), (before.raw, before.slots));
}

/// A reserved bit on an unplaced placement's slot makes `end`'s cancel panic under the pool gate. The record stays
/// occupied and undeparted, so service releases nothing, the key's next attempt is refused, and finalization returns
/// `Poisoned`: the record does not free while its slot's fate is unknown.
#[test]
fn a_panicking_end_of_an_unplaced_placement_keeps_its_record_occupied() {
    use super::attempt_tests::live;
    let extents = 6usize;
    let mut storage = storage_admitting(64 * 8, extents);
    let payload = payload(extents, 8);
    let body = payload.len() - METADATA;
    let admitted = admit(&storage, METADATA, body);
    let placing = begin(&storage, &key(3))
        .unwrap()
        .promise_storage(admitted, Some(METADATA), Some(body), &mut budget())
        .unwrap();
    assert_eq!(placing.placed(), 0);
    let live_pool = storage.live_pool().unwrap();
    let slot = (0..live_pool.records().len())
        .find(|&slot| live_pool.gate_state(slot).0 == super::tables::SlotState::Filling)
        .expect("the promise holds one filling slot");
    live_pool.edit_word(slot, |word| word | super::word::RESERVED);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| placing.end()));
    assert!(outcome.is_err(), "the cancel panics under the pool gate");
    drop(outcome);
    assert!(live_pool.try_lock_quiet().is_err());
    let occupied = live(1);
    assert_eq!(records(&storage)[0], occupied);
    assert_eq!(service(&storage).released, 0);
    assert_eq!(records(&storage)[0], occupied);
    assert_eq!(
        begin(&storage, &key(3)).err(),
        Some(super::BeginError::InProgress)
    );
    assert_eq!(
        storage.finalize(&mut budget()),
        Err(super::FinalizeError::Poisoned)
    );
}

/// A reserved bit planted on every free slot makes the promise's slot take
/// panic under the pool gate: the attempt's record stays occupied, the gate
/// stays poisoned and the fill service releases nothing.
#[test]
fn a_panicking_promise_keeps_the_attempts_record_occupied() {
    let extents = 6usize;
    let storage = storage_admitting(64 * 8, extents);
    let payload = payload(extents, 8);
    let body = payload.len() - METADATA;
    let admitted = admit(&storage, METADATA, body);
    let attempt = begin(&storage, &key(3)).unwrap();
    let occupied = records(&storage);
    let live_pool = storage.live_pool().unwrap();
    for slot in 0..live_pool.records().len() {
        live_pool.edit_word(slot, |word| word | RESERVED_BIT);
    }
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        attempt.promise_storage(admitted, Some(METADATA), Some(body), &mut budget())
    }));
    assert!(outcome.is_err());
    drop(outcome);
    assert!(live_pool.try_lock_quiet().is_err());
    assert_eq!(records(&storage), occupied);
    assert_eq!(service(&storage).released, 0);
    assert_eq!(records(&storage), occupied);
}

/// `Pool::sequence_extent` promises that a lookup outside its contract
/// panics and "the panic poisons the gate". A destructor of a thread that is
/// already unwinding makes that lookup, for a one-extent fill's slot, inside
/// `catch_unwind`: afterwards the gate is poisoned.
#[test]
fn a_sequence_extent_lookup_outside_its_contract_during_unwinding_poisons_the_gate() {
    let storage = storage();
    let live = storage.live_pool().unwrap();
    let fill = reserve(&storage, &key(1), &payload(1, 7));
    struct LooksUpOnDrop<'a>(&'a Storage<TestPlatform>, super::allocation::AllocationId);
    impl Drop for LooksUpOnDrop<'_> {
        fn drop(&mut self) {
            let live = self.0.live_pool().unwrap();
            let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = live.sequence_extent(self.1, 0);
            }));
            assert!(caught.is_err(), "premise: the lookup panicked");
        }
    }
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _lookup = LooksUpOnDrop(&storage, fill.id());
        panic!("an unrelated panic with a live lookup");
    }));
    assert!(outcome.is_err());
    assert!(
        matches!(live.try_lock_quiet(), Err(super::gate::GateError::Poisoned)),
        "the panic left the gate unpoisoned"
    );
    assert!(live.lock().is_none(), "a waiting hold passed the poison");
    drop(fill);
}

/// A placement whose run reservation panics under the pool gate (a ledger
/// whose free term holds no byte refuses the promised extent through
/// `Ledger`) unwinds through the placement, a local here as in the PREPARE:
/// the attempt's record stays occupied and undeparted, the gate stays
/// poisoned and the fill service releases nothing.
#[test]
fn a_panicking_placement_keeps_the_attempts_record_occupied() {
    let extents = 6usize;
    let storage = storage_admitting(64 * 8, extents);
    let payload = payload(extents, 8);
    let body = payload.len() - METADATA;
    let admitted = admit(&storage, METADATA, body);
    let mut placing = begin(&storage, &key(3))
        .unwrap()
        .promise_storage(admitted, Some(METADATA), Some(body), &mut budget())
        .unwrap();
    let occupied = records(&storage);
    let live_pool = storage.live_pool().unwrap();
    let mut access = live_pool.lock().unwrap();
    access.tables().extents().plant_ledger_free(0);
    access.release();
    let steps = placing.place_steps();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        placing.place(&mut WorkBudget::new(steps + steps / 2))
    }));
    assert!(outcome.is_err(), "premise: the placement panics");
    drop(outcome);
    assert!(live_pool.try_lock_quiet().is_err());
    assert_eq!(records(&storage), occupied);
    assert_eq!(service(&storage).released, 0);
    assert_eq!(records(&storage), occupied);
}
