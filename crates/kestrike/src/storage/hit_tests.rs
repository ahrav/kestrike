//! The device hit path through the storage API: a read takes over its lease's right and keeps the extent until its last terminal, every refused read owns nothing, and an integrity failure on a resident hit is a typed outcome that changes no index or slot state.

use std::panic::{AssertUnwindSafe, catch_unwind};

use super::allocation::AllocationId;
use super::attempt_tests::{invalidate, service};
use super::budget::WorkBudget;
use super::claim_exit_tests::{FREE, RETIRED, conserved_after_service, conserved_at};
use super::device::sim::{Event, Fault, QuiesceMode, SimControl, Unwind};
use super::device::{
    CommandToken, IO_UNIT, Operation, PoolKind, QuiesceProgress, RefusalReason, SubmitRefusal,
};
use super::finalize::Finalization;
use super::lease::ExtentLease;
use super::ledger::EngineBudget;
use super::lookup::LookupError;
use super::lookup_tests::lookup;
use super::owner::Storage;
use super::publish_tests::{
    RETRIES, TRIES, budget, candidates, install_seam, key, one_chain, one_fingerprint, report,
};
use super::record::HeaderMismatch;
use super::recovery::MetadataOutcome;
use super::register::Registration;
use super::reserve::ReserveError;
use super::seeded::SplitMix64;
use super::tables::{SlotIndex, SlotState};
use super::test_platform::{TestPlatform, finalize};
use super::volume_fixture::{
    BUFFER, DEPTH, Device, SESSION, TICK, ample_io, arena, arena_with, bootstrap, device_with,
    drive, extent, place, record_bytes, settle, step,
};
use super::writable_tests::{bytes, reserve, wide};
use super::{
    AttachError, FillPublishError, KeyReadError, ReadEvent, ReadOp, ReadRefusal, ReadStatus,
    ReceiveError, Volume,
};
use crate::index::Key;
use crate::sim::round::{Act, Actor, round};

fn refs(storage: &Storage<TestPlatform>, slot: usize) -> usize {
    storage.live_pool().unwrap().refs(slot)
}

/// Publishes `payload` under `key` with its first `metadata` bytes as metadata, and returns the publisher's lease.
pub(super) fn published<'s>(
    storage: &'s Storage<TestPlatform>,
    dev: &mut Device<'s, '_>,
    key: &Key,
    metadata: usize,
    payload: &[u8],
) -> ExtentLease<'s, TestPlatform> {
    let mut fill = reserve(storage, key, metadata, payload.len() - metadata).unwrap();
    dev.fill(&mut fill, payload);
    fill.publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
        .unwrap()
}

/// The token of the last read command the device accepted.
pub(super) fn last_read(control: &SimControl) -> CommandToken {
    control
        .events()
        .iter()
        .rev()
        .find_map(|event| match event {
            Event::Submitted(token, Operation::Read) => Some(*token),
            _ => None,
        })
        .unwrap()
}

/// Grace certification and service, enough to release a retired anchor and return its extent.
fn drain(storage: &Storage<TestPlatform>) {
    for _ in 0..4 {
        let _ = storage.certify(&mut WorkBudget::new(1 << 12)).unwrap();
        storage.service(&mut WorkBudget::new(1 << 12)).unwrap();
    }
}

/// How a key read enters the volume: the scalar `read_key`, or the prepared
/// entry with a context `Preparation` derived for its key at ordinal 0.
#[derive(Debug, Clone, Copy)]
enum Entry {
    Scalar,
    Prepared,
}

const ENTRIES: [Entry; 2] = [Entry::Scalar, Entry::Prepared];

/// A key read of `k` through `reader` on `dev`'s volume by `entry`, with
/// `retries`, `budget` and no deadline. A prepared read's context comes from
/// a preparation over the volume's storage that derived `prepared`'s route
/// at ordinal 0.
fn read_by<'s>(
    entry: Entry,
    dev: &mut Device<'s, '_>,
    reader: &mut Registration<'s, TestPlatform>,
    (prepared, k): (&Key, &Key),
    retries: usize,
    budget: &mut WorkBudget,
) -> Result<ReadOp, KeyReadError> {
    match entry {
        Entry::Scalar => dev.volume.read_key(reader, k, retries, budget, u64::MAX),
        Entry::Prepared => {
            let mut preparation = super::prepare::Preparation::new(dev.volume.storage());
            preparation.prime(std::slice::from_ref(prepared), 0);
            let context = preparation.take(0, k);
            assert_eq!(
                context.route().is_some(),
                prepared == k,
                "the route rides along"
            );
            dev.volume
                .read_key_prepared(reader, &context, retries, budget, u64::MAX)
        }
    }
}

/// `s4n-read-requires-lease-right`, `s4n-right-released-last-terminal`: a
/// read takes over its lease's right before its first submit and returns the
/// lease's credit; with its command held and the object invalidated, that
/// right alone keeps the retired slot held through grace and service, so the
/// extent is never reused under the read; the right is released once, at
/// the read's last terminal, and service then returns the slot.
#[test]
fn a_read_holds_its_lease_s_right_until_its_last_terminal() {
    let storage = wide(2, 8);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let payload = bytes(3 * 8192, 1);
    let k = key(1);
    let lease = published(&storage, &mut dev, &k, 5, &payload);
    let slot = lease.id().slot_index();
    let locator = storage.live_pool().unwrap().records()[slot].locator();
    assert_eq!(refs(&storage, slot), 2, "anchor and the publisher's right");
    assert_eq!(storage.lease_report().unwrap().reserved, 1);
    let op = dev.volume.read(lease, u64::MAX).unwrap();
    assert_eq!(refs(&storage, slot), 2, "the read holds the lease's right");
    assert_eq!(
        storage.lease_report().unwrap().reserved,
        0,
        "the lease's credit returned"
    );
    let token = last_read(&dev.control);
    dev.control.hold(token);
    let mut reader = storage.register().unwrap();
    assert!(
        lookup(&mut reader, &k, RETRIES).is_ok(),
        "a fresh lookup hits before the invalidation"
    );
    invalidate(&storage, &k).unwrap();
    assert_eq!(
        lookup(&mut reader, &k, RETRIES).err(),
        Some(LookupError::Missing),
        "a fresh lookup misses while the held read is outstanding"
    );
    drop(reader);
    drain(&storage);
    assert_eq!(
        refs(&storage, slot),
        1,
        "the anchor is released; the read's right remains"
    );
    assert_eq!(
        storage.slot_state(SlotIndex(slot)).unwrap().0,
        SlotState::Retired
    );
    // No reservation receives the extent while the read is in flight.
    let mut others = Vec::new();
    let exhausted = loop {
        match storage.reserve(Some(0), Some(IO_UNIT), &mut budget()) {
            Ok(other) => {
                let at = other.locator();
                let overlap = at.start_unit()
                    < locator.start_unit() + u64::from(locator.len_units())
                    && locator.start_unit() < at.start_unit() + u64::from(at.len_units());
                assert!(!overlap, "a reservation reused the extent under a read");
                others.push(other);
            }
            Err(error) => break error,
        }
    };
    assert!(!others.is_empty(), "the overlap check saw a reservation");
    assert_eq!(
        exhausted,
        ReserveError::ObjectSlotsFull,
        "reservations stop at the slots, the read's retired slot among them"
    );
    drop(others);
    assert!(
        dev.control.try_hold(token).is_ok(),
        "the held read command is still pending"
    );
    dev.control.release(token);
    let delivered = drive(&mut dev.volume, &dev.control, op);
    assert_eq!(delivered.status, ReadStatus::Complete);
    assert_eq!(delivered.bytes, payload);
    assert_eq!(refs(&storage, slot), 0, "released at the last terminal");
    drain(&storage);
    assert_eq!(
        storage.slot_state(SlotIndex(slot)).unwrap().0,
        SlotState::Free
    );
}

/// `s4n-refused-owns-nothing` (read part), R14: every refused read leaves the
/// response pool, the operation array, the table and the slot's count as
/// they were. A refusal before admission returns the lease with its right
/// and credit; a submit the device refuses releases the lease's right, which
/// the read had taken over.
#[test]
fn every_refused_read_owns_nothing() {
    let foreign = wide(2, 2);
    let foreign_buffers = arena();
    let mut foreign_dev = Device::new(&foreign, &foreign_buffers);
    let stranger = published(&foreign, &mut foreign_dev, &key(3), 0, &bytes(100, 3));
    let storage = wide(4, 2);
    let buffers = arena_with(1, 5);
    let mut dev = Device::new(&storage, &buffers);
    let first = published(&storage, &mut dev, &key(1), 0, &bytes(100, 1));
    let slot = first.id().slot_index();
    let unchanged = |dev: &Device<'_, '_>, refs_then: usize| {
        assert_eq!(buffers.report(PoolKind::ReadResponse).free, 1);
        assert_eq!(dev.volume.table_report().pending, 0);
        assert_eq!(refs(&storage, slot), refs_then);
    };
    // The device refuses the first command: the read took the lease's right and released it.
    dev.control.refuse_next(SubmitRefusal {
        reason: RefusalReason::InvalidRange,
        code: None,
    });
    let refused = dev.volume.read(first, u64::MAX).unwrap_err();
    assert!(matches!(refused.refusal, ReadRefusal::Submit(_)));
    assert!(refused.lease.is_none(), "the read ended the lease");
    unchanged(&dev, 1);
    assert_eq!(storage.lease_report().unwrap().reserved, 0);
    // One response buffer: a held chunk refuses the next read's buffer.
    let mut reader = storage.register().unwrap();
    let hit = lookup(&mut reader, &key(1), RETRIES).unwrap();
    let other = published(&storage, &mut dev, &key(2), 0, &bytes(100, 2));
    let op = dev.volume.read(hit, u64::MAX).unwrap();
    let mut out = Vec::with_capacity(4);
    let (mut chunk, mut done) = (None, None);
    for _ in 0..8 {
        step(&mut dev.volume, &dev.control, &mut out);
        for event in out.drain(..) {
            match event {
                super::ReadEvent::Chunk { chunk: held, .. } => chunk = Some(held),
                super::ReadEvent::Done { op: of, status, .. } => done = Some((of, status)),
            }
        }
    }
    assert_eq!(done, Some((op, ReadStatus::Complete)));
    assert!(chunk.is_some(), "the caller holds the only response buffer");
    let other_slot = other.id().slot_index();
    let refused = dev.volume.read(other, u64::MAX).unwrap_err();
    assert_eq!(refused.refusal, ReadRefusal::PoolExhausted);
    let other = refused
        .lease
        .expect("a refusal before admission returns the lease");
    assert_eq!(refs(&storage, other_slot), 2);
    drop(chunk);
    // A lease over another storage's object is refused before anything is touched.
    let refused = dev.volume.read(stranger, u64::MAX).unwrap_err();
    assert_eq!(refused.refusal, ReadRefusal::ForeignLease);
    assert!(refused.lease.is_some());
    assert_eq!(buffers.report(PoolKind::ReadResponse).free, 1);
    assert_eq!(refs(&storage, other_slot), 2);
    // After close every read refuses `Closed`.
    let _ = dev.volume.close();
    let refused = dev.volume.read(other, u64::MAX).unwrap_err();
    assert_eq!(refused.refusal, ReadRefusal::Closed);
    assert!(refused.lease.is_some());
    assert_eq!(refs(&storage, other_slot), 2);
}

/// A key read hands its lookup's right straight to the read: with seven
/// other leases on the object at `C = 8`, the read's lookup takes the last
/// right, the reserved credits stay as they were, the right alone keeps the
/// retired slot through grace and service, and it ends once, at the read's
/// last terminal. The scalar entry and the prepared entry each hold it.
#[test]
fn a_key_read_holds_its_lookup_s_right_and_takes_no_credit() {
    for entry in ENTRIES {
        key_read_holds_its_lookup_s_right(entry);
    }
}

fn key_read_holds_its_lookup_s_right(entry: Entry) {
    let storage = wide(2, 8);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let payload = bytes(3 * 8192, 4);
    let k = key(1);
    let publisher = published(&storage, &mut dev, &k, 5, &payload);
    let slot = publisher.id().slot_index();
    drop(publisher);
    let mut hoarder = storage.register().unwrap();
    let mut held = Vec::new();
    while let Ok(lease) = lookup(&mut hoarder, &key(1), RETRIES) {
        held.push(lease);
        if held.len() == 7 {
            break;
        }
    }
    let mut reader = storage.register().unwrap();
    let credits = storage.lease_report().unwrap().reserved;
    let op = read_by(
        entry,
        &mut dev,
        &mut reader,
        (&k, &k),
        RETRIES,
        &mut budget(),
    )
    .unwrap();
    assert_eq!(
        refs(&storage, slot),
        1 + held.len() + 1,
        "one right for the read"
    );
    assert_eq!(
        storage.lease_report().unwrap().reserved,
        credits,
        "no credit"
    );
    let token = last_read(&dev.control);
    dev.control.hold(token);
    drop(held);
    invalidate(&storage, &k).unwrap();
    drain(&storage);
    assert_eq!(
        refs(&storage, slot),
        1,
        "the read's right alone keeps the slot"
    );
    dev.control.release(token);
    let delivered = drive(&mut dev.volume, &dev.control, op);
    assert_eq!(delivered.status, ReadStatus::Complete);
    assert_eq!(delivered.bytes, payload);
    assert_eq!(refs(&storage, slot), 0, "released at the last terminal");
    drain(&storage);
    assert_eq!(
        storage.slot_state(SlotIndex(slot)).unwrap().0,
        SlotState::Free
    );
}

/// A key read of `k` through `reader` by `entry`, and its refusal if any.
fn key_read<'s>(
    entry: Entry,
    dev: &mut Device<'s, '_>,
    reader: &mut Registration<'s, TestPlatform>,
    k: &Key,
) -> Option<KeyReadError> {
    read_by(entry, dev, reader, (k, k), RETRIES, &mut budget()).err()
}

/// Every refused key read leaves the object's count, the response pool and
/// the table as they were: a lookup refusal reserves nothing, and a read
/// refusal after the lookup, a refused first command included, releases the
/// lookup's right. A registration of another storage is refused first, and
/// on the prepared entry so is a context prepared for another storage, with
/// the budget untouched. The scalar entry and the prepared entry each hold
/// it.
#[test]
fn every_refused_key_read_releases_its_lookup_s_right() {
    for entry in ENTRIES {
        every_refused_key_read_releases(entry);
    }
}

fn every_refused_key_read_releases(entry: Entry) {
    let storage = wide(4, 2);
    let foreign = wide(2, 2);
    let buffers = arena_with(1, 5);
    let mut dev = Device::new(&storage, &buffers);
    let mut stranger = foreign.register().unwrap();
    let first = published(&storage, &mut dev, &key(1), 0, &bytes(100, 1));
    let slot = first.id().slot_index();
    drop(first);
    let mut reader = storage.register().unwrap();
    let unchanged = |dev: &Device<'_, '_>| {
        assert_eq!(buffers.report(PoolKind::ReadResponse).free, 1);
        assert_eq!(dev.volume.table_report().pending, 0);
        assert_eq!(refs(&storage, slot), 1);
    };
    assert_eq!(
        key_read(entry, &mut dev, &mut stranger, &key(1)),
        Some(KeyReadError::ForeignRegistration)
    );
    drop(stranger);
    unchanged(&dev);
    if let Entry::Prepared = entry {
        let mut elsewhere = super::prepare::Preparation::new(&foreign);
        elsewhere.prime(&[key(1)], 0);
        let context = elsewhere.take(0, &key(1));
        let mut untouched = budget();
        assert_eq!(
            dev.volume
                .read_key_prepared(&mut reader, &context, RETRIES, &mut untouched, u64::MAX)
                .err(),
            Some(KeyReadError::ForeignRegistration)
        );
        assert_eq!(untouched.counters(), budget().counters());
        assert_eq!(untouched.remaining(), budget().remaining());
        unchanged(&dev);
    }
    assert_eq!(
        key_read(entry, &mut dev, &mut reader, &key(9)),
        Some(KeyReadError::Lookup(LookupError::Missing))
    );
    unchanged(&dev);
    dev.control.refuse_next(SubmitRefusal {
        reason: RefusalReason::InvalidRange,
        code: None,
    });
    assert!(matches!(
        key_read(entry, &mut dev, &mut reader, &key(1)),
        Some(KeyReadError::Read(ReadRefusal::Submit(_)))
    ));
    unchanged(&dev);
    // One response buffer: a held chunk refuses the next read's buffer after its lookup.
    let op = read_by(
        entry,
        &mut dev,
        &mut reader,
        (&key(1), &key(1)),
        RETRIES,
        &mut budget(),
    )
    .unwrap();
    let mut out = Vec::with_capacity(4);
    let (mut chunk, mut done) = (None, None);
    for _ in 0..8 {
        step(&mut dev.volume, &dev.control, &mut out);
        for event in out.drain(..) {
            match event {
                super::ReadEvent::Chunk { chunk: held, .. } => chunk = Some(held),
                super::ReadEvent::Done { op: of, status, .. } => done = Some((of, status)),
            }
        }
    }
    assert_eq!(done, Some((op, ReadStatus::Complete)));
    assert!(chunk.is_some(), "the caller holds the only response buffer");
    assert_eq!(
        key_read(entry, &mut dev, &mut reader, &key(1)),
        Some(KeyReadError::Read(ReadRefusal::PoolExhausted))
    );
    assert_eq!(refs(&storage, slot), 1);
    drop(chunk);
    let _ = dev.volume.close();
    assert_eq!(
        key_read(entry, &mut dev, &mut reader, &key(1)),
        Some(KeyReadError::Read(ReadRefusal::Closed))
    );
    unchanged(&dev);
}

/// R18, `s4n-integrity-failure-typed`, `s4n-chunk-exposure-prefix` (lease
/// path): a resident record whose third chunk is corrupted on the device
/// hands off the first two chunks, then ends `ChunkMismatch`; a corrupted
/// header ends `HeaderMismatch` with nothing exposed. Neither changes the
/// shard report or the slot's state, and a following invalidation by key
/// removes the object.
#[test]
fn an_integrity_failure_on_a_resident_hit_is_a_typed_outcome_and_changes_no_index_state() {
    let storage = wide(2, 8);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let payload = bytes(3 * 8192 + 100, 7);
    let k = key(1);
    let lease = published(&storage, &mut dev, &k, 0, &payload);
    let slot = lease.id().slot_index();
    let locator = storage.live_pool().unwrap().records()[slot].locator();
    let layout = storage.record.layout(0, payload.len() as u32);
    let mut record = extent(&storage, &dev.control, locator);
    let third = layout.chunk(2).unwrap();
    record[layout.header_bytes() + third.start as usize + 5] ^= 0x10;
    place(&storage, &dev.control, locator, &record);
    let shard = report(&storage, 0);
    let state = storage.slot_state(SlotIndex(slot));
    let op = dev.volume.read(lease.duplicate(), u64::MAX).unwrap();
    let delivered = drive(&mut dev.volume, &dev.control, op);
    assert_eq!(delivered.status, ReadStatus::ChunkMismatch { index: 2 });
    assert_eq!(delivered.bytes, payload[..third.start as usize]);
    assert_eq!(refs(&storage, slot), 2, "the failed read's right ended");
    assert_eq!(report(&storage, 0), shard);
    assert_eq!(storage.slot_state(SlotIndex(slot)), state);

    record[20] ^= 0x01;
    place(&storage, &dev.control, locator, &record);
    let mut reader = storage.register().unwrap();
    let hit = lookup(&mut reader, &k, RETRIES).unwrap();
    let op = dev.volume.read(hit.duplicate(), u64::MAX).unwrap();
    let delivered = drive(&mut dev.volume, &dev.control, op);
    assert!(
        matches!(
            delivered.status,
            ReadStatus::HeaderMismatch(HeaderMismatch::HeaderCrc { .. })
        ),
        "{:?}",
        delivered.status
    );
    assert!(delivered.bytes.is_empty());
    assert_eq!(refs(&storage, slot), 3, "the failed read's right ended");
    assert_eq!(report(&storage, 0), shard);
    assert_eq!(storage.slot_state(SlotIndex(slot)), state);
    drop((hit, lease));

    let removed = invalidate(&storage, &k).unwrap();
    assert_eq!(removed.removed.map(|(id, _)| id.slot_index()), Some(slot));
    assert_eq!(
        lookup(&mut reader, &k, RETRIES).err(),
        Some(LookupError::Missing)
    );
    settle(&mut dev.volume, &dev.control);
}

/// Releasing a quiesced volume ends every right its operations held: with a
/// lease's read and a fill's write both outstanding at the proven stop, the
/// release applies their terminals and frees the read, so the counts fall
/// to the storage's own holders, and after the object's invalidation, grace
/// and service the storage finalizes drained.
#[test]
fn a_released_volume_leaves_no_right_and_the_storage_finalizes_drained() {
    let mut storage = wide(2, 8);
    let buffers = arena();
    {
        let mut dev = Device::new(&storage, &buffers);
        let k = key(1);
        let lease = published(&storage, &mut dev, &k, 0, &bytes(100, 1));
        let slot = lease.id().slot_index();
        let _op = dev.volume.read(lease.duplicate(), u64::MAX).unwrap();
        dev.control.hold(last_read(&dev.control));
        let mut fill = reserve(&storage, &key(2), 0, 100).unwrap();
        assert_eq!(
            fill.receive(&mut dev.volume, &bytes(100, 2), &mut ample_io()),
            Ok(100)
        );
        let written = fill.id().slot_index();
        let write = dev
            .control
            .events()
            .iter()
            .rev()
            .find_map(|event| match event {
                Event::Submitted(token, Operation::Write) => Some(*token),
                _ => None,
            })
            .unwrap();
        dev.control.hold(write);
        assert_eq!((refs(&storage, slot), refs(&storage, written)), (3, 1));
        dev.control.set_quiesce(QuiesceMode::Reset);
        let Device { volume, .. } = dev;
        assert!(volume.release().is_ok(), "a reset proves the stop");
        assert_eq!((refs(&storage, slot), refs(&storage, written)), (2, 0));
        drop((fill, lease));
        invalidate(&storage, &k).unwrap();
        // The released volume persists no retirement, so the closed storage returns the held slot under the close waiver.
        storage.close();
        drain(&storage);
        service(&storage);
    }
    assert_eq!(finalize(&mut storage), Ok(Finalization::Drained));
}

/// A cancelled read keeps the right it took over from its lease until its
/// command's real terminal: with the command held, the cancel leaves the
/// read's right counted through the `Done { Cancelled }` delivery, and it
/// falls only once the held command ends.
#[test]
fn a_cancelled_read_keeps_its_right_until_the_command_ends() {
    let storage = wide(2, 8);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let lease = published(&storage, &mut dev, &key(1), 0, &bytes(100, 1));
    let slot = lease.id().slot_index();
    let op = dev.volume.read(lease, u64::MAX).unwrap();
    let token = last_read(&dev.control);
    dev.control.hold(token);
    dev.volume.cancel_read(op).unwrap();
    assert_eq!(refs(&storage, slot), 2, "the anchor and the read's right");
    let delivered = drive(&mut dev.volume, &dev.control, op);
    assert_eq!(delivered.status, ReadStatus::Cancelled);
    assert_eq!(refs(&storage, slot), 2, "held past the delivered outcome");
    dev.control.release(token);
    settle(&mut dev.volume, &dev.control);
    assert_eq!(refs(&storage, slot), 1, "released at the real terminal");
}

/// A stale record of the slot's earlier incarnation at a lease's extent,
/// with this object's key, lengths and session, ends the lease's read
/// `HeaderMismatch(Allocation)` with nothing exposed.
#[test]
fn a_stale_earlier_incarnation_record_at_a_lease_s_extent_is_refused() {
    let storage = wide(2, 8);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let payload = bytes(3000, 4);
    let k = key(1);
    let lease = published(&storage, &mut dev, &k, 0, &payload);
    let id = lease.id();
    let locator = storage.live_pool().unwrap().records()[id.slot_index()].locator();
    let earlier = AllocationId::new(id.slot(), id.incarnation() - 1);
    let stale = record_bytes(&storage, k, earlier, SESSION, &[], &payload);
    place(&storage, &dev.control, locator, &stale);
    let op = dev.volume.read(lease, u64::MAX).unwrap();
    let delivered = drive(&mut dev.volume, &dev.control, op);
    assert_eq!(
        delivered.status,
        ReadStatus::HeaderMismatch(HeaderMismatch::Allocation {
            expected: id.record_tag(),
            found: earlier.record_tag(),
        })
    );
    assert!(delivered.bytes.is_empty());
}

/// Incarnations count per slot, so header validation must match the lease's
/// slot before exposing bytes: another slot's record with this key, length,
/// session and incarnation ends the read `HeaderMismatch`.
#[test]
fn another_slot_s_record_at_the_same_incarnation_is_refused_at_a_lease_s_extent() {
    let storage = wide(2, 8);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let k = key(1);
    let incumbent = published(&storage, &mut dev, &k, 0, &bytes(3000, 4));
    let incumbent_locator =
        storage.live_pool().unwrap().records()[incumbent.id().slot_index()].locator();
    let stale = extent(&storage, &dev.control, incumbent_locator);
    let lease = published(&storage, &mut dev, &k, 0, &bytes(3000, 5));
    assert_ne!(lease.id().slot_index(), incumbent.id().slot_index());
    assert_eq!(lease.id().incarnation(), incumbent.id().incarnation());
    let locator = storage.live_pool().unwrap().records()[lease.id().slot_index()].locator();
    place(&storage, &dev.control, locator, &stale);
    let op = dev.volume.read(lease.duplicate(), u64::MAX).unwrap();
    let delivered = drive(&mut dev.volume, &dev.control, op);
    assert_eq!(
        delivered.status,
        ReadStatus::HeaderMismatch(HeaderMismatch::Allocation {
            expected: lease.id().record_tag(),
            found: incumbent.id().record_tag(),
        })
    );
    assert!(delivered.bytes.is_empty());
    assert_eq!(dev.volume.report().lookup_false_positives, 0);
}

/// `s4n-fingerprint-identity`: RAM matches an object by its fingerprint
/// alone and the read checks the full key. A record whose fingerprint is
/// forged to another key's, in the same chain and under the same tag, is
/// found by a lookup of that key, and the lease's read ends
/// `HeaderMismatch(Key)` with no byte exposed and one lookup false positive
/// counted. Before the forgery the other key is `Missing`; with the
/// fingerprint restored the owner's own key reads its bytes and counts
/// nothing.
#[test]
fn a_forged_fingerprint_hit_ends_in_a_key_mismatch_and_exposes_no_byte() {
    let mut storage = wide(2, 8);
    install_seam(&mut storage, one_chain);
    let storage = storage;
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let (owner, stranger) = (key(0x11), key(0x12));
    let payload = bytes(100, 3);
    let lease = published(&storage, &mut dev, &owner, 0, &payload);
    let slot = lease.id().slot_index();
    drop(lease);
    let mut reader = storage.register().unwrap();
    assert_eq!(
        lookup(&mut reader, &stranger, RETRIES).err(),
        Some(LookupError::Missing)
    );
    let record = &storage.live_pool().unwrap().records()[slot];
    let fingerprint = |k: &Key| storage.route(k).unwrap().fingerprint();
    assert_ne!(fingerprint(&owner), fingerprint(&stranger));
    record.set_fingerprint(fingerprint(&stranger));

    let hit = lookup(&mut reader, &stranger, RETRIES).unwrap();
    assert_eq!(hit.id().slot_index(), slot);
    let before = dev.volume.report();
    let op = dev.volume.read(hit, u64::MAX).unwrap();
    let delivered = drive(&mut dev.volume, &dev.control, op);
    assert_eq!(
        delivered.status,
        ReadStatus::HeaderMismatch(HeaderMismatch::Key)
    );
    assert!(delivered.bytes.is_empty() && delivered.ranges.is_empty());
    assert_eq!(
        dev.volume.report().lookup_false_positives,
        before.lookup_false_positives + 1
    );

    record.set_fingerprint(fingerprint(&owner));
    let own = lookup(&mut reader, &owner, RETRIES).unwrap();
    let op = dev.volume.read(own, u64::MAX).unwrap();
    let delivered = drive(&mut dev.volume, &dev.control, op);
    assert_eq!(delivered.status, ReadStatus::Complete);
    assert_eq!(delivered.bytes, payload);
    assert_eq!(
        dev.volume.report().lookup_false_positives,
        before.lookup_false_positives + 1
    );
    settle(&mut dev.volume, &dev.control);
}

/// `s4n-collision-displaces`: two keys with one whole fingerprint displace
/// each other. The second publication takes the first object's pair, `V`
/// stays one, and the incumbent is retired while its lease still reads its
/// own bytes. A lookup of the displaced key names the new object, whose read
/// ends `HeaderMismatch(Key)` and counts one false positive; the new key
/// reads its bytes. Once the leases are gone, grace and service return the
/// incumbent's slot.
#[test]
fn an_equal_fingerprint_publication_displaces_the_incumbent_and_its_key_reads_a_mismatch() {
    let mut storage = wide(2, 8);
    install_seam(&mut storage, one_fingerprint);
    let storage = storage;
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let (older, newer) = (key(0x11), key(0x12));
    assert_eq!(
        storage.route(&older).unwrap().fingerprint(),
        storage.route(&newer).unwrap().fingerprint()
    );
    let (older_bytes, newer_bytes) = (bytes(100, 1), bytes(100, 2));
    let incumbent = published(&storage, &mut dev, &older, 0, &older_bytes);
    let incumbent_slot = incumbent.id().slot_index();
    assert_eq!(report(&storage, 0).visible, 1);
    let displacer = published(&storage, &mut dev, &newer, 0, &newer_bytes);
    assert_ne!(displacer.id().slot_index(), incumbent_slot);
    assert_eq!(report(&storage, 0).visible, 1);
    assert_eq!(
        storage.slot_state(SlotIndex(incumbent_slot)).unwrap().0,
        SlotState::Retired
    );
    let op = dev.volume.read(incumbent.duplicate(), u64::MAX).unwrap();
    let delivered = drive(&mut dev.volume, &dev.control, op);
    assert_eq!(delivered.status, ReadStatus::Complete);
    assert_eq!(delivered.bytes, older_bytes);

    let mut reader = storage.register().unwrap();
    let stale = lookup(&mut reader, &older, RETRIES).unwrap();
    assert_eq!(stale.id(), displacer.id());
    let op = dev.volume.read(stale.duplicate(), u64::MAX).unwrap();
    let delivered = drive(&mut dev.volume, &dev.control, op);
    assert_eq!(
        delivered.status,
        ReadStatus::HeaderMismatch(HeaderMismatch::Key)
    );
    assert!(delivered.bytes.is_empty());
    assert_eq!(dev.volume.report().lookup_false_positives, 1);
    let fresh = lookup(&mut reader, &newer, RETRIES).unwrap();
    let op = dev.volume.read(fresh.duplicate(), u64::MAX).unwrap();
    let delivered = drive(&mut dev.volume, &dev.control, op);
    assert_eq!(delivered.status, ReadStatus::Complete);
    assert_eq!(delivered.bytes, newer_bytes);

    drop((incumbent, stale, fresh, displacer));
    drain(&storage);
    assert_eq!(
        storage.slot_state(SlotIndex(incumbent_slot)).unwrap().0,
        SlotState::Free
    );
    settle(&mut dev.volume, &dev.control);
}

/// `s4n-invalidate-all-matches`: invalidation by key removes the visible
/// object carrying the key's fingerprint, whichever key it holds, and no
/// object with that fingerprint survives it. After a displacement the one
/// visible object holds the newer key; invalidating the older key removes
/// it, the chain holds no candidate for either key, and both look up
/// `Missing`.
#[test]
fn invalidation_leaves_no_visible_object_with_the_keys_fingerprint() {
    let mut storage = wide(2, 8);
    install_seam(&mut storage, one_fingerprint);
    let storage = storage;
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let (older, newer) = (key(0x11), key(0x12));
    drop(published(&storage, &mut dev, &older, 0, &bytes(100, 1)));
    let displacer = published(&storage, &mut dev, &newer, 0, &bytes(100, 2)).id();
    let removed = invalidate(&storage, &older).unwrap();
    assert_eq!(removed.removed.map(|(id, _)| id), Some(displacer));
    assert!(candidates(&storage, &older).is_empty());
    assert!(candidates(&storage, &newer).is_empty());
    assert_eq!(report(&storage, 0).visible, 0);
    let mut reader = storage.register().unwrap();
    for k in [older, newer] {
        assert_eq!(
            lookup(&mut reader, &k, RETRIES).err(),
            Some(LookupError::Missing)
        );
    }
    settle(&mut dev.volume, &dev.control);
}

/// `s4n-miss-no-io`: over a seeded history in which every key shares one
/// chain and one tag and no fingerprint is forged, a lookup returns a lease
/// only for a published key, whose read completes with its current bytes;
/// every other key is `Missing` without a lease, so no read is submitted for
/// it, and no false positive is counted. Between rounds the history
/// invalidates a published key, which joins the keys that must miss,
/// replaces one with new bytes, or publishes an invalidated or fresh key,
/// and grace and service return the retired slots.
#[test]
fn seeded_misses_take_no_lease_and_submit_no_read() {
    let mut storage = wide(2, 8);
    install_seam(&mut storage, one_chain);
    let storage = storage;
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let mut rng = SplitMix64::new(0x4f23);
    let mut history = SplitMix64::new(0x4f24);
    let mut drawn = || {
        let mut k: Key = std::array::from_fn(|_| rng.next_u64() as u8);
        k[0] = 0x10 | (k[0] & 0x0F);
        k
    };
    let mut live: Vec<(Key, Vec<u8>)> = Vec::new();
    let mut gone: Vec<Key> = Vec::new();
    for n in 0..4 {
        let k = drawn();
        let payload = bytes(100, n);
        drop(published(&storage, &mut dev, &k, 0, &payload));
        service(&storage);
        live.push((k, payload));
    }
    let mut reader = storage.register().unwrap();
    let (mut hits, mut misses, mut gone_misses) = (0, 0, 0);
    // Invalidations, replacements and publications the history made.
    let mut steps = [0usize; 3];
    for round in 0..256 {
        if round % 8 == 7 {
            let pick = history.next_u64() as usize;
            match pick % 3 {
                0 if live.len() > 1 => {
                    let (k, _) = live.remove(pick / 3 % live.len());
                    assert!(invalidate(&storage, &k).unwrap().removed.is_some());
                    gone.push(k);
                    steps[0] += 1;
                }
                1 => {
                    let at = pick / 3 % live.len();
                    let payload = bytes(100, 0x40 + round as u64);
                    drop(published(&storage, &mut dev, &live[at].0, 0, &payload));
                    service(&storage);
                    live[at].1 = payload;
                    steps[1] += 1;
                }
                _ if live.len() < 4 => {
                    let k = gone.pop().unwrap_or_else(&mut drawn);
                    let payload = bytes(100, 0x1000 + round as u64);
                    drop(published(&storage, &mut dev, &k, 0, &payload));
                    service(&storage);
                    live.push((k, payload));
                    steps[2] += 1;
                }
                _ => {}
            }
            drain(&storage);
        }
        let (k, expected) = match round % 8 {
            0 => {
                let (k, payload) = &live[round / 8 % live.len()];
                (*k, Some(payload.clone()))
            }
            4 if !gone.is_empty() => {
                gone_misses += 1;
                (gone[round / 8 % gone.len()], None)
            }
            _ => (drawn(), None),
        };
        let submitted = dev.volume.report().reads_submitted;
        match (lookup(&mut reader, &k, RETRIES), expected) {
            (Ok(lease), Some(payload)) => {
                let op = dev.volume.read(lease, u64::MAX).unwrap();
                let delivered = drive(&mut dev.volume, &dev.control, op);
                assert_eq!(delivered.status, ReadStatus::Complete);
                assert_eq!(delivered.bytes, payload);
                hits += 1;
            }
            (Err(LookupError::Missing), None) => {
                assert_eq!(dev.volume.report().reads_submitted, submitted);
                misses += 1;
            }
            (outcome, expected) => panic!(
                "round {round}: {:?} for a key published: {}",
                outcome.map(|lease| lease.id()),
                expected.is_some()
            ),
        }
    }
    assert_eq!((hits, misses), (32, 224));
    assert!(steps.iter().all(|&n| n > 0), "{steps:?}");
    assert!(gone_misses > 0, "no invalidated key was looked up");
    assert_eq!(dev.volume.report().lookup_false_positives, 0);
    settle(&mut dev.volume, &dev.control);
}

/// Ticks until the device holds no command, returning every `Done` delivered.
fn settle_dones(dev: &mut Device<'_, '_>, now: u64) -> Vec<(ReadOp, ReadStatus)> {
    let mut out = Vec::with_capacity(8);
    let mut ended = Vec::new();
    for _ in 0..16 {
        let mut tick = || dev.control.tick(64);
        let mut poll = || {
            let _ = dev.volume.poll_storage(now, &mut out);
        };
        round(&mut [
            Act::new(Actor::Disk(0), &mut tick),
            Act::new(Actor::Volume(0), &mut poll),
        ]);
        ended.extend(out.drain(..).filter_map(|event| match event {
            ReadEvent::Done { op, status, .. } => Some((op, status)),
            ReadEvent::Chunk { .. } => None,
        }));
    }
    ended
}

/// `s4n-timeout-cancels-and-holds`: a read past
/// its deadline ends `Done { TimedOut }` while its command is held, and its
/// right alone keeps the retired slot through the object's
/// invalidation, grace and service, so no reservation receives the extent
/// under the pending command. The late terminal delivers nothing more and
/// releases the right, after which service returns the slot.
#[test]
fn a_timed_out_read_keeps_its_extent_and_right_until_the_real_terminal() {
    let storage = wide(2, 8);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let payload = bytes(3 * 8192, 5);
    let k = key(1);
    let lease = published(&storage, &mut dev, &k, 0, &payload);
    let slot = lease.id().slot_index();
    let locator = storage.live_pool().unwrap().records()[slot].locator();
    let op = dev.volume.read(lease, 10).unwrap();
    let token = last_read(&dev.control);
    dev.control.hold(token);
    assert_eq!(settle_dones(&mut dev, 10), [(op, ReadStatus::TimedOut)]);
    assert_eq!(refs(&storage, slot), 2, "the anchor and the read's right");
    invalidate(&storage, &k).unwrap();
    drain(&storage);
    assert_eq!(refs(&storage, slot), 1, "the read's right keeps the slot");
    assert_eq!(
        storage.slot_state(SlotIndex(slot)).unwrap().0,
        SlotState::Retired
    );
    let mut others = Vec::new();
    while let Ok(other) = storage.reserve(Some(0), Some(IO_UNIT), &mut budget()) {
        let at = other.locator();
        let overlap = at.start_unit() < locator.start_unit() + u64::from(locator.len_units())
            && locator.start_unit() < at.start_unit() + u64::from(at.len_units());
        assert!(
            !overlap,
            "a reservation reused the extent under a timed-out read"
        );
        others.push(other);
    }
    drop(others);
    dev.control.release(token);
    assert!(settle_dones(&mut dev, 10).is_empty(), "one Done per read");
    assert_eq!(refs(&storage, slot), 0, "released at the real terminal");
    drain(&storage);
    assert_eq!(
        storage.slot_state(SlotIndex(slot)).unwrap().0,
        SlotState::Free
    );
    assert_eq!(dev.volume.report().timed_out, 1);
}

/// `s4n-lost-refuses-closes` (storage part): after a driver unwinds in a
/// tick, and after the device refuses a fill's write `DeviceGone`, `receive`
/// refuses `Lost` with nothing copied or submitted and `read` refuses `Lost`
/// without spending the lease or taking a right; `close` then proves the
/// quiesce.
#[test]
fn a_lost_volume_refuses_receive_and_read_without_taking_a_token() {
    for gone in [false, true] {
        let storage = wide(2, 8);
        let buffers = arena();
        let mut dev = Device::new(&storage, &buffers);
        let lease = published(&storage, &mut dev, &key(1), 0, &bytes(100, 1));
        let slot = lease.id().slot_index();
        let mut fill = reserve(&storage, &key(2), 0, 100).unwrap();
        if gone {
            dev.control.set_gone();
            // The call that takes the last payload byte keeps its refused segment staged.
            assert_eq!(
                fill.receive(&mut dev.volume, &bytes(100, 2), &mut ample_io()),
                Ok(100)
            );
            assert_eq!(dev.volume.report().writes_refused, 1);
        } else {
            dev.control.unwind_next(Some(Unwind::Pick));
            let mut out = Vec::with_capacity(4);
            let unwound = catch_unwind(AssertUnwindSafe(|| dev.volume.poll_storage(0, &mut out)));
            assert!(unwound.is_err());
        }
        let before = (
            dev.volume.report().writes_submitted,
            buffers.report(PoolKind::ReceiveWrite).free,
            fill.received(),
        );
        let input = if gone { Vec::new() } else { bytes(100, 2) };
        assert_eq!(
            fill.receive(&mut dev.volume, &input, &mut ample_io()),
            Err(ReceiveError::Lost)
        );
        let after = (
            dev.volume.report().writes_submitted,
            buffers.report(PoolKind::ReceiveWrite).free,
            fill.received(),
        );
        assert_eq!(after, before, "gone {gone}");
        let refused = dev.volume.read(lease, u64::MAX).unwrap_err();
        assert_eq!(refused.refusal, ReadRefusal::Lost);
        assert!(refused.lease.is_some(), "the refusal returns the lease");
        assert_eq!(
            refs(&storage, slot),
            2,
            "the returned lease keeps its right"
        );
        assert_eq!(dev.volume.report().reads_submitted, 0);
        assert!(matches!(dev.volume.close(), QuiesceProgress::Quiesced(_)));
        fill.abort();
    }
}

/// `s4n-lost-refuses-closes`, `s4n-refused-owns-nothing` (receive part): a
/// fill's staged submit, retried by `receive`, is refused for good. On a live
/// volume the refusal is `Refused` with the device's reason; when the retry
/// itself meets the gone device, it is `Lost`. Either way `received` stays at
/// the payload length and the segment stays staged.
#[test]
fn a_refused_receive_names_lost_only_when_the_volume_is_lost() {
    let refusal = |reason| SubmitRefusal { reason, code: None };
    for gone in [false, true] {
        let storage = wide(2, 8);
        let buffers = arena();
        let mut dev = Device::new(&storage, &buffers);
        let mut fill = reserve(&storage, &key(1), 0, 100).unwrap();
        dev.control.refuse_next(refusal(RefusalReason::QueueFull));
        assert_eq!(
            fill.receive(&mut dev.volume, &bytes(100, 1), &mut ample_io()),
            Ok(100)
        );
        let expected = if gone {
            dev.control.set_gone();
            ReceiveError::Lost
        } else {
            let invalid = refusal(RefusalReason::InvalidRange);
            dev.control.refuse_next(invalid);
            ReceiveError::Refused(super::device::Refusal::Device(invalid))
        };
        assert_eq!(
            fill.receive(&mut dev.volume, &[], &mut ample_io()),
            Err(expected)
        );
        assert_eq!(dev.volume.is_lost(), gone);
        assert_eq!(fill.received(), 100);
        assert_eq!(fill.progress(&dev.volume).submitted_units, 0);
        assert!(matches!(dev.volume.close(), QuiesceProgress::Quiesced(_)));
        fill.abort();
    }
}

/// `s4n-early-drop-frees-nothing`, R17: a volume dropped before its quiesce
/// is proven, with a read and a write whose commands the device dropped,
/// frees nothing. The arena refuses release and hands itself back still
/// mapped, naming both held buffers; both operations' rights stay counted
/// after the lease, the fill and the object end; and finalization reports
/// both slots as pending obligations and never drains, however often it runs.
#[test]
fn a_volume_dropped_before_quiescence_frees_nothing() {
    let mut storage = wide(2, 8);
    let buffers = arena();
    let (read_slot, write_slot) = {
        let mut dev = Device::new(&storage, &buffers);
        let k = key(1);
        let lease = published(&storage, &mut dev, &k, 0, &bytes(100, 1));
        let read_slot = lease.id().slot_index();
        dev.volume.read(lease.duplicate(), u64::MAX).unwrap();
        dev.control
            .fault(last_read(&dev.control), Fault::DropCommand);
        let mut fill = reserve(&storage, &key(2), 0, 100).unwrap();
        assert_eq!(
            fill.receive(&mut dev.volume, &bytes(100, 2), &mut ample_io()),
            Ok(100)
        );
        let write_slot = fill.id().slot_index();
        let write = dev
            .control
            .events()
            .iter()
            .rev()
            .find_map(|event| match event {
                Event::Submitted(token, Operation::Write) => Some(*token),
                _ => None,
            })
            .unwrap();
        dev.control.fault(write, Fault::DropCommand);
        dev.control.tick(8);
        assert!(matches!(
            dev.volume.close(),
            QuiesceProgress::Draining { outstanding: 2 }
        ));
        drop(dev);
        assert_eq!(
            (refs(&storage, read_slot), refs(&storage, write_slot)),
            (3, 1)
        );
        drop(lease);
        fill.abort();
        invalidate(&storage, &k).unwrap();
        drain(&storage);
        service(&storage);
        (read_slot, write_slot)
    };
    assert_eq!(
        (refs(&storage, read_slot), refs(&storage, write_slot)),
        (1, 1),
        "each operation's right stays counted"
    );
    let blocked = buffers.release().unwrap_err();
    assert_eq!(
        blocked.held,
        [
            (PoolKind::ReadResponse, 1),
            (PoolKind::ReceiveWrite, 1),
            (PoolKind::Maintenance, 0),
            (PoolKind::PacketReceive, 0),
            (PoolKind::PacketHeader, 0),
            (PoolKind::Reservation, 0)
        ]
    );
    let arena = blocked.arena;
    assert!(arena.backing().extent() > 0, "the arena stays mapped");
    assert_eq!(arena.report(PoolKind::ReadResponse).storage, 1);
    assert_eq!(arena.report(PoolKind::ReceiveWrite).storage, 1);
    for _ in 0..3 {
        match finalize(&mut storage) {
            Ok(Finalization::Blocked(blockers)) => {
                // Both slots are retired or abandoned with a right still counted, so each is an undischarged obligation.
                assert_eq!(
                    (blockers.held_slots, blockers.pending),
                    (0, 2),
                    "{blockers:?}"
                );
            }
            other => panic!("finalization must stay blocked: {other:?}"),
        }
    }
}

/// `s4n-header-identity-triple` (cold-start part), `s4n-single-attach`
/// (across storages): a new storage over a device that still
/// holds a prior storage's records starts with every byte free and an empty
/// index, so no prior key is found, and it attaches its own volume with a
/// new session while the prior storage still refuses a second attach. A
/// record of the prior session forged at a new object's extent, with the
/// new object's key and incarnation, fails `HeaderMismatch::Session` with
/// nothing exposed.
#[test]
fn a_new_storage_and_session_over_old_device_bytes_trusts_nothing() {
    let prior = wide(2, 8);
    let prior_buffers = arena();
    let payload = bytes(3000, 9);
    let keys = [key(1), key(2)];
    let (image, old) = {
        let mut dev = Device::new(&prior, &prior_buffers);
        for k in &keys {
            drop(published(&prior, &mut dev, k, 0, &payload));
        }
        dev.persist_journal();
        (dev.control.device(0, 1 << 22), dev.volume.session())
    };
    let (disk, _) = device_with(7, BUFFER);
    let again = Volume::attach(
        &prior,
        &prior_buffers,
        disk,
        crate::storage::portable::scripted::ScriptedClock::trusted(),
        crate::storage::ServingAuthority::fixture(),
        DEPTH,
        TICK,
        &mut EngineBudget::new(1 << 24),
    );
    assert_eq!(
        again.err().map(|(error, _)| error),
        Some(AttachError::AlreadyAttached)
    );
    let storage = wide(2, 8);
    let buffers = arena();
    let (disk, control) = device_with(8, BUFFER);
    control.write_device(0, &image);
    let authority = crate::storage::ServingAuthority::fixture();
    let expected = authority.session().get();
    let mut volume = Volume::attach(
        &storage,
        &buffers,
        disk,
        crate::storage::portable::scripted::ScriptedClock::trusted(),
        authority,
        DEPTH,
        TICK,
        &mut EngineBudget::new(1 << 24),
    )
    .map_err(|(error, _)| error)
    .unwrap();
    bootstrap(&mut volume, &control);
    // The old image carries the prior volume's RESET roots, and this attach writes its higher session.
    let fresh = volume.session();
    assert_eq!(fresh, expected, "the RESET writes the authority's session");
    assert!(fresh > old);
    let mut dev = Device { volume, control };
    let raw = storage.pool_report().unwrap().ledger.unwrap().raw;
    assert_eq!(raw.free, 128 * IO_UNIT, "every payload unit starts free");
    assert_eq!(
        raw.metadata,
        crate::storage::TEST_METADATA_UNITS as usize * IO_UNIT,
        "the metadata prefix is the fixture's"
    );
    assert_eq!(
        raw.total(),
        Ok(144 * IO_UNIT),
        "the six terms sum to the raw bytes"
    );
    let mut reader = storage.register().unwrap();
    for k in &keys {
        assert_eq!(
            lookup(&mut reader, k, RETRIES).err(),
            Some(LookupError::Missing)
        );
    }
    let lease = published(&storage, &mut dev, &keys[0], 0, &payload);
    let slot = lease.id().slot_index();
    let locator = storage.live_pool().unwrap().records()[slot].locator();
    let stale = record_bytes(&storage, keys[0], lease.id(), old, &[], &payload);
    place(&storage, &dev.control, locator, &stale);
    let op = dev.volume.read(lease, u64::MAX).unwrap();
    let delivered = drive(&mut dev.volume, &dev.control, op);
    assert_eq!(
        delivered.status,
        ReadStatus::HeaderMismatch(HeaderMismatch::Session {
            expected: fresh,
            found: old,
        })
    );
    assert!(delivered.bytes.is_empty());
    let report = dev.volume.report();
    assert_eq!(
        (report.header_mismatch, report.lookup_false_positives),
        (1, 0)
    );
}

/// Reformatting after both root slots decode invalid assigns a fresh session.
/// If a lost write leaves the earlier formatting's record of the same key, slot
/// and incarnation at the reused extent, the read returns
/// `HeaderMismatch::Session` and exposes no bytes.
#[test]
fn a_reformat_over_old_device_bytes_rejects_the_earlier_formatting_s_records() {
    let prior = wide(2, 8);
    let prior_buffers = arena();
    let (old, new) = (bytes(3000, 9), bytes(3000, 10));
    let (image, old_session) = {
        let mut dev = Device::new(&prior, &prior_buffers);
        drop(published(&prior, &mut dev, &key(1), 0, &old));
        (dev.control.device(0, 1 << 22), dev.volume.session())
    };
    let storage = wide(2, 8);
    let buffers = arena();
    let (disk, control) = device_with(8, BUFFER);
    control.write_device(0, &image);
    // One flipped byte in each root slot invalidates both roots and leaves the payload region intact.
    control.write_device(200, &[!image[200]]);
    control.write_device(4096 + 200, &[!image[4096 + 200]]);
    let mut volume = Volume::attach(
        &storage,
        &buffers,
        disk,
        crate::storage::portable::scripted::ScriptedClock::trusted(),
        crate::storage::ServingAuthority::fixture(),
        DEPTH,
        TICK,
        &mut EngineBudget::new(1 << 24),
    )
    .map_err(|(error, _)| error)
    .unwrap();
    let mut out = Vec::with_capacity(16);
    for _ in 0..64 {
        if volume.metadata_outcome() != MetadataOutcome::Bootstrapping {
            break;
        }
        control.tick(64);
        let _ = volume.poll_storage(0, &mut out);
        out.clear();
    }
    assert_eq!(volume.metadata_outcome(), MetadataOutcome::Unformatted);
    volume
        .format_from(|drawn| {
            *drawn = [0x5A; 16];
            Ok(())
        })
        .expect("both slots decode invalid");
    bootstrap(&mut volume, &control);
    let fresh = volume.session();
    let mut dev = Device { volume, control };
    let lease = published(&storage, &mut dev, &key(1), 0, &new);
    let locator = storage.live_pool().unwrap().records()[lease.id().slot_index()].locator();
    let stale = record_bytes(&storage, key(1), lease.id(), old_session, &[], &old);
    place(&storage, &dev.control, locator, &stale);
    let op = dev.volume.read(lease, u64::MAX).unwrap();
    let delivered = drive(&mut dev.volume, &dev.control, op);
    assert_eq!(
        delivered.status,
        ReadStatus::HeaderMismatch(HeaderMismatch::Session {
            expected: fresh,
            found: old_session,
        })
    );
    assert!(delivered.bytes.is_empty());
}

/// A key read's lookup spends the budget it is given and nothing beyond: at
/// allowances of nothing, one step short of the guard bundle, the guard
/// bundle alone, one short of and exactly the guard bundle and hash charge,
/// and one step short of a resident hit's charge, the read is refused
/// `Lookup(Contended)` with nothing reserved; at exactly the charge it
/// starts; with no retries it is refused
/// `Lookup(Contended)`; a refused read leaves the next funded read on the
/// same registration its whole allowance; and on a closed volume a lookup
/// refusal precedes the volume's own. The prepared entry gives the scalar
/// entry's outcome, counters, remaining allowance and rights at every
/// allowance.
#[test]
fn a_key_read_spends_only_its_own_allowance() {
    use super::lookup::GUARD_STEPS;
    use crate::index::HASH_CHARGE;
    let fresh = |storage: &Storage<TestPlatform>| {
        let buffers = arena();
        let mut dev = Device::new(storage, &buffers);
        let publisher = published(storage, &mut dev, &key(1), 0, &bytes(100, 1));
        drop(publisher);
        let mut reader = storage.register().unwrap();
        let mut spent = WorkBudget::new(1 << 12);
        dev.volume
            .read_key(&mut reader, &key(1), RETRIES, &mut spent, u64::MAX)
            .unwrap();
        (1 << 12) - spent.remaining()
    };
    let charge = fresh(&wide(2, 8));
    let allowances = [
        0,
        GUARD_STEPS - 1,
        GUARD_STEPS,
        GUARD_STEPS + HASH_CHARGE - 1,
        GUARD_STEPS + HASH_CHARGE,
        charge - 1,
        charge,
    ];
    let mut seen = Vec::new();
    for (entry, allowance) in ENTRIES
        .into_iter()
        .flat_map(|entry| allowances.map(|allowance| (entry, allowance)))
    {
        let storage = wide(2, 8);
        let buffers = arena();
        let mut dev = Device::new(&storage, &buffers);
        let publisher = published(&storage, &mut dev, &key(1), 0, &bytes(100, 1));
        let slot = publisher.id().slot_index();
        drop(publisher);
        let mut reader = storage.register().unwrap();
        let mut work = WorkBudget::new(allowance);
        let read = read_by(
            entry,
            &mut dev,
            &mut reader,
            (&key(1), &key(1)),
            RETRIES,
            &mut work,
        );
        seen.push((
            allowance,
            read.as_ref().err().copied(),
            work.counters(),
            work.remaining(),
            refs(&storage, slot),
        ));
        if allowance == charge {
            assert!(read.is_ok(), "{allowance}");
            assert_eq!(refs(&storage, slot), 2, "{allowance}");
        } else {
            assert_eq!(
                read.err(),
                Some(KeyReadError::Lookup(LookupError::Contended)),
                "{allowance}"
            );
            assert_eq!(refs(&storage, slot), 1, "{allowance}");
            assert_eq!(dev.volume.table_report().pending, 0);
        }
        if allowance < GUARD_STEPS {
            assert_eq!(work.remaining(), allowance, "{allowance}");
            assert_eq!(work.counters().hashes, 0, "{allowance}");
        }
    }
    // The prepared entry's outcome, counters, remaining allowance and
    // rights equal the scalar entry's at every allowance.
    let (scalar, prepared) = seen.split_at(allowances.len());
    assert_eq!(scalar, prepared);

    for entry in ENTRIES {
        let storage = wide(2, 8);
        let buffers = arena();
        let mut dev = Device::new(&storage, &buffers);
        drop(published(&storage, &mut dev, &key(1), 0, &bytes(100, 1)));
        let mut reader = storage.register().unwrap();
        assert_eq!(
            read_by(
                entry,
                &mut dev,
                &mut reader,
                (&key(1), &key(1)),
                0,
                &mut budget()
            )
            .err(),
            Some(KeyReadError::Lookup(LookupError::Contended)),
            "{entry:?}"
        );
        let mut refused = WorkBudget::new(charge);
        assert_eq!(
            read_by(
                entry,
                &mut dev,
                &mut reader,
                (&key(9), &key(9)),
                RETRIES,
                &mut refused
            )
            .err(),
            Some(KeyReadError::Lookup(LookupError::Missing)),
            "{entry:?}"
        );
        let mut funded = WorkBudget::new(charge);
        assert_eq!(
            read_by(
                entry,
                &mut dev,
                &mut reader,
                (&key(1), &key(1)),
                RETRIES,
                &mut funded
            )
            .err(),
            None,
            "{entry:?}"
        );
        settle(&mut dev.volume, &dev.control);
        let _ = dev.volume.close();
        assert_eq!(
            read_by(
                entry,
                &mut dev,
                &mut reader,
                (&key(9), &key(9)),
                RETRIES,
                &mut budget()
            )
            .err(),
            Some(KeyReadError::Lookup(LookupError::Missing)),
            "{entry:?}"
        );
    }
}

/// A prepared key read serves only the key it is asked for and validates
/// afresh. A context asked for `B` at `A`'s entry, or for `A` at another
/// ordinal, carries no route and reads the requested key's own bytes.
/// After its route was prepared, `A` republished reads the new version's
/// bytes, `A` invalidated inside the lookup's final bracket reads `Missing`,
/// `A` past its deadline reads `Expired`, and a closed storage reads
/// `Closed`.
#[test]
fn a_prepared_key_read_serves_only_its_own_key_and_validates_afresh() {
    use super::prepare::Preparation;
    let storage = wide(4, 8);
    let buffers = arena_with(4, 5);
    let mut dev = Device::new(&storage, &buffers);
    let (a, b) = (key(1), key(2));
    drop(published(&storage, &mut dev, &a, 0, &bytes(100, 1)));
    drop(published(&storage, &mut dev, &b, 0, &bytes(120, 2)));
    let mut reader = storage.register().unwrap();
    let mut preparation = Preparation::new(&storage);
    fn read<'s>(
        dev: &mut Device<'s, '_>,
        reader: &mut Registration<'s, TestPlatform>,
        context: super::prepare::PreparedLookup<'s, TestPlatform>,
    ) -> Result<super::volume_fixture::Delivered, KeyReadError> {
        let op =
            dev.volume
                .read_key_prepared(reader, &context, RETRIES, &mut budget(), u64::MAX)?;
        Ok(drive(&mut dev.volume, &dev.control, op))
    }

    preparation.prime(&[a], 0);
    let swapped = preparation.take(0, &b);
    assert_eq!(swapped.route(), None);
    let delivered = read(&mut dev, &mut reader, swapped).unwrap();
    assert_eq!(
        (delivered.status, delivered.bytes),
        (ReadStatus::Complete, bytes(120, 2))
    );
    preparation.prime(&[a], 0);
    let shifted = preparation.take(1, &a);
    assert_eq!(shifted.route(), None);
    let delivered = read(&mut dev, &mut reader, shifted).unwrap();
    assert_eq!(
        (delivered.status, delivered.bytes),
        (ReadStatus::Complete, bytes(100, 1))
    );

    preparation.prime(&[a], 0);
    drop(published(&storage, &mut dev, &a, 0, &bytes(90, 3)));
    let delivered = read(&mut dev, &mut reader, preparation.take(0, &a)).unwrap();
    assert_eq!(
        (delivered.status, delivered.bytes),
        (ReadStatus::Complete, bytes(90, 3))
    );

    // Invalidated inside the prepared lookup's final bracket, after its
    // candidate was reserved: the moved sequence spends the attempt, and
    // the retry finds the key absent.
    preparation.prime(&[a], 0);
    let context = preparation.take(0, &a);
    let raced = super::lookup_tests::paused(
        &storage,
        super::lookup::Pause::FinalBracket,
        |storage| {
            invalidate(storage, &key(1)).unwrap();
        },
        || read(&mut dev, &mut reader, context).err(),
    );
    assert_eq!(raced, Some(KeyReadError::Lookup(LookupError::Missing)));

    let mut fill = reserve(&storage, &a, 0, 80).unwrap();
    dev.fill(&mut fill, &bytes(80, 4));
    let deadline = 10_000_000_000;
    drop(
        fill.publish(&mut dev.volume, deadline, TRIES, &mut budget())
            .unwrap(),
    );
    preparation.prime(&[a], 0);
    storage.platform.ticks(&[Some(deadline)]);
    assert_eq!(
        read(&mut dev, &mut reader, preparation.take(0, &a)).err(),
        Some(KeyReadError::Lookup(LookupError::Expired))
    );

    preparation.prime(&[b], 0);
    storage.close();
    assert_eq!(
        read(&mut dev, &mut reader, preparation.take(0, &b)).err(),
        Some(KeyReadError::Lookup(LookupError::Closed))
    );
}

crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
    a_cancelled_read_keeps_its_right_until_the_command_ends,
    a_forged_fingerprint_hit_ends_in_a_key_mismatch_and_exposes_no_byte,
    a_key_read_holds_its_lookup_s_right_and_takes_no_credit,
    a_key_read_spends_only_its_own_allowance,
    a_lost_volume_refuses_a_ready_fills_publication,
    a_lost_volume_refuses_receive_and_read_without_taking_a_token,
    a_new_storage_and_session_over_old_device_bytes_trusts_nothing,
    a_prepared_key_read_serves_only_its_own_key_and_validates_afresh,
    a_read_holds_its_lease_s_right_until_its_last_terminal,
    a_reformat_over_old_device_bytes_rejects_the_earlier_formatting_s_records,
    a_released_volume_leaves_no_right_and_the_storage_finalizes_drained,
    a_stale_earlier_incarnation_record_at_a_lease_s_extent_is_refused,
    a_timed_out_read_keeps_its_extent_and_right_until_the_real_terminal,
    a_volume_dropped_before_quiescence_frees_nothing,
    an_equal_fingerprint_publication_displaces_the_incumbent_and_its_key_reads_a_mismatch,
    an_integrity_failure_on_a_resident_hit_is_a_typed_outcome_and_changes_no_index_state,
    another_slot_s_record_at_the_same_incarnation_is_refused_at_a_lease_s_extent,
    every_refused_key_read_releases_its_lookup_s_right,
    every_refused_read_owns_nothing,
    invalidation_leaves_no_visible_object_with_the_keys_fingerprint,
    seeded_misses_take_no_lease_and_submit_no_read,
);

/// A volume lost after a fill's last write terminal refuses the fill's publication with `Lost`, as it refuses a receive, whether a poll that unwound lost the volume or the table's admission alone did, with no poll after the refused submit. The fill is still ready, and the refusal leaves the shard's sequence, its visible count and the key's candidates as they were.
#[test]
fn a_lost_volume_refuses_a_ready_fills_publication() {
    for gone in [false, true] {
        let storage = wide(2, 8);
        let buffers = arena();
        let mut dev = Device::new(&storage, &buffers);
        let mut fill = reserve(&storage, &key(2), 0, 100).unwrap();
        dev.fill(&mut fill, &bytes(100, 2));
        assert!(fill.is_ready(&dev.volume));
        // Reserved before the loss, which withdraws readiness for later reservations.
        let mut other = reserve(&storage, &key(3), 0, 100).unwrap();
        if gone {
            dev.control.set_gone();
            assert_eq!(
                other.receive(&mut dev.volume, &bytes(100, 3), &mut ample_io()),
                Ok(100)
            );
            assert_eq!(dev.volume.report().writes_refused, 1);
            assert!(dev.volume.is_lost());
        } else {
            dev.lose();
        }
        assert!(
            fill.is_ready(&dev.volume),
            "gone {gone}: the loss left the fill ready"
        );
        let before = report(&storage, 0);
        assert_eq!(
            fill.publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
                .err(),
            Some(FillPublishError::Lost),
            "gone {gone}"
        );
        let after = report(&storage, 0);
        assert_eq!(
            (after.sequence, after.visible),
            (before.sequence, before.visible),
            "gone {gone}"
        );
        assert_eq!(after.visible, 0, "gone {gone}");
        assert!(candidates(&storage, &key(2)).is_empty(), "gone {gone}");
        other.abort();
    }
}

/// `Lost` is judged before readiness: a fill with a write of its record outstanding refuses publication with `Lost` once the volume is lost, where the same fill on a live volume refuses `Incomplete`. The device is not advanced, so the test checks the order of the refusals alone.
#[test]
fn a_lost_volume_refuses_an_unready_fills_publication_as_lost() {
    for lost in [false, true] {
        let storage = wide(2, 8);
        let buffers = arena();
        let mut dev = Device::new(&storage, &buffers);
        let mut fill = reserve(&storage, &key(2), 4, 100).unwrap();
        assert_eq!(
            fill.receive(&mut dev.volume, &bytes(104, 2), &mut ample_io()),
            Ok(104)
        );
        assert!(
            fill.progress(&dev.volume).outstanding_units > 0,
            "a write of the record is outstanding"
        );
        if lost {
            dev.lose();
        }
        assert!(!fill.is_ready(&dev.volume), "lost {lost}");
        assert_eq!(
            fill.publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
                .err(),
            Some(if lost {
                FillPublishError::Lost
            } else {
                FillPublishError::Incomplete
            })
        );
        assert_eq!(report(&storage, 0).visible, 0, "lost {lost}");
    }
}

/// `ForeignVolume` is judged before `Lost`: a ready fill published through another storage's volume refuses `ForeignVolume` when that volume is lost, and its own storage publishes nothing.
/// The refusal retires the fill's slot with `ABANDONED`, the tables pass the
/// conservation judge, and one service pass frees the slot.
#[test]
fn a_lost_foreign_volume_refuses_publication_as_foreign() {
    let (storage, other) = (wide(2, 8), wide(2, 8));
    let (buffers, other_buffers) = (arena(), arena());
    let mut dev = Device::new(&storage, &buffers);
    let mut foreign = Device::new(&other, &other_buffers);
    let mut fill = reserve(&storage, &key(2), 0, 100).unwrap();
    dev.fill(&mut fill, &bytes(100, 2));
    assert!(fill.is_ready(&dev.volume));
    foreign.lose();
    assert!(!dev.volume.is_lost());
    let slot = fill.id().slot_index();
    assert_eq!(
        fill.publish(&mut foreign.volume, u64::MAX, TRIES, &mut budget())
            .err(),
        Some(FillPublishError::ForeignVolume)
    );
    conserved_at(&storage, slot, RETIRED);
    assert_eq!(report(&storage, 0).visible, 0);
    assert!(candidates(&storage, &key(2)).is_empty());
    conserved_after_service(&storage, slot, FREE);
}
