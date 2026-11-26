//! Tests derive expected state from protocol rules; the byte oracle reads each object back through the volume from the simulated device, against payloads the test builds, and `sequence` reads the shard's sequence word through its report.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Barrier, Mutex};

use super::admission::{Admitted, Decision};
use super::attempt_tests::{begin, departed, gate, invalidate, live, records, revoked, service};
use super::budget::WorkBudget;
use super::claim_exit_tests::{FREE, RETIRED, conserved_after_service, conserved_at};
use super::fill::Record;
use super::finalize::FinalizeError;
use super::image::NO_RECORD;
use super::join_tests::FOLLOWERS;
use super::lease::{Credit, CreditError, reserve_credit, reserve_shared_credits, return_credit};
use super::lookup_tests::{lookup, samples, ticks};
use super::owner::Storage;
use super::probe::{self, Event};
use super::publication::{CUT, Cut, INTERPOSE_BEFORE_INHIBITION, phase};
use super::publish_tests::{
    PAGE, RETRIES, TRIES, budget, candidates, index_config, install_seam, key, one_chain, refs,
    report, storage_config, storage_from,
};
use super::tables::{SlotIndex, SlotState};
use super::test_platform::{TestPlatform, finalize};
use super::volume_fixture::{Device, ample_io, arena, arena_with, drive};
use super::writable_tests::{next_claim, returned_claim};
use super::{
    ExtentLease, FillPublishError, FillServiceError, LookupError, ReadStatus, WritableFill,
};
use crate::index::{BucketView, IndexConfig, Key, OverflowLink, ShardIndex, TERMINAL};

const SHARD: ShardIndex = ShardIndex(0);
pub(super) const DEADLINE: u64 = u64::MAX;
/// One second on the engine's nanosecond timeline.
pub(super) const SECOND: u64 = 1_000_000_000;

pub(super) fn ready_with(
    fills: usize,
    lease_limit: usize,
    object_rights: usize,
) -> Storage<TestPlatform> {
    let fills = [fills];
    let index = IndexConfig {
        fills: &fills,
        ..index_config(&[8], (1, 1), 1)
    };
    let config = super::config::StorageConfig {
        lease_limit,
        object_rights,
        ..storage_config(8)
    };
    let storage = storage_from(&config, &index, TestPlatform::heap(PAGE));
    storage.platform.ticks(&[Some(1)]);
    storage
}

fn ready(fills: usize) -> Storage<TestPlatform> {
    ready_with(fills, 16, 8)
}

pub(super) fn admit(storage: &Storage<TestPlatform>, metadata: usize, body: usize) -> Admitted {
    match storage.decide_admission(Some(metadata), Some(body)) {
        Decision::Admit(admitted) => admitted,
        other => panic!("expected Admit, got {other:?}"),
    }
}

/// The payload a fill of `key` streams: the key's first four bytes, then `body`.
pub(super) fn payload(key: &Key, body: &[u8]) -> Vec<u8> {
    key[..4].iter().chain(body).copied().collect()
}

/// A fill of `key` reserved for `body`, or the reservation's refusal.
pub(super) fn reserved<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    key: &Key,
    body: &[u8],
) -> Result<WritableFill<'s, 'a, TestPlatform>, super::writable::FillReserveError> {
    reserved_with(storage, key, body, &mut budget())
}

/// [`reserved`] under `budget`.
fn reserved_with<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    key: &Key,
    body: &[u8],
    budget: &mut WorkBudget,
) -> Result<WritableFill<'s, 'a, TestPlatform>, super::writable::FillReserveError> {
    let attempt = begin(storage, key).unwrap();
    let admitted = admit(storage, 4, body.len());
    attempt.reserve_storage(admitted, Some(4), Some(body.len()), TRIES, budget)
}

pub(super) fn filled<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    dev: &mut Device<'s, 'a>,
    key: &Key,
    body: &[u8],
) -> WritableFill<'s, 'a, TestPlatform> {
    let mut fill = reserved(storage, key, body).unwrap();
    dev.fill(&mut fill, &payload(key, body));
    fill
}

pub(super) fn publish<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    dev: &mut Device<'s, 'a>,
    key: &Key,
    body: &[u8],
) -> Result<ExtentLease<'s, TestPlatform>, FillPublishError> {
    filled(storage, dev, key, body).publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
}

pub(super) fn credits(storage: &Storage<TestPlatform>) -> usize {
    storage.lease_report().unwrap().reserved
}

type CustodyWords = (usize, u64, usize, usize, u64);

fn custody(storage: &Storage<TestPlatform>) -> CustodyWords {
    let table = storage.root_image.fills[0].as_ref().unwrap();
    // SAFETY: the root mapping is live and only atomics are read.
    let custody = unsafe { &table.custody.as_slice(&storage.root)[0] };
    (
        custody.record.load(Ordering::Acquire),
        custody.serial.load(Ordering::Relaxed),
        custody.candidate.load(Ordering::Relaxed),
        custody.incumbent.load(Ordering::Relaxed),
        custody.phase.load(Ordering::Relaxed),
    )
}

fn no_custody() -> CustodyWords {
    (NO_RECORD, 0, NO_RECORD, NO_RECORD, phase::NONE)
}

fn sequence(storage: &Storage<TestPlatform>) -> u64 {
    report(storage, 0).sequence
}

fn scanned() -> usize {
    super::lease::RECORDS_SCANNED.with(std::cell::Cell::get)
}

pub(super) fn drain(storage: &Storage<TestPlatform>) {
    storage.service_fills(SHARD, TRIES, &mut budget()).unwrap();
    for _ in 0..8 {
        let _ = storage.certify(&mut WorkBudget::new(1 << 10)).unwrap();
        storage.service(&mut WorkBudget::new(1 << 10)).unwrap();
    }
}

fn missing(storage: &Storage<TestPlatform>, key: &Key) {
    let mut reader = storage.register().unwrap();
    assert_eq!(
        lookup(&mut reader, key, RETRIES).err(),
        Some(LookupError::Missing)
    );
}

#[test]
fn a_complete_fill_publishes_into_a_lease_and_a_lookup_hits_the_same_bytes() {
    let storage = ready(2);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let k = key(1);
    let body: Vec<u8> = (0..20u8).map(|b| b.wrapping_mul(7)).collect();
    let fill = filled(&storage, &mut dev, &k, &body);
    let allocations = crate::instrument::allocations();
    let lease = fill
        .publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
        .unwrap();
    assert_eq!(crate::instrument::allocations(), allocations);
    let id = lease.id();
    assert_eq!(refs(&storage, id), 2);
    assert_eq!(credits(&storage), 1);
    assert_eq!(candidates(&storage, &k), [id]);
    assert_eq!(report(&storage, 0).visible, 1);
    assert_eq!(records(&storage), [departed(1, true), Record::Free]);
    assert_eq!(custody(&storage), no_custody());
    assert_eq!(
        storage.slot_state(SlotIndex(id.slot_index())).map(|s| s.0),
        Some(SlotState::Resident)
    );

    let mut reader = storage.register().unwrap();
    ticks(&storage, &[Some(2)]);
    let hit = lookup(&mut reader, &k, RETRIES).unwrap();
    assert_eq!(hit.id(), id);
    assert_eq!(refs(&storage, id), 3);
    assert_eq!(dev.read(&lease), payload(&k, &body));
    assert_eq!(dev.read(&hit), payload(&k, &body));
    drop(hit);
    drop(lease);
    assert_eq!(refs(&storage, id), 1);
    assert_eq!(credits(&storage), 0);

    assert_eq!(service(&storage).released, 1);
    let removed = invalidate(&storage, &k).unwrap();
    assert_eq!(removed.removed.map(|(id, _)| id), Some(id));
    drop(reader);
    dev.persist_journal();
    drain(&storage);
    assert_eq!(
        storage.slot_state(SlotIndex(id.slot_index())).map(|s| s.0),
        Some(SlotState::Free)
    );
    let again = publish(&storage, &mut dev, &k, &[9; 20]).unwrap();
    assert_eq!(dev.read(&again), payload(&k, &[9; 20]));
    let mut reader = storage.register().unwrap();
    let hit = lookup(&mut reader, &k, RETRIES).unwrap();
    assert_eq!(dev.read(&hit), payload(&k, &[9; 20]));
}

/// At `C = 2` a publication with a joined follower installs the anchor, the
/// publisher's right and its row's retained right, filling the count to
/// `C + 1`: a lookup returns `LookupError::RetainLimit` until the
/// publisher's lease drops, and the read takes over the hit's right, keeping
/// the object's rights within `C`.
#[test]
fn a_joined_first_publisher_is_admitted_at_the_narrowest_right_limit() {
    let storage = ready_with(2, 16, 2);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let fill = filled(&storage, &mut dev, &key(1), &[1; 20]);
    let follower = storage
        .join_fill(&key(1), FOLLOWERS, TRIES, &mut budget())
        .unwrap();
    let lease = fill
        .publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
        .unwrap();
    let id = lease.id();
    assert_eq!(refs(&storage, id), 3);
    let mut reader = storage.register().unwrap();
    ticks(&storage, &[Some(2), Some(2)]);
    assert_eq!(
        lookup(&mut reader, &key(1), RETRIES).err(),
        Some(LookupError::RetainLimit)
    );
    drop(lease);
    let hit = lookup(&mut reader, &key(1), RETRIES).unwrap();
    assert_eq!(hit.id(), id);
    let op = dev.volume.read(hit, u64::MAX).unwrap();
    assert_eq!(
        refs(&storage, id),
        3,
        "the anchor, the row's right and the read's right"
    );
    assert_eq!(credits(&storage), 1, "the row's credit alone");
    let delivered = drive(&mut dev.volume, &dev.control, op);
    assert_eq!(delivered.status, ReadStatus::Complete);
    assert_eq!(delivered.bytes, payload(&key(1), &[1; 20]));
    assert_eq!(
        refs(&storage, id),
        2,
        "the read's right ended at its last terminal"
    );
    drop(follower);
    assert_eq!(service(&storage).released, 1);
    assert_eq!(refs(&storage, id), 1, "service returned the row's right");
    assert_eq!(credits(&storage), 0, "and its credit");
}

#[test]
fn every_refusal_consumes_the_fill_and_preserves_the_incumbent() {
    let storage = ready(4);
    let buffers = arena_with(4, 5);
    let mut dev = Device::new(&storage, &buffers);
    let k = key(1);
    let incumbent = publish(&storage, &mut dev, &k, &[0xA; 20]).unwrap();
    let incumbent_id = incumbent.id();
    drain(&storage);
    let before = (
        report(&storage, 0),
        refs(&storage, incumbent_id),
        credits(&storage),
    );
    // Once service releases the consumed fill's record, its place is back.
    let unchanged = |storage: &Storage<TestPlatform>| {
        storage.service_fills(SHARD, TRIES, &mut budget()).unwrap();
        assert_eq!(report(storage, 0).visible, before.0.visible);
        assert_eq!(report(storage, 0).reserved, before.0.reserved);
        assert_eq!(report(storage, 0).free_overflow, before.0.free_overflow);
        assert_eq!(refs(storage, incumbent_id), before.1);
        assert_eq!(credits(storage), before.2);
        assert_eq!(candidates(storage, &k), [incumbent_id]);
        assert_eq!(custody(storage), no_custody());
    };

    let attempt = begin(&storage, &k).unwrap();
    let serial = attempt.serial();
    let admitted = admit(&storage, 4, 20);
    let mut short = attempt
        .reserve_storage(admitted, Some(4), Some(20), TRIES, &mut budget())
        .unwrap();
    assert_eq!(short.receive(&mut dev.volume, &[1], &mut ample_io()), Ok(1));
    let stable = sequence(&storage);
    let slot = short.id().slot_index();
    assert_eq!(
        short
            .publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
            .err(),
        Some(FillPublishError::Incomplete)
    );
    conserved_at(&storage, slot, FREE);
    assert_eq!(sequence(&storage), stable);
    assert_eq!(records(&storage)[0], departed(serial, false));
    conserved_after_service(&storage, slot, FREE);
    unchanged(&storage);
    drain(&storage);

    let fill = filled(&storage, &mut dev, &k, &[3; 20]);
    let held = gate(&storage).lock().unwrap();
    let stable = sequence(&storage);
    let slot = fill.id().slot_index();
    assert_eq!(
        fill.publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
            .err(),
        Some(FillPublishError::Contended)
    );
    drop(held);
    conserved_at(&storage, slot, RETIRED);
    assert_eq!(sequence(&storage), stable);
    conserved_after_service(&storage, slot, FREE);
    unchanged(&storage);
    drain(&storage);
    let fill = filled(&storage, &mut dev, &k, &[3; 20]);
    let mut zero = WorkBudget::new(0);
    let slot = fill.id().slot_index();
    assert_eq!(
        fill.publish(&mut dev.volume, DEADLINE, TRIES, &mut zero)
            .err(),
        Some(FillPublishError::BudgetExhausted)
    );
    conserved_at(&storage, slot, RETIRED);
    conserved_after_service(&storage, slot, FREE);
    unchanged(&storage);
    drain(&storage);

    for (samples, expected) in [
        (&[None][..], FillPublishError::ClockUnavailable),
        (&[Some(10 * SECOND)][..], FillPublishError::Expired),
        (&[Some(11 * SECOND)][..], FillPublishError::Expired),
    ] {
        let fill = filled(&storage, &mut dev, &k, &[4; 20]);
        let candidate = fill.id();
        let serial = fill.serial();
        ticks(&storage, samples);
        let stable = sequence(&storage);
        probe::arm();
        assert_eq!(
            fill.publish(&mut dev.volume, 10 * SECOND, TRIES, &mut budget())
                .err(),
            Some(expected)
        );
        let log = probe::events();
        assert!(!log.overflowed);
        assert_eq!(
            log.events,
            [
                Event::Inhibit {
                    sequence: stable + 1
                },
                Event::Sampled { ticks: samples[0] },
                Event::Cutoff { closed: false },
                Event::Revoked { serial },
                Event::Committed {
                    sequence: stable + 2
                },
                Event::Detached {
                    slot: candidate.slot_index()
                },
            ]
        );
        assert_eq!(sequence(&storage), stable + 2);
        assert_eq!(refs(&storage, candidate), 0);
        conserved_at(&storage, candidate.slot_index(), RETIRED);
        assert_eq!(records(&storage)[0], departed(serial, true));
        conserved_after_service(&storage, candidate.slot_index(), FREE);
        unchanged(&storage);
        drain(&storage);
        ticks(&storage, &[Some(1)]);
    }

    ticks(&storage, &[Some(9 * SECOND)]);
    let replaced = filled(&storage, &mut dev, &k, &[5; 20])
        .publish(&mut dev.volume, 10 * SECOND, TRIES, &mut budget())
        .unwrap();
    assert_eq!(candidates(&storage, &k), [replaced.id()]);
    assert_eq!(dev.read(&replaced), payload(&k, &[5; 20]));
    assert_eq!(dev.read(&incumbent), payload(&k, &[0xA; 20]));
    assert_eq!(report(&storage, 0).visible, 1);
    drop(incumbent);
    drop(replaced);
    drain(&storage);
    ticks(&storage, &[Some(1)]);
}

/// A budget that pays for the completion's bind and nothing after it
/// refuses `BudgetExhausted` at the route's hash, after the slot is
/// `Resident` and before the shard gate. The refusal retires the slot with
/// `ABANDONED` and its extent held, the tables pass the conservation judge,
/// and one service pass returns the extent and frees the slot.
#[test]
fn a_publication_refused_after_its_bind_retires_its_slot_for_service() {
    let storage = ready(2);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let fill = filled(&storage, &mut dev, &key(1), &[1; 20]);
    let slot = fill.id().slot_index();
    let mut bind = WorkBudget::new(2);
    assert_eq!(
        fill.publish(&mut dev.volume, DEADLINE, TRIES, &mut bind)
            .err(),
        Some(FillPublishError::BudgetExhausted)
    );
    let spent = bind.counters();
    assert_eq!(
        (spent.coordination_attempts, spent.updates, spent.hashes),
        (1, 1, 0),
        "premise: the bind ran and the route's hash was refused"
    );
    conserved_at(&storage, slot, RETIRED);
    assert_eq!(report(&storage, 0).visible, 0);
    conserved_after_service(&storage, slot, FREE);
}

#[test]
fn a_revoked_attempt_publishes_superseded_and_leaves_its_replacement_intact() {
    let storage = ready(3);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let k = key(1);
    let incumbent = publish(&storage, &mut dev, &k, &[0xA; 20]).unwrap();
    drain(&storage);
    let first = filled(&storage, &mut dev, &k, &[1; 20]);
    let removed = invalidate(&storage, &k).unwrap();
    assert_eq!(removed.revoked, Some(first.serial()));
    assert_eq!(removed.removed.map(|(id, _)| id), Some(incumbent.id()));
    let second = begin(&storage, &k).unwrap();
    let stable = sequence(&storage);
    let slot = first.id().slot_index();
    assert_eq!(
        first
            .publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
            .err(),
        Some(FillPublishError::Superseded)
    );
    conserved_at(&storage, slot, RETIRED);
    assert_eq!(sequence(&storage), stable);
    assert_eq!(records(&storage)[1], live(second.serial()));
    missing(&storage, &k);
    assert_eq!(dev.read(&incumbent), payload(&k, &[0xA; 20]));
    conserved_after_service(&storage, slot, FREE);
    let admitted = admit(&storage, 4, 20);
    let mut fill = second
        .reserve_storage(admitted, Some(4), Some(20), TRIES, &mut budget())
        .unwrap();
    dev.fill(&mut fill, &payload(&k, &[2; 20]));
    let republished = fill
        .publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
        .unwrap();
    assert_eq!(candidates(&storage, &k), [republished.id()]);
    assert_eq!(dev.read(&republished), payload(&k, &[2; 20]));
}

#[test]
fn a_close_inside_the_inhibition_refuses_with_a_fresh_even_and_a_close_before_the_gate_costs_nothing()
 {
    let storage = ready(2);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let k = key(1);
    let incumbent = publish(&storage, &mut dev, &k, &[0xA; 20]).unwrap();
    drain(&storage);
    let stable = sequence(&storage);
    INTERPOSE_BEFORE_INHIBITION.with(|hook| {
        hook.set(Some(|closed| closed.store(true, Ordering::SeqCst)));
    });
    let fill = filled(&storage, &mut dev, &k, &[1; 20]);
    let serial = fill.serial();
    let slot = fill.id().slot_index();
    assert_eq!(
        fill.publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
            .err(),
        Some(FillPublishError::Closed)
    );
    conserved_at(&storage, slot, RETIRED);
    assert!(storage.is_closed());
    assert_eq!(sequence(&storage), stable + 2);
    assert_eq!(report(&storage, 0).visible, 1);
    assert_eq!(refs(&storage, incumbent.id()), 2);
    assert_eq!(dev.read(&incumbent), payload(&k, &[0xA; 20]));
    assert_eq!(records(&storage)[0], departed(serial, true));
    assert_eq!(custody(&storage), no_custody());
    conserved_after_service(&storage, slot, FREE);
    drain(&storage);

    let storage = ready(2);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let fill = filled(&storage, &mut dev, &k, &[1; 20]);
    let serial = fill.serial();
    storage.close();
    let mut spent = budget();
    let slot = fill.id().slot_index();
    assert_eq!(
        fill.publish(&mut dev.volume, DEADLINE, TRIES, &mut spent)
            .err(),
        Some(FillPublishError::Closed)
    );
    conserved_at(&storage, slot, RETIRED);
    assert_eq!(spent.counters().hashes, 0);
    assert_eq!(spent.counters().coordination_attempts, 1);
    assert_eq!(records(&storage)[0], departed(serial, false));
    conserved_after_service(&storage, slot, FREE);
}

#[test]
fn a_full_lease_limit_and_a_terminal_shard_refuse_at_reservation_before_any_upload() {
    use super::writable::FillReserveError;
    // The holder's lease takes one of the two credits, so a fill, which
    // reserves two, refuses after returning the one it found.
    let storage = ready_with(3, 2, 8);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let holder = publish(&storage, &mut dev, &key(1), &[1; 20]).unwrap();
    assert_eq!(credits(&storage), 1);
    drain(&storage);
    let stable = sequence(&storage);
    let before = super::writable_tests::partition(&storage);
    let claim = next_claim(&storage, &key(2));
    assert_eq!(
        reserved(&storage, &key(2), &[2; 20]).err(),
        Some(FillReserveError::LeaseLimit)
    );
    returned_claim(&storage, claim);
    assert_eq!(credits(&storage), 1);
    assert_eq!(sequence(&storage), stable);
    assert_eq!(report(&storage, 0).reserved, 0);
    assert_eq!(
        super::writable_tests::partition(&storage),
        before,
        "the extent returned"
    );
    missing(&storage, &key(2));
    drop(holder);
    drain(&storage);
    assert!(publish(&storage, &mut dev, &key(2), &[2; 20]).is_ok());

    let storage = ready(3);
    let control = super::attempt_tests::shard_control(&storage);
    control.sequence.store(TERMINAL - 2, Ordering::SeqCst);
    let claim = next_claim(&storage, &key(3));
    assert_eq!(
        reserved(&storage, &key(3), &[3; 20]).err(),
        Some(FillReserveError::IndexFull)
    );
    returned_claim(&storage, claim);
    assert!(report(&storage, 0).terminal);
    assert_eq!(report(&storage, 0).visible, 0);
    assert_eq!(credits(&storage), 0);
    drain(&storage);
    assert_eq!(
        reserved(&storage, &key(4), &[4; 20]).err(),
        Some(FillReserveError::IndexFull)
    );
}

/// The shard's free-stack entries below its top, read under no writer.
fn free_stack(storage: &Storage<TestPlatform>) -> Vec<usize> {
    let index = storage.index.as_ref().unwrap();
    let shard = index.image.shard(SHARD).unwrap();
    let top = report(storage, 0).free_overflow;
    // SAFETY: the index mapping is live and no gate is held, so this is the
    // only reference into the stack.
    let stack = unsafe { shard.stack(&index.mapping) };
    stack[..top].to_vec()
}

/// A reservation whose chain needs an overflow bucket and that the lease
/// limit refuses leaves the stack, its top and the shard report as they
/// were. Once the held lease ends, the same key pops overflow bucket zero.
#[test]
fn a_lease_limit_refusal_where_a_pop_is_needed_leaves_the_stack_untouched() {
    // Room for a full base bucket and one key beyond it.
    let index = IndexConfig {
        fills: &[16],
        ..index_config(&[16], (1, 1), 1)
    };
    let config = super::config::StorageConfig {
        lease_limit: 2,
        object_rights: 8,
        ..storage_config(20)
    };
    let mut storage = storage_from(&config, &index, TestPlatform::heap(PAGE));
    storage.platform.ticks(&[Some(1)]);
    install_seam(&mut storage, one_chain);
    let buffers = arena_with(4, 17);
    let mut dev = Device::new(&storage, &buffers);
    let geometry = storage.index.as_ref().unwrap().geometry.shards()[0];
    // Fifteen keys of one fingerprint and base bucket, `0x11 >> 4`: fourteen
    // fill the base bucket and the last pops an overflow bucket.
    let keys: [Key; 15] = std::array::from_fn(|n| key(0x11 + n as u8));
    for (n, k) in keys[..13].iter().enumerate() {
        drop(publish(&storage, &mut dev, k, &[n as u8; 20]).unwrap());
    }
    // The fourteenth lease holds one of the two lease credits, so a fill's
    // second credit refuses.
    let held = publish(&storage, &mut dev, &keys[13], &[13; 20]).unwrap();
    drain(&storage);
    let before = (report(&storage, 0), free_stack(&storage));
    assert_eq!(before.0.visible, 14);
    assert_eq!(before.0.free_overflow, geometry.overflow);
    assert_eq!(
        reserved(&storage, &keys[14], &[14; 20]).err(),
        Some(super::writable::FillReserveError::LeaseLimit)
    );
    assert_eq!((report(&storage, 0), free_stack(&storage)), before);
    missing(&storage, &keys[14]);
    drop(held);
    drain(&storage);
    let lease = publish(&storage, &mut dev, &keys[14], &[14; 20]).unwrap();
    assert_eq!(report(&storage, 0).free_overflow, geometry.overflow - 1);
    let index = storage.index.as_ref().unwrap();
    // SAFETY: the index mapping is live and no publisher runs.
    let buckets = unsafe { index.image.shard(SHARD).unwrap().buckets(&index.mapping) };
    assert_eq!(OverflowLink::decode(buckets[1].next()), Some(0));
    assert_eq!(buckets[geometry.base].control(), 1);
    assert!(candidates(&storage, &keys[14]).contains(&lease.id()));
}

/// The shard control the claim observer reads; set before its hook is armed.
static CLAIMS_OF: std::sync::atomic::AtomicPtr<super::shards::ShardControl> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());
/// `P_index` as the claim observer read it.
static CLAIMED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(usize::MAX);

fn observe_claims(_: &std::sync::atomic::AtomicBool) {
    let control = CLAIMS_OF.load(Ordering::SeqCst);
    // SAFETY: the test stores the address of the live shard control before
    // arming the hook, and the storage it lies in outlives the publication
    // that runs the hook.
    let reserved = unsafe { &*control }.reserved.load(Ordering::Relaxed);
    CLAIMED.store(reserved, Ordering::SeqCst);
}

/// A vacant key's lease publication holds exactly one additional-key claim
/// between its walk and its commit: `P_index` reads one at the interposition
/// point before the sequence goes odd, and the commit releases it as it
/// counts the key.
#[test]
fn a_vacant_key_holds_one_claim_until_its_commit() {
    let storage = ready(2);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let control = super::attempt_tests::shard_control(&storage);
    CLAIMS_OF.store(std::ptr::from_ref(control).cast_mut(), Ordering::SeqCst);
    assert_eq!(report(&storage, 0).reserved, 0);
    INTERPOSE_BEFORE_INHIBITION.with(|hook| hook.set(Some(observe_claims)));
    let lease = publish(&storage, &mut dev, &key(1), &[1; 20]).unwrap();
    assert_eq!(CLAIMED.load(Ordering::SeqCst), 1);
    let after = report(&storage, 0);
    assert_eq!((after.reserved, after.visible), (0, 1));
    drop(lease);
}

#[test]
fn the_parked_record_scan_debits_one_visit_per_record() {
    let storage = ready_with(3, 4, 8);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let held = publish(&storage, &mut dev, &key(1), &[1; 20]).unwrap();
    drain(&storage);
    let mut reader = storage.register().unwrap();
    ticks(&storage, &[Some(2), Some(2)]);
    let lease = lookup(&mut reader, &key(1), RETRIES).unwrap();
    assert_eq!(credits(&storage), 2);
    drop(lease);
    assert_eq!(credits(&storage), 1);

    // The reservation replaces `key(1)` while an incumbent lease is live,
    // isolating scan-budget consumption: it takes both of the fill's
    // credits from a parked record once the limit is full.
    let before = scanned();
    let mut spent = budget();
    let mut fill = reserved_with(&storage, &key(1), &[2; 20], &mut spent).unwrap();
    let loaded = scanned() - before;
    assert!(loaded >= 1);
    assert!(spent.counters().visits >= loaded);
    assert_eq!(credits(&storage), 3);
    dev.fill(&mut fill, &payload(&key(1), &[2; 20]));
    let published = fill
        .publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
        .unwrap();
    drain(&storage);

    let lease = lookup(&mut reader, &key(1), RETRIES).unwrap();
    assert_eq!(credits(&storage), 3);
    drop(lease);
    assert_eq!(credits(&storage), 2);
    // The credit alone, at the limit with one parked record: the attempt's
    // compare-exchange, the scan's visit, debited before the record is
    // loaded, then the record's take. One step refuses at the visit with
    // nothing scanned, two load the record and refuse at its take, and
    // three take the credit.
    let before = scanned();
    let mut one = WorkBudget::new(1);
    assert_eq!(
        reserve_credit(&storage, 3, Credit::Shared, &mut one),
        Err(CreditError::BudgetExhausted)
    );
    assert_eq!(
        (scanned() - before, one.counters().coordination_attempts),
        (0, 1)
    );
    let mut two = WorkBudget::new(2);
    assert_eq!(
        reserve_credit(&storage, 3, Credit::Shared, &mut two),
        Err(CreditError::BudgetExhausted)
    );
    assert_eq!((scanned() - before, two.counters().visits), (1, 1));
    assert_eq!(credits(&storage), 2);
    let mut three = WorkBudget::new(3);
    assert_eq!(
        reserve_credit(&storage, 3, Credit::Shared, &mut three),
        Ok(())
    );
    assert_eq!(scanned() - before, 2);
    assert_eq!(three.counters().coordination_attempts, 2);
    assert_eq!(three.remaining(), 0);
    assert_eq!(credits(&storage), 3);
    return_credit(&storage, Credit::Shared);
    assert_eq!(credits(&storage), 2);
    drop(published);
    drop(held);
}

/// A fill's two credits at the limit with nothing parked refuse
/// `LeaseLimit` after one paid exchange, the charge of one credit's refusal,
/// and a budget of that one step still refuses `LeaseLimit`.
#[test]
fn a_fills_credits_at_the_limit_refuse_after_one_exchange() {
    let storage = ready_with(3, 2, 8);
    for _ in 0..2 {
        reserve_credit(&storage, 2, Credit::Shared, &mut budget()).unwrap();
    }
    let mut one = WorkBudget::new(1);
    assert_eq!(
        reserve_shared_credits(&storage, 2, 2, &mut one),
        Err(CreditError::LeaseLimit)
    );
    assert_eq!(one.counters().coordination_attempts, 1);
    assert_eq!(credits(&storage), 2);
    for _ in 0..2 {
        return_credit(&storage, Credit::Shared);
    }
    let mut paid = budget();
    reserve_shared_credits(&storage, 2, 2, &mut paid).unwrap();
    assert_eq!(
        (credits(&storage), paid.counters().coordination_attempts),
        (2, 1)
    );
    for _ in 0..2 {
        return_credit(&storage, Credit::Shared);
    }
}

#[test]
fn only_the_publishers_sample_waits_for_its_earlier_stores() {
    let storage = ready(2);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let k = key(1);
    let fill = filled(&storage, &mut dev, &k, &[1; 20]);
    let (taken, ordered) = (samples(&storage), storage.platform.samples_after_stores());
    let lease = fill
        .publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
        .unwrap();
    // The portable pair's sample after the provider reading, then the publisher's in-hold sample after its odd store.
    assert_eq!(samples(&storage), taken + 2);
    assert_eq!(storage.platform.samples_after_stores(), ordered + 1);
    let mut reader = storage.register().unwrap();
    let hit = lookup(&mut reader, &k, RETRIES).unwrap();
    assert_eq!(samples(&storage), taken + 3);
    assert_eq!(storage.platform.samples_after_stores(), ordered + 1);
    drop(hit);
    drop(lease);
}

#[test]
fn a_publisher_paused_before_its_inhibition_samples_after_the_readers_lookup() {
    static PAUSE: Mutex<Option<Arc<Barrier>>> = Mutex::new(None);
    let storage = ready(2);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let k = key(1);
    let visible = publish(&storage, &mut dev, &key(2), &[2; 20]).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    *PAUSE.lock().unwrap() = Some(Arc::clone(&barrier));
    // A sample taken before the pause would read 9 and publish; the reader's hit consumes 9 and the inhibited sample reads 10.
    ticks(&storage, &[Some(9 * SECOND), Some(10 * SECOND)]);
    let fill = filled(&storage, &mut dev, &k, &[1; 20]);
    let serial = fill.serial();
    let slot = fill.id().slot_index();
    let stable = sequence(&storage);
    // The fill and its volume stay on this thread; the reader runs on
    // another while the publisher waits inside its hook.
    let (outcome, log) = std::thread::scope(|scope| {
        let storage = &storage;
        let k = &k;
        let reader = scope.spawn(move || {
            let barrier = PAUSE.lock().unwrap().clone().unwrap();
            barrier.wait();
            let mut reader = storage.register().unwrap();
            let taken = samples(storage);
            drop(lookup(&mut reader, &key(2), RETRIES).unwrap());
            assert_eq!(samples(storage), taken + 1);
            assert_eq!(
                lookup(&mut reader, k, RETRIES).err(),
                Some(LookupError::Missing)
            );
            barrier.wait();
        });
        INTERPOSE_BEFORE_INHIBITION.with(|hook| {
            hook.set(Some(|_| {
                let barrier = PAUSE.lock().unwrap().clone().unwrap();
                barrier.wait();
                barrier.wait();
            }));
        });
        probe::arm();
        let outcome = fill.publish(&mut dev.volume, 10 * SECOND, TRIES, &mut budget());
        let log = probe::events();
        reader.join().unwrap();
        (outcome.err(), log)
    });
    assert_eq!(outcome, Some(FillPublishError::Expired));
    assert_eq!(
        log.events,
        [
            Event::Inhibit {
                sequence: stable + 1
            },
            Event::Sampled {
                ticks: Some(10 * SECOND)
            },
            Event::Cutoff { closed: false },
            Event::Revoked { serial },
            Event::Committed {
                sequence: stable + 2
            },
            Event::Detached { slot },
        ]
    );
    missing(&storage, &k);
    assert_eq!(custody(&storage), no_custody());
    drop(visible);
}

#[test]
fn every_unwind_cut_leaves_a_known_owner_or_fixed_custody() {
    use Cut::*;
    let cuts = [
        BeforeGate,
        HeldPreCustody,
        DisarmedPreInhibition,
        AfterOdd,
        MidStores,
        AfterEvenPreSettle,
        SettledPreRelease,
        ReleasedPreRetirement,
    ];
    let cases = cuts
        .into_iter()
        .flat_map(|cut| [(cut, false), (cut, true)])
        .filter(|(cut, refused)| !(*refused && *cut == MidStores));
    for (cut, refused) in cases {
        let case = format!("{cut:?} refused={refused}");
        let mut storage = ready_with(2, 16, 8);
        let buffers = arena();
        let mut dev = Device::new(&storage, &buffers);
        let k = key(1);
        let incumbent = publish(&storage, &mut dev, &k, &[1; 20]).unwrap();
        let inc = incumbent.id();
        drain(&storage);
        ticks(&storage, &[Some(if refused { 10 * SECOND } else { 1 })]);
        let stable = sequence(&storage);
        let fill = filled(&storage, &mut dev, &k, &[2; 20]);
        let serial = fill.serial();
        let candidate = fill.id();
        CUT.with(|hook| hook.set(Some(cut)));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fill.publish(&mut dev.volume, 10 * SECOND, TRIES, &mut budget())
        }));
        assert!(outcome.is_err(), "{case}");
        drop(outcome);
        assert_eq!(CUT.with(std::cell::Cell::get), None, "{case}");

        let poisoned = !matches!(cut, BeforeGate | ReleasedPreRetirement);
        assert_eq!(gate(&storage).try_lock().is_err(), poisoned, "{case}");
        let odd = matches!(cut, AfterOdd | MidStores);
        let committed = matches!(
            cut,
            AfterEvenPreSettle | SettledPreRelease | ReleasedPreRetirement
        );
        let published = committed && !refused;
        let terminal = cut == AfterEvenPreSettle;
        let expected = if terminal {
            TERMINAL
        } else {
            stable + u64::from(odd) + 2 * u64::from(committed)
        };
        assert_eq!(sequence(&storage), expected, "{case}");

        let expected_phase = match cut {
            BeforeGate | HeldPreCustody | SettledPreRelease | ReleasedPreRetirement => phase::NONE,
            DisarmedPreInhibition => phase::PREPARED,
            AfterOdd => phase::INHIBITED,
            MidStores => phase::STORED,
            AfterEvenPreSettle if refused => phase::REFUSED,
            AfterEvenPreSettle => phase::COMMITTED,
        };
        let expected_custody = if expected_phase == phase::NONE {
            no_custody()
        } else {
            (
                0,
                serial,
                candidate.slot_index(),
                inc.slot_index(),
                expected_phase,
            )
        };
        assert_eq!(custody(&storage), expected_custody, "{case}");

        // Before settlement the claims stay held under custody. After it a refusal has already returned the anchor, the right and the credit, and a publication's unwind drops the preowned claims, which return the right and the credit and leave the anchor.
        let (candidate_refs, credit_count) = match cut {
            BeforeGate | HeldPreCustody => (0, 1),
            DisarmedPreInhibition | AfterOdd | MidStores | AfterEvenPreSettle => (2, 2),
            SettledPreRelease | ReleasedPreRetirement if refused => (0, 1),
            SettledPreRelease | ReleasedPreRetirement => (1, 1),
        };
        assert_eq!(refs(&storage, candidate), candidate_refs, "{case}");
        assert_eq!(credits(&storage), credit_count, "{case}");
        let expected_record = match cut {
            BeforeGate | HeldPreCustody => departed(serial, false),
            DisarmedPreInhibition | AfterOdd => live(serial),
            MidStores | AfterEvenPreSettle => revoked(serial),
            SettledPreRelease | ReleasedPreRetirement => departed(serial, true),
        };
        assert_eq!(records(&storage)[0], expected_record, "{case}");
        assert_eq!(refs(&storage, inc), 2, "{case}");
        let retired = published && cut != AfterEvenPreSettle;
        let state = storage.slot_state(SlotIndex(inc.slot_index())).map(|s| s.0);
        let expected_state = if retired {
            SlotState::Retired
        } else {
            SlotState::Resident
        };
        assert_eq!(state, Some(expected_state), "{case}");

        let mut reader = storage.register().unwrap();
        ticks(&storage, &[Some(1), Some(1)]);
        let visible = lookup(&mut reader, &k, RETRIES);
        match (odd || terminal, published) {
            (true, _) => assert_eq!(visible.err(), Some(LookupError::Contended), "{case}"),
            (false, false) => assert_eq!(visible.unwrap().id(), inc, "{case}"),
            (false, true) => assert_eq!(visible.unwrap().id(), candidate, "{case}"),
        }
        drop(reader);
        if poisoned {
            assert_eq!(
                storage.service_fills(SHARD, TRIES, &mut budget()).err(),
                Some(FillServiceError::Poisoned),
                "{case}"
            );
            drop(incumbent);
            drop(dev);
            assert_eq!(
                finalize(&mut storage),
                Err(FinalizeError::ShardPoisoned { shard: SHARD }),
                "{case}"
            );
        } else {
            drop(incumbent);
            drain(&storage);
            assert!(
                publish(&storage, &mut dev, &key(2), &[3; 20]).is_ok(),
                "{case}"
            );
        }
    }
}

#[test]
fn publication_allocates_nothing_and_stays_within_its_charge() {
    let storage = ready(2);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let fill = filled(&storage, &mut dev, &key(1), &[1; 20]);
    probe::arm();
    let allocations = crate::instrument::allocations();
    let mut spent = budget();
    let lease = fill
        .publish(&mut dev.volume, DEADLINE, TRIES, &mut spent)
        .unwrap();
    let counts = probe::counts();
    let counters = spent.counters();
    assert_eq!(crate::instrument::allocations(), allocations);
    assert_eq!(counts.gate_taken, 1);
    assert!(counts.loads <= counters.visits + counters.comparisons + counters.updates);
    drop(lease);
    assert_eq!(crate::instrument::allocations(), allocations);
}

/// The volume's domain when nonempty: its index, members head to tail, and
/// detached count.
fn domains(storage: &Storage<TestPlatform>) -> Vec<(usize, Vec<usize>, u32)> {
    let pool = storage.live_pool().unwrap();
    let mut access = pool.lock().unwrap();
    let mut tables = access.tables();
    let detached = tables.domain.detached;
    Some((0, tables.queue().members(), detached))
        .filter(|(_, members, detached)| !members.is_empty() || *detached != 0)
        .into_iter()
        .collect()
}

/// Replacement overlap in the policy domain: publishing B over a leased
/// incumbent A links B and detaches A in the retirement's hold, so the
/// domain holds B alone while A's bytes stay leased; the return clears A.
/// An invalidation whose retirement parks behind a held pool gate leaves B
/// linked until service sights it, and the sighting detaches it once.
#[test]
fn a_replaced_or_invalidated_incumbent_leaves_its_domain_once() {
    let storage = ready(2);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let k = key(1);
    let a = publish(&storage, &mut dev, &k, &[1; 20]).unwrap();
    let a_slot = a.id().slot_index();
    let class = 0;
    assert_eq!(domains(&storage), [(class, vec![a_slot], 0)]);
    let b = publish(&storage, &mut dev, &k, &[2; 20]).unwrap();
    let b_slot = b.id().slot_index();
    assert_eq!(domains(&storage), [(class, vec![b_slot], 1)]);
    assert_eq!(dev.read(&a), payload(&k, &[1; 20]));
    drop(a);
    dev.persist_journal();
    drain(&storage);
    assert_eq!(domains(&storage), [(class, vec![b_slot], 0)]);

    let pool = storage.live_pool().unwrap();
    let held = pool.lock().unwrap();
    invalidate(&storage, &k).unwrap();
    drop(held);
    assert_eq!(
        domains(&storage),
        [(class, vec![b_slot], 0)],
        "a parked retirement"
    );
    let _ = storage.certify(&mut budget()).unwrap();
    storage.service(&mut budget()).unwrap();
    assert_eq!(domains(&storage), [(class, vec![], 1)]);
    drop(b);
    dev.persist_journal();
    drain(&storage);
    assert!(domains(&storage).is_empty());
}

/// A shard whose `N` is one key: the first reservation claims the one
/// place and its fill publishes, and a second reservation refuses
/// `IndexFull` before any upload, its extent returned and its record
/// departed.
/// The refused reservation's slot is `Free` and the tables pass the
/// conservation judge.
#[test]
fn a_full_index_refuses_at_reservation_and_a_reserved_fill_publishes() {
    use super::writable::FillReserveError;
    let fills = [2];
    let index = IndexConfig {
        fills: &fills,
        ..index_config(&[1], (1, 1), 1)
    };
    let storage = storage_from(&storage_config(8), &index, TestPlatform::heap(PAGE));
    storage.platform.ticks(&[Some(1)]);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let mut first = reserved(&storage, &key(1), &[1; 20]).unwrap();
    assert_eq!(report(&storage, 0).reserved, 1);
    let before = super::writable_tests::partition(&storage);
    let claim = next_claim(&storage, &key(2));
    assert_eq!(
        reserved(&storage, &key(2), &[2; 20]).err(),
        Some(FillReserveError::IndexFull)
    );
    returned_claim(&storage, claim);
    assert_eq!(super::writable_tests::partition(&storage), before);
    assert_eq!(credits(&storage), 2, "the first fill's two credits alone");
    dev.fill(&mut first, &payload(&key(1), &[1; 20]));
    let lease = first
        .publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
        .unwrap();
    let after = report(&storage, 0);
    assert_eq!((after.visible, after.reserved), (1, 0));
    assert_eq!(credits(&storage), 1, "the lease took the fill's credit");
    drop(lease);
}

/// Each claim returns once: a refused publication refunds the place and
/// the credit under its hold; an aborted or dropped fill returns its credit
/// at once and service refunds its place; an invalidation refunds a
/// revoked fill's place and the fill returns its credit at its end.
/// The preparation's refusal retires the slot with `ABANDONED`, the tables pass
/// the conservation judge, and one service pass frees the slot.
#[test]
fn every_claim_returns_once_on_refusal_abort_drop_and_invalidation() {
    let storage = ready(4);
    let buffers = arena_with(4, 5);
    let mut dev = Device::new(&storage, &buffers);
    let idle = |storage: &Storage<TestPlatform>| {
        let report = report(storage, 0);
        (report.reserved, report.visible, credits(storage))
    };
    assert_eq!(idle(&storage), (0, 0, 0));

    // A refusal under the hold: the sample is past the deadline.
    let fill = filled(&storage, &mut dev, &key(1), &[1; 20]);
    assert_eq!(idle(&storage), (1, 0, 2));
    assert_eq!(
        fill.publish(&mut dev.volume, 0, TRIES, &mut budget()).err(),
        Some(FillPublishError::Expired)
    );
    assert_eq!(idle(&storage), (0, 0, 0));
    assert_eq!(service(&storage).released, 1);
    assert_eq!(idle(&storage), (0, 0, 0), "nothing refunds twice");

    // Abort and drop: the credit at once, the place once service releases
    // the record.
    for abort in [true, false] {
        let fill = reserved(&storage, &key(2), &[2; 20]).unwrap();
        if abort {
            fill.abort();
        } else {
            drop(fill);
        }
        assert_eq!(idle(&storage), (1, 0, 0));
        assert_eq!(service(&storage).released, 1);
        assert_eq!(idle(&storage), (0, 0, 0));
    }

    // Invalidation: the revoked fill's place under the invalidation's hold,
    // its credit at its end.
    let fill = reserved(&storage, &key(3), &[3; 20]).unwrap();
    assert!(invalidate(&storage, &key(3)).unwrap().revoked.is_some());
    assert_eq!(idle(&storage), (0, 0, 2));
    drop(fill);
    assert_eq!(idle(&storage), (0, 0, 0));
    assert_eq!(service(&storage).released, 1);
    assert_eq!(idle(&storage), (0, 0, 0), "nothing refunds twice");

    // A refusal from the preparation, after custody names the claims: the
    // shard went terminal between the reservation and its publication.
    let fill = filled(&storage, &mut dev, &key(4), &[4; 20]);
    assert_eq!(idle(&storage), (1, 0, 2));
    assert_eq!(pending_lanes(&storage), 1);
    super::attempt_tests::shard_control(&storage)
        .sequence
        .store(TERMINAL - 2, Ordering::SeqCst);
    let slot = fill.id().slot_index();
    assert_eq!(
        fill.publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
            .err(),
        Some(FillPublishError::IndexFull)
    );
    conserved_at(&storage, slot, RETIRED);
    assert!(report(&storage, 0).terminal);
    assert_eq!(idle(&storage), (0, 0, 0));
    assert_eq!(pending_lanes(&storage), 0);
    conserved_after_service(&storage, slot, FREE);
    assert_eq!(service(&storage).released, 1);
    assert_eq!(idle(&storage), (0, 0, 0), "nothing refunds twice");
}

/// An invalidation of the key while its replacement uploads removes the
/// incumbent and revokes the replacement; a removal of the incumbent alone
/// leaves no incumbent, so the replacement inserts through the place it
/// claimed at reservation.
#[test]
fn an_incumbent_removed_during_upload_is_replaced_through_the_claimed_place() {
    let storage = ready(4);
    let buffers = arena_with(4, 5);
    let mut dev = Device::new(&storage, &buffers);
    let k = key(1);
    let incumbent = publish(&storage, &mut dev, &k, &[1; 20]).unwrap();
    drain(&storage);
    let mut fill = reserved(&storage, &k, &[2; 20]).unwrap();
    assert_eq!(report(&storage, 0).reserved, 1);
    drop(incumbent);
    // The invalidation ends the incumbent's mapping and revokes the current
    // attempt; a new attempt on the key claims its own place.
    let invalidated = invalidate(&storage, &k).unwrap();
    assert!(invalidated.removed.is_some() && invalidated.revoked.is_some());
    drop(fill);
    drain(&storage);
    assert_eq!(report(&storage, 0).visible, 0);
    let incumbent = publish(&storage, &mut dev, &k, &[3; 20]).unwrap();
    fill = reserved(&storage, &k, &[4; 20]).unwrap();
    // A removal of the incumbent alone keeps the attempt current.
    let id = incumbent.id();
    drop(incumbent);
    drain(&storage);
    storage.remove(&k, id, TRIES, &mut budget()).unwrap();
    assert!(candidates(&storage, &k).is_empty());
    dev.fill(&mut fill, &payload(&k, &[4; 20]));
    let lease = fill
        .publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
        .unwrap();
    assert_eq!(candidates(&storage, &k), [lease.id()]);
    let after = report(&storage, 0);
    assert_eq!((after.visible, after.reserved), (1, 0));
    drop(lease);
}

/// A publication that claims its place only at publication, the test-only
/// `Completed` path, can reach Ready and then find the index full: the
/// planted late claim refuses `IndexFull` after the record is complete,
/// which the reservation's early claim rules out.
#[test]
fn negative_control_a_late_claim_lets_a_ready_object_refuse_index_full() {
    let fills = [2];
    let index = IndexConfig {
        fills: &fills,
        ..index_config(&[1], (1, 1), 1)
    };
    let storage = storage_from(&storage_config(8), &index, TestPlatform::heap(PAGE));
    storage.platform.ticks(&[Some(1)]);
    let held = reserved(&storage, &key(1), &[1; 20]).unwrap();
    let late = storage.reserve(Some(4), Some(20), &mut budget()).unwrap();
    let ready = late.complete(key(2), u64::MAX, &mut budget()).unwrap();
    let refused = ready
        .publish(TRIES, &mut budget())
        .err()
        .map(|(_, error)| error);
    assert_eq!(
        refused,
        Some(super::PublishError::IndexFull),
        "a ready object refused IndexFull"
    );
    drop(held);
}

/// Pending lanes in the shard's buckets, read under no writer.
fn pending_lanes(storage: &Storage<TestPlatform>) -> usize {
    let index = storage.index.as_ref().unwrap();
    // SAFETY: the index mapping is live and no gate is held.
    let buckets = unsafe { index.image.shard(SHARD).unwrap().buckets(&index.mapping) };
    buckets
        .iter()
        .map(|bucket| {
            (0..crate::index::PAIRS)
                .filter(|&pair| crate::index::is_pending(bucket.control(), pair))
                .count()
        })
        .sum()
}

/// A reserved control bit fails closed on a publication its shard's
/// sequence refuses: a fill whose pending pair sits in a bucket whose
/// control word carries a reserved bit, published after its shard went
/// terminal, refuses as corrupt with the pair still pending and the gate
/// poisoned, as the service pass does for the same bucket. A refund there
/// would free a lane in a bucket every chain walk refuses.
#[test]
fn a_terminal_publication_refuses_a_reserved_bit_in_the_claimed_bucket() {
    let storage = ready(4);
    let buffers = arena_with(4, 5);
    let mut dev = Device::new(&storage, &buffers);
    let fill = filled(&storage, &mut dev, &key(1), &[1; 20]);
    let index = storage.index.as_ref().unwrap();
    // SAFETY: the index mapping is live and no gate is held.
    let buckets = unsafe { index.image.shard(SHARD).unwrap().buckets(&index.mapping) };
    let (claimed, pair) = buckets
        .iter()
        .find_map(|bucket| {
            (0..crate::index::PAIRS)
                .find(|&pair| crate::index::is_pending(bucket.control(), pair))
                .map(|pair| (bucket, pair))
        })
        .expect("the fill's pending pair");
    let planted = claimed.control() | 1 << 60;
    claimed.corrupt(planted, claimed.next());
    super::attempt_tests::shard_control(&storage)
        .sequence
        .store(TERMINAL - 2, Ordering::SeqCst);
    let refused = fill
        .publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
        .err();
    let after = claimed.control();
    let poisoned = gate(&storage).is_poisoned();
    assert_eq!(
        (refused, poisoned, after),
        (Some(FillPublishError::Corrupt), true, planted),
        "a reserved control bit in the claimed bucket fails closed"
    );
    assert!(crate::index::is_pending(after, pair));
}

/// A replacement reserved while `V = N` refuses `IndexFull` before any
/// upload, the incumbent visible and nothing claimed; a replacement with
/// room activates nothing and frees its pending pair, and an insert
/// activates its pair, so no pending lane outlives a publication.
#[test]
fn a_full_index_replacement_refuses_early_and_no_pending_lane_outlives_publication() {
    use super::writable::FillReserveError;
    let fills = [2];
    let index = IndexConfig {
        fills: &fills,
        ..index_config(&[1], (1, 1), 1)
    };
    let storage = storage_from(&storage_config(8), &index, TestPlatform::heap(PAGE));
    storage.platform.ticks(&[Some(1)]);
    let buffers = arena();
    let mut dev = Device::new(&storage, &buffers);
    let incumbent = publish(&storage, &mut dev, &key(1), &[1; 20]).unwrap();
    assert_eq!(pending_lanes(&storage), 0, "the insert activated its pair");
    drain(&storage);
    let before = super::writable_tests::partition(&storage);
    assert_eq!(
        reserved(&storage, &key(1), &[2; 20]).err(),
        Some(FillReserveError::IndexFull)
    );
    assert_eq!(super::writable_tests::partition(&storage), before);
    assert_eq!(candidates(&storage, &key(1)), [incumbent.id()]);
    assert_eq!((report(&storage, 0).reserved, credits(&storage)), (0, 1));
    drop(incumbent);

    let storage = ready(4);
    let buffers = arena_with(4, 5);
    let mut dev = Device::new(&storage, &buffers);
    let first = publish(&storage, &mut dev, &key(1), &[1; 20]).unwrap();
    drain(&storage);
    let fill = filled(&storage, &mut dev, &key(1), &[2; 20]);
    assert_eq!(pending_lanes(&storage), 1);
    let second = fill
        .publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
        .unwrap();
    assert_eq!(pending_lanes(&storage), 0, "the replacement freed its pair");
    assert_eq!(candidates(&storage, &key(1)), [second.id()]);
    drop((first, second));
}

/// A reservation that pops and links an overflow bucket and then ends
/// leaves the bucket linked when service refunds its pair; the chain's next
/// reservation takes that bucket's free pair without a second pop.
#[test]
fn a_refunded_pair_in_a_popped_bucket_is_the_chains_next_place() {
    let index = IndexConfig {
        fills: &[16],
        ..index_config(&[16], (1, 1), 1)
    };
    let config = super::config::StorageConfig {
        lease_limit: 16,
        object_rights: 8,
        ..storage_config(20)
    };
    let mut storage = storage_from(&config, &index, TestPlatform::heap(PAGE));
    storage.platform.ticks(&[Some(1)]);
    install_seam(&mut storage, one_chain);
    let buffers = arena_with(4, 17);
    let mut dev = Device::new(&storage, &buffers);
    let keys: [Key; 16] = std::array::from_fn(|n| key(0x11 + n as u8));
    let mut held = Vec::new();
    for (n, k) in keys[..14].iter().enumerate() {
        held.push(publish(&storage, &mut dev, k, &[n as u8; 20]).unwrap());
    }
    drain(&storage);
    let full = report(&storage, 0).free_overflow;
    let popped = reserved(&storage, &keys[14], &[14; 20]).unwrap();
    assert_eq!(
        report(&storage, 0).free_overflow,
        full - 1,
        "the reservation popped a bucket"
    );
    popped.abort();
    drain(&storage);
    assert_eq!(pending_lanes(&storage), 0);
    assert_eq!(
        report(&storage, 0).free_overflow,
        full - 1,
        "the bucket stays linked"
    );
    let fill = reserved(&storage, &keys[15], &[15; 20]).unwrap();
    assert_eq!(report(&storage, 0).free_overflow, full - 1, "no second pop");
    assert_eq!(pending_lanes(&storage), 1);
    drop(fill);
    drop(held);
}

/// A reservation whose chain needs an overflow bucket takes one sequence
/// bracket for the link and leaves publication its own: with two brackets
/// of room it publishes, and with one it refuses `IndexFull` before any
/// upload, the stack, the sequence and the credit count untouched.
/// The refused reservation's slot is `Free` and the tables pass the
/// conservation judge.
#[test]
fn a_pop_reserves_sequence_room_for_its_link_and_its_publication() {
    use super::writable::FillReserveError;
    let index = IndexConfig {
        fills: &[16],
        ..index_config(&[16], (1, 1), 1)
    };
    let config = super::config::StorageConfig {
        lease_limit: 16,
        object_rights: 8,
        ..storage_config(20)
    };
    let mut storage = storage_from(&config, &index, TestPlatform::heap(PAGE));
    storage.platform.ticks(&[Some(1)]);
    install_seam(&mut storage, one_chain);
    let buffers = arena_with(4, 17);
    let mut dev = Device::new(&storage, &buffers);
    // Fifteen keys of one base bucket, `0x11 >> 4`: fourteen fill it and
    // the last pops an overflow bucket.
    let keys: [Key; 15] = std::array::from_fn(|n| key(0x11 + n as u8));
    let mut held = Vec::new();
    for (n, k) in keys[..14].iter().enumerate() {
        held.push(publish(&storage, &mut dev, k, &[n as u8; 20]).unwrap());
    }
    drain(&storage);
    let control = super::attempt_tests::shard_control(&storage);
    control.sequence.store(TERMINAL - 4, Ordering::SeqCst);
    let before = (report(&storage, 0), free_stack(&storage), credits(&storage));
    let claim = next_claim(&storage, &keys[14]);
    assert_eq!(
        reserved(&storage, &keys[14], &[14; 20]).err(),
        Some(FillReserveError::IndexFull),
        "one bracket of room is the publication's"
    );
    returned_claim(&storage, claim);
    assert_eq!(
        (report(&storage, 0), free_stack(&storage), credits(&storage)),
        before
    );
    assert!(!report(&storage, 0).terminal);
    assert_eq!(sequence(&storage), TERMINAL - 4);
    assert_eq!(pending_lanes(&storage), 0);
    missing(&storage, &keys[14]);

    drain(&storage);
    control.sequence.store(TERMINAL - 6, Ordering::SeqCst);
    held.push(publish(&storage, &mut dev, &keys[14], &[14; 20]).unwrap());
    assert_eq!(sequence(&storage), TERMINAL - 2);
    assert!(!report(&storage, 0).terminal);
    assert_eq!(
        report(&storage, 0).free_overflow,
        before.0.free_overflow - 1
    );
    drop(held);
}

/// A place word the table contradicts, naming a pair that is not pending
/// or a claim the shard does not count, is a malformed table: publication
/// refuses `Corrupt` before its bracket, poisons the gate and returns the
/// credit, and an invalidation of the key refuses `Corrupt` before its
/// bracket with the sequence even and the mapping intact.
/// Each publication refused `Corrupt` retires its slot with `ABANDONED`, the
/// tables pass the conservation judge, and one service pass frees the slot.
#[test]
fn a_place_word_the_table_contradicts_refuses_corrupt_before_the_bracket() {
    for counted in [true, false] {
        let storage = ready(2);
        let buffers = arena_with(4, 3);
        let mut dev = Device::new(&storage, &buffers);
        let fill = filled(&storage, &mut dev, &key(1), &[1; 20]);
        let control = super::attempt_tests::shard_control(&storage);
        if counted {
            let index = storage.index.as_ref().unwrap();
            // SAFETY: the index mapping is live and no gate is held.
            let buckets = unsafe { index.image.shard(SHARD).unwrap().buckets(&index.mapping) };
            let pending = buckets
                .iter()
                .find_map(|bucket| {
                    (0..crate::index::PAIRS)
                        .find(|&pair| crate::index::is_pending(bucket.control(), pair))
                        .map(|pair| (bucket, pair))
                })
                .unwrap();
            assert!(pending.0.cancel_pair(pending.1));
        } else {
            control.reserved.store(0, Ordering::Relaxed);
        }
        let stable = sequence(&storage);
        assert_eq!(
            invalidate(&storage, &key(1)).err(),
            Some(super::InvalidateError::Corrupt),
            "counted={counted}"
        );
        assert!(gate(&storage).is_poisoned());
        assert_eq!(sequence(&storage), stable, "the bracket never opened");
        assert_eq!(credits(&storage), 2, "the fill keeps its credits");
        drop(fill);
    }
    for counted in [true, false] {
        let storage = ready(2);
        let buffers = arena_with(4, 3);
        let mut dev = Device::new(&storage, &buffers);
        let fill = filled(&storage, &mut dev, &key(1), &[1; 20]);
        assert_eq!((report(&storage, 0).reserved, credits(&storage)), (1, 2));
        let control = super::attempt_tests::shard_control(&storage);
        if counted {
            let index = storage.index.as_ref().unwrap();
            // SAFETY: the index mapping is live and no gate is held.
            let buckets = unsafe { index.image.shard(SHARD).unwrap().buckets(&index.mapping) };
            let pending = buckets
                .iter()
                .find_map(|bucket| {
                    (0..crate::index::PAIRS)
                        .find(|&pair| crate::index::is_pending(bucket.control(), pair))
                        .map(|pair| (bucket, pair))
                })
                .unwrap();
            assert!(pending.0.cancel_pair(pending.1));
        } else {
            control.reserved.store(0, Ordering::Relaxed);
        }
        let stable = sequence(&storage);
        let slot = fill.id().slot_index();
        assert_eq!(
            fill.publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
                .err(),
            Some(FillPublishError::Corrupt),
            "counted={counted}"
        );
        conserved_at(&storage, slot, RETIRED);
        assert!(gate(&storage).is_poisoned());
        assert_eq!(sequence(&storage), stable, "the bracket never opened");
        assert_eq!(report(&storage, 0).visible, 0);
        assert_eq!(credits(&storage), 0, "the credits returned");
        conserved_after_service(&storage, slot, FREE);
    }
}

/// A place word names the pending pair its own fill reserved. A word that
/// names another fill's pending pair is a malformed table: publication
/// refuses `Corrupt` before its bracket and poisons the gate, with both
/// pairs still pending, both additional-key claims counted and zero
/// visible keys. The sibling keeps its word and publishes, spending its
/// one place.
#[test]
fn a_place_word_naming_another_fills_pending_pair_refuses_corrupt_before_the_bracket() {
    use super::place_claim::Claimed;
    for foreign in [false, true] {
        let storage = ready(2);
        let buffers = arena_with(4, 3);
        let mut dev = Device::new(&storage, &buffers);
        let table = storage.fill_table(SHARD).unwrap();
        let claims = |storage: &Storage<TestPlatform>| -> Vec<(usize, Claimed)> {
            // SAFETY: the storage is live and this single-threaded test is the
            // only path into the place words while the borrow lasts.
            let places = unsafe { storage.fill_hold(table) }.places;
            places
                .iter()
                .enumerate()
                .filter_map(|(at, &word)| Claimed::of(word).map(|claimed| (at, claimed)))
                .collect()
        };
        let fill = filled(&storage, &mut dev, &key(1), &[1; 20]);
        let own = claims(&storage);
        assert_eq!(own.len(), 1);
        let other = reserved(&storage, &key(2), &[2; 20]).unwrap();
        let both = claims(&storage);
        assert_eq!(both.len(), 2);
        let theirs = both.iter().find(|claim| **claim != own[0]).unwrap().1;
        assert_ne!(theirs, own[0].1);
        if foreign {
            // SAFETY: as above.
            unsafe { storage.fill_hold(table) }.places[own[0].0] = theirs.word();
        }
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fill.publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
                .map(|lease| lease.id())
        }));
        let poisoned = gate(&storage).is_poisoned();
        let state = (
            report(&storage, 0).reserved,
            report(&storage, 0).visible,
            pending_lanes(&storage),
        );
        std::mem::forget(other);
        if !foreign {
            assert!(outcome.unwrap().is_ok());
            assert_eq!((poisoned, state), (false, (1, 1, 1)));
            continue;
        }
        let shown = match outcome {
            Ok(result) => format!("returned {result:?}"),
            Err(panic) => panic
                .downcast_ref::<&str>()
                .map(|text| text.to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_default(),
        };
        assert_eq!(
            (shown.as_str(), poisoned, state),
            ("returned Err(Corrupt)", true, (2, 0, 2)),
        );
    }
}

/// A fill publication that replaces an incumbent an in-flight capture pass must still save copies the incumbent's
/// entry under the shard gate, the capture mutex and the pool gate. `Pool::capture_entry_into` panics under the pool
/// gate when the slot does not own its complete extent sequence, and the gate module states the rule for the pool and
/// shard gates: "A holder that panics poisons the gate on release". A plain guard taken by a thread that was already
/// unwinding releases unpoisoned on drop. The publication arms its three holds, the shard and pool gates with
/// `poison_on_unwind` and the capture guard with `PoisonOnUnwind`, so each poisons its lock as the panic unwinds
/// through it: the outcome is the same from a plain call and from a destructor that catches the panic while its
/// thread unwinds from another.
///
/// Control: with the incumbent's locator intact the same publication succeeds from both callers and poisons nothing.
#[test]
fn an_incumbent_save_panic_poisons_every_lock_of_a_fill_publication_even_during_unwinding() {
    struct RunsOnDrop<F: FnMut()>(F);
    impl<F: FnMut()> Drop for RunsOnDrop<F> {
        fn drop(&mut self) {
            // The copy's panic, when there is one, is judged below by the locks it leaves.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (self.0)()));
        }
    }
    for (corrupt, unwinding) in [(false, false), (false, true), (true, false), (true, true)] {
        let case = format!("corrupt={corrupt} unwinding={unwinding}");
        let storage = ready(4);
        let buffers = arena_with(4, 5);
        let mut dev = Device::new(&storage, &buffers);
        let k = key(1);
        let incumbent = publish(&storage, &mut dev, &k, &[0xA; 20]).unwrap();
        drain(&storage);
        let pool = storage.live_pool().unwrap();
        let record = &pool.records()[incumbent.id().slot_index()];
        let intact = record.locator();
        if corrupt {
            let unowned = super::held::Held::Sequence {
                block: super::blocks::Block(0),
                count: 2,
            };
            record.set_locator(unowned.locator());
        }
        storage.start_capture(8, true, 8).unwrap();
        let fill = filled(&storage, &mut dev, &k, &[4; 20]);
        ticks(&storage, &[Some(1)]);
        let published = std::cell::Cell::new(false);
        {
            let mut fill = Some(fill);
            let volume = &mut dev.volume;
            let mut publish = || {
                let lease = fill
                    .take()
                    .unwrap()
                    .publish(volume, DEADLINE, TRIES, &mut budget());
                published.set(lease.is_ok());
            };
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if unwinding {
                    let _publisher = RunsOnDrop(&mut publish);
                    panic!("an unrelated panic with a live publisher");
                }
                publish();
            }));
            // The premise: the corrupt arms panic in the copy, and the unwinding arms in the unrelated panic.
            assert_eq!(outcome.is_err(), corrupt || unwinding, "{case}");
        }
        assert_eq!(published.get(), !corrupt, "{case}");
        let expected = corrupt.then_some(super::gate::GateError::Poisoned);
        assert_eq!(gate(&storage).try_lock().is_err(), corrupt, "{case}");
        assert_eq!(pool.try_lock_quiet().err(), expected, "{case}");
        assert_eq!(pool.capture_lock().err(), expected, "{case}");
        record.set_locator(intact);
    }
}
/// `every_unwind_cut_leaves_a_known_owner_or_fixed_custody` holds an unwind at each cut inside the publication's shard hold to a poisoned shard gate (`gate.rs`: "A holder that panics poisons the gate on release"). The same unwind in a publication made by a destructor, while its thread unwinds from another panic, leaves the same gate: the shard guard, taken during the unwind, would otherwise release open on drop over the custody record and the odd sequence the cut left.
///
/// Sibling: the plain call, whose unwind poisons the gate at every one of these cuts.
#[test]
fn an_unwind_cut_poisons_the_shard_gate_of_a_fill_publication_even_during_unwinding() {
    struct RunsOnDrop<F: FnMut()>(F);
    impl<F: FnMut()> Drop for RunsOnDrop<F> {
        fn drop(&mut self) {
            // The cut's panic is judged below by the gate it leaves.
            let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (self.0)()));
            assert!(
                caught.is_err(),
                "premise: the publication unwinds at its cut"
            );
        }
    }
    use Cut::*;
    let cuts = [
        HeldPreCustody,
        DisarmedPreInhibition,
        AfterOdd,
        MidStores,
        AfterEvenPreSettle,
        SettledPreRelease,
    ];
    let mut open = Vec::new();
    for (cut, unwinding) in cuts.into_iter().flat_map(|cut| [(cut, false), (cut, true)]) {
        let storage = ready_with(2, 16, 8);
        let buffers = arena();
        let mut dev = Device::new(&storage, &buffers);
        let k = key(1);
        let incumbent = publish(&storage, &mut dev, &k, &[1; 20]).unwrap();
        drain(&storage);
        ticks(&storage, &[Some(1)]);
        let fill = filled(&storage, &mut dev, &k, &[2; 20]);
        CUT.with(|hook| hook.set(Some(cut)));
        {
            let mut fill = Some(fill);
            let volume = &mut dev.volume;
            let mut publish = || {
                drop(
                    fill.take()
                        .unwrap()
                        .publish(volume, 10 * SECOND, TRIES, &mut budget()),
                );
            };
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if unwinding {
                    let _publisher = RunsOnDrop(&mut publish);
                    panic!("an unrelated panic with a live publisher");
                }
                publish();
            }));
            assert!(outcome.is_err(), "premise: {cut:?} unwinding={unwinding}");
        }
        assert_eq!(
            CUT.with(std::cell::Cell::get),
            None,
            "premise: the cut was reached"
        );
        if gate(&storage).try_lock().is_ok() {
            open.push((cut, unwinding, sequence(&storage), custody(&storage).4));
        }
        std::mem::forget(incumbent);
    }
    assert_eq!(
        open,
        [],
        "(cut, unwinding, sequence, custody phase) of each publication whose unwind left its shard gate open"
    );
}
