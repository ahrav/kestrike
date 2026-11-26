//! Tests of fill followers: joins in both orders against publication, the
//! exact retained version through replacement, eviction and expiry, late
//! joins refused once the version's mapping ended, every producer terminal
//! under the follower mapping, the terminal read right's credit from Ready to
//! its last return and across publication's unwind cuts, the row's release
//! after its last observer, a reused slot's successor refused, and planted
//! controls for a fingerprint-only join and a failed join reported as
//! published.
//!
//! Expected outcomes come from an independent oracle: the history of what
//! each producer did, recorded by the test as it drives the producer, and
//! the payload bytes the test streamed for each version. A follower's
//! outcome and bytes are checked against that history, never against a
//! production counter.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::attempt_tests::{
    begin, departed, fill_serial, gate, invalidate, live, records, service, shard_control,
};
use super::budget::{WorkBudget, WorkKind};
use super::fill::{self, FIRST_SERIAL, Record};
use super::join::{INTERPOSE_AFTER_JOIN, PLANT, Plant};
use super::owner::Storage;
use super::probe;
use super::publication::{CUT, Cut};
use super::publication_tests::{
    DEADLINE, SECOND, credits, drain, filled, payload, publish, ready_with, reserved,
};
use super::publish_tests::{TRIES, budget, install_seam, key, one_fingerprint, refs};
use super::row::{self, Terminal};
use super::test_platform::TestPlatform;
use super::volume_fixture::{Device, ample_io, arena_with, read_back};
use super::{
    AllocationId, ExtentLease, FillEnd, FillFailure, FillFollower, FillPublishError, JoinError,
    JoinedReadError, JoinedVersion, ObserveError, Observed, ReadStatus, SlotIndex, SlotState,
    WorkCounters,
};
use crate::index::{HASH_CHARGE, Key, ShardIndex, TERMINAL};

const SHARD: ShardIndex = ShardIndex(0);
/// A per-fill follower limit no test reaches.
pub(super) const FOLLOWERS: u64 = u64::MAX;

/// One shard of four fill records, lease limit 16 and eight rights per
/// object.
fn ready() -> Storage<TestPlatform> {
    ready_with(4, 16, 8)
}

fn join<'s>(storage: &'s Storage<TestPlatform>, key: &Key) -> FillFollower<'s, TestPlatform> {
    storage
        .join_fill(key, FOLLOWERS, TRIES, &mut budget())
        .unwrap()
}

fn observe(follower: &FillFollower<'_, TestPlatform>) -> Observed {
    follower.observe(TRIES, &mut budget()).unwrap()
}

fn ended(follower: &FillFollower<'_, TestPlatform>) -> FillEnd {
    match observe(follower) {
        Observed::Ended(end) => end,
        Observed::Pending => panic!("the producer has ended"),
    }
}

fn version_of(follower: &FillFollower<'_, TestPlatform>) -> JoinedVersion {
    match ended(follower) {
        FillEnd::Published(version) => version,
        other => panic!("expected a published version, got {other:?}"),
    }
}

fn acquire(follower: FillFollower<'_, TestPlatform>) -> ExtentLease<'_, TestPlatform> {
    follower
        .acquire(TRIES, &mut budget())
        .map_err(|(_, error)| error)
        .unwrap()
}

fn refused(
    follower: FillFollower<'_, TestPlatform>,
) -> (FillFollower<'_, TestPlatform>, JoinedReadError) {
    follower.acquire(TRIES, &mut budget()).unwrap_err()
}

fn state(storage: &Storage<TestPlatform>, id: AllocationId) -> Option<SlotState> {
    storage.slot_state(SlotIndex(id.slot_index())).map(|s| s.0)
}

/// Returns every retired slot whose rights ended, without servicing fill
/// records.
fn drain_slots(storage: &Storage<TestPlatform>) {
    for _ in 0..8 {
        let _ = storage.certify(&mut WorkBudget::new(1 << 10)).unwrap();
        storage.service(&mut WorkBudget::new(1 << 10)).unwrap();
    }
}

/// What a producer did, as the test drove it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Produced {
    /// Published this allocation, whose payload is these bytes.
    Published(AllocationId, Vec<u8>),
    /// Ended without publishing and without a recorded failure.
    Missing,
    /// Ended with this recorded failure.
    Failed(FillFailure),
}

/// The independent oracle: each attempt's history by `(key, serial)`.
#[derive(Default)]
struct History {
    produced: HashMap<(Key, u64), Produced>,
}

/// Why the history rejected a follower.
#[derive(Debug, PartialEq, Eq)]
enum Rejected {
    /// The follower's key has no attempt of that serial.
    NoAttempt,
    /// The follower read another allocation than the one published.
    Allocation,
    /// The follower read bytes other than the version's.
    Bytes,
    /// The follower's end differs from the producer's.
    Outcome,
}

impl History {
    fn record(&mut self, key: Key, serial: u64, produced: Produced) {
        assert!(
            self.produced.insert((key, serial), produced).is_none(),
            "one outcome per attempt"
        );
    }

    /// Checks a follower of `key` that joined attempt `serial`, ended with
    /// `end` and, for a published end, read `bytes`.
    fn check(
        &self,
        key: &Key,
        serial: u64,
        end: FillEnd,
        bytes: Option<&[u8]>,
    ) -> Result<(), Rejected> {
        let produced = self
            .produced
            .get(&(*key, serial))
            .ok_or(Rejected::NoAttempt)?;
        match (produced, end) {
            (Produced::Published(id, payload), FillEnd::Published(version)) => {
                if version.id() != *id {
                    return Err(Rejected::Allocation);
                }
                if bytes != Some(&payload[..]) {
                    return Err(Rejected::Bytes);
                }
                Ok(())
            }
            (Produced::Missing, FillEnd::Missing) => Ok(()),
            (Produced::Failed(failure), FillEnd::Failed(seen)) if *failure == seen => Ok(()),
            _ => Err(Rejected::Outcome),
        }
    }
}

/// A follower that joined before the publication and one that joined after
/// it both read the producer's exact version, and the history accepts both.
#[test]
fn a_join_reads_the_producers_exact_version_in_both_orders() {
    let storage = ready();
    let buffers = arena_with(4, 5);
    let mut dev = Device::new(&storage, &buffers);
    let mut history = History::default();
    let k = key(1);
    let body = [7; 20];

    let fill = filled(&storage, &mut dev, &k, &body);
    let serial = fill.serial();
    let before = join(&storage, &k);
    assert_eq!(before.serial(), serial);
    assert_eq!(observe(&before), Observed::Pending);
    let lease = fill
        .publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
        .unwrap();
    let id = lease.id();
    history.record(k, serial, Produced::Published(id, payload(&k, &body)));
    let after = join(&storage, &k);
    assert_eq!(after.serial(), serial, "the departed publication is joined");

    for follower in [before, after] {
        let end = ended(&follower);
        let FillEnd::Published(version) = end else {
            panic!("expected a version, got {end:?}");
        };
        assert_eq!(
            (version.metadata_len(), version.body_len()),
            (4, body.len() as u32)
        );
        let read = acquire(follower);
        assert_eq!(read.id(), id);
        let bytes = dev.read(&read);
        history.check(&k, serial, end, Some(&bytes)).unwrap();
    }
    drop(lease);
}

/// The row of a fill a follower joined retains the version's right and the
/// terminal credit, so the follower reads the exact version after an
/// immediate replacement, while eviction passes the object over, and after
/// an expiry sweep, whose expired version the follower then refuses.
#[test]
fn a_retained_version_survives_immediate_replacement_eviction_and_expiry() {
    let storage = ready();
    let buffers = arena_with(4, 5);
    let mut dev = Device::new(&storage, &buffers);
    let mut history = History::default();
    let k = key(1);

    // Replacement: the follower joined the first fill, a second fill of the
    // key publishes over it at once.
    let first = filled(&storage, &mut dev, &k, &[1; 20]);
    let serial = first.serial();
    let follower = join(&storage, &k);
    let lease = first
        .publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
        .unwrap();
    let id = lease.id();
    history.record(k, serial, Produced::Published(id, payload(&k, &[1; 20])));
    assert_eq!(
        refs(&storage, id),
        3,
        "the anchor, the publisher and the row"
    );
    assert_eq!(credits(&storage), 2, "the lease's credit and the row's");
    drop(lease);
    let successor = publish(&storage, &mut dev, &k, &[2; 20]).unwrap();
    assert_ne!(successor.id(), id);
    let row = storage.fill_row(SHARD, 0);
    assert_eq!(
        (row.record, row.observers, row.allocation),
        (departed(serial, true), 1, id)
    );
    assert_eq!(
        row.terminal,
        Terminal::Published {
            retained: true,
            expires_at_s: u32::MAX
        }
    );
    drain(&storage);
    assert_eq!(
        state(&storage, id),
        Some(SlotState::Retired),
        "the replaced object is held by the row's right"
    );
    let end = ended(&follower);
    let read = acquire(follower);
    history
        .check(&k, serial, end, Some(&dev.read(&read)))
        .unwrap();
    drop((read, successor));

    // Eviction: the row's right holds the object, so SIEVE passes it while
    // the follower is joined; once the follower read and detached and the
    // row was freed, the object is evicted and its slot returns.
    let k2 = key(2);
    let fill = filled(&storage, &mut dev, &k2, &[3; 20]);
    let serial = fill.serial();
    let follower = join(&storage, &k2);
    let lease = fill
        .publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
        .unwrap();
    let id = lease.id();
    history.record(k2, serial, Produced::Published(id, payload(&k2, &[3; 20])));
    drop(lease);
    drain(&storage);
    for _ in 0..4 {
        let report = storage
            .evict_step(&mut super::evict_tests::generous(), |_, _| true)
            .unwrap();
        let evicted = matches!(
            report.commit,
            Some(super::evict::Commit::Evicted { victim, .. }) if victim == id
        );
        assert!(!evicted, "the held object is passed over");
    }
    assert_eq!(state(&storage, id), Some(SlotState::Resident));
    let end = ended(&follower);
    let read = acquire(follower);
    history
        .check(&k2, serial, end, Some(&dev.read(&read)))
        .unwrap();
    drop(read);
    drain(&storage);
    evict(&storage, id);
    dev.persist_journal();
    drain(&storage);
    dev.persist_journal();
    drain(&storage);
    assert_eq!(
        state(&storage, id),
        Some(SlotState::Free),
        "the evicted slot returned once the row's right ended"
    );

    // Expiry: the row's right holds the expired object, so the sweep passes
    // it over while the follower is joined; the follower refuses the
    // version as expired, and once the row is freed the sweep removes it.
    let k3 = key(3);
    let fill = filled(&storage, &mut dev, &k3, &[4; 20]);
    let follower = join(&storage, &k3);
    let lease = fill
        .publish(&mut dev.volume, 5 * SECOND, TRIES, &mut budget())
        .unwrap();
    let id = lease.id();
    drop(lease);
    storage.platform.ticks(&[Some(6 * SECOND)]);
    let sweep = |storage: &Storage<TestPlatform>| {
        for _ in 0..4 {
            storage
                .expire_step(&mut super::evict_tests::generous())
                .unwrap();
        }
    };
    sweep(&storage);
    drain(&storage);
    assert_eq!(state(&storage, id), Some(SlotState::Resident));
    let (follower, error) = refused(follower);
    assert_eq!(error, JoinedReadError::Expired);
    assert_eq!(credits(&storage), 1, "the row's credit alone");
    assert_eq!(refs(&storage, id), 2, "the anchor and the row's right");
    drop(follower);
    drain(&storage);
    sweep(&storage);
    dev.persist_journal();
    drain(&storage);
    assert_eq!(state(&storage, id), Some(SlotState::Free));
    assert_eq!(credits(&storage), 0);
}

/// Evicts `id`'s object through SIEVE steps, which clear its visited bit
/// first when a read set it.
fn evict(storage: &Storage<TestPlatform>, id: AllocationId) {
    for _ in 0..4 {
        storage
            .evict_step(&mut super::evict_tests::generous(), |_, _| true)
            .unwrap();
        if state(storage, id) == Some(SlotState::Retired) {
            return;
        }
    }
    panic!("the object was not evicted");
}

/// A late join reaches a publication only while its object is the key's
/// mapping: after a replacement the late reader joins the successor, and
/// after a removal it joins nothing, even while an earlier follower's row
/// and another lease still hold the removed object. A late follower whose
/// version was removed and whose slot was reused reports it missing and
/// gains no right on the successor.
#[test]
fn a_late_join_follows_only_the_current_mapping() {
    let storage = ready();
    let buffers = arena_with(4, 5);
    let mut dev = Device::new(&storage, &buffers);
    let k = key(1);
    let fill = filled(&storage, &mut dev, &k, &[1; 20]);
    let early = join(&storage, &k);
    let first = fill
        .publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
        .unwrap();
    let second = publish(&storage, &mut dev, &k, &[2; 20]).unwrap();
    let late = join(&storage, &k);
    assert_eq!(
        acquire(late).id(),
        second.id(),
        "a late reader joins the successor"
    );
    assert!(invalidate(&storage, &k).unwrap().removed.is_some());
    assert_eq!(
        storage.join_fill(&k, FOLLOWERS, TRIES, &mut budget()).err(),
        Some(JoinError::NoFill),
        "a removed mapping is joined by no later reader"
    );
    let read = acquire(early);
    assert_eq!(
        read.id(),
        first.id(),
        "the early follower keeps its version"
    );
    drop((read, first, second));

    // Slot reuse: a late follower of an unretained publication, then the
    // removal, the slot's return and its reuse by a successor.
    let storage = ready();
    let mut dev = Device::new(&storage, &buffers);
    let k = key(1);
    let lease = publish(&storage, &mut dev, &k, &[1; 20]).unwrap();
    let old = lease.id();
    let follower = join(&storage, &k);
    drop(lease);
    invalidate(&storage, &k).unwrap();
    dev.persist_journal();
    drain_slots(&storage);
    assert_eq!(state(&storage, old), Some(SlotState::Free));
    let mut held = Vec::new();
    let successor = loop {
        service(&storage);
        let lease = publish(&storage, &mut dev, &key(0x40 + held.len() as u8), &[3; 20]).unwrap();
        if lease.id().slot_index() == old.slot_index() {
            break lease;
        }
        held.push(lease);
        assert!(held.len() < 8, "a free slot is reused");
    };
    assert_ne!(successor.id(), old, "a new incarnation");
    let before = (refs(&storage, successor.id()), credits(&storage));
    let (follower, error) = refused(follower);
    assert_eq!(error, JoinedReadError::Missing);
    assert_eq!(
        (refs(&storage, successor.id()), credits(&storage)),
        before,
        "the successor gained no right and every credit returned"
    );
    drop((follower, successor, held));
}

/// Every producer terminal reaches its followers through the mapping: an
/// abort, a drop, a revocation and a supersession, an expired publication
/// report missing; a recorded failure and each refused publication's typed
/// failure report that failure. A revoked record stays pending until its
/// producer departs, and a revoked producer records no failure.
#[test]
fn each_producer_terminal_reaches_its_followers_through_the_mapping() {
    let storage = ready();
    let buffers = arena_with(4, 5);
    let mut dev = Device::new(&storage, &buffers);
    let mut history = History::default();
    let k = key(1);
    let follow = |history: &mut History, follower| followed(&storage, history, &k, follower);

    for abort in [true, false] {
        let fill = reserved(&storage, &k, &[1; 20]).unwrap();
        let follower = join(&storage, &k);
        history.record(k, fill.serial(), Produced::Missing);
        if abort {
            fill.abort();
        } else {
            drop(fill);
        }
        follow(&mut history, follower);
    }
    for failure in [
        FillFailure::DeviceError,
        FillFailure::TimedOut,
        FillFailure::Closed,
        FillFailure::OwnerUnavailable,
        FillFailure::StoragePressure,
    ] {
        let fill = reserved(&storage, &k, &[1; 20]).unwrap();
        let follower = join(&storage, &k);
        assert_eq!(observe(&follower), Observed::Pending);
        history.record(k, fill.serial(), Produced::Failed(failure));
        fill.fail(failure);
        follow(&mut history, follower);
    }

    // A revocation: pending until the revoked producer departs, which
    // records no failure.
    let fill = reserved(&storage, &k, &[1; 20]).unwrap();
    let follower = join(&storage, &k);
    history.record(k, fill.serial(), Produced::Missing);
    assert!(invalidate(&storage, &k).unwrap().revoked.is_some());
    assert_eq!(observe(&follower), Observed::Pending);
    fill.fail(FillFailure::DeviceError);
    follow(&mut history, follower);

    // A supersession: the invalidation revoked a complete fill, whose
    // publication then refuses.
    let fill = filled(&storage, &mut dev, &k, &[2; 20]);
    let follower = join(&storage, &k);
    history.record(k, fill.serial(), Produced::Missing);
    assert!(invalidate(&storage, &k).unwrap().revoked.is_some());
    assert_eq!(
        fill.publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
            .err(),
        Some(FillPublishError::Superseded)
    );
    follow(&mut history, follower);

    // Refused publications: an expired deadline, a missing sample, a busy
    // gate, an incomplete record.
    for (samples, deadline, produced) in [
        (Some(10 * SECOND), 10 * SECOND, Produced::Missing),
        (
            None,
            DEADLINE,
            Produced::Failed(FillFailure::ClockUnavailable),
        ),
    ] {
        let fill = filled(&storage, &mut dev, &k, &[2; 20]);
        let follower = join(&storage, &k);
        history.record(k, fill.serial(), produced);
        storage.platform.ticks(&[samples]);
        assert!(
            fill.publish(&mut dev.volume, deadline, TRIES, &mut budget())
                .is_err()
        );
        storage.platform.ticks(&[Some(1)]);
        follow(&mut history, follower);
    }
    let fill = filled(&storage, &mut dev, &k, &[2; 20]);
    let follower = join(&storage, &k);
    history.record(k, fill.serial(), Produced::Failed(FillFailure::Contended));
    let held = gate(&storage).lock().unwrap();
    assert_eq!(
        fill.publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
            .err(),
        Some(FillPublishError::Contended)
    );
    drop(held);
    follow(&mut history, follower);
    let mut short = reserved(&storage, &k, &[2; 20]).unwrap();
    assert_eq!(short.receive(&mut dev.volume, &[1], &mut ample_io()), Ok(1));
    let follower = join(&storage, &k);
    history.record(
        k,
        short.serial(),
        Produced::Failed(FillFailure::DeviceError),
    );
    assert_eq!(
        short
            .publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
            .err(),
        Some(FillPublishError::Incomplete)
    );
    follow(&mut history, follower);

    // A terminal shard's publication refuses for room.
    let fill = filled(&storage, &mut dev, &k, &[2; 20]);
    let follower = join(&storage, &k);
    history.record(
        k,
        fill.serial(),
        Produced::Failed(FillFailure::ObjectPressure),
    );
    shard_control(&storage)
        .sequence
        .store(TERMINAL - 2, Ordering::SeqCst);
    assert_eq!(
        fill.publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
            .err(),
        Some(FillPublishError::IndexFull)
    );
    follow(&mut history, follower);

    // The closed cutoff, on a fresh storage, whose serials start again.
    let storage = ready();
    let mut dev = Device::new(&storage, &buffers);
    let mut history = History::default();
    let fill = filled(&storage, &mut dev, &k, &[2; 20]);
    let follower = join(&storage, &k);
    history.record(k, fill.serial(), Produced::Failed(FillFailure::Closed));
    storage.close();
    assert_eq!(
        fill.publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
            .err(),
        Some(FillPublishError::Closed)
    );
    followed(&storage, &mut history, &k, follower);

    // A lost volume, on a fresh storage and device: the loss stays with the volume.
    let storage = ready();
    let mut dev = Device::new(&storage, &buffers);
    let mut history = History::default();
    let fill = filled(&storage, &mut dev, &k, &[2; 20]);
    let follower = join(&storage, &k);
    assert_eq!(observe(&follower), Observed::Pending);
    history.record(
        k,
        fill.serial(),
        Produced::Failed(FillFailure::OwnerUnavailable),
    );
    dev.lose();
    assert_eq!(
        fill.publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
            .err(),
        Some(FillPublishError::Lost)
    );
    followed(&storage, &mut history, &k, follower);
}

/// A refused publication revokes its record under its hold and departs
/// after the hold, so a follower observing in between finds the record
/// revoked, undeparted and its failure recorded: it stays pending, then
/// reports the failure at the departure.
#[test]
fn a_refusal_revoked_before_its_departure_reports_its_failure() {
    use std::cell::Cell;
    thread_local! {
        static SEEN: Cell<Option<Observed>> = const { Cell::new(None) };
    }
    let storage: &'static Storage<TestPlatform> = Box::leak(Box::new(ready()));
    let buffers: &'static _ = Box::leak(Box::new(arena_with(4, 5)));
    let mut dev = Device::new(storage, buffers);
    let k = key(1);
    let fill = filled(storage, &mut dev, &k, &[1; 20]);
    let follower: &'static FillFollower<'static, TestPlatform> =
        Box::leak(Box::new(join(storage, &k)));
    super::publication::REFUSAL_WINDOW.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(|| {
            SEEN.with(|seen| seen.set(Some(observe(follower))))
        }));
    });
    storage.platform.ticks(&[None]);
    assert_eq!(
        fill.publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
            .err(),
        Some(FillPublishError::ClockUnavailable)
    );
    assert_eq!(
        SEEN.with(Cell::get),
        Some(Observed::Pending),
        "inside the window"
    );
    assert!(matches!(
        storage.fill_row(SHARD, 0).record,
        Record::Occupied {
            departed: true,
            revoked: true,
            ..
        }
    ));
    assert_eq!(
        ended(follower),
        FillEnd::Failed(FillFailure::ClockUnavailable)
    );
}

/// A join beyond the caller's per-fill limit refuses with the count
/// unchanged; a detach makes room for the next.
#[test]
fn a_join_past_the_follower_limit_refuses() {
    let storage = ready();
    let k = key(1);
    let fill = reserved(&storage, &k, &[1; 20]).unwrap();
    let first = storage.join_fill(&k, 2, TRIES, &mut budget()).unwrap();
    let second = storage.join_fill(&k, 2, TRIES, &mut budget()).unwrap();
    assert_eq!(
        storage.join_fill(&k, 2, TRIES, &mut budget()).err(),
        Some(JoinError::FollowerLimit)
    );
    assert_eq!(storage.fill_row(SHARD, 0).observers, 2);
    drop(first);
    let third = storage.join_fill(&k, 2, TRIES, &mut budget()).unwrap();
    fill.fail(FillFailure::TimedOut);
    // An acquisition of an ended, unpublished record returns its outcome.
    let (third, error) = refused(third);
    assert_eq!(error, JoinedReadError::Failed(FillFailure::TimedOut));
    drop((second, third));
    assert_eq!(service(&storage).released, 1);
}

/// A row whose terminal no writer forms ends the service pass as corrupt
/// with its record occupied and its gate poisoned.
#[test]
fn service_refuses_a_malformed_row_and_keeps_its_record() {
    let storage = ready();
    let fill = reserved(&storage, &key(1), &[1; 20]).unwrap();
    let table = storage.fill_table(SHARD).unwrap();
    // SAFETY: the storage is live and only atomics are written; no gate
    // holder runs.
    let view = unsafe { storage.fill_view(table) };
    view.rows[0].record_failure(FillFailure::Closed);
    drop(fill);
    // A failure word with an unknown cause.
    let word = row::failed(FillFailure::Closed) & !(0xFF << 8) | 0xEE << 8;
    view.rows[0].plant_terminal(word);
    assert!(matches!(
        storage.service_fills(SHARD, TRIES, &mut budget()),
        Err(super::FillServiceError::Corrupt(_))
    ));
    assert!(gate(&storage).is_poisoned());
    let next = view.control.next_serial.load();
    let record = fill::decode(view.states[0].load(Ordering::Acquire), next).unwrap();
    assert!(record.is_departed(), "the record stays occupied");
}

/// Every follower of a record whose word turned malformed observes
/// `Corrupt`: the first observation poisons the gate, and the next finds
/// the gate poisoned over the same malformed word.
#[test]
fn every_follower_of_a_malformed_record_observes_corrupt() {
    let storage = ready();
    let fill = reserved(&storage, &key(1), &[1; 20]).unwrap();
    let (first, second) = (join(&storage, &key(1)), join(&storage, &key(1)));
    storage
        .fill_state(SHARD, 0)
        .store(fill::occupied(fill_serial(99)), Ordering::Relaxed);
    assert_eq!(
        first.observe(TRIES, &mut budget()),
        Err(ObserveError::Corrupt)
    );
    assert!(gate(&storage).is_poisoned());
    assert_eq!(
        second.observe(TRIES, &mut budget()),
        Err(ObserveError::Corrupt),
        "the gate poisoned over the malformed word"
    );
    drop((first, second, fill));
}

/// Checks `follower`'s end against `history`, detaches it, and checks that
/// service frees its record and every credit came back once.
fn followed(
    storage: &Storage<TestPlatform>,
    history: &mut History,
    key: &Key,
    follower: FillFollower<'_, TestPlatform>,
) {
    let serial = follower.serial();
    let end = ended(&follower);
    history.check(key, serial, end, None).unwrap();
    drop(follower);
    assert_eq!(service(storage).released, 1);
    assert_eq!(credits(storage), 0, "every credit returned once");
}

/// Ready holds the terminal read right's credit beside the publisher's: a
/// shortage refuses before the upload grant, every refusal and end returns
/// both once, an unjoined publication returns the terminal credit at once,
/// and a joined one moves it to the row, which returns it with its right
/// once after the last observer.
#[test]
fn ready_holds_terminal_read_right_capacity_and_every_claim_returns_once() {
    // Three credits: a fill takes two, so a second fill's second credit
    // refuses and returns the first.
    let storage = ready_with(4, 3, 8);
    let buffers = arena_with(4, 5);
    let mut dev = Device::new(&storage, &buffers);
    let fill = filled(&storage, &mut dev, &key(1), &[1; 20]);
    assert_eq!(credits(&storage), 2);
    assert_eq!(
        reserved(&storage, &key(2), &[2; 20]).err(),
        Some(super::FillReserveError::LeaseLimit)
    );
    assert_eq!(
        credits(&storage),
        2,
        "the refused fill returned its first credit"
    );
    assert_eq!(
        storage
            .join_fill(&key(2), FOLLOWERS, TRIES, &mut budget())
            .err(),
        Some(JoinError::NoFill),
        "the refused fill was never upload-granted"
    );
    assert_eq!(service(&storage).released, 1, "the refused fill's record");

    let first = join(&storage, &key(1));
    let second = join(&storage, &key(1));
    assert_eq!(storage.fill_row(SHARD, 0).observers, 2);
    let lease = fill
        .publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
        .unwrap();
    let id = lease.id();
    drop(lease);
    assert_eq!(credits(&storage), 1, "the row's credit");
    assert_eq!(refs(&storage, id), 2, "the anchor and the row's right");

    // The row stays while any follower is joined.
    drop(first);
    assert_eq!(service(&storage).released, 0);
    assert_eq!(storage.fill_row(SHARD, 0).observers, 1);
    let read = acquire(second);
    assert_eq!(storage.fill_row(SHARD, 0).observers, 0);
    assert_eq!(refs(&storage, id), 3);
    assert_eq!(service(&storage).released, 1);
    assert_eq!(refs(&storage, id), 2, "the row's right returned");
    assert_eq!(credits(&storage), 1, "the read's credit alone");
    assert_eq!(service(&storage).released, 0, "nothing returns twice");
    assert_eq!(refs(&storage, id), 2);
    drop(read);
    assert_eq!(credits(&storage), 0);
    assert_eq!(refs(&storage, id), 1);
}

/// A joined publication claims no credit: with every credit reserved, the
/// publisher's lease and the row keep the two the reservation took.
#[test]
fn a_joined_publication_claims_no_credit_at_the_limit() {
    let storage = ready_with(4, 3, 8);
    let buffers = arena_with(4, 5);
    let mut dev = Device::new(&storage, &buffers);
    let other = publish(&storage, &mut dev, &key(2), &[2; 20]).unwrap();
    drain(&storage);
    let fill = filled(&storage, &mut dev, &key(1), &[1; 20]);
    assert_eq!(credits(&storage), 3, "every credit reserved");
    let follower = join(&storage, &key(1));
    let lease = fill
        .publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
        .unwrap();
    assert_eq!(
        credits(&storage),
        3,
        "the lease and the row hold the fill's two"
    );
    assert_eq!(refs(&storage, lease.id()), 3);
    drop((follower, lease, other));
    assert_eq!(service(&storage).released, 1);
    assert_eq!(credits(&storage), 0);
}

/// With every lease credit held, a follower's lease acquisition refuses
/// `LeaseLimit` and keeps the follower, while its read-credit acquisition
/// takes the right alone and reaches the published version.
#[test]
fn a_followers_read_right_needs_no_lease_credit() {
    let storage = ready_with(4, 3, 8);
    let buffers = arena_with(4, 5);
    let mut dev = Device::new(&storage, &buffers);
    let other = publish(&storage, &mut dev, &key(2), &[2; 20]).unwrap();
    drain(&storage);
    let fill = filled(&storage, &mut dev, &key(1), &[1; 20]);
    let follower = join(&storage, &key(1));
    let lease = fill
        .publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
        .unwrap();
    assert_eq!(credits(&storage), 3, "every credit held");
    let (follower, error) = refused(follower);
    assert_eq!(error, JoinedReadError::LeaseLimit);
    let right = follower
        .acquire_right(TRIES, &mut budget())
        .map_err(|(_, error)| error)
        .unwrap();
    assert_eq!(right.id(), lease.id(), "the published version's right");
    assert_eq!(credits(&storage), 3, "the right takes no credit");
    assert_eq!(
        refs(&storage, lease.id()),
        4,
        "anchor, lease, row and right"
    );
    drop((right, lease, other));
}

/// A departed record whose retained right names a slot past the pool makes
/// service's refund panic under the shard gate (`release_right`, "# Panics":
/// "If `id`'s slot is outside `storage`'s slot table"), and the panic
/// poisons the gate (gate module doc: "A holder that panics poisons the gate
/// on release"). That holds also for a pass made by a destructor while its
/// thread unwinds from another panic, whose guard was taken during the
/// unwind.
#[test]
fn a_retained_right_past_the_pool_poisons_the_shard_gate_even_during_unwinding() {
    struct ServicesOnDrop<'d> {
        storage: &'d Storage<TestPlatform>,
        panicked: &'d std::cell::Cell<bool>,
    }
    impl Drop for ServicesOnDrop<'_> {
        fn drop(&mut self) {
            let storage = self.storage;
            let serviced = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                storage.service_fills(SHARD, TRIES, &mut budget())
            }));
            self.panicked.set(serviced.is_err());
        }
    }
    for unwinding in [false, true] {
        let storage = ready();
        let buffers = arena_with(4, 5);
        let mut dev = Device::new(&storage, &buffers);
        let fill = filled(&storage, &mut dev, &key(1), &[1; 20]);
        let follower = join(&storage, &key(1));
        let lease = fill
            .publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
            .unwrap();
        let slots = storage.live().unwrap().0.records().len();
        let fills = storage.fill_table(SHARD).unwrap();
        // SAFETY: the storage is live and only atomics are written; no gate
        // holder runs.
        let view = unsafe { storage.fill_view(fills) };
        assert_eq!(view.rows[0].retained(), Ok(Some(lease.id().record_tag())));
        let past = AllocationId::new(SlotIndex(slots), lease.id().incarnation());
        let Ok(super::row::Terminal::Published { expires_at_s, .. }) = view.rows[0].terminal()
        else {
            panic!("premise: the leader's row is published");
        };
        let (metadata_len, body_len) = view.rows[0].lengths();
        view.rows[0].mark_ready(past.record_tag(), metadata_len, body_len);
        view.rows[0].plant_terminal(super::row::published(expires_at_s, true));
        drop(follower);
        let panicked = std::cell::Cell::new(false);
        let caller = ServicesOnDrop {
            storage: &storage,
            panicked: &panicked,
        };
        if unwinding {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _caller = caller;
                panic!("an unrelated panic with a live caller");
            }));
            assert!(outcome.is_err());
        } else {
            drop(caller);
        }
        assert!(
            panicked.get(),
            "premise: the refund panicked, unwinding={unwinding}"
        );
        assert!(
            gate(&storage).is_poisoned(),
            "the refund's panic poisons the shard gate, unwinding={unwinding}"
        );
        drop(lease);
    }
}

/// A panic after the join increments the observer count leaves the interest
/// counted without a follower to release it. The panic poisons the shard
/// gate even when a destructor acquired the guard during an earlier unwind.
#[test]
fn a_join_that_panics_after_its_count_poisons_the_shard_gate_even_during_unwinding() {
    struct JoinsOnDrop<'d> {
        storage: &'d Storage<TestPlatform>,
        panicked: &'d std::cell::Cell<bool>,
    }
    impl Drop for JoinsOnDrop<'_> {
        fn drop(&mut self) {
            let storage = self.storage;
            let joined = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                drop(storage.join_fill(&key(1), FOLLOWERS, TRIES, &mut budget()));
            }));
            self.panicked.set(joined.is_err());
        }
    }
    for unwinding in [false, true] {
        let storage = ready();
        let fill = reserved(&storage, &key(1), &[1; 20]).unwrap();
        INTERPOSE_AFTER_JOIN.with(|hook| {
            hook.set(Some(|| panic!("a panic after the join's count")));
        });
        let panicked = std::cell::Cell::new(false);
        let caller = JoinsOnDrop {
            storage: &storage,
            panicked: &panicked,
        };
        if unwinding {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _caller = caller;
                panic!("an unrelated panic with a live caller");
            }));
            assert!(outcome.is_err());
        } else {
            drop(caller);
        }
        assert!(
            panicked.get(),
            "premise: the join panicked, unwinding={unwinding}"
        );
        assert_eq!(
            storage.fill_row(SHARD, 0).observers,
            1,
            "premise: the join counted its interest, unwinding={unwinding}"
        );
        assert!(
            gate(&storage).is_poisoned(),
            "the join's panic poisons the shard gate, unwinding={unwinding}"
        );
        drop(fill);
    }
}

#[test]
fn a_joined_acquisition_after_close_refuses_and_returns_its_reservations() {
    let storage = ready();
    let buffers = arena_with(4, 5);
    let mut dev = Device::new(&storage, &buffers);
    let fill = filled(&storage, &mut dev, &key(1), &[1; 20]);
    let follower = join(&storage, &key(1));
    let lease = fill
        .publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
        .unwrap();
    let id = lease.id();
    drop(lease);
    assert_eq!((credits(&storage), refs(&storage, id)), (1, 2));

    storage.close();
    let (follower, error) = refused(follower);
    assert_eq!(error, JoinedReadError::Closed);
    assert_eq!(
        (credits(&storage), refs(&storage, id)),
        (1, 2),
        "the row's credit and right alone"
    );
    assert_eq!(storage.fill_row(SHARD, 0).observers, 1);
    drop(follower);
    assert_eq!(service(&storage).released, 1);
    assert_eq!((credits(&storage), refs(&storage, id)), (0, 1));
}

/// Joins reach only upload-granted fills of the exact key, the most recent
/// joinable one first; an acquisition before the publication refuses
/// unpublished, and one at or past the object's deadline refuses expired,
/// each with its reservations returned.
#[test]
fn joins_take_only_upload_granted_fills_of_the_exact_key() {
    let mut storage = ready();
    install_seam(&mut storage, one_fingerprint);
    let buffers = arena_with(4, 5);
    let mut dev = Device::new(&storage, &buffers);
    let (k1, k2) = (key(0x10), key(0x11));
    assert_eq!(
        storage.route(&k1).unwrap().fingerprint(),
        storage.route(&k2).unwrap().fingerprint()
    );
    let attempt = super::attempt_tests::begin(&storage, &k1).unwrap();
    assert_eq!(
        storage
            .join_fill(&k1, FOLLOWERS, TRIES, &mut budget())
            .err(),
        Some(JoinError::NoFill),
        "a granted attempt holds no object yet"
    );
    drop(attempt);
    assert_eq!(service(&storage).released, 1);
    let fill = filled(&storage, &mut dev, &k1, &[1; 20]);
    assert_eq!(
        storage
            .join_fill(&k2, FOLLOWERS, TRIES, &mut budget())
            .err(),
        Some(JoinError::NoFill),
        "an equal fingerprint of another key is not joined"
    );
    drop(join(&storage, &k1));
    drop(fill);

    let storage = ready();
    let mut dev = Device::new(&storage, &buffers);
    let k = key(1);
    let fill = filled(&storage, &mut dev, &k, &[1; 20]);
    let first = join(&storage, &k);
    let second = join(&storage, &k);
    let (first, error) = refused(first);
    assert_eq!(error, JoinedReadError::Pending);
    let lease = fill
        .publish(&mut dev.volume, 5 * SECOND, TRIES, &mut budget())
        .unwrap();
    let id = lease.id();
    assert_eq!(version_of(&first).expires_at_s(), 5);
    // A newer upload of the key beside the retained publication: a new
    // reader joins the newer attempt, the earlier followers keep theirs.
    let newer = filled(&storage, &mut dev, &k, &[2; 20]);
    let third = join(&storage, &k);
    assert_eq!(third.serial(), newer.serial());
    assert_eq!(version_of(&first).id(), id);
    let before = (credits(&storage), refs(&storage, id));
    storage.platform.ticks(&[Some(5 * SECOND)]);
    let (second, error) = refused(second);
    assert_eq!(error, JoinedReadError::Expired);
    assert_eq!(
        (credits(&storage), refs(&storage, id)),
        before,
        "the refused acquisition returned what it reserved"
    );
    drop(second);
    storage.platform.ticks(&[Some(SECOND)]);
    let read = acquire(first);
    assert_eq!(dev.read(&read), payload(&k, &[1; 20]));
    drop((read, lease, third, newer));
}

/// An unwind at each publication cut with a follower joined leaves every
/// claim with a known owner: before custody the drop guard returns both
/// credits and the record departs with no outcome; under custody the claims
/// stay held; after settlement the row keeps its right and credit, which
/// service returns once after the follower read and detached.
#[test]
fn every_unwind_cut_with_a_follower_keeps_the_rows_claims_owned() {
    use Cut::*;
    for (cut, expected) in [
        (BeforeGate, (0, 0)),
        (HeldPreCustody, (0, 0)),
        (DisarmedPreInhibition, (3, 2)),
        (AfterOdd, (3, 2)),
        (MidStores, (3, 2)),
        (AfterEvenPreSettle, (3, 2)),
        (SettledPreRelease, (2, 1)),
        (ReleasedPreRetirement, (2, 1)),
    ] {
        let storage = ready();
        let buffers = arena_with(4, 5);
        let mut dev = Device::new(&storage, &buffers);
        let k = key(1);
        let fill = filled(&storage, &mut dev, &k, &[1; 20]);
        let id = fill.id();
        let follower = join(&storage, &k);
        CUT.with(|hook| hook.set(Some(cut)));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fill.publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
        }));
        assert!(outcome.is_err(), "{cut:?}");
        drop(outcome);
        assert_eq!((refs(&storage, id), credits(&storage)), expected, "{cut:?}");
        if matches!(cut, BeforeGate | ReleasedPreRetirement) {
            let end = ended(&follower);
            if cut == BeforeGate {
                assert_eq!(end, FillEnd::Missing);
                drop(follower);
            } else {
                let read = acquire(follower);
                assert_eq!(dev.read(&read), payload(&k, &[1; 20]));
                drop(read);
            }
            assert_eq!(service(&storage).released, 1, "{cut:?}");
            assert_eq!(credits(&storage), 0, "{cut:?}");
            assert_eq!(service(&storage).released, 0, "{cut:?}");
        } else {
            assert!(gate(&storage).is_poisoned(), "{cut:?}");
            // The follower reads its record without the gate, so the
            // poisoned shard still reports an undeparted record as pending
            // and a departed one by the terminal its departure fixed.
            match cut {
                HeldPreCustody => assert_eq!(ended(&follower), FillEnd::Missing),
                SettledPreRelease => {
                    let read = acquire(follower);
                    assert_eq!(dev.read(&read), payload(&k, &[1; 20]));
                    continue;
                }
                _ => assert_eq!(observe(&follower), Observed::Pending, "{cut:?}"),
            }
            drop(follower);
        }
    }
}

/// Observation and acquisition read the record while another holder has
/// the shard gate, and an observation pays no gate attempt.
#[test]
fn observation_and_acquisition_decide_while_the_gate_is_held() {
    let storage = ready();
    let buffers = arena_with(4, 5);
    let mut dev = Device::new(&storage, &buffers);
    let k = key(1);
    let fill = filled(&storage, &mut dev, &k, &[5; 20]);
    let follower = join(&storage, &k);
    let held = gate(&storage).lock().unwrap();
    let mut spent = budget();
    assert_eq!(follower.observe(0, &mut spent), Ok(Observed::Pending));
    assert_eq!(spent.counters().coordination_attempts, 0);
    drop(held);
    let lease = fill
        .publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
        .unwrap();
    let held = gate(&storage).lock().unwrap();
    let read = acquire(follower);
    drop(held);
    assert_eq!(read.id(), lease.id());
    assert_eq!(dev.read(&read), payload(&k, &[5; 20]));
    drop((read, lease));
}

/// Joins, observations and acquisitions allocate nothing, and a follower's
/// detach leaves no count behind.
#[test]
fn follower_paths_allocate_nothing() {
    let storage = ready();
    let buffers = arena_with(4, 5);
    let mut dev = Device::new(&storage, &buffers);
    let k = key(1);
    let fill = filled(&storage, &mut dev, &k, &[1; 20]);
    let allocations = crate::instrument::allocations();
    let follower = join(&storage, &k);
    let idle = join(&storage, &k);
    assert_eq!(observe(&follower), Observed::Pending);
    assert_eq!(crate::instrument::allocations(), allocations);
    let lease = fill
        .publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
        .unwrap();
    let allocations = crate::instrument::allocations();
    let read = acquire(follower);
    idle.detach();
    assert_eq!(crate::instrument::allocations(), allocations);
    assert_eq!(storage.fill_row(SHARD, 0).observers, 0);
    drop((read, lease));
    assert_eq!(service(&storage).released, 1);
    assert_eq!(storage.fill_row(SHARD, 0).record, Record::Free);
    let again = super::attempt_tests::begin(&storage, &k).unwrap();
    assert_eq!(storage.fill_row(SHARD, 0).record, live(again.serial()));
    assert_eq!(storage.fill_row(SHARD, 0).terminal, Terminal::Granted);
}

/// The planted fingerprint-only join follows another key's fill, which the
/// history rejects as an attempt the follower's key never made, and whose
/// bytes the volume's header check withholds; the production join refuses
/// the other key.
#[test]
fn negative_control_a_fingerprint_join_fails_the_history() {
    let mut storage = ready();
    install_seam(&mut storage, one_fingerprint);
    let buffers = arena_with(4, 5);
    let mut dev = Device::new(&storage, &buffers);
    let mut history = History::default();
    let (k1, k2) = (key(0x10), key(0x11));
    let fill = filled(&storage, &mut dev, &k1, &[1; 20]);
    let serial = fill.serial();
    assert_eq!(
        storage
            .join_fill(&k2, FOLLOWERS, TRIES, &mut budget())
            .err(),
        Some(JoinError::NoFill)
    );
    PLANT.with(|plant| plant.set(Some(Plant::FingerprintJoin)));
    let wrong = storage.join_fill(&k2, FOLLOWERS, TRIES, &mut budget());
    PLANT.with(|plant| plant.set(None));
    let wrong = wrong.unwrap();
    let lease = fill
        .publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
        .unwrap();
    history.record(
        k1,
        serial,
        Produced::Published(lease.id(), payload(&k1, &[1; 20])),
    );
    let end = ended(&wrong);
    assert!(matches!(end, FillEnd::Published(_)));
    let read = acquire(wrong);
    assert_eq!(
        history.check(&k2, serial, end, None),
        Err(Rejected::NoAttempt),
        "the history must reject a follower of another key"
    );
    let delivered = read_back(&mut dev.volume, &dev.control, &read);
    assert_ne!(delivered.status, ReadStatus::Complete);
    drop((read, lease));
}

/// The planted observation reports a recorded failure as a publication,
/// which the history rejects; the production observation reports the
/// failure.
#[test]
fn negative_control_a_failed_join_reported_as_published_fails_the_history() {
    let storage = ready();
    let mut history = History::default();
    let k = key(1);
    let fill = reserved(&storage, &k, &[1; 20]).unwrap();
    let serial = fill.serial();
    let planted = join(&storage, &k);
    let honest = join(&storage, &k);
    history.record(k, serial, Produced::Failed(FillFailure::DeviceError));
    fill.fail(FillFailure::DeviceError);
    PLANT.with(|plant| plant.set(Some(Plant::FailedAsPublished)));
    let end = ended(&planted);
    PLANT.with(|plant| plant.set(None));
    assert_eq!(
        history.check(&k, serial, end, None),
        Err(Rejected::Outcome),
        "the history must reject a failed join reported as published"
    );
    history.check(&k, serial, ended(&honest), None).unwrap();
}

/// `reader`'s incumbent-first search for `key`.
fn seek<'s>(
    reader: &mut super::Registration<'s, TestPlatform>,
    key: &Key,
) -> Result<super::Sought<'s, TestPlatform>, super::SoughtError> {
    reader.lookup_or_join(key, FOLLOWERS, 4, TRIES, &mut budget())
}

/// Whether `id`'s slot word carries the visited bit.
fn visited(storage: &Storage<TestPlatform>, id: AllocationId) -> bool {
    storage.live_pool().unwrap().word(id.slot_index()) & super::word::VISITED != 0
}

/// A reader is served incumbent first: a visible object is leased even
/// while a fill of its key uploads, a missing key joins its fill, and a key
/// with neither is missing.
#[test]
fn an_incumbent_hit_wins_over_a_concurrent_fill() {
    let storage = ready();
    let buffers = arena_with(4, 5);
    let mut dev = Device::new(&storage, &buffers);
    let mut reader = storage.register().unwrap();
    let k = key(1);
    assert_eq!(
        seek(&mut reader, &k).err(),
        Some(super::SoughtError::Missing)
    );
    let incumbent = publish(&storage, &mut dev, &k, &[1; 20]).unwrap();
    let fill = filled(&storage, &mut dev, &k, &[2; 20]);
    match seek(&mut reader, &k).unwrap() {
        super::Sought::Hit(lease) => assert_eq!(lease.id(), incumbent.id()),
        super::Sought::Joined(_) => panic!("the incumbent wins"),
    }
    assert!(visited(&storage, incumbent.id()), "the lookup's hit");
    for record in 0..4 {
        assert_eq!(
            storage.fill_row(SHARD, record).observers,
            0,
            "nothing joined at record {record}"
        );
    }
    let other = key(2);
    let second = filled(&storage, &mut dev, &other, &[3; 20]);
    let follower = match seek(&mut reader, &other).unwrap() {
        super::Sought::Joined(follower) => follower,
        super::Sought::Hit(_) => panic!("no object of the key is visible"),
    };
    assert_eq!(follower.serial(), second.serial());
    drop((follower, second, fill, incumbent));
}

#[test]
fn a_refused_search_hashes_nothing_and_a_served_one_hashes_once() {
    use super::lookup::LookupError;
    use super::prepare::AHEAD;
    use crate::index::DERIVATIONS;
    let passes = || DERIVATIONS.with(std::cell::Cell::get);
    let storage = ready();
    let mut reader = storage.register().unwrap();
    let k = key(1);
    for allowance in [0, AHEAD - 1] {
        let before = passes();
        let mut spent = WorkBudget::new(allowance);
        assert_eq!(
            reader
                .lookup_or_join(&k, FOLLOWERS, 4, TRIES, &mut spent)
                .err(),
            Some(super::SoughtError::Lookup(LookupError::Contended)),
            "{allowance}"
        );
        assert_eq!(passes(), before, "{allowance}");
        assert_eq!(spent.counters().hashes, 0, "{allowance}");
    }
    let before = passes();
    let mut spent = budget();
    assert_eq!(
        reader
            .lookup_or_join(&k, FOLLOWERS, 4, TRIES, &mut spent)
            .err(),
        Some(super::SoughtError::Missing)
    );
    assert_eq!(
        passes(),
        before + 1,
        "one pass serves the lookup and the join"
    );
    assert_eq!(spent.counters().hashes, HASH_CHARGE);
    storage.close();
    let before = passes();
    let mut spent = budget();
    assert_eq!(
        reader
            .lookup_or_join(&k, FOLLOWERS, 4, TRIES, &mut spent)
            .err(),
        Some(super::SoughtError::Lookup(LookupError::Closed))
    );
    assert_eq!(passes(), before);
    assert_eq!(spent.counters().hashes, 0);
}

/// A successful joined read sets the visited bit of the exact incarnation
/// it read and no other; a failed, an expired and a detached join set none.
#[test]
fn only_a_successful_join_records_a_hit_on_the_incarnation_it_read() {
    let storage = ready();
    let buffers = arena_with(4, 5);
    let mut dev = Device::new(&storage, &buffers);
    let k = key(1);

    // Read through an immediate replacement: the hit lands on the replaced
    // version the follower read, not on its successor.
    let fill = filled(&storage, &mut dev, &k, &[1; 20]);
    let follower = join(&storage, &k);
    let read = fill
        .publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
        .unwrap()
        .id();
    let successor = publish(&storage, &mut dev, &k, &[2; 20]).unwrap();
    assert!(!visited(&storage, read) && !visited(&storage, successor.id()));
    // SIEVE steps between the publication and the read choose no victim
    // while the successor is held, and clear no bit the read later sets.
    for _ in 0..3 {
        let report = storage
            .evict_step(&mut super::evict_tests::generous(), |_, _| true)
            .unwrap();
        assert!(report.commit.is_none(), "{report:?}");
    }
    drop(acquire(follower));
    assert!(visited(&storage, read), "the hit is the read incarnation's");
    assert!(
        !visited(&storage, successor.id()),
        "the successor earns none"
    );
    drop(successor);
    drain(&storage);

    // Failed, expired and timed-out joins.
    let k = key(2);
    let fill = reserved(&storage, &k, &[1; 20]).unwrap();
    let failed = join(&storage, &k);
    fill.fail(FillFailure::DeviceError);
    assert_eq!(
        refused(failed).1,
        JoinedReadError::Failed(FillFailure::DeviceError)
    );
    service(&storage);
    for expired in [true, false] {
        let fill = filled(&storage, &mut dev, &k, &[3; 20]);
        let follower = join(&storage, &k);
        let lease = fill
            .publish(&mut dev.volume, 5 * SECOND, TRIES, &mut budget())
            .unwrap();
        let id = lease.id();
        drop(lease);
        if expired {
            storage.platform.ticks(&[Some(5 * SECOND)]);
            assert_eq!(refused(follower).1, JoinedReadError::Expired);
            storage.platform.ticks(&[Some(1)]);
        } else {
            follower.detach();
        }
        assert!(!visited(&storage, id), "expired={expired}");
        service(&storage);
    }
}

/// A follower's version names the full 32-bit incarnation: a slot reused
/// by an incarnation sharing the version's low 16 bits, the index pair's
/// copy, refuses the follower's retain, which reports the version missing
/// and sets no bit on the successor.
#[test]
fn the_index_pairs_16_bit_copy_never_serves_as_hit_identity() {
    let storage = ready();
    let buffers = arena_with(4, 5);
    let mut dev = Device::new(&storage, &buffers);
    let k = key(1);
    let lease = publish(&storage, &mut dev, &k, &[1; 20]).unwrap();
    let old = lease.id();
    let follower = join(&storage, &k);
    drop(lease);
    invalidate(&storage, &k).unwrap();
    drain_slots(&storage);
    let live = publish(&storage, &mut dev, &key(2), &[2; 20]).unwrap();
    // The live object's word, carried to the old slot under an incarnation
    // `2^16` past the old one.
    let pool = storage.live_pool().unwrap();
    let template = pool.word(live.id().slot_index()) & !super::word::VISITED;
    let planted =
        template & !super::word::INCARNATION | u64::from(old.incarnation().wrapping_add(1 << 16));
    assert_eq!(planted as u16, old.incarnation() as u16);
    // SAFETY: the slot index was issued for this pool; no other thread runs.
    let word = unsafe { pool.slot_word(old.slot_index()) };
    let original = word.swap(planted, Ordering::Relaxed);
    let (follower, error) = refused(follower);
    assert_eq!(error, JoinedReadError::Missing);
    assert_eq!(word.load(Ordering::Relaxed), planted, "no right and no bit");
    // The positive control: the same word under the version's exact
    // incarnation admits the follower's retain and takes the hit.
    let exact = template & !super::word::INCARNATION | u64::from(old.incarnation());
    word.store(exact, Ordering::Relaxed);
    let read = acquire(follower);
    assert_eq!(read.id(), old);
    assert_ne!(word.load(Ordering::Relaxed) & super::word::VISITED, 0);
    // The planted word's count is the live lease's, so this lease's release
    // would decrement a count it never raised; the stored original below
    // restores the word instead.
    std::mem::forget(read);
    word.store(original, Ordering::Relaxed);
    drop(live);
}

/// A fill that ended without publishing, kept occupied by a joined follower,
/// can no longer replace its key's incumbent, so eviction removes the
/// incumbent; a live upload of the key still refuses it as replacing.
#[test]
fn a_departed_fill_with_followers_does_not_hold_back_eviction() {
    let storage = ready();
    let buffers = arena_with(4, 5);
    let mut dev = Device::new(&storage, &buffers);
    let k = key(1);
    let incumbent = publish(&storage, &mut dev, &k, &[1; 20]).unwrap().id();
    let fill = reserved(&storage, &k, &[2; 20]).unwrap();
    let follower = join(&storage, &k);
    let evict = |storage: &Storage<TestPlatform>| {
        storage
            .evict_step(&mut super::evict_tests::generous(), |_, _| true)
            .unwrap()
            .commit
    };
    assert!(matches!(
        evict(&storage),
        Some(super::evict::Commit::Replacing)
    ));
    fill.fail(FillFailure::DeviceError);
    assert!(matches!(
        evict(&storage),
        Some(super::evict::Commit::Evicted { victim, .. }) if victim == incumbent
    ));
    assert_eq!(ended(&follower), FillEnd::Failed(FillFailure::DeviceError));
}

/// A slot that returned after a joined read set its visited bit starts its
/// next object without that hit.
#[test]
fn a_reused_slot_never_inherits_a_joined_reads_hit() {
    let storage = ready();
    let buffers = arena_with(4, 5);
    let mut dev = Device::new(&storage, &buffers);
    let k = key(1);
    let fill = filled(&storage, &mut dev, &k, &[1; 20]);
    let follower = join(&storage, &k);
    let read = fill
        .publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
        .unwrap()
        .id();
    drop(acquire(follower));
    assert!(visited(&storage, read));
    invalidate(&storage, &k).unwrap();
    dev.persist_journal();
    drain(&storage);
    assert_eq!(state(&storage, read), Some(SlotState::Free));
    let mut held = Vec::new();
    let reused = loop {
        service(&storage);
        let lease = publish(&storage, &mut dev, &key(0x40 + held.len() as u8), &[2; 20]).unwrap();
        if lease.id().slot_index() == read.slot_index() {
            break lease;
        }
        held.push(lease);
        assert!(held.len() < 8, "a free slot is reused");
    };
    assert_ne!(reused.id(), read, "a new incarnation");
    assert!(
        !visited(&storage, reused.id()),
        "the reused slot starts unvisited"
    );
    drop((reused, held));
}

/// One record of a table [`planned`] lays out over the one-fingerprint
/// seam, which gives keys 1 to 4 fingerprint 0 and keys 0x21 to 0x24
/// fingerprint 2.
#[derive(Debug, Clone, Copy)]
enum Planned {
    /// An upload-granted fill of `key(n)`.
    Ready(u8),
    /// An attempt of `key(n)` before its upload grant.
    Granted(u8),
    /// An attempt of `key(n)` that departed and is not yet freed.
    Departed(u8),
    Free,
}

/// Records over several runs with a remainder, with Free and other-fingerprint
/// runs between the runs that hold the key's fingerprint, and a table
/// shorter than one run.
const TABLES: [&[Planned]; 3] = {
    use Planned::{Departed, Free, Granted, Ready};
    [
        &[
            Ready(1),
            Granted(0x21),
            Free,
            Departed(3),
            Granted(0x22),
            Free,
            Free,
            Free,
            Ready(2),
            Free,
        ],
        &[
            Ready(1),
            Granted(0x21),
            Granted(0x22),
            Granted(0x23),
            Free,
            Free,
            Free,
            Free,
            Granted(0x24),
            Ready(2),
            Free,
            Free,
        ],
        &[Ready(1), Free, Ready(2)],
    ]
};

/// A table as `(occupied, fingerprint)` per record.
fn prints(table: &[Planned]) -> Vec<(bool, u64)> {
    table
        .iter()
        .map(|planned| match *planned {
            Planned::Ready(n) | Planned::Granted(n) | Planned::Departed(n) => {
                (true, one_fingerprint(&key(n)))
            }
            Planned::Free => (false, 0),
        })
        .collect()
}

/// A storage whose fill table holds `table` with the owners forgotten, and
/// the position of the Ready fill of `key(2)`, whose serial is one past it.
fn planned(table: &[Planned]) -> (Storage<TestPlatform>, usize) {
    let mut storage = ready_with(table.len(), 64, 8);
    install_seam(&mut storage, one_fingerprint);
    let (mut freed, mut departing) = (Vec::new(), Vec::new());
    for (position, planned) in table.iter().enumerate() {
        match *planned {
            Planned::Ready(n) => std::mem::forget(reserved(&storage, &key(n), &[n; 20]).unwrap()),
            Planned::Granted(n) => std::mem::forget(begin(&storage, &key(n)).unwrap()),
            Planned::Departed(n) => departing.push(begin(&storage, &key(n)).unwrap()),
            Planned::Free => freed.push(begin(&storage, &key(0x60 + position as u8)).unwrap()),
        }
    }
    let released = freed.len();
    freed.into_iter().for_each(super::FillAttempt::abort);
    assert_eq!(service(&storage).released, released);
    departing.into_iter().for_each(super::FillAttempt::abort);
    let expected: Vec<Record> = table
        .iter()
        .zip(1..)
        .map(|(planned, serial)| match planned {
            Planned::Ready(_) | Planned::Granted(_) => live(serial),
            Planned::Departed(_) => departed(serial, false),
            Planned::Free => Record::Free,
        })
        .collect();
    assert_eq!(records(&storage), expected);
    let target = table
        .iter()
        .position(|planned| matches!(planned, Planned::Ready(2)))
        .unwrap();
    (storage, target)
}

#[test]
fn every_budget_cut_charges_the_join_scan_as_one_debit_per_step() {
    for table in TABLES {
        let (storage, target) = planned(table);
        let layout = prints(table);
        let reference = |cuts: usize, print: u64, joins: bool| {
            let mut budget = WorkBudget::new(cuts);
            let mut steps = || {
                budget.debit_n(WorkKind::Hash, HASH_CHARGE)?;
                budget.debit(WorkKind::CoordinationAttempt)?;
                for &(occupied, record_print) in &layout {
                    budget.debit(WorkKind::Visit)?;
                    if occupied && record_print == print {
                        budget.debit(WorkKind::Comparison)?;
                    }
                }
                if joins {
                    budget.debit(WorkKind::Update)?;
                }
                Ok::<(), super::budget::BudgetExhausted>(())
            };
            let exhausted = steps().is_err();
            (budget, exhausted)
        };
        // The allowance covers a visit and a comparison for each record.
        let full = HASH_CHARGE + 1 + 2 * layout.len() + 1;
        for k in [key(2), key(4), key(0x21), key(0x51)] {
            let (print, joins) = (one_fingerprint(&k), k == key(2));
            for cuts in 0..=full + 2 {
                let at = format!("{} records, key {:#x} at {cuts}", layout.len(), k[0]);
                let mut charged = WorkBudget::new(cuts);
                probe::arm();
                let joined = storage.join_fill(&k, FOLLOWERS, TRIES, &mut charged);
                let (expected, exhausted) = reference(cuts, print, joins);
                assert_eq!(charged, expected, "{at}");
                assert_eq!(probe::counts().loads, charged.counters().visits, "{at}");
                match joined {
                    Ok(follower) => {
                        assert!(joins && !exhausted, "{at}");
                        assert_eq!(follower.serial(), target as u64 + 1, "{at}");
                    }
                    Err(error) => assert_eq!(
                        error,
                        if exhausted {
                            JoinError::BudgetExhausted
                        } else {
                            JoinError::NoFill
                        },
                        "{at}"
                    ),
                }
            }
        }
        assert!(!gate(&storage).is_poisoned());
    }
}

/// Joins of `key(2)` against `storage`, funded and exactly funded for the
/// steps through record `reached`: each refuses `Corrupt`, poisons the gate
/// and charges `comparisons` comparisons and the visits through `reached`.
fn refused_corrupt(
    storage: impl Fn() -> Storage<TestPlatform>,
    reached: usize,
    comparisons: usize,
) {
    for tight in [false, true] {
        let storage = storage();
        let counters = WorkCounters {
            comparisons,
            coordination_attempts: 1,
            visits: reached + 1,
            updates: 0,
            hashes: HASH_CHARGE,
        };
        let mut charged = if tight {
            WorkBudget::new(HASH_CHARGE + 1 + reached + 1 + comparisons)
        } else {
            budget()
        };
        probe::arm();
        assert_eq!(
            storage
                .join_fill(&key(2), FOLLOWERS, TRIES, &mut charged)
                .err(),
            Some(JoinError::Corrupt),
            "record {reached}, tight: {tight}"
        );
        assert_eq!(
            charged.counters(),
            counters,
            "record {reached}, tight: {tight}"
        );
        assert_eq!(
            probe::counts().loads,
            reached + 1,
            "record {reached}, tight: {tight}"
        );
        assert!(gate(&storage).is_poisoned());
    }
}

#[test]
fn a_malformed_word_at_any_record_fails_the_join_closed() {
    for table in TABLES {
        let layout = prints(table);
        for position in 0..table.len() {
            let comparisons = layout[..position]
                .iter()
                .filter(|&&(occupied, print)| occupied && print == 0)
                .count();
            let storage = || {
                let (storage, _) = planned(table);
                storage
                    .fill_state(SHARD, position)
                    .store(fill::occupied(fill_serial(99)), Ordering::Relaxed);
                storage
            };
            refused_corrupt(storage, position, comparisons);
        }
    }
}

#[test]
fn a_malformed_row_of_the_keys_record_fails_the_join_closed() {
    for table in TABLES {
        let layout = prints(table);
        let (_, target) = planned(table);
        let comparisons = layout[..=target]
            .iter()
            .filter(|&&(occupied, print)| occupied && print == 0)
            .count();
        let storage = || {
            let (storage, target) = planned(table);
            let fills = storage.fill_table(SHARD).unwrap();
            // SAFETY: the storage is live and only atomics are written; no
            // gate holder runs.
            let view = unsafe { storage.fill_view(fills) };
            // A failure word with an unknown cause.
            let word = row::failed(FillFailure::Closed) & !(0xFF << 8) | 0xEE << 8;
            view.rows[target].plant_terminal(word);
            storage
        };
        refused_corrupt(storage, target, comparisons);
    }
}

/// A reserved control bit fails closed: a departed fill whose pending pair
/// sits in a bucket whose control word carries a reserved bit ends the
/// service pass as corrupt, with its record occupied, its pair still pending
/// and the gate poisoned.
#[test]
fn service_refuses_a_reserved_bit_in_the_claimed_bucket() {
    use crate::index::{BucketView, PAIRS, is_pending};
    let storage = ready();
    let fill = reserved(&storage, &key(1), &[1; 20]).unwrap();
    let index = storage.index.as_ref().unwrap();
    let shard = index.image.shard(SHARD).unwrap();
    // SAFETY: the index mapping is live.
    let buckets = unsafe { shard.buckets(&index.mapping) };
    let (claimed, pair) = buckets
        .iter()
        .find_map(|bucket| {
            (0..PAIRS)
                .find(|&pair| is_pending(bucket.control(), pair))
                .map(|pair| (bucket, pair))
        })
        .expect("the fill's pending pair");
    let planted = claimed.control() | 1 << 60;
    claimed.corrupt(planted, claimed.next());
    drop(fill);
    assert!(matches!(
        storage.service_fills(SHARD, TRIES, &mut budget()),
        Err(super::FillServiceError::Corrupt(_))
    ));
    assert!(gate(&storage).is_poisoned());
    assert_eq!(claimed.control(), planted, "the pending pair stays held");
    assert!(is_pending(claimed.control(), pair));
    let table = storage.fill_table(SHARD).unwrap();
    // SAFETY: the storage is live and only atomics are read.
    let view = unsafe { storage.fill_view(table) };
    let next = view.control.next_serial.load();
    let record = fill::decode(view.states[0].load(Ordering::Acquire), next).unwrap();
    assert!(record.is_departed(), "the record stays occupied");
}

fn place_naming_another_fill<'s>(
    storage: &'s Storage<TestPlatform>,
    foreign: bool,
) -> (
    super::WritableFill<'s, 's, TestPlatform>,
    super::WritableFill<'s, 's, TestPlatform>,
    super::place_claim::Claimed,
    super::place_claim::Claimed,
) {
    use super::place_claim::Claimed;
    let table = storage.fill_table(SHARD).unwrap();
    let claims = || -> Vec<(usize, Claimed)> {
        // SAFETY: the storage is live and this single-threaded test is the
        // only path into the place words while the borrow lasts.
        let places = unsafe { storage.fill_hold(table) }.places;
        places
            .iter()
            .enumerate()
            .filter_map(|(at, &word)| Claimed::of(word).map(|claimed| (at, claimed)))
            .collect()
    };
    let first = reserved(storage, &key(1), &[1; 20]).unwrap();
    let own = claims();
    assert_eq!(own.len(), 1);
    let (position, mine) = own[0];
    let second = reserved(storage, &key(2), &[2; 20]).unwrap();
    let theirs = claims()
        .into_iter()
        .find(|&(at, _)| at != position)
        .unwrap()
        .1;
    assert_ne!(theirs, mine);
    if foreign {
        // SAFETY: the storage is live and this single-threaded test is the
        // only path into the place words while the borrow lasts.
        unsafe { storage.fill_hold(table) }.places[position] = theirs.word();
    }
    (first, second, mine, theirs)
}

/// Whether each claim's pair is pending, and the shard's claim count.
fn claim_state(
    storage: &Storage<TestPlatform>,
    claims: [super::place_claim::Claimed; 2],
) -> ([bool; 2], usize) {
    use crate::index::{BucketView, is_pending};
    let index = storage.index.as_ref().unwrap();
    // SAFETY: the index mapping is live and no gate is held.
    let buckets = unsafe { index.image.shard(SHARD).unwrap().buckets(&index.mapping) };
    let pending = claims.map(|claimed| is_pending(buckets[claimed.bucket].control(), claimed.pair));
    let reserved = shard_control(storage).reserved.load(Ordering::Relaxed);
    (pending, reserved)
}

#[test]
fn service_refuses_a_departed_place_word_naming_another_fills_pending_pair() {
    for foreign in [false, true] {
        let storage = ready();
        let (departing, staying, mine, theirs) = place_naming_another_fill(&storage, foreign);
        drop(departing);
        let served = storage.service_fills(SHARD, TRIES, &mut budget());
        let state = claim_state(&storage, [mine, theirs]);
        if !foreign {
            assert!(served.is_ok());
            assert_eq!(state, ([false, true], 1));
            drop(staying);
            continue;
        }
        assert!(matches!(served, Err(super::FillServiceError::Corrupt(_))));
        assert!(gate(&storage).is_poisoned());
        assert_eq!(state, ([true, true], 2));
        std::mem::forget(staying);
    }
}

#[test]
fn an_invalidation_refuses_a_revoked_place_word_naming_another_fills_pending_pair() {
    for foreign in [false, true] {
        let storage = ready();
        let (revoked, staying, mine, theirs) = place_naming_another_fill(&storage, foreign);
        let invalidated = invalidate(&storage, &key(1));
        let state = claim_state(&storage, [mine, theirs]);
        if !foreign {
            assert!(invalidated.unwrap().revoked.is_some());
            assert_eq!(state, ([false, true], 1));
            drop(revoked);
            drop(staying);
            continue;
        }
        assert!(matches!(invalidated, Err(super::InvalidateError::Corrupt)));
        assert!(gate(&storage).is_poisoned());
        assert_eq!(state, ([true, true], 2));
        std::mem::forget(revoked);
        std::mem::forget(staying);
    }
}

/// A follower that finds the cutoff closed refuses `Closed` before its retain, so the published version earns no hit and a SIEVE step after close evicts it ahead of a newer object, as it does when the follower detaches instead.
#[test]
fn a_joined_acquisition_refused_closed_earns_no_hit() {
    for refused_closed in [true, false] {
        let storage = ready();
        let buffers = arena_with(4, 5);
        let mut dev = Device::new(&storage, &buffers);
        let fill = filled(&storage, &mut dev, &key(1), &[1; 20]);
        let follower = join(&storage, &key(1));
        let first = fill
            .publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
            .unwrap()
            .id();
        let second = publish(&storage, &mut dev, &key(2), &[2; 20]).unwrap().id();
        assert!(
            !visited(&storage, first) && !visited(&storage, second),
            "premise: publication sets no bit"
        );
        storage.close();
        if refused_closed {
            let (follower, error) = refused(follower);
            assert_eq!(error, JoinedReadError::Closed);
            drop(follower);
        } else {
            follower.detach();
        }
        service(&storage);
        assert!(
            !visited(&storage, first),
            "refused_closed={refused_closed}: no hit without a lease"
        );
        let report = storage
            .evict_step(&mut super::evict_tests::generous(), |_, _| true)
            .unwrap();
        assert!(
            matches!(report.commit, Some(super::evict::Commit::Evicted { victim, .. }) if victim == first),
            "refused_closed={refused_closed}: {report:?}"
        );
    }
}

/// Runs `acquire` with `storage` closed inside the next clock sample the platform takes on this thread.
fn closed_in_next_sample<R>(storage: &Storage<TestPlatform>, acquire: impl FnOnce() -> R) -> R {
    use super::test_platform::IN_SAMPLE;
    let address = std::ptr::from_ref(storage) as usize;
    IN_SAMPLE.with(|hook| {
        hook.set(Some(Box::new(move || {
            // SAFETY: the hook runs inside `acquire`, while the caller's borrow of the storage is live.
            let storage = unsafe { &*(address as *const Storage<TestPlatform>) };
            assert!(
                !storage.is_closed(),
                "premise: the close lands in the sample"
            );
            storage.close();
        })));
    });
    let outcome = acquire();
    assert!(
        IN_SAMPLE.with(std::cell::Cell::take).is_none(),
        "premise: the acquisition took a sample"
    );
    outcome
}

/// A close that lands inside the follower's reservation, after every cutoff read that precedes it, is caught by the `SeqCst` read after the reservation: the acquisition refuses `Closed` and returns its credit and right. The sibling whose sample closes nothing acquires its lease.
#[test]
fn a_close_during_a_joined_reservation_refuses_and_returns_its_reservations() {
    for closes in [true, false] {
        let storage = ready();
        let buffers = arena_with(4, 5);
        let mut dev = Device::new(&storage, &buffers);
        let fill = filled(&storage, &mut dev, &key(1), &[1; 20]);
        let follower = join(&storage, &key(1));
        let lease = fill
            .publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
            .unwrap();
        let id = lease.id();
        drop(lease);
        assert_eq!((credits(&storage), refs(&storage, id)), (1, 2), "premise");
        if closes {
            let (follower, error) =
                closed_in_next_sample(&storage, || follower.acquire(TRIES, &mut budget()))
                    .unwrap_err();
            assert_eq!(error, JoinedReadError::Closed);
            assert_eq!(
                (credits(&storage), refs(&storage, id)),
                (1, 2),
                "the row's credit and right alone"
            );
            assert_eq!(storage.fill_row(SHARD, 0).observers, 1);
            drop(follower);
        } else {
            let lease = follower.acquire(TRIES, &mut budget()).unwrap();
            assert_eq!(lease.id(), id);
            assert_eq!((credits(&storage), refs(&storage, id)), (2, 3));
            drop(lease);
        }
        assert_eq!(service(&storage).released, 1);
        assert_eq!((credits(&storage), refs(&storage, id)), (0, 1));
    }
}

/// A follower refused `Closed` by a close that lands inside its reservation holds no lease, so the published version earns no hit and a SIEVE step after close evicts it ahead of a newer object, as when the follower detaches instead.
#[test]
fn a_joined_acquisition_refused_closed_during_its_reservation_earns_no_hit() {
    for refused_closed in [true, false] {
        let storage = ready();
        let buffers = arena_with(4, 5);
        let mut dev = Device::new(&storage, &buffers);
        let fill = filled(&storage, &mut dev, &key(1), &[1; 20]);
        let follower = join(&storage, &key(1));
        let first = fill
            .publish(&mut dev.volume, DEADLINE, TRIES, &mut budget())
            .unwrap()
            .id();
        let second = publish(&storage, &mut dev, &key(2), &[2; 20]).unwrap().id();
        assert!(
            !visited(&storage, first) && !visited(&storage, second),
            "premise: publication sets no bit"
        );
        if refused_closed {
            let (follower, error) = closed_in_next_sample(&storage, || refused(follower));
            assert_eq!(error, JoinedReadError::Closed);
            drop(follower);
        } else {
            storage.close();
            follower.detach();
        }
        service(&storage);
        assert!(
            !visited(&storage, first),
            "refused_closed={refused_closed}: no hit without a lease"
        );
        let report = storage
            .evict_step(&mut super::evict_tests::generous(), |_, _| true)
            .unwrap();
        assert!(
            matches!(report.commit, Some(super::evict::Commit::Evicted { victim, .. }) if victim == first),
            "refused_closed={refused_closed}: {report:?}"
        );
    }
}

/// The fill records of the one shard `observed_over` builds.
const RECORDS: usize = 4;

/// What a test stores over the follower's record before it observes.
#[derive(Debug, Clone, Copy)]
enum Planted {
    /// The Free word.
    Free,
    /// The first attempt's serial, undeparted.
    EarlierSerial,
    /// The first attempt's serial, departed, over the row's own terminal.
    EarlierSerialDeparted,
    /// The follower's own serial, departed, with the grant's terminal.
    OwnDepartedGranted,
}

/// Runs `observe` on one follower of the key's second attempt with `planted`
/// stored over its record, then restores the record and its row before the
/// follower and its producer drop. Returns the observation and whether it
/// left the gate poisoned.
fn observed_over(
    planted: Planted,
    tries: usize,
    budget: &mut WorkBudget,
) -> (Result<Observed, ObserveError>, bool) {
    let storage: Storage<TestPlatform> = ready_with(RECORDS, 16, 8);
    drop(reserved(&storage, &key(1), &[1; 20]).unwrap());
    assert_eq!(service(&storage).released, 1, "the first attempt is freed");
    let fill = reserved(&storage, &key(1), &[1; 20]).unwrap();
    let follower = storage
        .join_fill(&key(1), u64::MAX, TRIES, &mut self::budget())
        .unwrap();
    let serial = fill_serial(follower.serial());
    let first = fill_serial(FIRST_SERIAL);
    assert!(serial.get() > FIRST_SERIAL, "an earlier serial was issued");
    let record = (0..RECORDS)
        .find(|record| {
            storage.fill_state(SHARD, *record).load(Ordering::Relaxed) == fill::occupied(serial)
        })
        .expect("the follower's record is occupied under its serial");
    let state = storage.fill_state(SHARD, record);
    let table = storage.fill_table(SHARD).unwrap();
    // SAFETY: the storage is live, `table` is its shard's fill table, and
    // the words are atomics no holder forms a `&mut` into.
    let view = unsafe { storage.fill_view(table) };
    let terminal = &view.rows[record];
    assert_eq!(terminal.terminal(), Ok(Terminal::Ready));
    assert_eq!(
        follower.observe(TRIES, &mut self::budget()),
        Ok(Observed::Pending),
        "the record as its producer left it is pending"
    );
    match planted {
        Planted::Free => state.store(fill::FREE, Ordering::Relaxed),
        Planted::EarlierSerial => state.store(fill::occupied(first), Ordering::Relaxed),
        Planted::EarlierSerialDeparted => {
            state.store(fill::occupied(first), Ordering::Relaxed);
            assert!(fill::depart(state, first));
        }
        Planted::OwnDepartedGranted => {
            assert!(fill::depart(state, serial));
            terminal.plant_terminal(row::GRANTED);
        }
    }
    let observed = follower.observe(tries, budget);
    let poisoned = gate(&storage).is_poisoned();
    state.store(fill::occupied(serial), Ordering::Relaxed);
    terminal.plant_terminal(row::READY);
    drop((follower, fill));
    (observed, poisoned)
}

/// A joined follower takes no terminal from a Free record: the word names
/// no attempt, so the observation outside the gate and the one under it
/// both find it malformed, and the follower reports `Corrupt` and poisons
/// the gate.
#[test]
fn a_free_record_is_corrupt_and_poisons_the_gate() {
    let (observed, poisoned) = observed_over(Planted::Free, TRIES, &mut budget());
    assert_eq!(observed, Err(ObserveError::Corrupt));
    assert!(poisoned);
}

/// A record occupied under a serial issued before the follower's own names
/// another attempt, departed or not: the follower reports `Corrupt` for it
/// and poisons the gate.
#[test]
fn a_record_of_an_earlier_issued_serial_is_corrupt_and_poisons_the_gate() {
    for planted in [Planted::EarlierSerial, Planted::EarlierSerialDeparted] {
        let (observed, poisoned) = observed_over(planted, TRIES, &mut budget());
        assert_eq!(observed, Err(ObserveError::Corrupt), "{planted:?}");
        assert!(poisoned, "{planted:?}");
    }
}

/// The follower's own record, departed while its row holds the grant's
/// terminal, is a state a joined fill never reaches, since a follower joins
/// only an upload-granted or a published record: the follower reports
/// `Corrupt` and poisons the gate.
#[test]
fn the_follower_s_own_departed_record_still_granted_is_corrupt_and_poisons_the_gate() {
    let (observed, poisoned) = observed_over(Planted::OwnDepartedGranted, TRIES, &mut budget());
    assert_eq!(observed, Err(ObserveError::Corrupt));
    assert!(poisoned);
}

/// The visit is paid before the first observation and each gate try before
/// the second, which runs only under the gate: an allowance that cannot pay
/// the visit or the gate try refuses `BudgetExhausted`, zero gate tries
/// refuse `Contended`, and each refusal leaves the gate unpoisoned.
#[test]
fn a_budget_or_gate_refusal_precedes_the_second_observation_and_poisons_nothing() {
    for planted in [Planted::EarlierSerial, Planted::OwnDepartedGranted] {
        let (observed, poisoned) = observed_over(planted, TRIES, &mut WorkBudget::new(0));
        assert_eq!(
            observed,
            Err(ObserveError::BudgetExhausted),
            "{planted:?}: the visit is unpaid"
        );
        assert!(!poisoned, "{planted:?}");
        let (observed, poisoned) = observed_over(planted, TRIES, &mut WorkBudget::new(1));
        assert_eq!(
            observed,
            Err(ObserveError::BudgetExhausted),
            "{planted:?}: the gate try is unpaid"
        );
        assert!(!poisoned, "{planted:?}");
        let (observed, poisoned) = observed_over(planted, 0, &mut budget());
        assert_eq!(
            observed,
            Err(ObserveError::Contended),
            "{planted:?}: no gate try"
        );
        assert!(!poisoned, "{planted:?}");
    }
}

/// The gate tries one observation may pay for.
const GATE_TRIES: usize = 1 << 20;
/// Schedules tried before the test gives up on meeting its interleaving.
const ROUNDS: usize = 64;

/// One follower of one pending fill. A second thread holds the shard gate
/// while the record's word is malformed, so a follower whose unlocked
/// observation runs before the restore finds the word malformed, and each
/// gate try it makes before the release finds the gate busy; the holder
/// then restores the word and releases the gate. The follower takes the
/// gate within `GATE_TRIES` paid tries, observes the restored word, returns
/// that observation and leaves the gate open and takeable.
///
/// The holder's restore can precede the follower's first read, so a round
/// counts only when the follower paid a gate try, which it does only after
/// a malformed first read; a round that read the restored word first, or
/// spent its tries before the release, runs again.
#[test]
fn a_word_well_formed_again_under_the_gate_returns_its_observation_and_leaves_the_gate_open() {
    let storage = ready_with(4, 16, 8);
    let fill = reserved(&storage, &key(1), &[1; 20]).unwrap();
    let follower = storage
        .join_fill(&key(1), u64::MAX, 2, &mut budget())
        .unwrap();
    assert_eq!(
        follower.observe(2, &mut budget()),
        Ok(Observed::Pending),
        "the producer has not ended"
    );
    let word = storage.fill_state(SHARD, 0);
    let (shard_gate, control) = (gate(&storage), shard_control(&storage));
    let sound = word.load(Ordering::Relaxed);
    let malformed = fill::occupied(fill_serial(99));
    assert_ne!(sound, malformed);

    let mut met = false;
    for _ in 0..ROUNDS {
        let (held, reading) = (AtomicBool::new(false), AtomicBool::new(false));
        let failed_before = control.failed_tries.load(Ordering::Relaxed);
        let mut allowance = WorkBudget::new(2 * GATE_TRIES);
        let observed = std::thread::scope(|scope| {
            scope.spawn(|| {
                let guard = shard_gate.try_lock().unwrap();
                word.store(malformed, Ordering::Release);
                held.store(true, Ordering::Release);
                while !reading.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
                std::thread::sleep(Duration::from_millis(1));
                word.store(sound, Ordering::Release);
                guard.release();
            });
            while !held.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            reading.store(true, Ordering::Release);
            follower.observe(GATE_TRIES, &mut allowance)
        });
        let attempts = allowance.counters().coordination_attempts;
        assert!(attempts <= GATE_TRIES, "each gate try is paid and bounded");
        assert_ne!(
            observed,
            Err(ObserveError::Corrupt),
            "the word is well formed whenever the gate is free"
        );
        if observed.is_err() || attempts == 0 {
            assert!(!shard_gate.is_poisoned());
            continue;
        }
        assert_eq!(
            observed,
            Ok(Observed::Pending),
            "the observation under the gate is the one returned"
        );
        assert!(
            !shard_gate.is_poisoned(),
            "a word well formed under the gate does not poison it"
        );
        let Ok(guard) = shard_gate.try_lock() else {
            panic!("the second observation released the gate");
        };
        guard.release();
        assert_eq!(
            control.failed_tries.load(Ordering::Relaxed) - failed_before,
            attempts - 1,
            "every try but the one that took the gate found it busy"
        );
        met = true;
        break;
    }
    assert!(met, "no round met a malformed first read and a free gate");
    assert_eq!(follower.observe(2, &mut budget()), Ok(Observed::Pending));
    drop((follower, fill));
}

/// The word stays malformed for both observations. The second takes the
/// gate with the first of its two allowed tries, returns `Corrupt` and
/// poisons the gate.
#[test]
fn a_word_still_malformed_under_the_gate_returns_corrupt_and_poisons_it() {
    let storage = ready_with(4, 16, 8);
    let fill = reserved(&storage, &key(1), &[1; 20]).unwrap();
    let follower = storage
        .join_fill(&key(1), u64::MAX, 2, &mut budget())
        .unwrap();
    storage
        .fill_state(SHARD, 0)
        .store(fill::occupied(fill_serial(99)), Ordering::Relaxed);
    let mut allowance = budget();
    assert_eq!(
        follower.observe(2, &mut allowance),
        Err(ObserveError::Corrupt)
    );
    assert_eq!(allowance.counters().coordination_attempts, 1);
    assert!(gate(&storage).is_poisoned());
    drop((follower, fill));
}
