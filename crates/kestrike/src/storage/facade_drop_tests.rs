//! Dropping the facade closes admission with the cutoff store `Storage::close` makes and does nothing else:
//! no wait, no sweep, no platform call, no mapping released.
//!
//! The tests read the storage around the drop: the cutoff reads set after it, and every report, the platform's
//! call log, its clock samples, its mappings and this thread's allocation count read as they did before it.
//! The store's `SeqCst` ordering is held by the atomic-site census, which names the store by its source text.
//!
//! The fixture is an indexed storage with resident published objects, a lease on one of them and a live
//! registration, the state in which a sweep, a retirement, a service pass or a certification would each move a
//! report. Every test decides its verdict into values, lets the lease, the registration and the storage go, and
//! asserts afterwards, so a failure ends in the test's own result line.

use std::sync::atomic::Ordering;

use super::budget::WorkBudget;
use super::closing::CloseError;
use super::lookup::LookupError;
use super::lookup_tests::{body, hit_key, key, publish, ticks};
use super::owner::Storage;
use super::publish_tests::{PAGE, RETRIES, budget, index_config, refs, storage_with};
use super::test_platform::{Op, TestPlatform};
use super::{AllocationId, ExtentLease, Registration};
use crate::index::ShardIndex;

/// A deadline 100 seconds into the engine's nanosecond timeline, past the fixture's one clock sample.
const DEADLINE: u64 = 100 * 1_000_000_000;

/// Slots of the fixture's storage.
const SLOTS: usize = 16;

/// The first byte of each published key.
const KEYS: [u8; 4] = [0x10, 0x11, 0x12, 0x13];

/// The published key the fixture leases.
const LEASED: u8 = 0x12;

/// Every report of the storage, the leased object's slot word (its state, flags, incarnation and reference
/// count), its reference count read through the pool, and the index shard's report, as text, so two samples
/// compare whole and a difference prints both.
fn observed(
    storage: &Storage<TestPlatform>,
    reader: &Registration<'_, TestPlatform>,
    id: AllocationId,
) -> String {
    let pool = storage.live_pool().unwrap();
    format!(
        "{:?}",
        (
            storage.era_report(),
            storage.lease_report(),
            storage.outstanding(),
            storage.registration_report(reader.index()),
            storage.pool_report(),
            storage.engine_used(),
            storage.shard_report(ShardIndex(0)),
            pool.word(id.slot_index()),
            refs(storage, id),
        )
    )
}

/// What one run of the scenario saw around the facade's drop.
struct Seen {
    /// The reports before the drop and after it.
    reports: (String, String),
    /// Platform calls logged before the drop and after it.
    calls: (usize, usize),
    /// Clock samples taken before the drop and after it.
    samples: (usize, usize),
    /// Mappings the platform released before the drop and after it.
    unmapped: (usize, usize),
    /// This thread's allocation count right before the drop and right after it.
    allocations: (usize, usize),
    /// Whether admission was closed before the drop and after it.
    closed: (bool, bool),
    /// Whether an explicit close-service call was refused `Open` before the drop.
    service_refused_open: bool,
    /// Whether the lease still named its key's object after the drop.
    lease_reads: bool,
    /// The next lookup on the surviving registration, after the drop.
    next_lookup: Option<LookupError>,
    /// Mappings the explicit close-service calls after the drop removed, summed until one reported complete.
    removed_by_service: usize,
    /// Whether those calls reached a complete pass.
    service_completed: bool,
    /// Whether the reports after the explicit close service differ from the ones before the drop.
    service_moved_reports: bool,
}

/// Publishes [`KEYS`], registers through the facade, leases [`LEASED`] through it, drops the facade between
/// two samples, and then lets the owner run close service, returning what it saw once every fixture is gone.
fn scenario() -> Seen {
    let platform = TestPlatform::heap(PAGE);
    let log = platform.log();
    let samples = platform.sample_counter();
    let limits = [8usize];
    let storage = storage_with(SLOTS, &index_config(&limits, (1, 1), 1), platform);
    ticks(&storage, &[Some(1)]);
    let ids: Vec<AllocationId> = (KEYS.iter())
        .map(|&n| publish(&storage, key(n), DEADLINE, &body(n)))
        .collect();
    let leased = ids[KEYS.iter().position(|&n| n == LEASED).unwrap()];

    let cache = storage.issue_cache().unwrap();
    let mut reader = cache.register().unwrap();
    let lease: ExtentLease<'_, TestPlatform> = cache
        .lookup(&mut reader, &key(LEASED), RETRIES, &mut budget())
        .unwrap();
    assert_eq!(lease.id(), leased, "the lease names the published object");
    let service_refused_open =
        storage.close_service(&mut WorkBudget::new(64)) == Err(CloseError::Open);

    let before = observed(&storage, &reader, leased);
    let closed_before = storage.is_closed();
    let calls_before = log.all().len();
    let samples_before = samples.load(Ordering::SeqCst);
    let unmapped_before = log.calls(Op::Unmap).len();
    let allocations_before = crate::instrument::allocations();
    drop(cache);
    let allocations_after = crate::instrument::allocations();
    let unmapped_after = log.calls(Op::Unmap).len();
    let samples_after = samples.load(Ordering::SeqCst);
    let calls_after = log.all().len();
    let closed_after = storage.is_closed();
    let after = observed(&storage, &reader, leased);

    // What stays legal after the drop, and what the drop left for the owner to schedule.
    let lease_reads = hit_key(&lease) == key(LEASED);
    let next_lookup = reader.lookup(&key(KEYS[0]), RETRIES, &mut budget()).err();
    let mut removed_by_service = 0;
    let mut service_completed = false;
    for _ in 0..1024 {
        let Ok(report) = storage.close_service(&mut WorkBudget::new(4096)) else {
            break;
        };
        removed_by_service += report.removed;
        if report.complete {
            service_completed = true;
            break;
        }
    }
    let serviced = observed(&storage, &reader, leased);
    let service_moved_reports = serviced != before;

    drop(lease);
    drop(reader);
    drop(storage);
    Seen {
        reports: (before, after),
        calls: (calls_before, calls_after),
        samples: (samples_before, samples_after),
        unmapped: (unmapped_before, unmapped_after),
        allocations: (allocations_before, allocations_after),
        closed: (closed_before, closed_after),
        service_refused_open,
        lease_reads,
        next_lookup,
        removed_by_service,
        service_completed,
        service_moved_reports,
    }
}

/// Dropping the facade over resident objects, a live lease and a live registration closes admission and moves
/// nothing else: every report of the storage, the leased object's slot word and reference count and the index
/// shard read the same after the drop as before it, the platform logged no call and released no mapping, and
/// the drop allocated nothing.
#[test]
fn dropping_the_facade_stores_the_cutoff_and_moves_no_report() {
    let seen = scenario();
    assert!(
        seen.service_refused_open,
        "admission is open before the drop"
    );
    assert_eq!(seen.closed, (false, true), "the drop closes admission");
    assert_eq!(
        seen.reports.1, seen.reports.0,
        "the facade's drop moved a report: after the drop, then before it"
    );
    assert_eq!(
        seen.calls.1, seen.calls.0,
        "the facade's drop made a platform call"
    );
    assert_eq!(
        seen.samples.1, seen.samples.0,
        "the facade's drop sampled the platform clock"
    );
    assert_eq!(
        seen.unmapped.1, seen.unmapped.0,
        "the facade's drop released a mapping"
    );
    assert_eq!(
        seen.allocations.1, seen.allocations.0,
        "the facade's drop allocated"
    );
}

/// The drop sweeps nothing, so the work stays the owner's: after the drop the lease still names its object,
/// the next lookup on the surviving registration is refused `Closed`, and the explicit close service that
/// follows is what removes every published object's mapping, which its reports count, and what moves the
/// reports the drop left alone.
#[test]
fn the_sweep_the_drop_left_out_is_the_owners_close_service() {
    let seen = scenario();
    assert!(seen.lease_reads, "the lease outlives the facade");
    assert_eq!(seen.next_lookup, Some(LookupError::Closed));
    assert!(
        seen.service_completed,
        "the owner's close service completes a pass"
    );
    assert_eq!(
        seen.removed_by_service,
        KEYS.len(),
        "the owner's close service removes each mapping the drop left in place"
    );
    assert!(
        seen.service_moved_reports,
        "a sweep moves the reports, so equal reports around the drop show the drop swept nothing"
    );
}
