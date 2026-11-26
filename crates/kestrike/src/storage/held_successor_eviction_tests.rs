//! After a stale commit that is `Absent`, a later removal step may evict the successor by its own identity.
//! Unheld, reclamation then frees the successor's slot at its incarnation. Held by a reader, the
//! successor's later eviction stays `Retired`; a history in which the held successor is reclaimed breaks
//! the property.
//!
//! Both tests build the same history on an eight-slot heap storage whose only resident is key 1's object:
//! the first removal step selects it, the hook between selection and commit invalidates key 1 and publishes
//! a successor under it, and the commit is `Absent` and leaves the successor `Resident`. The next step
//! commits `Evicted` with the successor's own slot and incarnation. Each of these is a premise, asserted
//! before the judgment.
//!
//! - Unheld: certification and service leave the successor's slot `Free` at the successor's incarnation.
//! - Held: a reader takes a lease on the successor between the second step's selection and its commit. The
//!   slot must stay `Retired` at the successor's incarnation through three rounds of certification and
//!   service, the lease must still name the successor under key 1 and admit a second right on it, and a
//!   publication made meanwhile must not take the slot. The slot becomes `Free` only after the lease is
//!   dropped and service runs again. The heap storage has no device, so the lease's identity, its key's
//!   fingerprint and the unreused slot stand for the bytes a read through it would return.
//!
//! Each test records what it sees into a value, a panic of service included, lets the lease go and asserts
//! afterwards, so a failure ends in the test's own result line.

use std::cell::{Cell, RefCell};
use std::panic::{AssertUnwindSafe, catch_unwind};

use super::attempt_tests::invalidate;
use super::evict::{Commit, INTERPOSE_BEFORE_COMMIT};
use super::evict_tests::{drain, generous, ready};
use super::lookup_tests::{body, hit_key, key, lookup, publish};
use super::owner::Storage;
use super::publish_tests::RETRIES;
use super::tables::{SlotIndex, SlotState};
use super::test_platform::TestPlatform;
use super::{AllocationId, ExtentLease};

/// Rounds of certification and service the held successor must stay retired through.
const ROUNDS: usize = 3;

thread_local! {
    /// The storage the commit hooks act on; a hook is a plain `fn()`.
    static STORAGE: Cell<Option<&'static Storage<TestPlatform>>> = const { Cell::new(None) };
    /// The identity the first step's hook published under key 1.
    static SUCCESSOR: Cell<Option<AllocationId>> = const { Cell::new(None) };
    /// The lease the second step's hook took on the successor.
    static LEASE: RefCell<Option<ExtentLease<'static, TestPlatform>>> = const { RefCell::new(None) };
}

fn storage() -> &'static Storage<TestPlatform> {
    STORAGE
        .with(Cell::get)
        .expect("the history set its storage")
}

/// Runs between the first step's selection and its commit: key 1's object is invalidated and a successor
/// is published under the same key.
fn replace_victim() {
    invalidate(storage(), &key(1)).expect("the selected victim's key invalidates");
    let successor = publish(storage(), key(1), u64::MAX, &body(2));
    SUCCESSOR.with(|cell| cell.set(Some(successor)));
}

/// Runs between the second step's selection and its commit: a reader takes a lease on the successor.
fn hold_successor() {
    let mut reader = storage().register().expect("a reader registers");
    let lease =
        lookup(&mut reader, &key(1), RETRIES).expect("the successor is visible before its commit");
    LEASE.with(|cell| *cell.borrow_mut() = Some(lease));
}

/// One removal step with `hook` between its selection and its commit.
fn step(hook: Option<fn()>) -> Option<Commit> {
    INTERPOSE_BEFORE_COMMIT.with(|cell| cell.set(hook));
    let report = storage().evict_step(&mut generous(), |_, _| true);
    INTERPOSE_BEFORE_COMMIT.with(|cell| cell.set(None));
    report.expect("the removal step ran").commit
}

fn state(id: AllocationId) -> (SlotState, u32) {
    storage()
        .slot_state(SlotIndex(id.slot_index()))
        .expect("the slot is in the pool")
}

/// What one run of the history showed.
#[derive(Debug)]
struct Seen {
    /// The object the first step selected.
    first: AllocationId,
    /// The first step's commit, under the replacement.
    stale: Option<Commit>,
    successor: AllocationId,
    /// The successor's slot right after the stale commit.
    spared: (SlotState, u32),
    /// The second step's commit.
    later: Option<Commit>,
    /// The identity and key of the lease the second step's hook took, if it took one.
    held: Option<(AllocationId, bool)>,
    /// Whether a second right on the held successor was granted while it was retired.
    second_right: Option<bool>,
    /// The slot a publication made under the lease took.
    beside: Option<usize>,
    /// The successor's slot after each round of certification and service, the lease still held.
    rounds: Vec<(SlotState, u32)>,
    /// The successor's slot after the lease, if any, was dropped and before service ran again.
    unserviced: Option<(SlotState, u32)>,
    /// The successor's slot after the lease, if any, was dropped and service ran again.
    released: Option<(SlotState, u32)>,
    /// Certification or service panicked.
    panicked: bool,
}

/// Runs the history; `hold` takes a lease on the successor between its selection and its commit.
fn history(hold: bool) -> Seen {
    let leaked: &'static Storage<TestPlatform> = Box::leak(Box::new(ready(8)));
    STORAGE.with(|cell| cell.set(Some(leaked)));
    let first = publish(leaked, key(1), u64::MAX, &body(1));
    let stale = step(Some(replace_victim));
    let successor = SUCCESSOR
        .with(Cell::get)
        .expect("the first step's hook published a successor");
    let spared = state(successor);
    let later = step(hold.then_some(hold_successor as fn()));
    let lease = LEASE.with(|cell| cell.borrow_mut().take());
    let mut seen = Seen {
        first,
        stale,
        successor,
        spared,
        later,
        held: lease
            .as_ref()
            .map(|lease| (lease.id(), hit_key(lease) == key(1))),
        second_right: None,
        beside: None,
        rounds: Vec::new(),
        unserviced: None,
        released: None,
        panicked: false,
    };
    // A panic of certification or service is the verdict of this run, not the end of the test thread.
    let drained = catch_unwind(AssertUnwindSafe(|| {
        let mut rounds = Vec::new();
        let (mut second_right, mut beside) = (None, None);
        for round in 0..ROUNDS {
            drain(leaked);
            rounds.push(state(successor));
            if let (0, Some(lease)) = (round, lease.as_ref()) {
                let second = lease.duplicate();
                second_right = Some(second.id() == successor);
                drop(second);
                beside = Some(publish(leaked, key(3), u64::MAX, &body(3)).slot_index());
            }
        }
        (rounds, second_right, beside)
    }));
    match drained {
        Ok((rounds, second_right, beside)) => {
            seen.rounds = rounds;
            seen.second_right = second_right;
            seen.beside = beside;
            drop(lease);
            seen.unserviced = Some(state(successor));
            let released = catch_unwind(AssertUnwindSafe(|| {
                drain(leaked);
                state(successor)
            }));
            seen.panicked = released.is_err();
            seen.released = released.ok();
        }
        Err(_) => {
            // The slot's count is no longer trusted, so the lease is not returned through it.
            std::mem::forget(lease);
            seen.panicked = true;
        }
    }
    seen
}

/// The premises both tests share: the stale commit is `Absent` and spares the successor, and the next step
/// evicts the successor by its own identity.
fn premises(seen: &Seen) {
    assert_ne!(
        seen.first, seen.successor,
        "the successor has its own identity"
    );
    assert_eq!(
        seen.stale,
        Some(Commit::Absent),
        "the commit under a completed replacement"
    );
    assert_eq!(
        seen.spared,
        (SlotState::Resident, seen.successor.incarnation()),
        "the stale commit spares the successor"
    );
    assert!(
        matches!(seen.later, Some(Commit::Evicted { victim, .. }) if victim == seen.successor),
        "the next step evicts the successor by its own identity: {:?}",
        seen.later
    );
}

#[test]
fn an_unheld_successor_evicted_by_a_later_step_is_freed_at_its_incarnation() {
    let seen = history(false);
    premises(&seen);
    assert_eq!(seen.held, None, "no reader holds the successor");
    assert!(!seen.panicked, "certification and service ran: {seen:?}");
    let free = (SlotState::Free, seen.successor.incarnation());
    assert_eq!(
        seen.rounds,
        vec![free; ROUNDS],
        "reclamation frees the unheld successor's slot"
    );
    assert_eq!(
        seen.released,
        Some(free),
        "the slot stays free at the successor's incarnation"
    );
}

#[test]
fn a_held_successor_evicted_by_a_later_step_stays_retired_until_its_lease_ends() {
    let seen = history(true);
    premises(&seen);
    assert_eq!(
        seen.held,
        Some((seen.successor, true)),
        "the reader's lease names the successor under its key"
    );
    assert!(
        !seen.panicked,
        "service of a held, evicted successor ran without a panic: {seen:?}"
    );
    let retired = (SlotState::Retired, seen.successor.incarnation());
    assert_eq!(
        seen.rounds,
        vec![retired; ROUNDS],
        "a held successor stays retired through certification and service"
    );
    assert_eq!(
        seen.second_right,
        Some(true),
        "the retired successor admits a second right"
    );
    assert!(
        seen.beside
            .is_some_and(|slot| slot != seen.successor.slot_index()),
        "a publication under the lease took the held slot: {:?}",
        seen.beside
    );
    assert_eq!(
        seen.unserviced,
        Some(retired),
        "the lease's drop leaves the slot retired for service to free"
    );
    assert_eq!(
        seen.released,
        Some((SlotState::Free, seen.successor.incarnation())),
        "the slot is freed only once the lease ended and service ran again"
    );
}
