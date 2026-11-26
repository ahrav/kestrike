//! One schedule over the composed endpoint of `net::composed_tests`: a GET streams through `Burst` on a
//! `MockPort` that withholds its transmit returns, so the device holds the GET's chains; a fault then makes the
//! transport recover; the device is set to return every chain within a turn; the owner closes. The two faulted
//! tests run it on a port that proves no stop, so the link is lost, and read the result through
//! `Owner::blockers()`: the chains stay out and the closed owner stays blocked by the draining GET alone. The
//! chains out of the header pool are compared with the chains the mock device holds, so a chain the transport
//! took back while the device may still read it shows as a difference. The control runs the same steps on a
//! port that proves its stop and observes one completed recovery, chains back in the pool while the device
//! still withholds its returns, and the close complete.
//!
//! Each test computes its observations while the fixtures live, drops the fixtures, then asserts.

use crate::native::Link;
use crate::storage::QuiesceProgress;
use crate::storage::owner_fixture::storage;

use super::composed_tests::composed;
use super::fetch::Outcome;
use super::owner::Blockers;
use super::owner_tests::{key, payload};

/// What makes the transport recover.
#[derive(Debug, Clone, Copy)]
enum Fault {
    /// The port's service reports a pending reset.
    PendingReset,
    /// A burst stops short and reports its first refused chain uncertain.
    UncertainPost,
}

/// What one run of the schedule showed.
#[derive(Debug)]
struct Observed {
    /// Header buffers the device held when the fault was armed.
    held_at_fault: u32,
    /// Whether the transport left `Link::Up` within the turns the schedule allows.
    recovered: bool,
    link: Link,
    /// Recoveries the transport started from the fault on, and the ones among them that left the link up.
    resets: u64,
    recoveries: u64,
    /// Chains the transport quarantined from the fault on.
    quarantined: u64,
    /// Header buffers out of the pool once the recovery ended.
    held_after_recovery: u32,
    /// Chains the mock device held once the recovery ended.
    device_after_recovery: u32,
    /// Header buffers out of the pool 40 turns after the device was set to return every chain within a turn.
    held_before_close: u32,
    /// Header buffers out of the pool 400 turns after the close.
    held_after_close: u32,
    blockers: Option<Blockers>,
    /// Whether the GET's client learned `Complete`.
    complete: bool,
}

/// Runs the schedule on a port that proves `proven_stops` stops before every later stop is unproven.
fn schedule(proven_stops: u32, fault: Fault) -> Observed {
    let storage = storage(8);
    let object = payload(40_000, 31);
    let mut c = composed(&storage, &[(key(1), 0, &object)], |port| {
        port.proven_stops = proven_stops
    });
    c.withhold_returns();
    let sent_before = c.owner.transport().report().sent;
    let get = c
        .client
        .get(key(1), 0, 1 << 20, c.turn * 100, 30_000_000)
        .expect("the active session admits a GET");
    c.turns_until(200, |c| c.owner.transport().report().sent > sent_before);
    let before_fault = c.owner.transport().report();
    let held_at_fault = match fault {
        Fault::PendingReset => {
            // The stream stalls once the device holds the read's sources, so these turns only settle it.
            c.turns(40);
            let held = c.chains_held();
            c.port().reset = true;
            held
        }
        Fault::UncertainPost => {
            let held = c.chains_held();
            let port = c.port();
            port.accept = 1;
            port.uncertain = true;
            held
        }
    };
    let recovered = c.turns_until(200, |c| c.owner.transport().link() != Link::Up);
    c.turns(40);
    let link = c.owner.transport().link();
    let after_recovery = c.owner.transport().report();
    let held_after_recovery = c.chains_held();
    let device_after_recovery = c.port().held.len() as u32;
    c.return_within_turn();
    c.turns(40);
    while c.client.take(get).is_some() {}
    let held_before_close = c.chains_held();
    let _ = c.owner.close(c.turn * 100);
    c.turns(400);
    let observed = Observed {
        held_at_fault,
        recovered,
        link,
        resets: after_recovery.resets - before_fault.resets,
        recoveries: after_recovery.recoveries - before_fault.recoveries,
        quarantined: after_recovery.quarantined - before_fault.quarantined,
        held_after_recovery,
        device_after_recovery,
        held_before_close,
        held_after_close: c.chains_held(),
        blockers: c.owner.blockers(),
        complete: matches!(c.client.outcome(get), Some(Outcome::Complete)),
    };
    drop(c);
    drop(storage);
    observed
}

/// Asserts what the owner discloses for a lost link: the device's chains stay out through the close, and the closed
/// owner, its volume quiesced, stays blocked by the one draining GET.
fn assert_custody_retained_and_close_blocked(seen: &Observed) {
    assert!(
        seen.held_at_fault > 0,
        "premise: the GET put chains with the device before the fault: {seen:?}"
    );
    assert!(
        seen.recovered && seen.link == Link::Lost && (seen.resets, seen.recoveries) == (1, 0),
        "premise: the transport started one recovery, its stop was unproven, and the link is lost: {seen:?}"
    );
    assert!(
        seen.device_after_recovery >= seen.held_at_fault,
        "premise: the device kept every chain it held through the unproven stop: {seen:?}"
    );
    assert_eq!(
        seen.held_after_recovery, seen.device_after_recovery,
        "every chain the device holds stays out of the pool through the unproven stop: {seen:?}"
    );
    assert_eq!(
        (seen.held_before_close, seen.held_after_close),
        (seen.held_after_recovery, seen.held_after_recovery),
        "a lost device returns nothing, before the close or after it: {seen:?}"
    );
    let blockers = seen.blockers;
    assert!(
        blockers.is_some(),
        "the closed owner's blockers hold while the device's chains are out: {seen:?}"
    );
    let blockers = blockers.expect("checked above");
    assert!(
        !blockers.open && matches!(blockers.quiesce, Some(QuiesceProgress::Quiesced(_))),
        "the owner closed and its volume quiesced, so only its requests block it: {seen:?}"
    );
    assert_eq!(
        (blockers.census.active, blockers.census.draining),
        (0, 1),
        "the GET holding the device's chains is the one blocker, draining: {seen:?}"
    );
    assert!(
        !seen.complete,
        "the GET's client never learns Complete across the lost link: {seen:?}"
    );
}

/// A pending reset makes the transport recover while the device holds the stalled GET's chains; the stop is
/// unproven, so the link is lost, every chain stays out, and the close stays blocked by the draining GET.
#[test]
fn a_reset_with_an_unproven_stop_keeps_the_chains_out_and_the_close_blocked() {
    let seen = schedule(0, Fault::PendingReset);
    assert_custody_retained_and_close_blocked(&seen);
}

/// An uncertain post makes the transport recover while the device holds the GET's first chains; the stop is
/// unproven, so the link is lost, every chain stays out, the quarantined one included, and the close stays
/// blocked by the draining GET.
#[test]
fn an_uncertain_post_with_an_unproven_stop_keeps_the_chains_out_and_the_close_blocked() {
    let seen = schedule(0, Fault::UncertainPost);
    assert_eq!(
        seen.quarantined, 1,
        "premise: the short burst left one chain uncertain and the transport quarantined it: {seen:?}"
    );
    assert_custody_retained_and_close_blocked(&seen);
}

/// The control: the same steps on a port that proves its stop. The reset makes the transport recover once, the
/// stop returns the device's chains while the device still withholds its own returns, the link comes back up,
/// and the closed owner drains to no blocker.
#[test]
fn the_same_reset_with_a_proven_stop_returns_the_chains_and_the_close_completes() {
    let seen = schedule(u32::MAX, Fault::PendingReset);
    assert!(
        seen.held_at_fault > 0,
        "premise: the GET put chains with the device before the fault: {seen:?}"
    );
    assert_eq!(
        (seen.resets, seen.recoveries, seen.link),
        (1, 1, Link::Up),
        "the reset made the transport recover once, and the proven stop let the device restart: {seen:?}"
    );
    assert!(
        seen.held_after_recovery < seen.held_at_fault,
        "the proven stop returned chains while the device withheld its own returns: {seen:?}"
    );
    assert_eq!(
        seen.held_after_close, 0,
        "every chain returned once the stop was proven and the device returned its chains: {seen:?}"
    );
    assert_eq!(
        seen.blockers, None,
        "the owner drained: every chain returned, every request ended: {seen:?}"
    );
}
