//! A cancelled GET keeps its request slot until the device ends the read it holds.
//!
//! Property, judged by the rule "a cancel released custody before the read's terminal": a GET that
//! its client cancels while the device still holds its read keeps its request, and so its slot and its
//! peer's share, until the device ends that read.
//!
//! Both histories run the single-owner world, whose scene publishes version A under key 1 before the run.
//! Client 1 issues a GET of key 1 and the history holds the GET's device read, so the read's command stays
//! outstanding on the device until the history releases it.
//!
//! - `cr1-get-cancelled-on-a-held-read`: the client cancels the GET. The history records
//!   the peer's active requests and the owner's live requests (active and draining) as the cancel begins,
//!   and waits until the owner ended the cancelled request: the peer holds fewer active requests. While
//!   the device still holds the read's command, `cancel_kept` fails with the rule unless the owner's live
//!   requests number at least those it held when the cancel began. The history then releases the read
//!   and requires the owner's requests to drain.
//! - `cr1-get-uncancelled-on-a-held-read`: the same steps with no cancel. The history
//!   records the same counts at the same point, waits the cancel's bound, and judges the same rule on the
//!   same reading while the device still holds the read's command. It then releases the read, requires the
//!   GET to return version A's exact bytes, and requires the owner's requests to drain.
//!
//! - `cr1-get-uncancelled-released` and `cr1-get-uncancelled-failed-read`: controls over the steps of
//!   `cr1-get-uncancelled-on-a-held-read`. `cr1-get-uncancelled-released` judges the owner's live
//!   requests as none; `cr1-get-uncancelled-failed-read` judges the GET as failed with no byte.
//!
//! Premises, each ending the run unsuccessful under its name when it does not form: the device read is
//! held before the cancel; the owner ended the cancelled request within the cancel's bound (in the sibling,
//! the owner kept the uncancelled request active); the device holds a command at the check.
//!
//! The first history's steps are those of the history `h2-get` of `histories.rs` up to its drain, with the
//! transmit references released before the drain as `h1-get` releases them.

use super::old_rights::{ENDED_SHORT, judge_complete};
use super::*;

/// The rule both histories judge (`narrate/rules.rs`).
const RELEASED_EARLY: &str = "a cancel released custody before the read's terminal";

const UNCANCELLED: &str = "the held read's GET stayed uncancelled";
const STILL_ACTIVE: &str = "the owner kept the uncancelled request active";
const HELD_AT_CHECK: &str = "the device held the uncancelled request's commands at its check";
const KEPT: &str = "the uncancelled request kept custody";
const DRAINED: &str = "the uncancelled request drained after its terminal";

/// The sibling's point of no cancel: records what `cancel_old` records, and sends nothing.
fn no_cancel(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    cancel_began(world, PeerId(1), now);
    mark(world, UNCANCELLED)
}

/// Ready once the bound a cancel has to reach the owner has passed since the point of no cancel.
fn cancel_bound_passed(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    now > world.history.since + CANCEL_BOUND_US
}

/// The sibling's judgment, on the reading `cancel_kept` judges: while the device holds the read's command,
/// the owner's live requests number at least those it held at the point of no cancel, and every transmit
/// reference withheld then is still withheld.
fn uncancelled_kept(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let live = u64::from(world.scene.owner.census().live());
    judge_uncancelled(world, live)
}

/// A control: the owner's live requests are judged as none, the count of an owner that released the
/// request while the device held its read.
fn uncancelled_released(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    judge_uncancelled(world, 0)
}

fn judge_uncancelled(world: &mut Mixed<'_, '_, '_>, live: u64) -> u64 {
    let (peer, active) = world
        .history
        .cancelled
        .expect("the counts recorded at the point of no cancel");
    for (formed, premise) in [
        (
            world.scene.owner.peer_census(peer).active >= active,
            STILL_ACTIVE,
        ),
        (world.scene.control.outstanding() > 0, HELD_AT_CHECK),
    ] {
        if !formed {
            world.first.record(Failure::Unsuccessful(premise));
            return 0;
        }
        mark(world, premise);
    }
    if live < world.history.kept || withheld(world) < world.history.refs {
        return fail(world, Obligation::Custody, RELEASED_EARLY);
    }
    mark(world, KEPT)
}

fn uncancelled_read(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.read(1);
    let get = world.gets[1].as_ref().expect("the old GET");
    let (outcome, bytes) = (get.outcome, get.bytes.clone());
    judge_complete(world, outcome, &bytes)
}

/// A control: the uncancelled GET is judged as failed with no byte delivered.
fn uncancelled_read_failed(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.read(1);
    judge_complete(world, Some(Outcome::Failed(Status::DeviceError)), &[])
}

fn mark_uncancelled_drained(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    mark(world, DRAINED)
}

const CANCELLED: [Step; 9] = [
    step("arm", always, arm),
    step("old-get", active_get, old_get),
    step("old-read-held", read_held, mark_read_held),
    step("cancel", always, cancel_old),
    step("cancel-kept", cancel_received, cancel_kept),
    step("release-old-read", always, release_reads),
    step("release-nic", always, release_nic),
    step("drained", drained, mark_drained),
    JUDGE,
];

const UNCANCELLED_STEPS: [Step; 10] = [
    step("arm", always, arm),
    step("old-get", active_get, old_get),
    step("old-read-held", read_held, mark_read_held),
    step("no-cancel", always, no_cancel),
    step("uncancelled-kept", cancel_bound_passed, uncancelled_kept),
    step("release-old-read", always, release_reads),
    step("old-right", old_decided, uncancelled_read),
    step("release-nic", always, release_nic),
    step("drained", drained, mark_uncancelled_drained),
    JUDGE,
];

const UNCANCELLED_RELEASED: [Step; 10] = replaced(
    UNCANCELLED_STEPS,
    "uncancelled-kept",
    step(
        "uncancelled-released",
        cancel_bound_passed,
        uncancelled_released,
    ),
);

const UNCANCELLED_FAILED_READ: [Step; 10] = replaced(
    UNCANCELLED_STEPS,
    "old-right",
    step("old-right-failed", old_decided, uncancelled_read_failed),
);

const CANCELLED_WITNESSES: &[&str] = &[
    "old read held",
    "held read cancelled",
    "the owner ended the cancelled request",
    "the device held the cancelled request's commands at its check",
    "cancel kept custody",
    "the cancelled request drained after its terminal",
];

const UNCANCELLED_WITNESSES: &[&str] = &[
    "old read held",
    UNCANCELLED,
    STILL_ACTIVE,
    HELD_AT_CHECK,
    KEPT,
    "old right returned its version",
    DRAINED,
];

const CANCELLED_JUDGED: &[Obligation] = &[Obligation::Custody, Obligation::Resources];

const UNCANCELLED_JUDGED: &[Obligation] = &[Obligation::Custody, Obligation::Bytes];

pub(super) const CHECKS: [(&str, Obligation); 1] = [(KEPT, Obligation::Custody)];

const KEPT_PREMISE: &[&str] = &["old read held", UNCANCELLED, STILL_ACTIVE, HELD_AT_CHECK];

const READ_PREMISE: &[&str] = &["old read held", UNCANCELLED, KEPT, "old read released"];

pub(super) const CANCELLED_READS: [History; 4] = [
    history(
        "cr1-get-cancelled-on-a-held-read",
        &CANCELLED,
        CANCELLED_WITNESSES,
        CANCELLED_JUDGED,
        Expect::Pass,
    ),
    history(
        "cr1-get-uncancelled-on-a-held-read",
        &UNCANCELLED_STEPS,
        UNCANCELLED_WITNESSES,
        UNCANCELLED_JUDGED,
        Expect::Pass,
    ),
    control(
        history(
            "cr1-get-uncancelled-released",
            &UNCANCELLED_RELEASED,
            UNCANCELLED_WITNESSES,
            UNCANCELLED_JUDGED,
            Expect::Violation(Obligation::Custody, RELEASED_EARLY),
        ),
        KEPT_PREMISE,
    ),
    control(
        history(
            "cr1-get-uncancelled-failed-read",
            &UNCANCELLED_FAILED_READ,
            UNCANCELLED_WITNESSES,
            UNCANCELLED_JUDGED,
            Expect::Violation(Obligation::Bytes, ENDED_SHORT),
        ),
        READ_PREMISE,
    ),
];
