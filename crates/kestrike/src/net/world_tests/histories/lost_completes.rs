//! A GET whose COMPLETE was lost on the link still ends with the object.
//!
//! Property: a GET whose final frame was lost on the link still ends with the object. The rule this
//! file judges is "a GET after a lost final frame ended without the object", which `long_exact` of
//! `histories/incidents.rs` raises; `narrate/rules.rs` holds its text.
//!
//! Both histories run the single-owner world. The owner publishes a three-fragment object under key 1, the
//! history arms the link between the owner and the reading client, and the client issues a GET of the key.
//!
//! - `lc1-get-complete-dropped`: the link drops the first COMPLETE toward the client and passes
//!   every later frame. The client holds every DATA fragment and no terminal, so it sends its final ACK
//!   again, and the owner, whose request has ended, must answer that ACK with the COMPLETE once more. The
//!   capture of the dropped COMPLETE is the premise: a run in which the link dropped none ends unsuccessful
//!   under LOST, whatever the GET did. Under the premise, a GET that ends in anything but `Complete` is the
//!   rule, and one that completes with other bytes is the rule's companion.
//! - `lc1-get-complete-carried`: the same steps with a link that only observes. Its
//!   premise is that the link carried a COMPLETE toward the client and dropped none; the GET is judged the
//!   same way.
//!
//! The steps that arm the drop and judge the read are those of `i3-get-complete` in
//! `histories/incidents.rs`. These histories add the link's capture of the COMPLETE as a premise.

use super::super::super::frame::Kind;
use super::incidents::{CLIENT, drop_complete, long_exact, set_rules};
use super::*;

const ARMED: &str = "the COMPLETE drop armed";
const OBSERVED: &str = "the link observed without a rule";
const LOST: &str = "the COMPLETE was lost";
const CARRIED: &str = "the COMPLETE was carried";
/// The mark `histories.rs` lists as a check of `Obligation::Bytes`.
const EXACT: &str = "the GET after the loss ended exactly";

/// The COMPLETE frames the link saw on their way to the client and dropped, or carried when `dropped` is
/// unset.
fn completes(world: &Mixed<'_, '_, '_>, dropped: bool) -> usize {
    world.scene.nets[0]
        .borrow()
        .rules()
        .captures()
        .iter()
        .filter(|capture| {
            capture.kind == Some(Kind::Complete)
                && capture.toward == CLIENT
                && capture.decision.drop.is_some() == dropped
        })
        .count()
}

/// The sibling: the link captures every frame and changes none.
fn observe(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    set_rules(world, Vec::new());
    mark(world, OBSERVED)
}

/// Ready once the link dropped a COMPLETE, or once the GET ended with none dropped.
fn lost_or_decided(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    completes(world, true) > 0 || fresh_decided(world, now)
}

/// The premise of the fault: the link dropped exactly one COMPLETE toward the client. It reads the link's
/// captures alone, which hold the drop whatever the owner does afterwards.
fn complete_lost(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let lost = completes(world, true) == 1;
    premised(world, lost, LOST)
}

/// The sibling's premise: the link carried a COMPLETE toward the client and dropped none.
fn complete_carried(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let carried = completes(world, true) == 0 && completes(world, false) > 0;
    premised(world, carried, CARRIED)
}

const LOSSY: [Step; 8] = [
    step("fill-long", always, fill_long),
    step("publish-long", fill_written, publish_fill),
    step("release-lease", always, release_reads),
    step("arm-link", always, drop_complete),
    step("get", active_put, fresh_get),
    step("complete-on-link", lost_or_decided, complete_lost),
    step("read", fresh_decided, long_exact),
    JUDGE,
];

const CLEAR: [Step; 8] = replaced(
    replaced(LOSSY, "arm-link", step("arm-link", always, observe)),
    "complete-on-link",
    step("complete-on-link", fresh_decided, complete_carried),
);

const LOSSY_WITNESSES: &[&str] = &[ARMED, LOST, EXACT];

const CLEAR_WITNESSES: &[&str] = &[OBSERVED, CARRIED, EXACT];

const JUDGED: &[Obligation] = &[Obligation::Bytes];

pub(super) const LOST_COMPLETES: [History; 2] = [
    control(
        history(
            "lc1-get-complete-dropped",
            &LOSSY,
            LOSSY_WITNESSES,
            JUDGED,
            Expect::Pass,
        ),
        &[LOST],
    ),
    control(
        history(
            "lc1-get-complete-carried",
            &CLEAR,
            CLEAR_WITNESSES,
            JUDGED,
            Expect::Pass,
        ),
        &[CARRIED],
    ),
];
