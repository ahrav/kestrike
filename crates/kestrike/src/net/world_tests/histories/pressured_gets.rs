//! A GET the owner refuses under pressure ends at the client no later than its one deadline, also
//! when every refusal is lost.
//!
//! Property: a GET the owner refuses under pressure ends at its client no later than its one
//! deadline, the issue time plus the wait the GET was issued with, also when no refusal reaches the
//! client. The rule this file judges is OUTLIVED below.
//!
//! Both histories run the single-owner world. Client 1 fills its share with two GETs of key 1 whose reads
//! the device holds, then issues a third GET of key 1 with the wait `WAIT_US`, which the owner refuses with
//! an ERROR, again for each retransmission. The judging step runs once the third GET decided or the world
//! time passed the issue plus `WAIT_US`, and fails with the rule in the second case, decided or not. The two
//! saturating GETs wait three times as long, so they hold the share for the third GET's whole life; that
//! both are still undecided when the third is judged is a premise of both histories.
//!
//! - `pg1-get-refusals-dropped`: client 1's link drops every ERROR toward the client, so only
//!   the client's own deadline ends the GET. That the link dropped at least one ERROR and delivered none is
//!   a premise, read from the link's captures after the judgment.
//! - `pg1-get-refusal-delivered`: the link changes no frame; that it delivered an ERROR
//!   to the client is the sibling's premise.
//! - `pg1-get-undecided-past-deadline`: the control. The steps of `pg1-get-refusals-dropped` with the
//!   third GET issued with the wait `2 * WAIT_US`, so it is undecided when the judged deadline passes.
//!
//! A premise that does not form ends the run unsuccessful under its name. Afterwards both histories release
//! the held reads and require each saturating GET to complete with the resident object's exact bytes.
//!
//! The steps that set the link's rules and read its captures follow `histories/incidents.rs`, whose own
//! are private.

use super::super::super::frame::Kind;
use super::super::super::rules::{Chain, Effect, MANIFEST, Rule, Selector};
use super::incidents::{over_share_decided, over_share_timed};
use super::*;

/// The rule both histories judge.
const OUTLIVED: &str = "a pressured request outlived its one deadline";

const READS_ARMED: &str = "read holds armed";
const READS_HELD: &str = "saturating reads held";
const DROP_ARMED: &str = "the link drops every ERROR toward the client";
const OBSERVED: &str = "the link observes and changes no frame";
const ISSUED: &str = "a GET past the share was issued";
const IN_TIME: &str = "the pressured GET ended by its one deadline";
const SATURATED: &str = "the share stayed saturated to the GET's end";
const UNDECIDED: &str = "the pressured GET was undecided past its one deadline";
const LOST: &str = "the link lost every refusal of the pressured GET";
const DELIVERED: &str = "the link delivered the pressured GET's refusal";

/// The client's end of a link.
const CLIENT: usize = 0;

/// Client 1's link, which carries the pressured GET and its refusals.
const LINK: usize = 1;

/// Every read command the device accepts from here on is held, and transmit references return as
/// usual; the step marks that the read holds are armed.
pub(super) fn arm_reads(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.hold_reads = true;
    mark(world, READS_ARMED)
}

/// One of the two GETs that fill client 1's share. Each waits `3 * WAIT_US`, past the deadline of the
/// GET issued beyond them, and completes once the history releases its read.
fn saturate_long(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    match world.scene.clients[1].get(key(1), 0, 1 << 20, now, 3 * super::super::WAIT_US) {
        Ok(id) => {
            world.history.ids.push(id);
            if world.history.ids.len() == 2 {
                mark(world, "share saturated")
            } else {
                STAY
            }
        }
        Err(_) => STAY,
    }
}

fn mark_reads_held(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    mark(world, READS_HELD)
}

/// Installs `rules` on client 1's link, with one tap after them that captures each frame's committed
/// decision.
fn set_rules(world: &mut Mixed<'_, '_, '_>, rules: Vec<Rule>) {
    let taps = [rules.len()];
    let chain = Chain::new(rules, &taps, &MANIFEST).expect("a bounded chain");
    world.scene.nets[LINK].borrow_mut().set_rules(chain);
}

/// ERROR frames toward the client that client 1's link has dropped, or carried when `dropped` is false.
fn errors(world: &Mixed<'_, '_, '_>, dropped: bool) -> usize {
    world.scene.nets[LINK]
        .borrow()
        .rules()
        .captures()
        .iter()
        .filter(|capture| {
            capture.kind == Some(Kind::Error)
                && capture.toward == CLIENT
                && capture.decision.drop.is_some() == dropped
        })
        .count()
}

/// The fault: from here on the link drops every ERROR toward client 1, the first refusal and each one
/// a retransmitted GET draws.
fn lose_errors(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let refusal = Selector::All(vec![Selector::Kind(Kind::Error), Selector::Toward(CLIENT)]);
    set_rules(world, vec![Rule::new(refusal, Effect::Drop)]);
    mark(world, DROP_ARMED)
}

/// The sibling: the link captures every frame and changes none.
fn observe(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    set_rules(world, Vec::new());
    mark(world, OBSERVED)
}

/// A control: the client keeps the GET past the share for two deadlines, and the history judges the
/// one deadline from its issue.
fn over_share_kept(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let wait = super::super::WAIT_US;
    match world.scene.clients[1].get(key(1), 0, 1 << 20, now, 2 * wait) {
        Ok(id) => {
            world.history.ids.push(id);
            world.history.since = now;
            world.history.wake = Some(now + wait + 1);
            mark(world, ISSUED)
        }
        Err(_) => STAY,
    }
}

/// Judges the GET past the share at `now`: a time later than `WAIT_US` after the issue is the rule,
/// whatever the outcome, and marks `UNDECIDED` when the GET holds none. A GET decided in time is
/// collected and retired, so the heal judges the two saturating GETs alone. Then the premises: both
/// saturating GETs are still undecided, and `formed`, read from the link's captures, decides `witness`.
fn judge_deadline(
    world: &mut Mixed<'_, '_, '_>,
    now: u64,
    formed: fn(&Mixed<'_, '_, '_>) -> bool,
    witness: &'static str,
) -> u64 {
    let id = world.history.ids[2];
    if deadline_passed(world, now) {
        if world.scene.clients[1].outcome(id).is_none() {
            mark(world, UNDECIDED);
        }
        return fail(world, Obligation::Resources, OUTLIVED);
    }
    let _ = world.collect_get(1, id);
    let _ = world.scene.clients[1].retire(id);
    world.history.ids.truncate(2);
    mark(world, IN_TIME);
    if !saturated_undecided(world) {
        world.first.record(Failure::Unsuccessful(SATURATED));
        return 0;
    }
    mark(world, SATURATED);
    if !formed(world) {
        world.first.record(Failure::Unsuccessful(witness));
        return 0;
    }
    mark(world, witness)
}

fn deadline_passed(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    now > world.history.since + super::super::WAIT_US
}

/// Ready once the GET past the share decided or its one deadline passed, so a GET its client never
/// ends is judged at the deadline.
fn over_share_due(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    over_share_decided(world, now) || deadline_passed(world, now)
}

/// Whether neither saturating GET has an outcome at its client.
fn saturated_undecided(world: &Mixed<'_, '_, '_>) -> bool {
    world
        .history
        .ids
        .iter()
        .all(|&id| world.scene.clients[1].outcome(id).is_none())
}

fn every_refusal_lost(world: &Mixed<'_, '_, '_>) -> bool {
    errors(world, true) >= 1 && errors(world, false) == 0
}

fn refusal_delivered(world: &Mixed<'_, '_, '_>) -> bool {
    errors(world, false) >= 1 && errors(world, true) == 0
}

fn ended_unanswered(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    judge_deadline(world, now, every_refusal_lost, LOST)
}

fn ended_answered(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    judge_deadline(world, now, refusal_delivered, DELIVERED)
}

const UNANSWERED: [Step; 9] = [
    step("arm", always, arm_reads),
    step("saturate", active_get, saturate_long),
    step("reads-held", reads_held, mark_reads_held),
    step("link", always, lose_errors),
    step("over-share", always, over_share_timed),
    step("over-share-ended", over_share_due, ended_unanswered),
    step("release", always, release_everything),
    step("healed", saturated_drained, saturated_exact),
    JUDGE,
];

const ANSWERED: [Step; 9] = replaced(
    replaced(UNANSWERED, "link", step("link", always, observe)),
    "over-share-ended",
    step("over-share-ended", over_share_due, ended_answered),
);

const KEPT_PAST_DEADLINE: [Step; 9] = replaced(
    UNANSWERED,
    "over-share",
    step("over-share-kept", always, over_share_kept),
);

const UNANSWERED_WITNESSES: &[&str] = &[
    "share saturated",
    READS_HELD,
    DROP_ARMED,
    ISSUED,
    IN_TIME,
    SATURATED,
    LOST,
    "qualified exact read",
];

const ANSWERED_WITNESSES: &[&str] = &[
    "share saturated",
    READS_HELD,
    OBSERVED,
    ISSUED,
    IN_TIME,
    SATURATED,
    DELIVERED,
    "qualified exact read",
];

const JUDGED: &[Obligation] = &[Obligation::Resources];

pub(super) const CHECKS: [(&str, Obligation); 1] = [(IN_TIME, Obligation::Resources)];

const UNDECIDED_PREMISE: &[&str] = &[READS_HELD, DROP_ARMED, ISSUED, UNDECIDED];

pub(super) const PRESSURED_GETS: [History; 3] = [
    history(
        "pg1-get-refusals-dropped",
        &UNANSWERED,
        UNANSWERED_WITNESSES,
        JUDGED,
        Expect::Pass,
    ),
    history(
        "pg1-get-refusal-delivered",
        &ANSWERED,
        ANSWERED_WITNESSES,
        JUDGED,
        Expect::Pass,
    ),
    control(
        history(
            "pg1-get-undecided-past-deadline",
            &KEPT_PAST_DEADLINE,
            UNANSWERED_WITNESSES,
            JUDGED,
            Expect::Violation(Obligation::Resources, OUTLIVED),
        ),
        UNDECIDED_PREMISE,
    ),
];
