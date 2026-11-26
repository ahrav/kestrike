//! A PUT RESULT that arrives after the upload's deadline decided it `Unknown` settles the upload
//! `Published`.
//!
//! Property: a PUT RESULT that matches an upload and arrives after the upload's deadline decided it
//! `Unknown` settles the upload `Published`. The rule this file judges is UNRESOLVED below.
//!
//! Both histories run one upload of version B under key 1 from the uploading client of the single-owner world.
//!
//! - `ru1-put-result-after-unknown`: a link rule delays every PUT RESULT toward the client by
//!   the request's wait, so the upload's deadline decides it `Unknown` while its RESULT is in flight. The
//!   history marks that, records how many RESULT frames the client's uploads had accepted, and waits until
//!   that count rose or the owner's retention of the result passed. The count rising is a premise: a run in
//!   which the delayed RESULT never reached the client ends unsuccessful under its name. With the RESULT
//!   accepted, an outcome other than `Published` is the rule.
//! - `ru1-put-result-before-unknown`: the same steps with no rule armed. The upload is
//!   decided by its first RESULT without going `Unknown`, and the same judgment finds it `Published`.
//! - `ru1-put-result-left-unknown` is a control: the first history's steps, whose judgment is handed a
//!   planted outcome, `Unknown`, once the RESULT was accepted, and fails it through the rule.
//!
//! The steps that arm the delay and watch the outcome are those of `i3-put-late` in
//! `histories/incidents.rs`. That history fails through a rule when no RESULT arrived; these treat the
//! arrival as a premise.

use super::incidents::{
    delay_results, mark_unknown, resolved_or_late, result_received, went_unknown,
};
use super::*;

/// The rule both histories judge.
const UNRESOLVED: &str = "a delayed matching RESULT left the unknown upload unresolved";

const ARMED: &str = "a RESULT delay armed";
const UNARMED: &str = "no RESULT delay armed";
const WENT_UNKNOWN: &str = "the upload went unknown before its RESULT arrived";
const DECIDED: &str = "the upload was decided by its first RESULT";
const ARRIVED: &str = "the RESULT reached the client's upload";
/// The mark of the judgment, a check of `Obligation::History`.
const RESOLVED: &str = "a matching RESULT settled the upload published";

/// The obligation the judgment's mark witnesses.
pub(super) const CHECKS: [(&str, Obligation); 1] = [(RESOLVED, Obligation::History)];

/// The sibling arms nothing.
fn delay_nothing(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    mark(world, UNARMED)
}

/// Begins the upload of version B and sets the history's deadline to the end of the owner's retention of
/// its result: the request's wait, then the owner's linger.
fn begin(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.allowed = vec![version_a(), version_b()];
    world.history.deadline = now + super::super::WAIT_US + super::super::OWNER.serve.linger_us;
    world.history.wake = Some(world.history.deadline + 1);
    put_begin_with(world, CacheVersion(0), version_b(), LABEL_B, now)
}

/// The sibling: the upload's first decision is not `Unknown`. The count of accepted RESULT frames is
/// taken as zero, so the judgment below requires the one RESULT that decided it.
fn mark_decided(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.results_received = 0;
    let id = world.history.put.expect("a PUT");
    let outcome = world.scene.clients[0].put_outcome(id);
    premised(
        world,
        outcome.is_some() && outcome != Some(UploadOutcome::Unknown),
        DECIDED,
    )
}

/// The premise of the judgment: the client's uploads accepted a RESULT.
fn arrived(world: &mut Mixed<'_, '_, '_>) -> bool {
    let received = result_received(world);
    premised(world, received, ARRIVED) != 0
}

/// With a RESULT accepted by the client's uploads, the upload's outcome is judged.
fn settled(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if !arrived(world) {
        return 0;
    }
    let id = world.history.put.expect("a PUT");
    let outcome = world.collect_put(id);
    judge_settled(world, outcome)
}

/// A control: the judgment is handed an upload its accepted RESULT left `Unknown`.
fn left_unknown(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if !arrived(world) {
        return 0;
    }
    judge_settled(world, Some(UploadOutcome::Unknown))
}

/// The judgment: an upload whose RESULT the client accepted is `Published`.
fn judge_settled(world: &mut Mixed<'_, '_, '_>, outcome: Option<UploadOutcome>) -> u64 {
    if outcome != Some(UploadOutcome::Published) {
        return fail(world, Obligation::History, UNRESOLVED);
    }
    world.history.allowed = vec![version_b()];
    mark(world, RESOLVED)
}

const LATE: [Step; 7] = [
    step("arm-delay", always, delay_results),
    step("put-begin", active_put, begin),
    step("put-prepare", always, put_prepare),
    step("put-supply", always, put_supply),
    step("unknown", went_unknown, mark_unknown),
    step("settled", resolved_or_late, settled),
    JUDGE,
];

const PROMPT: [Step; 7] = replaced(
    replaced(
        LATE,
        "arm-delay",
        step("arm-nothing", always, delay_nothing),
    ),
    "unknown",
    step("decided", put_decided, mark_decided),
);

const LEFT_UNKNOWN: [Step; 7] = replaced(
    LATE,
    "settled",
    step("settled-unknown", resolved_or_late, left_unknown),
);

const LEFT_UNKNOWN_PREMISE: &[&str] = &[WENT_UNKNOWN, ARRIVED];

const LATE_WITNESSES: &[&str] = &[
    ARMED,
    "upload begun",
    "upload prepared",
    "upload DATA supplied",
    WENT_UNKNOWN,
    ARRIVED,
    RESOLVED,
];

const PROMPT_WITNESSES: &[&str] = &[
    UNARMED,
    "upload begun",
    "upload prepared",
    "upload DATA supplied",
    DECIDED,
    ARRIVED,
    RESOLVED,
];

const JUDGED: &[Obligation] = &[Obligation::History];

pub(super) const RESOLVED_UPLOADS: [History; 3] = [
    uploading(
        history(
            "ru1-put-result-after-unknown",
            &LATE,
            LATE_WITNESSES,
            JUDGED,
            Expect::Pass,
        ),
        1,
    ),
    uploading(
        history(
            "ru1-put-result-before-unknown",
            &PROMPT,
            PROMPT_WITNESSES,
            JUDGED,
            Expect::Pass,
        ),
        1,
    ),
    control(
        uploading(
            history(
                "ru1-put-result-left-unknown",
                &LEFT_UNKNOWN,
                LATE_WITNESSES,
                JUDGED,
                Expect::Violation(Obligation::History, UNRESOLVED),
            ),
            1,
        ),
        LEFT_UNKNOWN_PREMISE,
    ),
];
