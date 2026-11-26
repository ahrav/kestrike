//! An upload whose DATA is never supplied is decided no later than one wait after its begin,
//! however often the owner repeats its READY.
//!
//! Property: the rule "a deferred upload outlived its one deadline": an upload has one deadline, its
//! begin plus the wait the caller gave (`WAIT_US`). An owner that stays reachable answers every resent
//! PREPARE with a READY, and no READY may move that deadline: an upload whose DATA is never supplied is
//! decided no later than one wait after its begin.
//!
//! Both histories run the single-owner world with one uploading client. A link rule that changes no
//! delivery of its own lets the script count the READY frames the link carried toward the client.
//!
//! - `df2-put-unsupplied-past-a-second-ready`: the client begins the upload of key 1 and prepares it, and
//!   the script supplies no DATA. The script waits until the link carried a second READY toward the
//!   client, then until the client decided the upload. The judging step compares its own time with the
//!   begin plus `WAIT_US` before it reads the outcome, and fails Resources with the rule when it runs
//!   later. A kill counts only with its premises marked: the upload was charged at the owner with no DATA
//!   supplied, and the owner repeated its READY. No premise names the time or the outcome.
//! - `df2-put-supplied-within-the-wait`: the same steps, with the DATA supplied where the
//!   first history stalls. The upload publishes inside the wait and the same time check passes.
//! - `df2-put-unsupplied-judged-past-its-wait`: a control. The first history's steps, with the upload
//!   judged two waits after its decision, fail with the rule once both premises are marked.
//!
//! The unsupplied upload is judged by `judge_deferred` of `histories/incidents.rs`, the judge of
//! `i4-put-deferred`, and the supplied one by that judge's time check, `deferred_in_time`.

use super::super::super::frame::Kind;
use super::super::super::rules::{Chain, Effect, MANIFEST, Rule, Selector};
use super::incidents::{deferred_extended, deferred_in_time, judge_deferred};
use super::*;

const RULE: &str = "a deferred upload outlived its one deadline";

const WATCHED: &str = "READY frames toward the client counted";
const STALLED: &str = "upload stalled before its DATA";
const REPEATED: &str = "the owner repeated its READY";
const SUPPLIED: &str = "upload DATA supplied";
const ENDED: &str = "the deferred upload ended at its one deadline";
const PUBLISHED: &str = "the supplied upload published inside its wait";

/// The link side of the uploading client.
const CLIENT: usize = 0;

/// Installs a rule that selects READY frames toward the client and leaves them delivered, with a tap
/// after it, so the link records every frame it carries with its decision.
fn watch_ready(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let ready = Selector::All(vec![
        Selector::Kind(Kind::PutReady),
        Selector::Toward(CLIENT),
    ]);
    let rules = vec![Rule::new(ready, Effect::Deliver)];
    let chain = Chain::new(rules, &[1], &MANIFEST).expect("a bounded chain");
    world.scene.nets[0].borrow_mut().set_rules(chain);
    mark(world, WATCHED)
}

/// READY frames the link carried toward the client and did not drop.
fn readies(world: &Mixed<'_, '_, '_>) -> usize {
    world.scene.nets[0]
        .borrow()
        .rules()
        .captures()
        .iter()
        .filter(|capture| {
            capture.kind == Some(Kind::PutReady)
                && capture.toward == CLIENT
                && capture.decision.drop.is_none()
        })
        .count()
}

/// A second READY reached the link toward the client, or the client decided the upload first; the
/// second case leaves the mark unwritten and the run unsuccessful.
fn ready_repeated(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    readies(world) >= 2 || put_decided(world, now)
}

fn mark_repeated(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let repeated = readies(world) >= 2;
    premised(world, repeated, REPEATED)
}

/// The sibling's upload needs no second READY: its DATA follows the first.
fn mark_single(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    mark(world, "the supplied upload needed no repeated READY")
}

/// Judges the supplied upload by the deferred upload's time check, then expects its publication.
fn judge_supplied(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    let outcome = world.collect_put(id);
    if !deferred_in_time(world, now) {
        return 0;
    }
    premised(world, outcome == Some(UploadOutcome::Published), PUBLISHED)
}

const DEFERRED: [Step; 7] = [
    step("watch-ready", always, watch_ready),
    step("put-begin", active_put, put_begin),
    step("put-prepare", always, put_prepare),
    step("deferred", always, stalled),
    step("ready-repeated", ready_repeated, mark_repeated),
    step("deadline", put_decided, judge_deferred),
    JUDGE,
];

const SUPPLIED_STEPS: [Step; 7] = replaced(
    replaced(
        replaced(DEFERRED, "deferred", step("deferred", always, put_supply)),
        "ready-repeated",
        step("ready-repeated", always, mark_single),
    ),
    "deadline",
    step("deadline", put_decided, judge_supplied),
);

const JUDGED_PAST_ITS_WAIT: [Step; 7] = replaced(
    DEFERRED,
    "deadline",
    step("deadline-extended", put_decided, deferred_extended),
);

const DEFERRED_WITNESSES: &[&str] = &[WATCHED, STALLED, REPEATED, ENDED];

const SUPPLIED_WITNESSES: &[&str] = &[WATCHED, SUPPLIED, PUBLISHED];

/// The marks a kill of the rule needs: the upload charged with no DATA supplied, and a repeated READY.
const PREMISE: &[&str] = &[STALLED, REPEATED];

/// The sibling's premise: the DATA was supplied.
const SIBLING_PREMISE: &[&str] = &[SUPPLIED];

const JUDGED: &[Obligation] = &[Obligation::Resources, Obligation::History];

/// The sibling judges the time alone: an outcome other than a publication ends its run unsuccessful.
const SUPPLIED_JUDGED: &[Obligation] = &[Obligation::Resources];

/// The obligation each judging step's mark judges: the unsupplied upload's outcome was one a deadline can
/// give, and the supplied upload was decided inside its wait.
pub(super) const CHECKS: [(&str, Obligation); 2] = [
    (ENDED, Obligation::History),
    (PUBLISHED, Obligation::Resources),
];

pub(super) const DEFERRED_DEADLINES: [History; 3] = [
    control(
        getting(
            uploading(
                history(
                    "df2-put-unsupplied-past-a-second-ready",
                    &DEFERRED,
                    DEFERRED_WITNESSES,
                    JUDGED,
                    Expect::Pass,
                ),
                1,
            ),
            [0, 0],
        ),
        PREMISE,
    ),
    control(
        getting(
            uploading(
                history(
                    "df2-put-supplied-within-the-wait",
                    &SUPPLIED_STEPS,
                    SUPPLIED_WITNESSES,
                    SUPPLIED_JUDGED,
                    Expect::Pass,
                ),
                1,
            ),
            [0, 0],
        ),
        SIBLING_PREMISE,
    ),
    control(
        getting(
            uploading(
                history(
                    "df2-put-unsupplied-judged-past-its-wait",
                    &JUDGED_PAST_ITS_WAIT,
                    DEFERRED_WITNESSES,
                    JUDGED,
                    Expect::Violation(Obligation::Resources, RULE),
                ),
                1,
            ),
            [0, 0],
        ),
        PREMISE,
    ),
];
