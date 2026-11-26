//! An upload the owner admitted whose DATA is never supplied ends `Unknown` or `Failed(TimedOut)`
//! at its deadline, never as not started.
//!
//! Property: the rule "a deferred upload ended with an outcome its deadline cannot give"
//! (net/world_tests/narrate/rules.rs): an upload the owner admitted and whose DATA its supplier never gave
//! ends at its one deadline as `Unknown` at the client or `Failed(TimedOut)` by the owner. Its BEGIN
//! reached the owner, so no ending may say the upload never started.
//!
//! Both histories run the single-owner world. Client 0 begins an upload of version B under key 1 with the
//! deadline `WAIT_US` and prepares it. Two premises are read before anything is judged, from state that is
//! the same with and without a defect in the client's ending: the upload has no outcome while the owner
//! counts a live request, and the owner answered the upload's PREPARE (the client's record of the upload
//! is in the `Ready` phase, which only the READY that fits the prepared shape gives it). A premise that
//! does not form ends the run unsuccessful under its name.
//!
//! - `df1-put-unsupplied-outcome`: no DATA is supplied. The history waits until the client
//!   decided the upload and judges the collected outcome with `judge_deferred` of
//!   histories/incidents.rs, the judge of `i4-put-deferred`: a decision later than `WAIT_US` after the
//!   begin fails with "a deferred upload outlived its one deadline", a publication fails with "a
//!   deferred upload published bytes its supplier never gave", and any outcome but `Unknown` or
//!   `Failed(TimedOut)` fails with the rule above.
//! - `df1-put-supplied-outcome`: after the begin, prepare, charge, and answered-PREPARE premises, the
//!   history supplies the DATA and requires the upload to end `Published`. It checks only publication,
//!   so it declares only the `History` obligation.
//! - `df1-put-unsupplied-judged-not-started`: a control. The first history's steps, with the decided
//!   upload judged as `NotStarted`, fail with the rule above once both premises are marked.

use super::incidents::{deferred_no_effect, judge_deferred};
use super::*;

const STALLED: &str = "upload stalled before its DATA";
const PREPARE_ANSWERED: &str = "the owner answered the upload's PREPARE";
const ENDED: &str = "the deferred upload ended at its one deadline";
const SUPPLIED: &str = "upload DATA supplied";
const PUBLISHED: &str = "upload published";

/// Whether the owner answered the upload's PREPARE: the client's record of the upload is in its `Ready`
/// phase, which it enters only on the READY that fits the shape its PREPARE fixed (`net/upload.rs`), and
/// in which alone it takes DATA.
fn prepare_answered(world: &Mixed<'_, '_, '_>) -> bool {
    world.history.put.is_some_and(|id| {
        world.scene.clients[0]
            .upload_snapshot(id)
            .contains("phase: Ready")
    })
}

/// The premises can be read: the owner answered the PREPARE, or the upload ended first.
fn prepare_answered_or_decided(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    prepare_answered(world) || put_decided(world, now)
}

/// The premises: the prepared upload has no outcome while the owner counts a live request, and the
/// owner answered its PREPARE.
fn upload_stalled(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let charged = !put_decided(world, now) && world.scene.owner.census().live() != 0;
    if premised(world, charged, STALLED) == 0 {
        return 0;
    }
    let answered = prepare_answered(world);
    premised(world, answered, PREPARE_ANSWERED)
}

const DEFERRED: [Step; 5] = [
    step("put-begin", active_put, put_begin),
    step("put-prepare", always, put_prepare),
    step("stalled", prepare_answered_or_decided, upload_stalled),
    step("deadline", put_decided, judge_deferred),
    JUDGE,
];

const SUPPLYING: [Step; 6] = [
    step("put-begin", active_put, put_begin),
    step("put-prepare", always, put_prepare),
    step("stalled", prepare_answered_or_decided, upload_stalled),
    step("put-supply", always, put_supply),
    step("put-result", put_decided, put_published),
    JUDGE,
];

const JUDGED_NOT_STARTED: [Step; 5] = replaced(
    DEFERRED,
    "deadline",
    step("deadline-no-effect", put_decided, deferred_no_effect),
);

const DEFERRED_WITNESSES: &[&str] = &[STALLED, PREPARE_ANSWERED, ENDED];

const SUPPLYING_WITNESSES: &[&str] = &[STALLED, PREPARE_ANSWERED, SUPPLIED, PUBLISHED];

const OBLIGATIONS: &[Obligation] = &[Obligation::Resources, Obligation::History];

/// The supplied history judges the publication alone.
const SUPPLIED_OBLIGATIONS: &[Obligation] = &[Obligation::History];

/// The marks a kill of the rule needs: the upload charged with no outcome, and its PREPARE answered.
const PREMISE: &[&str] = &[STALLED, PREPARE_ANSWERED];

/// The obligation the mark of the unsupplied upload's judging step judges beside its deadline: the outcome
/// was one a deadline can give.
pub(super) const CHECKS: [(&str, Obligation); 1] = [(ENDED, Obligation::History)];

pub(super) const DEFERRED_OUTCOMES: [History; 3] = [
    uploading(
        history(
            "df1-put-unsupplied-outcome",
            &DEFERRED,
            DEFERRED_WITNESSES,
            OBLIGATIONS,
            Expect::Pass,
        ),
        1,
    ),
    uploading(
        history(
            "df1-put-supplied-outcome",
            &SUPPLYING,
            SUPPLYING_WITNESSES,
            SUPPLIED_OBLIGATIONS,
            Expect::Pass,
        ),
        1,
    ),
    control(
        uploading(
            history(
                "df1-put-unsupplied-judged-not-started",
                &JUDGED_NOT_STARTED,
                DEFERRED_WITNESSES,
                OBLIGATIONS,
                Expect::Violation(
                    Obligation::History,
                    "a deferred upload ended with an outcome its deadline cannot give",
                ),
            ),
            1,
        ),
        PREMISE,
    ),
];

#[cfg(test)]
mod tests {
    use super::{DEFERRED_OUTCOMES, Expect, Obligation};

    /// The supplied history reads the upload's charge at the owner as a premise and judges the
    /// publication alone, so it declares only `History`. The unsupplied history also judges the
    /// deadline, a Resources check.
    #[test]
    fn each_history_declares_the_obligations_its_script_judges() {
        let declared: Vec<_> = DEFERRED_OUTCOMES
            .iter()
            .filter(|history| history.expect == Expect::Pass)
            .map(|history| (history.name, history.obligations))
            .collect();
        assert_eq!(
            declared,
            [
                (
                    "df1-put-unsupplied-outcome",
                    &[Obligation::Resources, Obligation::History][..]
                ),
                ("df1-put-supplied-outcome", &[Obligation::History][..]),
            ]
        );
    }
}
