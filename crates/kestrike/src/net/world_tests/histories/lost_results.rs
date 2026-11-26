//! An upload whose every fragment the owner acknowledged and whose RESULT is lost ends `Unknown`,
//! never as a failure.
//!
//! Property: an upload whose every fragment the owner acknowledged and whose RESULT is lost ends
//! `Unknown`, never as a failure. The rule this file judges is "a lost RESULT ended the upload as a failure".
//!
//! Both histories run the single-owner world. A link rule drops PUT RESULT frames toward the client, the
//! client uploads an object of three fragments, and the script waits until the client holds the owner's
//! receipt of every fragment and then until the client decided the upload.
//!
//! - `lo1-put-every-result-dropped`: the rule drops every RESULT. The client's resends run out
//!   with no RESULT delivered, so the only outcome that states what the client knows is `Unknown`.
//!   `Failed(_)` or `NotStarted` is the rule. The kill counts only with its premises marked: the drop
//!   armed, the receipt of every fragment, and a RESULT the link dropped.
//! - `lo1-put-first-result-dropped`: the rule drops the first RESULT alone. The owner
//!   replays its retained RESULT to the client's resend and the upload ends `Published`.
//!
//! The steps that arm the drop, upload the long object and judge the outcome are those of `i3-put-beyond`
//! and `i3-put-retry` in `histories/incidents.rs`. These histories add the dropped RESULT as a premise of
//! the rule's kill.

use super::super::super::frame::Kind;
use super::incidents::{
    captured, drop_every_result, drop_one_result, long_acked, long_begin, long_prepare, long_supply,
};
use super::*;

const ARMED: &str = "a RESULT drop armed";
const RECEIPT: &str = "upload receipt acknowledged";
const LOST: &str = "the link dropped a RESULT toward the client";
const UNKNOWN: &str = "the upload went unknown before its RESULT arrived";
const REPLAYED: &str = "a retained RESULT replayed after a lost one";
const PUBLISHED: &str = "upload published";
/// The mark of the judgment, a check of `Obligation::History`: the outcome the client decided is one a
/// client whose RESULT was lost may state.
const NOT_FAILED: &str = "the upload with a lost RESULT ended other than failed";

/// The obligation the judgment's mark witnesses.
pub(super) const CHECKS: [(&str, Obligation); 1] = [(NOT_FAILED, Obligation::History)];

/// Marks a RESULT the link dropped, so the rule's kill counts only when one was lost, then judges the
/// outcome the client decided as `result_judged` of `histories/incidents.rs` does: publication is
/// credited only once a RESULT reached the client, `Unknown` is what a client with no RESULT may say, and
/// any other outcome states a failure the client never learned of, which is the rule "a lost RESULT ended
/// the upload as a failure".
fn result_judged(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if captured(world, Kind::PutResult, true) > 0 {
        mark(world, LOST);
    }
    if incidents::result_judged(world, now) == 0 {
        return 0;
    }
    mark(world, NOT_FAILED)
}

const EVERY_RESULT_LOST: [Step; 7] = [
    step("arm-drop", always, drop_every_result),
    step("put-begin", active_put, long_begin),
    step("put-prepare", always, long_prepare),
    step("put-supply", always, long_supply),
    step("receipt", long_acked, mark_receipt),
    step("put-result", put_decided, result_judged),
    JUDGE,
];

const FIRST_RESULT_LOST: [Step; 7] = replaced(
    EVERY_RESULT_LOST,
    "arm-drop",
    step("arm-drop", always, drop_one_result),
);

const UNKNOWN_WITNESSES: &[&str] = &[ARMED, RECEIPT, LOST, UNKNOWN, NOT_FAILED];

const PUBLISHED_WITNESSES: &[&str] = &[ARMED, RECEIPT, LOST, REPLAYED, PUBLISHED, NOT_FAILED];

/// The marks a kill of the rule needs: the fault armed, every fragment acknowledged, a RESULT lost.
const PREMISE: &[&str] = &[ARMED, RECEIPT, LOST];

const JUDGED: &[Obligation] = &[Obligation::History];

pub(super) const LOST_RESULTS: [History; 2] = [
    control(
        getting(
            uploading(
                history(
                    "lo1-put-every-result-dropped",
                    &EVERY_RESULT_LOST,
                    UNKNOWN_WITNESSES,
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
                    "lo1-put-first-result-dropped",
                    &FIRST_RESULT_LOST,
                    PUBLISHED_WITNESSES,
                    JUDGED,
                    Expect::Pass,
                ),
                1,
            ),
            [0, 0],
        ),
        PREMISE,
    ),
];
