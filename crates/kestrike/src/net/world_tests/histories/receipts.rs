//! Receipt histories: a receipt of every fragment is no publication.
//!
//! A client reports an upload `Published` only after a PUT RESULT reached it. The owner's receipt of every
//! fragment says the bytes arrived; it does not say the owner published them. The rule is `UNBACKED` below,
//! which `narrate/rules.rs` holds.
//!
//! Both histories run the single-owner world and upload an object of three fragments under key 1. The
//! first step sets the chain of link rules, and the script then waits twice: until the client holds the
//! owner's cumulative receipt of every fragment, and until the client decided the upload. At the receipt
//! and at the decision, the rule checks two counts: the client's accepted RESULT count
//! (`Client::put_results()`) and the tap's count of PUT RESULT frames the link let across. A `Published`
//! outcome with either count at zero is the rule's violation.
//!
//! - `rc1-put-result-dropped`: the chain drops every PUT RESULT toward the client, for the
//!   whole run. The owner publishes and answers each resend from its retained result, and none arrives,
//!   so the client accepts no RESULT and the one outcome it may report is `Unknown`. The history requires
//!   the drop armed, the receipt of every fragment, a RESULT the link dropped, and the `Unknown` outcome.
//!   A kill of the rule counts once the drop is armed and the receipt is held.
//! - `rc1-put-result-crossed`: the same steps under a chain that only taps the
//!   link and drops nothing. A RESULT crosses toward the client, the client accepts it, and the upload
//!   ends `Published`.
//! - `rc1-put-receipt-as-publication` and `rc1-put-unknown-as-published`: controls over the steps of
//!   `rc1-put-result-dropped`. `rc1-put-receipt-as-publication` judges `Published` at the receipt;
//!   `rc1-put-unknown-as-published` judges `Published` at the decision. Both end in the rule's
//!   violation, since the client accepted no RESULT.
//! - `rc1-put-counted-result-as-published`: a control that runs `rc1-put-result-dropped` and judges
//!   `Published` at the decision with one RESULT counted as accepted. It ends in the rule's violation,
//!   since the link let no RESULT across.
//!
//! An outcome that is neither `Published` nor `Unknown` is not this rule's to judge. The
//! decision step leaves it unmarked, and the last step ends the history unsuccessful under the outcome's
//! witness.

use super::super::super::frame::Kind;
use super::super::super::rules::{Chain, MANIFEST};
use super::incidents::{
    captured, drop_every_result, long_acked, long_begin, long_prepare, long_supply,
};
use super::*;

/// The rule both histories judge.
const UNBACKED: &str = "an upload claimed publication without a delivered RESULT";

const ARMED: &str = "a RESULT drop armed";
const TAPPED: &str = "the link tapped with no RESULT drop";
const RECEIPT: &str = "the client held the receipt of every fragment";
const LOST: &str = "the link dropped a RESULT toward the client";
const CROSSED: &str = "a RESULT crossed the link toward the client";
const UNKNOWN: &str = "the upload ended unknown with no RESULT accepted";
const PUBLISHED: &str = "the upload ended published with a RESULT accepted";

/// The sibling's chain: the tap alone, so the link records what crosses and drops nothing.
fn tap_only(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let chain = Chain::new(Vec::new(), &[0], &MANIFEST).expect("a bounded chain");
    world.scene.nets[0].borrow_mut().set_rules(chain);
    mark(world, TAPPED)
}

/// The tap can count a queued PUT RESULT before the client accepts it, and the client code that decides
/// `Published` also maintains `accepted`. The check uses `crossed` as an independent count of PUT RESULT
/// frames the link let across.
fn unbacked(outcome: Option<UploadOutcome>, accepted: u64, crossed: usize) -> bool {
    outcome == Some(UploadOutcome::Published) && (accepted == 0 || crossed == 0)
}

/// Marks the receipt, then judges `reported`, what the client reports while it holds it: a receipt of
/// every fragment is no publication. The mark comes first because the rule's kill counts only with the
/// receipt witnessed.
fn judge_receipt(world: &mut Mixed<'_, '_, '_>, reported: Option<UploadOutcome>) -> u64 {
    let marked = mark(world, RECEIPT);
    let accepted = world.scene.clients[0].put_results();
    if unbacked(reported, accepted, captured(world, Kind::PutResult, false)) {
        return fail(world, Obligation::History, UNBACKED);
    }
    marked
}

fn receipt_judged(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    let reported = world.scene.clients[0].put_outcome(id);
    judge_receipt(world, reported)
}

fn receipt_as_publication(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    judge_receipt(world, Some(UploadOutcome::Published))
}

fn outcome_judged(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    let outcome = world.collect_put(id);
    let accepted = world.scene.clients[0].put_results();
    judge_outcome(world, outcome, accepted)
}

fn unknown_as_published(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    let _ = world.collect_put(id);
    let accepted = world.scene.clients[0].put_results();
    judge_outcome(world, Some(UploadOutcome::Published), accepted)
}

/// The control checks `Published` at the decision with an accepted RESULT count of one, even though the
/// link dropped every PUT RESULT.
fn counted_as_published(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    let _ = world.collect_put(id);
    judge_outcome(world, Some(UploadOutcome::Published), 1)
}

/// At the decision, the check compares the client's outcome and accepted RESULT count with the tap's PUT
/// RESULT count. `Published` with either count at zero violates the rule. `Published` with both counts
/// positive is the sibling's ending, and `Unknown` with none accepted is the scenario's; each is marked
/// with what the link's tap recorded. Any other pairing advances unmarked.
fn judge_outcome(
    world: &mut Mixed<'_, '_, '_>,
    outcome: Option<UploadOutcome>,
    accepted: u64,
) -> u64 {
    if unbacked(outcome, accepted, captured(world, Kind::PutResult, false)) {
        return fail(world, Obligation::History, UNBACKED);
    }
    if captured(world, Kind::PutResult, true) > 0 {
        mark(world, LOST);
    }
    if captured(world, Kind::PutResult, false) > 0 {
        mark(world, CROSSED);
    }
    match outcome {
        Some(UploadOutcome::Published) => {
            world.history.allowed = vec![long_b()];
            mark(world, PUBLISHED)
        }
        Some(UploadOutcome::Unknown) if accepted == 0 => mark(world, UNKNOWN),
        _ => 1,
    }
}

const EVERY_RESULT_DROPPED: [Step; 7] = [
    step("set-chain", always, drop_every_result),
    step("put-begin", active_put, long_begin),
    step("put-prepare", always, long_prepare),
    step("put-supply", always, long_supply),
    step("receipt", long_acked, receipt_judged),
    step("put-result", put_decided, outcome_judged),
    JUDGE,
];

const NO_RESULT_DROPPED: [Step; 7] = replaced(
    EVERY_RESULT_DROPPED,
    "set-chain",
    step("set-chain", always, tap_only),
);

const RECEIPT_AS_PUBLICATION: [Step; 7] = replaced(
    EVERY_RESULT_DROPPED,
    "receipt",
    step("receipt-as-publication", long_acked, receipt_as_publication),
);

const UNKNOWN_AS_PUBLISHED: [Step; 7] = replaced(
    EVERY_RESULT_DROPPED,
    "put-result",
    step("put-result-as-published", put_decided, unknown_as_published),
);

const COUNTED_AS_PUBLISHED: [Step; 7] = replaced(
    EVERY_RESULT_DROPPED,
    "put-result",
    step(
        "put-result-counted-as-published",
        put_decided,
        counted_as_published,
    ),
);

const UNKNOWN_WITNESSES: &[&str] = &[ARMED, RECEIPT, LOST, UNKNOWN];

const PUBLISHED_WITNESSES: &[&str] = &[TAPPED, RECEIPT, CROSSED, PUBLISHED];

/// The marks a kill of the rule needs in the scenario: the drop armed and the receipt of every fragment.
const DROP_PREMISE: &[&str] = &[ARMED, RECEIPT];

/// The marks a kill of the rule needs in the sibling: the tap set and the receipt of every fragment.
const TAP_PREMISE: &[&str] = &[TAPPED, RECEIPT];

const JUDGED: &[Obligation] = &[Obligation::History];

/// The obligation each receipt check's mark judges.
pub(super) const CHECKS: [(&str, Obligation); 2] = [
    (UNKNOWN, Obligation::History),
    (PUBLISHED, Obligation::History),
];

/// A receipt history: one upload of the uploading client and no GET.
const fn receipt(
    name: &'static str,
    script: &'static [Step],
    witnesses: &'static [&'static str],
    expect: Expect,
    premise: &'static [&'static str],
) -> History {
    control(
        getting(
            uploading(history(name, script, witnesses, JUDGED, expect), 1),
            [0, 0],
        ),
        premise,
    )
}

pub(super) const RECEIPTS: [History; 5] = [
    receipt(
        "rc1-put-result-dropped",
        &EVERY_RESULT_DROPPED,
        UNKNOWN_WITNESSES,
        Expect::Pass,
        DROP_PREMISE,
    ),
    receipt(
        "rc1-put-result-crossed",
        &NO_RESULT_DROPPED,
        PUBLISHED_WITNESSES,
        Expect::Pass,
        TAP_PREMISE,
    ),
    receipt(
        "rc1-put-receipt-as-publication",
        &RECEIPT_AS_PUBLICATION,
        UNKNOWN_WITNESSES,
        Expect::Violation(Obligation::History, UNBACKED),
        DROP_PREMISE,
    ),
    receipt(
        "rc1-put-unknown-as-published",
        &UNKNOWN_AS_PUBLISHED,
        UNKNOWN_WITNESSES,
        Expect::Violation(Obligation::History, UNBACKED),
        DROP_PREMISE,
    ),
    receipt(
        "rc1-put-counted-result-as-published",
        &COUNTED_AS_PUBLISHED,
        UNKNOWN_WITNESSES,
        Expect::Violation(Obligation::History, UNBACKED),
        DROP_PREMISE,
    ),
];

#[cfg(test)]
mod tests {
    use super::{UploadOutcome, unbacked};

    #[test]
    fn a_publication_is_backed_only_by_a_result_that_crossed_and_was_accepted() {
        let published = Some(UploadOutcome::Published);
        assert!(
            unbacked(published, 1, 0),
            "a publication counted as accepted with no RESULT across the link read as backed"
        );
        assert!(unbacked(published, 0, 1));
        assert!(unbacked(published, 0, 0));
        assert!(!unbacked(published, 1, 1));
        assert!(!unbacked(Some(UploadOutcome::Unknown), 0, 0));
        assert!(!unbacked(None, 0, 0));
    }
}
