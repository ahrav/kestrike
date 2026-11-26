//! A RESULT delayed past the client's resends resolves an abandoned Unknown upload Published while the
//! client still holds the request; with every RESULT dropped the upload stays Unknown past the owner's
//! retention.
//!
//! Property: a matching RESULT resolves a client's Unknown while the request is held, after an abandon as
//! well. The rule this file judges is UNRESOLVED below, a rule of `narrate/rules.rs`.
//!
//! The histories run one upload of the long object in the single-owner world. The client supplies every
//! fragment and the owner acknowledges them all, so the owner publishes the object and answers with PUT RESULT
//! frames. The client's PREPARE resends run out and the upload ends `Unknown`. The history then abandons the
//! upload and leaves it unretired, which is a premise, and records the count of RESULT frames the client's
//! uploads accepted. The histories differ in what the link does with the RESULT frames toward the client.
//!
//! - `dr1-put-result-delayed`: the link delays every PUT RESULT by the request's wait. The history waits
//!   until the accepted count rises or the owner's retention has passed. A count that did not rise is a
//!   premise that did not form. With the count risen, an outcome other than `Published` is the rule: the
//!   abandoned request the client held took a matching RESULT and stayed unresolved.
//! - `dr1-put-result-dropped`: the link drops every PUT RESULT instead. That the link dropped one is a
//!   premise, read from the link's captures. No RESULT reaches the client, and after the owner's retention
//!   passed the outcome is still `Unknown`.
//! - `dr1-put-result-held-back`: the link holds every PUT RESULT past the owner's retention and drops none.
//!   The upload stays `Unknown` as in the dropped history, with no dropped RESULT, so the run ends
//!   unsuccessful under the dropped history's premise.
//! - `dr1-put-result-left-unknown` and `dr1-put-result-invented` are controls. Each hands its history's
//!   judgment a planted outcome: `Unknown` once the delayed RESULT was accepted, which fails through
//!   UNRESOLVED, and `Published` with every RESULT dropped and none accepted, which fails through INVENTED.
//!
//! Each history then retires the request, checks that the outcome did not move without a RESULT, and reads
//! the key back: the long object where the upload resolved `Published`, the long object or its predecessor
//! where it stayed `Unknown`. The steps are those of `i3-put-late` and `i3-put-beyond` in
//! `histories/incidents.rs`, with the abandon and the two premises added.

use super::super::super::frame::Kind;
use super::super::super::rules::{Effect, Rule, Selector};
use super::incidents::{
    CLIENT, RETENTION_US, actual_exact, captured, clear_rules, delay_results, drop_every_result,
    judge_resolved, later_outcome, long_acked, long_begin, long_prepare, long_supply, mark_unknown,
    past_retention, resolved_or_late, result_received, set_rules, unrelated_get, unrelated_read,
    uploader_idle, went_unknown,
};
use super::*;

/// The rule the first history is judged through.
const UNRESOLVED: &str = "a delayed matching RESULT left the unknown upload unresolved";
const INVENTED: &str = "an upload resolved its unknown outcome without a matching RESULT";

const DELAY_ARMED: &str = "a RESULT delay armed";
const DROP_ARMED: &str = "a RESULT drop armed";
const HELD_BACK: &str = "a RESULT delay past retention armed";
const DROPPED_ONE: &str = "the link dropped a RESULT";
const WENT_UNKNOWN: &str = "the upload went unknown before its RESULT arrived";
const ABANDONED: &str = "the unknown upload was abandoned while held";
const RESULT_ARRIVED: &str = "a RESULT reached the held unknown upload";
const RESOLVED: &str = "a later matching RESULT resolved the unknown outcome";
const STAYED_UNKNOWN: &str = "the upload stayed unknown past retention";
const CONSISTENT: &str = "the upload's outcome stayed consistent";
const PROGRESSED: &str = "unrelated work progressed";
const AGREED: &str = "the GET agreed with the upload's outcome";

/// The falsifier's link holds every PUT RESULT toward the client past the owner's retention: none is
/// dropped and none arrives before the history judges the outcome.
fn delay_past_retention(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let result = Selector::All(vec![
        Selector::Kind(Kind::PutResult),
        Selector::Toward(CLIENT),
    ]);
    let turns = 2 * (super::super::WAIT_US + RETENTION_US) / super::super::LINK_TURN_US;
    set_rules(world, vec![Rule::new(result, Effect::Delay(turns))]);
    mark(world, HELD_BACK)
}

/// Records the RESULT frames the client's uploads had accepted when the upload went `Unknown`, then
/// abandons the upload and leaves it unretired. The premise forms when the client accepted the abandon,
/// so a RESULT that arrives later meets an abandoned upload its client still holds.
fn abandon_unknown(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    mark_unknown(world, now);
    let id = world.history.put.expect("a PUT");
    let abandoned = world.scene.clients[0].abandon(id);
    premised(world, abandoned, ABANDONED)
}

/// The premise of the first history's judgment: a RESULT reached the client's uploads after the upload
/// went `Unknown`, read from their count of accepted RESULT frames, apart from the outcome.
fn result_arrived(world: &mut Mixed<'_, '_, '_>) -> bool {
    let received = result_received(world);
    premised(world, received, RESULT_ARRIVED) != 0
}

/// With the RESULT accepted, the outcome the held request reports is judged by `judge_resolved` of
/// `histories/incidents.rs`: it must be `Published`.
fn resolved(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if !result_arrived(world) {
        return 0;
    }
    let id = world.history.put.expect("a PUT");
    let outcome = world.collect_put(id);
    judge_resolved(world, outcome)
}

/// A control: the judgment is handed a held upload its accepted RESULT left `Unknown`.
fn left_unknown(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if !result_arrived(world) {
        return 0;
    }
    judge_resolved(world, Some(UploadOutcome::Unknown))
}

/// The sibling's step: the outcome the held request reports once the owner's retention passed is judged.
fn stayed_unknown(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    let outcome = world.collect_put(id);
    judge_stayed(world, outcome)
}

/// A control: the judgment is handed an upload that reports `Published` while the link dropped every
/// RESULT and the client's uploads accepted none.
fn invented(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    judge_stayed(world, Some(UploadOutcome::Published))
}

/// The sibling's judgment: with a RESULT dropped and none accepted, the upload is still `Unknown` once
/// the owner's retention passed. An upload that reports `Published` with no RESULT accepted breaks its
/// rule whatever the link did. The dropped RESULT is read from the link's captures, which hold it before
/// the rules clear, and is the premise that separates a lost RESULT from one the owner never sent or the
/// link still holds.
fn judge_stayed(world: &mut Mixed<'_, '_, '_>, outcome: Option<UploadOutcome>) -> u64 {
    let received = result_received(world);
    if !received && outcome == Some(UploadOutcome::Published) {
        return fail(world, Obligation::History, INVENTED);
    }
    let dropped = captured(world, Kind::PutResult, true) > 0;
    if premised(world, dropped, DROPPED_ONE) == 0 {
        return 0;
    }
    premised(
        world,
        !received && outcome == Some(UploadOutcome::Unknown),
        STAYED_UNKNOWN,
    )
}

const DELAYED: [Step; 14] = [
    step("arm", always, delay_results),
    step("put-begin", active_put, long_begin),
    step("put-prepare", always, long_prepare),
    step("put-supply", always, long_supply),
    step("unrelated-get", active_get, unrelated_get),
    step("receipt", long_acked, mark_receipt),
    step("unknown", went_unknown, abandon_unknown),
    step("unrelated-read", old_decided, unrelated_read),
    step("result", resolved_or_late, resolved),
    step("clear", always, clear_rules),
    step("later", past_retention, later_outcome),
    step("qualified-get", uploader_idle, fresh_get),
    step("qualified-read", fresh_decided, actual_exact),
    JUDGE,
];

const DROPPED: [Step; 14] = replaced(
    replaced(DELAYED, "arm", step("arm", always, drop_every_result)),
    "result",
    step("result", resolved_or_late, stayed_unknown),
);

const HELD_BACK_STEPS: [Step; 14] =
    replaced(DROPPED, "arm", step("arm", always, delay_past_retention));

const LEFT_UNKNOWN: [Step; 14] = replaced(
    DELAYED,
    "result",
    step("result", resolved_or_late, left_unknown),
);

const INVENTED_STEPS: [Step; 14] = replaced(
    DROPPED,
    "result",
    step("result", resolved_or_late, invented),
);

const LEFT_UNKNOWN_PREMISE: &[&str] = &[ABANDONED, RESULT_ARRIVED];
const INVENTED_PREMISE: &[&str] = &[DROP_ARMED, ABANDONED];

const DELAYED_WITNESSES: &[&str] = &[
    DELAY_ARMED,
    "upload receipt acknowledged",
    WENT_UNKNOWN,
    ABANDONED,
    RESULT_ARRIVED,
    RESOLVED,
    CONSISTENT,
    PROGRESSED,
    AGREED,
];

const DROPPED_WITNESSES: &[&str] = &[
    DROP_ARMED,
    "upload receipt acknowledged",
    WENT_UNKNOWN,
    ABANDONED,
    DROPPED_ONE,
    STAYED_UNKNOWN,
    CONSISTENT,
    PROGRESSED,
    AGREED,
];

const HELD_BACK_WITNESSES: &[&str] = &[
    HELD_BACK,
    "upload receipt acknowledged",
    WENT_UNKNOWN,
    ABANDONED,
    DROPPED_ONE,
    STAYED_UNKNOWN,
    CONSISTENT,
    PROGRESSED,
    AGREED,
];

const JUDGED: &[Obligation] = &[Obligation::Bytes, Obligation::History, Obligation::Progress];

pub(super) const DELAYED_RESULTS: [History; 5] = [
    uploading(
        history(
            "dr1-put-result-delayed",
            &DELAYED,
            DELAYED_WITNESSES,
            JUDGED,
            Expect::Pass,
        ),
        1,
    ),
    uploading(
        history(
            "dr1-put-result-dropped",
            &DROPPED,
            DROPPED_WITNESSES,
            JUDGED,
            Expect::Pass,
        ),
        1,
    ),
    uploading(
        history(
            "dr1-put-result-held-back",
            &HELD_BACK_STEPS,
            HELD_BACK_WITNESSES,
            JUDGED,
            Expect::Unsuccessful(DROPPED_ONE),
        ),
        1,
    ),
    control(
        uploading(
            history(
                "dr1-put-result-left-unknown",
                &LEFT_UNKNOWN,
                DELAYED_WITNESSES,
                JUDGED,
                Expect::Violation(Obligation::History, UNRESOLVED),
            ),
            1,
        ),
        LEFT_UNKNOWN_PREMISE,
    ),
    control(
        uploading(
            history(
                "dr1-put-result-invented",
                &INVENTED_STEPS,
                DROPPED_WITNESSES,
                JUDGED,
                Expect::Violation(Obligation::History, INVENTED),
            ),
            1,
        ),
        INVENTED_PREMISE,
    ),
];

#[cfg(test)]
mod tests {
    use crate::sim::trace::{Outcome, PAYLOAD, Terminal, load};

    use super::super::super::bundle::{admit, traced};
    use super::super::super::replay::{Replayed, replay};
    use super::super::tests::{first_failure, manifest};
    use super::{DELAYED_RESULTS, DROPPED_ONE, Expect, Failure, INVENTED, Obligation, UNRESOLVED};

    /// The roots the seeded tests pin: a small one and two drawn from the 64-bit range.
    const ROOTS: [u64; 3] = [11, 4_302_617_955_180_736_441, 15_611_090_472_388_207_913];

    /// History `name` recorded under `root`: its ending, its violation record and whether the bundle
    /// replayed to an equal digest.
    fn ran_at(name: &str, root: u64) -> (Outcome, Option<[u8; PAYLOAD]>, bool) {
        let mut manifest = manifest(name);
        manifest.root = root;
        let closed = traced(admit(&manifest).expect("admitted"), Vec::new());
        let loaded = load(&closed.sink, manifest.capacity().records()).expect("a loadable bundle");
        let Terminal::Complete { outcome, .. } = loaded.terminal else {
            panic!("{name} at {root}: {:?}", loaded.terminal);
        };
        let reproduced = replay(&closed.sink).expect("a replay").0 == Replayed::Reproduced;
        (outcome, loaded.violation, reproduced)
    }

    /// Under each pinned root an abandoned `Unknown` upload its client still holds is resolved
    /// `Published` by its delayed RESULT, and stays `Unknown` past the owner's retention when the link
    /// dropped every RESULT.
    #[test]
    fn a_result_resolves_an_abandoned_unknown_upload_and_a_dropped_one_leaves_it_unknown() {
        for name in ["dr1-put-result-delayed", "dr1-put-result-dropped"] {
            for root in ROOTS {
                assert_eq!(
                    ran_at(name, root),
                    (Outcome::Pass, None, true),
                    "{name} at {root}"
                );
            }
        }
    }

    /// Each control hands its history's judgment a planted outcome and ends through that judgment's rule
    /// at each pinned root: an upload its accepted RESULT left `Unknown`, and an upload that reports
    /// `Published` with no RESULT accepted. Each declares a premise, and the family holds no other history
    /// that expects a violation.
    #[test]
    fn every_delayed_result_control_fails_through_its_named_check() {
        let killed = [
            ("dr1-put-result-left-unknown", UNRESOLVED),
            ("dr1-put-result-invented", INVENTED),
        ];
        let controls = DELAYED_RESULTS
            .iter()
            .filter(|h| matches!(h.expect, Expect::Violation(..)))
            .count();
        assert_eq!(controls, killed.len());
        for (name, rule) in killed {
            let declared = DELAYED_RESULTS.iter().find(|h| h.name == name).expect(name);
            assert_eq!(
                declared.expect,
                Expect::Violation(Obligation::History, rule),
                "{name}"
            );
            assert!(!declared.premise.is_empty(), "{name} declares its premise");
            for root in ROOTS {
                assert_eq!(
                    first_failure(name, root),
                    declared.expect.failure(),
                    "{name} at {root}"
                );
                let (outcome, violation, reproduced) = ran_at(name, root);
                assert_eq!(
                    (outcome, violation.is_some(), reproduced),
                    (Outcome::Violation, true, true),
                    "{name} at {root}"
                );
            }
        }
    }

    /// A link that holds every RESULT past the owner's retention leaves the upload `Unknown` with no
    /// RESULT dropped. The dropped history's judgment credits no lost RESULT then: the run ends
    /// unsuccessful under the premise that the link dropped one, at each pinned root.
    #[test]
    fn an_unknown_upload_with_no_dropped_result_ends_unsuccessful() {
        let name = "dr1-put-result-held-back";
        let declared = DELAYED_RESULTS.iter().find(|h| h.name == name).expect(name);
        assert_eq!(declared.expect, Expect::Unsuccessful(DROPPED_ONE));
        for root in ROOTS {
            assert_eq!(
                first_failure(name, root),
                Some(Failure::Unsuccessful(DROPPED_ONE)),
                "{name} at {root}"
            );
            assert_eq!(
                ran_at(name, root),
                (Outcome::Unsuccessful, None, true),
                "{name} at {root}"
            );
        }
    }
}
