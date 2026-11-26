//! Unknown-until-abandoned histories: a client closes an upload whose
//! outcome is `Unknown` before abandoning it, and a delayed RESULT later
//! resolves the upload it kept; and the client's `abandon` of an upload that
//! holds no outcome yet is refused, so every abandonment follows an
//! `Unknown` result.

use crate::oracle::{Script, check};

use super::super::super::super::adapters::put_outcome;
use super::super::silent_owners;
use super::*;

/// The link turns by which the sibling delays each RESULT toward the client:
/// an eighth of the client's deadline, so the RESULT reaches an undecided
/// upload.
const SHORT_DELAY_TURNS: u64 = super::super::super::WAIT_US / super::super::super::LINK_TURN_US / 8;

/// Delays each RESULT toward the client by a short delay, within the
/// upload's deadline.
fn u2_delay_briefly(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let result = Selector::All(vec![
        Selector::Kind(Kind::PutResult),
        Selector::Toward(CLIENT),
    ]);
    set_rules(
        world,
        vec![Rule::new(result, Effect::Delay(SHORT_DELAY_TURNS))],
    );
    mark(world, "a RESULT delay armed")
}

/// The upload went `Unknown` at its deadline and the history never
/// abandoned it; the client closes it. The close must keep the upload,
/// which the later RESULT judgment reads.
fn u2_close_unknown(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    mark_unknown(world, now);
    let id = world.history.put.expect("a PUT");
    let _ = world.scene.clients[0].retire(id);
    mark(
        world,
        "the client closed the unknown upload before abandoning it",
    )
}

/// A control: the client abandons the `Unknown` upload and then closes it,
/// which releases the upload before its delayed RESULT arrives.
fn u2_release_unknown(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    mark_unknown(world, now);
    let id = world.history.put.expect("a PUT");
    let _ = world.scene.clients[0].abandon(id);
    let _ = world.scene.clients[0].retire(id);
    mark(world, "the client abandoned and closed the unknown upload")
}

/// The sibling's close: the upload's receipt covers every fragment and no
/// RESULT has decided it yet; the client closes it.
fn u2_close_undecided(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    let witness = "the client closed the undecided upload";
    if world.scene.clients[0].put_outcome(id).is_some() {
        world.first.record(Failure::Unsuccessful(witness));
        return 0;
    }
    let _ = world.scene.clients[0].retire(id);
    mark(world, witness)
}

/// U2: every RESULT toward the uploading client is delayed past the
/// upload's deadline, so the upload goes `Unknown` with every fragment
/// received. The client then closes it without abandoning it. The close
/// keeps the upload, so the delayed RESULT resolves it `Published` and a
/// later GET reads its bytes. `u2-put-kept-past-a-close-undecided` delays
/// each RESULT by an eighth of the deadline instead, so the client closes
/// an undecided upload and the RESULT decides it before the deadline.
///
/// The histories judge the clause "a replacement after a possible send is
/// Unknown until abandoned" of the obligation record
/// `put-replay-and-unknown-outcome`, here for an `Unknown`
/// reached at the deadline: until abandonment, a close leaves the upload
/// with its client. They judge through the rules
/// "an upload resolved its unknown outcome before its RESULT was received"
/// and "a delayed matching RESULT left the unknown upload unresolved",
/// which `i3-put-late` already judges. They realize the `NoHeldUnknown`
/// witness of `tla/Lifecycle.tla` (`lifecycle_cases` in `tla/check.py`,
/// inverted invariant in `tla/LifecycleMC.tla`): the client is `Unknown`,
/// not abandoned and not closed, with the owner's fill ended, because the
/// model's `CClose` needs `Known`; `CResult` then decides it `Published`.
/// The client keeps the upload in `UploadCore::close`, whose
/// `Upload::known` is false for an `Unknown` upload that was not
/// abandoned. The control `u2-put-unknown-released-before-result`
/// abandons the upload before the close, which releases it as a defect in
/// `Upload::known` would.
const U2_PUT_CLOSED: [Step; 16] = replaced(
    I3_PUT_LATE,
    "unknown",
    step("unknown-closed", went_unknown, u2_close_unknown),
);

const U2_PUT_CLOSED_UNDECIDED: [Step; 16] = replaced(
    replaced(
        replaced(
            I3_PUT_LATE,
            "arm-delay",
            step("arm-delay-briefly", always, u2_delay_briefly),
        ),
        "unknown",
        step("closed-undecided", long_acked, u2_close_undecided),
    ),
    "resolved",
    step("put-result", put_decided, result_judged),
);

const U2_PUT_RELEASED: [Step; 16] = replaced(
    I3_PUT_LATE,
    "unknown",
    step("unknown-released", went_unknown, u2_release_unknown),
);

const U2_CLOSED_WITNESSES: &[&str] = &[
    "a RESULT delay armed",
    "upload receipt acknowledged",
    "the upload went unknown before its RESULT arrived",
    "the client closed the unknown upload before abandoning it",
    "a later matching RESULT resolved the unknown outcome",
    "the upload's outcome stayed consistent",
    "qualified exact read",
    "unrelated work progressed",
    "the GET agreed with the upload's outcome",
];

const U2_UNDECIDED_WITNESSES: &[&str] = &[
    "a RESULT delay armed",
    "upload receipt acknowledged",
    "the client closed the undecided upload",
    "upload published",
    "the upload's outcome stayed consistent",
    "qualified exact read",
    "unrelated work progressed",
    "the GET agreed with the upload's outcome",
];

const U2_RELEASED_WITNESSES: &[&str] = &[
    "a RESULT delay armed",
    "upload receipt acknowledged",
    "the upload went unknown before its RESULT arrived",
    "the client abandoned and closed the unknown upload",
    "a later matching RESULT resolved the unknown outcome",
    "the upload's outcome stayed consistent",
    "qualified exact read",
    "unrelated work progressed",
    "the GET agreed with the upload's outcome",
];

const U2_PREMISE: &[&str] = &["the upload went unknown before its RESULT arrived"];

const U3_UNDECIDED: &str = "the upload held no outcome at the first call of abandon";
const U3_EARLY_ACCEPTED: &str = "abandon answered true for the undecided upload";
const U3_EARLY_REFUSED: &str = "abandon answered false for the undecided upload";
const U3_NO_EARLY_CALL: &str = "no call of abandon before the upload was decided";
const U3_LATE_ACCEPTED: &str = "abandon answered true for the decided upload";
const U3_LATE_REFUSED: &str = "abandon answered false for the decided upload";
const U3_ABANDONED: &str = "the judged rows held an abandonment";
const U3_NOT_UNKNOWN: &str = "an abandonment of an attempt that was not Unknown";

/// Records the uploads the owner had published before this history's
/// upload, then drops every PUT RESULT frame toward the client.
fn u3_drop_every_result(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.published = world.scene.owner.put_report().published;
    drop_every_result(world, now)
}

/// Calls `Client::abandon` for the upload whose last fragment was just
/// supplied. Marks whether the upload held no outcome at the call, and the
/// answer.
fn u3_abandon_undecided(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    if world.scene.clients[0].put_outcome(id).is_none() {
        mark(world, U3_UNDECIDED);
    }
    if world.scene.clients[0].abandon(id) {
        mark(world, U3_EARLY_ACCEPTED)
    } else {
        mark(world, U3_EARLY_REFUSED)
    }
}

/// The step in the early call's place: it makes no call.
fn u3_no_early_abandon(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    mark(world, U3_NO_EARLY_CALL)
}

/// Calls `Client::abandon` for the decided upload, then writes the attempt
/// as oracle rows and judges them. The owner received the upload in full
/// and wrote it; its publication is a row once the owner's PUT report
/// counts it; an abandonment is a row for each call of `abandon` that
/// answered true, before the result row for the call on the undecided
/// upload and after it for this step's call. A verdict that violates
/// History fails with the verdict's own rule. A passing verdict marks that
/// the rows held an abandonment and the outcome the client reported.
fn u3_abandoned_and_judged(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    u3_judge(world, now, false)
}

fn u3_abandon_judged_first(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    u3_judge(world, now, true)
}

/// With `late_first`, the Abandon row of the call on the decided upload
/// precedes the result row.
fn u3_judge(world: &mut Mixed<'_, '_, '_>, now: u64, late_first: bool) -> u64 {
    let id = world.history.put.expect("a PUT");
    let Some(outcome) = world.collect_put(id) else {
        world
            .first
            .record(Failure::Unsuccessful("the judged upload held no outcome"));
        return 0;
    };
    let early = world.history.marks.contains(&U3_EARLY_ACCEPTED);
    let late = world.scene.clients[0].abandon(id);
    mark(
        world,
        if late {
            U3_LATE_ACCEPTED
        } else {
            U3_LATE_REFUSED
        },
    );
    let received = world.scene.clients[0].put_results();
    let body = version_b().len() as u64;
    let mut rows = Script::new();
    let op = rows.upload(silent_owners::KEY, LABEL_B, body, true);
    if silent_owners::owner_published(world, now) {
        rows.owner_publish(op, silent_owners::KEY, LABEL_B);
    }
    if early || (late && late_first) {
        rows.abandon(op, silent_owners::KEY);
    }
    rows.put_result(op, silent_owners::KEY, LABEL_B, put_outcome(outcome));
    if late && !late_first {
        rows.abandon(op, silent_owners::KEY);
    }
    let verdict = check(&rows.finish());
    if let Some((_, rule)) = verdict.violated() {
        return fail(world, Obligation::History, rule);
    }
    if !verdict.satisfies(&[Obligation::History]) {
        world.first.record(Failure::Unsuccessful(
            "the attempt's rows reached no history verdict",
        ));
        return 0;
    }
    mark(world, silent_owners::ROWS_PASSED);
    if early || late {
        mark(world, U3_ABANDONED);
    }
    match outcome {
        UploadOutcome::Unknown if received == 0 => mark(world, silent_owners::UNKNOWN),
        _ => 1,
    }
}

/// U3: every RESULT toward the uploading client is dropped, so the upload
/// the owner published is decided only by the client's deadline.
/// `u3-put-abandon-refused-while-undecided` calls `Client::abandon` right
/// after the upload's last fragment was supplied, while the upload holds no
/// outcome, and again once the client decided it;
/// `u3-put-abandoned-after-unknown` makes the second call alone. The
/// judging step writes the attempt as oracle rows in the order things
/// happened and passes them to `oracle::check`: an Abandon row before the
/// result row, which a call that answered true for the undecided upload
/// leaves, fails History with the oracle's rule for an abandonment of an
/// attempt that was not `Unknown`. Both histories pass only when their rows
/// held an Abandon row, so the rule judged an abandonment.
/// `u3-put-abandon-judged-before-unknown` is the control: it runs the steps
/// of `u3-put-abandoned-after-unknown`, and its judging step places the
/// Abandon row of the accepted call ahead of the result row.
///
/// A kill counts only with its premises marked: the drop armed, the upload
/// undecided at the first call of `abandon`, the owner's publication and a
/// RESULT the link dropped. No premise names an answer of `abandon` or the
/// upload's outcome.
const U3_ABANDON_UNDECIDED: [Step; 9] = [
    step("arm-drop", always, u3_drop_every_result),
    step("put-begin", active_put, silent_owners::begin),
    step("put-prepare", always, put_prepare),
    step("put-supply", always, put_supply),
    step("early-abandon", always, u3_abandon_undecided),
    step(
        "owner-published",
        silent_owners::owner_published,
        silent_owners::mark_owner_published,
    ),
    step(
        "result-fate",
        silent_owners::result_dropped,
        silent_owners::mark_lost,
    ),
    step("put-result", put_decided, u3_abandoned_and_judged),
    JUDGE,
];

const U3_ABANDON_UNKNOWN: [Step; 9] = replaced(
    U3_ABANDON_UNDECIDED,
    "early-abandon",
    step("early-abandon", always, u3_no_early_abandon),
);

const U3_ABANDON_JUDGED_FIRST: [Step; 9] = replaced(
    U3_ABANDON_UNKNOWN,
    "put-result",
    step(
        "put-result-abandon-first",
        put_decided,
        u3_abandon_judged_first,
    ),
);

const U3_UNDECIDED_WITNESSES: &[&str] = &[
    "a RESULT drop armed",
    U3_UNDECIDED,
    silent_owners::OWNER_PUBLISHED,
    silent_owners::LOST,
    silent_owners::ROWS_PASSED,
    U3_ABANDONED,
    silent_owners::UNKNOWN,
];

const U3_UNKNOWN_WITNESSES: &[&str] = &[
    "a RESULT drop armed",
    U3_NO_EARLY_CALL,
    silent_owners::OWNER_PUBLISHED,
    silent_owners::LOST,
    silent_owners::ROWS_PASSED,
    U3_ABANDONED,
    silent_owners::UNKNOWN,
];

const U3_UNDECIDED_PREMISE: &[&str] = &[
    "a RESULT drop armed",
    U3_UNDECIDED,
    silent_owners::OWNER_PUBLISHED,
    silent_owners::LOST,
];

const U3_UNKNOWN_PREMISE: &[&str] = &[
    "a RESULT drop armed",
    U3_NO_EARLY_CALL,
    silent_owners::OWNER_PUBLISHED,
    silent_owners::LOST,
];

const U3: &[Obligation] = &[Obligation::History];

/// The unknown-until-abandoned histories and their controls.
pub(crate) const UNKNOWNS: [History; 6] = [
    uploading(
        history(
            "u2-put-unknown-kept-past-a-close",
            &U2_PUT_CLOSED,
            U2_CLOSED_WITNESSES,
            I3_RESULT,
            Expect::Pass,
        ),
        1,
    ),
    uploading(
        history(
            "u2-put-kept-past-a-close-undecided",
            &U2_PUT_CLOSED_UNDECIDED,
            U2_UNDECIDED_WITNESSES,
            I3_RESULT,
            Expect::Pass,
        ),
        1,
    ),
    control(
        uploading(
            history(
                "u2-put-unknown-released-before-result",
                &U2_PUT_RELEASED,
                U2_RELEASED_WITNESSES,
                I3_RESULT,
                Expect::Violation(
                    Obligation::History,
                    "an upload resolved its unknown outcome before its RESULT was received",
                ),
            ),
            1,
        ),
        U2_PREMISE,
    ),
    control(
        getting(
            uploading(
                history(
                    "u3-put-abandon-refused-while-undecided",
                    &U3_ABANDON_UNDECIDED,
                    U3_UNDECIDED_WITNESSES,
                    U3,
                    Expect::Pass,
                ),
                1,
            ),
            [0, 0],
        ),
        U3_UNDECIDED_PREMISE,
    ),
    control(
        getting(
            uploading(
                history(
                    "u3-put-abandoned-after-unknown",
                    &U3_ABANDON_UNKNOWN,
                    U3_UNKNOWN_WITNESSES,
                    U3,
                    Expect::Pass,
                ),
                1,
            ),
            [0, 0],
        ),
        U3_UNKNOWN_PREMISE,
    ),
    control(
        getting(
            uploading(
                history(
                    "u3-put-abandon-judged-before-unknown",
                    &U3_ABANDON_JUDGED_FIRST,
                    U3_UNKNOWN_WITNESSES,
                    U3,
                    Expect::Violation(Obligation::History, U3_NOT_UNKNOWN),
                ),
                1,
            ),
            [0, 0],
        ),
        U3_UNKNOWN_PREMISE,
    ),
];

#[cfg(test)]
mod tests {
    use crate::net::observe::Failure;
    use crate::oracle::Obligation;
    use crate::sim::trace::{Outcome, PAYLOAD, Terminal, load};

    use super::super::super::super::bundle::{admit, failure_code, traced};
    use super::super::super::super::replay::{Replayed, replay};
    use super::super::super::tests::manifest;
    use super::{Expect, UNKNOWNS};

    /// The roots the seeded test pins: a small one and two drawn from the
    /// 64-bit range.
    const ROOTS: [u64; 3] = [11, 2_868_431_904_716_533_207, 13_407_166_382_559_114_071];

    /// History `name` recorded under `root`: its ending, its violation
    /// record and whether the bundle replayed to an equal digest.
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

    /// An upload closed while `Unknown` and not abandoned stays with its
    /// client, and its delayed RESULT resolves it `Published`, under each
    /// pinned root; an upload closed while undecided is decided by its
    /// RESULT.
    #[test]
    fn an_unknown_upload_survives_a_close_before_abandonment_and_its_result_resolves_it() {
        for name in [
            "u2-put-unknown-kept-past-a-close",
            "u2-put-kept-past-a-close-undecided",
        ] {
            for root in ROOTS {
                assert_eq!(
                    ran_at(name, root),
                    (Outcome::Pass, None, true),
                    "{name} at {root}"
                );
            }
        }
    }

    /// An abandon called while the upload holds no outcome and an abandon
    /// called once the upload ended `Unknown` each leave rows the oracle
    /// passes, under each pinned root: both histories pass with an
    /// abandonment among their judged rows and replay to an equal digest.
    #[test]
    fn an_abandon_follows_an_unknown_outcome_under_pinned_roots() {
        for name in [
            "u3-put-abandon-refused-while-undecided",
            "u3-put-abandoned-after-unknown",
        ] {
            for root in ROOTS {
                assert_eq!(
                    ran_at(name, root),
                    (Outcome::Pass, None, true),
                    "{name} at {root}"
                );
            }
        }
    }

    /// Each passing history activates the obligations it declares.
    #[test]
    fn every_passing_unknown_history_activates_the_obligations_it_declares() {
        for history in UNKNOWNS.iter().filter(|h| h.expect == Expect::Pass) {
            let activated = super::super::super::activated(history.witnesses);
            for obligation in history.obligations {
                assert!(
                    activated.contains(obligation),
                    "{}: {obligation:?} has no witnessed check",
                    history.name
                );
            }
        }
    }

    /// The control fails through its named rule once its premise is marked,
    /// and replays to an equal digest.
    #[test]
    fn every_unknown_control_fails_through_its_named_check() {
        let killed = [
            (
                "u2-put-unknown-released-before-result",
                Obligation::History,
                "an upload resolved its unknown outcome before its RESULT was received",
            ),
            (
                "u3-put-abandon-judged-before-unknown",
                Obligation::History,
                "an abandonment of an attempt that was not Unknown",
            ),
        ];
        for (name, obligation, rule) in killed {
            let declared = UNKNOWNS.iter().find(|h| h.name == name).expect(name);
            assert_eq!(
                declared.expect,
                Expect::Violation(obligation, rule),
                "{name}"
            );
            assert!(!declared.premise.is_empty(), "{name} declares its premise");
            for root in ROOTS {
                assert_eq!(
                    ran_at(name, root),
                    (
                        Outcome::Violation,
                        Some(failure_code(&Failure::Violation(obligation, rule))),
                        true
                    ),
                    "{name} at {root}"
                );
            }
        }
        let controls = UNKNOWNS.iter().filter(|h| h.expect != Expect::Pass).count();
        assert_eq!(controls, killed.len());
    }
}
