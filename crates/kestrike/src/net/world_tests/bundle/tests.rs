//! The mixed world's bundles: what an upload run records, its terminal
//! judgment, and the manifest bounds a run must fit.

use sha2::{Digest, Sha256};

use crate::oracle::Obligation;
use crate::sim::action::ActionKind;
use crate::sim::manifest::Manifest;
use crate::sim::trace::{Event, Infrastructure, Loaded, Outcome, PAYLOAD, Terminal, bit, load};
use crate::sim::turn::{End, Limit};

use super::super::super::audit::{Class, Reason, Record, Source, Verdict};
use super::super::super::observe::Failure;
use super::super::{FRAGMENT_LEN, Plan, QUIET, payload, upload_code};
use super::{
    ACT, AUDIT, Breach, FAILURE, IDENTITY, PUT, PutRecord, RULE, Refusal, SUPPLIED, Site, UPLOAD,
    UploadState, Violated, WITNESS, admit, breach, event_put, identity_event, judge, traced,
};

/// A manifest of `profile` with every bound at the run's own or above, and
/// `attempts` upload attempts.
pub(super) fn manifest(profile: &str, attempts: u64) -> Manifest {
    let text = crate::sim::manifest_tests::sample(profile, &"a".repeat(64), "x86_64-linux");
    Manifest::parse(&text)
        .unwrap()
        .with("upload_attempts", attempts)
}

/// Runs `manifest` into memory and loads the bundle it recorded.
pub(super) fn ran(manifest: &Manifest) -> (Terminal, [u8; 32], Loaded) {
    let closed = traced(admit(manifest).unwrap(), Vec::new());
    let loaded = load(&closed.sink, manifest.capacity().records()).unwrap();
    assert_eq!(
        (loaded.digest, loaded.terminal, loaded.work),
        (closed.digest, closed.terminal, closed.work)
    );
    (closed.terminal, closed.digest, loaded)
}

fn of(loaded: &Loaded, kind: u8) -> Vec<Event> {
    loaded
        .events
        .iter()
        .copied()
        .filter(|event| event.kind == kind)
        .collect()
}

/// The upload actions' kind codes and payloads.
fn puts(loaded: &Loaded) -> Vec<(ActionKind, [u8; PAYLOAD])> {
    of(loaded, PUT)
        .into_iter()
        .map(|event| {
            (
                ActionKind::from_code(event.payload[0]).unwrap(),
                event.payload,
            )
        })
        .collect()
}

/// An upload run records a bundle that counts: it loads to the run's
/// digest, terminal and work, every decision is a recorded choice, each
/// supply names the first 16 bytes of the SHA-256 of the bytes it offered
/// and three are accepted, the outcome collection names the published
/// outcome once it is decided, the upload state reaches its published
/// binding, every executed action has its record and witnessed ones their
/// witness, each upload action has one `PUT` event, and no failure is
/// recorded.
#[test]
fn an_upload_run_records_its_put_observations_and_counts() {
    let manifest = manifest("upload", 1);
    let (terminal, digest, loaded) = ran(&manifest);
    assert!(terminal.counts(), "{terminal:?}");
    assert_eq!(loaded.terminal, terminal);
    assert_eq!(loaded.digest, digest);
    assert_eq!(loaded.work.decisions, loaded.decisions);
    assert!(loaded.work.turns > 0 && loaded.work.virtual_us > 0);
    let object = payload(super::super::OBJECT_LEN as usize, 30);
    let supplied: Vec<PutRecord> = loaded
        .events
        .iter()
        .filter_map(PutRecord::of)
        .filter(|put| put.kind == Some(ActionKind::Supply))
        .collect();
    let accepted = supplied
        .iter()
        .filter(|put| put.outcome == SUPPLIED)
        .count();
    assert_eq!(
        accepted,
        super::FRAGMENTS as usize,
        "each fragment supplied once"
    );
    for put in &supplied {
        let start = put.fragment as usize * FRAGMENT_LEN as usize;
        let bytes = &object[start..(start + FRAGMENT_LEN as usize).min(object.len())];
        assert_eq!(
            put.supplied[..],
            Sha256::digest(bytes)[..16],
            "fragment {}",
            put.fragment
        );
    }
    let collected = puts(&loaded)
        .into_iter()
        .rev()
        .find(|(kind, _)| *kind == ActionKind::PutOutcome)
        .expect("an outcome collection");
    let code = PutRecord::of(&Event {
        kind: PUT,
        payload: collected.1,
    })
    .unwrap()
    .outcome;
    assert_eq!(
        u64::from(code),
        upload_code(super::super::super::upload::UploadOutcome::Published)
    );
    let states = of(&loaded, UPLOAD);
    assert!(
        states
            .windows(2)
            .all(|pair| pair[0].payload != pair[1].payload)
    );
    let decoded: Vec<UploadState> = states.iter().filter_map(UploadState::of).collect();
    assert_eq!(decoded.len(), states.len());
    assert!(
        decoded.last().unwrap().bound,
        "the owner binds the upload's key"
    );
    assert!(
        decoded.iter().any(|state| state.held > 0),
        "a device held a source"
    );
    assert!(of(&loaded, ACT).len() >= of(&loaded, WITNESS).len());
    assert!(!of(&loaded, WITNESS).is_empty());
    assert!(of(&loaded, FAILURE).is_empty() && loaded.violation.is_none());
    let put_turns = turns_in(&loaded, crate::sim::choice::Domain::Put as u8);
    assert_eq!(
        of(&loaded, PUT).len(),
        put_turns,
        "one PUT event per upload action"
    );
}

/// Upload actions among the turns the controller recorded: turns whose
/// event names domain `domain`.
fn turns_in(loaded: &Loaded, domain: u8) -> usize {
    loaded
        .turns
        .iter()
        .filter(|event| event[0] == domain)
        .count()
}

/// A `PUT` event's payload moves with each supplier input and outcome it
/// records: the supplied bytes' hash, the deferral's hold and the outcome.
#[test]
fn a_put_event_moves_with_its_supplier_input_and_outcome() {
    let base = event_put(ActionKind::Supply, 1, 7, 2, &[3; 16], 0, 1).payload;
    let variants = [
        event_put(ActionKind::Supply, 1, 7, 2, &[4; 16], 0, 1),
        event_put(ActionKind::Supply, 1, 7, 2, &[3; 16], 5_000, 1),
        event_put(ActionKind::Supply, 1, 7, 2, &[3; 16], 0, 0),
        event_put(ActionKind::DeferSupply, 1, 7, 2, &[3; 16], 0, 1),
        event_put(ActionKind::Supply, 2, 7, 2, &[3; 16], 0, 1),
    ];
    for variant in variants {
        assert_ne!(variant.payload, base);
    }
}

/// A resident record changed before the run fails the first stopped
/// boundary: the bundle records the failure as its flushed violation,
/// naming the bytes obligation, and its violation terminal never counts.
#[test]
fn an_observed_failure_is_the_bundles_violation() {
    let (terminal, _, loaded) = ran(&manifest("corrupted", 1));
    assert!(matches!(
        terminal,
        Terminal::Complete {
            outcome: Outcome::Violation,
            ..
        }
    ));
    assert!(!terminal.counts());
    let violation = loaded.violation.expect("the violation record");
    assert_eq!(violation[1], Obligation::Bytes as u8 + 1);
    assert!(
        of(&loaded, FAILURE).is_empty(),
        "the failure became the violation record"
    );
}

/// Each control of [`CORRUPTED`](super::CORRUPTED) is a control that runs
/// its profile's scenario with the resident record's byte changed, and its
/// run ends as a violation of the bytes obligation under the record-check
/// rule.
#[test]
fn every_corrupted_control_fails_the_record_check_in_its_profiles_scenario() {
    for (control, base) in super::CORRUPTED {
        assert_eq!(
            super::super::catalog::class(control),
            Some(super::super::catalog::Class::Control),
            "{control}"
        );
        assert_eq!(
            super::super::catalog::class(base),
            Some(super::super::catalog::Class::Live),
            "{base}"
        );
        let (planted, plain) = (
            super::named(control, 3).unwrap(),
            super::named(base, 3).unwrap(),
        );
        assert!(planted.1.corrupt_resident && !plain.1.corrupt_resident);
        let restored = Plan {
            corrupt_resident: false,
            ..planted.1
        };
        assert_eq!(
            format!("{restored:?}"),
            format!("{:?}", plain.1),
            "{control}"
        );
        assert_eq!(planted.0.declared, plain.0.declared, "{control}");
        let sample = crate::sim::manifest_tests::sample(control, &"a".repeat(64), "x86_64-linux");
        let (terminal, _, loaded) = ran(&Manifest::parse(&sample).unwrap());
        assert!(
            matches!(
                terminal,
                Terminal::Complete {
                    outcome: Outcome::Violation,
                    ..
                }
            ),
            "{control}: {terminal:?}"
        );
        assert_eq!(
            loaded.violation,
            Some(super::failure_code(&Failure::Violation(
                Obligation::Bytes,
                "a bound slot's record fails its header or chunk checks"
            ))),
            "{control}"
        );
    }
}

/// The sample manifest of `profile` at `root`.
fn rooted(profile: &str, root: u64) -> Manifest {
    let mut lines =
        crate::sim::manifest_tests::sample_lines(profile, &"a".repeat(64), "x86_64-linux");
    lines[2].1 = root.to_string();
    Manifest::parse(&crate::sim::manifest_tests::text(&lines)).unwrap()
}

/// Each control that plants at a collected result ends as a violation
/// under its rule on some root: `misread` under the complete-read rule of
/// the bytes obligation, `staged-hit` and `failing-hit` under the
/// unpublished-hit rule,
/// `failing-exposed` under the refused-read rule of the containment
/// obligation and `uncertain-published` under the rule for a publication
/// collected without its result. On every root tried, each ends in that
/// violation or, with no violation, short of a pass, and the scenario it
/// plants in ends without a violation.
#[test]
fn each_result_plant_fails_its_rule_and_its_scenario_ends_without_a_violation() {
    for (control, base, obligation, rule) in [
        (
            "misread",
            "upload",
            Obligation::Bytes,
            "a complete read returned bytes other than the label's content",
        ),
        (
            "staged-hit",
            "upload",
            Obligation::History,
            "a hit of a version no linearized fill published",
        ),
        (
            "failing-hit",
            "failing",
            Obligation::History,
            "a hit of a version no linearized fill published",
        ),
        (
            "failing-exposed",
            "failing",
            Obligation::Contain,
            "a refused read exposed bytes",
        ),
        (
            "uncertain-published",
            "uncertain",
            Obligation::History,
            "an upload collected as published without its result",
        ),
    ] {
        assert_eq!(
            super::super::catalog::class(control),
            Some(super::super::catalog::Class::Control),
            "{control}"
        );
        let expected = super::failure_code(&Failure::Violation(obligation, rule));
        let mut caught = 0;
        for root in 1..=6 {
            let (terminal, _, loaded) = ran(&rooted(control, root));
            match loaded.violation {
                Some(violation) => {
                    assert_eq!(violation, expected, "{control} root {root}");
                    caught += 1;
                }
                None => assert!(
                    !matches!(
                        terminal,
                        Terminal::Complete {
                            outcome: Outcome::Pass,
                            ..
                        }
                    ),
                    "{control} root {root}: {terminal:?}"
                ),
            }
            let (_, _, healthy) = ran(&rooted(base, root));
            assert_eq!(healthy.violation, None, "{base} root {root}");
        }
        assert!(caught > 0, "{control}");
    }
}

fn control_fails_on_three_roots(name: &str, plant: super::super::Plant, expected: Failure) {
    assert!(super::named(name, 1).unwrap().1.control(), "{name}");
    assert_eq!(
        super::super::catalog::class(name),
        Some(super::super::catalog::Class::Control),
        "{name}"
    );
    let code = super::failure_code(&expected);
    let outcome = |terminal: Terminal| match terminal {
        Terminal::Complete { outcome, .. } => Some(outcome),
        Terminal::Infrastructure { .. } => None,
    };
    for root in 1..=3 {
        let (terminal, _, loaded) = ran(&rooted(name, root));
        assert_eq!(
            outcome(terminal),
            Some(Outcome::Violation),
            "{name} root {root}"
        );
        assert_eq!(loaded.violation, Some(code), "{name} root {root}");
        assert_eq!(
            super::super::replay::premise(plant, &loaded),
            Some(true),
            "{name} root {root}"
        );
        let again = rerun(&rooted(name, root));
        assert!(again.acted, "{name} root {root}: the plant acted");
        assert_eq!(
            again.settled.first.as_ref(),
            Some(&expected),
            "{name} root {root}"
        );
        let (terminal, _, healthy) = ran(&rooted("upload", root));
        assert_eq!(outcome(terminal), Some(Outcome::Pass), "upload root {root}");
        assert_eq!(healthy.violation, None, "upload root {root}");
    }
}

/// The `leaked` control runs `upload`'s scenario with the leaked-unit plant.
/// The conservation check reports the leak as
/// `Failure::Violation(Obligation::Resources, FREE_RUNS)` once the plant
/// acts. The `upload` run of the same root passes, so the plant alone causes
/// the violation.
#[test]
fn the_leaked_control_fails_the_free_runs_on_every_root() {
    control_fails_on_three_roots(
        "leaked",
        super::super::Plant::LeakedUnit,
        Failure::Violation(Obligation::Resources, crate::net::observe::FREE_RUNS),
    );
}

/// The `uncounted` control's multiplexer drops the last lease one receive
/// filled and reports one fewer. On each of three pinned roots the run
/// fails under `UNACCOUNTED`, the datagram accounts rule, and `upload`
/// passes on the same root.
#[test]
fn the_uncounted_control_fails_the_datagram_accounts_on_three_roots() {
    control_fails_on_three_roots(
        "uncounted",
        super::super::Plant::Uncounted,
        Failure::Violation(Obligation::Contain, crate::net::observe::UNACCOUNTED),
    );
}

/// A publication claimed on the turn the run reaches its goal is judged
/// when the run ends: from this root the `acked` control's GET completes
/// before the claim, so no stopped boundary follows the claim, and the run
/// still ends as a violation under the rule for a publication collected
/// without its result. The claim is the run's last turn, and a rerun
/// limited to the run's own turn count still ends finished.
#[test]
fn a_claim_on_the_goals_turn_is_judged_when_the_run_ends() {
    let mut lines =
        crate::sim::manifest_tests::sample_lines("acked", &"a".repeat(64), "x86_64-linux");
    lines[2].1 = "23187".to_owned();
    let manifest = Manifest::parse(&crate::sim::manifest_tests::text(&lines)).unwrap();
    let (terminal, _, loaded) = ran(&manifest);
    let limited = rerun(&manifest.clone().with("turns", loaded.work.turns));
    assert_eq!(
        limited.report.end,
        End::Done,
        "premise: no stopped boundary follows the claim"
    );
    let published =
        super::super::upload_code(super::super::super::upload::UploadOutcome::Published);
    let claim = limited
        .acts
        .iter()
        .find(|act| act.kind == super::super::ActionKind::PutOutcome && act.outcome == published)
        .expect("premise: the control claimed the publication");
    assert_eq!(
        claim.turn as u64 + 1,
        limited.report.turn_count,
        "premise: the claim is the run's last turn, the turn that reaches the goal"
    );
    assert!(
        matches!(
            limited.get,
            Some((Some(super::super::super::fetch::Outcome::Complete), _))
        ),
        "premise: the GET completed before the claim's turn ended the run"
    );
    assert!(
        matches!(
            terminal,
            Terminal::Complete {
                outcome: Outcome::Violation,
                ..
            }
        ),
        "{terminal:?}"
    );
    assert_eq!(
        loaded.violation,
        Some(super::failure_code(&Failure::Violation(
            Obligation::History,
            "an upload collected as published without its result"
        )))
    );
}

/// A control that reaches its goal before its plant takes effect ends
/// `Unsuccessful` under `NO_EFFECT`. The `failing` scenario reaches its goal
/// with zero publications, so the published-byte and leaked-unit plants both
/// yield `Outcome::Unsuccessful` under `NO_EFFECT`.
#[test]
fn a_control_whose_plant_takes_no_effect_is_unsuccessful() {
    let sample = crate::sim::manifest_tests::sample("failing", &"a".repeat(64), "x86_64-linux");
    let manifest = Manifest::parse(&sample).unwrap();
    for plant in [
        super::super::Plant::PublishedByte,
        super::super::Plant::LeakedUnit,
    ] {
        let (profile, plan, goal) = super::named("failing", 1).unwrap();
        let admitted = super::Admitted {
            manifest: &manifest,
            scenario: (profile, Plan { plant, ..plan }, goal),
        };
        let closed = traced(admitted, Vec::new());
        assert!(
            matches!(
                closed.terminal,
                Terminal::Complete {
                    outcome: Outcome::Unsuccessful,
                    ..
                }
            ),
            "{plant:?}: {:?}",
            closed.terminal
        );
        let loaded = load(&closed.sink, manifest.capacity().records()).unwrap();
        assert_eq!(
            super::unsuccessful_rule(&loaded).as_deref(),
            Some(super::super::cluster::NO_EFFECT),
            "{plant:?}"
        );
    }
    let (terminal, _, _) = ran(&manifest);
    assert!(
        matches!(
            terminal,
            Terminal::Complete {
                outcome: Outcome::Pass,
                ..
            }
        ),
        "{terminal:?}"
    );
}

/// The Progress check judges client 1's episode only past its bound, so a
/// turn limit that stops `rekey-stalled` inside the bound leaves the plant
/// idle and the run inconclusive.
#[test]
fn a_stalled_heal_acts_once_its_episode_passes_its_bound() {
    let whole = manifest("rekey-stalled", 1);
    let cut = (1..64)
        .map(|turns| whole.clone().with("turns", turns))
        .find(|cut| rerun(cut).episodes.iter().any(|open| open.client == 1))
        .expect("a turn limit that stops the run past the rekey's delivery");
    let stopped = rerun(&cut);
    assert_eq!(stopped.report.end, End::Inconclusive(Limit::Total));
    assert_eq!(stopped.settled.first, None);
    assert!(!stopped.acted, "the episode is inside its bound");
    let (terminal, _, _) = ran(&cut);
    assert!(
        matches!(
            terminal,
            Terminal::Complete {
                outcome: Outcome::Inconclusive,
                ..
            }
        ),
        "{terminal:?}"
    );
    let stalled = rerun(&whole);
    assert_eq!(
        stalled.settled.first,
        Some(Failure::Violation(
            Obligation::Progress,
            "a healed request stalled past its bound"
        ))
    );
    assert!(stalled.acted, "the episode passed its bound");
}

/// The check of a publication reported without its result runs at the
/// next clock move. A turn limit that stops `acked` before that move, at
/// whichever turn, records no failure and leaves the plant idle: no check
/// was due. The whole run reaches that move, so its plant acted.
#[test]
fn an_acknowledged_publication_stopped_before_its_check_has_not_acted() {
    let text = crate::sim::manifest_tests::sample("acked", &"a".repeat(64), "x86_64-linux");
    let whole = Manifest::parse(&text.replace("root = 3", "root = 5")).unwrap();
    let failed = rerun(&whole);
    assert_eq!(
        failed.settled.first,
        Some(Failure::Violation(
            Obligation::History,
            "an upload collected as published without its result"
        ))
    );
    assert!(failed.acted, "the clock moved after the plant");
    for turns in 1..=failed.report.turn_count {
        let stopped = rerun(&whole.clone().with("turns", turns));
        assert_eq!(stopped.report.end, End::Inconclusive(Limit::Total));
        assert_eq!(
            (stopped.settled.first, stopped.acted),
            (None, false),
            "a turn limit of {turns}"
        );
    }
}

/// `uncertain-published` collects an upload of unknown outcome as
/// published, and the same check judges it at the next clock move or at
/// the end of a run that finishes. A turn limit that stops the run before
/// either, at whichever turn, records no failure and leaves the plant
/// idle; the whole run finishes, fails the check and counts its plant as
/// acted.
#[test]
fn an_unknown_publication_stopped_before_its_check_has_not_acted() {
    let mut lines = crate::sim::manifest_tests::sample_lines(
        "uncertain-published",
        &"a".repeat(64),
        "x86_64-linux",
    );
    lines[2].1 = "3".to_owned();
    let whole = Manifest::parse(&crate::sim::manifest_tests::text(&lines)).unwrap();
    let failed = rerun(&whole);
    assert_eq!(failed.report.end, End::Done);
    assert_eq!(
        failed.settled.first,
        Some(Failure::Violation(
            Obligation::History,
            "an upload collected as published without its result"
        ))
    );
    assert!(failed.acted, "the run finished after the plant");
    for turns in 1..=failed.report.turn_count {
        let stopped = rerun(&whole.clone().with("turns", turns));
        assert_eq!(stopped.report.end, End::Inconclusive(Limit::Total));
        assert_eq!(
            (stopped.settled.first, stopped.acted),
            (None, false),
            "a turn limit of {turns}"
        );
    }
}

/// `acked` at root 18149 reaches its goal with no clock move after its
/// report, so no stopped boundary follows the report: a turn limit of the
/// run's own turn count still ends it finished. The end of the run
/// compares the publication with the client's result and fails it, and
/// the plant counts as acted, so a comparison that missed it would end
/// the run under the missed-plant rule.
#[test]
fn an_acknowledged_publication_in_a_finished_run_is_judged_at_its_end() {
    let text = crate::sim::manifest_tests::sample("acked", &"a".repeat(64), "x86_64-linux");
    let whole = Manifest::parse(&text.replace("root = 3", "root = 18149")).unwrap();
    let finished = rerun(&whole);
    assert_eq!(finished.report.end, End::Done);
    assert!(matches!(
        finished.put,
        Some((
            Some(super::super::super::upload::UploadOutcome::Published),
            _
        ))
    ));
    let limited = rerun(&whole.clone().with("turns", finished.report.turn_count));
    assert_eq!(limited.report.end, End::Done);
    assert_eq!(
        finished.settled.first,
        Some(Failure::Violation(
            Obligation::History,
            "an upload collected as published without its result"
        ))
    );
    assert!(finished.acted, "the run finished after the report");
}

/// A byte the plant changes counts once a stopped boundary, or the run's
/// end, finds its record bound, which is when the record check reads it.
/// `planted` fails that check, so its plant acted. A turn limit that
/// stops it between the plant and the next boundary fails the check at
/// the run's end, which reads the record, and counts the plant too. In
/// `settled-faulted-invalidating-planted` at root 11 an invalidation
/// unbinds the record between the plant and the next stopped boundary: the
/// run finishes with no failure, the key unbound and the plant idle.
#[test]
fn a_changed_byte_acts_once_a_boundary_finds_its_record_bound() {
    let manifest = |profile: &str, root: u64| {
        let text = crate::sim::manifest_tests::sample(profile, &"a".repeat(64), "x86_64-linux");
        Manifest::parse(&text.replace("root = 3", &format!("root = {root}"))).unwrap()
    };
    let judged = rerun(&manifest("planted", 1));
    assert_eq!(
        judged.settled.first,
        Some(Failure::Violation(
            Obligation::Bytes,
            "a bound slot's record fails its header or chunk checks"
        ))
    );
    assert!(judged.acted, "a boundary read the changed record");
    let stopped = (1..judged.report.turn_count)
        .map(|turns| rerun(&manifest("planted", 1).with("turns", turns)))
        .find(|stopped| stopped.acted)
        .expect("a turn limit between the plant and the next boundary");
    assert_eq!(stopped.report.end, End::Inconclusive(Limit::Total));
    assert_eq!(stopped.settled.first, judged.settled.first);
    let unbound = rerun(&manifest("settled-faulted-invalidating-planted", 11));
    assert_eq!(unbound.report.end, End::Done);
    assert_eq!(unbound.settled.first, None);
    assert_eq!(unbound.extents.upload, None);
    assert!(!unbound.acted, "no boundary found the changed record bound");
}

/// A changed record is still bound when a binding names its slot at its
/// incarnation. A binding that names a slot the pool does not hold is not
/// that record, and the lookup leaves it to the boundary check, which
/// reports it.
#[test]
fn a_binding_past_the_pool_is_not_the_changed_record() {
    use crate::storage::lenses::{Binding, SlotFact};
    let binding = |slot| Binding {
        shard: 0,
        identity: crate::index::Identity {
            tag: 0,
            incarnation_low: 0,
            slot,
        },
    };
    let fact = SlotFact {
        incarnation: 3,
        resident: true,
        fingerprint: 0,
        session: 0,
        version: 0,
        device_unit: 0,
        len_units: 1,
    };
    assert!(super::super::binds(&[binding(0)], &[fact], (0, 3)));
    assert!(!super::super::binds(&[binding(0)], &[fact], (0, 4)));
    assert!(!super::super::binds(&[binding(5)], &[fact], (0, 3)));
    assert!(super::super::binds(
        &[binding(5), binding(0)],
        &[fact],
        (0, 3)
    ));
}

/// The stalled heal's plant counts as acted exactly when the Progress
/// check judged client 1's episode past its bound. Under each turn limit
/// around the first one that fails `rekey-stalled`, the plant acted when
/// the run records that failure and is idle when it records none.
#[test]
fn a_stalled_heal_acts_when_the_progress_check_judges_it_late() {
    let whole = manifest("rekey-stalled", 1);
    let stalled = Some(Failure::Violation(
        Obligation::Progress,
        "a healed request stalled past its bound",
    ));
    let failing = (400..600)
        .find(|&turns| rerun(&whole.clone().with("turns", turns)).settled.first == stalled)
        .expect("a turn limit past the episode's bound");
    for turns in failing - 8..failing + 8 {
        let stopped = rerun(&whole.clone().with("turns", turns));
        let failed = stopped.settled.first == stalled;
        assert_eq!(failed, turns >= failing, "a turn limit of {turns}");
        assert_eq!(stopped.acted, failed, "a turn limit of {turns}");
    }
}

/// One manifest records one digest, decision count and result in two runs,
/// though their diagnostics, such as wall time, differ; another root moves
/// the digest, and another build pin moves it while the run's terminal and
/// decisions stay, since the pin identifies the build and feeds no
/// decision.
#[test]
fn one_manifest_records_one_digest() {
    let manifest = manifest("upload", 1);
    let (first, digest, loaded) = ran(&manifest);
    let (second, again, reloaded) = ran(&manifest);
    assert_eq!(
        (first, digest, loaded.decisions),
        (second, again, reloaded.decisions)
    );
    let mut rooted = manifest.clone();
    rooted.root = 4;
    assert_ne!(ran(&rooted).1, digest);
    let mut rebuilt = manifest;
    rebuilt.build = "0".repeat(64);
    let (terminal, moved, run) = ran(&rebuilt);
    assert_ne!(moved, digest, "the build pin moves the digest");
    assert_eq!(
        (terminal, &run.tape, &run.turns, &run.events),
        (first, &loaded.tape, &loaded.turns, &loaded.events),
        "the build pin feeds no decision"
    );
}

/// A run over faulty links records each injected link outcome as an audit
/// event and each capture its taps took as a rule event, one for one, and
/// still counts.
#[test]
fn a_faulted_run_records_its_link_outcomes_and_rule_decisions() {
    let (terminal, _, loaded) = ran(&manifest("faulted", 1));
    assert!(terminal.counts(), "{terminal:?}");
    let injected = of(&loaded, AUDIT)
        .iter()
        .filter(|event| event.payload[1] == Class::Injected as u8)
        .count();
    assert!(injected > 0, "the faults fired");
    let again = rerun(&manifest("faulted", 1));
    let captures: usize = again.captures.iter().map(Vec::len).sum();
    assert!(captures > 0, "the taps saw decisions");
    assert_eq!(of(&loaded, RULE).len(), captures);
}

/// The mixed run `manifest` records, rerun outside the bundle recorder from
/// the same profile, root, links and limits.
pub(super) fn rerun(manifest: &Manifest) -> super::super::Ran {
    let (_, _, goal) = super::named(&manifest.profile, manifest.root).unwrap();
    rerun_until(manifest, goal)
}

/// [`rerun`] with `goal` in place of the profile's own.
pub(super) fn rerun_until(
    manifest: &Manifest,
    goal: fn(&super::super::Mixed<'_, '_, '_>) -> bool,
) -> super::super::Ran {
    let (profile, plan, _) = super::named(&manifest.profile, manifest.root).unwrap();
    let plan = Plan {
        link: super::super::super::link::LinkLimits {
            copy_bytes: manifest.count("link_copy_bytes") as usize,
            tx_slots: manifest.count("tx_slots") as usize,
        },
        ..plan
    };
    let limits = crate::sim::turn::Limits {
        total: manifest.count("turns"),
        same_time: manifest.count("same_time"),
        no_progress: manifest.count("no_progress"),
    };
    let chooser = profile.recorder(&super::super::sites_for(&plan));
    super::super::mixed_run(chooser, &profile, plan, goal, limits, &mut ()).0
}

/// A deferring run records each deferral with the time it holds the
/// supplier back, so the supplier's readiness is part of the digest.
#[test]
fn a_deferral_records_the_readiness_it_set() {
    let (terminal, _, loaded) = ran(&manifest("deferring", 1));
    assert!(terminal.counts(), "{terminal:?}");
    let deferrals: Vec<_> = puts(&loaded)
        .into_iter()
        .filter(|(kind, _)| *kind == ActionKind::DeferSupply)
        .collect();
    assert!(!deferrals.is_empty());
    for (_, payload) in deferrals {
        let put = PutRecord::of(&Event { kind: PUT, payload }).unwrap();
        assert!(put.held > 0);
    }
}

/// The world's configuration record carries the plan's declared reasons and
/// observed failure as canonical codes, so a Debug rendering of either
/// stays out of the digest.
#[test]
fn the_plan_records_canonical_codes() {
    let plan = Plan {
        declared: &[
            Reason::Oversize,
            Reason::Full(super::super::super::rules::Bound::Rules),
        ],
        observed: Some(&Failure::Violation(Obligation::Bytes, "a byte changed")),
        ..QUIET
    };
    let record = plan.record();
    for rendered in [
        format!("{:?}", plan.declared),
        format!("{:?}", plan.observed),
    ] {
        let rendered = rendered.as_bytes();
        assert!(
            !record
                .windows(rendered.len())
                .any(|window| window == rendered)
        );
    }
    assert!(record.windows(3).any(|window| window == [17, 0, 0]));
    assert!(record.windows(14).any(|window| window == b"a byte changed"));
    let healing = Plan {
        episodes: true,
        ..plan
    };
    assert_ne!(
        healing.record(),
        record,
        "the healed-episodes flag is recorded"
    );
}

/// The terminal judgment and the violation it pairs with each outcome: a
/// run declaring uploads that recorded none is unsuccessful; a run that ran
/// no boundary passes without counting; a defect is infrastructure keeping
/// its evidence; an observed violation, else a failing audit, is a
/// violation naming it, over any unsuccessful or inconclusive observation;
/// otherwise an unsuccessful observation is unsuccessful and an
/// inconclusive oracle verdict, audit or limit is inconclusive, each with no
/// violation.
#[test]
fn the_judgment_pairs_each_outcome_with_its_violation() {
    let both = bit(Obligation::Bytes) | bit(Obligation::History);
    let outcome = |judged: (Terminal, Option<Violated>)| {
        let variant = judged.1.map(|violated| violated.code()[0]);
        match judged.0 {
            Terminal::Complete { outcome, .. } => (Some(outcome), variant),
            Terminal::Infrastructure(_) => (None, variant),
        }
    };
    let (counted, none) = judge(End::Done, None, Verdict::Pass, (true, 3), 4);
    assert!(counted.counts() && none.is_none());
    assert_eq!(
        outcome(judge(End::Done, None, Verdict::Pass, (true, 0), 4)),
        (Some(Outcome::Unsuccessful), None)
    );
    let unchecked = judge(End::Done, None, Verdict::Pass, (false, 0), 0);
    assert_eq!(
        unchecked.0,
        Terminal::Complete {
            outcome: Outcome::Pass,
            fired: 0,
            required: both
        }
    );
    assert!(!unchecked.0.counts());
    let record = Record {
        class: Class::Harness,
        reason: Reason::Unattributed,
        source: Source::Device(1),
    };
    let failed = Verdict::Fail(record);
    let violated = Failure::Violation(Obligation::Bytes, "a byte changed");
    let unsuccessful = Failure::Unsuccessful("a witness never fired");
    let unsure = Failure::Oracle(crate::oracle::Verdict::Inconclusive(
        crate::oracle::Inconclusive::SearchBound { limit: 1 },
    ));
    let truncated = Failure::Truncated(Box::new(Failure::Violation(Obligation::Bytes, "cut")));
    let defect = End::Defect(crate::sim::turn::Defect::Due { now: 1, due: 1 });
    let limited = End::Inconclusive(Limit::Total);
    let bounded = Verdict::Inconclusive(super::super::super::rules::Bound::Records);
    let cases = [
        (defect, Some(&violated), Verdict::Pass, (None, Some(1))),
        (defect, None, Verdict::Pass, (None, None)),
        (defect, None, failed, (None, Some(4))),
        (
            End::Done,
            Some(&truncated),
            Verdict::Pass,
            (Some(Outcome::Unsuccessful), None),
        ),
        (
            End::Done,
            Some(&violated),
            failed,
            (Some(Outcome::Violation), Some(1)),
        ),
        (End::Done, None, failed, (Some(Outcome::Violation), Some(4))),
        (
            End::Done,
            Some(&unsuccessful),
            failed,
            (Some(Outcome::Violation), Some(4)),
        ),
        (
            End::Done,
            Some(&unsure),
            failed,
            (Some(Outcome::Violation), Some(4)),
        ),
        (limited, None, failed, (Some(Outcome::Violation), Some(4))),
        (
            End::Done,
            Some(&unsuccessful),
            Verdict::Pass,
            (Some(Outcome::Unsuccessful), None),
        ),
        (
            End::Done,
            Some(&unsure),
            Verdict::Pass,
            (Some(Outcome::Inconclusive), None),
        ),
        (
            End::Done,
            None,
            bounded,
            (Some(Outcome::Inconclusive), None),
        ),
        (
            limited,
            None,
            Verdict::Pass,
            (Some(Outcome::Inconclusive), None),
        ),
    ];
    for (end, failure, audit, expected) in cases {
        let judged = judge(end, failure, audit, (false, 0), 4);
        assert_eq!(outcome(judged), expected, "{end:?} {failure:?} {audit:?}");
    }
    for (failure, audit) in [(None, Verdict::Pass), (Some(&violated), failed)] {
        assert_eq!(
            judge(End::Halted, failure, audit, (false, 0), 4).0,
            Terminal::Infrastructure(crate::sim::trace::Infrastructure::Sink),
            "{failure:?} {audit:?}"
        );
    }
    // An observed violation names the identity over a failing audit, and
    // an audit alone names its record.
    let (_, both) = judge(End::Done, Some(&violated), failed, (false, 0), 4);
    assert_eq!(both, Some(Violated::Observed(violated.clone())));
    let (_, audited) = judge(End::Done, Some(&unsuccessful), failed, (false, 0), 4);
    assert_eq!(audited, Some(Violated::Audit(record)));
}

/// Version 2 of the identity lays out the version, variant, obligation
/// plus one, class plus one, site, the text's little-endian length and the
/// text's SHA-256, zero-padded: the SHA-256 of "abc" is the published test
/// vector.
#[test]
fn the_identity_has_a_fixed_encoding() {
    let event = identity_event(&Failure::Violation(Obligation::Bytes, "abc"), Site::Run);
    let mut expected = [0u8; PAYLOAD];
    expected[..7].copy_from_slice(&[2, 1, 1, 0, 1, 3, 0]);
    expected[7..39].copy_from_slice(&[
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ]);
    assert_eq!((event.kind, event.payload), (IDENTITY, expected));
    let settled = identity_event(&Failure::Violation(Obligation::Bytes, "abc"), Site::Settled);
    assert_eq!(settled.payload[4], 2);
    assert_ne!(
        settled.payload, event.payload,
        "the site is part of the identity"
    );
}

/// Each obligation's identity byte is fixed, and an audit identity of a
/// production device or link record lays out variant 4, no obligation, the
/// class plus one, the settled site, the 15-byte code's length and the
/// code's SHA-256, so an enum reorder changes these bytes only under a new
/// identity version. A link record's violation record has fixed bytes too.
#[test]
fn obligation_and_audit_identities_have_fixed_bytes() {
    let obligations = [
        (Obligation::Bytes, 1),
        (Obligation::History, 2),
        (Obligation::Custody, 3),
        (Obligation::Resources, 4),
        (Obligation::Restart, 5),
        (Obligation::Progress, 6),
        (Obligation::Isolation, 7),
        (Obligation::Contain, 8),
    ];
    for (obligation, byte) in obligations {
        let event = identity_event(&Failure::Violation(obligation, "abc"), Site::Run);
        assert_eq!(event.payload[2], byte, "{obligation:?}");
    }
    let audit = Violated::Audit(Record {
        class: Class::Production,
        reason: Reason::Unattributed,
        source: Source::Device(1),
    })
    .identity(Site::Run);
    let mut expected = [0u8; PAYLOAD];
    expected[..7].copy_from_slice(&[2, 4, 0, 5, 2, 15, 0]);
    expected[7..39].copy_from_slice(&[
        0xce, 0xff, 0x64, 0x70, 0xfa, 0xea, 0x74, 0x21, 0x03, 0x22, 0x73, 0x84, 0xfb, 0x40, 0x8a,
        0x8f, 0xf9, 0x26, 0x9d, 0x41, 0xef, 0x2b, 0xd7, 0x6d, 0x27, 0xca, 0xc4, 0xc8, 0x52, 0x18,
        0x9f, 0x3b,
    ]);
    assert_eq!((audit.kind, audit.payload), (IDENTITY, expected));
    // A link source packs place 1, the actor's low byte, and the far end
    // folded with the low nibble of the actor's high byte (actor bits 8 to
    // 11) into the violation record, and its identity hashes the actor and
    // far end at full width.
    let link = Violated::Audit(Record {
        class: Class::Production,
        reason: Reason::Unattributed,
        source: Source::Link {
            actor: 258,
            toward: 1,
        },
    });
    let mut record = [0u8; PAYLOAD];
    record[..8].copy_from_slice(&[4, 4, 24, 0, 0, 1, 2, 17]);
    assert_eq!(link.code(), record);
    let mut expected = [0u8; PAYLOAD];
    expected[..7].copy_from_slice(&[2, 4, 0, 5, 2, 15, 0]);
    expected[7..39].copy_from_slice(&[
        0xad, 0xfa, 0x61, 0xe6, 0x57, 0x7b, 0x57, 0xa4, 0x8f, 0x0b, 0xa5, 0x5b, 0x76, 0x6e, 0xeb,
        0xe2, 0x9e, 0x0e, 0xd8, 0xc4, 0xac, 0x03, 0x9f, 0x7d, 0x05, 0x6a, 0x14, 0xcd, 0x2e, 0x30,
        0x92, 0x52,
    ]);
    assert_eq!(link.identity(Site::Settled).payload, expected);
}

/// Audit records whose actors differ only in bits the violation record's
/// packed code drops share that code but keep distinct identities.
#[test]
fn audit_actors_the_violation_record_folds_keep_distinct_identities() {
    let at = |actor| {
        Violated::Audit(Record {
            class: Class::Production,
            reason: Reason::Unattributed,
            source: Source::Device(actor),
        })
    };
    let (low, high) = (at(1), at(4097));
    assert_eq!(low.code(), high.code());
    assert_ne!(low.identity(Site::Settled), high.identity(Site::Settled));
}

#[test]
fn an_audit_failure_names_its_class_and_no_obligation() {
    let violated = Failure::Violation(Obligation::History, "claimed on acknowledgment");
    let (_, code) = judge(End::Done, Some(&violated), Verdict::Pass, (false, 0), 4);
    assert_eq!(
        breach(&code.unwrap().code()),
        Some(Breach::Obligation(Obligation::History))
    );
    for class in [Class::Harness, Class::Production] {
        let record = Record {
            class,
            reason: Reason::Unattributed,
            source: Source::Device(1),
        };
        let (_, code) = judge(End::Done, None, Verdict::Fail(record), (false, 0), 4);
        assert_eq!(breach(&code.unwrap().code()), Some(Breach::Audit(class)));
    }
}

/// Each resource row the run holds at a fixed size refuses one below that
/// size and admits that size; a profile name no run goes by is refused.
#[test]
fn a_manifest_below_its_run_is_refused() {
    let held = [
        ("actors", 7),
        ("disk_depth", 8),
        ("rules", 32),
        ("taps", 8),
        ("captures", 4096),
        ("audit_records", 65536),
        ("registry", 4096),
        ("upload_attempts", 1),
        ("source_bytes", 3 * u64::from(FRAGMENT_LEN) - 100),
        ("slots", 1),
    ];
    for (key, size) in held {
        let at = manifest("upload", 1).with(key, size);
        assert!(admit(&at).is_ok(), "{key} at {size}");
        let below = manifest("upload", 1).with(key, size - 1);
        assert_eq!(
            admit(&below).err(),
            Some(Refusal::Bound(key)),
            "{key} below {size}"
        );
    }
    let scripted = manifest("corrupted", 1).with("scripted", 0);
    assert_eq!(admit(&scripted).err(), Some(Refusal::Bound("scripted")));
    assert!(admit(&manifest("corrupted", 1).with("scripted", 1)).is_ok());
    assert!(admit(&manifest("recovery-16k", 1).with("actors", 2)).is_ok());
    assert_eq!(
        admit(&manifest("recovery-16k", 1).with("actors", 1)).err(),
        Some(Refusal::Bound("actors"))
    );
    let refused = |manifest: &Manifest| admit(manifest).err();
    assert_eq!(refused(&manifest("upload", 1)), None);
    assert_eq!(
        refused(&manifest("uncertain", 1)),
        Some(Refusal::Bound("upload_attempts"))
    );
    assert_eq!(refused(&manifest("uncertain", 2)), None);
    let rules = manifest("upload", 1).with("rules", 31);
    assert_eq!(refused(&rules), Some(Refusal::Bound("rules")));
    let sources = manifest("upload", 1).with("source_bytes", 1);
    assert_eq!(refused(&sources), Some(Refusal::Bound("source_bytes")));
    assert_eq!(refused(&manifest("nonesuch", 1)), Some(Refusal::Profile));
}

/// A manifest whose record maximum leaves no room for its own canonical
/// text after the `Begin` record is refused as a records bound; the least
/// maximum admitted records the whole manifest.
#[test]
fn a_manifest_without_room_for_its_preamble_is_refused() {
    let tight = |records: u64| {
        manifest("upload", 1)
            .with("ring", 1)
            .with("records", records)
            .with("bytes", records * 48)
            .with("every", 256)
    };
    assert_eq!(admit(&tight(7)).err(), Some(Refusal::Bound("records")));
    let least = (7..)
        .find(|&records| admit(&tight(records)).is_ok())
        .unwrap();
    let (_, _, loaded) = ran(&tight(least));
    let recorded = loaded
        .fields
        .iter()
        .find(|(field, _)| *field == crate::sim::trace::Field::Manifest)
        .map(|(_, bytes)| bytes.as_slice());
    assert_eq!(recorded, Some(tight(least).canonical().as_bytes()));
}

/// A recovery run's terminal, arm by arm: a defect is infrastructure ahead
/// of everything; a failed check is a Restart violation naming its rule,
/// ahead of a lifecycle refusal or an unreadable conservation snapshot,
/// either of which is unsuccessful, and its record
/// stays under a defect; a limit, a check without a verdict or a skipped
/// cut is inconclusive; otherwise the run passes; Restart fires only once a
/// check judged it.
#[test]
fn a_recovery_run_is_judged_by_its_end_refusals_checks_and_skips() {
    use super::super::recovery::Ran;
    use crate::sim::choice::{ChoiceError, Chooser};
    use crate::sim::turn::{Defect, Report};
    let ran = |end, broken, failed, inconclusive, restarted, skipped| Ran {
        write_gap: None,
        compared_writes: Vec::new(),
        report: Report {
            record: Vec::new(),
            turns: Vec::new(),
            turn_count: 0,
            end,
            progress: 0,
            wall: std::time::Duration::ZERO,
            virtual_us: 0,
            skipped_us: 0,
        },
        draws: std::rc::Rc::new(std::cell::RefCell::new(Chooser::record(0, &[]))),
        failed,
        inconclusive,
        restarted,
        skipped,
        broken,
        alive: true,
        leaked: false,
        conserved: 0,
    };
    let restart = bit(Obligation::Restart);
    let complete = |outcome, fired| Terminal::Complete {
        outcome,
        fired,
        required: restart,
    };
    let defect = End::Defect(Defect::Choice(ChoiceError::Short));
    let rule = "a recovered candidate was found without admission";
    let unanswered = "the recovery check reached no verdict";
    let violated = Some(Violated::Observed(Failure::Violation(
        Obligation::Restart,
        rule,
    )));
    let cases = [
        (
            ran(defect, Some("x"), Some(rule), None, true, true),
            Terminal::Infrastructure(super::Infrastructure::Defect),
            violated.clone(),
        ),
        (
            ran(defect, Some("x"), None, None, true, true),
            Terminal::Infrastructure(super::Infrastructure::Defect),
            None,
        ),
        (
            ran(End::Done, Some("x"), Some(rule), None, true, false),
            complete(Outcome::Violation, restart),
            violated.clone(),
        ),
        (
            ran(End::Done, Some("x"), None, Some(unanswered), true, false),
            complete(Outcome::Unsuccessful, restart),
            None,
        ),
        (
            ran(End::Done, None, Some(rule), Some(unanswered), false, false),
            complete(Outcome::Violation, 0),
            violated.clone(),
        ),
        (
            ran(
                End::Inconclusive(Limit::Total),
                None,
                None,
                None,
                true,
                false,
            ),
            complete(Outcome::Inconclusive, restart),
            None,
        ),
        (
            ran(End::Done, None, None, Some(unanswered), false, false),
            complete(Outcome::Inconclusive, 0),
            None,
        ),
        (
            ran(End::Done, None, None, None, true, true),
            complete(Outcome::Inconclusive, restart),
            None,
        ),
        (
            ran(End::Done, None, None, None, true, false),
            complete(Outcome::Pass, restart),
            None,
        ),
    ];
    for (ran, terminal, violation) in cases {
        assert_eq!(super::judge_recovery(&ran), (terminal, violation));
    }
}

/// A run's failure surfaces at settlement until the stream carries a
/// `FAILURE` event: an unsuccessful check streams as `OBSERVED` and leaves
/// the site settled, and a violation streamed during the run moves it to
/// the run.
#[test]
fn the_identity_site_follows_the_streamed_failure_event() {
    let manifest = manifest("upload", 1);
    let mut streamed = super::Streamed::new(
        crate::sim::trace::Recorder::new(Vec::new(), manifest.capacity()),
        (),
    );
    streamed.events(&[super::failure_event(&Failure::Unsuccessful("x"))]);
    assert_eq!(streamed.site, Site::Settled);
    streamed.events(&[super::failure_event(&Failure::Violation(
        Obligation::Bytes,
        "abc",
    ))]);
    assert_eq!(streamed.site, Site::Run);
}

/// A violation judged at settlement with no `FAILURE` event streamed
/// records its violation record and then an identity whose site byte is
/// [`Site::Settled`], the stream's initial site.
#[test]
fn a_settled_violation_records_a_settled_identity() {
    use crate::sim::trace::{Outcome, Terminal, Work};
    let manifest = manifest("upload", 1);
    let mut streamed = super::Streamed::new(
        crate::sim::trace::Recorder::new(Vec::new(), manifest.capacity()),
        (),
    );
    let violated = Violated::Observed(Failure::Violation(Obligation::Restart, "abc"));
    super::record_violation(&mut streamed.recorder, &violated, streamed.site);
    let terminal = Terminal::Complete {
        outcome: Outcome::Violation,
        fired: 0,
        required: 0,
    };
    let sink = streamed.recorder.finish(terminal, Work::default()).sink;
    let loaded = load(&sink, manifest.capacity().records()).unwrap();
    assert_eq!(loaded.violation, Some(violated.code()));
    let identity = of(&loaded, IDENTITY);
    assert_eq!(identity.len(), 1, "{identity:?}");
    assert_eq!(identity[0].payload[4], Site::Settled as u8);
    assert_eq!(identity[0], violated.identity(Site::Settled));
}

/// The kind check accepts distinct kinds and refuses a repeated one,
/// adjacent or apart, at the last position included.
#[test]
fn the_kind_check_refuses_a_repeated_kind() {
    assert!(super::distinct(&[]));
    assert!(super::distinct(&[1, 2, 3]));
    assert!(!super::distinct(&[1, 2, 2]));
    assert!(!super::distinct(&[1, 2, 1]));
    assert!(super::distinct(super::KINDS));
}

/// A planted run's bundle recorded before the vocabulary's later kinds:
/// its manifest pins a placeholder executable, and the test decodes it
/// through the trace decoder at the event level.
const OLD_PLANTED: &[u8] = include_bytes!("../../../sim/fixtures/planted-v1.bundle");

/// The kinds the old planted bundle's profile record declares, by name.
const OLD_DECLARED: [&str; 7] = [
    "Get",
    "Read",
    "PutInvoke",
    "PutPrepare",
    "Supply",
    "DeferSupply",
    "PutOutcome",
];

/// How many upload events of each kind the old planted bundle carries.
const OLD_PUTS: [(&str, usize); 5] = [
    ("DeferSupply", 1),
    ("PutInvoke", 1),
    ("PutOutcome", 11),
    ("PutPrepare", 16),
    ("Supply", 3),
];

/// How many workload action turns of each kind the old planted bundle
/// took, each turn candidate carrying its kind's code above the workload
/// action base.
const OLD_TURNS: [(&str, usize); 2] = [("Get", 2), ("Read", 3)];

/// The old planted bundle decodes under this build's vocabulary: its
/// recorded manifest is refused by its version 1 before any replay, and it
/// loads to a complete violation of Bytes with no failure identity, so its
/// summary prints no identity line; its profile record's kind codes name
/// the kinds it declared when recorded, and the kind codes its upload
/// events and workload action turns carry name, kind by kind, the counts it
/// recorded. A kind inserted at or before `PutOutcome`, the highest code it
/// carries, shifts a recorded code and fails the names, as does a reorder
/// that moves a code it carries; `ActionKind`'s golden table pins every
/// position, reorders among codes this bundle never carries included.
pub(crate) fn an_old_bundle_decodes_its_action_codes() -> Result<(), String> {
    let refused = super::super::replay::recorded(OLD_PLANTED).err();
    let version = super::super::replay::Refused::Input(format!(
        "{:?}",
        crate::sim::manifest::ManifestError::Version {
            found: Some("1".into())
        }
    ));
    if refused.as_ref() != Some(&version) {
        return Err(format!("the old bundle's manifest is read as {refused:?}"));
    }
    let loaded = load(OLD_PLANTED, u64::MAX).map_err(|error| format!("{error:?}"))?;
    let violated = matches!(
        loaded.terminal,
        Terminal::Complete {
            outcome: Outcome::Violation,
            ..
        }
    ) && loaded.violation.as_ref().and_then(super::breach)
        == Some(super::Breach::Obligation(Obligation::Bytes));
    if !violated {
        return Err(format!("the old bundle ends {:?}", loaded.terminal));
    }
    if let Some(identity) = super::super::replay::violated(&loaded) {
        return Err(format!("the old bundle names an identity {identity:?}"));
    }
    let config = loaded
        .fields
        .iter()
        .find(|(field, _)| *field == crate::sim::trace::Field::Config)
        .map(|(_, bytes)| bytes.as_slice())
        .ok_or("the old bundle records no Config")?;
    let codes = crate::sim::action::Profile::declared_codes(config).ok_or("no profile record")?;
    let named = |code: u8| ActionKind::from_code(code).map(|kind| format!("{kind:?}"));
    let declared: Vec<String> = codes.iter().filter_map(|&code| named(code)).collect();
    if declared != OLD_DECLARED || declared.len() != codes.len() {
        return Err(format!(
            "the old profile's codes {codes:?} name {declared:?}"
        ));
    }
    let tally = |kinds: Vec<Option<String>>| {
        let mut counts = std::collections::BTreeMap::new();
        for kind in kinds {
            *counts
                .entry(kind.unwrap_or_else(|| "an unknown code".into()))
                .or_insert(0) += 1;
        }
        counts.into_iter().collect::<Vec<(String, usize)>>()
    };
    let puts = tally(
        of(&loaded, PUT)
            .iter()
            .filter_map(super::PutRecord::of)
            .map(|put| put.kind.map(|kind| format!("{kind:?}")))
            .collect(),
    );
    let turns = tally(
        loaded
            .turns
            .iter()
            .filter(|turn| turn[0] == crate::sim::choice::Domain::Workload as u8)
            .filter_map(|turn| {
                turn[1]
                    .checked_sub(super::super::ACTION)
                    .filter(|&code| code > 0)
            })
            .map(named)
            .collect(),
    );
    let pinned = |table: &[(&str, usize)]| -> Vec<(String, usize)> {
        table
            .iter()
            .map(|&(name, count)| (name.to_owned(), count))
            .collect()
    };
    if puts != pinned(&OLD_PUTS) || turns != pinned(&OLD_TURNS) {
        return Err(format!(
            "the old bundle's carried codes name {puts:?} and {turns:?}"
        ));
    }
    let carried = OLD_PUTS
        .iter()
        .chain(&OLD_TURNS)
        .map(|&(_, count)| count)
        .sum::<usize>();
    println!(
        "vocabulary: the old planted bundle decodes {} declared and {carried} carried action codes to their kinds, a complete violation of Bytes",
        codes.len(),
    );
    Ok(())
}

#[test]
fn an_old_planted_bundle_decodes_its_action_codes() {
    an_old_bundle_decodes_its_action_codes().unwrap();
}

/// Every end the controller reports encodes to its [`STOP`](super::STOP)
/// code, the stop event decodes to the name [`STOPS`](super::STOPS) gives
/// that code, and the composition round-trips exactly when one is given,
/// one with zero owners included. The composition's fields lie at their
/// documented little-endian offsets, and a code outside `STOPS` decodes as
/// `unknown`, apart from a bundle without a stop event.
#[test]
fn every_stop_round_trips_through_its_event() {
    use crate::sim::choice::ChoiceError;
    use crate::sim::entropy::DrawRefusal;
    use crate::sim::turn::Defect;
    let refusal = DrawRefusal {
        site: super::super::SITE,
        incarnation: 0,
        error: ChoiceError::Short,
    };
    let ends = [
        (End::Done, (1, 0), "goal"),
        (End::Inconclusive(Limit::Total), (2, 1), "limit turns"),
        (
            End::Inconclusive(Limit::SameTime),
            (2, 2),
            "limit same_time",
        ),
        (
            End::Inconclusive(Limit::NoProgress),
            (2, 3),
            "limit no_progress",
        ),
        (End::Inconclusive(Limit::Quiescent), (2, 4), "quiescent"),
        (
            End::Defect(Defect::Choice(ChoiceError::Short)),
            (3, 1),
            "defect choice",
        ),
        (
            End::Defect(Defect::Entropy(refusal)),
            (3, 2),
            "defect entropy",
        ),
        (
            End::Defect(Defect::Due { now: 1, due: 1 }),
            (3, 3),
            "defect due",
        ),
        (End::Halted, (4, 0), "halted"),
    ];
    assert_eq!(ends.len(), super::STOPS.len());
    let distinct = super::Composed {
        checked: 0x0102_0304_0506_0708,
        owners: 0x090a,
        clients: 0x0b0c,
    };
    let empty = super::Composed {
        checked: 5,
        owners: 0,
        clients: 0,
    };
    for (end, code, text) in ends {
        for composed in [None, Some(distinct), Some(empty)] {
            let event = super::stop_event(end, composed);
            assert_eq!(
                (event.payload[0], event.payload[1], event.payload[2]),
                (code.0, code.1, u8::from(composed.is_some())),
                "{text}"
            );
            let seen = super::observed(&[event]);
            assert_eq!(seen.stop, Some(code));
            assert_eq!(seen.stop_text(), text);
            assert_eq!(seen.composed, composed, "{text}");
        }
    }
    let event = super::stop_event(End::Done, Some(distinct));
    assert_eq!(
        event.payload[3..15],
        [8, 7, 6, 5, 4, 3, 2, 1, 0x0a, 0x09, 0x0c, 0x0b]
    );
    let unknown = super::observed(&[super::event(super::STOP, &[&[2, 5, 0]])]);
    assert_eq!(unknown.stop, Some((2, 5)));
    assert_eq!(unknown.stop_text(), "unknown");
    assert_eq!(unknown.composed, None);
    assert_eq!(super::observed(&[]).stop_text(), "unavailable");
}

/// An upload run records its stop at the goal and its composition: the
/// stopped boundaries, operations and witnesses the bundle reports equal
/// the boundaries, actions and witnessed actions of the same run outside
/// the recorder, and it delivers no fault over clean links; a faulted run
/// delivers exactly the injected link records its links' audits hold. A
/// faulted run stopped by its turn bound before any fault records its
/// composition and reports zero delivered faults. Only an injected link
/// audit record counts as a delivered fault.
#[test]
fn a_bundle_reports_its_stop_composition_and_delivered_faults() {
    let loaded_of = |manifest: &Manifest| ran(manifest).2;
    let plain = manifest("upload", 2);
    let mut upload = loaded_of(&plain);
    let again = rerun(&plain);
    let seen = super::observed(&upload.events);
    assert_eq!(seen.stop_text(), "goal");
    let composed = seen.composed.unwrap();
    assert_eq!((composed.owners, composed.clients), super::TOPOLOGY);
    assert!(again.boundaries > 0);
    assert_eq!(composed.checked, again.boundaries as u64);
    assert_eq!(seen.operations, again.acts.len() as u64);
    let witnessed = again
        .acts
        .iter()
        .filter(|act| super::super::witnessed(act.kind, act.outcome))
        .count();
    assert_eq!(seen.witnesses, witnessed as u64);
    assert!(seen.operations > seen.witnesses && seen.witnesses > 0);
    assert_eq!(seen.faults, 0);
    let audit = |class: Class| {
        let mut payload = [0; PAYLOAD];
        payload[1] = class as u8;
        Event {
            kind: AUDIT,
            payload,
        }
    };
    upload.events.push(audit(Class::Injected));
    upload.events.push(audit(Class::Modeled));
    assert_eq!(super::observed(&upload.events).faults, 1);
    let faulted = loaded_of(&manifest("faulted", 2));
    let injected = rerun(&manifest("faulted", 2))
        .audits
        .iter()
        .flatten()
        .filter(|record| record.class == Class::Injected)
        .count() as u64;
    assert!(injected > 0, "the faulted links deliver faults");
    assert_eq!(super::observed(&faulted.events).faults, injected);
    let bounded = loaded_of(&manifest("faulted", 2).with("turns", 3));
    let seen = super::observed(&bounded.events);
    assert_eq!(seen.stop_text(), "limit turns");
    assert!(
        seen.composed.is_some(),
        "a turn-bounded mixed run records its composition"
    );
    assert_eq!(seen.faults, 0);
    assert!(matches!(
        bounded.terminal,
        Terminal::Complete {
            outcome: Outcome::Inconclusive,
            ..
        }
    ));
}

/// The tuple contains, in order: the million-record run, the first
/// uncapped run found by the search, and the run with one fewer record of
/// capacity. A bundle holds at most its maximum, so the search starts at
/// the records the million-record bundle holds.
///
/// # Errors
///
/// Returns an error when manifest admission or bundle loading fails, the
/// loaded terminal, digest, or work differs from the run, or the first
/// uncapped run ends in an infrastructure class.
pub(crate) fn least_maximum(
    sized: impl Fn(u64) -> Manifest,
) -> Result<(Loaded, Loaded, Loaded), String> {
    const ROOMY: u64 = 1_000_000;
    let at = |records: u64| -> Result<(usize, Loaded), String> {
        let manifest = sized(records);
        let admitted = admit(&manifest).map_err(|refusal| format!("{refusal:?}"))?;
        let closed = traced(admitted, Vec::new());
        let loaded = load(&closed.sink, manifest.capacity().records())
            .map_err(|error| format!("{records}: {error:?}"))?;
        if (loaded.digest, loaded.terminal, loaded.work)
            != (closed.digest, closed.terminal, closed.work)
        {
            return Err(format!(
                "the bundle at {records} records loads apart from its run"
            ));
        }
        Ok((closed.sink.len() / crate::sim::trace::RECORD, loaded))
    };
    let (written, roomy) = at(ROOMY)?;
    let (mut least, mut tight) = (written as u64, None);
    let fits = loop {
        let (_, bounded) = at(least)?;
        if least >= ROOMY || bounded.terminal != Terminal::Infrastructure(Infrastructure::Cap) {
            break bounded;
        }
        tight = Some(bounded);
        least += 1;
    };
    if matches!(fits.terminal, Terminal::Infrastructure(_)) {
        return Err(format!(
            "the bundle at {least} records ended {:?}",
            fits.terminal
        ));
    }
    let tight = match tight {
        Some(tight) => tight,
        None => at(least - 1)?.1,
    };
    Ok((roomy, fits, tight))
}

/// The stop event is one of the records a run's record maximum holds. At
/// the least maximum where a violating or a passing run records its stop,
/// it completes with its own outcome; one record less keeps the violation
/// record but drops the stop, so the bundle ends as an infrastructure cap
/// whose observations are unavailable.
#[test]
fn the_stop_event_takes_a_record_of_the_maximum() {
    for (profile, outcome) in [("planted", Outcome::Violation), ("upload", Outcome::Pass)] {
        let sized = |records: u64| {
            manifest(profile, 2)
                .with("ring", 1)
                .with("records", records)
        };
        let (roomy, fits, tight) = least_maximum(sized).unwrap();
        assert!(
            matches!(roomy.terminal, Terminal::Complete { outcome: ended, .. } if ended == outcome),
            "{profile}: {:?}",
            roomy.terminal
        );
        assert_eq!(fits.terminal, roomy.terminal, "{profile}");
        assert!(super::observed(&fits.events).stop.is_some(), "{profile}");
        assert_eq!(
            tight.terminal,
            Terminal::Infrastructure(Infrastructure::Cap),
            "{profile}"
        );
        assert_eq!(tight.violation, roomy.violation, "{profile}");
        let seen = super::observed(&tight.events);
        assert_eq!((seen.stop, seen.composed), (None, None), "{profile}");
    }
}

/// The bytes a turn record holds after its outcome: its observation.
fn observation(record: &[u8]) -> [u8; crate::sim::trace::TURN_OBSERVATION] {
    record[36..48].try_into().expect("an observation")
}

/// Every collection result and status encodes to its declared variant,
/// status, client and owner bytes, every status the wire defines among
/// them, and none collects more than one result: a second collection in
/// one turn is multiple, and adding nothing leaves a collection as it is.
#[test]
fn collections_encode_as_declared_and_a_second_is_multiple() {
    use super::super::super::fetch::Outcome as Get;
    use super::super::super::frame::Status;
    use super::super::super::upload::UploadOutcome as Put;
    use super::Collected;
    assert_eq!(Collected::Absent.code(), [0; 12]);
    assert_eq!(
        Collected::Multiple.code(),
        [10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );
    let at = |variant: u8, status: u16| {
        let [low, high] = status.to_le_bytes();
        [variant, low, high, 0x34, 0x12, 0x78, 0x56, 0, 0, 0, 0, 0]
    };
    for wire in 1..=28 {
        let status = Status::from_wire(wire).unwrap();
        for (collected, variant) in [
            (Collected::Get(0x1234, 0x5678, Get::Pressure(status)), 3),
            (Collected::Get(0x1234, 0x5678, Get::Failed(status)), 4),
            (Collected::Get(0x1234, 0x5678, Get::Incomplete(status)), 5),
            (Collected::Put(0x1234, 0x5678, Put::Failed(status)), 7),
        ] {
            assert_eq!(collected.code(), at(variant, wire), "{collected:?}");
        }
    }
    for (collected, variant) in [
        (Collected::Get(0x1234, 0x5678, Get::Complete), 1),
        (Collected::Get(0x1234, 0x5678, Get::Missing), 2),
        (Collected::Put(0x1234, 0x5678, Put::Published), 6),
        (Collected::Put(0x1234, 0x5678, Put::NotStarted), 8),
        (Collected::Put(0x1234, 0x5678, Put::Unknown), 9),
    ] {
        assert_eq!(collected.code(), at(variant, 0), "{collected:?}");
        let mut turn = Collected::Absent;
        turn.add(collected);
        assert_eq!(turn, collected);
        for (next, then) in [
            (collected, Collected::Multiple),
            (Collected::Multiple, Collected::Multiple),
            (Collected::Absent, collected),
        ] {
            let mut twice = turn;
            twice.add(next);
            assert_eq!(twice, then);
        }
    }
    assert!(Status::from_wire(29).is_none() && Status::from_wire(0).is_none());
    let mut multiple = Collected::Multiple;
    multiple.add(Collected::Absent);
    assert_eq!(multiple, Collected::Multiple);
    assert_eq!(Collected::Get(0, 0, Get::Complete).code()[..1], [1]);
}

/// The acked plant takes an acknowledged upload as published while its
/// client has no result, so the world's planted outcome is not a client
/// result: that PutOutcome turn records no request observation, and the
/// run still fails as the plant's rule names.
#[test]
fn a_planted_publication_records_no_request_result() {
    let text = crate::sim::manifest_tests::sample("acked", &"a".repeat(64), "x86_64-linux");
    let bytes = traced(admit(&Manifest::parse(&text).unwrap()).unwrap(), Vec::new()).sink;
    let published = upload_code(super::super::super::upload::UploadOutcome::Published);
    let planted: Vec<_> = bytes
        .as_chunks::<48>()
        .0
        .iter()
        .filter(|record| {
            let candidate = crate::sim::choice::Candidate(record[12..28].try_into().unwrap());
            record[0] == crate::sim::trace::Tag::Turn as u8
                && record[12] == crate::sim::choice::Domain::Put as u8
                && super::super::put_kind(&candidate).0 == ActionKind::PutOutcome
                && record[28..36] == published.to_le_bytes()
        })
        .collect();
    assert!(!planted.is_empty(), "the plant published an upload");
    assert!(
        planted.iter().all(|record| record[36..] == [0; 12]),
        "{planted:?}"
    );
    let loaded = load(&bytes, u64::MAX).unwrap();
    let rule = b"an upload collected as published without its result";
    assert_eq!(
        loaded.violation.map(|code| code[3..3 + 41] == rule[..41]),
        Some(true)
    );
}

/// Each turn of a mixed upload run records what its action collected: a
/// decided GET's outcome at its client, the one upload's outcome its
/// client collected at client 0, and nothing at a turn that collected
/// nothing, so no turn
/// carries a result an earlier turn collected and a pending result
/// records nothing.
#[test]
fn mixed_turns_record_the_results_their_actions_collected() {
    use super::Collected;
    let (mut gets, mut puts) = (0, 0);
    for root in 1..=6 {
        let ran = super::super::mixed(
            &super::super::upload_profile(root),
            super::super::UPLOAD_PLAN,
            super::super::exactly_read,
        );
        for (at, turn) in ran.report.turns.iter().enumerate() {
            let decided: Vec<_> = ran.decided.iter().filter(|got| got.decided == at).collect();
            let collected = ran.acts.iter().filter(|act| {
                act.turn == at
                    && act.kind == ActionKind::PutOutcome
                    && act.outcome != super::super::REFUSED
            });
            let collected: Vec<_> = collected.collect();
            let expected = match (decided.as_slice(), collected.as_slice()) {
                ([], []) => Collected::Absent.code(),
                ([got], []) => {
                    gets += 1;
                    Collected::Get(got.client as u16, 0, got.outcome).code()
                }
                ([], [_]) => {
                    puts += 1;
                    let upload = ran.put.and_then(|(outcome, _)| outcome);
                    Collected::Put(0, 0, upload.expect("the collected upload")).code()
                }
                _ => Collected::Multiple.code(),
            };
            assert_eq!(
                turn.observation, expected,
                "root {root} turn {at}: {turn:?}"
            );
        }
    }
    assert!(
        gets > 0 && puts == 6,
        "{gets} GETs and {puts} uploads collected"
    );
}

#[test]
fn history_steps_record_the_results_they_collect() {
    use super::super::super::fetch::Outcome as Get;
    use super::super::super::frame::Status;
    use super::super::super::upload::UploadOutcome as Put;
    use super::Collected;
    let cases = [
        ("h1-get", "fresh-miss", Collected::Get(0, 0, Get::Missing)),
        (
            "h1-get",
            "qualified-read",
            Collected::Get(0, 0, Get::Complete),
        ),
        ("h1-put", "put-result", Collected::Put(0, 0, Put::Published)),
        (
            "i4-get-share",
            "over-share-ended",
            Collected::Get(1, 0, Get::Pressure(Status::RequestPressure)),
        ),
        ("i4-get-share", "healed", Collected::Multiple),
        (
            "i4-space",
            "put-refused",
            Collected::Put(0, 0, Put::Failed(Status::StoragePressure)),
        ),
        ("i2-put", "old-outcome", Collected::Put(2, 0, Put::Unknown)),
        (
            "i4-get-share",
            "healed-read",
            Collected::Get(1, 0, Get::Complete),
        ),
        (
            "i4-get-read-pool",
            "pool-refused",
            Collected::Get(1, 0, Get::Pressure(Status::RetransmissionPressure)),
        ),
        (
            "i4-put-request",
            "second-refused",
            Collected::Put(0, 0, Put::Failed(Status::RequestPressure)),
        ),
        (
            "i4-put-request",
            "first-result",
            Collected::Put(0, 0, Put::Published),
        ),
        (
            "i4-put-deferred",
            "healed-result",
            Collected::Put(0, 0, Put::Published),
        ),
        (
            "i4-put-source",
            "qualified-read",
            Collected::Get(0, 0, Get::Complete),
        ),
        (
            "i7-begin-refused-readmitted",
            "second-refused",
            Collected::Put(0, 0, Put::Failed(Status::RequestPressure)),
        ),
        (
            "i7-cancel-overtakes-begin",
            "settled",
            Collected::Put(0, 0, Put::Unknown),
        ),
        (
            "i7-get-refused-readmitted",
            "third-refused",
            Collected::Get(1, 0, Get::Pressure(Status::RequestPressure)),
        ),
        ("h6-get", "beside-read", Collected::Get(1, 1, Get::Complete)),
        (
            "lw1-waiter-submit-accepted",
            "borrower-published",
            Collected::Put(1, 0, Put::Published),
        ),
        (
            "lw1-waiter-submit-accepted",
            "waiter-published",
            Collected::Put(0, 0, Put::Published),
        ),
    ];
    let mut recorded = std::collections::HashMap::new();
    for (name, step, expected) in cases {
        let history = super::super::histories::every()
            .find(|history| history.name == name)
            .unwrap();
        let index = history
            .script
            .iter()
            .position(|known| known.name == step)
            .unwrap();
        let closed = recorded
            .entry(name)
            .or_insert_with(|| traced(admit(&manifest(name, 8)).unwrap(), Vec::new()));
        assert!(
            matches!(
                closed.terminal,
                Terminal::Complete {
                    outcome: Outcome::Pass,
                    ..
                }
            ),
            "{name}: {:?}",
            closed.terminal
        );
        let script = [
            crate::sim::choice::Domain::Workload as u8,
            super::super::SCRIPT,
        ];
        let ran_step: Vec<_> = closed
            .sink
            .as_chunks::<48>()
            .0
            .iter()
            .filter(|record| {
                let step = u32::from_be_bytes(record[15..19].try_into().unwrap());
                let outcome = u64::from_le_bytes(record[28..36].try_into().unwrap());
                record[0] == crate::sim::trace::Tag::Turn as u8
                    && record[12..14] == script
                    && step as usize == index
                    && outcome != super::super::histories::STAY
            })
            .collect();
        assert_eq!(ran_step.len(), 1, "{name} {step}");
        assert_eq!(observation(ran_step[0]), expected.code(), "{name} {step}");
    }
}

/// The sample bundles the worker's fresh-process replay, branch and pin
/// cases record, the planted, faulted and upload runs, hold turns that
/// collected a GET or PUT result, so those cases reproduce, fork and
/// refuse bundles that carry observations.
#[test]
fn the_worker_replay_and_branch_bundles_record_observations() {
    for profile in ["planted", "faulted", "upload"] {
        let text = crate::sim::manifest_tests::sample(profile, &"a".repeat(64), "x86_64-linux");
        let closed = traced(admit(&Manifest::parse(&text).unwrap()).unwrap(), Vec::new());
        let turns = closed.sink.as_chunks::<48>().0.iter();
        let mut turns = turns.filter(|record| record[0] == crate::sim::trace::Tag::Turn as u8);
        assert!(turns.any(|record| observation(record)[0] != 0), "{profile}");
    }
}

/// The control mark reversed. The compiler checks that it reverses to
/// [`super::CONTROL_MARK`], and a guard holds the scan's copy equal to it.
const REVERSED_CONTROL_MARK: &str = "kram eliforp lortnoc ekirtsek";

const _: () = {
    let (mark, reversed) = (
        super::CONTROL_MARK.as_bytes(),
        REVERSED_CONTROL_MARK.as_bytes(),
    );
    assert!(mark.len() == reversed.len());
    let mut at = 0;
    while at < mark.len() {
        assert!(mark[at] == reversed[mark.len() - 1 - at]);
        at += 1;
    }
};

/// Each file under `src`, binary fixtures included, spells the control
/// mark in pieces, since `sim/choice_tests.rs` embeds `bundle.rs` whole.
/// Of the files under `src`, only the linked [`super::CONTROL_MARK`] then
/// supplies the forward mark in the test executable, which runs every
/// control through the scenario lookup.
#[test]
fn the_test_executable_links_the_control_mark() {
    let needle: String = REVERSED_CONTROL_MARK.chars().rev().collect();
    // The executable embeds `REVERSED_CONTROL_MARK`, so a match establishes
    // linkage only when the scan uses the forward mark.
    assert!(
        needle.starts_with("kestrike ") && needle.ends_with(" mark"),
        "the scan searches for the forward control mark, not for {needle:?}"
    );
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    assert_eq!(
        super::super::files_holding(&src, needle.as_bytes()),
        Ok(Vec::new()),
        "these files spell the control mark whole"
    );
    let executable = std::fs::read("/proc/self/exe").unwrap();
    assert!(
        memchr::memmem::find(&executable, needle.as_bytes()).is_some(),
        "the test executable holds the control mark"
    );
}

/// [`super::named`] reaches the control mark for every name, including
/// names the lookup rejects.
#[test]
fn the_scenario_lookup_holds_the_control_mark() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/net/world_tests/bundle.rs"),
    )
    .unwrap();
    let signature = "\npub(super) fn named(name: &str, root: u64) -> Option<Scenario>";
    assert_eq!(source.matches(signature).count(), 1);
    let (_, body) = source.split_once(signature).unwrap();
    assert!(body.starts_with(" {\n    std::hint::black_box(CONTROL_MARK);\n"));
}

/// The chaos-point record cites the three tests that hold the control
/// mark's linkage: the lookup's reference, the test executable's copy and
/// the scan of the non-test binaries.
#[test]
fn the_chaos_point_record_cites_the_control_mark_s_three_tests() {
    let cited = crate::net::terminal_tests::record_tests(
        &crate::net::terminal_tests::OBLIGATIONS,
        "chaos-points-are-cataloged-seeded-and-absent-outside-test-builds",
    );
    for test in [
        "the_test_executable_links_the_control_mark",
        "the_scan_searches_for_the_control_mark",
        "the_scenario_lookup_holds_the_control_mark",
    ] {
        let id = format!("net::world_tests::bundle::tests::{test}");
        assert!(cited.contains(id.as_str()), "{id}");
    }
}

/// Counts the needle's reversal and the control assertion in the code
/// tokens of `scan`, and requires one of each. The loop over `scanned`
/// is the whole of `body`: it reads each binary whole as an ELF file and
/// applies the chaos search and then the control search to them.
fn searches_for_the_control_mark(scan: &str) -> bool {
    let code = crate::oracle::guard_tests::tokens(scan).concat();
    let reversed = "letcontrol:String=REVERSED_CONTROL_MARK.chars().rev().collect();";
    let refused = "assert!(memchr::memmem::find(&bytes,control.as_bytes()).is_none(),";
    let body = "forbinaryinscanned{letbytes=artifact(Path::new(binary)).unwrap();\
                assert!(memchr::memmem::find(&bytes,needle.as_bytes()).is_none(),\"\");\
                assert!(memchr::memmem::find(&bytes,control.as_bytes()).is_none(),\"\");}";
    code.matches(reversed).count() == 1 && code.matches(refused).count() == 1 && code.contains(body)
}

/// The test ties the scan's control needle in `tests/soak_cli.rs` to the
/// library's control mark. The guard reads code alone, so a control
/// assertion that stands in a comment fails it, and so does a scan that
/// leaves the loop ahead of the control search for one binary.
#[test]
fn the_scan_searches_for_the_control_mark() {
    let scan = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/soak_cli.rs"),
    )
    .unwrap();
    let prefix = "const REVERSED_CONTROL_MARK: &str = \"";
    assert_eq!(scan.matches(prefix).count(), 1);
    let start = scan.find(prefix).expect("the scan's control needle") + prefix.len();
    let text = &scan[start..start + scan[start..].find('"').unwrap()];
    assert_eq!(text, REVERSED_CONTROL_MARK);
    assert!(searches_for_the_control_mark(&scan));
    let commented: String = scan
        .lines()
        .map(|line| {
            if line.contains("control.as_bytes()") {
                format!("// {line}\n")
            } else {
                format!("{line}\n")
            }
        })
        .collect();
    assert!(!searches_for_the_control_mark(&commented));
    let skip =
        "            if binary.ends_with(\"bind\") {\n                continue;\n            }\n";
    for before in [
        "            let bytes = artifact(Path::new(binary)).unwrap();\n",
        "            assert!(\n                memchr::memmem::find(&bytes, control.as_bytes())",
    ] {
        let skipping = scan.replacen(before, &format!("{skip}{before}"), 1);
        assert_ne!(skipping, scan);
        assert!(!searches_for_the_control_mark(&skipping), "{before}");
    }
}
