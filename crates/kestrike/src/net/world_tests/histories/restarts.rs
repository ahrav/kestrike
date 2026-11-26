//! Relaunch histories: each closes its owner at one recovery cut, relaunches
//! it cold over the same media in one selected event, and judges the
//! relaunched owner's first answer for the cut's key under the
//! process-death cold-relaunch hypothesis.
//!
//! R1 cuts at a write boundary beside a held read: the replacement's write
//! and an old GET's read stay held through a stop the device leaves
//! pending, which retains both, and the history releases them so the
//! closed owner's queue empties before the relaunch runs. R2 cuts between
//! an upload's DATA acceptance and its publication: the owner's write of
//! the DATA is held when a proven stop drops it, and the upload stays
//! unsettled, its outcome undecided or Unknown. R3 cuts after an
//! acknowledged invalidation, which a fresh GET confirms before a proven
//! stop. R2 holds the upload DATA's transmit references from its arm step,
//! so its stop check compares the references the links withhold with
//! those withheld at the stop.
//!
//! The relaunch records the Restart row of the oracle rows its recovered
//! lookup is judged against, after checking that the next incarnation's
//! device shares the dead one's media handle. The relaunched owner's GET of
//! the cut's key is that lookup, and any answer that handed out bytes is a
//! hit judged with the registry's label for them. No admission precedes the
//! lookup under the cold-relaunch hypothesis, so the restart rule refuses
//! every hit and a passing history's relaunched owner answers Missing.
//! After the check each history fills and publishes a replacement on the
//! relaunched owner and reads it exactly. Each control requires the
//! relaunched owner's Missing answer, then takes it as a hit of a version
//! the dead incarnation held before its cut: the resident version in R1
//! and R3, the cut upload's in R2. The oracle refuses that hit as a
//! recovered candidate without admission.

use std::rc::Rc;

use crate::oracle::{KeyId, Outcome as Judged, Script, check};

use super::super::recovery::{HYPOTHESIS, recovered_answer};
use super::*;

/// Stops the owner under an `AllReturned` quiesce, which reports the stop
/// pending while the device goes on executing, so the commands the stop
/// retains complete once their holds end.
fn pending_stop(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.scene.control.set_quiesce(QuiesceMode::AllReturned);
    stop(world, now)
}

fn relaunchable(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world.relaunchable()
}

/// Relaunches the closed owner, fails Restart unless the next incarnation's
/// device shares the dead one's media handle, and opens the oracle rows of
/// its recovered lookup with the relaunch's Restart row.
fn relaunch_owner(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let media = world.scene.control.shared_media();
    world.relaunch(now);
    let mut rows = Script::new();
    rows.restart(HYPOTHESIS, KeyId(1));
    world.history.recovered = Some(rows);
    if !Rc::ptr_eq(&media, &world.scene.control.shared_media()) {
        return fail(
            world,
            Obligation::Restart,
            "a relaunch replaced the shared media",
        );
    }
    mark(world, "owner relaunched over the shared media")
}

/// Marks the cut upload unsettled while its outcome is undecided or
/// Unknown, and fails History for any settled outcome.
fn upload_unsettled(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    match world.collect_put(id) {
        None | Some(UploadOutcome::Unknown) => mark(world, "the cut upload stayed unsettled"),
        Some(UploadOutcome::Published) => fail(
            world,
            Obligation::History,
            "a cut upload settled as published",
        ),
        Some(_) => fail(
            world,
            Obligation::History,
            "a closed owner settled an upload from its receipt",
        ),
    }
}

/// Judges the relaunched owner's GET of key 1 as a recovered lookup after
/// the relaunch's Restart row: `Complete`, and `Incomplete` with bytes
/// handed out, is a hit labelled as the registry labels its bytes, or
/// `Label(0)` for bytes no registered version matches; `Missing` is a
/// miss; any other outcome records the run unsuccessful. With only the
/// Restart row recorded, the restart rule refuses every hit.
fn judge_recovered(world: &mut Mixed<'_, '_, '_>, outcome: Option<Outcome>, bytes: &[u8]) -> u64 {
    let mut rows = world
        .history
        .recovered
        .take()
        .expect("the relaunch recorded its Restart row");
    let Some(judged) = recovered_answer(outcome, bytes) else {
        world.first.record(Failure::Unsuccessful(
            "the relaunched owner answered its recovered lookup with neither a hit nor Missing",
        ));
        return 0;
    };
    let label = (judged == Judged::Hit).then(|| {
        let registry = world.registry.borrow();
        registry.label(&key(1), 0, bytes).unwrap_or(Label(0))
    });
    rows.recovered_lookup(HYPOTHESIS, KeyId(1), judged, label);
    let verdict = check(&rows.finish());
    if verdict.satisfies(&[Obligation::Restart]) {
        return mark(world, "the recovered lookup passed its restart check");
    }
    match verdict.violated() {
        Some((_, rule)) => fail(world, Obligation::Restart, rule),
        None => {
            world.first.record(Failure::Unsuccessful(
                "the recovered lookup reached no restart verdict",
            ));
            0
        }
    }
}

fn recovered_lookup(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let (outcome, bytes) = fresh_result(world);
    judge_recovered(world, outcome, &bytes)
}

/// A control: the relaunched owner's Missing answer is taken as a hit of
/// the resident version, as an owner that rebuilt its index from the dead
/// incarnation's records would serve it.
fn revived_resident(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    revived(world, &version_a())
}

/// A control: the relaunched owner's Missing answer is taken as a hit of
/// the cut upload's version, as an owner that published the upload from
/// its accepted DATA would serve it.
fn revived_upload(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    revived(world, &version_b())
}

/// Judges a hit of `version` in place of the relaunched owner's answer,
/// which must be the Missing its passing twin judges; any other answer
/// records the run unsuccessful.
fn revived(world: &mut Mixed<'_, '_, '_>, version: &[u8]) -> u64 {
    let (outcome, bytes) = fresh_result(world);
    if outcome != Some(Outcome::Missing) || !bytes.is_empty() {
        world.first.record(Failure::Unsuccessful(
            "the relaunched owner answered its recovered lookup with other than Missing",
        ));
        return 0;
    }
    judge_recovered(world, Some(Outcome::Complete), version)
}

/// The obligation each relaunch check's mark judges.
pub(super) const CHECKS: [(&str, Obligation); 2] = [
    (
        "the recovered lookup passed its restart check",
        Obligation::Restart,
    ),
    ("the cut upload stayed unsettled", Obligation::History),
];

/// The relaunched owner's recovered lookup, then a replacement it fills,
/// publishes and reads exactly.
const RELAUNCHED: [Step; 8] = [
    step("relaunch", relaunchable, relaunch_owner),
    step("recovered-get", active_put, fresh_get),
    step("recovered-lookup", fresh_decided, recovered_lookup),
    step("fill-after-relaunch", always, fill_b),
    step("publish-after-relaunch", fill_written, publish_fill),
    step("qualified-get", active_put, fresh_get),
    step("qualified-read", fresh_decided, fresh_exact_b),
    JUDGE,
];

/// R1: a held read and the replacement's held write through a stop the
/// device leaves pending, which retains both until the history releases
/// them.
const R1_GET: [Step; 16] = joined(
    [
        step("arm", always, arm_writes),
        step("old-get", active_get, old_get),
        step("old-read-held", read_held, mark_read_held),
        step("fill-replacement", always, fill_b),
        step("write-held", write_held, mark_write_held),
        step("stop", always, pending_stop),
        step("stop-retained", owner_polled, stop_retained),
        step("release-holds", always, release_device),
    ],
    RELAUNCHED,
);

const R1_GET_REVIVED: [Step; 16] = replaced(
    R1_GET,
    "recovered-lookup",
    step("recovered-revived", fresh_decided, revived_resident),
);

/// R2: an upload's DATA accepted and its write held when a proven stop
/// drops the write; the upload stays unsettled.
const R2_PUT: [Step; 17] = joined(
    [
        step("arm", always, arm_nic_writes),
        step("put-begin", active_put, put_begin),
        step("put-prepare", always, put_prepare),
        step("put-supply", always, put_supply),
        step("write-held", write_held, mark_write_held),
        step("receipt-acked", receipt_acked, mark_receipt),
        step("stop", always, reset_stop),
        step("stop-ended", owner_polled, reset_ended),
        step("upload-unsettled", always, upload_unsettled),
    ],
    RELAUNCHED,
);

const R2_PUT_REVIVED: [Step; 17] = replaced(
    R2_PUT,
    "recovered-lookup",
    step("recovered-revived", fresh_decided, revived_upload),
);

/// R3: an acknowledged invalidation, confirmed by a fresh GET's miss,
/// before a proven stop.
const R3_GET: [Step; 13] = joined(
    [
        step("invalidate", always, invalidate),
        step("fresh-get", active_put, fresh_get),
        step("fresh-miss", fresh_decided, fresh_missed),
        step("stop", always, reset_stop),
        step("stop-ended", owner_polled, reset_ended),
    ],
    RELAUNCHED,
);

const R3_GET_REVIVED: [Step; 13] = replaced(
    R3_GET,
    "recovered-lookup",
    step("recovered-revived", fresh_decided, revived_resident),
);

const RELAUNCH_WITNESSES: [&str; 4] = [
    "owner relaunched over the shared media",
    "the recovered lookup passed its restart check",
    "replacement published",
    "qualified exact read",
];

const R1_WITNESSES: &[&str] = &[
    "old read held",
    "owner write held",
    "owner stopped with a read held",
    "the stop retained its custody",
    RELAUNCH_WITNESSES[0],
    RELAUNCH_WITNESSES[1],
    RELAUNCH_WITNESSES[2],
    RELAUNCH_WITNESSES[3],
];
const R2_WITNESSES: &[&str] = &[
    "upload DATA supplied",
    "owner write held",
    "upload receipt acknowledged",
    "transmit references withheld at stop",
    "the proven stop ended its device custody",
    "the cut upload stayed unsettled",
    RELAUNCH_WITNESSES[0],
    RELAUNCH_WITNESSES[1],
    RELAUNCH_WITNESSES[2],
    RELAUNCH_WITNESSES[3],
];
const R3_WITNESSES: &[&str] = &[
    "invalidation acknowledged",
    "fresh GET missed",
    "the proven stop ended its device custody",
    RELAUNCH_WITNESSES[0],
    RELAUNCH_WITNESSES[1],
    RELAUNCH_WITNESSES[2],
    RELAUNCH_WITNESSES[3],
];

const RESTART: &[Obligation] = &[
    Obligation::Custody,
    Obligation::History,
    Obligation::Restart,
];

/// The rule the oracle's restart ledger breaks for a hit no admission
/// precedes.
const REVIVED: Expect = Expect::Violation(
    Obligation::Restart,
    "a recovered candidate was found without admission",
);

pub(super) const RESTARTS: [History; 6] = [
    relaunching(
        history("r1-get", &R1_GET, R1_WITNESSES, RESTART, Expect::Pass),
        1,
    ),
    relaunching(
        control(
            history(
                "r1-get-revived",
                &R1_GET_REVIVED,
                R1_WITNESSES,
                RESTART,
                REVIVED,
            ),
            &[
                "old read held",
                "owner write held",
                "owner stopped with a read held",
                "the stop retained its custody",
                "owner relaunched over the shared media",
            ],
        ),
        1,
    ),
    relaunching(
        uploading(
            history("r2-put", &R2_PUT, R2_WITNESSES, RESTART, Expect::Pass),
            1,
        ),
        1,
    ),
    relaunching(
        uploading(
            control(
                history(
                    "r2-put-revived",
                    &R2_PUT_REVIVED,
                    R2_WITNESSES,
                    RESTART,
                    REVIVED,
                ),
                &[
                    "owner write held",
                    "upload receipt acknowledged",
                    "transmit references withheld at stop",
                    "the proven stop ended its device custody",
                    "the cut upload stayed unsettled",
                    "owner relaunched over the shared media",
                ],
            ),
            1,
        ),
        1,
    ),
    relaunching(
        history("r3-get", &R3_GET, R3_WITNESSES, RESTART, Expect::Pass),
        1,
    ),
    relaunching(
        control(
            history(
                "r3-get-revived",
                &R3_GET_REVIVED,
                R3_WITNESSES,
                RESTART,
                REVIVED,
            ),
            &[
                "invalidation acknowledged",
                "fresh GET missed",
                "the proven stop ended its device custody",
                "owner relaunched over the shared media",
            ],
        ),
        1,
    ),
];

#[cfg(test)]
mod tests {
    use crate::oracle::{Obligation, Outcome as Judged};
    use crate::sim::trace::load;
    use crate::sim::turn::End;

    use super::super::super::super::fetch::Outcome;
    use super::super::super::super::frame::Status;
    use super::super::super::bundle::{admit, traced};
    use super::super::super::recovery::recovered_answer;
    use super::super::super::replay::{Replayed, replay};
    use super::super::tests::manifest;
    use super::{Expect, RESTARTS};

    #[test]
    fn a_recovered_answer_that_handed_out_bytes_is_a_hit() {
        let failed = Status::StoragePressure;
        assert_eq!(
            recovered_answer(Some(Outcome::Complete), b"v"),
            Some(Judged::Hit)
        );
        assert_eq!(
            recovered_answer(Some(Outcome::Incomplete(failed)), b"prefix"),
            Some(Judged::Hit)
        );
        assert_eq!(
            recovered_answer(Some(Outcome::Incomplete(failed)), b""),
            None
        );
        assert_eq!(
            recovered_answer(Some(Outcome::Missing), b""),
            Some(Judged::Missing)
        );
        assert_eq!(recovered_answer(Some(Outcome::Missing), b"prefix"), None);
        assert_eq!(recovered_answer(Some(Outcome::Failed(failed)), b""), None);
        assert_eq!(recovered_answer(None, b""), None);
    }

    /// The chooser admits the relaunching run's link-fault draws.
    #[test]
    fn a_relaunching_run_draws_link_faults_without_a_defect() {
        let (profile, mut plan, goal) = super::super::named("r1-get", 3).expect("r1-get");
        plan.link_faults = true;
        let chooser = profile.recorder(&super::super::super::sites());
        let (ran, first, _) = super::super::super::mixed_run(
            chooser,
            &profile,
            plan,
            goal,
            super::super::super::LIMITS,
            &mut (),
        );
        assert_eq!(first, None);
        assert_eq!(ran.report.end, End::Done);
        assert!(
            !ran.captures[0].is_empty(),
            "the relaunched client 0 link carries the plan's tapped fault rules"
        );
    }

    /// A relaunching history runs the conservation rule once per turn and
    /// clock move, across its relaunch, and passes.
    #[test]
    fn a_relaunched_incarnation_is_judged_after_every_turn() {
        let (profile, plan, goal) = super::super::named("r1-get", 3).expect("r1-get");
        assert!(plan.relaunches > 0, "premise: the history relaunches");
        let chooser = profile.recorder(&super::super::super::sites());
        let (ran, first, _) = super::super::super::mixed_run(
            chooser,
            &profile,
            plan,
            goal,
            super::super::super::LIMITS,
            &mut (),
        );
        assert_eq!(first, None);
        assert_eq!(ran.report.end, End::Done, "premise: the relaunch ran");
        assert_eq!(ran.audit, crate::net::audit::Verdict::Pass);
        // The relaunch turn judges the closed incarnation's boundary too,
        // which counts one boundary with no clock move.
        assert_eq!(
            ran.conserved + u64::from(plan.relaunches),
            ran.report.turn_count + ran.boundaries as u64
        );
    }

    /// The relaunch turn checks the successor's storage and emits a
    /// `FREE_RUNS` violation when the relaunch step leaks a unit there.
    #[test]
    fn a_unit_leaked_by_the_relaunch_step_fails_in_the_relaunch_turn() {
        fn relaunch_and_leak(world: &mut super::Mixed<'_, '_, '_>, now: u64) -> u64 {
            let closed: *const _ = world.storage();
            let out = super::relaunch_owner(world, now);
            assert!(
                !std::ptr::eq(closed, world.storage()),
                "premise: the relaunch installed a new storage"
            );
            assert!(
                crate::storage::owner_fixture::leak_unit(world.storage()),
                "premise: the successor leaked a unit"
            );
            out
        }
        const LEAKED: [super::Step; 16] = super::replaced(
            super::R1_GET,
            "relaunch",
            super::step("relaunch", super::relaunchable, relaunch_and_leak),
        );
        #[derive(Default)]
        struct Steps(Vec<(Option<u32>, bool)>);
        impl crate::sim::turn::Hook for Steps {
            fn clock(&mut self, _: &[u8], _: u64, events: &[crate::sim::trace::Event]) {
                self.0.push((None, failed(events)));
            }
            fn turn(
                &mut self,
                _: &[u8],
                turn: &crate::sim::turn::Turn,
                events: &[crate::sim::trace::Event],
            ) {
                let step = super::super::super::completed_step(&turn.event, turn.outcome);
                self.0.push((step, failed(events)));
            }
        }
        fn failed(events: &[crate::sim::trace::Event]) -> bool {
            events
                .iter()
                .any(|event| event.kind == super::super::super::bundle::FAILURE)
        }
        let relaunch = LEAKED
            .iter()
            .position(|step| step.name == "relaunch")
            .expect("a relaunch step") as u32;
        let (profile, mut plan, goal) = super::super::named("r1-get", 3).expect("r1-get");
        plan.script = &LEAKED;
        let chooser = profile.recorder(&super::super::super::sites());
        let mut steps = Steps::default();
        let (_, first, _) = super::super::super::mixed_run(
            chooser,
            &profile,
            plan,
            goal,
            super::super::super::LIMITS,
            &mut steps,
        );
        assert_eq!(
            first,
            Some(super::super::super::Failure::Violation(
                Obligation::Resources,
                crate::net::observe::FREE_RUNS
            ))
        );
        let emitted = steps.0.iter().find(|(_, failed)| *failed);
        assert_eq!(
            emitted.map(|(step, _)| *step),
            Some(Some(relaunch)),
            "the relaunch turn emitted the failure"
        );
    }

    /// Just before the relaunch, `aside` receives a lease on the closing
    /// owner's link, leaving the lease outside the closing owner's datagram
    /// count. The relaunch reads the closing incarnation's datagram
    /// accounts, and the relaunch turn emits their failure.
    #[test]
    fn a_lease_the_closing_owner_never_counted_fails_in_the_relaunch_turn() {
        fn uncounted_then_relaunch(world: &mut super::Mixed<'_, '_, '_>, now: u64) -> u64 {
            use crate::net::Datagrams;
            let mut aside = world.scene.owner.transport().rejoin(0);
            world.scene.nets[0].borrow_mut().inject(1, &[0x5a; 200]);
            let pool = crate::net::owner_tests::pool();
            let mut into = [None];
            let mut meta = [crate::net::Received::default()];
            assert_eq!(
                aside.receive(&pool, &mut into, &mut meta),
                Ok(1),
                "premise: a link delivered a lease toward the closing owner"
            );
            drop(into);
            super::relaunch_owner(world, now)
        }
        const UNCOUNTED: [super::Step; 16] = super::replaced(
            super::R1_GET,
            "relaunch",
            super::step("relaunch", super::relaunchable, uncounted_then_relaunch),
        );
        #[derive(Default)]
        struct Steps(Vec<(Option<u32>, bool)>);
        impl crate::sim::turn::Hook for Steps {
            fn clock(&mut self, _: &[u8], _: u64, events: &[crate::sim::trace::Event]) {
                self.0.push((None, failed(events)));
            }
            fn turn(
                &mut self,
                _: &[u8],
                turn: &crate::sim::turn::Turn,
                events: &[crate::sim::trace::Event],
            ) {
                let step = super::super::super::completed_step(&turn.event, turn.outcome);
                self.0.push((step, failed(events)));
            }
        }
        fn failed(events: &[crate::sim::trace::Event]) -> bool {
            events
                .iter()
                .any(|event| event.kind == super::super::super::bundle::FAILURE)
        }
        let relaunch = UNCOUNTED
            .iter()
            .position(|step| step.name == "relaunch")
            .expect("a relaunch step") as u32;
        let (profile, mut plan, goal) = super::super::named("r1-get", 3).expect("r1-get");
        plan.script = &UNCOUNTED;
        let chooser = profile.recorder(&super::super::super::sites());
        let mut steps = Steps::default();
        let (_, first, _) = super::super::super::mixed_run(
            chooser,
            &profile,
            plan,
            goal,
            super::super::super::LIMITS,
            &mut steps,
        );
        assert_eq!(
            first,
            Some(super::super::super::Failure::Violation(
                Obligation::Contain,
                crate::net::observe::UNACCOUNTED
            ))
        );
        let emitted = steps.0.iter().find(|(_, failed)| *failed);
        assert_eq!(
            emitted.map(|(step, _)| *step),
            Some(Some(relaunch)),
            "the relaunch turn emitted the failure"
        );
    }

    /// Every relaunch history is recorded under its manifest, ends as it
    /// declares and replays equal: each passing history passes its restart
    /// check and reads its replacement exactly, and each control fails
    /// through the oracle's restart rule under its premise.
    #[test]
    fn every_relaunch_history_ends_as_declared_and_replays_equal() {
        let rule = "a recovered candidate was found without admission";
        for name in ["r1-get-revived", "r2-put-revived", "r3-get-revived"] {
            let declared = RESTARTS.iter().find(|h| h.name == name).expect(name);
            assert_eq!(
                declared.expect,
                Expect::Violation(Obligation::Restart, rule),
                "{name}"
            );
            assert!(!declared.premise.is_empty(), "{name} declares its premise");
        }
        for history in &RESTARTS {
            let bytes = traced(
                admit(&manifest(history.name)).expect("admitted"),
                Vec::new(),
            )
            .sink;
            let loaded = load(&bytes, 1_000_000).expect("a loadable bundle");
            assert_eq!(history.ends_as_declared(&loaded), Ok(()));
            assert_eq!(
                replay(&bytes).expect("a replay").0,
                Replayed::Reproduced,
                "{}",
                history.name
            );
        }
    }

    #[test]
    fn a_cut_upload_decided_at_its_unsettled_check_is_that_turns_collection() {
        use super::super::super::super::upload::UploadOutcome;
        use super::super::super::bundle::Collected;
        use super::super::super::{LIMITS, Plan, SCRIPT, mixed_run, sites_for};
        use super::super::{STAY, Step, put_decided, replaced, step};
        const DECIDED: [Step; 17] = replaced(
            super::R2_PUT,
            "upload-unsettled",
            step(
                "upload-unsettled-decided",
                put_decided,
                super::upload_unsettled,
            ),
        );
        let (profile, plan, goal) = super::super::named("r2-put", 3).expect("r2-put");
        let plan = Plan {
            script: &DECIDED,
            ..plan
        };
        let chooser = profile.recorder(&sites_for(&plan));
        let (ran, _, _) = mixed_run(chooser, &profile, plan, goal, LIMITS, &mut ());
        let planted = DECIDED
            .iter()
            .position(|step| step.name == "upload-unsettled-decided")
            .expect("the planted step") as u32;
        let script = [crate::sim::choice::Domain::Workload as u8, SCRIPT];
        let checks: Vec<_> = ran
            .report
            .turns
            .iter()
            .filter(|turn| {
                turn.event.0[..2] == script
                    && turn.event.0[3..7] == planted.to_be_bytes()
                    && turn.outcome != STAY
            })
            .collect();
        assert_eq!(checks.len(), 1, "the planted check ran once");
        assert_eq!(
            checks[0].observation,
            Collected::Put(0, 0, UploadOutcome::Unknown).code()
        );
    }
}
