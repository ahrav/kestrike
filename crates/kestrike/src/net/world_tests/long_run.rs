//! The long-run gate's mixed GET/PUT phase: named scenarios of the mixed
//! world, each run at the root the gate names under its own link limits,
//! judged for a complete pass and for correlated witnesses, and one upload
//! and GET recorded as oracle rows and judged through the continuation.
//! The long scenario arms no witness: it runs two uploads of one key over
//! lossy, duplicating, reordering and delaying links for the phase's
//! high-water marks, and must pass completely.
//!
//! The manifest pins mixed root 3.
//!
//! A scenario passes only when the controller ended `Done`, both links'
//! and the device's audit passed, no stopped boundary or teardown observed
//! a failure and the storage census reconciled; an `Inconclusive` end is no
//! pass and names its limit. Each witness of [`REQUIRED`] fires for one
//! correlation, one upload attempt of one run or, for the pressure
//! witness, the run, only when every ingredient it needs was recorded for
//! that correlation; the recorder of each finds the ingredients in the
//! order its entry below states:
//!
//! - an upload the owner admitted, a write completion the device delivered
//!   after admission and a receipt the owner advanced after admission, a
//!   new binding of the key after that write, the client's `Published` after both, and an
//!   exact GET issued after it and decided while that binding stood, so no
//!   invalidation, replacement or expiry came between;
//! - a deferral, then an exact GET decided while the upload stayed
//!   undecided;
//! - source slots a device held while the link retained their transmit
//!   references, a NIC return event lowering that link's count, the slots
//!   released after it, and the client's `Published` after that, all while
//!   the attempt was live;
//! - the uploader's GET refused under request pressure while its upload
//!   stayed undecided, then the client's `Published` and another client's
//!   exact read;
//! - a published upload with a result a rule dropped after publication,
//!   collected `Unknown` and never `Published`;
//! - the first result a rule dropped, a later result delivered in the
//!   same session, and the client's `Published`;
//! - an upload cancelled, collected `Unknown`, abandoned and retried in the
//!   same session;
//! - a pressure act holding fills, one releasing them, and an accepted GET
//!   cancel in the same run.
//!
//! Counters, an attempted PREPARE, a receipt alone or a GET of the
//! incumbent object fire no publication witness.
//!
//! Each scenario's run samples the device's commands and store growth,
//! the uploading client's live uploads and source bytes, each link's
//! copied bytes, retained transmit references, captures and audit records,
//! and the observation registry; the phase samples its witness log, and
//! the recorded upload its continuation's frontier.

use crate::oracle::{ActionKind as RowKind, Custodian, Label, Owner, Recorder, Row, Verdict};
use crate::sim::action::{ActionKind, Profile};
use crate::sim::long_run_tests::{
    AUDIT_RECORDS, CAPTURES, COPY_BYTES, DEVICE_COMMANDS, DEVICE_GROWTH, FRONTIER, LIVE_UPLOADS,
    Marks, PARKED, REGISTRY, SOURCE_BYTES, TX_SLOTS, WITNESS_LOG,
};
use crate::sim::turn::End;

use super::super::adapters::{get, upload_published};
use super::super::audit::{Reason, Verdict as Audit};
use super::super::fetch::Outcome;
use super::super::frame::{Kind, Status};
use super::super::observe::{Cuts, Witnesses};
use super::super::owner_tests::{PRINCIPALS, key};
use super::super::put_tests::scene;
use super::super::rules::Dropped;
use super::super::upload::UploadOutcome;
use super::{
    LIMITS, Mixed, PRESSURE, PRESSURE_RELEASED, PUT_KEY, Plan, REFUSED, Ran, UPLOAD, UPLOAD_PLAN,
    boundary, coverage, exactly_read, get_decided, mixed_run, nic_return_link, sites_for,
    upload_code, upload_profile,
};

/// Entries each correlated witness log may hold before it refuses one.
pub(crate) const WITNESS_LIMIT: usize = 256;

pub(super) const PUBLISHED_READ: &str = "a remote PUT published and a later exact GET read it";
pub(super) const STALLED_READ: &str = "a GET completed exactly beside a stalled upload";
pub(super) const NIC_RETURN: &str = "upload sources held until their delayed NIC return";
pub(super) const REQUEST_PRESSURE: &str = "a GET refused under request pressure beside an upload";
pub(super) const LOST_RESULT: &str = "a published upload whose result was lost ended Unknown";
pub(super) const RESULT_REPLAY: &str = "a dropped result delivered again in the same session";
pub(super) const ABANDONED: &str = "an uncertain upload cancelled, abandoned and retried";
pub(super) const PRESSURE_HELD: &str = "pressure held and released fills beside a cancelled GET";

const ADMITTED: &str = "admitted";
const WRITTEN: &str = "write completion";
const RECEIPTED: &str = "receipt";
const PUBLISHED: &str = "publication";
const SUCCEEDED: &str = "client success";
const READ: &str = "exact GET";
const DEFERRED: &str = "deferral";
const UNDECIDED: &str = "undecided upload";
const HELD: &str = "device-held sources";
const RETURNED: &str = "NIC return";
const RELEASED: &str = "sources released";
const REFUSED_GET: &str = "refused GET";
const DROPPED: &str = "result dropped";
const UNKNOWN: &str = "unknown";
const LOST: &str = "result lost";
const RESENT: &str = "result resent";
const CANCELLED: &str = "cancelled";
const ABANDON: &str = "abandoned";
const RETRIED: &str = "retried";
const PRESSURED: &str = "fills held";
const UNPRESSURED: &str = "fills released";

/// Records one witness's ingredients found in a run for one attempt
/// under one correlation.
type Recording = fn(&Ran, u16, &mut Witnesses, u64);

/// One required witness: its name, the ingredients it needs, whether it
/// correlates per attempt or per run, and the recording that finds its
/// ingredients.
pub(super) struct Required {
    pub(super) name: &'static str,
    pub(super) needs: &'static [&'static str],
    per_attempt: bool,
    record: Recording,
}

/// Every required witness.
pub(super) const REQUIRED: [Required; 8] = [
    Required {
        name: PUBLISHED_READ,
        needs: &[ADMITTED, WRITTEN, RECEIPTED, PUBLISHED, SUCCEEDED, READ],
        per_attempt: true,
        record: published_read,
    },
    Required {
        name: STALLED_READ,
        needs: &[DEFERRED, READ, UNDECIDED],
        per_attempt: true,
        record: stalled_read,
    },
    Required {
        name: NIC_RETURN,
        needs: &[HELD, RETURNED, RELEASED, SUCCEEDED],
        per_attempt: true,
        record: nic_return,
    },
    Required {
        name: REQUEST_PRESSURE,
        needs: &[REFUSED_GET, SUCCEEDED, READ],
        per_attempt: true,
        record: request_pressure,
    },
    Required {
        name: LOST_RESULT,
        needs: &[PUBLISHED, DROPPED, UNKNOWN],
        per_attempt: true,
        record: lost_result,
    },
    Required {
        name: RESULT_REPLAY,
        needs: &[LOST, RESENT, SUCCEEDED],
        per_attempt: true,
        record: result_replay,
    },
    Required {
        name: ABANDONED,
        needs: &[CANCELLED, UNKNOWN, ABANDON, RETRIED],
        per_attempt: true,
        record: abandoned,
    },
    Required {
        name: PRESSURE_HELD,
        needs: &[PRESSURED, UNPRESSURED, CANCELLED],
        per_attempt: false,
        record: pressure_held,
    },
];

/// A witness log requiring every witness of [`REQUIRED`].
pub(super) fn required() -> Witnesses {
    let mut w = Witnesses::new(WITNESS_LIMIT);
    for required in &REQUIRED {
        w.require(required.name, required.needs);
    }
    w
}

/// One scenario of the phase: its name, profile, plan and goal, and the
/// witnesses it arms.
pub(super) struct Scenario {
    name: &'static str,
    profile: Profile,
    plan: Plan,
    goal: fn(&Mixed<'_, '_, '_>) -> bool,
    arms: &'static [&'static str],
}

/// The upload's outcome was collected and the GET client's read decided,
/// or no read was planned.
fn collected(world: &Mixed<'_, '_, '_>) -> bool {
    world.put.as_ref().is_some_and(|put| put.outcome.is_some())
        && (world.plan.gets[1] == 0 && world.gets[1].is_none() || get_decided(world))
}

/// The phase's scenarios at `root`.
pub(super) fn scenarios(root: u64) -> Vec<Scenario> {
    let [local, _, _, uncertain] = coverage(root);
    let (profile, plan, goal) = boundary::long(false, root);
    let long = Scenario {
        name: "long",
        profile,
        plan,
        goal,
        arms: &[],
    };
    let (profile, plan, goal) = boundary::named("boundary-tiny", root).expect("a boundary");
    let tiny = Scenario {
        name: "boundary-tiny",
        profile,
        plan,
        goal,
        arms: &[PUBLISHED_READ, NIC_RETURN, REQUEST_PRESSURE],
    };
    let stalled = Scenario {
        name: "stalled",
        profile: Profile {
            name: "stalled upload beside a GET",
            declared: [UPLOAD.as_slice(), &[ActionKind::DeferSupply]].concat(),
            root,
        },
        plan: Plan {
            withhold: u32::MAX,
            read_after_publish: false,
            read_during_stall: true,
            read_resident: true,
            ..UPLOAD_PLAN
        },
        goal: get_decided,
        arms: &[STALLED_READ],
    };
    let lost = Scenario {
        name: "lost-result",
        profile: upload_profile(root),
        plan: Plan {
            gets: [0, 0],
            read_after_publish: false,
            drop_result: true,
            ..UPLOAD_PLAN
        },
        goal: collected,
        arms: &[LOST_RESULT],
    };
    let replayed = Scenario {
        name: "result-replay",
        profile: upload_profile(root),
        plan: Plan {
            drop_first_result: true,
            ..UPLOAD_PLAN
        },
        goal: exactly_read,
        arms: &[PUBLISHED_READ, RESULT_REPLAY],
    };
    let parked = Scenario {
        name: "parked",
        profile: Profile {
            name: "parked GET behind a deferring upload",
            declared: [UPLOAD.as_slice(), &[ActionKind::DeferSupply]].concat(),
            root,
        },
        plan: super::parked::PARKED_PLAN,
        goal: exactly_read,
        arms: &[],
    };
    let covered: fn(&Mixed<'_, '_, '_>) -> bool = |world| world.covered();
    vec![
        long,
        tiny,
        stalled,
        parked,
        lost,
        replayed,
        Scenario {
            name: "uncertain",
            profile: uncertain.0,
            plan: uncertain.1,
            goal: covered,
            arms: &[ABANDONED],
        },
        Scenario {
            name: "local",
            profile: local.0,
            plan: local.1,
            goal: covered,
            arms: &[PRESSURE_HELD],
        },
    ]
}

/// Runs `scenario` under its own plan.
///
/// # Errors
///
/// A run that is no complete pass: its end, audit, first observed failure
/// or census, named with the scenario and root.
pub(super) fn run(scenario: &Scenario) -> Result<Ran, String> {
    let profile = &scenario.profile;
    let chooser = profile.recorder(&sites_for(&scenario.plan));
    let (ran, first, _) = mixed_run(
        chooser,
        profile,
        scenario.plan,
        scenario.goal,
        LIMITS,
        &mut (),
    );
    let at = format!("{} at root {}", scenario.name, profile.root);
    match ran.report.end {
        End::Done => {}
        End::Inconclusive(limit) => return Err(format!("{at}: inconclusive at {limit:?}")),
        end => return Err(format!("{at}: ended {end:?}")),
    }
    if ran.audit != Audit::Pass {
        return Err(format!("{at}: audit {:?}", ran.audit));
    }
    if let Some(failure) = first {
        return Err(format!("{at}: observed {failure:?}"));
    }
    if let Err(census) = &ran.settled.census {
        return Err(format!("{at}: census {census}"));
    }
    let parked = ran.seen.last().map_or(0, |seen| seen.parked);
    if parked > 0 {
        return Err(format!("{at}: {parked} GETs still parked"));
    }
    if scenario.name == "parked" && ran.parked.high_water == 0 {
        return Err(format!("{at}: no GET parked"));
    }
    Ok(ran)
}

/// The upload attempt live at `turn`.
fn attempt_at(ran: &Ran, turn: usize) -> Option<u16> {
    ran.seen.get(turn)?.upload.map(|(attempt, _)| attempt)
}

/// The turns of actions `kind` with an outcome `outcome` accepts, run
/// while `attempt` was the live upload.
fn turns(
    ran: &Ran,
    kind: ActionKind,
    attempt: u16,
    outcome: impl Fn(u64) -> bool,
) -> impl Iterator<Item = usize> {
    ran.acts
        .iter()
        .filter(move |act| {
            act.kind == kind && outcome(act.outcome) && attempt_at(ran, act.turn) == Some(attempt)
        })
        .map(|act| act.turn)
}

/// The first turn at or after `from` where `attempt`'s client collected
/// `Published`.
fn succeeded(ran: &Ran, attempt: u16, from: usize) -> Option<usize> {
    let published = upload_code(UploadOutcome::Published);
    turns(ran, ActionKind::PutOutcome, attempt, |outcome| {
        outcome == published
    })
    .find(|&t| t >= from)
}

/// An exact complete GET of `wanted` issued at or after `from`, by client
/// `client` when one is named; the turn that decided it.
fn exact_read(ran: &Ran, wanted: [u8; 32], from: usize, client: Option<usize>) -> Vec<usize> {
    let read = ran.decided.iter().filter(|decided| {
        decided.key == wanted
            && decided.issued >= from
            && decided.outcome == Outcome::Complete
            && decided.exact
            && client.is_none_or(|client| decided.client == client)
    });
    read.map(|decided| decided.decided).collect()
}

/// Every upload attempt the run saw.
fn attempts(ran: &Ran) -> Vec<u16> {
    let mut attempts: Vec<u16> = ran
        .seen
        .iter()
        .filter_map(|seen| seen.upload)
        .map(|(attempt, _)| attempt)
        .collect();
    attempts.dedup();
    attempts
}

/// Records the publication witness's ingredients for `attempt`.
fn published_read(ran: &Ran, attempt: u16, w: &mut Witnesses, at: u64) {
    let seen = &ran.seen;
    let ours = |t: usize| attempt_at(ran, t) == Some(attempt);
    let Some(admitted) = (0..seen.len()).find(|&t| {
        ours(t)
            && seen[t].upload.is_some_and(|(_, serial)| serial != 0)
            && seen[t].receipt.is_some_and(|(_, grant)| grant > 0)
    }) else {
        return;
    };
    w.ingredient(PUBLISHED_READ, at, ADMITTED);
    let incumbent = seen[admitted].binding;
    let receipted =
        (admitted..seen.len()).find(|&t| ours(t) && seen[t].receipt.is_some_and(|r| r.0 > 0));
    if receipted.is_some() {
        w.ingredient(PUBLISHED_READ, at, RECEIPTED);
    }
    let Some(written) =
        (admitted + 1..seen.len()).find(|&t| ours(t) && seen[t].written > seen[admitted].written)
    else {
        return;
    };
    w.ingredient(PUBLISHED_READ, at, WRITTEN);
    let Some(publication) = (admitted + 1..seen.len())
        .find(|&t| seen[t].binding.is_some() && seen[t].binding != incumbent)
        .filter(|&t| t >= written && ours(t))
    else {
        return;
    };
    w.ingredient(PUBLISHED_READ, at, PUBLISHED);
    let Some(success) = succeeded(
        ran,
        attempt,
        publication.max(receipted.unwrap_or(usize::MAX)),
    ) else {
        return;
    };
    w.ingredient(PUBLISHED_READ, at, SUCCEEDED);
    let binding = seen[publication].binding;
    let stood = |decided: usize| {
        seen[publication..=decided]
            .iter()
            .all(|s| s.binding == binding)
    };
    if exact_read(ran, key(PUT_KEY), success, None)
        .into_iter()
        .any(stood)
    {
        w.ingredient(PUBLISHED_READ, at, READ);
    }
}

/// Records the stalled-read witness's ingredients for `attempt`.
fn stalled_read(ran: &Ran, attempt: u16, w: &mut Witnesses, at: u64) {
    let Some(deferred) = turns(ran, ActionKind::DeferSupply, attempt, |_| true).next() else {
        return;
    };
    w.ingredient(STALLED_READ, at, DEFERRED);
    let resident = key(1);
    let Some(read) = exact_read(ran, resident, deferred, Some(1))
        .first()
        .copied()
    else {
        return;
    };
    w.ingredient(STALLED_READ, at, READ);
    let undecided = ran.seen[deferred..=read].iter().all(|seen| seen.uploading);
    if undecided && succeeded(ran, attempt, 0).is_none_or(|t| t > read) {
        w.ingredient(STALLED_READ, at, UNDECIDED);
    }
}

/// Records the NIC-return witness's ingredients for `attempt`.
fn nic_return(ran: &Ran, attempt: u16, w: &mut Witnesses, at: u64) {
    let seen = &ran.seen;
    let ours = |t: usize| attempt_at(ran, t) == Some(attempt);
    let Some(held) =
        (0..seen.len()).find(|&t| ours(t) && seen[t].device_held > 0 && seen[t].nic[0] > 0)
    else {
        return;
    };
    w.ingredient(NIC_RETURN, at, HELD);
    let Some(returned) = (held + 1..seen.len()).find(|&t| {
        ours(t)
            && nic_return_link(&ran.report.turns[t].event) == Some(0)
            && seen[t].withheld[0] < seen[t - 1].withheld[0]
    }) else {
        return;
    };
    w.ingredient(NIC_RETURN, at, RETURNED);
    let holding = seen[held].device_held;
    if seen[held..returned].iter().any(|s| s.device_held < holding) {
        return;
    }
    let Some(released) = (returned..seen.len()).find(|&t| ours(t) && seen[t].device_held < holding)
    else {
        return;
    };
    w.ingredient(NIC_RETURN, at, RELEASED);
    if succeeded(ran, attempt, released).is_some() {
        w.ingredient(NIC_RETURN, at, SUCCEEDED);
    }
}

/// Records the request-pressure witness's ingredients for `attempt`.
fn request_pressure(ran: &Ran, attempt: u16, w: &mut Witnesses, at: u64) {
    let refused = ran.decided.iter().find(|decided| {
        decided.client == 0
            && decided.outcome == Outcome::Pressure(Status::RequestPressure)
            && attempt_at(ran, decided.decided) == Some(attempt)
            && ran.seen[decided.issued..=decided.decided]
                .iter()
                .all(|seen| seen.uploading)
    });
    let Some(refused) = refused else {
        return;
    };
    w.ingredient(REQUEST_PRESSURE, at, REFUSED_GET);
    let Some(success) = succeeded(ran, attempt, refused.decided) else {
        return;
    };
    w.ingredient(REQUEST_PRESSURE, at, SUCCEEDED);
    if !exact_read(ran, key(PUT_KEY), success, Some(1)).is_empty() {
        w.ingredient(REQUEST_PRESSURE, at, READ);
    }
}

/// The first turn whose observation `of` reads more than `count` from.
fn turn_past(ran: &Ran, count: usize, of: impl Fn(&super::Seen) -> usize) -> Option<usize> {
    ran.seen.iter().position(|seen| of(seen) > count)
}

/// Records the lost-result witness's ingredients for `attempt`.
fn lost_result(ran: &Ran, attempt: u16, w: &mut Witnesses, at: u64) {
    let seen = &ran.seen;
    let ours = |t: usize| attempt_at(ran, t) == Some(attempt);
    let Some(publication) = (0..seen.len()).find(|&t| ours(t) && seen[t].binding.is_some()) else {
        return;
    };
    w.ingredient(LOST_RESULT, at, PUBLISHED);
    let drops = ran.audits[0].iter().enumerate();
    let dropped = drops
        .filter(|(_, record)| record.reason == Reason::RuleDrop)
        .find_map(|(index, _)| turn_past(ran, index, |seen| seen.audited[0]))
        .filter(|&t| ours(t) && t >= publication);
    let Some(dropped) = dropped else {
        return;
    };
    w.ingredient(LOST_RESULT, at, DROPPED);
    let unknown = upload_code(UploadOutcome::Unknown);
    let collected =
        turns(ran, ActionKind::PutOutcome, attempt, |o| o == unknown).find(|&t| t > dropped);
    if collected.is_some() && succeeded(ran, attempt, 0).is_none() {
        w.ingredient(LOST_RESULT, at, UNKNOWN);
    }
}

/// Records the result-replay witness's ingredients for `attempt`.
fn result_replay(ran: &Ran, attempt: u16, w: &mut Witnesses, at: u64) {
    let results = ran.captures[0]
        .iter()
        .enumerate()
        .filter(|(_, capture)| capture.kind == Some(Kind::PutResult));
    let mut lost = None;
    for (index, capture) in results {
        let Some(turn) = turn_past(ran, index, |seen| seen.captured[0]) else {
            continue;
        };
        if attempt_at(ran, turn) != Some(attempt) {
            continue;
        }
        match (lost, capture.decision.drop) {
            (None, Some(Dropped::Rule(_))) => {
                w.ingredient(RESULT_REPLAY, at, LOST);
                lost = Some(turn);
            }
            (Some(lost_at), None) => {
                let session = |t: usize| ran.seen[t].sessions[0];
                let same = session(lost_at) == session(turn);
                if same {
                    w.ingredient(RESULT_REPLAY, at, RESENT);
                    if succeeded(ran, attempt, turn).is_some() {
                        w.ingredient(RESULT_REPLAY, at, SUCCEEDED);
                    }
                    return;
                }
            }
            _ => {}
        }
    }
}

/// Records the abandonment witness's ingredients for `attempt`.
fn abandoned(ran: &Ran, attempt: u16, w: &mut Witnesses, at: u64) {
    let Some(cancelled) = turns(ran, ActionKind::PutCancel, attempt, |o| o != REFUSED).next()
    else {
        return;
    };
    w.ingredient(ABANDONED, at, CANCELLED);
    let unknown = upload_code(UploadOutcome::Unknown);
    let Some(collected) =
        turns(ran, ActionKind::PutOutcome, attempt, |o| o == unknown).find(|&t| t >= cancelled)
    else {
        return;
    };
    w.ingredient(ABANDONED, at, UNKNOWN);
    let Some(abandon) =
        turns(ran, ActionKind::Abandon, attempt, |o| o == 1).find(|&t| t > collected)
    else {
        return;
    };
    w.ingredient(ABANDONED, at, ABANDON);
    let session = |t: usize| ran.seen[t].sessions[0];
    let retried = turns(ran, ActionKind::Retry, attempt + 1, |o| o != REFUSED)
        .any(|t| t > abandon && session(t) == session(collected));
    if retried {
        w.ingredient(ABANDONED, at, RETRIED);
    }
}

/// Records the pressure witness's ingredients for the run, whatever the
/// attempt.
fn pressure_held(ran: &Ran, _attempt: u16, w: &mut Witnesses, at: u64) {
    let held = 1..=u64::from(PRESSURE);
    let acted = |kind: ActionKind, outcome: &dyn Fn(u64) -> bool| {
        ran.acts
            .iter()
            .any(|act| act.kind == kind && outcome(act.outcome))
    };
    if acted(ActionKind::Pressure, &|outcome| held.contains(&outcome)) {
        w.ingredient(PRESSURE_HELD, at, PRESSURED);
    }
    if acted(ActionKind::Pressure, &|outcome| outcome > PRESSURE_RELEASED) {
        w.ingredient(PRESSURE_HELD, at, UNPRESSURED);
    }
    if acted(ActionKind::Cancel, &|outcome| outcome != REFUSED) {
        w.ingredient(PRESSURE_HELD, at, CANCELLED);
    }
}

/// Arms and records the witnesses `scenario` names for its run `ran`, the
/// `index`th the phase judged, and fires each per attempt, the pressure
/// witness once per run.
///
/// # Panics
///
/// When `scenario` arms a witness [`REQUIRED`] lacks.
pub(super) fn witness(scenario: &Scenario, ran: &Ran, index: u64, w: &mut Witnesses) {
    for &armed in scenario.arms {
        let required = REQUIRED.iter().find(|required| required.name == armed);
        let required = required.expect("an armed witness is required");
        w.activate(armed);
        let run = index << 16;
        let correlations: Vec<(u16, u64)> = if required.per_attempt {
            let attempts = attempts(ran).into_iter();
            attempts.map(|a| (a, run | u64::from(a))).collect()
        } else {
            vec![(0, run)]
        };
        for (attempt, at) in correlations {
            (required.record)(ran, attempt, w, at);
            w.fire(armed, at);
        }
    }
}

/// Raises the marks to what `ran` held at its highest; a quantity `ran`
/// observed on no turn stays unmeasured.
fn sample(ran: &Ran, marks: &mut Marks) {
    let mut most = |name: &str, of: &dyn Fn(&super::Seen) -> usize| {
        if let Some(high) = ran.seen.iter().map(of).max() {
            marks.sample(name, high as u64);
        }
    };
    most(LIVE_UPLOADS, &|seen| seen.uploads);
    most(SOURCE_BYTES, &|seen| seen.source_bytes);
    most(COPY_BYTES, &|seen| seen.copied);
    most(TX_SLOTS, &|seen| seen.nic[0].max(seen.nic[1]));
    marks.sample(PARKED, u64::from(ran.parked.high_water));
    marks.sample(DEVICE_COMMANDS, ran.commands as u64);
    marks.sample(DEVICE_GROWTH, ran.grown as u64);
    let captures = ran.captures.iter().map(Vec::len).max();
    marks.sample(CAPTURES, captures.unwrap_or_default() as u64);
    let audits = ran.audits.iter().map(Vec::len).max();
    marks.sample(AUDIT_RECORDS, audits.unwrap_or_default() as u64);
    marks.sample(REGISTRY, ran.registry as u64);
}

/// Judges `rows` through the continuation and samples its frontier.
///
/// # Errors
///
/// The continuation's verdict when it is no pass.
pub(crate) fn continued(rows: &[Row], marks: &mut Marks) -> Result<(), String> {
    let mut cuts = Cuts::new(Owner(0));
    let verdict = cuts
        .cut(rows, &[])
        .map_err(|failure| format!("{failure:?}"))?;
    marks.sample(FRONTIER, cuts.collapsed().1 as u64);
    match verdict {
        Verdict::Pass(_) => Ok(()),
        verdict => Err(verdict
            .violated()
            .map_or(format!("{verdict:?}"), |v| format!("{v:?}"))),
    }
}

/// One upload and a GET of it on a fresh scene, recorded as oracle rows
/// and judged through the continuation; with `early_release`, the source
/// retention's release moves ahead of the first receipt ACK.
///
/// # Errors
///
/// The continuation's verdict when it is no pass.
pub(super) fn recorded_upload(early_release: bool, marks: &mut Marks) -> Result<String, String> {
    let mut judged = Err("the scene never ran".to_owned());
    scene(&PRINCIPALS, |mut scene| {
        let mut rec = Recorder::new(1);
        upload_published(&mut scene, &mut rec, PUT_KEY);
        get(&mut scene, &mut rec, PUT_KEY, Label(PUT_KEY.into()));
        let mut rows: Vec<Row> = rec.rows().to_vec();
        if early_release {
            let release = rows.iter().position(|row| {
                row.kind == RowKind::Release && row.custodian == Some(Custodian::Retransmission)
            });
            let ack = rows.iter().position(|row| row.kind == RowKind::Ack);
            if let (Some(release), Some(ack)) = (release, ack) {
                let moved = rows.remove(release);
                rows.insert(ack, moved);
                Recorder::renumber(&mut rows);
            }
        }
        judged = match continued(&rows, marks) {
            Ok(()) => Ok(format!("recorded upload: {} rows pass", rows.len())),
            Err(refused) => Err(format!("the recorded upload: {refused}")),
        };
    });
    judged
}

/// Runs the mixed phase at `root` into `marks` and returns its report
/// lines.
///
/// # Errors
///
/// The first scenario that is no complete pass, an unfired witness or a
/// recorded upload the oracle does not pass, named.
pub(crate) fn mixed_phase(root: u64, marks: &mut Marks) -> Result<Vec<String>, String> {
    let mut w = required();
    let mut report = Vec::new();
    for (index, scenario) in scenarios(root).iter().enumerate() {
        let ran = run(scenario)?;
        sample(&ran, marks);
        witness(scenario, &ran, index as u64, &mut w);
        report.push(format!(
            "mixed: {} at root {root}: {} turns, {} actions, {} GETs collected",
            scenario.name,
            ran.report.turns.len(),
            ran.acts.len(),
            ran.decided.len()
        ));
    }
    marks.sample(WITNESS_LOG, w.logged() as u64);
    w.verdict()
        .map_err(|failure| format!("mixed witnesses: {failure:?} ({w:?})"))?;
    report.push(recorded_upload(false, marks)?);
    report.push(format!("mixed witnesses: all {} fired", REQUIRED.len()));
    Ok(report)
}

#[cfg(test)]
mod tests;
