//! Silent-owner histories: an upload the owner published, with and without its RESULT reaching the client.
//!
//! The oracle's rule "an attempt that did not publish published": a client may report `Failed(_)` or
//! `NotStarted` only for an attempt whose publication cannot have landed. An upload the owner published,
//! whose client never received a RESULT, may therefore end only `Unknown`.
//!
//! Both histories run the single-owner world. The client uploads the one-fragment replacement of key 1, the
//! script waits until the owner's PUT report counts one more published upload, and then until the client
//! decided the upload. The judging step writes the attempt as oracle rows: the upload the owner received
//! and wrote, its acknowledged publication, and the outcome the client reported. It passes the rows to
//! `oracle::check` and fails History with the rule the verdict names.
//!
//! - `so1-put-result-lost`: a link rule drops every PUT RESULT toward the
//!   client, so the client's resends of PREPARE run out, or its deadline passes, with no reply. The kill
//!   counts only with its premises marked: the drop armed, the owner's publication, and a RESULT the link
//!   dropped. No premise names the outcome.
//! - `so1-put-result-delivered`: the same upload with no rule. The RESULT
//!   arrives, the upload ends `Published` and the same rows pass.
//! - `so1-put-result-lost-as-not-started` repeats `so1-put-result-lost` as a control: the rows carry
//!   `NotStarted` as the client's outcome.

use crate::oracle::{KeyId, Script, check};

use super::super::super::adapters::put_outcome;
use super::super::super::frame::Kind;
use super::incidents::captured;
use super::*;

const COUNTED: &str = "the owner's publications counted before the upload";
const ARMED: &str = "a RESULT drop armed";
pub(super) const OWNER_PUBLISHED: &str = "the owner published the upload";
pub(super) const LOST: &str = "the link dropped a RESULT toward the client";
const DELIVERED: &str = "no RESULT was dropped";
pub(super) const UNKNOWN: &str = "the upload ended unknown with no RESULT delivered";
const PUBLISHED: &str = "upload published";
/// Marked by a judge whose rows the oracle passed: this family's and the abandon histories' of
/// `incidents/unknowns.rs`. `CHECKS` credits the mark with History for both.
pub(super) const ROWS_PASSED: &str = "the oracle passed the attempt's rows";

/// The oracle's key of the uploaded object, key 1 of the scene.
pub(super) const KEY: KeyId = KeyId(1);

/// Records the uploads the owner had published before this history's upload.
fn count_published(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.published = world.scene.owner.put_report().published;
    mark(world, COUNTED)
}

/// Counts as `count_published` does, then drops every PUT RESULT frame toward the client.
fn drop_every_result(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    count_published(world, now);
    super::incidents::drop_every_result(world, now)
}

/// Starts the upload and keeps the run going past the client's deadline, the last of the ends that can
/// decide an upload no RESULT reaches.
pub(super) fn begin(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.wake = Some(now + super::super::WAIT_US + 1);
    put_begin(world, now)
}

/// The owner's PUT report counts an upload published since the history counted them.
pub(super) fn owner_published(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world.scene.owner.put_report().published > world.history.published
}

pub(super) fn mark_owner_published(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    mark(world, OWNER_PUBLISHED)
}

pub(super) fn result_dropped(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    captured(world, Kind::PutResult, true) > 0
}

pub(super) fn mark_lost(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    mark(world, LOST)
}

/// The sibling's link carries no rule, so it dropped no RESULT.
fn mark_delivered(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    mark(world, DELIVERED)
}

/// Writes the attempt as oracle rows and judges them. The owner received the upload in full and wrote it;
/// its publication is a row once the owner's PUT report counts it; the client's outcome is the result row.
/// A verdict that violates History fails with the verdict's own rule, whatever the outcome was. A passing
/// verdict marks the outcome the client reported.
fn judge_result(world: &mut Mixed<'_, '_, '_>, now: u64, outcome: UploadOutcome) -> u64 {
    let received = world.scene.clients[0].put_results();
    let body = VERSION_B_LEN as u64;
    let mut rows = Script::new();
    let op = rows.upload(KEY, LABEL_B, body, true);
    if owner_published(world, now) {
        rows.owner_publish(op, KEY, LABEL_B);
    }
    rows.put_result(op, KEY, LABEL_B, put_outcome(outcome));
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
    mark(world, ROWS_PASSED);
    match outcome {
        UploadOutcome::Unknown if received == 0 => mark(world, UNKNOWN),
        UploadOutcome::Published if received > 0 => mark(world, PUBLISHED),
        _ => 1,
    }
}

fn result_judged(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    let Some(outcome) = world.collect_put(id) else {
        world
            .first
            .record(Failure::Unsuccessful("the judged upload held no outcome"));
        return 0;
    };
    judge_result(world, now, outcome)
}

fn lost_as_not_started(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    let _ = world.collect_put(id);
    judge_result(world, now, UploadOutcome::NotStarted)
}

const EVERY_RESULT_LOST: [Step; 8] = [
    step("arm-drop", always, drop_every_result),
    step("put-begin", active_put, begin),
    step("put-prepare", always, put_prepare),
    step("put-supply", always, put_supply),
    step("owner-published", owner_published, mark_owner_published),
    step("result-fate", result_dropped, mark_lost),
    step("put-result", put_decided, result_judged),
    JUDGE,
];

const NO_RESULT_LOST: [Step; 8] = replaced(
    replaced(
        EVERY_RESULT_LOST,
        "arm-drop",
        step("arm-drop", always, count_published),
    ),
    "result-fate",
    step("result-fate", always, mark_delivered),
);

const LOST_AS_NOT_STARTED: [Step; 8] = replaced(
    EVERY_RESULT_LOST,
    "put-result",
    step(
        "put-result-as-not-started",
        put_decided,
        lost_as_not_started,
    ),
);

const UNKNOWN_WITNESSES: &[&str] = &[COUNTED, ARMED, OWNER_PUBLISHED, LOST, ROWS_PASSED, UNKNOWN];

const PUBLISHED_WITNESSES: &[&str] = &[COUNTED, OWNER_PUBLISHED, DELIVERED, ROWS_PASSED, PUBLISHED];

/// The marks a kill of the rule needs: the fault armed, the owner's publication, a RESULT lost.
const PREMISE: &[&str] = &[ARMED, OWNER_PUBLISHED, LOST];

/// The sibling's premise: the owner's publication.
const SIBLING_PREMISE: &[&str] = &[OWNER_PUBLISHED];

const JUDGED: &[Obligation] = &[Obligation::History];

pub(super) const CHECKS: [(&str, Obligation); 1] = [(ROWS_PASSED, Obligation::History)];

const fn silent_owner(
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

pub(super) const SILENT_OWNERS: [History; 3] = [
    silent_owner(
        "so1-put-result-lost",
        &EVERY_RESULT_LOST,
        UNKNOWN_WITNESSES,
        Expect::Pass,
        PREMISE,
    ),
    silent_owner(
        "so1-put-result-delivered",
        &NO_RESULT_LOST,
        PUBLISHED_WITNESSES,
        Expect::Pass,
        SIBLING_PREMISE,
    ),
    silent_owner(
        "so1-put-result-lost-as-not-started",
        &LOST_AS_NOT_STARTED,
        UNKNOWN_WITNESSES,
        Expect::Violation(
            Obligation::History,
            "an attempt that did not publish published",
        ),
        PREMISE,
    ),
];
