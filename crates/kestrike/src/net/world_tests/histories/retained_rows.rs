//! A PUT frame that names a GET's retained row leaves the row's watermark, binding, epoch, expiry
//! and outcome as they were and counts once.
//!
//! Property: a PUT frame naming a live GET, or its retained row once the GET's request released,
//! moves the owner's wrong-operation counter by one and leaves that GET's wire row (its watermark, table
//! handle and retained epoch, expiry and outcome) unchanged, and the GET completes with its exact version.
//! The rule this file judges is "a PUT frame naming a GET changed more than its counter".
//!
//! Both histories run the single-owner world, whose scene publishes version A under key 1 before the run.
//! Client 1 issues a GET of key 1 and the history holds its device read; client 0 issues a GET of the same
//! key beside it. The history reads the first GET's header from the link, so a forged frame carries that
//! GET's wire request ID, key and session.
//!
//! - `rr1-put-begin-at-a-retained-row`: a PUT CANCEL of that identity is injected
//!   while the GET is live, and, after the GET completed with its exact version and its request released,
//!   a PUT BEGIN of the same identity is injected at the row the GET left retained on its wire slot. After
//!   each frame, once the owner's wrong-operation counter moved, a step compares the named slot's row with
//!   its snapshot from before that frame and fails with the rule unless the row is equal and the counter
//!   rose by exactly one.
//! - `rr1-no-frame-at-a-retained-row`: the same steps with no frame at
//!   the retained row. The row is read at the same two points and must be equal with the counter unmoved.
//! - `rr1-put-begin-judged-as-no-frame` is a control: the first history's steps, with the sibling's
//!   judgment run once the owner counted the PUT BEGIN. The counter moved, so that judgment fails through
//!   the rule.
//!
//! Premises, each ending the run unsuccessful under its name when it does not form: at the first frame
//! the named slot is bound and the owner's census holds only the history's requests and live refresh GETs;
//! at the first comparison the concurrent GET is still live; before the second frame the named GET's
//! request has released and its slot holds a retained row.
//!
//! The snapshot holds the counter and the named slot alone, nothing owner-wide, so the concurrent GET does
//! not change it. The steps that learn the header, forge the frame, read the slot and compare it are those
//! of the s3-d-19 histories in `histories/cohorts.rs`, which also record relation rows; these histories
//! mark the same checks and record none.

use super::super::super::frame::Kind;
use super::cohorts::{
    MOVED_MORE, S19, S19_CONCURRENT_READ, S19_READ, S19_RETAINED_CHECKED, concurrent_decided,
    counters, forge, get_released, get_sent, judge_forged, live_at_owner, s19_concurrent_get,
    s19_concurrent_read, s19_counted, s19_formed, s19_learn, s19_read, s19_retained_checked,
};
use super::*;

const LEARNED: &str = "S3-D-19 the GET's header learned";
const LIVE_FRAME: &str = "a PUT CANCEL named the live GET";
const COUNTED: &str = "the wrong operation was counted";
const CONCURRENT: &str = "a concurrent GET stayed live through the check";
/// The mark `histories/cohorts.rs` lists as a check of `Obligation::Contain` at the live GET.
const LIVE_CHECKED: &str = S19[2];
const RETAINED: &str = "the named GET released and left its row retained";
const RETAINED_FRAME: &str = "a PUT BEGIN named the GET's retained row";
const NO_FRAME: &str = "no frame named the GET's retained row";
const RETAINED_KEPT: &str = "the retained row stayed as it was with no frame";

/// The premises of the first frame, then the frame: a PUT CANCEL at the live GET.
fn live_frame(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if let Err(reason) = s19_formed(world) {
        world.first.record(Failure::Unsuccessful(reason));
        return 0;
    }
    let get = world.history.learned.expect("the GET's header");
    forge(world, Kind::PutCancel, get.sequence + 1);
    mark(world, LIVE_FRAME)
}

fn mark_counted(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    mark(world, COUNTED)
}

/// The premise that the concurrent GET is still live, then the judgment of the frame at the live GET:
/// the row equals its snapshot and the counter rose by exactly one.
fn live_checked(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.gets[0].as_ref().expect("the concurrent GET").id;
    let wire = attempt(world, 0, id);
    let live = live_at_owner(world, 0, wire);
    if premised(world, live, CONCURRENT) == 0 {
        return 0;
    }
    let after = counters(world);
    if !judge_forged(world, after) {
        return 0;
    }
    mark(world, LIVE_CHECKED)
}

/// The premise of the second point: the named GET's slot is unbound and holds a retained row.
fn retained(world: &mut Mixed<'_, '_, '_>) -> bool {
    let named = counters(world);
    premised(
        world,
        named.active.is_none() && named.cached.is_some(),
        RETAINED,
    ) != 0
}

/// The fault: a PUT BEGIN of the named GET's identity at its retained row.
fn retained_frame(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if !retained(world) {
        return 0;
    }
    let get = world.history.learned.expect("the GET's header");
    forge(world, Kind::PutBegin, get.sequence + 100);
    mark(world, RETAINED_FRAME)
}

/// The sibling: the retained row is snapshotted and no frame names it.
fn no_frame(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if !retained(world) {
        return 0;
    }
    world.history.forged = Some(counters(world));
    mark(world, NO_FRAME)
}

/// The sibling's judgment: with no frame, the row and the counter read as they did.
fn retained_kept(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if world.history.forged != Some(counters(world)) {
        return fail(world, Obligation::Contain, MOVED_MORE);
    }
    mark(world, RETAINED_KEPT)
}

const FORGED: [Step; 15] = [
    step("arm", always, arm),
    step("named-get", active_get, old_get),
    step("learn", get_sent, s19_learn),
    step("concurrent-get", active_put, s19_concurrent_get),
    step("reads-held", reads_held, mark_read_held),
    step("live-frame", always, live_frame),
    step("live-counted", s19_counted, mark_counted),
    step("live-checked", always, live_checked),
    step("release-reads", always, release_reads),
    step("named-read", old_decided, s19_read),
    step("concurrent-read", concurrent_decided, s19_concurrent_read),
    step("release-nic", always, release_nic),
    step("retained-frame", get_released, retained_frame),
    step("retained-checked", s19_counted, s19_retained_checked),
    JUDGE,
];

const UNFORGED: [Step; 15] = replaced(
    replaced(
        FORGED,
        "retained-frame",
        step("retained-frame", get_released, no_frame),
    ),
    "retained-checked",
    step("retained-checked", always, retained_kept),
);

const FORGED_JUDGED_UNMOVED: [Step; 15] = replaced(
    FORGED,
    "retained-checked",
    step("retained-checked", s19_counted, retained_kept),
);

const FORGED_PREMISE: &[&str] = &[RETAINED, RETAINED_FRAME];

const FORGED_WITNESSES: &[&str] = &[
    LEARNED,
    LIVE_FRAME,
    COUNTED,
    CONCURRENT,
    LIVE_CHECKED,
    S19_READ,
    S19_CONCURRENT_READ,
    RETAINED,
    RETAINED_FRAME,
    S19_RETAINED_CHECKED,
];

const UNFORGED_WITNESSES: &[&str] = &[
    LEARNED,
    LIVE_FRAME,
    COUNTED,
    CONCURRENT,
    LIVE_CHECKED,
    S19_READ,
    S19_CONCURRENT_READ,
    RETAINED,
    NO_FRAME,
    RETAINED_KEPT,
];

const JUDGED: &[Obligation] = &[Obligation::Contain, Obligation::Bytes];

/// GET budgets: client 0's concurrent GET and client 1's named GET.
const GETS: [u32; 2] = [1, 1];

pub(super) const RETAINED_ROWS: [History; 3] = [
    getting(
        history(
            "rr1-put-begin-at-a-retained-row",
            &FORGED,
            FORGED_WITNESSES,
            JUDGED,
            Expect::Pass,
        ),
        GETS,
    ),
    getting(
        history(
            "rr1-no-frame-at-a-retained-row",
            &UNFORGED,
            UNFORGED_WITNESSES,
            JUDGED,
            Expect::Pass,
        ),
        GETS,
    ),
    control(
        getting(
            history(
                "rr1-put-begin-judged-as-no-frame",
                &FORGED_JUDGED_UNMOVED,
                FORGED_WITNESSES,
                JUDGED,
                Expect::Violation(Obligation::Contain, MOVED_MORE),
            ),
            GETS,
        ),
        FORGED_PREMISE,
    ),
];
