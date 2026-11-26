//! Late-RESULT histories: an upload whose write the device holds past the client's deadline, and one whose
//! write is released before it.
//!
//! An upload whose deadline passes before its RESULT ends `Unknown`, never `Published`, also when the owner
//! receipted every fragment. The rule is `PUBLISHED_EARLY` below, which `narrate/rules.rs` holds.
//!
//! Both histories run one upload of version B, one fragment, under key 1 from the uploading client of the
//! single-owner world, and hold every write command the owner's device accepts. Each waits until the device
//! holds the upload's write and until the client holds the owner's receipt of every fragment, so the client
//! has nothing left to send and awaits the RESULT alone.
//!
//! - `lr1-put-result-late`: the write stays held past the client's deadline. The outcome
//!   is judged at the first step after the deadline at which the client decided, with the write still
//!   pending on the device: no RESULT can exist, so `Unknown` is the only outcome that states what the
//!   client knows. While the write is pending, `Published` violates `PUBLISHED_EARLY` at every accepted
//!   RESULT count. The kill counts only with its premises marked: the hold armed, the write held, every
//!   fragment receipted with the upload undecided, and the write still pending at the judgment.
//! - `lr1-put-result-in-time`: the same steps, but the write is released before
//!   the deadline. The owner publishes and sends its RESULT. The upload must end `Published` with a
//!   RESULT accepted; any other outcome ends the run unsuccessful, since no deadline passed.
//! - `lr1-put-late-as-published` and `lr1-put-late-as-no-effect`: controls over the steps of
//!   `lr1-put-result-late` that judge the timed-out upload as `Published` and as `NotStarted`.
//! - `lr1-put-in-time-unpublished`: a control over the steps of `lr1-put-result-in-time` that judges
//!   the decided upload as `NotStarted` and ends unsuccessful.
//!
//! The hold, the wait for the deadline and the judgment follow `histories/incidents.rs` (`i1-put`), whose
//! own steps are private to that file and hold the transmit references as well.

use super::*;

/// The rule both histories judge.
const PUBLISHED_EARLY: &str = "a timed-out upload claimed publication before its RESULT";

/// The rule of the opposite misstatement, which `narrate/rules.rs` also holds.
const NO_EFFECT: &str = "a timed-out upload claimed no effect after its DATA reached the owner";

const ARMED: &str = "owner write commands held";
const WRITE_HELD: &str = "owner write held";
const RECEIPT: &str = "every fragment receipted, RESULT awaited";
const PENDING: &str = "the write was pending at the judgment";
const EARLY: &str = "the write released before the deadline";
const RELEASED: &str = "the held write released";
const UNKNOWN: &str = "the timed-out upload ended unknown";
const PUBLISHED: &str = "upload published by an accepted RESULT";

/// Marks `witness` when `formed`, and otherwise ends the run unsuccessful under it.
fn premise(world: &mut Mixed<'_, '_, '_>, formed: bool, witness: &'static str) -> u64 {
    if !formed {
        world.first.record(Failure::Unsuccessful(witness));
        return 0;
    }
    mark(world, witness)
}

/// Holds every write command the owner's device accepts from here on. Reads and transmit references run
/// free, so the owner's receipts reach the client.
fn hold_writes(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.hold_writes = true;
    mark(world, ARMED)
}

/// Begins the upload of version B and has the run reach the first microsecond past its deadline.
fn begin(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.deadline = now + super::super::WAIT_US;
    world.history.wake = Some(world.history.deadline + 1);
    put_begin(world, now)
}

/// Fragments of the uploaded object.
fn fragments() -> u32 {
    (VERSION_B_LEN as u32).div_ceil(FRAGMENT_LEN)
}

/// The client holds the owner's cumulative receipt of every fragment.
fn every_fragment_receipted(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world
        .history
        .put
        .and_then(|id| world.scene.clients[0].put_receipt(id))
        .is_some_and(|(_, base, _)| base >= fragments())
}

/// The receipt is a premise only while the upload is undecided: the client then awaits its RESULT.
fn receipt(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    let undecided = world.scene.clients[0].put_outcome(id).is_none();
    premise(world, undecided, RECEIPT)
}

/// Every write the history held is still pending on the device, and there is one.
fn write_pending(world: &Mixed<'_, '_, '_>) -> bool {
    !world.history.writes.is_empty() && writes_pending(world)
}

fn release_writes(world: &mut Mixed<'_, '_, '_>) {
    world.history.hold_writes = false;
    for token in std::mem::take(&mut world.history.writes) {
        world.scene.control.release(token);
    }
}

fn deadline_passed(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    now > world.history.deadline
}

/// The history requires `Unknown` because the write is still pending at the judgment.
fn judge_outcome(world: &mut Mixed<'_, '_, '_>, outcome: UploadOutcome) -> u64 {
    match outcome {
        UploadOutcome::Published => fail(world, Obligation::History, PUBLISHED_EARLY),
        UploadOutcome::Unknown => mark(world, UNKNOWN),
        UploadOutcome::NotStarted | UploadOutcome::Failed(_) => {
            fail(world, Obligation::History, NO_EFFECT)
        }
    }
}

/// The scenario's judgment: past the deadline, once the client decided, with the write still pending.
fn judged_while_held(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    let Some(outcome) = world.collect_put(id) else {
        return STAY;
    };
    let pending = write_pending(world);
    if premise(world, pending, PENDING) == 0 {
        return 0;
    }
    judge_outcome(world, outcome)
}

/// The control supplies `Published` as the timed-out upload's outcome.
fn held_as_published(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    judged_while_held_as(world, now, UploadOutcome::Published)
}

/// A control: the timed-out upload is judged as `NotStarted`, after the owner receipted its DATA.
fn held_as_no_effect(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    judged_while_held_as(world, now, UploadOutcome::NotStarted)
}

/// Collects the decided upload and judges `outcome` in its place, under the scenario's premise.
fn judged_while_held_as(world: &mut Mixed<'_, '_, '_>, _: u64, outcome: UploadOutcome) -> u64 {
    let id = world.history.put.expect("a PUT");
    if world.collect_put(id).is_none() {
        return STAY;
    }
    let pending = write_pending(world);
    if premise(world, pending, PENDING) == 0 {
        return 0;
    }
    judge_outcome(world, outcome)
}

/// Releases the held write after the judgment, so the run ends with no command held.
fn release_late(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    release_writes(world);
    mark(world, RELEASED)
}

/// The sibling releases the write while the upload is undecided and its deadline is ahead.
fn release_early(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    let ahead = now < world.history.deadline
        && world.scene.clients[0].put_outcome(id).is_none()
        && write_pending(world);
    release_writes(world);
    premise(world, ahead, EARLY)
}

/// The sibling's premise, once the client decided before its deadline: the upload is `Published` and
/// the client accepted a RESULT. The timeout rules judge a timed-out upload only, so any other outcome
/// ends the run unsuccessful.
fn judge_in_time(world: &mut Mixed<'_, '_, '_>, outcome: UploadOutcome) -> u64 {
    let backed = world.scene.clients[0].put_results() > 0;
    let published = matches!(outcome, UploadOutcome::Published) && backed;
    premise(world, published, PUBLISHED)
}

fn judged_when_decided(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    match world.collect_put(id) {
        Some(outcome) => judge_in_time(world, outcome),
        None => STAY,
    }
}

/// A control: the sibling's decided upload is judged as `NotStarted`.
fn decided_as_unpublished(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    match world.collect_put(id) {
        Some(_) => judge_in_time(world, UploadOutcome::NotStarted),
        None => STAY,
    }
}

const TIMED_OUT: [Step; 9] = [
    step("hold-writes", always, hold_writes),
    step("put-begin", active_put, begin),
    step("put-prepare", always, put_prepare),
    step("put-supply", always, put_supply),
    step("write-held", write_held, mark_write_held),
    step("receipt", every_fragment_receipted, receipt),
    step("deadline", deadline_passed, judged_while_held),
    step("release", always, release_late),
    JUDGE,
];

const RELEASED_IN_TIME: [Step; 9] = [
    step("hold-writes", always, hold_writes),
    step("put-begin", active_put, begin),
    step("put-prepare", always, put_prepare),
    step("put-supply", always, put_supply),
    step("write-held", write_held, mark_write_held),
    step("receipt", every_fragment_receipted, receipt),
    step("release", always, release_early),
    step("decided", put_decided, judged_when_decided),
    JUDGE,
];

const LATE_AS_PUBLISHED: [Step; 9] = replaced(
    TIMED_OUT,
    "deadline",
    step("deadline-as-published", deadline_passed, held_as_published),
);

const LATE_AS_NO_EFFECT: [Step; 9] = replaced(
    TIMED_OUT,
    "deadline",
    step("deadline-as-no-effect", deadline_passed, held_as_no_effect),
);

const IN_TIME_UNPUBLISHED: [Step; 9] = replaced(
    RELEASED_IN_TIME,
    "decided",
    step(
        "decided-as-unpublished",
        put_decided,
        decided_as_unpublished,
    ),
);

const TIMED_OUT_WITNESSES: &[&str] = &[
    ARMED,
    "upload begun",
    "upload prepared",
    "upload DATA supplied",
    WRITE_HELD,
    RECEIPT,
    PENDING,
    UNKNOWN,
    RELEASED,
];

const RELEASED_IN_TIME_WITNESSES: &[&str] = &[
    ARMED,
    "upload begun",
    "upload prepared",
    "upload DATA supplied",
    WRITE_HELD,
    RECEIPT,
    EARLY,
    PUBLISHED,
];

/// The marks a kill of the rule needs: the hold armed, the write held, every fragment receipted with the
/// upload undecided, and the write still pending when the outcome was judged.
const TIMED_OUT_PREMISE: &[&str] = &[ARMED, WRITE_HELD, RECEIPT, PENDING];

const RELEASED_IN_TIME_PREMISE: &[&str] = &[ARMED, WRITE_HELD, RECEIPT, EARLY];

const JUDGED: &[Obligation] = &[Obligation::History];

pub(super) const CHECKS: [(&str, Obligation); 2] = [
    (UNKNOWN, Obligation::History),
    (PUBLISHED, Obligation::History),
];

const fn late_result(
    name: &'static str,
    script: &'static [Step],
    witnesses: &'static [&'static str],
    expect: Expect,
    premise: &'static [&'static str],
) -> History {
    control(
        uploading(history(name, script, witnesses, JUDGED, expect), 1),
        premise,
    )
}

pub(super) const LATE_RESULTS: [History; 5] = [
    late_result(
        "lr1-put-result-late",
        &TIMED_OUT,
        TIMED_OUT_WITNESSES,
        Expect::Pass,
        TIMED_OUT_PREMISE,
    ),
    late_result(
        "lr1-put-result-in-time",
        &RELEASED_IN_TIME,
        RELEASED_IN_TIME_WITNESSES,
        Expect::Pass,
        RELEASED_IN_TIME_PREMISE,
    ),
    late_result(
        "lr1-put-late-as-published",
        &LATE_AS_PUBLISHED,
        TIMED_OUT_WITNESSES,
        Expect::Violation(Obligation::History, PUBLISHED_EARLY),
        TIMED_OUT_PREMISE,
    ),
    late_result(
        "lr1-put-late-as-no-effect",
        &LATE_AS_NO_EFFECT,
        TIMED_OUT_WITNESSES,
        Expect::Violation(Obligation::History, NO_EFFECT),
        TIMED_OUT_PREMISE,
    ),
    late_result(
        "lr1-put-in-time-unpublished",
        &IN_TIME_UNPUBLISHED,
        RELEASED_IN_TIME_WITNESSES,
        Expect::Unsuccessful(PUBLISHED),
        RELEASED_IN_TIME_PREMISE,
    ),
];
