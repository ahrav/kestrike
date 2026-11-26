//! Incident histories and their controls.

use super::*;

use super::super::super::frame::{Kind, Status, retry_wait};
use super::super::super::observe::UNCHECKED_RECORD;
use super::super::super::owner_tests::client_config;
use super::super::super::rules::{Chain, Effect, MANIFEST, Rule, Selector};
pub(crate) mod descending;
pub(super) mod unknowns;
use crate::storage::device::sim::Unwind;

const EXPIRY_S: u64 = 1;

const NANOS: u64 = 1_000_000_000;

fn publish_expiring(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let fill = world.history.fill.take().expect("a written fill");
    let deadline = (ticks(now) / NANOS + EXPIRY_S + 1) * NANOS;
    world.history.deadline = deadline;
    match world
        .scene
        .owner
        .publish_fill(fill, deadline, 2, &mut budget())
    {
        Ok(_) => {
            world.owner_due = now;
            mark(world, "replacement published with a finite expiry")
        }
        Err(_) => fail(
            world,
            Obligation::Progress,
            "the replacement never published",
        ),
    }
}

fn hold_clock_now(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if ticks(now) >= world.history.deadline {
        return fail(
            world,
            Obligation::History,
            "the held sample began at or past the deadline",
        );
    }
    world.history.clock = Some(ticks(now));
    world.history.wake = Some(world.history.deadline / 1_000 + 1);
    mark(world, "owner clock held below the deadline")
}

fn hold_clock_deadline(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.clock = Some(world.history.deadline);
    mark(world, "owner clock held at the deadline")
}

fn hold_clock_below(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.clock = Some(world.history.deadline - 1);
    mark(world, "owner clock held one tick below the deadline")
}

fn release_clock(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.clock = None;
    mark(world, "owner clock released")
}

/// The uploading client's session is active and the owner holds no request
/// of its peer.
pub(super) fn uploader_idle(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    let census = world.scene.owner.peer_census(PeerId(0));
    active_put(world, now) && census.active + census.draining == 0
}

fn past_deadline(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    ticks(now) > world.history.deadline
}

fn samples_projected(world: &Mixed<'_, '_, '_>) -> bool {
    world
        .clocks
        .iter()
        .all(|clock| clock.last == Some(clock.projection))
}

fn check_samples(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if !samples_projected(world) {
        return fail(
            world,
            Obligation::History,
            "an owner turn sampled a tick other than its projection",
        );
    }
    mark(world, "actor samples equal their projections")
}

fn served_under_held(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let (outcome, bytes) = fresh_result(world);
    if outcome != Some(Outcome::Complete) || bytes != version_b() {
        return fail(
            world,
            Obligation::Bytes,
            "a sample below the deadline missed the live version",
        );
    }
    mark(world, "a held sample served before its expiry")
}

fn missed_expired(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let (outcome, bytes) = fresh_result(world);
    if outcome != Some(Outcome::Missing) || !bytes.is_empty() {
        return fail(
            world,
            Obligation::History,
            "a GET at its expiry sample served the version",
        );
    }
    mark(world, "a sample at the deadline missed")
}

fn stayed_missing(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if missed_expired(world, now) == 0 {
        return 0;
    }
    mark(world, "the expired version stayed missing")
}

/// I1 for GET: under an owner clock held below the deadline, a GET after
/// the deadline in world time reads the replacement exactly; under a clock
/// held at the deadline, and once the clock follows world time again, a
/// GET misses.
const I1_GET: [Step; 15] = [
    step("fill-replacement", always, fill_b),
    step("publish-expiring", fill_written, publish_expiring),
    step("hold-clock", always, hold_clock_now),
    step("past-deadline-get", past_deadline, fresh_get),
    step("held-read", fresh_decided, served_under_held),
    step("hold-at-deadline", always, hold_clock_deadline),
    step("deadline-get", uploader_idle, fresh_get),
    step("deadline-read", fresh_decided, missed_expired),
    step("unrelated-get", active_get, unrelated_get),
    step("unrelated-read", old_decided, unrelated_read),
    step("release-clock", always, release_clock),
    step("qualified-get", uploader_idle, fresh_get),
    step("qualified-read", fresh_decided, stayed_missing),
    step("samples", always, check_samples),
    JUDGE,
];

const I1_GET_EQUALITY: [Step; 15] = replaced(
    I1_GET,
    "hold-at-deadline",
    step("hold-below-deadline", always, hold_clock_below),
);

const I1_WITNESSES: &[&str] = &[
    "replacement published with a finite expiry",
    "owner clock held below the deadline",
    "a held sample served before its expiry",
    "owner clock held at the deadline",
    "a sample at the deadline missed",
    "owner clock released",
    "the expired version stayed missing",
    "actor samples equal their projections",
    "unrelated work progressed",
];

fn note_sources(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.refs = withheld(world);
    allow(world, version_a());
    mark(world, "upload DATA held by the device")
}

fn note_write(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.wake = Some(world.history.since + super::super::WAIT_US + 1);
    mark(world, "owner write held")
}

fn put_deadline_passed(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    now > world.history.since + super::super::WAIT_US
}

fn deadline_kept(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    let outcome = world.collect_put(id);
    judge_deadline(world, outcome)
}

fn deadline_recycled(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    for net in &world.scene.nets {
        net.borrow_mut().release_tx();
    }
    deadline_kept(world, now)
}

fn deadline_no_effect(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    judge_deadline(world, Some(UploadOutcome::NotStarted))
}

/// A control: the client reports publication at its deadline while the
/// owner's write is still held, before any RESULT could have reached it.
fn deadline_published(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    judge_deadline(world, Some(UploadOutcome::Published))
}

/// The source and write are still held at the release, after the unrelated
/// work's polls of the uploading client; then every hold releases.
fn kept_then_release(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let kept = source_kept(&world.scene.clients[0], &version_b());
    if withheld(world) < world.history.refs || !writes_pending(world) || !kept {
        return fail(
            world,
            Obligation::Custody,
            "a deadline recycled sources the device still held",
        );
    }
    release_everything(world, now)
}

fn source_kept<'m>(
    client: &super::super::super::client::Client<'m, super::super::super::link::LinkEnd<'m>>,
    object: &[u8],
) -> bool {
    client
        .sources()
        .iter()
        .any(|slot| slot.piece().is_some() && slot.bytes() == object)
}

/// Judges the upload's outcome at its deadline, while the owner's write and
/// the NIC's DATA references are still held: no RESULT can have reached the
/// client, so the only outcome the client may hold is `Unknown`.
fn judge_deadline(world: &mut Mixed<'_, '_, '_>, outcome: Option<UploadOutcome>) -> u64 {
    match outcome {
        None => return STAY,
        Some(UploadOutcome::NotStarted | UploadOutcome::Failed(_)) => {
            return fail(
                world,
                Obligation::History,
                "a timed-out upload claimed no effect after its DATA reached the owner",
            );
        }
        Some(UploadOutcome::Published) => {
            return fail(
                world,
                Obligation::History,
                "a timed-out upload claimed publication before its RESULT",
            );
        }
        Some(UploadOutcome::Unknown) => {}
    }
    let kept = source_kept(&world.scene.clients[0], &version_b());
    if withheld(world) < world.history.refs || !writes_pending(world) || !kept {
        return fail(
            world,
            Obligation::Custody,
            "a deadline recycled sources the device still held",
        );
    }
    mark(world, "the client deadline passed with the write held")
}

fn judge_actual(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    let outcome = world.collect_put(id);
    world.history.allowed = match outcome {
        Some(UploadOutcome::Published) => vec![version_b()],
        Some(UploadOutcome::Unknown) => {
            let _ = world.scene.clients[0].abandon(id);
            vec![version_a(), version_b()]
        }
        Some(UploadOutcome::Failed(_)) => vec![version_a()],
        _ => {
            return fail(
                world,
                Obligation::History,
                "a timed-out upload claimed no effect after its DATA reached the owner",
            );
        }
    };
    let _ = world.scene.clients[0].retire(id);
    mark(world, "the upload's actual outcome judged")
}

pub(super) fn actual_exact(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let (outcome, bytes) = fresh_result(world);
    judge_exact(world, outcome, &bytes)
}

fn judge_exact(world: &mut Mixed<'_, '_, '_>, outcome: Option<Outcome>, bytes: &[u8]) -> u64 {
    if outcome != Some(Outcome::Complete) || !world.history.allowed.iter().any(|v| v == bytes) {
        return fail(
            world,
            Obligation::Bytes,
            "a GET disagreed with the upload's judged outcome",
        );
    }
    mark(world, "the GET agreed with the upload's outcome");
    mark(world, "qualified exact read")
}

/// Every `allowed` set `judge_actual` writes holds `version_a()`,
/// `version_b()` or both, so the control's `version_c()` fails `judge_exact`.
fn exact_against_other(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let _ = fresh_result(world);
    judge_exact(world, Some(Outcome::Complete), &version_c())
}

const I1_PUT: [Step; 14] = [
    step("arm", always, arm_nic_writes),
    step("put-begin", active_put, put_begin),
    step("put-prepare", always, put_prepare),
    step("put-supply", always, put_supply),
    step("source-held", sources_withheld, note_sources),
    step("write-held", write_held, note_write),
    step("deadline-passed", put_deadline_passed, deadline_kept),
    step("unrelated-get", active_get, unrelated_get),
    step("unrelated-read", old_decided, unrelated_read),
    step("resume", always, kept_then_release),
    step("decided", put_decided, judge_actual),
    step("qualified-get", uploader_idle, fresh_get),
    step("qualified-read", fresh_decided, actual_exact),
    JUDGE,
];

const I1_PUT_RECYCLED: [Step; 14] = replaced(
    I1_PUT,
    "deadline-passed",
    step("deadline-recycled", put_deadline_passed, deadline_recycled),
);

const I1_PUT_NO_EFFECT: [Step; 14] = replaced(
    I1_PUT,
    "deadline-passed",
    step(
        "deadline-no-effect",
        put_deadline_passed,
        deadline_no_effect,
    ),
);

const I1_PUT_PUBLISHED: [Step; 14] = replaced(
    I1_PUT,
    "deadline-passed",
    step(
        "deadline-published",
        put_deadline_passed,
        deadline_published,
    ),
);

const I1_PUT_DISAGREED: [Step; 14] = replaced(
    I1_PUT,
    "qualified-read",
    step("qualified-read-other", fresh_decided, exact_against_other),
);

const I1_PUT_WITNESSES: &[&str] = &[
    "upload DATA supplied",
    "upload DATA held by the device",
    "owner write held",
    "the client deadline passed with the write held",
    "the upload's actual outcome judged",
    "qualified exact read",
    "unrelated work progressed",
    "the GET agreed with the upload's outcome",
];

const I1_PUT_PREMISE: &[&str] = &["upload DATA held by the device", "owner write held"];

pub(super) const CLIENT: usize = 0;
const OWNER_SIDE: usize = 1;

pub(super) fn set_rules(world: &mut Mixed<'_, '_, '_>, rules: Vec<Rule>) {
    let taps = [rules.len()];
    let chain = Chain::new(rules, &taps, &MANIFEST).expect("a bounded chain");
    world.scene.nets[0].borrow_mut().set_rules(chain);
}

pub(super) fn clear_rules(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.results += captured(world, Kind::PutResult, false);
    let tap = Chain::new(Vec::new(), &[0], &MANIFEST).expect("a bounded chain");
    world.scene.nets[0].borrow_mut().set_rules(tap);
    mark(world, "the link's rules cleared")
}

pub(super) fn captured(world: &Mixed<'_, '_, '_>, kind: Kind, dropped: bool) -> usize {
    world.scene.nets[0]
        .borrow()
        .rules()
        .captures()
        .iter()
        .filter(|capture| capture.kind == Some(kind) && capture.decision.drop.is_some() == dropped)
        .count()
}

fn drop_final_data(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let last = fragments() - 1;
    let selector = Selector::All(vec![
        Selector::Kind(Kind::Data),
        Selector::Toward(CLIENT),
        Selector::Fragments { first: last, last },
    ]);
    set_rules(world, vec![Rule::new(selector, Effect::Drop).window(0, 1)]);
    mark(world, "the final DATA drop armed")
}

/// A control: every final DATA toward the client is dropped, so the GET
/// can never complete.
fn drop_every_final_data(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let last = fragments() - 1;
    let selector = Selector::All(vec![
        Selector::Kind(Kind::Data),
        Selector::Toward(CLIENT),
        Selector::Fragments { first: last, last },
    ]);
    set_rules(world, vec![Rule::new(selector, Effect::Drop)]);
    mark(world, "the final DATA drop armed")
}

pub(super) fn drop_complete(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let selector = Selector::All(vec![
        Selector::Kind(Kind::Complete),
        Selector::Toward(CLIENT),
    ]);
    set_rules(world, vec![Rule::new(selector, Effect::Drop).window(0, 1)]);
    mark(world, "the COMPLETE drop armed")
}

/// The GET after the one dropped final frame completes with the object's
/// exact bytes: the loss is recovered, never surfaced as a failure or a
/// prefix.
pub(super) fn long_exact(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let (outcome, bytes) = fresh_result(world);
    if outcome != Some(Outcome::Complete) {
        return fail(
            world,
            Obligation::Bytes,
            "a GET after a lost final frame ended without the object",
        );
    }
    if bytes != long_b() {
        return fail(
            world,
            Obligation::Bytes,
            "a GET after a lost final frame reported bytes other than the object's",
        );
    }
    mark(world, "the GET after the loss ended exactly")
}

fn lost(world: &mut Mixed<'_, '_, '_>, kind: Kind, witness: &'static str) -> u64 {
    if captured(world, kind, true) == 0 {
        return 1;
    }
    mark(world, witness)
}

fn data_lost(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    lost(world, Kind::Data, "the final DATA was lost")
}

fn complete_lost(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    lost(world, Kind::Complete, "the COMPLETE was lost")
}

fn publish_long(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    allow(world, long_b());
    publish_fill(world, now)
}

const I3_GET_DATA: [Step; 11] = [
    step("fill-long", always, fill_long),
    step("publish-long", fill_written, publish_long),
    step("release-lease", always, release_reads),
    step("arm-drop", always, drop_final_data),
    step("lossy-get", active_put, fresh_get),
    step("peer-get", active_get, unrelated_get),
    step("lossy-read", fresh_decided, long_exact),
    step("lost", always, data_lost),
    step("peer-read", old_decided, unrelated_read),
    step("clear", always, clear_rules),
    JUDGE,
];

const I3_GET_COMPLETE: [Step; 11] = replaced(
    replaced(
        I3_GET_DATA,
        "arm-drop",
        step("arm-drop", always, drop_complete),
    ),
    "lost",
    step("lost", always, complete_lost),
);

const I3_GET_DATA_NEVER_RESENT: [Step; 11] = replaced(
    I3_GET_DATA,
    "arm-drop",
    step("arm-drop", always, drop_every_final_data),
);

const I3_DATA_WITNESSES: &[&str] = &[
    "the final DATA drop armed",
    "the GET after the loss ended exactly",
    "the final DATA was lost",
    "unrelated work progressed",
];

const I3_COMPLETE_WITNESSES: &[&str] = &[
    "the COMPLETE drop armed",
    "the GET after the loss ended exactly",
    "the COMPLETE was lost",
    "unrelated work progressed",
];

fn prepare_len(world: &mut Mixed<'_, '_, '_>, body: usize) -> u64 {
    let id = world.history.put.expect("a PUT");
    match world.scene.clients[0].prepare(id, 0, body as u32, super::super::TTL_MS) {
        Ok(()) => mark(world, "upload prepared"),
        Err(_) => STAY,
    }
}

pub(super) fn long_prepare(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    prepare_len(world, LONG_B_LEN)
}

pub(super) fn long_begin(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.fragment = 0;
    world.history.allowed = vec![version_a(), long_b()];
    world.history.deadline = now + super::super::WAIT_US + RETENTION_US;
    world.history.wake = Some(world.history.deadline + 1);
    put_begin_with(world, CacheVersion(0), long_b(), LABEL_B, now)
}

/// Microseconds the owner keeps a finished upload's result past the later
/// of its deadline and its end.
pub(super) const RETENTION_US: u64 = super::super::OWNER.serve.linger_us;

pub(super) fn past_retention(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    now > world.history.deadline
}

pub(super) fn delay_results(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let result = Selector::All(vec![
        Selector::Kind(Kind::PutResult),
        Selector::Toward(CLIENT),
    ]);
    let turns = super::super::WAIT_US / super::super::LINK_TURN_US;
    set_rules(world, vec![Rule::new(result, Effect::Delay(turns))]);
    mark(world, "a RESULT delay armed")
}

pub(super) fn went_unknown(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world
        .history
        .put
        .is_some_and(|id| world.scene.clients[0].put_outcome(id) == Some(UploadOutcome::Unknown))
}

pub(super) fn mark_unknown(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.results_received = world.scene.clients[0].put_results();
    mark(world, "the upload went unknown before its RESULT arrived")
}

/// The delayed RESULT has reached the client: its uploads accepted a RESULT
/// frame after the upload went unknown.
pub(super) fn result_received(world: &Mixed<'_, '_, '_>) -> bool {
    world.scene.clients[0].put_results() > world.history.results_received
}

pub(super) fn resolved_or_late(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    result_received(world) || past_retention(world, now)
}

fn resolved(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    let outcome = world.collect_put(id);
    judge_resolved(world, outcome)
}

fn left_unknown(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    judge_resolved(world, Some(UploadOutcome::Unknown))
}

/// A control: the client reports publication on a timer before the
/// delayed RESULT reaches it.
fn resolved_early(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    judge_resolved(world, Some(UploadOutcome::Published))
}

pub(super) fn judge_resolved(world: &mut Mixed<'_, '_, '_>, outcome: Option<UploadOutcome>) -> u64 {
    if !result_received(world) {
        return fail(
            world,
            Obligation::History,
            "an upload resolved its unknown outcome before its RESULT was received",
        );
    }
    if outcome != Some(UploadOutcome::Published) {
        return fail(
            world,
            Obligation::History,
            "a delayed matching RESULT left the unknown upload unresolved",
        );
    }
    world.history.allowed = vec![long_b()];
    mark(
        world,
        "a later matching RESULT resolved the unknown outcome",
    )
}

pub(super) fn long_supply(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    let object = long_b();
    let count = (object.len() as u32).div_ceil(FRAGMENT_LEN);
    while world.history.fragment < count {
        let at = (world.history.fragment * FRAGMENT_LEN) as usize;
        let end = object.len().min(at + FRAGMENT_LEN as usize);
        if world.scene.clients[0]
            .supply(id, world.history.fragment, &object[at..end])
            .is_err()
        {
            return STAY;
        }
        world.history.fragment += 1;
    }
    mark(world, "upload DATA supplied")
}

fn lost_middle() -> Rule {
    let lost = Selector::All(vec![
        Selector::Kind(Kind::PutData),
        Selector::Toward(OWNER_SIDE),
        Selector::Fragments { first: 1, last: 1 },
    ]);
    Rule::new(lost, Effect::Drop).window(0, 1)
}

fn drop_middle_fragment(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    set_rules(world, vec![lost_middle()]);
    mark(world, "a fragment drop armed")
}

fn duplicate_fragments(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let data = Selector::All(vec![
        Selector::Kind(Kind::PutData),
        Selector::Toward(OWNER_SIDE),
    ]);
    set_rules(
        world,
        vec![lost_middle(), Rule::new(data, Effect::Duplicate)],
    );
    mark(world, "a fragment drop armed");
    mark(world, "every fragment duplicated")
}

fn drop_results(world: &mut Mixed<'_, '_, '_>, take: u32) -> u64 {
    let result = Selector::All(vec![
        Selector::Kind(Kind::PutResult),
        Selector::Toward(CLIENT),
    ]);
    set_rules(world, vec![Rule::new(result, Effect::Drop).window(0, take)]);
    mark(world, "a RESULT drop armed")
}

pub(super) fn drop_one_result(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    drop_results(world, 1)
}

pub(super) fn drop_every_result(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    drop_results(world, u32::MAX)
}

fn fragment_dropped(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    captured(world, Kind::PutData, true) > 0
}

pub(crate) const LOST_SOURCE_RELEASED: &str =
    "a lost fragment's source was released before its receipt";

/// A lost fragment retains its source bytes for resends until the cumulative
/// receipt covers it. The witness needs an observed hold: a turn before the
/// receipt that saw the source held, or a source still held after it. A first
/// turn after the release observes no hold and advances unmarked.
fn lost_source_held(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let object = long_b();
    let at = FRAGMENT_LEN as usize;
    let lost = &object[at..object.len().min(2 * at)];
    let held = source_kept(&world.scene.clients[0], lost);
    if receipt_base(world) >= 2 {
        if !held && !world.history.lost_held {
            return 1;
        }
        return mark(world, "the lost fragment's source stayed held");
    }
    if !held {
        return fail(world, Obligation::Custody, LOST_SOURCE_RELEASED);
    }
    world.history.lost_held = true;
    STAY
}

fn mark_hole(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    lost(world, Kind::PutData, "a fragment was lost before its ACK")
}

/// Judges the upload's outcome against the RESULT frames its client
/// received, so publication is credited only once a RESULT reached the
/// client, not once the owner sent one.
fn judge_result(world: &mut Mixed<'_, '_, '_>, outcome: Option<UploadOutcome>) -> u64 {
    let received = world.scene.clients[0].put_results();
    let dropped = captured(world, Kind::PutResult, true);
    match outcome {
        Some(UploadOutcome::Published) if received == 0 => fail(
            world,
            Obligation::History,
            "an upload claimed publication without a delivered RESULT",
        ),
        Some(UploadOutcome::Published) => {
            if dropped > 0 {
                mark(world, "a retained RESULT replayed after a lost one");
            }
            world.history.allowed = vec![long_b()];
            mark(world, "upload published")
        }
        Some(UploadOutcome::Unknown) => {
            world.history.allowed = vec![version_a(), long_b()];
            mark(world, "the upload went unknown before its RESULT arrived")
        }
        _ => fail(
            world,
            Obligation::History,
            "a lost RESULT ended the upload as a failure",
        ),
    }
}

pub(super) fn result_judged(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    let outcome = world.collect_put(id);
    judge_result(world, outcome)
}

pub(super) fn later_outcome(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    let outcome = world.collect_put(id);
    judge_later(world, outcome)
}

fn later_invented(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    judge_later(world, Some(UploadOutcome::Published))
}

/// If `world.plan.premise` lists `upload published` and the mark is missing,
/// `fail` records `Failure::Unsuccessful` for the first missing premise.
/// After the mark the upload's outcome is known, so the `Unknown` handed to
/// `judge_later` is a regression from a known outcome.
fn later_regressed(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if !world.history.marks.contains(&"upload published") {
        return fail(
            world,
            Obligation::History,
            "a known upload outcome regressed",
        );
    }
    judge_later(world, Some(UploadOutcome::Unknown))
}

fn judge_later(world: &mut Mixed<'_, '_, '_>, outcome: Option<UploadOutcome>) -> u64 {
    let id = world.history.put.expect("a PUT");
    if outcome == Some(UploadOutcome::Unknown) {
        mark(world, "the upload stayed unknown after its RESULT evidence");
    }
    let _ = world.scene.clients[0].abandon(id);
    let _ = world.scene.clients[0].retire(id);
    let delivered = world.history.results + captured(world, Kind::PutResult, false);
    let earlier = world.history.allowed.len() == 1;
    if outcome == Some(UploadOutcome::Published) && delivered == 0 {
        return fail(
            world,
            Obligation::History,
            "an upload resolved its unknown outcome without a matching RESULT",
        );
    }
    if earlier && outcome != Some(UploadOutcome::Published) {
        return fail(
            world,
            Obligation::History,
            "a known upload outcome regressed",
        );
    }
    mark(world, "the upload's outcome stayed consistent")
}

fn result_as_published(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    judge_result(world, Some(UploadOutcome::Published))
}

fn result_as_failed(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    judge_result(world, Some(UploadOutcome::Failed(Status::DeviceError)))
}

fn receipt_base(world: &Mixed<'_, '_, '_>) -> u32 {
    world
        .history
        .put
        .and_then(|id| world.scene.clients[0].put_receipt(id))
        .map_or(0, |(_, base, _)| base)
}

fn fragments() -> u32 {
    (LONG_B_LEN as u32).div_ceil(FRAGMENT_LEN)
}

fn credit_bounded(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    judge_credit(world, |ack| ack.base)
}

/// One PUT ACK the owner sent toward the client, beside the PUT DATA the
/// link had carried toward the owner before it.
struct Acked {
    /// The cumulative receipt base the ACK carried.
    base: u32,
    /// The cumulative grant the ACK carried.
    grant: u32,
    /// The contiguous PUT DATA fragment prefix carried before the ACK, which
    /// bounds a correct owner's receipt base.
    prefix: u32,
    copies: u32,
}

/// The upload's ACKs in link order.
fn acks(world: &Mixed<'_, '_, '_>) -> Vec<Acked> {
    let net = world.scene.nets[0].borrow();
    let mut captures: Vec<_> = net.rules().captures().to_vec();
    captures.sort_by_key(|capture| capture.ordinal);
    let mut carried = vec![false; fragments() as usize];
    let mut copies = 0;
    let mut acks = Vec::new();
    for capture in &captures {
        match capture.kind {
            Some(Kind::PutData)
                if capture.toward == OWNER_SIDE && capture.decision.drop.is_none() =>
            {
                if let Some(seen) = capture
                    .index
                    .and_then(|index| carried.get_mut(index as usize))
                {
                    *seen = true;
                }
                copies += 1 + u32::from(capture.decision.duplicate);
            }
            Some(Kind::PutAck) if capture.toward == CLIENT => {
                let prefix = carried.iter().position(|seen| !seen);
                acks.push(Acked {
                    base: capture.index.unwrap_or(0),
                    grant: capture.grant.unwrap_or(0),
                    prefix: prefix.map_or(fragments(), |at| at as u32),
                    copies,
                });
            }
            _ => {}
        }
    }
    acks
}

/// A control: the receipt an owner that credits every carried copy as a
/// new fragment would acknowledge.
fn credit_counted(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    judge_credit(world, |ack| ack.copies.min(fragments()))
}

/// Counting copies as fragments raises the base above the prefix only at an
/// ACK with `prefix < fragments()` and `copies > prefix`, so the witness
/// needs such an ACK. Each ACK's grant stays within the owner's window past
/// the fragments the link carried, and within the object.
fn judge_credit(world: &mut Mixed<'_, '_, '_>, receipt: fn(&Acked) -> u32) -> u64 {
    let acks = acks(world);
    let window = super::super::OWNER.caps.window;
    if acks
        .iter()
        .any(|ack| receipt(ack) > ack.prefix || ack.grant > (ack.prefix + window).min(fragments()))
    {
        return fail(
            world,
            Obligation::Resources,
            "a duplicate fragment created credit",
        );
    }
    let exposed = acks
        .iter()
        .any(|ack| ack.prefix < fragments() && ack.copies > ack.prefix);
    let duplicated = world.scene.nets[0]
        .borrow()
        .rules()
        .captures()
        .iter()
        .any(|capture| capture.kind == Some(Kind::PutData) && capture.decision.duplicate);
    if !exposed || !duplicated {
        return 1;
    }
    mark(world, "duplicates granted no extra credit")
}

pub(super) fn long_acked(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    receipt_base(world) >= fragments()
}

const I3_PUT_HOLE: [Step; 16] = [
    step("arm-drop", always, drop_middle_fragment),
    step("put-begin", active_put, long_begin),
    step("put-prepare", always, long_prepare),
    step("put-supply", always, long_supply),
    step("unrelated-get", active_get, unrelated_get),
    step("lost-held", fragment_dropped, lost_source_held),
    step("receipt", long_acked, mark_receipt),
    step("hole", always, mark_hole),
    step("unrelated-read", old_decided, unrelated_read),
    step("put-result", put_decided, result_judged),
    step("clear", always, clear_rules),
    step("later", past_retention, later_outcome),
    step("qualified-get", uploader_idle, fresh_get),
    step("qualified-read", fresh_decided, actual_exact),
    step("pad", always, removed_step),
    JUDGE,
];

const I3_PUT_DUPLICATE: [Step; 16] = replaced(
    replaced(
        replaced(
            I3_PUT_HOLE,
            "lost-held",
            step("lost-held", always, removed_step),
        ),
        "arm-drop",
        step("arm-duplicate", always, duplicate_fragments),
    ),
    "hole",
    step("credit", always, credit_bounded),
);

const I3_PUT_DUPLICATE_CREDIT: [Step; 16] = replaced(
    I3_PUT_DUPLICATE,
    "credit",
    step("credit-counted", always, credit_counted),
);

const I3_PUT_RETRY: [Step; 16] = replaced(
    replaced(
        replaced(
            I3_PUT_HOLE,
            "lost-held",
            step("lost-held", always, removed_step),
        ),
        "arm-drop",
        step("arm-drop", always, drop_one_result),
    ),
    "hole",
    step("no-hole", always, removed_step),
);

/// A control: the client reports publication at its receipt, before any
/// RESULT has reached it.
const I3_PUT_RETRY_EARLY: [Step; 16] = replaced(
    I3_PUT_RETRY,
    "put-result",
    step("put-result-early", long_acked, result_as_published),
);

const I3_PUT_RETRY_FAILED: [Step; 16] = replaced(
    I3_PUT_RETRY,
    "put-result",
    step("put-result-failed", put_decided, result_as_failed),
);

const I3_PUT_RETRY_REGRESSED: [Step; 16] = replaced(
    I3_PUT_RETRY,
    "later",
    step("later-regressed", past_retention, later_regressed),
);

const I3_PUT_BEYOND: [Step; 13] = [
    step("arm-drop", always, drop_every_result),
    step("put-begin", active_put, long_begin),
    step("put-prepare", always, long_prepare),
    step("put-supply", always, long_supply),
    step("unrelated-get", active_get, unrelated_get),
    step("receipt", long_acked, mark_receipt),
    step("unrelated-read", old_decided, unrelated_read),
    step("put-result", put_decided, result_judged),
    step("clear", always, clear_rules),
    step("later", past_retention, later_outcome),
    step("qualified-get", uploader_idle, fresh_get),
    step("qualified-read", fresh_decided, actual_exact),
    JUDGE,
];

const I3_PUT_INVENTED: [Step; 13] = replaced(
    I3_PUT_BEYOND,
    "later",
    step("later-invented", past_retention, later_invented),
);

const I3_PUT_LATE: [Step; 16] = replaced(
    replaced(
        replaced(
            I3_PUT_RETRY,
            "arm-drop",
            step("arm-delay", always, delay_results),
        ),
        "no-hole",
        step("unknown", went_unknown, mark_unknown),
    ),
    "put-result",
    step("resolved", resolved_or_late, resolved),
);

/// The control judges as soon as the upload went unknown, before the
/// delayed RESULT falls due.
const I3_PUT_LATE_EARLY: [Step; 16] = replaced(
    I3_PUT_LATE,
    "resolved",
    step("resolved-early", went_unknown, resolved_early),
);

const I3_PUT_LATE_UNRESOLVED: [Step; 16] = replaced(
    I3_PUT_LATE,
    "resolved",
    step("left-unknown", resolved_or_late, left_unknown),
);

const I3_PUT_RECEIPT: [Step; 13] = replaced(
    I3_PUT_BEYOND,
    "put-result",
    step("put-result-receipt", put_decided, result_as_published),
);

const I3_HOLE_WITNESSES: &[&str] = &[
    "a fragment drop armed",
    "upload DATA supplied",
    "upload receipt acknowledged",
    "a fragment was lost before its ACK",
    "upload published",
    "qualified exact read",
    "unrelated work progressed",
    "the upload's outcome stayed consistent",
    "the lost fragment's source stayed held",
    "the GET agreed with the upload's outcome",
];

const I3_DUPLICATE_WITNESSES: &[&str] = &[
    "a fragment drop armed",
    "every fragment duplicated",
    "upload DATA supplied",
    "upload receipt acknowledged",
    "duplicates granted no extra credit",
    "upload published",
    "qualified exact read",
    "unrelated work progressed",
    "the upload's outcome stayed consistent",
    "the GET agreed with the upload's outcome",
];

const I3_RETRY_WITNESSES: &[&str] = &[
    "a RESULT drop armed",
    "upload receipt acknowledged",
    "a retained RESULT replayed after a lost one",
    "upload published",
    "qualified exact read",
    "unrelated work progressed",
    "the upload's outcome stayed consistent",
    "the GET agreed with the upload's outcome",
];

const I3_LATE_WITNESSES: &[&str] = &[
    "a RESULT delay armed",
    "upload receipt acknowledged",
    "the upload went unknown before its RESULT arrived",
    "a later matching RESULT resolved the unknown outcome",
    "the upload's outcome stayed consistent",
    "qualified exact read",
    "unrelated work progressed",
    "the GET agreed with the upload's outcome",
];

const I3_BEYOND_WITNESSES: &[&str] = &[
    "a RESULT drop armed",
    "upload receipt acknowledged",
    "the upload went unknown before its RESULT arrived",
    "the upload stayed unknown after its RESULT evidence",
    "qualified exact read",
    "unrelated work progressed",
    "the upload's outcome stayed consistent",
    "the GET agreed with the upload's outcome",
];

pub(super) fn displace(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.displacements = world.scene.owner.session_report().displacements;
    allow(world, version_a());
    let scene = &mut *world.scene;
    let spare = scene.spare.as_mut().expect("a replacement client");
    std::mem::swap(&mut scene.clients[0], spare);
    scene.clients[0].session(now);
    mark(world, "a replacement client opened a session")
}

pub(super) fn displaced(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    world.scene.owner.session_report().displacements > world.history.displacements
        && active_put(world, now)
}

pub(super) fn mark_displaced(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    mark(world, "a replacement boot displaced the old session")
}

fn session_refusals(world: &Mixed<'_, '_, '_>) -> u64 {
    let report = world.scene.owner.session_report();
    report.stale + report.mismatched
}

pub(super) fn old_frames(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.noted_drops = session_refusals(world);
    let old = world.history.ids[0];
    let client = world.scene.spare.as_mut().expect("the displaced client");
    client.cancel(old);
    let _ = client.abandon(old);
    let _ = client.poll(now);
    mark(world, "the displaced client sent beside the successor")
}

pub(super) fn old_frames_refused(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    session_refusals(world) > world.history.noted_drops
}

pub(super) fn old_refused(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let refused = session_refusals(world);
    judge_refused(world, refused)
}

fn old_accepted(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let dropped = world.history.noted_drops;
    judge_refused(world, dropped)
}

fn judge_refused(world: &mut Mixed<'_, '_, '_>, dropped: u64) -> u64 {
    if dropped <= world.history.noted_drops {
        return fail(
            world,
            Obligation::Contain,
            "the owner accepted the displaced session's frames",
        );
    }
    mark(world, "the displaced session's frames were refused")
}

pub(super) fn old_kept(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let census = world.scene.owner.peer_census(PeerId(0));
    judge_kept(world, census)
}

/// A control: the displaced session's census reads as empty while the
/// device still holds its read.
fn old_freed(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    judge_kept(world, PeerCensus::default())
}

/// Judges the displaced session's slot, `census`, while the device holds
/// its read: the slot stays active or draining until that read's terminal.
/// A device that holds no command at the check leaves the history
/// unsuccessful.
fn judge_kept(world: &mut Mixed<'_, '_, '_>, census: PeerCensus) -> u64 {
    if world.scene.control.outstanding() == 0 {
        world.first.record(Failure::Unsuccessful(
            "the device held the displaced read at its check",
        ));
        return 0;
    }
    if census.active + census.draining == 0 {
        return fail(
            world,
            Obligation::Custody,
            "a displaced session freed its draining slot while its read was held",
        );
    }
    mark(
        world,
        "the displaced session's work drained only after its terminal",
    )
}

pub(super) fn old_drained(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    let census = world.scene.owner.peer_census(PeerId(0));
    census.active + census.draining == 0
}

pub(super) fn mark_old_drained(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    mark(world, "old work drained")
}

pub(super) fn new_get(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let old = old_get_wire(world);
    let Ok(id) = world.scene.clients[0].get(key(1), 0, 1 << 20, now, super::super::WAIT_US) else {
        return STAY;
    };
    world.history.ids.push(id);
    let wire = world.scene.clients[0].get_wire(id);
    let epoch = world.scene.clients[0].session_epoch();
    judge_identity(world, (wire, epoch), old)
}

/// A control: the retry is judged under the displaced GET's wire identity
/// and epoch.
fn new_get_same(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let old = old_get_wire(world);
    let Ok(id) = world.scene.clients[0].get(key(1), 0, 1 << 20, now, super::super::WAIT_US) else {
        return STAY;
    };
    world.history.ids.push(id);
    judge_identity(world, (old, world.history.old_epoch), old)
}

/// The request ID the displaced client's first GET carried on the wire.
fn old_get_wire(world: &Mixed<'_, '_, '_>) -> Option<u64> {
    let old = world.history.ids[0];
    world.scene.spare.as_ref()?.get_wire(old)
}

/// The request ID the displaced client's upload carried on the wire.
fn old_put_wire(world: &Mixed<'_, '_, '_>) -> Option<u64> {
    let old = world.history.ids[0];
    world.scene.spare.as_ref()?.put_wire(old)
}

/// Fails Contain when the replacement's request carries the displaced
/// request's wire identity under the displaced session's epoch; both are
/// the values the frames carry, not request-table handles.
fn judge_identity(
    world: &mut Mixed<'_, '_, '_>,
    (wire, epoch): (Option<u64>, Option<u64>),
    old: Option<u64>,
) -> u64 {
    if epoch == world.history.old_epoch && old.is_some() && wire == old {
        return fail(
            world,
            Obligation::Contain,
            "a retry reused its identity across the replacement",
        );
    }
    mark(world, "the replacement took a new session identity")
}

pub(super) fn new_decided(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world
        .history
        .ids
        .last()
        .is_some_and(|&id| world.scene.clients[0].outcome(id).is_some())
}

pub(super) fn new_exact(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = *world.history.ids.last().expect("the replacement's GET");
    let bytes = drain(&mut world.scene.clients[0], id);
    let outcome = world.collect_get(0, id);
    let _ = world.scene.clients[0].retire(id);
    if outcome != Some(Outcome::Complete) || bytes != version_c() {
        return fail(
            world,
            Obligation::Bytes,
            "the replacement's GET missed the visible version",
        );
    }
    mark(world, "the replacement read the visible version exactly");
    mark(world, "qualified exact read")
}

pub(super) fn fill_c(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    allow(world, version_c());
    fill_with(world, &version_c(), LABEL_C)
}

pub(super) fn note_epoch(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.old_epoch = world.scene.clients[0].session_epoch();
    mark(world, "old read held")
}

pub(super) fn old_held(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    !world.history.held.is_empty() && !world.history.ids.is_empty()
}

const I2_GET: [Step; 17] = [
    step("arm", always, arm),
    step("old-get", active_put, fresh_get),
    step("old-read-held", old_held, note_epoch),
    step("displace", always, displace),
    step("displaced", displaced, mark_displaced),
    step("old-kept", always, old_kept),
    step("release-old-read", always, release_reads),
    step("old-drained", old_drained, mark_old_drained),
    step("fill-successor", always, fill_c),
    step("publish-successor", fill_written, publish_fill),
    step("new-get", active_put, new_get),
    step("old-frames", always, old_frames),
    step("old-refused", old_frames_refused, old_refused),
    step("new-read", new_decided, new_exact),
    step("unrelated-get", active_get, unrelated_get),
    step("unrelated-read", old_decided, unrelated_read),
    JUDGE,
];

const I2_GET_ACCEPTED: [Step; 17] = replaced(
    I2_GET,
    "old-refused",
    step("old-accepted", always, old_accepted),
);

const I2_GET_FREED: [Step; 17] = replaced(I2_GET, "old-kept", step("old-freed", always, old_freed));

const I2_GET_SAME: [Step; 17] = replaced(
    I2_GET,
    "new-get",
    step("new-get-same", active_get, new_get_same),
);

const I2_WITNESSES: &[&str] = &[
    "old read held",
    "a replacement client opened a session",
    "a replacement boot displaced the old session",
    "the displaced session's frames were refused",
    "the displaced session's work drained only after its terminal",
    "old work drained",
    "the replacement took a new session identity",
    "qualified exact read",
    "unrelated work progressed",
    "the displaced client sent beside the successor",
    "the replacement read the visible version exactly",
];

fn note_put_epoch(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.old_epoch = world.scene.clients[0].session_epoch();
    world
        .history
        .ids
        .push(world.history.put.expect("the old PUT"));
    world.history.refs = withheld(world);
    world.history.deadline = world.history.since + super::super::WAIT_US;
    world.history.wake = Some(world.history.deadline + 1);
    mark(world, "owner write held")
}

/// Link turns the old session's first upload ACK waits before delivery.
const LATE_ACK_TURNS: u64 = 300;

fn arm_late_ack(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let ack = Selector::All(vec![Selector::Kind(Kind::PutAck), Selector::Toward(CLIENT)]);
    set_rules(
        world,
        vec![Rule::new(ack, Effect::Delay(LATE_ACK_TURNS)).window(0, 1)],
    );
    arm_nic_writes(world, now)
}

fn late_ack_sent(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world.scene.nets[0]
        .borrow()
        .rules()
        .captures()
        .iter()
        .any(|capture| {
            capture.kind == Some(Kind::PutAck) && capture.decision.delay == Some(LATE_ACK_TURNS)
        })
}

fn note_late_ack(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.arrival = now + LATE_ACK_TURNS * super::super::LINK_TURN_US + 1;
    world.history.wake = Some(world.history.arrival);
    world.history.mismatched = world.scene.clients[0].session_report().mismatched;
    mark(
        world,
        "an old-session ACK was delayed across the displacement",
    )
}

/// The delayed old-session ACK has reached the replacement and been
/// refused as naming another session: the replacement's mismatched count
/// moved past the one noted when the delay was armed.
fn late_ack_arrived(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    now >= world.history.arrival
        && world.scene.clients[0].session_report().mismatched > world.history.mismatched
}

fn successor_unmoved(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if world.history.since >= world.history.arrival {
        return 1;
    }
    let base = world
        .history
        .put
        .and_then(|id| world.scene.clients[0].put_receipt(id))
        .map_or(0, |(_, base, _)| base);
    if base != 0 {
        return fail(
            world,
            Obligation::Contain,
            "a late old-session ACK moved the successor's receipt",
        );
    }
    let old = world.history.ids[0];
    let old_wire = world
        .scene
        .spare
        .as_ref()
        .and_then(|client| client.put_wire(old));
    let new_wire = world
        .history
        .put
        .and_then(|id| world.scene.clients[0].put_wire(id));
    if old_wire.is_some() && old_wire == new_wire {
        mark(world, "the successor reused the old upload's wire identity");
    }
    mark(
        world,
        "the late old ACK left the successor's receipt unmoved",
    )
}

fn old_put_kept(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let old = world.scene.spare.as_mut().expect("the displaced client");
    let _ = old.poll(now);
    let kept = source_kept(old, &version_b());
    if withheld(world) < world.history.refs || !writes_pending(world) || !kept {
        return fail(
            world,
            Obligation::Custody,
            "a displaced upload released sources the device still held",
        );
    }
    mark(world, "the displaced upload kept its sources and write")
}

fn old_put_freed(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    for net in &world.scene.nets {
        net.borrow_mut().release_tx();
    }
    old_put_kept(world, now)
}

/// The displaced upload settles `Unknown`: the owner refused its frames
/// after the displacement, so no RESULT or PUT ERROR reached the displaced
/// client to establish publication or a named failure.
fn displaced_outcome(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let old = world.history.ids[0];
    let client = world.scene.spare.as_mut().expect("the displaced client");
    let _ = client.poll(now);
    let Some(outcome) = client.put_outcome(old) else {
        return STAY;
    };
    world
        .collected
        .add(super::super::bundle::Collected::Put(2, 0, outcome));
    if outcome != UploadOutcome::Unknown {
        return fail(
            world,
            Obligation::History,
            "a displaced upload whose DATA was accepted claimed no effect",
        );
    }
    mark(world, "the displaced upload's outcome matched its phase")
}

fn new_put(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let old = old_put_wire(world);
    allow(world, version_c());
    if world.history.ids.len() == 1 {
        let Ok(filler) = world.scene.clients[0].get(key(9), 0, 1 << 20, now, super::super::WAIT_US)
        else {
            return STAY;
        };
        world.history.ids.push(filler);
    }
    if put_begin_with(world, CacheVersion(0), version_c(), LABEL_C, now) == STAY {
        return STAY;
    }
    let id = world.history.put.expect("the replacement's PUT");
    let wire = world.scene.clients[0].put_wire(id);
    let epoch = world.scene.clients[0].session_epoch();
    judge_identity(world, (wire, epoch), old)
}

const I2_PUT: [Step; 24] = [
    step("arm", always, arm_late_ack),
    step("put-begin", active_put, put_begin),
    step("put-prepare", always, put_prepare),
    step("put-supply", always, put_supply),
    step("late-ack", late_ack_sent, note_late_ack),
    step("write-held", write_held, note_put_epoch),
    step("displace", always, displace),
    step("displaced", displaced, mark_displaced),
    step("old-kept", always, old_put_kept),
    step("unrelated-get", active_get, unrelated_get),
    step("unrelated-read", old_decided, unrelated_read),
    step("release", always, release_everything),
    step("old-drained", old_drained, mark_old_drained),
    step("new-put", active_put, new_put),
    step("new-prepare", always, put_prepare),
    step("old-frames", always, old_frames),
    step("old-refused", old_frames_refused, old_refused),
    step("successor-unmoved", late_ack_arrived, successor_unmoved),
    step("new-supply", always, successor_supply),
    step("new-result", put_decided, put_published),
    step("qualified-get", uploader_idle, fresh_get),
    step("qualified-read", fresh_decided, successor_exact),
    step("old-outcome", past_retention, displaced_outcome),
    JUDGE,
];

const I2_PUT_ACCEPTED: [Step; 24] = replaced(
    I2_PUT,
    "old-refused",
    step("old-accepted", always, old_accepted),
);

const I2_PUT_FREED: [Step; 24] =
    replaced(I2_PUT, "old-kept", step("old-freed", always, old_put_freed));

const I2_PUT_SAME: [Step; 24] = replaced(
    I2_PUT,
    "new-put",
    step("new-put-same", active_put, new_put_same),
);

/// A control: the replacement's upload is judged under the displaced
/// upload's wire identity and epoch.
fn new_put_same(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let old = old_put_wire(world);
    allow(world, version_c());
    if put_begin_with(world, CacheVersion(0), version_c(), LABEL_C, now) == STAY {
        return STAY;
    }
    judge_identity(world, (old, world.history.old_epoch), old)
}

const I2_PUT_WITNESSES: &[&str] = &[
    "upload DATA supplied",
    "owner write held",
    "a replacement client opened a session",
    "a replacement boot displaced the old session",
    "the displaced session's frames were refused",
    "the displaced upload kept its sources and write",
    "old work drained",
    "the displaced upload's outcome matched its phase",
    "the replacement took a new session identity",
    "upload published",
    "qualified exact read",
    "unrelated work progressed",
    "the displaced client sent beside the successor",
    "an old-session ACK was delayed across the displacement",
    "the late old ACK left the successor's receipt unmoved",
    "the successor reused the old upload's wire identity",
];

pub(super) fn over_share_timed(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    match world.scene.clients[1].get(key(1), 0, 1 << 20, now, super::super::WAIT_US) {
        Ok(id) => {
            world.history.ids.push(id);
            world.history.since = now;
            mark(world, "a GET past the share was issued")
        }
        Err(_) => STAY,
    }
}

pub(super) fn over_share_decided(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world
        .history
        .ids
        .get(2)
        .is_some_and(|&id| world.scene.clients[1].outcome(id).is_some())
}

fn pressured_extended(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    judge_pressured(world, now + 2 * super::super::WAIT_US)
}

pub(super) fn judge_pressured(world: &mut Mixed<'_, '_, '_>, decided_at: u64) -> u64 {
    let outcome = collect_pressured_get(world);
    judge_pressured_outcome(world, outcome, decided_at)
}

/// The control simulates an owner refusing the GET past the share with
/// `Status::RetransmissionPressure`, judged at the GET's issue time.
fn pressured_untyped(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let _ = collect_pressured_get(world);
    let planted = Some(Outcome::Pressure(Status::RetransmissionPressure));
    let since = world.history.since;
    judge_pressured_outcome(world, planted, since)
}

fn collect_pressured_get(world: &mut Mixed<'_, '_, '_>) -> Option<Outcome> {
    world.collect_get(1, world.history.ids[2])
}

fn judge_pressured_outcome(
    world: &mut Mixed<'_, '_, '_>,
    outcome: Option<Outcome>,
    decided_at: u64,
) -> u64 {
    let id = world.history.ids[2];
    if decided_at > world.history.since + super::super::WAIT_US {
        return fail(
            world,
            Obligation::Resources,
            "a pressured request outlived its one deadline",
        );
    }
    if outcome != Some(Outcome::Pressure(Status::RequestPressure)) {
        return fail(
            world,
            Obligation::Resources,
            "a GET past the share ended without a typed pressure outcome",
        );
    }
    let _ = world.scene.clients[1].retire(id);
    world.history.ids.truncate(2);
    mark(
        world,
        "the GET past the share ended typed within its deadline",
    )
}

const I4_GET_SHARE: [Step; 13] = [
    step("arm", always, arm),
    step("saturate", active_get, saturate),
    step("reads-held", reads_held, |world, _| {
        mark(world, "saturating reads held")
    }),
    step("over-share", always, over_share_timed),
    step("over-share-ended", over_share_decided, judge_pressured),
    step("peer-get", active_put, peer_get),
    step("peer-read", peer_decided_or_late, peer_exact),
    step("release", always, release_everything),
    step("healed", saturated_drained, saturated_exact),
    step("nic", released_or_late, released_in_domain),
    step("healed-get", active_get, healed_get),
    step("healed-read", old_decided, unrelated_read),
    JUDGE,
];

/// A control: the eligible peer's read is judged as if observed two bounds
/// late.
fn peer_exact_extended(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    peer_exact(world, now + 2 * BOUND_US)
}

const I4_GET_SHARE_PEER_LATE: [Step; 13] = replaced(
    I4_GET_SHARE,
    "peer-read",
    step("peer-read-late", peer_decided_or_late, peer_exact_extended),
);

const I4_GET_SHARE_EXTENDED: [Step; 13] = replaced(
    I4_GET_SHARE,
    "over-share-ended",
    step(
        "over-share-extended",
        over_share_decided,
        pressured_extended,
    ),
);

const I4_GET_SHARE_UNTYPED: [Step; 13] = replaced(
    I4_GET_SHARE,
    "over-share-ended",
    step("over-share-untyped", over_share_decided, pressured_untyped),
);

const I4_SHARE_WITNESSES: &[&str] = &[
    "share saturated",
    "saturating reads held",
    "a GET past the share was issued",
    "the GET past the share ended typed within its deadline",
    "eligible peer progressed",
    "qualified exact read",
    "unrelated work progressed",
];

fn exhaust_space(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    for name in 10..200u8 {
        match fill(world.storage(), &key(name), VERSION_B_LEN) {
            Some(fill) => world.history.reserved.push(fill),
            None => break,
        }
    }
    if world.history.reserved.is_empty() {
        return 1;
    }
    mark(world, "fill space exhausted")
}

fn release_space(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.reserved.clear();
    world.history.released_at = now;
    world.history.wake = Some(now + HEAL_US);
    mark(world, "fill space released")
}

fn refused_typed(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    judge_refused_typed(world, now)
}

/// A control: the refusal is judged as if observed two deadlines late.
fn refused_typed_extended(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    judge_refused_typed(world, now + 2 * super::super::WAIT_US)
}

fn judge_refused_typed(world: &mut Mixed<'_, '_, '_>, decided_at: u64) -> u64 {
    let outcome = collect_refused_put(world);
    judge_refused_outcome(world, outcome, decided_at)
}

/// The control hands the judge `Status::RequestPressure` where the upload
/// under exhausted fill space requires `Status::StoragePressure`, judged at
/// the upload's issue time.
fn refused_untyped(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let _ = collect_refused_put(world);
    let planted = Some(UploadOutcome::Failed(Status::RequestPressure));
    let since = world.history.since;
    judge_refused_outcome(world, planted, since)
}

fn collect_refused_put(world: &mut Mixed<'_, '_, '_>) -> Option<UploadOutcome> {
    let id = world.history.put.expect("a PUT");
    let outcome = world.collect_put(id);
    let _ = world.scene.clients[0].abandon(id);
    let _ = world.scene.clients[0].retire(id);
    outcome
}

fn judge_refused_outcome(
    world: &mut Mixed<'_, '_, '_>,
    outcome: Option<UploadOutcome>,
    decided_at: u64,
) -> u64 {
    if decided_at > world.history.since + super::super::WAIT_US {
        return fail(
            world,
            Obligation::Resources,
            "a pressured upload outlived its one deadline",
        );
    }
    if outcome != Some(UploadOutcome::Failed(Status::StoragePressure)) {
        return fail(
            world,
            Obligation::Resources,
            "an upload under pressure ended without a typed refusal",
        );
    }
    mark(world, "the pressured upload was refused typed")
}

pub(super) fn incumbent_kept(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let (outcome, bytes) = fresh_result(world);
    if outcome != Some(Outcome::Complete) || bytes != version_a() {
        return fail(
            world,
            Obligation::History,
            "a rejected upload erased the incumbent",
        );
    }
    mark(world, "the incumbent stayed exact")
}

fn erase_incumbent(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let _ = world.scene.owner.invalidate(&key(1), 3, &mut budget());
    world.owner_due = now;
    fresh_get(world, now)
}

const HEAL_US: u64 = 10 * super::super::super::owner::MAINTAIN_REST_US;

fn healed(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    active_put(world, now) && now >= world.history.released_at + HEAL_US
}

pub(super) fn healed_prepare(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if put_decided(world, now) {
        return healed_published(world, now);
    }
    put_prepare(world, now)
}

pub(super) fn healed_published(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    let outcome = world.collect_put(id);
    let _ = world.scene.clients[0].retire(id);
    if outcome != Some(UploadOutcome::Published) {
        return fail(
            world,
            Obligation::Progress,
            "a healed funded upload never published",
        );
    }
    mark(world, "upload published")
}

/// Whether a fragment the client sent toward the owner sat at or past the
/// grant the owner had issued before it, less `shrink`.
fn overran(world: &Mixed<'_, '_, '_>, shrink: u32) -> bool {
    let net = world.scene.nets[0].borrow();
    let mut captures: Vec<_> = net.rules().captures().to_vec();
    captures.sort_by_key(|capture| capture.ordinal);
    let mut issued = 0;
    captures.iter().any(|capture| match capture.kind {
        Some(Kind::PutReady | Kind::PutAck) if capture.toward == CLIENT => {
            issued = issued.max(capture.grant.unwrap_or(0));
            false
        }
        Some(Kind::PutData) if capture.toward == OWNER_SIDE => {
            capture.index.unwrap_or(0) + shrink >= issued
        }
        _ => false,
    })
}

fn within_grant(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    judge_grant(world, 0)
}

fn grant_shrunk(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    judge_grant(world, 1)
}

fn judge_grant(world: &mut Mixed<'_, '_, '_>, shrink: u32) -> u64 {
    if captured(world, Kind::PutData, false) == 0 {
        return fail(
            world,
            Obligation::Resources,
            "the credit check saw no captured fragment",
        );
    }
    let receipt = world
        .history
        .put
        .and_then(|id| world.scene.clients[0].put_receipt(id));
    let over = receipt.is_some_and(|(_, base, grant)| base > grant) || overran(world, shrink);
    if over {
        return fail(
            world,
            Obligation::Resources,
            "an upload passed its granted credit",
        );
    }
    mark(world, "the upload stayed within its granted credit")
}

fn prepare_or_refused(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if put_decided(world, now) {
        return mark(world, "the pressured upload ended before its PREPARE");
    }
    put_prepare(world, now)
}

fn stalled_beside_a(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    allow(world, version_a());
    stalled(world, now)
}

fn healed_get(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    allow(world, version_a());
    unrelated_get(world, now)
}

fn exhaust_pool(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let arena = world.scene.buffers.expect("the owner's arena");
    while let Ok(buffer) = arena.acquire(crate::storage::PoolKind::ReadResponse) {
        world.history.pool.push(buffer);
    }
    if world.history.pool.is_empty() {
        return 1;
    }
    mark(world, "the read-response pool exhausted")
}

fn release_pool(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.pool.clear();
    mark(world, "the read-response pool released")
}

fn pool_get(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    match world.scene.clients[1].get(key(1), 0, 1 << 20, now, super::super::WAIT_US) {
        Ok(id) => {
            world.history.peer = Some(id);
            world.history.since = now;
            mark(world, "a GET met the exhausted pool")
        }
        Err(_) => STAY,
    }
}

fn pool_decided(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world
        .history
        .peer
        .is_some_and(|id| world.scene.clients[1].outcome(id).is_some())
}

fn pool_refused(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let outcome = collect_pool_get(world);
    judge_pool_outcome(world, outcome, now)
}

/// The control simulates an owner refusing the GET under the exhausted
/// pool with `Status::RequestPressure`, judged at the GET's issue time.
fn pool_untyped(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let _ = collect_pool_get(world);
    let planted = Some(Outcome::Pressure(Status::RequestPressure));
    let since = world.history.since;
    judge_pool_outcome(world, planted, since)
}

fn collect_pool_get(world: &mut Mixed<'_, '_, '_>) -> Option<Outcome> {
    let id = world.history.peer.take().expect("the pool GET");
    let outcome = world.collect_get(1, id);
    let _ = world.scene.clients[1].retire(id);
    outcome
}

fn judge_pool_outcome(
    world: &mut Mixed<'_, '_, '_>,
    outcome: Option<Outcome>,
    decided_at: u64,
) -> u64 {
    if decided_at > world.history.since + super::super::WAIT_US {
        return fail(
            world,
            Obligation::Resources,
            "a pressured request outlived its one deadline",
        );
    }
    if outcome != Some(Outcome::Pressure(Status::RetransmissionPressure)) {
        return fail(
            world,
            Obligation::Resources,
            "a GET under an exhausted read pool ended without its typed pressure",
        );
    }
    mark(
        world,
        "the GET under the exhausted pool ended typed within its deadline",
    )
}

fn healed_exact_b(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    allow(world, version_b());
    let read = unrelated_read(world, now);
    if read == 0 {
        return 0;
    }
    mark(world, "the healed GET read exactly")
}

const I4_GET_READ_POOL: [Step; 12] = [
    step("exhaust-pool", always, exhaust_pool),
    step("pool-get", active_get, pool_get),
    step("pool-refused", pool_decided, pool_refused),
    step("put-begin", active_put, put_begin),
    step("put-prepare", always, put_prepare),
    step("put-supply", always, put_supply),
    step("put-result", put_decided, put_published),
    step("heal", always, release_pool),
    step("healed-get", active_get, unrelated_get),
    step("healed-read", old_decided, healed_exact_b),
    step("pad", always, removed_step),
    JUDGE,
];

const I4_GET_READ_POOL_REFUSING: [Step; 12] = replaced(
    I4_GET_READ_POOL,
    "heal",
    step("heal-never", always, removed_step),
);

const I4_GET_READ_POOL_UNTYPED: [Step; 12] = replaced(
    I4_GET_READ_POOL,
    "pool-refused",
    step("pool-untyped", pool_decided, pool_untyped),
);

const I4_READ_POOL_WITNESSES: &[&str] = &[
    "the read-response pool exhausted",
    "a GET met the exhausted pool",
    "the GET under the exhausted pool ended typed within its deadline",
    "upload published",
    "the read-response pool released",
    "the healed GET read exactly",
];

const I4_GET_SPACE: [Step; 6] = [
    step("exhaust", always, exhaust_space),
    step("incumbent-get", uploader_idle, fresh_get),
    step("incumbent-read", fresh_decided, incumbent_kept),
    step("unrelated-get", active_get, healed_get),
    step("unrelated-read", old_decided, unrelated_read),
    JUDGE,
];

const I4_GET_SPACE_WITNESSES: &[&str] = &[
    "fill space exhausted",
    "the incumbent stayed exact",
    "unrelated work progressed",
];

fn second_put(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let first = world.history.put.expect("the first PUT");
    world.history.ids.push(first);
    let Ok(id) = world.scene.clients[0].put(
        key(2),
        crate::storage::CacheVersion(0),
        now,
        super::super::WAIT_US,
    ) else {
        return STAY;
    };
    world.plan.puts -= 1;
    world.history.peer = Some(id);
    world.history.since = now;
    mark(world, "a second upload met the peer's upload share")
}

fn second_decided(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world
        .history
        .peer
        .is_some_and(|id| world.scene.clients[0].put_outcome(id).is_some())
}

fn second_refused(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let outcome = collect_second_put(world);
    judge_second_outcome(world, outcome, now)
}

/// The control simulates an owner refusing the upload past its share with
/// `Status::StoragePressure`, judged at the upload's issue time.
fn second_untyped(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let _ = collect_second_put(world);
    let planted = Some(UploadOutcome::Failed(Status::StoragePressure));
    let since = world.history.since;
    judge_second_outcome(world, planted, since)
}

fn collect_second_put(world: &mut Mixed<'_, '_, '_>) -> Option<UploadOutcome> {
    let id = world.history.peer.take().expect("the second PUT");
    let outcome = world.collect_put(id);
    let _ = world.scene.clients[0].retire(id);
    outcome
}

fn judge_second_outcome(
    world: &mut Mixed<'_, '_, '_>,
    outcome: Option<UploadOutcome>,
    decided_at: u64,
) -> u64 {
    if decided_at > world.history.since + super::super::WAIT_US {
        return fail(
            world,
            Obligation::Resources,
            "a pressured request outlived its one deadline",
        );
    }
    if outcome != Some(UploadOutcome::Failed(Status::RequestPressure)) {
        return fail(
            world,
            Obligation::Resources,
            "an upload past its share ended without its typed pressure",
        );
    }
    mark(world, "the upload past its share was refused typed")
}

const I4_PUT_REQUEST: [Step; 12] = [
    step("put-begin", active_put, put_begin),
    step("put-prepare", always, put_prepare),
    step("first-stalled", always, stalled_beside_a),
    step("second-put", active_put, second_put),
    step("second-refused", second_decided, second_refused),
    step("incumbent-get", active_get, unrelated_get),
    step("incumbent-read", old_decided, unrelated_read),
    step("first-supply", always, put_supply),
    step("first-result", put_decided, healed_published),
    step("qualified-get", uploader_idle, fresh_get),
    step("qualified-read", fresh_decided, fresh_exact_b),
    JUDGE,
];

const I4_PUT_REQUEST_UNTYPED: [Step; 12] = replaced(
    I4_PUT_REQUEST,
    "second-refused",
    step("second-untyped", second_decided, second_untyped),
);

const I4_REQUEST_WITNESSES: &[&str] = &[
    "upload stalled before its DATA",
    "a second upload met the peer's upload share",
    "the upload past its share was refused typed",
    "unrelated work progressed",
    "upload published",
    "qualified exact read",
];

fn many_fragments() -> Vec<u8> {
    payload(MANY_FRAGMENTS_LEN, 5)
}

const MANY_FRAGMENTS_LEN: usize = 6 * FRAGMENT_LEN as usize - 100;

/// The source bytes the uploading client holds at once while it uploads
/// `many_fragments()`: every one of its source slots full.
const MANY_SOURCE_BYTES: u32 = super::super::OWNER.caps.slots * FRAGMENT_LEN;

fn many_begin(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    clear_rules(world, now);
    many_begin_untapped(world, now)
}

/// `many_begin_untapped` starts the upload on the link's existing rule
/// chain. A history's link starts on the untapped `Chain::default()`.
fn many_begin_untapped(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.fragment = 0;
    allow(world, version_a());
    let Ok(id) = world.scene.clients[0].put(
        key(2),
        crate::storage::CacheVersion(0),
        now,
        super::super::WAIT_US,
    ) else {
        return STAY;
    };
    world.plan.puts -= 1;
    world
        .registry
        .borrow_mut()
        .register(key(2), LABEL_B, 0, many_fragments());
    world.history.put = Some(id);
    world.history.since = now;
    mark(world, "upload begun")
}

fn many_get(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    match world.scene.clients[0].get(key(2), 0, 1 << 20, now, super::super::WAIT_US) {
        Ok(id) => {
            world.history.ids.push(id);
            1
        }
        Err(_) => STAY,
    }
}

fn many_prepare(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    prepare_len(world, MANY_FRAGMENTS_LEN)
}

fn many_supply(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    let object = many_fragments();
    let count = (object.len() as u32).div_ceil(FRAGMENT_LEN);
    let slots = world.scene.clients[0].sources().len() as u32;
    while world.history.fragment < count {
        let at = (world.history.fragment * FRAGMENT_LEN) as usize;
        let end = object.len().min(at + FRAGMENT_LEN as usize);
        match world.scene.clients[0].supply(id, world.history.fragment, &object[at..end]) {
            Ok(_) => world.history.fragment += 1,
            Err(super::super::super::upload::SupplyRefused::Slots) => {
                let waited = "the upload waited on its source slots";
                if world.history.fragment >= slots && !world.history.marks.contains(&waited) {
                    mark(world, waited);
                }
                return STAY;
            }
            Err(_) => return STAY,
        }
    }
    1
}

fn many_exact(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = *world
        .history
        .ids
        .last()
        .expect("the GET of the uploaded object");
    collect(&mut world.scene.clients[0], id, &mut world.history.taken);
    let Some(outcome) = world.collect_get(0, id) else {
        return STAY;
    };
    let _ = world.scene.clients[0].retire(id);
    if outcome != Outcome::Complete || world.history.taken != many_fragments() {
        return fail(
            world,
            Obligation::History,
            "a qualified GET missed the visible version's exact bytes",
        );
    }
    mark(world, "qualified exact read")
}

const I4_PUT_SOURCE: [Step; 10] = [
    step("put-begin", active_put, many_begin),
    step("put-prepare", always, many_prepare),
    step("put-supply", always, many_supply),
    step("credit", put_decided, within_grant),
    step("put-result", put_decided, healed_published),
    step("unrelated-get", active_get, unrelated_get),
    step("unrelated-read", old_decided, unrelated_read),
    step("qualified-get", uploader_idle, many_get),
    step("qualified-read", always, many_exact),
    JUDGE,
];

const I4_PUT_SOURCE_OVER: [Step; 10] = replaced(
    I4_PUT_SOURCE,
    "credit",
    step("credit-shrunk", always, grant_shrunk),
);

const I4_PUT_SOURCE_UNTAPPED: [Step; 10] = replaced(
    I4_PUT_SOURCE,
    "put-begin",
    step("put-begin-untapped", active_put, many_begin_untapped),
);

const I4_SOURCE_WITNESSES: &[&str] = &[
    "the upload stayed within its granted credit",
    "the upload waited on its source slots",
    "unrelated work progressed",
    "upload published",
    "qualified exact read",
];

const I4_SPACE: [Step; 16] = [
    step("exhaust", always, exhaust_space),
    step("put-begin", active_put, put_begin),
    step("put-prepare", always, prepare_or_refused),
    step("put-refused", put_decided, refused_typed),
    step("incumbent-get", uploader_idle, fresh_get),
    step("incumbent-read", fresh_decided, incumbent_kept),
    step("peer-get", active_get, peer_old_get),
    step("peer-read", old_decided_or_late, peer_beside_stall),
    step("heal", always, release_space),
    step("healed-begin", healed, put_begin),
    step("healed-prepare", always, healed_prepare),
    step("healed-supply", always, put_supply),
    step("healed-result", put_decided, healed_published),
    step("qualified-get", uploader_idle, fresh_get),
    step("qualified-read", fresh_decided, fresh_exact_b),
    JUDGE,
];

const I4_SPACE_REFUSING: [Step; 16] =
    replaced(I4_SPACE, "heal", step("heal-never", always, removed_step));

const I4_SPACE_REFUSED_LATE: [Step; 16] = replaced(
    I4_SPACE,
    "put-refused",
    step("put-refused-late", put_decided, refused_typed_extended),
);

const I4_SPACE_UNTYPED: [Step; 16] = replaced(
    I4_SPACE,
    "put-refused",
    step("put-untyped", put_decided, refused_untyped),
);

const I4_SPACE_ERASED: [Step; 16] = replaced(
    I4_SPACE,
    "incumbent-get",
    step("incumbent-erased", uploader_idle, erase_incumbent),
);

const I4_SPACE_WITNESSES: &[&str] = &[
    "fill space exhausted",
    "the pressured upload was refused typed",
    "the incumbent stayed exact",
    "eligible peer progressed",
    "fill space released",
    "upload published",
    "qualified exact read",
];

/// A control: the deferred upload is judged two waits after its decision,
/// as an upload whose deadline a READY had moved would be seen.
pub(super) fn deferred_extended(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    judge_deferred(world, now + 2 * super::super::WAIT_US)
}

/// Judges the decided upload whose DATA its supplier never gave, seen
/// decided at `decided_at`: within one wait of its begin, it ended
/// `Unknown` or `Failed(TimedOut)`.
pub(super) fn judge_deferred(world: &mut Mixed<'_, '_, '_>, decided_at: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    let outcome = world.collect_put(id);
    judge_deferred_outcome(world, outcome, decided_at)
}

/// Judging at `world.history.since` keeps `decided_at` inside the deadline
/// check, so the planted `UploadOutcome::NotStarted` reaches the match on
/// `outcome` at any clock reading.
pub(super) fn deferred_no_effect(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let since = world.history.since;
    judge_deferred_outcome(world, Some(UploadOutcome::NotStarted), since)
}

/// The control simulates a deferred upload reporting
/// `UploadOutcome::Published`, judged at the upload's issue time.
fn deferred_published(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let since = world.history.since;
    judge_deferred_outcome(world, Some(UploadOutcome::Published), since)
}

/// Ends the upload at the client and returns whether `decided_at`, the
/// time a step observed the upload's outcome, is within the deadline. Each
/// upload starts one wait when it begins. An observation after the
/// deadline fails the run.
pub(super) fn deferred_in_time(world: &mut Mixed<'_, '_, '_>, decided_at: u64) -> bool {
    let id = world.history.put.expect("a PUT");
    let _ = world.scene.clients[0].abandon(id);
    let _ = world.scene.clients[0].retire(id);
    if decided_at > world.history.since + super::super::WAIT_US {
        fail(
            world,
            Obligation::Resources,
            "a deferred upload outlived its one deadline",
        );
        return false;
    }
    true
}

fn judge_deferred_outcome(
    world: &mut Mixed<'_, '_, '_>,
    outcome: Option<UploadOutcome>,
    decided_at: u64,
) -> u64 {
    if !deferred_in_time(world, decided_at) {
        return 0;
    }
    match outcome {
        Some(UploadOutcome::Published) => {
            return fail(
                world,
                Obligation::History,
                "a deferred upload published bytes its supplier never gave",
            );
        }
        // The BEGIN reached the owner, so the deadline ends the upload as
        // unknown at the client or timed out by the owner.
        Some(UploadOutcome::Unknown | UploadOutcome::Failed(Status::TimedOut)) => {}
        _ => {
            return fail(
                world,
                Obligation::History,
                "a deferred upload ended with an outcome its deadline cannot give",
            );
        }
    }
    mark(world, "the deferred upload ended at its one deadline")
}

const I4_PUT_DEFERRED: [Step; 15] = [
    step("put-begin", active_put, put_begin),
    step("put-prepare", always, put_prepare),
    step("deferred", always, stalled_beside_a),
    step("unrelated-get", active_get, unrelated_get),
    step("unrelated-read", old_decided, unrelated_read),
    step("deadline", put_decided, judge_deferred),
    step("incumbent-get", uploader_idle, fresh_get),
    step("incumbent-read", fresh_decided, incumbent_kept),
    step("healed-begin", uploader_idle, put_begin),
    step("healed-prepare", always, healed_prepare),
    step("healed-supply", always, put_supply),
    step("healed-result", put_decided, healed_published),
    step("qualified-get", uploader_idle, fresh_get),
    step("qualified-read", fresh_decided, fresh_exact_b),
    JUDGE,
];

const I4_PUT_DEFERRED_EXTENDED: [Step; 15] = replaced(
    I4_PUT_DEFERRED,
    "deadline",
    step("deadline-extended", put_decided, deferred_extended),
);

const I4_PUT_DEFERRED_NO_EFFECT: [Step; 15] = replaced(
    I4_PUT_DEFERRED,
    "deadline",
    step("deadline-no-effect", put_decided, deferred_no_effect),
);

const I4_PUT_DEFERRED_PUBLISHED: [Step; 15] = replaced(
    I4_PUT_DEFERRED,
    "deadline",
    step("deadline-published", put_decided, deferred_published),
);

const I4_DEFERRED_WITNESSES: &[&str] = &[
    "upload stalled before its DATA",
    "the deferred upload ended at its one deadline",
    "the incumbent stayed exact",
    "upload published",
    "qualified exact read",
    "unrelated work progressed",
];

/// A's first GET, issued after the count of uploads the owner began is
/// recorded.
pub(super) fn a_get(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.begun = world.scene.owner.put_report().begun;
    fresh_get(world, now)
}

fn upload_charged(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let begun = world.scene.owner.put_report().begun > world.history.begun;
    let pending = world
        .history
        .put
        .is_some_and(|id| world.scene.clients[0].put_outcome(id).is_none());
    if !begun || !pending {
        return 1;
    }
    mark(world, "the pending upload holds A's share")
}

fn a_over(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    match world.scene.clients[0].get(key(1), 0, 1 << 20, now, super::super::WAIT_US) {
        Ok(id) => {
            world.history.peer = Some(id);
            world.history.issued = now;
            mark(world, "A issued a GET past its share")
        }
        Err(_) => STAY,
    }
}

/// A's client decided the GET that `world.history.peer` names.
pub(super) fn a_over_decided(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world
        .history
        .peer
        .is_some_and(|id| world.scene.clients[0].outcome(id).is_some())
}

fn a_capped(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    judge_a_capped(world, now)
}

/// A control: A's refusal is judged as if observed two deadlines late.
fn a_capped_extended(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    judge_a_capped(world, now + 2 * super::super::WAIT_US)
}

fn judge_a_capped(world: &mut Mixed<'_, '_, '_>, decided_at: u64) -> u64 {
    let id = world.history.peer.take().expect("A's GET past its share");
    let outcome = world.collect_get(0, id);
    let _ = world.scene.clients[0].retire(id);
    if decided_at > world.history.issued + super::super::WAIT_US {
        return fail(
            world,
            Obligation::Resources,
            "a GET past a peer's share outlived its one deadline",
        );
    }
    if outcome != Some(Outcome::Pressure(Status::RequestPressure)) {
        return fail(
            world,
            Obligation::Resources,
            "a GET past a peer's share ended without a typed pressure outcome",
        );
    }
    mark(world, "A's GET past its share was refused typed")
}

fn b_read(world: &mut Mixed<'_, '_, '_>) -> (Option<Outcome>, Vec<u8>) {
    world.read(1);
    let get = world.gets[1].as_ref().expect("B's GET");
    (get.outcome, get.bytes.clone())
}

fn b_census(world: &Mixed<'_, '_, '_>, peer: PeerId) -> PeerCensus {
    world.scene.owner.peer_census(peer)
}

/// B's GET beside A's saturated share, issued at `now`.
fn b_get(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.b_issued = now;
    unrelated_get(world, now)
}

fn b_exact(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let read = b_read(world);
    b_charged(world, now, read, b_census)
}

/// A control: B's exact read is judged as if observed two deadlines late.
fn b_exact_extended(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let read = b_read(world);
    b_charged(world, now + 2 * super::super::WAIT_US, read, b_census)
}

fn b_timed_out(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let _ = b_read(world);
    let starved = (Some(Outcome::Failed(Status::TimedOut)), Vec::new());
    b_charged(world, now, starved, b_census)
}

fn b_globalized(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let read = b_read(world);
    b_charged(world, now, read, |world, _| {
        let [a, b] = [0, 1].map(|peer| world.scene.owner.peer_census(PeerId(peer)));
        PeerCensus {
            active: a.active + b.active,
            draining: a.draining + b.draining,
        }
    })
}

fn b_wrong_peer(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let read = b_read(world);
    b_charged(world, now, read, |world, peer| {
        world.scene.owner.peer_census(PeerId(1 - peer.0))
    })
}

/// A control: B's completed GET is read as charged to no peer while its
/// response is still retained.
fn b_uncharged(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let read = b_read(world);
    b_charged(world, now, read, |world, peer| match peer {
        PeerId(1) => PeerCensus::default(),
        peer => world.scene.owner.peer_census(peer),
    })
}

/// Judges B's read as observed at `decided_at`: it completed exactly within
/// one deadline of its issue, and each peer's charge stayed in its share.
fn b_charged(
    world: &mut Mixed<'_, '_, '_>,
    decided_at: u64,
    (outcome, bytes): (Option<Outcome>, Vec<u8>),
    charged: impl Fn(&Mixed<'_, '_, '_>, PeerId) -> PeerCensus,
) -> u64 {
    if decided_at > world.history.b_issued + super::super::WAIT_US {
        return fail(
            world,
            Obligation::Progress,
            "an eligible peer's GET starved behind a saturated share",
        );
    }
    if judge_peer_read(world, outcome, &bytes) == 0 {
        return 0;
    }
    let a = charged(world, PeerId(0));
    let b = charged(world, PeerId(1));
    let share = super::super::OWNER.peer_requests;
    if a.active + a.draining > share || b.active + b.draining > 1 || a.active + a.draining == 0 {
        return fail(
            world,
            Obligation::Resources,
            "a peer's share was charged with another peer's work",
        );
    }
    // B's completed GET drains in B's share while the history holds the
    // transmit references its response rode on.
    if world.history.hold_nic && b.active + b.draining != 1 {
        return fail(
            world,
            Obligation::Resources,
            "a retained GET left its peer's share before its release",
        );
    }
    let pending = world
        .history
        .marks
        .contains(&"the pending upload holds A's share");
    let attempts = world.scene.owner.put_report().begun - world.history.begun;
    if pending && (attempts != 1 || a.active + a.draining != 2) {
        return fail(
            world,
            Obligation::Resources,
            "a peer's share was charged with another peer's work",
        );
    }
    mark(world, "B progressed beside A's capped share");
    mark(world, "charges reconciled by peer")
}

const I5: [Step; 16] = [
    step("arm", always, arm),
    step("a-get", active_put, a_get),
    step("a-read-held", read_held, mark_read_held),
    step("a-put-begin", active_put, put_begin),
    step("a-put-prepare", always, put_prepare),
    step("a-upload-charged", always, upload_charged),
    step("a-over", always, a_over),
    step("a-capped", a_over_decided, a_capped),
    step("b-get", active_get, b_get),
    step("b-read", old_decided, b_exact),
    step("release", always, release_everything),
    step("a-supply", always, put_supply),
    step("a-result", put_decided, put_published),
    step("qualified-get", uploader_idle, fresh_get),
    step("qualified-read", fresh_decided, fresh_exact_b),
    JUDGE,
];

const I5_A_CAPPED_LATE: [Step; 16] = replaced(
    I5,
    "a-capped",
    step("a-capped-late", a_over_decided, a_capped_extended),
);

const I5_GLOBALIZED: [Step; 16] = replaced(
    I5,
    "b-read",
    step("b-read-globalized", old_decided, b_globalized),
);

const I5_B_UNCHARGED: [Step; 16] = replaced(
    I5,
    "b-read",
    step("b-read-uncharged", old_decided, b_uncharged),
);

const I5_WRONG_PEER: [Step; 16] = replaced(
    I5,
    "b-read",
    step("b-read-wrong-peer", old_decided, b_wrong_peer),
);

const I5_B_LATE: [Step; 16] = replaced(
    I5,
    "b-read",
    step("b-read-late", old_decided, b_exact_extended),
);

const I5_B_TIMED_OUT: [Step; 16] = replaced(
    I5,
    "b-read",
    step("b-read-timed-out", old_decided, b_timed_out),
);

const I5_MASKED: [Step; 16] = replaced(
    replaced(
        replaced(
            replaced(
                I5,
                "a-put-begin",
                step("a-second-get", active_put, fresh_get),
            ),
            "a-put-prepare",
            step("a-prepare-removed", always, removed_step),
        ),
        "a-supply",
        step("a-supply-removed", always, removed_step),
    ),
    "a-result",
    step("a-result-removed", always, removed_step),
);

const I5_MASKED_READ: [Step; 16] = replaced(
    replaced(
        I5_MASKED,
        "qualified-get",
        step("qualified-get-removed", always, removed_step),
    ),
    "qualified-read",
    step("qualified-read-removed", always, removed_step),
);

const I5_WITNESSES: &[&str] = &[
    "old read held",
    "the pending upload holds A's share",
    "A issued a GET past its share",
    "A's GET past its share was refused typed",
    "B progressed beside A's capped share",
    "charges reconciled by peer",
    "upload published",
    "qualified exact read",
];

pub(super) fn unrelated_get(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.hold_reads = false;
    old_get(world, now)
}

pub(super) fn unrelated_read(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.read(1);
    let get = world.gets[1].as_ref().expect("the unrelated GET");
    let (outcome, bytes) = (get.outcome, get.bytes.clone());
    let consistent = match outcome {
        Some(Outcome::Complete) => world.history.allowed.contains(&bytes),
        Some(Outcome::Missing) => world.history.allowed.is_empty() && bytes.is_empty(),
        _ => false,
    };
    if !consistent {
        return fail(
            world,
            Obligation::Progress,
            "unrelated work stalled or read bytes outside the visible versions",
        );
    }
    mark(world, "unrelated work progressed")
}

fn allow(world: &mut Mixed<'_, '_, '_>, object: Vec<u8>) {
    world.history.allowed = vec![object];
}

/// I6: the storage counts a local fill's write right before the driver
/// submit, so a submit that unwinds leaves the slot holding one right while
/// the reservation is not marked written. The storage holds the abandoned
/// extent until the write's terminal or the proven stop, so an abort of that
/// fill returns and the owner keeps operating on its lost volume.
fn i6_receive(world: &mut Mixed<'_, '_, '_>, unwinds: bool) -> u64 {
    let Some(mut fill) = fill(world.storage(), &key(2), VERSION_B_LEN) else {
        return STAY;
    };
    let object = version_b();
    let io = &mut crate::storage::WorkBudget::with_io(0, usize::MAX, usize::MAX);
    if unwinds {
        world.scene.control.unwind_next(Some(Unwind::Submit));
    }
    let received = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        world.scene.owner.receive_fill(&mut fill, &object, io)
    }));
    world.scene.control.unwind_next(None);
    let progress = world.scene.owner.fill_progress(&fill);
    let premise = progress.outstanding_commands == 1
        && if unwinds {
            received.is_err() && progress.submitted_units == 0
        } else {
            received.is_ok_and(|taken| taken == Ok(object.len())) && progress.submitted_units > 0
        };
    world.history.fill = Some(fill);
    let witness = if unwinds {
        "the first write's submit unwound"
    } else {
        "the first write submitted"
    };
    if !premise {
        world.first.record(Failure::Unsuccessful(witness));
        return 0;
    }
    mark(world, witness)
}

fn i6_receive_unwound(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    i6_receive(world, true)
}

fn i6_receive_submitted(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    i6_receive(world, false)
}

/// Aborts the kept fill while its one write command is still counted.
fn i6_abort(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let fill = world.history.fill.take().expect("a kept fill");
    let aborted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fill.abort()));
    if aborted.is_err() {
        return fail(
            world,
            Obligation::Contain,
            "an abort with a write outstanding unwound",
        );
    }
    mark(world, "the fill aborted and returned")
}

const I6_UNWOUND: [Step; 3] = [
    step("receive-unwound", always, i6_receive_unwound),
    step("abort", always, i6_abort),
    JUDGE,
];

const I6_SUBMITTED: [Step; 3] = [
    step("receive-submitted", always, i6_receive_submitted),
    step("abort", always, i6_abort),
    JUDGE,
];

const I6_UNWOUND_WITNESSES: &[&str] = &[
    "the first write's submit unwound",
    "the fill aborted and returned",
];

const I6_SUBMITTED_WITNESSES: &[&str] =
    &["the first write submitted", "the fill aborted and returned"];

const I6: &[Obligation] = &[Obligation::Contain];

/// I7: an answer the owner gives on a fresh wire identity settles that
/// identity. A refused BEGIN, a refused GET and an `UnknownOutcome` to a
/// CANCEL that overtook its BEGIN each settle the client once the answer
/// arrives; a retransmission carrying the same identity that the owner
/// admitted meanwhile would hold the peer's share, a slot and the key's fill
/// attempt until its deadline with no client to drive it. Each history
/// delays the answer behind the client's retransmission and judges the
/// identity's wire row once the client settled.
pub(super) fn i7_rules_on(world: &mut Mixed<'_, '_, '_>, net: usize, rules: Vec<Rule>) {
    let taps = [rules.len()];
    let chain = Chain::new(rules, &taps, &MANIFEST).expect("a bounded chain");
    world.scene.nets[net].borrow_mut().set_rules(chain);
}

pub(super) fn toward_client(kind: Kind) -> Selector {
    Selector::All(vec![Selector::Kind(kind), Selector::Toward(CLIENT)])
}

/// The refusal's ERROR reaches the client after its BEGIN retries, and the
/// AUTHORITY those retries earn after the ERROR.
fn i7_delay_answers(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    i7_rules_on(
        world,
        0,
        vec![
            Rule::new(toward_client(Kind::PutError), Effect::Delay(300)),
            Rule::new(toward_client(Kind::PutAuthority), Effect::Delay(600)),
        ],
    );
    mark(world, "the refusal and the admission delayed")
}

fn i7_prompt_answers(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    i7_rules_on(world, 0, Vec::new());
    mark(world, "the refusal and the admission delivered promptly")
}

/// Client 0's second PUT beside its stalled first one, its wire identity
/// kept for the row judged after its release.
fn i7_second_put(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let Ok(id) = world.scene.clients[0].put(
        key(2),
        crate::storage::CacheVersion(0),
        now,
        super::super::WAIT_US,
    ) else {
        return STAY;
    };
    world.plan.puts -= 1;
    put_attempt(world, id);
    world.history.peer = Some(id);
    world.history.since = now;
    mark(world, "a second upload met the peer's upload share")
}

fn i7_put_decided(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world
        .history
        .peer
        .is_some_and(|id| world.scene.clients[0].put_outcome(id).is_some())
}

/// Microseconds after the client settled before its identity's row is
/// judged: past the delayed admission's arrival and the client's last retry.
const I7_QUIET_US: u64 = 80_000;

fn i7_settle(world: &mut Mixed<'_, '_, '_>, now: u64, witness: &'static str) -> u64 {
    world.history.deadline = now + I7_QUIET_US;
    world.history.wake = Some(world.history.deadline + 1);
    mark(world, witness)
}

fn i7_second_refused(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let id = world.history.peer.expect("the second PUT");
    let outcome = world.collect_put(id);
    let _ = world.scene.clients[0].retire(id);
    if outcome != Some(UploadOutcome::Failed(Status::RequestPressure)) {
        world.first.record(Failure::Unsuccessful(
            "the upload past its share was refused typed",
        ));
        return 0;
    }
    i7_settle(world, now, "the upload past its share was refused typed")
}

fn i7_quiet(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    now > world.history.deadline
}

/// The wire identity client `actor`'s request `id` carried, kept at issue.
fn kept_attempt(world: &Mixed<'_, '_, '_>, actor: usize, id: RequestId) -> RequestId {
    RequestId::from_wire(kept_wire(world, actor, id).expect("the request's wire was kept"))
}

/// Keeps the wire identity client 0's upload `id` carries, read while the
/// upload is live, so steps after its retirement can still name it.
fn put_attempt(world: &mut Mixed<'_, '_, '_>, id: RequestId) {
    let wire = world.scene.clients[0]
        .put_wire(id)
        .expect("a live upload names its wire");
    world.history.attempts.push((0, id, wire));
}

/// Judges the settled request's wire row on peer `peer`: the client holds no
/// request for it, and the row binds no attempt at its generation. A row
/// bound at that generation is the admitted retransmission. A row whose
/// watermark is below that generation never settled it and leaves the
/// history unsuccessful.
fn i7_row(
    world: &mut Mixed<'_, '_, '_>,
    peer: PeerId,
    wire: RequestId,
    held: bool,
    rule: &'static str,
    witness: &'static str,
) -> u64 {
    if held {
        world.first.record(Failure::Unsuccessful(
            "the client retired the settled request",
        ));
        return 0;
    }
    let row = world
        .scene
        .owner
        .request_slot(peer, wire.slot())
        .unwrap_or_default();
    if row.watermark == Some(wire.generation()) && row.active.is_some() {
        return fail(world, Obligation::Resources, rule);
    }
    if row
        .watermark
        .is_none_or(|settled| settled < wire.generation())
    {
        world.first.record(Failure::Unsuccessful(witness));
        return 0;
    }
    mark(world, witness)
}

fn i7_put_row(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.peer.take().expect("the PUT");
    let wire = kept_attempt(world, 0, id);
    let held = world.scene.clients[0].put_wire(id).is_some();
    i7_row(
        world,
        PeerId(0),
        wire,
        held,
        "a settled upload's row held an admitted attempt",
        "the settled upload left no admitted attempt",
    )
}

const I7_BEGIN_DELAYED: [Step; 10] = [
    step("put-begin", active_put, put_begin),
    step("put-prepare", always, put_prepare),
    step("first-stalled", always, stalled),
    step("delay", always, i7_delay_answers),
    step("second-put", active_put, i7_second_put),
    step("first-supply", always, put_supply),
    step("first-result", put_decided, put_published),
    step("second-refused", i7_put_decided, i7_second_refused),
    step("row", i7_quiet, i7_put_row),
    JUDGE,
];

const I7_BEGIN_PROMPT: [Step; 10] = replaced(
    I7_BEGIN_DELAYED,
    "delay",
    step("prompt", always, i7_prompt_answers),
);

const I7_BEGIN_DELAYED_WITNESSES: &[&str] = &[
    "upload stalled before its DATA",
    "the refusal and the admission delayed",
    "a second upload met the peer's upload share",
    "upload published",
    "the upload past its share was refused typed",
    "the settled upload left no admitted attempt",
];

const I7_BEGIN_PROMPT_WITNESSES: &[&str] = &[
    "upload stalled before its DATA",
    "the refusal and the admission delivered promptly",
    "a second upload met the peer's upload share",
    "upload published",
    "the upload past its share was refused typed",
    "the settled upload left no admitted attempt",
];

/// The BEGIN reaches the owner after the CANCEL sent behind it.
fn i7_delay_begin(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let begin = Selector::All(vec![
        Selector::Kind(Kind::PutBegin),
        Selector::Toward(OWNER_SIDE),
    ]);
    i7_rules_on(world, 0, vec![Rule::new(begin, Effect::Delay(100))]);
    mark(world, "the BEGIN delayed behind its CANCEL")
}

fn i7_prompt_begin(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    i7_rules_on(world, 0, Vec::new());
    mark(world, "the BEGIN delivered ahead of its CANCEL")
}

fn i7_begin(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let Ok(id) = world.scene.clients[0].put(
        key(2),
        crate::storage::CacheVersion(0),
        now,
        super::super::WAIT_US,
    ) else {
        return STAY;
    };
    world.plan.puts -= 1;
    put_attempt(world, id);
    world.history.peer = Some(id);
    world.history.since = now;
    mark(world, "upload begun")
}

/// The link toward the owner carried the BEGIN, so a CANCEL sent now
/// follows a BEGIN the client has already handed off.
fn i7_begin_sent(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world.scene.nets[0]
        .borrow()
        .rules()
        .captures()
        .iter()
        .any(|capture| capture.kind == Some(Kind::PutBegin) && capture.toward == OWNER_SIDE)
}

fn i7_cancel(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.peer.expect("the PUT");
    world.scene.clients[0].cancel(id);
    mark(world, "the upload cancelled in Begin")
}

fn i7_cancelled(world: &mut Mixed<'_, '_, '_>, now: u64, unknown: bool) -> u64 {
    let id = world.history.peer.expect("the PUT");
    let outcome = world.collect_put(id);
    let witness = if unknown {
        "the cancel was answered unknown"
    } else {
        "the cancel ended the upload"
    };
    if unknown && outcome != Some(UploadOutcome::Unknown) {
        world.first.record(Failure::Unsuccessful(witness));
        return 0;
    }
    let _ = world.scene.clients[0].abandon(id);
    let _ = world.scene.clients[0].retire(id);
    i7_settle(world, now, witness)
}

fn i7_cancelled_unknown(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    i7_cancelled(world, now, true)
}

fn i7_cancelled_ended(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    i7_cancelled(world, now, false)
}

const I7_CANCEL_DELAYED: [Step; 6] = [
    step("delay-begin", always, i7_delay_begin),
    step("put-begin", active_put, i7_begin),
    step("cancel", i7_begin_sent, i7_cancel),
    step("settled", i7_put_decided, i7_cancelled_unknown),
    step("row", i7_quiet, i7_put_row),
    JUDGE,
];

const I7_CANCEL_PROMPT: [Step; 6] = replaced(
    replaced(
        I7_CANCEL_DELAYED,
        "delay-begin",
        step("prompt-begin", always, i7_prompt_begin),
    ),
    "settled",
    step("settled-ended", i7_put_decided, i7_cancelled_ended),
);

const I7_CANCEL_DELAYED_WITNESSES: &[&str] = &[
    "the BEGIN delayed behind its CANCEL",
    "upload begun",
    "the upload cancelled in Begin",
    "the cancel was answered unknown",
    "the settled upload left no admitted attempt",
];

const I7_CANCEL_PROMPT_WITNESSES: &[&str] = &[
    "the BEGIN delivered ahead of its CANCEL",
    "upload begun",
    "the upload cancelled in Begin",
    "the cancel ended the upload",
    "the settled upload left no admitted attempt",
];

fn i7_hold_reads(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.hold_reads = true;
    mark(world, "reads held")
}

fn i7_share_held(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world.scene.owner.peer_census(PeerId(1)).active >= 2 && world.history.held.len() >= 2
}

/// Client 1's GET past its saturated share; with `delayed`, its refusal
/// reaches the client after its GET retries and the START those retries
/// earn after the refusal.
fn i7_third_get(world: &mut Mixed<'_, '_, '_>, now: u64, delayed: bool) -> u64 {
    let Ok(id) = world.scene.clients[1].get(key(1), 0, 1 << 20, now, super::super::WAIT_US) else {
        return STAY;
    };
    let wire = world.scene.clients[1]
        .get_wire(id)
        .expect("a live GET names its wire");
    world.history.attempts.push((1, id, wire));
    world.history.peer = Some(id);
    world.history.since = now;
    if delayed {
        let start = Selector::All(vec![
            Selector::Kind(Kind::Start),
            Selector::Request(wire),
            Selector::Toward(CLIENT),
        ]);
        i7_rules_on(
            world,
            1,
            vec![
                Rule::new(toward_client(Kind::Error), Effect::Delay(300)),
                Rule::new(start, Effect::Delay(600)),
            ],
        );
        return mark(
            world,
            "a GET past the share issued, its refusal and START delayed",
        );
    }
    mark(world, "a GET past the share issued")
}

fn i7_third_get_delayed(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    i7_third_get(world, now, true)
}

fn i7_third_get_prompt(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    i7_third_get(world, now, false)
}

fn i7_get_decided(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world
        .history
        .peer
        .is_some_and(|id| world.scene.clients[1].outcome(id).is_some())
}

fn i7_third_refused(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let id = world.history.peer.expect("the third GET");
    let outcome = world.collect_get(1, id);
    let _ = world.scene.clients[1].retire(id);
    if outcome != Some(Outcome::Pressure(Status::RequestPressure)) {
        world.first.record(Failure::Unsuccessful(
            "the GET past the share was refused typed",
        ));
        return 0;
    }
    i7_settle(world, now, "the GET past the share was refused typed")
}

fn i7_get_row(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.peer.take().expect("the third GET");
    let wire = kept_attempt(world, 1, id);
    let held = world.scene.clients[1].get_wire(id).is_some();
    i7_row(
        world,
        PeerId(1),
        wire,
        held,
        "a settled GET's row held an admitted request",
        "the settled GET left no admitted request",
    )
}

const I7_GET_DELAYED: [Step; 7] = [
    step("hold-reads", always, i7_hold_reads),
    step("saturate", active_get, saturate),
    step("third-get", i7_share_held, i7_third_get_delayed),
    step("release-reads", always, release_reads),
    step("third-refused", i7_get_decided, i7_third_refused),
    step("row", i7_quiet, i7_get_row),
    JUDGE,
];

const I7_GET_PROMPT: [Step; 7] = replaced(
    I7_GET_DELAYED,
    "third-get",
    step("third-get-prompt", i7_share_held, i7_third_get_prompt),
);

const I7_GET_DELAYED_WITNESSES: &[&str] = &[
    "reads held",
    "share saturated",
    "a GET past the share issued, its refusal and START delayed",
    "the GET past the share was refused typed",
    "the settled GET left no admitted request",
];

const I7_GET_PROMPT_WITNESSES: &[&str] = &[
    "reads held",
    "share saturated",
    "a GET past the share issued",
    "the GET past the share was refused typed",
    "the settled GET left no admitted request",
];

const I7: &[Obligation] = &[Obligation::Resources];

/// I8: the client's next request on the wire slot of an upload the owner
/// ended is admitted on the peer's share and table room, whether or not the
/// upload's device write has returned. The history cancels an upload whose
/// DATA the owner accepted, holds its write, waits for the owner's PUT ERROR
/// to end the upload at the client, and issues a GET that takes the ended
/// upload's slot at a higher generation; the GET reads the resident version
/// exactly. `i8-get-after-upload-drained` issues the same GET after the
/// write drained.
fn i8_hold_writes(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.hold_writes = true;
    mark(world, "holds armed")
}

/// The wire identity the ended upload's frames carried.
fn i8_upload_wire(world: &Mixed<'_, '_, '_>) -> RequestId {
    kept_attempt(world, 0, world.history.put.expect("a PUT"))
}

/// The device still holds every write the history held.
fn i8_write_held(world: &Mixed<'_, '_, '_>) -> bool {
    !world.history.writes.is_empty() && writes_pending(world)
}

/// Whether the ended upload still drains behind the write the history
/// holds: its wire slot's watermark is the upload's generation, its peer
/// holds that one draining request, none active and room in its share, and
/// the device still holds every write the history held. Whether the slot
/// still binds the upload is what the GET judges, so the premise leaves it
/// out.
fn i8_draining(world: &Mixed<'_, '_, '_>) -> bool {
    let wire = i8_upload_wire(world);
    let row = world
        .scene
        .owner
        .request_slot(PeerId(0), wire.slot())
        .unwrap_or_default();
    let census = world.scene.owner.peer_census(PeerId(0));
    let share = world
        .plan
        .share
        .unwrap_or(super::super::OWNER.peer_requests);
    row.watermark == Some(wire.generation())
        && (census.active, census.draining) == (0, 1)
        && census.active + census.draining < share
        && i8_write_held(world)
}

/// The client ended the upload on the owner's PUT ERROR, which it judges
/// once, the first time the step runs; the step stays until the client can
/// retire the upload.
fn i8_ended(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    if kept_wire(world, 0, id).is_none() {
        if world.collect_put(id) != Some(UploadOutcome::Failed(Status::Cancelled)) {
            world.first.record(Failure::Unsuccessful(
                "the owner's PUT ERROR ended the cancelled upload at its client",
            ));
            return 0;
        }
        put_attempt(world, id);
    }
    if !i8_draining(world) {
        world.first.record(Failure::Unsuccessful(
            "the ended upload was still draining behind its held write",
        ));
        return 0;
    }
    if !world.scene.clients[0].retire(id) {
        return STAY;
    }
    mark(
        world,
        "the owner's PUT ERROR ended the cancelled upload at its client",
    )
}

fn i8_get(world: &mut Mixed<'_, '_, '_>, now: u64, drained: bool) -> u64 {
    let (premise, formed) = if drained {
        (
            "the ended upload drained before the GET",
            upload_drained(world, now),
        )
    } else {
        (
            "the ended upload's write was held at the GET",
            i8_draining(world),
        )
    };
    if !formed {
        world.first.record(Failure::Unsuccessful(premise));
        return 0;
    }
    if fresh_get(world, now) == STAY {
        return STAY;
    }
    let id = *world.history.ids.last().expect("the GET");
    let old = i8_upload_wire(world);
    let wire = RequestId::from_wire(attempt(world, 0, id));
    if wire.slot() != old.slot() || wire.generation() <= old.generation() {
        world.first.record(Failure::Unsuccessful(
            "the GET took the ended upload's wire slot at a higher generation",
        ));
        return 0;
    }
    mark(world, premise);
    mark(
        world,
        "the GET took the ended upload's wire slot at a higher generation",
    )
}

fn i8_get_draining(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    i8_get(world, now, false)
}

fn i8_get_drained(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    i8_get(world, now, true)
}

/// Judges the GET on the ended upload's wire slot: the owner admits it and
/// it reads the resident version exactly. A `RequestPressure` refusal while
/// the slot's row still binds a request and records the GET's generation as
/// refused is the binding's refusal, the Progress violation; every other
/// decided ending is judged against the resident version.
fn i8_read(world: &mut Mixed<'_, '_, '_>, drained: bool) -> u64 {
    let id = *world.history.ids.last().expect("the GET");
    if !drained && !i8_write_held(world) {
        let _ = world.collect_get(0, id);
        world.first.record(Failure::Unsuccessful(
            "the ended upload's write stayed held until the GET decided",
        ));
        return 0;
    }
    let wire = kept_attempt(world, 0, id);
    match world.scene.clients[0].outcome(id) {
        Some(Outcome::Pressure(Status::RequestPressure)) => {
            let row = world
                .scene
                .owner
                .request_slot(PeerId(0), wire.slot())
                .unwrap_or_default();
            if row.active.is_some() && row.refused == Some(wire.generation()) {
                let _ = world.collect_get(0, id);
                let _ = world.scene.clients[0].retire(id);
                return fail(
                    world,
                    Obligation::Progress,
                    "a request on an ended upload's wire slot was refused while its write drained",
                );
            }
        }
        Some(Outcome::Complete) => {
            mark(
                world,
                "the GET on the ended upload's wire slot was admitted",
            );
        }
        _ => {}
    }
    fresh_exact_of(world, &version_a())
}

fn i8_read_draining(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    i8_read(world, false)
}

fn i8_read_drained(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    i8_read(world, true)
}

/// Both I8 histories end the same upload the same way before they differ.
const I8_ENDED: [Step; 7] = [
    step("hold-writes", always, i8_hold_writes),
    step("put-begin", active_put, put_begin),
    step("put-prepare", always, put_prepare),
    step("put-supply", always, put_supply),
    step("write-held", write_held, mark_write_held),
    step("cancel-put", always, cancel_put),
    step("ended", put_decided, i8_ended),
];

const I8_DRAINING: [Step; 12] = joined(
    I8_ENDED,
    [
        step("get", active_put, i8_get_draining),
        step("read", fresh_decided, i8_read_draining),
        step("release", always, release_device),
        step("drained", upload_drained, mark_drained),
        JUDGE,
    ],
);

const I8_DRAINED: [Step; 12] = joined(
    I8_ENDED,
    [
        step("release", always, release_device),
        step("drained", upload_drained, mark_drained),
        step("get", active_put, i8_get_drained),
        step("read", fresh_decided, i8_read_drained),
        JUDGE,
    ],
);

const I8_DRAINING_WITNESSES: &[&str] = &[
    "upload DATA supplied",
    "owner write held",
    "upload cancelled with its DATA accepted",
    "the owner's PUT ERROR ended the cancelled upload at its client",
    "the ended upload's write was held at the GET",
    "the GET took the ended upload's wire slot at a higher generation",
    "the GET on the ended upload's wire slot was admitted",
    "qualified exact read",
    "the cancelled request drained after its terminal",
];

const I8_DRAINED_WITNESSES: &[&str] = &[
    "upload DATA supplied",
    "owner write held",
    "upload cancelled with its DATA accepted",
    "the owner's PUT ERROR ended the cancelled upload at its client",
    "the cancelled request drained after its terminal",
    "the ended upload drained before the GET",
    "the GET took the ended upload's wire slot at a higher generation",
    "the GET on the ended upload's wire slot was admitted",
    "qualified exact read",
];

const I8: &[Obligation] = &[Obligation::Progress, Obligation::History];

/// I9: a GET the owner refused on a wire slot that still bound a cancelled
/// GET is never admitted, also when the link lost the refusal's one ERROR
/// and the slot then freed: the owner drops the client's retransmissions,
/// the client ends at its own deadline, the owner admits no GET after the
/// successor was issued, and the slot's row keeps the refused generation
/// as its watermark with no bound request. The history holds the cancelled
/// GET's read, loses the successor's first ERROR toward the client and
/// releases the read. `i9-busy-refusal-delivered` runs the same steps over
/// a link that delivers the ERROR, where the client ends with the typed
/// refusal.
fn i9_refresh_ended(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    (0..world.scene.clients.len()).all(|client| {
        let wire = RequestId::from_wire(world.scene.template(client).request);
        world
            .scene
            .owner
            .request_slot(PeerId(client as u16), wire.slot())
            .is_some_and(|row| row.watermark == Some(wire.generation()) && row.active.is_none())
    })
}

/// Frames of `kind` the tap on the GET client's link saw toward `toward`,
/// counted by whether the link dropped them.
fn i9_captured(world: &Mixed<'_, '_, '_>, kind: Kind, toward: usize, dropped: bool) -> usize {
    world.scene.nets[1]
        .borrow()
        .rules()
        .captures()
        .iter()
        .filter(|capture| {
            capture.kind == Some(kind)
                && capture.toward == toward
                && capture.decision.drop.is_some() == dropped
        })
        .count()
}

/// The wire identities of the cancelled GET and of its successor.
fn i9_wires(world: &Mixed<'_, '_, '_>) -> (RequestId, RequestId) {
    let old = world.gets[1].as_ref().expect("the cancelled GET").id;
    let new = *world.history.ids.last().expect("the successor");
    (kept_attempt(world, 1, old), kept_attempt(world, 1, new))
}

/// The successor's wait: one retry interval after its second
/// retransmission. An unanswered GET retransmits `retry_wait(retry_us, 0)`
/// after its issue and `retry_wait(retry_us, 1)` after that, so the
/// successor sends two retransmissions and ends `TimedOut` before a third.
fn i9_wait_us() -> u64 {
    let retry_us = client_config(1).fetch.retry_us;
    let second_retransmission = retry_wait(retry_us, 0) + retry_wait(retry_us, 1);
    second_retransmission + retry_us
}

/// The successor GET on the cancelled GET's wire slot, issued while the
/// slot's row still binds the cancelled GET at its generation, over a link
/// that drops the first `lost` of the successor's ERRORs; `None` drops none.
/// The step keeps the owner's count of admitted GETs, which the judgment
/// requires unchanged.
fn i9_successor(world: &mut Mixed<'_, '_, '_>, now: u64, lost: Option<u32>) -> u64 {
    let old = world.gets[1].as_ref().expect("the cancelled GET").id;
    let old_wire = RequestId::from_wire(attempt(world, 1, old));
    let row = world
        .scene
        .owner
        .request_slot(PeerId(1), old_wire.slot())
        .unwrap_or_default();
    if row.active.is_none() || row.watermark != Some(old_wire.generation()) {
        world.first.record(Failure::Unsuccessful(
            "the cancelled GET kept its wire slot bound",
        ));
        return 0;
    }
    let issued = successor_get_named(world, now, i9_wait_us(), |id, _| id);
    if issued == STAY || issued == 0 {
        return issued;
    }
    if !world
        .history
        .marks
        .contains(&"successor reused the slot at a higher generation")
    {
        world.first.record(Failure::Unsuccessful(
            "successor reused the slot at a higher generation",
        ));
        return 0;
    }
    let (_, new) = i9_wires(world);
    let rules = lost.map_or_else(Vec::new, |take| {
        let refusal = Selector::All(vec![
            toward_client(Kind::Error),
            Selector::Request(new.wire()),
        ]);
        vec![Rule::new(refusal, Effect::Drop).window(0, take)]
    });
    i7_rules_on(world, 1, rules);
    world.history.admitted = world.scene.owner.serve_report().requests;
    mark(world, "the cancelled GET kept its wire slot bound")
}

fn i9_successor_lost(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    i9_successor(world, now, Some(1))
}

fn i9_successor_delivered(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    i9_successor(world, now, None)
}

/// The owner recorded the successor's generation as refused on the slot
/// the cancelled GET still binds.
fn i9_refused_bound(world: &Mixed<'_, '_, '_>) -> bool {
    let (old, new) = i9_wires(world);
    let row = world
        .scene
        .owner
        .request_slot(PeerId(1), new.slot())
        .unwrap_or_default();
    row.active.is_some()
        && row.watermark == Some(old.generation())
        && row.refused == Some(new.generation())
}

fn i9_refusal_lost(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    i9_refused_bound(world) && i9_captured(world, Kind::Error, CLIENT, true) >= 1
}

fn i9_refusal_sent(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    i9_refused_bound(world) && i9_captured(world, Kind::Error, CLIENT, false) >= 1
}

fn i9_mark_lost(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    mark(world, "the link lost the successor's first ERROR");
    mark(world, "the bound slot refused the successor's generation")
}

fn i9_mark_sent(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    mark(world, "the link delivered the successor's ERROR");
    mark(world, "the bound slot refused the successor's generation")
}

/// The owner holds nothing for the GET client and its slot is free at the
/// successor's generation: the device holds no command, the peer holds no
/// request, and the slot's row keeps the successor's generation as its
/// watermark with no bound request.
fn i9_idle(world: &Mixed<'_, '_, '_>) -> bool {
    let (_, new) = i9_wires(world);
    let row = world
        .scene
        .owner
        .request_slot(PeerId(1), new.slot())
        .unwrap_or_default();
    let census = world.scene.owner.peer_census(PeerId(1));
    world.scene.control.outstanding() == 0
        && census.active + census.draining == 0
        && row.active.is_none()
        && row.watermark == Some(new.generation())
}

/// The cancelled GET drained and its slot freed at the successor's
/// generation. The GET frames the link carried toward the owner so far are
/// the baseline the judge counts retransmissions from.
fn i9_healed(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if !i9_idle(world) {
        world.first.record(Failure::Unsuccessful(
            "the cancelled GET drained and freed its wire slot",
        ));
        return 0;
    }
    world.history.carried = i9_captured(world, Kind::Get, OWNER_SIDE, false) as u64;
    mark(world, "the cancelled GET drained and freed its wire slot")
}

/// [`i9_healed`] for a link that loses the refusal: the successor is still
/// undecided and the link delivered it no ERROR when its slot freed, so
/// every later retransmission meets the freed slot.
fn i9_healed_unanswered(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let id = *world.history.ids.last().expect("the successor");
    if world.collect_get(1, id).is_some() || i9_captured(world, Kind::Error, CLIENT, false) != 0 {
        world.first.record(Failure::Unsuccessful(
            "the successor was unanswered when its slot freed",
        ));
        return 0;
    }
    mark(world, "the successor was unanswered when its slot freed");
    i9_healed(world, now)
}

/// Judges the decided successor: an owner that admitted a GET since the
/// successor was issued, binds a request on the successor's slot, or
/// completed the successor admitted the refused identity, a Resources
/// violation. Otherwise the successor ended with `expected`, the outcome
/// its link leaves it; any other outcome leaves the history unsuccessful.
fn i9_judge(world: &mut Mixed<'_, '_, '_>, expected: Outcome) -> u64 {
    let id = *world.history.ids.last().expect("the successor");
    let outcome = world.collect_get(1, id);
    let _ = world.scene.clients[1].retire(id);
    let (_, new) = i9_wires(world);
    let bound = world
        .scene
        .owner
        .request_slot(PeerId(1), new.slot())
        .is_some_and(|row| row.active.is_some());
    let admitted = world.scene.owner.serve_report().requests != world.history.admitted;
    if admitted || bound || outcome == Some(Outcome::Complete) {
        return fail(
            world,
            Obligation::Resources,
            "a settled GET's row held an admitted request",
        );
    }
    if outcome != Some(expected) {
        world.first.record(Failure::Unsuccessful(
            "the refused successor ended unadmitted",
        ));
        return 0;
    }
    mark(world, "the refused successor ended unadmitted")
}

/// The successor whose refusal the link lost ends at its own deadline: at
/// least two of its retransmissions reached the owner after its slot
/// freed, and the link delivered it no ERROR. A run short of either leaves
/// the history unsuccessful once the admission judgment passed.
fn i9_judge_lost(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let resent = i9_captured(world, Kind::Get, OWNER_SIDE, false) as u64;
    let answered = i9_captured(world, Kind::Error, CLIENT, false);
    let formed = answered == 0 && resent >= world.history.carried + 2;
    if formed {
        mark(world, "the successor's retransmissions reached the owner");
    }
    let judged = i9_judge(world, Outcome::Failed(Status::TimedOut));
    if judged != 0 && !formed {
        world.first.record(Failure::Unsuccessful(
            "the successor's retransmissions reached the owner",
        ));
        return 0;
    }
    judged
}

/// The successor whose refusal the link delivered ends with it.
fn i9_judge_delivered(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    i9_judge(world, Outcome::Pressure(Status::RequestPressure))
}

/// The refused identity's row keeps its generation as the watermark and
/// binds no request once its client retired it: no retransmission was
/// admitted.
fn i9_row(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = *world.history.ids.last().expect("the successor");
    let (_, new) = i9_wires(world);
    let held = world.scene.clients[1].get_wire(id).is_some();
    i7_row(
        world,
        PeerId(1),
        new,
        held,
        "a settled GET's row held an admitted request",
        "the settled GET left no admitted request",
    )
}

const I9_LOST: [Step; 13] = [
    step("hold-reads", i9_refresh_ended, i7_hold_reads),
    step("old-get", active_get, old_get),
    step("old-read-held", read_held, mark_read_held),
    step("cancel", always, cancel_old),
    step("cancel-kept", cancel_received, cancel_kept),
    step("successor-get", active_get, i9_successor_lost),
    step("refused", i9_refusal_lost, i9_mark_lost),
    step("release-old-read", always, release_reads),
    step("drained", drained, mark_drained),
    step("healed", always, i9_healed_unanswered),
    step("successor-decided", successor_decided, i9_judge_lost),
    step("row", always, i9_row),
    JUDGE,
];

const I9_DELIVERED: [Step; 13] = replaced(
    replaced(
        replaced(
            replaced(
                I9_LOST,
                "successor-get",
                step("successor-get", active_get, i9_successor_delivered),
            ),
            "refused",
            step("refused", i9_refusal_sent, i9_mark_sent),
        ),
        "healed",
        step("healed", always, i9_healed),
    ),
    "successor-decided",
    step("successor-decided", successor_decided, i9_judge_delivered),
);

const I9_LOST_WITNESSES: &[&str] = &[
    "old read held",
    "held read cancelled",
    "the owner ended the cancelled request",
    "cancel kept custody",
    "successor reused the slot at a higher generation",
    "the cancelled GET kept its wire slot bound",
    "the link lost the successor's first ERROR",
    "the bound slot refused the successor's generation",
    "the cancelled request drained after its terminal",
    "the successor was unanswered when its slot freed",
    "the cancelled GET drained and freed its wire slot",
    "the successor's retransmissions reached the owner",
    "the refused successor ended unadmitted",
    "the settled GET left no admitted request",
];

const I9_DELIVERED_WITNESSES: &[&str] = &[
    "old read held",
    "held read cancelled",
    "the owner ended the cancelled request",
    "cancel kept custody",
    "successor reused the slot at a higher generation",
    "the cancelled GET kept its wire slot bound",
    "the link delivered the successor's ERROR",
    "the bound slot refused the successor's generation",
    "the cancelled request drained after its terminal",
    "the cancelled GET drained and freed its wire slot",
    "the refused successor ended unadmitted",
    "the settled GET left no admitted request",
];

const I9: &[Obligation] = &[Obligation::Resources];

/// I10: the owner's turn after a turn that unwound in the device submit of
/// an upload's write returns with every ready upload's held count equal to
/// its lane ring's entries, the upload ends `Unknown` with nothing published,
/// and the owner closes. The history drives the two owner turns
/// itself, in one step and each under `catch_unwind`, because the world's own
/// turn ends the run on an unwind. `i10-turn-after-submitted-upload-write`
/// runs the same turns with no unwind armed, and its upload publishes. The
/// history starts at [`i9_refresh_ended`], once the GETs the scene's setup
/// left live at both clients ended, so the upload is the only request the
/// owner holds when the two turns run.
///
/// The history judges three agreed properties. `PutCore::acknowledge`
/// asserts that a ready upload's held count equals its lane ring's entries.
/// A PUT record whose stage an unwind took ends `UnknownOutcome` at its next
/// BEGIN, PREPARE or CANCEL or at its deadline (`PutCore::live_frame`,
/// `Put::ending`). The obligation record
/// `remote-put-publishes-only-complete-current-bytes` requires every write
/// range written before a publication. Each of the history's six rule texts
/// has a control in `INCIDENTS` that replaces one step with a planted
/// defect.
///
/// `i10_granted` holds once the upload has its grant: the owner answered the
/// PREPARE with READY.
fn i10_granted(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world
        .history
        .put
        .and_then(|id| world.scene.clients[0].put_receipt(id))
        .is_some_and(|(_, _, grant)| grant > 0)
}

/// One owner turn at `now` with the world's poll bookkeeping, and the
/// payload of its unwind, if any.
fn i10_turn(world: &mut Mixed<'_, '_, '_>, now: u64) -> std::thread::Result<()> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        world.owner_turn(now);
    }))
}

/// The simulated driver's scripted unwind, as its submit raises it.
fn i10_driver_unwound(payload: &(dyn std::any::Any + Send)) -> bool {
    payload.downcast_ref::<&str>() == Some(&"the driver unwound")
}

/// The upload is the uploading peer's one request at the owner, bound at
/// the wire identity `wire`.
fn i10_live(world: &Mixed<'_, '_, '_>, wire: u64) -> bool {
    let census = world.scene.owner.peer_census(PeerId(0));
    super::cohorts::live_at_owner(world, 0, wire) && census.active + census.draining == 1
}

/// The defect a control's take step plants.
#[derive(Clone, Copy, PartialEq, Eq)]
enum I10Plant {
    /// The script's own turns, with no planted defect.
    None,
    /// The device submit of a take turn the script declares unarmed unwinds.
    UndeclaredUnwind,
    /// The owner's next turn unwinds in the driver's pick.
    NextTurnUnwinds,
    /// The ready-lane lens reports a held fragment its ring lacks.
    LanesDiffer,
}

/// Supplies the upload's one fragment, sends it, and runs the owner turn
/// that takes it, with the turn's device submit unwinding when `unwinds`;
/// then runs the owner's next turn through [`i10_next_turn`]. On the take
/// turn, an armed history resumes an unwind other than the driver's own,
/// so it ends the run as a panic, and the submitted history records any
/// unwind as a Contain violation. The armed history's witness forms only
/// when the volume counts one payload write submit whose driver call
/// unwound, so a turn that unwound in another submit leaves it unformed.
/// A control's `plant` arms the submit of an unarmed take turn or hands its
/// defect to the next turn.
fn i10_take(world: &mut Mixed<'_, '_, '_>, now: u64, unwinds: bool, plant: I10Plant) -> u64 {
    let id = world.history.put.expect("a PUT");
    if world.scene.clients[0].supply(id, 0, &version_b()).is_err() {
        return STAY;
    }
    let wire = world.scene.clients[0]
        .put_wire(id)
        .expect("a live upload names its wire");
    world.history.published = world.scene.owner.put_report().published;
    let before = world.scene.control.outstanding();
    world.polled[0] = true;
    let _ = world.scene.clients[0].poll(now);
    if unwinds || plant == I10Plant::UndeclaredUnwind {
        world.scene.control.unwind_next(Some(Unwind::Submit));
    }
    let turn = i10_turn(world, now);
    world.scene.control.unwind_next(None);
    let returned = match turn {
        Ok(()) => true,
        Err(payload) if unwinds && i10_driver_unwound(&*payload) => false,
        Err(_) if !unwinds => {
            return fail(
                world,
                Obligation::Contain,
                "the owner's turn unwound submitting the upload's write",
            );
        }
        Err(payload) => std::panic::resume_unwind(payload),
    };
    let after = world.scene.control.outstanding();
    let (witness, formed) = if unwinds {
        (
            "the owner's turn unwound in the upload's write submit",
            !returned
                && world.scene.owner.poisoned()
                && after == before
                && world.scene.owner.unwound_writes() == 1
                && i10_live(world, wire),
        )
    } else {
        (
            "the owner's turn submitted the upload's write",
            !world.scene.owner.poisoned() && after > before && i10_live(world, wire),
        )
    };
    if !formed {
        world.first.record(Failure::Unsuccessful(witness));
        return 0;
    }
    mark(world, witness);
    i10_next_turn(world, now, plant)
}

/// The owner's turn after the take turn returns, with every ready upload's
/// held count equal to its lane ring's entries; an unwind of it is a
/// Contain violation in both histories. A control's `plant` makes the turn
/// unwind in the driver's pick, or replaces the lens reading with one held
/// fragment over an empty ring.
fn i10_next_turn(world: &mut Mixed<'_, '_, '_>, now: u64, plant: I10Plant) -> u64 {
    if plant == I10Plant::NextTurnUnwinds {
        world.scene.control.unwind_next(Some(Unwind::Pick));
    }
    let turn = i10_turn(world, now);
    world.scene.control.unwind_next(None);
    if turn.is_err() {
        return fail(
            world,
            Obligation::Contain,
            "an owner turn unwound after the upload's write submit",
        );
    }
    let lanes = match plant {
        I10Plant::LanesDiffer => vec![(1, 0)],
        _ => world.scene.owner.put_ready_lanes(),
    };
    if lanes.iter().any(|&(held, ring)| held as usize != ring) {
        return fail(
            world,
            Obligation::Contain,
            "an upload's held count left its lane ring's entries",
        );
    }
    mark(world, "the owner's next turn returned")
}

fn i10_take_unwound(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    i10_take(world, now, true, I10Plant::None)
}

fn i10_take_submitted(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    i10_take(world, now, false, I10Plant::None)
}

/// A control: the submit of the take turn unwinds in the history that
/// declares the turn unarmed.
fn i10_take_undeclared(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    i10_take(world, now, false, I10Plant::UndeclaredUnwind)
}

/// A control: the owner's turn after the unwound take turn unwinds.
fn i10_take_next_unwound(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    i10_take(world, now, true, I10Plant::NextTurnUnwinds)
}

/// A control: after the next turn the lens reports an upload holding one
/// fragment its lane ring lacks.
fn i10_take_lanes_differ(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    i10_take(world, now, true, I10Plant::LanesDiffer)
}

/// The upload whose write submit unwound ends `Unknown` with nothing
/// published. A `NotStarted` or `Failed` outcome claims no effect, and a
/// publication is one the client reports or one the owner's count shows
/// since the take step; each fails under History.
fn i10_unpublished(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    let outcome = world.collect_put(id);
    i10_judge(world, outcome)
}

/// A control: the client reports `NotStarted` for the upload the owner
/// admitted.
fn i10_no_effect(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    i10_judge(world, Some(UploadOutcome::NotStarted))
}

/// A control: the client reports a publication for the upload whose write
/// submit unwound.
fn i10_published(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    i10_judge(world, Some(UploadOutcome::Published))
}

/// Judges `outcome` as [`i10_unpublished`] states, for the collected
/// outcome and for a control's planted one.
fn i10_judge(world: &mut Mixed<'_, '_, '_>, outcome: Option<UploadOutcome>) -> u64 {
    let id = world.history.put.expect("a PUT");
    let published = world.scene.owner.put_report().published != world.history.published;
    match outcome {
        None => {
            world.first.record(Failure::Unsuccessful(
                "the upload whose write unwound ended unpublished",
            ));
            0
        }
        Some(UploadOutcome::NotStarted | UploadOutcome::Failed(_)) => fail(
            world,
            Obligation::History,
            "an admitted upload whose write submit unwound claimed no effect",
        ),
        Some(outcome) if published || outcome == UploadOutcome::Published => fail(
            world,
            Obligation::History,
            "an upload whose write submit unwound published",
        ),
        Some(_) => {
            let _ = world.scene.clients[0].abandon(id);
            let _ = world.scene.clients[0].retire(id);
            mark(world, "the upload whose write unwound ended unpublished")
        }
    }
}

/// The owner closes without unwinding.
fn i10_close(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let unwound = i10_closed(world, now);
    i10_judge_close(world, unwound)
}

/// A control: the owner's close is judged as one that unwound.
fn i10_close_unwound(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let _ = i10_closed(world, now);
    i10_judge_close(world, true)
}

/// Closes the owner under `catch_unwind` and reports whether the close
/// unwound.
fn i10_closed(world: &mut Mixed<'_, '_, '_>, now: u64) -> bool {
    let closed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = world.scene.owner.close(now);
    }));
    world.closed = true;
    closed.is_err()
}

fn i10_judge_close(world: &mut Mixed<'_, '_, '_>, unwound: bool) -> u64 {
    if unwound {
        return fail(
            world,
            Obligation::Contain,
            "the owner's close unwound after the upload's write submit",
        );
    }
    mark(world, "the owner closed")
}

const I10_UNWOUND: [Step; 6] = [
    step("put-begin", i9_refresh_ended, put_begin),
    step("put-prepare", active_put, put_prepare),
    step("take-unwound", i10_granted, i10_take_unwound),
    step("put-result", put_decided, i10_unpublished),
    step("close", always, i10_close),
    JUDGE,
];

const I10_SUBMITTED: [Step; 6] = replaced(
    replaced(
        I10_UNWOUND,
        "take-unwound",
        step("take-submitted", i10_granted, i10_take_submitted),
    ),
    "put-result",
    step("put-result", put_decided, put_published),
);

const I10_UNDECLARED: [Step; 6] = replaced(
    I10_SUBMITTED,
    "take-submitted",
    step("take-undeclared-unwind", i10_granted, i10_take_undeclared),
);

const I10_NEXT_UNWOUND: [Step; 6] = replaced(
    I10_UNWOUND,
    "take-unwound",
    step("take-next-unwound", i10_granted, i10_take_next_unwound),
);

const I10_LANES_DIFFER: [Step; 6] = replaced(
    I10_UNWOUND,
    "take-unwound",
    step("take-lanes-differ", i10_granted, i10_take_lanes_differ),
);

const I10_NO_EFFECT: [Step; 6] = replaced(
    I10_UNWOUND,
    "put-result",
    step("put-no-effect", put_decided, i10_no_effect),
);

const I10_PUBLISHED: [Step; 6] = replaced(
    I10_UNWOUND,
    "put-result",
    step("put-published", put_decided, i10_published),
);

const I10_CLOSE_UNWOUND: [Step; 6] = replaced(
    I10_UNWOUND,
    "close",
    step("close-unwound", always, i10_close_unwound),
);

const I10_UNWOUND_WITNESSES: &[&str] = &[
    "upload prepared",
    "the owner's turn unwound in the upload's write submit",
    "the owner's next turn returned",
    "the upload whose write unwound ended unpublished",
    "the owner closed",
];

const I10_SUBMITTED_WITNESSES: &[&str] = &[
    "upload prepared",
    "the owner's turn submitted the upload's write",
    "the owner's next turn returned",
    "upload published",
    "the owner closed",
];

const I10: &[Obligation] = &[Obligation::Contain, Obligation::History];

const I10_PREPARED_PREMISE: &[&str] = &["upload prepared"];

const I10_TAKEN_PREMISE: &[&str] = &[
    "upload prepared",
    "the owner's turn unwound in the upload's write submit",
];

const I10_RETURNED_PREMISE: &[&str] = &[
    "upload prepared",
    "the owner's turn unwound in the upload's write submit",
    "the owner's next turn returned",
];

const I10_ENDED_PREMISE: &[&str] = &[
    "upload prepared",
    "the owner's turn unwound in the upload's write submit",
    "the owner's next turn returned",
    "the upload whose write unwound ended unpublished",
];

/// The oracle's rule for an owner that begins a fill for a wire identity whose
/// upload already ended.
const FILLED_AFTER_AUTHORITY: &str = "the owner filled after the attempt's authority";

/// Link turns the first BEGIN waits: 10,000 us, past the client's first
/// retransmission at 3,000 us and the whole upload that retransmission starts.
const LATE_TURNS: u64 = 100;

/// Link turns between the upload's decision and the late turn that the premise
/// requires, and the turns past the late turn before the owner is judged: the
/// late BEGIN's delivery, the owner's turn and its answer's way back.
const MARGIN_TURNS: u64 = 4;
const SETTLE_TURNS: u64 = 20;

const LINK_ARMED: &str = "the link took its rules";
const BEGIN_DELAYED: &str = "the first BEGIN was delayed";
const BEGIN_PROMPT: &str = "the first BEGIN was delivered promptly";
const ENDED_EARLY: &str = "the upload ended before the link's late turn";
const LATE_ANSWERED: &str = "the owner answered the late BEGIN";
const OWNER_SILENT: &str = "the owner sent nothing after the RESULT";
const ONE_FILL: &str = "the wire identity began one fill";

/// Gives the uploading client's link `rules`, tapped after the last so each
/// capture holds the decision the link committed, and keeps the uploads the
/// owner has begun so far.
fn arm_link(world: &mut Mixed<'_, '_, '_>, rules: Vec<Rule>) -> u64 {
    set_rules(world, rules);
    world.history.begun = world.scene.owner.put_report().begun;
    mark(world, LINK_ARMED)
}

/// The first PUT BEGIN toward the owner waits LATE_TURNS turns; every later one
/// is delivered as sent.
fn delay_first_begin(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let begin = Selector::All(vec![
        Selector::Kind(Kind::PutBegin),
        Selector::Toward(OWNER_SIDE),
    ]);
    arm_link(
        world,
        vec![Rule::new(begin, Effect::Delay(LATE_TURNS)).window(0, 1)],
    )
}

/// The sibling history's link carries every frame as sent.
fn i12_delay_nothing(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    arm_link(world, Vec::new())
}

/// Starts the upload and keeps the wire identity its frames carry, read while
/// the upload is live.
fn i12_begin(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let begun = put_begin(world, now);
    if begun == STAY {
        return STAY;
    }
    let id = world.history.put.expect("the upload");
    let wire = world.scene.clients[0]
        .put_wire(id)
        .expect("a live upload names its wire");
    world.history.attempts.push((0, id, wire));
    begun
}

/// The client took the owner's AUTHORITY: its upload names a fill serial. Until
/// then the client refuses a PREPARE, so the step that prepares waits behind
/// this guard and lets the clock reach the retransmission.
fn i12_authorized(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world.history.put.is_some_and(|id| {
        world.scene.clients[0]
            .put_receipt(id)
            .is_some_and(|(serial, _, _)| serial != 0)
    })
}

/// The delay each PUT BEGIN the link carried toward the owner took, in the
/// order sent.
fn begin_delays(world: &Mixed<'_, '_, '_>) -> Vec<Option<u64>> {
    world.scene.nets[0]
        .borrow()
        .rules()
        .captures()
        .iter()
        .filter(|capture| capture.kind == Some(Kind::PutBegin) && capture.toward == OWNER_SIDE)
        .map(|capture| capture.decision.delay)
        .collect()
}

fn begin_sent(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    !begin_delays(world).is_empty()
}

/// Keeps the link's late turn, LATE_TURNS turns after the first BEGIN was sent,
/// in both histories. The step runs in the turn's own time: its guard holds
/// from the send on, and the clock stands while a step is runnable.
fn note_begin(world: &mut Mixed<'_, '_, '_>, now: u64, delayed: bool) -> u64 {
    world.history.arrival = now + LATE_TURNS * super::super::LINK_TURN_US;
    let first = begin_delays(world).first().copied().flatten();
    let late = first == Some(LATE_TURNS);
    premised(
        world,
        late == delayed,
        if delayed { BEGIN_DELAYED } else { BEGIN_PROMPT },
    )
}

fn note_delayed(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    note_begin(world, now, true)
}

fn note_prompt(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    note_begin(world, now, false)
}

/// Frames the owner sent the client that end or answer an upload's BEGIN:
/// AUTHORITY, RESULT and ERROR.
fn owner_answers(world: &Mixed<'_, '_, '_>) -> usize {
    world.scene.nets[0]
        .borrow()
        .rules()
        .captures()
        .iter()
        .filter(|capture| {
            capture.toward == CLIENT
                && matches!(
                    capture.kind,
                    Some(Kind::PutAuthority | Kind::PutResult | Kind::PutError)
                )
        })
        .count()
}

/// The client decided the upload published and retires it. The premise forms
/// when that decision came MARGIN_TURNS turns or more before the late turn: the
/// owner freed the upload's record before it sent the RESULT the client decided
/// on. The answers so far are kept, and the history wakes past the late turn.
fn published_first(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if put_published(world, now) == 0 {
        return 0;
    }
    let early = now + MARGIN_TURNS * super::super::LINK_TURN_US <= world.history.arrival;
    world.history.results = owner_answers(world);
    world.history.deadline = world.history.arrival + SETTLE_TURNS * super::super::LINK_TURN_US;
    world.history.wake = Some(world.history.deadline + 1);
    premised(world, early, ENDED_EARLY)
}

fn late_turn_passed(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    now > world.history.deadline
}

/// The owner sent the client a frame after the upload's RESULT, its answer to
/// the BEGIN that arrived late. The owner sends a RESULT once at the
/// publication and otherwise only in answer to a frame.
fn late_answered(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let answered = owner_answers(world) > world.history.results;
    premised(world, answered, LATE_ANSWERED)
}

/// The sibling history: no BEGIN arrived late, so the owner sent the client
/// nothing more.
fn nothing_late(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let silent = owner_answers(world) == world.history.results;
    premised(world, silent, OWNER_SILENT)
}

/// The judgment: since the link was armed the owner began one fill, and the
/// upload's wire slot binds no request at the upload's generation. A second
/// fill or a bound request is an attempt the owner filled after its authority.
fn one_fill(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let begun = world.scene.owner.put_report().begun - world.history.begun;
    let wire = world
        .history
        .attempts
        .first()
        .map(|&(_, _, wire)| RequestId::from_wire(wire))
        .expect("the upload's wire was kept");
    let row = world
        .scene
        .owner
        .request_slot(PeerId(0), wire.slot())
        .unwrap_or_default();
    let bound = row.watermark == Some(wire.generation()) && row.active.is_some();
    if begun > 1 || bound {
        return fail(world, Obligation::History, FILLED_AFTER_AUTHORITY);
    }
    premised(world, begun == 1, ONE_FILL)
}

/// I12: a PUT BEGIN that arrives after its upload ended starts no second
/// fill for that wire identity. A link rule delays the client's first PUT
/// BEGIN toward the owner; the client's retransmission, which carries the
/// same wire identity, wins the owner's authority, and the upload publishes
/// and is retired before the delayed BEGIN arrives. That BEGIN then meets a
/// free binding: the owner must answer it and must have begun exactly one
/// fill for the identity, with no request bound to the wire slot. The
/// premises are the first BEGIN's delay, the publication before the link's
/// late turn, and the owner's answer to the late BEGIN. No RESULT is
/// delayed, and the judgment reads the owner's counter and row only.
const I12_LATE_BEGIN: [Step; 9] = [
    step("arm-link", always, delay_first_begin),
    step("put-begin", active_put, i12_begin),
    step("begin-sent", begin_sent, note_delayed),
    step("put-prepare", i12_authorized, put_prepare),
    step("put-supply", always, put_supply),
    step("put-result", put_decided, published_first),
    step("late-turn", late_turn_passed, late_answered),
    step("fills", always, one_fill),
    JUDGE,
];

/// The sibling: the same steps with no rule on the link. The one BEGIN is
/// delivered promptly, the owner sends the client nothing after the
/// upload's RESULT, and it began one fill.
const I12_PROMPT_BEGIN: [Step; 9] = replaced(
    replaced(
        replaced(
            I12_LATE_BEGIN,
            "arm-link",
            step("arm-link", always, i12_delay_nothing),
        ),
        "begin-sent",
        step("begin-sent", begin_sent, note_prompt),
    ),
    "late-turn",
    step("late-turn", late_turn_passed, nothing_late),
);

/// A control: the judgment runs while the upload is live. The client holds
/// the owner's AUTHORITY and the owner has begun the upload's one fill, so
/// the wire slot binds the upload's request at its generation and the
/// judgment fails that binding through its rule.
const I12_JUDGED_LIVE: [Step; 6] = [
    step("arm-link", always, i12_delay_nothing),
    step("put-begin", active_put, i12_begin),
    step("begin-sent", begin_sent, note_prompt),
    step("put-prepare", i12_authorized, put_prepare),
    step("fills", always, one_fill),
    JUDGE,
];

const I12_LATE_WITNESSES: &[&str] = &[
    LINK_ARMED,
    BEGIN_DELAYED,
    "upload DATA supplied",
    "upload published",
    ENDED_EARLY,
    LATE_ANSWERED,
    ONE_FILL,
];

const I12_PROMPT_WITNESSES: &[&str] = &[
    LINK_ARMED,
    BEGIN_PROMPT,
    "upload DATA supplied",
    "upload published",
    ENDED_EARLY,
    OWNER_SILENT,
    ONE_FILL,
];

const I12: &[Obligation] = &[Obligation::History];

const I12_LIVE_PREMISE: &[&str] = &[BEGIN_PROMPT, "upload prepared"];

/// The oracle's rule for an owner whose fill or READY names lengths other
/// than its BEGIN's.
const ANOTHER_MANIFEST: &str = "the owner prepared another manifest";

const OWNER_PUBLISHED: &str = "the owner published the upload";
const RECORD_BOUND: &str = "the index bound the upload's key to a record";
const RECORD_KEPT: &str = "the published record keeps the prepared lengths";
const RECORD_DAMAGED: &str = "the published record was damaged on the device";

/// I13's metadata length, inside the storage's metadata bound of 64 bytes.
const METADATA: u32 = 32;

/// Begins the upload of `version_b` under key 1 and registers its first
/// `METADATA` bytes as metadata.
fn begin_with_metadata(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let Ok(id) = world.scene.clients[0].put(
        key(1),
        crate::storage::CacheVersion(0),
        now,
        super::super::WAIT_US,
    ) else {
        return STAY;
    };
    world.plan.puts -= 1;
    world
        .registry
        .borrow_mut()
        .register(key(1), LABEL_B, METADATA, version_b());
    world.history.put = Some(id);
    world.history.since = now;
    mark(world, "upload begun")
}

/// Prepares `METADATA` bytes of metadata and the rest of `version_b` as the
/// body.
fn prepare_with_metadata(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    let body = version_b().len() as u32 - METADATA;
    match world.scene.clients[0].prepare(id, METADATA, body, super::super::TTL_MS) {
        Ok(()) => mark(world, "upload prepared"),
        Err(_) => STAY,
    }
}

/// The owner counted a publication, or the client learned the upload's end
/// without one.
fn published_or_decided(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    world.scene.owner.put_report().published > 0 || put_decided(world, now)
}

/// `bound_lengths` reads the metadata and payload lengths from device media
/// for the record bound to key 1. An unbound key yields `None`.
///
/// # Errors
///
/// `bound_lengths` maps errors reading bindings or slot facts to
/// `Failure::Unsuccessful` and propagates `Media::bound_record` errors
/// unchanged.
fn bound_lengths(world: &Mixed<'_, '_, '_>) -> Result<Option<(u32, usize)>, Failure> {
    let media = world.scene.media();
    let storage = media.storage();
    let (mut bindings, mut facts, mut record) = (Vec::new(), Vec::new(), Vec::new());
    let unreadable = |_| Failure::Unsuccessful("the storage was no longer live");
    storage.bindings_into(&mut bindings).map_err(unreadable)?;
    storage.slot_facts_into(&mut facts).map_err(unreadable)?;
    let wanted = key(1);
    for &binding in &bindings {
        let (bound, metadata, payload) = media.bound_record(binding, &facts, &mut record)?;
        if bound == wanted {
            return Ok(Some((metadata, payload.len())));
        }
    }
    Ok(None)
}

/// Judges the published record's lengths against `metadata` and the length
/// of `version_b`. The run requires both owner publication and a binding
/// for key 1. If either premise fails, the step records
/// `Failure::Unsuccessful` under that premise's name. A record that fails
/// the media read's checks ends the step in that read's violation.
fn judge_record(world: &mut Mixed<'_, '_, '_>, metadata: u32) -> u64 {
    if world.scene.owner.put_report().published == 0 {
        world.first.record(Failure::Unsuccessful(OWNER_PUBLISHED));
        return 0;
    }
    let recorded = match bound_lengths(world) {
        Ok(Some(recorded)) => recorded,
        Ok(None) => {
            world.first.record(Failure::Unsuccessful(RECORD_BOUND));
            return 0;
        }
        Err(Failure::Violation(obligation, rule)) => return fail(world, obligation, rule),
        Err(failure) => {
            world.first.record(failure);
            return 0;
        }
    };
    if recorded != (metadata, version_b().len()) {
        return fail(world, Obligation::History, ANOTHER_MANIFEST);
    }
    mark(world, RECORD_KEPT)
}

fn record_keeps_metadata(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    judge_record(world, METADATA)
}

fn record_keeps_no_metadata(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    judge_record(world, 0)
}

fn damaged_record_judged(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let published = world.scene.owner.put_report().published > 0;
    if published && super::super::bundle::change_published(&world.scene, 1) {
        mark(world, RECORD_DAMAGED);
    }
    record_keeps_metadata(world, now)
}

/// I13: the owner reserves and publishes an upload with the metadata and
/// body lengths its PREPARE named. The client registers its content with a
/// metadata length of 32 of its bytes, prepares those lengths and supplies
/// the bytes. In the owner turn that raises the owner's published count, a
/// step reads the record the index binds key 1 to from the device media
/// and fails unless the record's metadata length and payload length are
/// the prepared ones. The oracle raises the same rule from the owner's
/// Fill and Ready rows; this history reads the media, because those rows
/// repeat the lengths the PREPARE named whatever the owner reserved.
const I13_WITH_METADATA: [Step; 6] = [
    step("put-begin", active_put, begin_with_metadata),
    step("put-prepare", always, prepare_with_metadata),
    step("put-supply", always, put_supply),
    step(
        "published-record",
        published_or_decided,
        record_keeps_metadata,
    ),
    step("put-result", put_decided, put_published),
    JUDGE,
];

/// The sibling: the same steps with a prepared metadata length of 0.
const I13_WITHOUT_METADATA: [Step; 6] = [
    step("put-begin", active_put, put_begin),
    step("put-prepare", always, put_prepare),
    step("put-supply", always, put_supply),
    step(
        "published-record",
        published_or_decided,
        record_keeps_no_metadata,
    ),
    step("put-result", put_decided, put_published),
    JUDGE,
];

/// The damage step targets the record the owner published before the
/// judge reads it.
const I13_RECORD_DAMAGED: [Step; 6] = replaced(
    I13_WITH_METADATA,
    "published-record",
    step(
        "published-record-damaged",
        published_or_decided,
        damaged_record_judged,
    ),
);

/// The record retains its published metadata, but the replacement step
/// expects zero metadata.
const I13_JUDGED_WITHOUT_METADATA: [Step; 6] = replaced(
    I13_WITH_METADATA,
    "published-record",
    step(
        "published-record-as-no-metadata",
        published_or_decided,
        record_keeps_no_metadata,
    ),
);

const I13_WITNESSES: &[&str] = &[
    "upload prepared",
    "upload DATA supplied",
    RECORD_KEPT,
    "upload published",
];

/// A kill under the media read's rule requires `RECORD_DAMAGED` as evidence
/// that the damage step reached the owner's published record.
const I13_DAMAGED_PREMISE: &[&str] = &[RECORD_DAMAGED];

/// A manifest-rule kill requires evidence of both upload preparation and
/// DATA supply.
const I13_JUDGED_PREMISE: &[&str] = &["upload prepared", "upload DATA supplied"];

const I13: &[Obligation] = &[Obligation::History];

const BYTES_HISTORY: &[Obligation] = &[Obligation::Bytes, Obligation::History];
const I2: &[Obligation] = &[
    Obligation::Contain,
    Obligation::Bytes,
    Obligation::Custody,
    Obligation::Progress,
];
const I4: &[Obligation] = &[
    Obligation::Resources,
    Obligation::History,
    Obligation::Progress,
];
const I5_OBLIGATIONS: &[Obligation] = &[Obligation::Resources, Obligation::Progress];
const I3_GET: &[Obligation] = &[Obligation::Bytes, Obligation::Progress];
const I3_HOLE: &[Obligation] = &[
    Obligation::Bytes,
    Obligation::History,
    Obligation::Custody,
    Obligation::Progress,
];
const I3_DUPLICATE: &[Obligation] = &[
    Obligation::Contain,
    Obligation::Bytes,
    Obligation::History,
    Obligation::Resources,
    Obligation::Progress,
];
const I3_RESULT: &[Obligation] = &[Obligation::Bytes, Obligation::History, Obligation::Progress];
const I4_SHARE: &[Obligation] = &[Obligation::Resources, Obligation::Progress];
const I4_GET_SPACE_OBLIGATIONS: &[Obligation] = &[Obligation::History, Obligation::Progress];
const I2_PUT_OBLIGATIONS: &[Obligation] = &[
    Obligation::Contain,
    Obligation::Custody,
    Obligation::Progress,
];
const I1: &[Obligation] = &[Obligation::Bytes, Obligation::History, Obligation::Custody];

/// I11: a resident published earlier in an index chain is still read after
/// an insert into that chain. The `index::summary` module documentation
/// states that a chain's summary word never excludes a present tag, because
/// an insert stores the exact union over the chain's occupied pairs; a word
/// that excluded the resident's tag would make its lookup miss. The scene
/// publishes key 1, the resident, before the run, and each root draws the
/// hasher's key pair, so each run takes as its other key the lowest key
/// from 2 up that [`i11_joins_chain`] accepts under that pair.
/// `i11-resident-read-after-insert` uploads an object under the other key,
/// requires the owner's index to bind it, and then reads the resident with
/// a GET of client 1, which must complete with the resident's exact bytes.
/// `i11-resident-read-alone` runs the same GET with nothing bound under
/// the other key. `i11-resident-read-judged-missed` is the control: the
/// first history's steps with the resident's GET judged as a miss.
const I11_SHARED: &str =
    "the other key's insert joins the resident's chain with other summary bits";
const I11_INSERTED: &str = "the owner's index bound the uploaded key before the resident's GET";
const I11_ALONE: &str = "the owner's index bound nothing under the other key";
const I11_ISSUED: &str = "the resident's GET was issued";
const I11_READ: &str = "the resident's GET completed with the resident's exact bytes";

/// Whether an insert of key `name` joins the resident's chain and leaves
/// the summary the resident needs: both keys route to one base bucket of
/// one shard, and the resident's tag selects a summary bit that `name`'s
/// tag does not, so a word holding `name`'s bits alone excludes the
/// resident.
fn i11_joins_chain(world: &Mixed<'_, '_, '_>, name: u8) -> bool {
    let storage = world.storage();
    let (Some(resident), Some(other)) = (storage.route(&key(1)), storage.route(&key(name))) else {
        return false;
    };
    let needed = crate::index::summary_bits(resident.tag());
    resident.shard() == other.shard()
        && resident.bucket() == other.bucket()
        && needed & !crate::index::summary_bits(other.tag()) != 0
}

/// The run's other key, marked as chosen; a run whose hasher routes no
/// key into the resident's chain ends unsuccessful.
fn i11_other(world: &mut Mixed<'_, '_, '_>) -> Option<u8> {
    let other = (2..=u8::MAX).find(|&name| i11_joins_chain(world, name));
    if other.is_none() {
        world.first.record(Failure::Unsuccessful(I11_SHARED));
    } else if !world.history.marks.contains(&I11_SHARED) {
        mark(world, I11_SHARED);
    }
    other
}

/// Starts client 0's PUT of `version_b` under the other key, registered
/// under `LABEL_B`.
fn i11_begin(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let Some(other) = i11_other(world) else {
        return 0;
    };
    let Ok(id) = world.scene.clients[0].put(
        key(other),
        crate::storage::CacheVersion(0),
        now,
        super::super::WAIT_US,
    ) else {
        return STAY;
    };
    world.plan.puts -= 1;
    world
        .registry
        .borrow_mut()
        .register(key(other), LABEL_B, 0, version_b());
    world.history.put = Some(id);
    world.history.since = now;
    mark(world, "upload begun")
}

/// The premise after the upload's result and before the resident's GET:
/// the index binds the other key to its record, read from the index's
/// bindings and the record's key. A run without the binding ends
/// unsuccessful.
fn i11_inserted(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let Some(other) = i11_other(world) else {
        return 0;
    };
    if world.binding(other).is_none() {
        world.first.record(Failure::Unsuccessful(I11_INSERTED));
        return 0;
    }
    mark(world, I11_INSERTED)
}

/// The premise without the upload: the index binds nothing under the
/// other key.
fn i11_absent(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let Some(other) = i11_other(world) else {
        return 0;
    };
    if world.binding(other).is_some() {
        world.first.record(Failure::Unsuccessful(I11_ALONE));
        return 0;
    }
    mark(world, I11_ALONE)
}

/// Client 1's GET of the resident.
fn i11_get(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if old_get(world, now) == STAY {
        return STAY;
    }
    mark(world, I11_ISSUED)
}

/// Judges the resident's decided GET: anything but a complete read of its
/// exact bytes fails.
fn i11_judge(world: &mut Mixed<'_, '_, '_>, outcome: Option<Outcome>, bytes: &[u8]) -> u64 {
    if !super::cohorts::read_exact(outcome, bytes, &version_a()) {
        return fail(
            world,
            Obligation::Progress,
            "unrelated work stalled or read bytes outside the visible versions",
        );
    }
    mark(world, I11_READ)
}

fn i11_read(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.read(1);
    let get = world.gets[1].as_ref().expect("the resident's GET");
    let (outcome, bytes) = (get.outcome, get.bytes.clone());
    i11_judge(world, outcome, &bytes)
}

/// A control: the resident's GET is judged as the miss a summary word
/// without the resident's bits gives.
fn i11_read_as_missed(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.read(1);
    i11_judge(world, Some(Outcome::Missing), &[])
}

const I11_AFTER_INSERT: [Step; 8] = [
    step("put-begin", active_put, i11_begin),
    step("put-prepare", always, put_prepare),
    step("put-supply", always, put_supply),
    step("put-result", put_decided, put_published),
    step("other-bound", always, i11_inserted),
    step("resident-get", active_get, i11_get),
    step("resident-read", old_decided, i11_read),
    JUDGE,
];

const I11_JUDGED_MISSED: [Step; 8] = replaced(
    I11_AFTER_INSERT,
    "resident-read",
    step("resident-read-as-missed", old_decided, i11_read_as_missed),
);

const I11_NO_INSERT: [Step; 4] = [
    step("other-absent", always, i11_absent),
    step("resident-get", active_get, i11_get),
    step("resident-read", old_decided, i11_read),
    JUDGE,
];

const I11_AFTER_INSERT_WITNESSES: &[&str] = &[
    "upload published",
    I11_SHARED,
    I11_INSERTED,
    I11_ISSUED,
    I11_READ,
];

const I11_NO_INSERT_WITNESSES: &[&str] = &[I11_SHARED, I11_ALONE, I11_ISSUED, I11_READ];

const I11_PREMISE: &[&str] = &[I11_SHARED, I11_INSERTED, I11_ISSUED];

const I11: &[Obligation] = &[Obligation::Progress];

/// I14: an upload's outcome, once `Published`, stays `Published` when the
/// session that carried the upload is replaced. The oracle raises "a known
/// attempt result changed" from two result rows of one attempt
/// (`oracle/attempts.rs`, `judge_results`); the histories judge the client
/// through the same text. `i14-known-result-across-fresh-session` uploads
/// under key 1 and reads the outcome without retiring the upload, which
/// must read `Published`. The client then opens a fresh session beside its
/// active one. Once its active session epoch changed, which is when the
/// client ends the replaced session's requests, the same upload is read
/// again and must still read `Published`; it is retired only after that
/// second reading. `i14-known-result-in-one-session` takes the same two
/// readings with the session left as it is. A premise that does not form
/// ends the run unsuccessful under its name. `i14-known-result-changed` is a
/// control: the first history's steps, with the second reading judged as
/// `Failed(TimedOut)`.
const I14_FIRST_PUBLISHED: &str = "the first reading was Published";
const I14_OPENED: &str = "a fresh session opened";
const I14_REPLACED: &str = "the session was replaced";
const I14_KEPT: &str = "the session stayed";
const I14_STAYED: &str = "the known result stayed";

/// The first reading of the decided upload, collected and left unretired,
/// with the epoch of the session that carried it. A reading other than
/// `Published` forms no premise.
fn i14_first_reading(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    let outcome = world.collect_put(id);
    world.history.old_epoch = world.scene.clients[0].session_epoch();
    let carried = world.history.old_epoch.is_some();
    premised(
        world,
        carried && outcome == Some(UploadOutcome::Published),
        I14_FIRST_PUBLISHED,
    )
}

/// Opens a fresh session beside the active one; the wait for its
/// activation starts here.
fn i14_open_fresh(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.scene.clients[0].session(now);
    world.history.since = now;
    mark(world, I14_OPENED)
}

/// The client's active session is another than the one that carried the
/// upload.
fn i14_session_replaced(world: &Mixed<'_, '_, '_>) -> bool {
    let epoch = world.scene.clients[0].session_epoch();
    world.active(0) && epoch.is_some() && epoch != world.history.old_epoch
}

/// The fresh session replaced the old one, or the wait a request is given
/// passed without it.
fn i14_replaced_or_late(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    i14_session_replaced(world) || now >= world.history.since + super::super::WAIT_US
}

/// The second reading of the same upload, which fails unless it still
/// reads `Published`.
fn i14_second_reading(world: &mut Mixed<'_, '_, '_>) -> u64 {
    let id = world.history.put.expect("a PUT");
    let again = world.scene.clients[0].put_outcome(id);
    i14_judge_second(world, again)
}

/// The first reading established `Published`; the second, `again`, must
/// match.
fn i14_judge_second(world: &mut Mixed<'_, '_, '_>, again: Option<UploadOutcome>) -> u64 {
    let id = world.history.put.expect("a PUT");
    if again != Some(UploadOutcome::Published) {
        if let Some(again) = again {
            world
                .collected
                .add(super::super::bundle::Collected::Put(0, 0, again));
        }
        return fail(world, Obligation::History, "a known attempt result changed");
    }
    let _ = world.scene.clients[0].retire(id);
    mark(world, I14_STAYED)
}

/// Reads the upload again once the client's session epoch changed.
fn i14_reread_replaced(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let formed = i14_session_replaced(world);
    if premised(world, formed, I14_REPLACED) == 0 {
        return 0;
    }
    i14_second_reading(world)
}

/// A control: once the session was replaced, the second reading is judged
/// as `Failed(TimedOut)`, as a client that ended the replaced session's
/// published upload with its other requests would report it.
fn i14_reread_changed(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let formed = i14_session_replaced(world);
    if premised(world, formed, I14_REPLACED) == 0 {
        return 0;
    }
    i14_judge_second(world, Some(UploadOutcome::Failed(Status::TimedOut)))
}

/// A control: once the session was replaced, the second reading is judged
/// as absent, as a client that released the replaced session's published
/// upload with its other requests would report it.
fn i14_reread_dropped(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let formed = i14_session_replaced(world);
    if premised(world, formed, I14_REPLACED) == 0 {
        return 0;
    }
    i14_judge_second(world, None)
}

/// Reads the upload again while the session that carried it is still the
/// active one.
fn i14_reread_kept(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let epoch = world.scene.clients[0].session_epoch();
    let formed = world.active(0) && epoch == world.history.old_epoch;
    if premised(world, formed, I14_KEPT) == 0 {
        return 0;
    }
    i14_second_reading(world)
}

const I14_FRESH_SESSION: [Step; 7] = [
    step("put-begin", active_put, put_begin),
    step("put-prepare", always, put_prepare),
    step("put-supply", always, put_supply),
    step("first-reading", put_decided, i14_first_reading),
    step("fresh-session", always, i14_open_fresh),
    step("second-reading", i14_replaced_or_late, i14_reread_replaced),
    JUDGE,
];

const I14_ONE_SESSION: [Step; 6] = [
    step("put-begin", active_put, put_begin),
    step("put-prepare", always, put_prepare),
    step("put-supply", always, put_supply),
    step("first-reading", put_decided, i14_first_reading),
    step("second-reading", always, i14_reread_kept),
    JUDGE,
];

const I14_RESULT_CHANGED: [Step; 7] = replaced(
    I14_FRESH_SESSION,
    "second-reading",
    step(
        "second-reading-changed",
        i14_replaced_or_late,
        i14_reread_changed,
    ),
);

const I14_RESULT_DROPPED: [Step; 7] = replaced(
    I14_FRESH_SESSION,
    "second-reading",
    step(
        "second-reading-dropped",
        i14_replaced_or_late,
        i14_reread_dropped,
    ),
);

const I14_FRESH_WITNESSES: &[&str] = &[
    "upload prepared",
    "upload DATA supplied",
    I14_FIRST_PUBLISHED,
    I14_OPENED,
    I14_REPLACED,
    I14_STAYED,
];

const I14_ONE_WITNESSES: &[&str] = &[
    "upload prepared",
    "upload DATA supplied",
    I14_FIRST_PUBLISHED,
    I14_KEPT,
    I14_STAYED,
];

const I14: &[Obligation] = &[Obligation::History];

pub(crate) const INCIDENTS: [History; 95] = [
    history("i1-get", &I1_GET, I1_WITNESSES, BYTES_HISTORY, Expect::Pass),
    control(
        history(
            "i1-get-equality",
            &I1_GET_EQUALITY,
            I1_WITNESSES,
            BYTES_HISTORY,
            Expect::Violation(
                Obligation::History,
                "a GET at its expiry sample served the version",
            ),
        ),
        &[
            "a held sample served before its expiry",
            "owner clock held one tick below the deadline",
        ],
    ),
    uploading(
        history("i1-put", &I1_PUT, I1_PUT_WITNESSES, I1, Expect::Pass),
        1,
    ),
    control(
        uploading(
            history(
                "i1-put-recycled",
                &I1_PUT_RECYCLED,
                I1_PUT_WITNESSES,
                I1,
                Expect::Violation(
                    Obligation::Custody,
                    "a deadline recycled sources the device still held",
                ),
            ),
            1,
        ),
        I1_PUT_PREMISE,
    ),
    control(
        uploading(
            history(
                "i1-put-no-effect",
                &I1_PUT_NO_EFFECT,
                I1_PUT_WITNESSES,
                I1,
                Expect::Violation(
                    Obligation::History,
                    "a timed-out upload claimed no effect after its DATA reached the owner",
                ),
            ),
            1,
        ),
        I1_PUT_PREMISE,
    ),
    control(
        uploading(
            history(
                "i1-put-published",
                &I1_PUT_PUBLISHED,
                I1_PUT_WITNESSES,
                I1,
                Expect::Violation(
                    Obligation::History,
                    "a timed-out upload claimed publication before its RESULT",
                ),
            ),
            1,
        ),
        I1_PUT_PREMISE,
    ),
    history(
        "i3-get-data",
        &I3_GET_DATA,
        I3_DATA_WITNESSES,
        I3_GET,
        Expect::Pass,
    ),
    history(
        "i3-get-complete",
        &I3_GET_COMPLETE,
        I3_COMPLETE_WITNESSES,
        I3_GET,
        Expect::Pass,
    ),
    control(
        history(
            "i3-get-data-never-resent",
            &I3_GET_DATA_NEVER_RESENT,
            I3_DATA_WITNESSES,
            I3_GET,
            Expect::Violation(
                Obligation::Bytes,
                "a GET after a lost final frame ended without the object",
            ),
        ),
        &["the final DATA drop armed"],
    ),
    uploading(
        history(
            "i3-put-hole",
            &I3_PUT_HOLE,
            I3_HOLE_WITNESSES,
            I3_HOLE,
            Expect::Pass,
        ),
        1,
    ),
    uploading(
        history(
            "i3-put-duplicate",
            &I3_PUT_DUPLICATE,
            I3_DUPLICATE_WITNESSES,
            I3_DUPLICATE,
            Expect::Pass,
        ),
        1,
    ),
    control(
        uploading(
            history(
                "i3-put-duplicate-credit",
                &I3_PUT_DUPLICATE_CREDIT,
                I3_DUPLICATE_WITNESSES,
                I3_DUPLICATE,
                Expect::Violation(Obligation::Resources, "a duplicate fragment created credit"),
            ),
            1,
        ),
        &["every fragment duplicated", "upload receipt acknowledged"],
    ),
    uploading(
        history(
            "i3-put-retry",
            &I3_PUT_RETRY,
            I3_RETRY_WITNESSES,
            I3_RESULT,
            Expect::Pass,
        ),
        1,
    ),
    control(
        uploading(
            history(
                "i3-put-retry-early",
                &I3_PUT_RETRY_EARLY,
                I3_RETRY_WITNESSES,
                I3_RESULT,
                Expect::Violation(
                    Obligation::History,
                    "an upload claimed publication without a delivered RESULT",
                ),
            ),
            1,
        ),
        &["a RESULT drop armed"],
    ),
    control(
        uploading(
            history(
                "i3-put-lost-as-failure",
                &I3_PUT_RETRY_FAILED,
                I3_RETRY_WITNESSES,
                I3_RESULT,
                Expect::Violation(
                    Obligation::History,
                    "a lost RESULT ended the upload as a failure",
                ),
            ),
            1,
        ),
        &["a RESULT drop armed", "upload receipt acknowledged"],
    ),
    uploading(
        history(
            "i3-put-beyond",
            &I3_PUT_BEYOND,
            I3_BEYOND_WITNESSES,
            I3_RESULT,
            Expect::Pass,
        ),
        1,
    ),
    control(
        uploading(
            history(
                "i3-put-receipt-as-success",
                &I3_PUT_RECEIPT,
                I3_BEYOND_WITNESSES,
                I3_RESULT,
                Expect::Violation(
                    Obligation::History,
                    "an upload claimed publication without a delivered RESULT",
                ),
            ),
            1,
        ),
        &["a RESULT drop armed", "upload receipt acknowledged"],
    ),
    history("i2-get", &I2_GET, I2_WITNESSES, I2, Expect::Pass),
    control(
        history(
            "i2-get-accept-old",
            &I2_GET_ACCEPTED,
            I2_WITNESSES,
            I2,
            Expect::Violation(
                Obligation::Contain,
                "the owner accepted the displaced session's frames",
            ),
        ),
        &[
            "old read held",
            "a replacement boot displaced the old session",
        ],
    ),
    control(
        history(
            "i2-get-freed",
            &I2_GET_FREED,
            I2_WITNESSES,
            I2,
            Expect::Violation(
                Obligation::Custody,
                "a displaced session freed its draining slot while its read was held",
            ),
        ),
        &[
            "old read held",
            "a replacement boot displaced the old session",
        ],
    ),
    control(
        history(
            "i2-get-same-identity",
            &I2_GET_SAME,
            I2_WITNESSES,
            I2,
            Expect::Violation(
                Obligation::Contain,
                "a retry reused its identity across the replacement",
            ),
        ),
        &[
            "old read held",
            "a replacement boot displaced the old session",
            "old work drained",
        ],
    ),
    uploading(
        history(
            "i2-put",
            &I2_PUT,
            I2_PUT_WITNESSES,
            I2_PUT_OBLIGATIONS,
            Expect::Pass,
        ),
        2,
    ),
    control(
        uploading(
            history(
                "i2-put-freed",
                &I2_PUT_FREED,
                I2_PUT_WITNESSES,
                I2_PUT_OBLIGATIONS,
                Expect::Violation(
                    Obligation::Custody,
                    "a displaced upload released sources the device still held",
                ),
            ),
            2,
        ),
        &[
            "owner write held",
            "a replacement boot displaced the old session",
        ],
    ),
    control(
        uploading(
            history(
                "i2-put-same-identity",
                &I2_PUT_SAME,
                I2_PUT_WITNESSES,
                I2_PUT_OBLIGATIONS,
                Expect::Violation(
                    Obligation::Contain,
                    "a retry reused its identity across the replacement",
                ),
            ),
            2,
        ),
        &[
            "owner write held",
            "a replacement boot displaced the old session",
            "old work drained",
        ],
    ),
    history(
        "i4-get-share",
        &I4_GET_SHARE,
        I4_SHARE_WITNESSES,
        I4_SHARE,
        Expect::Pass,
    ),
    control(
        history(
            "i4-get-share-extended",
            &I4_GET_SHARE_EXTENDED,
            I4_SHARE_WITNESSES,
            I4_SHARE,
            Expect::Violation(
                Obligation::Resources,
                "a pressured request outlived its one deadline",
            ),
        ),
        &["saturating reads held", "a GET past the share was issued"],
    ),
    control(
        history(
            "i4-get-share-peer-late",
            &I4_GET_SHARE_PEER_LATE,
            I4_SHARE_WITNESSES,
            I4_SHARE,
            Expect::Violation(
                Obligation::Progress,
                "an eligible peer's GET starved behind a saturated share",
            ),
        ),
        &["saturating reads held"],
    ),
    uploading(
        history("i4-space", &I4_SPACE, I4_SPACE_WITNESSES, I4, Expect::Pass),
        2,
    ),
    control(
        uploading(
            history(
                "i4-space-always-refuse",
                &I4_SPACE_REFUSING,
                I4_SPACE_WITNESSES,
                I4,
                Expect::Violation(
                    Obligation::Progress,
                    "a healed funded upload never published",
                ),
            ),
            2,
        ),
        &[
            "fill space exhausted",
            "the pressured upload was refused typed",
        ],
    ),
    control(
        uploading(
            history(
                "i4-space-refused-late",
                &I4_SPACE_REFUSED_LATE,
                I4_SPACE_WITNESSES,
                I4,
                Expect::Violation(
                    Obligation::Resources,
                    "a pressured upload outlived its one deadline",
                ),
            ),
            2,
        ),
        &["fill space exhausted"],
    ),
    control(
        uploading(
            history(
                "i4-space-erased",
                &I4_SPACE_ERASED,
                I4_SPACE_WITNESSES,
                I4,
                Expect::Violation(
                    Obligation::History,
                    "a rejected upload erased the incumbent",
                ),
            ),
            2,
        ),
        &[
            "fill space exhausted",
            "the pressured upload was refused typed",
        ],
    ),
    uploading(
        history(
            "i4-put-deferred",
            &I4_PUT_DEFERRED,
            I4_DEFERRED_WITNESSES,
            I4,
            Expect::Pass,
        ),
        2,
    ),
    control(
        uploading(
            history(
                "i4-put-deferred-extended",
                &I4_PUT_DEFERRED_EXTENDED,
                I4_DEFERRED_WITNESSES,
                I4,
                Expect::Violation(
                    Obligation::Resources,
                    "a deferred upload outlived its one deadline",
                ),
            ),
            2,
        ),
        &["upload stalled before its DATA"],
    ),
    control(
        uploading(
            history(
                "i4-put-deferred-no-effect",
                &I4_PUT_DEFERRED_NO_EFFECT,
                I4_DEFERRED_WITNESSES,
                I4,
                Expect::Violation(
                    Obligation::History,
                    "a deferred upload ended with an outcome its deadline cannot give",
                ),
            ),
            2,
        ),
        &["upload stalled before its DATA"],
    ),
    uploading(
        history("i5", &I5, I5_WITNESSES, I5_OBLIGATIONS, Expect::Pass),
        1,
    ),
    control(
        uploading(
            history(
                "i5-a-capped-late",
                &I5_A_CAPPED_LATE,
                I5_WITNESSES,
                I5_OBLIGATIONS,
                Expect::Violation(
                    Obligation::Resources,
                    "a GET past a peer's share outlived its one deadline",
                ),
            ),
            1,
        ),
        &["A issued a GET past its share"],
    ),
    control(
        uploading(
            history(
                "i5-globalized-cap",
                &I5_GLOBALIZED,
                I5_WITNESSES,
                I5_OBLIGATIONS,
                Expect::Violation(
                    Obligation::Resources,
                    "a peer's share was charged with another peer's work",
                ),
            ),
            1,
        ),
        &[
            "the pending upload holds A's share",
            "A's GET past its share was refused typed",
        ],
    ),
    control(
        uploading(
            history(
                "i5-wrong-peer",
                &I5_WRONG_PEER,
                I5_WITNESSES,
                I5_OBLIGATIONS,
                Expect::Violation(
                    Obligation::Resources,
                    "a peer's share was charged with another peer's work",
                ),
            ),
            1,
        ),
        &[
            "the pending upload holds A's share",
            "A's GET past its share was refused typed",
        ],
    ),
    control(
        uploading(
            history(
                "i5-b-uncharged",
                &I5_B_UNCHARGED,
                I5_WITNESSES,
                I5_OBLIGATIONS,
                Expect::Violation(
                    Obligation::Resources,
                    "a retained GET left its peer's share before its release",
                ),
            ),
            1,
        ),
        &["holds armed", "A's GET past its share was refused typed"],
    ),
    control(
        uploading(
            history(
                "i5-b-late",
                &I5_B_LATE,
                I5_WITNESSES,
                I5_OBLIGATIONS,
                Expect::Violation(
                    Obligation::Progress,
                    "an eligible peer's GET starved behind a saturated share",
                ),
            ),
            1,
        ),
        &["the pending upload holds A's share"],
    ),
    control(
        uploading(
            history(
                "i5-b-timed-out",
                &I5_B_TIMED_OUT,
                I5_WITNESSES,
                I5_OBLIGATIONS,
                Expect::Violation(
                    Obligation::Progress,
                    "an eligible peer's GET starved behind a saturated share",
                ),
            ),
            1,
        ),
        &[
            "the pending upload holds A's share",
            "A's GET past its share was refused typed",
        ],
    ),
    uploading(
        history(
            "i5-get-masking",
            &I5_MASKED_READ,
            I5_WITNESSES,
            I5_OBLIGATIONS,
            Expect::Unsuccessful("the pending upload holds A's share"),
        ),
        1,
    ),
    control(
        uploading(
            history(
                "i3-put-invented-replay",
                &I3_PUT_INVENTED,
                I3_BEYOND_WITNESSES,
                I3_RESULT,
                Expect::Violation(
                    Obligation::History,
                    "an upload resolved its unknown outcome without a matching RESULT",
                ),
            ),
            1,
        ),
        &[
            "a RESULT drop armed",
            "the upload went unknown before its RESULT arrived",
        ],
    ),
    control(
        uploading(
            history(
                "i2-put-accept-old",
                &I2_PUT_ACCEPTED,
                I2_PUT_WITNESSES,
                I2_PUT_OBLIGATIONS,
                Expect::Violation(
                    Obligation::Contain,
                    "the owner accepted the displaced session's frames",
                ),
            ),
            2,
        ),
        &[
            "owner write held",
            "a replacement boot displaced the old session",
            "the displaced client sent beside the successor",
        ],
    ),
    uploading(
        history(
            "i3-put-late",
            &I3_PUT_LATE,
            I3_LATE_WITNESSES,
            I3_RESULT,
            Expect::Pass,
        ),
        1,
    ),
    uploading(
        history(
            "i4-get-read-pool",
            &I4_GET_READ_POOL,
            I4_READ_POOL_WITNESSES,
            I4_SHARE,
            Expect::Pass,
        ),
        1,
    ),
    control(
        uploading(
            history(
                "i4-get-read-pool-always-refuse",
                &I4_GET_READ_POOL_REFUSING,
                I4_READ_POOL_WITNESSES,
                I4_SHARE,
                Expect::Violation(
                    Obligation::Progress,
                    "unrelated work stalled or read bytes outside the visible versions",
                ),
            ),
            1,
        ),
        &[
            "the read-response pool exhausted",
            "the GET under the exhausted pool ended typed within its deadline",
        ],
    ),
    history(
        "i4-get-space",
        &I4_GET_SPACE,
        I4_GET_SPACE_WITNESSES,
        I4_GET_SPACE_OBLIGATIONS,
        Expect::Pass,
    ),
    uploading(
        history(
            "i4-put-request",
            &I4_PUT_REQUEST,
            I4_REQUEST_WITNESSES,
            I4,
            Expect::Pass,
        ),
        2,
    ),
    sourcing(
        uploading(
            history(
                "i4-put-source",
                &I4_PUT_SOURCE,
                I4_SOURCE_WITNESSES,
                I4,
                Expect::Pass,
            ),
            1,
        ),
        MANY_SOURCE_BYTES,
    ),
    control(
        uploading(
            history(
                "i3-put-late-early",
                &I3_PUT_LATE_EARLY,
                I3_LATE_WITNESSES,
                I3_RESULT,
                Expect::Violation(
                    Obligation::History,
                    "an upload resolved its unknown outcome before its RESULT was received",
                ),
            ),
            1,
        ),
        &[
            "a RESULT delay armed",
            "the upload went unknown before its RESULT arrived",
        ],
    ),
    control(
        uploading(
            history(
                "i3-put-late-unresolved",
                &I3_PUT_LATE_UNRESOLVED,
                I3_LATE_WITNESSES,
                I3_RESULT,
                Expect::Violation(
                    Obligation::History,
                    "a delayed matching RESULT left the unknown upload unresolved",
                ),
            ),
            1,
        ),
        &[
            "a RESULT delay armed",
            "the upload went unknown before its RESULT arrived",
        ],
    ),
    control(
        sourcing(
            uploading(
                history(
                    "i4-put-source-over-grant",
                    &I4_PUT_SOURCE_OVER,
                    I4_SOURCE_WITNESSES,
                    I4,
                    Expect::Violation(Obligation::Resources, "an upload passed its granted credit"),
                ),
                1,
            ),
            MANY_SOURCE_BYTES,
        ),
        &["the upload waited on its source slots"],
    ),
    getting(
        uploading(
            history(
                "i7-begin-refused-readmitted",
                &I7_BEGIN_DELAYED,
                I7_BEGIN_DELAYED_WITNESSES,
                I7,
                Expect::Pass,
            ),
            2,
        ),
        [0, 0],
    ),
    getting(
        uploading(
            history(
                "i7-begin-refused-prompt",
                &I7_BEGIN_PROMPT,
                I7_BEGIN_PROMPT_WITNESSES,
                I7,
                Expect::Pass,
            ),
            2,
        ),
        [0, 0],
    ),
    getting(
        uploading(
            history(
                "i7-cancel-overtakes-begin",
                &I7_CANCEL_DELAYED,
                I7_CANCEL_DELAYED_WITNESSES,
                I7,
                Expect::Pass,
            ),
            1,
        ),
        [0, 0],
    ),
    getting(
        uploading(
            history(
                "i7-begin-ahead-of-cancel",
                &I7_CANCEL_PROMPT,
                I7_CANCEL_PROMPT_WITNESSES,
                I7,
                Expect::Pass,
            ),
            1,
        ),
        [0, 0],
    ),
    getting(
        history(
            "i7-get-refused-readmitted",
            &I7_GET_DELAYED,
            I7_GET_DELAYED_WITNESSES,
            I7,
            Expect::Pass,
        ),
        [0, 3],
    ),
    getting(
        history(
            "i7-get-refused-prompt",
            &I7_GET_PROMPT,
            I7_GET_PROMPT_WITNESSES,
            I7,
            Expect::Pass,
        ),
        [0, 3],
    ),
    getting(
        history(
            "i6-fill-unwound-submit",
            &I6_UNWOUND,
            I6_UNWOUND_WITNESSES,
            I6,
            Expect::Pass,
        ),
        [0, 0],
    ),
    getting(
        history(
            "i6-fill-submitted",
            &I6_SUBMITTED,
            I6_SUBMITTED_WITNESSES,
            I6,
            Expect::Pass,
        ),
        [0, 0],
    ),
    uploading(
        history(
            "i8-get-on-draining-upload-slot",
            &I8_DRAINING,
            I8_DRAINING_WITNESSES,
            I8,
            Expect::Pass,
        ),
        1,
    ),
    uploading(
        history(
            "i8-get-after-upload-drained",
            &I8_DRAINED,
            I8_DRAINED_WITNESSES,
            I8,
            Expect::Pass,
        ),
        1,
    ),
    history(
        "i9-lost-busy-refusal-unanswered",
        &I9_LOST,
        I9_LOST_WITNESSES,
        I9,
        Expect::Pass,
    ),
    history(
        "i9-busy-refusal-delivered",
        &I9_DELIVERED,
        I9_DELIVERED_WITNESSES,
        I9,
        Expect::Pass,
    ),
    uploading(
        history(
            "i10-turn-after-unwound-upload-write",
            &I10_UNWOUND,
            I10_UNWOUND_WITNESSES,
            I10,
            Expect::Pass,
        ),
        1,
    ),
    uploading(
        history(
            "i10-turn-after-submitted-upload-write",
            &I10_SUBMITTED,
            I10_SUBMITTED_WITNESSES,
            I10,
            Expect::Pass,
        ),
        1,
    ),
    control(
        uploading(
            history(
                "i10-next-turn-unwound",
                &I10_NEXT_UNWOUND,
                I10_UNWOUND_WITNESSES,
                I10,
                Expect::Violation(
                    Obligation::Contain,
                    "an owner turn unwound after the upload's write submit",
                ),
            ),
            1,
        ),
        I10_TAKEN_PREMISE,
    ),
    control(
        uploading(
            history(
                "i10-held-count-differs",
                &I10_LANES_DIFFER,
                I10_UNWOUND_WITNESSES,
                I10,
                Expect::Violation(
                    Obligation::Contain,
                    "an upload's held count left its lane ring's entries",
                ),
            ),
            1,
        ),
        I10_TAKEN_PREMISE,
    ),
    control(
        uploading(
            history(
                "i10-unwound-no-effect",
                &I10_NO_EFFECT,
                I10_UNWOUND_WITNESSES,
                I10,
                Expect::Violation(
                    Obligation::History,
                    "an admitted upload whose write submit unwound claimed no effect",
                ),
            ),
            1,
        ),
        I10_RETURNED_PREMISE,
    ),
    control(
        uploading(
            history(
                "i10-unwound-published",
                &I10_PUBLISHED,
                I10_UNWOUND_WITNESSES,
                I10,
                Expect::Violation(
                    Obligation::History,
                    "an upload whose write submit unwound published",
                ),
            ),
            1,
        ),
        I10_RETURNED_PREMISE,
    ),
    control(
        uploading(
            history(
                "i10-close-unwound",
                &I10_CLOSE_UNWOUND,
                I10_UNWOUND_WITNESSES,
                I10,
                Expect::Violation(
                    Obligation::Contain,
                    "the owner's close unwound after the upload's write submit",
                ),
            ),
            1,
        ),
        I10_ENDED_PREMISE,
    ),
    control(
        uploading(
            history(
                "i10-submitted-turn-unwound",
                &I10_UNDECLARED,
                I10_SUBMITTED_WITNESSES,
                I10,
                Expect::Violation(
                    Obligation::Contain,
                    "the owner's turn unwound submitting the upload's write",
                ),
            ),
            1,
        ),
        I10_PREPARED_PREMISE,
    ),
    uploading(
        history(
            "i11-resident-read-after-insert",
            &I11_AFTER_INSERT,
            I11_AFTER_INSERT_WITNESSES,
            I11,
            Expect::Pass,
        ),
        1,
    ),
    history(
        "i11-resident-read-alone",
        &I11_NO_INSERT,
        I11_NO_INSERT_WITNESSES,
        I11,
        Expect::Pass,
    ),
    control(
        uploading(
            history(
                "i11-resident-read-judged-missed",
                &I11_JUDGED_MISSED,
                I11_AFTER_INSERT_WITNESSES,
                I11,
                Expect::Violation(
                    Obligation::Progress,
                    "unrelated work stalled or read bytes outside the visible versions",
                ),
            ),
            1,
        ),
        I11_PREMISE,
    ),
    getting(
        uploading(
            history(
                "i12-put-begin-after-its-upload-ended",
                &I12_LATE_BEGIN,
                I12_LATE_WITNESSES,
                I12,
                Expect::Pass,
            ),
            1,
        ),
        [0, 0],
    ),
    getting(
        uploading(
            history(
                "i12-put-begin-delivered-once",
                &I12_PROMPT_BEGIN,
                I12_PROMPT_WITNESSES,
                I12,
                Expect::Pass,
            ),
            1,
        ),
        [0, 0],
    ),
    control(
        getting(
            uploading(
                history(
                    "i12-put-judged-live",
                    &I12_JUDGED_LIVE,
                    I12_PROMPT_WITNESSES,
                    I12,
                    Expect::Violation(Obligation::History, FILLED_AFTER_AUTHORITY),
                ),
                1,
            ),
            [0, 0],
        ),
        I12_LIVE_PREMISE,
    ),
    control(
        history(
            "i4-get-share-untyped",
            &I4_GET_SHARE_UNTYPED,
            I4_SHARE_WITNESSES,
            I4_SHARE,
            Expect::Violation(
                Obligation::Resources,
                "a GET past the share ended without a typed pressure outcome",
            ),
        ),
        &["saturating reads held", "a GET past the share was issued"],
    ),
    control(
        uploading(
            history(
                "i4-get-read-pool-untyped",
                &I4_GET_READ_POOL_UNTYPED,
                I4_READ_POOL_WITNESSES,
                I4_SHARE,
                Expect::Violation(
                    Obligation::Resources,
                    "a GET under an exhausted read pool ended without its typed pressure",
                ),
            ),
            1,
        ),
        &[
            "the read-response pool exhausted",
            "a GET met the exhausted pool",
        ],
    ),
    control(
        uploading(
            history(
                "i4-put-request-untyped",
                &I4_PUT_REQUEST_UNTYPED,
                I4_REQUEST_WITNESSES,
                I4,
                Expect::Violation(
                    Obligation::Resources,
                    "an upload past its share ended without its typed pressure",
                ),
            ),
            2,
        ),
        &[
            "upload stalled before its DATA",
            "a second upload met the peer's upload share",
        ],
    ),
    control(
        uploading(
            history(
                "i4-space-untyped",
                &I4_SPACE_UNTYPED,
                I4_SPACE_WITNESSES,
                I4,
                Expect::Violation(
                    Obligation::Resources,
                    "an upload under pressure ended without a typed refusal",
                ),
            ),
            2,
        ),
        &["fill space exhausted"],
    ),
    control(
        uploading(
            history(
                "i4-put-deferred-published",
                &I4_PUT_DEFERRED_PUBLISHED,
                I4_DEFERRED_WITNESSES,
                I4,
                Expect::Violation(
                    Obligation::History,
                    "a deferred upload published bytes its supplier never gave",
                ),
            ),
            2,
        ),
        &["upload stalled before its DATA"],
    ),
    control(
        sourcing(
            uploading(
                history(
                    "i4-put-source-untapped",
                    &I4_PUT_SOURCE_UNTAPPED,
                    I4_SOURCE_WITNESSES,
                    I4,
                    Expect::Violation(
                        Obligation::Resources,
                        "the credit check saw no captured fragment",
                    ),
                ),
                1,
            ),
            MANY_SOURCE_BYTES,
        ),
        &["the upload waited on its source slots"],
    ),
    control(
        uploading(
            history(
                "i3-put-retry-regressed",
                &I3_PUT_RETRY_REGRESSED,
                I3_RETRY_WITNESSES,
                I3_RESULT,
                Expect::Violation(Obligation::History, "a known upload outcome regressed"),
            ),
            1,
        ),
        &["a RESULT drop armed", "upload published"],
    ),
    control(
        uploading(
            history(
                "i1-put-disagreed",
                &I1_PUT_DISAGREED,
                I1_PUT_WITNESSES,
                I1,
                Expect::Violation(
                    Obligation::Bytes,
                    "a GET disagreed with the upload's judged outcome",
                ),
            ),
            1,
        ),
        &["the upload's actual outcome judged"],
    ),
    uploading(
        history(
            "i13-put-with-metadata",
            &I13_WITH_METADATA,
            I13_WITNESSES,
            I13,
            Expect::Pass,
        ),
        1,
    ),
    uploading(
        history(
            "i13-put-without-metadata",
            &I13_WITHOUT_METADATA,
            I13_WITNESSES,
            I13,
            Expect::Pass,
        ),
        1,
    ),
    control(
        uploading(
            history(
                "i13-put-record-damaged",
                &I13_RECORD_DAMAGED,
                I13_WITNESSES,
                BYTES_HISTORY,
                Expect::Violation(Obligation::Bytes, UNCHECKED_RECORD),
            ),
            1,
        ),
        I13_DAMAGED_PREMISE,
    ),
    control(
        uploading(
            history(
                "i13-put-judged-without-metadata",
                &I13_JUDGED_WITHOUT_METADATA,
                I13_WITNESSES,
                I13,
                Expect::Violation(Obligation::History, ANOTHER_MANIFEST),
            ),
            1,
        ),
        I13_JUDGED_PREMISE,
    ),
    control(
        uploading(
            history(
                "i14-known-result-across-fresh-session",
                &I14_FRESH_SESSION,
                I14_FRESH_WITNESSES,
                I14,
                Expect::Pass,
            ),
            1,
        ),
        &[I14_FIRST_PUBLISHED, I14_REPLACED],
    ),
    control(
        uploading(
            history(
                "i14-known-result-in-one-session",
                &I14_ONE_SESSION,
                I14_ONE_WITNESSES,
                I14,
                Expect::Pass,
            ),
            1,
        ),
        &[I14_FIRST_PUBLISHED, I14_KEPT],
    ),
    control(
        uploading(
            history(
                "i14-known-result-changed",
                &I14_RESULT_CHANGED,
                I14_FRESH_WITNESSES,
                I14,
                Expect::Violation(Obligation::History, "a known attempt result changed"),
            ),
            1,
        ),
        &[I14_FIRST_PUBLISHED, I14_REPLACED],
    ),
    control(
        uploading(
            history(
                "i14-known-result-dropped",
                &I14_RESULT_DROPPED,
                I14_FRESH_WITNESSES,
                I14,
                Expect::Violation(Obligation::History, "a known attempt result changed"),
            ),
            1,
        ),
        &[I14_FIRST_PUBLISHED, I14_REPLACED],
    ),
];

#[cfg(test)]
mod tests {
    use crate::oracle::Obligation;
    use crate::sim::manifest::Manifest;
    use crate::sim::trace::{Loaded, Outcome, PAYLOAD, Terminal, load};
    use crate::sim::turn::End;

    use super::super::super::bundle::{Site, admit, failure_code, traced};
    use super::super::super::replay::{FailureIdentity, Replayed, replay, violated};
    use super::super::Expect;
    use super::INCIDENTS;
    use crate::net::observe::Failure;
    use crate::net::terminal_tests::{OBLIGATIONS, record_controls};

    fn manifest(name: &str) -> Manifest {
        let text = crate::sim::manifest_tests::sample(name, &"a".repeat(64), "x86_64-linux");
        Manifest::parse(&text).expect("a valid manifest")
    }

    fn ran(name: &str) -> (Outcome, Option<[u8; PAYLOAD]>, Vec<u8>) {
        let bytes = traced(admit(&manifest(name)).expect("admitted"), Vec::new()).sink;
        let loaded = load(&bytes, 1_000_000).expect("a loadable bundle");
        let Terminal::Complete { outcome, .. } = loaded.terminal else {
            panic!("{name}: {:?}", loaded.terminal);
        };
        (outcome, loaded.violation, bytes)
    }

    /// History `name` recorded under `root`: its terminal, its violation
    /// record and the bundle.
    fn ran_at(name: &str, root: u64) -> (Terminal, Option<[u8; PAYLOAD]>, Vec<u8>) {
        let (loaded, bytes) = loaded_at(name, root);
        (loaded.terminal, loaded.violation, bytes)
    }

    fn loaded_at(name: &str, root: u64) -> (Loaded, Vec<u8>) {
        let mut manifest = manifest(name);
        manifest.root = root;
        let closed = traced(admit(&manifest).expect("admitted"), Vec::new());
        let loaded = load(&closed.sink, manifest.capacity().records()).expect("a loadable bundle");
        (loaded, closed.sink)
    }

    fn hole_at(root: u64) -> (Outcome, Option<[u8; PAYLOAD]>) {
        let (terminal, violation, _) = ran_at("i3-put-hole", root);
        let Terminal::Complete { outcome, .. } = terminal else {
            panic!("{root}: {terminal:?}");
        };
        (outcome, violation)
    }

    /// History `name` under `root` replays to an equal digest and passes
    /// with no violation; the replay runs first, so a failing run is
    /// replayed too.
    fn passes_at(name: &str, root: u64) {
        let (terminal, violation, bytes) = ran_at(name, root);
        assert_eq!(
            replay(&bytes).expect("a replay").0,
            Replayed::Reproduced,
            "{name} at {root}"
        );
        assert!(
            matches!(
                terminal,
                Terminal::Complete {
                    outcome: Outcome::Pass,
                    ..
                }
            ) && violation.is_none(),
            "{name} at {root}: {terminal:?} {violation:?}"
        );
    }

    /// A local fill whose first write submit unwinds is aborted without
    /// unwinding again, under each sampled root: the storage abandons the extent in
    /// place instead of returning it with its right still counted.
    #[test]
    fn an_unwound_first_submit_leaves_the_fill_abortable() {
        for name in ["i6-fill-unwound-submit", "i6-fill-submitted"] {
            for root in [3, 7_677_221_855_602_090_617, 10_289_227_118_843_548_305] {
                passes_at(name, root);
            }
        }
    }

    /// The resident reads exactly after an insert under another key and
    /// with nothing bound under that key, under each sampled root.
    #[test]
    fn a_resident_reads_exactly_after_an_insert_under_another_key() {
        for name in ["i11-resident-read-after-insert", "i11-resident-read-alone"] {
            for root in [3, 7_677_221_855_602_090_617, 10_289_227_118_843_548_305] {
                passes_at(name, root);
            }
        }
    }

    /// A published upload still reads `Published` after its session is
    /// replaced and within one session, under each sampled root.
    #[test]
    fn a_published_upload_keeps_its_outcome_across_a_fresh_session() {
        for name in [
            "i14-known-result-across-fresh-session",
            "i14-known-result-in-one-session",
        ] {
            for root in [3, 7_677_221_855_602_090_617, 10_289_227_118_843_548_305] {
                passes_at(name, root);
            }
        }
    }

    /// An answer on a fresh wire identity settles it: under each sampled root, a
    /// refused BEGIN, a CANCEL answered unknown ahead of its BEGIN, and a
    /// refused GET leave no admitted request on their rows once the client
    /// settled, with the answers delayed behind the client's retransmissions.
    #[test]
    fn an_answer_on_a_fresh_identity_leaves_no_admitted_request() {
        for name in [
            "i7-begin-refused-readmitted",
            "i7-begin-refused-prompt",
            "i7-cancel-overtakes-begin",
            "i7-begin-ahead-of-cancel",
            "i7-get-refused-readmitted",
            "i7-get-refused-prompt",
        ] {
            for root in [7_677_221_855_602_090_617, 10_289_227_118_843_548_305] {
                passes_at(name, root);
            }
        }
    }

    /// A PUT BEGIN that arrives after its upload ended starts no second
    /// fill, under each sampled root: with the first BEGIN delayed past the
    /// upload's publication and with it delivered promptly, the owner began
    /// one fill and binds no request at the upload's wire slot. The
    /// judgment run while the upload is live ends in its violation under
    /// each of those roots and replays to an equal digest.
    #[test]
    fn a_put_begin_after_its_upload_ended_starts_no_second_fill() {
        let roots = [3, 7_677_221_855_602_090_617, 10_289_227_118_843_548_305];
        for name in [
            "i12-put-begin-after-its-upload-ended",
            "i12-put-begin-delivered-once",
        ] {
            for root in roots {
                passes_at(name, root);
            }
        }
        let rule = Failure::Violation(Obligation::History, super::FILLED_AFTER_AUTHORITY);
        for root in roots {
            let (terminal, violation, bytes) = ran_at("i12-put-judged-live", root);
            assert_eq!(
                replay(&bytes).expect("a replay").0,
                Replayed::Reproduced,
                "{root}"
            );
            assert!(
                matches!(
                    terminal,
                    Terminal::Complete {
                        outcome: Outcome::Violation,
                        ..
                    }
                ) && violation == Some(failure_code(&rule)),
                "{root}: {terminal:?} {violation:?}"
            );
        }
    }

    /// A GET on the wire slot of an upload the owner ended is admitted on
    /// the peer's share alone, under each sampled root: with the ended upload's
    /// write still outstanding and after it drained, the GET reads the
    /// resident version exactly.
    #[test]
    fn a_get_on_an_ended_uploads_wire_slot_is_admitted() {
        for name in [
            "i8-get-after-upload-drained",
            "i8-get-on-draining-upload-slot",
        ] {
            for root in [3, 7_677_221_855_602_090_617, 10_289_227_118_843_548_305] {
                passes_at(name, root);
            }
        }
    }

    /// The owner turn after a turn that unwound in an upload's write submit
    /// returns, under each sampled root, and so does the turn after a write
    /// that submitted.
    #[test]
    fn a_turn_after_an_unwound_upload_write_returns() {
        for name in [
            "i10-turn-after-submitted-upload-write",
            "i10-turn-after-unwound-upload-write",
        ] {
            for root in [3, 7_677_221_855_602_090_617, 10_289_227_118_843_548_305] {
                passes_at(name, root);
            }
        }
    }

    /// The record the owner publishes for an upload holds the metadata and
    /// payload lengths its PREPARE named, under each sampled root: with 32
    /// bytes of metadata prepared and with none.
    #[test]
    fn a_published_upload_s_record_holds_the_lengths_its_prepare_named() {
        for name in ["i13-put-with-metadata", "i13-put-without-metadata"] {
            for root in [3, 7_677_221_855_602_090_617, 10_289_227_118_843_548_305] {
                passes_at(name, root);
            }
        }
    }

    /// A GET refused on a wire slot a cancelled GET still binds is never
    /// admitted, under each sampled root: with the one ERROR lost and the
    /// slot then freed, the owner drops the client's retransmissions and
    /// the client ends at its deadline; with the ERROR delivered, the
    /// client ends with the refusal.
    #[test]
    fn a_get_refused_on_a_bound_slot_is_never_admitted_after_the_slot_frees() {
        for name in [
            "i9-busy-refusal-delivered",
            "i9-lost-busy-refusal-unanswered",
        ] {
            for root in [3, 7_677_221_855_602_090_617, 10_289_227_118_843_548_305] {
                passes_at(name, root);
            }
        }
    }

    #[test]
    fn a_setup_get_the_owner_admits_late_is_not_counted_as_the_refused_get() {
        passes_at("i9-busy-refusal-delivered", 1899);
    }

    #[test]
    fn a_lost_fragment_released_after_its_receipt_passes() {
        assert_eq!(hole_at(2_946_512_557_381_983_801), (Outcome::Pass, None));
    }

    #[test]
    fn a_lost_fragment_first_seen_held_after_its_receipt_passes() {
        assert_eq!(hole_at(8_865_281_517_519_135_030), (Outcome::Pass, None));
    }

    #[test]
    fn a_lost_fragment_never_seen_held_leaves_its_custody_unwitnessed() {
        assert_eq!(
            hole_at(2_079_899_249_879_653_367),
            (Outcome::Unsuccessful, None)
        );
    }

    #[test]
    fn a_healed_share_admits_a_get_on_the_reused_wire_slot() {
        let results: Vec<_> = [
            16_710_703_373_766_321_148,
            12_409_440_846_135_954_690,
            7_783_306_599_864_612_271,
        ]
        .into_iter()
        .map(|seed| {
            let mut manifest = manifest("i4-get-share").with("actors", 16);
            manifest.root = seed;
            let closed = traced(admit(&manifest).expect("admitted"), Vec::new());
            let loaded =
                load(&closed.sink, manifest.capacity().records()).expect("a loadable bundle");
            (seed, loaded.terminal, loaded.violation)
        })
        .collect();
        assert!(
            results.iter().all(|(_, terminal, violation)| {
                matches!(
                    terminal,
                    Terminal::Complete {
                        outcome: Outcome::Pass,
                        ..
                    }
                ) && violation.is_none()
            }),
            "{results:?}"
        );
    }

    #[test]
    fn every_passing_incident_passes_and_replays_equal() {
        for incident in INCIDENTS.iter().filter(|i| i.expect == Expect::Pass) {
            let (outcome, violation, bytes) = ran(incident.name);
            assert_eq!(outcome, Outcome::Pass, "{}: {violation:?}", incident.name);
            assert_eq!(
                replay(&bytes).expect("a replay").0,
                Replayed::Reproduced,
                "{}",
                incident.name
            );
        }
    }

    #[test]
    fn every_passing_incident_activates_the_obligations_it_declares() {
        for incident in INCIDENTS.iter().filter(|i| i.expect == Expect::Pass) {
            let activated = super::super::activated(incident.witnesses);
            for obligation in incident.obligations {
                let activated = activated.contains(obligation);
                assert!(
                    activated,
                    "{}: {obligation:?} has no witnessed check",
                    incident.name
                );
            }
        }
    }

    #[test]
    fn every_incident_control_fails_through_its_named_check() {
        use Obligation::{Bytes, Contain, Custody, History, Progress, Resources};
        let killed = [
            (
                "i1-get-equality",
                History,
                "a GET at its expiry sample served the version",
            ),
            (
                "i1-put-recycled",
                Custody,
                "a deadline recycled sources the device still held",
            ),
            (
                "i1-put-no-effect",
                History,
                "a timed-out upload claimed no effect after its DATA reached the owner",
            ),
            (
                "i1-put-published",
                History,
                "a timed-out upload claimed publication before its RESULT",
            ),
            (
                "i3-get-data-never-resent",
                Bytes,
                "a GET after a lost final frame ended without the object",
            ),
            (
                "i4-space-refused-late",
                Resources,
                "a pressured upload outlived its one deadline",
            ),
            (
                "i5-a-capped-late",
                Resources,
                "a GET past a peer's share outlived its one deadline",
            ),
            (
                "i2-get-accept-old",
                Contain,
                "the owner accepted the displaced session's frames",
            ),
            (
                "i2-get-freed",
                Custody,
                "a displaced session freed its draining slot while its read was held",
            ),
            (
                "i2-get-same-identity",
                Contain,
                "a retry reused its identity across the replacement",
            ),
            (
                "i2-put-accept-old",
                Contain,
                "the owner accepted the displaced session's frames",
            ),
            (
                "i2-put-freed",
                Custody,
                "a displaced upload released sources the device still held",
            ),
            (
                "i2-put-same-identity",
                Contain,
                "a retry reused its identity across the replacement",
            ),
            (
                "i3-put-receipt-as-success",
                History,
                "an upload claimed publication without a delivered RESULT",
            ),
            (
                "i3-put-duplicate-credit",
                Resources,
                "a duplicate fragment created credit",
            ),
            (
                "i3-put-retry-early",
                History,
                "an upload claimed publication without a delivered RESULT",
            ),
            (
                "i3-put-lost-as-failure",
                History,
                "a lost RESULT ended the upload as a failure",
            ),
            (
                "i3-put-invented-replay",
                History,
                "an upload resolved its unknown outcome without a matching RESULT",
            ),
            (
                "i4-get-share-extended",
                Resources,
                "a pressured request outlived its one deadline",
            ),
            (
                "i4-get-read-pool-always-refuse",
                Progress,
                "unrelated work stalled or read bytes outside the visible versions",
            ),
            (
                "i3-put-late-unresolved",
                History,
                "a delayed matching RESULT left the unknown upload unresolved",
            ),
            (
                "i4-put-source-over-grant",
                Resources,
                "an upload passed its granted credit",
            ),
            (
                "i4-space-always-refuse",
                Progress,
                "a healed funded upload never published",
            ),
            (
                "i4-space-erased",
                History,
                "a rejected upload erased the incumbent",
            ),
            (
                "i4-put-deferred-extended",
                Resources,
                "a deferred upload outlived its one deadline",
            ),
            (
                "i4-put-deferred-no-effect",
                History,
                "a deferred upload ended with an outcome its deadline cannot give",
            ),
            (
                "i4-get-share-peer-late",
                Progress,
                "an eligible peer's GET starved behind a saturated share",
            ),
            (
                "i5-globalized-cap",
                Resources,
                "a peer's share was charged with another peer's work",
            ),
            (
                "i5-wrong-peer",
                Resources,
                "a peer's share was charged with another peer's work",
            ),
            (
                "i5-b-uncharged",
                Resources,
                "a retained GET left its peer's share before its release",
            ),
            (
                "i3-put-late-early",
                History,
                "an upload resolved its unknown outcome before its RESULT was received",
            ),
            (
                "i5-b-late",
                Progress,
                "an eligible peer's GET starved behind a saturated share",
            ),
            (
                "i5-b-timed-out",
                Progress,
                "an eligible peer's GET starved behind a saturated share",
            ),
            (
                "i10-next-turn-unwound",
                Contain,
                "an owner turn unwound after the upload's write submit",
            ),
            (
                "i10-held-count-differs",
                Contain,
                "an upload's held count left its lane ring's entries",
            ),
            (
                "i10-unwound-no-effect",
                History,
                "an admitted upload whose write submit unwound claimed no effect",
            ),
            (
                "i10-unwound-published",
                History,
                "an upload whose write submit unwound published",
            ),
            (
                "i10-close-unwound",
                Contain,
                "the owner's close unwound after the upload's write submit",
            ),
            (
                "i10-submitted-turn-unwound",
                Contain,
                "the owner's turn unwound submitting the upload's write",
            ),
            (
                "i11-resident-read-judged-missed",
                Progress,
                "unrelated work stalled or read bytes outside the visible versions",
            ),
            (
                "i12-put-judged-live",
                History,
                "the owner filled after the attempt's authority",
            ),
            (
                "i4-get-share-untyped",
                Resources,
                "a GET past the share ended without a typed pressure outcome",
            ),
            (
                "i4-get-read-pool-untyped",
                Resources,
                "a GET under an exhausted read pool ended without its typed pressure",
            ),
            (
                "i4-put-request-untyped",
                Resources,
                "an upload past its share ended without its typed pressure",
            ),
            (
                "i4-space-untyped",
                Resources,
                "an upload under pressure ended without a typed refusal",
            ),
            (
                "i4-put-deferred-published",
                History,
                "a deferred upload published bytes its supplier never gave",
            ),
            (
                "i4-put-source-untapped",
                Resources,
                "the credit check saw no captured fragment",
            ),
            (
                "i3-put-retry-regressed",
                History,
                "a known upload outcome regressed",
            ),
            (
                "i1-put-disagreed",
                Bytes,
                "a GET disagreed with the upload's judged outcome",
            ),
            (
                "i13-put-record-damaged",
                Bytes,
                "a bound slot's record fails its header or chunk checks",
            ),
            (
                "i13-put-judged-without-metadata",
                History,
                "the owner prepared another manifest",
            ),
            (
                "i14-known-result-changed",
                History,
                "a known attempt result changed",
            ),
            (
                "i14-known-result-dropped",
                History,
                "a known attempt result changed",
            ),
        ];
        for (name, obligation, rule) in killed {
            let declared = INCIDENTS.iter().find(|i| i.name == name).expect(name);
            assert_eq!(
                declared.expect,
                Expect::Violation(obligation, rule),
                "{name}"
            );
            assert!(!declared.premise.is_empty(), "{name} declares its premise");
            let (outcome, violation, _) = ran(name);
            assert_eq!(
                (outcome, violation),
                (
                    Outcome::Violation,
                    Some(failure_code(&Failure::Violation(obligation, rule)))
                ),
                "{name}"
            );
        }
        let (outcome, violation, _) = ran("i5-get-masking");
        assert_eq!((outcome, violation), (Outcome::Unsuccessful, None));
        let controls = INCIDENTS
            .iter()
            .filter(|i| i.expect != Expect::Pass)
            .count();
        assert_eq!(controls, killed.len() + 1);
    }

    fn result_admitting_both(world: &mut super::Mixed<'_, '_, '_>, now: u64) -> u64 {
        let judged = super::result_judged(world, now);
        world.history.allowed = vec![super::version_a(), super::long_b()];
        judged
    }

    fn result_left_unknown(world: &mut super::Mixed<'_, '_, '_>, _: u64) -> u64 {
        let id = world.history.put.expect("a PUT");
        let _ = world.collect_put(id);
        super::judge_result(world, Some(super::UploadOutcome::Unknown))
    }

    const REGRESSED_ADMITTING_BOTH: [super::Step; 16] = super::replaced(
        super::I3_PUT_RETRY_REGRESSED,
        "put-result",
        super::step("put-result-both", super::put_decided, result_admitting_both),
    );

    const REGRESSED_LEFT_UNKNOWN: [super::Step; 16] = super::replaced(
        super::I3_PUT_RETRY_REGRESSED,
        "put-result",
        super::step(
            "put-result-unknown",
            super::put_decided,
            result_left_unknown,
        ),
    );

    fn ended_under(name: &str, script: &'static [super::Step]) -> (End, Option<Failure>) {
        let (profile, mut plan, goal) = super::super::named(name, 3).expect(name);
        plan.script = script;
        let chooser = profile.recorder(&super::super::super::sites_for(&plan));
        let (ran, first, _) = super::super::super::mixed_run(
            chooser,
            &profile,
            plan,
            goal,
            super::super::super::LIMITS,
            &mut (),
        );
        (ran.report.end, first)
    }

    /// The first failure history `name` records under root 3 with `script`
    /// in place of its own.
    fn first_failure_under(name: &str, script: &'static [super::Step]) -> Option<Failure> {
        ended_under(name, script).1
    }

    #[test]
    fn the_regressed_control_kills_only_through_the_published_upload_s_version() {
        let control = "i3-put-retry-regressed";
        assert_eq!(
            first_failure_under(control, &REGRESSED_LEFT_UNKNOWN),
            Some(Failure::Unsuccessful("upload published"))
        );
        assert_eq!(
            ended_under(control, &REGRESSED_ADMITTING_BOTH),
            (End::Done, None)
        );
    }

    type Ready = fn(&super::Mixed<'_, '_, '_>, u64) -> bool;
    type Run = fn(&mut super::Mixed<'_, '_, '_>, u64) -> u64;

    /// `script` with its step `at` running `run` once `ready` holds. A plan
    /// holds its script for the life of the process, so the copy is leaked.
    fn restepped<const N: usize>(
        script: [super::Step; N],
        at: &'static str,
        ready: Ready,
        run: Run,
    ) -> &'static [super::Step] {
        Box::leak(Box::new(super::replaced(
            script,
            at,
            super::step(at, ready, run),
        )))
    }

    /// The failure history `name` declares.
    fn declared(name: &str) -> Option<Failure> {
        let history = INCIDENTS.iter().find(|i| i.name == name).expect(name);
        history.expect.failure()
    }

    /// A GET that received none of its refusals ends `TimedOut` at its
    /// deadline, and a GET the owner serves past a limit ends `Complete`.
    const UNTYPED_GETS: [super::Outcome; 2] = [
        super::Outcome::Failed(super::Status::TimedOut),
        super::Outcome::Complete,
    ];

    /// An upload that sent its BEGIN and received no reply ends `Unknown`
    /// at its deadline, and an upload the owner admits past a limit can end
    /// `Published`.
    const UNTYPED_PUTS: [super::UploadOutcome; 2] = [
        super::UploadOutcome::Unknown,
        super::UploadOutcome::Published,
    ];

    /// The later claims of a published upload that withdraw its publication.
    const WITHDRAWN: [super::UploadOutcome; 2] = [
        super::UploadOutcome::Failed(super::Status::TimedOut),
        super::UploadOutcome::NotStarted,
    ];

    fn share_judged<const AT: usize>(world: &mut super::Mixed<'_, '_, '_>, _: u64) -> u64 {
        let _ = super::collect_pressured_get(world);
        let since = world.history.since;
        super::judge_pressured_outcome(world, Some(UNTYPED_GETS[AT]), since)
    }

    fn pool_judged<const AT: usize>(world: &mut super::Mixed<'_, '_, '_>, _: u64) -> u64 {
        let _ = super::collect_pool_get(world);
        let since = world.history.since;
        super::judge_pool_outcome(world, Some(UNTYPED_GETS[AT]), since)
    }

    fn second_judged<const AT: usize>(world: &mut super::Mixed<'_, '_, '_>, _: u64) -> u64 {
        let _ = super::collect_second_put(world);
        let since = world.history.since;
        super::judge_second_outcome(world, Some(UNTYPED_PUTS[AT]), since)
    }

    fn space_judged<const AT: usize>(world: &mut super::Mixed<'_, '_, '_>, _: u64) -> u64 {
        let _ = super::collect_refused_put(world);
        let since = world.history.since;
        super::judge_refused_outcome(world, Some(UNTYPED_PUTS[AT]), since)
    }

    fn later_judged<const AT: usize>(world: &mut super::Mixed<'_, '_, '_>, _: u64) -> u64 {
        super::judge_later(world, Some(WITHDRAWN[AT]))
    }

    /// Hands the exact judge a complete read that lacks the admitted
    /// version's last byte.
    fn short_read(world: &mut super::Mixed<'_, '_, '_>, _: u64) -> u64 {
        let _ = super::fresh_result(world);
        let admitted = world.history.allowed[0].clone();
        let short = &admitted[..admitted.len() - 1];
        super::judge_exact(world, Some(super::Outcome::Complete), short)
    }

    /// Hands the exact judge the admitted version's bytes from a read that
    /// ended `Incomplete`.
    fn unfinished_read(world: &mut super::Mixed<'_, '_, '_>, _: u64) -> u64 {
        let _ = super::fresh_result(world);
        let admitted = world.history.allowed[0].clone();
        let unfinished = super::Outcome::Incomplete(super::Status::TimedOut);
        super::judge_exact(world, Some(unfinished), &admitted)
    }

    /// Each judge of a typed, regressed or disagreed outcome fails through
    /// its rule for two outcomes beside the one its control plants: a
    /// refusal the link lost and a request served past its limit, a
    /// published upload's later claim of a failure or of no effect, and a
    /// read that ended one byte short or `Incomplete`.
    #[test]
    fn each_outcome_judge_fails_through_its_rule_for_two_more_outcomes_a_defect_gives() {
        let handed: [(&str, [&'static [super::Step]; 2]); 6] = [
            (
                "i4-get-share-untyped",
                [share_judged::<0> as Run, share_judged::<1>].map(|run| {
                    let ready = super::over_share_decided;
                    restepped(super::I4_GET_SHARE, "over-share-ended", ready, run)
                }),
            ),
            (
                "i4-get-read-pool-untyped",
                [pool_judged::<0> as Run, pool_judged::<1>].map(|run| {
                    restepped(
                        super::I4_GET_READ_POOL,
                        "pool-refused",
                        super::pool_decided,
                        run,
                    )
                }),
            ),
            (
                "i4-put-request-untyped",
                [second_judged::<0> as Run, second_judged::<1>].map(|run| {
                    let ready = super::second_decided;
                    restepped(super::I4_PUT_REQUEST, "second-refused", ready, run)
                }),
            ),
            (
                "i4-space-untyped",
                [space_judged::<0> as Run, space_judged::<1>]
                    .map(|run| restepped(super::I4_SPACE, "put-refused", super::put_decided, run)),
            ),
            (
                "i3-put-retry-regressed",
                [later_judged::<0> as Run, later_judged::<1>]
                    .map(|run| restepped(super::I3_PUT_RETRY, "later", super::past_retention, run)),
            ),
            (
                "i1-put-disagreed",
                [short_read as Run, unfinished_read].map(|run| {
                    restepped(super::I1_PUT, "qualified-read", super::fresh_decided, run)
                }),
            ),
        ];
        for (control, scripts) in handed {
            for (at, script) in scripts.into_iter().enumerate() {
                assert_eq!(
                    first_failure_under(control, script),
                    declared(control),
                    "{control}, outcome {at}"
                );
            }
        }
    }

    /// Each control that plants the outcome of a request with a deadline
    /// judges it at the request's issue time. Its plant step, first run
    /// after the deadline passed, ends the run under the control's own rule,
    /// ahead of which the judge checks the deadline.
    #[test]
    fn each_timed_control_fails_through_its_rule_when_its_plant_runs_past_the_deadline() {
        let late: [(&str, &'static [super::Step]); 6] = [
            (
                "i4-get-share-untyped",
                restepped(
                    super::I4_GET_SHARE_UNTYPED,
                    "over-share-untyped",
                    super::put_deadline_passed,
                    super::pressured_untyped,
                ),
            ),
            (
                "i4-get-read-pool-untyped",
                restepped(
                    super::I4_GET_READ_POOL_UNTYPED,
                    "pool-untyped",
                    super::put_deadline_passed,
                    super::pool_untyped,
                ),
            ),
            (
                "i4-put-request-untyped",
                restepped(
                    super::I4_PUT_REQUEST_UNTYPED,
                    "second-untyped",
                    super::put_deadline_passed,
                    super::second_untyped,
                ),
            ),
            (
                "i4-space-untyped",
                restepped(
                    super::I4_SPACE_UNTYPED,
                    "put-untyped",
                    super::put_deadline_passed,
                    super::refused_untyped,
                ),
            ),
            (
                "i4-put-deferred-published",
                restepped(
                    super::I4_PUT_DEFERRED_PUBLISHED,
                    "deadline-published",
                    super::put_deadline_passed,
                    super::deferred_published,
                ),
            ),
            (
                "i4-put-deferred-no-effect",
                restepped(
                    super::I4_PUT_DEFERRED_NO_EFFECT,
                    "deadline-no-effect",
                    super::put_deadline_passed,
                    super::deferred_no_effect,
                ),
            ),
        ];
        for (control, script) in late {
            assert_eq!(
                first_failure_under(control, script),
                declared(control),
                "{control}"
            );
        }
    }

    /// The eight controls the seeded test pins under two roots and the
    /// family's obligation record lists by rule.
    const TEXT_CONTROLS: [&str; 8] = [
        "i4-get-share-untyped",
        "i4-get-read-pool-untyped",
        "i4-put-request-untyped",
        "i4-space-untyped",
        "i4-put-deferred-published",
        "i4-put-source-untapped",
        "i3-put-retry-regressed",
        "i1-put-disagreed",
    ];

    /// The incident family's obligation record lists the rule of each
    /// control in [`TEXT_CONTROLS`] under the family's control test.
    #[test]
    fn the_family_record_lists_the_rule_of_each_incident_text_control() {
        let listed = record_controls(
            &OBLIGATIONS,
            "incident-histories-hold-their-witnesses-and-replay",
        );
        let test = concat!(
            "net::world_tests::histories::incidents::tests::",
            "every_incident_control_fails_through_its_named_check"
        );
        for name in TEXT_CONTROLS {
            let Some(Failure::Violation(_, rule)) = declared(name) else {
                panic!("{name} declares no violation");
            };
            assert!(listed.contains(&(test, rule)), "{name}: {rule}");
        }
    }

    #[test]
    fn each_incident_text_control_fails_through_its_check_under_pinned_roots() {
        for name in TEXT_CONTROLS {
            let declared = INCIDENTS.iter().find(|i| i.name == name).expect(name);
            let Expect::Violation(obligation, rule) = declared.expect else {
                panic!("{name}: {:?}", declared.expect);
            };
            let identity =
                FailureIdentity::of_failure(&Failure::Violation(obligation, rule), Site::Run);
            for root in [7_677_221_855_602_090_617, 10_289_227_118_843_548_305] {
                let (loaded, _) = loaded_at(name, root);
                assert_eq!(
                    declared.ends_as_declared(&loaded),
                    Ok(()),
                    "{name} at {root}"
                );
                assert_eq!(violated(&loaded), Some(identity), "{name} at {root}");
            }
        }
    }
}
