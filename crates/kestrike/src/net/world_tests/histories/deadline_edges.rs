//! Deadline-edge histories: a publication whose clock sample is at its deadline, and one a tick below it.
//!
//! The rule is `REACHED` below, a publication at or past its deadline, which `narrate/rules.rs` holds for the
//! oracle. In cache code the publication's visibility bracket keeps it (`storage::publication`): the bracket
//! takes one clock sample and compares its whole seconds with the record's deadline
//! (`storage::slot::expired`), and a sample that has reached the deadline refuses the publication `Expired`
//! and installs nothing.
//!
//! Both histories fill replacements of key 1 through the owner, beside the resident the scene published
//! with no deadline, and wait for each fill's write before they publish it with `Owner::publish_fill`.
//! The first publication carries a deadline of a whole second, at least one second past the world's
//! time, and the step before it pins the sample every owner-side turn takes (`State::clock`).
//!
//! - `de1-publish-at-deadline`: the sample is pinned at the deadline itself, so the
//!   publication is at its deadline. A lease is the rule; `Expired` is the refusal, and any other refusal
//!   ends the run unsuccessful under the refusal's witness. The clock is released and a GET must read the
//!   incumbent exactly. A second fill is then published under the deadline of tick 1, second 0, which
//!   the unpinned sample has passed: it is judged the same way and a GET must again read the incumbent
//!   exactly. A third fill then publishes under a live deadline and a GET reads it exactly, so neither
//!   refusal left the key unpublishable.
//! - `de1-publish-below-deadline`: the same steps without the fault. The sample is
//!   pinned one tick below the same deadline, so the first publication is live and must return a lease,
//!   and a GET reads the replacement exactly. The second fill publishes under a deadline one minute past
//!   the world's time and a GET reads it exactly.
//!
//! - `de1-publish-below-judged-reached`: the control. The steps of `de1-publish-below-deadline` with
//!   the first publication judged by `keyops::judge_reached`, which the lease fails with the rule.
//!
//! The refused publications are judged by `keyops::judge_reached`, the judgment of
//! `k1-publish-expired`, under a pinned sample.

use super::incidents::incumbent_kept;
use super::keyops::{fill_later, fill_second, judge_reached, rest, rested};
use super::*;

/// The rule, which `narrate/rules.rs` holds for the oracle.
const REACHED: &str = "a publication at or past its deadline";

/// Storage ticks in one second: a tick is a nanosecond and world time is in microseconds.
const SECOND_TICKS: u64 = 1_000 * super::super::SECOND_US;

/// The third replacement, which the scenario publishes once both refusals were judged.
const LABEL_D: Label = Label(23);

fn version_d() -> Vec<u8> {
    payload(1200, 6)
}

const HELD_AT: &str = "the storage's sample was pinned at the deadline";
const HELD_BELOW: &str = "the storage's sample was pinned one tick below the deadline";
const RELEASED: &str = "the storage's sample was released";
const AT_REFUSED: &str = "the publication at its deadline was refused";
const PAST_REFUSED: &str = "the publication past its deadline was refused";
const BELOW_PUBLISHED: &str = "the publication one tick below its deadline returned a lease";
const KEPT_AGAIN: &str = "the incumbent stayed exact after the second refusal";
const SECOND_READ: &str = "the second replacement was read exactly";
const THIRD_READ: &str = "the third replacement was read exactly";

/// Keeps the first publication's deadline: the second whole second after the world's time, in ticks.
fn set_deadline(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let deadline = (ticks(now) / SECOND_TICKS + 2) * SECOND_TICKS;
    world.history.deadline = deadline;
    deadline
}

/// Pins every later owner-side turn's sample at the deadline.
fn hold_at(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.clock = Some(set_deadline(world, now));
    mark(world, HELD_AT)
}

/// Pins every later owner-side turn's sample one tick below the deadline.
fn hold_below(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.clock = Some(set_deadline(world, now) - 1);
    mark(world, HELD_BELOW)
}

fn release(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.clock = None;
    mark(world, RELEASED)
}

/// The first publication of the scenario: the turn's sample is the pinned one, the deadline itself.
fn publish_at(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let deadline = world.history.deadline;
    judge_reached(world, now, deadline, AT_REFUSED)
}

/// The second publication of the scenario: the deadline is the timeline's first tick, second 0, which
/// the unpinned sample has passed.
fn publish_past(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    judge_reached(world, now, 1, PAST_REFUSED)
}

/// Publishes the kept fill under the live `deadline` and keeps its lease.
fn publish_live(
    world: &mut Mixed<'_, '_, '_>,
    now: u64,
    deadline: u64,
    published: &'static str,
) -> u64 {
    let fill = world.history.fill.take().expect("a written fill");
    let answer = world
        .scene
        .owner
        .publish_fill(fill, deadline, 2, &mut budget());
    rest(world, now);
    match answer {
        Ok(lease) => {
            world.history.lease = Some(lease);
            mark(world, published)
        }
        Err(_) => fail(
            world,
            Obligation::Progress,
            "the replacement never published",
        ),
    }
}

/// The first publication of the sibling: the turn's sample is the pinned one, one tick below the
/// deadline.
fn publish_below(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let deadline = world.history.deadline;
    publish_live(world, now, deadline, BELOW_PUBLISHED)
}

fn fill_third(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    fill_later(world, now, &version_d(), LABEL_D)
}

/// The GET after the second refusal reads the incumbent exactly, as the one after the first did.
fn incumbent_kept_again(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if incumbent_kept(world, now) == 0 {
        return 0;
    }
    mark(world, KEPT_AGAIN)
}

/// A later GET reads `expected` exactly.
fn later_exact(world: &mut Mixed<'_, '_, '_>, expected: &[u8], read: &'static str) -> u64 {
    if fresh_exact_of(world, expected) == 0 {
        return 0;
    }
    mark(world, read)
}

fn second_exact(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    later_exact(world, &version_c(), SECOND_READ)
}

fn third_exact(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    later_exact(world, &version_d(), THIRD_READ)
}

const REFUSED: [Step; 15] = [
    step("fill-replacement", always, fill_b),
    step("hold-clock-at-deadline", fill_written, hold_at),
    step("publish-at-deadline", always, publish_at),
    step("release-clock", always, release),
    step("incumbent-get", active_put, fresh_get),
    step("incumbent-read", fresh_decided, incumbent_kept),
    step("fill-second", rested, fill_second),
    step("publish-past-deadline", fill_written, publish_past),
    step("incumbent-get-again", active_put, fresh_get),
    step("incumbent-read-again", fresh_decided, incumbent_kept_again),
    step("fill-third", rested, fill_third),
    step("publish-third", fill_written, publish_fill),
    step("qualified-get", active_put, fresh_get),
    step("qualified-read", fresh_decided, third_exact),
    JUDGE,
];

const ADMITTED: [Step; 11] = [
    step("fill-replacement", always, fill_b),
    step("hold-clock-below-deadline", fill_written, hold_below),
    step("publish-below-deadline", always, publish_below),
    step("release-clock", always, release),
    step("qualified-get", active_put, fresh_get),
    step("qualified-read", fresh_decided, fresh_exact_b),
    step("fill-second", rested, fill_second),
    step("publish-second", fill_written, publish_fill),
    step("qualified-get-again", active_put, fresh_get),
    step("qualified-read-again", fresh_decided, second_exact),
    JUDGE,
];

const BELOW_JUDGED_REACHED: [Step; 11] = replaced(
    ADMITTED,
    "publish-below-deadline",
    step("publish-below-judged-reached", always, publish_at),
);

const REFUSED_WITNESSES: &[&str] = &[
    "replacement filled",
    HELD_AT,
    AT_REFUSED,
    RELEASED,
    "the incumbent stayed exact",
    PAST_REFUSED,
    KEPT_AGAIN,
    "replacement published",
    "qualified exact read",
    THIRD_READ,
];

const ADMITTED_WITNESSES: &[&str] = &[
    "replacement filled",
    HELD_BELOW,
    BELOW_PUBLISHED,
    RELEASED,
    "qualified exact read",
    "replacement published",
    SECOND_READ,
];

const JUDGED: &[Obligation] = &[Obligation::History];

pub(super) const CHECKS: [(&str, Obligation); 2] = [
    (AT_REFUSED, Obligation::History),
    (PAST_REFUSED, Obligation::History),
];

const BELOW_PREMISE: &[&str] = &["replacement filled", HELD_BELOW];

/// The publishing client issues every GET of a deadline-edge history.
const fn edge(
    name: &'static str,
    script: &'static [Step],
    witnesses: &'static [&'static str],
    expect: Expect,
) -> History {
    getting(history(name, script, witnesses, JUDGED, expect), [0, 0])
}

pub(super) const DEADLINE_EDGES: [History; 3] = [
    edge(
        "de1-publish-at-deadline",
        &REFUSED,
        REFUSED_WITNESSES,
        Expect::Pass,
    ),
    edge(
        "de1-publish-below-deadline",
        &ADMITTED,
        ADMITTED_WITNESSES,
        Expect::Pass,
    ),
    control(
        edge(
            "de1-publish-below-judged-reached",
            &BELOW_JUDGED_REACHED,
            ADMITTED_WITNESSES,
            Expect::Violation(Obligation::History, REACHED),
        ),
        BELOW_PREMISE,
    ),
];
