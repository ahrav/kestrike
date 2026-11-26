//! A GET whose owner clock sample equals the version's expiry misses.
//!
//! Property: a GET the owner serves under a clock sample equal to the version's expiry misses. The
//! rule this file judges is SERVED_AT_EXPIRY below, the text `narrate/rules.rs` lists.
//!
//! Both histories publish version B of key 1 through a local fill with a finite expiry at a whole second,
//! hold the owner's clock below that expiry, wait until world time is past it and read the version with a
//! first GET: the version is live and served before its expiry. They then move the held clock, issue a
//! second GET once the owner holds no request of the reading client, and judge that GET.
//!
//! - `ex1-get-at-the-expiry`: the clock is held at exactly the expiry. The second GET must
//!   end `Missing` with no bytes; any other ending is the rule.
//! - `ex1-get-below-the-expiry`: the clock is held one tick below the expiry, the
//!   last sample at which the version is live. The second GET must end `Complete` with version B's bytes.
//! - `ex1-get-below-judged-at-the-expiry`: the clock stays one tick below expiry, so the second GET
//!   returns `Complete`. The control judges that result against the miss expected at expiry.
//! - `ex1-get-at-judged-below-the-expiry`: the clock stays at expiry, so the second GET returns
//!   `Missing`. The control expects `Complete` with version B's bytes, the result one tick below expiry.
//!
//! Premises end a run unsuccessful under their own names and are no judgment of the rule: the publication,
//! the first GET's exact read, and an owner turn that took its last sample at the tick the history holds.
//! The expiry and clock steps follow `publish_expiring`, `hold_clock_now`, `hold_clock_deadline` and
//! `hold_clock_below` of `histories/incidents.rs`, which are private to that file.

use super::incidents::uploader_idle;
use super::*;

/// The rule, which `narrate/rules.rs` lists.
const SERVED_AT_EXPIRY: &str = "a GET at its expiry sample served the version";
/// The sibling's rule: the version is live one tick below its expiry.
const MISSED_BELOW: &str = "a sample below the deadline missed the live version";

const PUBLISHED: &str = "replacement published with a finite expiry";
const HELD_BELOW: &str = "owner clock held below the deadline";
/// A premise here: `served_before` ends the run unsuccessful under it and judges no rule.
const SERVED_BEFORE: &str = "a held sample served before its expiry";
const HELD_AT: &str = "owner clock held at the deadline";
const HELD_ONE_BELOW: &str = "owner clock held one tick below the deadline";
const SAMPLED_AT: &str = "an owner turn took its last sample at the expiry";
const SAMPLED_ONE_BELOW: &str = "an owner turn took its last sample one tick below the expiry";
/// A check of `Obligation::History` in the world's table.
const MISSED_AT: &str = "a sample at the deadline missed";
const SERVED_ONE_BELOW: &str = "a sample one tick below the expiry served the version";

/// Storage ticks in a second: a record keeps its expiry in whole seconds.
const NANOS: u64 = 1_000_000_000;
/// Whole seconds between the publication's second and the expiry.
const EXPIRY_S: u64 = 2;

/// Publishes the written fill with an expiry at a whole second, at least one second ahead.
fn publish_expiring(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let fill = world.history.fill.take().expect("a written fill");
    let deadline = (ticks(now) / NANOS + EXPIRY_S) * NANOS;
    world.history.deadline = deadline;
    let published = world
        .scene
        .owner
        .publish_fill(fill, deadline, 2, &mut budget())
        .is_ok();
    world.owner_due = now;
    let whole = deadline.is_multiple_of(NANOS) && ticks(now) < deadline;
    premised(world, published && whole, PUBLISHED)
}

/// Holds the owner's clock at the current tick, below the expiry, and wakes the run past the expiry.
fn hold_below(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let below = ticks(now) < world.history.deadline;
    if below {
        world.history.clock = Some(ticks(now));
        world.history.wake = Some(world.history.deadline / 1_000 + 1);
    }
    premised(world, below, HELD_BELOW)
}

fn past_deadline(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    ticks(now) > world.history.deadline
}

/// The witness: under the clock held below the expiry, a GET issued after the expiry in world time read
/// the version exactly.
fn served_before(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let (outcome, bytes) = fresh_result(world);
    let served = outcome == Some(Outcome::Complete) && bytes == version_b();
    premised(world, served, SERVED_BEFORE)
}

/// The fault: every later owner turn samples exactly the expiry.
fn hold_at_deadline(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.clock = Some(world.history.deadline);
    mark(world, HELD_AT)
}

/// The sibling: every later owner turn samples the last tick below the expiry.
fn hold_one_below(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.clock = Some(world.history.deadline - 1);
    mark(world, HELD_ONE_BELOW)
}

/// Whether an owner turn armed the tick `held` and left the platform with `held` as its last sample. A
/// turn the history does not hold arms a tick one past a whole microsecond, which neither held tick is.
fn sampled(world: &Mixed<'_, '_, '_>, held: u64) -> bool {
    world
        .clocks
        .iter()
        .any(|clock| clock.projection == held && clock.taken > 0 && clock.last == Some(held))
}

/// When the owner turn's final sample is at `held`, that sample establishes `witness`, and
/// `sampled_read` returns the fresh GET's outcome and bytes.
fn sampled_read(
    world: &mut Mixed<'_, '_, '_>,
    held: u64,
    witness: &'static str,
) -> Option<(Option<Outcome>, Vec<u8>)> {
    let formed = world.history.clock == Some(held) && sampled(world, held);
    if premised(world, formed, witness) == 0 {
        return None;
    }
    Some(fresh_result(world))
}

/// A GET issued while the clock is held at `held` must return `Missing` with an empty body, as at
/// expiry.
fn judge_missed(world: &mut Mixed<'_, '_, '_>, held: u64, witness: &'static str) -> u64 {
    let Some((outcome, bytes)) = sampled_read(world, held, witness) else {
        return 0;
    };
    if outcome != Some(Outcome::Missing) || !bytes.is_empty() {
        return fail(world, Obligation::History, SERVED_AT_EXPIRY);
    }
    mark(world, MISSED_AT)
}

/// A GET issued with the clock held at `held` must return the exact version expected before expiry.
fn judge_served(world: &mut Mixed<'_, '_, '_>, held: u64, witness: &'static str) -> u64 {
    let Some((outcome, bytes)) = sampled_read(world, held, witness) else {
        return 0;
    };
    if outcome != Some(Outcome::Complete) || bytes != version_b() {
        return fail(world, Obligation::Bytes, MISSED_BELOW);
    }
    mark(world, SERVED_ONE_BELOW)
}

fn missed_at_expiry(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let held = world.history.deadline;
    judge_missed(world, held, SAMPLED_AT)
}

fn served_one_below(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let held = world.history.deadline - 1;
    judge_served(world, held, SAMPLED_ONE_BELOW)
}

/// The control holds the clock one tick before expiry, when the version is live, but judges the GET as
/// if the clock had reached expiry.
fn missed_one_below(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let held = world.history.deadline - 1;
    judge_missed(world, held, SAMPLED_ONE_BELOW)
}

/// The clock stays at expiry, when the version is expired. The control judges the GET as if the clock
/// were one tick before expiry.
fn served_at_expiry(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let held = world.history.deadline;
    judge_served(world, held, SAMPLED_AT)
}

const AT_EXPIRY: [Step; 9] = [
    step("fill-replacement", always, fill_b),
    step("publish-expiring", fill_written, publish_expiring),
    step("hold-clock", always, hold_below),
    step("past-deadline-get", past_deadline, fresh_get),
    step("held-read", fresh_decided, served_before),
    step("hold-at-deadline", always, hold_at_deadline),
    step("deadline-get", uploader_idle, fresh_get),
    step("deadline-read", fresh_decided, missed_at_expiry),
    JUDGE,
];

const ONE_BELOW: [Step; 9] = [
    step("fill-replacement", always, fill_b),
    step("publish-expiring", fill_written, publish_expiring),
    step("hold-clock", always, hold_below),
    step("past-deadline-get", past_deadline, fresh_get),
    step("held-read", fresh_decided, served_before),
    step("hold-below-deadline", always, hold_one_below),
    step("deadline-get", uploader_idle, fresh_get),
    step("deadline-read", fresh_decided, served_one_below),
    JUDGE,
];

const BELOW_JUDGED_AT: [Step; 9] = replaced(
    ONE_BELOW,
    "deadline-read",
    step("deadline-read-judged-at", fresh_decided, missed_one_below),
);

const AT_JUDGED_BELOW: [Step; 9] = replaced(
    AT_EXPIRY,
    "deadline-read",
    step(
        "deadline-read-judged-below",
        fresh_decided,
        served_at_expiry,
    ),
);

const AT_EXPIRY_WITNESSES: &[&str] = &[
    PUBLISHED,
    HELD_BELOW,
    SERVED_BEFORE,
    HELD_AT,
    SAMPLED_AT,
    MISSED_AT,
];

const ONE_BELOW_WITNESSES: &[&str] = &[
    PUBLISHED,
    HELD_BELOW,
    SERVED_BEFORE,
    HELD_ONE_BELOW,
    SAMPLED_ONE_BELOW,
    SERVED_ONE_BELOW,
];

const AT_EXPIRY_JUDGED: &[Obligation] = &[Obligation::History];

const ONE_BELOW_JUDGED: &[Obligation] = &[Obligation::Bytes];

/// The obligation the sibling's check mark judges.
pub(super) const CHECKS: [(&str, Obligation); 1] = [(SERVED_ONE_BELOW, Obligation::Bytes)];

const AT_PREMISE: &[&str] = &[PUBLISHED, HELD_AT, SAMPLED_AT];

const ONE_BELOW_PREMISE: &[&str] = &[PUBLISHED, HELD_ONE_BELOW, SAMPLED_ONE_BELOW];

pub(super) const EXPIRY_SAMPLES: [History; 4] = [
    history(
        "ex1-get-at-the-expiry",
        &AT_EXPIRY,
        AT_EXPIRY_WITNESSES,
        AT_EXPIRY_JUDGED,
        Expect::Pass,
    ),
    history(
        "ex1-get-below-the-expiry",
        &ONE_BELOW,
        ONE_BELOW_WITNESSES,
        ONE_BELOW_JUDGED,
        Expect::Pass,
    ),
    control(
        history(
            "ex1-get-below-judged-at-the-expiry",
            &BELOW_JUDGED_AT,
            AT_EXPIRY_WITNESSES,
            AT_EXPIRY_JUDGED,
            Expect::Violation(Obligation::History, SERVED_AT_EXPIRY),
        ),
        ONE_BELOW_PREMISE,
    ),
    control(
        history(
            "ex1-get-at-judged-below-the-expiry",
            &AT_JUDGED_BELOW,
            ONE_BELOW_WITNESSES,
            ONE_BELOW_JUDGED,
            Expect::Violation(Obligation::Bytes, MISSED_BELOW),
        ),
        AT_PREMISE,
    ),
];

#[cfg(test)]
mod tests {
    use super::{EXPIRY_SAMPLES, Expect, MISSED_AT, SERVED_ONE_BELOW};

    /// A premise judges nothing, so the obligations a passing history declares are exactly those
    /// the mark of its judging step activates.
    #[test]
    fn every_passing_expiry_history_declares_the_obligations_its_judging_mark_activates() {
        let judged = [
            ("ex1-get-at-the-expiry", MISSED_AT),
            ("ex1-get-below-the-expiry", SERVED_ONE_BELOW),
        ];
        let passing: Vec<_> = EXPIRY_SAMPLES
            .iter()
            .filter(|history| history.expect == Expect::Pass)
            .collect();
        assert_eq!(passing.len(), judged.len());
        for (name, mark) in judged {
            let history = passing.iter().find(|h| h.name == name).expect(name);
            assert!(history.witnesses.contains(&mark), "{name}");
            assert_eq!(
                super::super::activated(&[mark]),
                history.obligations,
                "{name}"
            );
        }
    }
}
