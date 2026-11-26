//! Root-slot histories: a tenure on a device whose persistence unit is
//! 16384 bytes publishes capture passes as checkpoints and closes, and a
//! probe attaches its media on a storage of its own under another session.
//!
//! Property: [`REISSUED`], array `MIXED` of
//! `crates/kestrike/src/net/world_tests/narrate/rules.rs`, under
//! `Obligation::Restart`. The rule states the clause "every relaunch writes
//! its tenure session above every generation the slots held" of the
//! obligation record `reset-roots-leave-no-older-root-selectable` in
//! `verification/obligations.json`, and NO-REISSUE of
//! `crates/kestrike/src/storage/recovery/mod.rs`: "The bootstrap refuses
//! `StaleSession` when a valid root holds a generation at or above the
//! session, so the roots it writes stay the highest."
//!
//! Each history runs under `Geometry::WideUnit`, whose run draws one
//! fixture session before its scene, so the tenure's session
//! `session_at(g, n)` has `n` of 1 or more and the probe can attach under
//! `session_at(g, n - 1)`. The tenure's checkpoint units land at 4096-byte
//! offsets from byte 0 and its root blocks at 16384-byte offsets from byte
//! 0, so two checkpoints in two slots overwrite both root blocks.
//!
//! The judgment reads the probe's outcomes, the root writes the probe's own
//! device executed, and the generations both root blocks decode to after
//! the probe, against `held`, the generation both blocks decoded to before
//! the passes. `StaleSession` with no root write and both blocks still at
//! `held` passes the check. A root write that decodes at or below `held`
//! fails the check under every final outcome of the probe and every later
//! content of the root blocks. Before that failure a probe whose first
//! outcome was `Unformatted` marks [`UNFORMATTED`], and a probe that found
//! neither block decoding marks [`LOST`]; the pin declares both marks as
//! its premise. `Verdict::Unjudged` ends the history Unsuccessful under
//! [`JUDGED`].
//!
//! The second pass runs through the first pass's steps, so a second pass
//! that does not start or publish ends the run Unsuccessful under the first
//! pass's premise text, and the run's marks name the last step that
//! completed. Each publish step ends the run Unsuccessful under the pass's
//! premise once [`UNIT_WAITS`] of its visits in a row leave the pass
//! waiting while the scene's device accepts and delivers no command.

use crate::storage::device::Operation;
use crate::storage::owner_fixture::{arena, storage_shaped_as};
use crate::storage::volume_fixture::{BUFFER, Probe, attach_probing, root_generations, unit};
use crate::storage::{MetadataOutcome, session_at};

use super::warm_loads::{
    ADMITTED, OWNER_CLOSED, PASS_PUBLISHED, PASS_STARTED, SUFFIX_OPENED, arm_warm, close_first,
    open_tenure_suffix, publish_pass, start_pass,
};
use super::*;

const HELD: &str = "both root slots held the tenure's session";
const SECOND_STARTED: &str = "a second capture pass started";
const SECOND_PUBLISHED: &str = "a second capture pass published";
const BELOW: &str = "a lower session attached the media";
const ABOVE: &str = "a higher session attached the media";
const JUDGED: &str = "the probe reached a root verdict";
const STALE: &str = "the lower-session attach ended StaleSession";
const UNFORMATTED: &str = "the lower-session attach read Unformatted";
const LOST: &str = "no root block decoded before the probe";
const KEPT: &str = "no attach wrote a root generation at or below a held one";

/// The rule the judgment raises.
const REISSUED: &str = "an attach wrote a root generation at or below one the root slots held";

/// The obligation each root-slot check's mark judges.
pub(super) const CHECKS: [(&str, Obligation); 1] = [(KEPT, Obligation::Restart)];

/// Visits a publish step makes in a row while its pass waits and the
/// scene's device accepts and delivers no command, before the step ends
/// the run Unsuccessful. The visit bound lets the publish step report a
/// stalled pass before the run reaches its same-time limit of 400 turns.
const UNIT_WAITS: u32 = 256;

/// The scene's device's command counts: reads and writes accepted, reads
/// and writes delivered, and injected completions delivered.
type Counts = [usize; 5];

/// The generations both root blocks decode to, `None` for a block that
/// does not decode.
type Generations = [Option<u64>; 2];

/// A publish step's run of waiting visits over unchanged device counts.
#[derive(Clone, Copy, Default)]
struct Waits {
    seen: Counts,
    idle: u32,
}

impl Waits {
    /// Counts one visit that left the pass waiting with the device's counts
    /// at `counts`; returns whether fewer than [`UNIT_WAITS`] visits in a
    /// row saw the same counts.
    fn wait(&mut self, counts: Counts) -> bool {
        if counts != self.seen {
            *self = Self {
                seen: counts,
                idle: 0,
            };
            return true;
        }
        self.idle = self.idle.saturating_add(1);
        self.idle < UNIT_WAITS
    }
}

/// `roots_held` captures the tenure state; `publish_bounded` uses `waits`
/// to bound stalled visits.
#[derive(Clone)]
pub(super) struct Roots {
    /// The tenure's session, which `roots_held` compares both decoded
    /// generations with.
    held: u64,
    generation: u64,
    attempts: u32,
    /// The generations both root blocks decode to before the probe, what the
    /// probe saw, and the generations both blocks decode to after it.
    probed: Option<(Generations, Probe, Generations)>,
    waits: Waits,
}

fn roots_held(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let tenure = world.scene.owner.tenure();
    let session = tenure.get();
    let target = tenure.target();
    let media = world.scene.control.shared_media();
    let generations = root_generations(&media, unit());
    let held = unit() == BUFFER && generations == [Some(session); 2];
    world.history.roots = Some(Roots {
        held: session,
        generation: target.generation.get(),
        attempts: target.attempts,
        probed: None,
        waits: Waits::default(),
    });
    premised(world, held, HELD)
}

fn device_counts(world: &Mixed<'_, '_, '_>) -> Counts {
    let device = &world.scene.control;
    [
        device.accepted(Operation::Read),
        device.accepted(Operation::Write),
        device.delivered(Operation::Read),
        device.delivered(Operation::Write),
        device.delivered_injections(),
    ]
}

/// The [`UNIT_WAITS`] bound lets `PASS_PUBLISHED` report a stalled pass
/// before the run reaches its same-time turn limit.
fn publish_bounded(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let published = publish_pass(world, now);
    let counts = device_counts(world);
    let roots = world.history.roots.as_mut().expect("the held roots");
    if published != STAY {
        roots.waits = Waits::default();
        return published;
    }
    if roots.waits.wait(counts) {
        return STAY;
    }
    premised(world, false, PASS_PUBLISHED)
}

/// A 0 is the refusal `start_pass` recorded.
fn start_second(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    match start_pass(world, now) {
        0 => 0,
        _ => mark(world, SECOND_STARTED),
    }
}

/// A 0 is the refusal `publish_bounded` recorded.
fn publish_second(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    match publish_bounded(world, now) {
        STAY => STAY,
        0 => 0,
        _ => mark(world, SECOND_PUBLISHED),
    }
}

fn quiet(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world.closed && world.scene.control.pending() == 0
}

fn probe(
    world: &mut Mixed<'_, '_, '_>,
    attempt: fn(u32) -> Option<u32>,
    reissue: bool,
    witness: &'static str,
) -> u64 {
    let roots = world.history.roots.clone().expect("the held roots");
    // `session_at(g, n)` bumps attempt count `n` to `n + 1`.
    let Some(attempts) = roots.attempts.checked_sub(1).and_then(attempt) else {
        return premised(world, false, witness);
    };
    let media = world.scene.control.shared_media();
    let (shape, chunk_len) = world.plan.geometry.shape();
    let storage = storage_shaped_as(shape, chunk_len);
    let arena = arena(16);
    let before = root_generations(&media, unit());
    let at = session_at(roots.generation, attempts);
    let Ok(probed) = attach_probing(&storage, &arena, &media, at, reissue) else {
        return premised(world, false, witness);
    };
    let after = root_generations(&media, unit());
    world.history.roots = Some(Roots {
        probed: Some((before, probed, after)),
        ..roots
    });
    mark(world, witness)
}

fn probe_below(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    probe(world, |n| n.checked_sub(1), false, BELOW)
}

/// The next attempt serves as the reissue control.
fn probe_reissuing(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    probe(world, |n| n.checked_add(1), true, ABOVE)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    /// `StaleSession` is the probe's final outcome, its device wrote no
    /// root, and both root blocks still decode to the held generation.
    Kept,
    /// The probe's device wrote a root that decodes at or below the held
    /// generation, under any final outcome and whatever the root blocks
    /// decode to after the probe.
    Reissued,
    /// Every other observation: an undecodable root write or one above the
    /// held generation with none at or below it, or no root write without
    /// the refusal and the unchanged blocks `Kept` requires.
    Unjudged,
}

/// `after` holds the generations both root blocks decode to after `probe`.
fn verdict(held: u64, probe: &Probe, after: Generations) -> Verdict {
    let at_or_below = |generation: &Option<u64>| generation.is_some_and(|g| g <= held);
    if probe.root_writes.iter().any(at_or_below) {
        return Verdict::Reissued;
    }
    let refused = probe.last == MetadataOutcome::StaleSession;
    if refused && probe.root_writes.is_empty() && after == [Some(held); 2] {
        return Verdict::Kept;
    }
    Verdict::Unjudged
}

fn judge_roots(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let roots = world.history.roots.clone().expect("the held roots");
    let Some((before, probed, after)) = roots.probed else {
        return premised(world, false, JUDGED);
    };
    match verdict(roots.held, &probed, after) {
        Verdict::Kept => {
            mark(world, STALE);
            mark(world, KEPT)
        }
        Verdict::Reissued => {
            if before == [None; 2] {
                mark(world, LOST);
            }
            if probed.first == MetadataOutcome::Unformatted {
                mark(world, UNFORMATTED);
            }
            fail(world, Obligation::Restart, REISSUED)
        }
        Verdict::Unjudged => premised(world, false, JUDGED),
    }
}

const RS1_LOST: [Step; 11] = [
    step("arm", always, arm_warm),
    step("roots-held", always, roots_held),
    step("start-pass", always, start_pass),
    step("publish-pass", always, publish_bounded),
    step("open-suffix", always, open_tenure_suffix),
    step("start-pass-2", always, start_second),
    step("publish-pass-2", always, publish_second),
    step("close-owner", always, close_first),
    step("probe-below", quiet, probe_below),
    step("judge-roots", always, judge_roots),
    JUDGE,
];

const fn removed(name: &'static str) -> Step {
    step(name, always, removed_step)
}

const RS1_KEPT: [Step; 11] = {
    let script = replaced(RS1_LOST, "start-pass", removed("no-pass"));
    let script = replaced(script, "publish-pass", removed("no-publish"));
    let script = replaced(script, "open-suffix", removed("no-suffix"));
    let script = replaced(script, "start-pass-2", removed("no-pass-2"));
    replaced(script, "publish-pass-2", removed("no-publish-2"))
};

const RS1_REISSUED: [Step; 11] = replaced(
    RS1_KEPT,
    "probe-below",
    step("probe-reissuing", quiet, probe_reissuing),
);

const RS1_LOST_WITNESSES: &[&str] = &[
    ADMITTED,
    HELD,
    PASS_STARTED,
    PASS_PUBLISHED,
    SUFFIX_OPENED,
    SECOND_STARTED,
    SECOND_PUBLISHED,
    OWNER_CLOSED,
    BELOW,
];

const RS1_KEPT_WITNESSES: &[&str] = &[ADMITTED, HELD, OWNER_CLOSED, BELOW, STALE, KEPT];

const RS1_REISSUED_WITNESSES: &[&str] = &[ADMITTED, HELD, OWNER_CLOSED, ABOVE];

/// The marks the control's run holds before its judgment.
const REISSUED_PREMISE: &[&str] = &[HELD, OWNER_CLOSED, ABOVE];

const OBLIGATIONS: &[Obligation] = &[Obligation::Restart];

const ROOT_REISSUED: Expect = Expect::Violation(Obligation::Restart, REISSUED);

const fn root_slot(
    name: &'static str,
    script: &'static [Step],
    witnesses: &'static [&'static str],
    expect: Expect,
) -> History {
    wide(history(name, script, witnesses, OBLIGATIONS, expect))
}

/// The marks the pin's run holds before its judgment's violation.
const LOST_PREMISE: &[&str] = &[LOST, UNFORMATTED];

pub(super) const ROOT_SLOTS: [History; 3] = [
    History {
        premise: LOST_PREMISE,
        ..root_slot(
            "rs1-wide-unit-roots-lost",
            &RS1_LOST,
            RS1_LOST_WITNESSES,
            ROOT_REISSUED,
        )
    },
    root_slot(
        "rs1-wide-unit-without-pass",
        &RS1_KEPT,
        RS1_KEPT_WITNESSES,
        Expect::Pass,
    ),
    control(
        root_slot(
            "rs1-without-pass-reissued",
            &RS1_REISSUED,
            RS1_REISSUED_WITNESSES,
            ROOT_REISSUED,
        ),
        REISSUED_PREMISE,
    ),
];

#[cfg(test)]
mod tests {
    use crate::oracle::Obligation;
    use crate::storage::MetadataOutcome::{MetadataFailed, Open, StaleSession, Unformatted};
    use crate::storage::volume_fixture::{Probe, unit};

    use super::super::super::{LIMITS, Step, mixed_run, sites_for};
    use super::super::tests::{ends_as_declared_at, first_failure, manifest};
    use super::super::{Failure, always, named, replaced, step};
    use super::{
        Expect, LOST, Mixed, PASS_PUBLISHED, REISSUED, ROOT_SLOTS, RS1_LOST, UNFORMATTED,
        UNIT_WAITS, Verdict, Waits, publish_bounded, verdict,
    };

    const ROOTS: [u64; 3] = [1, 2, 4_302_617_955_180_736_441];

    #[test]
    fn every_root_slot_control_fails_through_its_named_check() {
        let reissued = Expect::Violation(Obligation::Restart, REISSUED);
        for history in &ROOT_SLOTS {
            let name = history.name;
            match name {
                "rs1-without-pass-reissued" => {
                    assert_eq!(history.expect, reissued, "{name}");
                    assert!(!history.premise.is_empty(), "{name} declares its premise");
                }
                "rs1-wide-unit-roots-lost" => {
                    assert_eq!(history.expect, reissued, "{name}");
                    assert_eq!(history.premise, [LOST, UNFORMATTED], "{name}");
                }
                _ => assert_eq!(history.expect, Expect::Pass, "{name}"),
            }
            for root in ROOTS {
                assert_eq!(
                    first_failure(name, root),
                    history.expect.failure(),
                    "{name} at {root}"
                );
                assert_eq!(unit(), 4096, "{name} at {root}");
            }
        }
    }

    #[test]
    fn every_root_slot_history_ends_as_declared_and_replays_equal() {
        for history in &ROOT_SLOTS {
            ends_as_declared_at(history, manifest(history.name).root);
            assert_eq!(unit(), 4096, "{}", history.name);
        }
    }

    #[test]
    fn every_root_slot_history_ends_as_declared_under_pinned_roots() {
        for history in &ROOT_SLOTS {
            for root in ROOTS {
                ends_as_declared_at(history, root);
                assert_eq!(unit(), 4096, "{} at {root}", history.name);
            }
        }
    }

    fn probe(
        first: crate::storage::MetadataOutcome,
        last: crate::storage::MetadataOutcome,
        root_writes: &[Option<u64>],
    ) -> Probe {
        Probe {
            first,
            last,
            root_writes: root_writes.to_vec(),
        }
    }

    #[test]
    fn the_root_verdict_needs_every_observation_it_names() {
        const HELD: u64 = 40;
        let cases = [
            (
                probe(StaleSession, StaleSession, &[]),
                [Some(HELD); 2],
                Verdict::Kept,
            ),
            (
                probe(StaleSession, StaleSession, &[]),
                [Some(HELD), Some(HELD - 2)],
                Verdict::Unjudged,
            ),
            (
                probe(StaleSession, StaleSession, &[]),
                [Some(HELD), None],
                Verdict::Unjudged,
            ),
            (
                probe(StaleSession, StaleSession, &[Some(HELD)]),
                [Some(HELD); 2],
                Verdict::Reissued,
            ),
            (
                probe(StaleSession, StaleSession, &[Some(HELD - 2)]),
                [Some(HELD - 2), Some(HELD)],
                Verdict::Reissued,
            ),
            (
                probe(MetadataFailed, MetadataFailed, &[Some(HELD - 2)]),
                [Some(HELD - 2), Some(HELD)],
                Verdict::Reissued,
            ),
            (
                probe(StaleSession, StaleSession, &[Some(HELD)]),
                [Some(HELD), None],
                Verdict::Reissued,
            ),
            (
                probe(StaleSession, StaleSession, &[Some(HELD + 2)]),
                [Some(HELD + 2), Some(HELD)],
                Verdict::Unjudged,
            ),
            (
                probe(StaleSession, StaleSession, &[None]),
                [Some(HELD); 2],
                Verdict::Unjudged,
            ),
            (
                probe(Unformatted, Open, &[Some(HELD - 2); 2]),
                [Some(HELD - 2); 2],
                Verdict::Reissued,
            ),
            (
                probe(Open, Open, &[Some(HELD); 2]),
                [Some(HELD); 2],
                Verdict::Reissued,
            ),
            (probe(Open, Open, &[]), [Some(HELD); 2], Verdict::Unjudged),
            (
                probe(Open, Open, &[None, None]),
                [Some(HELD); 2],
                Verdict::Unjudged,
            ),
            (
                probe(Open, Open, &[Some(HELD + 2); 2]),
                [Some(HELD + 2); 2],
                Verdict::Unjudged,
            ),
            (
                probe(Open, Open, &[Some(HELD - 2)]),
                [Some(HELD - 2), None],
                Verdict::Reissued,
            ),
            (
                probe(Open, Open, &[Some(HELD - 2)]),
                [Some(HELD - 2), Some(HELD + 2)],
                Verdict::Reissued,
            ),
            (
                probe(
                    Open,
                    Open,
                    &[Some(HELD - 2), Some(HELD + 2), Some(HELD + 2)],
                ),
                [Some(HELD + 2); 2],
                Verdict::Reissued,
            ),
            (
                probe(MetadataFailed, MetadataFailed, &[Some(HELD - 2), None]),
                [None; 2],
                Verdict::Reissued,
            ),
            (
                probe(Unformatted, Unformatted, &[]),
                [None; 2],
                Verdict::Unjudged,
            ),
            (
                probe(
                    Unformatted,
                    crate::storage::MetadataOutcome::Bootstrapping,
                    &[],
                ),
                [None; 2],
                Verdict::Unjudged,
            ),
        ];
        for (probed, after, expected) in cases {
            assert_eq!(
                verdict(HELD, &probed, after),
                expected,
                "{probed:?} {after:?}"
            );
        }
    }

    #[test]
    fn a_publish_wait_ends_after_its_visits_over_unchanged_counts() {
        let mut waits = Waits::default();
        let counts = [1, 2, 3, 4, 0];
        assert!(waits.wait(counts));
        for _ in 1..UNIT_WAITS {
            assert!(waits.wait(counts));
        }
        assert!(waits.wait([1, 2, 3, 5, 0]));
        for _ in 1..UNIT_WAITS {
            assert!(waits.wait([1, 2, 3, 5, 0]));
        }
        assert!(!waits.wait([1, 2, 3, 5, 0]));
    }

    fn publish_held(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
        for held in world.scene.control.held() {
            if !held.moved && !held.posted {
                world.scene.control.hold(held.token);
            }
        }
        publish_bounded(world, now)
    }

    const STALLED: [Step; 11] = replaced(
        RS1_LOST,
        "publish-pass",
        step("publish-pass", always, publish_held),
    );

    #[test]
    fn a_publish_over_a_held_unit_command_ends_unsuccessful_under_its_pass() {
        for root in ROOTS {
            let (profile, mut plan, goal) =
                named("rs1-wide-unit-roots-lost", root).expect("the pin");
            plan.script = &STALLED;
            let chooser = profile.recorder(&sites_for(&plan));
            let (_, first, _) = mixed_run(chooser, &profile, plan, goal, LIMITS, &mut ());
            assert_eq!(
                first,
                Some(Failure::Unsuccessful(PASS_PUBLISHED)),
                "at {root}"
            );
            assert_eq!(unit(), 4096, "at {root}");
        }
    }
}
