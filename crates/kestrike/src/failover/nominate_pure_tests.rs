//! `nominate` is a function of its evidence alone.
//!
//! The arbiter evaluates detector evidence and returns the first refusal or a flip nomination. It performs no
//! effect and spends no permit or budget.
//!
//! The test holds a fixed set of evidence: three that pass every check (the base evidence, the same evidence
//! for another target, and the same evidence at a later `now` with a clock sampled then) and seven that each
//! fail one check. It calls `nominate` on them in a fixed interleaved order, builds each evidence afresh for
//! each call, and compares every answer with the answer the test's own table gives for that evidence. The
//! table depends on the evidence alone, so an answer that changes with the calls made before it disagrees
//! with the table. The test runs on one thread and holds no fixture.

use super::arbiter::{
    ArbiterBounds, Clock, Decline, FlipNomination, Nomination, Observation, nominate,
};
use super::arbiter_tests::{bounds, nomination, target, votes};
use super::retire::Target;

/// One evidence of the fixed set. Each differs from `Base` in the one input its name says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Evidence {
    /// Passes every check: two Dead votes of two partitions and classes at `now` 10, the clock sampled at 7.
    Base,
    /// `Base` with the observation opened for another target; it passes every check.
    OtherTarget,
    /// `Base` at `LATER` with the clock sampled at `LATER`; it passes every check.
    Later,
    /// `Base` at `LATER` with the clock still sampled at 7, older than `clock_age`.
    LaterStaleClock,
    /// `Base` with `k` of 1 in the bounds.
    BadBounds,
    /// `Base` from an unhealthy observer.
    Unhealthy,
    /// `Base` at `now` 1, before the suspicion's stamp of 3.
    BeforeSuspicion,
    /// `Base` with no vote.
    NoVotes,
    /// `Base` with the first vote alone, one partition where `k` is 2.
    OneVote,
    /// `Base` with an untrusted clock.
    Untrusted,
}
use Evidence::{
    BadBounds, Base, BeforeSuspicion, Later, LaterStaleClock, NoVotes, OneVote, OtherTarget,
    Unhealthy, Untrusted,
};

/// The later `now`; it is more than `clock_age` (3) past the base clock sample of 7.
const LATER: u64 = 20;

/// The target `OtherTarget` names: the base target after one more attempt.
fn other_target() -> Target {
    Target {
        attempts: target().attempts + 1,
        ..target()
    }
}

/// The table of expected answers: for each evidence the nomination of the observation's target or
/// the first refusal in the order the checks run. It reads the evidence's name and nothing else.
fn expected(evidence: Evidence) -> Result<FlipNomination, Decline> {
    match evidence {
        Base | Later => Ok(FlipNomination { target: target() }),
        OtherTarget => Ok(FlipNomination {
            target: other_target(),
        }),
        LaterStaleClock | Untrusted => Err(Decline::ClockUntrusted),
        BadBounds => Err(Decline::Bounds),
        Unhealthy => Err(Decline::ObserverUnhealthy),
        BeforeSuspicion => Err(Decline::StaleSuspicion),
        // The base bounds have a dwell of 2 and the base `now` is 10.
        NoVotes => Err(Decline::SelfSuspect { until: 12 }),
        OneVote => Err(Decline::Quorum),
    }
}

/// Builds `evidence` afresh from the base bounds, votes and nomination and returns the arbiter's answer to it.
fn answer(evidence: Evidence) -> Result<FlipNomination, Decline> {
    let all = votes();
    let votes = match evidence {
        NoVotes => &all[..0],
        OneVote => &all[..1],
        _ => &all[..],
    };
    let b = match evidence {
        BadBounds => ArbiterBounds { k: 1, ..bounds() },
        _ => bounds(),
    };
    let base = nomination(votes);
    let n = match evidence {
        Base | BadBounds | NoVotes | OneVote => base,
        OtherTarget => Nomination {
            observation: Observation {
                target: other_target(),
                ..base.observation
            },
            ..base
        },
        Later => Nomination {
            now: LATER,
            clock: Clock::Trusted { sampled_at: LATER },
            ..base
        },
        LaterStaleClock => Nomination { now: LATER, ..base },
        Unhealthy => Nomination {
            observer_healthy: false,
            ..base
        },
        BeforeSuspicion => Nomination { now: 1, ..base },
        Untrusted => Nomination {
            clock: Clock::Untrusted,
            ..base
        },
    };
    nominate(&b, &n)
}

/// The order of the calls. Every refusal is asked before the first nomination and again after nominations; each
/// nominating evidence is repeated at once and again after calls with other evidence that nominates or refuses.
/// The order holds fifteen calls that nominate.
const ORDER: [Evidence; 40] = [
    // Refusals before any nomination.
    BadBounds,
    Unhealthy,
    BeforeSuspicion,
    NoVotes,
    OneVote,
    LaterStaleClock,
    Untrusted,
    // The base nomination, repeated at once.
    Base,
    Base,
    Base,
    // The refusals after a nomination.
    OneVote,
    Untrusted,
    BadBounds,
    Unhealthy,
    BeforeSuspicion,
    NoVotes,
    LaterStaleClock,
    // Nominations of another target and at a later time, each followed by the base nomination.
    OtherTarget,
    Base,
    Later,
    Base,
    OtherTarget,
    OtherTarget,
    Later,
    Later,
    // Refusals between nominations.
    OneVote,
    Base,
    Untrusted,
    OtherTarget,
    LaterStaleClock,
    Later,
    NoVotes,
    Base,
    // The refusals once more, after every nomination.
    BadBounds,
    Unhealthy,
    BeforeSuspicion,
    NoVotes,
    OneVote,
    LaterStaleClock,
    Untrusted,
];

/// The arbiter's answer is a function of its evidence alone. Every call of `ORDER` returns the answer
/// the table gives its evidence, whatever calls came before it: evidence that passes every check is nominated
/// with its observation's target on the first call and on every repeat, and evidence that fails a check gets the
/// same first refusal before and after a nomination.
#[test]
fn the_answer_to_given_evidence_does_not_depend_on_earlier_calls() {
    let nominating = ORDER.iter().filter(|e| expected(**e).is_ok()).count();
    assert!(
        nominating >= 2,
        "premise: the order holds at least two calls whose evidence passes every check, it holds {nominating}"
    );
    let mut disagreements = Vec::new();
    for (call, evidence) in ORDER.into_iter().enumerate() {
        let got = answer(evidence);
        let want = expected(evidence);
        if got != want {
            disagreements.push(format!(
                "call {call} with evidence {evidence:?} returned {got:?}, its evidence alone gives {want:?}"
            ));
        }
    }
    assert!(
        disagreements.is_empty(),
        "nominate's answer depends on more than its evidence: {}",
        disagreements.join("; ")
    );
}
