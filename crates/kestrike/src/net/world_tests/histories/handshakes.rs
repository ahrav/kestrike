//! Handshake histories: a replacement client opens while the older boot's
//! HELLO takes the owner's pending handshake for the peer.
//!
//! Property: obligation record `q1-handshake-eventual-activation`, whose
//! transition is "a client's bounded CONFIRM repeats and fresh HELLO after a
//! stale older-boot
//! HELLO displaced the owner's pending handshake" and whose invariant is
//! "once the environment is stable ... every client ends with an active
//! session".
//!
//! Q1 realizes the schedule of the Q1 session model's reachability
//! witnesses `witnessPendingDisplaced` and `witnessDisplacedRestart`, the
//! cases `reach-witnessPendingDisplaced` and `reach-witnessDisplacedRestart`
//! of `quint/check.py`: a replacement boot sends its HELLO, the owner's
//! CHALLENGE for it is delayed, and the older boot's HELLO reaches the owner
//! in that delay and takes the pending handshake. The replacement's CONFIRM
//! and each of its [`CONFIRM_REPEATS`] repeats then name a handshake the
//! owner no longer holds, and the client restarts with a fresh HELLO. No
//! frame is delayed or sent by the older boot after that HELLO, so the
//! environment is stable from there on. The sibling runs the same steps
//! without the older boot's HELLO, so the delayed CHALLENGE's CONFIRM
//! activates.
//!
//! Each history then judges that the owner and the replacement client hold
//! one session for the peer, other than the one the older boot held, and
//! that a GET under it reads the resident version exactly inside its one
//! deadline. The judgment sets no deadline of its own for the activation:
//! it reads the client's own end of the opening, which is an active session
//! or [`SessionState::Failed`] once the client spent its bootstrap resends.
//! A client that has neither failed nor agreed on a session when the
//! history's wait ends leaves the run unsuccessful. Every premise reads state that exists with and without a
//! defect: the link's record of the delayed CHALLENGE and the owner's count
//! of frames that named no session or handshake it held. A run whose owner
//! refused fewer frames than the CONFIRM and its repeats ends unsuccessful
//! under that premise.
//!
//! The judged step's check is shared by its control, which passes it one
//! planted observation: the client read as failed without a session, as a
//! client that repeated its CONFIRM without bound ends its opening.

use super::super::super::CONFIRM_REPEATS;
use super::super::super::client::SessionState;
use super::super::super::frame::Kind;
use super::super::super::rules::{Chain, Effect, MANIFEST, Rule, Selector};
use super::incidents::displace;
use super::*;

/// The link side of the replaced client and its replacement.
const CLIENT: usize = 0;

/// Link turns the replacement's first CHALLENGE waits before delivery: less
/// than the client's bootstrap resend interval, so the client's opening
/// HELLO is sent once.
const CHALLENGE_TURNS: u64 = 20;

/// The rule for a client the owner's displaced pending handshake left
/// without a session; record `q1-handshake-eventual-activation`: "once the
/// environment is stable ... every client ends with an active session".
pub(crate) const UNOPENED: &str =
    "the owner's displaced pending handshake left its client without a session";

/// The rule for the activated client's GET missing the resident version.
const MISSED: &str = "the replacement's GET missed the visible version";

const DELAY_ARMED: &str = "a CHALLENGE delay armed";
const OPENED: &str = "a replacement client opened a session";
const OLDER_HELLO: &str = "the older boot's HELLO followed the replacement's";
const QUIET_OLDER: &str = "the older boot stayed silent";
const REFUSED: &str = "the owner refused the replacement's CONFIRM and its repeats";
const SETTLED: &str = "the client's opening ended inside the history's wait";
const ACTIVATED: &str = "the client activated after its handshake";
const EXACT: &str = "the activated client read the resident version exactly";

/// Delays the next CHALLENGE toward the client and records the epoch of the
/// session the older boot holds.
fn delay_challenge(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let challenge = Selector::All(vec![
        Selector::Kind(Kind::Challenge),
        Selector::Toward(CLIENT),
    ]);
    let rules = vec![Rule::new(challenge, Effect::Delay(CHALLENGE_TURNS)).window(0, 1)];
    let taps = [rules.len()];
    let chain = Chain::new(rules, &taps, &MANIFEST).expect("a bounded chain");
    world.scene.nets[0].borrow_mut().set_rules(chain);
    world.history.old_epoch = world.scene.clients[0].session_epoch();
    mark(world, DELAY_ARMED)
}

/// The owner answered the replacement's HELLO, and the link holds that
/// CHALLENGE.
fn challenge_delayed(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world.scene.nets[0]
        .borrow()
        .rules()
        .captures()
        .iter()
        .any(|capture| {
            capture.kind == Some(Kind::Challenge) && capture.decision.delay == Some(CHALLENGE_TURNS)
        })
}

/// Frames the owner refused as naming no session or handshake it holds.
fn owner_mismatched(world: &Mixed<'_, '_, '_>) -> u64 {
    world.scene.owner.session_report().mismatched
}

/// The older boot opens beside its active session while the replacement's
/// CHALLENGE is in flight; this is the history's last fault.
fn older_hello(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.noted_drops = owner_mismatched(world);
    world.history.since = now;
    let older = world.scene.spare.as_mut().expect("the older boot");
    older.session(now);
    let _ = older.poll(now);
    mark(world, OLDER_HELLO)
}

/// The sibling's step: the older boot sends nothing.
fn older_silent(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.noted_drops = owner_mismatched(world);
    world.history.since = now;
    mark(world, QUIET_OLDER)
}

/// The owner refused the replacement's CONFIRM and every repeat of it, or
/// the history's bound passed.
fn confirms_refused_or_late(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    confirms_refused(world) || now > world.history.since + BOUND_US
}

fn confirms_refused(world: &Mixed<'_, '_, '_>) -> bool {
    owner_mismatched(world) > world.history.noted_drops + u64::from(CONFIRM_REPEATS)
}

/// Marks the displaced handshake's premise; a run whose owner refused
/// fewer CONFIRMs ends unsuccessful under it.
fn mark_refused(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if !confirms_refused(world) {
        world.first.record(Failure::Unsuccessful(REFUSED));
        return 0;
    }
    mark(world, REFUSED)
}

/// The session the replacement client holds when the owner holds the same
/// one for the peer and it is not the older boot's.
fn agreed(world: &Mixed<'_, '_, '_>) -> Option<u64> {
    let client = world.scene.clients[0].session_epoch();
    let owner = world.scene.owner.session_epoch(PeerId(0));
    (client.is_some() && client == owner && client != world.history.old_epoch)
        .then_some(client)
        .flatten()
}

/// The client's opening ended, in an agreed session or failed, or the
/// history's wait passed.
fn opening_ended_or_late(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    agreed(world).is_some()
        || world.scene.clients[0].state() == SessionState::Failed
        || now > world.history.since + BOUND_US
}

fn activated(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let state = world.scene.clients[0].state();
    let session = agreed(world);
    judge_session(world, state, session)
}

/// A control: the client reads as failed without a session, as one that
/// repeated its CONFIRM without bound ends its opening.
fn left_unopened(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    judge_session(world, SessionState::Failed, None)
}

/// Judges the client's end of its opening once the faults ended: `session`
/// is the session it shares with the owner for the peer, and `state` its
/// own session state. A client that failed without that session breaks the
/// property; one that has not failed and shares no such session leaves the
/// history unsuccessful.
fn judge_session(world: &mut Mixed<'_, '_, '_>, state: SessionState, session: Option<u64>) -> u64 {
    if session.is_some() {
        return mark(world, ACTIVATED);
    }
    if state != SessionState::Failed {
        world.first.record(Failure::Unsuccessful(SETTLED));
        return 0;
    }
    fail(world, Obligation::Progress, UNOPENED)
}

fn activated_get(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    match world.scene.clients[0].get(key(1), 0, 1 << 20, now, super::super::WAIT_US) {
        Ok(id) => {
            world.history.ids.push(id);
            1
        }
        Err(_) => STAY,
    }
}

fn get_decided(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world
        .history
        .ids
        .last()
        .is_some_and(|&id| world.scene.clients[0].outcome(id).is_some())
}

/// The activated client's GET reads the resident version exactly.
fn get_exact(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = *world
        .history
        .ids
        .last()
        .expect("the activated client's GET");
    let bytes = drain(&mut world.scene.clients[0], id);
    let outcome = world.collect_get(0, id);
    let _ = world.scene.clients[0].retire(id);
    if outcome != Some(Outcome::Complete) || bytes != version_a() {
        return fail(world, Obligation::Bytes, MISSED);
    }
    mark(world, EXACT);
    mark(world, "qualified exact read")
}

/// The obligation each handshake check's mark judges.
pub(super) const CHECKS: [(&str, Obligation); 2] = [
    (ACTIVATED, Obligation::Progress),
    (EXACT, Obligation::Bytes),
];

/// What follows the handshake in both histories.
const AFTER: [Step; 4] = [
    step("activated", opening_ended_or_late, activated),
    step("activated-get", active_put, activated_get),
    step("activated-read", get_decided, get_exact),
    JUDGE,
];

/// Q1: the older boot's HELLO takes the owner's pending handshake while
/// the replacement's CHALLENGE is delayed.
const Q1_GET: [Step; 8] = joined(
    [
        step("delay-challenge", active_put, delay_challenge),
        step("replace", always, displace),
        step("older-hello", challenge_delayed, older_hello),
        step("confirms-refused", confirms_refused_or_late, mark_refused),
    ],
    AFTER,
);

/// The sibling: the same delayed CHALLENGE with the older boot silent.
const Q1_GET_UNDISPLACED: [Step; 7] = joined(
    [
        step("delay-challenge", active_put, delay_challenge),
        step("replace", always, displace),
        step("older-silent", challenge_delayed, older_silent),
    ],
    AFTER,
);

const Q1_GET_UNOPENED: [Step; 8] = replaced(
    Q1_GET,
    "activated",
    step("left-unopened", opening_ended_or_late, left_unopened),
);

const Q1_WITNESSES: &[&str] = &[
    DELAY_ARMED,
    OPENED,
    OLDER_HELLO,
    REFUSED,
    ACTIVATED,
    EXACT,
    "qualified exact read",
];

const Q1_UNDISPLACED_WITNESSES: &[&str] = &[
    DELAY_ARMED,
    OPENED,
    QUIET_OLDER,
    ACTIVATED,
    EXACT,
    "qualified exact read",
];

const Q1_PREMISE: &[&str] = &[DELAY_ARMED, OPENED, OLDER_HELLO, REFUSED];

const Q1: &[Obligation] = &[Obligation::Progress, Obligation::Bytes];

pub(super) const HANDSHAKES: [History; 3] = [
    history(
        "q1-get-after-a-displaced-handshake",
        &Q1_GET,
        Q1_WITNESSES,
        Q1,
        Expect::Pass,
    ),
    history(
        "q1-get-after-an-undisplaced-handshake",
        &Q1_GET_UNDISPLACED,
        Q1_UNDISPLACED_WITNESSES,
        Q1,
        Expect::Pass,
    ),
    control(
        history(
            "q1-client-left-without-a-session",
            &Q1_GET_UNOPENED,
            Q1_WITNESSES,
            Q1,
            Expect::Violation(Obligation::Progress, UNOPENED),
        ),
        Q1_PREMISE,
    ),
];

#[cfg(test)]
mod tests {
    use crate::net::observe::Failure;
    use crate::oracle::Obligation;
    use crate::sim::trace::{Outcome, PAYLOAD, Terminal, load};

    use super::super::super::bundle::{admit, failure_code, traced};
    use super::super::super::replay::{Replayed, replay};
    use super::super::Expect;
    use super::super::tests::manifest;
    use super::{HANDSHAKES, UNOPENED};

    /// History `name` recorded under `root`: its terminal, its violation
    /// record and the bundle.
    fn ran_at(name: &str, root: u64) -> (Terminal, Option<[u8; PAYLOAD]>, Vec<u8>) {
        let mut manifest = manifest(name);
        manifest.root = root;
        let closed = traced(admit(&manifest).expect("admitted"), Vec::new());
        let loaded = load(&closed.sink, manifest.capacity().records()).expect("a loadable bundle");
        (loaded.terminal, loaded.violation, closed.sink)
    }

    #[test]
    fn every_handshake_history_ends_as_declared_and_replays_equal() {
        for history in &HANDSHAKES {
            let bytes = traced(
                admit(&manifest(history.name)).expect("admitted"),
                Vec::new(),
            )
            .sink;
            let loaded = load(&bytes, 1_000_000).expect("a loadable bundle");
            assert_eq!(
                history.ends_as_declared(&loaded),
                Ok(()),
                "{}",
                history.name
            );
            assert_eq!(
                replay(&bytes).expect("a replay").0,
                Replayed::Reproduced,
                "{}",
                history.name
            );
        }
    }

    #[test]
    fn every_passing_handshake_history_activates_the_obligations_it_declares() {
        for history in HANDSHAKES.iter().filter(|h| h.expect == Expect::Pass) {
            let activated = super::super::activated(history.witnesses);
            for obligation in history.obligations {
                assert!(
                    activated.contains(obligation),
                    "{}: {obligation:?} has no witnessed check",
                    history.name
                );
            }
        }
    }

    #[test]
    fn every_handshake_control_fails_through_its_named_check() {
        let killed = [(
            "q1-client-left-without-a-session",
            Obligation::Progress,
            UNOPENED,
        )];
        for (name, obligation, rule) in killed {
            let declared = HANDSHAKES.iter().find(|h| h.name == name).expect(name);
            assert_eq!(
                declared.expect,
                Expect::Violation(obligation, rule),
                "{name}"
            );
            assert!(!declared.premise.is_empty(), "{name} declares its premise");
            let (terminal, violation, _) = ran_at(name, 3);
            assert!(
                matches!(
                    terminal,
                    Terminal::Complete {
                        outcome: Outcome::Violation,
                        ..
                    }
                ),
                "{name}: {terminal:?}"
            );
            assert_eq!(
                violation,
                Some(failure_code(&Failure::Violation(obligation, rule))),
                "{name}"
            );
        }
        let controls = HANDSHAKES
            .iter()
            .filter(|h| h.expect != Expect::Pass)
            .count();
        assert_eq!(controls, killed.len());
    }

    /// Under each pinned root, the replacement client activates after the
    /// older boot's HELLO took the owner's pending handshake, and after an
    /// undisturbed handshake, and its GET reads the resident version
    /// exactly; each run replays to an equal digest.
    #[test]
    fn a_client_activates_after_a_displaced_handshake_and_reads_exactly() {
        for name in [
            "q1-get-after-a-displaced-handshake",
            "q1-get-after-an-undisplaced-handshake",
        ] {
            for root in [3, 7_677_221_855_602_090_617, 10_289_227_118_843_548_305] {
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
        }
    }
}
