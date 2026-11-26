//! Second-copy histories: a replacement client opens while the link
//! delivers every frame of its handshake twice.
//!
//! Property: obligation record `q1-handshake-identity-safety`: "an
//! activation binds exactly the handshake it completes" and "a refused frame
//! changes no session state".
//!
//! Q2 realizes the schedule of the Q1 session model's reachability
//! witnesses `witnessStaleHello`, `witnessChallengeStale`,
//! `witnessConfirmStale` and `witnessReadyRepeat`, the `reach-` cases of
//! those names in `quint/check.py`: a replacement boot opens while the link
//! delivers a second copy of its HELLO, of the owner's CHALLENGE, of its
//! CONFIRM and of the READY. The ends refuse the second HELLO, CHALLENGE
//! and CONFIRM as stale, and the second READY repeats the active session.
//! The sibling runs the same opening with single copies.
//!
//! Each history judges that the owner and the replacement client hold one
//! session for the peer at the one epoch the opening issued, the epoch
//! after the older boot's, that the owner counted one displacement and the
//! client one activation, and that a GET under the session reads the
//! resident version exactly inside its one deadline. The premise is the
//! link's record of its rule decisions to duplicate the four frames, which
//! exists with and without a defect; a run whose rules duplicated fewer
//! frames ends unsuccessful under it, and so does a run whose ends share no
//! session once the client's opening fails or the history's wait ends.
//!
//! The judged step's check is shared by its control, which passes it one
//! planted observation: the shared session read one epoch past the issued
//! one, the epoch a second accepted HELLO would issue.

use super::super::super::client::SessionState;
use super::super::super::frame::Kind;
use super::super::super::rules::{Chain, Effect, MANIFEST, Rule, Selector};
use super::incidents::displace;
use super::*;

/// The link side of the replaced client and its replacement.
const CLIENT: usize = 0;

/// The link side of the owner.
const OWNER: usize = 1;

/// The four frames of one handshake and the link side each travels toward.
const FRAMES: [(Kind, usize); 4] = [
    (Kind::Hello, OWNER),
    (Kind::Challenge, CLIENT),
    (Kind::Confirm, OWNER),
    (Kind::Ready, CLIENT),
];

/// Second copies the two ends refuse as stale: the HELLO, the CHALLENGE and
/// the CONFIRM. The second READY repeats the active session and counts as
/// no refusal.
const REFUSED_COPIES: u64 = 3;

/// The rule for a session a second copy of a handshake frame moved; record
/// `q1-handshake-identity-safety`: "a refused frame changes no session
/// state".
pub(crate) const MOVED: &str = "the handshake's second copies moved its session";

/// The rule for the client's GET missing the resident version.
const MISSED: &str = "the replacement's GET missed the visible version";

const COPIES_ARMED: &str = "a second copy of each handshake frame armed";
const SINGLE: &str = "the handshake's frames stayed single";
const OPENED: &str = "a replacement client opened a session";
const COPIED: &str = "the link's rules duplicated each handshake frame";
const SHARED: &str = "the ends shared a session inside the history's wait";
const ONE_SESSION: &str = "the handshake left one session at its issued epoch";
const EXACT: &str = "the client read the resident version exactly after its one handshake";

/// Duplicates the next HELLO and CONFIRM toward the owner and the next
/// CHALLENGE and READY toward the client, and records the epoch of the
/// session the older boot holds.
fn duplicate_frames(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let rules: Vec<Rule> = FRAMES
        .iter()
        .map(|&(kind, toward)| {
            let frame = Selector::All(vec![Selector::Kind(kind), Selector::Toward(toward)]);
            Rule::new(frame, Effect::Duplicate).window(0, 1)
        })
        .collect();
    let taps = [rules.len()];
    let chain = Chain::new(rules, &taps, &MANIFEST).expect("a bounded chain");
    world.scene.nets[0].borrow_mut().set_rules(chain);
    world.history.old_epoch = world.scene.clients[0].session_epoch();
    mark(world, COPIES_ARMED)
}

/// The sibling's step: records the older boot's epoch and arms nothing.
fn single_frames(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.old_epoch = world.scene.clients[0].session_epoch();
    mark(world, SINGLE)
}

/// Opens the replacement boot and records the owner's stale and duplicate
/// refusals before it; the history's wait starts here.
fn open_replacement(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let owner = world.scene.owner.session_report();
    world.history.noted_drops = owner.stale + owner.duplicate;
    world.history.since = now;
    displace(world, now)
}

/// Whether the link's rule chain decided a second copy of each of the four
/// frames.
fn copied(world: &Mixed<'_, '_, '_>) -> bool {
    let net = world.scene.nets[0].borrow();
    FRAMES.iter().all(|&(kind, toward)| {
        net.rules().captures().iter().any(|capture| {
            capture.kind == Some(kind) && capture.toward == toward && capture.decision.duplicate
        })
    })
}

fn copied_or_late(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    copied(world) || now > world.history.since + BOUND_US
}

/// Marks the premise; a run whose rules duplicated fewer frames ends
/// unsuccessful under it.
fn mark_copied(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if !copied(world) {
        world.first.record(Failure::Unsuccessful(COPIED));
        return 0;
    }
    mark(world, COPIED)
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

/// Frames the two ends refused as stale or duplicate: the owner's count
/// over its life and the replacement client's since it opened.
fn refused_copies(world: &Mixed<'_, '_, '_>) -> u64 {
    let owner = world.scene.owner.session_report();
    let client = world.scene.clients[0].session_report();
    owner.stale + owner.duplicate + client.stale + client.duplicate
}

/// The client's opening ended, in an agreed session or failed, or the
/// history's wait passed.
fn opening_ended_or_late(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    agreed(world).is_some()
        || world.scene.clients[0].state() == SessionState::Failed
        || now > world.history.since + BOUND_US
}

/// The ends agreed on a session and refused at least [`REFUSED_COPIES`]
/// more frames as stale or duplicate than the owner had before the opening,
/// or the client's opening failed, or the history's wait passed.
fn copies_handled_or_late(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    (agreed(world).is_some() && refused_copies(world) >= world.history.noted_drops + REFUSED_COPIES)
        || world.scene.clients[0].state() == SessionState::Failed
        || now > world.history.since + BOUND_US
}

/// The epoch the two ends share, the owner's displacements since the
/// opening and the client's activations.
fn session_counts(world: &Mixed<'_, '_, '_>) -> (Option<u64>, u64, u64) {
    let displaced = world.scene.owner.session_report().displacements - world.history.displacements;
    let activations = world.scene.clients[0].session_report().activations;
    (agreed(world), displaced, activations)
}

fn one_session(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let (session, displaced, activations) = session_counts(world);
    judge_one(world, session, displaced, activations)
}

/// A control: the shared session reads one epoch past the issued one, the
/// epoch a second accepted HELLO would issue.
fn session_moved(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let (session, displaced, activations) = session_counts(world);
    judge_one(
        world,
        session.map(|epoch| epoch + 1),
        displaced,
        activations,
    )
}

/// Judges the handshake's end: `session` is the epoch both ends hold, which
/// must be the one epoch after the older boot's, with one displacement at
/// the owner and one activation at the client. Ends that share no session
/// leave the history unsuccessful.
fn judge_one(
    world: &mut Mixed<'_, '_, '_>,
    session: Option<u64>,
    displaced: u64,
    activations: u64,
) -> u64 {
    let Some(session) = session else {
        world.first.record(Failure::Unsuccessful(SHARED));
        return 0;
    };
    let issued = world.history.old_epoch.map(|epoch| epoch + 1);
    if Some(session) != issued || displaced != 1 || activations != 1 {
        return fail(world, Obligation::Contain, MOVED);
    }
    mark(world, ONE_SESSION)
}

fn session_get(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
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

/// The client's GET under the one session reads the resident version
/// exactly.
fn get_exact(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = *world.history.ids.last().expect("the client's GET");
    let bytes = drain(&mut world.scene.clients[0], id);
    let outcome = world.collect_get(0, id);
    let _ = world.scene.clients[0].retire(id);
    if outcome != Some(Outcome::Complete) || bytes != version_a() {
        return fail(world, Obligation::Bytes, MISSED);
    }
    mark(world, EXACT);
    mark(world, "qualified exact read")
}

/// The obligation each second-copy check's mark judges.
pub(super) const CHECKS: [(&str, Obligation); 2] = [
    (ONE_SESSION, Obligation::Contain),
    (EXACT, Obligation::Bytes),
];

/// What follows the handshake's end in both histories.
const AFTER: [Step; 3] = [
    step("session-get", active_put, session_get),
    step("session-read", get_decided, get_exact),
    JUDGE,
];

/// Q2: the link delivers a second copy of every frame of the handshake.
const Q2_GET: [Step; 7] = joined(
    [
        step("duplicate-frames", active_put, duplicate_frames),
        step("replace", always, open_replacement),
        step("copies-delivered", copied_or_late, mark_copied),
        step("one-session", copies_handled_or_late, one_session),
    ],
    AFTER,
);

/// The sibling: the same opening with single copies.
const Q2_GET_SINGLE: [Step; 6] = joined(
    [
        step("single-frames", active_put, single_frames),
        step("replace", always, open_replacement),
        step("one-session", opening_ended_or_late, one_session),
    ],
    AFTER,
);

const Q2_GET_MOVED: [Step; 7] = replaced(
    Q2_GET,
    "one-session",
    step("session-moved", copies_handled_or_late, session_moved),
);

const Q2_WITNESSES: &[&str] = &[
    COPIES_ARMED,
    OPENED,
    COPIED,
    ONE_SESSION,
    EXACT,
    "qualified exact read",
];

const Q2_SINGLE_WITNESSES: &[&str] = &[SINGLE, OPENED, ONE_SESSION, EXACT, "qualified exact read"];

const Q2_PREMISE: &[&str] = &[COPIES_ARMED, OPENED, COPIED];

const Q2: &[Obligation] = &[Obligation::Contain, Obligation::Bytes];

pub(super) const COPIES: [History; 3] = [
    history(
        "q2-get-after-a-duplicated-handshake",
        &Q2_GET,
        Q2_WITNESSES,
        Q2,
        Expect::Pass,
    ),
    history(
        "q2-get-after-a-single-handshake",
        &Q2_GET_SINGLE,
        Q2_SINGLE_WITNESSES,
        Q2,
        Expect::Pass,
    ),
    control(
        history(
            "q2-duplicate-moved-the-session",
            &Q2_GET_MOVED,
            Q2_WITNESSES,
            Q2,
            Expect::Violation(Obligation::Contain, MOVED),
        ),
        Q2_PREMISE,
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
    use super::{COPIES, MOVED};

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
    fn every_second_copy_history_ends_as_declared_and_replays_equal() {
        for history in &COPIES {
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
    fn every_passing_second_copy_history_activates_the_obligations_it_declares() {
        for history in COPIES.iter().filter(|h| h.expect == Expect::Pass) {
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
    fn every_second_copy_control_fails_through_its_named_check() {
        let killed = [("q2-duplicate-moved-the-session", Obligation::Contain, MOVED)];
        for (name, obligation, rule) in killed {
            let declared = COPIES.iter().find(|h| h.name == name).expect(name);
            assert_eq!(
                declared.expect,
                Expect::Violation(obligation, rule),
                "{name}"
            );
            assert!(!declared.premise.is_empty(), "{name} declares its premise");
            let (terminal, violation, _) = ran_at(name, 5);
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
        let controls = COPIES.iter().filter(|h| h.expect != Expect::Pass).count();
        assert_eq!(controls, killed.len());
    }

    /// Under each pinned root, a handshake whose every frame the link
    /// delivers twice, and one with single copies, leaves one session at
    /// the epoch it issued, and the client's GET reads the resident version
    /// exactly; each run replays to an equal digest.
    #[test]
    fn a_handshake_delivered_twice_leaves_one_session_and_reads_exactly() {
        for name in [
            "q2-get-after-a-duplicated-handshake",
            "q2-get-after-a-single-handshake",
        ] {
            for root in [5, 7_677_221_855_602_090_617, 10_289_227_118_843_548_305] {
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
