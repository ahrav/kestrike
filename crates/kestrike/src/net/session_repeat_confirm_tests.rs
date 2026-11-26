//! An owner answers a CONFIRM by activating the matching pending handshake, or by repeating
//! the READY of the active one; READY echoes the CONFIRM's bootstrap sequence; a sequence at or below its
//! nonce's floor is `Stale`.
//!
//! Both tests bootstrap one client against an owner `Sessions` table as net/auth_tests.rs does, with the
//! owner's READY lost, so the client still holds its pending handshake and repeats its CONFIRM through
//! `Sessions::confirm`. Before the repeat the owner admits one session frame and takes two send sequences.
//!
//! - `a_repeated_confirm_of_the_active_session_repeats_ready_and_changes_nothing`: the repeat, at a bootstrap
//!   sequence above the floor, returns a READY of the same epoch that echoes the repeat's sequence, replaces
//!   nothing, counts no activation and no displacement, leaves the send sequence where it was and the replay
//!   window as it was (the admitted frame is still `Duplicate`); the same repeat delivered again is `Stale`.
//! - `a_confirm_of_the_active_session_at_or_below_its_floor_is_stale`: the activating CONFIRM delivered
//!   again, at the floor, and a CONFIRM one sequence below it are `Stale`, and the session stays as it was.

use super::auth::KeyRing;
use super::auth_tests::{
    CLIENT_NONCE, OWNER_NONCE, authenticate, delivered, get, parsed, rings, sealed, sessions,
};
use super::datagram::PeerId;
use super::frame::{Direction, Kind};
use super::session::{Activation, Bootstrap, Role, SessionReject, SessionReport, Sessions};

const PEER: PeerId = PeerId(0);

/// The owner's answer to the client's CONFIRM `step`.
fn confirmed(
    owner: &mut Sessions,
    rings: &(KeyRing, KeyRing),
    step: &Bootstrap,
) -> Result<Activation, SessionReject> {
    delivered(rings, step, |frame| owner.on_confirm(frame))
}

/// A session frame of the client: a GET in session `epoch` at session sequence `sequence`.
fn session_frame(rings: &(KeyRing, KeyRing), epoch: u64, sequence: u64) -> Vec<u8> {
    let get = get(epoch, sequence, CLIENT_NONCE);
    sealed(&rings.1, PEER, &get, &[], Direction::ClientToOwner)
}

fn admitted(
    owner: &mut Sessions,
    rings: &(KeyRing, KeyRing),
    datagram: &[u8],
) -> Result<u64, SessionReject> {
    let frame = parsed(datagram);
    let frame =
        authenticate(&rings.0, &frame, PEER, Direction::ClientToOwner).expect("an authentic frame");
    owner.admit(&frame).map(|session| session.epoch)
}

/// An owner with an active session that admitted one session frame and took send sequences 1 and 2, the
/// client that still holds the handshake pending because the owner's READY was lost, the CONFIRM that
/// activated the session, the admitted frame's datagram and the owner's report at that point.
struct Scene {
    owner: Sessions,
    client: Sessions,
    rings: (KeyRing, KeyRing),
    confirm: Bootstrap,
    epoch: u64,
    frame: Vec<u8>,
    report: SessionReport,
}

fn scene() -> Scene {
    let rings = rings();
    let mut owner = sessions(Role::Owner, OWNER_NONCE, 1);
    let mut client = sessions(Role::Client, CLIENT_NONCE, 1);
    let hello = client.hello(PEER).expect("a HELLO");
    let challenge = delivered(&rings, &hello, |frame| owner.on_hello(frame)).expect("a CHALLENGE");
    let confirm =
        delivered(&rings, &challenge, |frame| client.on_challenge(frame)).expect("a CONFIRM");
    let activation = confirmed(&mut owner, &rings, &confirm).expect("an activation");
    let epoch = activation.ready.epoch;
    let frame = session_frame(&rings, epoch, 1);
    assert_eq!(
        admitted(&mut owner, &rings, &frame),
        Ok(epoch),
        "the session frame is admitted"
    );
    assert_eq!(
        (owner.next_sequence(PEER), owner.next_sequence(PEER)),
        (Ok(1), Ok(2)),
        "the owner took send sequences 1 and 2"
    );
    let report = owner.report();
    assert_eq!(report.activations, 1, "the handshake activated once");
    Scene {
        owner,
        client,
        rings,
        confirm,
        epoch,
        frame,
        report,
    }
}

/// What the owner's session shows after an answer: its activation and displacement counts, the epoch of
/// its active session, the next send sequence, and what a second delivery of the admitted frame returns.
type Observed = (
    (u64, u64),
    Option<u64>,
    Result<u64, SessionReject>,
    Result<u64, SessionReject>,
);

/// Reads [`Observed`] from the owner's session.
fn observed(scene: &mut Scene) -> Observed {
    let report = scene.owner.report();
    (
        (report.activations, report.displacements),
        scene.owner.active(PEER).map(|session| session.epoch),
        scene.owner.next_sequence(PEER),
        admitted(&mut scene.owner, &scene.rings, &scene.frame),
    )
}

#[test]
fn a_repeated_confirm_of_the_active_session_repeats_ready_and_changes_nothing() {
    let mut scene = scene();
    let repeat = scene
        .client
        .confirm(PEER)
        .expect("the client repeats its CONFIRM");
    let above = repeat.sequence > scene.confirm.sequence
        && repeat.epoch == scene.epoch
        && repeat.kind == Kind::Confirm;
    let answer = confirmed(&mut scene.owner, &scene.rings, &repeat);
    let ready = answer.map(|activation| {
        (
            activation.ready.kind,
            activation.ready.epoch,
            activation.ready.sequence,
            activation.replaced,
        )
    });
    let after = observed(&mut scene);
    let again =
        confirmed(&mut scene.owner, &scene.rings, &repeat).map(|activation| activation.ready.epoch);
    assert!(
        above,
        "the repeat names the active session above its nonce's floor"
    );
    assert_eq!(
        ready,
        Ok((Kind::Ready, scene.epoch, repeat.sequence, None)),
        "the owner repeats the READY of the active session, echoing the CONFIRM's sequence"
    );
    assert_eq!(
        after,
        (
            (scene.report.activations, scene.report.displacements),
            Some(scene.epoch),
            Ok(3),
            Err(SessionReject::Duplicate),
        ),
        "a repeated READY leaves the session as it is"
    );
    assert_eq!(
        again,
        Err(SessionReject::Stale),
        "the same CONFIRM a second time is at its nonce's floor"
    );
}

#[test]
fn a_confirm_of_the_active_session_at_or_below_its_floor_is_stale() {
    let mut scene = scene();
    let at_floor = scene.confirm;
    let below = Bootstrap {
        sequence: scene.confirm.sequence - 1,
        ..scene.confirm
    };
    let answers = [at_floor, below].map(|step| {
        confirmed(&mut scene.owner, &scene.rings, &step).map(|activation| activation.ready.epoch)
    });
    let stale = scene.owner.report().stale - scene.report.stale;
    let after = observed(&mut scene);
    assert!(
        below.sequence > 0,
        "the CONFIRM below the floor keeps a nonzero sequence"
    );
    assert_eq!(
        answers,
        [Err(SessionReject::Stale), Err(SessionReject::Stale)],
        "a CONFIRM at or below its nonce's floor is Stale"
    );
    assert_eq!(stale, 2, "each stale CONFIRM is counted");
    assert_eq!(
        after,
        (
            (scene.report.activations, scene.report.displacements),
            Some(scene.epoch),
            Ok(3),
            Err(SessionReject::Duplicate),
        ),
        "a stale CONFIRM leaves the session as it is"
    );
}
