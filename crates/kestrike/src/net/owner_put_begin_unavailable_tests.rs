//! BEGIN runs session admission, then the owner's admission state (a lost volume or a prior
//! poison answers `OwnerUnavailable`), then PUT permission, the PUT population cap and the peer's PUT share,
//! and only after the namespace preflight does it begin a fill.
//!
//! Every test runs the same steps on an owner that grants PUT to both peers: peer 1 begins a PUT and sends its
//! PREPARE, then peer 0 and peer 1 each send a fresh BEGIN on a wire identity the owner has not seen.
//!
//! - Lost volume: the device refuses the PREPARE's header write as gone. The owner stays open and unpoisoned.
//! - Unwound turn: the PREPARE's reservation unwinds the owner's turn, which the test catches; the owner
//!   reports `poisoned()` and the volume is untouched.
//! - Controls: the same steps with no fault. Peer 0's fresh BEGIN is granted.
//!
//! Under a fault each fresh BEGIN must draw exactly one PUT ERROR `OwnerUnavailable` and no PUT AUTHORITY,
//! leave the census's live count where it was and leave `put_report().begun` at the one BEGIN the setup made.
//! Peer 1 still holds its unwound PUT in the second case, so its refusal also shows that the admission state
//! answers before the peer's PUT share does.
//!
//! Each run records what it saw into a value; the assertions run after the scene and its fixtures are gone.

use crate::storage::owner_fixture::INTERPOSE_BEFORE_REVALIDATION;
use crate::storage::{RefusalReason, SubmitRefusal};

use super::frame::{Kind, Status};
use super::owner_tests::PRINCIPALS;
use super::put_tests::{Scene, error, prepare, request, scene};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    LostVolume,
    UnwoundTurn,
}

/// A PUT reply as the tests read it: its kind and, for a PUT ERROR, its status.
type Reply = (Kind, Option<Status>);

/// What one fresh BEGIN drew and left behind.
#[derive(Debug, PartialEq, Eq)]
struct Fresh {
    peer: usize,
    replies: Vec<Reply>,
    live: u32,
    begun: u64,
}

#[derive(Debug)]
struct Observed {
    /// The replies peer 1 drew for the PREPARE that carries the fault; empty when the turn unwound.
    prepared: Vec<Reply>,
    /// Whether the turns that took the PREPARE unwound.
    unwound: bool,
    poisoned: bool,
    /// Live requests and granted BEGINs after the fault and before the fresh BEGINs.
    live: u32,
    begun: u64,
    fresh: Vec<Fresh>,
}

fn replies(scene: &mut Scene<'_, '_>, peer: usize) -> Vec<Reply> {
    scene
        .replies(peer)
        .iter()
        .map(|header| (header.kind, error(header)))
        .collect()
}

/// Peer 1 begins a PUT of key 5 and sends a PREPARE of `body_len` bytes under `fault`; then each of
/// `peers` sends a fresh BEGIN of key 6 at a request the owner has not seen.
fn run(fault: Fault, body_len: u32, peers: &[usize]) -> Observed {
    let mut observed = None;
    scene(&PRINCIPALS, |mut scene| {
        let at = request(1, 1);
        let serial = scene.begin(1, at, 5);
        let header = scene.frame(
            1,
            Kind::PutPrepare,
            at,
            5,
            prepare(serial, body_len, 60_000),
        );
        match fault {
            Fault::None => {}
            Fault::LostVolume => scene.control.refuse_next(SubmitRefusal {
                reason: RefusalReason::DeviceGone,
                code: None,
            }),
            Fault::UnwoundTurn => INTERPOSE_BEFORE_REVALIDATION.with(|hook| {
                hook.set(Some(|_| {
                    std::panic::resume_unwind(Box::new("the reservation unwound"))
                }));
            }),
        }
        scene.inject(1, &header);
        let unwound =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| scene.turns(4))).is_err();
        INTERPOSE_BEFORE_REVALIDATION.with(|hook| hook.set(None));
        let prepared = replies(&mut scene, 1);
        let poisoned = scene.owner.poisoned();
        let (live, begun) = (scene.live(), scene.owner.put_report().begun);
        let fresh = peers
            .iter()
            .map(|&peer| {
                let begin = scene.frame(peer, Kind::PutBegin, request(2, 1), 6, |_| {});
                scene.inject(peer, &begin);
                scene.turns(4);
                Fresh {
                    peer,
                    replies: replies(&mut scene, peer),
                    live: scene.live(),
                    begun: scene.owner.put_report().begun,
                }
            })
            .collect();
        observed = Some(Observed {
            prepared,
            unwound,
            poisoned,
            live,
            begun,
            fresh,
        });
    });
    observed.expect("the scene ran its body")
}

/// The refusal the admission state gives `peer`: one PUT ERROR `OwnerUnavailable`, with the live requests and the
/// granted BEGINs as the fault left them.
fn refused(peer: usize, live: u32) -> Fresh {
    Fresh {
        peer,
        replies: vec![(Kind::PutError, Some(Status::OwnerUnavailable))],
        live,
        begun: 1,
    }
}

#[test]
fn a_begin_at_an_open_owner_whose_volume_is_lost_is_refused_owner_unavailable() {
    let observed = run(Fault::LostVolume, 0, &[0, 1]);
    assert_eq!(
        (&observed.prepared[..], observed.unwound, observed.poisoned),
        (
            &[(Kind::PutError, Some(Status::OwnerUnavailable))][..],
            false,
            false
        ),
        "premise: the PREPARE's header write lost the volume and no turn unwound: {observed:?}"
    );
    assert_eq!(
        (observed.live, observed.begun),
        (0, 1),
        "premise: the lost volume ended the one PUT the setup began: {observed:?}"
    );
    assert_eq!(
        observed.fresh,
        [refused(0, 0), refused(1, 0)],
        "a BEGIN at an owner whose volume is lost draws OwnerUnavailable and grants nothing"
    );
}

#[test]
fn a_begin_at_an_owner_whose_earlier_turn_unwound_is_refused_owner_unavailable() {
    let observed = run(Fault::UnwoundTurn, 100, &[0, 1]);
    assert_eq!(
        (&observed.prepared[..], observed.unwound, observed.poisoned),
        (&[][..], true, true),
        "premise: the PREPARE's reservation unwound its turn and poisoned the owner: {observed:?}"
    );
    assert_eq!(
        (observed.live, observed.begun),
        (1, 1),
        "premise: the unwound PUT's record outlives the unwind: {observed:?}"
    );
    assert_eq!(
        observed.fresh,
        [refused(0, 1), refused(1, 1)],
        "a BEGIN at an owner whose earlier turn unwound draws OwnerUnavailable and grants nothing"
    );
}

/// The controls: the same steps with no fault, an empty PREPARE as in the lost-volume test and a 100-byte
/// one as in the unwound-turn test. Peer 0's fresh BEGIN is granted and counted.
#[test]
fn the_same_begin_at_a_healthy_owner_is_granted() {
    for body_len in [0, 100] {
        let observed = run(Fault::None, body_len, &[0]);
        assert_eq!(
            (observed.unwound, observed.poisoned, observed.begun),
            (false, false, 1),
            "premise: no turn unwound and the setup's BEGIN is the one granted: {observed:?}"
        );
        assert!(
            observed
                .prepared
                .iter()
                .all(|&(kind, _)| kind != Kind::PutError),
            "premise: the PREPARE of {body_len} bytes was not refused: {observed:?}"
        );
        assert_eq!(
            observed.fresh,
            [Fresh {
                peer: 0,
                replies: vec![(Kind::PutAuthority, None)],
                live: observed.live + 1,
                begun: 2,
            }],
            "a BEGIN at a healthy owner is granted PUT AUTHORITY and counted: {observed:?}"
        );
    }
}
