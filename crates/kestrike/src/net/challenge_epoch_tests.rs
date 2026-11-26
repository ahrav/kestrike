//! The epoch each CHALLENGE of an owner takes.
//!
//! The owner's pending epoch advances by one per CHALLENGE with checked
//! arithmetic, so every epoch is at least 1 and each peer's epochs are
//! distinct within one owner boot.
//!
//! Each test drives an owner's `Sessions` table for one peer with
//! authenticated bootstrap frames a client would send, written by hand so a
//! CONFIRM can name any CHALLENGE the owner issued. The expected epoch is the
//! test's own count of the HELLOs the owner accepted, starting at 1. HELLOs
//! arrive in a row with no CONFIRM between them, under one client boot nonce
//! and under two, before an activation and after one. A CONFIRM that names a
//! CHALLENGE a later HELLO replaced, with that CHALLENGE's epoch, nonces and
//! caps, must be refused `Mismatch` and leave the active session as it was;
//! the CONFIRM of the latest CHALLENGE must activate that CHALLENGE's epoch.

use super::auth::{Authenticated, KeyRing};
use super::auth_tests::{CAPS, OWNER_NONCE, delivered, rings, sessions};
use super::datagram::PeerId;
use super::frame::Kind;
use super::session::{
    Activation, Bootstrap, Replaced, Role, SessionReject, SessionReport, Sessions,
};

/// Two boot nonces of the one client.
const BOOT_A: [u8; 16] = [0x0C; 16];
const BOOT_B: [u8; 16] = [0x0D; 16];
const PEER: PeerId = PeerId(0);

/// An owner's session table for one client, the two ends' key rings, and
/// the test's own count of the HELLOs the owner accepted.
struct Owner {
    sessions: Sessions,
    rings: (KeyRing, KeyRing),
    accepted: u64,
}

impl Owner {
    fn new() -> Self {
        Self {
            sessions: sessions(Role::Owner, OWNER_NONCE, 1),
            rings: rings(),
            accepted: 0,
        }
    }

    /// Encodes and tags `step` as the client sends it, then parses and
    /// authenticates the datagram as the owner receives it, and hands the
    /// authenticated frame with the table to `handle`.
    fn deliver<T>(
        &mut self,
        step: &Bootstrap,
        handle: impl FnOnce(&mut Sessions, &Authenticated<'_, '_>) -> T,
    ) -> T {
        delivered(&self.rings, step, |frame| handle(&mut self.sessions, frame))
    }

    /// Delivers a HELLO under client boot `nonce` at bootstrap `sequence`,
    /// which the owner must accept, and returns its CHALLENGE with the epoch
    /// the test expects of it: the count of HELLOs the owner has accepted.
    fn hello(&mut self, nonce: [u8; 16], sequence: u64) -> (Bootstrap, u64) {
        let hello = Bootstrap {
            tenure: None,
            peer: PEER,
            kind: Kind::Hello,
            owner_nonce: [0; 16],
            client_nonce: nonce,
            epoch: 0,
            caps: CAPS,
            sequence,
        };
        let challenge = self
            .deliver(&hello, |sessions, frame| sessions.on_hello(frame))
            .expect("the owner accepts a HELLO above its nonce's floor");
        self.accepted += 1;
        (challenge, self.accepted)
    }

    /// Delivers the CONFIRM a client sends for `challenge` at bootstrap
    /// `sequence`: the CHALLENGE's epoch, both its nonces and its caps.
    fn confirm(
        &mut self,
        challenge: &Bootstrap,
        sequence: u64,
    ) -> Result<Activation, SessionReject> {
        let confirm = Bootstrap {
            kind: Kind::Confirm,
            sequence,
            ..*challenge
        };
        self.deliver(&confirm, |sessions, frame| sessions.on_confirm(frame))
    }

    /// The active session's epoch and the table's counts of activations and
    /// mismatched frames.
    fn state(&self) -> (Option<u64>, u64, u64) {
        let SessionReport {
            activations,
            mismatched,
            ..
        } = self.sessions.report();
        (
            self.sessions.active(PEER).map(|session| session.epoch),
            activations,
            mismatched,
        )
    }
}

/// The CHALLENGE the owner must answer the test's `expected`-th accepted
/// HELLO with, sent under client boot `nonce` at bootstrap `sequence`.
fn challenge_of(expected: u64, nonce: [u8; 16], sequence: u64) -> Bootstrap {
    Bootstrap {
        tenure: None,
        peer: PEER,
        kind: Kind::Challenge,
        owner_nonce: OWNER_NONCE,
        client_nonce: nonce,
        epoch: expected,
        caps: CAPS,
        sequence,
    }
}

/// The READY that answers the CONFIRM of `challenge` at bootstrap `sequence`.
fn ready_of(challenge: &Bootstrap, sequence: u64) -> Bootstrap {
    Bootstrap {
        kind: Kind::Ready,
        sequence,
        ..*challenge
    }
}

/// Three HELLOs under one client boot nonce, with no CONFIRM between them,
/// draw CHALLENGEs of epochs 1, 2 and 3. A CONFIRM for the first or the
/// second CHALLENGE, each replaced by a later HELLO, is refused `Mismatch`
/// and activates nothing; the CONFIRM for the third activates epoch 3.
#[test]
fn hellos_in_a_row_under_one_nonce_take_epochs_one_two_three_and_only_the_last_confirms() {
    let mut owner = Owner::new();
    let challenges: Vec<(Bootstrap, u64)> = (1..=3)
        .map(|sequence| owner.hello(BOOT_A, sequence))
        .collect();
    for (at, (challenge, expected)) in challenges.iter().enumerate() {
        let sequence = at as u64 + 1;
        assert_eq!(*expected, sequence, "the test counts each accepted HELLO");
        assert_eq!(
            *challenge,
            challenge_of(*expected, BOOT_A, sequence),
            "CHALLENGE {sequence} carries the epoch one above the CHALLENGE before it, from 1"
        );
    }
    assert_eq!(owner.state(), (None, 0, 0), "a HELLO activates nothing");

    let replaced = [
        owner.confirm(&challenges[0].0, 4),
        owner.confirm(&challenges[1].0, 5),
    ];
    let after_replaced = owner.state();
    let latest = owner.confirm(&challenges[2].0, 6);
    assert_eq!(
        replaced,
        [Err(SessionReject::Mismatch); 2],
        "a CONFIRM answering a replaced CHALLENGE matches nothing"
    );
    assert_eq!(
        after_replaced,
        (None, 0, 2),
        "the two refused CONFIRMs activated nothing and were counted"
    );
    assert_eq!(
        latest,
        Ok(Activation {
            ready: ready_of(&challenge_of(3, BOOT_A, 3), 6),
            replaced: None,
        }),
        "the CONFIRM of the latest CHALLENGE activates its epoch"
    );
    assert_eq!(owner.state(), (Some(3), 1, 2));
}

/// HELLOs that alternate between two client boot nonces, with no CONFIRM
/// between them, still draw one epoch each from the peer's one counter: 1 to
/// 4. A CONFIRM for a replaced CHALLENGE of either nonce is refused
/// `Mismatch`, and the CONFIRM for the fourth activates epoch 4.
#[test]
fn hellos_in_a_row_under_two_nonces_take_consecutive_epochs_from_one_counter() {
    let mut owner = Owner::new();
    let sent = [(BOOT_A, 1), (BOOT_B, 1), (BOOT_A, 2), (BOOT_B, 2)];
    let challenges = sent.map(|(nonce, sequence)| owner.hello(nonce, sequence));
    for (at, ((nonce, sequence), (challenge, expected))) in sent.iter().zip(&challenges).enumerate()
    {
        assert_eq!(*expected, at as u64 + 1);
        assert_eq!(
            *challenge,
            challenge_of(*expected, *nonce, *sequence),
            "CHALLENGE {} carries the epoch one above the CHALLENGE before it, from 1",
            at + 1
        );
    }

    let replaced = [
        owner.confirm(&challenges[0].0, 3),
        owner.confirm(&challenges[1].0, 3),
        owner.confirm(&challenges[2].0, 3),
    ];
    let after_replaced = owner.state();
    let latest = owner.confirm(&challenges[3].0, 3);
    assert_eq!(
        replaced,
        [Err(SessionReject::Mismatch); 3],
        "a CONFIRM answering a replaced CHALLENGE matches nothing"
    );
    assert_eq!(after_replaced, (None, 0, 3));
    assert_eq!(
        latest,
        Ok(Activation {
            ready: ready_of(&challenge_of(4, BOOT_B, 2), 3),
            replaced: None,
        }),
        "the CONFIRM of the latest CHALLENGE activates its epoch"
    );
    assert_eq!(owner.state(), (Some(4), 1, 3));
}

/// After an activation the counter goes on from the last CHALLENGE, not from
/// the active session: with epoch 1 active, two HELLOs in a row under the
/// same boot nonce draw epochs 2 and 3 and leave epoch 1 active; the CONFIRM
/// for epoch 2 is refused and epoch 1 stays active; the CONFIRM for epoch 3
/// replaces epoch 1 without a displacement. Two HELLOs in a row under the
/// other boot nonce then draw epochs 4 and 5; the CONFIRM for epoch 4 is
/// refused, and the CONFIRM for epoch 5 displaces epoch 3.
#[test]
fn hellos_in_a_row_after_an_activation_take_the_next_epochs_and_keep_the_active_session() {
    let mut owner = Owner::new();
    let (first, expected) = owner.hello(BOOT_A, 1);
    assert_eq!((first, expected), (challenge_of(1, BOOT_A, 1), 1));
    assert_eq!(
        owner.confirm(&first, 2),
        Ok(Activation {
            ready: ready_of(&first, 2),
            replaced: None,
        })
    );
    assert_eq!(owner.state(), (Some(1), 1, 0));

    let same = [owner.hello(BOOT_A, 3), owner.hello(BOOT_A, 4)];
    assert_eq!(
        same,
        [
            (challenge_of(2, BOOT_A, 3), 2),
            (challenge_of(3, BOOT_A, 4), 3)
        ],
        "each CHALLENGE after the activation carries the epoch one above the CHALLENGE before it"
    );
    assert_eq!(
        owner.state(),
        (Some(1), 1, 0),
        "a HELLO preserves the active session"
    );
    let (replaced, after_replaced) = (owner.confirm(&same[0].0, 5), owner.state());
    let latest = owner.confirm(&same[1].0, 6);
    assert_eq!(
        (replaced, after_replaced),
        (Err(SessionReject::Mismatch), (Some(1), 1, 1)),
        "a CONFIRM answering a replaced CHALLENGE matches nothing and epoch 1 stays active"
    );
    assert_eq!(
        latest,
        Ok(Activation {
            ready: ready_of(&same[1].0, 6),
            replaced: Some(Replaced {
                epoch: 1,
                displaced: false,
            }),
        })
    );
    assert_eq!(owner.state(), (Some(3), 2, 1));

    let other = [owner.hello(BOOT_B, 1), owner.hello(BOOT_B, 2)];
    assert_eq!(
        other,
        [
            (challenge_of(4, BOOT_B, 1), 4),
            (challenge_of(5, BOOT_B, 2), 5)
        ],
        "a HELLO under another boot nonce draws from the same counter"
    );
    let (replaced, after_replaced) = (owner.confirm(&other[0].0, 3), owner.state());
    let latest = owner.confirm(&other[1].0, 4);
    assert_eq!(
        (replaced, after_replaced),
        (Err(SessionReject::Mismatch), (Some(3), 2, 2)),
        "a CONFIRM answering a replaced CHALLENGE matches nothing and epoch 3 stays active"
    );
    assert_eq!(
        latest,
        Ok(Activation {
            ready: ready_of(&other[1].0, 4),
            replaced: Some(Replaced {
                epoch: 3,
                displaced: true,
            }),
        })
    );
    assert_eq!(owner.state(), (Some(5), 3, 2));
}
