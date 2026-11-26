//! On an owner, a client bootstrap sequence is checked against the floor of its boot nonce and
//! raises that floor. Sequence 0 is always stale. A nonce other than the active one and the most recent other one
//! starts a new floor at its sequence and passes.
//!
//! The tests deliver authenticated HELLOs and CONFIRMs to one owner `Sessions` table under two client boot
//! nonces, at rising, repeated, lower and zero bootstrap sequences. `Model` keeps, apart from the code, the highest
//! sequence each nonce passed, the epochs issued, and the pending and active handshakes; every verdict, the stale
//! count and the owner's state after every step are compared with it. No step displaces a nonce.

use std::collections::BTreeMap;

use super::auth::KeyRing;
use super::auth_tests::{CAPS, OWNER_NONCE, delivered, rings, sessions};
use super::datagram::PeerId;
use super::frame::Kind;
use super::session::{Bootstrap, Role, SessionReject, Sessions};

const NONCE_A: [u8; 16] = [0x0C; 16];
const NONCE_B: [u8; 16] = [0x0D; 16];
const PEER: PeerId = PeerId(0);

/// One bootstrap frame a client sends: a HELLO, or a CONFIRM naming the session of `epoch`.
#[derive(Debug, Clone, Copy)]
enum Sent {
    Hello {
        nonce: [u8; 16],
        sequence: u64,
    },
    Confirm {
        nonce: [u8; 16],
        epoch: u64,
        sequence: u64,
    },
}

impl Sent {
    fn step(self) -> Bootstrap {
        let (kind, owner_nonce, client_nonce, epoch, sequence) = match self {
            Sent::Hello { nonce, sequence } => (Kind::Hello, [0; 16], nonce, 0, sequence),
            Sent::Confirm {
                nonce,
                epoch,
                sequence,
            } => (Kind::Confirm, OWNER_NONCE, nonce, epoch, sequence),
        };
        Bootstrap {
            tenure: None,
            peer: PEER,
            kind,
            owner_nonce,
            client_nonce,
            epoch,
            caps: CAPS,
            sequence,
        }
    }
}

/// Delivers `sent` to the owner as an authenticated frame and returns the epoch and the echoed bootstrap sequence
/// of the CHALLENGE or READY it answers with, or its refusal.
fn deliver(
    owner: &mut Sessions,
    rings: &(KeyRing, KeyRing),
    sent: Sent,
) -> Result<(u64, u64), SessionReject> {
    delivered(rings, &sent.step(), |frame| match sent {
        Sent::Hello { .. } => owner
            .on_hello(frame)
            .map(|reply| (reply.epoch, reply.sequence)),
        Sent::Confirm { .. } => owner
            .on_confirm(frame)
            .map(|answer| (answer.ready.epoch, answer.ready.sequence)),
    })
}

/// What the property and the handshake rules predict, kept apart from the code under test.
#[derive(Default)]
struct Model {
    /// The highest bootstrap sequence each client boot nonce passed.
    highest: BTreeMap<[u8; 16], u64>,
    /// Epochs issued: one for each HELLO that passed.
    issued: u64,
    pending: Option<(u64, [u8; 16])>,
    active: Option<(u64, [u8; 16])>,
    stale: u64,
}

impl Model {
    /// The answer the owner owes `sent`: the epoch and echoed sequence, or `Stale`.
    fn answer(&mut self, sent: Sent) -> Result<(u64, u64), SessionReject> {
        let (nonce, sequence) = match sent {
            Sent::Hello { nonce, sequence }
            | Sent::Confirm {
                nonce, sequence, ..
            } => (nonce, sequence),
        };
        // Sequence 0 is stale, and so is a sequence at or below the highest its nonce passed.
        let passes = sequence != 0 && self.highest.get(&nonce).is_none_or(|&top| sequence > top);
        if !passes {
            self.stale += 1;
            return Err(SessionReject::Stale);
        }
        self.highest.insert(nonce, sequence);
        match sent {
            Sent::Hello { .. } => {
                self.issued += 1;
                self.pending = Some((self.issued, nonce));
                Ok((self.issued, sequence))
            }
            Sent::Confirm { epoch, .. } => {
                if self.pending == Some((epoch, nonce)) {
                    self.active = self.pending.take();
                }
                Ok((epoch, sequence))
            }
        }
    }
}

/// Runs `script` against a fresh owner and returns every disagreement with the model, and the stale count the
/// model ends with.
fn disagreements(script: &[Sent]) -> (Vec<String>, u64) {
    let rings = rings();
    let mut owner = sessions(Role::Owner, OWNER_NONCE, 1);
    let mut model = Model::default();
    let mut found = Vec::new();
    for (at, &sent) in script.iter().enumerate() {
        let expected = model.answer(sent);
        let got = deliver(&mut owner, &rings, sent);
        if got != expected {
            found.push(format!(
                "step {at} {sent:?}: answered {got:?}, the floor rule gives {expected:?}"
            ));
        }
        let stale = owner.report().stale;
        if stale != model.stale {
            found.push(format!(
                "step {at} {sent:?}: {stale} stale counted, expected {}",
                model.stale
            ));
        }
        // A stale frame leaves the pending handshake, the active session and the epoch counter as they were; a
        // passing one moves them as the model did.
        let view = owner.view(PEER);
        let state = (view.pending, view.active, view.issued);
        if state != (model.pending, model.active, model.issued) {
            found.push(format!(
                "step {at} {sent:?}: pending, active, issued are {state:?}, expected {:?}",
                (model.pending, model.active, model.issued)
            ));
        }
        let admitted = owner.active(PEER).map(|session| session.epoch);
        if admitted != model.active.map(|(epoch, _)| epoch) {
            found.push(format!(
                "step {at} {sent:?}: the active session is {admitted:?}"
            ));
        }
    }
    (found, model.stale)
}

fn hello(nonce: [u8; 16], sequence: u64) -> Sent {
    Sent::Hello { nonce, sequence }
}

fn confirm(nonce: [u8; 16], epoch: u64, sequence: u64) -> Sent {
    Sent::Confirm {
        nonce,
        epoch,
        sequence,
    }
}

/// HELLOs and CONFIRMs at or below their nonce's floor, or at sequence 0, are `Stale` and change nothing; the
/// first HELLO of a nonce passes at whatever nonzero sequence it carries, and each pass raises that nonce's floor
/// alone.
#[test]
fn a_bootstrap_frame_at_or_below_its_nonces_floor_or_at_zero_is_stale() {
    let (a, b) = (NONCE_A, NONCE_B);
    let script = [
        hello(a, 0),         // zero before any floor: stale
        hello(a, 5),         // the first HELLO of A passes at 5: epoch 1 pending
        hello(a, 5),         // a second copy: stale
        hello(a, 3),         // lower: stale
        confirm(a, 1, 5),    // a CONFIRM naming the pending session at the floor: stale
        confirm(a, 1, 0),    // at zero: stale
        confirm(a, 1, 6),    // above the floor: activates epoch 1
        confirm(a, 1, 6),    // a second copy, naming the active session: stale
        confirm(a, 1, 4),    // lower: stale
        confirm(a, 1, 8),    // a repeat above the floor passes and raises it
        hello(a, 8),         // a HELLO at the floor a CONFIRM raised: stale
        hello(a, 7),         // lower: stale
        hello(a, 9),         // rising: epoch 2 pending
        hello(b, 0),         // the other nonce at zero: stale
        hello(b, 1000),      // the first HELLO of B passes at 1000: epoch 3 pending
        hello(b, 1000),      // a second copy: stale
        hello(b, 999),       // lower: stale
        confirm(b, 3, 1000), // B's CONFIRM naming the pending session at its floor: stale
        confirm(b, 3, 0),    // at zero: stale
        hello(b, 1001),      // rising: epoch 4 pending
        hello(a, 9),         // A's floor stayed while B's moved: stale
        confirm(a, 1, 8),    // A's active session at its CONFIRM's old sequence: stale
        hello(a, 10),        // rising: epoch 5 pending
        confirm(a, 5, 10),   // at the floor its HELLO set: stale
        confirm(a, 5, 11),   // above it: activates epoch 5
        confirm(a, 5, 11),   // a second copy: stale
    ];
    let (found, stale) = disagreements(&script);
    assert_eq!(stale, 18, "premise: the script holds eighteen stale frames");
    assert!(found.is_empty(), "bootstrap floor: {found:#?}");
}

/// The same handshakes with every sequence rising: nothing is stale, so the stale verdicts above come from the
/// floor and not from the frames.
#[test]
fn rising_bootstrap_sequences_all_pass() {
    let (a, b) = (NONCE_A, NONCE_B);
    let script = [
        hello(a, 5),
        confirm(a, 1, 6),
        confirm(a, 1, 8),
        hello(a, 9),
        hello(b, 1000),
        hello(b, 1001),
        hello(a, 10),
        confirm(a, 5, 11),
    ];
    let (found, stale) = disagreements(&script);
    assert_eq!(stale, 0, "premise: the script holds no stale frame");
    assert!(found.is_empty(), "bootstrap floor: {found:#?}");
}
