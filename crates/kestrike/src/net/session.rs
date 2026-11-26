//! Per-peer sessions: the HELLO, CHALLENGE, CONFIRM and READY bootstrap, activation and displacement, per-direction replay windows, send sequences, and quiescent re-key.
//!
//! Invariants owned by this module:
//!
//! - Every handler takes an [`Authenticated`] frame, so no unauthenticated byte changes a session; a bootstrap body is read only through the tag that covers it.
//! - [`Sessions::admit`] refuses bootstrap kinds, ownership kinds other than PROBE and the WrongOwner that answers it, and kinds that travel away from this role, before the replay window or any counter moves.
//! - Each peer holds at most one active session and one pending handshake. A HELLO replaces only the pending handshake and preserves the active session; only the CONFIRM matching the current pending epoch, client nonce, owner nonce and caps activates a session, and a CONFIRM naming the active session at a bootstrap sequence above its nonce's floor raises that floor and repeats READY, leaving the session as it is.
//! - The owner's pending epoch advances by one per CHALLENGE with checked arithmetic, so every epoch is at least 1 and each peer's epochs are distinct within one owner boot; a peer whose epoch or bootstrap sequence is exhausted retires for good and is counted.
//! - A client's HELLO and CONFIRM carry its bootstrap sequence, separate from session sequences, which rises by one per bootstrap frame; the owner's CHALLENGE and READY echo the sequence of the frame they answer, and a client accepts only a reply echoing its last bootstrap frame, so no reply to an earlier frame, from this or an earlier owner boot, changes its handshake.
//! - An owner keeps a floor of the highest bootstrap sequence per client boot nonce for the active session's nonce and the most recent other nonce, and treats the nonce the last activation displaced as stale; a frame at or below its nonce's floor is dropped. A replayed HELLO from a client boot older than both can replace the pending handshake, which leaves the active session unchanged. A HELLO under such a nonce also replaces the other-nonce floor, so the replaced nonce's earlier bootstrap sequences pass again; each such HELLO leaves the active session and its floor unchanged.
//! - The owner takes a HELLO under every nonce whose floor it passes, because client boot nonces are unordered and a rebooted client's HELLO looks like a stale one. A client therefore repeats the CONFIRM of one pending handshake at most [`CONFIRM_REPEATS`] times and then restarts with a fresh HELLO, so a stale HELLO that replaced the owner's pending handshake delays activation by those repeats and one HELLO round trip once delivery recovers.
//! - A session's sequences start at 1 in each direction, and each frame staged for sending takes the next one, retransmissions included, so each GET frame of a packed datagram carries its own. A staged frame that fails to encode or tag, or that the transport refuses, spends its sequence, so the sequences a peer receives rise with gaps. The receiver keeps the highest sequence accepted and a bitmap of `window_cap + 64` entries rounded up to whole words, charged at initialization: sequence 0 and a sequence at or below `highest` minus the bitmap's entry count are stale, a seen one is a duplicate, and either is dropped before any session or request state changes.
//! - Activating a session for a client boot nonce other than the active one displaces the old session; the caller retires its matched work with drain custody, and the displacement is counted.
//! - Re-key replaces the ring's keys and key epoch, retires every session and pending handshake and replaces the boot nonce in place, as one operation that runs only while no request is active or draining.

use std::num::NonZeroU64;

use crate::storage::{EngineBudget, EngineBudgetExceeded};

use super::auth::{Authenticated, KeyEntry, KeyError, KeyRing};
use super::datagram::PeerId;
use super::frame::{BOOTSTRAP_BODY_LEN, Direction, Header, Kind, MAX_SLOT_CAP, MAX_WINDOW};
use super::requests::RequestCensus;

/// CONFIRM repeats a client sends for one pending handshake before [`Sessions::confirm`] refuses and the client restarts with a fresh HELLO.
///
/// An owner takes a HELLO under any client boot nonce whose floor it passes, because boot nonces are unordered and a rebooted client's HELLO looks like a stale one. A delayed HELLO from the client's older boot can therefore replace the pending handshake after its CHALLENGE went out, and every CONFIRM for that handshake then mismatches. The bound limits that loss to these repeats and one HELLO round trip. Two repeats cover a READY lost twice in a row; a third loss costs a HELLO round trip and a fresh epoch, which the client endpoint sends while `bootstrap_attempts` exceeds this bound.
pub const CONFIRM_REPEATS: u32 = 2;

/// Which end of the protocol a session table serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Owner,
    Client,
}

/// Request-slot and window caps, as a bootstrap body carries them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    pub slots: u32,
    pub window: u32,
}

impl Caps {
    /// The caps a bootstrap body names, slots then window as big-endian `u32`s; the codec has checked their ranges.
    #[inline]
    pub(super) fn from_body(body: [u8; BOOTSTRAP_BODY_LEN]) -> Self {
        let word = u64::from_be_bytes(body);
        Self {
            slots: (word >> 32) as u32,
            window: word as u32,
        }
    }

    pub fn body(&self) -> [u8; BOOTSTRAP_BODY_LEN] {
        let mut body = [0; BOOTSTRAP_BODY_LEN];
        body[..4].copy_from_slice(&self.slots.to_be_bytes());
        body[4..].copy_from_slice(&self.window.to_be_bytes());
        body
    }

    /// Whether both caps are negotiable: slots in `1..=MAX_SLOT_CAP` and the window in `1..=MAX_WINDOW`.
    pub fn in_range(&self) -> bool {
        (1..=MAX_SLOT_CAP).contains(&self.slots) && (1..=MAX_WINDOW).contains(&self.window)
    }

    /// Each cap's minimum of the two.
    pub fn meet(self, other: Self) -> Self {
        Self {
            slots: self.slots.min(other.slots),
            window: self.window.min(other.window),
        }
    }
}

/// The fields of a bootstrap frame to send, which the caller encodes and tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bootstrap {
    pub tenure: Option<super::ownership::Tenure>,
    pub peer: PeerId,
    pub kind: Kind,
    pub owner_nonce: [u8; 16],
    pub client_nonce: [u8; 16],
    /// The pending or active session epoch, zero on HELLO.
    pub epoch: u64,
    pub caps: Caps,
    /// The sender's bootstrap sequence.
    pub sequence: u64,
}

/// The active session a frame was admitted under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admitted {
    pub peer: PeerId,
    pub epoch: u64,
    pub caps: Caps,
}

/// An owner's answer to a CONFIRM: its READY reply and, for a new activation, the session it replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Activation {
    pub ready: Bootstrap,
    /// The previously active session's epoch and whether the client's boot nonce changed, which displaces its work.
    pub replaced: Option<Replaced>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Replaced {
    pub epoch: u64,
    pub displaced: bool,
}

/// Why an authenticated frame or a send was refused. `Stale` and `Duplicate` raise their report counter, as does `Mismatch` for a frame that names no matching session, handshake or client nonce; `Exhausted` retires the peer or session, and a bootstrap frame at a nonzero sequence under a client nonce outside both floors and the displaced nonce starts that nonce's floor at its sequence and passes the floor check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionReject {
    /// The handler belongs to the other role: a caller defect, apart from anything a peer sent.
    Role,
    /// The peer retired after a counter was exhausted.
    Retired,
    /// The frame's kind does not belong to this role's handler.
    Kind,
    /// The peer lies outside the table, lacks the pending handshake or active session the call needs, has spent its pending handshake's [`CONFIRM_REPEATS`] repeats, or no session or handshake matches the frame's epoch, nonces and caps.
    Mismatch,
    /// A bootstrap sequence of 0, at or below its nonce's floor or under the displaced nonce, a client reply echoing a sequence other than its last bootstrap frame, or a session sequence of 0 or at or below the window's floor.
    Stale,
    /// A session sequence already accepted.
    Duplicate,
    /// A counter would pass its maximum; the peer or session retired.
    Exhausted,
}

/// Session counters over the table's life.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionReport {
    pub activations: u64,
    /// Activations that replaced a session of another client boot nonce.
    pub displacements: u64,
    pub retired_peers: u64,
    pub stale: u64,
    pub duplicate: u64,
    pub mismatched: u64,
    /// Sessions that ended because their send sequence was spent.
    pub exhausted_sessions: u64,
}

/// A pending or active session's identity. Its epoch is at least 1: an owner issues epochs from 1, and the codec requires a nonzero epoch on every bootstrap kind but HELLO.
#[derive(Debug, Clone, Copy)]
struct Handshake {
    tenure: Option<super::ownership::Tenure>,
    epoch: NonZeroU64,
    owner_nonce: [u8; 16],
    client_nonce: [u8; 16],
    caps: Caps,
}

impl Handshake {
    /// Whether `header` names this session: its epoch and both boot nonces.
    fn names(&self, header: &Header) -> bool {
        self.epoch.get() == header.epoch
            && self.owner_nonce == header.owner_nonce
            && self.client_nonce == header.client_nonce
    }

    fn admitted(&self, peer: PeerId) -> Admitted {
        Admitted {
            peer,
            epoch: self.epoch.get(),
            caps: self.caps,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Active {
    handshake: Handshake,
    /// The next sequence this end sends; at `u64::MAX` the session ends instead.
    send: u64,
    /// The newest sequence accepted from the peer, with its place in the replay bitmap.
    newest: Newest,
}

/// The highest bootstrap sequence a client boot nonce has used; bootstrap sequences start at 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Floor {
    nonce: [u8; 16],
    highest: NonZeroU64,
}

#[derive(Debug, Clone, Copy, Default)]
struct Peer {
    pending: Option<Handshake>,
    active: Option<Active>,
    /// The owner's last issued epoch.
    issued: u64,
    /// A client's bootstrap frames sent; the last one is the one a reply must echo.
    bootstrap_sent: u64,
    /// On an owner, the floor of the active session's client nonce.
    active_floor: Option<Floor>,
    /// On an owner, the floor of the most recent other client nonce.
    other_floor: Option<Floor>,
    /// On an owner, the client nonce the last activation displaced; its frames are stale.
    displaced: Option<[u8; 16]>,
    /// On a client, the CONFIRM repeats sent for the pending handshake, at most [`CONFIRM_REPEATS`]. The repeats belong to the pending handshake: `on_challenge`, the one client path that installs one, resets them, and `rekey`, which ends one, resets them with it.
    confirm_repeats: u32,
    retired: bool,
}

impl Peer {
    /// Retires the peer for good, ending its session and pending handshake.
    fn retire(&mut self) {
        self.retired = true;
        self.active = None;
        self.pending = None;
    }
}

/// Why a re-key did not run; nothing changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RekeyError {
    /// Requests are still active or draining.
    Busy { census: RequestCensus },
    /// The replacement keys were refused.
    Keys(KeyError),
}

/// The sessions of one endpoint with its fixed peers.
pub struct Sessions {
    role: Role,
    /// Whether [`admit`](Self::admit) takes a frame of each kind byte under a session: every kind that travels toward this role except the bootstrap kinds, with PROBE and WrongOwner alone of the ownership kinds.
    admitted: [bool; 1 << u8::BITS],
    /// This end's boot nonce: the owner nonce on an owner, the client nonce on a client.
    nonce: [u8; 16],
    caps: Caps,
    peers: Box<[Peer]>,
    /// Each peer's replay bitmap, `words` words at `peer * words`. A session's window starts at sequence 0 in word 0, and an advance writes every entry it passes, so the entries inside a session's window hold only that session's sequences; activation also clears the peer's words.
    bits: Box<[u64]>,
    words: usize,
    report: SessionReport,
}

impl Sessions {
    /// Replay bitmap words per peer for a `window_cap`-fragment window.
    pub fn words(window_cap: u32) -> usize {
        (window_cap as usize + 64).div_ceil(64)
    }

    /// Bytes a table of `peers` peers with a `window_cap` window charges.
    pub fn charge(peers: u16, window_cap: u32) -> usize {
        usize::from(peers) * (size_of::<Peer>() + Self::words(window_cap) * size_of::<u64>())
    }

    /// A table for `role` with boot `nonce` and this end's `caps`, charging [`charge`](Self::charge) bytes.
    /// `nonce` is a nonzero nonce from [`nonce_from`](super::auth::nonce_from), and `caps` lie within `1..=65536` slots and `1..=4096` fragments.
    ///
    /// # Errors
    ///
    /// `EngineBudgetExceeded` with `budget` unchanged.
    pub fn new(
        role: Role,
        nonce: [u8; 16],
        caps: Caps,
        peers: u16,
        budget: &mut EngineBudget,
    ) -> Result<Self, EngineBudgetExceeded> {
        debug_assert!(
            (1..=MAX_SLOT_CAP).contains(&caps.slots) && (1..=MAX_WINDOW).contains(&caps.window)
        );
        debug_assert_ne!(
            nonce, [0; 16],
            "a boot nonce comes from `nonce_from`, which refuses zero"
        );
        budget.charge(Self::charge(peers, caps.window))?;
        let words = Self::words(caps.window);
        let inbound = match role {
            Role::Owner => Direction::ClientToOwner,
            Role::Client => Direction::OwnerToClient,
        };
        let admitted = std::array::from_fn(|wire| {
            Kind::from_wire(wire as u8).is_some_and(|kind| {
                !kind.is_bootstrap()
                    && (!kind.is_ownership() || matches!(kind, Kind::Probe | Kind::WrongOwner))
                    && kind.direction() == inbound
            })
        });
        Ok(Self {
            role,
            admitted,
            nonce,
            caps,
            peers: vec![Peer::default(); usize::from(peers)].into_boxed_slice(),
            bits: vec![0; usize::from(peers) * words].into_boxed_slice(),
            words,
            report: SessionReport::default(),
        })
    }

    pub fn nonce(&self) -> [u8; 16] {
        self.nonce
    }

    pub fn report(&self) -> SessionReport {
        self.report
    }

    /// The active session's epoch and caps for `peer`.
    pub fn active(&self, peer: PeerId) -> Option<Admitted> {
        let active = self.peers.get(usize::from(peer.0))?.active?;
        Some(active.handshake.admitted(peer))
    }

    pub(super) fn bind_tenure(&mut self, peer: PeerId, tenure: super::ownership::Tenure) {
        if let Some(active) = self
            .peers
            .get_mut(usize::from(peer.0))
            .and_then(|s| s.active.as_mut())
        {
            active.handshake.tenure = Some(tenure);
        }
    }
    pub fn tenure(&self, peer: PeerId) -> Option<super::ownership::Tenure> {
        self.peers
            .get(usize::from(peer.0))?
            .active?
            .handshake
            .tenure
    }
    pub(super) fn end_sessions(&mut self) {
        for peer in &mut self.peers {
            peer.active = None;
            peer.pending = None;
        }
    }

    /// The owner and client boot nonces of `peer`'s active session, which every frame under it carries.
    pub fn nonces(&self, peer: PeerId) -> Option<([u8; 16], [u8; 16])> {
        let handshake = self.peers.get(usize::from(peer.0))?.active?.handshake;
        Some((handshake.owner_nonce, handshake.client_nonce))
    }

    fn peer_mut(&mut self, peer: PeerId) -> Result<&mut Peer, SessionReject> {
        let state = self
            .peers
            .get_mut(usize::from(peer.0))
            .ok_or(SessionReject::Mismatch)?;
        if state.retired {
            return Err(SessionReject::Retired);
        }
        Ok(state)
    }

    /// Takes a client's next bootstrap sequence for `peer`, retiring the peer when it is exhausted.
    fn bootstrap_sequence(&mut self, peer: PeerId) -> Result<u64, SessionReject> {
        let state = self.peer_mut(peer)?;
        match state.bootstrap_sent.checked_add(1) {
            Some(next) => {
                state.bootstrap_sent = next;
                Ok(next)
            }
            None => {
                state.retire();
                self.report.retired_peers += 1;
                Err(SessionReject::Exhausted)
            }
        }
    }

    /// On an owner, checks a client bootstrap sequence against the floor of its boot nonce and raises that floor.
    /// Sequence 0 and the displaced nonce are always stale. A nonce other than the active one and the most recent other one starts a new floor at `sequence`, replacing the other one, and passes.
    fn check_floor(
        &mut self,
        peer: PeerId,
        nonce: [u8; 16],
        sequence: u64,
    ) -> Result<(), SessionReject> {
        let state = self.peer_mut(peer)?;
        let sequence = match NonZeroU64::new(sequence) {
            Some(sequence) if state.displaced != Some(nonce) => sequence,
            _ => return Err(self.stale()),
        };
        let floor = if state.active_floor.is_some_and(|floor| floor.nonce == nonce) {
            state.active_floor.as_mut()
        } else if state.other_floor.is_some_and(|floor| floor.nonce == nonce) {
            state.other_floor.as_mut()
        } else {
            state.other_floor = Some(Floor {
                nonce,
                highest: sequence,
            });
            return Ok(());
        };
        match floor {
            Some(floor) if sequence > floor.highest => {
                floor.highest = sequence;
                Ok(())
            }
            _ => Err(self.stale()),
        }
    }

    /// Counts a stale frame in the report and returns `Stale`.
    fn stale(&mut self) -> SessionReject {
        self.report.stale += 1;
        SessionReject::Stale
    }

    /// On a client, checks that a reply echoes the last bootstrap sequence sent to `peer`; until the first bootstrap frame goes out, every reply is stale.
    fn check_echo(&mut self, peer: PeerId, sequence: u64) -> Result<(), SessionReject> {
        let state = self.peer_mut(peer)?;
        if sequence != state.bootstrap_sent || sequence == 0 {
            return Err(self.stale());
        }
        Ok(())
    }

    /// A client's HELLO toward `peer`, replacing any pending handshake; the active session stays.
    ///
    /// # Errors
    ///
    /// `Role` on an owner, `Mismatch` for a peer outside the table, `Retired`, or `Exhausted` when the bootstrap sequence is spent.
    pub fn hello(&mut self, peer: PeerId) -> Result<Bootstrap, SessionReject> {
        if self.role != Role::Client {
            return Err(SessionReject::Role);
        }
        let sequence = self.bootstrap_sequence(peer)?;
        self.peer_mut(peer)?.pending = None;
        Ok(Bootstrap {
            tenure: None,
            peer,
            kind: Kind::Hello,
            owner_nonce: [0; 16],
            client_nonce: self.nonce,
            epoch: 0,
            caps: self.caps,
            sequence,
        })
    }

    /// An owner's answer to a HELLO: a new pending handshake at the next epoch, replacing any older one, and its CHALLENGE, which echoes the HELLO's bootstrap sequence.
    ///
    /// # Errors
    ///
    /// `Role` on a client, `Kind`, `Mismatch` for a peer outside the table, `Retired`, `Stale` for sequence 0, a sequence at or below its nonce's floor, or a displaced nonce, or `Exhausted` when the epoch is spent.
    pub fn on_hello(&mut self, frame: &Authenticated<'_, '_>) -> Result<Bootstrap, SessionReject> {
        let header = frame.header();
        if self.role != Role::Owner {
            return Err(SessionReject::Role);
        }
        if header.kind != Kind::Hello {
            return Err(SessionReject::Kind);
        }
        let peer = frame.peer();
        // The nonces load once as `u128` values, so the floor check, the pending handshake and the CHALLENGE copy them from registers.
        let client_nonce = u128::from_ne_bytes(header.client_nonce);
        self.check_floor(peer, client_nonce.to_ne_bytes(), header.sequence)?;
        let caps = Caps::from_body(frame.frame().bootstrap_body()).meet(self.caps);
        let owner_nonce = u128::from_ne_bytes(self.nonce);
        let state = self.peer_mut(peer)?;
        let Some(epoch) = NonZeroU64::MIN.checked_add(state.issued) else {
            state.retire();
            self.report.retired_peers += 1;
            return Err(SessionReject::Exhausted);
        };
        state.issued = epoch.get();
        let handshake = Handshake {
            tenure: None,
            epoch,
            owner_nonce: owner_nonce.to_ne_bytes(),
            client_nonce: client_nonce.to_ne_bytes(),
            caps,
        };
        state.pending = Some(handshake);
        Ok(reply(peer, Kind::Challenge, handshake, header.sequence))
    }

    /// A client's answer to the CHALLENGE that echoes its last HELLO: the pending handshake it names, with the challenge's caps met against this end's, and its CONFIRM.
    ///
    /// # Errors
    ///
    /// `Role` on an owner, `Kind`, `Retired`, `Mismatch` for another client nonce, epoch 0 or a peer outside the table, `Stale` for a challenge to any HELLO but the last one sent or before any HELLO, or `Exhausted`.
    pub fn on_challenge(
        &mut self,
        frame: &Authenticated<'_, '_>,
    ) -> Result<Bootstrap, SessionReject> {
        let header = frame.header();
        if self.role != Role::Client {
            return Err(SessionReject::Role);
        }
        if header.kind != Kind::Challenge {
            return Err(SessionReject::Kind);
        }
        if header.client_nonce != self.nonce {
            self.report.mismatched += 1;
            return Err(SessionReject::Mismatch);
        }
        let Some(epoch) = NonZeroU64::new(header.epoch) else {
            self.report.mismatched += 1;
            return Err(SessionReject::Mismatch);
        };
        let peer = frame.peer();
        self.check_echo(peer, header.sequence)?;
        let sequence = self.bootstrap_sequence(peer)?;
        // The nonces load as `u128` values, so their two copies, into the pending handshake and the CONFIRM, stay in registers.
        let owner_nonce = u128::from_ne_bytes(header.owner_nonce);
        let client_nonce = u128::from_ne_bytes(self.nonce);
        let handshake = Handshake {
            tenure: None,
            epoch,
            owner_nonce: owner_nonce.to_ne_bytes(),
            client_nonce: client_nonce.to_ne_bytes(),
            caps: Caps::from_body(frame.frame().bootstrap_body()).meet(self.caps),
        };
        let state = self.peer_mut(peer)?;
        state.pending = Some(handshake);
        state.confirm_repeats = 0;
        Ok(reply(peer, Kind::Confirm, handshake, sequence))
    }

    /// A client's repeated CONFIRM for its pending handshake, at a fresh bootstrap sequence, after its READY went missing; each pending handshake gets at most [`CONFIRM_REPEATS`] repeats.
    ///
    /// # Errors
    ///
    /// `Role` on an owner, `Mismatch` without a pending handshake, once its repeats are spent, or for a peer outside the table, `Retired`, or `Exhausted`. On `Mismatch` the caller restarts the handshake with [`hello`](Self::hello).
    pub fn confirm(&mut self, peer: PeerId) -> Result<Bootstrap, SessionReject> {
        if self.role != Role::Client {
            return Err(SessionReject::Role);
        }
        let state = self.peer_mut(peer)?;
        if state.confirm_repeats >= CONFIRM_REPEATS {
            return Err(SessionReject::Mismatch);
        }
        let pending = state.pending.ok_or(SessionReject::Mismatch)?;
        let sequence = self.bootstrap_sequence(peer)?;
        self.peer_mut(peer)?.confirm_repeats += 1;
        Ok(reply(peer, Kind::Confirm, pending, sequence))
    }

    /// An owner's answer to a CONFIRM: activating the matching pending handshake, or repeating the READY of the active one; READY echoes the CONFIRM's bootstrap sequence.
    ///
    /// # Errors
    ///
    /// `Role` on a client, `Kind`, `Retired`, `Mismatch` when neither the pending nor the active session matches or the peer is outside the table, or `Stale` for sequence 0, a sequence at or below its nonce's floor, or a displaced nonce.
    pub fn on_confirm(
        &mut self,
        frame: &Authenticated<'_, '_>,
    ) -> Result<Activation, SessionReject> {
        let header = frame.header();
        if self.role != Role::Owner {
            return Err(SessionReject::Role);
        }
        if header.kind != Kind::Confirm {
            return Err(SessionReject::Kind);
        }
        let peer = frame.peer();
        let matches = |handshake: &Handshake| {
            handshake.names(&header)
                && handshake.caps == Caps::from_body(frame.frame().bootstrap_body())
        };
        let state = self.peer_mut(peer)?;
        let (handshake, activates) = if let Some(active) = state
            .active
            .as_ref()
            .filter(|active| matches(&active.handshake))
        {
            (active.handshake, false)
        } else if let Some(pending) = state.pending.as_ref().filter(|pending| matches(pending)) {
            (*pending, true)
        } else {
            self.report.mismatched += 1;
            return Err(SessionReject::Mismatch);
        };
        self.answer_confirm(peer, &header, handshake, activates)
    }

    /// The READY for a CONFIRM naming `handshake` once its bootstrap sequence passes the floor, activating `handshake` when `activates`.
    /// `#[inline(never)]` confines the additional register saves to `answer_confirm`, so `on_confirm` handles session-mismatch returns through its matching code alone.
    ///
    /// # Errors
    ///
    /// `Retired` or `Stale` from the floor check, before any session state changes.
    #[inline(never)]
    fn answer_confirm(
        &mut self,
        peer: PeerId,
        header: &Header,
        handshake: Handshake,
        activates: bool,
    ) -> Result<Activation, SessionReject> {
        self.check_floor(peer, header.client_nonce, header.sequence)?;
        let replaced = if activates {
            self.activate(peer, handshake)
        } else {
            None
        };
        Ok(Activation {
            ready: reply(peer, Kind::Ready, handshake, header.sequence),
            replaced,
        })
    }

    /// `on_ready` activates the client when READY echoes its last CONFIRM and matches its pending handshake. It returns the admitted session, the replaced session so the caller can fail or retry its requests, and the decoded READY body, which gives the caller the shard the session serves. READY binds the tenure named in its body and must match the handshake's caps. A repeated READY preserves the active session, must match its bound tenure and caps, and returns that session with `None` for the replaced session and its own decoded body.
    ///
    /// # Errors
    ///
    /// `Role` on an owner, `Kind`, `Retired`, `Mismatch`, or `Stale` for a READY to any other CONFIRM. A READY whose body fails to decode, or whose caps or tenure conflict, returns `Mismatch` and counts in `mismatched`.
    pub fn on_ready(
        &mut self,
        frame: &Authenticated<'_, '_>,
    ) -> Result<(Admitted, Option<Replaced>, super::ownership::ReadyBody), SessionReject> {
        let header = frame.header();
        if self.role != Role::Client {
            return Err(SessionReject::Role);
        }
        if header.kind != Kind::Ready {
            return Err(SessionReject::Kind);
        }
        let Ok(ready) = super::ownership::ReadyBody::decode(frame.frame().raw_body()) else {
            self.report.mismatched += 1;
            return Err(SessionReject::Mismatch);
        };
        let peer = frame.peer();
        let matches = |handshake: &Handshake| handshake.names(&header);
        let state = self.peer_mut(peer)?;
        if let Some(active) = state.active.filter(|active| matches(&active.handshake)) {
            if Some(ready.tenure) != active.handshake.tenure || ready.caps != active.handshake.caps
            {
                self.report.mismatched += 1;
                return Err(SessionReject::Mismatch);
            }
            return Ok((active.handshake.admitted(peer), None, ready));
        }
        let Some(mut pending) = state.pending.filter(matches) else {
            self.report.mismatched += 1;
            return Err(SessionReject::Mismatch);
        };
        if ready.caps != pending.caps {
            self.report.mismatched += 1;
            return Err(SessionReject::Mismatch);
        }
        pending.tenure = Some(ready.tenure);
        self.check_echo(peer, header.sequence)?;
        let replaced = self.activate(peer, pending);
        Ok((pending.admitted(peer), replaced, ready))
    }

    /// Whether admitting `later` before `earlier` in one peer's session makes `earlier` stale, because `later` is at least the window's `words * 64` entries ahead.
    pub(super) fn ages_out(&self, earlier: u64, later: u64) -> bool {
        later.saturating_sub(earlier) >= self.words as u64 * 64
    }

    /// Makes `handshake` the peer's active session with fresh sequences and an empty replay window, and reports the session it replaced.
    /// On an owner, the new client nonce's floor becomes the active floor and a displaced nonce is remembered as stale.
    fn activate(&mut self, peer: PeerId, handshake: Handshake) -> Option<Replaced> {
        let at = usize::from(peer.0);
        let state = &mut self.peers[at];
        let replaced = state.active.map(|old| Replaced {
            epoch: old.handshake.epoch.get(),
            displaced: old.handshake.client_nonce != handshake.client_nonce,
        });
        if self.role == Role::Owner {
            let nonce = handshake.client_nonce;
            if let Some(old) = state.active_floor.filter(|floor| floor.nonce != nonce) {
                state.displaced = Some(old.nonce);
            }
            if state.other_floor.is_some_and(|floor| floor.nonce == nonce) {
                state.active_floor = state.other_floor.take();
            }
        }
        state.pending = None;
        state.active = Some(Active {
            handshake,
            send: 1,
            newest: Newest::default(),
        });
        self.bits[at * self.words..][..self.words].fill(0);
        self.report.activations += 1;
        self.report.displacements += u64::from(replaced.is_some_and(|old| old.displaced));
        replaced
    }

    /// Admits `frame` as [`admit`](Self::admit) does when it names its peer's active session under a sequence above
    /// every sequence that session admitted, and reports whether it did. The sender numbers its frames in send
    /// order, so it sent an admitted frame after every frame the session has taken. Any other frame returns `false`
    /// and moves neither the replay window nor a counter.
    pub fn admit_newest(&mut self, frame: &Authenticated<'_, '_>) -> bool {
        let header = frame.header();
        let newest = (self.peers.get(usize::from(frame.peer().0)))
            .and_then(|state| state.active.as_ref())
            .is_some_and(|active| {
                active.handshake.names(&header) && header.sequence > active.newest.sequence
            });
        newest && self.admit(frame).is_ok()
    }

    /// Admits a non-bootstrap frame under the peer's active session: its epoch and both nonces must match, and its sequence must pass the replay window, which then records it.
    ///
    /// # Errors
    ///
    /// `Kind` for a bootstrap frame, an ownership frame other than PROBE and its WrongOwner answer, or one this role never receives, `Retired`, `Mismatch`, `Stale` or `Duplicate`.
    #[inline]
    pub fn admit(&mut self, frame: &Authenticated<'_, '_>) -> Result<Admitted, SessionReject> {
        let header = frame.header();
        if !self.admitted[usize::from(header.kind as u8)] {
            return Err(SessionReject::Kind);
        }
        let peer = frame.peer();
        let at = usize::from(peer.0);
        let state = self.peers.get_mut(at).ok_or(SessionReject::Mismatch)?;
        if state.retired {
            return Err(SessionReject::Retired);
        }
        let Some(active) = state
            .active
            .as_mut()
            .filter(|active| active.handshake.names(&header))
        else {
            self.report.mismatched += 1;
            return Err(SessionReject::Mismatch);
        };
        let sequence = header.sequence;
        // The next sequence inside the newest entry's block passes no entry and keeps its word.
        if sequence.wrapping_sub(active.newest.sequence) == 1 && !sequence.is_multiple_of(64) {
            self.bits[at * self.words + active.newest.word] |= 1 << (sequence % 64);
            active.newest.sequence = sequence;
            return Ok(active.handshake.admitted(peer));
        }
        self.record(peer, sequence)
    }

    /// # Panics
    ///
    /// - If `peer` lies outside the table or has no active session; [`admit`](Self::admit) matches the frame to that session before it calls `record`.
    #[inline(never)]
    fn record(&mut self, peer: PeerId, sequence: u64) -> Result<Admitted, SessionReject> {
        let at = usize::from(peer.0);
        let active = self
            .peers
            .get_mut(at)
            .and_then(|state| state.active.as_mut())
            .expect("`admit` matched the frame to the peer's active session");
        let bits = &mut self.bits[at * self.words..][..self.words];
        match accept(bits, &mut active.newest, sequence) {
            Ok(()) => Ok(active.handshake.admitted(peer)),
            Err(reject) => {
                match reject {
                    SessionReject::Duplicate => self.report.duplicate += 1,
                    _ => self.report.stale += 1,
                }
                Err(reject)
            }
        }
    }

    /// Takes the next sequence this end sends under `peer`'s active session.
    ///
    /// # Errors
    ///
    /// `Mismatch` without an active session, `Retired`, or `Exhausted` once the sequence is spent, which also retires the session.
    #[inline]
    pub fn next_sequence(&mut self, peer: PeerId) -> Result<u64, SessionReject> {
        let state = self.peer_mut(peer)?;
        let active = state.active.as_mut().ok_or(SessionReject::Mismatch)?;
        let sequence = active.send;
        match sequence.checked_add(1) {
            Some(next) => {
                active.send = next;
                Ok(sequence)
            }
            None => {
                state.active = None;
                self.report.exhausted_sessions += 1;
                Err(SessionReject::Exhausted)
            }
        }
    }

    /// Re-keys a quiescent endpoint in place: replaces `ring`'s keys and moves it to `key_epoch`, retires every session and pending handshake with the handshake's CONFIRM repeats, and moves to boot `nonce`, keeping every charged array.
    /// Peers retired by exhaustion stay retired, and the owner's bootstrap floors stay, so bootstrap sequences keep rising across the re-key.
    ///
    /// # Errors
    ///
    /// `Busy` with the census while any request is active or draining, else `Keys` when the ring refuses the entries; either leaves the ring and the sessions unchanged.
    pub fn rekey(
        &mut self,
        ring: &mut KeyRing,
        entries: &[KeyEntry<'_>],
        key_epoch: u32,
        nonce: [u8; 16],
        census: RequestCensus,
    ) -> Result<(), RekeyError> {
        debug_assert_ne!(
            nonce, [0; 16],
            "a boot nonce comes from `nonce_from`, which refuses zero"
        );
        if census.live() > 0 {
            return Err(RekeyError::Busy { census });
        }
        ring.replace(entries, key_epoch).map_err(RekeyError::Keys)?;
        for state in &mut self.peers {
            state.pending = None;
            state.active = None;
            state.confirm_repeats = 0;
        }
        self.nonce = nonce;
        Ok(())
    }
}

/// A bootstrap reply carrying `handshake`.
fn reply(peer: PeerId, kind: Kind, handshake: Handshake, sequence: u64) -> Bootstrap {
    Bootstrap {
        tenure: handshake.tenure,
        peer,
        kind,
        owner_nonce: handshake.owner_nonce,
        client_nonce: handshake.client_nonce,
        epoch: handshake.epoch.get(),
        caps: handshake.caps,
        sequence,
    }
}

/// The newest sequence a replay window accepted and the bitmap word that holds its entry.
///
/// An entry's word lies as many words from this one as the two sequences' 64-entry blocks lie apart, wrapping at the bitmap's length, so every word is found by an addition. A window starts at sequence 0 in word 0.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Newest {
    pub(super) sequence: u64,
    word: usize,
}

/// Records `sequence` in a replay window of `bits.len() * 64` entries ending at `newest`.
///
/// # Errors
///
/// - `Stale` for sequence 0 or a sequence at or below `newest.sequence - bits.len() * 64`.
/// - `Duplicate` for a sequence the window already holds.
pub(super) fn accept(
    bits: &mut [u64],
    newest: &mut Newest,
    sequence: u64,
) -> Result<(), SessionReject> {
    let words = bits.len();
    let size = words as u64 * 64;
    if sequence == 0 {
        return Err(SessionReject::Stale);
    }
    let bit = 1 << (sequence % 64);
    if sequence > newest.sequence {
        let mut word = newest.word;
        if sequence - newest.sequence >= size {
            bits.fill(0);
        } else {
            // The entries passed are those above the newest one in its word, every word between, and those below the sequence's in its word.
            let above = !(u64::MAX >> (63 - newest.sequence % 64));
            let below = bit - 1;
            let blocks = sequence / 64 - newest.sequence / 64;
            if blocks == 0 {
                bits[word] &= !(above & below);
            } else {
                bits[word] &= !above;
                for _ in 1..blocks {
                    word = following(word, words);
                    bits[word] = 0;
                }
                word = following(word, words);
                bits[word] &= !below;
            }
        }
        bits[word] |= bit;
        *newest = Newest { sequence, word };
        return Ok(());
    }
    if newest.sequence - sequence >= size {
        return Err(SessionReject::Stale);
    }
    // The sequence lies at most `words` blocks back, so one subtraction wraps its word.
    let back = (newest.sequence / 64 - sequence / 64) as usize;
    let word = newest.word + words - back;
    let word = if word >= words { word - words } else { word };
    if bits[word] & bit != 0 {
        return Err(SessionReject::Duplicate);
    }
    bits[word] |= bit;
    Ok(())
}

/// The word after `word` in a bitmap of `words` words, wrapping to word 0.
fn following(word: usize, words: usize) -> usize {
    if word + 1 == words { 0 } else { word + 1 }
}

#[cfg(test)]
impl Sessions {
    /// Sets `peer`'s issued epoch and bootstrap count, so tests reach their exhaustion.
    pub(super) fn set_counters(&mut self, peer: PeerId, issued: u64, bootstrap_sent: u64) {
        let state = &mut self.peers[usize::from(peer.0)];
        state.issued = issued;
        state.bootstrap_sent = bootstrap_sent;
    }

    /// Sets the next sequence `peer`'s active session sends.
    pub(super) fn set_send(&mut self, peer: PeerId, send: u64) {
        if let Some(active) = self.peers[usize::from(peer.0)].active.as_mut() {
            active.send = send;
        }
    }

    /// `peer`'s bootstrap state as a replay compares it: the pending and active handshakes as their epoch and client nonce, the last issued epoch, the bootstrap frames sent, both floors as their nonce and highest sequence, the displaced nonce and the CONFIRM repeats.
    pub(super) fn view(&self, peer: PeerId) -> PeerView {
        let state = &self.peers[usize::from(peer.0)];
        let handshake = |h: Handshake| (h.epoch.get(), h.client_nonce);
        let floor = |f: Floor| (f.nonce, f.highest.get());
        PeerView {
            pending: state.pending.map(handshake),
            active: state.active.map(|active| handshake(active.handshake)),
            issued: state.issued,
            bootstrap_sent: state.bootstrap_sent,
            active_floor: state.active_floor.map(floor),
            other_floor: state.other_floor.map(floor),
            displaced: state.displaced,
            confirm_repeats: state.confirm_repeats,
        }
    }
}

/// One peer's bootstrap state, which [`Sessions::view`] returns.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PeerView {
    pub pending: Option<(u64, [u8; 16])>,
    pub active: Option<(u64, [u8; 16])>,
    pub issued: u64,
    pub bootstrap_sent: u64,
    pub active_floor: Option<([u8; 16], u64)>,
    pub other_floor: Option<([u8; 16], u64)>,
    pub displaced: Option<[u8; 16]>,
    pub confirm_repeats: u32,
}
