//! Quint Connect replay of the Q1 session model's traces against [`Sessions`].
//!
//! The driver plays the model's environment and calls the implementation for
//! every action a trace records, feeding it only the recorded inputs; the
//! trace's own states are the expected post-states.
//!
//! Action mapping, per client `c1` (owner peer 0) and `c2` (owner peer 1):
//!
//! - `init`: one owner table over both clients and one client table per
//!   client, each with its own key ring at key epoch 1 and an empty network.
//! - `retry(c)`: the client endpoint's bootstrap resend, [`Sessions::confirm`]
//!   and on its refusal [`Sessions::hello`]; the frame is sealed under the
//!   client's ring and sent.
//! - `deliverToOwner(c)` and `deliverToClient(c)`: the recorded frame `f` is
//!   found among the frames in flight, one copy is taken, its bytes are parsed
//!   and authenticated by the receiver's ring, and the matching handler runs:
//!   `on_hello`, `on_confirm` and `admit` on the owner, `on_challenge`,
//!   `on_ready` and `admit` on the client. The reply to an accepted HELLO,
//!   CHALLENGE or CONFIRM is sealed and sent.
//! - `clientData(c)` and `ownerData(c)`: a CANCEL from the client or an ERROR
//!   from the owner under the sender's active session, at its next session
//!   sequence.
//! - `lose` and `duplicate`: one copy of `f` leaves or joins the network.
//! - `reboot(c)`: a new client table under the client's next boot nonce.
//! - `reopen(c)`: the client endpoint's `session` call beside its active
//!   session, [`Sessions::hello`], sealed and sent; the client is opening
//!   again.
//! - `rekey`: [`Sessions::rekey`] on every table with new keys, the next key
//!   epoch and new boot nonces; the frames in flight are dropped.
//! - `stabilize`: the network stops faulting.
//!
//! The network follows the model's: a frame joins its channel while the
//! channel has room before stability, and a copy past the copy bound is lost
//! before stability and flagged after it.
//!
//! Comparison fields, after every action: for each owner peer the pending and
//! active handshakes (epoch and client nonce), the last issued epoch, both
//! bootstrap floors and the displaced nonce; for each client its boot nonce,
//! bootstrap frames sent, pending and active handshakes and CONFIRM repeats,
//! read through [`Sessions::view`], and whether it is opening, which the
//! driver holds as the client endpoint does: set by `init`, `reboot`, `rekey`
//! and `reopen`, cleared when a READY activates its handshake; the frames in
//! flight with their copies;
//! the stability, re-key, fault and overflow counters; and the step's action,
//! peer and verdict. A data frame's verdict is `accepted` when its session
//! check passed, including a `Stale` or `Duplicate` replay-window refusal,
//! matching the model's session-only data check. Sequences and epochs are
//! relabelled by rank exactly as the model relabels them. The comparison
//! covers exactly these fields.
//!
//! A divergence names the action index, the field and both values. A driver
//! panic names its class: code defect, driver defect, unsupported schedule or
//! abstraction mismatch. A comparison divergence is classified into one of
//! these before any model or projection change, and its trace is kept as a
//! fixture. The committed fixtures replay under plain `cargo test`. Each is
//! the counterexample of an inverted invariant in `quint/replay.qnt`, recorded
//! by `quint run quint/replay.qnt --main replay --backend typescript --mbt
//! --invariant <name> --seed <seed> --max-samples <samples> --max-steps <steps>
//! --n-traces 1 --out-itf <file>` under Quint 0.33.0:
//! `pending_displacement.itf.json` from `noDisplacedActivation` and
//! `clean_activation.itf.json` from `noCleanActivation`, each at seed `0x1`
//! and 5000 samples of 30 steps; `repeat_then_rekey.itf.json` from
//! `noRekeyAfterRepeat` with `--step bootstrapThenRekey` at seed `0x1`, 2000
//! samples of 12 steps; `reopen_window.itf.json` from `noReopenWindow` with
//! `--step openThenReopen` at seed `0x1`, 500 samples of 30 steps.
//!
//! The generated replay runs 50 traces of `replay.qnt`'s `step` and 10 of
//! its `openThenReopen` recipe, whose traces are traces of `step` restricted
//! to the choices that keep faults and instability for a reopen; `step`'s
//! random traces spend every fault or stabilize before a client activates and
//! so reach no reopen.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use itf::Value;
use itf::de::As;
use quint_connect::{Driver, State, Step};
use serde::Deserialize;

use crate::storage::{Crc32c, EngineBudget};

use super::auth::{KeyEntry, KeyRing};
use super::datagram::{HEADER_LEN, PeerId};
use super::frame::{Direction, Header, Kind, Status, encode, parse, seal};
use super::requests::RequestCensus;
use super::serve::header;
use super::session::{Bootstrap, Caps, PeerView, Role, SessionReject, Sessions};

const ENDPOINT: u32 = 0x00E1_0001;
const CLIENTS: [&str; 2] = ["c1", "c2"];
const PRINCIPALS: [u32; 2] = [0x0000_0C11, 0x0000_0C22];
const CAPS: Caps = Caps {
    slots: 8,
    window: 8,
};
/// The model's capacities: bootstrap frames toward the owner and toward a client, and copies of one frame.
const CAP_TO_OWNER: usize = 2;
const CAP_TO_CLIENT: usize = 1;
const COPIES: i64 = 2;
const OWNER: PeerId = PeerId(0);

/// A client boot nonce as the model names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
struct Nonce {
    boot: i64,
    key: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
struct Handshake {
    epoch: i64,
    client: Nonce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
struct Floor {
    nonce: Nonce,
    highest: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OwnerPeer {
    #[serde(with = "As::<itf::de::Option<_>>")]
    pending: Option<Handshake>,
    #[serde(with = "As::<itf::de::Option<_>>")]
    active: Option<Handshake>,
    issued: i64,
    #[serde(with = "As::<itf::de::Option<_>>")]
    active_floor: Option<Floor>,
    #[serde(with = "As::<itf::de::Option<_>>")]
    other_floor: Option<Floor>,
    #[serde(with = "As::<itf::de::Option<_>>")]
    displaced: Option<Nonce>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Client {
    nonce: Nonce,
    sent: i64,
    #[serde(with = "As::<itf::de::Option<_>>")]
    pending: Option<Handshake>,
    #[serde(with = "As::<itf::de::Option<_>>")]
    active: Option<Handshake>,
    repeats: i64,
    opening: bool,
}

/// A frame as the model names it; `seq` is 0 on data frames.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Frame {
    kind: String,
    peer: String,
    to_owner: bool,
    client: Nonce,
    epoch: i64,
    seq: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Model {
    owner: BTreeMap<String, OwnerPeer>,
    clients: BTreeMap<String, Client>,
    net: BTreeMap<Frame, i64>,
    stable: bool,
    rekeys: i64,
    faults: i64,
    overflow: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Last {
    act: String,
    peer: String,
    verdict: String,
}

thread_local! {
    /// The first field that differed in the last failed comparison, with both values.
    static DIVERGENCE: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// The compared projection of one state, as the trace records it or as the driver observes it.
#[derive(Debug, Clone, Deserialize)]
struct Observed {
    #[serde(rename = "replay::Q::s")]
    s: Model,
    #[serde(rename = "replay::Q::last")]
    last: Last,
    /// The action index the driver observed this state after, set by the driver only.
    #[serde(skip)]
    index: usize,
}

impl Observed {
    /// The first field in which `self`, the trace's state, and `observed`, the driver's, differ.
    fn divergence(&self, observed: &Observed) -> Option<String> {
        let at = observed.index;
        let report = |field: String, spec: String, code: String| {
            Some(format!(
                "action {at}: {field}: model {spec}, implementation {code}"
            ))
        };
        let debug = |value: &dyn std::fmt::Debug| format!("{value:?}");
        if self.last != observed.last {
            return report("last".into(), debug(&self.last), debug(&observed.last));
        }
        let first = |prefix: String, fields: Vec<(&str, String, String)>| {
            fields
                .into_iter()
                .find(|(_, spec, code)| spec != code)
                .and_then(|(field, spec, code)| report(format!("{prefix}.{field}"), spec, code))
        };
        let pair = |field, spec: &dyn std::fmt::Debug, code: &dyn std::fmt::Debug| {
            (field, format!("{spec:?}"), format!("{code:?}"))
        };
        let keys = |m: &Model| {
            (
                m.owner.keys().cloned().collect::<Vec<_>>(),
                m.clients.keys().cloned().collect::<Vec<_>>(),
            )
        };
        if keys(&self.s) != keys(&observed.s) {
            return report(
                "s.owner and s.clients peers".into(),
                debug(&keys(&self.s)),
                debug(&keys(&observed.s)),
            );
        }
        for (name, spec) in &self.s.owner {
            let OwnerPeer {
                pending,
                active,
                issued,
                active_floor,
                other_floor,
                displaced,
            } = spec;
            let code = &observed.s.owner[name];
            let found = first(
                format!("s.owner.{name}"),
                vec![
                    pair("pending", pending, &code.pending),
                    pair("active", active, &code.active),
                    pair("issued", issued, &code.issued),
                    pair("activeFloor", active_floor, &code.active_floor),
                    pair("otherFloor", other_floor, &code.other_floor),
                    pair("displaced", displaced, &code.displaced),
                ],
            );
            if found.is_some() {
                return found;
            }
        }
        for (name, spec) in &self.s.clients {
            let Client {
                nonce,
                sent,
                pending,
                active,
                repeats,
                opening,
            } = spec;
            let code = &observed.s.clients[name];
            let found = first(
                format!("s.clients.{name}"),
                vec![
                    pair("nonce", nonce, &code.nonce),
                    pair("sent", sent, &code.sent),
                    pair("pending", pending, &code.pending),
                    pair("active", active, &code.active),
                    pair("repeats", repeats, &code.repeats),
                    pair("opening", opening, &code.opening),
                ],
            );
            if found.is_some() {
                return found;
            }
        }
        if self.s.net != observed.s.net {
            return report("s.net".into(), debug(&self.s.net), debug(&observed.s.net));
        }
        let counters = |m: &Model| (m.stable, m.rekeys, m.faults, m.overflow);
        if counters(&self.s) != counters(&observed.s) {
            return report(
                "s.stable, s.rekeys, s.faults, s.overflow".into(),
                debug(&counters(&self.s)),
                debug(&counters(&observed.s)),
            );
        }
        None
    }
}

impl PartialEq for Observed {
    fn eq(&self, other: &Self) -> bool {
        let divergence = self.divergence(other);
        let equal = divergence.is_none();
        DIVERGENCE.with(|slot| *slot.borrow_mut() = divergence);
        equal
    }
}

impl State<Replay> for Observed {
    fn from_driver(driver: &Replay) -> quint_connect::Result<Self> {
        Ok(driver.observe())
    }
}

/// The traces and actions a replay ran.
#[derive(Debug, Default)]
struct Counts {
    traces: usize,
    actions: usize,
    longest: usize,
    /// Executions of each action, so a replay shows which actions it reached.
    per_action: BTreeMap<String, usize>,
}

/// A frame in flight: its identity in the implementation's own sequences and epochs, its copies and its sealed bytes.
struct InFlight {
    frame: Frame,
    copies: i64,
    bytes: Vec<u8>,
}

struct ClientEnd {
    sessions: Sessions,
    ring: KeyRing,
    nonce: Nonce,
    /// Whether an opening is under way, as the client endpoint tracks it.
    opening: bool,
}

/// The replay driver: the owner's and each client's session table and key ring, and the model's network.
struct Replay {
    crc: Crc32c,
    owner: Sessions,
    owner_ring: KeyRing,
    owner_key: i64,
    clients: Vec<ClientEnd>,
    net: Vec<InFlight>,
    stable: bool,
    rekeys: i64,
    faults: i64,
    overflow: bool,
    last: Last,
    index: usize,
    counts: Rc<RefCell<Counts>>,
}

/// The key of `principal` at key epoch `key`: distinct per principal and epoch.
fn key_of(principal: u32, key: i64) -> [u8; 32] {
    let mut bytes = [0x40 + key as u8; 32];
    bytes[..4].copy_from_slice(&principal.to_be_bytes());
    bytes
}

fn owner_nonce(key: i64) -> [u8; 16] {
    [0xA0 + key as u8; 16]
}

/// The implementation's boot nonce for client `index` under the model's `nonce`; nonzero for every boot and key epoch.
fn client_nonce(index: usize, nonce: Nonce) -> [u8; 16] {
    let mut bytes = [0x5C; 16];
    bytes[0] = index as u8 + 1;
    bytes[1] = nonce.boot as u8 + 1;
    bytes[2] = nonce.key as u8 + 1;
    bytes
}

fn nonce_of(bytes: [u8; 16]) -> Nonce {
    Nonce {
        boot: i64::from(bytes[1]) - 1,
        key: i64::from(bytes[2]) - 1,
    }
}

fn handshake_of(view: Option<(u64, [u8; 16])>) -> Option<Handshake> {
    view.map(|(epoch, client)| Handshake {
        epoch: epoch as i64,
        client: nonce_of(client),
    })
}

fn floor_of(view: Option<([u8; 16], u64)>) -> Option<Floor> {
    view.map(|(nonce, highest)| Floor {
        nonce: nonce_of(nonce),
        highest: highest as i64,
    })
}

/// Seals `header` with `ring`'s tag for `peer` as `direction` sends it, returning the datagram.
fn sealed(
    crc: Crc32c,
    ring: &KeyRing,
    peer: PeerId,
    header: &Header,
    body: &[u8],
    direction: Direction,
) -> Vec<u8> {
    let mut out = [0u8; HEADER_LEN];
    encode(crc, header, [body, &[]], &mut out).expect("a canonical frame");
    let mut digest = [0; 16];
    let input = ring
        .mac_input(peer, &out, [body, &[]], (ENDPOINT, direction), &mut digest)
        .expect("a mac input");
    let tag = ring.tag(peer, &input).expect("a key");
    seal(&mut out, tag);
    let mut datagram = out.to_vec();
    datagram.extend_from_slice(body);
    datagram
}

/// A data frame under `sessions`' active session with its peer `session_peer`: a CANCEL from a client or an ERROR from the owner, sealed under `ring` at the session's next sequence, with its model identity.
fn data_frame(
    crc: Crc32c,
    sessions: &mut Sessions,
    ring: &KeyRing,
    session_peer: PeerId,
    index: usize,
    to_owner: bool,
) -> (Frame, Vec<u8>) {
    let (epoch, _) = sessions
        .view(session_peer)
        .active
        .expect("a data frame needs an active session");
    let (owner_nonce, client_nonce) = sessions.nonces(session_peer).expect("an active session");
    let sequence = sessions
        .next_sequence(session_peer)
        .expect("a send sequence");
    let (kind, status, direction) = if to_owner {
        (Kind::Cancel, Status::Cancelled, Direction::ClientToOwner)
    } else {
        (Kind::Error, Status::Missing, Direction::OwnerToClient)
    };
    let header = Header {
        principal: PRINCIPALS[index],
        key_epoch: ring.epoch(),
        owner_nonce,
        client_nonce,
        sequence,
        epoch,
        status: status as u16,
        ..header(kind, 1, [0; 32])
    };
    let bytes = sealed(crc, ring, session_peer, &header, &[], direction);
    let frame = Frame {
        kind: "data".into(),
        peer: CLIENTS[index].into(),
        to_owner,
        client: nonce_of(client_nonce),
        epoch: epoch as i64,
        seq: 0,
    };
    (frame, bytes)
}

/// `v`'s rank among the positive values of `values`, keeping 0 as 0, as the model relabels sequences and epochs.
fn rank(values: &BTreeSet<i64>, v: i64) -> i64 {
    if v == 0 {
        0
    } else {
        values.iter().filter(|u| **u > 0 && **u < v).count() as i64 + 1
    }
}

fn verdict(result: Result<(), SessionReject>) -> String {
    match result {
        Ok(()) => "accepted",
        Err(SessionReject::Stale) => "stale",
        Err(SessionReject::Mismatch) => "mismatch",
        Err(other @ (SessionReject::Role | SessionReject::Kind)) => {
            panic!("driver defect: a handler refused with {other:?}")
        }
        Err(other) => panic!("abstraction mismatch: a handler refused with {other:?}, which the model's bounds never reach"),
    }
    .into()
}

impl Replay {
    fn new(counts: Rc<RefCell<Counts>>) -> Self {
        let mut budget = EngineBudget::new(1 << 22);
        let owner_ring = KeyRing::load(
            &PRINCIPALS,
            &Self::owner_entries(0).each_ref().map(|(p, k)| KeyEntry {
                principal: *p,
                key: k,
            }),
            1,
            &mut budget,
        )
        .expect("owner keys");
        let owner =
            Sessions::new(Role::Owner, owner_nonce(0), CAPS, 2, &mut budget).expect("owner table");
        let clients = (0..CLIENTS.len())
            .map(|index| Self::client(index, Nonce { boot: 0, key: 0 }, 1))
            .collect();
        Self {
            crc: Crc32c::detect(),
            owner,
            owner_ring,
            owner_key: 0,
            clients,
            net: Vec::new(),
            stable: false,
            rekeys: 0,
            faults: 0,
            overflow: false,
            last: Last {
                act: "init".into(),
                peer: String::new(),
                verdict: String::new(),
            },
            index: 0,
            counts,
        }
    }

    fn owner_entries(key: i64) -> [(u32, [u8; 32]); 2] {
        PRINCIPALS.map(|principal| (principal, key_of(principal, key)))
    }

    /// A client table for client `index` under `nonce`, keyed at key epoch `epoch`.
    fn client(index: usize, nonce: Nonce, epoch: u32) -> ClientEnd {
        let mut budget = EngineBudget::new(1 << 20);
        let principal = PRINCIPALS[index];
        let key = key_of(principal, i64::from(epoch) - 1);
        let ring = KeyRing::load(
            &[principal],
            &[KeyEntry {
                principal,
                key: &key,
            }],
            epoch,
            &mut budget,
        )
        .expect("client key");
        let sessions = Sessions::new(
            Role::Client,
            client_nonce(index, nonce),
            CAPS,
            1,
            &mut budget,
        )
        .expect("client table");
        ClientEnd {
            sessions,
            ring,
            nonce,
            opening: true,
        }
    }

    fn index_of(peer: &str) -> usize {
        CLIENTS
            .iter()
            .position(|c| *c == peer)
            .unwrap_or_else(|| panic!("unsupported schedule: peer {peer:?}"))
    }

    fn bootstrap_frame(&self, index: usize, step: &Bootstrap) -> (Frame, Vec<u8>) {
        let to_owner = step.kind.direction() == Direction::ClientToOwner;
        let (ring, peer) = if to_owner {
            (&self.clients[index].ring, OWNER)
        } else {
            (&self.owner_ring, PeerId(index as u16))
        };
        assert_eq!(
            step.peer, peer,
            "code defect: a bootstrap step for {} names peer {:?}",
            CLIENTS[index], step.peer
        );
        let body = super::frame_tests::bootstrap_body(step);
        let header = Header {
            principal: PRINCIPALS[index],
            key_epoch: ring.epoch(),
            owner_nonce: step.owner_nonce,
            client_nonce: step.client_nonce,
            sequence: step.sequence,
            epoch: step.epoch,
            datagram_len: body.len() as u32,
            ..header(step.kind, 0, [0; 32])
        };
        let bytes = sealed(self.crc, ring, peer, &header, &body, step.kind.direction());
        let kind = match step.kind {
            Kind::Hello => "hello",
            Kind::Challenge => "challenge",
            Kind::Confirm => "confirm",
            Kind::Ready => "ready",
            other => panic!("code defect: a bootstrap answer of kind {other:?}"),
        };
        let frame = Frame {
            kind: kind.into(),
            peer: CLIENTS[index].into(),
            to_owner,
            client: nonce_of(step.client_nonce),
            epoch: step.epoch as i64,
            seq: step.sequence as i64,
        };
        (frame, bytes)
    }

    /// Adds one copy of `frame` as the model's network does.
    fn send(&mut self, frame: Frame, bytes: Vec<u8>) {
        if let Some(entry) = self.net.iter_mut().find(|entry| entry.frame == frame) {
            if entry.copies < COPIES {
                entry.copies += 1;
            } else {
                self.overflow |= self.stable;
            }
            return;
        }
        let data = frame.kind == "data";
        let held = self
            .net
            .iter()
            .filter(|e| {
                e.frame.peer == frame.peer
                    && e.frame.to_owner == frame.to_owner
                    && (e.frame.kind == "data") == data
            })
            .count();
        let cap = if data {
            1
        } else if frame.to_owner {
            CAP_TO_OWNER
        } else {
            CAP_TO_CLIENT
        };
        if self.stable || held < cap {
            self.net.push(InFlight {
                frame,
                copies: 1,
                bytes,
            });
        }
    }

    /// Takes one copy of the frame in flight that the model names `f` in the current state, returning its identity and bytes.
    fn take(&mut self, f: &Frame) -> (Frame, Vec<u8>) {
        let at = self.position(f);
        let entry = &mut self.net[at];
        let taken = (entry.frame.clone(), entry.bytes.clone());
        entry.copies -= 1;
        if entry.copies == 0 {
            self.net.remove(at);
        }
        taken
    }

    /// The index of the frame in flight that the model names `f` in the current state.
    fn position(&self, f: &Frame) -> usize {
        let labels = self.labels();
        self.net
            .iter()
            .position(|entry| labels.frame(&entry.frame) == *f)
            .unwrap_or_else(|| panic!("driver defect: no frame in flight is the model's {f:?}"))
    }

    fn awaiting(&self, index: usize) -> bool {
        let nonce = self.clients[index].nonce;
        self.net.iter().any(|e| {
            e.frame.peer == CLIENTS[index] && e.frame.kind != "data" && e.frame.client == nonce
        })
    }

    fn event(&mut self, act: &str, peer: &str, verdict: &str) {
        self.last = Last {
            act: act.into(),
            peer: peer.into(),
            verdict: verdict.into(),
        };
    }

    /// Runs one recorded action with its nondeterministic picks.
    fn apply(&mut self, action: &str, peer: Option<String>, f: Option<Frame>) {
        let peer_name = peer.unwrap_or_default();
        match action {
            "init" => {
                let counts = Rc::clone(&self.counts);
                *self = Self::new(counts);
                self.counts.borrow_mut().traces += 1;
            }
            "retry" => {
                let index = Self::index_of(&peer_name);
                let early = self.awaiting(index);
                let client = &mut self.clients[index].sessions;
                let (step, kind) = match client.confirm(OWNER) {
                    Ok(step) => (step, "confirm"),
                    Err(_) => (client.hello(OWNER).expect("a client HELLO"), "hello"),
                };
                let (frame, bytes) = self.bootstrap_frame(index, &step);
                self.send(frame, bytes);
                self.faults += i64::from(early);
                self.event("retry", &peer_name, kind);
            }
            "deliverToOwner" => {
                let f = f.expect("deliverToOwner picks a frame");
                let verdict = self.deliver_to_owner(Self::index_of(&peer_name), &f);
                self.event(action, &peer_name, &verdict);
            }
            "deliverToClient" => {
                let f = f.expect("deliverToClient picks a frame");
                let verdict = self.deliver_to_client(Self::index_of(&peer_name), &f);
                self.event(action, &peer_name, &verdict);
            }
            "clientData" => {
                let index = Self::index_of(&peer_name);
                let crc = self.crc;
                let end = &mut self.clients[index];
                let (frame, bytes) =
                    data_frame(crc, &mut end.sessions, &end.ring, OWNER, index, true);
                self.send(frame, bytes);
                self.event(action, &peer_name, "");
            }
            "ownerData" => {
                let index = Self::index_of(&peer_name);
                let (frame, bytes) = data_frame(
                    self.crc,
                    &mut self.owner,
                    &self.owner_ring,
                    PeerId(index as u16),
                    index,
                    false,
                );
                self.send(frame, bytes);
                self.event(action, &peer_name, "");
            }
            "lose" => {
                let f = f.expect("lose picks a frame");
                self.take(&f);
                self.faults += 1;
                self.event(action, &f.peer, "");
            }
            "duplicate" => {
                let f = f.expect("duplicate picks a frame");
                let at = self.position(&f);
                self.net[at].copies += 1;
                self.faults += 1;
                self.event(action, &f.peer, "");
            }
            "reboot" => {
                let index = Self::index_of(&peer_name);
                let end = &self.clients[index];
                let nonce = Nonce {
                    boot: end.nonce.boot + 1,
                    key: end.nonce.key,
                };
                let epoch = end.ring.epoch();
                self.clients[index] = Self::client(index, nonce, epoch);
                self.faults += 1;
                self.event(action, &peer_name, "");
            }
            "reopen" => {
                let index = Self::index_of(&peer_name);
                let end = &mut self.clients[index];
                let hello = end.sessions.hello(OWNER).expect("a client HELLO");
                end.opening = true;
                let (frame, bytes) = self.bootstrap_frame(index, &hello);
                self.send(frame, bytes);
                self.faults += 1;
                self.event(action, &peer_name, "");
            }
            "rekey" => self.rekey(),
            "stabilize" => {
                self.stable = true;
                self.event(action, "", "");
            }
            other => panic!("unsupported schedule: action {other:?}"),
        }
        self.index += 1;
        let mut counts = self.counts.borrow_mut();
        counts.actions += 1;
        counts.longest = counts.longest.max(self.index);
        *counts.per_action.entry(action.into()).or_default() += 1;
    }

    fn deliver_to_owner(&mut self, index: usize, f: &Frame) -> String {
        let (frame, bytes) = self.take(f);
        let peer = PeerId(index as u16);
        let parsed = parse(self.crc, &bytes, false).expect("a canonical frame");
        let Ok(authenticated) =
            self.owner_ring
                .authenticate(&parsed, peer, ENDPOINT, Direction::ClientToOwner)
        else {
            panic!("driver defect: the owner refused a frame sealed under its own key epoch");
        };
        match frame.kind.as_str() {
            "hello" => match self.owner.on_hello(&authenticated) {
                Ok(challenge) => {
                    let (frame, bytes) = self.bootstrap_frame(index, &challenge);
                    self.send(frame, bytes);
                    verdict(Ok(()))
                }
                Err(reject) => verdict(Err(reject)),
            },
            "confirm" => {
                let before = self.owner.view(peer).active;
                match self.owner.on_confirm(&authenticated) {
                    Ok(activation) => {
                        let activated = self.owner.view(peer).active != before;
                        let (frame, bytes) = self.bootstrap_frame(index, &activation.ready);
                        self.send(frame, bytes);
                        if activated { "activated" } else { "repeat" }.into()
                    }
                    Err(reject) => verdict(Err(reject)),
                }
            }
            _ => match self.owner.admit(&authenticated) {
                Ok(_) | Err(SessionReject::Duplicate | SessionReject::Stale) => verdict(Ok(())),
                Err(reject) => verdict(Err(reject)),
            },
        }
    }

    fn deliver_to_client(&mut self, index: usize, f: &Frame) -> String {
        let (frame, bytes) = self.take(f);
        let parsed = parse(self.crc, &bytes, false).expect("a canonical frame");
        let end = &mut self.clients[index];
        let Ok(authenticated) =
            end.ring
                .authenticate(&parsed, OWNER, ENDPOINT, Direction::OwnerToClient)
        else {
            panic!("driver defect: a client refused a frame sealed under its own key epoch");
        };
        match frame.kind.as_str() {
            "challenge" => match end.sessions.on_challenge(&authenticated) {
                Ok(confirm) => {
                    let (frame, bytes) = self.bootstrap_frame(index, &confirm);
                    self.send(frame, bytes);
                    verdict(Ok(()))
                }
                Err(reject) => verdict(Err(reject)),
            },
            "ready" => {
                let before = end.sessions.view(OWNER).active;
                match end.sessions.on_ready(&authenticated) {
                    Ok(_) if end.sessions.view(OWNER).active == before => "repeat".into(),
                    Ok(_) => {
                        end.opening = false;
                        "activated".into()
                    }
                    Err(reject) => verdict(Err(reject)),
                }
            }
            _ => match end.sessions.admit(&authenticated) {
                Ok(_) | Err(SessionReject::Duplicate | SessionReject::Stale) => verdict(Ok(())),
                Err(reject) => verdict(Err(reject)),
            },
        }
    }

    fn rekey(&mut self) {
        let key = self.owner_key + 1;
        let epoch = self.owner_ring.epoch() + 1;
        let entries = Self::owner_entries(key);
        let entries = entries.each_ref().map(|(principal, key)| KeyEntry {
            principal: *principal,
            key,
        });
        self.owner
            .rekey(
                &mut self.owner_ring,
                &entries,
                epoch,
                owner_nonce(key),
                RequestCensus::default(),
            )
            .expect("an owner re-key");
        for (index, end) in self.clients.iter_mut().enumerate() {
            let principal = PRINCIPALS[index];
            let bytes = key_of(principal, key);
            let nonce = Nonce {
                boot: end.nonce.boot,
                key,
            };
            end.sessions
                .rekey(
                    &mut end.ring,
                    &[KeyEntry {
                        principal,
                        key: &bytes,
                    }],
                    epoch,
                    client_nonce(index, nonce),
                    RequestCensus::default(),
                )
                .expect("a client re-key");
            end.nonce = nonce;
            end.opening = true;
        }
        self.owner_key = key;
        self.net.clear();
        self.rekeys += 1;
        self.faults += 1;
        self.event("rekey", "", "");
    }

    fn views(&self) -> (Vec<PeerView>, Vec<PeerView>) {
        let owner = (0..CLIENTS.len())
            .map(|i| self.owner.view(PeerId(i as u16)))
            .collect();
        let clients = self
            .clients
            .iter()
            .map(|end| end.sessions.view(OWNER))
            .collect();
        (owner, clients)
    }

    /// The rank sets of the current state: epochs per peer, and sequences per peer and client nonce.
    fn labels(&self) -> Labels {
        let (owner, clients) = self.views();
        let mut labels = Labels::default();
        for (index, name) in CLIENTS.iter().enumerate() {
            let epochs = labels.epochs.entry((*name).into()).or_default();
            let o = owner[index];
            epochs.insert(o.issued as i64);
            for h in [
                o.pending,
                o.active,
                clients[index].pending,
                clients[index].active,
            ]
            .into_iter()
            .flatten()
            {
                epochs.insert(h.0 as i64);
            }
            let end = &self.clients[index];
            labels
                .seqs
                .entry(((*name).into(), end.nonce))
                .or_default()
                .insert(clients[index].bootstrap_sent as i64);
            for floor in [o.active_floor, o.other_floor].into_iter().flatten() {
                labels
                    .seqs
                    .entry(((*name).into(), nonce_of(floor.0)))
                    .or_default()
                    .insert(floor.1 as i64);
            }
        }
        for entry in &self.net {
            labels
                .epochs
                .entry(entry.frame.peer.clone())
                .or_default()
                .insert(entry.frame.epoch);
            labels
                .seqs
                .entry((entry.frame.peer.clone(), entry.frame.client))
                .or_default()
                .insert(entry.frame.seq);
        }
        labels
    }

    /// The driver's state in the model's vocabulary, relabelled as the model relabels it.
    fn observe(&self) -> Observed {
        let labels = self.labels();
        let (owner, clients) = self.views();
        let epoch = |peer: &str, h: Option<(u64, [u8; 16])>| {
            handshake_of(h).map(|h| Handshake {
                epoch: labels.epoch(peer, h.epoch),
                ..h
            })
        };
        let floor = |peer: &str, f: Option<([u8; 16], u64)>| {
            floor_of(f).map(|f| Floor {
                highest: labels.seq(peer, f.nonce, f.highest),
                ..f
            })
        };
        let owner = CLIENTS
            .iter()
            .zip(&owner)
            .map(|(name, o)| {
                let view = OwnerPeer {
                    pending: epoch(name, o.pending),
                    active: epoch(name, o.active),
                    issued: labels.epoch(name, o.issued as i64),
                    active_floor: floor(name, o.active_floor),
                    other_floor: floor(name, o.other_floor),
                    displaced: o.displaced.map(nonce_of),
                };
                ((*name).into(), view)
            })
            .collect();
        let clients = CLIENTS
            .iter()
            .zip(clients.iter().zip(&self.clients))
            .map(|(name, (c, end))| {
                let view = Client {
                    nonce: end.nonce,
                    sent: labels.seq(name, end.nonce, c.bootstrap_sent as i64),
                    pending: epoch(name, c.pending),
                    active: epoch(name, c.active),
                    repeats: i64::from(c.confirm_repeats),
                    opening: end.opening,
                };
                ((*name).into(), view)
            })
            .collect();
        let net = self
            .net
            .iter()
            .map(|entry| (labels.frame(&entry.frame), entry.copies))
            .collect();
        Observed {
            s: Model {
                owner,
                clients,
                net,
                stable: self.stable,
                rekeys: self.rekeys,
                faults: self.faults,
                overflow: self.overflow,
            },
            last: self.last.clone(),
            index: self.index,
        }
    }
}

#[derive(Default)]
struct Labels {
    epochs: BTreeMap<String, BTreeSet<i64>>,
    seqs: BTreeMap<(String, Nonce), BTreeSet<i64>>,
}

impl Labels {
    fn epoch(&self, peer: &str, v: i64) -> i64 {
        self.epochs.get(peer).map_or(0, |values| rank(values, v))
    }

    fn seq(&self, peer: &str, nonce: Nonce, v: i64) -> i64 {
        self.seqs
            .get(&(peer.into(), nonce))
            .map_or(0, |values| rank(values, v))
    }

    fn frame(&self, raw: &Frame) -> Frame {
        Frame {
            epoch: self.epoch(&raw.peer, raw.epoch),
            seq: self.seq(&raw.peer, raw.client, raw.seq),
            ..raw.clone()
        }
    }
}

impl Driver for Replay {
    type State = Observed;

    fn step(&mut self, step: &Step) -> quint_connect::Result {
        let pick = |name: &str| step.nondet_picks.get(name).cloned();
        let peer = pick("peer").map(String::deserialize).transpose()?;
        let f = pick("f").map(Frame::deserialize).transpose()?;
        self.apply(&step.action_taken, peer, f);
        Ok(())
    }
}

/// One recorded state: the action that produced it, its picks and the expected projection.
struct Recorded {
    action: String,
    peer: Option<String>,
    f: Option<Frame>,
    expected: Observed,
}

/// A recorded trace's states.
fn recorded(text: &str) -> Vec<Recorded> {
    let trace: serde_json::Value = serde_json::from_str(text).expect("an ITF trace");
    trace["states"]
        .as_array()
        .expect("the trace's states")
        .iter()
        .map(|state| {
            let state = serde_json::from_value::<Value>(state.clone()).expect("an ITF state");
            let Value::Record(record) = state else {
                panic!("a trace state is a record");
            };
            let action = String::deserialize(
                record
                    .get("mbt::actionTaken")
                    .expect("mbt::actionTaken")
                    .clone(),
            )
            .expect("an action name");
            let Some(Value::Record(picks)) = record.get("mbt::nondetPicks") else {
                panic!("mbt::nondetPicks is a record");
            };
            let some = |name: &str| match picks.get(name) {
                Some(Value::Record(option))
                    if option.get("tag") == Some(&Value::String("Some".into())) =>
                {
                    option.get("value").cloned()
                }
                _ => None,
            };
            let peer = some("peer").map(|v| String::deserialize(v).expect("a peer"));
            let f = some("f").map(|v| Frame::deserialize(v).expect("a frame"));
            let expected =
                Observed::deserialize(Value::Record(record)).expect("the trace's projection");
            Recorded {
                action,
                peer,
                f,
                expected,
            }
        })
        .collect()
}

/// Replays a recorded trace and returns the first divergence, or the number of actions replayed.
fn replay(text: &str) -> Result<usize, String> {
    let mut driver = Replay::new(Rc::default());
    let steps = recorded(text);
    for step in &steps {
        driver.apply(&step.action, step.peer.clone(), step.f.clone());
        if let Some(divergence) = step.expected.divergence(&driver.observe()) {
            return Err(divergence);
        }
    }
    Ok(steps.len())
}

const CLEAN: &str = include_str!("q1_fixtures/clean_activation.itf.json");
const DISPLACEMENT: &str = include_str!("q1_fixtures/pending_displacement.itf.json");
const REPEAT_THEN_REKEY: &str = include_str!("q1_fixtures/repeat_then_rekey.itf.json");
const REOPEN_WINDOW: &str = include_str!("q1_fixtures/reopen_window.itf.json");

/// A clean activation replays: every action executes and every projected state matches.
#[test]
fn the_clean_activation_fixture_replays() {
    let steps = recorded(CLEAN);
    assert!(
        steps.iter().all(|step| step.expected.s.faults == 0),
        "the fixture holds no fault"
    );
    let last = &steps.last().expect("a nonempty trace").expected;
    assert!(last.s.clients["c1"].active.is_some());
    assert_eq!(replay(CLEAN), Ok(steps.len()));
}

/// The pending-displacement fixture replays: a stale HELLO from c1's older boot displaces the owner's pending handshake, the CONFIRM and its two repeats mismatch, and the fresh HELLO activates the session, with every projected state matching.
#[test]
fn the_pending_displacement_fixture_replays() {
    let steps = recorded(DISPLACEMENT);
    let displaced = steps.iter().position(|step| {
        step.action == "deliverToOwner"
            && step
                .f
                .as_ref()
                .is_some_and(|f| f.kind == "hello" && f.peer == "c1" && f.client.boot == 0)
            && step.expected.last.verdict == "accepted"
    });
    let displaced = displaced.expect("the older boot's HELLO is accepted");
    let after = &steps[displaced..];
    let mismatched = after
        .iter()
        .filter(|step| {
            step.action == "deliverToOwner"
                && step.f.as_ref().is_some_and(|f| f.kind == "confirm")
                && step.expected.last.verdict == "mismatch"
        })
        .count();
    assert_eq!(mismatched, 3, "the CONFIRM and its two repeats mismatch");
    assert!(
        after.iter().any(|step| {
            step.expected.last.act == "retry"
                && step.expected.last.verdict == "hello"
                && step.expected.last.peer == "c1"
        }),
        "the client restarts"
    );
    assert!(
        steps.last().expect("a nonempty trace").expected.s.clients["c1"]
            .active
            .is_some(),
        "the client activates"
    );
    assert_eq!(replay(DISPLACEMENT), Ok(steps.len()));
}

#[test]
fn the_repeat_then_rekey_fixture_replays() {
    let steps = recorded(REPEAT_THEN_REKEY);
    let rekey = steps
        .iter()
        .position(|step| step.action == "rekey")
        .expect("a re-key");
    assert!(
        steps[..rekey].iter().any(
            |step| step.expected.last.act == "retry" && step.expected.last.verdict == "confirm"
        ),
        "c1 repeats its CONFIRM before the re-key"
    );
    assert_eq!(steps[rekey - 1].expected.s.clients["c1"].repeats, 1);
    assert_eq!(steps[rekey].expected.s.clients["c1"].repeats, 0);
    assert_eq!(replay(REPEAT_THEN_REKEY), Ok(steps.len()));
}

/// The reopen-window fixture replays: client c1 activates, reopens beside its active session, and the owner activates the new handshake while c1 still holds the replaced one, with every projected state matching.
#[test]
fn the_reopen_window_fixture_replays() {
    let steps = recorded(REOPEN_WINDOW);
    let reopened = steps
        .iter()
        .position(|step| step.action == "reopen" && step.expected.last.peer == "c1")
        .expect("c1 reopens");
    let before = &steps[reopened].expected.s.clients["c1"];
    assert!(
        before.active.is_some() && before.opening,
        "the reopen leaves the active session and starts an opening"
    );
    let last = &steps.last().expect("a nonempty trace").expected.s;
    let (client, owner) = (last.clients["c1"].active, last.owner["c1"].active);
    assert!(
        client.is_some_and(|c| owner.is_some_and(|o| o.client == c.client && o.epoch > c.epoch)),
        "the owner holds the later handshake of the same client nonce"
    );
    assert_eq!(replay(REOPEN_WINDOW), Ok(steps.len()));
}

/// The comparison names the action index, the field and both values: a fixture whose recorded verdict at one action is altered, or with one action removed, fails at that action.
#[test]
fn an_altered_or_shortened_trace_fails_at_the_action_it_changes() {
    let mut trace: serde_json::Value = serde_json::from_str(DISPLACEMENT).expect("JSON");
    let states = trace["states"].as_array_mut().expect("states");
    let at = states
        .iter()
        .position(|s| s["replay::Q::last"]["verdict"] == "mismatch")
        .expect("a mismatch");
    states[at]["replay::Q::last"]["verdict"] = "accepted".into();
    let failure = replay(&trace.to_string()).expect_err("an altered verdict diverges");
    assert!(
        failure.starts_with(&format!("action {}: last:", at + 1)),
        "{failure}"
    );
    assert!(
        failure.contains("verdict: \"accepted\"") && failure.contains("verdict: \"mismatch\""),
        "{failure}"
    );

    let mut trace: serde_json::Value = serde_json::from_str(DISPLACEMENT).expect("JSON");
    let states = trace["states"].as_array_mut().expect("states");
    let at = states
        .iter()
        .position(|s| s["mbt::actionTaken"] == "reboot")
        .expect("a reboot");
    states.remove(at);
    let failure = replay(&trace.to_string()).expect_err("a skipped action diverges");
    assert!(
        failure.starts_with(&format!("action {}: ", at + 1)),
        "{failure}"
    );
}

#[test]
#[should_panic(expected = "code defect: a bootstrap step for c2 names peer PeerId(1)")]
fn a_bootstrap_step_naming_another_peer_is_a_code_defect() {
    let mut replay = Replay::new(Rc::default());
    let mut hello = replay.clients[1]
        .sessions
        .hello(OWNER)
        .expect("a client HELLO");
    hello.peer = PeerId(1);
    replay.bootstrap_frame(1, &hello);
}

/// Quint Connect generates traces of `quint/replay.qnt` and replays each action against `Sessions`, comparing every projected state. The report line counts executions of each action; `quint/check.py` reads the model's actions from `quint/session.qnt` and requires every action to be reached. Quint Connect requires `quint` on `PATH`, which the scheduled `quint` lane provides.
#[test]
#[ignore = "generated Q1 traces; the quint lane runs it with Quint on PATH"]
fn connect_replays_generated_q1_traces() {
    let counts: Rc<RefCell<Counts>> = Rc::default();
    let spec = concat!(env!("CARGO_MANIFEST_DIR"), "/../../quint/replay.qnt");
    // 50 traces of `step`, then 10 of the reopen recipe, which `step`'s random traces never reach.
    let batches = [(None, 50), (Some("openThenReopen"), 10)];
    for (step, samples) in batches {
        let config = quint_connect::runner::Config {
            test_name: "connect_replays_generated_q1_traces".into(),
            gen_config: quint_connect::runner::RunConfig {
                spec: spec.into(),
                main: Some("replay".into()),
                init: None,
                step: step.map(Into::into),
                max_samples: Some(samples),
                max_steps: Some(40),
                seed: "0x52".into(),
            },
        };
        let result = quint_connect::runner::run_test(Replay::new(Rc::clone(&counts)), config);
        let divergence = DIVERGENCE.with(|slot| slot.borrow().clone());
        if let Err(error) = result {
            panic!(
                "replay diverged: {}; {error:#}",
                divergence.unwrap_or_else(|| "no field recorded".into())
            );
        }
    }
    let counts = counts.borrow();
    assert_eq!(counts.traces, 60, "every generated trace replayed");
    let per_action: Vec<String> = counts
        .per_action
        .iter()
        .map(|(action, n)| format!("{action}:{n}"))
        .collect();
    println!(
        "q1 connect replay: traces={} actions={} longest={} per_action={} agreement=all",
        counts.traces,
        counts.actions,
        counts.longest,
        per_action.join(",")
    );
}
