//! The client endpoint against a test owner over the seeded simulated link.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use crate::sim::round::{Act, Actor, round};
use crate::storage::seeded::SplitMix64;
use crate::storage::{CacheVersion, Crc32c, EngineBudget};

use super::auth::{KeyEntry, KeyRing};
use super::client::{
    AdmissionRefusals, Client, ClientConfig, ClientMemory, GetRefused, SessionState,
};
use super::datagram::{DatagramError, Datagrams, HEADER_LEN, Outgoing, Payload, PeerId, Received};
use super::ena_hardware_tests::hex;
use super::fetch::{Decider, FetchConfig, Outcome, OutcomeCounts, Releases, Terminal};
use super::frame::{Direction, Header, Kind, Status, encode, parse, seal};
use super::frame_tests::put_frame;
use super::link::{Faults, LinkEnd, Net, network};
use super::packet::{PacketLease, PacketPool};
use super::requests::{RequestId, RequestTable};
use super::serve::{GetOutcome, Manifest, ReadEnd, ServeConfig, header};
use super::serve_tests::Core;
use super::session::{Bootstrap, CONFIRM_REPEATS, Caps, Role, Sessions};
use super::upload::UploadOutcome;

const ENDPOINT: u32 = 0x00E1_0001;
const PRINCIPAL: u32 = 0x0000_0C11;
const KEY: [u8; 32] = [0x6B; 32];
const CAPS: Caps = Caps {
    slots: 8,
    window: 8,
};

const CONFIG: ClientConfig = ClientConfig {
    endpoint: ENDPOINT,
    principal: PRINCIPAL,
    caps: CAPS,
    fetch: FetchConfig {
        retry_us: 3_000,
        attempts: 20,
        window: 8,
        boxes: 24,
    },
    upload: super::upload::UploadConfig {
        retry_us: 3_000,
        attempts: 20,
    },
    bootstrap_retry_us: 5_000,
    bootstrap_attempts: 4,
    batch: 8,
};

const SERVE: ServeConfig = ServeConfig {
    retry_us: 2_000,
    attempts: 50,
    linger_us: 50_000,
    rate_per_sec: 10_000_000,
    burst: 64,
    slots: 8,
    replies: 8,
    max_wait_us: 30_000_000,
};

fn keys() -> [KeyEntry<'static>; 1] {
    [KeyEntry {
        principal: PRINCIPAL,
        key: &KEY,
    }]
}

/// A receive pool of 40 buffers with 8 reserved for control, so 32 data buffers back the client's 24.
fn receive_pool() -> PacketPool<'static> {
    super::packet::test_pool(40, 8).unwrap()
}

fn releases() -> Releases {
    Releases::new(8, &mut EngineBudget::new(1 << 20)).unwrap()
}

pub(super) fn routes() -> std::sync::Arc<super::ShardRoutes> {
    let capacity = std::num::NonZeroU32::new(8).unwrap();
    std::sync::Arc::new(super::ShardRoutes::new(capacity, &mut EngineBudget::new(1 << 20)).unwrap())
}

fn client<'m, D: Datagrams<'m>>(
    pool: &'m PacketPool<'m>,
    releases: &'m Releases,
    transport: D,
) -> Client<'m, D> {
    client_with(pool, releases, transport, CONFIG)
}

fn client_with<'m, D: Datagrams<'m>>(
    pool: &'m PacketPool<'m>,
    releases: &'m Releases,
    transport: D,
    config: ClientConfig,
) -> Client<'m, D> {
    client_with_nonce(pool, releases, transport, config, super::auth::os_entropy)
}

/// A client under `config` over `transport` whose boot nonce `nonce` fills.
fn client_with_nonce<'m, D: Datagrams<'m>>(
    pool: &'m PacketPool<'m>,
    releases: &'m Releases,
    transport: D,
    config: ClientConfig,
    nonce: impl FnOnce(&mut [u8; 16]) -> Result<(), super::auth::EntropyError>,
) -> Client<'m, D> {
    let memory = ClientMemory {
        receive: pool,
        releases,
        requests: RequestTable::new(8, 1, 8),
        sources: Box::default(),
        routes: routes(),
    };
    Client::initialize_with_nonce(
        config,
        memory,
        transport,
        &keys(),
        1,
        &mut EngineBudget::new(1 << 24),
        nonce,
    )
    .unwrap()
}

/// A test owner: its key ring, session table and transfer core, and the objects it stores; a `refusal` answers every GET with that status.
struct Owner {
    crc: Crc32c,
    ring: KeyRing,
    sessions: Sessions,
    serve: Core<Box<[u8]>>,
    pool: &'static PacketPool<'static>,
    objects: Vec<([u8; 32], Vec<u8>)>,
    refusal: Option<Status>,
    /// The owner takes no turn, as an owner that stopped answering.
    silent: bool,
}

impl Owner {
    fn new(objects: Vec<([u8; 32], Vec<u8>)>) -> Self {
        Self::booted(objects, [0x0A; 16])
    }

    fn booted(objects: Vec<([u8; 32], Vec<u8>)>, nonce: [u8; 16]) -> Self {
        Self::sized(objects, nonce, CAPS, SERVE)
    }

    /// A test owner of boot nonce `nonce` whose sessions take `caps` and whose serve core runs `serve` over a
    /// request table of `serve.slots` slots.
    fn sized(
        objects: Vec<([u8; 32], Vec<u8>)>,
        nonce: [u8; 16],
        caps: Caps,
        serve: ServeConfig,
    ) -> Self {
        let mut budget = EngineBudget::new(1 << 26);
        let table = RequestTable::new(serve.slots, 1, serve.slots);
        Self {
            crc: Crc32c::detect(),
            ring: KeyRing::load(&[PRINCIPAL], &keys(), 1, &mut budget).unwrap(),
            sessions: Sessions::new(Role::Owner, nonce, caps, 1, &mut budget).unwrap(),
            serve: Core::new(serve, table, 1, 16, 0, 4, &mut budget).unwrap(),
            pool: Box::leak(Box::new(super::packet::test_pool(16, 8).unwrap())),
            objects,
            refusal: None,
            silent: false,
        }
    }

    /// One owner turn at `now_us` over `end`: receive, bootstrap and request handling, timers, then sends.
    fn turn<'a, D: Datagrams<'a>>(&mut self, end: &mut D, now_us: u64) {
        if self.silent {
            return;
        }
        let mut leases: [Option<PacketLease<'_>>; 8] = std::array::from_fn(|_| None);
        let mut meta = [Received::default(); 8];
        let got = end.receive(self.pool, &mut leases, &mut meta).unwrap_or(0);
        let mut replies = Vec::new();
        for (lease, meta) in leases.iter().zip(meta).take(got) {
            let (Some(lease), Some(peer)) = (lease, meta.peer) else {
                continue;
            };
            for bytes in super::rules::frames_of(lease.bytes()) {
                self.frame(bytes, meta.truncated, peer, now_us, &mut replies);
            }
        }
        drop(leases);
        for reply in &replies {
            self.send_bootstrap(end, reply);
        }
        self.serve.tick(now_us);
        self.serve.release_drained(|_| true);
        let Self {
            serve,
            sessions,
            ring,
            crc,
            ..
        } = self;
        serve.poll(now_us, 16, |frames| {
            let mut taken = 0;
            for frame in frames {
                let (Some((owner_nonce, client_nonce)), Ok(sequence)) = (
                    sessions.nonces(frame.peer),
                    sessions.next_sequence(frame.peer),
                ) else {
                    taken += 1;
                    continue;
                };
                let header = Header {
                    principal: PRINCIPAL,
                    key_epoch: 1,
                    owner_nonce,
                    client_nonce,
                    sequence,
                    epoch: frame.epoch,
                    datagram_len: (frame.payload[0].len() + frame.payload[1].len()) as u32,
                    ..frame.header
                };
                let payload = [frame.payload[0].bytes(), frame.payload[1].bytes()];
                if !sealed_send(*crc, ring, end, &header, payload) {
                    break;
                }
                taken += 1;
            }
            taken
        });
    }

    /// Handles one frame of a received datagram as a lone datagram of its bytes.
    fn frame(
        &mut self,
        bytes: &[u8],
        truncated: bool,
        peer: PeerId,
        now_us: u64,
        replies: &mut Vec<Bootstrap>,
    ) {
        let Ok(frame) = parse(self.crc, bytes, truncated) else {
            return;
        };
        let Ok(frame) = self
            .ring
            .authenticate(&frame, peer, ENDPOINT, Direction::ClientToOwner)
        else {
            return;
        };

        let header = frame.header();
        match header.kind {
            Kind::Hello => replies.extend(self.sessions.on_hello(&frame).ok()),
            Kind::Confirm => {
                if let Ok(activation) = self.sessions.on_confirm(&frame) {
                    if activation.replaced.is_some() {
                        self.serve.retire_peer(peer, now_us);
                    }
                    replies.push(activation.ready);
                }
            }
            Kind::Get | Kind::Ack | Kind::Cancel => {
                let Ok(session) = self.sessions.admit(&frame) else {
                    return;
                };
                match header.kind {
                    Kind::Get => self.get(session, &header, now_us),
                    Kind::Ack => self.serve.ack(session, &header, now_us),
                    _ => self.serve.cancel(session, &header, now_us),
                }
            }
            _ => {}
        }
    }

    fn get(&mut self, session: super::session::Admitted, header: &Header, now_us: u64) {
        let GetOutcome::Read { id, .. } = self.serve.get(session, header, now_us) else {
            return;
        };
        let object = self.objects.iter().find(|(key, _)| *key == header.key);
        match (self.refusal, object) {
            (Some(status), _) => self.serve.read_refused(id, status, now_us),
            (None, None) => self.serve.read_refused(id, Status::Missing, now_us),
            (None, Some((_, payload))) => {
                let manifest = Manifest {
                    allocation: 0x5_0000_0001,
                    metadata_len: 0,
                    body_len: payload.len() as u32,
                };
                let total = payload.len() as u64;
                let chunk: Box<[u8]> = payload.clone().into();
                self.serve.read_started(id);
                if total > 0 {
                    self.serve.chunk(id, manifest, 0..total, chunk, &[], now_us);
                }
                self.serve
                    .read_done(id, ReadEnd::Complete(manifest), now_us);
            }
        }
    }

    fn send_bootstrap<'a, D: Datagrams<'a>>(&mut self, end: &mut D, step: &Bootstrap) {
        let body = super::frame_tests::bootstrap_body(step);
        let header = Header {
            principal: PRINCIPAL,
            key_epoch: 1,
            owner_nonce: step.owner_nonce,
            client_nonce: step.client_nonce,
            sequence: step.sequence,
            epoch: step.epoch,
            datagram_len: body.len() as u32,
            ..header(step.kind, 0, [0; 32])
        };
        sealed_send(self.crc, &self.ring, end, &header, [&body, &[]]);
    }
}

/// Encodes `header` over `payload` and seals it with `ring`'s tag for peer 0 as `direction` sends it.
fn sealed_header(
    crc: Crc32c,
    ring: &KeyRing,
    header: &Header,
    payload: [&[u8]; 2],
    direction: Direction,
) -> [u8; HEADER_LEN] {
    let mut encoded = [0u8; HEADER_LEN];
    encode(crc, header, payload, &mut encoded).expect("canonical");
    let mut digest = [0; 16];
    let input = ring
        .mac_input(
            PeerId(0),
            &encoded,
            payload,
            (ENDPOINT, direction),
            &mut digest,
        )
        .expect("a canonical frame");
    let tag = ring.tag(PeerId(0), &input).expect("a key");
    seal(&mut encoded, tag);
    encoded
}

/// Encodes, tags and sends one owner frame, returning whether the transport took or failed it.
fn sealed_send<'a, D: Datagrams<'a>>(
    crc: Crc32c,
    ring: &KeyRing,
    end: &mut D,
    header: &Header,
    payload: [&[u8]; 2],
) -> bool {
    let encoded = sealed_header(crc, ring, header, payload, Direction::OwnerToClient);
    end.send(&[Outgoing {
        peer: PeerId(0),
        header: &encoded,
        payload: [Payload::Inline(payload[0]), Payload::Inline(payload[1])],
    }])
    .map_or(true, |sent| sent == 1)
}

fn object(len: usize, seed: u64) -> Vec<u8> {
    let mut rng = SplitMix64::new(seed);
    (0..len).map(|_| rng.next_u64() as u8).collect()
}

/// Turns both ends over the simulated network from turn `start`, 100 µs per turn, each turn as one controller round, until `done` holds or `turns` pass; returns the turn reached.
fn drive<'m, D: Datagrams<'m>>(
    client: &mut Client<'m, D>,
    owner: &mut Owner,
    owner_end: &mut LinkEnd<'_>,
    net: &Rc<RefCell<Net<'_>>>,
    start: u64,
    turns: u64,
    mut done: impl FnMut(&mut Client<'m, D>) -> bool,
) -> u64 {
    for turn in start..start + turns {
        round(&mut [
            Act::new(Actor::Link(0), &mut || net.borrow_mut().advance(turn)),
            Act::new(Actor::Client(0), &mut || {
                let _ = client.poll(turn * 100);
            }),
            Act::new(Actor::Double(0), &mut || owner.turn(owner_end, turn * 100)),
        ]);
        if done(client) {
            return turn + 1;
        }
    }
    start + turns
}

fn active<'m, D: Datagrams<'m>>(client: &mut Client<'m, D>) -> bool {
    client.state() == SessionState::Active
}

/// A session opens through the bootstrap; each GET then yields its fragments in order with exact bytes and exactly one `Complete`, each logical GET is a fresh lookup at the owner, and a missing key ends `Missing`.
#[test]
fn a_session_and_gets_deliver_ordered_fragments_and_one_outcome() {
    let source = object(70_000, 1);
    let pool = receive_pool();
    let releases = releases();
    let (client_end, mut owner_end, net) = network(64, 8384, 3, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![([1; 32], source.clone())]);
    let mut client = client(&pool, &releases, client_end);
    assert_eq!(
        client.get([1; 32], 0, 1 << 20, 0, 1_000_000),
        Err(GetRefused::NoSession)
    );
    assert_eq!(
        client.put([1; 32], CacheVersion(0), 0, 1_000_000),
        Err(super::client::PutRefused::NoSession)
    );
    assert_eq!(
        client.invalidate([1; 32], 0, 1),
        Err(super::client::PutRefused::NoSession)
    );
    client.session(0);
    let mut turn = drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        0,
        1_000,
        active,
    );
    assert_eq!(client.state(), SessionState::Active);
    for _ in 0..2 {
        let id = client
            .get([1; 32], 0, 1 << 20, turn * 100, 1_000_000)
            .unwrap();
        let mut bytes = Vec::new();
        let mut outcomes = Vec::new();
        turn = drive(
            &mut client,
            &mut owner,
            &mut owner_end,
            &net,
            turn,
            5_000,
            |client| {
                while let Some(fragment) = client.take(id) {
                    assert_eq!(fragment.offset(), bytes.len() as u64, "in order");
                    bytes.extend_from_slice(fragment.bytes());
                }
                outcomes.extend(client.outcome(id));
                !outcomes.is_empty()
            },
        );
        assert_eq!(outcomes, [Outcome::Complete]);
        assert_eq!(bytes, source);
        assert!(client.retire(id));
    }
    assert_eq!(
        owner.serve.report().requests,
        2,
        "a fresh lookup per logical GET"
    );
    let missing = client
        .get([2; 32], 0, 1 << 20, turn * 100, 1_000_000)
        .unwrap();
    drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        turn,
        5_000,
        |client| client.outcome(missing).is_some(),
    );
    assert_eq!(client.outcome(missing), Some(Outcome::Missing));
}

/// Owner pressure statuses reach the application as their own outcome, so storage and retransmission pressure stay distinct, and the client's own receive pressure refuses a GET before it starts.
#[test]
fn pressure_outcomes_name_their_resource() {
    let pool = receive_pool();
    let releases = releases();
    let (client_end, mut owner_end, net) = network(64, 8384, 4, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![([1; 32], object(1000, 2))]);
    let mut client = client(&pool, &releases, client_end);
    client.session(0);
    let mut turn = drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        0,
        1_000,
        active,
    );
    for status in [Status::StoragePressure, Status::RetransmissionPressure] {
        owner.refusal = Some(status);
        let id = client
            .get([1; 32], 0, 1 << 20, turn * 100, 1_000_000)
            .unwrap();
        turn = drive(
            &mut client,
            &mut owner,
            &mut owner_end,
            &net,
            turn,
            5_000,
            |client| client.outcome(id).is_some(),
        );
        assert_eq!(client.outcome(id), Some(Outcome::Pressure(status)));
        assert!(client.retire(id));
    }
    for key in 0..3 {
        client
            .get([key; 32], 0, 1 << 20, turn * 100, 1_000_000)
            .unwrap();
    }
    assert_eq!(
        client.get([9; 32], 0, 1 << 20, turn * 100, 1_000_000),
        Err(GetRefused::ReceivePressure),
        "three windows of eight reserve all 24 boxes"
    );
    let refused = client.refusals();
    assert_eq!(
        (
            refused.receive_pressure,
            refused.no_session,
            refused.request_pressure
        ),
        (1, 0, 0),
        "the refused GET counts under its cause"
    );
}

/// Leases taken before a timeout, a cancel and the client's close stay readable after each, and every box returns to its pool once they drop.
#[test]
fn leases_outlive_poll_timeout_cancel_and_close() {
    let source = object(90_000, 5);
    let pool = receive_pool();
    let releases = releases();
    let (client_end, mut owner_end, net) = network(64, 8384, 5, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![([1; 32], source.clone())]);
    let mut held = Vec::new();
    let mut client = client(&pool, &releases, client_end);
    client.session(0);
    let turn = drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        0,
        1_000,
        active,
    );
    let timed = client.get([1; 32], 0, 1 << 20, turn * 100, 3_000).unwrap();
    let cancelled = client
        .get([1; 32], 0, 1 << 20, turn * 100, 1_000_000)
        .unwrap();
    let open = client
        .get([1; 32], 0, 1 << 20, turn * 100, 1_000_000)
        .unwrap();
    let mut taken = [0; 3];
    let turn = drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        turn,
        20,
        |client| {
            for (at, id) in [timed, cancelled, open].into_iter().enumerate() {
                if let Some(fragment) = client.take(id) {
                    taken[at] += 1;
                    held.push(fragment);
                }
            }
            false
        },
    );
    assert!(
        taken.iter().all(|count| *count > 0),
        "fragments of every request were taken: {taken:?}"
    );
    client.cancel(cancelled);
    drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        turn,
        100,
        |client| client.outcome(timed).is_some(),
    );
    assert_eq!(
        client.outcome(timed),
        Some(Outcome::Incomplete(Status::TimedOut))
    );
    assert_eq!(
        client.outcome(cancelled),
        Some(Outcome::Incomplete(Status::Cancelled))
    );
    let (closed, _transport) = client.close((turn + 100) * 100);
    assert!(
        closed.sent >= 1 && !closed.blocked,
        "the open request's CANCEL went out: {closed:?}"
    );
    for fragment in &held {
        let start = fragment.offset() as usize;
        assert_eq!(
            fragment.bytes(),
            &source[start..start + fragment.bytes().len()]
        );
    }
    assert!(pool.report().data > 0, "the held leases keep their boxes");
    drop(held);
    assert_eq!(pool.report().data, 0, "every box returned to its pool");
}

/// With no owner answering, the opening ends `Failed` after its bounded resends; once an owner that served a session dies, a GET ends with an explicit outcome by its deadline, and a fresh opening ends `Failed` while the old session still accepts GETs.
#[test]
fn an_absent_owner_yields_bounded_outcomes() {
    let pool = receive_pool();
    let releases = releases();
    {
        let (client_end, _owner_end, _net) = network(64, 8384, 6, [Faults::default(); 2]);
        let mut client = client(&pool, &releases, client_end);
        client.session(0);
        let mut turn = 0;
        while client.state() == SessionState::Opening && turn < 10_000 {
            client.poll(turn * 100);
            turn += 1;
        }
        assert_eq!(client.state(), SessionState::Failed);
        let bound =
            (u64::from(CONFIG.bootstrap_attempts) + 1) * CONFIG.bootstrap_retry_us / 100 + 2;
        assert!(turn <= bound, "failed at turn {turn}, bound {bound}");
    }
    let (client_end, mut owner_end, net) = network(64, 8384, 7, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![([1; 32], object(500_000, 6))]);
    let mut client = client(&pool, &releases, client_end);
    client.session(0);
    let turn = drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        0,
        1_000,
        active,
    );
    let id = client.get([1; 32], 0, 1 << 20, turn * 100, 50_000).unwrap();
    net.borrow_mut().kill(1);
    let mut last = turn;
    while client.outcome(id).is_none() && last < turn + 1_000 {
        client.poll(last * 100);
        last += 1;
    }
    assert!(
        matches!(
            client.outcome(id),
            Some(Outcome::Incomplete(Status::TimedOut) | Outcome::Failed(Status::TimedOut))
        ),
        "{:?}",
        client.outcome(id)
    );
    assert!(
        last * 100 <= turn * 100 + 50_000 + 200,
        "within the deadline"
    );
    client.session(last * 100);
    let mut turn = last;
    while client.state() == SessionState::Opening && turn < last + 10_000 {
        client.poll(turn * 100);
        turn += 1;
    }
    assert_eq!(
        client.state(),
        SessionState::Failed,
        "a fresh opening that spent its resends fails beside the active session"
    );
    assert!(
        client.get([1; 32], 0, 1 << 20, turn * 100, 50_000).is_ok(),
        "the active session still serves GETs"
    );
}

/// A fresh session that replaces the active one ends the old session's live requests with `SessionMismatch`.
#[test]
fn a_session_change_ends_old_requests() {
    let pool = receive_pool();
    let releases = releases();
    let (client_end, mut owner_end, net) = network(64, 8384, 8, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![]);
    let mut client = client(&pool, &releases, client_end);
    client.session(0);
    let turn = drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        0,
        1_000,
        active,
    );
    let old = client
        .get([1; 32], 0, 1 << 20, turn * 100, 10_000_000)
        .unwrap();
    client.poll(turn * 100);
    net.borrow_mut().clear(1);
    client.session(turn * 100);
    assert_eq!(client.state(), SessionState::Opening);
    drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        turn + 1,
        1_000,
        active,
    );
    assert_eq!(
        client.outcome(old),
        Some(Outcome::Failed(Status::SessionMismatch))
    );
    let terminal = client.terminal(old).unwrap();
    assert!(terminal.decided_by == Decider::Session && terminal.censored());
    assert_eq!(client.fetch_report().outcomes.session_ended, 1);
}

/// A restarted owner with a new boot nonce and a fresh session table names the same epoch as the session it lost; the client's fresh session activates at its first READY, ending the old session's requests with `SessionMismatch`, and the owner counts one activation.
#[test]
fn a_restarted_owner_reusing_the_epoch_replaces_the_session() {
    let pool = receive_pool();
    let releases = releases();
    let (client_end, mut owner_end, net) = network(64, 8384, 12, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![]);
    let mut client = client(&pool, &releases, client_end);
    client.session(0);
    let turn = drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        0,
        1_000,
        active,
    );
    let old = client
        .get([1; 32], 0, 1 << 20, turn * 100, 10_000_000)
        .unwrap();
    client.poll(turn * 100);
    net.borrow_mut().clear(1);
    let mut restarted = Owner::booted(vec![], [0x0B; 16]);
    client.session(turn * 100);
    drive(
        &mut client,
        &mut restarted,
        &mut owner_end,
        &net,
        turn + 1,
        1_000,
        active,
    );
    assert_eq!(
        client.outcome(old),
        Some(Outcome::Failed(Status::SessionMismatch))
    );
    assert_eq!(
        restarted.sessions.report().activations,
        1,
        "the first READY activated the session"
    );
}

/// A refused bootstrap frame, GET or CANCEL stays due with a deadline one
/// retry interval out, so a caller sleeping until the deadline wakes to resend
/// it and a caller looping on `poll` is not told to spin; the next poll that
/// sends clears the refusal.
#[test]
fn a_refused_send_stays_due_for_the_next_poll() {
    refused_sends(0, false);
}

#[test]
fn a_refused_send_goes_out_at_its_deadline() {
    refused_sends(7_000, true);
}

fn refused_sends(at: u64, at_deadline: bool) {
    let pool = receive_pool();
    let releases = releases();
    let (client_end, mut owner_end, net) = network(64, 8384, 9, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![]);
    let mut client = client(&pool, &releases, client_end);
    let refusing = Faults {
        would_block: 100,
        ..Faults::default()
    };
    client.session(at);
    assert_eq!(client.next_deadline_us(), Some(0), "the HELLO is due");
    net.borrow_mut().set_faults(1, refusing);
    let report = client.poll(at);
    assert_eq!((report.blocked, report.sent), (true, 0));
    assert_eq!(
        client.next_deadline_us(),
        Some(at + CONFIG.bootstrap_retry_us),
        "the refused HELLO waits one bootstrap retry for the next poll"
    );
    net.borrow_mut().set_faults(1, Faults::default());
    let resend = match at_deadline {
        true => at + CONFIG.bootstrap_retry_us,
        false => at + 100,
    };
    let report = client.poll(resend);
    assert_eq!((report.blocked, report.sent), (false, 1));
    let start = resend / 100 + 1;
    let mut turn = start;
    while client.state() != SessionState::Active && turn < start + 1_000 {
        round(&mut [
            Act::new(Actor::Link(0), &mut || net.borrow_mut().advance(turn)),
            Act::new(Actor::Client(0), &mut || {
                let _ = client.poll(turn * 100);
            }),
            Act::new(Actor::Double(0), &mut || {
                owner.turn(&mut owner_end, turn * 100)
            }),
        ]);
        turn += 1;
    }
    assert_eq!(client.state(), SessionState::Active);
    let now = turn * 100;
    client.poll(now);
    assert_eq!(
        client.next_deadline_us(),
        None,
        "an active, idle session has no timer"
    );
    let id = client.get([1; 32], 0, 1 << 20, now, 1_000_000).unwrap();
    assert_eq!(client.next_deadline_us(), Some(0), "the GET is due");
    net.borrow_mut().set_faults(1, refusing);
    let report = client.poll(now);
    assert_eq!((report.blocked, report.sent), (true, 0));
    let retry = now + CONFIG.fetch.retry_us;
    assert!(
        client
            .next_deadline_us()
            .is_some_and(|deadline| now < deadline && deadline <= retry),
        "the refused GET waits at most one fetch retry for the next poll"
    );
    net.borrow_mut().set_faults(1, Faults::default());
    let resend = match at_deadline {
        true => retry,
        false => now,
    };
    let report = client.poll(resend);
    assert_eq!(
        (report.blocked, report.sent),
        (false, 1),
        "the GET goes out"
    );
    assert!(
        client
            .next_deadline_us()
            .is_some_and(|deadline| deadline > 0),
        "a retry is armed"
    );
    client.cancel(id);
    net.borrow_mut().set_faults(1, refusing);
    let now = resend + 1;
    assert!(client.poll(now).blocked);
    assert_eq!(
        client.next_deadline_us(),
        Some(now + CONFIG.fetch.retry_us),
        "the refused CANCEL of a decided request waits one fetch retry"
    );
}

#[test]
fn a_refused_put_waits_one_upload_retry_not_one_fetch_retry() {
    let pool = receive_pool();
    let releases = releases();
    let (client_end, mut owner_end, net) = network(64, 8384, 9, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![]);
    let config = ClientConfig {
        fetch: FetchConfig {
            retry_us: 1_000_000,
            ..CONFIG.fetch
        },
        ..CONFIG
    };
    let mut client = client_with(&pool, &releases, client_end, config);
    client.session(0);
    let turn = drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        0,
        1_000,
        active,
    );
    assert!(active(&mut client));
    let now = turn * 100;
    client.put([1; 32], CacheVersion(0), now, 100_000).unwrap();
    let blocked = Faults {
        would_block: 100,
        ..Faults::default()
    };
    net.borrow_mut().set_faults(1, blocked);
    assert!(client.poll(now).blocked);
    assert_eq!(
        client.next_deadline_us(),
        Some(now + config.upload.retry_us),
        "the refused BEGIN waits one upload retry"
    );
}

/// A send batch GET frames fill keeps one send for the upload core's due frame, so GETs streaming fragments cannot hold a BEGIN unsent to its deadline.
#[test]
fn a_due_put_frame_is_sent_beside_a_full_get_batch() {
    let pool = receive_pool();
    let releases = releases();
    let (client_end, mut owner_end, net) = network(64, 8384, 9, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![([1; 32], object(2_000_000, 9))]);
    let mut client = client_with(
        &pool,
        &releases,
        client_end,
        ClientConfig { batch: 3, ..CONFIG },
    );
    client.session(0);
    let turn = drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        0,
        1_000,
        active,
    );
    assert!(active(&mut client));
    let now = turn * 100;
    let gets: Vec<_> = (0..3)
        .map(|_| client.get([1; 32], 0, 1 << 21, now, 10_000_000).unwrap())
        .collect();
    let id = client.put([2; 32], CacheVersion(0), now, 2_000).unwrap();
    for turn in turn..turn + 40 {
        round(&mut [
            Act::new(Actor::Link(0), &mut || net.borrow_mut().advance(turn)),
            Act::new(Actor::Client(0), &mut || {
                let _ = client.poll(turn * 100);
                for get in &gets {
                    while client.take(*get).is_some() {}
                }
            }),
            Act::new(Actor::Double(0), &mut || {
                owner.turn(&mut owner_end, turn * 100)
            }),
        ]);
    }
    assert_eq!(
        client.put_outcome(id),
        Some(UploadOutcome::Unknown),
        "the BEGIN was handed to a send before its deadline"
    );
}

/// The phase a [`put_shape_member`] upload reaches before its reply arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PutPhase {
    /// The client sent PREPARE and awaits READY.
    Prepared,
    Ready,
    /// Every fragment receipted, with a PREPARE resent since, so a matching ACK has a resend count to clear.
    Received,
    /// `Received`, then an `UnknownOutcome` ERROR settled the upload `Unknown`.
    Unknown,
}

/// The serial the test owner's AUTHORITY grants and the 3-fragment body the client prepares.
const PUT_SERIAL: u64 = 5;
const PUT_TOTAL: u32 = 3 * 8192;

/// Seals `header` as the test owner's next frame to the client under the live session's nonces, epoch and sequence, then polls the client at `turn`, which receives it.
fn deliver<'m, D: Datagrams<'m>>(
    client: &mut Client<'m, D>,
    owner: &mut Owner,
    end: &mut LinkEnd<'_>,
    net: &Rc<RefCell<Net<'_>>>,
    header: Header,
    turn: u64,
) -> super::client::PollReport {
    let admitted = owner.sessions.active(PeerId(0)).unwrap();
    let (owner_nonce, client_nonce) = owner.sessions.nonces(PeerId(0)).unwrap();
    let header = Header {
        principal: PRINCIPAL,
        key_epoch: 1,
        owner_nonce,
        client_nonce,
        sequence: owner.sessions.next_sequence(PeerId(0)).unwrap(),
        epoch: admitted.epoch,
        ..header
    };
    let mut encoded = [0u8; HEADER_LEN];
    encode(owner.crc, &header, [&[], &[]], &mut encoded).unwrap();
    assert!(
        parse(owner.crc, &encoded, false).is_ok(),
        "the reply is a canonical frame"
    );
    assert!(sealed_send(
        owner.crc,
        &owner.ring,
        end,
        &header,
        [&[], &[]]
    ));
    net.borrow_mut().advance(turn);
    client.poll(turn * 100)
}

/// Polls the client at `turn` with nothing new in flight.
fn quiet<'m, D: Datagrams<'m>>(client: &mut Client<'m, D>, net: &Rc<RefCell<Net<'_>>>, turn: u64) {
    net.borrow_mut().advance(turn);
    let _ = client.poll(turn * 100);
}

/// A client upload under an authenticated session reaches `phase`; then a sealed, canonical `kind` reply for its request, key and serial carrying `foreign`'s manifest leaves the upload's whole state unchanged and counts one dropped frame, and the same reply under the prepared manifest is taken and changes it. `edit` sets each reply's kind-specific fields, an ACK's receipt index and grant or a READY's grant, and may tell the two replies apart by their count. In `Received` the client supplied fragments 0 and 1, and the full ACK receipts all three, an owner receipt the dispatch accepts. Returns the upload's outcome, receipt and whole state after the matching reply, for the caller's effect check.
fn put_shape_member(
    phase: PutPhase,
    kind: Kind,
    foreign: Manifest,
    edit: impl Fn(&mut Header),
) -> (Option<UploadOutcome>, Option<(u64, u32, u32)>, String) {
    let member = format!("{kind:?} in {phase:?}");
    let pool = receive_pool();
    let releases = releases();
    let shared = crate::storage::owner_fixture::arena(4);
    let sources = super::memory::sources(&shared, 4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, mut owner_end, net) = network(64, 8384, 41, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![]);
    let memory = ClientMemory {
        receive: &pool,
        releases: &releases,
        requests: RequestTable::new(8, 1, 8),
        sources,
        routes: routes(),
    };
    let mut client = Client::initialize(
        CONFIG,
        memory,
        client_end,
        &keys(),
        1,
        &mut EngineBudget::new(1 << 24),
    )
    .unwrap();
    client.session(0);
    let mut turn = drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        0,
        1_000,
        active,
    );
    assert!(active(&mut client));
    let key = [7; 32];
    let id = client
        .put(key, CacheVersion(0), turn * 100, 1 << 40)
        .unwrap();
    let wire = client.put_wire(id).unwrap();
    let base = header(Kind::PutAuthority, wire, key);
    let shaped = |kind: Kind, manifest: &Manifest| Header {
        status: 0,
        ..super::serve::manifest_header(kind, wire, key, manifest)
    };
    let prepared = Manifest {
        allocation: PUT_SERIAL,
        metadata_len: 0,
        body_len: PUT_TOTAL,
    };
    quiet(&mut client, &net, turn);
    let (authority, _) = put_frame(Kind::PutAuthority, &base);
    deliver(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        authority,
        turn,
    );
    client.prepare(id, 0, PUT_TOTAL, 60_000).unwrap();
    turn += 1;
    quiet(&mut client, &net, turn);
    if phase != PutPhase::Prepared {
        let ready = Header {
            grant: 2,
            ..shaped(Kind::PutReady, &prepared)
        };
        turn += 1;
        assert_eq!(
            deliver(&mut client, &mut owner, &mut owner_end, &net, ready, turn).dropped,
            0,
            "{member}: READY"
        );
        let object = object(PUT_TOTAL as usize, 41);
        for index in 0..2 {
            let at = index * 8192;
            assert!(
                client
                    .supply(id, index as u32, &object[at..at + 8192])
                    .is_ok()
            );
        }
        turn += 1;
        quiet(&mut client, &net, turn);
        assert_eq!(
            client.put_receipt(id),
            Some((PUT_SERIAL, 0, 2)),
            "{member}: ready"
        );
    }
    if matches!(phase, PutPhase::Received | PutPhase::Unknown) {
        let full = Header {
            index: 3,
            grant: 3,
            ..shaped(Kind::PutAck, &prepared)
        };
        turn += 1;
        assert_eq!(
            deliver(&mut client, &mut owner, &mut owner_end, &net, full, turn).dropped,
            0,
            "{member}: full ACK"
        );
        // A retry interval later the upload resends its PREPARE.
        turn += CONFIG.upload.retry_us / 100 + 1;
        quiet(&mut client, &net, turn);
        assert_eq!(
            client.put_receipt(id).map(|(_, base, _)| base),
            Some(3),
            "{member}: received"
        );
        assert!(
            client.upload_snapshot(id).contains("sends: 1"),
            "{member}: the PREPARE was resent"
        );
    }
    if phase == PutPhase::Unknown {
        let unknown = Header {
            allocation: PUT_SERIAL,
            status: Status::UnknownOutcome as u16,
            ..header(Kind::PutError, wire, key)
        };
        turn += 1;
        assert_eq!(
            deliver(&mut client, &mut owner, &mut owner_end, &net, unknown, turn).dropped,
            0,
            "{member}: ERROR"
        );
        assert_eq!(client.put_outcome(id), Some(UploadOutcome::Unknown));
    }
    turn += 1;
    quiet(&mut client, &net, turn);
    let before = client.upload_snapshot(id);
    let admitted = client.session_report();
    let mut wrong = shaped(kind, &foreign);
    edit(&mut wrong);
    assert_eq!(
        deliver(&mut client, &mut owner, &mut owner_end, &net, wrong, turn).dropped,
        1,
        "{member}: dropped"
    );
    assert_eq!(client.upload_snapshot(id), before, "{member}: unchanged");
    assert_eq!(
        client.session_report(),
        admitted,
        "{member}: the session admitted the reply"
    );
    let mut right = shaped(kind, &prepared);
    edit(&mut right);
    assert_eq!(
        deliver(&mut client, &mut owner, &mut owner_end, &net, right, turn).dropped,
        0,
        "{member}: taken"
    );
    let after = client.upload_snapshot(id);
    assert_ne!(after, before, "{member}: acted on");
    (client.put_outcome(id), client.put_receipt(id), after)
}

/// The foreign manifest of the shape tests: the prepared 3-fragment total split as 100 metadata bytes and the rest, so only the shape differs.
const SPLIT: Manifest = Manifest {
    allocation: PUT_SERIAL,
    metadata_len: 100,
    body_len: PUT_TOTAL - 100,
};

/// The foreign manifest of the oversize tests: 5 fragments, so an ACK index of 4 and grant of 5 fit it and exceed the prepared count of 3.
const WIDER: Manifest = Manifest {
    allocation: PUT_SERIAL,
    metadata_len: 0,
    body_len: 5 * 8192,
};

/// A foreign manifest that keeps the prepared body and adds 100 metadata bytes: 4 fragments, so an ACK index and grant of 4 fit it and exceed the prepared count of 3.
const TAILED: Manifest = Manifest {
    allocation: PUT_SERIAL,
    metadata_len: 100,
    body_len: PUT_TOTAL,
};

/// Sets an ACK's receipt index to 4 and its grant to its own count for a reply naming a foreign count, and both to 3 for the prepared manifest.
fn oversize(reply: &mut Header) {
    let foreign = reply.count != PUT_TOTAL.div_ceil(8192);
    reply.index = if foreign { 4 } else { 3 };
    reply.grant = if foreign { reply.count } else { 3 };
}

fn ack(index: u32, grant: u32) -> impl Fn(&mut Header) {
    move |reply: &mut Header| {
        reply.index = index;
        reply.grant = grant;
    }
}

/// A matching READY readies the upload with its grant.
#[test]
fn a_foreign_shape_ready_before_ready_changes_nothing() {
    let (outcome, receipt, _) =
        put_shape_member(PutPhase::Prepared, Kind::PutReady, SPLIT, |reply| {
            reply.grant = 3
        });
    assert_eq!(
        (outcome, receipt.map(|(_, base, grant)| (base, grant))),
        (None, Some((0, 3)))
    );
}

/// A matching READY raises the grant from 2 to 3.
#[test]
fn a_foreign_shape_ready_while_ready_changes_nothing() {
    let (_, receipt, _) = put_shape_member(PutPhase::Ready, Kind::PutReady, SPLIT, |reply| {
        reply.grant = 3
    });
    assert_eq!(receipt.map(|(_, _, grant)| grant), Some(3));
}

/// A matching ACK raises the receipt base to 1.
#[test]
fn a_foreign_shape_ack_while_ready_changes_nothing() {
    let (_, receipt, _) = put_shape_member(PutPhase::Ready, Kind::PutAck, SPLIT, ack(1, 3));
    assert_eq!(receipt.map(|(_, base, _)| base), Some(1));
}

/// A matching ACK clears the resend count the PREPARE resend left.
#[test]
fn a_foreign_shape_ack_once_received_changes_nothing() {
    let (_, _, after) = put_shape_member(PutPhase::Received, Kind::PutAck, SPLIT, ack(3, 3));
    assert!(after.contains("sends: 0"), "the ACK cleared the resends");
}

/// In every phase, each under a foreign manifest that changes only the split and one that changes only the metadata length: a matching RESULT publishes the upload, from `Unknown` too.
#[test]
fn a_foreign_shape_result_changes_nothing_in_any_phase() {
    for phase in [
        PutPhase::Prepared,
        PutPhase::Ready,
        PutPhase::Received,
        PutPhase::Unknown,
    ] {
        for foreign in [SPLIT, TAILED] {
            let (outcome, _, _) = put_shape_member(phase, Kind::PutResult, foreign, |_| {});
            assert_eq!(outcome, Some(UploadOutcome::Published), "{phase:?}");
        }
    }
}

/// Under a foreign manifest of a larger body and one of the prepared body with metadata added: a matching ACK of the prepared count receipts every fragment.
#[test]
fn an_ack_past_the_prepared_count_while_ready_changes_nothing() {
    for foreign in [WIDER, TAILED] {
        let (_, receipt, _) = put_shape_member(PutPhase::Ready, Kind::PutAck, foreign, oversize);
        assert_eq!(receipt.map(|(_, base, _)| base), Some(3));
    }
}

/// Under both foreign manifests of the ready test: a matching ACK clears the resend count the PREPARE resend left.
#[test]
fn an_ack_past_the_prepared_count_once_received_changes_nothing() {
    for foreign in [WIDER, TAILED] {
        let (_, _, after) = put_shape_member(PutPhase::Received, Kind::PutAck, foreign, oversize);
        assert!(after.contains("sends: 0"), "the ACK cleared the resends");
    }
}

/// A PUT frame left unsent because the session's send sequence ran out counts as dropped, as a GET frame does, and the upload ends `NotStarted`.
#[test]
fn a_put_frame_past_the_send_sequence_counts_as_dropped() {
    let pool = receive_pool();
    let releases = releases();
    let (client_end, mut owner_end, net) = network(64, 8384, 9, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![]);
    let mut client = client(&pool, &releases, client_end);
    client.session(0);
    let turn = drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        0,
        1_000,
        active,
    );
    assert!(active(&mut client));
    let now = turn * 100;
    let id = client
        .put([2; 32], CacheVersion(0), now, 1_000_000)
        .unwrap();
    client.sessions_mut().set_send(PeerId(0), u64::MAX);
    let report = client.poll(now);
    assert_eq!(
        (report.sent, report.dropped),
        (0, 1),
        "the BEGIN past the sequence is dropped: {report:?}"
    );
    assert_eq!(client.put_outcome(id), Some(UploadOutcome::NotStarted));
}

/// A GET frame past the send sequence ends the active session and fails its GET with `SessionMismatch` in the same poll.
#[test]
fn a_get_past_the_send_sequence_ends_with_its_session() {
    let pool = receive_pool();
    let releases = releases();
    let (client_end, mut owner_end, net) = network(64, 8384, 8, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![]);
    let mut client = client(&pool, &releases, client_end);
    client.session(0);
    let turn = drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        0,
        1_000,
        active,
    );
    let now = turn * 100;
    let old = client.get([1; 32], 0, 1 << 20, now, 10_000_000).unwrap();
    client.sessions_mut().set_send(PeerId(0), u64::MAX);
    let report = client.poll(now);
    assert_eq!(
        (report.sent, report.dropped),
        (0, 1),
        "the GET past the sequence is dropped: {report:?}"
    );
    assert_eq!(client.sessions_mut().active(PeerId(0)), None);
    assert_eq!(
        client.outcome(old),
        Some(Outcome::Failed(Status::SessionMismatch)),
        "the spent sequence ends the session's GET in the same poll"
    );
    client.session(now);
    assert_eq!(client.state(), SessionState::Opening);
    drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        turn + 1,
        1_000,
        active,
    );
    assert_eq!(
        client.outcome(old),
        Some(Outcome::Failed(Status::SessionMismatch)),
        "the fresh session leaves the outcome in place"
    );
    let terminal = client.terminal(old).unwrap();
    assert!(terminal.decided_by == Decider::Session && terminal.censored());
}

/// Send limits a test sets on a [`Throttled`] end while the client owns it.
#[derive(Default)]
struct Limits {
    /// Datagrams one call takes at most.
    per_call: Cell<usize>,
    /// Datagrams the end takes in all before it refuses every send, when set.
    allowance: Cell<Option<usize>>,
    /// The next call fails before taking anything.
    fail_next: Cell<bool>,
    /// When set, the calls that still succeed or refuse before one call fails before taking anything.
    fail_after: Cell<Option<usize>>,
    /// The lengths of the datagrams each call was given, a failed or refused call included.
    offered: RefCell<Vec<Vec<usize>>>,
}

/// A simulated end whose sends obey the shared [`Limits`].
struct Throttled<'a> {
    end: LinkEnd<'a>,
    limits: Rc<Limits>,
}

impl<'a> Throttled<'a> {
    /// `end` under limits that take every datagram a call offers, with the limits.
    fn new(end: LinkEnd<'a>) -> (Self, Rc<Limits>) {
        let limits = Rc::new(Limits::default());
        limits.per_call.set(usize::MAX);
        let throttled = Self {
            end,
            limits: limits.clone(),
        };
        (throttled, limits)
    }
}

impl<'a> Datagrams<'a> for Throttled<'a> {
    fn receive<'p>(
        &mut self,
        pool: &'p PacketPool<'a>,
        into: &mut [Option<PacketLease<'p>>],
        meta: &mut [Received],
    ) -> Result<usize, DatagramError> {
        self.end.receive(pool, into, meta)
    }

    fn rx_ring(&self) -> u32 {
        self.end.rx_ring()
    }

    fn reclaim(&mut self) {
        self.end.reclaim();
    }

    fn send(&mut self, batch: &[Outgoing<'_, 'a>]) -> Result<usize, DatagramError> {
        let lengths = batch.iter().map(Outgoing::len).collect();
        self.limits.offered.borrow_mut().push(lengths);
        let scripted = match self.limits.fail_after.get() {
            Some(0) => {
                self.limits.fail_after.set(None);
                true
            }
            Some(calls) => {
                self.limits.fail_after.set(Some(calls - 1));
                false
            }
            None => false,
        };
        if self.limits.fail_next.replace(false) || scripted {
            return Err(DatagramError::Failed {
                code: Some(libc::EIO),
            });
        }
        let allowance = self.limits.allowance.get();
        let wanted = batch
            .len()
            .min(self.limits.per_call.get())
            .min(allowance.unwrap_or(usize::MAX));
        let sent = self.end.send(&batch[..wanted])?;
        self.limits.allowance.set(allowance.map(|left| left - sent));
        Ok(sent)
    }
}

/// Drives until every request in `ids` ends, then checks each completed with `source`'s bytes and retires it; returns the turn reached.
fn finish_all<'m, D: Datagrams<'m>>(
    client: &mut Client<'m, D>,
    owner: &mut Owner,
    owner_end: &mut LinkEnd<'_>,
    net: &Rc<RefCell<Net<'_>>>,
    turn: u64,
    ids: &[RequestId],
    source: &[u8],
) -> u64 {
    let mut bytes = vec![Vec::new(); ids.len()];
    let turn = drive(client, owner, owner_end, net, turn, 5_000, |client| {
        for (id, bytes) in ids.iter().zip(&mut bytes) {
            while let Some(fragment) = client.take(*id) {
                bytes.extend_from_slice(fragment.bytes());
            }
        }
        ids.iter().all(|id| client.outcome(*id).is_some())
    });
    for (id, bytes) in ids.iter().zip(&bytes) {
        assert_eq!(client.outcome(*id), Some(Outcome::Complete));
        assert_eq!(bytes, source);
        assert!(client.retire(*id));
    }
    turn
}

/// One poll hands its request frames to the transport together: three due GETs leave as one packed datagram, which a transport taking one datagram per call takes in that poll; a refused datagram's frames stay due until the next poll sends them; a call that fails counts its packed datagram as sent and lost, and each of its GETs completes through its own retry. Every GET then completes.
#[test]
fn a_poll_sends_its_request_frames_together_and_keeps_refused_ones_due() {
    let source = object(20_000, 11);
    let pool = receive_pool();
    let releases = releases();
    let (client_end, mut owner_end, net) = network(64, 8384, 10, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![([1; 32], source.clone())]);
    let (transport, limits) = Throttled::new(client_end);
    let mut client = client(&pool, &releases, transport);
    client.session(0);
    let mut turn = drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        0,
        1_000,
        active,
    );
    assert_eq!(client.state(), SessionState::Active);
    fn get<'m>(client: &mut Client<'m, Throttled<'m>>, turn: u64) -> Vec<RequestId> {
        (0..3)
            .map(|_| {
                client
                    .get([1; 32], 0, 1 << 20, turn * 100, 1_000_000)
                    .unwrap()
            })
            .collect()
    }

    limits.per_call.set(1);
    let ids = get(&mut client, turn);
    let report = client.poll(turn * 100);
    assert_eq!(
        (report.sent, report.blocked),
        (1, false),
        "three GETs go out as one packed datagram through calls of one datagram"
    );
    turn = finish_all(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        turn + 1,
        &ids,
        &source,
    );

    limits.allowance.set(Some(0));
    let ids = get(&mut client, turn);
    let report = client.poll(turn * 100);
    assert_eq!((report.sent, report.blocked), (0, true));
    limits.allowance.set(None);
    let report = client.poll(turn * 100);
    assert_eq!(
        (report.sent, report.blocked),
        (1, false),
        "the next poll sends the refused GETs"
    );
    turn = finish_all(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        turn + 1,
        &ids,
        &source,
    );

    limits.fail_next.set(true);
    let ids = get(&mut client, turn);
    let report = client.poll(turn * 100);
    assert_eq!(
        (report.sent, report.blocked, report.failed),
        (0, false, Some(Some(libc::EIO))),
        "the failed call loses the packed datagram of three GETs"
    );
    assert!(take_toward(&net, 1).is_empty());
    assert_eq!(client.poll(turn * 100).sent, 0, "none of the three is due");
    assert_eq!(
        client.next_deadline_us(),
        Some(turn * 100 + CONFIG.fetch.retry_us)
    );
    let retries = client.fetch_report().get_retries;
    finish_all(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        turn + 1,
        &ids,
        &source,
    );
    assert_eq!(
        client.fetch_report().get_retries - retries,
        3,
        "each GET of the lost datagram retried"
    );
    assert_eq!(
        owner.serve.report().requests,
        9,
        "every GET reached the owner"
    );
}

/// Steady-state get, poll, take, cancel, finish and lease release allocate nothing on the client; the simulated link keeps its own allocations out of the count, so only the client's paths are measured.
#[test]
fn steady_state_client_paths_allocate_nothing() {
    let pool = receive_pool();
    let releases = releases();
    let (client_end, mut owner_end, net) = network(64, 8384, 8, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![([1; 32], object(40_000, 8))]);
    let mut client = client(&pool, &releases, client_end);
    let mut turn = 0;
    client.session(0);
    while !active(&mut client) && turn < 1_000 {
        round(&mut [
            Act::new(Actor::Link(0), &mut || net.borrow_mut().advance(turn)),
            Act::new(Actor::Client(0), &mut || {
                let _ = client.poll(turn * 100);
            }),
            Act::new(Actor::Double(0), &mut || {
                owner.turn(&mut owner_end, turn * 100)
            }),
        ]);
        turn += 1;
    }
    assert_eq!(client.state(), SessionState::Active);
    let mut allocations = 0;
    let mut measure = |work: &mut dyn FnMut()| {
        let before = crate::instrument::allocations();
        work();
        allocations += crate::instrument::allocations() - before;
    };
    for _ in 0..3 {
        let mut ids = None;
        measure(&mut || {
            let id = client.get([1; 32], 0, 1 << 20, turn * 100, 1_000_000).ok();
            let cancelled = client.get([1; 32], 0, 1 << 20, turn * 100, 1_000_000).ok();
            if let Some(cancelled) = cancelled {
                client.cancel(cancelled);
            }
            ids = id.zip(cancelled);
        });
        let (id, cancelled) = ids.expect("two GETs");
        for _ in 0..10_000 {
            round(&mut [
                Act::new(Actor::Link(0), &mut || net.borrow_mut().advance(turn)),
                Act::new(Actor::Client(0), &mut || {
                    measure(&mut || {
                        client.poll(turn * 100);
                        while let Some(fragment) = client.take(id) {
                            drop(fragment);
                        }
                    });
                }),
                Act::new(Actor::Double(0), &mut || {
                    owner.turn(&mut owner_end, turn * 100)
                }),
            ]);
            turn += 1;
            if client.outcome(id).is_some() {
                break;
            }
        }
        assert_eq!(client.outcome(id), Some(Outcome::Complete));
        measure(&mut || {
            client.poll(turn * 100);
            assert!(client.retire(id));
            assert!(client.retire(cancelled));
        });
    }
    assert_eq!(allocations, 0);
}

/// A transport whose sends always fail.
struct Failing;

impl Datagrams<'_> for Failing {
    fn receive<'p>(
        &mut self,
        _: &'p PacketPool<'p>,
        _: &mut [Option<PacketLease<'p>>],
        _: &mut [Received],
    ) -> Result<usize, DatagramError> {
        Ok(0)
    }

    fn rx_ring(&self) -> u32 {
        0
    }

    fn reclaim(&mut self) {}

    fn send(&mut self, _: &[Outgoing<'_, '_>]) -> Result<usize, DatagramError> {
        Err(DatagramError::Failed {
            code: Some(libc::ENETUNREACH),
        })
    }
}

/// A transport that fails every send spends the opening's resends like lost frames, so the opening ends `Failed` within its bound, and every poll that sends reports the failure; a zero batch is refused at initialization.
#[test]
fn a_failing_transport_ends_the_opening() {
    let pool = receive_pool();
    let releases = releases();
    let mut client = client(&pool, &releases, Failing);
    client.session(0);
    assert_eq!(
        client.poll(0).failed,
        Some(Some(libc::ENETUNREACH)),
        "the poll reports the failure"
    );
    let mut turn = 1;
    let mut failures = 1;
    while client.state() == SessionState::Opening && turn < 10_000 {
        failures += u32::from(client.poll(turn * 100).failed == Some(Some(libc::ENETUNREACH)));
        turn += 1;
    }
    assert_eq!(client.state(), SessionState::Failed);
    assert_eq!(
        failures,
        CONFIG.bootstrap_attempts + 1,
        "every send's failure was reported"
    );
    let bound = (u64::from(CONFIG.bootstrap_attempts) + 1) * CONFIG.bootstrap_retry_us / 100 + 2;
    assert!(turn <= bound, "failed at turn {turn}, bound {bound}");
    let memory = ClientMemory {
        receive: &pool,
        releases: &releases,
        requests: RequestTable::new(8, 1, 8),
        sources: Box::default(),
        routes: routes(),
    };
    let zero = ClientConfig { batch: 0, ..CONFIG };
    let refused = Client::initialize(
        zero,
        memory,
        Failing,
        &keys(),
        1,
        &mut EngineBudget::new(1 << 24),
    );
    assert!(matches!(refused, Err(super::client::ClientError::Batch)));
}

/// A replayed READY of the active session, arriving while a fresh session opens, leaves the opening under way.
#[test]
fn a_replayed_ready_leaves_an_opening_alone() {
    let pool = receive_pool();
    let releases = releases();
    let (client_end, mut owner_end, net) = network(64, 8384, 11, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![]);
    let mut client = client(&pool, &releases, client_end);
    client.session(0);
    let mut ready = None;
    let mut turn = 0;
    while client.state() != SessionState::Active && turn < 1_000 {
        round(&mut [
            Act::new(Actor::Link(0), &mut || net.borrow_mut().advance(turn)),
            Act::new(Actor::Client(0), &mut || {
                let _ = client.poll(turn * 100);
            }),
            // The owner's READY is observed in flight right after the turn
            // that sends it, before the client can take it.
            Act::new(Actor::Double(0), &mut || {
                owner.turn(&mut owner_end, turn * 100);
                net.borrow_mut().advance(turn + 1);
                ready = net.borrow().peek(0).or(ready.take());
            }),
        ]);
        turn += 1;
    }
    assert_eq!(client.state(), SessionState::Active);
    let ready = ready.expect("the owner's READY was in flight");
    let kind = parse(Crc32c::detect(), &ready, false)
        .expect("canonical")
        .header()
        .kind;
    assert_eq!(kind, Kind::Ready);
    client.session(turn * 100);
    net.borrow_mut().inject(0, &ready);
    client.poll(turn * 100);
    assert_eq!(
        client.state(),
        SessionState::Opening,
        "the opening continues"
    );
}

/// An accepted CHALLENGE restarts the resend count: the CONFIRM answering it, whose READY never arrives, goes out once, and the opening sends `bootstrap_attempts` more bootstrap frames before it ends `Failed`.
#[test]
fn a_confirm_gets_its_own_resends() {
    let pool = receive_pool();
    let releases = releases();
    let (client_end, mut owner_end, net) = network(64, 8384, 13, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![]);
    let mut client = client(&pool, &releases, client_end);
    client.session(0);
    let mut turn = 0;
    let (killed, mut sent) = (std::cell::Cell::new(false), 0);
    while !killed.get() && turn < 1_000 {
        round(&mut [
            Act::new(Actor::Link(0), &mut || net.borrow_mut().advance(turn)),
            // A poll after the kill in this round already answers the
            // CHALLENGE, so its CONFIRM counts.
            Act::new(Actor::Client(0), &mut || {
                let frames = client.poll(turn * 100).sent;
                if killed.get() {
                    sent += frames;
                }
            }),
            // The link toward the owner dies right after the turn that puts
            // the CHALLENGE in flight, so the client's CONFIRM never arrives.
            Act::new(Actor::Double(0), &mut || {
                owner.turn(&mut owner_end, turn * 100);
                if net.borrow().pending(0) > 0 {
                    net.borrow_mut().kill(1);
                    killed.set(true);
                }
            }),
        ]);
        turn += 1;
    }
    assert!(killed.get(), "the owner's CHALLENGE is in flight");
    while client.state() == SessionState::Opening && turn < 10_000 {
        round(&mut [
            Act::new(Actor::Link(0), &mut || net.borrow_mut().advance(turn)),
            Act::new(Actor::Client(0), &mut || {
                sent += client.poll(turn * 100).sent
            }),
        ]);
        turn += 1;
    }
    assert_eq!(client.state(), SessionState::Failed);
    assert_eq!(sent, CONFIG.bootstrap_attempts + 1);
}

/// A HELLO datagram from a client boot `nonce` at bootstrap `sequence`, sealed under `owner`'s key for its one client.
fn older_boot_hello(owner: &Owner, nonce: [u8; 16], sequence: u64) -> Vec<u8> {
    let body = CAPS.body();
    let header = Header {
        principal: PRINCIPAL,
        key_epoch: 1,
        owner_nonce: [0; 16],
        client_nonce: nonce,
        sequence,
        epoch: 0,
        datagram_len: body.len() as u32,
        ..header(Kind::Hello, 0, [0; 32])
    };
    let mut datagram = sealed_header(
        owner.crc,
        &owner.ring,
        &header,
        [&body, &[]],
        Direction::ClientToOwner,
    )
    .to_vec();
    datagram.extend_from_slice(&body);
    datagram
}

/// A delayed HELLO from the client's older boot reaches the owner after its CHALLENGE and before the client's CONFIRM, and replaces the owner's pending handshake. The client repeats its CONFIRM `CONFIRM_REPEATS` times, then restarts with a fresh HELLO within its bootstrap resends and activates under its own nonces.
#[test]
fn a_stale_older_boot_hello_cannot_wedge_the_opening() {
    let pool = receive_pool();
    let releases = releases();
    let (client_end, mut owner_end, net) = network(64, 8384, 31, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![]);
    let mut client = client(&pool, &releases, client_end);
    let stale = older_boot_hello(&owner, [0x0D; 16], 1);
    client.session(0);
    let (mut injected, mut turn) = (false, 0);
    while client.state() == SessionState::Opening && turn < 10_000 {
        round(&mut [
            Act::new(Actor::Link(0), &mut || net.borrow_mut().advance(turn)),
            Act::new(Actor::Client(0), &mut || {
                let _ = client.poll(turn * 100);
            }),
            // The stale HELLO goes in behind the turn that puts the first
            // CHALLENGE in flight, so it reaches the owner before the CONFIRM.
            Act::new(Actor::Double(0), &mut || {
                owner.turn(&mut owner_end, turn * 100);
                if !injected && net.borrow().pending(0) > 0 {
                    net.borrow_mut().inject(1, &stale);
                    injected = true;
                }
            }),
        ]);
        turn += 1;
    }
    assert!(injected, "the stale HELLO was delivered");
    assert_eq!(client.state(), SessionState::Active, "at turn {turn}");
    let bound = (u64::from(CONFIRM_REPEATS) + 1) * CONFIG.bootstrap_retry_us / 100 + 4;
    assert!(
        turn <= bound,
        "activation at turn {turn} follows the repeats and one HELLO round trip, by turn {bound}"
    );
    let report = owner.sessions.report();
    assert_eq!(
        (report.mismatched, report.activations),
        (u64::from(1 + CONFIRM_REPEATS), 1),
        "the CONFIRM and its repeats mismatched before one activation"
    );
    assert_eq!(
        owner.sessions.nonces(PeerId(0)),
        Some(([0x0A; 16], client.boot_nonce()))
    );
}

/// Closing while an opening's HELLO waits gives the open request's CANCEL the one send the transport takes.
#[test]
fn close_sends_cancels_in_place_of_a_pending_opening() {
    let pool = receive_pool();
    let releases = releases();
    let (client_end, mut owner_end, net) = network(64, 8384, 14, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![([1; 32], object(500_000, 14))]);
    let (transport, limits) = Throttled::new(client_end);
    let mut client = client(&pool, &releases, transport);
    client.session(0);
    let turn = drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        0,
        1_000,
        active,
    );
    client
        .get([1; 32], 0, 1 << 20, turn * 100, 10_000_000)
        .unwrap();
    client.poll(turn * 100);
    client.session(turn * 100);
    limits.allowance.set(Some(1));
    let (closed, _transport) = client.close(turn * 100);
    assert_eq!(
        (closed.sent, closed.blocked),
        (1, false),
        "the CANCEL took the one send: {closed:?}"
    );
    let newest = net.borrow().peek(1).expect("a datagram toward the owner");
    let kind = parse(Crc32c::detect(), &newest, false)
        .expect("canonical")
        .header()
        .kind;
    assert_eq!(kind, Kind::Cancel);
}

/// A receive pool with fewer data buffers than the fetch core promises, or a control reserve below the batch, is refused at initialization.
#[test]
fn an_undersized_receive_pool_is_refused() {
    let releases = releases();
    for (count, control_reserve) in [(30, 8), (40, 4)] {
        let pool = super::packet::test_pool(count, control_reserve).unwrap();
        let memory = ClientMemory {
            receive: &pool,
            releases: &releases,
            requests: RequestTable::new(8, 1, 8),
            sources: Box::default(),
            routes: routes(),
        };
        let mut budget = EngineBudget::new(1 << 24);
        let refused = Client::initialize(CONFIG, memory, Failing, &keys(), 1, &mut budget);
        assert!(
            matches!(refused, Err(super::client::ClientError::Pool)),
            "{count} buffers, {control_reserve} reserved"
        );
        assert_eq!(budget.used(), 0);
    }
}

/// A receive pool whose control reserve cannot hold the device ring's posted buffers plus one batch is refused at initialization; one buffer more is accepted.
#[test]
fn a_pool_below_the_ring_plus_a_batch_is_refused() {
    const PRIOR_USE: usize = 4096;
    let releases = releases();
    for (ring, reserve, accepted) in [(8, 15, false), (8, 16, true), (7, 15, true)] {
        let pool = super::packet::test_pool(24 + reserve, reserve).unwrap();
        let memory = ClientMemory {
            receive: &pool,
            releases: &releases,
            requests: RequestTable::new(8, 1, 8),
            sources: Box::default(),
            routes: routes(),
        };
        let mut budget = EngineBudget::new(1 << 24);
        budget.charge(PRIOR_USE).unwrap();
        let (mut end, _, _) = network(64, 8384, 0, [Faults::default(); 2]);
        end.set_ring(ring);
        assert_eq!(end.rx_ring() as usize, ring);
        let started = Client::initialize(CONFIG, memory, end, &keys(), 1, &mut budget);
        assert_eq!(
            started.is_ok(),
            accepted,
            "a reserve of {reserve} over a ring of {ring}"
        );
        if accepted {
            assert!(budget.used() > PRIOR_USE);
        } else {
            assert!(matches!(started, Err(super::client::ClientError::Pool)));
            assert_eq!(budget.used(), PRIOR_USE);
        }
    }
}

/// Retired buffers count against `data_cap()` and preserve the configured control reserve.
#[test]
fn a_retired_receive_buffer_leaves_the_control_reserve_unchanged() {
    use crate::storage::PoolKind;

    use super::packet::{PacketUse, test_arena};

    let releases = releases();
    for (reserve, accepted) in [(15, false), (16, true)] {
        let count = 25 + reserve;
        let packets = test_arena(count, 16384);
        let pool = PacketPool::new(&packets, PoolKind::PacketReceive, reserve).unwrap();
        for index in 0..count as usize {
            packets
                .pools()
                .set_incarnation(PoolKind::PacketReceive, index, u64::MAX);
        }
        drop(pool.acquire(PacketUse::Control).unwrap());
        assert_eq!(packets.report(PoolKind::PacketReceive).retired, 1);
        assert_eq!(pool.data_cap(), CONFIG.fetch.boxes);
        assert_eq!(pool.report().count - pool.data_cap(), reserve + 1);
        let memory = ClientMemory {
            receive: &pool,
            releases: &releases,
            requests: RequestTable::new(8, 1, 8),
            sources: Box::default(),
            routes: routes(),
        };
        let mut budget = EngineBudget::new(1 << 24);
        let (mut end, _, _) = network(64, 8384, 0, [Faults::default(); 2]);
        end.set_ring(8);
        let started = Client::initialize(CONFIG, memory, end, &keys(), 1, &mut budget);
        assert_eq!(
            started.is_ok(),
            accepted,
            "a reserve of {reserve} beside one retired buffer"
        );
        if !accepted {
            assert!(matches!(started, Err(super::client::ClientError::Pool)));
            assert_eq!(budget.used(), 0);
        }
    }
}

/// With every grant held by the application, the device ring stays full: each receive refills every free ring entry, and no datagram finds the ring empty. Releasing the held fragments returns credit, and the GET completes with exact bytes.
#[test]
fn the_ring_stays_full_while_the_application_holds_every_grant() {
    let source = object(150_000, 61);
    let pool = super::packet::test_pool(40, 16).unwrap();
    let releases = releases();
    let (mut client_end, mut owner_end, net) = network(64, 8384, 61, [Faults::default(); 2]);
    client_end.set_ring(8);
    let mut owner = Owner::new(vec![([1; 32], source.clone())]);
    let mut client = client(&pool, &releases, client_end);
    client.session(0);
    let turn = drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        0,
        1_000,
        active,
    );
    let id = client
        .get([1; 32], 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let mut held = Vec::new();
    let turn = drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        turn,
        400,
        |client| {
            while let Some(fragment) = client.take(id) {
                held.push(fragment);
            }
            false
        },
    );
    assert_eq!(
        held.len(),
        CONFIG.fetch.window as usize,
        "the window's grant is held"
    );
    assert_eq!(client.outcome(id), None);
    let report = pool.report();
    assert_eq!(
        report.count - report.free - report.data - report.control,
        8,
        "the ring holds eight posted buffers"
    );
    assert!(
        report.data as usize >= held.len(),
        "every held fragment is a data lease"
    );
    assert_eq!(
        net.borrow().report(0).missed,
        0,
        "no datagram found the ring empty"
    );
    let mut bytes: Vec<u8> = held
        .iter()
        .flat_map(|fragment| fragment.bytes().to_vec())
        .collect();
    drop(held);
    drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        turn,
        20_000,
        |client| {
            while let Some(fragment) = client.take(id) {
                bytes.extend_from_slice(fragment.bytes());
            }
            client.outcome(id).is_some()
        },
    );
    assert_eq!(client.outcome(id), Some(Outcome::Complete));
    assert_eq!(bytes, source);
    assert_eq!(net.borrow().report(0).missed, 0);
}

/// A GET beyond the owner's negotiated slot cap is refused locally as request pressure, so the owner never sees a GET it would answer `InvalidRequest`: with an owner cap of 2 slots and a client table of 8, the third GET is refused and the two live ones complete.
#[test]
fn gets_beyond_the_negotiated_slot_cap_are_refused_locally() {
    let pool = receive_pool();
    let releases = releases();
    let (client_end, mut owner_end, net) = network(64, 8384, 21, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![([1; 32], object(20_000, 21))]);
    owner.sessions = Sessions::new(
        Role::Owner,
        [0x0A; 16],
        Caps {
            slots: 2,
            window: 8,
        },
        1,
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap();
    let mut client = client(&pool, &releases, client_end);
    client.session(0);
    let turn = drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        0,
        1_000,
        active,
    );
    let now = turn * 100;
    let first = client.get([1; 32], 0, 1 << 20, now, 10_000_000).unwrap();
    let second = client.get([1; 32], 0, 1 << 20, now, 10_000_000).unwrap();
    assert_eq!(
        client.get([1; 32], 0, 1 << 20, now, 10_000_000),
        Err(GetRefused::RequestPressure),
        "the third GET exceeds the owner's slot cap"
    );
    drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        turn,
        2_000,
        |client| client.outcome(first).is_some() && client.outcome(second).is_some(),
    );
    assert_eq!(client.outcome(first), Some(Outcome::Complete));
    assert_eq!(client.outcome(second), Some(Outcome::Complete));
}

/// A CHALLENGE that arrives after the opening spent its HELLO resends resumes the opening: the CONFIRM it answers with gets its own resends when the READY is lost, so the session completes without another `session` call.
#[test]
fn a_late_challenge_resumes_the_opening() {
    let pool = receive_pool();
    let releases = releases();
    let (client_end, mut owner_end, net) = network(64, 8384, 22, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![]);
    let mut client = client(&pool, &releases, client_end);
    client.session(0);
    let mut turn = 0;
    let mut challenge = None;
    // Every CHALLENGE is held back, so the opening spends its HELLO resends and fails.
    while client.state() == SessionState::Opening && turn < 10_000 {
        round(&mut [
            Act::new(Actor::Link(0), &mut || net.borrow_mut().advance(turn)),
            Act::new(Actor::Client(0), &mut || {
                let _ = client.poll(turn * 100);
            }),
            Act::new(Actor::Double(0), &mut || {
                owner.turn(&mut owner_end, turn * 100);
                challenge = net.borrow().peek(0).or(challenge.take());
                net.borrow_mut().clear(0);
            }),
        ]);
        turn += 1;
    }
    assert_eq!(client.state(), SessionState::Failed);
    let challenge = challenge.expect("a CHALLENGE was in flight");
    assert_eq!(
        parse(Crc32c::detect(), &challenge, false)
            .expect("canonical")
            .header()
            .kind,
        Kind::Challenge
    );
    // The last HELLO's CHALLENGE arrives late, before the round that
    // delivers it.
    let mut confirmed = None;
    net.borrow_mut().inject(0, &challenge);
    round(&mut [
        Act::new(Actor::Link(0), &mut || net.borrow_mut().advance(turn)),
        Act::new(Actor::Client(0), &mut || {
            confirmed = Some(client.poll(turn * 100))
        }),
    ]);
    let confirmed = confirmed.expect("the round polled the client");
    assert_eq!(confirmed.sent, 1, "the CONFIRM went out: {confirmed:?}");
    assert_eq!(client.state(), SessionState::Opening);
    // The READY is lost; the CONFIRM must be resent.
    round(&mut [
        Act::new(Actor::Link(0), &mut || net.borrow_mut().advance(turn + 1)),
        Act::new(Actor::Double(0), &mut || {
            owner.turn(&mut owner_end, turn * 100);
            net.borrow_mut().clear(0);
        }),
    ]);
    let resend_at = turn * 100 + CONFIG.bootstrap_retry_us;
    assert!(
        client
            .next_deadline_us()
            .is_some_and(|deadline| deadline <= resend_at),
        "the deadline names the CONFIRM resend"
    );
    let resent = client.poll(resend_at).sent;
    assert_eq!(resent, 1, "the CONFIRM was resent");
    // With the network whole again, the opening completes.
    let turn = resend_at / 100 + 1;
    let end = drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        turn,
        1_000,
        active,
    );
    assert_eq!(client.state(), SessionState::Active, "at turn {end}");
}

/// `close` sends every undecided request's CANCEL, in as many bounded sends as the live requests need, so a batch smaller than the live count discards none: three live GETs under a batch of one send three CANCELs.
#[test]
fn close_sends_every_cancel_beyond_one_batch() {
    let pool = receive_pool();
    let releases = releases();
    let (client_end, mut owner_end, net) = network(64, 8384, 23, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![([1; 32], object(500_000, 23))]);
    let memory = ClientMemory {
        receive: &pool,
        releases: &releases,
        requests: RequestTable::new(8, 1, 8),
        sources: Box::default(),
        routes: routes(),
    };
    let mut client = Client::initialize(
        ClientConfig { batch: 1, ..CONFIG },
        memory,
        client_end,
        &keys(),
        1,
        &mut EngineBudget::new(1 << 24),
    )
    .unwrap();
    client.session(0);
    let turn = drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        0,
        1_000,
        active,
    );
    let now = turn * 100;
    for _ in 0..3 {
        client.get([1; 32], 0, 1 << 20, now, 10_000_000).unwrap();
    }
    let before = net.borrow().pending(1);
    let (closed, _transport) = client.close(now);
    assert_eq!(
        (closed.sent, closed.blocked),
        (3, false),
        "every CANCEL went out: {closed:?}"
    );
    assert_eq!(net.borrow().pending(1), before + 3);
}

/// Session caps outside the wire's ranges are refused at initialization, charging nothing: a zero slot cap and a window above the wire's maximum.
#[test]
fn invalid_caps_are_refused_at_initialization() {
    let pool = receive_pool();
    let releases = releases();
    for caps in [
        Caps {
            slots: 0,
            window: 8,
        },
        Caps {
            slots: 8,
            window: super::frame::MAX_WINDOW + 1,
        },
    ] {
        let memory = ClientMemory {
            receive: &pool,
            releases: &releases,
            requests: RequestTable::new(8, 1, 8),
            sources: Box::default(),
            routes: routes(),
        };
        let mut budget = EngineBudget::new(1 << 24);
        let refused = Client::initialize(
            ClientConfig { caps, ..CONFIG },
            memory,
            Failing,
            &keys(),
            1,
            &mut budget,
        );
        assert!(
            matches!(refused, Err(super::client::ClientError::Caps)),
            "{caps:?}"
        );
        assert_eq!(budget.used(), 0);
    }
}

/// A receive pool whose buffers' data room cannot hold a complete protocol datagram is refused at initialization, since every DATA frame would arrive truncated.
#[test]
fn a_pool_of_short_buffers_is_refused() {
    let releases = releases();
    let pool = super::packet::test_pool_with(40, 8, 8192).unwrap();
    let memory = ClientMemory {
        receive: &pool,
        releases: &releases,
        requests: RequestTable::new(8, 1, 8),
        sources: Box::default(),
        routes: routes(),
    };
    let mut budget = EngineBudget::new(1 << 24);
    let refused = Client::initialize(CONFIG, memory, Failing, &keys(), 1, &mut budget);
    assert!(matches!(refused, Err(super::client::ClientError::Pool)));
    assert_eq!(budget.used(), 0);
}

/// `close` after a poll the transport refused still sends every CANCEL: the earlier refusal does not stand in for a refusal during the close.
#[test]
fn close_after_a_blocked_poll_sends_the_cancels() {
    let pool = receive_pool();
    let releases = releases();
    let (client_end, mut owner_end, net) = network(64, 8384, 24, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![([1; 32], object(500_000, 24))]);
    let (transport, limits) = Throttled::new(client_end);
    let mut client = client(&pool, &releases, transport);
    client.session(0);
    let turn = drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        0,
        1_000,
        active,
    );
    let now = turn * 100;
    for _ in 0..2 {
        client.get([1; 32], 0, 1 << 20, now, 10_000_000).unwrap();
    }
    limits.allowance.set(Some(0));
    assert!(client.poll(now).blocked, "the GETs were refused");
    limits.allowance.set(None);
    let before = net.borrow().pending(1);
    let (closed, _transport) = client.close(now);
    assert_eq!(
        (closed.sent, closed.blocked),
        (2, false),
        "both CANCELs went out: {closed:?}"
    );
    assert_eq!(net.borrow().pending(1), before + 2);
}

/// Every PUT kind, sealed under the client's live session and naming the request of a live GET, moves only the client's drop counter: session admission admits the five kinds an owner sends, recording their sequences, and refuses the rest, the client holds no PUT handler, the fetch core sees nothing, and the GET completes with exact bytes.
#[test]
fn every_put_kind_reaching_the_client_is_dropped_with_counters_only() {
    let source = object(20_000, 5);
    let pool = receive_pool();
    let releases = releases();
    let (client_end, mut owner_end, net) = network(64, 8384, 9, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![([1; 32], source.clone())]);
    let mut client = client(&pool, &releases, client_end);
    client.session(0);
    let mut turn = drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        0,
        1_000,
        active,
    );
    assert_eq!(client.state(), SessionState::Active);
    let id = client
        .get([1; 32], 0, 1 << 20, turn * 100, 1_000_000)
        .unwrap();
    client.poll(turn * 100);
    let get = net
        .borrow()
        .peek(1)
        .and_then(|bytes| {
            parse(Crc32c::detect(), &bytes, false)
                .ok()
                .map(|frame| frame.header())
        })
        .expect("the GET toward the owner");
    let (owner_nonce, client_nonce) = owner.sessions.nonces(PeerId(0)).unwrap();
    let before = client.fetch_report();
    let mut sent = 0;
    let mut sequences = Vec::new();
    for kind in Kind::ALL.into_iter().filter(|kind| kind.is_put()) {
        let base = Header {
            owner_nonce,
            client_nonce,
            sequence: owner.sessions.next_sequence(PeerId(0)).unwrap(),
            ..get
        };
        sequences.push((kind, base.sequence));
        let (put, body) = put_frame(kind, &base);
        assert!(sealed_send(
            owner.crc,
            &owner.ring,
            &mut owner_end,
            &put,
            [&body, &[]]
        ));
        sent += 1;
    }
    // One receive batch holds eight datagrams, so the client alone polls until the link toward it is empty.
    let (mut received, mut dropped) = (0, 0);
    while net.borrow().pending(0) > 0 {
        round(&mut [
            Act::new(Actor::Link(0), &mut || net.borrow_mut().advance(turn)),
            Act::new(Actor::Client(0), &mut || {
                let report = client.poll(turn * 100);
                received += report.received;
                dropped += report.dropped;
            }),
        ]);
        turn += 1;
    }
    assert_eq!((received, dropped), (sent, sent));
    assert_eq!(client.fetch_report(), before);
    assert_eq!(client.outcome(id), None, "the GET is still live");
    // Admission recorded the sequences of the five PUT kinds an owner sends, and dispatch drops the kinds sent the wrong way before admission sees their sequences: an ERROR for a request the client never made, at each PUT frame's sequence, drops exactly where admission saw that sequence.
    for (kind, sequence) in sequences {
        let error = Header {
            kind: Kind::Error,
            principal: PRINCIPAL,
            key_epoch: 1,
            owner_nonce,
            client_nonce,
            sequence,
            epoch: get.epoch,
            status: Status::Missing as u16,
            ..header(Kind::Error, 3 << 48 | 1, [9; 32])
        };
        let mut report = None;
        // The ERROR is in flight before the round whose advance delivers it.
        assert!(sealed_send(
            owner.crc,
            &owner.ring,
            &mut owner_end,
            &error,
            [&[], &[]]
        ));
        round(&mut [
            Act::new(Actor::Link(0), &mut || net.borrow_mut().advance(turn)),
            Act::new(Actor::Client(0), &mut || {
                report = Some(client.poll(turn * 100))
            }),
        ]);
        let report = report.expect("the round polled the client");
        turn += 1;
        let seen = kind.direction() == Direction::OwnerToClient;
        assert_eq!(
            (report.received, report.dropped),
            (1, u32::from(seen)),
            "{kind:?}"
        );
    }
    let mut bytes = Vec::new();
    drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        turn,
        5_000,
        |client| {
            while let Some(fragment) = client.take(id) {
                bytes.extend_from_slice(fragment.bytes());
            }
            client.outcome(id).is_some()
        },
    );
    assert_eq!(client.outcome(id), Some(Outcome::Complete));
    assert_eq!(bytes, source);
}

crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
    a_due_put_frame_is_sent_beside_a_full_get_batch,
    a_late_challenge_resumes_the_opening,
    a_put_frame_past_the_send_sequence_counts_as_dropped,
    a_refused_put_waits_one_upload_retry_not_one_fetch_retry,
    a_refused_send_stays_due_for_the_next_poll,
    a_replayed_ready_leaves_an_opening_alone,
    a_restarted_owner_reusing_the_epoch_replaces_the_session,
    a_session_change_ends_old_requests,
    an_absent_owner_yields_bounded_outcomes,
    close_after_a_blocked_poll_sends_the_cancels,
    close_sends_cancels_in_place_of_a_pending_opening,
    close_sends_every_cancel_beyond_one_batch,
    every_put_kind_reaching_the_client_is_dropped_with_counters_only,
    gets_beyond_the_negotiated_slot_cap_are_refused_locally,
    leases_outlive_poll_timeout_cancel_and_close,
    the_ring_stays_full_while_the_application_holds_every_grant,
);

/// A client under `config` over a link whose owner end no owner polls, so every bootstrap frame goes unanswered.
fn silent_client<'m>(
    pool: &'m PacketPool<'m>,
    releases: &'m Releases,
    config: ClientConfig,
) -> (Client<'m, LinkEnd<'m>>, Rc<RefCell<Net<'m>>>) {
    let (client_end, _owner_end, net) = network(64, 8384, 51, [Faults::default(); 2]);
    (client_with(pool, releases, client_end, config), net)
}

/// Once an unanswered HELLO is sent, the client reports its resend time, 0 and `u64::MAX` included, and the poll at that time resends it.
#[test]
fn a_bootstrap_timer_is_present_at_every_timestamp() {
    let pool = receive_pool();
    let releases = releases();
    for (member, now, retry_us, due) in [
        ("bootstrap-timer-zero-live", 0, 0, 0),
        ("bootstrap-timer-max-live", 0, u64::MAX, u64::MAX),
        (
            "bootstrap-timer-saturating-live",
            u64::MAX - 5,
            100,
            u64::MAX,
        ),
    ] {
        let config = ClientConfig {
            bootstrap_retry_us: retry_us,
            ..CONFIG
        };
        let (mut client, net) = silent_client(&pool, &releases, config);
        client.session(now);
        assert_eq!(client.poll(now).sent, 1, "{member}: the HELLO");
        assert_eq!(client.next_deadline_us(), Some(due), "{member}");
        if due > now {
            assert_eq!(
                client.poll(due - 1).sent,
                0,
                "{member}: no resend before its time"
            );
        }
        assert_eq!(client.poll(due).sent, 1, "{member}: the resend at its time");
        assert_eq!(client.bootstrap_sent(), 2, "{member}");
        drop(net);
    }
}

/// A client with no timer and nothing due reports none, at time 0 before any session and at `u64::MAX` with an active session and every request retired.
#[test]
fn a_client_without_timers_reports_none_at_the_first_and_last_timestamps() {
    let pool = receive_pool();
    let releases = releases();
    let (mut idle, _net) = silent_client(&pool, &releases, CONFIG);
    assert_eq!(idle.next_deadline_us(), None, "client-timers-absent-zero");
    let _ = idle.poll(0);
    assert_eq!(idle.next_deadline_us(), None, "client-timers-absent-zero");
    drop(idle);

    let (client_end, mut owner_end, net) = network(64, 8384, 52, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![([1; 32], object(100, 52))]);
    let mut client = client(&pool, &releases, client_end);
    client.session(0);
    let turn = drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        0,
        1_000,
        active,
    );
    let id = client
        .get([1; 32], 0, 1 << 20, turn * 100, 10_000_000)
        .unwrap();
    let turn = drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        turn,
        1_000,
        |client| {
            while client.take(id).is_some() {}
            client.outcome(id).is_some()
        },
    );
    assert_eq!(client.outcome(id), Some(Outcome::Complete));
    drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        turn,
        10,
        |_| false,
    );
    assert!(client.retire(id));
    let _ = client.poll(u64::MAX);
    assert_eq!(client.next_deadline_us(), None, "client-timers-absent-max");
    assert!(active(&mut client));
}

/// With a GET and a PUT both waiting on an owner that hears nothing, the client reports the earlier of their timers, then the later once the earlier request ends at its deadline.
#[test]
fn a_client_reports_the_earliest_timer_across_gets_and_puts() {
    let pool = receive_pool();
    let releases = releases();
    let (client_end, mut owner_end, net) = network(64, 8384, 53, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![]);
    let config = ClientConfig {
        fetch: FetchConfig {
            retry_us: u64::MAX,
            ..CONFIG.fetch
        },
        upload: super::upload::UploadConfig {
            retry_us: u64::MAX,
            ..CONFIG.upload
        },
        ..CONFIG
    };
    let mut client = client_with(&pool, &releases, client_end, config);
    client.session(0);
    let turn = drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        0,
        1_000,
        active,
    );
    // The owner hears nothing more, so both requests wait on their timers.
    net.borrow_mut().set_faults(
        1,
        Faults {
            loss: 100,
            ..Faults::default()
        },
    );
    let now = turn * 100;
    let get = client.get([1; 32], 0, 1 << 20, now, 50_000).unwrap();
    let put = client.put([2; 32], CacheVersion(0), now, 20_000).unwrap();
    let _ = client.poll(now);
    assert_eq!(
        client.next_deadline_us(),
        Some(now + 20_000),
        "the PUT's deadline"
    );
    let _ = client.poll(now + 20_000);
    assert!(client.put_outcome(put).is_some());
    assert_eq!(client.outcome(get), None);
    assert_eq!(
        client.next_deadline_us(),
        Some(now + 50_000),
        "then the GET's"
    );
}

/// A client holding a cancelled GET it has not retired, a live GET and a live PUT, both with deadlines at `u64::MAX`, polls at `u64::MAX`. Each core acts only on its own live request, which ends at its deadline, and the cancelled GET keeps its outcome.
#[test]
fn a_poll_at_the_last_timestamp_acts_on_each_core_only_for_its_own_requests() {
    let pool = receive_pool();
    let releases = releases();
    let (client_end, mut owner_end, net) = network(64, 8384, 55, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![]);
    // Retries every `u64::MAX` microseconds leave each request's timer at its deadline.
    let config = ClientConfig {
        fetch: FetchConfig {
            retry_us: u64::MAX,
            ..CONFIG.fetch
        },
        upload: super::upload::UploadConfig {
            retry_us: u64::MAX,
            ..CONFIG.upload
        },
        ..CONFIG
    };
    let mut client = client_with(&pool, &releases, client_end, config);
    client.session(0);
    let turn = drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        0,
        1_000,
        active,
    );
    net.borrow_mut().set_faults(
        1,
        Faults {
            loss: 100,
            ..Faults::default()
        },
    );
    let now = turn * 100;
    let cancelled = client.get([1; 32], 0, 1 << 20, now, 10_000).unwrap();
    let live = client.get([2; 32], 0, 1 << 20, now, u64::MAX).unwrap();
    let put = client.put([3; 32], CacheVersion(0), now, u64::MAX).unwrap();
    client.cancel(cancelled);
    let _ = client.poll(now);
    assert_eq!(
        client.outcome(cancelled),
        Some(Outcome::Failed(Status::Cancelled))
    );
    assert_eq!(
        client.next_deadline_us(),
        Some(u64::MAX),
        "the client reports the GET's and the PUT's timer at the last timestamp"
    );
    let _ = client.poll(u64::MAX);
    assert_eq!(
        client.outcome(cancelled),
        Some(Outcome::Failed(Status::Cancelled)),
        "the cancelled GET keeps its outcome"
    );
    assert_eq!(
        client.outcome(live),
        Some(Outcome::Failed(Status::TimedOut))
    );
    assert_eq!(client.put_outcome(put), Some(UploadOutcome::Unknown));
    assert_eq!(client.next_deadline_us(), None);
}

/// Bootstrap counts its sends, the first included, and fails the opening once the count exceeds the limit. At limit 0 the first resend time fails it; at `u32::MAX`, a count seeded at the limit resends once, its count passing `u32::MAX` without wrapping, and the next resend time fails it.
#[test]
fn bootstrap_resends_hold_at_zero_and_at_the_largest_limit() {
    let pool = receive_pool();
    let releases = releases();
    for (member, attempts, seed) in [
        ("bootstrap-retry-zero", 0, None),
        ("bootstrap-retry-max", u32::MAX, Some(u64::from(u32::MAX))),
    ] {
        let config = ClientConfig {
            bootstrap_retry_us: 1_000,
            bootstrap_attempts: attempts,
            ..CONFIG
        };
        let (mut client, _net) = silent_client(&pool, &releases, config);
        client.session(0);
        assert_eq!(client.poll(0).sent, 1, "{member}: the HELLO");
        let mut now = 1_000;
        if let Some(seed) = seed {
            client.seed_bootstrap_sent(seed);
            assert_eq!(client.poll(now).sent, 1, "{member}: the last resend");
            assert_eq!(client.bootstrap_sent(), seed + 1);
            now += 1_000;
        }
        assert_eq!(client.poll(now).sent, 0, "{member}: no further send");
        assert_eq!(client.state(), SessionState::Failed, "{member}");
    }
}

/// A HELLO the transport blocks consumes no send, a failed or lost one consumes one, an accepted CHALLENGE restarts the count so the CONFIRM answering it is the one send counted, and a new opening restarts it.
#[test]
fn bootstrap_counts_failed_sends_and_restarts_at_a_challenge() {
    let pool = receive_pool();
    let releases = releases();
    let (client_end, mut owner_end, net) = network(64, 8384, 54, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![]);
    let config = ClientConfig {
        bootstrap_retry_us: 1_000,
        ..CONFIG
    };
    let mut client = client_with(&pool, &releases, client_end, config);
    client.session(0);
    net.borrow_mut().set_faults(
        1,
        Faults {
            would_block: 100,
            ..Faults::default()
        },
    );
    assert!(client.poll(0).blocked);
    assert_eq!(
        client.bootstrap_sent(),
        0,
        "a blocked HELLO consumes no send"
    );
    net.borrow_mut().set_faults(
        1,
        Faults {
            error: 100,
            ..Faults::default()
        },
    );
    let retry = client.next_deadline_us().unwrap();
    assert!(client.poll(retry).failed.is_some());
    assert_eq!(client.bootstrap_sent(), 1, "a failed HELLO consumes one");
    net.borrow_mut().set_faults(
        1,
        Faults {
            loss: 100,
            ..Faults::default()
        },
    );
    let mut now = client.next_deadline_us().unwrap();
    let _ = client.poll(now);
    assert_eq!(client.bootstrap_sent(), 2, "a lost resend is counted");
    net.borrow_mut().set_faults(1, Faults::default());
    now = client.next_deadline_us().unwrap();
    let _ = client.poll(now);
    assert_eq!(client.bootstrap_sent(), 3);
    for turn in 0..4 {
        let at = now / 100 + turn;
        net.borrow_mut().advance(at);
        owner.turn(&mut owner_end, at * 100);
        net.borrow_mut().advance(at + 1);
        let _ = client.poll((at + 1) * 100);
        if client.bootstrap_sent() < 3 {
            break;
        }
    }
    assert_eq!(
        client.bootstrap_sent(),
        1,
        "the CHALLENGE restarted the count and its CONFIRM is the one send"
    );
    client.session(now);
    assert_eq!(
        client.bootstrap_sent(),
        0,
        "a new opening restarts the count"
    );
}

/// Witness `get-altered-same-crc`: an on-path change to a sealed GET DATA frame's body that keeps its crc32c is dropped at the client's receive boundary before any request or session state reads it, and the honest frame at the same send sequence, arriving after it, is admitted and delivered, so the GET completes with the owner's exact bytes.
#[test]
fn a_get_data_body_altered_on_path_is_dropped_before_delivery() {
    let source = object(10_000, 89);
    let pool = receive_pool();
    let releases = releases();
    let (client_end, mut owner_end, net) = network(64, 8384, 89, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![([1; 32], source.clone())]);
    let mut client = client(&pool, &releases, client_end);
    client.session(0);
    let start = drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        0,
        1_000,
        active,
    );
    let id = client
        .get([1; 32], 0, 1 << 20, start * 100, 1_000_000)
        .unwrap();
    let crc = Crc32c::detect();
    let (mut altered, mut bytes, mut dropped) = (false, Vec::new(), 0);
    let sessions = client.session_report();
    for turn in start..start + 2_000 {
        net.borrow_mut().advance(turn);
        let report = client.poll(turn * 100);
        dropped += report.dropped;
        while let Some(fragment) = client.take(id) {
            bytes.extend_from_slice(fragment.bytes());
        }
        if client.outcome(id).is_some() {
            break;
        }
        owner.turn(&mut owner_end, turn * 100);
        if !altered {
            let mut queued = Vec::new();
            net.borrow_mut().retain(0, |frame| {
                queued.push(frame.to_vec());
                false
            });
            for frame in queued {
                let kind = parse(crc, &frame, false).map(|parsed| parsed.header().kind);
                if !altered && kind == Ok(Kind::Data) {
                    let mut changed = frame.clone();
                    super::auth_tests::crc_preserving_flip(&mut changed, HEADER_LEN + 40);
                    assert!(parse(crc, &changed, false).unwrap().check_body(crc).is_ok());
                    net.borrow_mut().inject(0, &changed);
                    altered = true;
                }
                net.borrow_mut().inject(0, &frame);
            }
        }
    }
    assert!(altered, "a sealed GET DATA frame was altered on path");
    assert_eq!(dropped, 1, "the client dropped one frame");
    assert_eq!(
        client.session_report(),
        sessions,
        "the altered frame never reached the session table, so the honest one's sequence stayed fresh"
    );
    assert_eq!(client.outcome(id), Some(Outcome::Complete));
    assert_eq!(bytes, source, "the GET delivered the owner's exact bytes");
}

/// A logical request's account in the campaign's ledger: the client's terminal observation, a refusal at
/// admission, a generator that never handed the request to the client, or an admitted request still undecided
/// at the cutoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Accounted {
    Terminal(Terminal),
    Refused(GetRefused),
    Unsent,
    Unresolved(RequestId),
}

/// The report counts the ledger's terminals imply, classed from each terminal's decider and outcome.
fn implied(accounts: &[(u64, Accounted)]) -> (OutcomeCounts, AdmissionRefusals) {
    let (mut outcomes, mut refused) = (OutcomeCounts::default(), AdmissionRefusals::default());
    for (_, account) in accounts {
        match account {
            Accounted::Terminal(terminal) => match (terminal.decided_by, terminal.outcome) {
                (Decider::Wait, _) => outcomes.timed_out += 1,
                (Decider::Cancel, _) => outcomes.cancelled += 1,
                (Decider::Session, _) => outcomes.session_ended += 1,
                (Decider::Owner, Outcome::Complete) => outcomes.complete += 1,
                (Decider::Owner, Outcome::Missing) => outcomes.missing += 1,
                (Decider::Owner, Outcome::Pressure(_)) => outcomes.pressure += 1,
                (Decider::Owner, Outcome::Failed(_)) => outcomes.failed += 1,
                (Decider::Owner, Outcome::Incomplete(_)) => outcomes.incomplete += 1,
            },
            Accounted::Refused(GetRefused::NoSession) => refused.no_session += 1,
            Accounted::Refused(GetRefused::ReceivePressure) => refused.receive_pressure += 1,
            Accounted::Refused(GetRefused::RequestPressure) => refused.request_pressure += 1,
            Accounted::Refused(GetRefused::Unrouted) => refused.unrouted += 1,
            Accounted::Unsent | Accounted::Unresolved(_) => {}
        }
    }
    (outcomes, refused)
}

/// Reconciles every intended logical request with its accounts, each needing exactly one, and the client's
/// reports with the counts the accounts imply, so a missing account or a report that drops a class names it.
fn reconcile(
    intended: &[u64],
    accounts: &[(u64, Accounted)],
    report: (OutcomeCounts, AdmissionRefusals),
) -> Result<(), String> {
    for logical in intended {
        let found = accounts.iter().filter(|(of, _)| of == logical).count();
        if found != 1 {
            return Err(format!("logical request {logical} has {found} accounts"));
        }
    }
    if let Some((stray, _)) = accounts.iter().find(|(of, _)| !intended.contains(of)) {
        return Err(format!("account for unintended request {stray}"));
    }
    let implied = implied(accounts);
    if report != implied {
        return Err(format!(
            "report {report:?} against the ledger's {implied:?}"
        ));
    }
    Ok(())
}

/// Turns the client and owner from `turn` until `done`, given the client and the turn's poll time, holds;
/// returns the turn reached and the decided count the client's polls reported.
fn drive_counted<'m, D: Datagrams<'m>>(
    client: &mut Client<'m, D>,
    owner: &mut Owner,
    owner_end: &mut LinkEnd<'_>,
    net: &Rc<RefCell<Net<'_>>>,
    turn: u64,
    mut done: impl FnMut(&mut Client<'m, D>, u64) -> bool,
) -> (u64, u32) {
    let mut decided = 0;
    for turn in turn..turn + 2_000 {
        net.borrow_mut().advance(turn);
        decided += client.poll(turn * 100).decided;
        owner.turn(owner_end, turn * 100);
        if done(client, turn * 100) {
            return (turn + 1, decided);
        }
    }
    panic!("the history settles within 2000 turns");
}

/// A recorded history of eight logical GETs reconciles to one account each and to the client's reports: two
/// complete, the owner answers one with its own ERROR `TimedOut`, the application cancels one, one times out on
/// the client while the owner stays silent, one is refused at admission, one the generator never sent and one
/// is admitted and still undecided at the cutoff. Each terminal keeps the attempt the client admitted, the
/// caller's intended arrival and the time of the poll that decided it; only the client's own ends are
/// censored. Dropping any account or any reported class fails the reconciliation, naming what is missing.
#[test]
fn every_logical_request_reconciles_to_one_account_and_a_dropped_one_fails() {
    let source = object(20_000, 9);
    let pool = receive_pool();
    let releases = releases();
    let (client_end, mut owner_end, net) = network(64, 8384, 9, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![([1; 32], source)]);
    let mut client = client(&pool, &releases, client_end);
    let early = client.get_intended([1; 32], 0, 1 << 20, 0, 0, 1_000_000);
    assert_eq!(early, Err(GetRefused::NoSession));
    let mut accounts = vec![(1, Accounted::Refused(early.unwrap_err()))];
    client.session(0);
    let turn = drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        0,
        1_000,
        active,
    );
    let now = turn * 100;
    let first = client
        .get_intended([1; 32], 0, 1 << 20, now - 40, now, 1_000_000)
        .unwrap();
    let second = client
        .get_intended([1; 32], 0, 1 << 20, now - 10, now, 1_000_000)
        .unwrap();
    let mut settled_us = None;
    let (turn, decided) = drive_counted(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        turn,
        |client, at| {
            while client.take(first).is_some() || client.take(second).is_some() {}
            if client.outcome(first).is_some() && settled_us.is_none() {
                settled_us = Some((client.terminal(first).unwrap().decided_us, at));
            }
            client.outcome(first).is_some() && client.outcome(second).is_some()
        },
    );
    assert_eq!(decided, 2, "the polls report the two GETs they decided");
    for (logical, id, intended) in [(2, first, now - 40), (3, second, now - 10)] {
        let terminal = client.terminal(id).expect("a decided GET has its terminal");
        assert_eq!(
            (
                terminal.attempt,
                terminal.intended_us,
                terminal.outcome,
                terminal.decided_by
            ),
            (id, intended, Outcome::Complete, Decider::Owner)
        );
        assert!(
            terminal.decided_us > now && terminal.decided_us < turn * 100 && !terminal.censored()
        );
        accounts.push((logical, Accounted::Terminal(terminal)));
        assert!(client.retire(id));
    }
    assert!(
        settled_us.is_some_and(|(decided, polled)| decided == polled && decided > now),
        "the decision takes the time of the poll that received the COMPLETE: {settled_us:?}"
    );
    owner.refusal = Some(Status::TimedOut);
    let refused = client
        .get([1; 32], 0, 1 << 20, turn * 100, 1_000_000)
        .unwrap();
    let (turn, _) = drive_counted(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        turn,
        |client, _| client.outcome(refused).is_some(),
    );
    let terminal = client.terminal(refused).unwrap();
    assert_eq!(
        (terminal.outcome, terminal.decided_by),
        (Outcome::Failed(Status::TimedOut), Decider::Owner)
    );
    assert!(
        !terminal.censored(),
        "the owner's own timeout is its terminal observation"
    );
    accounts.push((4, Accounted::Terminal(terminal)));
    assert!(client.retire(refused));
    owner.refusal = None;
    owner.silent = true;
    let now = turn * 100;
    let cancelled = client.get([1; 32], 0, 1 << 20, now, 1_000_000).unwrap();
    let timed = client
        .get_intended([1; 32], 0, 1 << 20, now, now, 3_000)
        .unwrap();
    let open = client.get([1; 32], 0, 1 << 20, now, 1_000_000).unwrap();
    client.cancel(cancelled);
    let (_, decided) = drive_counted(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        turn,
        |client, _| client.outcome(timed).is_some(),
    );
    assert_eq!(
        decided, 1,
        "the polls report the timeout; the cancel counts in the fetch report alone"
    );
    let (cancel, wait) = (
        client.terminal(cancelled).unwrap(),
        client.terminal(timed).unwrap(),
    );
    assert_eq!(
        (cancel.outcome, cancel.decided_by, cancel.decided_us),
        (Outcome::Failed(Status::Cancelled), Decider::Cancel, now),
        "the cancel takes the time of the latest admission"
    );
    assert_eq!(
        (wait.outcome, wait.decided_by),
        (Outcome::Failed(Status::TimedOut), Decider::Wait)
    );
    assert!(
        cancel.censored() && wait.censored(),
        "the owner's work for both stays unobserved"
    );
    assert!(wait.decided_us >= now + 3_000);
    assert_eq!(
        client.terminal(open),
        None,
        "the open GET is still undecided at the cutoff"
    );
    accounts.extend([
        (5, Accounted::Terminal(cancel)),
        (6, Accounted::Terminal(wait)),
        (7, Accounted::Unsent),
        (8, Accounted::Unresolved(open)),
    ]);
    let intended = [1, 2, 3, 4, 5, 6, 7, 8];
    let report = (client.fetch_report().outcomes, client.refusals());
    assert_eq!(reconcile(&intended, &accounts, report), Ok(()));
    for dropped in 0..accounts.len() {
        let mut short = accounts.clone();
        let (logical, _) = short.remove(dropped);
        assert_eq!(
            reconcile(&intended, &short, implied(&short)),
            Err(format!("logical request {logical} has 0 accounts")),
            "dropping request {logical}'s account fails the reconciliation"
        );
    }
    let (outcomes, refusals) = report;
    let dropped_classes = [
        OutcomeCounts {
            complete: 0,
            ..outcomes
        },
        OutcomeCounts {
            failed: 0,
            ..outcomes
        },
        OutcomeCounts {
            cancelled: 0,
            ..outcomes
        },
        OutcomeCounts {
            timed_out: 0,
            ..outcomes
        },
    ];
    for short in dropped_classes {
        assert!(
            reconcile(&intended, &accounts, (short, refusals)).is_err(),
            "a report that drops a class fails: {short:?}"
        );
    }
    assert!(
        reconcile(
            &intended,
            &accounts,
            (outcomes, AdmissionRefusals::default())
        )
        .is_err()
    );
}

/// One field of [`OutcomeCounts`].
type Class = fn(&OutcomeCounts) -> u64;

/// The fetch core counts every outcome shape in exactly one class: the owner's outcomes by their own class,
/// and the client's own ends by who ended them, whatever the outcome; only the client's own ends are censored.
#[test]
fn each_outcome_counts_in_one_class_by_its_decider() {
    let owner: [(Outcome, Class); 5] = [
        (Outcome::Complete, |c| c.complete),
        (Outcome::Missing, |c| c.missing),
        (Outcome::Pressure(Status::StoragePressure), |c| c.pressure),
        (Outcome::Failed(Status::TimedOut), |c| c.failed),
        (Outcome::Incomplete(Status::Cancelled), |c| c.incomplete),
    ];
    let client: [(Decider, Class); 3] = [
        (Decider::Wait, |c| c.timed_out),
        (Decider::Cancel, |c| c.cancelled),
        (Decider::Session, |c| c.session_ended),
    ];
    let cases =
        owner
            .iter()
            .map(|&(outcome, class)| (Decider::Owner, outcome, class))
            .chain(client.iter().flat_map(|&(by, class)| {
                owner.iter().map(move |&(outcome, _)| (by, outcome, class))
            }));
    for (by, outcome, class) in cases {
        let mut counted = OutcomeCounts::default();
        counted.count(outcome, by);
        assert_eq!(
            (class(&counted), counted.total()),
            (1, 1),
            "{by:?} {outcome:?}"
        );
        let terminal = Terminal {
            attempt: RequestId::from_wire(1),
            intended_us: 0,
            decided_us: 0,
            decided_by: by,
            outcome,
        };
        assert_eq!(
            terminal.censored(),
            by != Decider::Owner,
            "{by:?} {outcome:?}"
        );
    }
}

/// The history of a client whose owner restarts: the first owner activates
/// one session, or a second beside it when `reopen`, the client admits a GET
/// under it, then a restarted owner with a new boot nonce answers. With
/// `cancel_at`, the client cancels the GET just before its poll at that turn.
/// Returns the turn whose poll activated the fresh session, that poll's
/// report, and the lost and the fresh session's epochs.
fn restarted_owner_history(
    reopen: bool,
    cancel_at: Option<u64>,
) -> (u64, super::client::PollReport, u64, u64) {
    let pool = receive_pool();
    let releases = releases();
    let (client_end, mut owner_end, net) = network(64, 8384, 12, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![]);
    let mut client = client(&pool, &releases, client_end);
    client.session(0);
    let mut turn = drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        0,
        1_000,
        active,
    );
    if reopen {
        let first = client.session_epoch();
        client.session(turn * 100);
        turn = drive(
            &mut client,
            &mut owner,
            &mut owner_end,
            &net,
            turn,
            1_000,
            |client| client.state() == SessionState::Active && client.session_epoch() != first,
        );
    }
    let lost = client
        .session_epoch()
        .expect("premise: the first owner's session is active");
    let old = client
        .get([1; 32], 0, 1 << 20, turn * 100, 10_000_000)
        .unwrap();
    client.poll(turn * 100);
    net.borrow_mut().clear(1);
    let mut restarted = Owner::booted(vec![], [0x0B; 16]);
    let activations = client.session_report().activations;
    client.session(turn * 100);
    for turn in turn + 1..turn + 1_001 {
        net.borrow_mut().advance(turn);
        if cancel_at == Some(turn) {
            client.cancel(old);
        }
        let report = client.poll(turn * 100);
        if client.session_report().activations > activations {
            let fresh = client.session_epoch().expect("the fresh session is active");
            return (turn, report, lost, fresh);
        }
        restarted.turn(&mut owner_end, turn * 100);
    }
    panic!("the fresh session activates within 1000 turns");
}

/// A frame whose session ended goes unsent and counts as dropped: a GET
/// cancelled after its owner restarted, just before the poll whose READY
/// activates the fresh session, ends with the lost session, and that poll
/// drops its CANCEL and sends nothing.
/// The restarted owner numbers the fresh session's epoch as it numbered the
/// lost one, so only the session's identity, not its epoch number, tells the
/// two apart.
#[test]
fn a_cancel_queued_under_a_lost_session_is_not_sent_under_a_restarted_owner_s_same_epoch() {
    let (activated, quiet, lost, fresh) = restarted_owner_history(false, None);
    assert_eq!(lost, fresh, "premise: the restarted owner reuses the epoch");
    assert_eq!(
        quiet.sent, 0,
        "premise: the activating poll has nothing to send"
    );
    let (turn, report, ..) = restarted_owner_history(false, Some(activated));
    assert_eq!(
        turn, activated,
        "premise: the cancel leaves the activation's turn"
    );
    assert_eq!(report.sent, 0, "{report:?}");
    assert_eq!(report.dropped, quiet.dropped + 1, "{report:?}");
}

/// The sibling with a lost session numbered apart from the fresh one: the
/// same cancel's CANCEL is dropped unsent at the activating poll.
#[test]
fn a_cancel_queued_under_a_lost_session_with_another_epoch_is_dropped_unsent() {
    let (activated, quiet, lost, fresh) = restarted_owner_history(true, None);
    assert_ne!(lost, fresh, "premise: the epochs differ");
    assert_eq!(
        quiet.sent, 0,
        "premise: the activating poll has nothing to send"
    );
    let (turn, report, ..) = restarted_owner_history(true, Some(activated));
    assert_eq!(turn, activated);
    assert_eq!(report.sent, 0, "{report:?}");
    assert_eq!(report.dropped, quiet.dropped + 1, "{report:?}");
}

/// A PUT control frame past the send sequence ends its session's requests in the poll that spent the sequence, as a GET frame past it does: the session's GET ends `SessionMismatch` and the upload `NotStarted`.
#[test]
fn a_put_control_frame_past_the_send_sequence_ends_the_sessions_gets() {
    let pool = receive_pool();
    let releases = releases();
    let (client_end, mut owner_end, net) = network(64, 8384, 13, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![]);
    let mut client = client(&pool, &releases, client_end);
    client.session(0);
    let turn = drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        0,
        1_000,
        active,
    );
    assert!(active(&mut client));
    let now = turn * 100;
    let get = client.get([1; 32], 0, 1 << 20, now, 10_000_000).unwrap();
    assert_eq!(client.poll(now).sent, 1, "premise: the GET went out");
    let put = client
        .put([2; 32], CacheVersion(0), now, 1_000_000)
        .unwrap();
    client.sessions_mut().set_send(PeerId(0), u64::MAX);
    let report = client.poll(now);
    assert_eq!(
        (report.sent, report.dropped),
        (0, 1),
        "the BEGIN past the sequence is dropped: {report:?}"
    );
    assert_eq!(client.sessions_mut().active(PeerId(0)), None);
    assert_eq!(
        client.outcome(get),
        Some(Outcome::Failed(Status::SessionMismatch)),
        "the spent sequence ends the session's GET in the same poll"
    );
    assert_eq!(client.put_outcome(put), Some(UploadOutcome::NotStarted));
}

/// A PUT DATA frame past the send sequence ends its session's requests in the poll that spent the sequence: the session's GET ends `SessionMismatch` and the upload, whose control frames went out, ends `Unknown`.
#[test]
fn a_put_data_frame_past_the_send_sequence_ends_the_sessions_gets() {
    let pool = receive_pool();
    let releases = releases();
    let shared = crate::storage::owner_fixture::arena(4);
    let sources = super::memory::sources(&shared, 4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, mut owner_end, net) = network(64, 8384, 14, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![]);
    let memory = ClientMemory {
        receive: &pool,
        releases: &releases,
        requests: RequestTable::new(8, 1, 8),
        sources,
        routes: routes(),
    };
    let mut client = Client::initialize(
        CONFIG,
        memory,
        client_end,
        &keys(),
        1,
        &mut EngineBudget::new(1 << 24),
    )
    .unwrap();
    client.session(0);
    let mut turn = drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        0,
        1_000,
        active,
    );
    assert!(active(&mut client));
    let key = [7; 32];
    let get = client
        .get([1; 32], 0, 1 << 20, turn * 100, 1 << 40)
        .unwrap();
    let put = client
        .put(key, CacheVersion(0), turn * 100, 1 << 40)
        .unwrap();
    let wire = client.put_wire(put).unwrap();
    quiet(&mut client, &net, turn);
    let (authority, _) = put_frame(Kind::PutAuthority, &header(Kind::PutAuthority, wire, key));
    deliver(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        authority,
        turn,
    );
    client.prepare(put, 0, PUT_TOTAL, 60_000).unwrap();
    turn += 1;
    quiet(&mut client, &net, turn);
    let prepared = Manifest {
        allocation: PUT_SERIAL,
        metadata_len: 0,
        body_len: PUT_TOTAL,
    };
    let ready = Header {
        status: 0,
        grant: 2,
        ..super::serve::manifest_header(Kind::PutReady, wire, key, &prepared)
    };
    turn += 1;
    assert_eq!(
        deliver(&mut client, &mut owner, &mut owner_end, &net, ready, turn).dropped,
        0,
        "premise: the READY is taken"
    );
    let fragment = object(8192, 14);
    assert!(client.supply(put, 0, &fragment).is_ok());
    client.sessions_mut().set_send(PeerId(0), u64::MAX);
    let report = client.poll(turn * 100);
    assert_eq!(
        (report.sent, report.dropped),
        (0, 1),
        "the DATA frame past the sequence is dropped: {report:?}"
    );
    assert_eq!(client.sessions_mut().active(PeerId(0)), None);
    assert_eq!(
        client.outcome(get),
        Some(Outcome::Failed(Status::SessionMismatch)),
        "the spent sequence ends the session's GET in the same poll"
    );
    assert_eq!(client.put_outcome(put), Some(UploadOutcome::Unknown));
}

/// For an empty body, `encode_with_body_crc` with the crc32c of the empty byte string must produce the same header bytes as `encode`.
#[test]
fn a_frame_without_a_body_carries_the_crc_of_no_bytes() {
    use super::frame::encode_with_body_crc;
    let crc = Crc32c::detect();
    assert_eq!(crc.checksum(&[]), 0);
    let get = Header {
        principal: PRINCIPAL,
        key_epoch: 1,
        owner_nonce: [0x0A; 16],
        client_nonce: [0x0C; 16],
        sequence: 9,
        epoch: 3,
        body_len: 1 << 20,
        grant: 4,
        remaining_ms: 1_000,
        ..header(Kind::Get, 1 << 48 | 7, [5; 32])
    };
    let (mut folded, mut constant) = ([0u8; HEADER_LEN], [0u8; HEADER_LEN]);
    encode(crc, &get, [&[], &[]], &mut folded).unwrap();
    encode_with_body_crc(crc, &get, [&[], &[]], crc.checksum(&[]), &mut constant).unwrap();
    assert_eq!(folded, constant);
    assert!(parse(crc, &constant, false).is_ok());
}

/// The route check's word comparison answers what the route's own comparison answers. For a Candidate, a Bound route, a Conflict, a Dark generation and a route raised past the tenure, `bound_at` at the index `slot` returns equals `route(shard)` being Bound to the asked tenure, for the held tenure, another host at its `(g, a)`, and a later attempt and generation; a shard without a route has no index.
#[test]
fn the_route_word_comparison_answers_as_the_route_does() {
    use crate::failover::identity::Exhid;
    use crate::failover::route::{FrameKind, HolderFrame};
    use crate::net::ownership::{ActivatedEpoch, Shard, ShardGeneration, Tenure};
    let tenure = |g: u64, a: u32, x: u8| Tenure {
        generation: ShardGeneration::new(g).unwrap(),
        epoch: ActivatedEpoch::new(2 * a).unwrap(),
        host: Exhid::new([x; 16]).unwrap(),
    };
    let frame = |kind, g, a, x| HolderFrame {
        tenure: tenure(g, a, x),
        kind,
    };
    let shard = Shard::new(3).unwrap();
    let asked = [
        tenure(1, 2, 1),
        tenure(1, 2, 2),
        tenure(1, 3, 1),
        tenure(2, 1, 1),
    ];
    let histories: [&[HolderFrame]; 7] = [
        &[],
        &[frame(FrameKind::Candidate, 1, 2, 1)],
        &[frame(FrameKind::Ready, 1, 2, 1)],
        &[
            frame(FrameKind::Ready, 1, 2, 1),
            frame(FrameKind::Ready, 1, 2, 2),
        ],
        &[
            frame(FrameKind::Ready, 1, 2, 1),
            frame(FrameKind::Retired, 1, 1, 1),
        ],
        &[
            frame(FrameKind::Ready, 1, 2, 1),
            frame(FrameKind::Candidate, 1, 3, 1),
        ],
        &[
            frame(FrameKind::Ready, 1, 2, 1),
            frame(FrameKind::Ready, 2, 1, 1),
        ],
    ];
    let mut bound = 0;
    for (at, history) in histories.iter().enumerate() {
        let routes = routes();
        for frame in *history {
            routes.observe(shard, *frame);
        }
        let slot = routes.slot(shard);
        assert_eq!(slot.is_some(), !history.is_empty(), "history {at}");
        for tenure in asked {
            let expected = routes
                .route(shard)
                .is_some_and(|route| route.response(tenure));
            bound += u32::from(expected);
            if let Some(slot) = slot {
                assert_eq!(
                    routes.bound_at(slot, shard, tenure),
                    expected,
                    "history {at}, {tenure:?}"
                );
            }
        }
    }
    assert_eq!(
        bound, 2,
        "the Bound route and the raised one each bind one asked tenure"
    );
}

/// A client whose READY names a shard the full route table does not hold has no slot for its route check to read, and the session stays unrouted.
#[test]
fn a_ready_for_a_shard_the_full_table_does_not_hold_leaves_the_session_unrouted() {
    use crate::failover::identity::Exhid;
    use crate::failover::route::{FrameKind, HolderFrame};
    use crate::net::ownership::{ActivatedEpoch, Shard, ShardGeneration, Tenure};
    let pool = receive_pool();
    let releases = releases();
    let (client_end, mut owner_end, net) = network(64, 8384, 15, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![]);
    let capacity = std::num::NonZeroU32::new(1).unwrap();
    let full = std::sync::Arc::new(
        super::ShardRoutes::new(capacity, &mut EngineBudget::new(1 << 20)).unwrap(),
    );
    let other = Shard::new(3).unwrap();
    full.observe(
        other,
        HolderFrame {
            tenure: Tenure {
                generation: ShardGeneration::new(1).unwrap(),
                epoch: ActivatedEpoch::new(2).unwrap(),
                host: Exhid::new([9; 16]).unwrap(),
            },
            kind: FrameKind::Candidate,
        },
    );
    let memory = ClientMemory {
        receive: &pool,
        releases: &releases,
        requests: RequestTable::new(8, 1, 8),
        sources: Box::default(),
        routes: full.clone(),
    };
    let mut client = Client::initialize(
        CONFIG,
        memory,
        client_end,
        &keys(),
        1,
        &mut EngineBudget::new(1 << 24),
    )
    .unwrap();
    client.session(0);
    let turn = drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        0,
        1_000,
        active,
    );
    assert!(active(&mut client));
    assert_eq!(full.held(), 1);
    assert_eq!(full.slot(Shard::new(7).unwrap()), None);
    assert_eq!(
        client.get([1; 32], 0, 1 << 20, turn * 100, 1_000_000),
        Err(GetRefused::Unrouted)
    );
    let _ = client.poll(turn * 100);
    assert_eq!(
        client.get([1; 32], 0, 1 << 20, turn * 100, 1_000_000),
        Err(GetRefused::Unrouted),
        "the session stays unrouted on later polls"
    );
}

/// A client of boot nonce `[0x0C; 16]` over `transport`, so the frames it sends repeat byte for byte across runs.
fn pinned_client<'m, D: Datagrams<'m>>(
    pool: &'m PacketPool<'m>,
    releases: &'m Releases,
    transport: D,
) -> Client<'m, D> {
    client_with_nonce(pool, releases, transport, CONFIG, |nonce| {
        *nonce = [0x0C; 16];
        Ok(())
    })
}

/// A client of boot nonce `[0x0C; 16]` under `config` with `sources`, over a request table of `config.caps.slots`
/// slots.
fn pinned_client_with<'m, D: Datagrams<'m>>(
    pool: &'m PacketPool<'m>,
    releases: &'m Releases,
    transport: D,
    config: ClientConfig,
    sources: Box<[super::upload::SourceSlot<'m>]>,
) -> Client<'m, D> {
    let slots = config.caps.slots;
    let memory = ClientMemory {
        receive: pool,
        releases,
        requests: RequestTable::new(slots, 1, slots),
        sources,
        routes: routes(),
    };
    Client::initialize_with_nonce(
        config,
        memory,
        transport,
        &keys(),
        1,
        &mut EngineBudget::new(1 << 24),
        |nonce| {
            *nonce = [0x0C; 16];
            Ok(())
        },
    )
    .unwrap()
}

/// Every datagram in flight on `net` toward end `side`, in queue order; the link keeps none of them.
fn take_toward(net: &Rc<RefCell<Net<'_>>>, side: usize) -> Vec<Vec<u8>> {
    let mut taken = Vec::new();
    net.borrow_mut().retain(side, |bytes| {
        taken.push(bytes.to_vec());
        false
    });
    taken
}

/// The kind, request and sequence of one datagram the client sent, parsed as one frame.
fn kind_request_sequence(datagram: &[u8]) -> (Kind, u64, u64) {
    let header = parse(Crc32c::detect(), datagram, false)
        .expect("one canonical frame")
        .header();
    (header.kind, header.request, header.sequence)
}

/// A pinned client whose session with the test owner is active, its link and owner, and the turn reached; nothing is in flight toward the owner.
fn pinned_session<'m>(
    pool: &'m PacketPool<'m>,
    releases: &'m Releases,
) -> (
    Client<'m, LinkEnd<'m>>,
    Owner,
    LinkEnd<'m>,
    Rc<RefCell<Net<'m>>>,
    u64,
) {
    let (client_end, mut owner_end, net) = network(64, 8384, 3, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![([1; 32], object(40_000, 5))]);
    let mut client = pinned_client(pool, releases, client_end);
    client.session(0);
    let turn = drive(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        0,
        1_000,
        active,
    );
    assert_eq!(client.state(), SessionState::Active);
    assert!(take_toward(&net, 1).is_empty(), "nothing in flight");
    (client, owner, owner_end, net, turn)
}

/// The 192 bytes of the lone GET [`a_lone_get_leaves_in_one_datagram_of_the_pinned_bytes`] sends.
const LONE_GET: &str = "494d474e455430310003050000c0000000000c11000000010a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000000000000000000000000000100000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000800000000000003e801010101010101010101010101010101010101010101010101010101010101013a64418d000000000000000000000001cf6575b568c14be88434085aa5d64b55";

/// One `Client::get` and one poll under fixed keys, boot nonces and times put one 192-byte datagram toward the owner,
/// and its bytes equal [`LONE_GET`]: a lone GET's datagram is fixed byte for byte, so an owner that reads one frame
/// from each datagram reads it.
#[test]
fn a_lone_get_leaves_in_one_datagram_of_the_pinned_bytes() {
    let pool = receive_pool();
    let releases = releases();
    let (mut client, _owner, _owner_end, net, turn) = pinned_session(&pool, &releases);
    client
        .get([1; 32], 0, 1 << 20, turn * 100, 1_000_000)
        .unwrap();
    let report = client.poll(turn * 100);
    assert_eq!(report.sent, 1);
    let sent = take_toward(&net, 1);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].len(), HEADER_LEN);
    assert_eq!(kind_request_sequence(&sent[0]).0, Kind::Get);
    assert_eq!(hex(&sent[0]), LONE_GET);
}

/// Moves the link to `turn` and runs one test-owner turn, which receives what the client sent and answers it.
fn owner_turn(
    owner: &mut Owner,
    owner_end: &mut LinkEnd<'_>,
    net: &Rc<RefCell<Net<'_>>>,
    turn: u64,
) {
    net.borrow_mut().advance(turn);
    owner.turn(owner_end, turn * 100);
}

/// The datagrams toward the client that answer `request`'s START, taken off the link; every other datagram stays.
fn take_start(net: &Rc<RefCell<Net<'_>>>, request: u64) -> Vec<u8> {
    let crc = Crc32c::detect();
    let mut start = None;
    net.borrow_mut().retain(0, |bytes| {
        let header = parse(crc, bytes, false).expect("a frame").header();
        if header.kind == Kind::Start && header.request == request {
            start = Some(bytes.to_vec());
        }
        header.request != request
    });
    start.expect("the owner's START")
}

/// The two datagrams of [`a_poll_of_one_get_and_one_ack_sends_the_pinned_datagrams`] whose hand-out puts the GET
/// first, in send order.
const GET_THEN_ACK: [&str; 2] = [
    "494d474e455430310003050000c0000000000c11000000010a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0001000000000001000000000000000200000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000800000000000003e80101010101010101010101010101010101010101010101010101010101010101446aa765000000000000000000000001a567ba61f84e8d4ecc9e1e2178e9e317",
    "494d474e455430310003080000c0000000000c11000000010a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000000000000000000000000000300000005000000010000000000009c400000000000009c400000000000000005000000000000000000000000000000080000000000000000010101010101010101010101010101010101010101010101010101010101010172bb7a5a000000000000000000000001b12e53f8ad69a9d459cff5d2751b54f5",
];

/// The two datagrams of [`a_poll_of_one_get_and_one_ack_sends_the_pinned_datagrams`] whose hand-out puts the ACK
/// first, in send order.
const ACK_THEN_GET: [&str; 2] = [
    "494d474e455430310003080000c0000000000c11000000010a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0001000000000001000000000000000400000005000000010000000000009c400000000000009c400000000000000005000000000000000000000000000000080000000000000000010101010101010101010101010101010101010101010101010101010101010111cce7bd000000000000000000000001ffa7bb670227559607000d3ffc0de789",
    "494d474e455430310003050000c0000000000c11000000010a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0002000000000002000000000000000500000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000800000000000003e801010101010101010101010101010101010101010101010101010101010101014a330aa20000000000000000000000016b047fd753f29c54ca3f1a7f8f98f6bb",
];

/// A poll that hands out one GET and one ACK sends two 192-byte datagrams in hand-out order, each frame under the next
/// session sequence, and their bytes equal [`GET_THEN_ACK`] or [`ACK_THEN_GET`], by hand-out order. In the GET-first
/// poll, request A's START arrives while B's GET waits in the slot after the cursor, so the hand-out reaches B's GET
/// before it wraps to A's ACK. In the ACK-first poll, request D's START arrives alone first, so D's ACK leaves the
/// cursor at A's slot, ahead of B's. Each setup poll hands out one GET, at one time and with no owner turn between
/// them, so both GETs reach the owner in one turn as lone datagrams.
#[test]
fn a_poll_of_one_get_and_one_ack_sends_the_pinned_datagrams() {
    let pools = [receive_pool(), receive_pool()];
    let boards = [releases(), releases()];
    let (mut client, mut owner, mut owner_end, net, turn) = pinned_session(&pools[0], &boards[0]);
    let now = turn * 100;
    let a = client.get([1; 32], 0, 1 << 20, now, 1_000_000).unwrap();
    assert_eq!(client.poll(now).sent, 1);
    let [(Kind::Get, wire_a, 1)] = sent_frames(&net)[..] else {
        panic!("A's GET")
    };
    owner_turn(&mut owner, &mut owner_end, &net, turn + 1);
    let start = take_start(&net, wire_a);
    net.borrow_mut().clear(0);
    net.borrow_mut().inject(0, &start);
    let b = client
        .get([1; 32], 0, 1 << 20, now + 100, 1_000_000)
        .unwrap();
    assert_eq!((a.slot(), b.slot()), (0, 1));
    assert_eq!(client.poll(now + 100).sent, 2);
    let sent = take_toward(&net, 1);
    let shape: Vec<_> = sent
        .iter()
        .map(|datagram| kind_request_sequence(datagram))
        .collect();
    assert_eq!(shape, [(Kind::Get, 1 << 48 | 1, 2), (Kind::Ack, wire_a, 3)]);
    assert!(sent.iter().all(|datagram| datagram.len() == HEADER_LEN));
    let sent: Vec<_> = sent.iter().map(|datagram| hex(datagram)).collect();
    assert_eq!(sent, GET_THEN_ACK);

    let (mut client, mut owner, mut owner_end, net, turn) = pinned_session(&pools[1], &boards[1]);
    let now = turn * 100;
    let d = client.get([1; 32], 0, 1 << 20, now, 1_000_000).unwrap();
    assert_eq!(client.poll(now).sent, 1);
    let a = client.get([1; 32], 0, 1 << 20, now, 1_000_000).unwrap();
    assert_eq!(client.poll(now).sent, 1);
    let [(Kind::Get, wire_d, 1), (Kind::Get, wire_a, 2)] = sent_frames(&net)[..] else {
        panic!("D's and A's GETs")
    };
    owner_turn(&mut owner, &mut owner_end, &net, turn + 1);
    let start = take_start(&net, wire_a);
    let start_d = take_start(&net, wire_d);
    net.borrow_mut().clear(0);
    net.borrow_mut().inject(0, &start_d);
    assert_eq!(client.poll(now + 100).sent, 1);
    let acked: Vec<_> = take_toward(&net, 1)
        .iter()
        .map(|datagram| kind_request_sequence(datagram))
        .collect();
    assert_eq!(acked, [(Kind::Ack, wire_d, 3)]);
    net.borrow_mut().inject(0, &start);
    let b = client
        .get([1; 32], 0, 1 << 20, now + 200, 1_000_000)
        .unwrap();
    assert_eq!((d.slot(), a.slot(), b.slot()), (0, 1, 2));
    assert_eq!(client.poll(now + 200).sent, 2);
    let sent = take_toward(&net, 1);
    let shape: Vec<_> = sent
        .iter()
        .map(|datagram| kind_request_sequence(datagram))
        .collect();
    assert_eq!(shape, [(Kind::Ack, wire_a, 4), (Kind::Get, 2 << 48 | 2, 5)]);
    assert!(sent.iter().all(|datagram| datagram.len() == HEADER_LEN));
    let sent: Vec<_> = sent.iter().map(|datagram| hex(datagram)).collect();
    assert_eq!(sent, ACK_THEN_GET);
}

/// The kind, request and sequence of each datagram in flight toward the owner; the link keeps them.
fn sent_frames(net: &Rc<RefCell<Net<'_>>>) -> Vec<(Kind, u64, u64)> {
    let mut frames = Vec::new();
    net.borrow_mut().retain(1, |datagram| {
        frames.push(kind_request_sequence(datagram));
        true
    });
    frames
}

mod packed;
