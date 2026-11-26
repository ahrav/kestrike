//! Schedules whose owner transmits through the burst logic on a mock port, so
//! the owner's transmit custody is the device's: a chain the mock accepted stays
//! off its pools' free stacks until the device returns it or a proven stop ends
//! it, and the client at the other end sees only the bytes the device accepted.
//! The bridge carries each client datagram into the mock port as an arriving
//! frame and each chain the device accepted toward the client; a chain the
//! device kept uncertain reaches no one. The schedules hold the
//! owner's NIC returns and write terminals and the client's NIC returns
//! independently, then observe the outcomes and the source, extent, buffer and
//! request ledgers.

use std::cell::RefCell;
use std::rc::Rc;

use spdk_sys as sys;

use crate::instrument::charged;
use crate::native::mock::{self, Forged, MockPort, arrive_on, chain_bytes, inbound, iova};
use crate::native::{Burst, Link, OpsState, Role, Station, Wire};
use crate::storage::owner_fixture::{
    Device, SimControl, SimDisk, TestPlatform, last_read, publish, storage, write_tokens,
};
use crate::storage::{
    BufferArena, BufferConfig, EngineBudget, HugepageSize, NodeMask, PacketLayout, PoolKind,
    PoolSpec, RawPartition, Storage,
};

use super::FRAME_OVERHEAD;
use super::client::{Client, SessionState};
use super::fetch::Releases;
use super::geometry::FRAGMENT_LEN;
use super::link::{Faults, LinkEnd, Net, network};
use super::owner::{Bundle, Keys, Owner, OwnerConfig};
use super::owner_tests::{OWNER, PRINCIPALS, entries, key, payload, sourced_client};
use super::packet::PacketPool;
use super::requests::RequestCensus;
use super::upload::UploadOutcome;
use crate::sim::round::{Act, Actor, round};

/// The owner's station, with four ports.
pub(super) const LOCAL: Station = Station {
    mac: [2, 0, 0, 0, 0, 1],
    ip: [10, 0, 0, 1],
    port: 7000,
    ports: 4,
};
/// The client's station, the wire's one peer.
pub(super) const PEER: Station = Station {
    mac: [2, 0, 0, 0, 0, 2],
    ip: [10, 0, 0, 2],
    port: 9000,
    ports: 1,
};

/// Buffers of the read-response and packet header pools.
const COUNT: u32 = 8;

/// A leaked heap arena serving both the storage side (read-response sources,
/// receive-write and maintenance buffers) and the burst logic (packet header
/// and receive buffers), so the owner's reply chunks are the sources the
/// payload pool names.
fn composite_arena() -> &'static BufferArena<TestPlatform> {
    let pools = [
        PoolSpec {
            kind: PoolKind::ReadResponse,
            count: COUNT,
            buffer_len: 16384,
        },
        PoolSpec {
            kind: PoolKind::ReceiveWrite,
            count: 4,
            buffer_len: 16384,
        },
        PoolSpec {
            kind: PoolKind::Maintenance,
            count: 1,
            buffer_len: 4096,
        },
        PoolSpec {
            kind: PoolKind::PacketReceive,
            count: 32,
            buffer_len: 16384,
        },
        PoolSpec {
            kind: PoolKind::PacketHeader,
            count: COUNT,
            buffer_len: 4096,
        },
    ];
    let config = BufferConfig {
        hugepage: HugepageSize::TwoMiB,
        nodes: NodeMask::from_nodes(&[0]).unwrap(),
        pools: &pools,
    }
    .validate()
    .unwrap();
    let arena = BufferArena::initialize(
        &config,
        TestPlatform::heap(4096),
        &mut EngineBudget::new(usize::MAX),
    )
    .unwrap();
    let arena = Box::leak(Box::new(arena));
    arena.backing().base().as_ptr().expose_provenance();
    arena
}

/// A hold armed on a later read: the last read seen, the new reads still to
/// let pass before holding one, and the read held.
struct ReadHold {
    seen: Option<crate::storage::CommandToken>,
    pass: usize,
    held: Option<crate::storage::CommandToken>,
}

type BurstOwner<'s> = Owner<'s, 'static, 'static, TestPlatform, SimDisk, Burst<'static, MockPort>>;

/// The composed endpoint: an owner transmitting through the burst logic on a
/// mock port, a client across a simulated link, and the bridge carrying
/// datagrams between them; `turn` counts completed turns, each 100 µs of
/// clock for the client and the owner.
pub(super) struct Composed<'s> {
    pub(super) owner: BurstOwner<'s>,
    pub(super) control: SimControl,
    pub(super) client: Client<'static, LinkEnd<'static>>,
    pub(super) net: Rc<RefCell<Net<'static>>>,
    /// The owner's end of the simulated link, through which the bridge takes
    /// the client's datagrams as a receiver does, so the link keeps the
    /// client's device references as it would for a delivered datagram.
    link: LinkEnd<'static>,
    // leases the bridge receives the client's datagrams into
    bridge_pool: &'static PacketPool<'static>,
    pub(super) arena: &'static BufferArena<TestPlatform>,
    // receive pool state and layout the bridge builds arriving mbufs on
    receive_ops: &'static OpsState,
    layout: PacketLayout,
    /// Chains the bridge carried to the client.
    pub(super) carried: u64,
    pub(super) turn: u64,
    /// While set, the count of storage writes before the ones to hold and
    /// the writes held so far.
    holding: Option<(usize, Vec<crate::storage::CommandToken>)>,
    /// While set, the last read seen, the reads still to let pass and the
    /// read held since the arm.
    read_hold: Option<ReadHold>,
    /// While set, the datagrams the bridge carried to the client since the arm.
    tapped: Option<Vec<Vec<u8>>>,
    /// What building the wire, the burst logic and the owner, in that order,
    /// charged to the one engine budget and allocated on the heap.
    pub(super) charges: [(usize, usize); 3],
}

/// Starts the composed endpoint over `storage` with `objects` published and
/// the mock port configured by `port`, and opens the client's session.
pub(super) fn composed<'s>(
    storage: &'s Storage<TestPlatform>,
    objects: &[([u8; 32], usize, &[u8])],
    port: impl FnOnce(&mut MockPort),
) -> Composed<'s> {
    let arena = composite_arena();
    let mut device = Device::new(storage, arena);
    for (key, metadata, payload) in objects {
        publish(storage, &mut device, key, *metadata, payload);
    }
    let Device { volume, control } = device;
    let header = mock::arena_pool(arena, PoolKind::PacketHeader, Role::Header);
    let payload_pool = mock::payload_pool(arena, COUNT);
    let receive_ops = mock::arena_pool(arena, PoolKind::PacketReceive, Role::Receive);
    let receive: &'static PacketPool<'static> = Box::leak(Box::new(
        PacketPool::new(arena, PoolKind::PacketReceive, 16).unwrap(),
    ));
    // Each turn's cleanup returns every chain the device holds, as a healthy
    // device does within a turn; a schedule withholds returns explicitly.
    let mut mock_port = MockPort {
        receive: Some(receive_ops.state),
        cleanup: (0, usize::MAX),
        ..MockPort::open()
    };
    port(&mut mock_port);
    let mut budget = EngineBudget::new(1 << 26);
    let (wire, wire_charged, wire_allocated) = charged(&mut budget, |budget| {
        Wire::new(LOCAL, std::slice::from_ref(&PEER), budget).unwrap()
    });
    let translation = Box::leak(Box::new(Forged(iova, || true)));
    let watch = crate::native::mock::watch();
    let (burst, burst_charged, burst_allocated) = charged(&mut budget, |budget| {
        Burst::new(
            mock_port,
            wire,
            [header.state, payload_pool.state, receive_ops.state],
            translation,
            watch,
            8,
            budget,
        )
        .unwrap()
    });
    let cache = storage.issue_cache().unwrap();
    let registration = cache.register().unwrap();
    let keys = Keys {
        principals: &PRINCIPALS[..1],
        entries: &entries()[..1],
        epoch: 1,
        put: &PRINCIPALS[..1],
    };
    let (owner, owner_charged, owner_allocated) = charged(&mut budget, |budget| {
        Owner::start(
            OwnerConfig { batch: 8, ..OWNER },
            Bundle {
                cache,
                registration,
                volume,
            },
            keys,
            burst,
            receive,
            budget,
        )
        .map_err(|refused| refused.error)
        .unwrap()
    });
    let sourcing: &'static BufferArena<TestPlatform> =
        Box::leak(Box::new(crate::storage::owner_fixture::arena(4)));
    let pool: &'static PacketPool<'static> = Box::leak(Box::new(super::owner_tests::pool()));
    let releases: &'static Releases = Box::leak(Box::new(
        Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap(),
    ));
    let (end, link, net) = network(64, 8384, 90, [Faults::default(); 2]);
    let bridge_pool: &'static PacketPool<'static> = Box::leak(Box::new(super::owner_tests::pool()));
    let client = sourced_client(
        0,
        pool,
        releases,
        end,
        super::memory::sources(sourcing, 4, &mut EngineBudget::new(1 << 20)).unwrap(),
        super::auth::os_entropy,
    );
    let charges = [
        (wire_charged, wire_allocated),
        (burst_charged, burst_allocated),
        (owner_charged, owner_allocated),
    ];
    let mut composed = Composed {
        owner,
        control,
        client,
        net,
        link,
        bridge_pool,
        arena,
        receive_ops: receive_ops.state,
        layout: receive.layout(),
        carried: 0,
        turn: 0,
        holding: None,
        read_hold: None,
        tapped: None,
        charges,
    };
    composed.client.session(0);
    composed.turns_until(5_000, |c| c.client.state() == SessionState::Active);
    assert_eq!(composed.client.state(), SessionState::Active);
    composed
}

impl Composed<'_> {
    pub(super) fn port(&mut self) -> &mut MockPort {
        self.owner.transport_mut().port_mut()
    }

    /// Carries the client's datagrams into the mock port as arriving frames,
    /// receiving them through the link as a datagram receiver does.
    fn inbound(&mut self) {
        use super::Datagrams;
        let mut datagrams = Vec::new();
        loop {
            let mut into: [Option<super::PacketLease<'_>>; 8] = Default::default();
            let mut meta = [super::Received::default(); 8];
            let count = self
                .link
                .receive(self.bridge_pool, &mut into, &mut meta)
                .unwrap();
            if count == 0 {
                break;
            }
            for lease in into.iter().take(count).flatten() {
                datagrams.push(lease.bytes().to_vec());
            }
        }
        // A device whose link is down or lost receives nothing.
        if self.owner.transport().link() != Link::Up {
            return;
        }
        // A ring of `ring` descriptors holds `ring - 1` posted buffers, the
        // count the mock's restart posts.
        let posted = self.port().ring as usize - 1;
        for datagram in datagrams {
            // A full receive ring drops the frame, as it does under an owner
            // that stopped receiving.
            if self.port().arriving.len() >= posted {
                continue;
            }
            let (frame, meta) = inbound(&LOCAL, &PEER, &datagram);
            let mbuf = arrive_on(
                self.receive_ops,
                self.layout,
                &frame,
                meta,
                sys::RTE_PKTMBUF_HEADROOM as u16,
            );
            self.port().arriving.push(mbuf);
        }
    }

    /// Carries each chain the device accepted since the last turn toward the
    /// client, reading its bytes while the mock still holds it; the mock keeps
    /// the chain until the device returns it.
    pub(super) fn outbound(&mut self) {
        let accepted = self.port().take_accepted();
        self.carried += accepted.len() as u64;
        for head in accepted {
            let chain = chain_bytes(head);
            let datagram = &chain[FRAME_OVERHEAD..];
            if let Some(tapped) = &mut self.tapped {
                tapped.push(datagram.to_vec());
            }
            self.net.borrow_mut().inject(0, datagram);
        }
    }

    /// One turn as one controller round: the link advances, the client
    /// polls, its datagrams arrive at the mock, the device ticks, the owner
    /// polls, and the owner's new chains reach the client, in that order
    /// under the legacy schedule; a generated schedule runs the link
    /// advance first and then the order it picks. The owner's action carries
    /// the chains the device accepted before the poll as well, so a chain
    /// reaches the client before the poll's reclaim can return it.
    pub(super) fn turn(&mut self) {
        let turn = self.turn;
        let this = RefCell::new(&mut *self);
        round(&mut [
            Act::new(Actor::Link(0), &mut || {
                this.borrow().net.borrow_mut().advance(turn);
            }),
            Act::new(Actor::Client(0), &mut || {
                let _ = this.borrow_mut().client.poll(turn * 100);
            }),
            Act::new(Actor::Harness(0), &mut || this.borrow_mut().inbound()),
            Act::new(Actor::Disk(0), &mut || this.borrow().control.tick(64)),
            Act::new(Actor::Owner(0), &mut || {
                let mut this = this.borrow_mut();
                this.outbound();
                this.owner.poll(turn * 100);
                this.hold_new_writes();
                this.hold_new_read();
            }),
            Act::new(Actor::Harness(1), &mut || this.borrow_mut().outbound()),
        ]);
        self.turn += 1;
    }

    pub(super) fn turns(&mut self, turns: u64) {
        for _ in 0..turns {
            self.turn();
        }
    }

    /// Runs turns until `done` holds, at most `limit`; returns whether `done`
    /// holds after the last check.
    pub(super) fn turns_until(&mut self, limit: u64, done: impl Fn(&Self) -> bool) -> bool {
        for _ in 0..limit {
            if done(self) {
                return true;
            }
            self.turn();
        }
        done(self)
    }

    /// Holds each storage write past the holding mark that is not held yet.
    /// The owner's action calls it right after its poll, so a write the poll
    /// submits is held before any device tick can run it.
    fn hold_new_writes(&mut self) {
        let Some((from, held)) = &mut self.holding else {
            return;
        };
        for token in write_tokens(&self.control)
            .into_iter()
            .skip(*from + held.len())
        {
            self.control.hold(token);
            held.push(token);
        }
    }

    /// Arms a hold on the read the owner submits after letting `pass` new
    /// reads run; the owner's action holds it right after the poll that
    /// submits it, before any device tick can run it. The fixture's storage
    /// reads one command at a time, so each poll submits at most one read
    /// and the last read submitted identifies it.
    pub(super) fn arm_read_hold(&mut self, pass: usize) {
        self.read_hold = Some(ReadHold {
            seen: last_read(&self.control),
            pass,
            held: None,
        });
    }

    /// Counts one new read against the armed hold, letting it run while
    /// `pass` reads remain and holding it otherwise.
    fn hold_new_read(&mut self) {
        let Some(hold @ ReadHold { held: None, .. }) = &mut self.read_hold else {
            return;
        };
        let Some(token) = last_read(&self.control).filter(|token| Some(*token) != hold.seen) else {
            return;
        };
        hold.seen = Some(token);
        if hold.pass > 0 {
            hold.pass -= 1;
        } else {
            self.control.hold(token);
            hold.held = Some(token);
        }
    }

    /// Starts keeping a copy of each datagram the bridge carries to the client.
    pub(super) fn tap(&mut self) {
        self.tapped = Some(Vec::new());
    }

    /// The datagrams carried since the tap, ending it.
    pub(super) fn tapped(&mut self) -> Vec<Vec<u8>> {
        self.tapped.take().unwrap_or_default()
    }

    /// Whether a datagram carried since the tap satisfies `found`.
    pub(super) fn carried_any(&self, found: impl Fn(&[u8]) -> bool) -> bool {
        self.tapped
            .as_ref()
            .is_some_and(|tapped| tapped.iter().any(|datagram| found(datagram)))
    }

    /// The read the armed hold caught.
    pub(super) fn held_read(&self) -> Option<crate::storage::CommandToken> {
        self.read_hold.as_ref().and_then(|hold| hold.held)
    }

    /// The device keeps every chain it accepts until a stop returns it.
    pub(super) fn withhold_returns(&mut self) {
        self.port().cleanup = (0, 0);
    }

    /// The device returns every chain it holds within a turn.
    pub(super) fn return_within_turn(&mut self) {
        self.port().cleanup = (0, usize::MAX);
    }

    /// Header buffers the device holds.
    pub(super) fn chains_held(&self) -> u32 {
        self.out(PoolKind::PacketHeader)
    }

    /// Buffers of the arena's `kind` pool out of it.
    pub(super) fn out(&self, kind: PoolKind) -> u32 {
        let report = self.arena.report(kind);
        report.count - report.free
    }

    /// The client's source slots still holding a piece.
    fn sources_held(&self) -> usize {
        self.client
            .sources()
            .iter()
            .filter(|slot| slot.piece().is_some())
            .count()
    }

    pub(super) fn census(&self) -> RequestCensus {
        self.owner.census()
    }

    pub(super) fn ledger(&self, storage: &Storage<TestPlatform>) -> RawPartition {
        storage.pool_report().unwrap().ledger.unwrap().raw
    }
}

impl Composed<'_> {
    /// Starts an upload of `object` under `name` and drives it through PREPARE; returns the request.
    fn prepare(&mut self, name: u8, object: &[u8]) -> super::requests::RequestId {
        let id = self
            .client
            .put(
                key(name),
                crate::storage::CacheVersion(0),
                self.turn * 100,
                2_000_000,
            )
            .unwrap();
        let mut prepared = Err(super::upload::PrepareRefused::Phase);
        for _ in 0..400 {
            self.turn();
            prepared = self.client.prepare(id, 0, object.len() as u32, 60_000);
            if prepared != Err(super::upload::PrepareRefused::Phase) {
                break;
            }
        }
        assert_eq!(prepared, Ok(()));
        id
    }

    /// Supplies every fragment of `object` to the upload `id` as READY admits them.
    fn supply(&mut self, id: super::requests::RequestId, object: &[u8]) {
        let count = object.len().div_ceil(8192);
        let mut next = 0;
        for _ in 0..400 {
            while next < count {
                let piece = &object[next * 8192..object.len().min((next + 1) * 8192)];
                if self.client.supply(id, next as u32, piece).is_err() {
                    break;
                }
                next += 1;
            }
            if next == count {
                break;
            }
            self.turn();
        }
        assert_eq!(next, count, "every fragment supplied");
    }

    fn outcome(&self, id: super::requests::RequestId) -> Option<UploadOutcome> {
        self.client.put_outcome(id)
    }

    fn storage_writes(&self) -> Vec<crate::storage::CommandToken> {
        write_tokens(&self.control)
    }
}

/// The GET schedule over the composed endpoint: a 40,000-byte object reads
/// back exact through chains the mock accepts and keeps. Each held chain pins
/// its chunk's read-response source, so the read stalls once the device holds
/// its two chunks and resumes only as the device returns them; the owner's
/// request drains until every chain is back, and the extent ledger is
/// unchanged.
#[test]
fn a_get_through_the_mock_port_reads_back_exact_and_drains_after_the_device_returns() {
    let storage = storage(8);
    let object = payload(40_000, 11);
    let mut c = composed(&storage, &[(key(1), 0, &object)], |_| {});
    let before = c.ledger(&storage);
    c.withhold_returns();
    let id = c
        .client
        .get(key(1), 0, 1 << 20, c.turn * 100, 30_000_000)
        .unwrap();
    let mut bytes = Vec::new();
    let mut stalled = 0;
    for _ in 0..200 {
        c.turn();
        let had = bytes.len();
        while let Some(fragment) = c.client.take(id) {
            bytes.extend_from_slice(fragment.bytes());
        }
        stalled = if bytes.len() == had { stalled + 1 } else { 0 };
        if stalled > 20 {
            break;
        }
    }
    assert!(
        stalled > 20,
        "the read stalls while the device holds its chains"
    );
    assert!(!bytes.is_empty() && bytes.len() < object.len());
    assert!(c.chains_held() > 0);
    assert_eq!(
        c.owner.transport().report().exhausted,
        0,
        "the header pool has room"
    );
    let sources = c.arena.report(PoolKind::ReadResponse);
    assert!(
        sources.application == 2 && sources.free > 0,
        "the device holds the read's two chunk sources while the pool has room: {sources:?}"
    );
    assert_eq!(c.client.outcome(id), None);
    assert_eq!(
        c.census().live(),
        1,
        "the request lives while the device holds its chains"
    );
    // The device returns one chain per turn.
    c.port().cleanup = (0, 1);
    for _ in 0..400 {
        c.turn();
        while let Some(fragment) = c.client.take(id) {
            bytes.extend_from_slice(fragment.bytes());
        }
        if c.client.outcome(id).is_some() {
            break;
        }
    }
    assert_eq!(c.client.outcome(id), Some(super::fetch::Outcome::Complete));
    assert_eq!(bytes, object);
    assert!(c.client.retire(id));
    c.turns(16);
    assert_eq!(c.chains_held(), 0);
    assert_eq!(c.arena.report(PoolKind::ReadResponse).nic_held, 0);
    assert_eq!(c.census().live(), 0);
    assert_eq!(c.ledger(&storage), before, "a read changes no extent");
    assert_eq!(c.owner.transport().link(), Link::Up);
    assert_eq!(
        c.carried,
        c.owner.transport().report().sent,
        "the bridge carried every chain the device accepted"
    );
}

impl Composed<'_> {
    /// Whether the owner's storage maps `name` now, through a fresh registration.
    fn visible(&self, storage: &Storage<TestPlatform>, name: u8) -> bool {
        let mut reader = storage.register().unwrap();
        reader
            .lookup(&key(name), 4, &mut crate::storage::WorkBudget::new(1 << 16))
            .is_ok()
    }
}

/// Drives the PUT-beside-GET schedule up to the owner's recovery: two
/// source-backed fragments uploaded with their NIC returns withheld and both
/// writes held, then a GET. The device accepts the GET's first reply burst,
/// START and DATA 0, in full, then accepts DATA 1 and keeps DATA 2 uncertain.
/// Returns the upload, the GET, the two held write tokens and the ledger the
/// held writes keep reserved.
fn put_beside_partial_get(
    c: &mut Composed<'_>,
    storage: &Storage<TestPlatform>,
    object: &[u8],
    published: &[u8],
) -> (
    super::requests::RequestId,
    super::requests::RequestId,
    Vec<crate::storage::CommandToken>,
    RawPartition,
) {
    let before = c.storage_writes().len();
    let id = c.prepare(5, object);
    c.net
        .borrow_mut()
        .set_tx_release(super::link::TxRelease::Withheld);
    c.supply(id, object);
    c.holding = Some((before, Vec::new()));
    for _ in 0..40 {
        c.hold_new_writes();
        if c.holding.as_ref().is_some_and(|(_, held)| held.len() == 2) {
            break;
        }
        c.turn();
    }
    let (_, held_writes) = c.holding.take().expect("holding");
    assert_eq!(
        held_writes.len(),
        2,
        "the payload and header writes are held"
    );
    assert_eq!(
        c.net.borrow().withheld(),
        2,
        "the NIC holds both DATA sources"
    );
    assert_eq!(c.sources_held(), 2);
    assert_eq!(c.outcome(id), None);
    let reserved = c.ledger(storage);
    assert_eq!(
        reserved.reserved,
        object.len(),
        "the fill holds the upload's bytes reserved"
    );
    c.port().cleanup = (0, 0);
    let held_before = c.port().held.len();
    let sent_before = c.owner.transport().report().sent;
    let get = c
        .client
        .get(key(1), 0, 1 << 20, c.turn * 100, 2_000_000)
        .unwrap();
    let mut bytes = Vec::new();
    let mut custody = None;
    let mut armed = false;
    for _ in 0..60 {
        c.turn();
        if !armed && c.owner.transport().report().sent > sent_before {
            let port = c.port();
            port.accept = 1;
            port.uncertain = true;
            armed = true;
        }
        while let Some(fragment) = c.client.take(get) {
            bytes.extend_from_slice(fragment.bytes());
        }
        if custody.is_none() && c.owner.transport().report().quarantined == 1 {
            custody = Some((c.chains_held(), c.port().held.len()));
        }
    }
    assert_eq!(
        custody,
        Some((held_before as u32 + 4, held_before + 4)),
        "before recovery the device holds START, DATA 0 and DATA 1 accepted and DATA 2 quarantined, and the pools hold exactly the device's chains"
    );
    assert_eq!(
        c.owner.transport().report().quarantined,
        1,
        "one chain was kept uncertain"
    );
    assert_eq!(
        bytes.len(),
        2 * FRAGMENT_LEN as usize,
        "the GET got exactly the two accepted DATA fragments, never the uncertain one"
    );
    assert!(
        bytes == published[..bytes.len()],
        "the accepted DATA bytes are exact"
    );
    assert_eq!(
        c.outcome(id),
        None,
        "the upload stays undecided while its writes are held"
    );
    assert!(!c.visible(storage, 5));
    assert_eq!(
        c.ledger(storage),
        reserved,
        "the held writes keep the extent reserved"
    );
    (id, get, held_writes, reserved)
}

/// The PUT schedule beside a GET whose recovery proves the stop and fails the
/// restart: the link goes down with every held chain returned, the upload
/// publishes only once the held writes end, the client learns Unknown and
/// never a false Published, its device-held sources stay held until the NIC
/// returns them, and the owner closes once its custody drained.
#[test]
fn a_put_beside_a_partially_transmitted_get_publishes_only_after_its_held_write() {
    let storage = storage(8);
    let object = payload(2 * 8192, 21);
    let published = payload(40_000, 22);
    let mut c = composed(&storage, &[(key(1), 0, &published)], |port| {
        port.restart_error = Some(libc::EIO);
    });
    let (id, get, held_writes, _) = put_beside_partial_get(&mut c, &storage, &object, &published);
    assert_eq!(
        c.owner.transport().link(),
        Link::Down,
        "the restart failed after a proven stop"
    );
    assert_eq!(c.chains_held(), 0, "the proven stop returned every chain");
    for token in &held_writes {
        c.control.release(*token);
    }
    c.turns(40);
    assert!(
        c.visible(&storage, 5),
        "the fill published once its writes ended"
    );
    assert_eq!(c.ledger(&storage).reserved, 0);
    assert_eq!(c.outcome(id), None, "no RESULT crosses the down link");
    assert_eq!(c.sources_held(), 2, "the client's sources stay device-held");
    // The client's resends run out against the down link: the upload ends
    // Unknown, which keeps the device-held sources until the NIC returns them,
    // and the GET ends short of Complete.
    c.turns_until(400_000, |c| c.outcome(id).is_some());
    assert_eq!(c.outcome(id), Some(UploadOutcome::Unknown));
    c.turns_until(400_000, |c| c.client.outcome(get).is_some());
    assert!(
        matches!(
            c.client.outcome(get),
            Some(super::fetch::Outcome::Incomplete(_) | super::fetch::Outcome::Failed(_))
        ),
        "the GET ends short of Complete after its accepted prefix: {:?}",
        c.client.outcome(get)
    );
    assert_eq!(c.sources_held(), 2);
    c.net.borrow_mut().release_tx();
    c.turns(4);
    assert_eq!(c.sources_held(), 0, "the NIC's return frees the sources");
    let _ = c.owner.close(c.turn * 100);
    c.turns(40);
    assert_eq!(
        c.owner.blockers(),
        None,
        "the owner drained: every chain returned, every request ended"
    );
}

/// The same schedule under an unproven stop: the link is lost with every chain
/// the device holds kept, the ledgers stay where the held writes left them
/// through the upload's deadline, the extent returns unpublished once the
/// writes end, and the GET whose chains the lost device holds alone keeps the
/// owner's close blocked.
#[test]
fn an_unproven_stop_beside_a_held_upload_retains_custody_and_blocks_the_close() {
    let storage = storage(8);
    let object = payload(2 * 8192, 23);
    let published = payload(40_000, 24);
    let mut c = composed(&storage, &[(key(1), 0, &published)], |port| {
        port.proven_stops = 0
    });
    let (id, get, held_writes, reserved) =
        put_beside_partial_get(&mut c, &storage, &object, &published);
    assert_eq!(
        c.owner.transport().link(),
        Link::Lost,
        "the stop was unproven"
    );
    let held = c.chains_held();
    assert!(held > 0, "the device keeps every chain it held");
    c.turns(40);
    assert_eq!(c.chains_held(), held, "no chain returned");
    assert_eq!(
        c.ledger(&storage),
        reserved,
        "the held writes keep the extent reserved"
    );
    assert_eq!(c.outcome(id), None);
    assert!(!c.visible(&storage, 5));
    // The owner's upload deadline passes with the writes still held: the fill
    // keeps its extent reserved until its writes end, then frees it unpublished.
    c.turns(25_000);
    assert_eq!(
        c.ledger(&storage),
        reserved,
        "a timed-out fill keeps its held writes' extent"
    );
    assert_eq!(
        (c.census().active, c.census().draining),
        (0, 2),
        "the timed-out upload drains until its writes end, the GET until its chains return"
    );
    assert!(!c.visible(&storage, 5));
    for token in &held_writes {
        c.control.release(*token);
    }
    c.turns(40);
    assert_eq!(
        c.ledger(&storage).reserved,
        0,
        "the writes ended and the extent returned"
    );
    assert!(
        !c.visible(&storage, 5),
        "a timed-out upload publishes nothing"
    );
    let _ = c.owner.close(c.turn * 100);
    c.turns(40);
    assert_eq!(c.chains_held(), held, "a lost device returns nothing");
    let blockers = c.owner.blockers().expect("the close stays blocked");
    assert_eq!(
        (blockers.census.active, blockers.census.draining),
        (0, 1),
        "the GET holding the device's chains: {blockers:?}"
    );
    assert!(
        !matches!(c.client.outcome(get), Some(super::fetch::Outcome::Complete)),
        "the GET's client never learns Complete across the lost link"
    );
}

#[test]
fn a_serving_owner_stops_serving_on_sigterm_and_closes_once_its_work_in_flight_drains() {
    let scenario = || {
        let storage = storage(8);
        let object = payload(40_000, 5);
        let mut c = composed(&storage, &[(key(1), 0, &object)], |_| {});
        c.withhold_returns();
        let id = c
            .client
            .get(key(1), 0, 1 << 20, c.turn * 100, 30_000_000)
            .unwrap();
        // A non-default inherited action, with its own flags and mask, stands in for a harness's handler.
        extern "C" fn inherited_handler(
            _: libc::c_int,
            _: *mut libc::siginfo_t,
            _: *mut libc::c_void,
        ) {
        }
        /// Puts the test process's own SIGTERM action back when dropped, on a failed assertion as on success.
        struct Restore(libc::sigaction);
        impl Drop for Restore {
            fn drop(&mut self) {
                // SAFETY: restores an action `sigaction` reported for this process.
                unsafe { libc::sigaction(libc::SIGTERM, &self.0, std::ptr::null_mut()) };
            }
        }
        // SAFETY: installs a handler that does nothing, saving the test process's own action to restore below.
        let original = Restore(unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = inherited_handler
                as extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void)
                as libc::sighandler_t;
            action.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
            libc::sigemptyset(&mut action.sa_mask);
            libc::sigaddset(&mut action.sa_mask, libc::SIGUSR1);
            let mut original: libc::sigaction = std::mem::zeroed();
            assert_eq!(libc::sigaction(libc::SIGTERM, &action, &mut original), 0);
            original
        });
        let inherited = sigterm_action();
        let mut serving = super::serving::Serving::start(std::time::Duration::from_secs(600));
        let mut served = 0;
        while serving.keep() {
            c.turn();
            served += 1;
            while c.client.take(id).is_some() {}
            if served == 8 {
                assert!(c.chains_held() > 0, "the device holds the GET's chains");
                // SAFETY: raises SIGTERM on this thread, whose handler `Serving::start` installed.
                assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
            }
            assert!(served < 100, "the close request stops the loop");
        }
        assert_eq!(
            served, 8,
            "the loop stops at the first check after the signal"
        );
        assert!(!serving.keep(), "the close request holds");
        assert!(serving.signalled());
        drop(serving);
        // A loop its time limit ended stays unsignalled, whatever arrives after the last `keep`.
        let mut timed = super::serving::Serving::start(std::time::Duration::from_millis(1));
        while timed.keep() {}
        // SAFETY: raises SIGTERM on this thread, whose handler `Serving::start` installed.
        assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
        assert!(
            !timed.signalled(),
            "a signal after the time limit ended the loop does not make the run a signalled one"
        );
        drop(timed);
        let restored = sigterm_action();
        drop(original);
        assert_eq!(
            restored.sa_sigaction, inherited.sa_sigaction,
            "dropping the loop restores the SIGTERM handler the test inherited"
        );
        assert_eq!(
            restored.sa_flags, inherited.sa_flags,
            "dropping the loop restores the inherited action's flags, SA_SIGINFO included"
        );
        // SAFETY: reads membership in a mask `sigaction` filled.
        assert_eq!(
            unsafe { libc::sigismember(&restored.sa_mask, libc::SIGUSR1) },
            1,
            "dropping the loop restores the inherited action's mask"
        );
        let _ = c.owner.close(c.turn * 100);
        c.turns(4);
        assert!(
            c.owner.blockers().is_some(),
            "the close waits while the device holds the GET's chains"
        );
        c.port().cleanup = (0, 1);
        for _ in 0..400 {
            c.turn();
            while c.client.take(id).is_some() {}
            if c.owner.blockers().is_none() {
                break;
            }
        }
        assert_eq!(c.chains_held(), 0);
        assert_eq!(
            c.owner.blockers(),
            None,
            "the owner closes once every chain returned and every request ended"
        );
    };
    // The generated corpus already owns a child; run here to preserve its
    // thread-local schedule. A standalone invocation gets its own child.
    if crate::exact_child::is_child(
        "net::composed_tests::generated_orders_keep_every_listed_outcome",
    ) {
        scenario();
    } else {
        crate::exact_child::run(
            "net::composed_tests::a_serving_owner_stops_serving_on_sigterm_and_closes_once_its_work_in_flight_drains",
            std::time::Duration::from_secs(30),
            scenario,
        );
    }
}

#[test]
fn generated_orders_keep_every_listed_outcome() {
    // Keep the schedule and its SIGTERM scenario in the same child so the
    // thread-local generated order reaches every scenario without leaking
    // signal state into other tests.
    crate::exact_child::run(
        "net::composed_tests::generated_orders_keep_every_listed_outcome",
        std::time::Duration::from_secs(30),
        || {
            use crate::sim::round::{ROOTS, generated};

            for root in ROOTS {
                generated(
                    root,
                    "a_get_through_the_mock_port_reads_back_exact_and_drains_after_the_device_returns",
                    a_get_through_the_mock_port_reads_back_exact_and_drains_after_the_device_returns,
                );
                generated(
                    root,
                    "a_put_beside_a_partially_transmitted_get_publishes_only_after_its_held_write",
                    a_put_beside_a_partially_transmitted_get_publishes_only_after_its_held_write,
                );
                generated(
                    root,
                    "a_serving_owner_stops_serving_on_sigterm_and_closes_once_its_work_in_flight_drains",
                    a_serving_owner_stops_serving_on_sigterm_and_closes_once_its_work_in_flight_drains,
                );
                generated(
                    root,
                    "an_unproven_stop_beside_a_held_upload_retains_custody_and_blocks_the_close",
                    an_unproven_stop_beside_a_held_upload_retains_custody_and_blocks_the_close,
                );
            }
        },
    );
}

/// The action `sigaction` reports for SIGTERM: handler, flags and mask.
fn sigterm_action() -> libc::sigaction {
    // SAFETY: a zeroed `sigaction` is a valid out-parameter, and a null new action reads the
    // disposition without changing it.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        assert_eq!(
            libc::sigaction(libc::SIGTERM, std::ptr::null(), &mut action),
            0
        );
        action
    }
}
