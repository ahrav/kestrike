//! The owner endpoint over a simulated storage stack and the seeded simulator, with the client endpoint as its peer.

use std::cell::RefCell;
use std::rc::Rc;

use crate::storage::owner_fixture::{
    Device, Fault, Plant, QuiesceMode, SimControl, SimDisk, TestPlatform, arena, forge, invalidate,
    last_read, narrow, one_chain_storage, publish, publish_sequence, reserve, sequence_storage,
    storage,
};
use crate::storage::{BufferArena, CacheVersion, EngineBudget, Storage};
use crate::storage::{
    HeaderMismatch, LookupError, ReadRefusal, ReadStatus, Refusal, RefusalReason, SubmitRefusal,
};

use super::adapters::fills_written;
use super::auth::{KeyEntry, KeyError};
use super::client::{Client, ClientConfig, ClientMemory, SessionState};
use super::datagram::{DatagramError, Datagrams, Outgoing, PeerId, Received};
use super::fetch::{FetchConfig, Outcome, Releases};
use super::frame::{MAX_WINDOW, Status};
use super::link::{Faults, LinkEnd, Net, network};
use super::owner::{
    Bundle, Keys, MAINTAIN_REST_US, Owner, OwnerConfig, OwnerError, OwnerRekeyError, TurnSources,
    lookup_status, read_status, refusal_status,
};
use super::pace::Shaper;
pub(crate) use super::packet::test_arena as packet_arena;
use super::packet::{PacketLease, PacketPool};
use super::parked::FollowConfig;
use super::put::PutConfig;
use super::requests::{RequestId, RequestTable};
use super::serve::ServeConfig;
use super::session::{Caps, RekeyError};
use super::upload::UploadOutcome;
use crate::oracle::Obligation::{Bytes, Isolation, Resources};
use crate::sim::round::{Act, Actor, push_each, round};

pub(super) const ENDPOINT: u32 = 0x00E1_0001;
pub(crate) const PRINCIPALS: [u32; 2] = [0x0C11, 0x0C12];
const KEYS: [[u8; 32]; 2] = [[0x6B; 32], [0x6C; 32]];
pub(super) const CAPS: Caps = Caps {
    slots: 4,
    window: 4,
};

pub(crate) const OWNER: OwnerConfig = OwnerConfig {
    endpoint: ENDPOINT,
    caps: CAPS,
    serve: ServeConfig {
        retry_us: 2_000,
        attempts: 50,
        linger_us: 50_000,
        rate_per_sec: 10_000_000,
        burst: 64,
        slots: 4,
        replies: 8,
        max_wait_us: 30_000_000,
    },
    batch: 8,
    lookup_retries: 3,
    lookup_work: 1024,
    request_slots: 4,
    peer_requests: 2,
    get_reserve: 1,
    peer_get_reserve: 1,
    maintain_work: 1 << 12,
    put: PutConfig {
        puts: 2,
        peer_puts: 1,
        run_waiters: 2,
        get_backlog: u32::MAX,
        commands: 8,
        command_bytes: 1 << 20,
        window: 4,
        copy_bytes: 1 << 16,
        publish_tries: 4,
        publish_work: 1 << 12,
    },
    follow: FollowConfig {
        followers: 4,
        fill_followers: 2,
        peer_followers: 2,
        wake: 4,
    },
};

pub(super) fn client_config(peer: usize) -> ClientConfig {
    ClientConfig {
        endpoint: ENDPOINT,
        principal: PRINCIPALS[peer],
        caps: CAPS,
        fetch: FetchConfig {
            retry_us: 3_000,
            attempts: 30,
            window: 4,
            boxes: 16,
        },
        upload: super::upload::UploadConfig {
            retry_us: 3_000,
            attempts: 20,
        },
        bootstrap_retry_us: 5_000,
        bootstrap_attempts: 4,
        batch: 8,
    }
}

pub(crate) fn entries() -> [KeyEntry<'static>; 2] {
    [
        KeyEntry {
            principal: PRINCIPALS[0],
            key: &KEYS[0],
        },
        KeyEntry {
            principal: PRINCIPALS[1],
            key: &KEYS[1],
        },
    ]
}

pub(super) fn pool() -> PacketPool<'static> {
    super::packet::test_pool(32, 8).unwrap()
}

pub(super) fn key(n: u8) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = n;
    key[31] = n.wrapping_mul(7);
    key
}

pub(super) fn payload(len: usize, seed: u64) -> Vec<u8> {
    let mut rng = crate::storage::seeded::SplitMix64::new(seed);
    (0..len).map(|_| rng.next_u64() as u8).collect()
}

/// How the next receive reports one of its datagrams: from no peer,
/// truncated, or as a vacant slot whose lease was returned. `Surplus`
/// ignores its position: the receive reports one datagram past the slots
/// it was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Relabel {
    Stranger,
    Truncated,
    Vacant,
    Surplus,
}

thread_local! {
    /// Datagrams of the next [`Mux`] receive on this thread to report
    /// differently, by position in the batch.
    pub(super) static RELABEL: std::cell::RefCell<Vec<(usize, Relabel)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// While a swallow is pending, the next [`Mux`] receive that fills a slot
/// drops the last lease, reports one fewer datagram, and spends the swallow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Swallow {
    Unset,
    Pending,
    Spent,
}

/// The owner's transport over one simulated link per peer: the owner reaches peer `i` through link `i`, and each receive takes an equal share of the batch from every link, modelling a socket that interleaves its senders' datagrams; a later link's call error ends the batch with the count so far. It records the largest batch one `send` call carried, the calls that failed, the reclaim and receive calls, and the receives that followed a reclaim with no receive between.
pub(crate) struct Mux<'a> {
    ends: Vec<LinkEnd<'a>>,
    strangers: Vec<LinkEnd<'a>>,
    pub(super) largest_batch: usize,
    pub(super) failed_calls: u64,
    pub(super) largest_failed_batch: usize,
    pub(super) reclaims: u64,
    pub(super) receives: u64,
    pub(super) receives_after_reclaim: u64,
    pub(super) egress_reads: u64,
    reclaimed: bool,
    swallow: Swallow,
}

impl<'a> Mux<'a> {
    pub(crate) fn new(ends: Vec<LinkEnd<'a>>) -> Self {
        Self {
            ends,
            strangers: Vec::new(),
            largest_batch: 0,
            failed_calls: 0,
            largest_failed_batch: 0,
            reclaims: 0,
            receives: 0,
            receives_after_reclaim: 0,
            egress_reads: 0,
            reclaimed: false,
            swallow: Swallow::Unset,
        }
    }

    /// Adds `end` as a link whose datagrams `receive` reports with no peer, as it does for a source outside the configured peer list.
    pub(super) fn with_stranger(mut self, end: LinkEnd<'a>) -> Self {
        self.strangers.push(end);
        self
    }

    /// Only the first call arms this multiplexer's swallow. Its next receive
    /// that fills a slot drops the last lease it filled and reports one
    /// fewer, so the owner's `received` falls one short of what its links
    /// delivered.
    pub(super) fn swallow_next(&mut self) {
        if self.swallow == Swallow::Unset {
            self.swallow = Swallow::Pending;
        }
    }

    /// Whether a receive of this multiplexer dropped a lease for the swallow
    /// [`Self::swallow_next`] armed.
    pub(super) fn swallowed(&self) -> bool {
        self.swallow == Swallow::Spent
    }

    pub(super) fn swallow_unarmed(&self) -> bool {
        self.swallow == Swallow::Unset
    }

    pub(super) fn rejoin(&self, at: usize) -> LinkEnd<'a> {
        self.ends[at].rejoin()
    }
}

impl<'a> Datagrams<'a> for Mux<'a> {
    fn receive<'p>(
        &mut self,
        pool: &'p PacketPool<'a>,
        into: &mut [Option<PacketLease<'p>>],
        meta: &mut [Received],
    ) -> Result<usize, DatagramError> {
        self.receives += 1;
        self.receives_after_reclaim += u64::from(std::mem::take(&mut self.reclaimed));
        // Each link takes an equal share of the batch, as a socket interleaves its senders' datagrams.
        let links = self.ends.len() + self.strangers.len();
        let share = (into.len().min(meta.len()) / links).max(1);
        let peers = (0..self.ends.len()).map(|peer| Some(PeerId(peer as u16)));
        let sources = peers.chain(std::iter::repeat(None));
        let mut got = 0;
        let links = self.ends.iter_mut().chain(&mut self.strangers).zip(sources);
        for (at, (end, peer)) in links.enumerate() {
            let room = share.min(into.len().min(meta.len()) - got);
            // As the receive contract requires, every lease handed back
            // counts: a later link's call error ends the batch with the
            // count so far, and only the first link's error fails the call.
            let n = match end.receive(pool, &mut into[got..got + room], &mut meta[got..got + room])
            {
                Ok(n) => n,
                Err(error) if at == 0 => return Err(error),
                Err(_) => break,
            };
            for entry in &mut meta[got..got + n] {
                entry.peer = peer;
            }
            got += n;
        }
        if self.swallow == Swallow::Pending && got > 0 {
            got -= 1;
            into[got] = None;
            self.swallow = Swallow::Spent;
        }
        for (at, relabel) in RELABEL.with(|relabels| std::mem::take(&mut *relabels.borrow_mut())) {
            match relabel {
                Relabel::Stranger => meta[at].peer = None,
                Relabel::Truncated => meta[at].truncated = true,
                Relabel::Vacant => into[at] = None,
                Relabel::Surplus => got = into.len() + 1,
            }
        }
        Ok(got)
    }

    fn rx_ring(&self) -> u32 {
        self.ends
            .iter()
            .chain(&self.strangers)
            .map(Datagrams::rx_ring)
            .sum()
    }

    fn reclaim(&mut self) {
        self.reclaims += 1;
        self.reclaimed = true;
        self.ends
            .iter_mut()
            .chain(&mut self.strangers)
            .for_each(Datagrams::reclaim);
    }

    fn egress_exceeded(&mut self) -> Option<u64> {
        self.egress_reads += 1;
        None
    }

    fn send(&mut self, batch: &[Outgoing<'_, 'a>]) -> Result<usize, DatagramError> {
        self.largest_batch = self.largest_batch.max(batch.len());
        let mut sent = 0;
        for datagram in batch {
            let Some(end) = self.ends.get_mut(usize::from(datagram.peer.0)) else {
                break;
            };
            let taken = match end.send(&[Outgoing {
                peer: PeerId(0),
                ..*datagram
            }]) {
                Ok(taken) => taken,
                // As `sendmmsg` does, a failed first datagram fails the call and a later one ends the accepted prefix.
                Err(error) if sent == 0 => {
                    self.failed_calls += 1;
                    self.largest_failed_batch = self.largest_failed_batch.max(batch.len());
                    return Err(error);
                }
                Err(_) => break,
            };
            if taken == 0 {
                break;
            }
            sent += 1;
        }
        Ok(sent)
    }
}

pub(crate) type TestOwner<'s, 'a, 'm> = Owner<'s, 'a, 'm, TestPlatform, SimDisk, Mux<'a>>;

/// A started owner over `storage`, its objects published first, serving `peers` simulated links.
pub(super) fn start<'s, 'a, 'm>(
    storage: &'s Storage<TestPlatform>,
    buffers: &'a BufferArena<TestPlatform>,
    receive: &'m PacketPool<'a>,
    objects: &[([u8; 32], usize, &[u8])],
    ends: Vec<LinkEnd<'a>>,
) -> (TestOwner<'s, 'a, 'm>, SimControl) {
    start_over(OWNER, storage, buffers, receive, objects, Mux::new(ends))
}

fn start_over<'s, 'a, 'm>(
    config: OwnerConfig,
    storage: &'s Storage<TestPlatform>,
    buffers: &'a BufferArena<TestPlatform>,
    receive: &'m PacketPool<'a>,
    objects: &[([u8; 32], usize, &[u8])],
    transport: Mux<'a>,
) -> (TestOwner<'s, 'a, 'm>, SimControl) {
    let mut device = Device::new(storage, buffers);
    for (key, metadata, payload) in objects {
        publish(storage, &mut device, key, *metadata, payload);
    }
    let Device { volume, control } = device;
    let cache = storage.issue_cache().unwrap();
    let registration = cache.register().unwrap();
    let peers = transport.ends.len();
    // The second peer, when there is one, holds PUT permission.
    let keys = Keys {
        principals: &PRINCIPALS[..peers],
        entries: &entries()[..peers],
        epoch: 1,
        put: &PRINCIPALS[1..peers.max(1)],
    };
    let owner = Owner::start(
        config,
        Bundle {
            cache,
            registration,
            volume,
        },
        keys,
        transport,
        receive,
        &mut EngineBudget::new(1 << 26),
    )
    .map_err(|refused| refused.error)
    .unwrap();
    (owner, control)
}

pub(super) fn client<'m>(
    peer: usize,
    pool: &'m PacketPool<'m>,
    releases: &'m Releases,
    end: LinkEnd<'m>,
) -> Client<'m, LinkEnd<'m>> {
    sourced_client(
        peer,
        pool,
        releases,
        end,
        Box::default(),
        super::auth::os_entropy,
    )
}

/// A client of peer `peer` with source slots `sources`, its boot nonce from `nonce`.
pub(crate) fn sourced_client<'m>(
    peer: usize,
    pool: &'m PacketPool<'m>,
    releases: &'m Releases,
    end: LinkEnd<'m>,
    sources: Box<[super::upload::SourceSlot<'m>]>,
    nonce: impl FnOnce(&mut [u8; 16]) -> Result<(), super::auth::EntropyError>,
) -> Client<'m, LinkEnd<'m>> {
    configured_client(
        peer,
        client_config(peer),
        pool,
        releases,
        end,
        sources,
        nonce,
        super::client_tests::routes(),
    )
}

/// [`sourced_client`] of peer `peer` under `config` and `routes`, over a request table of as many slots as its session
/// caps.
#[allow(clippy::too_many_arguments)]
pub(super) fn configured_client<'m>(
    peer: usize,
    config: ClientConfig,
    pool: &'m PacketPool<'m>,
    releases: &'m Releases,
    end: LinkEnd<'m>,
    sources: Box<[super::upload::SourceSlot<'m>]>,
    nonce: impl FnOnce(&mut [u8; 16]) -> Result<(), super::auth::EntropyError>,
    routes: std::sync::Arc<super::ShardRoutes>,
) -> Client<'m, LinkEnd<'m>> {
    let memory = ClientMemory {
        receive: pool,
        releases,
        requests: RequestTable::new(config.caps.slots, 1, config.caps.slots),
        sources,
        routes,
    };
    let key = [entries()[peer]];
    Client::initialize_with_nonce(
        config,
        memory,
        end,
        &key,
        1,
        &mut EngineBudget::new(1 << 24),
        nonce,
    )
    .unwrap()
}

/// Turns every link, every client, the device and the owner as one controller round per turn from turn `start` until `done` holds or `turns` pass, 100 µs per turn; returns the turn reached.
pub(super) fn drive<'m>(
    clients: &mut [&mut Client<'m, LinkEnd<'m>>],
    owner: &mut TestOwner<'_, '_, '_>,
    control: &SimControl,
    nets: &[Rc<RefCell<Net<'_>>>],
    start: u64,
    turns: u64,
    mut done: impl FnMut(&mut [&mut Client<'m, LinkEnd<'m>>]) -> bool,
) -> u64 {
    let nets: Vec<_> = nets.iter().collect();
    for turn in start..start + turns {
        super::oracle_endpoint_tests::turn_both(
            clients,
            &mut [(&mut *owner, control)],
            &nets,
            turn,
        );
        if done(clients) {
            return turn + 1;
        }
    }
    start + turns
}

/// Takes every fragment of `id` the client has, in order, into `bytes`.
pub(crate) fn collect<'m>(
    client: &mut Client<'m, LinkEnd<'m>>,
    id: RequestId,
    bytes: &mut Vec<u8>,
) {
    while let Some(fragment) = client.take(id) {
        assert_eq!(fragment.offset(), bytes.len() as u64, "in order");
        bytes.extend_from_slice(fragment.bytes());
    }
}

/// A multi-frame GET under seeded loss, duplication and reordering delivers the exact bytes of the one published version and ends `Complete`, through a fresh lookup and a volume read.
#[test]
fn a_multi_frame_get_delivers_one_version_under_faults() {
    let object = payload(40_000, 1);
    for (seed, faults) in [
        (1, Faults::default()),
        (
            2,
            Faults {
                loss: 10,
                duplicate: 10,
                reorder: 20,
                ..Faults::default()
            },
        ),
        (
            3,
            Faults {
                loss: 20,
                ..Faults::default()
            },
        ),
    ] {
        let storage = storage(8);
        let buffers = arena(8);
        let receive = pool();
        let client_pool = pool();
        let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
        let (client_end, owner_end, net) = network(64, 8384, seed, [faults; 2]);
        let (mut owner, control) = start(
            &storage,
            &buffers,
            &receive,
            &[(key(1), 10, &object)],
            vec![owner_end],
        );
        let mut client = client(0, &client_pool, &releases, client_end);
        client.session(0);
        let nets = [net];
        let turn = drive(
            &mut [&mut client],
            &mut owner,
            &control,
            &nets,
            0,
            5_000,
            |clients| clients[0].state() == SessionState::Active,
        );
        assert_eq!(client.state(), SessionState::Active, "seed {seed}");
        let id = client
            .get(key(1), 64, 1 << 20, turn * 100, 5_000_000)
            .unwrap();
        let mut bytes = Vec::new();
        drive(
            &mut [&mut client],
            &mut owner,
            &control,
            &nets,
            turn,
            50_000,
            |clients| {
                collect(clients[0], id, &mut bytes);
                clients[0].outcome(id).is_some()
            },
        );
        collect(&mut client, id, &mut bytes);
        assert_eq!(client.outcome(id), Some(Outcome::Complete), "seed {seed}");
        assert_eq!(bytes, object, "seed {seed}");
    }
}

/// Two multi-frame GETs in flight from one client make its ACKs arrive next to each other, so the owner tags them in pairs; every paired ACK still authenticates, the owner drops nothing, and both GETs deliver their exact bytes.
#[test]
fn adjacent_acks_authenticate_in_pairs_and_deliver_every_byte() {
    let objects = [payload(40_000, 11), payload(40_000, 12)];
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 21, [Faults::default(); 2]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 10, &objects[0]), (key(2), 10, &objects[1])],
        vec![owner_end],
    );
    let mut client = client(0, &client_pool, &releases, client_end);
    client.session(0);
    let nets = [net];
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        0,
        5_000,
        |clients| clients[0].state() == SessionState::Active,
    );
    assert_eq!(client.state(), SessionState::Active);
    super::owner::PAIRED_BARE.with(|count| count.set(0));
    let ids = [1u8, 2].map(|n| {
        client
            .get(key(n), 64, 1 << 20, turn * 100, 5_000_000)
            .unwrap()
    });
    let mut bytes = [Vec::new(), Vec::new()];
    drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        50_000,
        |clients| {
            for (id, bytes) in ids.iter().zip(bytes.iter_mut()) {
                collect(clients[0], *id, bytes);
            }
            ids.iter().all(|id| clients[0].outcome(*id).is_some())
        },
    );
    for (id, bytes) in ids.iter().zip(bytes.iter_mut()) {
        collect(&mut client, *id, bytes);
        assert_eq!(client.outcome(*id), Some(Outcome::Complete));
    }
    assert_eq!(bytes[0], objects[0]);
    assert_eq!(bytes[1], objects[1]);
    assert!(
        super::owner::PAIRED_BARE.with(std::cell::Cell::get) >= 2,
        "at least one adjacent pair of ACKs took paired tags"
    );
    assert_eq!(owner.report().dropped, 0, "every paired ACK authenticated");
}

/// A client whose window spans one command still gets a command ahead: the owner reads it past the client's grant, and the GET delivers every byte in order.
#[test]
fn a_window_of_one_command_still_reads_ahead_and_delivers_every_byte() {
    let object = payload(40_000, 6);
    let storage = crate::storage::owner_fixture::storage_reading_ahead(8);
    let buffers = arena(12);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 14, [Faults::default(); 2]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 10, &object)],
        vec![owner_end],
    );
    let mut config = client_config(0);
    // The fixture's commands carry 16 KiB, two fragments.
    config.fetch.window = 2;
    let key_entry = [entries()[0]];
    let mut client = Client::initialize(
        config,
        ClientMemory {
            receive: &client_pool,
            releases: &releases,
            requests: RequestTable::new(4, 1, 4),
            sources: Box::default(),
            routes: super::client_tests::routes(),
        },
        client_end,
        &key_entry,
        1,
        &mut EngineBudget::new(1 << 24),
    )
    .unwrap();
    client.session(0);
    let nets = [net];
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        0,
        5_000,
        |clients| clients[0].state() == SessionState::Active,
    );
    let id = client
        .get(key(1), 64, 1 << 20, turn * 100, 5_000_000)
        .unwrap();
    let mut bytes = Vec::new();
    drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        50_000,
        |clients| {
            collect(clients[0], id, &mut bytes);
            clients[0].outcome(id).is_some()
        },
    );
    collect(&mut client, id, &mut bytes);
    assert_eq!(client.outcome(id), Some(Outcome::Complete));
    assert_eq!(bytes, object);
    assert!(
        owner.volume_report().reads_ahead > 0,
        "a command ahead past a one-command grant"
    );
}
/// On a volume that reads one or three commands ahead, a multi-command GET submits commands ahead of the one outstanding or verifying, and still delivers every byte in order under faults; the object of the deeper volume spans four commands.
#[test]
fn a_get_on_a_volume_that_reads_ahead_submits_a_command_ahead_and_delivers_every_byte() {
    for (seed, faults, ahead, object) in [
        (11, Faults::default(), 1, payload(40_000, 4)),
        (
            12,
            Faults {
                loss: 10,
                reorder: 20,
                ..Faults::default()
            },
            1,
            payload(40_000, 4),
        ),
        (13, Faults::default(), 3, payload(49_000, 7)),
        (
            14,
            Faults {
                loss: 10,
                reorder: 20,
                ..Faults::default()
            },
            3,
            payload(49_000, 7),
        ),
    ] {
        let storage = crate::storage::owner_fixture::storage_reading_ahead_by(8, ahead);
        // Each of the four request slots holds two response buffers plus one per command ahead.
        let buffers = arena(4 * (2 + u32::from(ahead)));
        let receive = pool();
        let client_pool = pool();
        let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
        let (client_end, owner_end, net) = network(64, 8384, seed, [faults; 2]);
        let (mut owner, control) = start(
            &storage,
            &buffers,
            &receive,
            &[(key(1), 10, &object)],
            vec![owner_end],
        );
        let mut client = client(0, &client_pool, &releases, client_end);
        client.session(0);
        let nets = [net];
        let turn = drive(
            &mut [&mut client],
            &mut owner,
            &control,
            &nets,
            0,
            5_000,
            |clients| clients[0].state() == SessionState::Active,
        );
        let id = client
            .get(key(1), 64, 1 << 20, turn * 100, 5_000_000)
            .unwrap();
        let mut bytes = Vec::new();
        drive(
            &mut [&mut client],
            &mut owner,
            &control,
            &nets,
            turn,
            50_000,
            |clients| {
                collect(clients[0], id, &mut bytes);
                clients[0].outcome(id).is_some()
            },
        );
        collect(&mut client, id, &mut bytes);
        assert_eq!(client.outcome(id), Some(Outcome::Complete), "seed {seed}");
        assert_eq!(bytes, object, "seed {seed}");
        assert!(
            owner.volume_report().reads_ahead > 0,
            "a command ahead, seed {seed}"
        );
    }
}

/// Submitting a read's last command ends its grant demand even when the volume has spare read-ahead depth; the grant pass stays idle while that command is outstanding.
#[test]
fn a_read_whose_last_command_is_outstanding_leaves_no_grant_pass_pending() {
    let object = payload(4_000, 9);
    for ahead in [1, 3] {
        let storage = crate::storage::owner_fixture::storage_reading_ahead_by(8, ahead);
        let buffers = arena(4 * (2 + u32::from(ahead)));
        let receive = pool();
        let client_pool = pool();
        let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
        let (client_end, owner_end, net) = network(64, 8384, 15, [Faults::default(); 2]);
        let (mut owner, control) = start(
            &storage,
            &buffers,
            &receive,
            &[(key(1), 10, &object)],
            vec![owner_end],
        );
        let mut client = client(0, &client_pool, &releases, client_end);
        let turn = open(
            &mut client,
            &mut owner,
            &control,
            std::slice::from_ref(&net),
            0,
        );
        let id = client
            .get(key(1), 64, 1 << 20, turn * 100, 5_000_000)
            .unwrap();
        let (token, mut turn) = hold_next_read(&mut client, &mut owner, &control, &net, turn);
        for _ in 0..20 {
            round(&mut [
                Act::new(Actor::Link(0), &mut || net.borrow_mut().advance(turn)),
                Act::new(Actor::Client(0), &mut || {
                    let _ = client.poll(turn * 100);
                }),
                Act::new(Actor::Owner(0), &mut || owner.poll(turn * 100)),
            ]);
            assert!(
                !owner.grant_pending(),
                "the grant pass idles while the last command is held, {ahead} ahead"
            );
            turn += 1;
        }
        control.release(token);
        let mut bytes = Vec::new();
        drive(
            &mut [&mut client],
            &mut owner,
            &control,
            &[net],
            turn,
            20_000,
            |clients| {
                collect(clients[0], id, &mut bytes);
                clients[0].outcome(id).is_some()
            },
        );
        collect(&mut client, id, &mut bytes);
        assert_eq!(client.outcome(id), Some(Outcome::Complete), "{ahead} ahead");
        assert_eq!(bytes, object, "{ahead} ahead");
    }
}

#[test]
fn a_get_whose_first_command_waits_still_reads_ahead_and_completes() {
    let object = payload(40_000, 5);
    let storage = crate::storage::owner_fixture::storage_reading_ahead(8);
    let buffers = arena(12);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 13, [Faults::default(); 2]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 10, &object)],
        vec![owner_end],
    );
    let mut client = client(0, &client_pool, &releases, client_end);
    client.session(0);
    let nets = [net];
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        0,
        5_000,
        |clients| clients[0].state() == SessionState::Active,
    );
    control.refuse_next(SubmitRefusal {
        reason: RefusalReason::QueueFull,
        code: None,
    });
    let id = client
        .get(key(1), 64, 1 << 20, turn * 100, 5_000_000)
        .unwrap();
    let (mut held, mut bytes) = (Vec::new(), Vec::new());
    drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        20_000,
        |clients| {
            while let Some(fragment) = clients[0].take(id) {
                assert_eq!(fragment.offset(), bytes.len() as u64, "in order");
                bytes.extend_from_slice(fragment.bytes());
                if held.len() < 2 {
                    held.push(fragment);
                }
            }
            clients[0].outcome(id).is_some()
        },
    );
    assert_eq!(
        owner.volume_report().reads_waited,
        1,
        "the first command waited"
    );
    assert_eq!(client.outcome(id), Some(Outcome::Complete));
    assert_eq!(bytes, object);
    assert_eq!(
        owner.volume_report().reads_ahead,
        2,
        "both commands after the waited first one went ahead"
    );
    drop(held);
}

/// Read-response buffers out of the free stack: retained, NIC-held or under a command.
pub(super) fn read_custody(buffers: &BufferArena<TestPlatform>) -> u32 {
    let report = buffers.report(crate::storage::PoolKind::ReadResponse);
    report.count - report.free - report.retired
}

/// A chunk the receipt passed stays retained while the link holds a reference to it, so with every return withheld a read stops at two buffers, holding no more than two at any turn, whatever the client acknowledged. Once the link returns its references with no further ACK or receive, the owner drops the chunks in its next turns, grants the read's next command and finishes the GET with exact bytes and one version; the request then drains.
#[test]
fn a_withheld_return_stops_the_read_at_two_buffers_until_the_device_returns() {
    use super::link::TxRelease;
    let object = payload(45_000, 31);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 31, [Faults::default(); 2]);
    net.borrow_mut().set_tx_release(TxRelease::Withheld);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 10, &object)],
        vec![owner_end],
    );
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let turn = open(&mut client, &mut owner, &control, &nets, 0);
    let id = client
        .get(key(1), 64, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let mut bytes = Vec::new();
    let mut most = 0;
    // Shorter than the client's retry budget, so the client still waits.
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        300,
        |clients| {
            collect(clients[0], id, &mut bytes);
            most = most.max(read_custody(&buffers));
            false
        },
    );
    assert_eq!(
        client.outcome(id),
        None,
        "the read waits on the device's returns"
    );
    assert_eq!(
        (most, read_custody(&buffers)),
        (2, 2),
        "at most two buffers, both retained for the device"
    );
    assert!(
        !bytes.is_empty() && bytes.len() < object.len(),
        "the client took what the two buffers held"
    );
    let pending = nets[0].borrow().pending(1);
    let before = last_read(&control);
    nets[0].borrow_mut().release_tx();
    nets[0].borrow_mut().set_tx_release(TxRelease::AtDelivery);
    // The returns alone restart the read: the owner's next turn drops both chunks and grants the next command before any frame arrives.
    owner.poll(turn * 100);
    assert_eq!(
        nets[0].borrow().pending(1),
        pending,
        "no frame reached the owner"
    );
    assert_ne!(
        last_read(&control),
        before,
        "a dropped chunk let the read's next command go out"
    );
    assert!(read_custody(&buffers) <= 2);
    drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn + 1,
        20_000,
        |clients| {
            collect(clients[0], id, &mut bytes);
            most = most.max(read_custody(&buffers));
            clients[0].outcome(id).is_some()
        },
    );
    collect(&mut client, id, &mut bytes);
    assert_eq!(client.outcome(id), Some(Outcome::Complete));
    assert_eq!(bytes, object);
    assert_eq!(most, 2, "per-read occupancy never exceeded two");
    assert_eq!(nets[0].borrow().report(0).altered, 0);
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        30_000,
        2_000,
        |_| false,
    );
    assert_eq!(
        owner.census().draining + owner.census().active,
        0,
        "the request drained by turn {turn}"
    );
    assert_eq!(read_custody(&buffers), 0);
}

/// Returns delayed and reordered past the final ACK, under loss, duplication and reordering: every GET delivers its exact bytes and one version, no retained buffer is freed or reacquired before its last reference returns, so no delivered datagram differs from its bytes at send, and no read holds more than two buffers, a chunk with several references among them counting once.
#[test]
fn delayed_and_reordered_returns_keep_every_byte() {
    use super::link::TxRelease;
    let objects = [payload(45_000, 41), payload(40_000, 42)];
    for (seed, release, faults) in [
        (
            141,
            TxRelease::Delayed(40),
            Faults {
                loss: 10,
                duplicate: 20,
                reorder: 20,
                ..Faults::default()
            },
        ),
        (
            142,
            TxRelease::Delayed(200),
            Faults {
                reorder: 30,
                delay: 30,
                duplicate: 30,
                ..Faults::default()
            },
        ),
    ] {
        let transfer = transfer_twice(seed, release, faults, &objects);
        assert_eq!(
            transfer.altered, 0,
            "seed {seed}: no delivered byte changed after send"
        );
        assert_eq!(transfer.done, [true, true], "seed {seed}");
        assert_eq!(
            transfer.mismatched, 0,
            "seed {seed}: no buffer was freed while held"
        );
        let net = transfer.net;
        assert!(
            net.duplicated > 0 && net.reordered > 0,
            "seed {seed}: the faults were reached: {net:?}"
        );
        assert!(transfer.retries > 0, "seed {seed}: the owner retransmitted");
        assert!(
            transfer.shared,
            "seed {seed}: several sends shared one source"
        );
    }
}

/// The negative control: the same schedules with the link returning each reference at send, ignoring the count, let storage reacquire and overwrite a buffer before a delayed copy of its datagram reaches the client, which the byte oracle sees.
#[test]
fn premature_returns_fail_the_byte_oracle() {
    use super::link::TxRelease;
    let objects = [payload(45_000, 41), payload(40_000, 42)];
    let faults = Faults {
        reorder: 30,
        delay: 30,
        duplicate: 30,
        ..Faults::default()
    };
    let premature = transfer_twice(42, TxRelease::Premature, faults, &objects);
    assert!(
        premature.altered > 0,
        "a reused buffer changed a datagram in flight"
    );
    let counted = transfer_twice(42, TxRelease::AtDelivery, faults, &objects);
    assert_eq!(
        (counted.altered, counted.done),
        (0, [true, true]),
        "the counted schedule keeps every byte"
    );
}

/// What [`transfer_twice`] observed.
struct Transfer {
    /// Datagrams toward the client whose delivered bytes differed from their bytes at send.
    altered: u64,
    /// Whether each GET completed with its exact bytes.
    done: [bool; 2],
    /// The direction toward the client's counters.
    net: super::link::NetReport,
    /// Owner retransmission rounds.
    retries: u64,
    /// The link held more device references than buffers at some turn, so several sends shared one source.
    shared: bool,
    /// Device returns that named no live reference, which a buffer freed while held would cause.
    mismatched: u64,
}

/// Two GETs, one after the other, of `objects` over a link with `release` and `faults` in both directions, each GET waiting for the previous request to drain; checks at every turn that no read holds more than two buffers and, at the end, that every buffer returned to its free stack.
fn transfer_twice(
    seed: u64,
    release: super::link::TxRelease,
    faults: Faults,
    objects: &[Vec<u8>; 2],
) -> Transfer {
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, seed, [faults; 2]);
    net.borrow_mut().set_tx_release(release);
    let published = [
        (key(1), 10, objects[0].as_slice()),
        (key(2), 0, objects[1].as_slice()),
    ];
    let (mut owner, control) = start(&storage, &buffers, &receive, &published, vec![owner_end]);
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let mut turn = open(&mut client, &mut owner, &control, &nets, 0);
    let mut done = [false; 2];
    let mut shared = false;
    for (at, object) in objects.iter().enumerate() {
        let id = client
            .get(key(at as u8 + 1), 64, 1 << 20, turn * 100, 30_000_000)
            .unwrap();
        let mut bytes = Vec::new();
        turn = drive(
            &mut [&mut client],
            &mut owner,
            &control,
            &nets,
            turn,
            60_000,
            |clients| {
                collect(clients[0], id, &mut bytes);
                let custody = read_custody(&buffers);
                assert!(
                    custody <= 2,
                    "seed {seed}: a read held more than two buffers"
                );
                shared |= nets[0].borrow().nic_held() > custody as usize;
                clients[0].outcome(id).is_some()
            },
        );
        collect(&mut client, id, &mut bytes);
        done[at] = client.outcome(id) == Some(Outcome::Complete) && bytes == *object;
        done[at] &= client.retire(id);
        // The request keeps its share while it drains, so the next GET waits for the drain.
        for _ in 0..5_000 {
            if owner.census().active + owner.census().draining == 0 {
                break;
            }
            turn = drive(
                &mut [&mut client],
                &mut owner,
                &control,
                &nets,
                turn,
                1,
                |_| false,
            );
        }
        assert_eq!(
            owner.census().active + owner.census().draining,
            0,
            "seed {seed}: GET {at} drained"
        );
    }
    nets[0].borrow_mut().release_tx();
    let report = buffers.report(crate::storage::PoolKind::ReadResponse);
    assert_eq!(
        report.free + report.retired,
        report.count,
        "seed {seed}: every buffer returned"
    );
    let net = nets[0].borrow().report(0);
    Transfer {
        altered: net.altered,
        done,
        net,
        retries: owner.serve_report().retries,
        shared,
        mismatched: report.mismatched,
    }
}

/// A logical end with device references out, its read held and its ERROR queued stops every send at once and keeps the request draining, its slot and share held, until all three end: each run ends a different condition last, so every pair of the ERROR's send, the read's drain and the device's return leaves it draining, and the third releases it. The run that ends the ERROR last checks the pending ERROR while the read drained and the device returned.
#[test]
fn a_draining_request_waits_for_its_error_its_read_and_its_device_returns() {
    for last in 0..3 {
        drain_with_last(last);
    }
}

/// A read error with device references out ends the request with a queued ERROR; the request keeps draining while the ERROR waits and while the device holds the chunk, and drains once both end.
#[test]
fn a_read_error_with_device_references_out_keeps_the_request_draining() {
    use super::link::TxRelease;
    let object = payload(45_000, 52);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 52, [Faults::default(); 2]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &object)],
        vec![owner_end],
    );
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let turn = open(&mut client, &mut owner, &control, &nets, 0);
    nets[0].borrow_mut().set_tx_release(TxRelease::Withheld);
    client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let (token, turn) = hold_next_read(&mut client, &mut owner, &control, &nets[0], turn);
    control.release(token);
    let (second, turn) = hold_next_read(&mut client, &mut owner, &control, &nets[0], turn);
    // Both directions block, so the owner's ERROR stays queued and no client CANCEL clears it.
    let block = Faults {
        would_block: 100,
        ..Faults::default()
    };
    nets[0].borrow_mut().set_faults(0, block);
    nets[0].borrow_mut().set_faults(1, block);
    control.fault(
        second,
        Fault::Status(crate::storage::DeviceStatus::Kernel(-libc::EIO)),
    );
    control.release(second);
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        400,
        |_| false,
    );
    assert_eq!(
        owner.census().draining,
        1,
        "the ERROR is queued and the device holds the first chunk"
    );
    let queued = owner.census().live();
    nets[0].borrow_mut().set_faults(0, Faults::default());
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        400,
        |_| false,
    );
    assert_eq!(
        owner.census().draining,
        1,
        "the ERROR went out; the device still holds the chunk"
    );
    let sent = owner.census().live();
    nets[0].borrow_mut().release_tx();
    drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        400,
        |_| false,
    );
    assert_eq!(owner.census().draining + owner.census().active, 0);
    let verdict =
        super::oracle_endpoint_tests::draining_share([queued, sent, owner.census().live()]);
    assert!(verdict.satisfies(&[Resources]), "{verdict:?}");
    assert_eq!(read_custody(&buffers), 0);
}

/// One controller round at `turn`: the link, the client, the device and the owner, in that order. Returns the kinds of the frames queued toward the owner after the client's poll, which the owner's poll receives later in the same round, and the read the owner's poll submitted, if any; holding that read before the device's next tick keeps it outstanding.
fn observed_turn<'m>(
    client: &mut Client<'m, LinkEnd<'m>>,
    owner: &mut TestOwner<'_, '_, '_>,
    control: &SimControl,
    net: &Rc<RefCell<Net<'_>>>,
    turn: u64,
) -> (
    Vec<super::frame::Kind>,
    Option<crate::storage::CommandToken>,
) {
    let crc = crate::storage::Crc32c::detect();
    let before = last_read(control);
    let mut kinds = Vec::new();
    round(&mut [
        Act::new(Actor::Link(0), &mut || net.borrow_mut().advance(turn)),
        Act::new(Actor::Client(0), &mut || {
            let _ = client.poll(turn * 100);
            net.borrow_mut().retain(1, |bytes| {
                for bytes in super::rules::frames_of(bytes) {
                    if let Ok(frame) = super::frame::parse(crc, bytes, false) {
                        kinds.push(frame.header().kind);
                    }
                }
                true
            });
        }),
        Act::new(Actor::Disk(0), &mut || control.tick(64)),
        Act::new(Actor::Owner(0), &mut || owner.poll(turn * 100)),
    ]);
    (
        kinds,
        last_read(control).filter(|token| Some(*token) != before),
    )
}

/// Witness `put-ring-get-refusal-drop`: peer 0's reply ring of two holds two PUT ERRORs its spent pacing tokens keep queued, and its next GET refusal is dropped at insertion; the GET ends once, at its deadline, the ring later sends exactly the two PUT ERRORs, and the owner's request records and buffers release only after the link and the device return their references.
///
/// Geometry: one peer whose owner paces at 1 frame per second with a burst of 2 and a reply ring of 2, two GETs per peer and a PUT grant list that excludes the peer; a 1,000-byte object in one fragment; GET deadlines 20 ms after each GET and a PUT deadline 4 ms after its BEGIN; lossless links and 100 µs per turn, every frame a poll sends receivable at its receiver's next poll.
///
/// Schedule: GET 1 stages START and DATA while the link holds no transmit slot, so the owner's first batch goes out as a one-frame prefix and the owner refunds the DATA's token; once the link has slots, the DATA spends the second token and the link withholds its reference. The client's PUT BEGIN and its resend 3 ms later are refused, both PUT ERRORs fill the ring, and the PUT ends at its 4 ms deadline. GET 2 and GET 3 then arrive in one turn: GET 2 takes the peer's second request share and its read is held by the device, and GET 3 is refused under request pressure into the full ring. Once every deadline has passed, the clock moves 2 s so the pacer refills and the ring drains, and 2 s more show it empty; the client then replaces its session, the link returns its references, and the device completes the held read.
#[test]
fn a_dropped_get_refusal_ends_at_its_deadline_and_custody_waits_for_the_devices() {
    use super::frame::Kind;
    use super::link::{LinkLimits, TxRelease, UNBOUNDED};
    const WAIT_US: u64 = 20_000;
    const PUT_WAIT_US: u64 = 4_000;
    let paced = OwnerConfig {
        serve: ServeConfig {
            rate_per_sec: 1,
            burst: 2,
            replies: 2,
            ..OWNER.serve
        },
        ..OWNER
    };
    let object = payload(1_000, 61);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 61, [Faults::default(); 2]);
    let (mut owner, control) = start_over(
        paced,
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &object)],
        Mux::new(vec![owner_end]),
    );
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let net = &nets[0];
    let mut turn = open(&mut client, &mut owner, &control, &nets, 0);
    let crc = crate::storage::Crc32c::detect();
    // Every frame the link carries toward the client, parsed after each round; the link keeps them, so the client still receives each.
    let toward_client = |seen: &mut Vec<super::frame::Header>| {
        net.borrow_mut().retain(0, |bytes| {
            if let Ok(frame) = super::frame::parse(crc, bytes, false) {
                seen.push(frame.header());
            }
            true
        });
    };
    // The custody check after every round: each reference the link or the device holds keeps a read-response buffer out of the free stack.
    let assert_held = || {
        let held = net.borrow().nic_held() + control.outstanding();
        assert!(
            read_custody(&buffers) as usize >= held,
            "a buffer under a device reference returned to the free stack"
        );
    };
    // The same check once the owner holds no buffer of its own beyond those references: each buffer out of the free stack is under one reference.
    let assert_custody = || {
        let held = net.borrow().nic_held() + control.outstanding();
        assert_eq!(
            read_custody(&buffers) as usize,
            held,
            "buffers out of the free stack against device references"
        );
    };
    let mut seen = Vec::new();
    net.borrow_mut().set_tx_release(TxRelease::Withheld);
    // With no transmit slot the link takes START, whose bytes it copies, and refuses the DATA after it.
    net.borrow_mut().set_limits(LinkLimits {
        tx_slots: 0,
        ..UNBOUNDED
    });
    let first = client.get(key(1), 0, 1 << 20, turn * 100, WAIT_US).unwrap();
    let first_deadline = turn * 100 + WAIT_US;
    let start = turn;
    while net.borrow().report(0).full == 0 {
        assert!(turn < start + 100, "GET 1's batch reached the link");
        observed_turn(&mut client, &mut owner, &control, net, turn);
        toward_client(&mut seen);
        assert_held();
        turn += 1;
    }
    assert_eq!(
        seen.iter().map(|header| header.kind).collect::<Vec<_>>(),
        [Kind::Start],
        "the link accepted START and refused the DATA after it"
    );
    net.borrow_mut().set_limits(UNBOUNDED);
    let start = turn;
    while net.borrow().nic_held() == 0 {
        assert!(turn < start + 100, "GET 1's DATA reached the link");
        observed_turn(&mut client, &mut owner, &control, net, turn);
        toward_client(&mut seen);
        assert_held();
        turn += 1;
    }
    assert_custody();
    // The PUT ends before GET 3 arrives, and resends of the live GET 1 and GET 2 queue no reply, so after GET 3's refusal only GET 3's own resends meet the ring. The BEGIN's refusal settles its identity, so the resend replays the refusal into the ring without a second refusal count.
    let put = client
        .put(
            key(7),
            crate::storage::CacheVersion(0),
            turn * 100,
            PUT_WAIT_US,
        )
        .unwrap();
    let put_wire = client.put_wire(put).unwrap();
    let start = turn;
    while owner.serve_report().reply_high_water < 2 {
        assert!(
            turn < start + 100,
            "the PUT BEGIN and its resend reached the owner"
        );
        observed_turn(&mut client, &mut owner, &control, net, turn);
        toward_client(&mut seen);
        assert_custody();
        turn += 1;
    }
    assert_eq!(
        (
            owner.put_report().refused_other,
            owner.serve_report().dropped_replies
        ),
        (1, 0),
        "the ring holds the PUT ERROR and its replay"
    );
    assert!(
        seen.iter().all(|header| !header.kind.is_put()),
        "pacing keeps both PUT ERRORs queued"
    );
    let start = turn;
    while client.put_outcome(put).is_none() {
        assert!(turn < start + 100, "the PUT ended at its deadline");
        observed_turn(&mut client, &mut owner, &control, net, turn);
        toward_client(&mut seen);
        assert_custody();
        turn += 1;
    }
    let second = client.get(key(1), 0, 1 << 20, turn * 100, WAIT_US).unwrap();
    let third = client.get(key(1), 0, 1 << 20, turn * 100, WAIT_US).unwrap();
    let third_wire = client.get_wire(third).unwrap();
    let deadline = turn * 100 + WAIT_US;
    let dropped = owner.serve_report().dropped_replies;
    let (kinds, read) = observed_turn(&mut client, &mut owner, &control, net, turn);
    let token = read.expect("GET 2's read was submitted");
    control.hold(token);
    toward_client(&mut seen);
    assert_custody();
    turn += 1;
    assert_eq!(
        kinds,
        [Kind::Get, Kind::Get],
        "only GET 2 and GET 3 reached this poll"
    );
    assert_eq!(
        owner.census().active,
        2,
        "GET 1 and GET 2 hold the peer's shares"
    );
    assert_eq!(
        owner.serve_report().dropped_replies,
        dropped + 1,
        "GET 3's refusal is the one reply the full ring dropped"
    );
    // Each request keeps the one outcome it reaches, and GET 2 and GET 3 reach theirs at the poll of their deadline.
    let ids = [first, second, third];
    let mut outcomes = [None; 3];
    while turn * 100 <= deadline + 1_000 {
        observed_turn(&mut client, &mut owner, &control, net, turn);
        toward_client(&mut seen);
        assert_custody();
        for (request, id) in ids.into_iter().enumerate() {
            match (outcomes[request], client.outcome(id)) {
                (Some((_, kept)), now) => {
                    assert_eq!(now, Some(kept), "request {request} keeps its one outcome")
                }
                (None, Some(outcome)) => outcomes[request] = Some((turn * 100, outcome)),
                (None, None) => {}
            }
        }
        turn += 1;
    }
    let ended = outcomes.map(|outcome| outcome.expect("every GET ended"));
    assert_eq!(
        ended[0],
        (first_deadline, Outcome::Failed(Status::TimedOut)),
        "GET 1 ended at the poll of its deadline, its fragment untaken"
    );
    assert_eq!(
        ended[1],
        (deadline, Outcome::Failed(Status::TimedOut)),
        "GET 2 ended at the poll of its deadline"
    );
    assert_eq!(
        ended[2],
        (deadline, Outcome::Failed(Status::TimedOut)),
        "GET 3 ended at the poll of its deadline"
    );
    assert!(
        owner.serve_report().dropped_replies > dropped + 1,
        "GET 3's resends met the full ring too"
    );
    assert_eq!(owner.census().active, 0);
    assert_eq!(
        owner.census().draining,
        2,
        "the link and the device hold GET 1 and GET 2"
    );
    // Two seconds refill the pacer, so the ring sends exactly what it kept: the two PUT ERRORs.
    turn += 20_000;
    let kept = seen.len();
    for _ in 0..10 {
        observed_turn(&mut client, &mut owner, &control, net, turn);
        toward_client(&mut seen);
        assert_custody();
        turn += 1;
    }
    let replies: Vec<_> = seen[kept..]
        .iter()
        .filter(|header| header.kind.is_put() || header.kind == Kind::Error)
        .map(|header| (header.kind, header.request))
        .collect();
    assert_eq!(
        replies,
        [(Kind::PutError, put_wire), (Kind::PutError, put_wire)],
        "the full ring kept its two PUT ERRORs"
    );
    // Two more seconds refill the pacer again, and the drained ring sends nothing more.
    turn += 20_000;
    let kept = seen.len();
    for _ in 0..10 {
        observed_turn(&mut client, &mut owner, &control, net, turn);
        toward_client(&mut seen);
        assert_custody();
        turn += 1;
    }
    assert!(
        seen[kept..]
            .iter()
            .all(|header| !header.kind.is_put() && header.kind != Kind::Error),
        "the ring held only the two PUT ERRORs"
    );
    assert!(
        seen.iter()
            .all(|header| !(header.kind == Kind::Error && header.request == third_wire)),
        "no ERROR for GET 3 reached the link"
    );
    assert_eq!(owner.report().failed, 0, "no frame failed in the transport");
    client.session(turn * 100);
    let replaced = client.session_epoch();
    let start = turn;
    while client.state() != SessionState::Active || client.session_epoch() == replaced {
        assert!(turn < start + 2_000, "the replacement session opened");
        observed_turn(&mut client, &mut owner, &control, net, turn);
        assert_custody();
        turn += 1;
    }
    for _ in 0..20 {
        observed_turn(&mut client, &mut owner, &control, net, turn);
        assert_custody();
        turn += 1;
    }
    assert_eq!(
        owner.census().draining,
        2,
        "session replacement leaves custody held"
    );
    net.borrow_mut().release_tx();
    let start = turn;
    while owner.census().draining == 2 {
        assert!(
            turn < start + 1_000,
            "GET 1 drained once the link returned its reference"
        );
        observed_turn(&mut client, &mut owner, &control, net, turn);
        assert_custody();
        turn += 1;
    }
    assert_eq!(
        owner.census().draining,
        1,
        "the device still holds GET 2's read"
    );
    control.release(token);
    let start = turn;
    while owner.census() != Default::default() {
        assert!(
            turn < start + 1_000,
            "GET 2 drained once the device completed its read"
        );
        observed_turn(&mut client, &mut owner, &control, net, turn);
        assert_custody();
        turn += 1;
    }
    assert_eq!(
        read_custody(&buffers),
        0,
        "every buffer returned to the free stack"
    );
    // The client keeps each GET's one outcome through the replacement and releases each request once.
    for (request, id) in ids.into_iter().enumerate() {
        assert_eq!(client.outcome(id), Some(ended[request].1));
        assert!(client.retire(id), "request {request} releases");
        assert!(!client.retire(id), "request {request} releases once");
    }
    assert_eq!(client.reserved(), 0, "the GETs returned every receive box");
}

/// A closed owner sends and receives nothing, yet its turns still take the device's returns through the transport, so a request ended by the close with chunks the device still reads drains, and the owner shuts down once the last reference returns.
#[test]
fn a_closed_owner_drains_once_the_device_returns_its_references() {
    use super::link::TxRelease;
    let object = payload(45_000, 53);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 53, [Faults::default(); 2]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &object)],
        vec![owner_end],
    );
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let turn = open(&mut client, &mut owner, &control, &nets, 0);
    nets[0].borrow_mut().set_tx_release(TxRelease::Delayed(300));
    client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        40,
        |_| false,
    );
    assert!(
        nets[0].borrow().nic_held() > 0,
        "the device holds sent chunks"
    );
    let _ = owner.close(turn * 100);
    let mut at = turn;
    while owner.blockers().is_some() && at < turn + 1_000 {
        round(&mut [
            Act::new(Actor::Link(0), &mut || nets[0].borrow_mut().advance(at)),
            Act::new(Actor::Disk(0), &mut || control.tick(64)),
            Act::new(Actor::Owner(0), &mut || owner.poll(at * 100)),
        ]);
        at += 1;
    }
    assert!(
        owner.blockers().is_none(),
        "the returns arrived through the closed owner's turns"
    );
    assert!(at > turn + 1, "the close waited on the device's returns");
    assert_eq!(nets[0].borrow().nic_held(), 0);
    assert!(owner.shutdown().is_ok());
}

/// Each turn takes the transport's device returns first, open or closed: one reclaim per turn, and every receive follows its turn's reclaim.
#[test]
fn each_turn_takes_device_returns_before_it_receives() {
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let (_client_end, owner_end, _net) = network(64, 8384, 1, [Faults::default(); 2]);
    let (mut owner, control) = start(&storage, &buffers, &receive, &[], vec![owner_end]);
    for turn in 0..5 {
        round(&mut [
            Act::new(Actor::Disk(0), &mut || control.tick(64)),
            Act::new(Actor::Owner(0), &mut || owner.poll(turn * 100)),
        ]);
    }
    let _ = owner.close(500);
    let mut turn = 5;
    while (owner.blockers().is_some() || turn < 8) && turn < 1_000 {
        round(&mut [
            Act::new(Actor::Disk(0), &mut || control.tick(64)),
            Act::new(Actor::Owner(0), &mut || owner.poll(turn * 100)),
        ]);
        turn += 1;
    }
    let Ok(shutdown) = owner.shutdown() else {
        panic!("a quiesced owner shuts down");
    };
    let mux = shutdown.transport;
    assert_eq!(mux.reclaims, turn, "one reclaim per turn, open or closed");
    assert_eq!(mux.receives, 5, "a closed owner receives nothing");
    assert_eq!(
        mux.receives_after_reclaim, 5,
        "every receive follows its turn's reclaim"
    );
}

#[test]
fn an_unreported_allowance_count_is_read_once_per_control_interval() {
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let (_client_end, owner_end, _net) = network(64, 8384, 1, [Faults::default(); 2]);
    let (mut owner, control) = start(&storage, &buffers, &receive, &[], vec![owner_end]);
    for turn in 0..1_000 {
        round(&mut [
            Act::new(Actor::Disk(0), &mut || control.tick(64)),
            Act::new(Actor::Owner(0), &mut || owner.poll(turn * 100)),
        ]);
    }
    let _ = owner.close(100_000);
    let mut turn = 1_000;
    while owner.blockers().is_some() && turn < 1_100 {
        round(&mut [
            Act::new(Actor::Disk(0), &mut || control.tick(64)),
            Act::new(Actor::Owner(0), &mut || owner.poll(turn * 100)),
        ]);
        turn += 1;
    }
    let Ok(shutdown) = owner.shutdown() else {
        panic!("an idle owner shuts down");
    };
    let elapsed_us = turn * 100;
    assert!(
        shutdown.transport.egress_reads <= elapsed_us / Shaper::CONTROL_US,
        "{} reads over {elapsed_us} µs",
        shutdown.transport.egress_reads
    );
    assert!(shutdown.transport.egress_reads >= 4);
}

/// Runs the drain scenario, ending the ERROR send (0), the read (1) or the device returns (2) last.
fn drain_with_last(last: usize) {
    use super::link::TxRelease;
    let object = payload(45_000, 51);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 51, [Faults::default(); 2]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &object)],
        vec![owner_end],
    );
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let turn = open(&mut client, &mut owner, &control, &nets, 0);
    nets[0].borrow_mut().set_tx_release(TxRelease::Withheld);
    // A short deadline ends the request with a TimedOut ERROR while its second command is held.
    let id = client.get(key(1), 0, 1 << 20, turn * 100, 30_000).unwrap();
    let (token, turn) = hold_next_read(&mut client, &mut owner, &control, &nets[0], turn);
    control.release(token);
    let (second, turn) = hold_next_read(&mut client, &mut owner, &control, &nets[0], turn);
    let mut taken = Vec::new();
    collect(&mut client, id, &mut taken);
    assert!(
        nets[0].borrow().nic_held() > 0,
        "the first chunk's datagrams are held by the device"
    );
    // Both directions block, so the owner's ERROR stays queued and the client's CANCEL, which would clear it, never arrives.
    let block = Faults {
        would_block: 100,
        ..Faults::default()
    };
    nets[0].borrow_mut().set_faults(0, block);
    nets[0].borrow_mut().set_faults(1, block);
    let sent = owner.report().sent;
    let mut turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        600,
        |_| false,
    );
    assert_eq!(
        owner.report().sent,
        sent,
        "the ended request sends nothing, its ERROR blocked"
    );
    let draining = |owner: &TestOwner<'_, '_, '_>| owner.census().draining;
    assert_eq!(draining(&owner), 1, "the deadline ended the request");
    let ends: [&dyn Fn(); 3] = [
        &|| nets[0].borrow_mut().set_faults(0, Faults::default()),
        &|| control.release(second),
        &|| nets[0].borrow_mut().release_tx(),
    ];
    let order: Vec<usize> = (0..3).filter(|&at| at != last).chain([last]).collect();
    for (step, &at) in order.iter().enumerate() {
        ends[at]();
        turn = drive(
            &mut [&mut client],
            &mut owner,
            &control,
            &nets,
            turn,
            400,
            |_| false,
        );
        let expected = u32::from(step < 2);
        assert_eq!(
            draining(&owner),
            expected,
            "last {last}, after ending {order:?}[..={step}]"
        );
    }
    assert_eq!(owner.census().active, 0);
    assert_eq!(
        read_custody(&buffers),
        0,
        "last {last}: every buffer returned"
    );
}

/// A burst's lookahead covers only GETs that parse: datagrams whose kind
/// byte says GET but that fail to parse, from a peer or from a source
/// outside the peer list, hint no index line, and each is dropped.
#[test]
fn a_burst_of_unparseable_gets_prepares_no_lookup() {
    use super::frame::{KEY_AT, KIND_AT, Kind};
    use crate::storage::prefetch::{READ_HINTS, WRITE_HINTS};
    let object = payload(4_000, 3);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let (_client_end, owner_end, peer_net) = network(64, 8384, 3, [Faults::default(); 2]);
    let (_stranger_end, stranger_owner_end, stranger_net) =
        network(64, 8384, 4, [Faults::default(); 2]);
    let (mut owner, control) = start_over(
        OWNER,
        &storage,
        &buffers,
        &receive,
        &[(key(1), 10, &object)],
        Mux::new(vec![owner_end]).with_stranger(stranger_owner_end),
    );
    let datagram = |kind: Kind, n: u8| {
        let mut bytes = [0u8; 192];
        bytes[KIND_AT] = kind as u8;
        bytes[KEY_AT..KEY_AT + 32].copy_from_slice(&key(n));
        bytes
    };
    let hints = || {
        (
            READ_HINTS.with(std::cell::Cell::get),
            WRITE_HINTS.with(std::cell::Cell::get),
        )
    };
    let turn = |owner: &mut TestOwner<'_, '_, '_>, gets: u8, from: &Rc<RefCell<Net<'_>>>| {
        for n in 1..=gets {
            from.borrow_mut().inject(1, &datagram(Kind::Get, n));
        }
        peer_net.borrow_mut().inject(1, &datagram(Kind::Ack, 1));
        stranger_net
            .borrow_mut()
            .inject(1, &datagram(Kind::Hello, 1));
        // The counts before the round: the link advances change neither, and
        // a generated order may run the owner's poll right after them.
        let (reads, writes) = hints();
        let dropped = owner.report().dropped;
        round(&mut [
            Act::new(Actor::Link(0), &mut || peer_net.borrow_mut().advance(1)),
            Act::new(Actor::Link(1), &mut || stranger_net.borrow_mut().advance(1)),
            Act::new(Actor::Disk(0), &mut || control.tick(64)),
            Act::new(Actor::Owner(0), &mut || owner.poll(100)),
        ]);
        let (reads_after, writes_after) = hints();
        (
            owner.report().dropped - dropped,
            reads_after - reads,
            writes_after - writes,
        )
    };
    let settled = (0..16).any(|_| {
        let (dropped, reads, writes) = turn(&mut owner, 0, &peer_net);
        assert_eq!(dropped, 2, "no datagram parses");
        (reads, writes) == (0, 0)
    });
    assert!(settled, "a GET-free turn settles to no hint");
    assert_eq!(
        turn(&mut owner, 3, &peer_net),
        (5, 0, 0),
        "every datagram is dropped, and an unparseable GET adds no hint"
    );
    assert_eq!(
        turn(&mut owner, 3, &stranger_net),
        (5, 0, 0),
        "every datagram is dropped, and the GETs of a source outside the peer list add no hint"
    );
}

/// A turn's frames reach the transport as one batch: serving a 40,000-byte GET over a clean link, whose 16 KiB buffers yield two whole fragments per turn, the owner hands batches of two datagrams to `send`, and the client receives the exact bytes.
#[test]
fn a_turns_frames_reach_the_transport_as_one_batch() {
    let object = payload(40_000, 1);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 1, [Faults::default(); 2]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 10, &object)],
        vec![owner_end],
    );
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let turn = open(&mut client, &mut owner, &control, &nets, 0);
    let id = client
        .get(key(1), 64, 1 << 20, turn * 100, 5_000_000)
        .unwrap();
    let mut bytes = Vec::new();
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        50_000,
        |clients| {
            collect(clients[0], id, &mut bytes);
            clients[0].outcome(id).is_some()
        },
    );
    collect(&mut client, id, &mut bytes);
    assert_eq!(client.outcome(id), Some(Outcome::Complete));
    assert_eq!(bytes, object);
    assert!(client.retire(id));
    let _ = owner.close(turn * 100);
    let mut turn = turn;
    while owner.blockers().is_some() && turn < 100_000 {
        round(&mut [
            Act::new(Actor::Disk(0), &mut || control.tick(64)),
            Act::new(Actor::Owner(0), &mut || owner.poll(turn * 100)),
        ]);
        turn += 1;
    }
    let shutdown = owner.shutdown().ok().expect("a clean shutdown");
    assert_eq!(
        shutdown.transport.largest_batch, 2,
        "a chunk's two fragments go out together"
    );
}

/// A session for `client` against `owner`, returning the turn reached.
pub(super) fn open<'m>(
    client: &mut Client<'m, LinkEnd<'m>>,
    owner: &mut TestOwner<'_, '_, '_>,
    control: &SimControl,
    nets: &[Rc<RefCell<Net<'_>>>],
    start: u64,
) -> u64 {
    client.session(start * 100);
    let turn = drive(
        &mut [client],
        owner,
        control,
        nets,
        start,
        5_000,
        |clients| clients[0].state() == SessionState::Active,
    );
    assert_eq!(client.state(), SessionState::Active);
    turn
}

/// Turns the link, `client`, the owner and the device as one controller round per turn until the owner submits a read, which the device then holds before its tick; returns its token and the turn reached.
pub(super) fn hold_next_read<'m>(
    client: &mut Client<'m, LinkEnd<'m>>,
    owner: &mut TestOwner<'_, '_, '_>,
    control: &SimControl,
    net: &Rc<RefCell<Net<'_>>>,
    start: u64,
) -> (crate::storage::CommandToken, u64) {
    let before = last_read(control);
    for turn in start..start + 1_000 {
        let held = std::cell::Cell::new(None);
        let mut advance = || net.borrow_mut().advance(turn);
        let mut poll = || {
            let _ = client.poll(turn * 100);
        };
        let mut serve = || {
            owner.poll(turn * 100);
            if let Some(token) = last_read(control).filter(|token| Some(*token) != before) {
                control.hold(token);
                held.set(Some(token));
            }
        };
        let mut tick = || {
            if held.get().is_none() {
                control.tick(64);
            }
        };
        round(&mut [
            Act::new(Actor::Link(0), &mut advance),
            Act::new(Actor::Client(0), &mut poll),
            Act::new(Actor::Owner(0), &mut serve),
            Act::new(Actor::Disk(0), &mut tick),
        ]);
        if let Some(token) = held.get() {
            return (token, turn + 1);
        }
    }
    panic!("the owner submitted no read");
}

/// A slow peer that holds its whole data window while losing its ACKs, so the owner keeps retransmitting toward it, delays neither another peer's small GET, its ACKs nor its outcome, on a volume that reads one command at a time and on one that reads a command ahead past the slow peer's grant.
#[test]
fn a_slow_peer_holding_its_window_delays_no_other_peer() {
    slow_peer_delays_no_other_peer(&storage(8), &arena(8));
    let reading_ahead = crate::storage::owner_fixture::storage_reading_ahead(8);
    slow_peer_delays_no_other_peer(&reading_ahead, &arena(12));
}

fn slow_peer_delays_no_other_peer(
    storage: &Storage<TestPlatform>,
    buffers: &BufferArena<TestPlatform>,
) {
    let large = payload(45_000, 2);
    let small = super::oracle_endpoint_tests::served_content(900);
    let receive = pool();
    // The slow peer's ACKs are often lost, so the owner keeps retransmitting toward it while it holds its window.
    let toward_owner = Faults {
        loss: 30,
        ..Faults::default()
    };
    let pools = [pool(), pool()];
    let releases = [
        Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap(),
        Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap(),
    ];
    let (slow_end, owner_slow, slow_net) = network(64, 8384, 9, [Faults::default(), toward_owner]);
    let (fast_end, owner_fast, fast_net) = network(64, 8384, 5, [Faults::default(); 2]);
    let (mut owner, control) = start(
        storage,
        buffers,
        &receive,
        &[(key(1), 0, &large), (key(2), 0, &small)],
        vec![owner_slow, owner_fast],
    );
    let mut slow = client(0, &pools[0], &releases[0], slow_end);
    let mut fast = client(1, &pools[1], &releases[1], fast_end);
    let nets = [slow_net, fast_net];
    slow.session(0);
    fast.session(0);
    let turn = drive(
        &mut [&mut slow, &mut fast],
        &mut owner,
        &control,
        &nets,
        0,
        5_000,
        |clients| {
            clients
                .iter()
                .all(|client| client.state() == SessionState::Active)
        },
    );
    let held = slow
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let mut leases = Vec::new();
    // The slow application takes every fragment and keeps the leases, so its window stays full.
    let turn = drive(
        &mut [&mut slow, &mut fast],
        &mut owner,
        &control,
        &nets,
        turn,
        300,
        |clients| {
            while let Some(fragment) = clients[0].take(held) {
                leases.push(fragment);
            }
            false
        },
    );
    assert_eq!(leases.len(), 4, "the slow peer holds its whole window");
    let quick = fast
        .get(key(2), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let mut bytes = Vec::new();
    let done = drive(
        &mut [&mut slow, &mut fast],
        &mut owner,
        &control,
        &nets,
        turn,
        200,
        |clients| {
            collect(clients[1], quick, &mut bytes);
            clients[1].outcome(quick).is_some()
        },
    );
    assert_eq!(fast.outcome(quick), Some(Outcome::Complete));
    assert_eq!(bytes, small);
    assert!(
        done - turn < 200,
        "the small GET finished in {} turns",
        done - turn
    );
    drive(
        &mut [&mut slow, &mut fast],
        &mut owner,
        &control,
        &nets,
        done,
        2_000,
        |_| false,
    );
    let verdict = super::oracle_endpoint_tests::healthy_gets(
        storage,
        (
            &small,
            fills_written(&owner, &control)
                .pop()
                .expect("the preload's write evidence"),
        ),
        vec![(done - turn, 200, bytes.clone())],
        (1, owner.census().live()),
    );
    assert!(verdict.satisfies(&[Isolation, Bytes]), "{verdict:?}");
    assert_eq!(
        slow.outcome(held),
        None,
        "the slow transfer still waits on its application"
    );
    assert!(
        owner.serve_report().retries > 0,
        "the owner retransmitted toward the slow peer"
    );
    drop(leases);
}

/// The owner loses only the failed batch's leading frame and resubmits the remaining frames, so persistent send errors toward one peer preserve delivery to the other peer.
#[test]
fn a_send_error_toward_one_peer_loses_only_that_peers_frame() {
    let object = payload(40_000, 8);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let pools = [pool(), pool()];
    let releases = [
        Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap(),
        Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap(),
    ];
    let (lost_end, owner_lost, lost_net) = network(64, 8384, 6, [Faults::default(); 2]);
    let (kept_end, owner_kept, kept_net) = network(64, 8384, 7, [Faults::default(); 2]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &object)],
        vec![owner_lost, owner_kept],
    );
    let mut lost = client(0, &pools[0], &releases[0], lost_end);
    let mut kept = client(1, &pools[1], &releases[1], kept_end);
    let nets = [lost_net, kept_net];
    lost.session(0);
    kept.session(0);
    let turn = drive(
        &mut [&mut lost, &mut kept],
        &mut owner,
        &control,
        &nets,
        0,
        5_000,
        |clients| {
            clients
                .iter()
                .all(|client| client.state() == SessionState::Active)
        },
    );
    let stranded = lost
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let id = kept
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    nets[0].borrow_mut().set_faults(
        0,
        Faults {
            error: 100,
            ..Faults::default()
        },
    );
    let mut bytes = Vec::new();
    let turn = drive(
        &mut [&mut lost, &mut kept],
        &mut owner,
        &control,
        &nets,
        turn,
        20_000,
        |clients| {
            collect(clients[1], id, &mut bytes);
            clients[1].outcome(id).is_some()
        },
    );
    collect(&mut kept, id, &mut bytes);
    assert_eq!(kept.outcome(id), Some(Outcome::Complete));
    assert_eq!(bytes, object);
    assert_eq!(
        lost.outcome(stranded),
        None,
        "no frame reached the lost peer"
    );
    let failed = owner.report().failed;
    let _ = lost.close(turn * 100);
    let _ = owner.close(turn * 100);
    let mut turn = turn;
    while owner.blockers().is_some() && turn < 100_000 {
        let mut advances: Vec<_> = nets
            .iter()
            .map(|net| move || net.borrow_mut().advance(turn))
            .collect();
        let mut tick = || control.tick(64);
        let mut serve = || owner.poll(turn * 100);
        let mut acts = Vec::new();
        push_each(&mut acts, Actor::Link, &mut advances);
        acts.push(Act::new(Actor::Disk(0), &mut tick));
        acts.push(Act::new(Actor::Owner(0), &mut serve));
        round(&mut acts);
        turn += 1;
    }
    let shutdown = owner.shutdown().ok().expect("a clean shutdown");
    assert!(
        shutdown.transport.largest_failed_batch >= 2,
        "a failed call described another frame behind the lost peer's"
    );
    assert_eq!(
        failed, shutdown.transport.failed_calls,
        "each failed call loses only the frame that led it"
    );
}

/// A spent send sequence ends the peer's session and, in the same poll, retires its requests; a fresh session's GET on the reused client slot then completes with the object's bytes.
#[test]
fn a_spent_send_sequence_retires_the_peers_requests_with_its_session() {
    let object = payload(40_000, 21);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 21, [Faults::default(); 2]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &object)],
        vec![owner_end],
    );
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let turn = open(&mut client, &mut owner, &control, &nets, 0);
    let first = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let mut leases = Vec::new();
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        2_000,
        |clients| {
            leases.extend(clients[0].take(first));
            !leases.is_empty()
        },
    );
    assert_eq!(owner.census().active, 1, "the transfer is under way");
    owner.exhaust_sends(PeerId(0));
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        100,
        |_| false,
    );
    assert_eq!(
        owner.census().active,
        0,
        "the peer's request retired with its exhausted session"
    );
    client.cancel(first);
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        20,
        |_| false,
    );
    assert!(client.retire(first));
    let turn = open(&mut client, &mut owner, &control, &nets, turn);
    let again = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    assert_eq!(again.slot(), first.slot(), "the client reuses the slot");
    let mut bytes = Vec::new();
    drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        5_000,
        |clients| {
            collect(clients[0], again, &mut bytes);
            clients[0].outcome(again).is_some()
        },
    );
    assert_eq!(client.outcome(again), Some(Outcome::Complete));
    assert_eq!(bytes, object);
}

/// A GET whose final ACK and last DATA device return reach the COMPLETE poll frees its wire slot for the next poll's higher generation.
#[test]
fn a_complete_poll_releases_the_wire_slot_after_the_last_device_return() {
    let object = payload(900, 26);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 26, [Faults::default(); 2]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &object)],
        vec![owner_end],
    );
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let turn = open(&mut client, &mut owner, &control, &nets, 0);
    let first = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let wire = RequestId::from_wire(client.get_wire(first).unwrap());
    assert_eq!(wire.slot(), 0);
    let (token, turn) = hold_next_read(&mut client, &mut owner, &control, &nets[0], turn);
    nets[0]
        .borrow_mut()
        .set_tx_release(super::link::TxRelease::Withheld);
    control.release(token);
    control.tick(64);
    nets[0].borrow_mut().advance(turn);
    owner.poll(turn * 100);

    nets[0].borrow_mut().advance(turn + 1);
    let received = client.poll((turn + 1) * 100);
    assert_eq!(received.received, 2, "START and the single DATA frame");
    assert_eq!(received.sent, 1, "the final ACK waits for the owner");
    let mut bytes = Vec::new();
    collect(&mut client, first, &mut bytes);
    assert_eq!(bytes, object);
    assert_eq!(client.outcome(first), None);
    assert_eq!(nets[0].borrow().withheld(), 1);
    assert_eq!(owner.census().active, 1);

    // The device return and final ACK become visible to the same COMPLETE poll.
    nets[0].borrow_mut().return_tx(0);
    nets[0].borrow_mut().advance(turn + 2);
    assert_eq!(nets[0].borrow().reclaimable(1), 1);
    let before = owner.report();
    owner.poll((turn + 2) * 100);
    assert_eq!(owner.report().received - before.received, 1);
    assert_eq!(owner.report().sent - before.sent, 1);
    assert_eq!(nets[0].borrow().nic_held(), 0);
    assert_eq!(owner.census().active, 0, "COMPLETE ended the GET");

    nets[0].borrow_mut().advance(turn + 3);
    client.poll((turn + 3) * 100);
    assert_eq!(client.outcome(first), Some(Outcome::Complete));
    assert!(client.retire(first));
    let again = client
        .get(key(1), 0, 1 << 20, (turn + 3) * 100, 30_000_000)
        .unwrap();
    let next_wire = RequestId::from_wire(client.get_wire(again).unwrap());
    assert_eq!(next_wire.slot(), wire.slot());
    assert!(next_wire.generation() > wire.generation());
    nets[0]
        .borrow_mut()
        .set_tx_release(super::link::TxRelease::AtDelivery);
    client.poll((turn + 3) * 100);
    nets[0].borrow_mut().advance(turn + 4);
    owner.poll((turn + 4) * 100);
    bytes.clear();
    drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn + 5,
        5_000,
        |clients| {
            collect(clients[0], again, &mut bytes);
            clients[0].outcome(again).is_some()
        },
    );
    assert_eq!(client.outcome(again), Some(Outcome::Complete));
    assert_eq!(bytes, object);
}

/// The owner's timeout ERROR ends transmission for a GET whose device command is held and frees its wire slot, so a later generation on that slot completes during the drain, as does a successor GET on another slot. The held command keeps the request slot draining against the peer's share until its late terminal proves the drain.
#[test]
fn a_sent_timeout_keeps_custody_until_the_late_terminal() {
    let object = payload(30_000, 6);
    let next = payload(12_000, 16);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 6, [Faults::default(); 2]);
    let (mut owner, control) = start_over(
        OwnerConfig {
            serve: ServeConfig {
                max_wait_us: 5_000,
                ..OWNER.serve
            },
            ..OWNER
        },
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &object), (key(2), 0, &next)],
        Mux::new(vec![owner_end]),
    );
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let turn = open(&mut client, &mut owner, &control, &nets, 0);
    let id = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let (token, turn) = hold_next_read(&mut client, &mut owner, &control, &nets[0], turn);
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        200,
        |_| false,
    );
    assert_eq!(client.outcome(id), Some(Outcome::Failed(Status::TimedOut)));
    assert_eq!(
        owner.census().draining + owner.census().active,
        1,
        "the held command keeps the request's slot"
    );
    assert_eq!(
        owner.serve_report().errors_by_status[Status::TimedOut as usize - 1],
        1
    );
    let sent = owner.report().sent;
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        50,
        |_| false,
    );
    assert_eq!(
        owner.report().sent,
        sent,
        "a timed-out request sends nothing more"
    );
    let successor = client
        .get(key(2), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let mut bytes = Vec::new();
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        5_000,
        |clients| {
            collect(clients[0], successor, &mut bytes);
            clients[0].outcome(successor).is_some()
        },
    );
    assert_eq!(client.outcome(successor), Some(Outcome::Complete));
    assert_eq!(bytes, next, "the successor's bytes are its own");
    assert!(client.retire(successor));
    assert!(client.retire(id));
    let replacing = client
        .get(key(2), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    assert_eq!(
        replacing.slot(),
        id.slot(),
        "the client reuses the draining request's slot"
    );
    bytes.clear();
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        5_000,
        |clients| {
            collect(clients[0], replacing, &mut bytes);
            clients[0].outcome(replacing).is_some()
        },
    );
    assert_eq!(client.outcome(replacing), Some(Outcome::Complete));
    assert_eq!(bytes, next);
    assert_eq!(owner.census().draining, 1);
    assert_eq!(owner.serve_report().refused_pressure.busy, 0);
    assert_eq!(
        owner.volume_report().quarantines,
        1,
        "the timeout quarantined the held command"
    );
    control.release(token);
    drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        50,
        |_| false,
    );
    assert_eq!(
        owner.census().active + owner.census().draining,
        0,
        "the late terminal proved the drain"
    );
}

/// A read that started before its object was invalidated finishes with exactly the version it acquired, while a GET issued during that read looks the key up afresh and finds it gone.
#[test]
fn a_read_before_invalidation_finishes_and_the_next_get_looks_up_afresh() {
    let object = payload(20_000, 7);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 7, [Faults::default(); 2]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &object)],
        vec![owner_end],
    );
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let turn = open(&mut client, &mut owner, &control, &nets, 0);
    let first = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let (token, turn) = hold_next_read(&mut client, &mut owner, &control, &nets[0], turn);
    invalidate(&storage, &key(1)).unwrap();
    let second = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        5_000,
        |clients| clients[0].outcome(second).is_some(),
    );
    assert_eq!(
        client.outcome(second),
        Some(Outcome::Missing),
        "the GET during the read looked the key up afresh"
    );
    assert_eq!(
        client.outcome(first),
        None,
        "the earlier read still holds its command"
    );
    control.release(token);
    let mut bytes = Vec::new();
    drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        5_000,
        |clients| {
            collect(clients[0], first, &mut bytes);
            clients[0].outcome(first).is_some()
        },
    );
    assert_eq!(client.outcome(first), Some(Outcome::Complete));
    assert_eq!(bytes, object, "the acquired version");
}

/// An empty object completes with no bytes, and a header corrupted on its way from the device ends the GET with an integrity error and no byte exposed.
#[test]
fn an_empty_object_completes_and_a_corrupt_header_succeeds_never() {
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 8, [Faults::default(); 2]);
    let object = payload(5_000, 8);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &[]), (key(2), 0, &object)],
        vec![owner_end],
    );
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let turn = open(&mut client, &mut owner, &control, &nets, 0);
    let empty = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let mut bytes = Vec::new();
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        5_000,
        |clients| {
            collect(clients[0], empty, &mut bytes);
            clients[0].outcome(empty).is_some()
        },
    );
    assert_eq!(client.outcome(empty), Some(Outcome::Complete));
    assert!(bytes.is_empty());
    let corrupt = client
        .get(key(2), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let (token, turn) = hold_next_read(&mut client, &mut owner, &control, &nets[0], turn);
    control.fault(token, Fault::CorruptSuccess);
    control.release(token);
    let mut bytes = Vec::new();
    drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        5_000,
        |clients| {
            collect(clients[0], corrupt, &mut bytes);
            clients[0].outcome(corrupt).is_some()
        },
    );
    assert_eq!(
        client.outcome(corrupt),
        Some(Outcome::Failed(Status::IntegrityError))
    );
    assert!(bytes.is_empty(), "no byte of a corrupt record is exposed");
    assert_eq!(
        (owner.report().false_positives, owner.report().defects),
        (0, 0)
    );
}

/// A lookup that finds another key's object through a shared fingerprint ends `Missing` with no byte exposed, counted as a false positive and not a defect.
#[test]
fn a_fingerprint_false_positive_answers_missing() {
    let object = payload(5_000, 12);
    let storage = one_chain_storage();
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 12, [Faults::default(); 2]);
    let (owner_key, stranger) = (key(0x11), key(0x12));
    let mut device = Device::new(&storage, &buffers);
    publish(&storage, &mut device, &owner_key, 0, &object);
    forge(&storage, &owner_key, &stranger);
    let Device { volume, control } = device;
    let cache = storage.issue_cache().unwrap();
    let registration = cache.register().unwrap();
    let keys = Keys {
        principals: &PRINCIPALS[..1],
        entries: &entries()[..1],
        epoch: 1,
        put: &[],
    };
    let bundle = Bundle {
        cache,
        registration,
        volume,
    };
    let mut owner = Owner::start(
        OWNER,
        bundle,
        keys,
        Mux::new(vec![owner_end]),
        &receive,
        &mut EngineBudget::new(1 << 26),
    )
    .map_err(|refused| refused.error)
    .unwrap();
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let turn = open(&mut client, &mut owner, &control, &nets, 0);
    let id = client
        .get(stranger, 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let mut bytes = Vec::new();
    drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        5_000,
        |clients| {
            collect(clients[0], id, &mut bytes);
            clients[0].outcome(id).is_some()
        },
    );
    assert_eq!(client.outcome(id), Some(Outcome::Missing));
    assert!(bytes.is_empty());
    assert_eq!(
        (owner.report().false_positives, owner.report().defects),
        (1, 0)
    );
}

/// A GET of an object whose second extent is sealed under another key
/// delivers the first extent's bytes and ends `IntegrityError`, counted as
/// neither a false positive nor a defect: the first header verified the
/// key, so the mismatch names the object's block pointing at a stranger's
/// extent, not a fingerprint collision.
#[test]
fn a_wrong_key_at_a_later_extent_answers_integrity_error_after_the_first_extent() {
    let storage = sequence_storage();
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 12, [Faults::default(); 2]);
    let mut device = Device::new(&storage, &buffers);
    let plant = Plant::Identity(1, |identity| identity.key[0] ^= 1);
    let payload = publish_sequence(&storage, &mut device, &key(1), 3, 0, Some(plant));
    let Device { volume, control } = device;
    let cache = storage.issue_cache().unwrap();
    let registration = cache.register().unwrap();
    let keys = Keys {
        principals: &PRINCIPALS[..1],
        entries: &entries()[..1],
        epoch: 1,
        put: &[],
    };
    let bundle = Bundle {
        cache,
        registration,
        volume,
    };
    let mut owner = Owner::start(
        OWNER,
        bundle,
        keys,
        Mux::new(vec![owner_end]),
        &receive,
        &mut EngineBudget::new(1 << 26),
    )
    .map_err(|refused| refused.error)
    .unwrap();
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let turn = open(&mut client, &mut owner, &control, &nets, 0);
    let id = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let mut bytes = Vec::new();
    drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        20_000,
        |clients| {
            collect(clients[0], id, &mut bytes);
            clients[0].outcome(id).is_some()
        },
    );
    assert_eq!(
        client.outcome(id),
        Some(Outcome::Incomplete(Status::IntegrityError))
    );
    let first = crate::storage::EXTENT_PAYLOAD as usize;
    assert!(bytes == payload[..first], "the first extent alone");
    assert_eq!(
        (owner.report().false_positives, owner.report().defects),
        (0, 0)
    );
}

/// A volume lost under a GET answers it `OwnerUnavailable`, closes admission so a later GET is refused the same way without a read, and counts no defect.
#[test]
fn a_lost_volume_closes_admission() {
    let object = payload(5_000, 13);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 13, [Faults::default(); 2]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &object)],
        vec![owner_end],
    );
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let turn = open(&mut client, &mut owner, &control, &nets, 0);
    control.set_gone();
    let first = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        5_000,
        |clients| clients[0].outcome(first).is_some(),
    );
    assert_eq!(
        client.outcome(first),
        Some(Outcome::Failed(Status::OwnerUnavailable))
    );
    let reads = owner.volume_report().reads_submitted;
    let second = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        5_000,
        |clients| clients[0].outcome(second).is_some(),
    );
    assert_eq!(
        client.outcome(second),
        Some(Outcome::Failed(Status::OwnerUnavailable))
    );
    assert_eq!(
        owner.volume_report().reads_submitted,
        reads,
        "the refused GET started no read"
    );
    assert_eq!(owner.report().defects, 0);
}

/// With two rights per object and a lease held outside the owner, a second concurrent GET of one key, whose lookup would need a third right, ends with object pressure while the first read runs.
#[test]
fn same_key_rights_bound_concurrent_reads() {
    let object = payload(10_000, 9);
    let storage = storage(2);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 9, [Faults::default(); 2]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &object)],
        vec![owner_end],
    );
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let turn = open(&mut client, &mut owner, &control, &nets, 0);
    let mut reader = storage.register().unwrap();
    let lease = reader
        .lookup(&key(1), 3, &mut crate::storage::WorkBudget::new(1 << 12))
        .unwrap();
    let first = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let (token, turn) = hold_next_read(&mut client, &mut owner, &control, &nets[0], turn);
    let second = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    for at in turn..turn + 100 {
        round(&mut [
            Act::new(Actor::Link(0), &mut || nets[0].borrow_mut().advance(at)),
            Act::new(Actor::Client(0), &mut || {
                let _ = client.poll(at * 100);
            }),
            Act::new(Actor::Owner(0), &mut || owner.poll(at * 100)),
        ]);
    }
    assert_eq!(
        client.outcome(second),
        Some(Outcome::Pressure(Status::ObjectPressure))
    );
    control.release(token);
    let mut bytes = Vec::new();
    drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn + 100,
        5_000,
        |clients| {
            collect(clients[0], first, &mut bytes);
            clients[0].outcome(first).is_some()
        },
    );
    assert_eq!(client.outcome(first), Some(Outcome::Complete));
    assert_eq!(bytes, object);
    drop((lease, reader));
}

/// A bundle over two storages, a request table larger than the volume's read records, and a read path whose span is below one fragment are each refused with the whole bundle back and the budget unchanged; the returned bundle then starts once.
#[test]
fn incoherent_bundles_and_spans_are_refused_with_the_bundle_returned() {
    let receive = pool();
    let keys = Keys {
        principals: &PRINCIPALS[..1],
        entries: &entries()[..1],
        epoch: 1,
        put: &[],
    };
    let (one, other) = (storage(8), storage(8));
    let buffers = arena(8);
    let Device { volume, .. } = Device::new(&other, &buffers);
    let cache = one.issue_cache().unwrap();
    let registration = cache.register().unwrap();
    let mut budget = EngineBudget::new(1 << 26);
    let (_, end, _) = network(4, 8384, 1, [Faults::default(); 2]);
    let refused = Owner::start(
        OWNER,
        Bundle {
            cache,
            registration,
            volume,
        },
        keys,
        Mux::new(vec![end]),
        &receive,
        &mut budget,
    )
    .err()
    .unwrap();
    assert_eq!(refused.error, OwnerError::Foreign);
    assert_eq!(budget.used(), 0);
    drop(refused);

    let storage = storage(8);
    let buffers = arena(8);
    let Device { volume, .. } = Device::new(&storage, &buffers);
    let cache = storage.issue_cache().unwrap();
    let registration = cache.register().unwrap();
    let (_, end, _) = network(4, 8384, 1, [Faults::default(); 2]);
    let wide = OwnerConfig {
        request_slots: 5,
        peer_requests: 5,
        ..OWNER
    };
    let refused = Owner::start(
        wide,
        Bundle {
            cache,
            registration,
            volume,
        },
        keys,
        Mux::new(vec![end]),
        &receive,
        &mut budget,
    )
    .err()
    .unwrap();
    assert_eq!(
        refused.error,
        OwnerError::Capacity {
            slots: 5,
            read_ops: 4,
            buffers: 8
        }
    );
    assert_eq!(budget.used(), 0);
    let super::owner::Refused {
        bundle, transport, ..
    } = *refused;
    let started = Owner::start(OWNER, bundle, keys, transport, &receive, &mut budget);
    assert!(started.is_ok(), "the returned bundle starts");
    assert!(budget.used() > 0);
    drop(started);

    let (storage, buffers) = narrow(4096, 8, 4096);
    let Device { volume, .. } = Device::new(&storage, &buffers);
    let cache = storage.issue_cache().unwrap();
    let registration = cache.register().unwrap();
    let (_, end, _) = network(4, 8384, 1, [Faults::default(); 2]);
    let mut budget = EngineBudget::new(1 << 26);
    let refused = Owner::start(
        OWNER,
        Bundle {
            cache,
            registration,
            volume,
        },
        keys,
        Mux::new(vec![end]),
        &receive,
        &mut budget,
    )
    .err()
    .unwrap();
    assert!(
        matches!(refused.error, OwnerError::Geometry(_)),
        "{:?}",
        refused.error
    );
    assert_eq!(budget.used(), 0);
}

/// Every lookup error, read refusal and read status maps to its wire status, and a refusal a correct owner never sees counts as a defect.
#[test]
fn storage_outcomes_map_to_their_wire_statuses() {
    let lookups = [
        (LookupError::Missing, Status::Missing),
        (LookupError::Expired, Status::Expired),
        (LookupError::Contended, Status::Contended),
        (LookupError::LeaseLimit, Status::LeasePressure),
        (LookupError::RetainLimit, Status::ObjectPressure),
        (LookupError::ClockUnavailable, Status::ClockUnavailable),
        (LookupError::Closed, Status::Closed),
    ];
    for (error, status) in lookups {
        assert_eq!(lookup_status(error), status, "{error:?}");
    }
    let queue_full = SubmitRefusal {
        reason: RefusalReason::QueueFull,
        code: None,
    };
    let invalid = SubmitRefusal {
        reason: RefusalReason::InvalidRange,
        code: None,
    };
    let refusals = [
        (
            ReadRefusal::PoolExhausted,
            Status::RetransmissionPressure,
            false,
        ),
        (ReadRefusal::OpsExhausted, Status::ReadOpsPressure, false),
        (
            ReadRefusal::Submit(Refusal::TableFull { abandoned: 0 }),
            Status::OwnerUnavailable,
            true,
        ),
        (
            ReadRefusal::Submit(Refusal::Device(queue_full)),
            Status::OwnerUnavailable,
            true,
        ),
        (
            ReadRefusal::Submit(Refusal::Device(invalid)),
            Status::DeviceError,
            false,
        ),
        (
            ReadRefusal::Submit(Refusal::TooLong),
            Status::DeviceError,
            false,
        ),
        (ReadRefusal::Layout, Status::IntegrityError, false),
        (ReadRefusal::Closed, Status::Closed, false),
        (ReadRefusal::Lost, Status::OwnerUnavailable, false),
        (ReadRefusal::ForeignLease, Status::OwnerUnavailable, true),
    ];
    for (refusal, status, defect) in refusals {
        assert_eq!(refusal_status(refusal), (status, defect), "{refusal:?}");
    }
    let statuses = [
        (ReadStatus::DeviceError, Status::DeviceError),
        (ReadStatus::Short, Status::Short),
        (
            ReadStatus::HeaderMismatch(HeaderMismatch::Magic { found: 0 }),
            Status::IntegrityError,
        ),
        (
            ReadStatus::ChunkMismatch { index: 1 },
            Status::IntegrityError,
        ),
        (
            ReadStatus::HeaderMismatch(HeaderMismatch::Allocation {
                expected: 1,
                found: 2,
            }),
            Status::IntegrityError,
        ),
        (
            ReadStatus::HeaderMismatch(HeaderMismatch::Session {
                expected: 1,
                found: 2,
            }),
            Status::IntegrityError,
        ),
        (
            ReadStatus::HeaderMismatch(HeaderMismatch::CacheVersion {
                expected: 1,
                found: 2,
            }),
            Status::IntegrityError,
        ),
        (
            ReadStatus::HeaderMismatch(HeaderMismatch::ForeignSession {
                found: 1 << 32 | 6,
                reader: 1 << 32 | 4,
            }),
            Status::IntegrityError,
        ),
        (ReadStatus::Cancelled, Status::Cancelled),
        (ReadStatus::TimedOut, Status::TimedOut),
        (ReadStatus::Quiesced, Status::Closed),
        (ReadStatus::Lost, Status::OwnerUnavailable),
        (ReadStatus::Complete, Status::IntegrityError),
    ];
    for (read, status) in statuses {
        for verified in [false, true] {
            assert_eq!(read_status(read, verified), status, "{read:?} {verified}");
        }
    }
    // A key mismatch at the first extent is the lookup's false positive; at a later extent, after an earlier header verified, an integrity failure.
    let key = ReadStatus::HeaderMismatch(HeaderMismatch::Key);
    assert_eq!(read_status(key, false), Status::Missing);
    assert_eq!(read_status(key, true), Status::IntegrityError);
}

/// A basic close stops admission and sends, cancels the running read so the volume quarantines its held command, and closes the volume; a GET after the close gets no reply, and the held command keeps its custody until its terminal.
#[test]
fn close_stops_sends_and_cancels_running_reads() {
    let object = payload(30_000, 10);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 10, [Faults::default(); 2]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &object)],
        vec![owner_end],
    );
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let turn = open(&mut client, &mut owner, &control, &nets, 0);
    client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let (token, turn) = hold_next_read(&mut client, &mut owner, &control, &nets[0], turn);
    let progress = owner.close(turn * 100);
    assert!(
        !matches!(progress, crate::storage::QuiesceProgress::Quiesced(_)),
        "the held command keeps the device busy: {progress:?}"
    );
    assert_eq!(
        owner.volume_report().quarantines,
        1,
        "the close cancelled the running read while the volume accepted it"
    );
    let (sent, received) = (owner.report().sent, owner.report().received);
    let late = client.get(key(1), 0, 1 << 20, turn * 100, 3_000).unwrap();
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        100,
        |_| false,
    );
    assert_eq!(owner.report().sent, sent, "a closed owner sends nothing");
    assert_eq!(
        owner.report().received,
        received,
        "a closed owner admits nothing"
    );
    assert_eq!(
        client.outcome(late),
        Some(Outcome::Failed(Status::TimedOut)),
        "the late GET got no reply"
    );
    assert_eq!(
        owner.census().active + owner.census().draining,
        1,
        "custody stays with the held command"
    );
    control.release(token);
    drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        50,
        |_| false,
    );
    assert_eq!(owner.census().active + owner.census().draining, 0);
    assert!(
        matches!(
            owner.quiesce(),
            Some(crate::storage::QuiesceProgress::Quiesced(_))
        ),
        "later polls closed the volume until it quiesced: {:?}",
        owner.quiesce()
    );
}

/// Once warm, the hit path allocates nothing on the owner over the simulated link: GET admission, the receive window's preparation, lookups, reads, grants, the storage tick, its events and the sends of two whole transfers whose GETs arrive together. The link keeps its own allocations out of the count.
#[test]
fn the_hit_path_allocates_nothing() {
    hit_path_allocates_nothing(super::rules::Chain::default());
}

/// The hit path stays allocation-free with a composed rule chain delaying, duplicating, reordering and dropping its traffic: the chain runs inside the link's own uncounted work.
#[test]
fn the_hit_path_allocates_nothing_under_composed_rules() {
    use super::frame::Kind;
    use super::rules::{Chain, Effect, MANIFEST, Rule, Selector};
    let rules = vec![
        Rule::new(Selector::Kind(Kind::Data), Effect::Delay(2)).window(1, 3),
        Rule::new(Selector::Kind(Kind::Data), Effect::Duplicate).window(4, 2),
        Rule::new(Selector::Toward(1), Effect::Reorder),
        Rule::new(Selector::Kind(Kind::Ack), Effect::Drop).window(2, 1),
    ];
    hit_path_allocates_nothing(Chain::new(rules, &[4], &MANIFEST).unwrap());
}

fn hit_path_allocates_nothing(rules: super::rules::Chain) {
    let object = payload(30_000, 11);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 11, [Faults::default(); 2]);
    let composed = !rules.is_empty();
    let mut rules = Some(rules);
    let mut device = Device::new(&storage, &buffers);
    publish(&storage, &mut device, &key(1), 0, &object);
    let Device { volume, control } = device;
    let cache = storage.issue_cache().unwrap();
    let registration = cache.register().unwrap();
    let keys = Keys {
        principals: &PRINCIPALS[..1],
        entries: &entries()[..1],
        epoch: 1,
        put: &[],
    };
    let bundle = Bundle {
        cache,
        registration,
        volume,
    };
    let mut owner = Owner::start(
        OWNER,
        bundle,
        keys,
        Mux::new(vec![owner_end]),
        &receive,
        &mut EngineBudget::new(1 << 26),
    )
    .map_err(|refused| refused.error)
    .unwrap();
    let memory = ClientMemory {
        receive: &client_pool,
        releases: &releases,
        requests: RequestTable::new(4, 1, 4),
        sources: Box::default(),
        routes: super::client_tests::routes(),
    };
    let key_entry = [entries()[0]];
    let mut client = Client::initialize(
        client_config(0),
        memory,
        client_end,
        &key_entry,
        1,
        &mut EngineBudget::new(1 << 24),
    )
    .unwrap();
    let mut turn = 0;
    client.session(0);
    while client.state() != SessionState::Active && turn < 5_000 {
        round(&mut [
            Act::new(Actor::Link(0), &mut || net.borrow_mut().advance(turn)),
            Act::new(Actor::Client(0), &mut || {
                let _ = client.poll(turn * 100);
            }),
            Act::new(Actor::Disk(0), &mut || control.tick(64)),
            Act::new(Actor::Owner(0), &mut || owner.poll(turn * 100)),
        ]);
        turn += 1;
    }
    assert_eq!(client.state(), SessionState::Active);
    let mut allocations = Vec::new();
    let mut measured = (0, [super::link::NetReport::default(); 2]);
    for round in 0..3 {
        if round == 1 {
            if let Some(rules) = rules.take() {
                net.borrow_mut().set_rules(rules);
            }
            let net = net.borrow();
            measured = (net.rules().captures().len(), [net.report(0), net.report(1)]);
        }
        // Two GETs leave the client together and reach the owner as one
        // receive window.
        let ids = [0, 1].map(|_| {
            client
                .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
                .unwrap()
        });
        let windows = owner.windows();
        let mut owner_allocations = 0;
        for _ in 0..50_000 {
            crate::sim::round::round(&mut [
                Act::new(Actor::Link(0), &mut || net.borrow_mut().advance(turn)),
                Act::new(Actor::Client(0), &mut || {
                    let _ = client.poll(turn * 100);
                }),
                Act::new(Actor::Owner(0), &mut || {
                    let before = crate::instrument::allocations();
                    owner.poll(turn * 100);
                    owner_allocations += crate::instrument::allocations() - before;
                }),
                Act::new(Actor::Disk(0), &mut || control.tick(64)),
            ]);
            turn += 1;
            for id in ids {
                while let Some(fragment) = client.take(id) {
                    drop(fragment);
                }
            }
            // The round ends once the owner drained both requests, so the next round's GETs find their wire slots free under every order.
            let census = owner.census();
            if ids.iter().all(|id| client.outcome(*id).is_some())
                && census.active + census.draining == 0
            {
                break;
            }
        }
        for id in ids {
            assert_eq!(client.outcome(id), Some(Outcome::Complete), "round {round}");
            assert!(client.retire(id));
        }
        assert!(
            owner.windows().prepared > windows.prepared,
            "round {round} prepared a window"
        );
        allocations.push(owner_allocations);
    }
    assert_eq!(
        allocations[1..],
        [0, 0],
        "warm rounds allocate nothing: {allocations:?}"
    );
    if composed {
        use super::frame::Kind;
        use super::rules::{Decision, Dropped};
        let net = net.borrow();
        let (from, armed) = measured;
        let captures = &net.rules().captures()[from..];
        let acted = |kind: Kind, effect: fn(&Decision) -> bool| {
            captures
                .iter()
                .any(|capture| capture.kind == Some(kind) && effect(&capture.decision))
        };
        assert!(acted(Kind::Data, |d| d.delay == Some(2)), "a delayed DATA");
        assert!(acted(Kind::Data, |d| d.duplicate), "a duplicated DATA");
        assert!(
            acted(Kind::Ack, |d| d.drop == Some(Dropped::Rule(3))),
            "a dropped ACK"
        );
        assert!(
            captures
                .iter()
                .any(|capture| capture.toward == 1 && capture.decision.reorder == Some(true)),
            "reordered client traffic"
        );
        let (toward_client, toward_owner) = (net.report(0), net.report(1));
        assert!(
            toward_client.delayed > armed[0].delayed
                && toward_client.duplicated > armed[0].duplicated
                && toward_owner.lost > armed[1].lost,
            "the effects reached the measured rounds: {armed:?} {toward_client:?} {toward_owner:?}"
        );
    }
}

/// A peer flooding HELLOs, each at a fresh bootstrap sequence, delays neither another peer's opening nor its small GET: bootstrap replies keep one slot per peer and at most half of each turn's sends.
#[test]
fn a_hello_flood_delays_no_other_peer() {
    let small = super::oracle_endpoint_tests::served_content(900);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let pools = [pool(), pool()];
    let releases = [
        Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap(),
        Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap(),
    ];
    let (flood_end, owner_flood, flood_net) = network(256, 8384, 14, [Faults::default(); 2]);
    let (fast_end, owner_fast, fast_net) = network(64, 8384, 15, [Faults::default(); 2]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(2), 0, &small)],
        vec![owner_flood, owner_fast],
    );
    let mut flood = client(0, &pools[0], &releases[0], flood_end);
    let mut fast = client(1, &pools[1], &releases[1], fast_end);
    let nets = [flood_net, fast_net];
    fast.session(0);
    let mut quick = None;
    let mut bytes = Vec::new();
    let mut turn = 0;
    while turn < 2_000 {
        round(&mut [
            Act::new(Actor::Link(0), &mut || nets[0].borrow_mut().advance(turn)),
            Act::new(Actor::Link(1), &mut || nets[1].borrow_mut().advance(turn)),
            Act::new(Actor::Client(0), &mut || {
                for _ in 0..8 {
                    flood.session(turn * 100);
                    let _ = flood.poll(turn * 100);
                }
            }),
            Act::new(Actor::Client(1), &mut || {
                let _ = fast.poll(turn * 100);
            }),
            Act::new(Actor::Disk(0), &mut || control.tick(64)),
            Act::new(Actor::Owner(0), &mut || owner.poll(turn * 100)),
        ]);
        if quick.is_none() && fast.state() == SessionState::Active {
            quick = fast.get(key(2), 0, 1 << 20, turn * 100, 30_000_000).ok();
        }
        if let Some(id) = quick {
            collect(&mut fast, id, &mut bytes);
            if fast.outcome(id).is_some() {
                break;
            }
        }
        turn += 1;
    }
    let id = quick.expect("the fast peer's session opened");
    assert!(
        owner.report().received > 4 * turn,
        "the flood reached the owner: {} datagrams in {turn} turns",
        owner.report().received
    );
    assert_eq!(fast.outcome(id), Some(Outcome::Complete));
    assert_eq!(bytes, small);
    assert!(turn < 300, "the fast peer finished at turn {turn}");
    let mut at = turn;
    for _ in 0..2_000 {
        if owner.census().live() == 0 {
            break;
        }
        at = drive(&mut [&mut fast], &mut owner, &control, &nets, at, 1, |_| {
            false
        });
    }
    let verdict = super::oracle_endpoint_tests::healthy_gets(
        &storage,
        (
            &small,
            fills_written(&owner, &control)
                .pop()
                .expect("the preload's write evidence"),
        ),
        vec![(turn, 300, bytes)],
        (0, owner.census().live()),
    );
    assert!(verdict.satisfies(&[Isolation, Bytes]), "{verdict:?}");
}

/// Every startup refusal returns the whole bundle with the budget unchanged: caps outside the bootstrap range, peer shares above the request slots, a borrowed response buffer, maintenance work below the storage's minimum, a batch of one, a PUT grant naming an unknown principal, and a budget one byte short of the owner's charge. A started owner grants PUT to exactly the configured principal.
#[test]
fn every_startup_refusal_leaves_the_budget_unchanged() {
    let receive = pool();
    let keys = Keys {
        principals: &PRINCIPALS,
        entries: &entries(),
        epoch: 1,
        put: &PRINCIPALS[1..],
    };
    let object = payload(20_000, 18);
    let storage = storage(8);
    let buffers = arena(8);
    let mut device = Device::new(&storage, &buffers);
    publish(&storage, &mut device, &key(1), 0, &object);
    let held = crate::storage::owner_fixture::held_chunk(&storage, &mut device, &key(1));
    let Device { volume, .. } = device;
    let cache = storage.issue_cache().unwrap();
    let registration = cache.register().unwrap();
    let mut bundle = Bundle {
        cache,
        registration,
        volume,
    };
    let ends = || {
        let (_, a, _) = network(4, 8384, 1, [Faults::default(); 2]);
        let (_, b, _) = network(4, 8384, 2, [Faults::default(); 2]);
        Mux::new(vec![a, b])
    };
    let mut held = Some(held);
    let cases = [
        (
            OwnerConfig {
                caps: Caps { slots: 0, ..CAPS },
                ..OWNER
            },
            &receive,
            OwnerError::Caps,
        ),
        (
            OwnerConfig {
                caps: Caps {
                    window: MAX_WINDOW + 1,
                    ..CAPS
                },
                ..OWNER
            },
            &receive,
            OwnerError::Caps,
        ),
        (
            OwnerConfig {
                peer_requests: 3,
                ..OWNER
            },
            &receive,
            OwnerError::Requests,
        ),
        (
            OwnerConfig {
                serve: ServeConfig {
                    slots: CAPS.slots - 1,
                    ..OWNER.serve
                },
                ..OWNER
            },
            &receive,
            OwnerError::Requests,
        ),
        (
            OwnerConfig {
                serve: ServeConfig {
                    replies: 0,
                    ..OWNER.serve
                },
                ..OWNER
            },
            &receive,
            OwnerError::Requests,
        ),
        (OWNER, &receive, OwnerError::Borrowed),
        (
            OwnerConfig {
                maintain_work: 1,
                ..OWNER
            },
            &receive,
            OwnerError::Maintenance {
                minimum: storage.maintain_minimum(),
            },
        ),
        (
            OwnerConfig { batch: 1, ..OWNER },
            &receive,
            OwnerError::Batch,
        ),
    ];
    for (config, receive, error) in cases {
        if matches!(error, OwnerError::Maintenance { .. }) {
            // The response buffer returns, so the later checks are the first to refuse.
            held = None;
        }
        let mut budget = EngineBudget::new(1 << 26);
        let refused = Owner::start(config, bundle, keys, ends(), receive, &mut budget)
            .err()
            .unwrap();
        assert_eq!(refused.error, error);
        assert_eq!(budget.used(), 0);
        bundle = refused.bundle;
    }
    assert!(held.is_none());
    let mut budget = EngineBudget::new(1 << 26);
    let unknown = Keys {
        put: &[0x0BAD],
        ..keys
    };
    let refused = Owner::start(OWNER, bundle, unknown, ends(), &receive, &mut budget)
        .err()
        .unwrap();
    assert_eq!(
        refused.error,
        OwnerError::Permits(KeyError::Unknown { principal: 0x0BAD })
    );
    assert_eq!(budget.used(), 0);
    bundle = refused.bundle;
    let mut probe = EngineBudget::new(1 << 26);
    let started = Owner::start(OWNER, bundle, keys, ends(), &receive, &mut probe)
        .map_err(|refused| refused.error)
        .unwrap();
    assert_eq!(started.put_permission(PeerId(1)), Ok(()));
    for peer in [0, 2, u16::MAX] {
        assert_eq!(
            started.put_permission(PeerId(peer)),
            Err(Status::PermissionDenied),
            "peer {peer}"
        );
    }
    let charge = probe.used();
    drop(started);
    let other = storage_and_bundle_charge(charge);
    assert!(matches!(other, OwnerError::Budget(_)), "{other:?}");
}

/// `OwnerError::Batch` bounds the batch and the transport's posted receive
/// ring by the receive pool's control reserve. A retired receive buffer
/// shrinks the data cap and never returns, so it adds no buffer to the
/// reserve: a start one buffer over the reserve refuses `Batch` before and
/// after a retirement.
#[test]
fn a_retired_receive_buffer_leaves_the_batch_reserve_unchanged() {
    use crate::storage::PoolKind;

    use super::packet::{PacketUse, test_arena};

    let entries = entries();
    let keys = Keys {
        principals: &PRINCIPALS,
        entries: &entries,
        epoch: 1,
        put: &PRINCIPALS[1..],
    };
    let ends = || {
        let (_, a, _) = network(4, 8384, 1, [Faults::default(); 2]);
        let (_, b, _) = network(4, 8384, 2, [Faults::default(); 2]);
        Mux::new(vec![a, b])
    };
    let control = OWNER.batch + ends().rx_ring() - 1;
    let packets = test_arena(32, 16384);
    let receive = PacketPool::new(&packets, PoolKind::PacketReceive, control).unwrap();
    let storage = storage(8);
    let buffers = arena(8);
    let Device { volume, .. } = Device::new(&storage, &buffers);
    let cache = storage.issue_cache().unwrap();
    let registration = cache.register().unwrap();
    let bundle = Bundle {
        cache,
        registration,
        volume,
    };
    let mut budget = EngineBudget::new(1 << 26);
    let refused = Owner::start(OWNER, bundle, keys, ends(), &receive, &mut budget)
        .err()
        .unwrap();
    assert_eq!(
        refused.error,
        OwnerError::Batch,
        "one buffer over the reserve"
    );
    for index in 0..32 {
        packets
            .pools()
            .set_incarnation(PoolKind::PacketReceive, index, u64::MAX);
    }
    drop(receive.acquire(PacketUse::Control).unwrap());
    assert_eq!(packets.report(PoolKind::PacketReceive).retired, 1);
    assert_eq!(receive.report().count - receive.data_cap(), control + 1);
    let started = Owner::start(OWNER, refused.bundle, keys, ends(), &receive, &mut budget);
    assert_eq!(
        started.err().map(|refused| refused.error),
        Some(OwnerError::Batch),
        "a retired buffer is no control buffer"
    );
}

/// Starts an owner over a fresh stack with a budget one byte short of `charge`, returning its refusal after checking the budget stayed unchanged.
fn storage_and_bundle_charge(charge: usize) -> OwnerError {
    let receive = pool();
    let keys = Keys {
        principals: &PRINCIPALS,
        entries: &entries(),
        epoch: 1,
        put: &[],
    };
    let storage = storage(8);
    let buffers = arena(8);
    let Device { volume, .. } = Device::new(&storage, &buffers);
    let cache = storage.issue_cache().unwrap();
    let registration = cache.register().unwrap();
    let (_, a, _) = network(4, 8384, 1, [Faults::default(); 2]);
    let (_, b, _) = network(4, 8384, 2, [Faults::default(); 2]);
    let mut budget = EngineBudget::new(charge - 1);
    let refused = Owner::start(
        OWNER,
        Bundle {
            cache,
            registration,
            volume,
        },
        keys,
        Mux::new(vec![a, b]),
        &receive,
        &mut budget,
    )
    .err()
    .unwrap();
    assert_eq!(budget.used(), 0, "a refused start charges nothing");
    refused.error
}

/// A chunk that fails its checksum after earlier fragments reached the application ends the GET `Incomplete`, so the exposed bytes are a prefix of one version and never a success.
#[test]
fn a_chunk_mismatch_after_exposure_ends_incomplete() {
    let object = payload(40_000, 19);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 19, [Faults::default(); 2]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &object)],
        vec![owner_end],
    );
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let turn = open(&mut client, &mut owner, &control, &nets, 0);
    let id = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let (first, turn) = hold_next_read(&mut client, &mut owner, &control, &nets[0], turn);
    control.release(first);
    let (second, turn) = hold_next_read(&mut client, &mut owner, &control, &nets[0], turn);
    let mut bytes = Vec::new();
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        5_000,
        |clients| {
            collect(clients[0], id, &mut bytes);
            !bytes.is_empty()
        },
    );
    control.fault(second, Fault::CorruptSuccess);
    control.release(second);
    drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        5_000,
        |clients| {
            collect(clients[0], id, &mut bytes);
            clients[0].outcome(id).is_some()
        },
    );
    assert_eq!(
        client.outcome(id),
        Some(Outcome::Incomplete(Status::IntegrityError))
    );
    assert!(!bytes.is_empty() && bytes.len() < object.len());
    assert_eq!(bytes, object[..bytes.len()], "a prefix of the one version");
}

/// Streams `payload` into a local fill of `key` through `owner` while every client and the owner keep turning and `each` runs after every turn, then publishes it; returns the turn reached.
#[allow(clippy::too_many_arguments)]
fn fill_through<'s, 'm>(
    storage: &'s Storage<TestPlatform>,
    owner: &mut TestOwner<'s, '_, '_>,
    clients: &mut [&mut Client<'m, LinkEnd<'m>>],
    control: &SimControl,
    nets: &[Rc<RefCell<Net<'_>>>],
    key: &[u8; 32],
    payload: &[u8],
    start: u64,
    mut each: impl FnMut(&mut [&mut Client<'m, LinkEnd<'m>>]),
) -> u64 {
    let mut fill = reserve(storage, key, 0, payload.len()).expect("a fill");
    let mut taken = 0;
    let mut turn = start;
    while !owner.fill_progress(&fill).is_ready() {
        if taken < payload.len()
            && let Ok(n) = owner.receive_fill(
                &mut fill,
                &payload[taken..(taken + 4096).min(payload.len())],
                &mut crate::storage::WorkBudget::with_io(0, usize::MAX, usize::MAX),
            )
        {
            taken += n;
        }
        turn = drive(clients, owner, control, nets, turn, 1, |_| false);
        each(clients);
        assert!(turn < start + 10_000, "the fill finished its writes");
    }
    let mut budget = crate::storage::WorkBudget::new(1024);
    let lease = owner
        .publish_fill(fill, u64::MAX, 2, &mut budget)
        .expect("published");
    drop(lease);
    turn
}

/// An acknowledged close cuts off a later local publication: a closed owner aborts a fill whose writes finished and refuses it with `Closed`, and the key stays unpublished.
#[test]
fn a_closed_owner_refuses_a_local_fill_publication() {
    let filled = payload(25_000, 25);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let (_client_end, owner_end, net) = network(64, 8384, 25, [Faults::default(); 2]);
    let (mut owner, control) = start(&storage, &buffers, &receive, &[], vec![owner_end]);
    let nets = [net];
    let mut fill = reserve(&storage, &key(2), 0, filled.len()).expect("a fill");
    let mut taken = 0;
    let mut turn = 0;
    while !owner.fill_progress(&fill).is_ready() {
        if taken < filled.len()
            && let Ok(n) = owner.receive_fill(
                &mut fill,
                &filled[taken..(taken + 4096).min(filled.len())],
                &mut crate::storage::WorkBudget::with_io(0, usize::MAX, usize::MAX),
            )
        {
            taken += n;
        }
        turn = drive(&mut [], &mut owner, &control, &nets, turn, 1, |_| false);
        assert!(turn < 10_000, "the fill finished its writes");
    }
    let _ = owner.close(turn * 100);
    let refused = owner.publish_fill(
        fill,
        u64::MAX,
        2,
        &mut crate::storage::WorkBudget::new(1024),
    );
    assert_eq!(
        refused.err(),
        Some(crate::storage::FillPublishError::Closed)
    );
    let visible = storage
        .register()
        .unwrap()
        .lookup(&key(2), 4, &mut crate::storage::WorkBudget::new(1 << 16))
        .is_ok();
    assert!(!visible, "the refused fill published nothing");
}

/// A volume lost to a local fill's write closes admission for later GETs, as the module's lost-volume invariant states, so a GET of a key the storage never held is refused `OwnerUnavailable` rather than answered `Missing`.
#[test]
fn a_volume_lost_to_a_local_fill_write_refuses_a_later_get_of_an_absent_key() {
    let object = payload(5_000, 13);
    let filled = payload(9_000, 14);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 13, [Faults::default(); 2]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &object)],
        vec![owner_end],
    );
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let mut turn = open(&mut client, &mut owner, &control, &nets, 0);
    control.set_gone();
    let mut fill = reserve(&storage, &key(3), 0, filled.len()).expect("a fill");
    let mut taken = 0;
    let begun = turn;
    while owner.volume_report().writes_refused == 0 && turn < begun + 2_000 {
        if taken < filled.len()
            && let Ok(n) = owner.receive_fill(
                &mut fill,
                &filled[taken..(taken + 4096).min(filled.len())],
                &mut crate::storage::WorkBudget::with_io(0, usize::MAX, usize::MAX),
            )
        {
            taken += n;
        }
        turn = drive(
            &mut [&mut client],
            &mut owner,
            &control,
            &nets,
            turn,
            1,
            |_| false,
        );
    }
    assert_eq!(
        owner.volume_report().writes_refused,
        1,
        "premise: the gone device refused the fill's write, which loses the volume"
    );
    fill.abort();
    let absent = client
        .get(key(2), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        5_000,
        |clients| clients[0].outcome(absent).is_some(),
    );
    assert_eq!(owner.volume_report().reads_submitted, 0);
    assert_eq!(
        client.outcome(absent),
        Some(Outcome::Failed(Status::OwnerUnavailable)),
        "the lost volume closed admission before the absent key's lookup"
    );
}

/// A local fill streamed and published through the owner while another peer's transfer runs serves a later GET with its exact bytes, and the running transfer completes unchanged.
#[test]
fn a_local_fill_publishes_during_another_transfer() {
    let large = payload(40_000, 20);
    let filled = payload(25_000, 21);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let pools = [pool(), pool()];
    let releases = [
        Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap(),
        Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap(),
    ];
    let (reader_end, owner_reader, reader_net) = network(64, 8384, 20, [Faults::default(); 2]);
    let (getter_end, owner_getter, getter_net) = network(64, 8384, 21, [Faults::default(); 2]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &large)],
        vec![owner_reader, owner_getter],
    );
    let mut reader = client(0, &pools[0], &releases[0], reader_end);
    let mut getter = client(1, &pools[1], &releases[1], getter_end);
    let nets = [reader_net, getter_net];
    reader.session(0);
    getter.session(0);
    let turn = drive(
        &mut [&mut reader, &mut getter],
        &mut owner,
        &control,
        &nets,
        0,
        5_000,
        |clients| {
            clients
                .iter()
                .all(|client| client.state() == SessionState::Active)
        },
    );
    let running = reader
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let (mut first, mut second) = (Vec::new(), Vec::new());
    let turn = fill_through(
        &storage,
        &mut owner,
        &mut [&mut reader, &mut getter],
        &control,
        &nets,
        &key(3),
        &filled,
        turn,
        |clients| collect(clients[0], running, &mut first),
    );
    assert!(
        !first.is_empty(),
        "the transfer ran while the fill streamed"
    );
    let fresh = getter
        .get(key(3), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    drive(
        &mut [&mut reader, &mut getter],
        &mut owner,
        &control,
        &nets,
        turn,
        10_000,
        |clients| {
            collect(clients[0], running, &mut first);
            collect(clients[1], fresh, &mut second);
            clients[0].outcome(running).is_some() && clients[1].outcome(fresh).is_some()
        },
    );
    assert_eq!(reader.outcome(running), Some(Outcome::Complete));
    assert_eq!(first, large);
    assert_eq!(
        getter.outcome(fresh),
        Some(Outcome::Complete),
        "{:?} {:?} {:?}",
        owner.serve_report(),
        owner.report(),
        owner.census()
    );
    assert_eq!(second, filled);
}

/// The acknowledged close binds the RAM-only `Owner::invalidate` too: the closed owner refuses it with `Closed`, and the published key stays readable.
#[test]
fn a_closed_owner_refuses_a_ram_only_invalidation() {
    let object = payload(20_000, 24);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let (_client_end, owner_end, _net) = network(64, 8384, 24, [Faults::default(); 2]);
    let (mut owner, _control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &object)],
        vec![owner_end],
    );
    let visible = || {
        storage
            .register()
            .unwrap()
            .lookup(&key(1), 4, &mut crate::storage::WorkBudget::new(1 << 16))
            .is_ok()
    };
    assert!(visible(), "premise: the preload published the key");
    let _ = owner.close(0);
    let refused = owner.invalidate(&key(1), 2, &mut crate::storage::WorkBudget::new(1024));
    assert_eq!(refused.err(), Some(crate::storage::InvalidateError::Closed));
    assert!(visible(), "the refused invalidation kept the mapping");
}

/// An object invalidated and republished through the owner while an earlier read of it runs: the earlier GET finishes with exactly the old version, and a GET issued during that read receives exactly the new one.
#[test]
fn an_invalidated_and_republished_key_serves_each_version_whole() {
    let old = payload(20_000, 22);
    let new = payload(18_000, 23);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 22, [Faults::default(); 2]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &old)],
        vec![owner_end],
    );
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let turn = open(&mut client, &mut owner, &control, &nets, 0);
    let first = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let (token, turn) = hold_next_read(&mut client, &mut owner, &control, &nets[0], turn);
    owner
        .invalidate(&key(1), 2, &mut crate::storage::WorkBudget::new(1024))
        .unwrap();
    let mut fill = reserve(&storage, &key(1), 0, new.len()).expect("a fill");
    let mut taken = 0;
    let mut turn = turn;
    while !owner.fill_progress(&fill).is_ready() {
        if taken < new.len()
            && let Ok(n) = owner.receive_fill(
                &mut fill,
                &new[taken..(taken + 4096).min(new.len())],
                &mut crate::storage::WorkBudget::with_io(0, usize::MAX, usize::MAX),
            )
        {
            taken += n;
        }
        // The held read's command stays held while the fill's writes run.
        round(&mut [
            Act::new(Actor::Link(0), &mut || nets[0].borrow_mut().advance(turn)),
            Act::new(Actor::Client(0), &mut || {
                let _ = client.poll(turn * 100);
            }),
            Act::new(Actor::Disk(0), &mut || control.tick(64)),
            Act::new(Actor::Owner(0), &mut || owner.poll(turn * 100)),
        ]);
        turn += 1;
        assert!(turn < 20_000);
    }
    drop(
        owner
            .publish_fill(
                fill,
                u64::MAX,
                2,
                &mut crate::storage::WorkBudget::new(1024),
            )
            .unwrap(),
    );
    let second = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let mut fresh = Vec::new();
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        5_000,
        |clients| {
            collect(clients[0], second, &mut fresh);
            clients[0].outcome(second).is_some()
        },
    );
    assert_eq!(client.outcome(second), Some(Outcome::Complete));
    assert_eq!(fresh, new, "the GET during the read found the new version");
    assert_eq!(
        client.outcome(first),
        None,
        "the earlier read still holds its command"
    );
    control.release(token);
    let mut acquired = Vec::new();
    drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        5_000,
        |clients| {
            collect(clients[0], first, &mut acquired);
            clients[0].outcome(first).is_some()
        },
    );
    assert_eq!(client.outcome(first), Some(Outcome::Complete));
    assert_eq!(
        acquired, old,
        "the earlier read kept the version it acquired"
    );
}

/// Polls the owner, its device and every client until the owner can shut down, then shuts it down; returns its report if it did within the turns.
fn shut_down<'m>(
    mut owner: TestOwner<'_, '_, '_>,
    clients: &mut [&mut Client<'m, LinkEnd<'m>>],
    control: &SimControl,
    nets: &[Rc<RefCell<Net<'_>>>],
    start: u64,
) -> Option<super::owner::OwnerReport> {
    for turn in start..start + 2_000 {
        if owner.blockers().is_none() {
            return owner.shutdown().ok().map(|shutdown| shutdown.report);
        }
        drive(clients, &mut owner, control, nets, turn, 1, |_| false);
    }
    None
}

/// Shutdown from every endpoint state stops admission and sends first and releases the volume only once every request was released and the volume quiesced: idle, mid-handshake, mid-transfer, with a held command, and after a lost volume; close cancels every running read before closing the volume, so no chunk reaches a request after it.
#[test]
fn shutdown_from_every_state_releases_only_after_the_drain() {
    let object = payload(40_000, 24);
    for state in ["idle", "handshake", "transfer", "held", "lost"] {
        let storage = storage(8);
        let buffers = arena(8);
        let receive = pool();
        let client_pool = pool();
        let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
        let (client_end, owner_end, net) = network(64, 8384, 24, [Faults::default(); 2]);
        let (mut owner, control) = start(
            &storage,
            &buffers,
            &receive,
            &[(key(1), 0, &object)],
            vec![owner_end],
        );
        let mut client = client(0, &client_pool, &releases, client_end);
        let nets = [net];
        let mut held = None;
        let mut turn = 0;
        match state {
            "idle" => {}
            "handshake" => {
                client.session(0);
                round(&mut [
                    Act::new(Actor::Client(0), &mut || {
                        let _ = client.poll(0);
                    }),
                    Act::new(Actor::Link(0), &mut || nets[0].borrow_mut().advance(1)),
                    Act::new(Actor::Owner(0), &mut || owner.poll(100)),
                ]);
                turn = 2;
            }
            _ => {
                turn = open(&mut client, &mut owner, &control, &nets, 0);
                if state == "lost" {
                    control.set_gone();
                }
                let id = client
                    .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
                    .unwrap();
                if state == "lost" {
                    turn = drive(
                        &mut [&mut client],
                        &mut owner,
                        &control,
                        &nets,
                        turn,
                        5_000,
                        |clients| clients[0].outcome(id).is_some(),
                    );
                    assert_eq!(
                        client.outcome(id),
                        Some(Outcome::Failed(Status::OwnerUnavailable))
                    );
                } else {
                    let (token, at) =
                        hold_next_read(&mut client, &mut owner, &control, &nets[0], turn);
                    turn = at;
                    if state == "held" {
                        held = Some(token);
                    } else {
                        control.release(token);
                        turn = drive(
                            &mut [&mut client],
                            &mut owner,
                            &control,
                            &nets,
                            turn,
                            3,
                            |_| false,
                        );
                    }
                }
            }
        }
        let progress = owner.close(turn * 100);
        let sent = owner.report().sent;
        let blocked = owner.blockers();
        if state == "held" {
            assert!(
                !matches!(progress, crate::storage::QuiesceProgress::Quiesced(_)),
                "{state}"
            );
            assert!(
                blocked
                    .is_some_and(|blockers| blockers.census.draining + blockers.census.active == 1),
                "{state}: {blocked:?}"
            );
            let refused = owner
                .shutdown()
                .err()
                .expect("a held command blocks the release");
            owner = refused.0;
            control.release(held.take().unwrap());
        }
        let report = shut_down(owner, &mut [&mut client], &control, &nets, turn)
            .expect("the owner shut down after its drain");
        assert_eq!(
            report.sent, sent,
            "{state}: nothing was sent after the close"
        );
        assert!(
            state == "idle" || report.maintained > 0,
            "{state}: maintenance ran in the owner's turns"
        );
    }
}

/// A quiesce the device never proves, or one it fails, leaves the owner blocked with every custody kept: the held request stays live, the progress stays short of `Quiesced`, and release never runs.
#[test]
fn a_failed_quiesce_reports_its_blockers_and_keeps_custody() {
    for mode in [QuiesceMode::Unproven, QuiesceMode::Failed(Some(libc::EIO))] {
        let object = payload(30_000, 25);
        let storage = storage(8);
        let buffers = arena(8);
        let receive = pool();
        let client_pool = pool();
        let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
        let (client_end, owner_end, net) = network(64, 8384, 25, [Faults::default(); 2]);
        let (mut owner, control) = start(
            &storage,
            &buffers,
            &receive,
            &[(key(1), 0, &object)],
            vec![owner_end],
        );
        let mut client = client(0, &client_pool, &releases, client_end);
        let nets = [net];
        let turn = open(&mut client, &mut owner, &control, &nets, 0);
        client
            .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
            .unwrap();
        let (_token, turn) = hold_next_read(&mut client, &mut owner, &control, &nets[0], turn);
        control.set_quiesce(mode);
        let _ = owner.close(turn * 100);
        let turn = drive(
            &mut [&mut client],
            &mut owner,
            &control,
            &nets,
            turn,
            200,
            |_| false,
        );
        let blockers = owner.blockers().expect("the owner stays blocked");
        assert_eq!(
            blockers.census.active + blockers.census.draining,
            1,
            "{mode:?}: the held request keeps its custody"
        );
        assert!(
            !matches!(
                blockers.quiesce,
                Some(crate::storage::QuiesceProgress::Quiesced(_))
            ),
            "{mode:?}: {blockers:?}"
        );
        let (owner, again) = *owner
            .shutdown()
            .err()
            .expect("release never runs before a proven drain");
        assert_eq!(again.census, blockers.census);
        drop((owner, turn));
    }
}

/// A warm re-key of a quiescent owner keeps its bundle, its charges and its PUT grant: the old key's session no longer serves, a client under the new key bootstraps, and a resident object serves again; a re-key with a live request is refused.
#[test]
fn a_warm_rekey_serves_resident_hits_afterwards() {
    let object = payload(20_000, 26);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let pools = [pool(), pool()];
    let releases = [
        Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap(),
        Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap(),
    ];
    let (old_end, owner_old, old_net) = network(64, 8384, 26, [Faults::default(); 2]);
    let (new_end, owner_new, new_net) = network(64, 8384, 27, [Faults::default(); 2]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &object)],
        vec![owner_old, owner_new],
    );
    let mut old = client(0, &pools[0], &releases[0], old_end);
    let nets = [old_net, new_net];
    let turn = open(&mut old, &mut owner, &control, &nets, 0);
    let live = old.get(key(1), 0, 1 << 20, turn * 100, 30_000_000).unwrap();
    let (token, turn) = hold_next_read(&mut old, &mut owner, &control, &nets[0], turn);
    let new_keys = [[0x7E; 32], [0x7F; 32]];
    let new_entries = [
        KeyEntry {
            principal: PRINCIPALS[0],
            key: &new_keys[0],
        },
        KeyEntry {
            principal: PRINCIPALS[1],
            key: &new_keys[1],
        },
    ];
    let before = owner.boot_nonce();
    assert!(matches!(
        owner.rekey(&new_entries, 2, turn * 100),
        Err(super::owner::OwnerRekeyError::Rekey(
            super::session::RekeyError::Busy { .. }
        ))
    ));
    assert_eq!(
        owner.boot_nonce(),
        before,
        "a refused re-key changes nothing"
    );
    assert!(matches!(
        owner.rekey_with_nonce(&new_entries, 2, turn * 100, |_| unreachable!(
            "a busy re-key draws no nonce"
        )),
        Err(super::owner::OwnerRekeyError::Rekey(
            super::session::RekeyError::Busy { .. }
        ))
    ));
    control.release(token);
    let mut live_bytes = Vec::new();
    let turn = drive(
        &mut [&mut old],
        &mut owner,
        &control,
        &nets,
        turn,
        5_000,
        |clients| {
            collect(clients[0], live, &mut live_bytes);
            clients[0].outcome(live).is_some()
        },
    );
    assert_eq!(
        old.outcome(live),
        Some(Outcome::Complete),
        "the old session's live GET finished"
    );
    assert_eq!(live_bytes, object);
    assert!(old.retire(live));
    let turn = drive(
        &mut [&mut old],
        &mut owner,
        &control,
        &nets,
        turn,
        100,
        |_| false,
    );
    let (volume, nonce) = (owner.volume_report(), owner.boot_nonce());
    owner.rekey(&new_entries, 2, turn * 100).unwrap();
    assert_ne!(owner.boot_nonce(), nonce, "a fresh boot nonce");
    assert_eq!(
        (
            owner.put_permission(PeerId(0)),
            owner.put_permission(PeerId(1))
        ),
        (Err(Status::PermissionDenied), Ok(())),
        "the re-key keeps the PUT grant"
    );
    assert_eq!(
        owner.volume_report(),
        volume,
        "the volume stays attached and untouched"
    );
    let stale = old.get(key(1), 0, 1 << 20, turn * 100, 20_000).unwrap();
    let turn = drive(
        &mut [&mut old],
        &mut owner,
        &control,
        &nets,
        turn,
        400,
        |clients| clients[0].outcome(stale).is_some(),
    );
    assert!(
        matches!(old.outcome(stale), Some(Outcome::Failed(_))),
        "the old key's session no longer serves: {:?}",
        old.outcome(stale)
    );
    let memory = ClientMemory {
        receive: &pools[1],
        releases: &releases[1],
        requests: RequestTable::new(4, 1, 4),
        sources: Box::default(),
        routes: super::client_tests::routes(),
    };
    let entry = [new_entries[1]];
    let mut fresh = Client::initialize(
        client_config(1),
        memory,
        new_end,
        &entry,
        2,
        &mut EngineBudget::new(1 << 24),
    )
    .unwrap();
    fresh.session(turn * 100);
    let turn = drive(
        &mut [&mut fresh],
        &mut owner,
        &control,
        &nets,
        turn,
        5_000,
        |clients| clients[0].state() == SessionState::Active,
    );
    assert_eq!(
        fresh.state(),
        SessionState::Active,
        "the new key bootstraps"
    );
    let hit = fresh
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let mut bytes = Vec::new();
    drive(
        &mut [&mut fresh],
        &mut owner,
        &control,
        &nets,
        turn,
        5_000,
        |clients| {
            collect(clients[0], hit, &mut bytes);
            clients[0].outcome(hit).is_some()
        },
    );
    assert_eq!(
        fresh.outcome(hit),
        Some(Outcome::Complete),
        "the resident object serves after the re-key"
    );
    assert_eq!(bytes, object);
}

/// A transport whose sends panic while `armed` is set.
struct Panicking<'a>(Mux<'a>, Rc<std::cell::Cell<bool>>);

impl<'a> Datagrams<'a> for Panicking<'a> {
    fn receive<'p>(
        &mut self,
        pool: &'p PacketPool<'a>,
        into: &mut [Option<PacketLease<'p>>],
        meta: &mut [Received],
    ) -> Result<usize, DatagramError> {
        self.0.receive(pool, into, meta)
    }

    fn rx_ring(&self) -> u32 {
        self.0.rx_ring()
    }

    fn reclaim(&mut self) {
        self.0.reclaim();
    }

    fn send(&mut self, batch: &[Outgoing<'_, 'a>]) -> Result<usize, DatagramError> {
        assert!(!self.1.get(), "the transport unwinds");
        self.0.send(batch)
    }
}

/// One turn of the link, `client`, the device and `owner` at `turn`, as one controller round.
fn turn_once<'m>(
    client: &mut Client<'m, LinkEnd<'m>>,
    owner: &mut Owner<'_, 'm, '_, TestPlatform, SimDisk, Panicking<'m>>,
    net: &Rc<RefCell<Net<'_>>>,
    control: &SimControl,
    turn: u64,
) {
    turn_then(client, owner, net, control, turn, || {});
}

/// [`turn_once`], running `after` in the owner's action right after its
/// poll, so `after` sees what that poll did before a later action of the
/// round changes it.
fn turn_then<'m>(
    client: &mut Client<'m, LinkEnd<'m>>,
    owner: &mut Owner<'_, 'm, '_, TestPlatform, SimDisk, Panicking<'m>>,
    net: &Rc<RefCell<Net<'_>>>,
    control: &SimControl,
    turn: u64,
    mut after: impl FnMut(),
) {
    round(&mut [
        Act::new(Actor::Link(0), &mut || net.borrow_mut().advance(turn)),
        Act::new(Actor::Client(0), &mut || {
            let _ = client.poll(turn * 100);
        }),
        Act::new(Actor::Disk(0), &mut || control.tick(64)),
        Act::new(Actor::Owner(0), &mut || {
            owner.poll(turn * 100);
            after();
        }),
    ]);
}

/// What one run of [`unwound_turn`] observed, in the order it observed it.
#[derive(Debug)]
struct Unwound {
    /// A panic left `Owner::poll` during the turns of the missing-key GET.
    unwound: bool,
    /// `poisoned()` right after those turns.
    poisoned_at_once: bool,
    /// `poisoned()` after the 200 complete polls that followed them.
    poisoned_after_polls: bool,
    /// The outcome of a GET of a published key sent after those polls.
    later_get: Option<Outcome>,
    /// Lookups that reached their pin while the later GET was handled.
    later_lookups: u64,
    /// Whether the device saw a new read command while the later GET was handled.
    later_read: bool,
    /// The outcome of a PUT whose BEGIN was sent once the later GET was answered.
    later_put: Option<UploadOutcome>,
    /// BEGINs that acquired fill authority while the later PUT BEGIN was handled.
    later_begun: u64,
    /// The answer to a re-key after the later GET and PUT BEGIN, with the first read still held.
    rekey: Result<(), OwnerRekeyError>,
    /// Requests active or draining after the 200 polls, and after the later GET and PUT BEGIN were answered.
    custody_held: [u32; 2],
    /// Requests active or draining after the owner closed and polled with the first read still held; `None` when the device returned the read to an open owner.
    custody_closed: Option<u32>,
    /// Requests active or draining once the device returned the held read.
    custody_drained: u32,
    /// `poisoned()` at the end of the run, after the close.
    poisoned_closed: bool,
}

/// Runs one owner and one client over the link and the device. A GET of key 1 is admitted and its read held at the device. With `plant`, the owner's next send, a missing key's ERROR, panics inside `Owner::poll` and the run catches the unwind; right after it, before any poll, the owner refuses `extract` and a re-key. Complete polls follow, then a GET of key 2, a PUT BEGIN of key 3 and a re-key. With `close_held` the owner closes while the device holds the first read and the device returns the read to the closed owner; otherwise the device returns it to the open owner, which closes once the request drained.
fn unwound_turn(plant: bool, close_held: bool) -> Unwound {
    let first = payload(30_000, 28);
    let second = payload(9_000, 29);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 28, [Faults::default(); 2]);
    let mut device = Device::new(&storage, &buffers);
    publish(&storage, &mut device, &key(1), 0, &first);
    publish(&storage, &mut device, &key(2), 0, &second);
    let Device { volume, control } = device;
    let cache = storage.issue_cache().unwrap();
    let registration = cache.register().unwrap();
    let keys = Keys {
        principals: &PRINCIPALS[..1],
        entries: &entries()[..1],
        epoch: 1,
        put: &PRINCIPALS[..1],
    };
    let armed = Rc::new(std::cell::Cell::new(false));
    let transport = Panicking(Mux::new(vec![owner_end]), Rc::clone(&armed));
    let mut owner = Owner::start(
        OWNER,
        Bundle {
            cache,
            registration,
            volume,
        },
        keys,
        transport,
        &receive,
        &mut EngineBudget::new(1 << 26),
    )
    .map_err(|refused| refused.error)
    .unwrap();
    let mut client = client(0, &client_pool, &releases, client_end);
    client.session(0);
    let mut turn = 0;
    while client.state() != SessionState::Active && turn < 5_000 {
        turn_once(&mut client, &mut owner, &net, &control, turn);
        turn += 1;
    }
    let running = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let before = last_read(&control);
    // The read is held right after the owner's poll submits it, before a
    // device tick can run it.
    let mut held = None;
    while held.is_none() && turn < 10_000 {
        turn_then(&mut client, &mut owner, &net, &control, turn, || {
            let read = last_read(&control);
            if read != before {
                let token = read.expect("a submitted read");
                control.hold(token);
                held = Some(token);
            }
        });
        turn += 1;
    }
    let token = held.expect("the owner submitted the running read");
    armed.set(plant);
    // A missing key's ERROR is the next frame the owner sends.
    let missing = client
        .get(key(9), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        for at in turn..turn + 100 {
            turn_once(&mut client, &mut owner, &net, &control, at);
        }
    }))
    .is_err();
    let poisoned_at_once = owner.poisoned();
    let fresh_key = [0x55; 32];
    let entry = [KeyEntry {
        principal: PRINCIPALS[0],
        key: &fresh_key,
    }];
    if unwound {
        let live = owner.census().live();
        let Err(back) = owner.extract() else {
            panic!("an unwound turn is no boundary to extract at");
        };
        owner = *back;
        assert_eq!(
            owner.census().live(),
            live,
            "the owner comes back unchanged"
        );
        assert_eq!(
            owner.rekey(&entry, 2, turn * 100),
            Err(OwnerRekeyError::Poisoned),
            "a poisoned owner keeps its keys"
        );
        assert_eq!(
            owner.rekey_with_nonce(&entry, 2, turn * 100, |_| unreachable!(
                "a poisoned re-key draws no nonce"
            )),
            Err(OwnerRekeyError::Poisoned)
        );
    }
    armed.set(false);
    turn += 100;
    // The pending ERROR goes out and its request releases, freeing the peer's second share.
    for at in turn..turn + 200 {
        turn_once(&mut client, &mut owner, &net, &control, at);
    }
    turn += 200;
    let poisoned_after_polls = owner.poisoned();
    let custody_after_polls = owner.census().live();
    let _ = client.retire(missing);

    let (lookups, read) = (owner.lookups(), last_read(&control));
    let later_get = client
        .get(key(2), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    for at in turn..turn + 400 {
        turn_once(&mut client, &mut owner, &net, &control, at);
        while let Some(fragment) = client.take(later_get) {
            drop(fragment);
        }
    }
    turn += 400;
    let later_lookups = owner.lookups() - lookups;
    let later_read = last_read(&control) != read;
    let begun = owner.put_report().begun;
    let later_put = client
        .put(key(3), CacheVersion(0), turn * 100, 30_000_000)
        .unwrap();
    for at in turn..turn + 400 {
        turn_once(&mut client, &mut owner, &net, &control, at);
    }
    turn += 400;
    let later_begun = owner.put_report().begun - begun;
    let rekey = owner.rekey(&entry, 2, turn * 100);
    let custody_answered = owner.census().live();

    let mut custody_closed = None;
    if close_held {
        let _ = owner.close(turn * 100);
        for at in turn..turn + 400 {
            turn_once(&mut client, &mut owner, &net, &control, at);
        }
        turn += 400;
        custody_closed = Some(owner.census().live());
    }
    control.release(token);
    for at in turn..turn + 5_000 {
        turn_once(&mut client, &mut owner, &net, &control, at);
        while let Some(fragment) = client.take(running) {
            drop(fragment);
        }
        if client.outcome(running).is_some() && owner.census().live() == 0 {
            break;
        }
    }
    let custody_drained = owner.census().live();
    if !close_held {
        assert_eq!(
            owner.quiesce(),
            None,
            "the owner is open while its request drains"
        );
        let _ = owner.close(turn * 100);
    }
    Unwound {
        unwound,
        poisoned_at_once,
        poisoned_after_polls,
        later_get: client.outcome(later_get),
        later_lookups,
        later_read,
        later_put: client.put_outcome(later_put),
        later_begun,
        rekey,
        custody_held: [custody_after_polls, custody_answered],
        custody_closed,
        custody_drained,
        poisoned_closed: owner.poisoned(),
    }
}

/// Requires what every run with the fault shows up to the re-key: the turn unwound, the owner is poisoned at once and after complete polls, a later GET and a later PUT BEGIN are refused `OwnerUnavailable` with no lookup, read command or fill authority, the re-key is refused `Poisoned`, and the admitted read's request stays in the census.
fn admission_ended(seen: &Unwound) {
    assert!(seen.unwound, "a send unwound the turn: {seen:?}");
    assert!(
        seen.poisoned_at_once,
        "the unwound turn shows at once: {seen:?}"
    );
    assert!(
        seen.poisoned_after_polls,
        "the owner stays poisoned after complete polls: {seen:?}"
    );
    assert_eq!(
        seen.later_get,
        Some(Outcome::Failed(Status::OwnerUnavailable)),
        "admission is poisoned: {seen:?}"
    );
    assert_eq!(
        (seen.later_lookups, seen.later_read),
        (0, false),
        "the refused GET takes no lookup and no read command: {seen:?}"
    );
    assert_eq!(
        (seen.later_put, seen.later_begun),
        (Some(UploadOutcome::Failed(Status::OwnerUnavailable)), 0),
        "the refused PUT BEGIN takes no fill authority: {seen:?}"
    );
    assert_eq!(
        seen.rekey,
        Err(OwnerRekeyError::Poisoned),
        "a re-key after complete polls is still refused: {seen:?}"
    );
    assert_eq!(
        seen.custody_held,
        [1, 1],
        "the running request keeps its custody: {seen:?}"
    );
}

/// A turn that unwinds poisons admission: later GETs and PUT BEGINs are refused `OwnerUnavailable`, while the request running when it unwound keeps its custody until its read drains on the open owner.
#[test]
fn an_unwound_turn_poisons_admission_and_keeps_custody() {
    let seen = unwound_turn(true, false);
    admission_ended(&seen);
    assert_eq!(
        seen.custody_drained, 0,
        "custody ends only with the drain: {seen:?}"
    );
    assert!(
        seen.poisoned_closed,
        "the poison stays visible after the close: {seen:?}"
    );
}

/// An owner that closes after a turn unwound, while the device holds an admitted read, keeps that read's request in its census until the device returns the read.
#[test]
fn a_close_after_an_unwound_turn_keeps_the_held_read_in_custody() {
    let seen = unwound_turn(true, true);
    admission_ended(&seen);
    assert_eq!(
        (seen.custody_closed, seen.custody_drained),
        (Some(1), 0),
        "the request stays in the census through the close and leaves once the device returns its read: {seen:?}"
    );
    assert!(
        seen.poisoned_closed,
        "the poison stays visible after the close: {seen:?}"
    );
}

/// The steps of `a_close_after_an_unwound_turn_keeps_the_held_read_in_custody` with no fault: no turn unwinds, the owner is never poisoned, and the later GET and PUT BEGIN are admitted, so that test's refusals come from the unwound turn.
#[test]
fn turns_that_all_complete_leave_admission_open() {
    let seen = unwound_turn(false, true);
    assert!(!seen.unwound, "no turn unwound: {seen:?}");
    assert!(
        !seen.poisoned_at_once && !seen.poisoned_after_polls && !seen.poisoned_closed,
        "an owner whose turns all completed is not poisoned: {seen:?}"
    );
    assert_eq!(
        seen.later_get,
        Some(Outcome::Complete),
        "the later GET is admitted and served: {seen:?}"
    );
    assert!(
        seen.later_lookups >= 1 && seen.later_read,
        "the later GET takes a lookup and a read command: {seen:?}"
    );
    assert_eq!(
        (seen.later_put, seen.later_begun),
        (None, 1),
        "the later PUT BEGIN takes fill authority and its upload awaits the caller's PREPARE: {seen:?}"
    );
    assert!(
        matches!(
            seen.rekey,
            Err(OwnerRekeyError::Rekey(RekeyError::Busy { .. }))
        ),
        "a re-key with the admitted read live is refused Busy: {seen:?}"
    );
    assert_eq!(
        seen.custody_drained, 0,
        "custody ends once the closed owner's volume drains the read: {seen:?}"
    );
}

/// A restart over a fresh storage changes the session: the restarted owner draws a new boot nonce, the client's old session no longer serves, and after a new bootstrap the restarted owner's empty index answers the earlier key `Missing`; `a_new_storage_and_session_over_old_device_bytes_trusts_nothing` in the storage hit tests shows that a storage over old device bytes trusts none of them.
#[test]
fn a_cold_restart_changes_the_session_and_starts_cold() {
    let object = payload(10_000, 29);
    let first_storage = storage(8);
    let first_buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let second_storage = storage(8);
    let second_buffers = arena(8);
    let (client_end, owner_end, net) = network(64, 8384, 29, [Faults::default(); 2]);
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let (nonce, turn, owner_end) = {
        let (mut owner, control) = start(
            &first_storage,
            &first_buffers,
            &receive,
            &[(key(1), 0, &object)],
            vec![owner_end],
        );
        let turn = open(&mut client, &mut owner, &control, &nets, 0);
        let hit = client
            .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
            .unwrap();
        let turn = drive(
            &mut [&mut client],
            &mut owner,
            &control,
            &nets,
            turn,
            5_000,
            |clients| {
                while let Some(fragment) = clients[0].take(hit) {
                    drop(fragment);
                }
                clients[0].outcome(hit).is_some()
            },
        );
        assert_eq!(client.outcome(hit), Some(Outcome::Complete));
        assert!(client.retire(hit));
        let nonce = owner.boot_nonce();
        let _ = owner.close(turn * 100);
        let mut owner = owner;
        let mut turn = turn;
        while owner.blockers().is_some() && turn < 100_000 {
            turn = drive(
                &mut [&mut client],
                &mut owner,
                &control,
                &nets,
                turn,
                1,
                |_| false,
            );
        }
        let shutdown = owner.shutdown().ok().expect("a clean shutdown");
        (
            nonce,
            turn,
            shutdown
                .transport
                .ends
                .into_iter()
                .next()
                .expect("the link"),
        )
    };
    let (mut owner, control) = start(
        &second_storage,
        &second_buffers,
        &receive,
        &[],
        vec![owner_end],
    );
    assert_ne!(
        owner.boot_nonce(),
        nonce,
        "the restart drew a new boot nonce"
    );
    let stale = client.get(key(1), 0, 1 << 20, turn * 100, 20_000).unwrap();
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        400,
        |clients| clients[0].outcome(stale).is_some(),
    );
    assert!(
        matches!(client.outcome(stale), Some(Outcome::Failed(_))),
        "the old session no longer serves"
    );
    let turn = open(&mut client, &mut owner, &control, &nets, turn);
    let cold = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        5_000,
        |clients| clients[0].outcome(cold).is_some(),
    );
    assert_eq!(
        client.outcome(cold),
        Some(Outcome::Missing),
        "the lost index starts cold"
    );
}

/// With maintenance funded, the first turn runs one storage maintenance call within its work steps; a call that finds no more work rests the stage for `MAINTAIN_REST_US` microseconds of turn time, an invalidation forwarded through the owner ends the rest so the next turn calls again, and zero work keeps the stage idle.
#[test]
fn the_turn_runs_funded_maintenance_and_rests_when_the_storage_is_done() {
    let object = payload(900, 31);
    for funded in [true, false] {
        let storage = storage(8);
        let buffers = arena(8);
        let receive = pool();
        let mut device = Device::new(&storage, &buffers);
        publish(&storage, &mut device, &key(1), 0, &object);
        let Device { volume, .. } = device;
        let cache = storage.issue_cache().unwrap();
        let registration = cache.register().unwrap();
        let keys = Keys {
            principals: &PRINCIPALS[..1],
            entries: &entries()[..1],
            epoch: 1,
            put: &[],
        };
        let (_, end, _) = network(4, 8384, 1, [Faults::default(); 2]);
        let config = OwnerConfig {
            maintain_work: if funded {
                storage.maintain_minimum()
            } else {
                0
            },
            ..OWNER
        };
        let mut owner = Owner::start(
            config,
            Bundle {
                cache,
                registration,
                volume,
            },
            keys,
            Mux::new(vec![end]),
            &receive,
            &mut EngineBudget::new(1 << 26),
        )
        .map_err(|refused| refused.error)
        .unwrap();
        if !funded {
            for turn in 0..20 {
                owner.poll(turn * 100);
            }
            assert_eq!(owner.report().maintained, 0, "zero work calls nothing");
            continue;
        }
        // The stage calls every turn while the storage reports more work, then rests once a call finds none.
        let mut now = 0;
        let mut rested_at = None;
        while now < 2_000 {
            let before = owner.report().maintained;
            owner.poll(now);
            if owner.report().maintained == before {
                rested_at = Some(now);
                break;
            }
            now += 100;
        }
        let rested_at = rested_at.expect("the storage reports no more work within twenty turns");
        assert!(rested_at >= 100, "the first turn calls");
        let calls = owner.report().maintained;
        // The clean call ran on the turn before the first rested one.
        let rest_ends = rested_at - 100 + MAINTAIN_REST_US;
        owner.poll(rest_ends - 1);
        assert_eq!(
            owner.report().maintained,
            calls,
            "the stage rests until the rest's time has passed"
        );
        owner.poll(rest_ends);
        assert_eq!(
            owner.report().maintained,
            calls + 1,
            "the rest ends and the stage calls again"
        );
        owner.poll(rest_ends + 1);
        assert_eq!(
            owner.report().maintained,
            calls + 1,
            "a clean call rests again"
        );
        owner
            .invalidate(&key(1), 2, &mut crate::storage::WorkBudget::new(1024))
            .expect("the object is resident");
        owner.poll(rest_ends + 2);
        assert_eq!(
            owner.report().maintained,
            calls + 2,
            "an invalidation ends the rest"
        );
        assert_eq!(owner.report().maintenance_refused, 0);
    }
}

/// A GET whose read starts while an earlier request still awaits its final ACK, so the volume hands it the earlier read's freed operation slot, keeps its binding when the earlier request releases, and completes.
#[test]
fn a_read_reusing_a_freed_operation_slot_keeps_its_binding() {
    let first = payload(9_000, 30);
    let second = payload(12_000, 31);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 30, [Faults::default(); 2]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &first), (key(2), 0, &second)],
        vec![owner_end],
    );
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let turn = open(&mut client, &mut owner, &control, &nets, 0);
    let a = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let mut b = None;
    let (mut first_bytes, mut second_bytes) = (Vec::new(), Vec::new());
    for at in turn..turn + 5_000 {
        round(&mut [
            Act::new(Actor::Link(0), &mut || nets[0].borrow_mut().advance(at)),
            Act::new(Actor::Client(0), &mut || {
                let _ = client.poll(at * 100);
            }),
            Act::new(Actor::Disk(0), &mut || control.tick(64)),
            Act::new(Actor::Owner(0), &mut || owner.poll(at * 100)),
        ]);
        collect(&mut client, a, &mut first_bytes);
        if b.is_none() && !first_bytes.is_empty() {
            // The earlier read finished its one command, so the next read reuses its operation slot.
            b = client.get(key(2), 0, 1 << 20, at * 100, 30_000_000).ok();
        }
        if let Some(b) = b {
            collect(&mut client, b, &mut second_bytes);
            if client.outcome(a).is_some() && client.outcome(b).is_some() {
                break;
            }
        }
    }
    let b = b.expect("the second GET started");
    assert_eq!(client.outcome(a), Some(Outcome::Complete));
    assert_eq!(first_bytes, first);
    assert_eq!(client.outcome(b), Some(Outcome::Complete));
    assert_eq!(second_bytes, second);
}

/// Each peer's bootstrap reply leaves in the poll that receives its HELLO when the reply rotation reaches it after an idle peer.
#[test]
fn a_bootstrap_reply_leaves_in_the_poll_that_receives_its_hello() {
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let pools = [pool(), pool()];
    let releases = [
        Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap(),
        Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap(),
    ];
    let (first_end, owner_first, first_net) = network(64, 8384, 21, [Faults::default(); 2]);
    let (second_end, owner_second, second_net) = network(64, 8384, 22, [Faults::default(); 2]);
    let (mut owner, _control) = start(
        &storage,
        &buffers,
        &receive,
        &[],
        vec![owner_first, owner_second],
    );
    let mut clients = [
        client(0, &pools[0], &releases[0], first_end),
        client(1, &pools[1], &releases[1], second_end),
    ];
    let nets = [first_net, second_net];
    // The rotation starts at peer 0 on the first poll and at peer 1 on the second, so each reply follows an idle peer.
    for (turn, peer) in [(0u64, 1usize), (1, 0)] {
        clients[peer].session(turn * 100);
        // The HELLO is in flight before the round whose owner poll receives
        // it, so the client's poll is a round of its own.
        round(&mut [Act::new(Actor::Client(peer as u16), &mut || {
            let _ = clients[peer].poll(turn * 100);
        })]);
        round(&mut [
            Act::new(Actor::Link(0), &mut || nets[0].borrow_mut().advance(turn)),
            Act::new(Actor::Link(1), &mut || nets[1].borrow_mut().advance(turn)),
            Act::new(Actor::Owner(0), &mut || owner.poll(turn * 100)),
        ]);
        assert_eq!(
            nets[peer].borrow().pending(0),
            1,
            "peer {peer}'s CHALLENGE left at turn {turn}"
        );
    }
}

/// A transport that takes part of a turn's batch loses no frame: the frames it left go out in later turns without a retry, so the GET completes with exactly one send of each of its frames.
#[test]
fn a_transport_that_takes_part_of_a_turn_loses_no_frame() {
    let object = payload(40_000, 23);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    // A link holding one datagram, so a turn's sends past the first are left with the owner.
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(1, 8384, 23, [Faults::default(); 2]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &object)],
        vec![owner_end],
    );
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let turn = open(&mut client, &mut owner, &control, &nets, 0);
    let bootstrap_sends = owner.report().sent;
    let id = client
        .get(key(1), 0, 1 << 20, turn * 100, 5_000_000)
        .unwrap();
    let mut bytes = Vec::new();
    drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        50_000,
        |clients| {
            collect(clients[0], id, &mut bytes);
            clients[0].outcome(id).is_some()
        },
    );
    collect(&mut client, id, &mut bytes);
    assert_eq!(client.outcome(id), Some(Outcome::Complete));
    assert_eq!(bytes, object);
    let report = owner.report();
    assert_eq!(owner.serve_report().retries, 0, "no frame was lost");
    assert_eq!(report.failed, 0);
    assert_eq!(
        report.sent - bootstrap_sends,
        7,
        "START, five fragments and COMPLETE, each sent once"
    );
}

#[test]
fn a_failed_transport_call_counts_its_frames_failed_and_retries_recover() {
    let object = payload(40_000, 28);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let faults = [
        Faults {
            error: 50,
            ..Faults::default()
        },
        Faults::default(),
    ];
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 28, faults);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &object)],
        vec![owner_end],
    );
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let turn = open(&mut client, &mut owner, &control, &nets, 0);
    let sent_before = owner.report().sent;
    let id = client
        .get(key(1), 0, 1 << 20, turn * 100, 5_000_000)
        .unwrap();
    let mut bytes = Vec::new();
    let mut received = 0u64;
    for turn in turn..turn + 50_000 {
        round(&mut [
            Act::new(Actor::Link(0), &mut || nets[0].borrow_mut().advance(turn)),
            Act::new(Actor::Client(0), &mut || {
                received += u64::from(client.poll(turn * 100).received);
            }),
            Act::new(Actor::Disk(0), &mut || control.tick(64)),
            Act::new(Actor::Owner(0), &mut || owner.poll(turn * 100)),
        ]);
        collect(&mut client, id, &mut bytes);
        if client.outcome(id).is_some() {
            break;
        }
    }
    collect(&mut client, id, &mut bytes);
    assert_eq!(client.outcome(id), Some(Outcome::Complete));
    assert_eq!(bytes, object);
    let report = owner.report();
    // Which send calls fail follows the order of the calls, so the listed
    // order's draws fail one and resend its frames; every order keeps the
    // outcome, the bytes and the sent accounting below.
    if crate::sim::round::legacy() {
        assert!(report.failed > 0, "{report:?}");
        let serve = owner.serve_report();
        assert!(
            serve.retries + serve.hole_resends > 0,
            "the lost frames were resent: {serve:?}"
        );
    }
    // Datagrams the link still holds toward the client left the owner as well.
    let in_flight = nets[0].borrow().pending(0) as u64;
    assert_eq!(
        report.sent - sent_before,
        received + in_flight,
        "every datagram counted sent left for the client: {report:?}"
    );
}

/// A read bound in a later request slot keeps taking grants once the request in an earlier slot released: a GET stalled at its window behind a finished GET still completes with its own bytes.
#[test]
fn a_read_past_a_released_request_slot_keeps_its_grants() {
    let first = payload(49_000, 23);
    let second = payload(49_000, 24);
    // One-fragment read commands, so each GET's read needs grants until its last fragment.
    let (storage, buffers) = narrow(8192, 8, 8192);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 23, [Faults::default(); 2]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &first), (key(2), 0, &second)],
        vec![owner_end],
    );
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let mut turn = open(&mut client, &mut owner, &control, &nets, 0);
    // Untaken fragments hold each GET at its window, so the first keeps request slot 0 while the second takes slot 1.
    let early = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        100,
        |_| false,
    );
    let late = client
        .get(key(2), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        100,
        |_| false,
    );
    assert_eq!(owner.census().active, 2, "both GETs wait at their windows");
    assert_eq!(client.outcome(late), None);
    let mut early_bytes = Vec::new();
    let limit = turn + 2_000;
    while client.outcome(early).is_none() || owner.census().active + owner.census().draining > 1 {
        assert!(turn < limit, "the first GET finished and released");
        turn = drive(
            &mut [&mut client],
            &mut owner,
            &control,
            &nets,
            turn,
            1,
            |_| false,
        );
        collect(&mut client, early, &mut early_bytes);
    }
    assert_eq!(client.outcome(early), Some(Outcome::Complete));
    assert_eq!(early_bytes, first);
    let mut late_bytes = Vec::new();
    drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        2_000,
        |clients| {
            collect(clients[0], late, &mut late_bytes);
            clients[0].outcome(late).is_some()
        },
    );
    collect(&mut client, late, &mut late_bytes);
    assert_eq!(client.outcome(late), Some(Outcome::Complete));
    assert_eq!(late_bytes, second);
}

/// A re-handshake under the client's same boot nonce replaces its session, and the client ends the replaced session's requests without a CANCEL, so the owner ends them too: the request whose read the device holds turns draining, the drain then frees its slot, and a GET under the new session on the same wire slot completes.
#[test]
fn a_same_boot_session_replacement_ends_the_replaced_requests() {
    let object = payload(30_000, 31);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 31, [Faults::default(); 2]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &object)],
        vec![owner_end],
    );
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let turn = open(&mut client, &mut owner, &control, &nets, 0);
    let replaced = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let (token, turn) = hold_next_read(&mut client, &mut owner, &control, &nets[0], turn);
    let turn = open(&mut client, &mut owner, &control, &nets, turn);
    assert_eq!(
        client.outcome(replaced),
        Some(Outcome::Failed(Status::SessionMismatch))
    );
    assert_eq!(
        owner.census().active,
        0,
        "the replaced session's request ended"
    );
    assert_eq!(
        owner.census().draining,
        1,
        "the held read keeps its custody"
    );
    control.release(token);
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        50,
        |_| false,
    );
    assert_eq!(owner.census().active + owner.census().draining, 0);
    assert!(client.retire(replaced));
    let successor = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    assert_eq!(successor.slot(), replaced.slot());
    let mut bytes = Vec::new();
    drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        5_000,
        |clients| {
            collect(clients[0], successor, &mut bytes);
            clients[0].outcome(successor).is_some()
        },
    );
    collect(&mut client, successor, &mut bytes);
    assert_eq!(client.outcome(successor), Some(Outcome::Complete));
    assert_eq!(bytes, object);
}

#[test]
fn a_peer_whose_sends_fail_loses_no_other_peers_frames() {
    let stuck = payload(45_000, 32);
    let small = super::oracle_endpoint_tests::served_content(30_000);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let pools = [pool(), pool()];
    let releases = [
        Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap(),
        Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap(),
    ];
    let (dead_end, owner_dead, dead_net) = network(64, 8384, 32, [Faults::default(); 2]);
    let (live_end, owner_live, live_net) = network(64, 8384, 33, [Faults::default(); 2]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &stuck), (key(2), 0, &small)],
        vec![owner_dead, owner_live],
    );
    let mut dead = client(0, &pools[0], &releases[0], dead_end);
    let mut live = client(1, &pools[1], &releases[1], live_end);
    let nets = [dead_net, live_net];
    dead.session(0);
    live.session(0);
    let turn = drive(
        &mut [&mut dead, &mut live],
        &mut owner,
        &control,
        &nets,
        0,
        5_000,
        |clients| {
            clients
                .iter()
                .all(|client| client.state() == SessionState::Active)
        },
    );
    dead.get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let mut turn = drive(
        &mut [&mut dead, &mut live],
        &mut owner,
        &control,
        &nets,
        turn,
        1,
        |_| false,
    );
    assert_eq!(owner.census().active, 1, "the owner took the stuck GET");
    // From here every send toward the stuck peer fails; its client is no longer polled, so every failed call on its link is one of the owner's.
    nets[0].borrow_mut().set_faults(
        0,
        Faults {
            error: 100,
            ..Faults::default()
        },
    );
    let mut gets = Vec::new();
    for _ in 0..4 {
        let id = live
            .get(key(2), 0, 1 << 20, turn * 100, 30_000_000)
            .unwrap();
        let mut bytes = Vec::new();
        let began = turn;
        turn = drive(
            &mut [&mut live],
            &mut owner,
            &control,
            &nets,
            turn,
            5_000,
            |clients| {
                collect(clients[0], id, &mut bytes);
                clients[0].outcome(id).is_some()
            },
        );
        collect(&mut live, id, &mut bytes);
        assert_eq!(live.outcome(id), Some(Outcome::Complete));
        assert_eq!(bytes, small);
        assert!(live.retire(id));
        gets.push((turn - began, 5_000, bytes));
    }
    for _ in 0..2_000 {
        if owner.census().live() == 0 {
            break;
        }
        turn = drive(
            &mut [&mut live],
            &mut owner,
            &control,
            &nets,
            turn,
            1,
            |_| false,
        );
    }
    let verdict = super::oracle_endpoint_tests::healthy_gets(
        &storage,
        (
            &small,
            fills_written(&owner, &control)
                .pop()
                .expect("the preload's write evidence"),
        ),
        gets,
        (1, owner.census().live()),
    );
    assert!(verdict.satisfies(&[Isolation, Bytes]), "{verdict:?}");
    let errors = nets[0].borrow().report(0).errors;
    let failed = owner.report().failed;
    assert!(failed > 0, "the owner kept sending toward the stuck peer");
    assert!(
        failed <= errors,
        "every failed frame led a failed call toward the stuck peer: {failed} failed, {errors} failed calls"
    );
}

/// A lease leaked from a local publish outlives a clean owner shutdown and blocks the storage's finalization, which counts it among its reserved leases, so nothing it holds is reused.
#[test]
fn a_leaked_lease_blocks_finalization_after_shutdown() {
    let filled = payload(9_000, 32);
    let mut storage = storage(8);
    {
        let buffers = arena(8);
        let receive = pool();
        let client_pool = pool();
        let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
        let (client_end, owner_end, net) = network(64, 8384, 32, [Faults::default(); 2]);
        let (mut owner, control) = start(&storage, &buffers, &receive, &[], vec![owner_end]);
        let mut client = client(0, &client_pool, &releases, client_end);
        let nets = [net];
        let mut fill = reserve(&storage, &key(4), 0, filled.len()).expect("a fill");
        let mut taken = 0;
        let mut turn = 0;
        while !owner.fill_progress(&fill).is_ready() {
            if taken < filled.len() {
                taken += owner
                    .receive_fill(
                        &mut fill,
                        &filled[taken..],
                        &mut crate::storage::WorkBudget::with_io(0, usize::MAX, usize::MAX),
                    )
                    .unwrap_or(0);
            }
            turn = drive(
                &mut [&mut client],
                &mut owner,
                &control,
                &nets,
                turn,
                1,
                |_| false,
            );
        }
        let lease = owner
            .publish_fill(
                fill,
                u64::MAX,
                2,
                &mut crate::storage::WorkBudget::new(1024),
            )
            .unwrap();
        std::mem::forget(lease);
        let _ = owner.close(turn * 100);
        while owner.blockers().is_some() && turn < 10_000 {
            turn = drive(
                &mut [&mut client],
                &mut owner,
                &control,
                &nets,
                turn,
                1,
                |_| false,
            );
        }
        let shutdown = owner.shutdown().ok().expect("the owner shuts down");
        drop(shutdown);
    }
    match storage.finalize(&mut crate::storage::WorkBudget::new(1 << 16)) {
        Ok(crate::storage::Finalization::Blocked(blockers)) => {
            assert_eq!(blockers.leases, 1, "{blockers:?}")
        }
        other => panic!("the leaked lease blocks finalization: {other:?}"),
    }
}

/// A re-key discards the bootstrap replies still waiting for a blocked transport and the count the reply round stops on with them, so an idle re-keyed owner's reply round ends at once.
#[test]
fn a_rekey_discards_waiting_replies_with_their_count() {
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    // The owner's sends toward the client would block, so its CHALLENGE waits in the reply queue.
    let blocked = Faults {
        would_block: 100,
        ..Faults::default()
    };
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 29, [blocked, Faults::default()]);
    let (mut owner, _control) = start(&storage, &buffers, &receive, &[], vec![owner_end]);
    let mut client = client(0, &client_pool, &releases, client_end);
    client.session(0);
    // The HELLO is in flight before the round whose owner poll receives it,
    // so the client's poll is a round of its own.
    round(&mut [Act::new(Actor::Client(0), &mut || {
        let _ = client.poll(0);
    })]);
    round(&mut [
        Act::new(Actor::Link(0), &mut || net.borrow_mut().advance(0)),
        Act::new(Actor::Owner(0), &mut || owner.poll(0)),
    ]);
    assert_eq!(owner.waiting_replies(), 1, "the CHALLENGE waits");
    let new_key = [0x7E; 32];
    let new_entries = [KeyEntry {
        principal: PRINCIPALS[0],
        key: &new_key,
    }];
    owner.rekey(&new_entries, 2, 100).unwrap();
    assert_eq!(owner.waiting_replies(), 0, "the re-key discards the reply");
    owner.poll(200);
    assert_eq!(owner.waiting_replies(), 0);
}

#[test]
fn service_disk_reaches_the_attached_driver() {
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let (_client_end, owner_end, _net) = network(64, 8384, 13, [Faults::default(); 2]);
    let (mut owner, control) = start(&storage, &buffers, &receive, &[], vec![owner_end]);
    owner.poll(0);
    let calls = control.driver_calls();
    owner.service_disk();
    assert_eq!(control.driver_calls(), calls + 1);
}

/// The shutdown hands back the driver the volume attached: under `AllReturned` with nothing outstanding the driver still runs and answers its caller's own quiesce, and under a device stop it reports the stop again.
#[test]
fn the_shutdown_hands_back_the_attached_driver() {
    use crate::storage::{Disk, QuiesceStatus, Quiesced};
    for (mode, proof) in [
        (QuiesceMode::AllReturned, Quiesced::AllReturned),
        (QuiesceMode::Reset, Quiesced::DeviceStopped),
    ] {
        let object = payload(30_000, 28);
        let storage = storage(8);
        let buffers = arena(8);
        let receive = pool();
        let client_pool = pool();
        let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
        let (client_end, owner_end, net) = network(64, 8384, 28, [Faults::default(); 2]);
        let (mut owner, control) = start(
            &storage,
            &buffers,
            &receive,
            &[(key(1), 0, &object)],
            vec![owner_end],
        );
        let mut client = client(0, &client_pool, &releases, client_end);
        let nets = [net];
        let mut turn = open(&mut client, &mut owner, &control, &nets, 0);
        if proof == Quiesced::DeviceStopped {
            client
                .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
                .unwrap();
            turn = hold_next_read(&mut client, &mut owner, &control, &nets[0], turn).1;
        }
        control.set_quiesce(mode);
        let _ = owner.close(turn * 100);
        let end = turn + 1_000;
        while owner.blockers().is_some() && turn < end {
            round(&mut [
                Act::new(Actor::Link(0), &mut || nets[0].borrow_mut().advance(turn)),
                Act::new(Actor::Disk(0), &mut || control.tick(64)),
                Act::new(Actor::Owner(0), &mut || owner.poll(turn * 100)),
            ]);
            turn += 1;
        }
        let shutdown = owner.shutdown().ok().expect("a clean shutdown");
        assert_eq!(shutdown.proof, proof, "{mode:?}");
        let mut disk = shutdown.disk;
        let calls = control.driver_calls();
        let status = disk.quiesce();
        assert_eq!(
            control.driver_calls(),
            calls + 1,
            "{mode:?}: the attached driver answered"
        );
        let expected = if proof == Quiesced::DeviceStopped {
            QuiesceStatus::Stopped
        } else {
            QuiesceStatus::Pending
        };
        assert_eq!(status, expected, "{mode:?}");
    }
}

#[test]
fn a_local_fill_submits_only_what_the_callers_budget_funds() {
    let filled = payload(1_000, 33);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let (_client_end, owner_end, _net) = network(64, 8384, 33, [Faults::default(); 2]);
    let (mut owner, _control) = start(&storage, &buffers, &receive, &[], vec![owner_end]);
    let mut fill = reserve(&storage, &key(5), 0, filled.len()).expect("a fill");
    let mut none = crate::storage::WorkBudget::new(0);
    assert_eq!(
        owner.receive_fill(&mut fill, &filled, &mut none),
        Ok(filled.len())
    );
    assert_eq!(owner.fill_progress(&fill).submitted_units, 0);
    assert_eq!(
        owner.receive_fill(&mut fill, &[], &mut none),
        Err(crate::storage::ReceiveError::Budget(
            crate::storage::BudgetShort {
                dimension: crate::storage::BudgetDimension::Operations
            }
        ))
    );
    let mut one = crate::storage::WorkBudget::with_io(0, 1, usize::MAX);
    assert_eq!(owner.receive_fill(&mut fill, &[], &mut one), Ok(0));
    let progress = owner.fill_progress(&fill);
    assert_eq!(progress.submitted_units, progress.len_units);
    assert_eq!(one.operations_used(), 1);
    fill.abort();
}

const EDGE_METADATA_CAP: usize = 64;
const EDGE_BODY_CAP: usize = 3 * 16384;
const EDGE_CHUNK: usize = crate::storage::owner_fixture::CHUNK_LEN as usize;
const EDGE_FRAGMENT: usize = super::geometry::FRAGMENT_LEN as usize;
const WINDOW_FILLING: usize = EDGE_CHUNK - (108 + 4 * 2);

const EDGE_OBJECTS: [(usize, usize); 8] = [
    (0, 0),
    (EDGE_METADATA_CAP, 0),
    (0, EDGE_FRAGMENT - 1),
    (0, EDGE_FRAGMENT),
    (0, EDGE_FRAGMENT + 1),
    (0, WINDOW_FILLING),
    (10, 3 * EDGE_FRAGMENT + 5),
    (EDGE_METADATA_CAP, EDGE_BODY_CAP),
];

/// Publishes `object` under `key(1)` with its first `metadata` bytes as metadata in a world of its own, on a link
/// seeded `seed`, and runs `gets` in one client session, in order. Each entry is a GET's caps and whether it
/// completes. A GET that completes delivers the object's exact bytes, and every fragment it takes names the
/// lengths the object was published with, whatever its caps. A GET that does not ends `Failed(TooLarge)` at
/// the client with no byte taken and the client's pool as it was.
fn edge_gets(seed: u64, metadata: usize, object: &[u8], gets: &[((usize, usize), bool)]) {
    let body = object.len() - metadata;
    let storage = storage(8);
    assert_eq!(storage.payload_cap(), EDGE_METADATA_CAP + EDGE_BODY_CAP);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, seed, [Faults::default(); 2]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), metadata, object)],
        vec![owner_end],
    );
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let mut turn = open(&mut client, &mut owner, &control, &nets, 0);
    let published = vec![(metadata as u32, body as u32); object.len().div_ceil(EDGE_FRAGMENT)];
    for &(caps, completes) in gets {
        let at = format!("object ({metadata}, {body}) under caps {caps:?}");
        let free = client_pool.report().free;
        let (outcome, bytes, named, reached) =
            edge_get(&mut client, &mut owner, &control, &nets, turn, key(1), caps);
        turn = reached;
        if completes {
            assert_eq!(outcome, Some(Outcome::Complete), "{at}");
            assert_eq!(bytes, object, "{at}");
            assert_eq!(named, published, "{at}");
        } else {
            assert_eq!(outcome, Some(Outcome::Failed(Status::TooLarge)), "{at}");
            assert!(bytes.is_empty(), "{at}");
            assert_eq!(client_pool.report().free, free, "{at}");
        }
    }
}

/// Each object of [`EDGE_OBJECTS`], in one session of a world of its own, reads back exact under caps of
/// exactly its lengths and under the widest caps, and is refused under a cap one byte below each of its
/// lengths that is not zero.
/// A 40,000-byte object with 24 bytes of metadata gives the same answers when each GET is the first of a session
/// of its own: exact caps, caps one byte above each length, where a manifest that echoed the caps would
/// differ, and a cap one byte below either length; and so does a 40,000-byte object without metadata under
/// exact caps.
#[test]
fn objects_at_every_named_size_read_back_exact_and_one_byte_over_a_cap_is_refused() {
    let header = 108 + 4 * (WINDOW_FILLING.div_ceil(EDGE_CHUNK) + 1);
    assert_eq!(header + WINDOW_FILLING, EDGE_CHUNK);
    let filling = crate::storage::RecordConfig {
        chunk_len: EDGE_CHUNK as u32,
    }
    .validate()
    .unwrap()
    .layout(0, WINDOW_FILLING as u32);
    assert_eq!(filling.record_len(), EDGE_CHUNK as u64);
    for (n, &(metadata, body)) in EDGE_OBJECTS.iter().enumerate() {
        let object = payload(metadata + body, 100 + n as u64);
        let widest = (u32::MAX as usize, u32::MAX as usize);
        let mut gets = vec![((metadata, body), true), (widest, true)];
        if body > 0 {
            gets.push(((metadata, body - 1), false));
        }
        if metadata > 0 {
            gets.push(((metadata - 1, body), false));
        }
        edge_gets(31, metadata, &object, &gets);
    }
    const TOTAL: usize = 40_000;
    const METADATA: usize = 24;
    const BODY: usize = TOTAL - METADATA;
    const { assert!(TOTAL > EDGE_FRAGMENT, "the object spans several fragments") };
    let object = payload(TOTAL, 41);
    for get in [
        ((METADATA, BODY), true),
        ((METADATA + 1, BODY + 1), true),
        ((METADATA - 1, BODY), false),
        ((METADATA, BODY - 1), false),
    ] {
        edge_gets(7, METADATA, &object, &[get]);
    }
    edge_gets(7, 0, &payload(TOTAL, 42), &[((0, TOTAL), true)]);
}

/// A served object's DATA frames carry payload-only body crcs: each frame's
/// crc, derived from the record's window crcs, equals the crc32c of the
/// object bytes at its fragment's offset, so the header context the record
/// binds stays off the wire.
#[test]
fn served_data_body_crcs_are_payload_only() {
    use super::frame::{Kind, parse};
    let (metadata, body) = (10, 3 * EDGE_FRAGMENT + 5);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 37, [Faults::default(); 2]);
    let object = payload(metadata + body, 41);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), metadata, &object)],
        vec![owner_end],
    );
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let start_turn = open(&mut client, &mut owner, &control, &nets, 0);
    let id = client
        .get(
            key(1),
            metadata as u32,
            body as u32,
            start_turn * 100,
            30_000_000,
        )
        .unwrap();
    let crc = crate::storage::Crc32c::detect();
    let (mut checked, mut bytes) = (std::collections::BTreeSet::new(), Vec::new());
    for turn in start_turn..start_turn + 20_000 {
        for side in 0..2 {
            nets[0].borrow_mut().retain(side, |datagram| {
                if let Ok(frame) = parse(crc, datagram, false)
                    && frame.header().kind == Kind::Data
                {
                    let start = frame.header().offset as usize;
                    let fragment = &object[start..start + frame.raw_body().len()];
                    assert_eq!(frame.body_crc(), crc.checksum(fragment), "at {start}");
                    checked.insert(start);
                }
                true
            });
        }
        super::oracle_endpoint_tests::turn_both(
            &mut [&mut client],
            &mut [(&mut owner, &control)],
            &[&nets[0]],
            turn,
        );
        collect(&mut client, id, &mut bytes);
        if client.outcome(id).is_some() {
            break;
        }
    }
    assert_eq!(client.outcome(id), Some(Outcome::Complete));
    assert_eq!(bytes, object);
    // Every fragment's offset was seen on the wire, a resend's included once.
    assert_eq!(checked.len(), (metadata + body).div_ceil(EDGE_FRAGMENT));
}

/// What [`edge_get`] returns: the GET's outcome, the bytes of the fragments the client took in offset order, the `(metadata_len, body_len)` each fragment's manifest names, and the turn reached.
type EdgeGet = (Option<Outcome>, Vec<u8>, Vec<(u32, u32)>, u64);

/// Runs one GET of `key` under the caps `(metadata, body)` to its end.
fn edge_get<'m>(
    client: &mut Client<'m, LinkEnd<'m>>,
    owner: &mut TestOwner<'_, '_, '_>,
    control: &SimControl,
    nets: &[Rc<RefCell<Net<'_>>>],
    turn: u64,
    key: [u8; 32],
    (metadata, body): (usize, usize),
) -> EdgeGet {
    let id = client
        .get(key, metadata as u32, body as u32, turn * 100, 30_000_000)
        .unwrap();
    let (mut bytes, mut named) = (Vec::new(), Vec::new());
    let mut take = |client: &mut Client<'m, LinkEnd<'m>>| {
        while let Some(fragment) = client.take(id) {
            assert_eq!(fragment.offset(), bytes.len() as u64, "in order");
            let manifest = fragment.manifest();
            named.push((manifest.metadata_len, manifest.body_len));
            bytes.extend_from_slice(fragment.bytes());
        }
    };
    let turn = drive(
        &mut [client],
        owner,
        control,
        nets,
        turn,
        20_000,
        |clients| {
            take(clients[0]);
            clients[0].outcome(id).is_some()
        },
    );
    take(client);
    (client.outcome(id), bytes, named, turn)
}

#[test]
fn window_caps_start_at_n_minus_one_and_n_and_refuse_n_plus_one() {
    for (window, refused) in [
        (MAX_WINDOW - 1, None),
        (MAX_WINDOW, None),
        (MAX_WINDOW + 1, Some(OwnerError::Caps)),
    ] {
        let storage = storage(8);
        let buffers = arena(8);
        let receive = pool();
        let Device { volume, .. } = Device::new(&storage, &buffers);
        let cache = storage.issue_cache().unwrap();
        let registration = cache.register().unwrap();
        let bundle = Bundle {
            cache,
            registration,
            volume,
        };
        let entries = entries();
        let keys = Keys {
            principals: &PRINCIPALS[..1],
            entries: &entries[..1],
            epoch: 1,
            put: &PRINCIPALS[..1],
        };
        let config = OwnerConfig {
            caps: Caps { window, ..CAPS },
            ..OWNER
        };
        let ends = Mux::new(vec![network(4, 8384, 33, [Faults::default(); 2]).1]);
        let started = Owner::start(
            config,
            bundle,
            keys,
            ends,
            &receive,
            &mut EngineBudget::new(1 << 26),
        );
        assert_eq!(
            started.err().map(|refused| refused.error),
            refused,
            "window {window}"
        );
    }
}

/// Starts an owner under `config` over a fresh windowed storage whose index
/// admits batches of `batch_max` keys, with exactly `budget` bytes, and
/// returns the bytes it charged, or its refusal with the budget checked
/// unchanged. A refusal comes with the bytes a second start charged an ample
/// budget over the bundle and the transport the refusal returned, or `None`
/// when that start was refused too.
fn charged(
    config: OwnerConfig,
    batch_max: usize,
    budget: usize,
) -> Result<(usize, usize), (OwnerError, Option<usize>)> {
    let receive = pool();
    let keys = Keys {
        principals: &PRINCIPALS,
        entries: &entries(),
        epoch: 1,
        put: &[],
    };
    let storage = crate::storage::owner_fixture::storage_windowed(batch_max, 4);
    let buffers = arena(8);
    let Device { volume, .. } = Device::new(&storage, &buffers);
    let cache = storage.issue_cache().unwrap();
    let registration = cache.register().unwrap();
    let (_, a, _) = network(4, 8384, 1, [Faults::default(); 2]);
    let (_, b, _) = network(4, 8384, 2, [Faults::default(); 2]);
    let mut engine = EngineBudget::new(budget);
    let bundle = Bundle {
        cache,
        registration,
        volume,
    };
    match Owner::start(
        config,
        bundle,
        keys,
        Mux::new(vec![a, b]),
        &receive,
        &mut engine,
    ) {
        Ok(owner) => Ok((engine.used(), owner.window_charge())),
        Err(refused) => {
            assert_eq!(engine.used(), 0, "a refused start charges nothing");
            let refused = *refused;
            let mut ample = EngineBudget::new(1 << 26);
            let again = Owner::start(
                config,
                refused.bundle,
                keys,
                refused.transport,
                &receive,
                &mut ample,
            )
            .is_ok()
            .then(|| ample.used());
            Err((refused.error, again))
        }
    }
}

/// Start charges the receive window once, before anything is built: 32
/// bytes per key and 16 per tag of its capacity `C = min(batch, BatchMax)`
/// when `C` is at least two and one GET's allowance reaches `AHEAD`, its
/// guard bundle and hash charge, and nothing for keys or tags otherwise,
/// beside the lookahead every owner carries. The exact charge starts the
/// owner; one byte short refuses it with the budget unchanged and returns
/// the bundle and the transport, over which a second start charges the same
/// bytes, for each capacity. An allowance of exactly `AHEAD` charges what
/// the fixture's larger one does.
#[test]
fn start_charges_the_receive_window_from_its_capacity() {
    use crate::storage::AHEAD;
    const { assert!(OWNER.lookup_work > AHEAD) };
    let scalar = |config: OwnerConfig| OwnerConfig {
        lookup_work: AHEAD - 1,
        ..config
    };
    // The exact charge starts the owner, and one byte less is refused whole and restarts.
    let exact = |config: OwnerConfig, batch_max: usize, charge: usize, window: usize| {
        assert_eq!(charged(config, batch_max, charge), Ok((charge, window)));
        assert_eq!(
            charged(config, batch_max, charge - 1)
                .map_err(|(error, again)| (matches!(error, OwnerError::Budget(_)), again)),
            Err((true, Some(charge))),
            "batch {}, limit {batch_max}, lookup_work {}",
            config.batch,
            config.lookup_work
        );
    };
    let cases = [
        (OWNER, 8, 8),
        (OWNER, 4, 4),
        (OWNER, 2, 2),
        (OWNER, 1, 0),
        (OWNER, 0, 0),
        (OwnerConfig { batch: 4, ..OWNER }, 8, 4),
        (OwnerConfig { batch: 2, ..OWNER }, 8, 2),
        (OwnerConfig { batch: 2, ..OWNER }, 2, 2),
        (OwnerConfig { batch: 2, ..OWNER }, 1, 0),
        (OwnerConfig { batch: 2, ..OWNER }, 0, 0),
        (scalar(OWNER), 8, 0),
        (
            OwnerConfig {
                lookup_work: AHEAD,
                ..OWNER
            },
            8,
            8,
        ),
    ];
    for (config, batch_max, capacity) in cases {
        // The same owner with no window charges every other structure alike.
        let (base, _) = charged(scalar(config), batch_max, 1 << 26).unwrap();
        let (charge, window) = charged(config, batch_max, 1 << 26).unwrap();
        // The window's share: its keys' and tags' arrays and the lookahead's own bytes.
        let keys = std::alloc::Layout::array::<[u8; 32]>(capacity)
            .unwrap()
            .size();
        let tags = std::alloc::Layout::array::<[u8; super::auth::TAG_LEN]>(capacity)
            .unwrap()
            .size();
        let lookahead = size_of::<crate::storage::Preparation<'static, TestPlatform>>();
        assert_eq!(
            window,
            keys + tags + lookahead,
            "batch {}, limit {batch_max}",
            config.batch
        );
        assert_eq!(
            charge,
            base + 48 * capacity,
            "batch {}, limit {batch_max}",
            config.batch
        );
        exact(config, batch_max, charge, window);
        if config.lookup_work > AHEAD {
            let least = OwnerConfig {
                lookup_work: AHEAD,
                ..config
            };
            assert_eq!(
                charged(least, batch_max, 1 << 26),
                Ok((charge, window)),
                "batch {}, limit {batch_max}: the least allowance that carries a window",
                config.batch
            );
            exact(least, batch_max, charge, window);
        }
    }
}

#[test]
fn start_charges_the_parked_table_only_with_joins_on() {
    let off = OwnerConfig {
        follow: FollowConfig::OFF,
        ..OWNER
    };
    let (on, _) = charged(OWNER, 8, 1 << 26).unwrap();
    let (off_charge, _) = charged(off, 8, 1 << 26).unwrap();
    let peers = u16::try_from(PRINCIPALS.len()).unwrap();
    let table =
        super::parked::Parked::<TestPlatform>::bytes(OWNER.follow, OWNER.request_slots, peers);
    assert!(table > 0);
    assert_eq!(on - off_charge, table, "joins off charge no parked table");
    assert_eq!(
        super::parked::Parked::<TestPlatform>::bytes(FollowConfig::OFF, OWNER.request_slots, peers),
        0
    );
}

crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
    a_burst_of_unparseable_gets_prepares_no_lookup,
    a_sent_timeout_keeps_custody_until_the_late_terminal,
    a_chunk_mismatch_after_exposure_ends_incomplete,
    a_closed_owner_drains_once_the_device_returns_its_references,
    a_cold_restart_changes_the_session_and_starts_cold,
    a_draining_request_waits_for_its_error_its_read_and_its_device_returns,
    a_failed_transport_call_counts_its_frames_failed_and_retries_recover,
    a_fingerprint_false_positive_answers_missing,
    a_get_whose_first_command_waits_still_reads_ahead_and_completes,
    a_hello_flood_delays_no_other_peer,
    a_local_fill_publishes_during_another_transfer,
    a_read_before_invalidation_finishes_and_the_next_get_looks_up_afresh,
    a_read_error_with_device_references_out_keeps_the_request_draining,
    a_read_past_a_released_request_slot_keeps_its_grants,
    a_read_reusing_a_freed_operation_slot_keeps_its_binding,
    a_read_whose_last_command_is_outstanding_leaves_no_grant_pass_pending,
    a_same_boot_session_replacement_ends_the_replaced_requests,
    a_send_error_toward_one_peer_loses_only_that_peers_frame,
    a_slow_peer_holding_its_window_delays_no_other_peer,
    a_spent_send_sequence_retires_the_peers_requests_with_its_session,
    a_transport_that_takes_part_of_a_turn_loses_no_frame,
    a_turns_frames_reach_the_transport_as_one_batch,
    a_warm_rekey_serves_resident_hits_afterwards,
    a_window_of_one_command_still_reads_ahead_and_delivers_every_byte,
    a_withheld_return_stops_the_read_at_two_buffers_until_the_device_returns,
    an_empty_object_completes_and_a_corrupt_header_succeeds_never,
    an_invalidated_and_republished_key_serves_each_version_whole,
    an_unreported_allowance_count_is_read_once_per_control_interval,
    an_unwound_turn_poisons_admission_and_keeps_custody,
    close_stops_sends_and_cancels_running_reads,
    delayed_and_reordered_returns_keep_every_byte,
    objects_at_every_named_size_read_back_exact_and_one_byte_over_a_cap_is_refused,
    premature_returns_fail_the_byte_oracle,
    same_key_rights_bound_concurrent_reads,
    shutdown_from_every_state_releases_only_after_the_drain,
    the_hit_path_allocates_nothing,
    the_shutdown_hands_back_the_attached_driver,
    the_turn_runs_funded_maintenance_and_rests_when_the_storage_is_done,
);

/// The owner's report observes its turns and its holdings: the gap between turns' starts lands in its
/// power-of-two bucket and the longest gap keeps what the turn before it did, and the retained census counts
/// the read buffers and device commands a GET holds while it runs and returns to the idle census once the GET ends.
#[test]
fn the_report_keeps_poll_gaps_and_the_retained_census() {
    let object = payload(40_000, 7);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 7, [Faults::default(); 2]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 10, &object)],
        vec![owner_end],
    );
    let idle = owner.report().retained;
    owner.poll(1_000);
    owner.poll(1_005);
    owner.poll(1_005 + 300);
    let report = owner.report();
    assert_eq!(
        report.poll_gaps[2], 1,
        "a 5 µs gap lands in the 4 to 8 µs bucket"
    );
    assert_eq!(
        report.poll_gaps[8], 1,
        "a 300 µs gap lands in the 256 to 512 µs bucket"
    );
    assert_eq!(
        report.poll_gaps.iter().sum::<u64>(),
        2,
        "two gaps between three turns"
    );
    assert_eq!(
        (report.poll_gap_max_us, report.poll_gap_max_after),
        (300, TurnSources::default())
    );
    let mut client = client(0, &client_pool, &releases, client_end);
    client.session(0);
    let nets = [net];
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        14,
        5_000,
        |clients| clients[0].state() == SessionState::Active,
    );
    let id = client
        .get(key(1), 64, 1 << 20, turn * 100, 5_000_000)
        .unwrap();
    let net_refs: Vec<_> = nets.iter().collect();
    let (mut bytes, mut busiest, mut held) = (Vec::new(), idle, idle);
    for turn in turn..turn + 50_000 {
        super::oracle_endpoint_tests::turn_both(
            &mut [&mut client],
            &mut [(&mut owner, &control)],
            &net_refs,
            turn,
        );
        collect(&mut client, id, &mut bytes);
        held = owner.report().retained;
        busiest.buffers = busiest.buffers.max(held.buffers);
        busiest.commands = busiest.commands.max(held.commands);
        if client.outcome(id).is_some() && held == idle {
            break;
        }
    }
    let report = owner.report();
    assert_eq!(client.outcome(id), Some(Outcome::Complete));
    assert_eq!(bytes, object);
    assert!(
        busiest.buffers > idle.buffers && busiest.commands > idle.commands,
        "the GET held read buffers and device commands: {busiest:?} over {idle:?}"
    );
    assert_eq!(
        held, idle,
        "the ended GET's buffers, commands and packets returned"
    );
    let mut turn = turn + 50_000;
    let sources = loop {
        let before = owner.report();
        let _ = client.get(key(1), 64, 1 << 20, turn * 100, 5_000_000);
        super::oracle_endpoint_tests::turn_both(
            &mut [&mut client],
            &mut [(&mut owner, &control)],
            &net_refs,
            turn,
        );
        let after = owner.report();
        turn += 1;
        if after.received > before.received {
            break (after.received - before.received, after.sent - before.sent);
        }
    };
    let last_us = (turn - 1) * 100;
    owner.poll(last_us + (1 << 30));
    let gaps = owner.report();
    assert_eq!(gaps.poll_gap_max_us, 1 << 30);
    assert_eq!(
        (
            gaps.poll_gap_max_after.received,
            gaps.poll_gap_max_after.sent
        ),
        sources,
        "the longest gap keeps what the turn before it received and sent"
    );
    assert_eq!(
        gaps.poll_gaps[23], 1,
        "a gap past 2^23 µs lands in the last bucket"
    );
    let zero = gaps.poll_gaps[0];
    owner.poll(last_us + (1 << 30));
    owner.poll(last_us);
    assert_eq!(
        owner.report().poll_gaps[0],
        zero + 2,
        "a zero gap and a clock that steps back land in the first bucket"
    );
    assert_eq!(
        report.poll_gap_max_us, 300,
        "the driven turns are 100 µs apart"
    );
    assert!(
        report.poll_gaps[6] > 0,
        "100 µs gaps land in the 64 to 128 µs bucket"
    );
}

/// The first gap sets the maximum even at 0 µs, and a later tie keeps the first turn's sources.
#[test]
fn the_first_gap_keeps_its_turn_sources_at_zero_length() {
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 7, [Faults::default(); 2]);
    let (mut owner, _control) = start(&storage, &buffers, &receive, &[], vec![owner_end]);
    let mut client = client(0, &client_pool, &releases, client_end);
    client.session(0);
    for turn in 0..8 {
        net.borrow_mut().advance(turn);
        let _ = client.poll(turn * 100);
    }
    net.borrow_mut().advance(16);
    owner.poll(1_600);
    let first = owner.report();
    assert!(first.received > 0, "the first turn received the HELLO");
    owner.poll(1_600);
    owner.poll(1_600);
    let report = owner.report();
    assert_eq!(report.poll_gaps[0], 2, "two zero-length gaps");
    assert_eq!(
        (report.poll_gap_max_us, report.poll_gap_max_after),
        (
            0,
            TurnSources {
                received: first.received,
                sent: first.sent,
                published: 0,
            }
        ),
        "the first gap keeps the first turn's sources and the tie keeps them"
    );
}

#[test]
fn a_gap_after_an_unwound_turn_keeps_what_that_turn_received() {
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 29, [Faults::default(); 2]);
    let Device { volume, control } = Device::new(&storage, &buffers);
    let cache = storage.issue_cache().unwrap();
    let registration = cache.register().unwrap();
    let keys = Keys {
        principals: &PRINCIPALS[..1],
        entries: &entries()[..1],
        epoch: 1,
        put: &[],
    };
    let armed = Rc::new(std::cell::Cell::new(false));
    let transport = Panicking(Mux::new(vec![owner_end]), Rc::clone(&armed));
    let mut owner = Owner::start(
        OWNER,
        Bundle {
            cache,
            registration,
            volume,
        },
        keys,
        transport,
        &receive,
        &mut EngineBudget::new(1 << 26),
    )
    .map_err(|refused| refused.error)
    .unwrap();
    let mut client = client(0, &client_pool, &releases, client_end);
    client.session(0);
    let mut turn = 0;
    while client.state() != SessionState::Active && turn < 5_000 {
        turn_once(&mut client, &mut owner, &net, &control, turn);
        turn += 1;
    }
    for _ in 0..10 {
        turn_once(&mut client, &mut owner, &net, &control, turn);
        turn += 1;
    }
    let idle = owner.report().received;
    turn_once(&mut client, &mut owner, &net, &control, turn);
    turn += 1;
    assert_eq!(
        owner.report().received,
        idle,
        "the last whole turn received nothing"
    );
    armed.set(true);
    // A missing key's ERROR is the next frame the owner sends, so the turn that receives the GET unwinds.
    client
        .get(key(9), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let (mut started, mut last_us) = (owner.report().received, 0);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        for at in turn..turn + 100 {
            net.borrow_mut().advance(at);
            let _ = client.poll(at * 100);
            control.tick(64);
            (started, last_us) = (owner.report().received, at * 100);
            owner.poll(at * 100);
        }
    }));
    assert!(unwound.is_err(), "a send unwound the turn");
    let received = owner.report().received - started;
    assert!(received > 0, "the unwound turn received the GET");
    armed.set(false);
    owner.poll(last_us + (1 << 30));
    let report = owner.report();
    assert_eq!(report.poll_gap_max_us, 1 << 30);
    assert_eq!(
        report.poll_gap_max_after.received, received,
        "the longest gap keeps what the unwound turn before it received"
    );
}

#[test]
fn the_owner_opens_fills_only_at_its_caller_s_begin_replay() {
    use crate::storage::owner_fixture::{BUFFER, DEPTH, TICK, device_with};
    use crate::storage::{MetadataOutcome, Readiness, ReadinessError, Volume};
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let (disk, control) = device_with(7, BUFFER);
    let mut volume = Volume::attach(
        &storage,
        &buffers,
        disk,
        crate::storage::portable::scripted::ScriptedClock::trusted(),
        crate::storage::ServingAuthority::fixture(),
        DEPTH,
        TICK,
        &mut EngineBudget::new(1 << 25),
    )
    .map_err(|(error, _)| error)
    .unwrap();
    let mut out = Vec::with_capacity(16);
    for _ in 0..64 {
        if volume.metadata_outcome() == MetadataOutcome::Unformatted {
            volume.format().unwrap();
        }
        control.tick(64);
        let _ = volume.poll_storage(0, &mut out);
    }
    drop(out);
    assert_eq!(volume.readiness(), Readiness::Loaded);
    let (_client_end, owner_end, _net) = network(64, 8384, 22, [Faults::default(); 2]);
    let cache = storage.issue_cache().unwrap();
    let registration = cache.register().unwrap();
    let mut owner = Owner::start(
        OWNER,
        Bundle {
            cache,
            registration,
            volume,
        },
        Keys {
            principals: &PRINCIPALS[..1],
            entries: &entries()[..1],
            epoch: 1,
            put: &[],
        },
        Mux::new(vec![owner_end]),
        &receive,
        &mut EngineBudget::new(1 << 26),
    )
    .map_err(|refused| refused.error)
    .unwrap();
    for turn in 0..16 {
        control.tick(64);
        owner.poll(turn * 100);
    }
    assert_eq!(owner.readiness(), Readiness::Loaded);
    assert_eq!(owner.report().maintained, 3, "{:?}", owner.report());
    assert_eq!(owner.maintain_rest_until_us(), Some(2_100));
    assert_eq!(owner.complete_replay(), Err(ReadinessError::NotReady));
    assert_eq!(
        owner.begin_replay(storage.feed_contract(), 0),
        Ok(Readiness::Live)
    );
    assert_eq!(
        owner.maintain_rest_until_us(),
        None,
        "reaching Live ends the rest"
    );
    owner.poll(1_600);
    assert_eq!(owner.report().maintained, 4, "the next turn maintains");
}

/// The owner's coverage wrappers are the storage's: an invalidation through the owner returns `Ok`, an advance to zero refuses `Zero`, and an advance to 1 applies and repeats `Unchanged`.
#[test]
fn the_owner_s_coverage_wrappers_forward_to_the_storage() {
    use crate::storage::{Advance, CoverageError};
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let (_client_end, owner_end, _net) = network(64, 8384, 22, [Faults::default(); 2]);
    let body = payload(4096, 5);
    let (mut owner, _control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &body), (key(2), 0, &body)],
        vec![owner_end],
    );
    owner
        .invalidate(&key(1), 2, &mut crate::storage::WorkBudget::new(1024))
        .unwrap();
    assert_eq!(owner.advance_coverage(0), Err(CoverageError::Zero));
    assert_eq!(owner.advance_coverage(1), Ok(Advance::Advanced));
    assert_eq!(owner.advance_coverage(1), Ok(Advance::Unchanged));
}

/// Withdrawal retires client work, ends the sessions and closes fill admission in the owner step that applies it, while the device retains the read's buffers until their terminals return. The owner's sent count stays constant in Withdrawn, and shutdown succeeds after the owner drains.
#[test]
fn withdrawn_close_effects_keep_custody() {
    for disk_held in [false, true] {
        withdrawn_close_effects_keep_custody_with(disk_held);
    }
}

fn withdrawn_close_effects_keep_custody_with(disk_held: bool) {
    use super::link::TxRelease;
    use crate::failover::serving::{Cause, Effect, Event, State};
    let object = payload(45_000, 53);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 53, [Faults::default(); 2]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &object)],
        vec![owner_end],
    );
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let turn = open(&mut client, &mut owner, &control, &nets, 0);
    if !disk_held {
        nets[0].borrow_mut().set_tx_release(TxRelease::Delayed(300));
    }
    client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let (held, turn) = if disk_held {
        let (held, turn) = hold_next_read(&mut client, &mut owner, &control, &nets[0], turn);
        (Some(held), turn)
    } else {
        let turn = drive(
            &mut [&mut client],
            &mut owner,
            &control,
            &nets,
            turn,
            40,
            |_| false,
        );
        (None, turn)
    };
    assert!(owner.census().live() > 0, "the GET is in flight");
    assert!(owner.session_epoch(PeerId(0)).is_some());
    assert!(read_custody(&buffers) > 0, "the read holds buffers");
    let registrations = storage.outstanding().registrations;
    assert!(
        registrations > 0,
        "the owner holds its storage handle registrations"
    );
    let accepted = control.capture().accepted;
    let sent = owner.report().sent;
    let outcome = owner.authority_event(Event::Withdraw(Cause::Planned), turn * 100);
    assert!(matches!(
        outcome,
        crate::failover::serving::Outcome::Moved {
            to: State::Withdrawn,
            effect: Effect::None
        }
    ));
    assert_eq!(owner.census().active, 0, "GET and PUT work retired");
    assert_eq!(owner.waiting_replies(), 0, "waiting replies cleared");
    assert_eq!(owner.session_epoch(PeerId(0)), None, "the session ended");
    assert_eq!(
        reserve(&storage, &key(2), 0, 20).err(),
        Some(crate::storage::FillReserveError::Closed),
        "fill admission closed"
    );
    assert_eq!(
        owner
            .invalidate(&key(1), 2, &mut crate::storage::WorkBudget::new(1024))
            .err(),
        Some(crate::storage::InvalidateError::Withdrawn),
        "INVALIDATE acknowledgments stop"
    );
    assert!(
        read_custody(&buffers) > 0,
        "the device keeps the read's buffers until its terminals"
    );
    let mut at = turn;
    if let Some(held) = held {
        for _ in 0..32 {
            round(&mut [
                Act::new(Actor::Link(0), &mut || nets[0].borrow_mut().advance(at)),
                Act::new(Actor::Disk(0), &mut || control.tick(64)),
                Act::new(Actor::Owner(0), &mut || owner.poll(at * 100)),
            ]);
            at += 1;
        }
        assert!(
            read_custody(&buffers) > 0,
            "the held device read keeps its command and buffer across the withdrawal"
        );
        assert!(
            owner.census().live() > 0,
            "the retired GET awaits its terminal"
        );
        control.release(held);
    }
    while read_custody(&buffers) > 0 && at < turn + 1_000 {
        round(&mut [
            Act::new(Actor::Link(0), &mut || nets[0].borrow_mut().advance(at)),
            Act::new(Actor::Disk(0), &mut || control.tick(64)),
            Act::new(Actor::Owner(0), &mut || owner.poll(at * 100)),
        ]);
        at += 1;
    }
    assert_eq!(owner.report().sent, sent, "Withdrawn sends nothing");
    assert_eq!(
        control.capture().accepted,
        accepted,
        "no device command follows the withdrawal"
    );
    assert_eq!(
        storage.outstanding().registrations,
        registrations,
        "the storage handle registrations stay"
    );
    assert_eq!(
        read_custody(&buffers),
        0,
        "every buffer returned at its terminal"
    );
    assert_eq!(owner.census().live(), 0, "the retired GET drained");
    assert_eq!(owner.authority_report().state, State::Withdrawn);
    let _ = owner.close(at * 100);
    while owner.blockers().is_some() && at < turn + 2_000 {
        round(&mut [
            Act::new(Actor::Link(0), &mut || nets[0].borrow_mut().advance(at)),
            Act::new(Actor::Disk(0), &mut || control.tick(64)),
            Act::new(Actor::Owner(0), &mut || owner.poll(at * 100)),
        ]);
        at += 1;
    }
    assert!(owner.shutdown().is_ok());
}

/// The availability withhold returns `Missing` for new GETs while a previously admitted device read completes and the tenure stays `Serving`. Clearing the peer input restores hits for the same key.
#[test]
fn a_withheld_get_answers_missing_and_an_admitted_read_completes() {
    use crate::failover::serving::{Event, State};
    use crate::failover::withhold::{M_US, W_US};
    struct Clock(Rc<std::cell::Cell<u64>>);
    impl crate::storage::ServingClock for Clock {
        fn now_us(&self) -> Option<u64> {
            Some(self.0.get())
        }
    }
    let object = payload(40_000, 61);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 61, [Faults::default(); 2]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &object)],
        vec![owner_end],
    );
    let time = Rc::new(std::cell::Cell::new(0));
    owner.set_serving_clock(Box::new(Clock(Rc::clone(&time))));
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let turn = open(&mut client, &mut owner, &control, &nets, 0);
    owner.authority_event(Event::Refresh { at: 0 }, turn * 100);
    owner.authority_event(Event::ReadFailed { sent_at: 1 }, turn * 100);
    let admitted = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let (held, turn) = hold_next_read(&mut client, &mut owner, &control, &nets[0], turn);
    time.set(W_US + 1);
    owner.authority_event(
        Event::Peer {
            read_at: Some(M_US + 2),
        },
        turn * 100,
    );
    let withheld = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    control.release(held);
    let mut bytes = Vec::new();
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        50_000,
        |clients| {
            collect(clients[0], admitted, &mut bytes);
            clients[0].outcome(admitted).is_some() && clients[0].outcome(withheld).is_some()
        },
    );
    collect(&mut client, admitted, &mut bytes);
    assert_eq!(client.outcome(admitted), Some(Outcome::Complete));
    assert_eq!(bytes, object);
    assert_eq!(client.outcome(withheld), Some(Outcome::Missing));
    let report = owner.authority_report();
    assert_eq!(
        (report.state, report.withdrawal, report.withheld),
        (State::Serving, None, true)
    );
    owner.authority_event(Event::Peer { read_at: None }, turn * 100);
    assert!(!owner.authority_report().withheld);
    let served = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let mut bytes = Vec::new();
    drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        50_000,
        |clients| {
            collect(clients[0], served, &mut bytes);
            clients[0].outcome(served).is_some()
        },
    );
    collect(&mut client, served, &mut bytes);
    assert_eq!(client.outcome(served), Some(Outcome::Complete));
    assert_eq!(bytes, object);
}

#[test]
fn timed_out_reads_fill_the_peer_share_after_their_wire_bindings_free() {
    let object = payload(900, 27);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 27, [Faults::default(); 2]);
    let (mut owner, control) = start_over(
        OwnerConfig {
            serve: ServeConfig {
                max_wait_us: 5_000,
                ..OWNER.serve
            },
            ..OWNER
        },
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &object)],
        Mux::new(vec![owner_end]),
    );
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let mut turn = open(&mut client, &mut owner, &control, &nets, 0);
    let mut tokens = Vec::new();
    for count in 1..=OWNER.peer_requests {
        let id = client
            .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
            .unwrap();
        let wire = RequestId::from_wire(client.get_wire(id).unwrap());
        assert_eq!(wire.slot(), 0);
        let (token, held_turn) = hold_next_read(&mut client, &mut owner, &control, &nets[0], turn);
        tokens.push(token);
        turn = drive(
            &mut [&mut client],
            &mut owner,
            &control,
            &nets,
            held_turn,
            200,
            |clients| clients[0].outcome(id).is_some(),
        );
        assert_eq!(client.outcome(id), Some(Outcome::Failed(Status::TimedOut)));
        assert_eq!(
            owner.serve_report().errors_by_status[Status::TimedOut as usize - 1],
            u64::from(count)
        );
        assert!(client.retire(id));
        assert_eq!(owner.census().draining, count);
    }
    let replacing = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    assert_eq!(
        RequestId::from_wire(client.get_wire(replacing).unwrap()).slot(),
        0
    );
    turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        200,
        |clients| clients[0].outcome(replacing).is_some(),
    );
    assert_eq!(
        client.outcome(replacing),
        Some(Outcome::Pressure(Status::RequestPressure))
    );
    assert_eq!(owner.serve_report().refused_pressure.peer, 1);
    assert_eq!(owner.serve_report().refused_pressure.busy, 0);
    assert_eq!(owner.census().draining, OWNER.peer_requests);
    assert_eq!(
        owner.volume_report().quarantines,
        u64::from(OWNER.peer_requests)
    );
    for token in tokens {
        control.release(token);
    }
    drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        50,
        |_| false,
    );
    assert_eq!(owner.census().live(), 0);
}

#[test]
fn a_complete_frees_the_wire_binding_while_the_nic_keeps_custody() {
    let object = payload(900, 28);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 28, [Faults::default(); 2]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &object)],
        vec![owner_end],
    );
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let turn = open(&mut client, &mut owner, &control, &nets, 0);
    let first = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let wire = RequestId::from_wire(client.get_wire(first).unwrap());
    let (token, turn) = hold_next_read(&mut client, &mut owner, &control, &nets[0], turn);
    nets[0]
        .borrow_mut()
        .set_tx_release(super::link::TxRelease::Withheld);
    control.release(token);
    control.tick(64);
    nets[0].borrow_mut().advance(turn);
    owner.poll(turn * 100);
    nets[0].borrow_mut().advance(turn + 1);
    let received = client.poll((turn + 1) * 100);
    assert_eq!((received.received, received.sent), (2, 1));
    let mut bytes = Vec::new();
    collect(&mut client, first, &mut bytes);
    assert_eq!(bytes, object);
    nets[0].borrow_mut().advance(turn + 2);
    owner.poll((turn + 2) * 100);
    assert_eq!(owner.census().draining, 1);
    assert_eq!(nets[0].borrow().nic_held(), 1);
    nets[0].borrow_mut().advance(turn + 3);
    client.poll((turn + 3) * 100);
    assert_eq!(client.outcome(first), Some(Outcome::Complete));
    assert!(client.retire(first));
    let again = client
        .get(key(1), 0, 1 << 20, (turn + 3) * 100, 30_000_000)
        .unwrap();
    let next_wire = RequestId::from_wire(client.get_wire(again).unwrap());
    assert_eq!(next_wire.slot(), wire.slot());
    assert!(next_wire.generation() > wire.generation());
    nets[0]
        .borrow_mut()
        .set_tx_release(super::link::TxRelease::AtDelivery);
    let (next_token, turn) = hold_next_read(&mut client, &mut owner, &control, &nets[0], turn + 3);
    assert_eq!(owner.census().active, 1);
    assert_eq!(owner.census().draining, 1);
    assert_eq!(nets[0].borrow().nic_held(), 1);
    control.release(next_token);
    bytes.clear();
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        5_000,
        |clients| {
            collect(clients[0], again, &mut bytes);
            clients[0].outcome(again).is_some()
        },
    );
    assert_eq!(client.outcome(again), Some(Outcome::Complete));
    assert_eq!(bytes, object);
    assert_eq!(owner.census().draining, 1);
    assert_eq!(owner.serve_report().refused_pressure.busy, 0);
    assert_eq!(nets[0].borrow().nic_held(), 1);
    nets[0].borrow_mut().return_tx(0);
    drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        50,
        |_| false,
    );
    assert_eq!(nets[0].borrow().nic_held(), 0);
    assert_eq!(owner.census().live(), 0);
}

#[test]
fn a_silent_cancel_keeps_its_wire_binding_until_the_read_drains() {
    let object = payload(900, 29);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 29, [Faults::default(); 2]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &object)],
        vec![owner_end],
    );
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let turn = open(&mut client, &mut owner, &control, &nets, 0);
    let first = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let wire = RequestId::from_wire(client.get_wire(first).unwrap());
    let (token, turn) = hold_next_read(&mut client, &mut owner, &control, &nets[0], turn);
    client.cancel(first);
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        50,
        |_| false,
    );
    assert_eq!(
        client.outcome(first),
        Some(Outcome::Failed(Status::Cancelled))
    );
    assert_eq!(owner.serve_report().errors, 0);
    assert_eq!(owner.census().draining, 1);
    assert!(client.retire(first));
    let replacing = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    assert_eq!(
        RequestId::from_wire(client.get_wire(replacing).unwrap()).slot(),
        wire.slot()
    );
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        200,
        |clients| clients[0].outcome(replacing).is_some(),
    );
    assert_eq!(
        client.outcome(replacing),
        Some(Outcome::Pressure(Status::RequestPressure))
    );
    assert_eq!(owner.serve_report().refused_pressure.busy, 1);
    assert_eq!(owner.serve_report().refused_pressure.peer, 0);
    assert_eq!(owner.volume_report().quarantines, 1);
    control.release(token);
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        50,
        |_| false,
    );
    assert_eq!(owner.census().live(), 0);
    assert!(client.retire(replacing));
    let again = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let mut bytes = Vec::new();
    drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        5_000,
        |clients| {
            collect(clients[0], again, &mut bytes);
            clients[0].outcome(again).is_some()
        },
    );
    assert_eq!(client.outcome(again), Some(Outcome::Complete));
    assert_eq!(bytes, object);
}

/// Another client has committed a later version of the held entry's page, and the tenure's client has recorded it,
/// while the fencing still knows the earlier one. The page write fails its condition and the fencing reads the page
/// again. The store answers that read with the page's previous version, below the client's watermark. The call
/// returns that regression as the withdrawal, leaves the authority withdrawn for the regression with peer 0's
/// session ended, drops the one held entry before it returns, leaves `acknowledged` empty in that call and the
/// next, and keeps the owner's sent count where it was.
#[test]
fn a_store_regression_observed_while_covering_withdraws_the_authority_in_that_call() {
    use super::put_tests::{fenced_coverage, scene};
    use crate::failover::records::CoveragePage;
    use crate::failover::serving::{Cause, State};
    use crate::storage::page_coverage::{Interval, Withdraw, page_of};
    use crate::storage::store::sim::Arm;
    use crate::storage::store::{Key, Regression, StoreError};
    use crate::storage::store_tests::{client, record_under, seeded_under};
    use crate::storage::{CacheVersion, WorkBudget};
    scene(&PRINCIPALS, |mut scene| {
        let store = seeded_under(scene.owner.tenure());
        let (fencing, mut tenure) = fenced_coverage(&store, scene.owner.tenure());
        scene.owner.install_coverage(fencing).unwrap();
        let mut budget = WorkBudget::new(1 << 12);
        let versions = Interval::new(CacheVersion(1), CacheVersion(1)).unwrap();
        (scene.owner)
            .invalidate_interval(&key(1), versions, 4, &mut budget)
            .unwrap();
        assert_eq!(
            scene.owner.authority_report().state,
            State::Serving,
            "the owner serves while it holds the entry"
        );
        assert!(scene.owner.session_epoch(PeerId(0)).is_some());

        let record = record_under(scene.owner.tenure());
        let page = Key::Page(record.shard, page_of(&key(1), record.pages));
        let mut other = client(&store);
        let read = other.read::<CoveragePage>(page).unwrap();
        let rewritten = read.value().clone();
        other.replace(&read, rewritten).unwrap();
        tenure.read::<CoveragePage>(page).unwrap();

        store.schedule(Arm::Pass);
        store.schedule(Arm::StaleCurrentRead);
        let sent = scene.owner.report().sent;
        let mut acknowledged = Vec::new();
        let now = scene.turn * 100;
        assert_eq!(
            scene.owner.held_invalidations(),
            1,
            "the owner holds the entry when the call starts"
        );
        let withdrawn = (scene.owner).cover_pending(&mut tenure, &mut acknowledged, now);
        assert_eq!(
            withdrawn,
            Err(Withdraw::Store(StoreError::Regression(Regression::Value(
                page
            )))),
            "the call returns the fencing's withdrawal"
        );
        let report = scene.owner.authority_report();
        assert_eq!(
            (report.state, report.withdrawal),
            (State::Withdrawn, Some(Cause::Regression)),
            "the regression withdraws the serving authority before the call returns"
        );
        assert_eq!(
            scene.owner.session_epoch(PeerId(0)),
            None,
            "the withdrawal ends the sessions"
        );
        assert!(acknowledged.is_empty(), "no held entry is acknowledged");
        assert_eq!(
            scene.owner.held_invalidations(),
            0,
            "the withdrawal drops the held entry before the call returns"
        );
        let later = (scene.owner).cover_pending(&mut tenure, &mut acknowledged, now);
        assert_eq!(later, Ok(()));
        assert!(
            acknowledged.is_empty(),
            "no later call acknowledges the dropped entry"
        );
        scene.polls(4);
        assert_eq!(
            scene.owner.report().sent,
            sent,
            "nothing is sent after the withdrawal"
        );
    });
}

/// A receive over two links whose second link fails its call after the
/// first delivered: the receive contract counts every lease it hands back
/// in its count, so the first link's datagram must reach the owner's
/// `received`.
#[test]
fn a_later_links_call_error_keeps_the_earlier_links_datagrams() {
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let failing = Faults {
        error: 100,
        ..Faults::default()
    };
    let (_, first_owner, first) = network(64, 8384, 71, [Faults::default(); 2]);
    let (_, second_owner, second) = network(64, 8384, 72, [Faults::default(), failing]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[],
        vec![first_owner, second_owner],
    );
    first.borrow_mut().inject(1, &[0x5a; 200]);
    let before = owner.report();
    owner.poll(100);
    let delivered = first.borrow().report(1).delivered;
    assert_eq!(delivered, 1, "premise: the first link delivered");
    assert!(
        second.borrow().report(1).errors > 0,
        "premise: the second link failed its call"
    );
    assert_eq!(control.outstanding(), 0);
    let after = owner.report();
    assert_eq!(after.received - before.received, delivered);
    let moved = |reason: crate::net::DropReason| {
        after.dropped_by[reason as usize] - before.dropped_by[reason as usize]
    };
    assert_eq!(
        (
            moved(crate::net::DropReason::Malformed),
            moved(crate::net::DropReason::Vacant)
        ),
        (1, 0),
        "the first link's lease reached the parser"
    );
}

/// An empty receive leaves an armed swallow pending on its multiplexer,
/// the unarmed multiplexer keeps its lease, and the armed multiplexer's
/// next receive that fills a slot drops that lease, so its owner's
/// `received` falls one short of what its link delivered.
#[test]
fn an_armed_swallow_stays_with_its_multiplexer() {
    let (storage, other_storage) = (storage(8), storage(8));
    let (buffers, other_buffers) = (arena(8), arena(8));
    let (receive, other_receive) = (pool(), pool());
    let (_, end, net) = network(64, 8384, 71, [Faults::default(); 2]);
    let (_, other_end, other_net) = network(64, 8384, 72, [Faults::default(); 2]);
    let (mut owner, _control) = start(&storage, &buffers, &receive, &[], vec![end]);
    let (mut other, _other_control) = start(
        &other_storage,
        &other_buffers,
        &other_receive,
        &[],
        vec![other_end],
    );
    owner.transport_mut().swallow_next();
    owner.poll(100);
    assert!(
        !owner.transport().swallowed(),
        "a receive that fills no slot leaves the swallow pending"
    );
    other_net.borrow_mut().inject(1, &[0x5a; 200]);
    other.poll(100);
    assert_eq!(other_net.borrow().report(1).delivered, 1);
    assert_eq!(
        other.report().received,
        1,
        "the other multiplexer kept its lease"
    );
    assert!(!other.transport().swallowed());
    let before = owner.report().received;
    net.borrow_mut().inject(1, &[0x5a; 200]);
    owner.poll(200);
    assert_eq!(net.borrow().report(1).delivered, 1);
    assert!(owner.transport().swallowed());
    assert_eq!(
        owner.report().received,
        before,
        "the armed multiplexer dropped the lease"
    );
}
