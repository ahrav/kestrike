use std::cell::RefCell;
use std::rc::Rc;

use crate::sim::round::{Act, Actor, afresh, push_each, round};
use crate::storage::device::sim::{Event, Fault, Unwind};
use crate::storage::owner_fixture::write_tokens;
use crate::storage::owner_fixture::{
    BODY_CAP, Device, FIXTURE, INTERPOSE_BEFORE_REVALIDATION, PUTS, SimControl, SimDisk,
    TestPlatform, arena, cut_next_publication, device_with, publish,
    sequence_storage_with_metadata, set_clock, storage, storage_leasing, storage_marked,
    storage_watched,
};
use crate::storage::{
    BufferArena, CommandToken, Crc32c, DeviceStatus, EngineBudget, RawPartition, RefusalReason,
    Storage, SubmitRefusal, VolumeWatermarks, WorkBudget,
};

use super::auth::{KeyEntry, KeyRing};
use super::client::{Client, ClientConfig, SessionState};
use super::datagram::{HEADER_LEN, MAX_DATAGRAM, PeerId};
use super::fetch::Releases;
use super::frame::{
    Direction, FrameError, Header, Kind, Status, encode, mac_input_for, parse, seal,
};
use super::frame_tests::{put_frame, reseal};
use super::geometry::{FRAGMENT_LEN, FragmentGeometry};
use super::link::{Faults, LinkEnd, Net, network};
use super::observe::Media;
use super::owner::{Bundle, Keys, Owner, OwnerConfig, OwnerError, OwnerRekeyError, Refused};
use super::owner_tests::{
    Mux, OWNER, PRINCIPALS, TestOwner, client_config, configured_client, drive, entries, key, open,
    payload, pool,
};
use super::packet::PacketPool;
use super::put::{
    Deadlines, Occupancy, PutConfig, PutCore, PutLimits, PutReport, ReserveRefusal, next_set,
    take_fill_reads, take_floor_reads, take_progress_visits, take_proven_run_waits,
    take_renumberings,
};
use super::requests::RequestId;
use super::requests::RequestTable;
use super::serve::ServeConfig;
use super::served::Requests;
use super::session::RekeyError;

pub(crate) struct Scene<'s, 'm> {
    pub(crate) owner: TestOwner<'s, 'm, 'm>,
    pub(crate) control: SimControl,
    pub(super) nets: [Rc<RefCell<Net<'m>>>; 2],
    pub(super) storage: &'s Storage<TestPlatform>,
    pub(super) clients: [Client<'m, LinkEnd<'m>>; 2],
    /// A replacement for client 0 under a new boot nonce, on a second end
    /// of client 0's link, with its own source slots and no session until a
    /// test opens one.
    pub(super) spare: Option<Client<'m, LinkEnd<'m>>>,
    /// The owner's buffer arena, which serves its read responses.
    pub(super) buffers: Option<&'m BufferArena<TestPlatform>>,
    pub(super) sourcing: &'m BufferArena<TestPlatform>,
    pub(super) rings: [KeyRing; 2],
    templates: [Header; 2],
    /// The handle of the GET each peer's latest refresh admitted, `None` before its first refresh.
    template_ids: [Option<RequestId>; 2],
    sequences: [u64; 2],
    pub(crate) turn: u64,
    /// A check of the owner that every turn runs after its poll.
    pub(super) audit: Option<Box<TurnCheck<'s, 'm>>>,
}

/// A client or test-side step that [`Scene::turn_with`] runs as one action
/// of the turn's round, listed before the scene's link, disk and owner
/// actions. It receives the scene's clients, its links and the turn's time
/// in microseconds.
pub(super) type Step<'f, 'm> = (
    Actor,
    &'f mut dyn FnMut(&mut [Client<'m, LinkEnd<'m>>; 2], &[Rc<RefCell<Net<'m>>>; 2], u64),
);

/// A step [`Scene::turn_then`] runs in the owner's action after its poll,
/// over the device and both links.
pub(super) type After<'f, 'm> = dyn FnMut(&SimControl, &[Rc<RefCell<Net<'m>>>; 2]) + 'f;

/// A check [`Scene`] runs over its owner after each poll.
pub(super) type TurnCheck<'s, 'm> = dyn Fn(&TestOwner<'s, 'm, 'm>) + 's;

type Started<'s, 'a, 'm> = Result<(TestOwner<'s, 'a, 'm>, SimControl), (OwnerError, EngineBudget)>;

type Refusal<'s, 'a> = (
    Box<Refused<'s, 'a, TestPlatform, SimDisk, Mux<'a>>>,
    EngineBudget,
);

pub(super) fn start_owner<'s, 'a, 'm>(
    storage: &'s Storage<TestPlatform>,
    buffers: &'a BufferArena<TestPlatform>,
    receive: &'m PacketPool<'a>,
    ends: Vec<LinkEnd<'a>>,
    config: OwnerConfig,
    put: &[u32],
    nonce: impl FnOnce(&mut [u8; 16]) -> Result<(), super::auth::EntropyError>,
) -> Started<'s, 'a, 'm> {
    let mut device = Device::new(storage, buffers);
    publish(storage, &mut device, &key(1), 0, &payload(1000, 1));
    start_on(device, storage, receive, ends, (config, put), nonce)
}

/// Starts an owner over `device`, the volume of `storage`, serving the peers
/// of `ends` under `config` with PUT granted to `put`.
pub(super) fn start_on<'s, 'a, 'm>(
    device: Device<'s, 'a>,
    storage: &'s Storage<TestPlatform>,
    receive: &'m PacketPool<'a>,
    ends: Vec<LinkEnd<'a>>,
    (config, put): (OwnerConfig, &[u32]),
    nonce: impl FnOnce(&mut [u8; 16]) -> Result<(), super::auth::EntropyError>,
) -> Started<'s, 'a, 'm> {
    start_refusing(device, storage, receive, ends, (config, put), nonce)
        .map_err(|(refused, budget)| (refused.error, budget))
}

/// `start_refusing` returns the refused bundle and transport so callers can retry startup.
fn start_refusing<'s, 'a, 'm>(
    device: Device<'s, 'a>,
    storage: &'s Storage<TestPlatform>,
    receive: &'m PacketPool<'a>,
    ends: Vec<LinkEnd<'a>>,
    (config, put): (OwnerConfig, &[u32]),
    nonce: impl FnOnce(&mut [u8; 16]) -> Result<(), super::auth::EntropyError>,
) -> Result<(TestOwner<'s, 'a, 'm>, SimControl), Refusal<'s, 'a>> {
    let Device { volume, control } = device;
    let cache = storage.issue_cache().unwrap();
    let registration = cache.register().unwrap();
    let entries = entries();
    let keys = keys(&entries[..ends.len()], put);
    let mut budget = EngineBudget::new(1 << 26);
    match Owner::start_with_nonce(
        config,
        Bundle {
            cache,
            registration,
            volume,
        },
        keys,
        Mux::new(ends),
        receive,
        &mut budget,
        nonce,
    ) {
        Ok(owner) => Ok((owner, control)),
        Err(refused) => Err((refused, budget)),
    }
}

fn keys<'k>(entries: &'k [KeyEntry<'k>], put: &'k [u32]) -> Keys<'k> {
    let principals: &'static [u32; 2] = &PRINCIPALS;
    Keys {
        principals: &principals[..entries.len()],
        entries,
        epoch: 1,
        put,
    }
}

pub(crate) fn scene(put: &[u32], body: impl FnOnce(Scene<'_, '_>)) {
    scene_with(OWNER, put, body);
}

pub(super) fn scene_with(config: OwnerConfig, put: &[u32], body: impl FnOnce(Scene<'_, '_>)) {
    scene_over(storage(8), config, put, body);
}

pub(super) fn scene_over(
    storage: Storage<TestPlatform>,
    config: OwnerConfig,
    put: &[u32],
    body: impl FnOnce(Scene<'_, '_>),
) {
    scene_drawn(storage, config, put, None, body);
}

/// What a scene draws from a run's chooser: the owner's and two clients'
/// boot nonces, in that order, and its two links' faults at the sites of
/// the named link actors.
pub(super) struct Drawn<'d> {
    pub(super) nonces: [[u8; 16]; 3],
    pub(super) draws: &'d super::link::Draws,
    pub(super) links: [u16; 2],
}

/// Source slots client 0 of [`scene_drawn`] and [`scene_unformatted`]
/// holds, and its spare as well; client 1 holds none, except in a
/// [`scene_relaunching`] scene that gives it a count.
pub(crate) const SOURCES: u32 = 4;

/// [`scene_over`] whose owner and clients start from the drawn nonces and
/// whose links draw from the run's chooser when `drawn` is given, else from
/// the operating system's entropy and each link's own chooser.
pub(super) fn scene_drawn(
    storage: Storage<TestPlatform>,
    config: OwnerConfig,
    put: &[u32],
    drawn: Option<Drawn<'_>>,
    body: impl FnOnce(Scene<'_, '_>),
) {
    scene_built(
        storage,
        (config, true),
        client_config(0),
        SOURCES,
        put,
        drawn,
        body,
    );
}

/// [`scene_with`] whose client 0 and its spare run under `client`, each with `sources` source slots.
pub(super) fn scene_with_client(
    config: OwnerConfig,
    client: ClientConfig,
    sources: u32,
    put: &[u32],
    body: impl FnOnce(Scene<'_, '_>),
) {
    scene_built(storage(8), (config, true), client, sources, put, None, body);
}

/// A scene whose owner's volume found both root slots invalid and was never formatted, so its bootstrap holds every fill at `Bootstrapping`; the scene publishes nothing.
pub(super) fn scene_unformatted(body: impl FnOnce(Scene<'_, '_>)) {
    scene_built(
        storage(8),
        (OWNER, false),
        client_config(0),
        SOURCES,
        &PRINCIPALS,
        None,
        body,
    );
}

/// The scene's owner starts over a published object on a formatted volume when `formatted`, else over [`scene_unformatted`]'s volume.
fn scene_built(
    storage: Storage<TestPlatform>,
    settings: (OwnerConfig, bool),
    first: ClientConfig,
    sources: u32,
    put: &[u32],
    drawn: Option<Drawn<'_>>,
    body: impl FnOnce(Scene<'_, '_>),
) {
    let shape = (first, [sources, 0], put);
    scene_incarnations(storage, settings, shape, drawn, Vec::new(), |scene, _| {
        body(scene);
    });
}

/// What [`scene_relaunching`] builds one more scene's resources from: its
/// storage, its owner's and clients' boot nonces, and the link actors its
/// two links draw at over the run's chooser. A relaunch's successor's links
/// draw only once that relaunch launches them as their actors' next
/// incarnations; a scene that starts beside the first launches its links
/// at once.
pub(super) struct Successor {
    pub(super) storage: Storage<TestPlatform>,
    pub(super) nonces: [[u8; 16]; 3],
    pub(super) links: [u16; 2],
    /// A relaunch starts the scene, which launches its links.
    pub(super) relaunched: bool,
}

/// [`scene_drawn`] beside the resources of one more scene per entry of
/// `successors`; client 1 of the first scene holds `second_sources` source
/// slots.
pub(super) fn scene_relaunching(
    storage: Storage<TestPlatform>,
    (config, second_sources): (OwnerConfig, u32),
    drawn: Drawn<'_>,
    successors: Vec<Successor>,
    body: impl for<'s, 'm> FnOnce(Scene<'s, 'm>, Vec<super::restart::Fresh<'s, 'm>>),
) {
    scene_incarnations(
        storage,
        (config, true),
        (client_config(0), [SOURCES, second_sources], &PRINCIPALS),
        Some(drawn),
        successors,
        body,
    );
}

/// The boot nonce of a drawn scene's spare client: the first client's drawn
/// nonce `drawn` with its first byte flipped, so the two clients differ.
pub(super) fn spare_nonce(drawn: [u8; 16]) -> [u8; 16] {
    let mut nonce = drawn;
    nonce[0] ^= 0xFF;
    nonce
}

/// [`scene_built`] that also builds each successor's [`Fresh`](super::restart::Fresh)
/// resources in the scene's scope, after the scene's own links.
fn scene_incarnations(
    storage: Storage<TestPlatform>,
    (config, formatted): (OwnerConfig, bool),
    (first, [sources, second_sources], put): (ClientConfig, [u32; 2], &[u32]),
    drawn: Option<Drawn<'_>>,
    successors: Vec<Successor>,
    body: impl for<'s, 'm> FnOnce(Scene<'s, 'm>, Vec<super::restart::Fresh<'s, 'm>>),
) {
    let nonces = drawn.as_ref().map(|drawn| drawn.nonces);
    let nonce = |actor: usize| {
        move |bytes: &mut [u8; 16]| match nonces {
            Some(drawn) => {
                *bytes = drawn[actor];
                Ok(())
            }
            None => super::auth::os_entropy(bytes),
        }
    };
    let later = successors.len();
    let later_buffers: Vec<_> = (0..later).map(|_| arena(16)).collect();
    let later_sourcing: Vec<_> = (0..later).map(|_| arena(sources)).collect();
    let later_packets: Vec<_> = (0..3 * later)
        .map(|_| super::packet::test_arena(32, 16384))
        .collect();
    fn view(arena: &BufferArena<TestPlatform>) -> super::packet::PacketPool<'_> {
        super::packet::PacketPool::new(arena, crate::storage::PoolKind::PacketReceive, 8).unwrap()
    }
    let later_receive: Vec<_> = (0..later).map(|n| view(&later_packets[3 * n])).collect();
    let later_pools: Vec<[_; 2]> = (0..later)
        .map(|n| {
            [
                view(&later_packets[3 * n + 1]),
                view(&later_packets[3 * n + 2]),
            ]
        })
        .collect();
    let later_releases: Vec<[Releases; 2]> = (0..later)
        .map(|_| {
            [first.caps.slots, 4]
                .map(|slots| Releases::new(slots, &mut EngineBudget::new(1 << 20)).unwrap())
        })
        .collect();
    // Two receive-write buffers a fill record, at least the four of `arena`, so each upload stages a segment while another is at the device.
    let buffers =
        crate::storage::volume_fixture::arena_with(16, (2 * storage.fill_capacity() as u32).max(4));
    // Every arena, pool and release set lives in this scope, so a scene returns every byte it took.
    let packets = [0; 4].map(|_| super::packet::test_arena(32, 16384));
    let receive = view(&packets[0]);
    let sourcing = arena(sources);
    let spare_sourcing = arena(sources);
    let second_sourcing = (second_sources > 0).then(|| arena(second_sources));
    let pools = [view(&packets[1]), view(&packets[2]), view(&packets[3])];
    let releases = [first.caps.slots, 4, first.caps.slots]
        .map(|slots| Releases::new(slots, &mut EngineBudget::new(1 << 20)).unwrap());
    let clean = [Faults::default(); 2];
    let ((end0, owner0, net0), (end1, owner1, net1)) = match &drawn {
        Some(drawn) => (
            super::link::network_drawn(64, 8384, clean, (drawn.draws, drawn.links[0])),
            super::link::network_drawn(64, 8384, clean, (drawn.draws, drawn.links[1])),
        ),
        None => (network(64, 8384, 102, clean), network(64, 8384, 103, clean)),
    };
    let ends = vec![owner0, owner1];
    let (owner, control) = if formatted {
        start_owner(&storage, &buffers, &receive, ends, config, put, nonce(0))
    } else {
        let (disk, control) = device_with(7, crate::storage::owner_fixture::BUFFER);
        let volume = crate::storage::Volume::attach(
            &storage,
            &buffers,
            disk,
            crate::storage::portable::scripted::ScriptedClock::trusted(),
            crate::storage::ServingAuthority::fixture(),
            crate::storage::owner_fixture::DEPTH,
            crate::storage::owner_fixture::TICK,
            &mut EngineBudget::new(1 << 24),
        )
        .map_err(|(error, _)| error)
        .expect("attach");
        let device = Device { volume, control };
        start_on(device, &storage, &receive, ends, (config, put), nonce(0))
    }
    .unwrap();
    let nets = [net0, net1];
    let spare_end = end0.rejoin();
    let routes = super::client_tests::routes();
    let clients = [
        configured_client(
            0,
            first,
            &pools[0],
            &releases[0],
            end0,
            super::memory::sources(&sourcing, sources, &mut EngineBudget::new(1 << 20)).unwrap(),
            nonce(1),
            routes.clone(),
        ),
        configured_client(
            1,
            super::owner_tests::client_config(1),
            &pools[1],
            &releases[1],
            end1,
            second_sourcing.as_ref().map_or_else(Box::default, |arena| {
                super::memory::sources(arena, second_sources, &mut EngineBudget::new(1 << 20))
                    .unwrap()
            }),
            nonce(2),
            routes,
        ),
    ];
    let mut scene = assemble((owner, control), nets, &storage, clients, &sourcing, 0);
    let spare = move |bytes: &mut [u8; 16]| match nonces {
        Some(drawn) => {
            *bytes = spare_nonce(drawn[1]);
            Ok(())
        }
        None => super::auth::os_entropy(bytes),
    };
    scene.buffers = Some(&buffers);
    scene.spare = Some(configured_client(
        0,
        first,
        &pools[2],
        &releases[2],
        spare_end,
        super::memory::sources(&spare_sourcing, sources, &mut EngineBudget::new(1 << 20)).unwrap(),
        spare,
        super::client_tests::routes(),
    ));
    let mut links: Vec<_> = scene.nets.iter().map(Rc::clone).collect();
    let fresh = (0..later)
        .map(|n| {
            let drawn = drawn
                .as_ref()
                .expect("a relaunching scene draws its successors' links from the run's chooser");
            let successor = &successors[n];
            let [(end0, owner0, net0), (end1, owner1, net1)] = successor.links.map(|link| {
                if successor.relaunched {
                    super::link::network_later(64, 8384, clean, (drawn.draws, link))
                } else {
                    super::link::network_drawn(64, 8384, clean, (drawn.draws, link))
                }
            });
            links.extend([Rc::clone(&net0), Rc::clone(&net1)]);
            super::restart::Fresh {
                storage: &successors[n].storage,
                buffers: &later_buffers[n],
                receive: &later_receive[n],
                sourcing: &later_sourcing[n],
                links: super::restart::Links {
                    clients: [end0, end1],
                    owners: [owner0, owner1],
                    nets: [net0, net1],
                    pools: &later_pools[n],
                    releases: &later_releases[n],
                },
                nonces: successors[n].nonces,
            }
        })
        .collect();
    body(scene, fresh);
    for net in links {
        assert_eq!(
            net.borrow().draw_error(),
            None,
            "every link draw was a recorded choice"
        );
    }
}

/// A scene over a started owner and its two clients: the clients open their
/// sessions in order, starting at turn `turn`, and each learns a GET
/// template from a frame its link clears before the owner polls.
pub(super) fn assemble<'s, 'm>(
    (mut owner, control): (TestOwner<'s, 'm, 'm>, SimControl),
    nets: [Rc<RefCell<Net<'m>>>; 2],
    storage: &'s Storage<TestPlatform>,
    mut clients: [Client<'m, LinkEnd<'m>>; 2],
    sourcing: &'m BufferArena<TestPlatform>,
    mut turn: u64,
) -> Scene<'s, 'm> {
    let live = owner.readiness() == crate::storage::Readiness::Live;
    for client in &mut clients {
        if live {
            turn = open(client, &mut owner, &control, &nets, turn);
        }
    }
    let mut scene = unopened((owner, control), nets, storage, clients, sourcing, turn);
    if live {
        scene.refresh(0);
        scene.refresh(1);
    }
    scene
}

/// A scene over a started owner and its two clients at turn `turn`, whose
/// clients hold whatever sessions they opened before and whose GET
/// templates stay blank.
pub(super) fn unopened<'s, 'm>(
    (owner, control): (TestOwner<'s, 'm, 'm>, SimControl),
    nets: [Rc<RefCell<Net<'m>>>; 2],
    storage: &'s Storage<TestPlatform>,
    clients: [Client<'m, LinkEnd<'m>>; 2],
    sourcing: &'m BufferArena<TestPlatform>,
    turn: u64,
) -> Scene<'s, 'm> {
    let rings = [0, 1].map(|peer| {
        KeyRing::load(
            &PRINCIPALS[peer..=peer],
            &entries()[peer..=peer],
            1,
            &mut EngineBudget::new(1 << 20),
        )
        .unwrap()
    });
    let blank = super::serve::header(Kind::Get, 0, [0; 32]);
    Scene {
        owner,
        control,
        nets,
        storage,
        clients,
        spare: None,
        buffers: None,
        sourcing,
        rings,
        templates: [blank; 2],
        template_ids: [None; 2],
        sequences: [0; 2],
        turn,
        audit: None,
    }
}

pub(super) fn request(slot: u16, generation: u64) -> u64 {
    u64::from(slot) << 48 | generation
}

pub(super) fn prepare(serial: u64, body_len: u32, ttl_ms: u32) -> impl FnOnce(&mut Header) {
    move |header| {
        header.allocation = serial;
        header.metadata_len = 0;
        header.body_len = body_len;
        header.total = u64::from(body_len);
        header.count = FragmentGeometry::fragments(u64::from(body_len)) as u32;
        header.remaining_ms = ttl_ms;
    }
}

pub(super) fn cancel(serial: u64) -> impl FnOnce(&mut Header) {
    move |header| header.allocation = serial
}

pub(super) fn error(header: &Header) -> Option<Status> {
    (header.kind == Kind::PutError).then(|| Status::from_wire(header.status).unwrap())
}

impl<'s, 'm> Scene<'s, 'm> {
    pub(super) fn refresh(&mut self, peer: usize) {
        let crc = Crc32c::detect();
        let id = self.clients[peer]
            .get(key(9), 0, 1 << 20, self.turn * 100, 30_000_000)
            .unwrap();
        self.template_ids[peer] = Some(id);
        self.clients[peer].poll(self.turn * 100);
        let template = self.nets[peer]
            .borrow()
            .peek(1)
            .and_then(|bytes| parse(crc, &bytes, false).ok().map(|frame| frame.header()))
            .expect("the GET toward the owner");
        self.nets[peer].borrow_mut().clear(1);
        self.sequences[peer] = template.sequence;
        self.templates[peer] = template;
    }

    /// The owner's datagram accounts against what the scene's links
    /// delivered toward it, end 1 of each link.
    pub(super) fn accounts(&self) -> Result<(), super::observe::Failure> {
        let links = self.nets.iter().map(|net| net.borrow().report(1));
        super::observe::accounts(&self.owner.report(), self.owner.poisoned(), links)
    }

    pub(super) fn template(&self, peer: usize) -> Header {
        self.templates[peer]
    }

    /// The handle of the GET whose header [`template`](Self::template) returns.
    pub(super) fn template_id(&self, peer: usize) -> RequestId {
        self.template_ids[peer].expect("a refreshed template")
    }

    pub(super) fn reopen(&mut self, peer: usize) {
        self.open(peer);
        self.refresh(peer);
    }

    /// Opens a session for client `peer` and drives it until it is active.
    pub(super) fn open(&mut self, peer: usize) {
        let start = self.turn;
        self.clients[peer].session(start * 100);
        while self.clients[peer].state() != SessionState::Active {
            assert!(self.turn < start + 5_000, "the session opened");
            self.turn = drive(
                &mut [&mut self.clients[peer]],
                &mut self.owner,
                &self.control,
                &self.nets,
                self.turn,
                1,
                |_| false,
            );
            self.audited();
        }
    }

    pub(super) fn frame(
        &mut self,
        peer: usize,
        kind: Kind,
        request: u64,
        name: u8,
        edit: impl FnOnce(&mut Header),
    ) -> Header {
        self.sequences[peer] += 1;
        let base = Header {
            request,
            sequence: self.sequences[peer],
            key: key(name),
            ..self.templates[peer]
        };
        let (mut header, _) = put_frame(kind, &base);
        edit(&mut header);
        header
    }

    /// The next GET from `peer` for `request` and key `name`: the peer's
    /// learned GET template under the session's next sequence number.
    pub(super) fn get(&mut self, peer: usize, request: u64, name: u8) -> Header {
        self.sequences[peer] += 1;
        Header {
            request,
            sequence: self.sequences[peer],
            key: key(name),
            ..self.templates[peer]
        }
    }

    /// Every frame the owner sent toward `peer` since the last call, parsed,
    /// in send order; the link keeps none of them.
    pub(super) fn sent(&mut self, peer: usize) -> Vec<Header> {
        let crc = Crc32c::detect();
        let mut sent = Vec::new();
        self.nets[peer].borrow_mut().retain(0, |bytes| {
            if let Ok(frame) = parse(crc, bytes, false) {
                sent.push(frame.header());
            }
            false
        });
        sent
    }

    /// The storage's raw byte ledger.
    fn ledger(&self) -> RawPartition {
        self.storage.pool_report().unwrap().ledger.unwrap().raw
    }

    /// Whether the owner's storage maps key `name` now: a lookup through a
    /// fresh registration acquires it.
    pub(super) fn visible(&self, name: u8) -> bool {
        let mut reader = self.storage.register().unwrap();
        reader
            .lookup(&key(name), 4, &mut WorkBudget::new(1 << 16))
            .is_ok()
    }

    pub(super) fn media(&self) -> Media<'s> {
        Media::new(
            self.storage,
            self.control.clone(),
            self.owner.record_session(),
        )
    }

    pub(super) fn turns(&mut self, turns: u64) {
        for _ in 0..turns {
            self.turn_with(&mut []);
        }
    }

    /// One turn as one controller round of `lead`'s steps, every link's
    /// advance, the disk's tick and the owner's poll, in that listed order
    /// under the legacy schedule and in the order the thread's schedule
    /// picks otherwise.
    pub(super) fn turn_with(&mut self, lead: &mut [Step<'_, 'm>]) {
        self.turn_then(lead, &mut |_, _| {});
    }

    /// [`turn_with`](Self::turn_with), running `after` in the owner's action
    /// right after its poll, so `after` acts on what that poll did, such as a
    /// write it submitted or a frame it sent, before a later action of the
    /// round changes it.
    pub(super) fn turn_then(&mut self, lead: &mut [Step<'_, 'm>], after: &mut After<'_, 'm>) {
        let turn = self.turn;
        let now = turn * 100;
        {
            let clients = RefCell::new(&mut self.clients);
            let clients = &clients;
            let nets = &self.nets;
            let mut steps: Vec<_> = lead
                .iter_mut()
                .map(|(actor, step)| (*actor, move || step(&mut clients.borrow_mut(), nets, now)))
                .collect();
            let mut advances: Vec<_> = nets
                .iter()
                .map(|net| move || net.borrow_mut().advance(turn))
                .collect();
            let control = &self.control;
            let mut tick = || control.tick(64);
            let owner = &mut self.owner;
            let mut poll = || {
                owner.poll(now);
                after(control, nets);
            };
            let mut acts = Vec::new();
            for (actor, step) in &mut steps {
                acts.push(Act::new(*actor, step));
            }
            push_each(&mut acts, Actor::Link, &mut advances);
            acts.push(Act::new(Actor::Disk(0), &mut tick));
            acts.push(Act::new(Actor::Owner(0), &mut poll));
            round(&mut acts);
        }
        self.turn += 1;
        self.audited();
    }

    /// The audit checks the owner's state after each turn.
    fn audited(&self) {
        if let Some(audit) = &self.audit {
            audit(&self.owner);
        }
    }

    /// Turns every link and polls the owner as one controller round per
    /// poll, leaving the disk untouched.
    pub(super) fn polls(&mut self, polls: u64) {
        for _ in 0..polls {
            let turn = self.turn;
            let nets = &self.nets;
            let mut advances: Vec<_> = nets
                .iter()
                .map(|net| move || net.borrow_mut().advance(turn))
                .collect();
            let owner = &mut self.owner;
            let mut poll = || owner.poll(turn * 100);
            let mut acts = Vec::new();
            push_each(&mut acts, Actor::Link, &mut advances);
            acts.push(Act::new(Actor::Owner(0), &mut poll));
            round(&mut acts);
            self.turn += 1;
            self.audited();
        }
    }

    pub(super) fn inject(&mut self, peer: usize, header: &Header) {
        self.inject_edited(peer, header, &[], |_| {});
    }

    pub(super) fn inject_edited(
        &mut self,
        peer: usize,
        header: &Header,
        body: &[u8],
        edit: impl FnOnce(&mut [u8]),
    ) {
        let datagram = self.sealed(peer, header, body, edit);
        self.nets[peer].borrow_mut().inject(1, &datagram);
    }

    /// The datagram of `header` and `body` toward the owner, its encoded header edited by `edit` and then tagged under
    /// peer `peer`'s key.
    pub(super) fn sealed(
        &self,
        peer: usize,
        header: &Header,
        body: &[u8],
        edit: impl FnOnce(&mut [u8]),
    ) -> Vec<u8> {
        let crc = Crc32c::detect();
        let mut encoded = [0u8; HEADER_LEN];
        encode(crc, header, [body, &[]], &mut encoded).unwrap();
        edit(&mut encoded);
        let input = mac_input_for(
            &encoded,
            [body, &[]],
            OWNER.endpoint,
            Direction::ClientToOwner,
        )
        .unwrap();
        let tag = self.rings[peer].tag(PeerId(0), &input).unwrap();
        seal(&mut encoded, tag);
        let mut datagram = encoded.to_vec();
        datagram.extend_from_slice(body);
        datagram
    }

    pub(super) fn fragment(
        &mut self,
        at: u64,
        serial: u64,
        object: &[u8],
        index: u32,
    ) -> (Header, Vec<u8>) {
        self.fragment_from(1, at, serial, 5, object, index)
    }

    /// The DATA frame of fragment `index` of `object` from `peer` for key `name`.
    fn fragment_from(
        &mut self,
        peer: usize,
        at: u64,
        serial: u64,
        name: u8,
        object: &[u8],
        index: u32,
    ) -> (Header, Vec<u8>) {
        let start = index as usize * FRAGMENT_LEN as usize;
        let body = object[start..(start + FRAGMENT_LEN as usize).min(object.len())].to_vec();
        let total = object.len() as u64;
        let header = self.frame(peer, Kind::PutData, at, name, |header| {
            header.allocation = serial;
            header.metadata_len = 0;
            header.body_len = total as u32;
            header.total = total;
            header.count = FragmentGeometry::fragments(total) as u32;
            header.index = index;
            header.offset = start as u64;
            header.datagram_len = body.len() as u32;
        });
        (header, body)
    }

    fn put_data(&mut self, header: &Header, body: &[u8]) -> Vec<Header> {
        self.inject_edited(1, header, body, |_| {});
        self.turns(4);
        self.replies(1)
    }

    pub(super) fn replies(&mut self, peer: usize) -> Vec<Header> {
        let crc = Crc32c::detect();
        let mut replies = Vec::new();
        self.nets[peer].borrow_mut().retain(0, |bytes| {
            if let Ok(frame) = parse(crc, bytes, false)
                && frame.header().kind.is_put()
            {
                replies.push(frame.header());
            }
            false
        });
        replies
    }

    fn send(&mut self, peer: usize, header: &Header) -> Vec<Header> {
        self.inject(peer, header);
        self.turns(4);
        self.replies(peer)
    }

    pub(super) fn one(&mut self, peer: usize, header: &Header) -> Header {
        let replies = self.send(peer, header);
        assert_eq!(replies.len(), 1, "{replies:?}");
        replies[0]
    }

    pub(super) fn fetch(&mut self, name: u8) -> Vec<u8> {
        let (outcome, bytes) = self.read(0, name, 0);
        assert_eq!(outcome, Some(super::fetch::Outcome::Complete));
        bytes
    }

    pub(super) fn read(
        &mut self,
        reader: usize,
        name: u8,
        metadata_cap: u32,
    ) -> (Option<super::fetch::Outcome>, Vec<u8>) {
        let id = self.clients[reader]
            .get(
                key(name),
                metadata_cap,
                1 << 20,
                self.turn * 100,
                30_000_000,
            )
            .unwrap();
        let mut bytes = Vec::new();
        for _ in 0..4_000 {
            let turn = self.turn;
            let now = turn * 100;
            {
                let nets = &self.nets;
                let mut advances: Vec<_> = nets
                    .iter()
                    .map(|net| move || net.borrow_mut().advance(turn))
                    .collect();
                let client = &mut self.clients[reader];
                let mut client_poll = || {
                    let _ = client.poll(now);
                };
                let control = &self.control;
                let mut tick = || control.tick(64);
                let owner = &mut self.owner;
                let mut owner_poll = || owner.poll(now);
                let mut acts = Vec::new();
                push_each(&mut acts, Actor::Link, &mut advances);
                acts.push(Act::new(Actor::Client(reader as u16), &mut client_poll));
                acts.push(Act::new(Actor::Disk(0), &mut tick));
                acts.push(Act::new(Actor::Owner(0), &mut owner_poll));
                round(&mut acts);
            }
            self.turn += 1;
            self.audited();
            while let Some(fragment) = self.clients[reader].take(id) {
                bytes.extend_from_slice(fragment.bytes());
            }
            if self.clients[reader].outcome(id).is_some() {
                break;
            }
        }
        let outcome = self.clients[reader].outcome(id);
        if outcome.is_some() {
            assert!(self.clients[reader].retire(id));
        }
        (outcome, bytes)
    }

    pub(super) fn live(&self) -> u32 {
        self.owner.census().live()
    }

    pub(super) fn begin(&mut self, peer: usize, at: u64, name: u8) -> u64 {
        let begin = self.frame(peer, Kind::PutBegin, at, name, |_| {});
        let authority = self.one(peer, &begin);
        assert_eq!(authority.kind, Kind::PutAuthority, "{authority:?}");
        assert_ne!(authority.allocation, 0);
        authority.allocation
    }
}

/// A PUT BEGIN from each peer arrives in one receive batch, one next to the other. The owner computes both tags in one pass of two chains, and each BEGIN is answered with its authority.
#[test]
fn adjacent_put_control_frames_authenticate_in_one_paired_computation() {
    scene(&PRINCIPALS, |mut scene| {
        let at = request(1, 1);
        let dropped = scene.owner.report().dropped;
        super::owner::PAIRED_BARE.with(|count| count.set(0));
        for peer in 0..2 {
            let begin = scene.frame(peer, Kind::PutBegin, at, 5 + peer as u8, |_| {});
            scene.inject(peer, &begin);
        }
        scene.turns(4);
        assert_eq!(
            super::owner::PAIRED_BARE.with(std::cell::Cell::get),
            2,
            "the two BEGINs took their tags from one paired computation"
        );
        for peer in 0..2 {
            let kinds: Vec<_> = scene.replies(peer).iter().map(|reply| reply.kind).collect();
            assert_eq!(kinds, [Kind::PutAuthority], "peer {peer}");
        }
        assert_eq!(scene.owner.report().dropped, dropped);
    });
}

/// Of two adjacent PUT BEGINs, peer 0's carries a tag computed under peer 1's key. The paired computation refuses that frame alone: the owner drops it and answers peer 1's BEGIN.
#[test]
fn a_wrongly_tagged_control_frame_in_a_pair_is_dropped_alone() {
    scene(&PRINCIPALS, |mut scene| {
        let at = request(1, 1);
        let dropped = scene.owner.report().dropped;
        super::owner::PAIRED_BARE.with(|count| count.set(0));
        let forged = scene.frame(0, Kind::PutBegin, at, 5, |_| {});
        let encoded = scene.sealed(1, &forged, &[], |_| {});
        scene.nets[0].borrow_mut().inject(1, &encoded);
        let begin = scene.frame(1, Kind::PutBegin, at, 6, |_| {});
        scene.inject(1, &begin);
        scene.turns(4);
        assert_eq!(
            super::owner::PAIRED_BARE.with(std::cell::Cell::get),
            2,
            "the two BEGINs shared one paired computation"
        );
        assert_eq!(
            scene.owner.report().dropped,
            dropped + 1,
            "the wrongly tagged BEGIN is dropped"
        );
        assert!(scene.replies(0).is_empty(), "and gets no answer");
        let kinds: Vec<_> = scene.replies(1).iter().map(|reply| reply.kind).collect();
        assert_eq!(kinds, [Kind::PutAuthority]);
    });
}

#[test]
fn a_lost_authority_or_ready_replays_the_same_attempt() {
    scene(&PRINCIPALS, |mut scene| {
        let at = request(1, 1);
        let serial = scene.begin(1, at, 5);
        assert_eq!(scene.begin(1, at, 5), serial);
        assert_eq!(scene.live(), 1);
        let first = scene.frame(1, Kind::PutPrepare, at, 5, prepare(serial, 100, 60_000));
        let ready = scene.one(1, &first);
        let fields = |header: &Header| {
            (
                header.kind,
                header.allocation,
                header.total,
                header.count,
                header.grant,
            )
        };
        assert_eq!(fields(&ready), (Kind::PutReady, serial, 100, 1, 1));
        let resent = scene.frame(1, Kind::PutPrepare, at, 5, prepare(serial, 100, 60_000));
        assert_eq!(fields(&scene.one(1, &resent)), fields(&ready));
        assert_eq!(scene.begin(1, at, 5), serial);
        assert_eq!(scene.live(), 1);
        let other = scene.frame(0, Kind::PutBegin, request(2, 1), 5, |_| {});
        assert_eq!(error(&scene.one(0, &other)), Some(Status::InProgress));
        assert_eq!(scene.live(), 1, "the key holds one attempt");
    });
}

#[test]
fn a_changed_prepare_conflicts_and_keeps_the_authority() {
    scene(&PRINCIPALS, |mut scene| {
        let at = request(1, 1);
        let serial = scene.begin(1, at, 5);
        let first = scene.frame(1, Kind::PutPrepare, at, 5, prepare(serial, 100, 60_000));
        assert_eq!(scene.one(1, &first).kind, Kind::PutReady);
        for changed in [
            prepare(serial, 200, 60_000),
            prepare(serial, 100, 120_000),
            prepare(serial + 1, 100, 60_000),
        ] {
            let header = scene.frame(1, Kind::PutPrepare, at, 5, changed);
            assert_eq!(
                error(&scene.one(1, &header)),
                Some(Status::ConflictingRequest)
            );
        }
        let rekeyed = scene.frame(1, Kind::PutBegin, at, 6, |_| {});
        assert_eq!(
            error(&scene.one(1, &rekeyed)),
            Some(Status::ConflictingRequest)
        );
        let resent = scene.frame(1, Kind::PutPrepare, at, 5, prepare(serial, 100, 60_000));
        assert_eq!(scene.one(1, &resent).kind, Kind::PutReady);
        assert_eq!(scene.live(), 1);
    });
}

#[test]
fn prepare_refusals_end_the_attempt_with_their_status() {
    scene(&PRINCIPALS, |mut scene| {
        let cases = [
            (Some(1), false, Status::TooLarge, BODY_CAP + 1),
            (None, false, Status::ClockUnavailable, 100),
            (Some(u64::MAX - 1), false, Status::InvalidRequest, 100),
            (
                Some((u64::from(u32::MAX) - 1) * 1_000_000_000),
                false,
                Status::InvalidRequest,
                100,
            ),
            (Some(1), true, Status::Closed, 100),
        ];
        for (n, (clock, close, status, body)) in cases.into_iter().enumerate() {
            let at = request(1, n as u64 + 1);
            let name = 10 + n as u8;
            let serial = scene.begin(1, at, name);
            set_clock(scene.storage, &[clock]);
            if close {
                scene.storage.close();
            }
            let before = scene.owner.put_report();
            let header = scene.frame(1, Kind::PutPrepare, at, name, prepare(serial, body, 1_000));
            assert_eq!(error(&scene.one(1, &header)), Some(status), "{status:?}");
            set_clock(scene.storage, &[Some(1)]);
            assert_eq!(scene.live(), 0, "{status:?} ended the attempt");
            let refused = scene.owner.put_report();
            let counts = |report: &PutReport| {
                (
                    report.reserve_refused,
                    report.failed_other,
                    refusal_parts(report),
                )
            };
            assert_eq!(
                counts(&refused),
                (before.reserve_refused + 1, before.failed_other + 1, [0; 4]),
                "{status:?}"
            );
            let resent = scene.frame(1, Kind::PutPrepare, at, name, prepare(serial, body, 1_000));
            assert_eq!(
                error(&scene.one(1, &resent)),
                Some(status),
                "the row replays"
            );
            assert_eq!(
                counts(&scene.owner.put_report()),
                counts(&refused),
                "{status:?}: the replay counts nothing"
            );
            scene.turns(50);
        }
    });
}

/// A PREPARE for an object of three extents reaches READY under reservation
/// work that funds the promise and one extent's placement per call, and
/// under work one step short of the promise and a placement, which places
/// nothing at the PREPARE: the placement spans progress turns, each funded
/// with the reservation work, and the fill then primes as a one-extent fill
/// does, with nothing left promised.
#[test]
fn a_multi_extent_prepare_places_over_turns_within_the_reservation_work() {
    for short in [false, true] {
        let (storage, steps, promise_cost) = three_extent_storage();
        let config = OwnerConfig {
            lookup_work: if short {
                promise_cost + steps - 1
            } else {
                promise_cost + steps + 2
            },
            ..OWNER
        };
        scene_over(storage, config, &PRINCIPALS, |mut scene| {
            let at = request(1, 1);
            let serial = scene.begin(1, at, 10);
            let header = scene.frame(1, Kind::PutPrepare, at, 10, three_extents(serial));
            scene.inject(1, &header);
            scene.polls(1);
            let mut kinds: Vec<_> = scene.replies(1).iter().map(|reply| reply.kind).collect();
            assert_ne!(
                kinds,
                [Kind::PutError],
                "short {short}: the PREPARE kept its placement"
            );
            let report = scene.owner.put_report();
            assert_eq!(report.reserve_refused, 0, "short {short}");
            assert!(report.place_waits >= 1, "short {short}: {report:?}");
            scene.polls(6);
            kinds.extend(scene.replies(1).iter().map(|reply| reply.kind));
            assert_eq!(kinds, [Kind::PutReady], "short {short}");
            assert_eq!(
                scene.owner.put_report().reserve_refused,
                0,
                "short {short}: the progress turns' placements waited"
            );
            assert_eq!(scene.storage.pool_report().unwrap().escrow_units, 0);
            assert_eq!(scene.live(), 1, "short {short}");
        });
    }
}

/// A reservation work one step short of a placement leaves the PREPARE
/// placing, and the progress turn in the same poll then refuses the PUT with
/// `Contended`; that refusal counts in `reserve_refused` and in no part.
#[test]
fn a_progress_turn_short_of_a_placement_step_counts_in_the_total_alone() {
    let (storage, steps, _) = three_extent_storage();
    let config = OwnerConfig {
        lookup_work: steps - 1,
        ..OWNER
    };
    scene_over(storage, config, &PRINCIPALS, |mut scene| {
        let at = request(1, 1);
        let serial = scene.begin(1, at, 10);
        let header = scene.frame(1, Kind::PutPrepare, at, 10, three_extents(serial));
        scene.inject(1, &header);
        scene.polls(1);
        let errors: Vec<_> = scene.replies(1).iter().filter_map(error).collect();
        assert_eq!(errors, [Status::Contended]);
        let report = scene.owner.put_report();
        assert_eq!(report.place_waits, 1, "the PREPARE waited: {report:?}");
        assert_eq!(
            (report.reserve_refused, refusal_parts(&report)),
            (1, [0; 4]),
            "{report:?}"
        );
        assert_eq!(report.failed_other, 1, "{report:?}");
        assert_eq!(scene.storage.pool_report().unwrap().escrow_units, 0);
        assert_eq!(scene.live(), 0);
    });
}

const THREE_EXTENT_LENGTHS: (u32, u32) = (2 * 253_952, 1);

/// A sequence storage that admits an object of three extents. The first
/// number is one placement's steps, the gate try plus the extent work bound.
/// The second is the promise's cost: the steps a reservation spends funding
/// the promise before the first placement's preflight refuses. Service then
/// clears the probe attempt.
fn three_extent_storage() -> (Storage<TestPlatform>, usize, usize) {
    let (metadata_len, body_len) = THREE_EXTENT_LENGTHS;
    let lengths = (Some(metadata_len as usize), Some(body_len as usize));
    let storage = sequence_storage_with_metadata(metadata_len as usize);
    let crate::storage::Decision::Admit(admitted) = storage.decide_admission(lengths.0, lengths.1)
    else {
        panic!("the caps admit the object");
    };
    assert_eq!(admitted.extents(), 3);
    let steps = 1 + storage.pool_report().unwrap().extent_bound;
    let mut probe = WorkBudget::new(steps - 1);
    let refused = storage
        .begin_fill(
            &key(99),
            crate::storage::CacheVersion(0),
            3,
            &mut WorkBudget::new(1 << 10),
        )
        .unwrap()
        .reserve_storage(admitted, lengths.0, lengths.1, 3, &mut probe)
        .err();
    assert_eq!(
        refused,
        Some(crate::storage::FillReserveError::BudgetExhausted)
    );
    let promise_cost = steps - 1 - probe.remaining();
    for _ in 0..4 {
        storage
            .service_fills(
                crate::index::ShardIndex(0),
                3,
                &mut WorkBudget::new(1 << 10),
            )
            .unwrap();
        let _ = storage.service(&mut WorkBudget::new(1 << 10));
    }
    (storage, steps, promise_cost)
}

pub(super) fn three_extents(serial: u64) -> impl FnOnce(&mut Header) {
    let (metadata_len, body_len) = THREE_EXTENT_LENGTHS;
    move |header| {
        prepare(serial, body_len, 1_000)(header);
        header.metadata_len = metadata_len;
        header.total = u64::from(metadata_len + body_len);
        header.count = FragmentGeometry::fragments(header.total) as u32;
    }
}

#[test]
fn begin_refusals_admit_nothing() {
    scene(&PRINCIPALS[1..], |mut scene| {
        let volume = scene.owner.volume_report();
        let denied = scene.frame(0, Kind::PutBegin, request(1, 1), 5, |_| {});
        assert_eq!(
            error(&scene.one(0, &denied)),
            Some(Status::PermissionDenied)
        );
        assert_eq!(scene.live(), 0);
        assert_eq!(scene.owner.volume_report(), volume);
        scene.begin(1, request(1, 1), 5);
        let over = scene.frame(1, Kind::PutBegin, request(2, 1), 6, |_| {});
        assert_eq!(
            error(&scene.one(1, &over)),
            Some(Status::RequestPressure),
            "the peer holds its one PUT"
        );
        assert_eq!(scene.live(), 1);
    });
    scene(&PRINCIPALS, |mut scene| {
        scene.begin(1, request(1, 1), 5);
        scene.begin(0, request(1, 1), 6);
        assert_eq!(scene.live(), 2, "another peer's BEGIN is admitted");
    });
}

/// Peers' frames reach one receive batch in peer order, so peer 0's PREPARE loses the volume before peer 1's BEGIN in the same batch asks for authority.
#[test]
fn a_begin_behind_the_prepare_that_lost_the_volume_is_refused_in_the_same_batch() {
    scene(&PRINCIPALS, |mut scene| {
        let at = request(1, 1);
        let serial = scene.begin(0, at, 5);
        scene.control.refuse_next(SubmitRefusal {
            reason: RefusalReason::DeviceGone,
            code: None,
        });
        let empty = scene.frame(0, Kind::PutPrepare, at, 5, prepare(serial, 0, 60_000));
        scene.inject(0, &empty);
        let begin = scene.frame(1, Kind::PutBegin, request(1, 1), 6, |_| {});
        scene.inject(1, &begin);
        scene.turns(4);
        assert_eq!(
            scene.replies(0).iter().map(error).collect::<Vec<_>>(),
            [Some(Status::OwnerUnavailable)],
            "the header write lost the volume"
        );
        let replies = scene.replies(1);
        assert_eq!(
            replies.iter().map(error).collect::<Vec<_>>(),
            [Some(Status::OwnerUnavailable)],
            "the BEGIN behind the losing PREPARE finds the lost volume: {replies:?}"
        );
        assert_eq!(scene.live(), 0, "the refused BEGIN acquired nothing");
    });
}

#[test]
fn a_volume_lost_to_a_put_write_refuses_later_begins() {
    scene(&PRINCIPALS, |mut scene| {
        let at = request(1, 1);
        let serial = scene.begin(1, at, 5);
        scene.control.refuse_next(SubmitRefusal {
            reason: RefusalReason::DeviceGone,
            code: None,
        });
        let empty = scene.frame(1, Kind::PutPrepare, at, 5, prepare(serial, 0, 60_000));
        assert_eq!(
            error(&scene.one(1, &empty)),
            Some(Status::OwnerUnavailable),
            "the header write lost the volume"
        );
        assert_eq!(scene.live(), 0);
        for peer in [1, 0] {
            let begin = scene.frame(peer, Kind::PutBegin, request(2, 1), 6, |_| {});
            assert_eq!(
                error(&scene.one(peer, &begin)),
                Some(Status::OwnerUnavailable),
                "peer {peer}'s BEGIN finds the lost volume"
            );
            assert_eq!(scene.live(), 0, "the refused BEGIN acquired nothing");
        }
    });
}

#[test]
fn a_configuration_over_the_put_caps_refuses_start() {
    for (config, expected) in [
        (
            OwnerConfig {
                put: PutConfig {
                    peer_puts: 2,
                    ..OWNER.put
                },
                ..OWNER
            },
            OwnerError::Puts,
        ),
        (
            OwnerConfig {
                put: PutConfig {
                    puts: 3,
                    peer_puts: 1,
                    ..OWNER.put
                },
                ..OWNER
            },
            OwnerError::FillCapacity {
                puts: 3,
                capacity: 2,
            },
        ),
        (
            OwnerConfig {
                request_slots: 1,
                peer_requests: 1,
                ..OWNER
            },
            OwnerError::Puts,
        ),
        (
            OwnerConfig {
                put: PutConfig {
                    commands: 0,
                    ..OWNER.put
                },
                ..OWNER
            },
            OwnerError::Puts,
        ),
        (
            OwnerConfig {
                put: PutConfig {
                    get_backlog: 0,
                    ..OWNER.put
                },
                ..OWNER
            },
            OwnerError::Puts,
        ),
        (
            OwnerConfig {
                put: PutConfig {
                    command_bytes: 0,
                    ..OWNER.put
                },
                ..OWNER
            },
            OwnerError::Puts,
        ),
        (
            OwnerConfig {
                put: PutConfig {
                    command_bytes: 1,
                    ..OWNER.put
                },
                ..OWNER
            },
            OwnerError::Puts,
        ),
        (
            OwnerConfig {
                put: PutConfig {
                    publish_tries: 0,
                    ..PUTLESS.put
                },
                ..PUTLESS
            },
            OwnerError::Puts,
        ),
        (
            OwnerConfig {
                put: PutConfig {
                    publish_work: 0,
                    ..PUTLESS.put
                },
                ..PUTLESS
            },
            OwnerError::Puts,
        ),
    ] {
        let storage = storage(8);
        let buffers = arena(8);
        let receive = pool();
        let (_end, owner_end, _net) = network(64, 8384, 92, [Faults::default(); 2]);
        let ends = if config.request_slots == 1 {
            vec![owner_end]
        } else {
            let (_other, second, _net) = network(64, 8384, 93, [Faults::default(); 2]);
            vec![owner_end, second]
        };
        let refused = start_owner(
            &storage,
            &buffers,
            &receive,
            ends,
            config,
            &PRINCIPALS,
            super::auth::os_entropy,
        );
        let Err((error, budget)) = refused else {
            panic!("{config:?} started");
        };
        assert_eq!(error, expected, "{config:?}");
        assert_eq!(budget, EngineBudget::new(1 << 26));
    }
}

/// Each reserved fill holds two lease credits, the publisher's and its
/// terminal read right's. A lease limit of twice the PUT cap starts the
/// owner, so the fill records hold that many fills and the lease limit alone
/// decides below it: one credit short of two per fill, and one credit per
/// fill, each refuse `FillCapacity` naming half the lease limit, with the
/// budget and the storage unchanged and the bundle whole.
#[test]
fn a_lease_limit_below_the_put_cap_refuses_start() {
    let puts = OWNER.put.puts as usize;
    assert!(puts > 0, "the owner serves PUTs");
    let refused = |lease_limit: usize| {
        Err(OwnerError::FillCapacity {
            puts: OWNER.put.puts,
            capacity: lease_limit / 2,
        })
    };
    for (lease_limit, expected) in [
        (2 * puts, Ok(())),
        (2 * puts - 1, refused(2 * puts - 1)),
        (puts, refused(puts)),
    ] {
        assert_eq!(
            start_or_retry(&storage_leasing(lease_limit), OWNER),
            expected,
            "a lease limit of {lease_limit}"
        );
    }
}

/// [`storage_watched`] at the structural floor of [`OWNER`]'s PUTs, `T`
/// the largest charge, less `below` units, and that floor.
fn floored(below: u64) -> (Storage<TestPlatform>, u64) {
    assert_eq!(
        OWNER.put.puts, PUTS,
        "the default watermarks cover the owner's PUTs"
    );
    let mut floor = 0;
    let storage = storage_watched(|marks| {
        floor = marks.low_units;
        Some(VolumeWatermarks {
            low_units: marks.low_units - below,
            ..marks
        })
    });
    (storage, floor)
}

/// Starts an owner under `config` over `storage`'s volume serving two
/// peers. A refusal comes back with the budget and the storage unchanged,
/// and an owner without PUTs starts over the bundle it returned, so the
/// refusal handed the bundle back whole.
fn start_or_retry(storage: &Storage<TestPlatform>, config: OwnerConfig) -> Result<(), OwnerError> {
    let buffers = arena(8);
    let receive = pool();
    let mut device = Device::new(storage, &buffers);
    publish(storage, &mut device, &key(1), 0, &payload(1000, 1));
    let domain = storage.domain_report();
    let (_end, first, _net) = network(64, 8384, 92, [Faults::default(); 2]);
    let (_other, second, _net2) = network(64, 8384, 93, [Faults::default(); 2]);
    let ends = vec![first, second];
    let refusing = start_refusing(
        device,
        storage,
        &receive,
        ends,
        (config, &PRINCIPALS),
        super::auth::os_entropy,
    );
    let Err((refused, mut budget)) = refusing else {
        return Ok(());
    };
    assert_eq!(budget, EngineBudget::new(1 << 26), "{:?}", refused.error);
    assert_eq!(storage.domain_report(), domain, "{:?}", refused.error);
    let entries = entries();
    let keys = keys(&entries, &PRINCIPALS);
    let Refused {
        error,
        bundle,
        transport,
    } = *refused;
    let retried = Owner::start(PUTLESS, bundle, keys, transport, &receive, &mut budget);
    assert!(retried.is_ok(), "the returned bundle starts: {error:?}");
    Err(error)
}

/// [`OWNER`] with no PUTs.
const PUTLESS: OwnerConfig = OwnerConfig {
    put: PutConfig {
        puts: 0,
        peer_puts: 0,
        ..OWNER.put
    },
    ..OWNER
};

/// An owner with PUTs starts at `low_units` equal to the structural floor
/// of its PUTs and refuses one unit below it, naming both values, with the
/// budget and the storage unchanged and the bundle whole.
#[test]
fn an_owner_with_puts_starts_at_the_structural_floor_and_refuses_one_unit_below() {
    let (at, floor) = floored(0);
    assert_eq!(start_or_retry(&at, OWNER), Ok(()));
    let (below, _) = floored(1);
    assert_eq!(
        start_or_retry(&below, OWNER),
        Err(OwnerError::WatermarkFloor {
            low_units: floor - 1,
            floor: Ok(floor),
        })
    );
}

/// Start takes the floor check after the fill-capacity check and before
/// the GET-reserve check: below the floor, a PUT cap over the fill records
/// still refuses `FillCapacity`, and a zero GET reserve refuses
/// `WatermarkFloor`.
#[test]
fn the_floor_check_runs_after_fill_capacity_and_before_the_get_reserve() {
    let over = OwnerConfig {
        put: PutConfig {
            puts: 3,
            ..OWNER.put
        },
        ..OWNER
    };
    assert_eq!(
        start_or_retry(&floored(1).0, over),
        Err(OwnerError::FillCapacity {
            puts: 3,
            capacity: 2,
        })
    );
    let unreserved = OwnerConfig {
        get_reserve: 0,
        ..OWNER
    };
    let (below, floor) = floored(1);
    assert_eq!(
        start_or_retry(&below, unreserved),
        Err(OwnerError::WatermarkFloor {
            low_units: floor - 1,
            floor: Ok(floor),
        })
    );
}

/// An undefined floor refuses an owner with PUTs: a retired allowance
/// whose sum with the floor's other terms passes `u64::MAX` names the
/// floor method's error. An owner without PUTs below the floor, and an
/// owner with PUTs over storage without watermarks, start.
#[test]
fn an_undefined_floor_refuses_and_an_owner_without_puts_or_watermarks_starts() {
    let mut low_units = 0;
    let unbounded = storage_watched(|marks| {
        low_units = marks.low_units;
        Some(VolumeWatermarks {
            retired_units: u64::MAX,
            ..marks
        })
    });
    assert_eq!(
        start_or_retry(&unbounded, OWNER),
        Err(OwnerError::WatermarkFloor {
            low_units,
            floor: Err(crate::storage::ConfigError::FloorOverflow {
                promises: OWNER.put.puts,
            }),
        })
    );
    let under_its_own = storage_watched(|marks| {
        let largest = marks.retired_units;
        Some(VolumeWatermarks {
            low_units: marks.low_units - 2 * largest,
            retired_units: 2 * largest,
            ..marks
        })
    });
    assert_eq!(start_or_retry(&under_its_own, PUTLESS), Ok(()));
    let unwatched = storage_watched(|_| None);
    assert_eq!(start_or_retry(&unwatched, OWNER), Ok(()));
}

#[test]
fn a_floor_above_the_placeable_ceiling_refuses_an_owner_with_puts() {
    let payload_units = FIXTURE.units as u64;
    let (mut low_units, mut floor) = (0, 0);
    let exceeding = storage_watched(|marks| {
        (low_units, floor) = (
            marks.low_units,
            marks.low_units - marks.retired_units + payload_units,
        );
        Some(VolumeWatermarks {
            retired_units: payload_units,
            ..marks
        })
    });
    let ceiling = exceeding.domain_report().unwrap().placeable_units;
    assert!(
        ceiling < floor,
        "the empty volume holds {ceiling} placeable units"
    );
    assert_eq!(
        start_or_retry(&exceeding, OWNER),
        Err(OwnerError::WatermarkFloor {
            low_units,
            floor: Err(crate::storage::ConfigError::FloorExceedsCeiling { floor, ceiling }),
        })
    );
}

#[test]
fn a_cancel_before_data_ends_the_attempt_and_retains_its_terminal() {
    scene(&PRINCIPALS, |mut scene| {
        let at = request(1, 1);
        let serial = scene.begin(1, at, 5);
        let header = scene.frame(1, Kind::PutCancel, at, 5, cancel(serial));
        assert_eq!(error(&scene.one(1, &header)), Some(Status::Cancelled));
        assert_eq!(scene.live(), 0);
        let again = scene.frame(1, Kind::PutCancel, at, 5, cancel(serial));
        assert_eq!(error(&scene.one(1, &again)), Some(Status::Cancelled));
        let late = scene.frame(1, Kind::PutPrepare, at, 5, prepare(serial, 100, 60_000));
        assert_eq!(error(&scene.one(1, &late)), Some(Status::Cancelled));
        assert_eq!(scene.live(), 0);
    });
}

/// A turn that unwinds inside a PUT's reservation takes the record's stage with it. The record's next frame ends it with `UnknownOutcome`: the owner holds no attempt to replay authority for and no fill to make READY.
#[test]
fn an_unwound_stage_ends_the_put_on_its_next_frame() {
    scene(&PRINCIPALS, |mut scene| {
        let at = request(1, 1);
        let serial = scene.begin(1, at, 5);
        let header = scene.frame(1, Kind::PutPrepare, at, 5, prepare(serial, 100, 60_000));
        INTERPOSE_BEFORE_REVALIDATION.with(|hook| {
            hook.set(Some(|_| {
                std::panic::resume_unwind(Box::new("the reservation unwound"))
            }));
        });
        let unwound =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| scene.send(1, &header)));
        assert!(unwound.is_err(), "the reservation unwound the turn");
        assert!(scene.owner.poisoned());
        assert_eq!(scene.live(), 1, "the record outlives the unwind");
        let again = scene.frame(1, Kind::PutBegin, at, 5, |_| {});
        assert_eq!(error(&scene.one(1, &again)), Some(Status::UnknownOutcome));
        assert_eq!(scene.live(), 0);
        let late = scene.frame(1, Kind::PutPrepare, at, 5, prepare(serial, 100, 60_000));
        assert_eq!(error(&scene.one(1, &late)), Some(Status::UnknownOutcome));
    });
}

/// Polls the owner once with the simulated driver's next submit unwinding,
/// and requires that unwind and the owner's poison; any other unwind resumes.
fn unwound_write_submit(scene: &mut Scene<'_, '_>) {
    scene.control.unwind_next(Some(Unwind::Submit));
    let now = scene.turn * 100;
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| scene.owner.poll(now)));
    scene.control.unwind_next(None);
    scene.turn += 1;
    match unwound {
        Ok(()) => panic!("the write submit unwound the turn"),
        Err(payload) if payload.downcast_ref::<&str>() == Some(&"the driver unwound") => {}
        Err(payload) => std::panic::resume_unwind(payload),
    }
    assert!(scene.owner.poisoned());
}

/// A turn that unwinds retrying an upload's staged final segment, with no
/// new DATA, takes the upload's stage with it as a fragment's receive does:
/// later turns return, and the next PREPARE ends the upload with
/// `UnknownOutcome` and its key unpublished.
/// The unwinding turn drops the upload's fill, which returns its two lease credits.
#[test]
fn a_turn_after_an_unwound_final_segment_retry_returns_and_ends_the_upload_unknown() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(100, 25);
        let credits = scene.storage.lease_report().unwrap().reserved;
        let (at, serial) = ready_upload(&mut scene, &object);
        let (zero, body) = scene.fragment(at, serial, &object, 0);
        for _ in 0..2 {
            scene.control.refuse_next(SubmitRefusal {
                reason: RefusalReason::QueueFull,
                code: None,
            });
        }
        scene.inject_edited(1, &zero, &body, |_| {});
        scene.polls(1);
        assert_eq!(scene.owner.put_report().receive_waits, 1);
        assert_eq!(scene.owner.put_ready_lanes(), [(0, 0)]);
        assert_eq!(
            scene.storage.lease_report().unwrap().reserved,
            credits + 2,
            "the ready upload's fill holds its two credits"
        );
        unwound_write_submit(&mut scene);
        assert_eq!(scene.live(), 1, "the record outlives the unwind");
        scene.turns(4);
        assert_eq!(scene.owner.put_ready_lanes(), []);
        scene.replies(1);
        let prepare = scene.frame(
            1,
            Kind::PutPrepare,
            at,
            5,
            prepare(serial, object.len() as u32, 60_000),
        );
        assert_eq!(error(&scene.one(1, &prepare)), Some(Status::UnknownOutcome));
        assert_eq!(scene.live(), 0);
        assert_eq!(
            scene.storage.lease_report().unwrap().reserved,
            credits,
            "the unwound receive dropped the fill, which returned its credits"
        );
        assert!(!scene.visible(5));
    });
}

/// A turn that unwinds in the device submit of an upload's write takes the
/// upload's stage with it: the owner's later turns return with no ready
/// upload whose held count differs from its lane ring, a resent DATA finds
/// no ready upload to take it, the upload's next PREPARE ends it with
/// `UnknownOutcome`, and its key stays unpublished.
/// The unwinding turn drops the upload's fill, which returns its two lease credits.
#[test]
fn a_turn_after_an_unwound_write_submit_returns_and_ends_the_upload_unknown() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(2 * FRAGMENT_LEN as usize, 63);
        let credits = scene.storage.lease_report().unwrap().reserved;
        let (at, serial) = ready_upload(&mut scene, &object);
        assert_eq!(scene.owner.put_ready_lanes(), [(0, 0)]);
        let (ahead, body) = scene.fragment(at, serial, &object, 1);
        scene.inject_edited(1, &ahead, &body, |_| {});
        scene.polls(1);
        assert_eq!(
            scene.owner.put_ready_lanes(),
            [(1, 1)],
            "the fragment past the hole waits in the ring"
        );
        let (header, body) = scene.fragment(at, serial, &object, 0);
        scene.inject_edited(1, &header, &body, |_| {});
        assert_eq!(
            scene.storage.lease_report().unwrap().reserved,
            credits + 2,
            "the ready upload's fill holds its two credits"
        );
        unwound_write_submit(&mut scene);
        assert_eq!(scene.live(), 1, "the record outlives the unwind");
        scene.turns(4);
        assert_eq!(
            scene.owner.put_ready_lanes(),
            [],
            "the unwound upload left its ready stage"
        );
        scene.replies(1);
        let (again, body) = scene.fragment(at, serial, &object, 0);
        assert!(scene.put_data(&again, &body).is_empty());
        assert_eq!(scene.live(), 1, "the resent DATA leaves the record");
        let prepare = scene.frame(
            1,
            Kind::PutPrepare,
            at,
            5,
            prepare(serial, object.len() as u32, 60_000),
        );
        assert_eq!(error(&scene.one(1, &prepare)), Some(Status::UnknownOutcome));
        assert_eq!(scene.live(), 0);
        assert_eq!(
            scene.storage.lease_report().unwrap().reserved,
            credits,
            "the unwound receive dropped the fill, which returned its credits"
        );
        assert!(!scene.visible(5));
    });
}

/// A turn that unwinds in the device submit of an empty object's header
/// segment, the write its priming receive makes, takes the upload's stage
/// with it as a ready upload's receive does: later turns return and answer
/// nothing for the upload, its next PREPARE ends it with `UnknownOutcome`,
/// and its key stays unpublished.
/// The unwinding turn drops the upload's fill, which returns its two lease credits.
#[test]
fn a_turn_after_an_unwound_priming_submit_returns_and_ends_the_upload_unknown() {
    scene(&PRINCIPALS, |mut scene| {
        let credits = scene.storage.lease_report().unwrap().reserved;
        let at = request(1, 1);
        let serial = scene.begin(1, at, 5);
        let header = scene.frame(1, Kind::PutPrepare, at, 5, prepare(serial, 0, 60_000));
        scene.inject(1, &header);
        unwound_write_submit(&mut scene);
        assert_eq!(scene.live(), 1, "the record outlives the unwind");
        scene.turns(4);
        let later: Vec<_> = scene.replies(1).iter().map(error).collect();
        assert_eq!(
            later,
            [],
            "later turns answer nothing for the upload the unwind left without a stage"
        );
        let again = scene.frame(1, Kind::PutPrepare, at, 5, prepare(serial, 0, 60_000));
        assert_eq!(error(&scene.one(1, &again)), Some(Status::UnknownOutcome));
        assert_eq!(scene.live(), 0);
        assert_eq!(
            scene.storage.lease_report().unwrap().reserved,
            credits,
            "the unwound receive dropped the fill, which returned its credits"
        );
        assert!(!scene.visible(5));
    });
}

#[test]
fn session_replacement_retires_put_evidence() {
    scene(&PRINCIPALS, |mut scene| {
        let at = request(1, 1);
        let serial = scene.begin(1, at, 5);
        assert_eq!(scene.live(), 1);
        scene.reopen(1);
        assert_eq!(scene.live(), 0, "the replaced session's PUT ended");
        let header = scene.frame(1, Kind::PutPrepare, at, 5, prepare(serial, 100, 60_000));
        assert_eq!(error(&scene.one(1, &header)), Some(Status::UnknownOutcome));
        assert_eq!(scene.live(), 0);
    });
}

#[test]
fn a_published_empty_object_replays_until_its_window_ends() {
    scene(&PRINCIPALS, |mut scene| {
        let at = request(1, 1);
        let begin = scene.frame(1, Kind::PutBegin, at, 5, |header| header.remaining_ms = 10);
        let serial = scene.one(1, &begin).allocation;
        let before = scene.owner.volume_report().writes_submitted;
        let header = scene.frame(1, Kind::PutPrepare, at, 5, prepare(serial, 0, 60_000));
        let replies = scene.send(1, &header);
        let kinds: Vec<_> = replies.iter().map(|reply| reply.kind).collect();
        assert_eq!(kinds, [Kind::PutReady, Kind::PutResult]);
        assert_eq!((replies[0].grant, replies[1].allocation), (0, serial));
        assert_eq!(scene.live(), 0);
        let writes = scene.owner.volume_report().writes_submitted;
        assert_eq!(writes, before + 1, "the header's one write");
        let mut budget = WorkBudget::new(1 << 12);
        scene.owner.invalidate(&key(5), 4, &mut budget).unwrap();
        let resent = scene.frame(1, Kind::PutPrepare, at, 5, prepare(serial, 0, 60_000));
        assert_eq!(
            scene.one(1, &resent).kind,
            Kind::PutResult,
            "success outlives invalidation"
        );
        assert_eq!(scene.owner.volume_report().writes_submitted, writes);
        let unbegun = scene.frame(1, Kind::PutPrepare, request(2, 1), 5, prepare(9, 0, 60_000));
        assert_eq!(error(&scene.one(1, &unbegun)), Some(Status::UnknownOutcome));
        scene.turns((OWNER.serve.linger_us + 10_000) / 100 + 1);
        let expired = scene.frame(1, Kind::PutPrepare, at, 5, prepare(serial, 0, 60_000));
        assert_eq!(error(&scene.one(1, &expired)), Some(Status::UnknownOutcome));
        let older = scene.frame(1, Kind::PutBegin, request(1, 0), 5, |_| {});
        assert_eq!(error(&scene.one(1, &older)), Some(Status::UnknownOutcome));
        assert_eq!(scene.live(), 0);
        assert_eq!(scene.owner.volume_report().writes_submitted, writes);
    });
}

#[test]
fn the_progress_scan_visits_only_waiting_puts() {
    scene(&PRINCIPALS, |mut scene| {
        let held = request(1, 1);
        let serial = scene.begin(0, held, 5);
        let header = scene.frame(0, Kind::PutPrepare, held, 5, prepare(serial, 100, 60_000));
        assert_eq!(scene.one(0, &header).kind, Kind::PutReady);
        let at = request(1, 1);
        let serial = scene.begin(1, at, 6);
        let header = scene.frame(1, Kind::PutPrepare, at, 6, prepare(serial, 0, 60_000));
        scene.inject(1, &header);
        scene.polls(1);
        let kinds: Vec<_> = scene.replies(1).iter().map(|reply| reply.kind).collect();
        assert_eq!(kinds, [Kind::PutReady], "the header write is outstanding");
        assert_eq!(scene.live(), 2);
        take_progress_visits();
        scene.polls(5);
        assert_eq!(
            take_progress_visits(),
            5,
            "each turn visits the waiting PUT and skips the primed one"
        );
        scene.turns(2);
        let kinds: Vec<_> = scene.replies(1).iter().map(|reply| reply.kind).collect();
        assert_eq!(kinds, [Kind::PutResult]);
        // The visits across the two turns depend on whether a turn's device
        // tick precedes its owner poll; the listed order publishes in one
        // visit.
        let visits = take_progress_visits();
        if crate::sim::round::legacy() {
            assert_eq!(visits, 1, "the publishing turn's one visit");
        }
        scene.polls(3);
        assert_eq!(take_progress_visits(), 0, "nothing waits after the publish");
        assert_eq!(scene.live(), 1, "the primed PUT stays");
    });
}

#[test]
fn renumbering_the_admission_order_keeps_a_waiting_upload_first() {
    scene(&PRINCIPALS, |mut scene| {
        let first = request(1, 1);
        let begun = scene.begin(0, first, 39);
        let header = scene.frame(0, Kind::PutCancel, first, 39, cancel(begun));
        assert_eq!(error(&scene.one(0, &header)), Some(Status::Cancelled));
        let object = payload(FRAGMENT_LEN as usize, 29);
        let (at, serial) = ready_upload(&mut scene, &object);
        let (header, body) = scene.fragment(at, serial, &object, 0);
        scene.inject_edited(1, &header, &body, |_| {});
        scene.polls(3);
        let held = super::adapters::written_commands(
            scene.owner.volume_bound(),
            &scene.control.capture(),
            serial,
        );
        assert_eq!(held.len(), 1, "the upload's one write is at the device");
        scene
            .control
            .hold(crate::storage::CommandToken::from_raw(held[0].token));
        let upload = scene.owner.put_admission_order();
        assert_eq!(upload.len(), 1);
        take_renumberings();
        for n in 0..16u8 {
            let other = request(1, u64::from(n) + 2);
            let begun = scene.begin(0, other, 40 + n);
            let header = scene.frame(0, Kind::PutCancel, other, 40 + n, cancel(begun));
            assert_eq!(error(&scene.one(0, &header)), Some(Status::Cancelled));
        }
        assert!(take_renumberings() >= 2, "the begins renumbered the order");
        let last = request(1, 18);
        let begun = scene.begin(0, last, 60);
        let order = scene.owner.put_admission_order();
        assert_eq!(order.len(), 2);
        assert_eq!(order[0], upload[0], "the upload stays first: {order:?}");
        let header = scene.frame(0, Kind::PutCancel, last, 60, cancel(begun));
        assert_eq!(error(&scene.one(0, &header)), Some(Status::Cancelled));
        take_progress_visits();
        scene.polls(1);
        assert_eq!(take_progress_visits(), 1, "the upload still waits");
        scene
            .control
            .release(crate::storage::CommandToken::from_raw(held[0].token));
        scene.turns(10);
        let kinds: Vec<_> = scene.replies(1).iter().map(|reply| reply.kind).collect();
        assert!(kinds.contains(&Kind::PutResult), "{kinds:?}");
        assert_eq!(scene.live(), 0);
    });
}

/// Once a progress visit has read the fill of an upload whose every unit is at the device, the later turns visit the upload and read no fill until one of its commands ends. The turn that applies the terminal reads the fill, and the upload publishes.
#[test]
fn a_fully_submitted_fill_is_read_again_only_after_one_of_its_commands_ends() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(FRAGMENT_LEN as usize, 25);
        let (at, serial) = ready_upload(&mut scene, &object);
        let (header, body) = scene.fragment(at, serial, &object, 0);
        scene.inject_edited(1, &header, &body, |_| {});
        // The polls leave the disk untouched, so the upload's one write stays at the device.
        scene.polls(3);
        let report = scene.owner.volume_report();
        assert_eq!(report.writes_submitted - report.writes_done, 1);
        take_progress_visits();
        take_fill_reads();
        scene.polls(5);
        assert_eq!(take_progress_visits(), 5, "each turn visits the upload");
        assert_eq!(
            take_fill_reads(),
            0,
            "no command ended, so no turn reads the fill"
        );
        scene.turns(2);
        assert!(take_fill_reads() >= 1, "the terminal's turn reads the fill");
        let kinds: Vec<_> = scene.replies(1).iter().map(|reply| reply.kind).collect();
        assert!(kinds.contains(&Kind::PutResult), "{kinds:?}");
    });
}

/// An upload whose every unit is at the device fails in the first turn whose deadline sample lies past the serving window, while the machine still serves under the same tenure and none of the upload's commands ended.
#[test]
fn a_fully_submitted_upload_fails_in_the_turn_its_token_stops_admitting_fills() {
    scene(&PRINCIPALS, |mut scene| {
        let time = Rc::new(std::cell::Cell::new(0));
        scene
            .owner
            .set_serving_clock(Box::new(crate::storage::volume_fixture::ServingTime(
                Rc::clone(&time),
            )));
        let object = payload(FRAGMENT_LEN as usize, 26);
        let (at, serial) = ready_upload(&mut scene, &object);
        let (header, body) = scene.fragment(at, serial, &object, 0);
        scene.inject_edited(1, &header, &body, |_| {});
        scene.polls(5);
        let report = scene.owner.volume_report();
        assert_eq!(report.writes_submitted - report.writes_done, 1);
        let serving = scene.owner.authority_report();
        let failed = scene.owner.put_report().failed_other;
        time.set(u64::MAX);
        scene.polls(1);
        let report = scene.owner.authority_report();
        assert_eq!(
            (report.state, report.tenure),
            (crate::failover::serving::State::Serving, serving.tenure),
            "the machine serves under the same tenure"
        );
        assert_eq!(
            scene.owner.put_report().failed_other,
            failed + 1,
            "the upload fails in the turn its token stops admitting fills"
        );
    });
}

/// An empty object has no write, so its PREPARE is followed at once by its
/// publication. The PREPARE arrives with the storage clock at 2.5 s and a
/// TTL of one second: the storage's deadline is 3.5 s rounded down to 3 s.
/// A publication at 2.9 s ends with one PUT RESULT and a GET completes with
/// no byte; one at 3.2 s or 10 s ends with one PUT ERROR `Expired`, counts a
/// failed publication and none published, and a GET ends `Missing`. Either
/// way the PUT record is released.
#[test]
fn the_storage_deadline_rounds_down_to_whole_seconds() {
    use super::fetch::Outcome;
    let clocks = [
        (2_900_000_000, true),
        (3_200_000_000, false),
        (10_000_000_000, false),
    ];
    for (late, published) in clocks {
        scene(&PRINCIPALS, |mut scene| {
            let at = request(1, 1);
            let serial = scene.begin(1, at, 5);
            set_clock(scene.storage, &[Some(2_500_000_000)]);
            let header = scene.frame(1, Kind::PutPrepare, at, 5, prepare(serial, 0, 1_000));
            scene.inject(1, &header);
            scene.turns(1);
            set_clock(scene.storage, &[Some(late)]);
            scene.turns(4);
            let mut replies = scene.replies(1);
            let last = replies.last().expect("a terminal");
            if published {
                assert_eq!(last.kind, Kind::PutResult, "{replies:?}");
            } else {
                assert_eq!(error(last), Some(Status::Expired), "{replies:?}");
            }
            scene.turns(4);
            replies.extend(scene.replies(1));
            let terminals = replies
                .iter()
                .filter(|reply| matches!(reply.kind, Kind::PutResult | Kind::PutError))
                .count();
            assert_eq!(terminals, 1, "clock {late}: one terminal: {replies:?}");
            let report = scene.owner.put_report();
            assert_eq!(
                (scene.live(), report.published, report.failed_publish),
                (0, u64::from(published), u64::from(!published)),
                "clock {late}"
            );
            let (outcome, bytes) = scene.read(0, 5, 0);
            let read = if published {
                Outcome::Complete
            } else {
                Outcome::Missing
            };
            assert_eq!((outcome, bytes.len()), (Some(read), 0), "clock {late}");
        });
    }
}

#[test]
fn an_idle_authority_times_out_and_retains_the_timeout() {
    scene(&PRINCIPALS, |mut scene| {
        let at = request(1, 1);
        let begin = scene.frame(1, Kind::PutBegin, at, 5, |header| header.remaining_ms = 5);
        let serial = scene.one(1, &begin).allocation;
        scene.turns(60);
        let replies = scene.replies(1);
        assert_eq!(replies.len(), 1, "{replies:?}");
        assert_eq!(error(&replies[0]), Some(Status::TimedOut));
        assert_eq!(scene.live(), 0);
        let late = scene.frame(1, Kind::PutPrepare, at, 5, prepare(serial, 100, 60_000));
        assert_eq!(error(&scene.one(1, &late)), Some(Status::TimedOut));
    });
}

#[test]
fn a_shorter_begin_replay_moves_the_deadline() {
    scene(&PRINCIPALS, |mut scene| {
        let at = request(1, 1);
        let begin = scene.frame(1, Kind::PutBegin, at, 5, |header| {
            header.remaining_ms = 20_000
        });
        scene.one(1, &begin);
        let shorter = scene.frame(1, Kind::PutBegin, at, 5, |header| header.remaining_ms = 5);
        assert_eq!(scene.one(1, &shorter).kind, Kind::PutAuthority);
        let longer = scene.frame(1, Kind::PutBegin, at, 5, |header| {
            header.remaining_ms = 30_000
        });
        assert_eq!(scene.one(1, &longer).kind, Kind::PutAuthority);
        scene.turns(60);
        let replies = scene.replies(1);
        assert_eq!(replies.len(), 1, "{replies:?}");
        assert_eq!(error(&replies[0]), Some(Status::TimedOut));
        assert_eq!(scene.live(), 0);
    });
}

#[test]
fn a_duplicate_prepare_keeps_the_sampled_expiry() {
    scene(&PRINCIPALS, |mut scene| {
        let at = request(1, 1);
        let serial = scene.begin(1, at, 5);
        set_clock(scene.storage, &[Some(2_500_000_000)]);
        let first = scene.frame(1, Kind::PutPrepare, at, 5, prepare(serial, 0, 1_000));
        scene.inject(1, &first);
        scene.polls(2);
        set_clock(scene.storage, &[Some(3_100_000_000)]);
        let again = scene.frame(1, Kind::PutPrepare, at, 5, prepare(serial, 0, 1_000));
        scene.inject(1, &again);
        scene.polls(2);
        set_clock(scene.storage, &[Some(3_200_000_000)]);
        scene.turns(4);
        let replies = scene.replies(1);
        let kinds: Vec<_> = replies.iter().map(|reply| reply.kind).collect();
        assert_eq!(kinds, [Kind::PutReady, Kind::PutReady, Kind::PutError]);
        assert_eq!(error(&replies[2]), Some(Status::Expired));
    });
}

#[test]
fn a_zero_ttl_prepare_drops_at_parse_and_keeps_the_attempt() {
    scene(&PRINCIPALS, |mut scene| {
        let at = request(1, 1);
        let serial = scene.begin(1, at, 5);
        let dropped = scene.owner.report().dropped;
        let zero = scene.frame(1, Kind::PutPrepare, at, 5, prepare(serial, 100, 1));
        scene.inject_edited(1, &zero, &[], |bytes| {
            bytes[124..128].fill(0);
            reseal(bytes);
        });
        scene.turns(4);
        assert!(scene.replies(1).is_empty());
        assert_eq!(scene.owner.report().dropped, dropped + 1);
        assert_eq!(scene.live(), 1);
        let valid = scene.frame(1, Kind::PutPrepare, at, 5, prepare(serial, 100, 1_000));
        assert_eq!(scene.one(1, &valid).kind, Kind::PutReady);
    });
}

#[test]
fn a_begin_the_namespace_refuses_repeats_its_refusal() {
    scene(&PRINCIPALS, |mut scene| {
        scene.sequences[1] += 1;
        let get = Header {
            request: request(1, 1),
            sequence: scene.sequences[1],
            key: key(1),
            ..scene.templates[1]
        };
        scene.inject(1, &get);
        scene.polls(2);
        assert_eq!(scene.live(), 1, "the GET holds wire slot 1");
        for _ in 0..2 {
            let busy = scene.frame(1, Kind::PutBegin, request(1, 2), 5, |_| {});
            let replies = scene.send(1, &busy);
            let put: Vec<_> = replies.iter().filter_map(error).collect();
            assert_eq!(put, [Status::RequestPressure]);
        }
        let report = scene.owner.put_report();
        assert_eq!(
            (report.refused_live, report.refused_namespace),
            (0, 2),
            "the namespace, not the PUT capacity, refused: {report:?}"
        );
        assert_eq!(
            scene.begin(0, request(1, 1), 5),
            scene.begin(0, request(1, 1), 5)
        );
    });
}

#[test]
fn typed_refusals_precede_admission_and_a_wrong_serial_conflicts() {
    scene(&PRINCIPALS, |mut scene| {
        let last = request(1, crate::net::GENERATION_LIMIT);
        let exhausted = scene.frame(1, Kind::PutBegin, last, 5, |_| {});
        assert_eq!(
            error(&scene.one(1, &exhausted)),
            Some(Status::CounterExhausted)
        );
        let outside = scene.frame(1, Kind::PutBegin, request(4, 1), 5, |_| {});
        assert_eq!(error(&scene.one(1, &outside)), Some(Status::InvalidRequest));
        assert_eq!(scene.live(), 0);
        let serial = scene.begin(1, request(1, 1), 5);
        let wrong = scene.frame(1, Kind::PutCancel, request(1, 1), 5, cancel(serial + 1));
        assert_eq!(
            error(&scene.one(1, &wrong)),
            Some(Status::ConflictingRequest)
        );
        assert_eq!(scene.live(), 1);
    });
}

#[test]
fn a_session_slot_cap_below_the_namespace_width_refuses_the_begin() {
    let config = OwnerConfig {
        serve: ServeConfig {
            slots: 8,
            ..OWNER.serve
        },
        ..OWNER
    };
    scene_with(config, &PRINCIPALS, |mut scene| {
        let beyond = scene.frame(1, Kind::PutBegin, request(5, 1), 5, |_| {});
        assert_eq!(error(&scene.one(1, &beyond)), Some(Status::InvalidRequest));
        assert_eq!(scene.live(), 0);
    });
}

#[test]
fn a_peer_whose_share_gets_hold_refuses_the_begin_and_leaves_the_key_free() {
    scene(&PRINCIPALS, |mut scene| {
        for slot in [1, 2] {
            scene.sequences[1] += 1;
            let get = Header {
                request: request(slot, 1),
                sequence: scene.sequences[1],
                key: key(1),
                ..scene.templates[1]
            };
            scene.inject(1, &get);
        }
        scene.polls(2);
        assert_eq!(scene.live(), 2, "the peer's GETs hold its share");
        for _ in 0..2 {
            let begin = scene.frame(1, Kind::PutBegin, request(3, 1), 5, |_| {});
            let replies = scene.send(1, &begin);
            let put: Vec<_> = replies.iter().filter_map(error).collect();
            assert_eq!(put, [Status::RequestPressure]);
        }
        scene.begin(0, request(1, 1), 5);
    });
}

/// The owner's admission state: its live requests, the PUT occupancy and the
/// BEGINs that acquired fill authority.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Admission {
    live: u32,
    occupancy: Occupancy,
    begun: u64,
}

fn admission(scene: &Scene<'_, '_>) -> Admission {
    Admission {
        live: scene.live(),
        occupancy: scene.owner.put_occupancy(),
        begun: scene.owner.put_report().begun,
    }
}

/// How long a cancelled upload drains before the next frame.
#[derive(Debug, Clone, Copy)]
enum Drain {
    /// Twenty turns.
    Turns,
    /// Single turns, at most 64, up to the first that leaves no live request
    /// and no live PUT: the next frame arrives as soon as the share is free.
    Released,
}

/// Peer 1 holds its one PUT with an upload of key 5 on wire slot 1. With
/// `refuse`, a BEGIN of `identity` for key 6 beside it is refused
/// `RequestPressure`, counts once under the peer's share and changes no
/// admission state. The upload is cancelled and drains by `drain`, which
/// ends the cause of the refusal. Returns the reply to the BEGIN of
/// `identity` sent after the drain, with the admission state it arrived at.
fn begin_after_release(
    scene: &mut Scene<'_, '_>,
    identity: u64,
    refuse: bool,
    drain: Drain,
) -> (Header, Admission) {
    let holder = scene.begin(1, request(1, 1), 5);
    let held = admission(scene);
    assert_eq!(held.live, 1, "the upload is the one live request");
    let share = scene.owner.put_report().refused_peer_share;
    if refuse {
        let beside = scene.frame(1, Kind::PutBegin, identity, 6, |_| {});
        assert_eq!(error(&scene.one(1, &beside)), Some(Status::RequestPressure));
    }
    assert_eq!(
        scene.owner.put_report().refused_peer_share - share,
        u64::from(refuse),
        "the peer's share is the cause of the refusal"
    );
    assert_eq!(
        admission(scene),
        held,
        "the refusal left the live requests, the PUT occupancy and the BEGINs begun unchanged"
    );
    let stop = scene.frame(1, Kind::PutCancel, request(1, 1), 5, cancel(holder));
    assert_eq!(error(&scene.one(1, &stop)), Some(Status::Cancelled));
    match drain {
        Drain::Turns => scene.turns(20),
        Drain::Released => {
            for _ in 0..64 {
                if scene.live() == 0 && scene.owner.put_occupancy().live == 0 {
                    break;
                }
                scene.turns(1);
            }
        }
    }
    let drained = admission(scene);
    assert_eq!(
        (drained.live, drained.occupancy.live, drained.begun),
        (0, 0, held.begun),
        "{drain:?}: the cancelled upload released its record and the share, and no BEGIN acquired authority"
    );
    let again = scene.frame(1, Kind::PutBegin, identity, 6, |_| {});
    (scene.one(1, &again), drained)
}

/// A BEGIN refused under the peer's PUT share settles its wire identity:
/// once the share frees, the same BEGIN resent replays the refusal and
/// admits no attempt, whether it arrives as soon as the share is free or
/// twenty turns after the cancel. A client that took the refusal as final
/// otherwise leaves an attempt holding the share, a lane and the key until
/// its deadline. The wire slot's next generation is admitted.
#[test]
fn a_refused_begin_resent_after_the_share_frees_replays_its_refusal() {
    for drain in [Drain::Turns, Drain::Released] {
        scene(&PRINCIPALS, |mut scene| {
            let (reply, drained) = begin_after_release(&mut scene, request(2, 1), true, drain);
            assert_eq!(
                (reply.kind, error(&reply)),
                (Kind::PutError, Some(Status::RequestPressure)),
                "{drain:?}: {reply:?}"
            );
            assert_eq!(
                admission(&scene),
                drained,
                "{drain:?}: the refused identity admits no attempt"
            );
            scene.begin(1, request(2, 2), 6);
            assert_eq!(
                (scene.live(), scene.owner.put_report().begun),
                (1, drained.begun + 1),
                "{drain:?}: the next generation is the one live request and the one new attempt"
            );
        });
    }
}

/// The same BEGIN first sent once the share is free is admitted, so the
/// resent BEGIN of
/// `a_refused_begin_resent_after_the_share_frees_replays_its_refusal` is
/// refused for its earlier refusal alone.
#[test]
fn a_begin_first_sent_after_the_share_frees_is_admitted() {
    scene(&PRINCIPALS, |mut scene| {
        let (reply, drained) =
            begin_after_release(&mut scene, request(2, 1), false, Drain::Released);
        assert_eq!(reply.kind, Kind::PutAuthority, "{reply:?}");
        assert_eq!(
            (scene.live(), scene.owner.put_report().begun),
            (1, drained.begun + 1),
            "the admitted BEGIN is the one live request and the one new attempt"
        );
    });
}

/// A BEGIN refused while a live upload still binds its wire slot settles
/// its identity with the refused generation alone: once that upload ends
/// and frees the slot, the same BEGIN resent is answered `UnknownOutcome`
/// and admits no attempt. The wire slot's next generation is admitted.
#[test]
fn a_begin_refused_on_a_bound_wire_slot_admits_no_attempt_after_the_slot_frees() {
    scene(&PRINCIPALS, |mut scene| {
        let (reply, drained) = begin_after_release(&mut scene, request(1, 2), true, Drain::Turns);
        assert_eq!(
            (reply.kind, error(&reply)),
            (Kind::PutError, Some(Status::UnknownOutcome)),
            "{reply:?}"
        );
        assert_eq!(
            admission(&scene),
            drained,
            "the refused identity admits no attempt"
        );
        scene.begin(1, request(1, 3), 6);
        assert_eq!(
            (scene.live(), scene.owner.put_report().begun),
            (1, drained.begun + 1),
            "the next generation is the one live request and the one new attempt"
        );
    });
}

/// The same BEGIN first sent once the upload freed the wire slot is
/// admitted, so the resent BEGIN of
/// `a_begin_refused_on_a_bound_wire_slot_admits_no_attempt_after_the_slot_frees`
/// is refused for its earlier refusal alone.
#[test]
fn a_begin_first_sent_after_the_wire_slot_frees_is_admitted() {
    scene(&PRINCIPALS, |mut scene| {
        let (reply, drained) = begin_after_release(&mut scene, request(1, 2), false, Drain::Turns);
        assert_eq!(reply.kind, Kind::PutAuthority, "{reply:?}");
        assert_eq!(
            (scene.live(), scene.owner.put_report().begun),
            (1, drained.begun + 1),
            "the admitted BEGIN is the one live request and the one new attempt"
        );
    });
}

/// A CANCEL or PREPARE that reaches the owner ahead of its BEGIN is
/// answered `UnknownOutcome` and settles the identity, so the BEGIN that
/// arrives after it admits no attempt the settled client would never drive.
#[test]
fn a_begin_behind_a_frame_answered_unknown_admits_no_attempt() {
    for kind in [Kind::PutCancel, Kind::PutPrepare] {
        for version in [0, 4] {
            scene(&PRINCIPALS, |scene| {
                begin_behind_unknown(scene, kind, version)
            });
        }
    }
}

/// `version` is the cache version the late BEGIN names.
fn begin_behind_unknown(mut scene: Scene<'_, '_>, kind: Kind, version: u64) {
    let early = match kind {
        Kind::PutCancel => scene.frame(1, kind, request(1, 1), 5, cancel(0)),
        _ => scene.frame(1, kind, request(1, 1), 5, prepare(7, 100, 60_000)),
    };
    assert_eq!(
        error(&scene.one(1, &early)),
        Some(Status::UnknownOutcome),
        "{version:?} {kind:?}"
    );
    let late = scene.frame(1, Kind::PutBegin, request(1, 1), 5, |header| {
        header.offset = version;
    });
    let reply = scene.one(1, &late);
    assert_eq!(
        (reply.kind, error(&reply)),
        (Kind::PutError, Some(Status::UnknownOutcome)),
        "{version:?} {kind:?}: {reply:?}"
    );
    assert_eq!(scene.live(), 0, "{version:?} {kind:?}");
    scene.begin(1, request(1, 2), 5);
}

/// A GET refused under its peer's request share settles its wire identity:
/// once the share frees, the same GET resent replays the refusal and starts
/// no read, so a client that took the refusal as final leaves no request on
/// the owner.
#[test]
fn a_refused_get_resent_after_the_share_frees_replays_its_refusal() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(2 * FRAGMENT_LEN as usize, 47);
        let (at, serial) = ready_upload(&mut scene, &object);
        for slot in [1, 2] {
            let parked = scene.get(0, request(slot, 1), 5);
            scene.inject(0, &parked);
        }
        scene.turns(4);
        assert_eq!(
            scene.owner.parked_count(),
            2,
            "both GETs park and hold the peer's share"
        );
        let answers = |scene: &mut Scene<'_, '_>| -> Vec<(Kind, Option<Status>)> {
            scene
                .sent(0)
                .iter()
                .filter(|header| header.request == request(3, 1))
                .map(|header| (header.kind, Status::from_wire(header.status)))
                .collect()
        };
        let refused = scene.get(0, request(3, 1), 5);
        scene.inject(0, &refused);
        scene.turns(4);
        assert_eq!(
            answers(&mut scene),
            [(Kind::Error, Some(Status::RequestPressure))]
        );
        let stop = scene.frame(1, Kind::PutCancel, at, 5, cancel(serial));
        scene.inject(1, &stop);
        scene.turns(40);
        let census = scene.owner.peer_census(PeerId(0));
        assert_eq!(
            census.active + census.draining,
            0,
            "the parked GETs ended and released the share"
        );
        let resent = scene.get(0, request(3, 1), 5);
        scene.inject(0, &resent);
        scene.turns(4);
        assert_eq!(
            answers(&mut scene),
            [(Kind::Error, Some(Status::RequestPressure))],
            "the refused identity replays its refusal"
        );
        let census = scene.owner.peer_census(PeerId(0));
        assert_eq!(census.active + census.draining, 0, "and starts no request");
    });
}

#[test]
fn an_ended_put_frees_its_key_for_a_later_begin() {
    scene(&PRINCIPALS, |mut scene| {
        let first = scene.begin(1, request(1, 1), 5);
        let ready = scene.frame(
            1,
            Kind::PutPrepare,
            request(1, 1),
            5,
            prepare(first, 100, 60_000),
        );
        assert_eq!(scene.one(1, &ready).kind, Kind::PutReady);
        let stop = scene.frame(1, Kind::PutCancel, request(1, 1), 5, cancel(0));
        assert_eq!(error(&scene.one(1, &stop)), Some(Status::Cancelled));
        scene.turns(20);
        let second = scene.begin(1, request(1, 2), 5);
        assert_ne!(second, first);
    });
}

pub(super) fn ready_upload(scene: &mut Scene<'_, '_>, object: &[u8]) -> (u64, u64) {
    let at = request(1, 1);
    (at, ready_upload_at(scene, at, 5, object))
}

fn ready_upload_at(scene: &mut Scene<'_, '_>, at: u64, name: u8, object: &[u8]) -> u64 {
    ready_upload_from(scene, 1, at, name, object)
}

pub(super) fn ready_upload_from(
    scene: &mut Scene<'_, '_>,
    peer: usize,
    at: u64,
    name: u8,
    object: &[u8],
) -> u64 {
    let serial = scene.begin(peer, at, name);
    let header = scene.frame(
        peer,
        Kind::PutPrepare,
        at,
        name,
        prepare(serial, object.len() as u32, 60_000),
    );
    let ready = scene.one(peer, &header);
    let count = FragmentGeometry::fragments(object.len() as u64) as u32;
    assert_eq!((ready.kind, ready.grant), (Kind::PutReady, count.min(4)));
    serial
}

fn acks(replies: &[Header]) -> Vec<(u32, u64, u32)> {
    replies
        .iter()
        .filter(|reply| reply.kind == Kind::PutAck)
        .map(|reply| (reply.index, reply.offset, reply.grant))
        .collect()
}

#[test]
fn reordered_duplicate_and_lost_fragments_reassemble_across_the_ring() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(6 * FRAGMENT_LEN as usize, 7);
        let (at, serial) = ready_upload(&mut scene, &object);
        let writes = scene.owner.volume_report().writes_submitted;
        let (one, body) = scene.fragment(at, serial, &object, 1);
        assert_eq!(acks(&scene.put_data(&one, &body)), [(0, 1, 4)]);
        let (zero, body) = scene.fragment(at, serial, &object, 0);
        let replies = scene.put_data(&zero, &body);
        assert_eq!(
            acks(&replies).last().map(|ack| (ack.0, ack.2)),
            Some((2, 6))
        );
        let (again, body) = scene.fragment(at, serial, &object, 0);
        assert_eq!(
            acks(&scene.put_data(&again, &body)).len(),
            1,
            "a consumed duplicate repeats the ACK"
        );
        let mut replies = Vec::new();
        for index in [3, 5, 2, 4, 5] {
            let (header, body) = scene.fragment(at, serial, &object, index);
            replies.extend(scene.put_data(&header, &body));
        }
        scene.turns(10);
        replies.extend(scene.replies(1));
        assert_eq!(acks(&replies).iter().map(|ack| ack.0).max(), Some(6));
        let results = replies.iter().filter(|reply| reply.kind == Kind::PutResult);
        assert_eq!(results.count(), 1, "{replies:?}");
        assert_eq!(scene.live(), 0);
        assert!(scene.owner.volume_report().writes_submitted > writes);
        assert_eq!(scene.fetch(5), object);
    });
}

/// Three PUT DATA frames of one receive batch authenticate through one pass of three chains, and the upload they complete publishes its bytes.
#[test]
fn three_data_frames_of_one_batch_authenticate_in_one_pass() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(3 * FRAGMENT_LEN as usize, 27);
        let (at, serial) = ready_upload(&mut scene, &object);
        super::owner::TRIPLED_DATA.with(|count| count.set(0));
        for index in 0..3 {
            let (header, body) = scene.fragment(at, serial, &object, index);
            scene.inject_edited(1, &header, &body, |_| {});
        }
        scene.turns(10);
        assert_eq!(
            super::owner::TRIPLED_DATA.with(std::cell::Cell::get),
            3,
            "one pass of three chains"
        );
        let kinds: Vec<_> = scene.replies(1).iter().map(|reply| reply.kind).collect();
        assert!(kinds.contains(&Kind::PutResult), "{kinds:?}");
        assert_eq!(scene.fetch(5), object);
    });
}

/// One of three PUT DATA frames of a batch arrives with a changed body byte under its original tag. The pass of three chains refuses that frame alone: the owner drops it, takes the other two, and the upload publishes once the fragment arrives unchanged.
#[test]
fn a_changed_frame_among_three_is_dropped_alone() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(3 * FRAGMENT_LEN as usize, 28);
        let (at, serial) = ready_upload(&mut scene, &object);
        super::owner::TRIPLED_DATA.with(|count| count.set(0));
        let dropped = scene.owner.report().dropped;
        for index in 0..3 {
            let (header, body) = scene.fragment(at, serial, &object, index);
            if index != 1 {
                scene.inject_edited(1, &header, &body, |_| {});
                continue;
            }
            let mut datagram = scene.sealed(1, &header, &body, |_| {});
            datagram[HEADER_LEN + 100] ^= 1;
            scene.nets[1].borrow_mut().inject(1, &datagram);
        }
        scene.turns(4);
        assert_eq!(
            super::owner::TRIPLED_DATA.with(std::cell::Cell::get),
            3,
            "the three frames shared one pass"
        );
        assert_eq!(
            scene.owner.report().dropped,
            dropped + 1,
            "the changed frame is dropped"
        );
        let replies = scene.replies(1);
        assert_eq!(
            acks(&replies).last().map(|ack| ack.0),
            Some(1),
            "fragment 0 is received and fragment 1 is missing: {replies:?}"
        );
        let (header, body) = scene.fragment(at, serial, &object, 1);
        let kinds: Vec<_> = scene
            .put_data(&header, &body)
            .iter()
            .map(|reply| reply.kind)
            .collect();
        scene.turns(10);
        let kinds: Vec<_> = kinds
            .into_iter()
            .chain(scene.replies(1).iter().map(|reply| reply.kind))
            .collect();
        assert!(kinds.contains(&Kind::PutResult), "{kinds:?}");
        assert_eq!(scene.fetch(5), object);
    });
}

/// An authentic version 2 PUT DATA of a granted fragment reaches the owner and is dropped at parse, alone and as one
/// of a full DATA group: each drop is counted, the group's version 3 neighbors are received around the missing
/// fragment, and the version 3 copies at the refused frames' sequences are then taken, so no refusal consumed a
/// replay position, and the upload publishes.
#[test]
fn a_version_2_put_data_is_dropped_alone_and_within_a_data_group() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(4 * FRAGMENT_LEN as usize, 29);
        let (at, serial) = ready_upload(&mut scene, &object);
        let datagrams: Vec<Vec<u8>> = (0..4)
            .map(|index| {
                let (header, body) = scene.fragment(at, serial, &object, index);
                scene.sealed(1, &header, &body, |_| {})
            })
            .collect();
        let v2 = |scene: &Scene<'_, '_>, index: usize| {
            super::frame_tests::recast_to_version_2(
                &scene.rings[1],
                PeerId(0),
                OWNER.endpoint,
                &datagrams[index],
                Direction::ClientToOwner,
            )
        };
        let before = scene.owner.report();
        let lone = v2(&scene, 0);
        scene.nets[1].borrow_mut().inject(1, &lone);
        scene.turns(4);
        let alone = scene.owner.report();
        assert_eq!(
            (alone.received, alone.dropped),
            (before.received + 1, before.dropped + 1),
            "the lone version 2 fragment reaches the owner and is dropped"
        );
        assert_eq!(acks(&scene.replies(1)), [], "no fragment is received");
        let grouped = v2(&scene, 1);
        for recast in [&lone, &grouped] {
            assert_eq!(
                parse(Crc32c::detect(), recast, false).err(),
                Some(FrameError::Version { found: 2 })
            );
        }
        super::owner::TRIPLED_DATA.with(|count| count.set(0));
        for datagram in [&datagrams[0], &grouped, &datagrams[2], &datagrams[3]] {
            scene.nets[1].borrow_mut().inject(1, datagram);
        }
        scene.turns(4);
        assert_eq!(
            super::owner::TRIPLED_DATA.with(std::cell::Cell::get),
            3,
            "the group's three version 3 fragments share one pass"
        );
        let group = scene.owner.report();
        assert_eq!(
            (group.received, group.dropped),
            (alone.received + 4, alone.dropped + 1),
            "the group's version 2 fragment alone is dropped"
        );
        let replies = scene.replies(1);
        assert_eq!(
            acks(&replies).last().map(|ack| (ack.0, ack.1)),
            Some((1, 0b11)),
            "fragments 0, 2 and 3 are received and fragment 1 is missing: {replies:?}"
        );
        scene.nets[1].borrow_mut().inject(1, &datagrams[1]);
        scene.turns(10);
        let kinds: Vec<_> = scene.replies(1).iter().map(|reply| reply.kind).collect();
        assert!(kinds.contains(&Kind::PutResult), "{kinds:?}");
        assert_eq!(scene.fetch(5), object);
    });
}

#[test]
fn a_changed_duplicate_ends_the_upload_with_conflicting_data() {
    for consumed in [false, true] {
        let config = OwnerConfig {
            put: PutConfig {
                copy_bytes: 1 << 16,
                ..OWNER.put
            },
            ..OWNER
        };
        scene_with(config, &PRINCIPALS, |mut scene| {
            let object = payload(4 * FRAGMENT_LEN as usize, 8);
            let (at, serial) = ready_upload(&mut scene, &object);
            let index = u32::from(!consumed);
            let (header, body) = scene.fragment(at, serial, &object, index);
            scene.put_data(&header, &body);
            let (changed, mut body) = scene.fragment(at, serial, &object, index);
            body[0] ^= 1;
            let replies = scene.put_data(&changed, &body);
            let errors: Vec<_> = replies.iter().filter_map(error).collect();
            assert_eq!(errors, [Status::ConflictingData], "consumed {consumed}");
            scene.turns(20);
            assert_eq!(scene.live(), 0, "the drain ended, consumed {consumed}");
        });
    }
}

#[test]
fn a_consumed_short_final_fragment_compares_by_its_retained_digest() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(2 * FRAGMENT_LEN as usize + 100, 14);
        let (at, serial) = ready_upload(&mut scene, &object);
        for index in 0..3 {
            let (header, body) = scene.fragment(at, serial, &object, index);
            scene.inject_edited(1, &header, &body, |_| {});
        }
        scene.polls(4);
        scene.replies(1);
        assert_eq!(scene.live(), 1, "unfinished writes hold publication");
        let writes = scene.owner.volume_report().writes_submitted;
        let (again, body) = scene.fragment(at, serial, &object, 2);
        scene.inject_edited(1, &again, &body, |_| {});
        scene.polls(4);
        assert_eq!(
            acks(&scene.replies(1)),
            [(3, 0, 3)],
            "an equal duplicate repeats the ACK"
        );
        assert_eq!(scene.owner.volume_report().writes_submitted, writes);
        let (changed, mut body) = scene.fragment(at, serial, &object, 2);
        body[99] ^= 1;
        scene.inject_edited(1, &changed, &body, |_| {});
        scene.polls(4);
        let errors: Vec<_> = scene.replies(1).iter().filter_map(error).collect();
        assert_eq!(errors, [Status::ConflictingData]);
        scene.turns(20);
        assert_eq!(scene.live(), 0, "the drain ended");
    });
}

/// Witness `consumed-crc-collision`: fragment 1 of a 3-fragment upload is consumed while the owner holds the attempt `Ready`, its writes unfinished so publication waits. An equal resend repeats the ACK with no new credit or write. A resend whose body differs and keeps the same crc32c, sealed by the uploading session under a fresh sequence, ends the attempt `ConflictingData`; the fill drains and the key stays unpublished.
#[test]
fn a_consumed_fragment_resent_with_a_colliding_crc_ends_the_upload() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(3 * FRAGMENT_LEN as usize, 15);
        let (at, serial) = ready_upload(&mut scene, &object);
        let before = scene.owner.volume_report().writes_submitted;
        for index in 0..3 {
            let (header, body) = scene.fragment(at, serial, &object, index);
            scene.inject_edited(1, &header, &body, |_| {});
        }
        scene.polls(4);
        scene.replies(1);
        assert_eq!(scene.live(), 1, "unfinished writes hold publication");
        let writes = scene.owner.volume_report().writes_submitted;
        assert!(
            writes > before,
            "the owner submitted writes, so its consume pass ran"
        );
        let (again, body) = scene.fragment(at, serial, &object, 1);
        scene.inject_edited(1, &again, &body, |_| {});
        scene.polls(4);
        assert_eq!(
            acks(&scene.replies(1)),
            [(3, 0, 3)],
            "an equal resend repeats the ACK"
        );
        assert_eq!(scene.owner.volume_report().writes_submitted, writes);
        let (changed, mut body) = scene.fragment(at, serial, &object, 1);
        super::auth_tests::crc_preserving_flip(&mut body, 40);
        let crc = Crc32c::detect();
        assert_ne!(body, fragment_bytes(&object, 1));
        assert_eq!(
            crc.checksum(&body),
            crc.checksum(fragment_bytes(&object, 1)),
            "the resend keeps the fragment's crc32c"
        );
        scene.inject_edited(1, &changed, &body, |_| {});
        scene.polls(4);
        let errors: Vec<_> = scene.replies(1).iter().filter_map(error).collect();
        assert_eq!(errors, [Status::ConflictingData]);
        assert_eq!(
            scene.owner.volume_report().writes_submitted,
            writes,
            "the conflicting resend writes nothing"
        );
        scene.turns(20);
        assert_eq!(scene.live(), 0, "the drain ended");
        assert!(!scene.visible(5), "the conflicting attempt never published");
    });
}

/// A 6-fragment upload under a receive ring of 4 consumes fragments 0 to 3, then 4 and 5, whose ring entries are 0 and 1 again; each consumed fragment keeps its own evidence by index. An equal resend of fragment 0 repeats the ACK, and a resend of fragment 4 whose body keeps its crc32c ends the attempt `ConflictingData`.
#[test]
fn consumed_fragments_past_the_ring_wrap_compare_their_own_evidence() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(6 * FRAGMENT_LEN as usize, 16);
        let (at, serial) = ready_upload(&mut scene, &object);
        let before = scene.owner.volume_report().writes_submitted;
        for window in [0..4, 4..6] {
            for index in window {
                let (header, body) = scene.fragment(at, serial, &object, index);
                scene.inject_edited(1, &header, &body, |_| {});
            }
            scene.polls(4);
            scene.replies(1);
        }
        assert_eq!(scene.live(), 1, "unfinished writes hold publication");
        let writes = scene.owner.volume_report().writes_submitted;
        assert!(
            writes > before,
            "the owner submitted writes, so its consume pass ran"
        );
        let (again, body) = scene.fragment(at, serial, &object, 0);
        scene.inject_edited(1, &again, &body, |_| {});
        scene.polls(4);
        assert_eq!(
            acks(&scene.replies(1)),
            [(6, 0, 6)],
            "an equal resend of fragment 0 repeats the ACK"
        );
        let (changed, mut body) = scene.fragment(at, serial, &object, 4);
        super::auth_tests::crc_preserving_flip(&mut body, 40);
        scene.inject_edited(1, &changed, &body, |_| {});
        scene.polls(4);
        let errors: Vec<_> = scene.replies(1).iter().filter_map(error).collect();
        assert_eq!(errors, [Status::ConflictingData]);
        assert_eq!(scene.owner.volume_report().writes_submitted, writes);
        scene.turns(20);
        assert_eq!(scene.live(), 0, "the drain ended");
    });
}

#[test]
fn a_group_of_consumed_resends_compares_each_with_its_own_evidence() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(6 * FRAGMENT_LEN as usize, 17);
        let (at, serial) = ready_upload(&mut scene, &object);
        for window in [0..4, 4..6] {
            for index in window {
                let (header, body) = scene.fragment(at, serial, &object, index);
                scene.inject_edited(1, &header, &body, |_| {});
            }
            scene.polls(4);
            scene.replies(1);
        }
        let writes = scene.owner.volume_report().writes_submitted;
        let dropped = scene.owner.report().dropped;
        let groups = retag_groups();
        for index in 0..4 {
            let (header, body) = scene.fragment(at, serial, &object, index);
            scene.inject_edited(1, &header, &body, |_| {});
        }
        scene.polls(1);
        assert_eq!(
            retag_groups()[4],
            groups[4] + 1,
            "one group tagged all four"
        );
        assert_eq!(
            acks(&scene.replies(1)),
            [(6, 0, 6)],
            "the equal burst repeats the ACK"
        );
        assert_eq!(
            scene.owner.report().dropped,
            dropped,
            "every resend compared"
        );
        for index in 0..4 {
            let (header, mut body) = scene.fragment(at, serial, &object, index);
            if index == 2 {
                super::auth_tests::crc_preserving_flip(&mut body, 100);
            }
            scene.inject_edited(1, &header, &body, |_| {});
        }
        scene.polls(4);
        let errors: Vec<_> = scene.replies(1).iter().filter_map(error).collect();
        assert_eq!(errors, [Status::ConflictingData]);
        assert_eq!(scene.owner.volume_report().writes_submitted, writes);
        scene.turns(20);
        assert_eq!(scene.live(), 0, "the drain ended");
        assert!(!scene.visible(5), "the conflicting attempt never published");
    });
}

#[test]
fn three_resends_around_a_fresh_fragment_keep_their_positions() {
    for flipped in [None, Some(1), Some(2)] {
        scene(&PRINCIPALS, |mut scene| {
            let object = payload(6 * FRAGMENT_LEN as usize, 20);
            let (at, serial) = ready_upload(&mut scene, &object);
            for index in 0..4 {
                let (header, body) = scene.fragment(at, serial, &object, index);
                scene.inject_edited(1, &header, &body, |_| {});
            }
            scene.polls(4);
            scene.replies(1);
            let dropped = scene.owner.report().dropped;
            let groups = retag_groups();
            for index in [0, 1, 4, 2] {
                let (header, mut body) = scene.fragment(at, serial, &object, index);
                if flipped == Some(index) {
                    super::auth_tests::crc_preserving_flip(&mut body, 33);
                }
                scene.inject_edited(1, &header, &body, |_| {});
            }
            scene.polls(1);
            assert_eq!(retag_groups()[3], groups[3] + 1, "one group tagged three");
            let replies = scene.replies(1);
            let errors: Vec<_> = replies.iter().filter_map(error).collect();
            match flipped {
                None => {
                    assert_eq!(errors, []);
                    assert_eq!(acks(&replies).last().map(|ack| ack.0), Some(5));
                    assert_eq!(scene.owner.report().dropped, dropped);
                }
                Some(index) => {
                    assert_eq!(errors, [Status::ConflictingData], "flipped {index}");
                    scene.turns(20);
                    assert!(!scene.visible(5));
                }
            }
        });
    }
}

#[test]
fn a_resend_ahead_of_fresh_fragments_acts_before_them() {
    for conflicting in [false, true] {
        scene(&PRINCIPALS, |mut scene| {
            let object = payload(6 * FRAGMENT_LEN as usize, 18);
            let (at, serial) = ready_upload(&mut scene, &object);
            for index in 0..4 {
                let (header, body) = scene.fragment(at, serial, &object, index);
                scene.inject_edited(1, &header, &body, |_| {});
            }
            scene.polls(4);
            scene.replies(1);
            let writes = scene.owner.volume_report().writes_submitted;
            let dropped = scene.owner.report().dropped;
            for index in [0, 4, 1, 5] {
                let (header, mut body) = scene.fragment(at, serial, &object, index);
                if conflicting && index == 0 {
                    super::auth_tests::crc_preserving_flip(&mut body, 7);
                }
                scene.inject_edited(1, &header, &body, |_| {});
            }
            scene.polls(4);
            let replies = scene.replies(1);
            let errors: Vec<_> = replies.iter().filter_map(error).collect();
            if conflicting {
                assert_eq!(errors, [Status::ConflictingData]);
                assert_eq!(
                    scene.owner.report().dropped - dropped,
                    3,
                    "fragments 4, 1 and 5 arrived after the attempt ended"
                );
                assert_eq!(scene.owner.volume_report().writes_submitted, writes);
                scene.turns(20);
                assert!(!scene.visible(5));
            } else {
                assert_eq!(errors, []);
                assert_eq!(scene.owner.report().dropped, dropped);
                assert_eq!(acks(&replies).last().map(|ack| ack.0), Some(6));
                scene.turns(20);
                assert_eq!(scene.fetch(5), object);
            }
        });
    }
}

#[test]
fn resends_of_two_peers_in_one_group_compare_under_their_own_keys() {
    for conflicting in [false, true] {
        scene(&PRINCIPALS, |mut scene| {
            let names = [6, 5];
            let objects = [21, 22].map(|seed| payload(3 * FRAGMENT_LEN as usize, seed));
            let mut uploads = [(0, 0); 2];
            for peer in 0..2 {
                let at = request(2, 1);
                let serial = scene.begin(peer, at, names[peer]);
                let len = objects[peer].len() as u32;
                let header = scene.frame(
                    peer,
                    Kind::PutPrepare,
                    at,
                    names[peer],
                    prepare(serial, len, 60_000),
                );
                assert_eq!(scene.one(peer, &header).kind, Kind::PutReady);
                uploads[peer] = (at, serial);
            }
            for (peer, &(at, serial)) in uploads.iter().enumerate() {
                for index in 0..3 {
                    let (header, body) =
                        scene.fragment_from(peer, at, serial, names[peer], &objects[peer], index);
                    scene.inject_edited(peer, &header, &body, |_| {});
                }
            }
            scene.polls(4);
            for peer in 0..2 {
                assert_eq!(acks(&scene.replies(peer)).last().map(|ack| ack.0), Some(3));
            }
            let groups = retag_groups();
            for (peer, index) in [(0, 0), (0, 1), (1, 0), (1, 1)] {
                let (at, serial) = uploads[peer];
                let (header, mut body) =
                    scene.fragment_from(peer, at, serial, names[peer], &objects[peer], index);
                if conflicting && (peer, index) == (1, 1) {
                    super::auth_tests::crc_preserving_flip(&mut body, 50);
                }
                scene.inject_edited(peer, &header, &body, |_| {});
            }
            scene.polls(1);
            assert_eq!(
                retag_groups()[4],
                groups[4] + 1,
                "one group held both peers"
            );
            let errors = [0, 1].map(|peer| {
                scene
                    .replies(peer)
                    .iter()
                    .filter_map(error)
                    .collect::<Vec<_>>()
            });
            let expected: &[Status] = if conflicting {
                &[Status::ConflictingData]
            } else {
                &[]
            };
            assert_eq!(errors[0], [], "peer 0's resends match");
            assert_eq!(errors[1], expected);
            scene.turns(20);
            assert!(scene.visible(names[0]));
            assert_eq!(scene.visible(names[1]), !conflicting);
        });
    }
}

#[test]
fn resend_comparisons_spend_the_copy_budget() {
    let config = OwnerConfig {
        put: PutConfig {
            copy_bytes: 2 * MAX_DATAGRAM,
            ..OWNER.put
        },
        ..OWNER
    };
    scene_with(config, &PRINCIPALS, |mut scene| {
        let object = payload(4 * FRAGMENT_LEN as usize, 19);
        let (at, serial) = ready_upload(&mut scene, &object);
        for index in 0..4 {
            let (header, body) = scene.fragment(at, serial, &object, index);
            scene.inject_edited(1, &header, &body, |_| {});
        }
        scene.polls(6);
        assert_eq!(acks(&scene.replies(1)).last().map(|ack| ack.0), Some(4));
        let dropped = scene.owner.report().dropped;
        let groups = retag_groups();
        for index in 0..4 {
            let (header, body) = scene.fragment(at, serial, &object, index);
            scene.inject_edited(1, &header, &body, |_| {});
        }
        scene.polls(1);
        assert_eq!(
            scene.owner.report().dropped - dropped,
            2,
            "the budget compares two resends"
        );
        assert_eq!(
            retag_groups(),
            {
                let mut after = groups;
                after[2] += 1;
                after
            },
            "only the two paid resends were hashed"
        );
        assert_eq!(acks(&scene.replies(1)), [(4, 0, 4)]);
        for index in 2..4 {
            let (header, body) = scene.fragment(at, serial, &object, index);
            scene.inject_edited(1, &header, &body, |_| {});
        }
        scene.polls(1);
        assert_eq!(scene.owner.report().dropped - dropped, 2);
        let errors: Vec<_> = scene.replies(1).iter().filter_map(error).collect();
        assert_eq!(errors, []);
    });
}

#[test]
fn held_resend_comparisons_spend_the_copy_budget() {
    let config = OwnerConfig {
        put: PutConfig {
            copy_bytes: 2 * MAX_DATAGRAM,
            ..OWNER.put
        },
        ..OWNER
    };
    scene_with(config, &PRINCIPALS, |mut scene| {
        let object = payload(4 * FRAGMENT_LEN as usize, 23);
        let (at, serial) = ready_upload(&mut scene, &object);
        for index in 1..4 {
            let (header, body) = scene.fragment(at, serial, &object, index);
            scene.inject_edited(1, &header, &body, |_| {});
        }
        scene.polls(4);
        scene.replies(1);
        let dropped = scene.owner.report().dropped;
        let groups = retag_groups();
        for index in 1..4 {
            let (header, body) = scene.fragment(at, serial, &object, index);
            scene.inject_edited(1, &header, &body, |_| {});
        }
        scene.polls(1);
        assert_eq!(
            scene.owner.report().dropped - dropped,
            1,
            "the budget compares two held resends"
        );
        assert_eq!(retag_groups(), groups, "held resends compare bytes");
        let errors: Vec<_> = scene.replies(1).iter().filter_map(error).collect();
        assert_eq!(errors, []);
        let (header, body) = scene.fragment(at, serial, &object, 0);
        scene.inject_edited(1, &header, &body, |_| {});
        scene.turns(20);
        assert_eq!(scene.fetch(5), object);
    });
}

fn retag_groups() -> [usize; 5] {
    super::put::RETAG_GROUPS.with(std::cell::Cell::get)
}

/// Fragment `index` of `object`.
fn fragment_bytes(object: &[u8], index: usize) -> &[u8] {
    let start = index * FRAGMENT_LEN as usize;
    &object[start..object.len().min(start + FRAGMENT_LEN as usize)]
}

#[test]
fn a_fragment_above_the_grant_is_dropped() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(6 * FRAGMENT_LEN as usize, 9);
        let (at, serial) = ready_upload(&mut scene, &object);
        let dropped = scene.owner.report().dropped;
        let (beyond, body) = scene.fragment(at, serial, &object, 4);
        assert!(scene.put_data(&beyond, &body).is_empty());
        assert_eq!(scene.owner.report().dropped, dropped + 1);
    });
}

#[test]
fn a_cancel_during_writes_keeps_the_fill_until_its_writes_end() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(2 * FRAGMENT_LEN as usize, 10);
        let (at, serial) = ready_upload(&mut scene, &object);
        for index in 0..2 {
            let (header, body) = scene.fragment(at, serial, &object, index);
            scene.inject_edited(1, &header, &body, |_| {});
        }
        scene.polls(2);
        let stop = scene.frame(1, Kind::PutCancel, at, 5, cancel(serial));
        scene.inject(1, &stop);
        scene.polls(2);
        assert_eq!(scene.live(), 1, "the fill drains its writes");
        scene.turns(20);
        assert_eq!(scene.live(), 0);
        let errors: Vec<_> = scene.replies(1).iter().filter_map(error).collect();
        assert_eq!(errors, [Status::Cancelled]);
    });
}

#[test]
fn a_window_over_the_receive_data_cap_refuses_start() {
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let (_end, owner_end, _net) = network(64, 8384, 94, [Faults::default(); 2]);
    let (_other, second, _net2) = network(64, 8384, 95, [Faults::default(); 2]);
    let config = OwnerConfig {
        put: PutConfig {
            window: 16,
            ..OWNER.put
        },
        ..OWNER
    };
    let refused = start_owner(
        &storage,
        &buffers,
        &receive,
        vec![owner_end, second],
        config,
        &PRINCIPALS,
        super::auth::os_entropy,
    );
    assert!(matches!(refused, Err((OwnerError::Puts, _))));
}

#[test]
fn a_full_window_burst_acknowledges_only_the_window() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(6 * FRAGMENT_LEN as usize, 11);
        let (at, serial) = ready_upload(&mut scene, &object);
        for index in 0..5 {
            let (header, body) = scene.fragment(at, serial, &object, index);
            scene.inject_edited(1, &header, &body, |_| {});
        }
        scene.turns(4);
        let acks = acks(&scene.replies(1));
        // One ACK per turn carries the base the turn's fragments reached and a grant at most one window past the fragments still held; the ring holds four of the five, so the fifth waits for a later grant.
        assert!(!acks.is_empty(), "{acks:?}");
        assert!(acks.iter().all(|ack| ack.2 <= ack.0 + 4), "{acks:?}");
        assert!(acks[0].0 >= 4, "{acks:?}");
        assert!(
            acks.windows(2).all(|pair| pair[1].0 <= pair[0].2),
            "above the grant: {acks:?}"
        );
        assert_eq!(scene.live(), 1);
    });
}

#[test]
fn a_duplicate_prepare_beside_data_shares_the_turns_one_ack() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(6 * FRAGMENT_LEN as usize, 12);
        let (at, serial) = ready_upload(&mut scene, &object);
        let (zero, body) = scene.fragment(at, serial, &object, 0);
        assert_eq!(acks(&scene.put_data(&zero, &body)), [(1, 0, 5)]);
        let (one, body) = scene.fragment(at, serial, &object, 1);
        scene.inject_edited(1, &one, &body, |_| {});
        let again = scene.frame(
            1,
            Kind::PutPrepare,
            at,
            5,
            prepare(serial, object.len() as u32, 60_000),
        );
        scene.inject(1, &again);
        scene.turns(4);
        let acks = acks(&scene.replies(1));
        assert_eq!(acks, [(2, 0, 6)], "one ACK per PUT per turn");
    });
}

#[test]
fn an_ended_upload_returns_its_ring_for_the_next() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(4 * FRAGMENT_LEN as usize, 12);
        let (at, serial) = ready_upload(&mut scene, &object);
        let (one, body) = scene.fragment(at, serial, &object, 1);
        scene.put_data(&one, &body);
        let stop = scene.frame(1, Kind::PutCancel, at, 5, cancel(serial));
        assert_eq!(error(&scene.one(1, &stop)), Some(Status::Cancelled));
        scene.turns(20);
        assert_eq!(scene.live(), 0);
        let next = request(1, 2);
        let serial = scene.begin(1, next, 5);
        let prepare = scene.frame(
            1,
            Kind::PutPrepare,
            next,
            5,
            prepare(serial, object.len() as u32, 60_000),
        );
        assert_eq!(scene.one(1, &prepare).kind, Kind::PutReady);
        let other = payload(4 * FRAGMENT_LEN as usize, 13);
        let (fresh, body) = scene.fragment(next, serial, &other, 1);
        assert_eq!(acks(&scene.put_data(&fresh, &body)), [(0, 1, 4)]);
    });
}

/// The peer observation reads only the lanes marked as counting a write
/// command, and names each marked lane's upload by the lane's recorded
/// holder. So after every turn each upload that counts a command is marked,
/// and each marked lane's holder is a live upload of that peer on that lane:
/// a cancelled upload that drains its writes, a published one, and the
/// uploads that take their lanes next leave no mark behind.
#[test]
fn every_marked_lane_names_the_live_upload_that_counts_its_commands() {
    scene(&PRINCIPALS, |mut scene| {
        scene.audit = Some(Box::new(|owner| {
            assert_eq!(owner.check_put_holding(), Ok(()));
        }));
        let object = payload(4 * FRAGMENT_LEN as usize, 12);
        let (at, serial) = ready_upload(&mut scene, &object);
        for index in 0..2 {
            let (header, body) = scene.fragment(at, serial, &object, index);
            scene.put_data(&header, &body);
        }
        let stop = scene.frame(1, Kind::PutCancel, at, 5, cancel(serial));
        assert_eq!(error(&scene.one(1, &stop)), Some(Status::Cancelled));
        scene.turns(20);
        assert_eq!(scene.live(), 0, "the cancelled upload drained");
        for generation in 2..5 {
            publish_upload(&mut scene, request(1, generation), 5, &object);
            assert_eq!(scene.live(), 0, "upload {generation} published");
        }
        assert_eq!(scene.fetch(5), object);
    });
}

#[test]
fn an_uploaded_object_publishes_once_and_serves_its_exact_bytes() {
    for len in [
        FRAGMENT_LEN as usize,
        2 * FRAGMENT_LEN as usize,
        30_000,
        4 * FRAGMENT_LEN as usize,
        6 * FRAGMENT_LEN as usize,
    ] {
        scene(&PRINCIPALS, |mut scene| {
            let object = payload(len, len as u64);
            let (at, serial) = ready_upload(&mut scene, &object);
            let count = FragmentGeometry::fragments(len as u64) as u32;
            let mut kinds = Vec::new();
            for index in 0..count {
                let (header, body) = scene.fragment(at, serial, &object, index);
                kinds.extend(
                    scene
                        .put_data(&header, &body)
                        .iter()
                        .map(|reply| reply.kind),
                );
            }
            scene.turns(10);
            kinds.extend(scene.replies(1).iter().map(|reply| reply.kind));
            let results = kinds
                .iter()
                .filter(|kind| **kind == Kind::PutResult)
                .count();
            assert_eq!(results, 1, "{len}: {kinds:?}");
            assert_eq!(scene.live(), 0);
            let resent = scene.frame(
                1,
                Kind::PutPrepare,
                at,
                5,
                prepare(serial, len as u32, 60_000),
            );
            assert_eq!(scene.one(1, &resent).kind, Kind::PutResult);
            assert_eq!(scene.fetch(5), object, "{len}");
        });
    }
}

#[test]
fn a_publish_error_ends_the_upload_with_its_status() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(FRAGMENT_LEN as usize, 14);
        set_clock(scene.storage, &[Some(1)]);
        let (at, serial) = ready_upload(&mut scene, &object);
        set_clock(scene.storage, &[Some(120 * 1_000_000_000)]);
        let (header, body) = scene.fragment(at, serial, &object, 0);
        let mut replies = scene.put_data(&header, &body);
        scene.turns(10);
        replies.extend(scene.replies(1));
        let errors: Vec<_> = replies.iter().filter_map(error).collect();
        assert_eq!(
            errors,
            [Status::Expired],
            "{replies:?} live {}",
            scene.live()
        );
        assert_eq!(scene.live(), 0);
    });
}

#[test]
fn close_drains_a_writing_upload_before_shutdown() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(2 * FRAGMENT_LEN as usize, 15);
        let (at, serial) = ready_upload(&mut scene, &object);
        for index in 0..2 {
            let (header, body) = scene.fragment(at, serial, &object, index);
            scene.inject_edited(1, &header, &body, |_| {});
        }
        scene.polls(2);
        let report = scene.owner.volume_report();
        assert!(report.writes_submitted > report.writes_done);
        assert!(matches!(
            scene.owner.rekey(&entries(), 2, scene.turn * 100),
            Err(OwnerRekeyError::Rekey(RekeyError::Busy { .. }))
        ));
        scene.owner.close(scene.turn * 100);
        scene.polls(5);
        assert_eq!(scene.live(), 1, "the fill stays until its writes end");
        assert!(scene.owner.blockers().is_some());
        scene.turns(40);
        assert_eq!(scene.live(), 0);
        assert!(scene.owner.blockers().is_none());
    });
}

/// With the other peer idle, a peer's upload holds all four of its segment
/// writes at once, twice the peer's share of two.
#[test]
fn a_peer_takes_the_write_commands_an_idle_peer_leaves() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(6 * FRAGMENT_LEN as usize, 16);
        let (at, serial) = ready_upload(&mut scene, &object);
        let mut peak = 0;
        for batch in [0..2, 2..6] {
            for index in batch {
                let (header, body) = scene.fragment(at, serial, &object, index);
                scene.inject_edited(1, &header, &body, |_| {});
            }
            for _ in 0..3 {
                scene.polls(1);
                let report = scene.owner.volume_report();
                peak = peak.max(report.writes_submitted - report.writes_done);
            }
        }
        assert_eq!(peak, 4);
    });
}

/// Peer 1's upload holds every write command the volume admits, more than
/// the peer's share of one, and has a segment waiting when peer 0's upload
/// has writes to submit. The first command the device accepts after one of
/// peer 1's ends is peer 0's, whichever upload was admitted first and so
/// whichever the progress pass visits first.
#[test]
fn a_freed_write_command_goes_to_the_peer_below_its_share() {
    let at = request(1, 1);
    let feed =
        |scene: &mut Scene<'_, '_>, peer: usize, (name, serial): (u8, u64), object: &[u8]| {
            for batch in [0..2, 2..6] {
                for index in batch {
                    let (header, body) = scene.fragment_from(peer, at, serial, name, object, index);
                    scene.inject_edited(peer, &header, &body, |_| {});
                }
                scene.polls(3);
            }
        };
    let commands = |scene: &Scene<'_, '_>, serial: u64| {
        super::adapters::written_commands(
            scene.owner.volume_bound(),
            &scene.control.capture(),
            serial,
        )
    };
    // The progress pass visits the upload admitted first before the other, so the two admission orders cover both visit orders in the turn that sees the freed command.
    for lender_first in [false, true] {
        // Six read records leave the writes two slots, one a peer, and the metadata share one more while no metadata command claims it, and three fill records give the scene six receive-write buffers, so the uploads wait for commands with buffers to spare.
        let storage = crate::storage::owner_fixture::storage_filling(6, 3);
        scene_over(storage, OWNER, &PRINCIPALS, |mut scene| {
            let objects = [21, 22].map(|seed| payload(6 * FRAGMENT_LEN as usize, seed));
            let (borrower, lender) = if lender_first {
                let lender = ready_upload_from(&mut scene, 1, at, 5, &objects[0]);
                (ready_upload_from(&mut scene, 0, at, 6, &objects[1]), lender)
            } else {
                let borrower = ready_upload_from(&mut scene, 0, at, 6, &objects[1]);
                (
                    borrower,
                    ready_upload_from(&mut scene, 1, at, 5, &objects[0]),
                )
            };
            feed(&mut scene, 1, (5, lender), &objects[0]);
            let held: Vec<_> = commands(&scene, lender)
                .into_iter()
                .filter(|command| command.delivered.is_none())
                .collect();
            assert_eq!(
                held.len(),
                3,
                "peer 1 holds the write share and the idle metadata slot, three times its share, with segments waiting"
            );
            for command in &held {
                scene
                    .control
                    .hold(crate::storage::CommandToken::from_raw(command.token));
            }
            let waits = scene.owner.put_report().command_waits;
            feed(&mut scene, 0, (6, borrower), &objects[1]);
            assert!(commands(&scene, borrower).is_empty(), "no command is free");
            assert!(
                scene.owner.put_report().command_waits > waits,
                "peer 0's upload waits for a command"
            );
            let last = held.iter().map(|command| command.ordinal).max();
            scene
                .control
                .release(crate::storage::CommandToken::from_raw(held[0].token));
            scene.turns(3);
            let next = |serial: u64| {
                commands(&scene, serial)
                    .iter()
                    .map(|command| command.ordinal)
                    .filter(|ordinal| Some(*ordinal) > last)
                    .min()
            };
            let first = next(borrower).expect("peer 0's upload wrote");
            assert!(
                next(lender).is_none_or(|ordinal| ordinal > first),
                "the freed command goes to the peer below its share"
            );
        });
    }
}

/// Two uploads, one a peer, hold the three write commands the volume admits,
/// the older upload two and the younger one, and each has a segment waiting.
/// The younger upload's command ends. The freed command goes to the upload
/// whose BEGIN was admitted first, whichever peer began first, with the
/// terminal seen after zero or one idle turn.
#[test]
fn a_freed_write_command_goes_to_the_upload_admitted_first() {
    let at = request(1, 1);
    let commands = |scene: &Scene<'_, '_>, serial: u64| {
        super::adapters::written_commands(
            scene.owner.volume_bound(),
            &scene.control.capture(),
            serial,
        )
    };
    let feed = |scene: &mut Scene<'_, '_>,
                peer: usize,
                (name, serial): (u8, u64),
                object: &[u8],
                fragments: std::ops::Range<u32>| {
        for index in fragments {
            let (header, body) = scene.fragment_from(peer, at, serial, name, object, index);
            scene.inject_edited(peer, &header, &body, |_| {});
        }
        scene.polls(3);
    };
    for (older, younger) in [(0, 1), (1, 0)] {
        for idle in 0..2 {
            // Six read records leave the writes two slots, one a peer, and the metadata share one more while no metadata command claims it; three fill records give the scene six receive-write buffers.
            let storage = crate::storage::owner_fixture::storage_filling(6, 3);
            scene_over(storage, OWNER, &PRINCIPALS, |mut scene| {
                let objects = [31, 32].map(|seed| payload(6 * FRAGMENT_LEN as usize, seed));
                let first = ready_upload_from(&mut scene, older, at, 7, &objects[0]);
                let second = ready_upload_from(&mut scene, younger, at, 8, &objects[1]);
                // Four fragments complete one segment of an upload, and the last two complete its other three.
                feed(&mut scene, older, (7, first), &objects[0], 0..4);
                feed(&mut scene, younger, (8, second), &objects[1], 0..4);
                feed(&mut scene, older, (7, first), &objects[0], 4..6);
                feed(&mut scene, younger, (8, second), &objects[1], 4..6);
                let held = [first, second].map(|serial| commands(&scene, serial));
                assert_eq!(
                    held.each_ref().map(Vec::len),
                    [2, 1],
                    "the older upload holds two commands and the younger one, each at least its peer's share, with segments of both waiting"
                );
                scene.polls(idle);
                for command in &held[0] {
                    scene
                        .control
                        .hold(crate::storage::CommandToken::from_raw(command.token));
                }
                scene.turns(1);
                assert_eq!(
                    [first, second].map(|serial| commands(&scene, serial).len()),
                    [3, 1],
                    "older {older}, idle {idle}: the freed command goes to the upload admitted first"
                );
            });
        }
    }
}

/// Peer 1's upload holds four write commands, twice its share, and peer 0's
/// upload takes the last command the volume admits for its one segment: it
/// holds fewer commands than its share of two and has nothing left to
/// submit. That turn and each turn after it lends, because an upload that
/// waits for its terminals alone asks for no command.
#[test]
fn an_upload_waiting_for_its_terminals_alone_leaves_the_turn_lending() {
    let at = request(1, 1);
    let commands = |scene: &Scene<'_, '_>, serial: u64| {
        super::adapters::written_commands(
            scene.owner.volume_bound(),
            &scene.control.capture(),
            serial,
        )
    };
    // Four read records leave the writes four slots, two a peer, and the metadata share one more while no metadata command claims it; three fill records give the scene six receive-write buffers.
    let storage = crate::storage::owner_fixture::storage_filling(4, 3);
    scene_over(storage, OWNER, &PRINCIPALS, |mut scene| {
        let small = payload(FRAGMENT_LEN as usize, 23);
        let large = payload(6 * FRAGMENT_LEN as usize, 24);
        let waiter = ready_upload_from(&mut scene, 0, at, 6, &small);
        let borrower = ready_upload_from(&mut scene, 1, at, 5, &large);
        let before = scene.owner.volume_report().writes_submitted;
        for batch in [0..2, 2..6] {
            for index in batch {
                let (header, body) = scene.fragment_from(1, at, borrower, 5, &large, index);
                scene.inject_edited(1, &header, &body, |_| {});
            }
            scene.polls(3);
        }
        assert_eq!(
            commands(&scene, borrower).len(),
            4,
            "peer 1 holds four write commands, twice its share"
        );
        let (header, body) = scene.fragment_from(0, at, waiter, 6, &small, 0);
        scene.inject_edited(0, &header, &body, |_| {});
        for turn in 0..4 {
            scene.polls(1);
            assert!(
                scene.owner.put_lends(),
                "turn {turn}: no PUT with a write to submit found the commands taken"
            );
        }
        assert_eq!(
            commands(&scene, waiter).len(),
            1,
            "peer 0's one segment is at the device"
        );
        assert_eq!(
            scene.owner.volume_report().writes_submitted,
            before + 5,
            "the two uploads hold every write command the volume admits"
        );
    });
}

/// A turn's budget is one write command, fewer than the volume admits.
/// Peer 1's upload was admitted first, holds its share of two write commands
/// and has two more segments to submit when peer 0's upload has one. The
/// upload admitted first takes the next turn's command, its peer's third.
/// Peer 0's upload, below its share with commands free at the device, takes
/// the command after that one.
#[test]
fn a_spent_turn_budget_gives_the_next_command_to_the_peer_below_its_share() {
    let at = request(1, 1);
    let commands = |scene: &Scene<'_, '_>, serial: u64| {
        super::adapters::written_commands(
            scene.owner.volume_bound(),
            &scene.control.capture(),
            serial,
        )
        .len()
    };
    let config = OwnerConfig {
        put: PutConfig {
            commands: 1,
            ..OWNER.put
        },
        ..OWNER
    };
    // Four read records leave the writes four slots, two a peer, and the metadata share one more while no metadata command claims it; three fill records give the scene six receive-write buffers.
    let storage = crate::storage::owner_fixture::storage_filling(4, 3);
    scene_over(storage, config, &PRINCIPALS, |mut scene| {
        let small = payload(FRAGMENT_LEN as usize, 25);
        let large = payload(6 * FRAGMENT_LEN as usize, 26);
        let borrower = ready_upload_from(&mut scene, 1, at, 5, &large);
        let waiter = ready_upload_from(&mut scene, 0, at, 6, &small);
        for index in 0..2 {
            let (header, body) = scene.fragment_from(1, at, borrower, 5, &large, index);
            scene.inject_edited(1, &header, &body, |_| {});
        }
        scene.polls(3);
        for index in 2..6 {
            let (header, body) = scene.fragment_from(1, at, borrower, 5, &large, index);
            scene.inject_edited(1, &header, &body, |_| {});
        }
        for _ in 0..8 {
            if commands(&scene, borrower) == 2 {
                break;
            }
            scene.polls(1);
        }
        assert_eq!(
            commands(&scene, borrower),
            2,
            "peer 1 holds its share, with two segments waiting"
        );
        let (header, body) = scene.fragment_from(0, at, waiter, 6, &small, 0);
        scene.inject_edited(0, &header, &body, |_| {});
        let mut held = Vec::new();
        for _ in 0..4 {
            scene.polls(1);
            held.push((commands(&scene, borrower), commands(&scene, waiter)));
            if held.last().is_some_and(|&(_, waiter)| waiter == 1) {
                break;
            }
        }
        assert_eq!(
            held.last(),
            Some(&(3, 1)),
            "peer 0's upload writes before peer 1 takes a second command beyond its share: {held:?}"
        );
    });
}

/// A turn copies two fragments and a window holds four. The upload admitted
/// first keeps more fragments held than a turn copies, and the other peer's
/// upload, admitted after it, holds its one fragment from before the first
/// turn. Each turn's copy budget goes to the upload admitted first, whichever
/// peer began first, so the later upload's write is submitted only after the
/// earlier upload submitted all four of its own. Every turn lends: both
/// peers find a write command, and the wait is for the copy budget alone.
#[test]
fn the_copy_budget_goes_to_the_upload_admitted_first() {
    let at = request(1, 1);
    let commands = |scene: &Scene<'_, '_>, serial: u64| {
        super::adapters::written_commands(
            scene.owner.volume_bound(),
            &scene.control.capture(),
            serial,
        )
        .len()
    };
    let config = OwnerConfig {
        put: PutConfig {
            copy_bytes: 2 * MAX_DATAGRAM,
            ..OWNER.put
        },
        ..OWNER
    };
    for (older, younger) in [(1, 0), (0, 1)] {
        // Four read records leave the writes four slots, two a peer, and the metadata share one more while no metadata command claims it; three fill records give the scene six receive-write buffers.
        let storage = crate::storage::owner_fixture::storage_filling(4, 3);
        scene_over(storage, config, &PRINCIPALS, |mut scene| {
            let large = payload(6 * FRAGMENT_LEN as usize, 27);
            let small = payload(FRAGMENT_LEN as usize, 28);
            let first = ready_upload_from(&mut scene, older, at, 5, &large);
            let second = ready_upload_from(&mut scene, younger, at, 6, &small);
            for index in 0..4 {
                let (header, body) = scene.fragment_from(older, at, first, 5, &large, index);
                scene.inject_edited(older, &header, &body, |_| {});
            }
            let (header, body) = scene.fragment_from(younger, at, second, 6, &small, 0);
            scene.inject_edited(younger, &header, &body, |_| {});
            let mut held = Vec::new();
            for turn in 0..6 {
                scene.polls(1);
                assert!(
                    scene.owner.put_lends(),
                    "older {older}, turn {turn}: each upload found a write command"
                );
                held.push((commands(&scene, first), commands(&scene, second)));
                if held.last().is_some_and(|&(_, second)| second == 1) {
                    break;
                }
                if turn == 0 {
                    for index in 4..6 {
                        let (header, body) =
                            scene.fragment_from(older, at, first, 5, &large, index);
                        scene.inject_edited(older, &header, &body, |_| {});
                    }
                }
            }
            assert_eq!(
                held.last(),
                Some(&(4, 1)),
                "older {older}: the later upload writes once the earlier one submitted every segment: {held:?}"
            );
            assert!(
                held.len() > 2,
                "older {older}: the later upload held its fragment through turns that copied the earlier upload's: {held:?}"
            );
        });
    }
}

#[test]
fn a_whole_upload_submits_every_segment_after_its_last_fragment() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(6 * FRAGMENT_LEN as usize, 17);
        let (at, serial) = ready_upload(&mut scene, &object);
        let before = scene.owner.volume_report().writes_submitted;
        for index in 0..6 {
            let (header, body) = scene.fragment(at, serial, &object, index);
            scene.put_data(&header, &body);
        }
        scene.turns(20);
        let report = scene.owner.volume_report();
        assert_eq!(report.writes_submitted - before, 4, "{report:?}");
        assert_eq!(report.writes_submitted, report.writes_done);
    });
}

pub(super) fn upload_within(
    scene: &mut Scene<'_, '_>,
    object: &[u8],
    remaining_ms: u32,
) -> (u64, u64) {
    upload_at(scene, request(1, 1), object, remaining_ms)
}

pub(super) fn upload_at(
    scene: &mut Scene<'_, '_>,
    at: u64,
    object: &[u8],
    remaining_ms: u32,
) -> (u64, u64) {
    let begin = scene.frame(1, Kind::PutBegin, at, 5, |header| {
        header.remaining_ms = remaining_ms
    });
    let serial = scene.one(1, &begin).allocation;
    let header = scene.frame(
        1,
        Kind::PutPrepare,
        at,
        5,
        prepare(serial, object.len() as u32, 60_000),
    );
    assert_eq!(scene.one(1, &header).kind, Kind::PutReady);
    (at, serial)
}

/// Begins a one-fragment upload of key 5 with a wait of 5 ms on peer 1 and
/// hands its fragment to the owner's link. Returns the object.
fn begin_brief_upload(scene: &mut Scene<'_, '_>) -> Vec<u8> {
    let object = payload(FRAGMENT_LEN as usize, 19);
    let (at, serial) = upload_within(scene, &object, 5);
    let (header, body) = scene.fragment(at, serial, &object, 0);
    scene.inject_edited(1, &header, &body, |_| {});
    object
}

/// The turn of the first owner poll at the deadline of
/// [`begin_brief_upload`]'s upload: with the disk held for the whole run,
/// the turn whose poll ends the upload `TimedOut`. The owner's count of
/// timed-out uploads changes in that poll.
fn brief_upload_deadline() -> u64 {
    let mut deadline = 0;
    afresh(|| {
        scene(&PRINCIPALS, |mut scene| {
            begin_brief_upload(&mut scene);
            while scene.owner.put_report().failed_timed_out == 0 {
                scene.polls(1);
                assert!(scene.turn < 10_000);
            }
            deadline = scene.turn - 1;
        })
    });
    deadline
}

/// The owner's write commands the device has not ended, its live requests,
/// and its uploads ended `TimedOut` and published.
fn upload_counts(scene: &Scene<'_, '_>) -> (u64, u32, u64, u64) {
    let volume = scene.owner.volume_report();
    let put = scene.owner.put_report();
    (
        volume.writes_submitted - volume.writes_done,
        scene.live(),
        put.failed_timed_out,
        put.published,
    )
}

/// Runs [`begin_brief_upload`]'s upload with the disk held until turn
/// `write_end`, whose disk tick ends the write before the owner's poll of
/// that turn, then five more turns. With `publishes` the upload publishes in
/// that turn, draws a PUT RESULT and no PUT ERROR, and a GET returns its
/// bytes; otherwise that poll ends it `TimedOut` with no PUT RESULT, nothing
/// is published and a GET of the key ends `Missing`.
fn brief_upload_whose_write_ends_in(write_end: u64, publishes: bool) {
    use super::fetch::Outcome;
    afresh(|| {
        scene(&PRINCIPALS, |mut scene| {
            let object = begin_brief_upload(&mut scene);
            scene.polls(write_end - scene.turn);
            assert_eq!(
                upload_counts(&scene),
                (1, 1, 0, 0),
                "before the write's turn the upload is live with its one write held by the disk"
            );
            let early = scene.replies(1);
            assert!(
                early
                    .iter()
                    .all(|reply| !matches!(reply.kind, Kind::PutError | Kind::PutResult)),
                "the owner sent no terminal before the write's turn: {early:?}"
            );
            scene.turns(1);
            let (held, _, timed_out, published) = upload_counts(&scene);
            assert_eq!(held, 0, "the turn's disk tick ended the write");
            assert_eq!(
                (timed_out, published),
                if publishes { (0, 1) } else { (1, 0) },
                "the poll of the turn the write ended in decides the upload"
            );
            scene.turns(5);
            let drained = upload_counts(&scene);
            let replies = scene.replies(1);
            let errors: Vec<_> = replies.iter().filter_map(error).collect();
            let results = replies
                .iter()
                .filter(|reply| reply.kind == Kind::PutResult)
                .count();
            let visible = scene.visible(5);
            let (outcome, bytes) = scene.read(0, 5, 0);
            if publishes {
                assert_eq!(errors, [], "{replies:?}");
                assert!(results >= 1, "{replies:?}");
                assert_eq!((drained.2, drained.3), (0, 1));
                assert!(visible, "the storage holds the object under the key");
                assert_eq!((outcome, bytes == object), (Some(Outcome::Complete), true));
            } else {
                assert_eq!(errors, [Status::TimedOut], "{replies:?}");
                assert_eq!(results, 0, "{replies:?}");
                assert_eq!(drained, (0, 0, 1, 0));
                assert!(!visible, "the storage holds no object under the key");
                assert_eq!((outcome, bytes == object), (Some(Outcome::Missing), false));
            }
        })
    });
}

/// A write that ends in the turn whose owner poll is the first at the
/// upload's deadline: that poll ends the upload `TimedOut` before it would
/// publish, with one PUT ERROR, no PUT RESULT and the key missing.
#[test]
fn a_deadline_in_the_publishing_turn_ends_the_upload_before_publication() {
    brief_upload_whose_write_ends_in(brief_upload_deadline(), false);
}

/// The same write ending one turn before the deadline publishes in that
/// turn, and the deadline's turn, which follows, leaves it published.
#[test]
fn a_write_ending_a_turn_before_the_deadline_publishes() {
    brief_upload_whose_write_ends_in(brief_upload_deadline() - 1, true);
}

#[test]
fn an_unwound_publication_ends_unknown_and_refuses_new_uploads() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(FRAGMENT_LEN as usize, 18);
        let (at, serial) = upload_within(&mut scene, &object, 20);
        let (header, body) = scene.fragment(at, serial, &object, 0);
        cut_next_publication();
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            scene.inject_edited(1, &header, &body, |_| {});
            scene.turns(10);
        }));
        assert!(unwound.is_err());
        let mut replies = Vec::new();
        scene.turns(300);
        assert!(scene.owner.poisoned());
        replies.extend(scene.replies(1));
        let errors: Vec<_> = replies.iter().filter_map(error).collect();
        assert_eq!(errors, [Status::UnknownOutcome], "{replies:?}");
        assert!(replies.iter().all(|reply| reply.kind != Kind::PutResult));
        let next = scene.frame(1, Kind::PutBegin, request(1, 2), 6, |_| {});
        assert_eq!(error(&scene.one(1, &next)), Some(Status::OwnerUnavailable));
    });
}

#[test]
fn a_publish_allowance_below_one_publication_ends_contended() {
    let config = OwnerConfig {
        put: PutConfig {
            publish_work: 1,
            ..OWNER.put
        },
        ..OWNER
    };
    scene_with(config, &PRINCIPALS, |mut scene| {
        let object = payload(FRAGMENT_LEN as usize, 20);
        let (at, serial) = ready_upload(&mut scene, &object);
        let (header, body) = scene.fragment(at, serial, &object, 0);
        let mut replies = scene.put_data(&header, &body);
        scene.turns(10);
        replies.extend(scene.replies(1));
        let errors: Vec<_> = replies.iter().filter_map(error).collect();
        assert_eq!(errors, [Status::Contended], "{replies:?}");
        assert_eq!(scene.live(), 0);
    });
}

#[test]
fn a_get_progresses_while_an_upload_fills_its_window() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(6 * FRAGMENT_LEN as usize, 21);
        let (at, serial) = ready_upload(&mut scene, &object);
        for index in 0..6 {
            let (header, body) = scene.fragment(at, serial, &object, index);
            scene.inject_edited(1, &header, &body, |_| {});
        }
        let start = scene.turn;
        assert_eq!(scene.fetch(1), payload(1000, 1));
        assert!(scene.turn - start < 100, "{}", scene.turn - start);
        let mut replies = Vec::new();
        for index in 4..6 {
            let (header, body) = scene.fragment(at, serial, &object, index);
            replies.extend(scene.put_data(&header, &body));
        }
        scene.turns(10);
        replies.extend(scene.replies(1));
        assert!(
            replies.iter().any(|reply| reply.kind == Kind::PutResult),
            "{replies:?}"
        );
        assert_eq!(scene.fetch(5), object);
    });
}

#[test]
fn an_invalidation_during_writes_keeps_the_upload_unpublished() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(2 * FRAGMENT_LEN as usize, 22);
        let (at, serial) = ready_upload(&mut scene, &object);
        for index in 0..2 {
            let (header, body) = scene.fragment(at, serial, &object, index);
            scene.inject_edited(1, &header, &body, |_| {});
        }
        scene.polls(2);
        let mut budget = WorkBudget::new(1 << 12);
        scene.owner.invalidate(&key(5), 4, &mut budget).unwrap();
        scene.turns(20);
        let replies = scene.replies(1);
        let errors: Vec<_> = replies.iter().filter_map(error).collect();
        assert_eq!(errors, [Status::Contended], "{replies:?}");
        assert!(replies.iter().all(|reply| reply.kind != Kind::PutResult));
        assert_eq!(scene.live(), 0);
        let id = scene.clients[0]
            .get(key(5), 0, 1 << 20, scene.turn * 100, 30_000_000)
            .unwrap();
        for _ in 0..50 {
            scene.turn_with(&mut [(Actor::Client(0), &mut |clients, _, now| {
                let _ = clients[0].poll(now);
            })]);
        }
        assert_eq!(
            scene.clients[0].outcome(id),
            Some(super::fetch::Outcome::Missing)
        );
    });
}

/// Sends fragments `indices` of `object` for the attempt `serial` at `at`,
/// polls the owner without ticking the device, and returns the write commands
/// the device accepted meanwhile, each still in flight.
pub(super) fn send_all(
    scene: &mut Scene<'_, '_>,
    at: u64,
    serial: u64,
    object: &[u8],
    indices: std::ops::Range<u32>,
) -> Vec<CommandToken> {
    let before = write_tokens(&scene.control).len();
    for index in indices {
        let (header, body) = scene.fragment(at, serial, object, index);
        scene.inject_edited(1, &header, &body, |_| {});
    }
    scene.polls(4);
    let writes = write_tokens(&scene.control).split_off(before);
    assert!(
        !writes.is_empty(),
        "the device accepted the upload's writes"
    );
    writes
}

/// A failed header write, the record's last write after its payload write,
/// ends the upload with `DeviceError`: no RESULT, the fill drains, and a GET
/// finds the key missing.
#[test]
fn a_failed_final_header_write_ends_the_upload_unpublished() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(2 * FRAGMENT_LEN as usize, 41);
        let (at, serial) = ready_upload(&mut scene, &object);
        let writes = send_all(&mut scene, at, serial, &object, 0..2);
        assert_eq!(writes.len(), 2, "one payload write, then the header write");
        let header = writes[1];
        scene
            .control
            .fault(header, Fault::Status(DeviceStatus::Kernel(-5)));
        scene.turns(20);
        let replies = scene.replies(1);
        let errors: Vec<_> = replies.iter().filter_map(error).collect();
        assert_eq!(errors, [Status::DeviceError], "{replies:?}");
        assert!(replies.iter().all(|reply| reply.kind != Kind::PutResult));
        assert_eq!(scene.live(), 0);
        assert!(!scene.visible(5));
        assert_eq!(scene.read(0, 5, 0).0, Some(super::fetch::Outcome::Missing));
    });
}

/// A follower joined to an upload whose header write fails reports the
/// upload's `DeviceError` once the fill drains, the cause the producer
/// recorded before it departed.
#[test]
fn a_failed_upload_records_its_cause_for_its_followers() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(2 * FRAGMENT_LEN as usize, 44);
        let (at, serial) = ready_upload(&mut scene, &object);
        let follower = scene
            .storage
            .join_fill(&key(5), u64::MAX, 4, &mut WorkBudget::new(1 << 12))
            .unwrap();
        assert_eq!(follower.serial(), serial);
        let writes = send_all(&mut scene, at, serial, &object, 0..2);
        scene
            .control
            .fault(writes[1], Fault::Status(DeviceStatus::Kernel(-5)));
        scene.turns(20);
        assert_eq!(
            follower.observe(4, &mut WorkBudget::new(1 << 12)),
            Ok(crate::storage::Observed::Ended(
                crate::storage::FillEnd::Failed(crate::storage::FillFailure::DeviceError)
            ))
        );
    });
}

#[test]
fn a_cancelled_upload_leaves_its_followers_missing() {
    for status in [Status::Cancelled, Status::TimedOut] {
        scene(&PRINCIPALS, |mut scene| {
            let object = payload(2 * FRAGMENT_LEN as usize, 45);
            let (at, serial) = ready_upload(&mut scene, &object);
            let follower = scene
                .storage
                .join_fill(&key(5), u64::MAX, 4, &mut WorkBudget::new(1 << 12))
                .unwrap();
            assert_eq!(follower.serial(), serial);
            let stop = scene.frame(1, Kind::PutCancel, at, 5, |header| {
                cancel(serial)(header);
                header.status = status as u16;
            });
            assert_eq!(error(&scene.one(1, &stop)), Some(status));
            scene.turns(20);
            assert_eq!(
                follower.observe(4, &mut WorkBudget::new(1 << 12)),
                Ok(crate::storage::Observed::Ended(
                    crate::storage::FillEnd::Missing
                )),
                "{status:?}"
            );
        });
    }
}

#[test]
fn a_parked_get_answers_missing_at_its_wake_once_the_withhold_holds() {
    use crate::failover::serving::Event as Authority;
    use crate::failover::withhold::{M_US, W_US};
    struct Clock;
    impl crate::storage::ServingClock for Clock {
        fn now_us(&self) -> Option<u64> {
            Some(W_US + 1)
        }
    }
    scene(&PRINCIPALS, |mut scene| {
        scene.owner.set_serving_clock(Box::new(Clock));
        let object = payload(2 * FRAGMENT_LEN as usize, 47);
        let (at, serial) = ready_upload(&mut scene, &object);
        let get = scene.get(0, request(2, 1), 5);
        scene.inject(0, &get);
        scene.turns(4);
        assert_eq!(scene.owner.parked_count(), 1, "the GET parks on the upload");
        assert!(scene.sent(0).iter().all(|reply| reply.kind != Kind::Error));
        scene.owner.authority_event(Authority::Refresh { at: 0 }, 0);
        scene
            .owner
            .authority_event(Authority::ReadFailed { sent_at: 1 }, 0);
        scene.owner.authority_event(
            Authority::Peer {
                read_at: Some(M_US + 2),
            },
            0,
        );
        assert!(scene.owner.authority_report().withheld);
        for index in 0..2 {
            let (header, body) = scene.fragment(at, serial, &object, index);
            scene.inject_edited(1, &header, &body, |_| {});
        }
        scene.turns(20);
        assert!(scene.visible(5), "the producer completes");
        assert_eq!(scene.owner.parked_count(), 0, "the follower detached");
        let statuses: Vec<_> = scene
            .sent(0)
            .iter()
            .filter(|reply| reply.kind == Kind::Error)
            .map(|reply| Status::from_wire(reply.status))
            .collect();
        assert_eq!(
            statuses,
            [Some(Status::Missing)],
            "the woken GET answers a miss"
        );
    });
}

#[test]
fn a_closed_owner_records_closed_for_its_uploads_followers() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(2 * FRAGMENT_LEN as usize, 46);
        let (_, serial) = ready_upload(&mut scene, &object);
        let follower = scene
            .storage
            .join_fill(&key(5), u64::MAX, 4, &mut WorkBudget::new(1 << 12))
            .unwrap();
        assert_eq!(follower.serial(), serial);
        scene.owner.close(scene.turn * 100);
        scene.turns(20);
        assert_eq!(scene.live(), 0);
        assert_eq!(
            follower.observe(4, &mut WorkBudget::new(1 << 12)),
            Ok(crate::storage::Observed::Ended(
                crate::storage::FillEnd::Failed(crate::storage::FillFailure::Closed)
            ))
        );
    });
}

/// Every upload status that names a producer outcome a GET can carry maps to
/// the failure its followers report, and every other status, a
/// cancellation, an expiry or a status of PUT alone, maps to none.
#[test]
fn upload_statuses_map_to_the_failures_followers_report() {
    use crate::storage::FillFailure;
    for wire in 1..=28u16 {
        let status = Status::from_wire(wire).unwrap();
        let expected = match status {
            Status::DeviceError => Some(FillFailure::DeviceError),
            Status::TimedOut => Some(FillFailure::TimedOut),
            Status::Closed => Some(FillFailure::Closed),
            Status::OwnerUnavailable => Some(FillFailure::OwnerUnavailable),
            Status::ClockUnavailable => Some(FillFailure::ClockUnavailable),
            Status::Contended => Some(FillFailure::Contended),
            Status::StoragePressure => Some(FillFailure::StoragePressure),
            Status::ObjectPressure => Some(FillFailure::ObjectPressure),
            _ => None,
        };
        assert_eq!(super::put::fill_failure(status), expected, "{status:?}");
        if expected.is_some() {
            assert!(status.is_get(), "{status:?} reaches a GET follower");
        }
    }
}

/// A write of a revoked attempt held past its successor's publication: the
/// successor takes a new serial and publishes its own bytes while the old
/// fill drains, and the old write's late terminal leaves the successor's
/// record readable and exact.
#[test]
fn an_old_write_terminal_after_revocation_leaves_the_live_successor_intact() {
    scene(&PRINCIPALS, |mut scene| {
        let first = payload(2 * FRAGMENT_LEN as usize, 42);
        let (at, serial) = ready_upload(&mut scene, &first);
        let old = send_all(&mut scene, at, serial, &first, 0..2);
        scene.control.hold(old[0]);
        let mut budget = WorkBudget::new(1 << 12);
        scene.owner.invalidate(&key(5), 4, &mut budget).unwrap();
        scene.turns(20);
        assert!(
            scene
                .replies(1)
                .iter()
                .all(|reply| reply.kind != Kind::PutResult)
        );
        assert_eq!(scene.live(), 1, "the revoked fill keeps its held write");
        // The successor arrives from the other peer, whose PUT lane is free.
        let next = payload(FRAGMENT_LEN as usize, 43);
        let later = request(1, 1);
        let successor = scene.begin(0, later, 5);
        assert_ne!(successor, serial);
        let prepared = scene.frame(
            0,
            Kind::PutPrepare,
            later,
            5,
            prepare(successor, next.len() as u32, 60_000),
        );
        assert_eq!(scene.one(0, &prepared).kind, Kind::PutReady);
        let (header, body) = scene.fragment_from(0, later, successor, 5, &next, 0);
        scene.inject_edited(0, &header, &body, |_| {});
        scene.turns(20);
        let replies = scene.replies(0);
        assert!(
            replies.iter().any(|reply| reply.kind == Kind::PutResult),
            "{replies:?}"
        );
        assert_eq!(scene.live(), 1, "the old fill still holds its write");
        scene.control.release(old[0]);
        scene.turns(20);
        let errors: Vec<_> = scene.replies(1).iter().filter_map(error).collect();
        assert_eq!(
            errors,
            [Status::Contended],
            "the revoked attempt ends unpublished"
        );
        assert_eq!(scene.live(), 0, "the old fill ends at its late terminal");
        // The raw frames above spent client 0's session sequence; a new session reads.
        scene.reopen(0);
        assert_eq!(
            scene.fetch(5),
            next,
            "the late terminal leaves the successor exact"
        );
    });
}

/// A refused submit that loses the volume after another write of the same
/// upload was accepted: the upload ends `OwnerUnavailable` unpublished, the
/// ended fill keeps the accepted write until its terminal, and the lost volume
/// refuses a later BEGIN.
#[test]
fn an_owner_loss_after_an_accepted_submit_ends_unpublished_and_refuses_later_begins() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(6 * FRAGMENT_LEN as usize, 44);
        let (at, serial) = ready_upload(&mut scene, &object);
        let accepted = send_all(&mut scene, at, serial, &object, 0..4);
        for &token in &accepted {
            scene.control.hold(token);
        }
        scene.control.refuse_next(SubmitRefusal {
            reason: RefusalReason::DeviceGone,
            code: None,
        });
        for index in 4..6 {
            let (header, body) = scene.fragment(at, serial, &object, index);
            scene.inject_edited(1, &header, &body, |_| {});
        }
        scene.polls(8);
        assert!(
            scene.control.events().iter().any(|event| matches!(
                event,
                Event::Refused {
                    reason: RefusalReason::DeviceGone,
                    ..
                }
            )),
            "this upload's next write met the refusal"
        );
        let replies = scene.replies(1);
        let errors: Vec<_> = replies.iter().filter_map(error).collect();
        assert_eq!(
            errors,
            [Status::OwnerUnavailable],
            "the refused submit lost the volume"
        );
        assert!(replies.iter().all(|reply| reply.kind != Kind::PutResult));
        assert_eq!(scene.live(), 1, "the ended fill keeps its accepted write");
        let begin = scene.frame(0, Kind::PutBegin, request(2, 3), 6, |_| {});
        assert_eq!(
            error(&scene.one(0, &begin)),
            Some(Status::OwnerUnavailable),
            "the lost volume refuses a later BEGIN"
        );
        for &token in &accepted {
            scene.control.release(token);
        }
        scene.turns(20);
        assert_eq!(scene.live(), 0, "the fill ends at its write's terminal");
        assert!(!scene.visible(5));
    });
}

/// Stale frames of a published upload on a wire slot a successor now holds: a
/// DATA frame of the older generation drops with a count, its PREPARE answers
/// `UnknownOutcome`, the successor's receipt stays where it was, and the
/// successor's own matching PREPARE still replays its ACK.
#[test]
fn stale_frames_of_a_released_upload_reach_no_successor_on_the_same_wire_slot() {
    scene(&PRINCIPALS, |mut scene| {
        let first = payload(FRAGMENT_LEN as usize, 48);
        let (at, serial) = ready_upload(&mut scene, &first);
        let (header, body) = scene.fragment(at, serial, &first, 0);
        scene.inject_edited(1, &header, &body, |_| {});
        scene.turns(20);
        assert!(scene.replies(1).iter().any(|r| r.kind == Kind::PutResult));
        assert_eq!(scene.live(), 0);
        // The successor takes the same wire slot under the next generation.
        let next = payload(2 * FRAGMENT_LEN as usize, 49);
        let later = request(1, 2);
        let successor = scene.begin(1, later, 5);
        assert_ne!(successor, serial);
        let prepared = scene.frame(
            1,
            Kind::PutPrepare,
            later,
            5,
            prepare(successor, next.len() as u32, 60_000),
        );
        assert_eq!(scene.one(1, &prepared).kind, Kind::PutReady);
        let (header, body) = scene.fragment(later, successor, &next, 0);
        assert_eq!(
            acks(&scene.put_data(&header, &body)).last(),
            Some(&(1, 0, 2))
        );
        // Stale DATA of the released upload drops with a count; its PREPARE
        // answers UnknownOutcome.
        let dropped = scene.owner.report().dropped;
        let (stale, body) = scene.fragment(at, serial, &first, 0);
        assert!(scene.put_data(&stale, &body).is_empty());
        assert_eq!(scene.owner.report().dropped, dropped + 1);
        let retry = scene.frame(
            1,
            Kind::PutPrepare,
            at,
            5,
            prepare(serial, first.len() as u32, 60_000),
        );
        assert_eq!(error(&scene.one(1, &retry)), Some(Status::UnknownOutcome));
        // The successor's receipt is unchanged and its matching PREPARE replays the ACK.
        let again = scene.frame(
            1,
            Kind::PutPrepare,
            later,
            5,
            prepare(successor, next.len() as u32, 60_000),
        );
        assert_eq!(acks(&[scene.one(1, &again)]), [(1, 0, 2)]);
        assert_eq!(scene.live(), 1);
    });
}

/// Session replacement after DATA was accepted, with the upload's writes held:
/// the replaced upload's logical work ends and its fill drains until its own
/// writes end, keeping the extent reserved, its wire slot bound, the peer's
/// one PUT share and the key's fill authority; the peer's BEGIN in the new
/// session is refused while the fill drains and admitted on the old slot once
/// it released; the other peer's successor on another key is admitted and
/// published beside the draining custody from its own share; stale DATA,
/// PREPARE and CANCEL of the old serial, delivered before
/// and after the successor's admission, drop or answer without touching the
/// successor's receipt or publication; the old writes' terminals, one before
/// and one after the successor's admission, end only the old fill, whose
/// extent returns unpublished.
#[test]
fn a_replaced_upload_drains_its_own_writes_while_a_successor_publishes_beside_it() {
    scene(&PRINCIPALS, |mut scene| {
        let old = payload(2 * FRAGMENT_LEN as usize, 51);
        let (at, serial) = ready_upload(&mut scene, &old);
        let writes = send_all(&mut scene, at, serial, &old, 0..2);
        for &token in &writes {
            scene.control.hold(token);
        }
        let reserved = scene.ledger();
        assert_eq!(
            reserved.reserved,
            old.len(),
            "the fill holds the old bytes reserved"
        );
        scene.reopen(1);
        assert_eq!(
            scene.live(),
            1,
            "the replaced upload's fill drains its held writes"
        );
        assert_eq!(scene.ledger(), reserved);
        // Stale frames of the old serial before any successor exists.
        let (stale, body) = scene.fragment(at, serial, &old, 1);
        assert!(scene.put_data(&stale, &body).is_empty());
        let retry = scene.frame(
            1,
            Kind::PutPrepare,
            at,
            5,
            prepare(serial, old.len() as u32, 60_000),
        );
        assert_eq!(
            error(&scene.one(1, &retry)),
            Some(Status::UnknownOutcome),
            "the old serial answers UnknownOutcome in the new session"
        );
        // One write's terminal before any successor: the fill keeps draining
        // on the other, with its extent reserved.
        scene.control.release(writes[0]);
        scene.turns(20);
        assert_eq!(
            scene.live(),
            1,
            "one held write keeps the old fill draining"
        );
        assert_eq!(scene.ledger(), reserved);
        // The peer's one PUT share stays the draining fill's, and the key's
        // fill authority is the old fill's until it ends. The wire binding's
        // own refusal is `namespace_tests::retirement_forgets_evidence_and_keeps_a_drain_bound_until_its_own_release`.
        let begin = scene.frame(1, Kind::PutBegin, at, 5, |_| {});
        assert_eq!(
            error(&scene.one(1, &begin)),
            Some(Status::RequestPressure),
            "the draining fill holds the peer's share"
        );
        let same_key = scene.frame(0, Kind::PutBegin, request(2, 1), 5, |_| {});
        assert_eq!(
            error(&scene.one(0, &same_key)),
            Some(Status::InProgress),
            "the draining fill keeps the key's authority"
        );
        // The InProgress refusal settled peer 0's generation 1 on wire slot 2,
        // so its successor takes the next generation.
        let new = payload(FRAGMENT_LEN as usize, 52);
        let later = request(2, 2);
        let successor = scene.begin(0, later, 6);
        assert_ne!(successor, serial);
        let prepared = scene.frame(
            0,
            Kind::PutPrepare,
            later,
            6,
            prepare(successor, new.len() as u32, 60_000),
        );
        assert_eq!(scene.one(0, &prepared).kind, Kind::PutReady);
        let (header, body) = scene.fragment_from(0, later, successor, 6, &new, 0);
        scene.inject_edited(0, &header, &body, |_| {});
        scene.turns(20);
        let replies = scene.replies(0);
        assert!(
            replies.iter().any(|reply| reply.kind == Kind::PutResult),
            "{replies:?}"
        );
        assert_eq!(scene.live(), 1, "the old fill is still draining");
        assert_eq!(
            scene.ledger().reserved,
            reserved.reserved,
            "the old extent stays reserved"
        );
        // Stale frames of the old serial after the successor published.
        let (stale, body) = scene.fragment(at, serial, &old, 0);
        assert!(scene.put_data(&stale, &body).is_empty());
        let cancel_old = scene.frame(1, Kind::PutCancel, at, 5, cancel(serial));
        assert_eq!(
            error(&scene.one(1, &cancel_old)),
            Some(Status::UnknownOutcome)
        );
        let again = scene.frame(
            0,
            Kind::PutPrepare,
            later,
            6,
            prepare(successor, new.len() as u32, 60_000),
        );
        assert_eq!(
            scene.one(0, &again).kind,
            Kind::PutResult,
            "the successor replays its own result"
        );
        scene.reopen(0);
        assert_eq!(scene.fetch(6), new, "the successor's bytes are published");
        assert!(!scene.visible(5), "the old upload published nothing");
        // The old fill's last write ends: the fill aborts and its extent returns unpublished.
        scene.control.release(writes[1]);
        scene.turns(20);
        assert_eq!(scene.live(), 0, "the old fill ended at its own terminals");
        assert_eq!(scene.ledger().reserved, 0);
        assert!(!scene.visible(5));
        assert_eq!(
            scene.fetch(6),
            new,
            "the old terminals left the successor's record exact"
        );
        // The old slot and the key are reusable once the old binding released;
        // the new session's refused BEGIN settled generation 1 on the slot, so
        // its next BEGIN there takes generation 2.
        let reuse = scene.begin(1, request(1, 2), 5);
        assert_ne!(reuse, serial);
        assert_eq!(scene.live(), 1);
    });
}

/// An upload cancelled with its writes held beside a healthy GET of another
/// key: the GET completes exact while the cancelled fill holds its writes,
/// and the fill ends only after the late writes reach their terminals.
#[test]
fn late_writes_after_a_cancel_drain_beside_a_healthy_get() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(2 * FRAGMENT_LEN as usize, 45);
        let (at, serial) = ready_upload(&mut scene, &object);
        let writes = send_all(&mut scene, at, serial, &object, 0..2);
        for &token in &writes {
            scene.control.hold(token);
        }
        let stop = scene.frame(1, Kind::PutCancel, at, 5, cancel(serial));
        scene.inject(1, &stop);
        scene.turns(4);
        assert_eq!(scene.live(), 1, "the cancelled fill holds its writes");
        assert_eq!(
            scene.fetch(1),
            payload(1000, 1),
            "a healthy GET beside the held writes"
        );
        // A generated order can deliver the GET's COMPLETE in the round the
        // owner sends it, before the owner's next turn releases the ended
        // GET, so the scene turns, bounded, until that release.
        crate::sim::round::catch_up(|| {
            scene.live() == 1 || {
                scene.turns(1);
                false
            }
        });
        assert_eq!(scene.live(), 1);
        for &token in &writes {
            scene.control.release(token);
        }
        scene.turns(20);
        assert_eq!(scene.live(), 0);
        let errors: Vec<_> = scene.replies(1).iter().filter_map(error).collect();
        assert_eq!(errors, [Status::Cancelled]);
        assert!(!scene.visible(5));
    });
}

/// An upload that ends with a device write outstanding frees its wire slot
/// once its PUT ERROR is sent, whichever end sends it: a GET of the same peer
/// on that slot at the next generation is admitted and starts while the ended
/// fill still holds its write, and the fill drains once the write returns.
/// The wire binding is the only state the end releases early; the draining
/// record keeps its table slot until the write's terminal.
#[test]
fn an_ended_upload_frees_its_wire_slot_while_its_write_drains() {
    for end in [Status::Cancelled, Status::TimedOut, Status::DeviceError] {
        scene(&PRINCIPALS, |mut scene| {
            let object = payload(2 * FRAGMENT_LEN as usize, 62);
            let remaining_ms = if end == Status::TimedOut { 30 } else { 60_000 };
            let (at, serial) = upload_at(&mut scene, request(1, 1), &object, remaining_ms);
            let writes = send_all(&mut scene, at, serial, &object, 0..2);
            let held = match end {
                Status::Cancelled => {
                    writes.iter().for_each(|&token| scene.control.hold(token));
                    let stop = scene.frame(1, Kind::PutCancel, at, 5, cancel(serial));
                    scene.inject(1, &stop);
                    writes.clone()
                }
                Status::TimedOut => {
                    writes.iter().for_each(|&token| scene.control.hold(token));
                    while scene.owner.put_report().failed_timed_out == 0 {
                        scene.turns(1);
                        assert!(scene.turn < 5_000, "the upload's deadline passed");
                    }
                    writes.clone()
                }
                _ => {
                    scene.control.hold(writes[0]);
                    scene
                        .control
                        .fault(writes[1], Fault::Status(DeviceStatus::Kernel(-5)));
                    vec![writes[0]]
                }
            };
            scene.turns(4);
            let sent = scene.sent(1);
            assert_eq!(
                sent.iter()
                    .filter(|frame| frame.request == at)
                    .filter_map(error)
                    .collect::<Vec<_>>(),
                [end],
                "{end:?}: the owner sent the upload's terminal: {sent:?}"
            );
            assert_eq!(
                scene.owner.put_occupancy().live,
                1,
                "{end:?}: the ended fill holds its write"
            );
            assert!(
                !slot_bound(&scene, 1),
                "{end:?}: the sent terminal freed the slot"
            );
            let again = scene.frame(1, Kind::PutCancel, at, 5, cancel(serial));
            assert_eq!(
                error(&scene.one(1, &again)),
                Some(end),
                "{end:?}: the unbound draining record's terminal replays"
            );
            reused_while_draining(&mut scene, &held, &format!("{end:?}"));
        });
    }
}

/// Whether peer 1's wire slot `slot` binds a request.
pub(super) fn slot_bound(scene: &Scene<'_, '_>, slot: u16) -> bool {
    scene
        .owner
        .request_slot(PeerId(1), slot)
        .is_some_and(|row| row.active.is_some())
}

/// A GET of peer 1 on wire slot 1 at generation 2 is admitted and starts
/// while the ended fill still holds the writes `held`, and the fill drains
/// once they return, its key unpublished.
fn reused_while_draining(scene: &mut Scene<'_, '_>, held: &[CommandToken], label: &str) {
    let reuse = request(1, 2);
    let get = scene.get(1, reuse, 1);
    scene.inject(1, &get);
    scene.turns(4);
    let answers: Vec<_> = scene
        .sent(1)
        .into_iter()
        .filter(|frame| frame.request == reuse)
        .collect();
    assert_eq!(
        answers.first().map(|frame| frame.kind),
        Some(Kind::Start),
        "{label}: the GET on the ended upload's wire slot is admitted: {answers:?}"
    );
    assert_eq!(
        scene.owner.put_occupancy().live,
        1,
        "{label}: the write is still held"
    );
    for &token in held {
        scene.control.release(token);
    }
    scene.turns(20);
    assert_eq!(
        scene.owner.put_occupancy().live,
        0,
        "{label}: the ended fill drains at its write's terminal"
    );
    assert!(!scene.visible(5));
}

/// An upload whose first PUT ERROR a full reply ring dropped still holds its
/// wire slot while its write drains; the answer its client's resent CANCEL
/// draws frees the slot once sent: the replayed terminal while the retained
/// row lasts, and `UnknownOutcome` after it expired. A GET of the same peer
/// on that slot at the next generation is then admitted while the ended
/// fill still holds its write.
#[test]
fn a_replayed_put_error_frees_the_wire_slot_its_dropped_terminal_kept() {
    let config = OwnerConfig {
        serve: ServeConfig {
            replies: 1,
            ..OWNER.serve
        },
        ..OWNER
    };
    for (remaining_ms, answer) in [(60_000, Status::Cancelled), (30, Status::UnknownOutcome)] {
        scene_with(config, &PRINCIPALS, |mut scene| {
            let object = payload(2 * FRAGMENT_LEN as usize, 64);
            let (at, serial) = upload_at(&mut scene, request(1, 1), &object, remaining_ms);
            let writes = send_all(&mut scene, at, serial, &object, 0..2);
            writes.iter().for_each(|&token| scene.control.hold(token));
            scene.turns(4);
            scene.sent(1);
            let dropped = scene.owner.serve_report().dropped_replies;
            let other = scene.frame(1, Kind::PutCancel, request(2, 1), 6, cancel(serial));
            let stop = scene.frame(1, Kind::PutCancel, at, 5, cancel(serial));
            scene.inject(1, &other);
            scene.inject(1, &stop);
            scene.turns(4);
            let sent = scene.sent(1);
            assert!(
                sent.iter().all(|frame| frame.request != at),
                "{answer:?}: the full ring dropped the upload's terminal: {sent:?}"
            );
            assert_eq!(scene.owner.serve_report().dropped_replies, dropped + 1);
            assert_eq!(scene.owner.put_report().cancelled, 1);
            if answer == Status::UnknownOutcome {
                scene.turns((u64::from(remaining_ms) * 1_000 + config.serve.linger_us) / 100 + 20);
                scene.sent(1);
            }
            assert!(
                slot_bound(&scene, 1),
                "{answer:?}: the unsent terminal left the slot bound"
            );
            let again = scene.frame(1, Kind::PutCancel, at, 5, cancel(serial));
            assert_eq!(error(&scene.one(1, &again)), Some(answer));
            reused_while_draining(&mut scene, &writes, &format!("{answer:?}"));
        });
    }
}

#[test]
fn a_forged_fragment_in_a_pair_drops_alone_and_the_upload_completes_exact() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(4 * FRAGMENT_LEN as usize, 23);
        let (at, serial) = ready_upload(&mut scene, &object);
        let dropped = scene.owner.report().dropped;
        for index in 0..4 {
            let (header, body) = scene.fragment(at, serial, &object, index);
            if index != 1 {
                scene.inject_edited(1, &header, &body, |_| {});
                continue;
            }
            let mut forged = scene.sealed(1, &header, &body, |_| {});
            forged[HEADER_LEN + 4000] ^= 1;
            scene.nets[1].borrow_mut().inject(1, &forged);
        }
        scene.turns(4);
        assert_eq!(scene.owner.report().dropped, dropped + 1);
        let last = *acks(&scene.replies(1)).last().unwrap();
        assert_eq!((last.0, last.1), (1, 0b11), "{last:?}");
        let (header, body) = scene.fragment(at, serial, &object, 1);
        scene.put_data(&header, &body);
        scene.turns(10);
        assert_eq!(scene.live(), 0);
        assert_eq!(scene.fetch(5), object);
    });
}

/// The later frame of a receive batch that opens with fragment 0 of a ready upload.
#[derive(Debug, Clone, Copy)]
enum Later {
    /// The upload's PREPARE, sent again.
    Prepare,
    /// A GET of a key the owner does not hold.
    Get,
}

/// What the owner did with such a batch and with the upload's last fragment after it.
#[derive(Debug)]
struct Batch {
    /// How far the later frame's sequence lies above fragment 0's.
    distance: u64,
    /// Frames the owner dropped over the batch's turns.
    dropped: u64,
    /// The highest base a PUT ACK of those turns carried; `None` when the owner sent no PUT ACK.
    base: Option<u32>,
    /// The statuses of the PUT ERRORs the owner sent, over the batch's turns and the turns after fragment 1.
    errors: Vec<Status>,
    /// PUT RESULTs the owner sent once fragment 1 followed.
    results: usize,
}

/// The replay window's size in sequences under the owner's caps.
fn replay_window() -> u64 {
    super::session::Sessions::words(OWNER.caps.window) as u64 * 64
}

/// Readies a two-fragment upload, then injects fragment 0 and, behind it, a `later` frame of the same peer whose
/// sequence lies `distance` above the fragment's, both before the owner's next turn. The owner holds PUT DATA
/// frames in a group and handles other frames as it meets them. Admitting a later frame one replay window or more
/// above the fragment would age the fragment out, so the owner takes the pending group before such a frame. After
/// the owner's turns fragment 1 follows and the upload runs out.
fn batch_of_fragment_then(later: Later, distance: u64) -> Batch {
    let mut batch = None;
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(2 * FRAGMENT_LEN as usize, 24);
        let (at, serial) = ready_upload(&mut scene, &object);
        let dropped = scene.owner.report().dropped;
        let (zero, body) = scene.fragment(at, serial, &object, 0);
        let sequence = zero.sequence + distance;
        let behind = match later {
            Later::Prepare => scene.frame(1, Kind::PutPrepare, at, 5, |header| {
                prepare(serial, object.len() as u32, 60_000)(header);
                header.sequence = sequence;
            }),
            Later::Get => Header {
                sequence,
                ..scene.get(1, request(2, 1), 9)
            },
        };
        scene.inject_edited(1, &zero, &body, |_| {});
        scene.inject(1, &behind);
        scene.turns(4);
        let first = scene.replies(1);
        let dropped = scene.owner.report().dropped - dropped;
        // The scene numbers its frames from its own counter, which the later frame's sequence left behind.
        let (last, body) = scene.fragment(at, serial, &object, 1);
        let last = Header {
            sequence: behind.sequence + 1,
            ..last
        };
        scene.inject_edited(1, &last, &body, |_| {});
        scene.turns(12);
        let rest = scene.replies(1);
        batch = Some(Batch {
            distance: behind.sequence - zero.sequence,
            dropped,
            base: acks(&first).iter().map(|ack| ack.0).max(),
            errors: first.iter().chain(&rest).filter_map(error).collect(),
            results: (rest.iter())
                .filter(|reply| reply.kind == Kind::PutResult)
                .count(),
        });
    });
    batch.expect("the scene ran its body")
}

/// The outcome every distance must give: the batch loses no frame, fragment 0 is receipted and the upload
/// publishes once.
fn kept_and_receipted(batch: &Batch) {
    assert_eq!(batch.dropped, 0, "no frame dropped: {batch:?}");
    assert_eq!(batch.base, Some(1), "fragment 0 taken: {batch:?}");
    assert_eq!(batch.errors, [], "no PUT ERROR: {batch:?}");
    assert_eq!(batch.results, 1, "the upload publishes once: {batch:?}");
}

/// A resent PREPARE exactly one replay window above the pending fragment would age the fragment out; the owner
/// takes the fragment first.
#[test]
fn a_fragment_ahead_of_a_frame_a_replay_window_later_is_taken() {
    let batch = batch_of_fragment_then(Later::Prepare, replay_window());
    assert_eq!(batch.distance, replay_window());
    kept_and_receipted(&batch);
}

/// A GET three replay windows above the pending fragment would age the fragment out as well; the owner takes the
/// fragment first.
#[test]
fn a_fragment_ahead_of_a_get_three_replay_windows_later_is_taken() {
    let batch = batch_of_fragment_then(Later::Get, 3 * replay_window());
    assert_eq!(batch.distance, 3 * replay_window());
    kept_and_receipted(&batch);
}

/// The control: a PREPARE one sequence short of a window leaves the fragment inside the window whichever frame
/// the session admits first, and the outcome is the same.
#[test]
fn a_fragment_ahead_of_a_frame_inside_its_replay_window_is_taken() {
    let batch = batch_of_fragment_then(Later::Prepare, replay_window() - 1);
    assert_eq!(batch.distance, replay_window() - 1);
    kept_and_receipted(&batch);
}

#[test]
fn the_put_core_charges_exactly_the_bytes_it_allocates() {
    let (slots, peers) = (130, 3);
    let requests = Requests::<(), ()>::new(
        RequestTable::new(slots, peers, 2),
        4,
        &mut EngineBudget::new(1 << 24),
    )
    .unwrap();
    let config = PutConfig {
        puts: 3,
        ..OWNER.put
    };
    let limits = PutLimits {
        linger_us: 0,
        max_wait_us: 0,
        tries: 1,
        work: 1,
        fragments: 7,
        write_cap: 8,
    };
    let charge = PutCore::charge(&config, (peers, slots), limits.fragments).unwrap();
    let mut exact = EngineBudget::new(charge);
    let bytes = crate::instrument::allocated_bytes();
    let core = PutCore::new(config, &limits, &requests, &mut exact);
    assert_eq!(
        crate::instrument::allocated_bytes() - bytes,
        charge,
        "the charge is the bytes the core allocates"
    );
    assert!(core.is_ok());
    assert_eq!(exact.used(), charge);
    let wider = PutCore::charge(&config, (peers, slots), limits.fragments + 1).unwrap();
    assert_eq!(
        wider - charge,
        config.puts as usize * 24,
        "each lane holds 24 bytes of evidence per fragment"
    );
}

#[test]
fn the_reserve_tally_counts_each_refusal_once_and_a_pressure_cause_in_its_one_part() {
    use crate::storage::{FillReserveError as Error, LayoutError};
    use ReserveRefusal::{Before, Fill};
    const SLOTS: usize = 0;
    const PAYLOAD: usize = 1;
    const CLEAN: usize = 2;
    const RETIRED: usize = 3;
    let rows = [
        (Fill(Error::TornDown), Status::OwnerUnavailable, None),
        (
            Fill(Error::Layout(LayoutError::UnknownLength)),
            Status::TooLarge,
            None,
        ),
        (Fill(Error::Closed), Status::Closed, None),
        (Fill(Error::BudgetExhausted), Status::Contended, None),
        (Fill(Error::Contended), Status::Contended, None),
        (
            Fill(Error::ObjectSlotsFull),
            Status::StoragePressure,
            Some(SLOTS),
        ),
        (
            Fill(Error::PayloadFull),
            Status::StoragePressure,
            Some(PAYLOAD),
        ),
        (
            Fill(Error::CleanReserve),
            Status::StoragePressure,
            Some(CLEAN),
        ),
        (
            Fill(Error::RetiredPressure),
            Status::StoragePressure,
            Some(RETIRED),
        ),
        (Fill(Error::Superseded), Status::Contended, None),
        (Fill(Error::Bootstrapping), Status::Contended, None),
        (Fill(Error::Corrupt), Status::OwnerUnavailable, None),
        (Fill(Error::IndexFull), Status::ObjectPressure, None),
        (Fill(Error::LeaseLimit), Status::LeasePressure, None),
        (Before(Status::TooLarge), Status::TooLarge, None),
        (
            Before(Status::OwnerUnavailable),
            Status::OwnerUnavailable,
            None,
        ),
        (Before(Status::Closed), Status::Closed, None),
        (
            Before(Status::ClockUnavailable),
            Status::ClockUnavailable,
            None,
        ),
        (Before(Status::InvalidRequest), Status::InvalidRequest, None),
    ];
    let requests = Requests::<(), ()>::new(
        RequestTable::new(4, 2, 2),
        4,
        &mut EngineBudget::new(1 << 24),
    )
    .unwrap();
    let limits = PutLimits {
        linger_us: 0,
        max_wait_us: 0,
        tries: 1,
        work: 1,
        fragments: 7,
        write_cap: 8,
    };
    for (refusal, status, part) in rows {
        let mut core = PutCore::new(
            OWNER.put,
            &limits,
            &requests,
            &mut EngineBudget::new(1 << 24),
        )
        .unwrap();
        assert_eq!(core.report(), PutReport::default());
        assert_eq!(core.reserve_status(refusal), status, "{refusal:?}");
        let report = core.report();
        let mut expected = [0; 4];
        if let Some(part) = part {
            expected[part] = 1;
        }
        assert_eq!(
            (report.reserve_refused, refusal_parts(&report)),
            (1, expected),
            "{refusal:?}"
        );
        assert_eq!(
            report.reserve_refused_bootstrapping,
            u64::from(matches!(refusal, Fill(Error::Bootstrapping))),
            "{refusal:?}"
        );
        assert_eq!(
            PutReport {
                reserve_refused: 0,
                reserve_refused_slots: 0,
                reserve_refused_payload: 0,
                reserve_refused_clean_reserve: 0,
                reserve_refused_retired: 0,
                reserve_refused_bootstrapping: 0,
                ..report
            },
            PutReport::default(),
            "{refusal:?} moves no other counter"
        );
    }
}

pub(super) fn refusal_parts(report: &PutReport) -> [u64; 4] {
    [
        report.reserve_refused_slots,
        report.reserve_refused_payload,
        report.reserve_refused_clean_reserve,
        report.reserve_refused_retired,
    ]
}

/// Uploads `object` under key `name` at request `at` from peer 1 and runs
/// the turns that publish it.
fn publish_upload(scene: &mut Scene<'_, '_>, at: u64, name: u8, object: &[u8]) {
    let serial = ready_upload_at(scene, at, name, object);
    for index in 0..FragmentGeometry::fragments(object.len() as u64) as u32 {
        let (header, body) = scene.fragment_from(1, at, serial, name, object, index);
        scene.put_data(&header, &body);
    }
    scene.turns(10);
}

/// With the clean reserve `UNITS - 3 × Cmax` and `T = Cmax`, the structural
/// floor of the owner's two PUTs is the payload units, so the owner starts.
/// Two published uploads of the largest charge and the scene's one-unit
/// object leave `Cmax - 1` units claimable with maintenance idle, and a
/// third PREPARE of the largest body refuses on the clean reserve before
/// any change.
#[test]
fn a_prepare_short_of_the_clean_reserve_counts_under_its_part() {
    const UNITS: u64 = 130;
    let storage = storage_marked(UNITS as usize, |largest| {
        UNITS - (u64::from(PUTS) + 1) * largest
    });
    assert_eq!(
        storage.domain_report().unwrap().placeable_units,
        UNITS,
        "the largest charge divides the payload units"
    );
    let idle = OwnerConfig {
        maintain_work: 0,
        ..OWNER
    };
    scene_over(storage, idle, &PRINCIPALS, |mut scene| {
        for (generation, name) in [(1, 6), (2, 7)] {
            let object = payload(BODY_CAP as usize, u64::from(name));
            publish_upload(&mut scene, request(1, generation), name, &object);
            // Service frees the published upload's fill record for the next BEGIN.
            scene
                .storage
                .service_fills(
                    crate::index::ShardIndex(0),
                    3,
                    &mut WorkBudget::new(1 << 10),
                )
                .unwrap();
        }
        assert_eq!(scene.owner.put_report().published, 2);
        let domain = scene.storage.domain_report().unwrap();
        assert_eq!(domain.low_units, UNITS, "the floor is the payload units");
        assert_eq!(
            (u64::from(PUTS) + 1) * (domain.claimable_units + 1),
            UNITS - domain.reserve_units,
            "one unit short of the largest charge: {domain:?}"
        );
        let at = request(1, 3);
        let serial = scene.begin(1, at, 10);
        let (ledger, escrowed) = (scene.ledger(), escrow(&scene));
        let header = scene.frame(
            1,
            Kind::PutPrepare,
            at,
            10,
            prepare(serial, BODY_CAP, 1_000),
        );
        assert_eq!(error(&scene.one(1, &header)), Some(Status::StoragePressure));
        assert_eq!(scene.live(), 0, "the refusal ended the attempt");
        assert_eq!((scene.ledger(), escrow(&scene)), (ledger, escrowed));
        let report = scene.owner.put_report();
        assert_eq!(
            (report.reserve_refused, refusal_parts(&report)),
            (1, [0, 0, 1, 0]),
            "{report:?}"
        );
        assert_eq!(report.failed_other, 1, "{report:?}");
    });
}

/// An unformatted recovery owner keeps READY and payload work withheld.
#[test]
fn recovering_withholds_ready_and_put_under_received_client_traffic() {
    scene_unformatted(|mut scene| {
        let before = scene.owner.report();
        let ledger = scene.ledger();
        scene.clients[0].session(0);
        for turn in 1..16 {
            let _ = scene.clients[0].poll(turn * 100);
            scene.nets[0].borrow_mut().advance(turn);
            scene.owner.poll(turn * 100);
        }
        assert!(scene.owner.report().received > before.received);
        assert_ne!(scene.clients[0].state(), SessionState::Active);
        assert_eq!(
            scene.owner.authority_report().state,
            crate::failover::serving::State::Recovering
        );
        assert_eq!(scene.owner.report().sent, before.sent);
        assert_eq!(scene.live(), 0);
        assert_eq!(scene.ledger(), ledger);
        assert_eq!(scene.owner.put_report().published, 0);
    });
}

#[test]
fn a_prepare_after_a_withdrawal_ends_closed() {
    scene(&PRINCIPALS, |mut scene| {
        assert_eq!(
            scene.storage.withdraw(),
            crate::storage::Readiness::Withheld
        );
        let at = request(1, 1);
        let serial = scene.begin(1, at, 10);
        let ledger = scene.ledger();
        let header = scene.frame(1, Kind::PutPrepare, at, 10, prepare(serial, 100, 1_000));
        assert_eq!(error(&scene.one(1, &header)), Some(Status::Closed));
        assert_eq!(scene.live(), 0, "the refusal ended the attempt");
        assert_eq!(scene.ledger(), ledger);
        let report = scene.owner.put_report();
        assert_eq!(
            (
                report.reserve_refused,
                report.reserve_refused_bootstrapping,
                refusal_parts(&report)
            ),
            (1, 0, [0; 4]),
            "{report:?}"
        );
    });
}

#[test]
fn a_prepare_at_the_retired_allowance_counts_under_its_part_and_keeps_the_incumbent() {
    let storage = storage(8);
    let idle = OwnerConfig {
        maintain_work: 0,
        ..OWNER
    };
    scene_over(storage, idle, &PRINCIPALS, |mut scene| {
        let object = payload(BODY_CAP as usize, 31);
        publish_upload(&mut scene, request(1, 1), 5, &object);
        assert_eq!(scene.owner.put_report().published, 1);
        let mut budget = WorkBudget::new(1 << 12);
        scene.owner.invalidate(&key(5), 4, &mut budget).unwrap();
        let domain = scene.storage.domain_report().unwrap();
        assert_eq!(domain.retired_units, domain.retired_limit, "{domain:?}");
        let incumbent = scene.fetch(1);
        scene
            .storage
            .service_fills(
                crate::index::ShardIndex(0),
                3,
                &mut WorkBudget::new(1 << 10),
            )
            .unwrap();
        assert_eq!(scene.storage.domain_report(), Some(domain));
        let at = request(1, 2);
        let serial = scene.begin(1, at, 1);
        let (ledger, escrowed) = (scene.ledger(), escrow(&scene));
        let header = scene.frame(1, Kind::PutPrepare, at, 1, prepare(serial, 100, 1_000));
        assert_eq!(error(&scene.one(1, &header)), Some(Status::StoragePressure));
        assert_eq!(scene.live(), 0, "the refusal ended the attempt");
        assert_eq!((scene.ledger(), escrow(&scene)), (ledger, escrowed));
        let report = scene.owner.put_report();
        assert_eq!(
            (report.reserve_refused, refusal_parts(&report)),
            (1, [0, 0, 0, 1]),
            "{report:?}"
        );
        assert_eq!(report.failed_other, 1, "{report:?}");
        assert_eq!(scene.fetch(1), incumbent, "the incumbent stays readable");
    });
}

pub(super) fn escrow(scene: &Scene<'_, '_>) -> u64 {
    scene.storage.pool_report().unwrap().escrow_units
}

#[test]
fn a_refused_priming_receive_counts_as_a_receive_wait() {
    scene(&PRINCIPALS, |mut scene| {
        let at = request(1, 1);
        let serial = scene.begin(1, at, 5);
        scene.control.refuse_next(SubmitRefusal {
            reason: RefusalReason::QueueFull,
            code: None,
        });
        let empty = scene.frame(1, Kind::PutPrepare, at, 5, prepare(serial, 0, 60_000));
        scene.inject(1, &empty);
        scene.polls(1);
        assert_eq!(scene.owner.put_report().receive_waits, 1);
        scene.turns(20);
        assert_eq!(scene.owner.put_report().published, 1);
    });
}

#[test]
fn a_terminal_priming_receive_counts_as_a_failed_receive() {
    scene(&PRINCIPALS, |mut scene| {
        let at = request(1, 1);
        let serial = scene.begin(1, at, 5);
        scene.control.refuse_next(SubmitRefusal {
            reason: RefusalReason::InvalidRange,
            code: None,
        });
        let empty = scene.frame(1, Kind::PutPrepare, at, 5, prepare(serial, 0, 60_000));
        scene.inject(1, &empty);
        scene.polls(1);
        let errors: Vec<_> = scene.replies(1).iter().filter_map(error).collect();
        assert_eq!(errors, [Status::DeviceError]);
        let report = scene.owner.put_report();
        assert_eq!((report.failed_receive, report.failed_other), (1, 1));
    });
}

#[test]
fn a_refused_final_segment_receive_counts_as_a_receive_wait() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(100, 25);
        let (at, serial) = ready_upload(&mut scene, &object);
        let (zero, body) = scene.fragment(at, serial, &object, 0);
        for _ in 0..2 {
            scene.control.refuse_next(SubmitRefusal {
                reason: RefusalReason::QueueFull,
                code: None,
            });
        }
        scene.inject_edited(1, &zero, &body, |_| {});
        scene.polls(1);
        assert_eq!(
            scene.owner.put_report().receive_waits,
            1,
            "the fragment's receive keeps its refused segment staged, and the last-segment receive waits"
        );
        scene.turns(20);
        assert_eq!(scene.owner.put_report().published, 1);
        assert_eq!(scene.fetch(5), object);
    });
}

#[test]
fn a_put_in_a_slot_an_ended_put_freed_still_times_out() {
    scene(&PRINCIPALS, |mut scene| {
        scene.begin(1, request(1, 1), 5);
        let stop = scene.frame(1, Kind::PutCancel, request(1, 1), 5, cancel(0));
        assert_eq!(error(&scene.one(1, &stop)), Some(Status::Cancelled));
        assert_eq!(scene.live(), 0);
        let begin = scene.frame(1, Kind::PutBegin, request(1, 2), 5, |header| {
            header.remaining_ms = 5
        });
        assert_eq!(scene.one(1, &begin).kind, Kind::PutAuthority);
        scene.turns(60);
        let replies = scene.replies(1);
        assert_eq!(replies.len(), 1, "{replies:?}");
        assert_eq!(error(&replies[0]), Some(Status::TimedOut));
        assert_eq!(scene.live(), 0);
    });
}

#[test]
fn the_put_slot_scan_agrees_with_a_model_across_word_boundaries() {
    let mut seed = 0x9E37_79B9_7F4A_7C15_u64;
    let mut patterns = vec![
        [0; 3],
        [1, 0, 0],
        [1 << 63, 0, 0],
        [0, 1, 0],
        [0, 0, 1 << 63],
    ];
    for _ in 0..32 {
        let mut words = [0; 3];
        for word in &mut words {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            *word = seed & (seed >> 17) & (seed >> 31);
        }
        patterns.push(words);
    }
    for words in patterns {
        let set = |bit: u32| words[bit as usize / 64] & (1 << (bit % 64)) != 0;
        for from in 0..=200 {
            let model = (from..192).find(|&bit| set(bit));
            assert_eq!(next_set(&words, from), model, "{words:x?} from {from}");
        }
    }
}

#[test]
fn puts_time_out_in_deadline_order_whatever_their_admission_order() {
    scene(&PRINCIPALS, |mut scene| {
        let long = scene.frame(0, Kind::PutBegin, request(1, 1), 5, |header| {
            header.remaining_ms = 20
        });
        assert_eq!(scene.one(0, &long).kind, Kind::PutAuthority);
        let short = scene.frame(1, Kind::PutBegin, request(1, 1), 6, |header| {
            header.remaining_ms = 5
        });
        assert_eq!(scene.one(1, &short).kind, Kind::PutAuthority);
        scene.turns(60);
        let replies = scene.replies(1);
        assert_eq!(replies.len(), 1, "{replies:?}");
        assert_eq!(error(&replies[0]), Some(Status::TimedOut));
        assert!(scene.replies(0).is_empty(), "the later deadline holds");
        assert_eq!(scene.live(), 1);
        scene.turns(200);
        let replies = scene.replies(0);
        assert_eq!(replies.len(), 1, "{replies:?}");
        assert_eq!(error(&replies[0]), Some(Status::TimedOut));
        assert_eq!(scene.live(), 0);
    });
}

#[test]
fn empty_objects_prepared_together_both_publish() {
    scene(&PRINCIPALS, |mut scene| {
        let serials = [
            scene.begin(0, request(1, 1), 5),
            scene.begin(1, request(1, 1), 6),
        ];
        for (peer, name) in [(0, 5), (1, 6)] {
            let empty = prepare(serials[peer], 0, 60_000);
            let header = scene.frame(peer, Kind::PutPrepare, request(1, 1), name, empty);
            scene.inject(peer, &header);
        }
        scene.turns(4);
        for peer in 0..2 {
            let kinds: Vec<_> = scene.replies(peer).iter().map(|reply| reply.kind).collect();
            assert_eq!(kinds, [Kind::PutReady, Kind::PutResult], "peer {peer}");
        }
        assert_eq!(scene.live(), 0);
    });
}

#[test]
fn the_deadline_heap_pops_like_a_model() {
    let (puts, slots) = (24_u32, 64_u16);
    let mut seed = 0x2545_F491_4F6C_DD1D_u64;
    let mut next = |bound: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % bound
    };
    let mut heap = Deadlines::new(puts, u32::from(slots));
    let mut model: Vec<(u64, u16)> = Vec::new();
    for step in 0..20_000 {
        match next(4) {
            0 if model.len() < puts as usize => {
                let slot = (0..slots)
                    .cycle()
                    .skip(next(u64::from(slots)) as usize)
                    .find(|slot| model.iter().all(|&(_, held)| held != *slot))
                    .unwrap();
                let deadline_us = next(1_000);
                heap.push(slot, deadline_us);
                model.push((deadline_us, slot));
            }
            1 if !model.is_empty() => {
                let at = next(model.len() as u64) as usize;
                let deadline_us = next(1_000);
                heap.lower(model[at].1, deadline_us);
                model[at].0 = model[at].0.min(deadline_us);
            }
            2 if !model.is_empty() => {
                let (_, slot) = model.swap_remove(next(model.len() as u64) as usize);
                heap.remove(slot);
                heap.remove(slot);
                heap.lower(slot, 0);
            }
            _ => {
                let now_us = next(1_000);
                let earliest = model.iter().map(|&(deadline_us, _)| deadline_us).min();
                match heap.pop_due(now_us) {
                    Some(slot) => {
                        let at = model.iter().position(|&(_, held)| held == slot).unwrap();
                        assert_eq!(Some(model[at].0), earliest, "step {step}");
                        assert!(model[at].0 <= now_us, "step {step}");
                        model.swap_remove(at);
                        heap.remove(slot);
                    }
                    None => assert!(earliest.is_none_or(|at| at > now_us), "step {step}"),
                }
            }
        }
    }
    let mut last = 0;
    while let Some(slot) = heap.pop_due(u64::MAX) {
        let at = model.iter().position(|&(_, held)| held == slot).unwrap();
        assert!(model[at].0 >= last);
        last = model.swap_remove(at).0;
    }
    assert!(model.is_empty());
}

mod oracle_writes {
    use crate::oracle::{
        ActionKind, Checkpoint, Custodian, Obligation, Outcome, Recorder, ReportKind, ReportState,
        ResourceKind, Row, check,
    };
    use crate::storage::device::sim::Event;
    use crate::storage::device::slot_of;
    use crate::storage::{CommandToken, Operation};

    use super::{FRAGMENT_LEN, Kind, PRINCIPALS, Scene, cancel, payload, ready_upload, scene};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Write {
        Submitted(CommandToken),
        Delivered(CommandToken),
    }

    /// The event ring must retain every write submission and delivery, so
    /// their counts match the simulator's life-long counters.
    fn device_writes(scene: &Scene<'_, '_>) -> Vec<Write> {
        let mut writes = Vec::new();
        let mut submitted = Vec::new();
        for event in scene.control.events() {
            match event {
                Event::Submitted(token, Operation::Write) => {
                    submitted.push(token);
                    writes.push(Write::Submitted(token));
                }
                Event::Delivered(token) if submitted.contains(&token) => {
                    writes.push(Write::Delivered(token));
                }
                _ => {}
            }
        }
        let delivered = writes.len() - submitted.len();
        assert_eq!(
            (submitted.len(), delivered),
            (
                scene.control.accepted(Operation::Write),
                scene.control.delivered(Operation::Write)
            ),
            "the event ring holds every write\n{}",
            scene.control.describe()
        );
        writes
    }

    fn in_flight(writes: &[Write]) -> Vec<CommandToken> {
        writes
            .iter()
            .filter_map(|write| match *write {
                Write::Submitted(token) if !writes.contains(&Write::Delivered(token)) => {
                    Some(token)
                }
                _ => None,
            })
            .collect()
    }

    fn command(token: CommandToken) -> (ResourceKind, u32, u64) {
        (
            ResourceKind::Command,
            u32::from(slot_of(token)),
            token.raw(),
        )
    }

    /// The scene models successful device writes, so each write terminal is
    /// `Outcome::Complete`.
    #[derive(Default)]
    struct Writes {
        seen: usize,
    }

    impl Writes {
        fn observe(&mut self, scene: &Scene<'_, '_>, rec: &mut Recorder) -> Vec<Write> {
            let writes = device_writes(scene);
            for write in &writes[self.seen..] {
                match *write {
                    Write::Submitted(token) => {
                        rec.take(command(token), Custodian::Storage, None);
                    }
                    Write::Delivered(token) => {
                        rec.terminal(command(token), Outcome::Complete);
                    }
                }
            }
            self.seen = writes.len();
            let report = scene.owner.volume_report();
            assert_eq!(report.writes_failed, 0, "every write completes");
            rec.report(
                ResourceKind::Command,
                ReportKind::Table,
                ReportState::Value(report.writes_submitted - report.writes_done),
            );
            writes
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Stop {
        Cancel,
        Close,
    }

    /// A remote PUT whose two fragments start their writes, then `stop`: the
    /// fill drains, each accepted write command stays in storage custody
    /// until its terminal, and the drained owner reaches a released
    /// checkpoint.
    fn stopped_writes(stop: Stop) -> (Vec<Row>, Vec<Write>) {
        let mut rec = Recorder::new(1);
        let mut device = Vec::new();
        scene(&PRINCIPALS, |mut scene| {
            let mut writes = Writes::default();
            let object = payload(2 * FRAGMENT_LEN as usize, 10);
            let (at, serial) = ready_upload(&mut scene, &object);
            for index in 0..2 {
                let (header, body) = scene.fragment(at, serial, &object, index);
                scene.inject_edited(1, &header, &body, |_| {});
            }
            scene.polls(2);
            let started = in_flight(&writes.observe(&scene, &mut rec));
            assert!(!started.is_empty(), "a write is in flight");
            match stop {
                Stop::Cancel => {
                    let frame = scene.frame(1, Kind::PutCancel, at, 5, cancel(serial));
                    scene.inject(1, &frame);
                    for token in started {
                        rec.cancel(command(token));
                    }
                }
                Stop::Close => {
                    scene.owner.close(scene.turn * 100);
                    rec.close(Outcome::Acknowledged);
                }
            }
            scene.polls(2);
            let early = in_flight(&writes.observe(&scene, &mut rec));
            assert!(
                early.len() > 1,
                "two writes outlive the {stop:?}: {early:?}"
            );
            assert_eq!(scene.live(), 1, "the fill drains its writes");
            scene.control.hold(early[0]);
            scene.turns(4);
            assert!(
                !in_flight(&writes.observe(&scene, &mut rec)).contains(&early[1]),
                "a later write completes before the held one"
            );
            scene.control.release(early[0]);
            scene.turns(40);
            device = writes.observe(&scene, &mut rec);
            assert_eq!(scene.live(), 0);
            assert!(in_flight(&device).is_empty());
            rec.checkpoint(Checkpoint::Released);
        });
        (rec.rows().to_vec(), device)
    }

    #[test]
    fn a_stopped_upload_keeps_each_write_command_until_its_terminal() {
        for stop in [Stop::Cancel, Stop::Close] {
            let (rows, _) = stopped_writes(stop);
            let verdict = check(&Recorder::rebuilt(rows));
            assert!(
                verdict.satisfies(&[Obligation::Custody, Obligation::Resources]),
                "{stop:?}: {verdict:?}"
            );
        }
    }

    /// Take rows follow device submission order, which maps each recorded
    /// command identity to its device token.
    #[test]
    fn each_write_terminal_names_the_command_the_device_delivered() {
        for stop in [Stop::Cancel, Stop::Close] {
            let (rows, device) = stopped_writes(stop);
            let tokens = |delivered: bool| -> Vec<CommandToken> {
                device
                    .iter()
                    .filter_map(|write| match (*write, delivered) {
                        (Write::Submitted(token), false) | (Write::Delivered(token), true) => {
                            Some(token)
                        }
                        _ => None,
                    })
                    .collect()
            };
            let (submitted, delivered) = (tokens(false), tokens(true));
            let named = |kind: ActionKind| -> Vec<_> {
                rows.iter()
                    .filter(|row| row.kind == kind)
                    .map(|row| (row.resource(), row.incarnation))
                    .collect()
            };
            let takes = named(ActionKind::Take);
            assert_eq!(takes.len(), submitted.len(), "{stop:?}");
            let terminals: Vec<CommandToken> = named(ActionKind::Terminal)
                .into_iter()
                .map(|identity| {
                    let at = takes
                        .iter()
                        .position(|take| *take == identity)
                        .expect("a terminal names a taken command");
                    submitted[at]
                })
                .collect();
            assert_eq!(terminals, delivered, "{stop:?}");
        }
    }

    #[test]
    fn a_dropped_write_terminal_fails_the_report_and_the_released_checkpoint() {
        for stop in [Stop::Cancel, Stop::Close] {
            let (mut rows, _) = stopped_writes(stop);
            let last = rows
                .iter()
                .rposition(|r| r.kind == ActionKind::Terminal)
                .expect("a terminal row");
            rows.remove(last);
            assert_eq!(
                check(&Recorder::rebuilt(rows.clone())).violated(),
                Some((
                    Obligation::Resources,
                    "a production report disagreed with the independent count"
                )),
                "{stop:?}"
            );
            let report = rows
                .iter()
                .rposition(|r| r.kind == ActionKind::Report)
                .expect("a report row");
            rows.remove(report);
            assert_eq!(
                check(&Recorder::rebuilt(rows)).violated(),
                Some((
                    Obligation::Resources,
                    "a released checkpoint kept capacity its obligations no longer justify"
                )),
                "{stop:?}"
            );
        }
    }

    crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
        a_dropped_write_terminal_fails_the_report_and_the_released_checkpoint,
        a_stopped_upload_keeps_each_write_command_until_its_terminal,
        each_write_terminal_names_the_command_the_device_delivered,
    );
}

crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
    a_begin_behind_the_prepare_that_lost_the_volume_is_refused_in_the_same_batch,
    a_begin_the_namespace_refuses_repeats_its_refusal,
    a_cancel_before_data_ends_the_attempt_and_retains_its_terminal,
    a_cancel_during_writes_keeps_the_fill_until_its_writes_end,
    a_changed_duplicate_ends_the_upload_with_conflicting_data,
    a_changed_prepare_conflicts_and_keeps_the_authority,
    a_configuration_over_the_put_caps_refuses_start,
    a_consumed_short_final_fragment_compares_by_its_retained_digest,
    a_duplicate_prepare_keeps_the_sampled_expiry,
    a_failed_final_header_write_ends_the_upload_unpublished,
    a_forged_fragment_in_a_pair_drops_alone_and_the_upload_completes_exact,
    a_fragment_above_the_grant_is_dropped,
    a_fragment_ahead_of_a_frame_a_replay_window_later_is_taken,
    a_freed_write_command_goes_to_the_peer_below_its_share,
    a_full_window_burst_acknowledges_only_the_window,
    a_get_progresses_while_an_upload_fills_its_window,
    a_lost_authority_or_ready_replays_the_same_attempt,
    a_peer_takes_the_write_commands_an_idle_peer_leaves,
    a_peer_whose_share_gets_hold_refuses_the_begin_and_leaves_the_key_free,
    a_publish_error_ends_the_upload_with_its_status,
    a_published_empty_object_replays_until_its_window_ends,
    a_put_in_a_slot_an_ended_put_freed_still_times_out,
    a_refused_final_segment_receive_counts_as_a_receive_wait,
    a_refused_priming_receive_counts_as_a_receive_wait,
    a_replaced_upload_drains_its_own_writes_while_a_successor_publishes_beside_it,
    a_session_slot_cap_below_the_namespace_width_refuses_the_begin,
    a_terminal_priming_receive_counts_as_a_failed_receive,
    a_volume_lost_to_a_put_write_refuses_later_begins,
    a_whole_upload_submits_every_segment_after_its_last_fragment,
    a_window_over_the_receive_data_cap_refuses_start,
    a_zero_ttl_prepare_drops_at_parse_and_keeps_the_attempt,
    an_ended_put_frees_its_key_for_a_later_begin,
    an_ended_upload_returns_its_ring_for_the_next,
    an_idle_authority_times_out_and_retains_the_timeout,
    an_invalidation_during_writes_keeps_the_upload_unpublished,
    an_old_write_terminal_after_revocation_leaves_the_live_successor_intact,
    an_owner_loss_after_an_accepted_submit_ends_unpublished_and_refuses_later_begins,
    an_owner_loss_before_the_last_write_terminal_publishes_nothing,
    an_unwound_publication_ends_unknown_and_refuses_new_uploads,
    an_unwound_stage_ends_the_put_on_its_next_frame,
    an_uploaded_object_publishes_once_and_serves_its_exact_bytes,
    begin_refusals_admit_nothing,
    close_drains_a_writing_upload_before_shutdown,
    empty_objects_prepared_together_both_publish,
    late_writes_after_a_cancel_drain_beside_a_healthy_get,
    prepare_refusals_end_the_attempt_with_their_status,
    puts_time_out_in_deadline_order_whatever_their_admission_order,
    reordered_duplicate_and_lost_fragments_reassemble_across_the_ring,
    session_replacement_retires_put_evidence,
    stale_frames_of_a_released_upload_reach_no_successor_on_the_same_wire_slot,
    the_progress_scan_visits_only_waiting_puts,
    the_storage_deadline_rounds_down_to_whole_seconds,
    typed_refusals_precede_admission_and_a_wrong_serial_conflicts,
);

/// The per-turn allowances of the turns a history checks: write commands, copy bytes and maintenance steps per owner turn, and bytes verified per tick.
#[derive(Debug, Clone, Copy)]
struct Allowances {
    commands: usize,
    copy_bytes: usize,
    maintain: usize,
    validate_bytes: usize,
    /// Parked entries one wake and detach pass visits.
    wake: usize,
}

/// For each allowance, the first turn it bound: a fill's writes spent every write command; the copies spent the whole copy budget; the allowance stopped a maintenance call in front of a stage it could not fund; the wake pass made every visit its allowance grants.
#[derive(Debug, Default)]
struct Bound {
    commands: Option<u64>,
    copy: Option<u64>,
    maintain: Option<u64>,
    wake: Option<u64>,
}

/// One owner turn, then its per-turn spending against `limits`, recording in `bound` the first turn each allowance bound; a failure names the turn.
/// Write commands are checked twice: the PUT report's count the turn's budget charged, and the volume's submitted writes, which count each write command the table accepted. Maintenance steps are the steps the call's budget counted by kind, and one maintenance call at most runs per poll, counted from the owner's report. Copy bytes are the per-turn copy budget's own count, which the PUT core's payload copies and resend comparisons charge; the check is of that accounting, which caps each copy at the budget's remaining bytes before the copy and debits each comparison before it runs.
fn checked_turn(scene: &mut Scene<'_, '_>, limits: Allowances, bound: &mut Bound) {
    let writes = scene.owner.put_report().write_commands;
    let submitted = scene.owner.volume_report().writes_submitted;
    let verified = scene.owner.volume_report().validated_bytes;
    let maintain_calls = scene.owner.report().maintained + scene.owner.report().maintenance_refused;
    let parked = scene.owner.parked_count() as usize;
    let turn = scene.turn;
    scene.turns(1);
    let commands = (scene.owner.put_report().write_commands - writes) as usize;
    let submits = (scene.owner.volume_report().writes_submitted - submitted) as usize;
    let copied = scene.owner.put_turn_copy_bytes();
    let (maintained, stopped) = scene.owner.maintain_spent();
    let calls =
        scene.owner.report().maintained + scene.owner.report().maintenance_refused - maintain_calls;
    let validated = (scene.owner.volume_report().validated_bytes - verified) as usize;
    let woke = scene.owner.wake_visits() as usize;
    for (what, spent, limit) in [
        ("wake visits", woke, limits.wake),
        ("write commands", commands, limits.commands),
        ("submitted writes", submits, limits.commands),
        ("copy bytes", copied, limits.copy_bytes),
        ("maintenance steps", maintained, limits.maintain),
        ("verified bytes", validated, limits.validate_bytes),
        ("maintenance calls", calls as usize, 1),
    ] {
        assert!(spent <= limit, "turn {turn}: {spent} {what} above {limit}");
    }
    let first = |seen: &mut Option<u64>, now: bool| {
        if now && seen.is_none() {
            *seen = Some(turn);
        }
    };
    first(&mut bound.commands, commands == limits.commands);
    first(&mut bound.copy, copied == limits.copy_bytes);
    first(&mut bound.maintain, stopped);
    // The wake allowance binds in a turn that began with more GETs parked than it visits.
    first(&mut bound.wake, woke == limits.wake && parked > limits.wake);
}

/// Owner turns over a publication burst: eight objects of six fragments, one per slot, uploaded one after another by injected PUT frames, each window of granted DATA frames arriving in one turn, under one write command and two datagrams of copy per turn and maintenance at its minimum.
/// Every turn stays within each allowance. The command and copy allowances bind in some turn: a window of four DATA frames outruns the two-datagram copy budget, which a partial copy spends exactly, and a fill's writes meet the one-command budget.
/// Maintenance makes at most one call per poll, each spending at most its allowance, and the burst records the first call the allowance stops in front of a stage the remainder cannot fund: at the maintenance minimum, any call in which a stage spent steps before the stage with the largest minimum. The objects are retired at the end so the reclaims also run under the allowance, and the turns after the invalidations return every retired unit.
/// The verification allowance stays at or below its limit and is slack here, since the burst only writes; the volume tick tests show it and the tick bursts binding.
/// The loop caps guard against a hang; the bounds are the per-turn assertions.
/// `lower` maps the configured allowances to the thresholds each turn is checked against; the identity keeps them.
fn allowances_over_a_burst(lower: impl FnOnce(Allowances) -> Allowances) {
    let storage = storage(8);
    let minimum = storage.maintain_minimum();
    let config = OwnerConfig {
        put: PutConfig {
            commands: 1,
            copy_bytes: 2 * MAX_DATAGRAM,
            ..OWNER.put
        },
        maintain_work: minimum,
        follow: super::parked::FollowConfig {
            wake: 1,
            ..OWNER.follow
        },
        ..OWNER
    };
    let configured = Allowances {
        commands: config.put.commands,
        copy_bytes: config.put.copy_bytes,
        maintain: config.maintain_work,
        wake: config.follow.wake as usize,
        // The scene's volume attaches with the fixture's tick configuration.
        validate_bytes: crate::storage::owner_fixture::TICK.validate_bytes,
    };
    let limits = lower(configured);
    scene_over(storage, config, &PRINCIPALS, |mut scene| {
        let mut bound = Bound::default();
        for name in 5..13u8 {
            let object = payload(6 * FRAGMENT_LEN as usize, u64::from(name));
            // Maintenance evicts until the placeable units pass the low watermark; the PUT starts once a slot is free, no retired unit holds the allowance the promise checks, and the placeable units pass that watermark.
            for _ in 0..16 {
                let free = scene
                    .storage
                    .pool_report()
                    .unwrap()
                    .ledger
                    .unwrap()
                    .slots
                    .free;
                let domain = scene.storage.domain_report().unwrap();
                if free > 0
                    && domain.retired_units == 0
                    && domain.placeable_units > domain.low_units
                {
                    break;
                }
                checked_turn(&mut scene, limits, &mut bound);
            }
            let at = request(1, u64::from(name));
            let begin = scene.frame(1, Kind::PutBegin, at, name, |_| {});
            scene.inject(1, &begin);
            let mut serial = None;
            for _ in 0..8 {
                checked_turn(&mut scene, limits, &mut bound);
                serial = scene
                    .replies(1)
                    .iter()
                    .find(|reply| reply.kind == Kind::PutAuthority)
                    .map(|reply| reply.allocation)
                    .or(serial);
                if serial.is_some() {
                    break;
                }
            }
            let serial = serial.expect("the owner granted authority");
            let ready = scene.frame(
                1,
                Kind::PutPrepare,
                at,
                name,
                prepare(serial, object.len() as u32, 60_000),
            );
            scene.inject(1, &ready);
            let count = FragmentGeometry::fragments(object.len() as u64) as u32;
            let (mut granted, mut sent, mut published) = (0, 0, false);
            for _ in 0..200 {
                checked_turn(&mut scene, limits, &mut bound);
                for reply in scene.replies(1) {
                    match reply.kind {
                        Kind::PutReady | Kind::PutAck => granted = granted.max(reply.grant),
                        Kind::PutResult => published = true,
                        _ => {}
                    }
                }
                if published {
                    break;
                }
                if name == 5 && granted > 0 && sent == 0 {
                    // Two GETs of the first object join its granted upload and park ahead of its fragments, so the one-visit wake allowance binds while both wait.
                    for slot in 0..2 {
                        let get = scene.get(0, request(slot, 1), name);
                        scene.inject(0, &get);
                    }
                }
                // Every granted fragment arrives in the next turn's receive batch.
                while sent < granted.min(count) {
                    let (data, body) = scene.fragment_from(1, at, serial, name, &object, sent);
                    scene.inject_edited(1, &data, &body, |_| {});
                    sent += 1;
                }
            }
            assert!(published, "object {name} published");
            assert!(scene.visible(name));
            if name == 5 {
                // The joined GETs read the object; their cancels end them, so their rights return before the invalidations.
                for slot in 0..2 {
                    let get = scene.get(0, request(slot, 1), name);
                    let cancel = Header {
                        sequence: get.sequence,
                        status: Status::Cancelled as u16,
                        ..super::serve::header(Kind::Cancel, get.request, get.key)
                    };
                    let cancel = Header {
                        principal: get.principal,
                        key_epoch: get.key_epoch,
                        owner_nonce: get.owner_nonce,
                        client_nonce: get.client_nonce,
                        epoch: get.epoch,
                        ..cancel
                    };
                    scene.inject(0, &cancel);
                }
            }
        }
        // The invalidations retire every object together, so the last turns' maintenance reclaims under the allowance; the retired units drain to zero.
        for name in 5..13u8 {
            scene
                .owner
                .invalidate(&key(name), 2, &mut WorkBudget::new(1 << 12))
                .unwrap();
        }
        let retired = scene.storage.domain_report().unwrap().retired_units;
        assert!(retired > 0, "the invalidations retired the burst's units");
        for _ in 0..16 {
            checked_turn(&mut scene, limits, &mut bound);
        }
        assert_eq!(
            scene.storage.domain_report().unwrap().retired_units,
            0,
            "the turns after the invalidations returned every retired unit"
        );
        assert!(
            bound.commands.is_some()
                && bound.copy.is_some()
                && bound.maintain.is_some()
                && bound.wake.is_some(),
            "each of the command, copy, maintenance and wake allowances binds in some turn: {bound:?}"
        );
    });
}

#[test]
fn owner_turns_stay_within_their_command_copy_verification_maintenance_and_wake_allowances() {
    allowances_over_a_burst(|configured| configured);
}

/// The planted lower threshold: one write command below the configured allowance fails the same check in the first turn whose fill spends the whole budget.
#[test]
#[should_panic(expected = "turn 9: 1 write commands above 0")]
fn negative_control_a_lower_command_threshold_fails_in_the_binding_turn() {
    allowances_over_a_burst(|configured| Allowances {
        commands: configured.commands - 1,
        ..configured
    });
}

/// The planted lower threshold for wake visits: one visit below the configured allowance fails the same check in the first turn whose pass makes every visit it may.
#[test]
#[should_panic(expected = "turn 8: 1 wake visits above 0")]
fn negative_control_a_lower_wake_threshold_fails_in_the_binding_turn() {
    allowances_over_a_burst(|configured| Allowances {
        wake: configured.wake - 1,
        ..configured
    });
}

/// The planted lower threshold for copy bytes: one byte below the configured allowance fails the same check in the first turn whose copies spend the whole budget.
#[test]
#[should_panic(expected = "turn 8: 16768 copy bytes above 16767")]
fn negative_control_a_lower_copy_threshold_fails_in_the_binding_turn() {
    allowances_over_a_burst(|configured| Allowances {
        copy_bytes: configured.copy_bytes - 1,
        ..configured
    });
}

const RUN_WAIT_SHAPE: crate::storage::owner_fixture::Shape = crate::storage::owner_fixture::Shape {
    units: 512,
    slots: 32,
};

/// A sequence storage of 512 units and 32 slots that admits three-extent
/// objects, the scenes' fragmented volume.
pub(super) fn fragmentable_storage() -> Storage<TestPlatform> {
    crate::storage::owner_fixture::sequence_storage_shaped(
        THREE_EXTENT_LENGTHS.0 as usize,
        RUN_WAIT_SHAPE,
    )
}

/// A one-extent claim of `units` units on `storage`, its bytes carried as
/// metadata.
fn claim(
    storage: &Storage<TestPlatform>,
    units: usize,
) -> Result<crate::storage::ExtentReservation<'_, TestPlatform>, crate::storage::ReserveError> {
    storage.reserve(
        Some(units * crate::storage::IO_UNIT - 2048),
        Some(0),
        &mut WorkBudget::new(1 << 20),
    )
}

/// Fragments `storage`: `holes` free runs of 40 units, each followed by a
/// one-unit pin, then 40-unit fillers until at most 41 units stay free, so no
/// free run holds a full extent. Returns the pins in address order, then the
/// fillers.
pub(super) fn pin_holes(
    storage: &Storage<TestPlatform>,
    holes: usize,
) -> Vec<crate::storage::ExtentReservation<'_, TestPlatform>> {
    let direct = |units: usize| claim(storage, units).unwrap();
    let mut held = Vec::new();
    let mut cut = Vec::new();
    for _ in 0..holes {
        cut.push(direct(40));
        held.push(direct(1));
    }
    while storage.pool_report().unwrap().ledger.unwrap().raw.free / crate::storage::IO_UNIT > 41 {
        held.push(direct(40));
    }
    for hole in cut {
        hole.cancel().unwrap();
    }
    held
}

/// The placing PUTs whose fill waits for a free run, read from their stages, after checking that the PUT core's count agrees.
fn run_waiters(scene: &Scene<'_, '_>) -> u32 {
    let waiting = scene.owner.waiting_placements();
    assert_eq!(
        scene.owner.put_report().run_waiters,
        waiting,
        "the PUT core's count"
    );
    waiting
}

fn capped(run_waiters: u32) -> OwnerConfig {
    OwnerConfig {
        put: PutConfig {
            run_waiters,
            ..OWNER.put
        },
        ..OWNER
    }
}

/// [`scene_over`] whose audit checks, after each turn, that `owner.put_report().run_waiters` is at most `config.put.run_waiters` and equals the live PUTs whose placing fill waits for a free run. The audit reads owner state alone, so it runs while a scene holds the pool gate.
pub(super) fn run_wait_scene(
    storage: Storage<TestPlatform>,
    config: OwnerConfig,
    body: impl FnOnce(Scene<'_, '_>),
) {
    scene_over(storage, config, &PRINCIPALS, |mut scene| {
        scene.audit = Some(Box::new(move |owner| {
            let waiters = owner.put_report().run_waiters;
            assert!(waiters <= config.put.run_waiters, "{waiters} waiters");
            assert_eq!(waiters, owner.waiting_placements());
            if let Err(defect) = owner.check_marked_waiters() {
                panic!("{defect}");
            }
        }));
        body(scene);
    });
}

/// On a fragmented volume a three-extent PREPARE keeps its promise and waits:
/// no reply over many polls, one run wait per poll in `run_waits` and none in
/// `place_waits`, the escrow at the charge and one run waiter; a resent
/// PREPARE changes none of it. Once three pins return, their holes join into
/// runs that hold the extents, and the PUT reaches READY with the escrow and
/// the waiter counter back to zero.
#[test]
fn a_fragmented_prepare_waits_for_a_run_and_reaches_ready_once_runs_form() {
    run_wait_scene(fragmentable_storage(), OWNER, |mut scene| {
        let mut pins = pin_holes(scene.storage, 8);
        let at = request(1, 1);
        let serial = scene.begin(1, at, 10);
        let header = scene.frame(1, Kind::PutPrepare, at, 10, three_extents(serial));
        scene.inject(1, &header);
        scene.polls(1);
        assert!(scene.replies(1).is_empty(), "the PREPARE waits");
        let report = scene.owner.put_report();
        assert_eq!(
            (report.reserve_refused, report.place_waits),
            (0, 0),
            "{report:?}"
        );
        assert_eq!(
            report.run_waits, 1,
            "the PREPARE's poll placed once: {report:?}"
        );
        let charge = escrow(&scene);
        assert!(charge > 0);
        for poll in 1..=10 {
            if poll == 5 {
                let resent = scene.frame(1, Kind::PutPrepare, at, 10, three_extents(serial));
                scene.inject(1, &resent);
            }
            scene.polls(1);
            assert!(scene.replies(1).is_empty());
            let report = scene.owner.put_report();
            assert_eq!(
                (report.run_waits, report.place_waits),
                (1 + poll, 0),
                "one placement per poll"
            );
            assert_eq!(escrow(&scene), charge);
            assert_eq!(run_waiters(&scene), 1);
        }
        for pin in pins.drain(..3) {
            pin.cancel().unwrap();
        }
        scene.polls(10);
        let kinds: Vec<_> = scene.replies(1).iter().map(|reply| reply.kind).collect();
        assert_eq!(kinds, [Kind::PutReady]);
        assert_eq!(escrow(&scene), 0);
        assert_eq!(run_waiters(&scene), 0);
        assert_eq!(scene.owner.put_report().reserve_refused, 0);
        drop(pins);
    });
}

/// A PREPARE that places its first extent in the one run that holds one and
/// then finds no run for the next waits on the following turns.
#[test]
fn a_prepare_that_placed_an_extent_and_then_finds_no_run_waits() {
    run_wait_scene(fragmentable_storage(), OWNER, |mut scene| {
        let mut pins = pin_holes(scene.storage, 8);
        pins.remove(0).cancel().unwrap();
        let at = request(1, 1);
        let serial = scene.begin(1, at, 10);
        let header = scene.frame(1, Kind::PutPrepare, at, 10, three_extents(serial));
        scene.inject(1, &header);
        scene.polls(1);
        let charge = escrow(&scene);
        for polls in 1..=4 {
            assert!(scene.replies(1).is_empty(), "the PUT waits");
            let report = scene.owner.put_report();
            assert_eq!(
                (report.place_waits, report.run_waits),
                (1, polls),
                "the PREPARE placed an extent, then one run wait per poll: {report:?}"
            );
            assert_eq!(report.reserve_refused, 0, "{report:?}");
            assert_eq!(escrow(&scene), charge);
            assert_eq!(run_waiters(&scene), 1);
            scene.polls(1);
        }
        drop(pins);
    });
}

/// Fragmentation held past the deadline ends the wait with storage pressure
/// on the first polls at the deadline, counted once in the total, the payload
/// part and `failed_other`, with the escrow refunded once and the waiter
/// counter back to zero, whether the PUT placed no extent or one.
#[test]
fn a_run_wait_past_its_deadline_ends_with_storage_pressure_counted_once() {
    for returned in [0, 1] {
        run_wait_scene(fragmentable_storage(), OWNER, |mut scene| {
            let mut pins = pin_holes(scene.storage, 8);
            for pin in pins.drain(..returned) {
                pin.cancel().unwrap();
            }
            let at = request(1, 1);
            let begun = scene.turn * 100;
            let begin = scene.frame(1, Kind::PutBegin, at, 10, |header| header.remaining_ms = 5);
            let serial = scene.one(1, &begin).allocation;
            let header = scene.frame(1, Kind::PutPrepare, at, 10, three_extents(serial));
            scene.inject(1, &header);
            while (scene.turn + 2) * 100 < begun + 5_000 {
                scene.polls(1);
                assert!(
                    scene.replies(1).is_empty(),
                    "{returned}: no reply before the deadline"
                );
            }
            assert_eq!(run_waiters(&scene), 1, "{returned}");
            scene.polls(4);
            let errors: Vec<_> = scene.replies(1).iter().filter_map(error).collect();
            assert_eq!(errors, [Status::StoragePressure], "{returned}");
            let report = scene.owner.put_report();
            assert_eq!(
                (
                    report.reserve_refused,
                    refusal_parts(&report),
                    report.failed_other
                ),
                (1, [0, 1, 0, 0], 1),
                "{returned}: {report:?}"
            );
            assert_eq!(report.failed_timed_out, 0, "{report:?}");
            assert_eq!(
                report.place_waits, returned as u64,
                "{returned}: extents placed before the wait"
            );
            assert_eq!(escrow(&scene), 0);
            assert_eq!(run_waiters(&scene), 0);
            assert_eq!(scene.live(), 0);
            let late = scene.frame(1, Kind::PutPrepare, at, 10, three_extents(serial));
            assert_eq!(
                error(&scene.one(1, &late)),
                Some(Status::StoragePressure),
                "{returned}: a late PREPARE replays the retained status"
            );
            drop(pins);
        });
    }
}

/// A placement that makes progress on the last turn before the deadline
/// clears the builder's waiting state, so the deadline ends the PUT
/// `TimedOut` and the refusal counters stay at zero.
#[test]
fn a_placement_that_progressed_before_its_deadline_times_out() {
    run_wait_scene(fragmentable_storage(), OWNER, |mut scene| {
        let mut pins = pin_holes(scene.storage, 8);
        pins.remove(0).cancel().unwrap();
        let at = request(1, 1);
        let begun = scene.turn * 100;
        let begin = scene.frame(1, Kind::PutBegin, at, 10, |header| header.remaining_ms = 5);
        let serial = scene.one(1, &begin).allocation;
        let header = scene.frame(1, Kind::PutPrepare, at, 10, three_extents(serial));
        scene.inject(1, &header);
        while (scene.turn + 2) * 100 < begun + 5_000 {
            scene.polls(1);
        }
        scene.polls(1);
        assert_eq!(run_waiters(&scene), 1);
        // The pin separates two free holes whose combined capacity holds an extent.
        pins.remove(1).cancel().unwrap();
        let places = scene.owner.put_report().place_waits;
        scene.polls(1);
        assert_eq!(
            scene.owner.put_report().place_waits,
            places + 1,
            "the last turn placed"
        );
        assert_eq!(run_waiters(&scene), 0);
        assert!(scene.replies(1).is_empty(), "the PUT still places");
        scene.polls(4);
        let errors: Vec<_> = scene.replies(1).iter().filter_map(error).collect();
        assert_eq!(errors, [Status::TimedOut]);
        let report = scene.owner.put_report();
        assert_eq!(
            (
                report.reserve_refused,
                refusal_parts(&report),
                report.failed_timed_out
            ),
            (0, [0; 4], 1),
            "{report:?}"
        );
        assert_eq!(escrow(&scene), 0);
        assert_eq!(run_waiters(&scene), 0);
        assert_eq!(scene.live(), 0);
        drop(pins);
    });
}

/// A second poll at the PREPARE's `now_us` is a later turn, so the waiter
/// retries its placement in that poll.
#[test]
fn a_run_waiter_retries_on_a_later_poll_at_the_same_time() {
    run_wait_scene(fragmentable_storage(), OWNER, |mut scene| {
        let pins = pin_holes(scene.storage, 8);
        let at = request(1, 1);
        let serial = scene.begin(1, at, 10);
        let header = scene.frame(1, Kind::PutPrepare, at, 10, three_extents(serial));
        scene.inject(1, &header);
        scene.polls(1);
        assert_eq!(scene.owner.put_report().run_waits, 1);
        let now = (scene.turn - 1) * 100;
        scene.owner.poll(now);
        scene.audited();
        assert_eq!(
            scene.owner.put_report().run_waits,
            2,
            "the repeat poll placed once"
        );
        drop(pins);
    });
}

#[test]
fn a_run_waiter_beyond_the_run_bound_waits_while_the_pool_gate_is_held() {
    run_wait_scene(fragmentable_storage(), OWNER, |mut scene| {
        let pins = pin_holes(scene.storage, 8);
        let at = request(1, 1);
        let serial = scene.begin(1, at, 10);
        let header = scene.frame(1, Kind::PutPrepare, at, 10, three_extents(serial));
        scene.inject(1, &header);
        scene.polls(2);
        let before = scene.owner.put_report();
        let storage = scene.storage;
        crate::storage::owner_fixture::with_pool_held(storage, || scene.polls(1));
        let report = scene.owner.put_report();
        assert_eq!(
            (report.run_waits, report.place_waits),
            (before.run_waits + 1, before.place_waits),
            "{report:?}"
        );
        assert!(scene.replies(1).is_empty());
        assert_eq!(run_waiters(&scene), 1);
        drop(pins);
    });
}

/// A later BEGIN that lowers the deadline while the PUT waits ends the wait
/// at the lowered deadline, with storage pressure.
#[test]
fn a_later_begin_that_lowers_the_deadline_ends_the_run_wait_there() {
    run_wait_scene(fragmentable_storage(), OWNER, |mut scene| {
        let pins = pin_holes(scene.storage, 8);
        let at = request(1, 1);
        let begin = scene.frame(1, Kind::PutBegin, at, 10, |header| {
            header.remaining_ms = 20_000
        });
        let serial = scene.one(1, &begin).allocation;
        let header = scene.frame(1, Kind::PutPrepare, at, 10, three_extents(serial));
        scene.inject(1, &header);
        scene.polls(4);
        assert!(scene.replies(1).is_empty());
        let lowered = scene.turn * 100;
        let shorter = scene.frame(1, Kind::PutBegin, at, 10, |header| header.remaining_ms = 5);
        assert_eq!(scene.one(1, &shorter).kind, Kind::PutAuthority);
        while (scene.turn + 2) * 100 < lowered + 5_000 {
            scene.polls(1);
            assert!(
                scene.replies(1).is_empty(),
                "no reply before the lowered deadline"
            );
        }
        scene.polls(4);
        let errors: Vec<_> = scene.replies(1).iter().filter_map(error).collect();
        assert_eq!(errors, [Status::StoragePressure]);
        let report = scene.owner.put_report();
        assert_eq!(
            (report.reserve_refused, refusal_parts(&report)),
            (1, [0, 1, 0, 0]),
            "{report:?}"
        );
        assert_eq!(escrow(&scene), 0);
        assert_eq!(scene.live(), 0);
        assert_eq!(run_waiters(&scene), 0);
        drop(pins);
    });
}

/// A CANCEL during the wait ends the PUT with the client's status and no
/// refusal tally, the escrow and the waiter counter back to zero; an owner
/// close during a wait sends no reply and leaves both at zero with no tally.
#[test]
fn cancel_and_close_end_a_run_wait_without_a_tally() {
    run_wait_scene(fragmentable_storage(), OWNER, |mut scene| {
        let pins = pin_holes(scene.storage, 8);
        let at = request(1, 1);
        let serial = scene.begin(1, at, 10);
        let header = scene.frame(1, Kind::PutPrepare, at, 10, three_extents(serial));
        scene.inject(1, &header);
        scene.polls(3);
        assert_eq!(run_waiters(&scene), 1);
        let cancel = scene.frame(1, Kind::PutCancel, at, 10, cancel(serial));
        scene.inject(1, &cancel);
        scene.polls(2);
        let errors: Vec<_> = scene.replies(1).iter().filter_map(error).collect();
        assert_eq!(errors, [Status::Cancelled]);
        let report = scene.owner.put_report();
        assert_eq!(
            (report.reserve_refused, refusal_parts(&report)),
            (0, [0; 4]),
            "{report:?}"
        );
        assert_eq!(escrow(&scene), 0);
        assert_eq!(run_waiters(&scene), 0);
        let at = request(2, 1);
        let serial = scene.begin(1, at, 11);
        let header = scene.frame(1, Kind::PutPrepare, at, 11, three_extents(serial));
        scene.inject(1, &header);
        scene.polls(3);
        assert_eq!(run_waiters(&scene), 1);
        scene.replies(1);
        let before = scene.owner.put_report();
        let now = scene.turn * 100;
        let _ = scene.owner.close(now);
        scene.polls(20);
        assert!(
            scene.replies(1).is_empty(),
            "close sends the waiter no reply"
        );
        assert_eq!(scene.live(), 0);
        let report = scene.owner.put_report();
        assert_eq!(
            (
                report.reserve_refused,
                report.run_wait_refused,
                report.failed_other,
                report.failed_timed_out,
                report.cancelled
            ),
            (
                before.reserve_refused,
                before.run_wait_refused,
                before.failed_other,
                before.failed_timed_out,
                before.cancelled
            ),
            "close tallies no refusal: {report:?}"
        );
        assert_eq!(escrow(&scene), 0);
        assert_eq!(run_waiters(&scene), 0);
        drop(pins);
    });
}

/// A one-extent PREPARE that finds no run of its units refuses with storage
/// pressure in the same turn and registers no waiter.
#[test]
fn a_one_extent_prepare_without_a_run_refuses_at_once() {
    run_wait_scene(fragmentable_storage(), OWNER, |mut scene| {
        let pins = pin_holes(scene.storage, 8);
        let at = request(1, 1);
        let serial = scene.begin(1, at, 10);
        let header = scene.frame(1, Kind::PutPrepare, at, 10, one_extent(serial, 50));
        scene.inject(1, &header);
        scene.polls(1);
        let errors: Vec<_> = scene.replies(1).iter().filter_map(error).collect();
        assert_eq!(errors, [Status::StoragePressure]);
        let report = scene.owner.put_report();
        assert_eq!(
            (report.reserve_refused, refusal_parts(&report)),
            (1, [0, 1, 0, 0])
        );
        assert_eq!(report.run_waits, 0);
        assert_eq!(run_waiters(&scene), 0);
        drop(pins);
    });
}

/// A PREPARE of a one-extent object charging about `units` units, its
/// payload carried as metadata.
fn one_extent(serial: u64, units: u32) -> impl FnOnce(&mut Header) {
    move |header| {
        prepare(serial, 1, 60_000)(header);
        header.metadata_len = units * crate::storage::IO_UNIT as u32 - 2048;
        header.total = u64::from(header.metadata_len + 1);
        header.count = FragmentGeometry::fragments(header.total) as u32;
    }
}

/// A storage for the rest scenes and an owner whose maintenance work covers
/// its minimum.
fn resting() -> (Storage<TestPlatform>, OwnerConfig) {
    let storage = fragmentable_storage();
    let config = OwnerConfig {
        maintain_work: storage.maintain_minimum().max(OWNER.maintain_work),
        ..OWNER
    };
    (storage, config)
}

/// Turns until the maintenance stage rests.
fn rested(scene: &mut Scene<'_, '_>) {
    for _ in 0..400 {
        if scene
            .owner
            .maintain_rest_until_us()
            .is_some_and(|until| until > (scene.turn + 1) * 100)
        {
            return;
        }
        scene.turns(1);
    }
    panic!(
        "maintenance never rested: {:?}",
        scene.storage.domain_report()
    );
}

/// With the maintenance stage resting, the poll whose PREPARE starts a run
/// wait runs maintenance; a repeated no-run refusal on a later poll leaves a
/// rest in place.
#[test]
fn the_first_run_wait_ends_the_maintenance_rest_and_a_repeat_does_not() {
    let (storage, config) = resting();
    run_wait_scene(storage, config, |mut scene| {
        let pins = pin_holes(scene.storage, 8);
        rested(&mut scene);
        let at = request(1, 1);
        let serial = scene.begin(1, at, 10);
        rested(&mut scene);
        let before = scene.owner.report().maintained;
        let header = scene.frame(1, Kind::PutPrepare, at, 10, three_extents(serial));
        scene.inject(1, &header);
        scene.polls(1);
        assert_eq!(
            scene.owner.report().maintained,
            before + 1,
            "the wake ran maintenance"
        );
        rested(&mut scene);
        let before = scene.owner.report().maintained;
        let waits = scene.owner.put_report().run_waits;
        scene.polls(1);
        assert_eq!(
            scene.owner.put_report().run_waits,
            waits + 1,
            "the repeat waited"
        );
        assert_eq!(
            scene.owner.report().maintained,
            before,
            "the repeat left the rest"
        );
        drop(pins);
    });
}

/// A PUT that places an extent at PREPARE and starts waiting on the same
/// poll's progress turn ends the maintenance rest in that poll.
#[test]
fn a_run_wait_that_starts_on_a_progress_turn_ends_the_maintenance_rest() {
    let (storage, config) = resting();
    run_wait_scene(storage, config, |mut scene| {
        let mut pins = pin_holes(scene.storage, 8);
        pins.remove(0).cancel().unwrap();
        let at = request(1, 1);
        let serial = scene.begin(1, at, 10);
        rested(&mut scene);
        let before = scene.owner.report().maintained;
        let header = scene.frame(1, Kind::PutPrepare, at, 10, three_extents(serial));
        scene.inject(1, &header);
        scene.polls(1);
        let report = scene.owner.put_report();
        assert_eq!((report.place_waits, report.run_waits), (1, 1), "{report:?}");
        assert_eq!(
            scene.owner.report().maintained,
            before + 1,
            "the wake ran maintenance"
        );
        drop(pins);
    });
}

/// A waiter that places an extent stops waiting; its next no-run refusal is
/// a first registration again and ends a rest that outlasts that poll.
#[test]
fn a_waiter_that_placed_and_waits_again_ends_the_maintenance_rest_again() {
    let (storage, config) = resting();
    run_wait_scene(storage, config, |mut scene| {
        let mut pins = pin_holes(scene.storage, 8);
        let at = request(1, 1);
        let serial = scene.begin(1, at, 10);
        let header = scene.frame(1, Kind::PutPrepare, at, 10, three_extents(serial));
        scene.inject(1, &header);
        scene.polls(1);
        assert_eq!(run_waiters(&scene), 1);
        rested(&mut scene);
        pins.remove(0).cancel().unwrap();
        scene.polls(1);
        assert_eq!(run_waiters(&scene), 0, "the placement progressed");
        let rest = scene.owner.maintain_rest_until_us();
        assert!(
            rest.is_some_and(|until| until > scene.turn * 100),
            "the rest outlasts the next poll: {rest:?}"
        );
        let before = scene.owner.report().maintained;
        scene.polls(1);
        assert_eq!(run_waiters(&scene), 1, "the PUT waits again");
        assert_eq!(
            scene.owner.report().maintained,
            before + 1,
            "the second registration ran maintenance"
        );
        drop(pins);
    });
}

/// A PREPARE that starts a run wait ends the rest when an older waiter
/// repeats its no-run refusal later in the same poll.
#[test]
fn a_repeat_wait_in_the_same_poll_keeps_a_new_waiters_wake() {
    let (storage, config) = resting();
    run_wait_scene(storage, config, |mut scene| {
        let pins = pin_holes(scene.storage, 8);
        let first = request(1, 1);
        let serial = scene.begin(0, first, 10);
        let header = scene.frame(0, Kind::PutPrepare, first, 10, three_extents(serial));
        scene.inject(0, &header);
        scene.polls(1);
        let second = request(1, 1);
        let serial = scene.begin(1, second, 11);
        rested(&mut scene);
        let (before, waits) = (
            scene.owner.report().maintained,
            scene.owner.put_report().run_waits,
        );
        let header = scene.frame(1, Kind::PutPrepare, second, 11, three_extents(serial));
        scene.inject(1, &header);
        scene.polls(1);
        assert_eq!(run_waiters(&scene), 2);
        assert_eq!(
            scene.owner.put_report().run_waits,
            waits + 2,
            "both PUTs waited in the poll"
        );
        assert_eq!(
            scene.owner.report().maintained,
            before + 1,
            "the new waiter's wake ran maintenance"
        );
        drop(pins);
    });
}

/// Run waiters hold their request slots: with the live-PUT cap at two and
/// both peers' PUTs waiting for a run, a third BEGIN refuses
/// `RequestPressure` at the `puts` cap, the check that precedes the peer's,
/// as it does for any two live PUTs.
#[test]
fn run_waiters_hold_their_slots_so_a_begin_at_the_cap_refuses_request_pressure() {
    run_wait_scene(fragmentable_storage(), OWNER, |mut scene| {
        let pins = pin_holes(scene.storage, 8);
        for (peer, name) in [(0, 10), (1, 11)] {
            let at = request(1, 1);
            let serial = scene.begin(peer, at, name);
            let header = scene.frame(peer, Kind::PutPrepare, at, name, three_extents(serial));
            scene.inject(peer, &header);
            scene.polls(1);
        }
        assert_eq!(run_waiters(&scene), 2);
        assert_eq!(scene.live(), 2);
        let third = scene.frame(1, Kind::PutBegin, request(2, 1), 12, |_| {});
        assert_eq!(error(&scene.one(1, &third)), Some(Status::RequestPressure));
        assert_eq!(scene.owner.put_report().refused_global_cap, 1);
        drop(pins);
    });
}

/// A waiting PUT keeps its promise in escrow, so a one-extent PREPARE that
/// the volume admitted before the waiter refuses `CleanReserve` beside it.
/// The fixture's fill records admit two live PUTs, so one waiter stands for
/// the several a larger owner holds.
#[test]
fn a_waiting_promise_makes_a_one_extent_prepare_refuse_clean_reserve() {
    run_wait_scene(fragmentable_storage(), OWNER, |mut scene| {
        let pins = pin_holes(scene.storage, 3);
        let before = scene.storage.domain_report().unwrap().claimable_units;
        let at = request(1, 1);
        let serial = scene.begin(1, at, 10);
        let header = scene.frame(1, Kind::PutPrepare, at, 10, three_extents(serial));
        scene.inject(1, &header);
        scene.polls(1);
        assert_eq!(run_waiters(&scene), 1);
        let domain = scene.storage.domain_report().unwrap();
        assert_eq!(before - domain.claimable_units, domain.escrow_units);
        // Two units past the claimable ones, so the charge passes them whatever
        // its record header rounds to.
        let units = domain.claimable_units as u32 + 2;
        assert!(
            units <= 40 && u64::from(units) <= before,
            "{units} units fit a hole and the volume before the waiter"
        );
        let at = request(2, 1);
        let serial = scene.begin(0, at, 12);
        let header = scene.frame(0, Kind::PutPrepare, at, 12, one_extent(serial, units));
        scene.inject(0, &header);
        scene.polls(1);
        let errors: Vec<_> = scene.replies(0).iter().filter_map(error).collect();
        assert_eq!(errors, [Status::StoragePressure]);
        let report = scene.owner.put_report();
        assert_eq!(refusal_parts(&report), [0, 0, 1, 0], "{report:?}");
        drop(pins);
    });
}

/// The control for the clean-reserve shift: on the same volume with no
/// waiter, the one-extent PREPARE of the clean-reserve scene's size reaches
/// READY.
#[test]
fn without_a_waiter_the_same_one_extent_prepare_reaches_ready() {
    run_wait_scene(fragmentable_storage(), OWNER, |mut scene| {
        let pins = pin_holes(scene.storage, 3);
        let resident = |scene: &Scene<'_, '_>| {
            let ledger = scene.storage.pool_report().unwrap().ledger.unwrap();
            ledger.raw.resident.div_ceil(crate::storage::IO_UNIT) as u64
        };
        let before = scene.storage.domain_report().unwrap().claimable_units + resident(&scene);
        let at = request(1, 1);
        let serial = scene.begin(1, at, 10);
        let header = scene.frame(1, Kind::PutPrepare, at, 10, three_extents(serial));
        scene.inject(1, &header);
        scene.polls(1);
        let units = scene.storage.domain_report().unwrap().claimable_units as u32 + 2;
        let cancel = scene.frame(1, Kind::PutCancel, at, 10, cancel(serial));
        scene.inject(1, &cancel);
        scene.polls(2);
        scene.replies(1);
        assert_eq!(
            scene.storage.domain_report().unwrap().claimable_units + resident(&scene),
            before,
            "the cancel returns its claim; a resident the PREPARE evicted returns its units at once"
        );
        let at = request(2, 1);
        let serial = scene.begin(0, at, 12);
        let header = scene.frame(0, Kind::PutPrepare, at, 12, one_extent(serial, units));
        scene.inject(0, &header);
        scene.polls(1);
        let kinds: Vec<_> = scene.replies(0).iter().map(|reply| reply.kind).collect();
        assert_eq!(kinds, [Kind::PutReady]);
        drop(pins);
    });
}

/// Observational: a waiter races a stream of one-extent claims; every eighth
/// poll a pin returns and the stream claims a hole before the waiter's next
/// turn. The waiter ends by its deadline, ready or with storage pressure, and
/// the test prints which with its run waits.
#[test]
fn a_run_waiter_beside_a_one_extent_stream_ends_by_its_deadline() {
    run_wait_scene(fragmentable_storage(), OWNER, |mut scene| {
        let mut pins = pin_holes(scene.storage, 8);
        let at = request(1, 1);
        let begin = scene.frame(1, Kind::PutBegin, at, 10, |header| header.remaining_ms = 5);
        let serial = scene.one(1, &begin).allocation;
        let header = scene.frame(1, Kind::PutPrepare, at, 10, three_extents(serial));
        scene.inject(1, &header);
        scene.polls(1);
        assert_eq!(scene.owner.put_report().run_waits, 1, "the PREPARE waits");
        let mut stream = Vec::new();
        for turn in 0..80 {
            if turn % 8 == 0 && !pins.is_empty() {
                pins.remove(0).cancel().unwrap();
                if let Ok(claim) = claim(scene.storage, 40) {
                    stream.push(claim);
                }
            }
            scene.polls(1);
        }
        let ended: Vec<_> = scene
            .replies(1)
            .iter()
            .map(|reply| (reply.kind, error(reply)))
            .collect();
        eprintln!(
            "the waiter's replies {ended:?} after {} run waits beside {} one-extent claims",
            scene.owner.put_report().run_waits,
            stream.len()
        );
        // A ready waiter that the client never feeds ends at its deadline too.
        assert!(
            matches!(
                ended.as_slice(),
                [(Kind::PutError, Some(Status::StoragePressure))]
                    | [
                        (Kind::PutReady, None),
                        (Kind::PutError, Some(Status::TimedOut))
                    ]
            ),
            "{ended:?}"
        );
        assert_eq!(scene.live(), 0);
        assert_eq!(escrow(&scene), 0);
        assert_eq!(run_waiters(&scene), 0);
        drop((stream, pins));
    });
}

/// The volume's free units plus the units evictions hold in flight. An eviction's return moves units from in flight to free, leaving the sum unchanged.
fn free_units(storage: &Storage<TestPlatform>) -> u64 {
    let domain = storage.domain_report().unwrap();
    domain.free_units + domain.in_flight_units
}

/// [`pin_holes`] over eight holes, then polls until maintenance has evicted the published object, the one object the scene holds.
fn settled_holes<'s>(
    scene: &mut Scene<'s, '_>,
) -> Vec<crate::storage::ExtentReservation<'s, TestPlatform>> {
    let pins = pin_holes(scene.storage, 8);
    for _ in 0..100 {
        if scene.storage.maintain_totals().evicted == 1 {
            return pins;
        }
        scene.polls(1);
    }
    panic!(
        "maintenance never evicted: {:?}",
        scene.storage.domain_report()
    );
}

/// Start admits a run-waiter cap `W` in `1..=puts` when `puts` is positive
/// and any `W` when `puts` is zero; the cap refusal names both values,
/// follows the PUT shape check, precedes the fill-capacity check, and
/// returns the budget unchanged.
#[test]
fn start_admits_a_run_waiter_cap_from_one_to_puts_and_any_cap_without_puts() {
    let shaped = |puts: u32, peer_puts: u32, run_waiters: u32| OwnerConfig {
        put: PutConfig {
            puts,
            peer_puts,
            run_waiters,
            ..OWNER.put
        },
        ..OWNER
    };
    assert!(
        matches!(
            start_or_retry(&storage(8), shaped(3, 1, 3)),
            Err(OwnerError::FillCapacity { puts: 3, .. })
        ),
        "three PUTs exceed the fill capacity"
    );
    let refusal = |run_waiters, puts| Err(OwnerError::RunWaiters { run_waiters, puts });
    for (config, expected) in [
        (shaped(2, 1, 0), refusal(0, 2)),
        (shaped(2, 1, 3), refusal(3, 2)),
        (shaped(2, 1, 1), Ok(())),
        (shaped(2, 1, 2), Ok(())),
        (shaped(0, 0, 0), Ok(())),
        (shaped(0, 0, 5), Ok(())),
        (shaped(2, 2, 0), Err(OwnerError::Puts)),
        (shaped(3, 1, 4), refusal(4, 3)),
    ] {
        assert_eq!(start_or_retry(&storage(8), config), expected, "{config:?}");
    }
}

/// With the one waiter `W = 1` admits, a second three-extent PUT whose
/// placement finds no run is refused `StoragePressure` in that poll, at its
/// PREPARE when it placed nothing and on the progress turn after placing one
/// extent. The refusal counts once in `run_wait_refused` and in
/// `failed_other`, nowhere in `reserve_refused` or `run_waits`, sets no
/// run-wait wake, and leaves the waiter count, the waiter's escrow and one
/// live PUT. Once the waiter ends, service returns every placed extent and
/// both fill records take new BEGINs.
#[test]
fn a_placement_at_the_cap_ends_its_put_in_its_turn_holding_nothing() {
    for placed in [0, 1] {
        run_wait_scene(fragmentable_storage(), capped(1), |mut scene| {
            let mut pins = settled_holes(&mut scene);
            let waiter = request(1, 1);
            let waiting = scene.begin(1, waiter, 10);
            let header = scene.frame(1, Kind::PutPrepare, waiter, 10, three_extents(waiting));
            scene.inject(1, &header);
            scene.polls(1);
            assert_eq!(scene.owner.put_report().run_waiters, 1, "{placed}");
            assert!(
                scene.owner.run_wait_woke(),
                "{placed}: a first registration wakes"
            );
            let charge = escrow(&scene);
            let at = request(1, 1);
            let serial = scene.begin(0, at, 11);
            for pin in pins.drain(..placed) {
                pin.cancel().unwrap();
            }
            let free = free_units(scene.storage);
            let before = scene.owner.put_report();
            let header = scene.frame(0, Kind::PutPrepare, at, 11, three_extents(serial));
            scene.inject(0, &header);
            scene.polls(1);
            let errors: Vec<_> = scene.replies(0).iter().filter_map(error).collect();
            assert_eq!(errors, [Status::StoragePressure], "{placed}");
            let report = scene.owner.put_report();
            assert_eq!(
                (report.run_wait_refused, report.failed_other),
                (before.run_wait_refused + 1, before.failed_other + 1),
                "{placed}: {report:?}"
            );
            assert_eq!(
                (report.reserve_refused, refusal_parts(&report)),
                (0, [0; 4]),
                "{placed}: {report:?}"
            );
            assert_eq!(
                (report.run_waits, report.place_waits),
                (before.run_waits + 1, before.place_waits + placed as u64),
                "{placed}: the waiter's retry is the poll's one run wait: {report:?}"
            );
            assert_eq!(report.run_waiters, 1, "{placed}");
            assert!(
                !scene.owner.run_wait_woke(),
                "{placed}: the refusal sets no wake"
            );
            assert_eq!((escrow(&scene), scene.live()), (charge, 1), "{placed}");
            let cancel = scene.frame(1, Kind::PutCancel, waiter, 10, cancel(waiting));
            scene.inject(1, &cancel);
            scene.polls(20);
            let errors: Vec<_> = scene.replies(1).iter().filter_map(error).collect();
            assert_eq!(errors, [Status::Cancelled], "{placed}");
            assert_eq!((scene.live(), escrow(&scene)), (0, 0), "{placed}");
            assert_eq!(
                free_units(scene.storage),
                free,
                "{placed}: every extent returned"
            );
            scene.begin(0, request(2, 1), 12);
            scene.begin(1, request(2, 1), 13);
            drop(pins);
        });
    }
}

/// Under `W = 1` the lone waiter's repeat no-run refusals leave the count at
/// one and never meet the cap. Its first progressing placement lowers the
/// count to zero, and its next no-run refusal raises it to one again as a
/// new registration.
#[test]
fn a_lone_waiter_at_the_cap_retries_and_registers_again_after_progress() {
    run_wait_scene(fragmentable_storage(), capped(1), |mut scene| {
        let mut pins = pin_holes(scene.storage, 8);
        let at = request(1, 1);
        let serial = scene.begin(1, at, 10);
        let header = scene.frame(1, Kind::PutPrepare, at, 10, three_extents(serial));
        scene.inject(1, &header);
        scene.polls(1);
        for poll in 1..=5 {
            scene.polls(1);
            let report = scene.owner.put_report();
            assert_eq!(
                (
                    report.run_waiters,
                    report.run_waits,
                    report.run_wait_refused
                ),
                (1, 1 + poll, 0),
                "{report:?}"
            );
            assert!(!scene.owner.run_wait_woke(), "a repeat sets no wake");
        }
        pins.remove(0).cancel().unwrap();
        scene.polls(1);
        assert_eq!(
            scene.owner.put_report().run_waiters,
            0,
            "the placement progressed"
        );
        scene.polls(1);
        let report = scene.owner.put_report();
        assert_eq!(
            (report.run_waiters, report.run_wait_refused),
            (1, 0),
            "{report:?}"
        );
        assert!(scene.owner.run_wait_woke(), "the second registration wakes");
        assert!(scene.replies(1).is_empty());
        drop(pins);
    });
}

#[test]
fn a_waiter_counts_one_run_wait_per_poll_beside_other_progress_and_alone() {
    run_wait_scene(fragmentable_storage(), OWNER, |mut scene| {
        let pins = settled_holes(&mut scene);
        let at = request(1, 1);
        let serial = scene.begin(1, at, 10);
        let header = scene.frame(1, Kind::PutPrepare, at, 10, three_extents(serial));
        scene.inject(1, &header);
        scene.polls(2);
        let upload = request(1, 1);
        let serial = scene.begin(0, upload, 11);
        let header = scene.frame(0, Kind::PutPrepare, upload, 11, prepare(serial, 0, 60_000));
        scene.inject(0, &header);
        scene.polls(1);
        let kinds: Vec<_> = scene.replies(0).iter().map(|reply| reply.kind).collect();
        assert_eq!(kinds, [Kind::PutReady], "the header write is outstanding");
        let before = scene.owner.put_report().run_waits;
        take_progress_visits();
        take_proven_run_waits();
        scene.polls(5);
        assert_eq!(
            (
                take_progress_visits(),
                scene.owner.put_report().run_waits - before,
                take_proven_run_waits()
            ),
            (10, 5, 5),
            "each poll visits both PUTs and counts the waiter's proven run wait"
        );
        for _ in 0..10 {
            scene.turns(1);
            if scene.live() == 1 {
                break;
            }
        }
        let kinds: Vec<_> = scene.replies(0).iter().map(|reply| reply.kind).collect();
        assert_eq!(kinds, [Kind::PutResult], "the other PUT published");
        assert_eq!(scene.live(), 1);
        let before = scene.owner.put_report().run_waits;
        take_progress_visits();
        take_proven_run_waits();
        scene.polls(5);
        let report = scene.owner.put_report();
        assert_eq!(
            (
                take_progress_visits(),
                report.run_waits - before,
                take_proven_run_waits()
            ),
            (5, 5, 5),
            "the lone waiter is visited and counted once per poll"
        );
        assert_eq!((report.run_waiters, report.place_waits), (1, 0));
        assert!(scene.replies(1).is_empty());
        drop(pins);
    });
}

#[test]
fn a_run_that_holds_one_waiters_extent_ends_that_wait_and_leaves_the_longer_one() {
    for long_ends_first in [false, true] {
        run_wait_scene(fragmentable_storage(), OWNER, |mut scene| {
            for pin in settled_holes(&mut scene) {
                pin.cancel().unwrap();
            }
            let direct = |units: usize| claim(scene.storage, units).unwrap();
            let first = direct(62);
            let mut held = vec![direct(1)];
            let gap = direct(50);
            held.push(direct(1));
            let mut cut = Vec::new();
            for _ in 0..6 {
                cut.push(direct(40));
                held.push(direct(1));
            }
            while scene
                .storage
                .pool_report()
                .unwrap()
                .ledger
                .unwrap()
                .raw
                .free
                / crate::storage::IO_UNIT
                > 41
            {
                held.push(direct(40));
            }
            first.cancel().unwrap();
            for hole in cut {
                hole.cancel().unwrap();
            }
            let short = request(1, 1);
            let serial = scene.begin(1, short, 10);
            let header = scene.frame(1, Kind::PutPrepare, short, 10, |header| {
                three_extents(serial)(header);
                header.metadata_len = 253_952 + 44 * crate::storage::IO_UNIT as u32;
                header.total = u64::from(header.metadata_len + header.body_len);
                header.count = FragmentGeometry::fragments(header.total) as u32;
            });
            scene.inject(1, &header);
            scene.polls(3);
            let long = request(1, 1);
            let long_serial = scene.begin(0, long, 11);
            let header = scene.frame(0, Kind::PutPrepare, long, 11, three_extents(long_serial));
            scene.inject(0, &header);
            scene.polls(3);
            let report = scene.owner.put_report();
            assert_eq!(
                (report.run_waiters, report.place_waits),
                (2, 1),
                "both wait, the shorter one after placing its first extent: {report:?}"
            );
            let proven = |scene: &mut Scene<'_, '_>, polls: u64| {
                let before = scene.owner.put_report().run_waits;
                take_progress_visits();
                take_proven_run_waits();
                scene.polls(polls);
                (
                    take_progress_visits(),
                    scene.owner.put_report().run_waits - before,
                    take_proven_run_waits(),
                )
            };
            assert_eq!(proven(&mut scene, 3), (6, 6, 6), "both waits are proven");
            if long_ends_first {
                let end = scene.frame(0, Kind::PutCancel, long, 11, cancel(long_serial));
                scene.inject(0, &end);
                scene.polls(1);
                let errors: Vec<_> = scene.replies(0).iter().filter_map(error).collect();
                assert_eq!(errors, [Status::Cancelled]);
                assert_eq!(
                    proven(&mut scene, 3),
                    (3, 3, 3),
                    "the shorter wait keeps the floor and stays proven"
                );
                drop(held);
                return;
            }
            gap.cancel().unwrap();
            scene.polls(1);
            assert_eq!(
                scene.owner.put_report().run_waiters,
                1,
                "the shorter extent placed"
            );
            scene.polls(2);
            let kinds: Vec<_> = scene.replies(1).iter().map(|reply| reply.kind).collect();
            assert_eq!(kinds, [Kind::PutReady]);
            assert!(scene.replies(0).is_empty(), "the longer extent still waits");
            assert_eq!(scene.owner.put_report().run_waiters, 1);
            let (_, waits, proofs) = proven(&mut scene, 3);
            assert_eq!(
                (waits, proofs),
                (3, 3),
                "the floor rose to the longer extent, whose waits are proven again"
            );
            for pin in held {
                pin.cancel().unwrap();
            }
            scene.polls(3);
            let kinds: Vec<_> = scene.replies(0).iter().map(|reply| reply.kind).collect();
            assert_eq!(kinds, [Kind::PutReady], "the longer extent placed");
            assert_eq!(scene.owner.put_report().run_waiters, 0);
        });
    }
}

/// Two placements wait for a run and nothing else waits. Each pass counts both waits from the run bound, and the admission order holds the same two slots in the same order after the passes.
#[test]
fn passes_over_marked_waiters_alone_count_each_waiter_and_keep_the_admission_order() {
    run_wait_scene(fragmentable_storage(), OWNER, |mut scene| {
        let pins = settled_holes(&mut scene);
        for (peer, name) in [(1, 10), (0, 11)] {
            let at = request(1, 1);
            let serial = scene.begin(peer, at, name);
            let header = scene.frame(peer, Kind::PutPrepare, at, name, three_extents(serial));
            scene.inject(peer, &header);
            scene.polls(1);
        }
        scene.polls(1);
        let order = scene.owner.put_admission_order();
        assert_eq!(order.len(), 2, "{order:?}");
        take_proven_run_waits();
        scene.polls(4);
        assert_eq!(take_proven_run_waits(), 8, "every pass is proven");
        assert_eq!(scene.owner.put_admission_order(), order);
        drop(pins);
    });
}

#[test]
fn a_run_an_earlier_put_returns_in_the_pass_ends_a_marked_wait_in_that_poll() {
    run_wait_scene(fragmentable_storage(), OWNER, |mut scene| {
        for pin in settled_holes(&mut scene) {
            pin.cancel().unwrap();
        }
        let direct = |units: usize| claim(scene.storage, units).unwrap();
        let run = direct(62);
        let mut held = vec![direct(1)];
        let mut cut = Vec::new();
        for _ in 0..6 {
            cut.push(direct(40));
            held.push(direct(1));
        }
        while scene
            .storage
            .pool_report()
            .unwrap()
            .ledger
            .unwrap()
            .raw
            .free
            / crate::storage::IO_UNIT
            > 41
        {
            held.push(direct(40));
        }
        run.cancel().unwrap();
        for hole in cut {
            hole.cancel().unwrap();
        }
        let upload = request(1, 1);
        let begin = scene.frame(0, Kind::PutBegin, upload, 11, |header| {
            header.remaining_ms = 5
        });
        let serial = scene.one(0, &begin).allocation;
        let header = scene.frame(0, Kind::PutPrepare, upload, 11, |header| {
            prepare(serial, 1, 60_000)(header);
            header.metadata_len = 200_000;
            header.total = u64::from(header.metadata_len + header.body_len);
            header.count = FragmentGeometry::fragments(header.total) as u32;
        });
        assert_eq!(scene.one(0, &header).kind, Kind::PutReady);
        let at = request(1, 1);
        let serial = scene.begin(1, at, 10);
        let header = scene.frame(1, Kind::PutPrepare, at, 10, three_extents(serial));
        scene.inject(1, &header);
        scene.polls(2);
        take_proven_run_waits();
        scene.polls(1);
        assert_eq!(
            (
                scene.owner.put_report().run_waiters,
                take_proven_run_waits()
            ),
            (1, 1),
            "the waiter is marked while the upload holds the long run"
        );
        for _ in 0..200 {
            scene.polls(1);
            if scene.replies(0).iter().any(|reply| error(reply).is_some()) {
                assert_eq!(
                    scene.owner.put_report().run_waiters,
                    0,
                    "the waiter placed in the poll the upload ended"
                );
                drop(held);
                return;
            }
        }
        panic!("the upload never reached its deadline");
    });
}

#[test]
fn a_cancelled_waiter_with_nothing_placed_holds_no_slot_or_escrow_after_its_poll() {
    run_wait_scene(fragmentable_storage(), OWNER, |mut scene| {
        let pins = settled_holes(&mut scene);
        let free_slots = |scene: &Scene<'_, '_>| scene.storage.domain_report().unwrap().free_slots;
        let at = request(1, 1);
        let serial = scene.begin(1, at, 10);
        let idle = free_slots(&scene);
        let header = scene.frame(1, Kind::PutPrepare, at, 10, three_extents(serial));
        scene.inject(1, &header);
        scene.polls(2);
        assert_eq!(scene.owner.put_report().run_waiters, 1);
        assert_eq!(free_slots(&scene), idle - 1, "the promise holds a slot");
        let end = scene.frame(1, Kind::PutCancel, at, 10, cancel(serial));
        scene.inject(1, &end);
        scene.polls(1);
        let errors: Vec<_> = scene.replies(1).iter().filter_map(error).collect();
        assert_eq!(errors, [Status::Cancelled]);
        assert_eq!((free_slots(&scene), escrow(&scene)), (idle, 0));
        drop(pins);
    });
}

/// How a waiting PUT leaves `Placing`.
#[derive(Debug, Clone, Copy)]
enum Exit {
    Deadline,
    Cancel,
    SessionEnd,
    Close,
}

/// A PUT that placed one extent and then waits leaves the waiter count once
/// at its deadline, a CANCEL, its session's end or the owner's close, and
/// service returns its placed extent and block: the free units come back to
/// their level before its PREPARE, with the escrow at zero.
#[test]
fn every_exit_of_a_waiter_that_placed_an_extent_returns_what_it_placed() {
    for exit in [Exit::Deadline, Exit::Cancel, Exit::SessionEnd, Exit::Close] {
        run_wait_scene(fragmentable_storage(), OWNER, |mut scene| {
            let mut pins = settled_holes(&mut scene);
            pins.remove(0).cancel().unwrap();
            let free = free_units(scene.storage);
            let at = request(1, 1);
            let begin = scene.frame(1, Kind::PutBegin, at, 10, |header| header.remaining_ms = 5);
            let serial = scene.one(1, &begin).allocation;
            let header = scene.frame(1, Kind::PutPrepare, at, 10, three_extents(serial));
            scene.inject(1, &header);
            scene.polls(1);
            let report = scene.owner.put_report();
            assert_eq!(
                (report.place_waits, report.run_waiters),
                (1, 1),
                "{exit:?}: {report:?}"
            );
            assert!(
                free_units(scene.storage) < free,
                "{exit:?}: an extent is placed"
            );
            take_proven_run_waits();
            scene.polls(2);
            assert_eq!(
                take_proven_run_waits(),
                1,
                "{exit:?}: the waiter is marked before it ends"
            );
            match exit {
                Exit::Deadline => {
                    for _ in 0..100 {
                        if scene.live() == 0 {
                            break;
                        }
                        scene.polls(1);
                    }
                }
                Exit::Cancel => {
                    let cancel = scene.frame(1, Kind::PutCancel, at, 10, cancel(serial));
                    scene.inject(1, &cancel);
                    scene.polls(1);
                }
                Exit::SessionEnd => scene.reopen(1),
                Exit::Close => {
                    let _ = scene.owner.close(scene.turn * 100);
                    scene.polls(1);
                }
            }
            let report = scene.owner.put_report();
            let deadline = u64::from(matches!(exit, Exit::Deadline));
            assert_eq!(
                (
                    scene.live(),
                    report.run_waiters,
                    report.reserve_refused,
                    report.run_wait_refused,
                    report.failed_other,
                    report.failed_timed_out,
                    report.cancelled
                ),
                (
                    0,
                    0,
                    deadline,
                    0,
                    deadline,
                    0,
                    u64::from(matches!(exit, Exit::Cancel))
                ),
                "{exit:?}: only the deadline tallies a refusal: {report:?}"
            );
            scene.polls(20);
            assert_eq!(escrow(&scene), 0, "{exit:?}");
            assert_eq!(free_units(scene.storage), free, "{exit:?}");
            drop(pins);
        });
    }
}

#[test]
fn waiters_ending_in_one_turn_clear_their_marks_without_reading_marked_records() {
    for exit in [Exit::Deadline, Exit::Close] {
        run_wait_scene(fragmentable_storage(), OWNER, |mut scene| {
            let pins = pin_holes(scene.storage, 8);
            let at = request(1, 1);
            let waiters = [(0, 10), (1, 11)];
            for (peer, name) in waiters {
                let begin = scene.frame(peer, Kind::PutBegin, at, name, |header| {
                    header.remaining_ms = 5
                });
                scene.inject(peer, &begin);
            }
            scene.turns(4);
            for (peer, name) in waiters {
                let authority = scene.replies(peer);
                assert_eq!(authority.len(), 1, "{exit:?}: {authority:?}");
                let serial = authority[0].allocation;
                let header = scene.frame(peer, Kind::PutPrepare, at, name, three_extents(serial));
                scene.inject(peer, &header);
            }
            scene.polls(2);
            take_proven_run_waits();
            scene.polls(1);
            assert_eq!(
                (
                    scene.owner.put_report().run_waiters,
                    take_proven_run_waits()
                ),
                (2, 2),
                "{exit:?}: both waiters are marked"
            );
            take_floor_reads();
            match exit {
                Exit::Deadline => {
                    for _ in 0..100 {
                        scene.polls(1);
                        if scene.live() < 2 {
                            break;
                        }
                    }
                    assert_eq!(scene.live(), 0, "{exit:?}: one tick ends both waiters");
                }
                Exit::Close => {
                    let _ = scene.owner.close(scene.turn * 100);
                    scene.polls(1);
                }
                Exit::Cancel | Exit::SessionEnd => unreachable!("the scene ends both at once"),
            }
            scene.polls(1);
            assert_eq!(
                (scene.live(), scene.owner.put_report().run_waiters),
                (0, 0),
                "{exit:?}"
            );
            assert_eq!(take_floor_reads(), 0, "{exit:?}: no mark is left to read");
            drop(pins);
        });
    }
}

/// [`fragmentable_storage`] over two index shards of 16 slots and one fill
/// record each.
fn two_shard_storage() -> Storage<TestPlatform> {
    crate::storage::owner_fixture::two_shard_sequence_storage(
        THREE_EXTENT_LENGTHS.0 as usize,
        RUN_WAIT_SHAPE,
        1,
    )
}

/// Key names from 10 on whose keys route to `shard` of `storage`.
fn names_in(storage: &Storage<TestPlatform>, shard: usize) -> impl Iterator<Item = u8> + '_ {
    (10..=u8::MAX).filter(move |&name| storage.route(&key(name)).unwrap().shard().0 == shard)
}

/// `body` takes a scene over [`two_shard_storage`] that holds one live fill
/// in each shard, both under one serial, after the owner validated fragment
/// 0 of each with its validation record on, and each fill's key name and
/// serial, in shard order.
pub(super) fn scene_with_one_serial_in_two_shards(
    body: impl FnOnce(Scene<'_, '_>, [(u8, u64); 2]),
) {
    scene_over(two_shard_storage(), OWNER, &PRINCIPALS, |mut scene| {
        let object = payload(FRAGMENT_LEN as usize, 21);
        let mut names = [0, 1].map(|shard| names_in(scene.storage, shard));
        let mut generation = 0;
        let mut ready = |scene: &mut Scene<'_, '_>, peer: usize| {
            generation += 1;
            let (at, name) = (request(1, generation), names[peer].next().unwrap());
            let serial = scene.begin(peer, at, name);
            let prepared = prepare(serial, object.len() as u32, 60_000);
            let header = scene.frame(peer, Kind::PutPrepare, at, name, prepared);
            assert_eq!(scene.one(peer, &header).kind, Kind::PutReady);
            (at, name, serial)
        };
        let send = |scene: &mut Scene<'_, '_>, peer: usize, (at, name, serial)| {
            let (header, body) = scene.fragment_from(peer, at, serial, name, &object, 0);
            scene.inject_edited(peer, &header, &body, |_| {});
        };
        let mut fills = [ready(&mut scene, 0), ready(&mut scene, 1)];
        for _ in 0..4 {
            if fills[0].2 == fills[1].2 {
                break;
            }
            let behind = usize::from(fills[1].2 < fills[0].2);
            send(&mut scene, behind, fills[behind]);
            scene.turns(OWNER.serve.linger_us / 100 + 8);
            let published = scene.replies(behind);
            assert_eq!(
                published.last().map(|reply| reply.kind),
                Some(Kind::PutResult)
            );
            fills[behind] = ready(&mut scene, behind);
        }
        assert_eq!(
            fills[0].2, fills[1].2,
            "the shard behind published fills until both issued one serial"
        );
        scene.owner.track_put_validation();
        for (peer, &fill) in fills.iter().enumerate() {
            send(&mut scene, peer, fill);
            scene.polls(1);
        }
        body(scene, fills.map(|(_, name, serial)| (name, serial)));
    });
}

/// Fill serials are shard-local; validation records distinguish fills with
/// equal serials by key.
#[test]
fn validations_under_one_serial_in_two_shards_name_their_own_keys() {
    scene_with_one_serial_in_two_shards(|scene, fills| {
        let (validations, overflow) = scene.owner.put_validated();
        assert!(!overflow);
        let named: Vec<_> = validations
            .iter()
            .map(|v| (v.key, v.serial, v.index, v.base))
            .collect();
        assert_eq!(named, fills.map(|(name, serial)| (key(name), serial, 0, 1)));
    });
}

/// On the two-shard fixture, with `request_slots` equal to `puts` plus
/// `get_reserve` and both PUT slots held by waiters, one in each shard, a
/// GET takes a reserved slot and receives its lookup's answer, `Missing`
/// once maintenance evicted the published object, and a third BEGIN refuses
/// `RequestPressure` at the `puts` cap.
#[test]
fn waiters_in_every_put_slot_leave_the_get_reserve_to_gets() {
    let config = OwnerConfig {
        get_reserve: 2,
        ..OWNER
    };
    assert_eq!(config.request_slots, config.put.puts + config.get_reserve);
    run_wait_scene(two_shard_storage(), config, |mut scene| {
        let pins = settled_holes(&mut scene);
        let names = [0, 1].map(|shard| names_in(scene.storage, shard).next().unwrap());
        for (peer, name) in [(0, names[0]), (1, names[1])] {
            let at = request(1, 1);
            let serial = scene.begin(peer, at, name);
            let header = scene.frame(peer, Kind::PutPrepare, at, name, three_extents(serial));
            scene.inject(peer, &header);
            scene.polls(1);
        }
        assert_eq!(scene.owner.put_report().run_waiters, 2);
        assert_eq!(scene.live(), 2);
        let get = scene.get(0, request(2, 1), 1);
        scene.inject(0, &get);
        scene.polls(2);
        let replies: Vec<_> = scene
            .sent(0)
            .iter()
            .filter(|header| header.request == request(2, 1))
            .map(|header| (header.kind, Status::from_wire(header.status)))
            .collect();
        assert_eq!(
            replies,
            [(Kind::Error, Some(Status::Missing))],
            "the GET's lookup answers"
        );
        assert_eq!(scene.owner.serve_report().refused_pressure.table, 0);
        let name = names_in(scene.storage, 0).nth(1).unwrap();
        let third = scene.frame(1, Kind::PutBegin, request(2, 1), name, |_| {});
        assert_eq!(error(&scene.one(1, &third)), Some(Status::RequestPressure));
        let report = scene.owner.put_report();
        assert_eq!(
            (report.refused_global_cap, report.run_waiters),
            (1, 2),
            "{report:?}"
        );
        drop(pins);
    });
}

/// On the two-shard fixture, with the waiter holding its shard's one fill
/// record, a BEGIN whose key routes to that shard refuses `StoragePressure`
/// for `FillSlotsFull`, counted once in `refused_fill_slots`, while a BEGIN
/// whose key routes to the other shard takes that shard's free record.
#[test]
fn a_waiter_holding_its_shards_record_refuses_a_begin_there_and_not_in_the_other_shard() {
    run_wait_scene(two_shard_storage(), OWNER, |mut scene| {
        let pins = pin_holes(scene.storage, 8);
        let mut held = names_in(scene.storage, 0);
        let (waiter, blocked) = (held.next().unwrap(), held.next().unwrap());
        let open = names_in(scene.storage, 1).next().unwrap();
        let at = request(1, 1);
        let serial = scene.begin(1, at, waiter);
        let header = scene.frame(1, Kind::PutPrepare, at, waiter, three_extents(serial));
        scene.inject(1, &header);
        scene.polls(1);
        assert_eq!(scene.owner.put_report().run_waiters, 1);
        let refused = scene.frame(0, Kind::PutBegin, request(1, 1), blocked, |_| {});
        assert_eq!(
            error(&scene.one(0, &refused)),
            Some(Status::StoragePressure)
        );
        let report = scene.owner.put_report();
        assert_eq!(
            (
                report.refused_fill_slots,
                report.reserve_refused,
                scene.live()
            ),
            (1, 0, 1),
            "{report:?}"
        );
        scene.begin(0, request(2, 1), open);
        assert_eq!(scene.live(), 2);
        assert_eq!(scene.owner.put_report().refused_fill_slots, 1);
        drop(pins);
    });
}

/// Two PREPAREs that find no run in one poll under `W = 1` meet the count
/// as each one's placement leaves it: the first registers, and the second
/// is refused at the cap in that poll.
#[test]
fn two_placements_in_one_poll_admit_one_waiter_under_a_cap_of_one() {
    run_wait_scene(fragmentable_storage(), capped(1), |mut scene| {
        let pins = pin_holes(scene.storage, 8);
        let at = request(1, 1);
        let serials =
            [(0, 10), (1, 11)].map(|(peer, name)| (peer, name, scene.begin(peer, at, name)));
        for (peer, name, serial) in serials {
            let header = scene.frame(peer, Kind::PutPrepare, at, name, three_extents(serial));
            scene.inject(peer, &header);
        }
        scene.polls(1);
        let errors: Vec<_> = [0, 1]
            .into_iter()
            .flat_map(|peer| scene.replies(peer))
            .filter_map(|reply| error(&reply))
            .collect();
        assert_eq!(errors, [Status::StoragePressure]);
        let report = scene.owner.put_report();
        assert_eq!(
            (
                report.run_waiters,
                report.run_wait_refused,
                report.run_waits
            ),
            (1, 1, 1),
            "{report:?}"
        );
        assert_eq!(scene.live(), 1);
        assert!(scene.owner.run_wait_woke());
        drop(pins);
    });
}

/// A builder promised outside the owner that waits for a run sets its own
/// waiting flag and leaves the PUT core's count at zero. Under `W = 1` the
/// owner then admits its own first waiter: the core counts one beside the
/// outside waiter, and no PUT is refused at the cap.
#[test]
fn the_put_cores_count_decides_the_cap_beside_a_waiter_outside_the_owner() {
    scene_over(
        fragmentable_storage(),
        capped(1),
        &PRINCIPALS,
        |mut scene| {
            let pins = pin_holes(scene.storage, 8);
            let (metadata_len, body_len) = THREE_EXTENT_LENGTHS;
            let mut outside = scene
                .storage
                .promise(
                    Some(metadata_len as usize),
                    Some(body_len as usize),
                    &mut WorkBudget::new(1 << 16),
                )
                .unwrap();
            assert_eq!(
                outside.place(&mut WorkBudget::new(1 << 16)).err(),
                Some(crate::storage::PromiseError::Reserve(
                    crate::storage::ReserveError::PayloadFull
                ))
            );
            assert!(outside.waiting());
            assert_eq!(
                run_waiters(&scene),
                0,
                "the outside builder is not the core's"
            );
            let at = request(1, 1);
            let serial = scene.begin(1, at, 10);
            let header = scene.frame(1, Kind::PutPrepare, at, 10, three_extents(serial));
            scene.inject(1, &header);
            scene.polls(1);
            assert!(scene.replies(1).is_empty(), "the PREPARE waits");
            let report = scene.owner.put_report();
            assert_eq!(
                (report.run_waiters, report.run_wait_refused),
                (1, 0),
                "{report:?}"
            );
            assert_eq!(run_waiters(&scene), 1);
            assert!(outside.waiting(), "the outside builder still waits");
            outside.cancel();
            drop(pins);
        },
    );
}

/// Under `W = 2` two waiters count two. A CANCEL of one lowers the count to
/// one and leaves the other counted; a returned pin instead lets one waiter
/// place an extent, and that progressing placement lowers the count from
/// two to one in its poll while the other waiter stays counted. An owner
/// close ends both waiters in one turn, the count reaching zero with no
/// refusal or failure tallied.
#[test]
fn waiters_leaving_the_wait_lower_the_count_once_each() {
    #[derive(Debug, Clone, Copy, PartialEq)]
    enum Leave {
        Cancel,
        Progress,
        Close,
    }
    for leave in [Leave::Cancel, Leave::Progress, Leave::Close] {
        run_wait_scene(fragmentable_storage(), OWNER, |mut scene| {
            let mut pins = pin_holes(scene.storage, 8);
            let at = request(1, 1);
            let serials =
                [(0, 10), (1, 11)].map(|(peer, name)| (peer, name, scene.begin(peer, at, name)));
            for (peer, name, serial) in serials {
                let header = scene.frame(peer, Kind::PutPrepare, at, name, three_extents(serial));
                scene.inject(peer, &header);
            }
            scene.polls(1);
            assert_eq!(scene.owner.put_report().run_waiters, 2, "{leave:?}");
            let before = scene.owner.put_report();
            match leave {
                Leave::Cancel => {
                    let (peer, name, serial) = serials[0];
                    let cancel = scene.frame(peer, Kind::PutCancel, at, name, cancel(serial));
                    scene.inject(peer, &cancel);
                }
                Leave::Progress => pins.remove(0).cancel().unwrap(),
                Leave::Close => {
                    let _ = scene.owner.close(scene.turn * 100);
                }
            }
            scene.polls(1);
            let report = scene.owner.put_report();
            let (waiters, live) = match leave {
                Leave::Cancel => (1, 1),
                Leave::Progress => (1, 2),
                Leave::Close => (0, 0),
            };
            assert_eq!(
                (report.run_waiters, scene.live()),
                (waiters, live),
                "{leave:?}: {report:?}"
            );
            assert_eq!(
                (
                    report.run_wait_refused,
                    report.reserve_refused,
                    report.failed_other,
                    report.failed_timed_out
                ),
                (
                    0,
                    before.reserve_refused,
                    before.failed_other,
                    before.failed_timed_out
                ),
                "{leave:?}: {report:?}"
            );
            drop(pins);
        });
    }
}

/// A returned pin raises the run bound over a waiter's next extent, so its
/// retry tries the pool gate. With the gate held the retry counts one place
/// wait, the builder keeps waiting, and both waiter counts, the escrow,
/// the refusal tallies and the replies stay unchanged. Once the gate is
/// free, the next retry places an extent and both counts fall to zero.
#[test]
fn a_waiters_retry_at_a_busy_pool_gate_keeps_it_counted() {
    run_wait_scene(fragmentable_storage(), capped(1), |mut scene| {
        let mut pins = pin_holes(scene.storage, 8);
        let at = request(1, 1);
        let serial = scene.begin(1, at, 10);
        let header = scene.frame(1, Kind::PutPrepare, at, 10, three_extents(serial));
        scene.inject(1, &header);
        scene.polls(1);
        assert_eq!(scene.owner.put_report().run_waiters, 1);
        let charge = escrow(&scene);
        pins.remove(0).cancel().unwrap();
        let before = scene.owner.put_report();
        let storage = scene.storage;
        crate::storage::owner_fixture::with_pool_held(storage, || scene.polls(1));
        let report = scene.owner.put_report();
        assert_eq!(
            (
                report.run_waiters,
                report.run_waits,
                report.place_waits,
                report.run_wait_refused,
                report.failed_other
            ),
            (
                1,
                before.run_waits,
                before.place_waits + 1,
                0,
                before.failed_other
            ),
            "{report:?}"
        );
        assert_eq!(
            (report.reserve_refused, refusal_parts(&report)),
            (before.reserve_refused, refusal_parts(&before)),
            "{report:?}"
        );
        assert_eq!(run_waiters(&scene), 1);
        assert_eq!(escrow(&scene), charge);
        assert!(scene.replies(1).is_empty());
        scene.polls(1);
        let report = scene.owner.put_report();
        assert_eq!(
            (
                scene.live(),
                report.run_waiters,
                report.place_waits,
                report.run_wait_refused,
                report.failed_other
            ),
            (1, 0, before.place_waits + 2, 0, before.failed_other),
            "the free gate lets the retry place an extent: {report:?}"
        );
        assert_eq!(run_waiters(&scene), 0);
        drop(pins);
    });
}

/// A fencing of tenure 0 of the store-test shard with every page fenced over `store`.
pub(super) fn fenced_coverage(
    store: &crate::storage::store::sim::Shared,
    session: &crate::storage::Session,
) -> (
    crate::storage::page_coverage::Fencing,
    crate::storage::store::Client<
        crate::storage::store::sim::Shared,
        crate::storage::store::sim::MemLog,
    >,
) {
    use crate::storage::page_coverage::{Fencing, Progress};
    use crate::storage::store_tests::{client, record_under};
    let mut client = client(store);
    let record = record_under(session);
    let mut fencing = Fencing::new(&record, session, 4).unwrap();
    for at in 0..record.pages.get() {
        assert!(
            (0..8).any(|_| fencing.fence(&mut client, at) == Ok(Progress::Done)),
            "page {} fences",
            at
        );
    }
    (fencing, client)
}

/// Version 0 alone, the version a PUT BEGIN with a zero offset names.
fn version_zero() -> crate::storage::page_coverage::Interval {
    use crate::storage::CacheVersion;
    crate::storage::page_coverage::Interval::new(CacheVersion(0), CacheVersion(0)).unwrap()
}

/// A one-fragment upload of key `name` brought to `Ready`: the BEGIN, then the PREPARE whose header write is the
/// payload's first write.
pub(super) fn ready_named(scene: &mut Scene<'_, '_>, at: u64, name: u8, object: &[u8]) -> u64 {
    let begin = scene.frame(1, Kind::PutBegin, at, name, |header| {
        header.remaining_ms = 10_000
    });
    let authority = scene.one(1, &begin);
    assert_eq!(
        (authority.kind, error(&authority)),
        (Kind::PutAuthority, None),
        "key {name}"
    );
    let serial = authority.allocation;
    let header = scene.frame(
        1,
        Kind::PutPrepare,
        at,
        name,
        prepare(serial, object.len() as u32, 60_000),
    );
    assert_eq!(scene.one(1, &header).kind, Kind::PutReady);
    serial
}

/// The publication outcome of key `name`'s ready upload once its one fragment arrives.
pub(super) fn finish_named(
    scene: &mut Scene<'_, '_>,
    at: u64,
    serial: u64,
    name: u8,
    object: &[u8],
) -> Option<Status> {
    let (header, body) = scene.fragment_from(1, at, serial, name, object, 0);
    let replies = scene.put_data(&header, &body);
    let last = replies.last().expect("the publication's reply");
    match last.kind {
        Kind::PutResult => None,
        _ => Some(error(last).expect("a PUT ERROR")),
    }
}

/// FILL admission checks `(k, v)` against the tenure's coverage twice. An acknowledged INVALIDATE and one whose
/// page write timed out each refuse the BEGIN before any payload write. Coverage that arrives between the payload
/// write and the index insert, with the attempt unrevoked, refuses the publication, and the key stays unmapped. A
/// FILL acknowledged at its insert keeps its result after a later INVALIDATE. The control plants a publication
/// that skips the insert recheck: the covered FILL is published and served.
#[test]
fn fill_coverage_checked_twice() {
    use crate::storage::store::sim::Arm;
    let zero = version_zero();
    for skip in [false, true] {
        scene(&PRINCIPALS, |mut scene| {
            let store = crate::storage::store_tests::seeded_under(scene.owner.tenure());
            let (fencing, mut client) = fenced_coverage(&store, scene.owner.tenure());
            scene.owner.install_coverage(fencing).unwrap();
            let mut budget = WorkBudget::new(1 << 12);
            let mut acknowledged = Vec::new();
            scene
                .owner
                .invalidate_interval(&key(5), zero, 4, &mut budget)
                .unwrap();
            scene
                .owner
                .cover_pending(&mut client, &mut acknowledged, 0)
                .unwrap();
            assert_eq!(acknowledged, [(key(5), zero)]);
            store.schedule(Arm::Timeout { commit: false });
            scene
                .owner
                .invalidate_interval(&key(6), zero, 4, &mut budget)
                .unwrap();
            scene
                .owner
                .cover_pending(&mut client, &mut acknowledged, 0)
                .unwrap();
            assert_eq!(
                acknowledged.len(),
                1,
                "the timed-out write acknowledges nothing"
            );
            let writes = scene.owner.volume_report().writes_submitted;
            for (slot, name) in [(1, 5), (2, 6)] {
                let begin = scene.frame(1, Kind::PutBegin, request(slot, 1), name, |header| {
                    header.remaining_ms = 10_000
                });
                assert_eq!(
                    error(&scene.one(1, &begin)),
                    Some(Status::Contended),
                    "key {name}"
                );
            }
            assert_eq!(
                scene.owner.volume_report().writes_submitted,
                writes,
                "no payload write"
            );
            let object = payload(100, 3);
            let serial = ready_named(&mut scene, request(3, 1), 7, &object);
            scene.owner.coverage_mut().unwrap().hold((key(7), zero));
            super::put::SKIP_INSERT_RECHECK.with(|cell| cell.set(skip));
            let outcome = finish_named(&mut scene, request(3, 1), serial, 7, &object);
            super::put::SKIP_INSERT_RECHECK.with(|cell| cell.set(false));
            if skip {
                assert_eq!(
                    (outcome, scene.visible(7)),
                    (None, true),
                    "the control admits the covered FILL"
                );
                return;
            }
            assert_eq!(
                (outcome, scene.visible(7)),
                (Some(Status::Contended), false)
            );
            let serial = ready_named(&mut scene, request(0, 1), 8, &object);
            assert_eq!(
                finish_named(&mut scene, request(0, 1), serial, 8, &object),
                None
            );
            scene
                .owner
                .invalidate_interval(&key(8), zero, 4, &mut budget)
                .unwrap();
            let resent = scene.frame(
                1,
                Kind::PutPrepare,
                request(0, 1),
                8,
                prepare(serial, 100, 60_000),
            );
            assert_eq!(
                scene.one(1, &resent).kind,
                Kind::PutResult,
                "the acknowledged FILL stands"
            );
        });
    }
}

/// A store double that counts every request and, while `down` is set, answers each read unavailable and each write
/// with an unknown outcome that does not apply, as a partition from the store would.
#[derive(Clone)]
struct Partition {
    store: crate::storage::store::sim::Shared,
    down: Rc<std::cell::Cell<bool>>,
    calls: Rc<std::cell::Cell<usize>>,
}

impl crate::storage::store::Store for Partition {
    fn namespace(&self) -> crate::failover::records::Namespace {
        self.store.namespace()
    }

    fn read(
        &mut self,
        key: &crate::storage::store::Key,
    ) -> Result<Option<crate::storage::store::Item>, crate::storage::store::Unavailable> {
        self.calls.set(self.calls.get() + 1);
        if self.down.get() {
            return Err(crate::storage::store::Unavailable);
        }
        self.store.read(key)
    }

    fn write(
        &mut self,
        key: &crate::storage::store::Key,
        write: &crate::storage::store::Write,
    ) -> crate::storage::store::Outcome {
        self.calls.set(self.calls.get() + 1);
        if self.down.get() {
            return crate::storage::store::Outcome::Unknown;
        }
        self.store.write(key, write)
    }
}

/// With the store double partitioned, an owner turn keeps serving: a hit returns the published bytes and a FILL
/// is acknowledged with its PUT RESULT while the double records no request, and an INVALIDATE's acknowledgment
/// waits until the partition heals and its page write commits.
#[test]
fn store_partition_hits_and_fills_continue() {
    use crate::storage::page_coverage::{Fencing, Progress};
    use crate::storage::store::sim::MemLog;
    use crate::storage::store_tests::{record_under, seeded_under};
    scene(&PRINCIPALS, |mut scene| {
        let partition = Partition {
            store: seeded_under(scene.owner.tenure()),
            down: Rc::new(std::cell::Cell::new(false)),
            calls: Rc::new(std::cell::Cell::new(0)),
        };
        let mut client =
            crate::storage::store::Client::open(partition.clone(), MemLog::default()).unwrap();
        let record = record_under(scene.owner.tenure());
        let mut fencing = Fencing::new(&record, scene.owner.tenure(), 4).unwrap();
        for at in 0..record.pages.get() {
            assert!(
                (0..8).any(|_| fencing.fence(&mut client, at) == Ok(Progress::Done)),
                "page {} fences",
                at
            );
        }
        scene.owner.install_coverage(fencing).unwrap();
        let object = payload(100, 7);
        let serial = ready_named(&mut scene, request(1, 1), 5, &object);
        assert_eq!(
            finish_named(&mut scene, request(1, 1), serial, 5, &object),
            None
        );
        partition.down.set(true);
        let calls = partition.calls.get();
        assert_eq!(scene.fetch(5), object, "the hit serves the published bytes");
        let serial = ready_named(&mut scene, request(0, 1), 6, &object);
        assert_eq!(
            finish_named(&mut scene, request(0, 1), serial, 6, &object),
            None,
            "the FILL is acknowledged"
        );
        assert_eq!(scene.fetch(6), object);
        assert_eq!(
            partition.calls.get(),
            calls,
            "no hit or FILL acknowledgment called the store"
        );
        let mut budget = WorkBudget::new(1 << 12);
        let mut acknowledged = Vec::new();
        scene
            .owner
            .invalidate_interval(&key(5), version_zero(), 4, &mut budget)
            .unwrap();
        for _ in 0..4 {
            scene
                .owner
                .cover_pending(&mut client, &mut acknowledged, 0)
                .unwrap();
        }
        assert!(
            acknowledged.is_empty(),
            "the INVALIDATE's acknowledgment waits for the store"
        );
        assert!(!scene.visible(5), "the INVALIDATE removed the key at once");
        partition.down.set(false);
        while acknowledged.is_empty() {
            scene
                .owner
                .cover_pending(&mut client, &mut acknowledged, 0)
                .unwrap();
        }
        assert_eq!(acknowledged, [(key(5), version_zero())]);
    });
}

/// The GET serving path, the PUT path and the storage's fill and lookup modules name no store module, store type,
/// store client or watermark log outside comments, and the owner
/// and the fencing hold no store client among their fields: the store reaches an INVALIDATE's page write only
/// through the client a caller lends `Owner::cover_pending`.
#[test]
fn serving_and_fill_paths_hold_no_store_client() {
    for (name, source) in [
        ("serve.rs", include_str!("serve.rs")),
        ("put.rs", include_str!("put.rs")),
        ("fill.rs", include_str!("../storage/fill.rs")),
        ("lookup.rs", include_str!("../storage/lookup.rs")),
    ] {
        let code: String = (source.lines())
            .map(|line| line.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        for token in [
            "store::",
            "store,",
            "store}",
            "Store",
            "Client<",
            "WatermarkLog",
        ] {
            let named = code.match_indices(token).any(|(at, _)| {
                !code[..at]
                    .chars()
                    .next_back()
                    .is_some_and(|before| before.is_alphanumeric() || before == '_')
            });
            assert!(!named, "{name} names `{token}`");
        }
    }
    for (name, source, opening) in [
        ("owner.rs", include_str!("owner.rs"), "pub struct Owner<"),
        (
            "coverage.rs",
            include_str!("../storage/cache/coverage.rs"),
            "pub struct Fencing {",
        ),
    ] {
        let at = source.find(opening).unwrap();
        let fields: String = (source[at..at + source[at..].find("\n}\n").unwrap()].lines())
            .map(|line| line.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !fields.contains("Client") && !fields.contains("Store"),
            "{name}'s fields hold a store client"
        );
    }
}

impl Scene<'_, '_> {
    /// The frames of `kind` the owner sent toward `peer`, taken off the link undelivered.
    fn sent_of(&mut self, peer: usize, kind: Kind) -> Vec<Header> {
        let crc = Crc32c::detect();
        let mut sent = Vec::new();
        self.nets[peer]
            .borrow_mut()
            .retain(0, |bytes| match parse(crc, bytes, false) {
                Ok(frame) if frame.header().kind == kind => {
                    sent.push(frame.header());
                    false
                }
                _ => true,
            });
        sent
    }
}

pub(super) fn versions(low: u64, high: u64) -> crate::storage::page_coverage::Interval {
    use crate::storage::CacheVersion;
    crate::storage::page_coverage::Interval::new(CacheVersion(low), CacheVersion(high)).unwrap()
}

/// Installs a fenced coverage over a fresh store and acknowledges INVALIDATE(`name`, `[low, high]`) on it.
fn covering(
    scene: &mut Scene<'_, '_>,
    name: u8,
    (low, high): (u64, u64),
) -> (
    crate::storage::store::sim::Shared,
    crate::storage::store::Client<
        crate::storage::store::sim::Shared,
        crate::storage::store::sim::MemLog,
    >,
) {
    let store = crate::storage::store_tests::seeded_under(scene.owner.tenure());
    let (fencing, mut client) = fenced_coverage(&store, scene.owner.tenure());
    scene.owner.install_coverage(fencing).unwrap();
    let mut budget = WorkBudget::new(1 << 12);
    scene
        .owner
        .invalidate_interval(&key(name), versions(low, high), 4, &mut budget)
        .unwrap();
    let mut acknowledged = Vec::new();
    scene
        .owner
        .cover_pending(&mut client, &mut acknowledged, 0)
        .unwrap();
    assert_eq!(acknowledged, [(key(name), versions(low, high))]);
    (store, client)
}

/// Under INVALIDATE(k, [5, 9]), whose interval excludes version 0: a BEGIN at version 0, which is judged by its key,
/// is refused for k and admitted for a key the coverage leaves untouched; a BEGIN of k is refused at version 6 and
/// admitted, published and served at version 4; and a version 0 FILL of a key covered after its payload write is
/// refused at the insert.
#[test]
fn version_zero_and_named_version_fills_meet_coverage() {
    scene(&PRINCIPALS, |mut scene| {
        let _store = covering(&mut scene, 5, (5, 9));
        let zero = scene.frame(1, Kind::PutBegin, request(0, 1), 5, |header| {
            header.remaining_ms = 10_000
        });
        assert_eq!(error(&scene.one(1, &zero)), Some(Status::Contended));
        let object = payload(100, 9);
        let serial = ready_named(&mut scene, request(2, 1), 8, &object);
        scene
            .owner
            .coverage_mut()
            .unwrap()
            .hold((key(8), versions(5, 9)));
        let outcome = finish_named(&mut scene, request(2, 1), serial, 8, &object);
        assert_eq!(
            (outcome, scene.visible(8)),
            (Some(Status::Contended), false)
        );
    });
    scene(&PRINCIPALS, |mut scene| {
        let _store = covering(&mut scene, 5, (5, 9));
        let six = scene.frame(1, Kind::PutBegin, request(0, 2), 5, |header| {
            header.remaining_ms = 10_000;
            header.offset = 6;
        });
        let refused = scene.send(1, &six);
        assert_eq!(
            refused.iter().map(error).collect::<Vec<_>>(),
            [Some(Status::Contended)]
        );
        let four = scene.frame(1, Kind::PutBegin, request(1, 1), 5, |header| {
            header.remaining_ms = 10_000;
            header.offset = 4;
        });
        let authority = scene.send(1, &four);
        assert_eq!(
            authority.iter().map(|reply| reply.kind).collect::<Vec<_>>(),
            [Kind::PutAuthority]
        );
        let object = payload(100, 9);
        let serial = authority[0].allocation;
        let prepared = scene.frame(
            1,
            Kind::PutPrepare,
            request(1, 1),
            5,
            prepare(serial, 100, 60_000),
        );
        assert_eq!(scene.one(1, &prepared).kind, Kind::PutReady);
        assert_eq!(
            finish_named(&mut scene, request(1, 1), serial, 5, &object),
            None
        );
        assert_eq!(
            scene.fetch(5),
            object,
            "version 4 of the covered key serves"
        );
        let mut reader = scene.storage.register().unwrap();
        let lease = reader
            .lookup(&key(5), 4, &mut WorkBudget::new(1 << 16))
            .unwrap();
        let mut facts = Vec::new();
        scene.storage.slot_facts_into(&mut facts).unwrap();
        assert_eq!(
            facts[lease.id().slot_index()].version,
            4,
            "the stored version is the BEGIN's"
        );
        drop(lease);
        drop(reader);
        let begin = scene.frame(1, Kind::PutBegin, request(3, 1), 9, |header| {
            header.remaining_ms = 10_000;
            header.offset = 4;
        });
        let authority = scene.one(1, &begin);
        assert_eq!(authority.kind, Kind::PutAuthority);
        let prepared = scene.frame(
            1,
            Kind::PutPrepare,
            request(3, 1),
            9,
            prepare(authority.allocation, 100, 60_000),
        );
        assert_eq!(scene.one(1, &prepared).kind, Kind::PutReady);
        (scene.owner.coverage_mut().unwrap()).hold((key(9), versions(3, 5)));
        let outcome = finish_named(&mut scene, request(3, 1), authority.allocation, 9, &object);
        assert_eq!(
            (outcome, scene.visible(9)),
            (Some(Status::Contended), false),
            "a versioned FILL covered after its payload write is refused at the insert"
        );
    });
}

/// The PUT's fingerprint includes its version, so a BEGIN resent under the same request with a different version,
/// version 0 included, is refused as a conflicting request both while the PUT is live and from its retained outcome.
/// A BEGIN matching a current retained PUT outcome's fingerprint replays that outcome.
#[test]
fn a_put_begin_resent_with_another_version_conflicts() {
    scene(&PRINCIPALS, |mut scene| {
        let at = request(1, 1);
        let begin = |scene: &mut Scene<'_, '_>, version: u64| {
            scene.frame(1, Kind::PutBegin, at, 5, |header| {
                header.remaining_ms = 10_000;
                header.offset = version;
            })
        };
        let first = begin(&mut scene, 6);
        let serial = scene.send(1, &first)[0].allocation;
        for other in [7, 0] {
            let resent = begin(&mut scene, other);
            let replies = scene.send(1, &resent);
            assert_eq!(
                replies.iter().map(error).collect::<Vec<_>>(),
                [Some(Status::ConflictingRequest)],
                "version {other}"
            );
        }
        let same = begin(&mut scene, 6);
        assert_eq!(scene.send(1, &same)[0].kind, Kind::PutAuthority);
        let prepared = scene.frame(1, Kind::PutPrepare, at, 5, prepare(serial, 100, 60_000));
        assert_eq!(scene.one(1, &prepared).kind, Kind::PutReady);
        assert_eq!(
            finish_named(&mut scene, at, serial, 5, &payload(100, 4)),
            None
        );
        let changed = begin(&mut scene, 7);
        assert_eq!(
            scene
                .send(1, &changed)
                .iter()
                .map(error)
                .collect::<Vec<_>>(),
            [Some(Status::ConflictingRequest)],
            "the retained outcome refuses another version"
        );
        let repeated = begin(&mut scene, 6);
        assert_eq!(scene.send(1, &repeated)[0].kind, Kind::PutResult);
        let mut reader = scene.storage.register().unwrap();
        let lease = reader
            .lookup(&key(5), 4, &mut WorkBudget::new(1 << 16))
            .unwrap();
        let mut facts = Vec::new();
        scene.storage.slot_facts_into(&mut facts).unwrap();
        assert_eq!(facts[lease.id().slot_index()].version, 6);
    });
}

/// Held INVALIDATEs on two pages, interleaved: each page takes one write for its entries, and an entry is
/// acknowledged only by its own page's acknowledged write, so a timed-out page write acknowledges nothing until
/// the next call commits it. Over the wire, a resend of a pending INVALIDATE is held once and answered by one
/// INVALIDATED, and a timed-out page's entries receive INVALIDATED only after the page write commits.
#[test]
fn held_invalidates_commit_per_page() {
    use crate::storage::page_coverage::{decode_entries, page_of};
    use crate::storage::store::Key;
    use crate::storage::store::sim::Arm;
    use crate::storage::store_tests::{page, record, shard};
    scene(&PRINCIPALS, |mut scene| {
        let store = crate::storage::store_tests::seeded_under(scene.owner.tenure());
        let (fencing, mut client) = fenced_coverage(&store, scene.owner.tenure());
        scene.owner.install_coverage(fencing).unwrap();
        let pages = record().pages;
        let on = |at: u16| (1..=u8::MAX).filter(move |&n| page_of(&key(n), pages) == at);
        let (zero, one): (Vec<u8>, Vec<u8>) = (on(0).take(2).collect(), on(1).take(1).collect());
        let mut budget = WorkBudget::new(1 << 12);
        for n in [zero[0], one[0], zero[1]] {
            scene
                .owner
                .invalidate_interval(&key(n), versions(1, 2), 4, &mut budget)
                .unwrap();
        }
        let commits = |at: u16| store.0.borrow().commit_count(&Key::Page(shard(), at));
        let before = (commits(0), commits(1));
        store.schedule(Arm::Pass);
        store.schedule(Arm::Timeout { commit: false });
        let mut acknowledged = Vec::new();
        scene
            .owner
            .cover_pending(&mut client, &mut acknowledged, 0)
            .unwrap();
        acknowledged.sort_unstable();
        let mut first = vec![
            (key(zero[0]), versions(1, 2)),
            (key(zero[1]), versions(1, 2)),
        ];
        first.sort_unstable();
        assert_eq!(
            acknowledged, first,
            "page 0's write acknowledges page 0's entries"
        );
        assert_eq!((commits(0), commits(1)), (before.0 + 1, before.1));
        scene
            .owner
            .cover_pending(&mut client, &mut acknowledged, 0)
            .unwrap();
        assert_eq!(acknowledged[2..], [(key(one[0]), versions(1, 2))]);
        assert_eq!(commits(1), before.1 + 1);
        acknowledged.clear();
        let wire = |scene: &mut Scene<'_, '_>, at: u64, n: u8, version: u64| {
            let header = scene.frame(1, Kind::Invalidate, at, n, |header| {
                header.allocation = version;
                header.offset = version;
            });
            scene.inject(1, &header);
        };
        wire(&mut scene, request(1, 1), zero[0], 4);
        wire(&mut scene, request(1, 1), zero[0], 4);
        wire(&mut scene, request(2, 1), one[0], 6);
        scene.turns(4);
        store.schedule(Arm::Pass);
        store.schedule(Arm::Timeout { commit: false });
        scene
            .owner
            .cover_pending(&mut client, &mut acknowledged, 0)
            .unwrap();
        assert_eq!(
            acknowledged,
            [(key(zero[0]), versions(4, 4))],
            "the resend is held once"
        );
        assert_eq!(commits(0), before.0 + 2);
        scene.turns(4);
        let sent = scene.sent_of(1, Kind::Invalidated);
        let answered: Vec<_> = sent
            .iter()
            .map(|reply| (reply.request, reply.key))
            .collect();
        assert_eq!(
            answered,
            [(request(1, 1), key(zero[0]))],
            "page 1's write timed out"
        );
        scene
            .owner
            .cover_pending(&mut client, &mut acknowledged, 0)
            .unwrap();
        scene.turns(4);
        let sent = scene.sent_of(1, Kind::Invalidated);
        let answered: Vec<_> = sent
            .iter()
            .map(|reply| (reply.request, reply.key))
            .collect();
        assert_eq!(answered, [(request(2, 1), key(one[0]))]);
        let held = decode_entries(&page(&store, 0).entries).unwrap();
        assert_eq!(
            held.iter()
                .filter(|entry| **entry == (key(zero[0]), versions(4, 4)))
                .count(),
            1
        );
    });
}

/// An owner holds at most `INVALIDATIONS` INVALIDATEs. At capacity, the owner returns `Contended` and preserves
/// coverage. Resending a held pair returns `Ok(None)`, with the removal run only for the first. A newer fence drops
/// every held INVALIDATE unacknowledged and withdraws serving authority. An unfenced owner refuses INVALIDATE
/// `Withdrawn`.
#[test]
fn held_invalidates_cap_and_clear_on_withdrawal() {
    use crate::storage::CacheVersion;
    use crate::storage::page_coverage::{Fencing, Progress, Withdraw};
    use crate::storage::store_tests::client;
    scene(&PRINCIPALS, |mut scene| {
        let mut budget = WorkBudget::new(1 << 12);
        assert_eq!(
            scene
                .owner
                .invalidate_interval(&key(1), versions(1, 1), 4, &mut budget)
                .err(),
            Some(crate::storage::InvalidateError::Withdrawn)
        );
        let store = crate::storage::store_tests::seeded_under(scene.owner.tenure());
        let (fencing, mut tenure) = fenced_coverage(&store, scene.owner.tenure());
        scene.owner.install_coverage(fencing).unwrap();
        for n in 0..super::owner::INVALIDATIONS as u8 {
            scene
                .owner
                .invalidate_interval(&key(n), versions(1, 1), 4, &mut budget)
                .unwrap();
        }
        let over = scene
            .owner
            .invalidate_interval(&key(200), versions(3, 3), 4, &mut budget);
        assert_eq!(over.err(), Some(crate::storage::InvalidateError::Contended));
        assert_eq!(
            scene
                .owner
                .invalidate_interval(&key(0), versions(1, 1), 4, &mut budget),
            Ok(None),
            "a resend of a held pair runs no removal"
        );
        let held = scene.owner.coverage_mut().unwrap();
        assert!(
            held.admits(&key(200), CacheVersion(3)),
            "the refused INVALIDATE leaves the coverage as it was"
        );
        let next = crate::storage::next_session();
        let record = crate::storage::store_tests::record_under(&next);
        let mut successor = Fencing::new(&record, &next, 4).unwrap();
        let mut other = client(&store);
        for at in 0..record.pages.get() {
            assert!(
                (0..8).any(|_| successor.fence(&mut other, at) == Ok(Progress::Done)),
                "page {} fences",
                at
            );
        }
        let mut acknowledged = Vec::new();
        let withdrawn = scene.owner.cover_pending(&mut tenure, &mut acknowledged, 0);
        assert!(
            matches!(withdrawn, Err(Withdraw::NewerFence { .. })),
            "{withdrawn:?}"
        );
        assert!(
            matches!(
                scene.owner.authority_report().withdrawal,
                Some(crate::failover::serving::Cause::NewerFence { .. })
            ),
            "{:?}",
            scene.owner.authority_report()
        );
        assert!(acknowledged.is_empty());
        assert_eq!(
            scene.owner.cover_pending(&mut tenure, &mut acknowledged, 0),
            Ok(()),
            "the queue is empty"
        );
        assert!(acknowledged.is_empty());
    });
}

/// A client PUT sends a BEGIN naming its cache version in the offset field, version 0 as well as a nonzero version.
#[test]
fn a_client_put_names_its_version_in_its_begin() {
    for version in [0, 4] {
        scene(&PRINCIPALS, |mut scene| {
            let now = scene.turn * 100;
            scene.clients[0]
                .put(
                    key(6),
                    crate::storage::CacheVersion(version),
                    now,
                    30_000_000,
                )
                .unwrap();
            scene.clients[0].poll(now);
            let bytes = scene.nets[0]
                .borrow()
                .peek(1)
                .expect("the BEGIN toward the owner");
            let sent = parse(Crc32c::detect(), &bytes, false).unwrap().header();
            assert_eq!((sent.kind, sent.offset), (Kind::PutBegin, version));
        });
    }
}

#[test]
fn invalidate_needs_the_put_grant_and_an_open_owner() {
    use crate::storage::CacheVersion;
    scene(&PRINCIPALS[1..], |mut scene| {
        let store = crate::storage::store_tests::seeded_under(scene.owner.tenure());
        let (fencing, mut client) = fenced_coverage(&store, scene.owner.tenure());
        scene.owner.install_coverage(fencing).unwrap();
        let object = payload(100, 2);
        let serial = ready_named(&mut scene, request(1, 1), 5, &object);
        assert_eq!(
            finish_named(&mut scene, request(1, 1), serial, 5, &object),
            None
        );
        let denied = scene.frame(0, Kind::Invalidate, request(2, 1), 5, |header| {
            header.allocation = 0;
            header.offset = 0;
        });
        scene.inject(0, &denied);
        scene.turns(4);
        let mut acknowledged = Vec::new();
        scene
            .owner
            .cover_pending(&mut client, &mut acknowledged, 0)
            .unwrap();
        assert!(
            acknowledged.is_empty() && scene.visible(5),
            "a peer outside the PUT grant removes nothing"
        );
        assert!(
            (scene.owner.coverage_mut().unwrap()).admits(&key(5), CacheVersion(0)),
            "and adds no coverage"
        );
        let granted = scene.frame(1, Kind::Invalidate, request(3, 1), 5, |header| {
            header.allocation = 0;
            header.offset = 0;
        });
        scene.inject(1, &granted);
        scene.turns(4);
        assert!(
            !scene.visible(5),
            "a granted peer's INVALIDATE removes the key"
        );
        scene.owner.close(scene.turn * 100);
        scene
            .owner
            .cover_pending(&mut client, &mut acknowledged, 0)
            .unwrap();
        assert!(
            acknowledged.is_empty(),
            "a closed owner acknowledges no held INVALIDATE"
        );
        assert_eq!(
            (scene.owner)
                .invalidate_interval(&key(6), versions(0, 0), 4, &mut WorkBudget::new(1 << 12))
                .err(),
            Some(crate::storage::InvalidateError::Closed),
            "a closed owner refuses a local INVALIDATE"
        );
    });
}

#[test]
fn a_failed_removal_holds_nothing() {
    use crate::storage::CacheVersion;
    scene(&PRINCIPALS, |mut scene| {
        let store = crate::storage::store_tests::seeded_under(scene.owner.tenure());
        let (fencing, mut client) = fenced_coverage(&store, scene.owner.tenure());
        scene.owner.install_coverage(fencing).unwrap();
        let object = payload(100, 2);
        let serial = ready_named(&mut scene, request(1, 1), 5, &object);
        assert_eq!(
            finish_named(&mut scene, request(1, 1), serial, 5, &object),
            None
        );
        let refused =
            (scene.owner).invalidate_interval(&key(5), versions(3, 5), 4, &mut WorkBudget::new(0));
        assert_eq!(
            refused.err(),
            Some(crate::storage::InvalidateError::BudgetExhausted)
        );
        assert!(scene.visible(5), "the removal did not run");
        assert!(
            (scene.owner.coverage_mut().unwrap()).admits(&key(5), CacheVersion(4)),
            "the refused INVALIDATE adds no coverage"
        );
        let mut acknowledged = Vec::new();
        scene
            .owner
            .cover_pending(&mut client, &mut acknowledged, 0)
            .unwrap();
        assert!(acknowledged.is_empty(), "nothing was queued");
        assert!(
            (scene.owner)
                .invalidate_interval(&key(5), versions(3, 5), 4, &mut WorkBudget::new(1 << 12))
                .unwrap()
                .is_some()
        );
        scene
            .owner
            .cover_pending(&mut client, &mut acknowledged, 0)
            .unwrap();
        assert_eq!(acknowledged, [(key(5), versions(3, 5))]);
    });
}

#[test]
fn a_withdrawn_owner_writes_and_acknowledges_no_held_invalidate() {
    use crate::failover::serving::{Cause, Event};
    use crate::storage::page_coverage::page_of;
    use crate::storage::store::Key;
    use crate::storage::store_tests::{record, shard};
    for event in [Event::Withdraw(Cause::Planned), Event::Close] {
        scene(&PRINCIPALS, |mut scene| {
            let store = crate::storage::store_tests::seeded_under(scene.owner.tenure());
            let (fencing, mut client) = fenced_coverage(&store, scene.owner.tenure());
            scene.owner.install_coverage(fencing).unwrap();
            (scene.owner)
                .invalidate_interval(&key(5), versions(3, 5), 4, &mut WorkBudget::new(1 << 12))
                .unwrap();
            let page = Key::Page(shard(), page_of(&key(5), record().pages));
            let before = store.0.borrow().commit_count(&page);
            (scene.owner).authority_event(event, scene.turn * 100);
            let mut acknowledged = Vec::new();
            scene
                .owner
                .cover_pending(&mut client, &mut acknowledged, 0)
                .unwrap();
            assert_eq!(acknowledged, [], "{event:?}");
            assert_eq!(store.0.borrow().commit_count(&page), before, "{event:?}");
        });
    }
}

#[test]
fn a_withdrawn_or_closed_authority_refuses_invalidates() {
    use crate::failover::serving::{Cause, Event};
    for event in [Event::Withdraw(Cause::Planned), Event::Close] {
        scene(&PRINCIPALS, |mut scene| {
            let store = crate::storage::store_tests::seeded_under(scene.owner.tenure());
            let (fencing, _) = fenced_coverage(&store, scene.owner.tenure());
            scene.owner.install_coverage(fencing).unwrap();
            let mut budget = WorkBudget::new(1 << 12);
            (scene.owner)
                .invalidate_interval(&key(5), versions(3, 5), 4, &mut budget)
                .unwrap();
            (scene.owner).authority_event(event, scene.turn * 100);
            assert_eq!(
                (scene.owner)
                    .invalidate_interval(&key(5), versions(3, 5), 4, &mut budget)
                    .err(),
                Some(crate::storage::InvalidateError::Withdrawn),
                "{event:?}: a held entry"
            );
            assert_eq!(
                (scene.owner)
                    .invalidate_interval(&key(6), versions(1, 1), 4, &mut budget)
                    .err(),
                Some(crate::storage::InvalidateError::Withdrawn),
                "{event:?}: a new entry"
            );
        });
    }
}

#[test]
fn a_local_invalidate_joins_a_wire_held_entry_at_capacity() {
    scene(&PRINCIPALS, |mut scene| {
        let store = crate::storage::store_tests::seeded_under(scene.owner.tenure());
        let (fencing, mut client) = fenced_coverage(&store, scene.owner.tenure());
        scene.owner.install_coverage(fencing).unwrap();
        let mut budget = WorkBudget::new(1 << 12);
        for n in 1..super::owner::INVALIDATIONS as u8 {
            (scene.owner)
                .invalidate_interval(&key(n), versions(1, 1), 4, &mut budget)
                .unwrap();
        }
        let wire = scene.frame(1, Kind::Invalidate, request(1, 1), 100, |header| {
            header.allocation = 3;
            header.offset = 5;
        });
        scene.inject(1, &wire);
        scene.turns(4);
        assert_eq!(
            (scene.owner).invalidate_interval(&key(100), versions(3, 5), 4, &mut budget),
            Ok(None),
            "the local INVALIDATE joins the held wire entry"
        );
        let mut acknowledged = Vec::new();
        scene
            .owner
            .cover_pending(&mut client, &mut acknowledged, 0)
            .unwrap();
        assert_eq!(
            acknowledged
                .iter()
                .filter(|entry| **entry == (key(100), versions(3, 5)))
                .count(),
            1
        );
        scene.turns(4);
        assert_eq!(scene.sent_of(1, Kind::Invalidated).len(), 1);
    });
}

#[test]
fn invalidates_of_one_entry_from_two_peers_acknowledge_it_once() {
    scene(&PRINCIPALS, |mut scene| {
        let store = crate::storage::store_tests::seeded_under(scene.owner.tenure());
        let (fencing, mut client) = fenced_coverage(&store, scene.owner.tenure());
        scene.owner.install_coverage(fencing).unwrap();
        for peer in [0, 1] {
            let frame = scene.frame(peer, Kind::Invalidate, request(1, 1), 5, |header| {
                header.allocation = 3;
                header.offset = 5;
            });
            scene.inject(peer, &frame);
        }
        scene.turns(4);
        let mut acknowledged = Vec::new();
        scene
            .owner
            .cover_pending(&mut client, &mut acknowledged, 0)
            .unwrap();
        assert_eq!(acknowledged, [(key(5), versions(3, 5))]);
        scene.turns(4);
        assert_eq!(scene.sent_of(0, Kind::Invalidated).len(), 1);
        assert_eq!(scene.sent_of(1, Kind::Invalidated).len(), 1);
        (scene.owner)
            .invalidate_interval(&key(5), versions(3, 5), 4, &mut WorkBudget::new(1 << 12))
            .unwrap();
        scene
            .owner
            .cover_pending(&mut client, &mut acknowledged, 0)
            .unwrap();
        assert_eq!(
            acknowledged,
            [(key(5), versions(3, 5)), (key(5), versions(3, 5))],
            "a later acknowledgment of the entry is appended"
        );
    });
}

/// One page write acknowledges every entry it carried once, in the order the entries were held, and leaves the
/// other page's entries held: 58 entries of page 0 held around two of page 1, one of them also held by two peers,
/// are acknowledged by page 0's write, and the next call acknowledges page 1's two. The 58 keys include pairs that
/// share a class of the filter the owner tests an entry against before it searches the entries it acknowledged.
#[test]
fn a_page_write_acknowledges_each_carried_entry_once_in_held_order() {
    use crate::storage::page_coverage::page_of;
    use crate::storage::store::sim::Arm;
    use crate::storage::store_tests::record;
    scene(&PRINCIPALS, |mut scene| {
        let store = crate::storage::store_tests::seeded_under(scene.owner.tenure());
        let (fencing, mut client) = fenced_coverage(&store, scene.owner.tenure());
        scene.owner.install_coverage(fencing).unwrap();
        let pages = record().pages;
        let on = |at: u16| (1..=u8::MAX).filter(move |&n| page_of(&key(n), pages) == at);
        let fours = on(0).filter(|n| n % 4 == 0);
        let (zero, one): (Vec<u8>, Vec<u8>) = (fours.take(58).collect(), on(1).take(2).collect());
        for peer in [0, 1] {
            let frame = scene.frame(peer, Kind::Invalidate, request(1, 1), zero[7], |header| {
                header.allocation = 3;
                header.offset = 5;
            });
            scene.inject(peer, &frame);
        }
        scene.turns(4);
        let shared = (key(zero[7]), versions(3, 5));
        let mut budget = WorkBudget::new(1 << 14);
        let mut held = vec![shared];
        let order = (zero[..29].iter())
            .chain(&one)
            .chain(&zero[29..])
            .filter(|&&n| n != zero[7]);
        for &n in order {
            let entry = (key(n), versions(1, 2));
            (scene.owner)
                .invalidate_interval(&entry.0, entry.1, 4, &mut budget)
                .unwrap();
            held.push(entry);
        }
        assert_eq!(scene.owner.held_invalidations(), 61);
        let on_one = |entry: &crate::storage::page_coverage::Entry| page_of(&entry.0, pages) == 1;
        let first: Vec<_> = held
            .iter()
            .filter(|entry| !on_one(entry))
            .copied()
            .collect();
        let second: Vec<_> = held.iter().filter(|entry| on_one(entry)).copied().collect();
        store.schedule(Arm::Pass);
        store.schedule(Arm::Timeout { commit: false });
        let mut acknowledged = Vec::new();
        scene
            .owner
            .cover_pending(&mut client, &mut acknowledged, 0)
            .unwrap();
        assert_eq!(acknowledged, first, "page 0's entries, once each, as held");
        assert_eq!(scene.owner.held_invalidations(), 2);
        scene.turns(4);
        assert_eq!(scene.sent_of(0, Kind::Invalidated).len(), 1);
        assert_eq!(scene.sent_of(1, Kind::Invalidated).len(), 1);
        acknowledged.clear();
        scene
            .owner
            .cover_pending(&mut client, &mut acknowledged, 0)
            .unwrap();
        assert_eq!(acknowledged, second);
        assert_eq!(scene.owner.held_invalidations(), 0);
    });
}

/// A session that holds an entry while the page write carrying that entry is in flight is acknowledged by that
/// write's commit: the entry is acknowledged once, no entry stays held, and each session receives its INVALIDATED.
#[test]
fn a_session_that_holds_a_carried_entry_in_flight_is_acknowledged_by_its_write() {
    use crate::storage::page_coverage::Cover;
    scene(&PRINCIPALS, |mut scene| {
        let store = crate::storage::store_tests::seeded_under(scene.owner.tenure());
        let (fencing, mut client) = fenced_coverage(&store, scene.owner.tenure());
        scene.owner.install_coverage(fencing).unwrap();
        let invalidate = |scene: &mut Scene<'_, '_>, peer: usize| {
            let frame = scene.frame(peer, Kind::Invalidate, request(1, 1), 5, |header| {
                header.allocation = 3;
                header.offset = 5;
            });
            scene.inject(peer, &frame);
            scene.turns(4);
        };
        invalidate(&mut scene, 0);
        let request = scene.owner.cover_begin(None, 0).unwrap().expect("a write");
        invalidate(&mut scene, 1);
        assert_eq!(scene.owner.held_invalidations(), 2);
        let mut acknowledged = Vec::new();
        let ended = (scene.owner).cover_end(request.run(&mut client), &mut acknowledged, 0);
        assert!(matches!(ended, Ok(Cover::Done)), "{ended:?}");
        assert_eq!(acknowledged, [(key(5), versions(3, 5))]);
        assert_eq!(scene.owner.held_invalidations(), 0);
        scene.turns(4);
        assert_eq!(scene.sent_of(0, Kind::Invalidated).len(), 1);
        assert_eq!(scene.sent_of(1, Kind::Invalidated).len(), 1);
    });
}

#[test]
fn an_invalidated_dropped_by_a_full_reply_ring_is_recovered_by_a_resend() {
    use crate::storage::page_coverage::page_of;
    use crate::storage::store_tests::record;
    let config = OwnerConfig {
        serve: ServeConfig {
            replies: 1,
            ..OWNER.serve
        },
        ..OWNER
    };
    scene_with(config, &PRINCIPALS, |mut scene| {
        let store = crate::storage::store_tests::seeded_under(scene.owner.tenure());
        let (fencing, mut client) = fenced_coverage(&store, scene.owner.tenure());
        scene.owner.install_coverage(fencing).unwrap();
        let pages = record().pages;
        let mut same = (1..=u8::MAX).filter(|&n| page_of(&key(n), pages) == 0);
        let (a, b) = (same.next().unwrap(), same.next().unwrap());
        let interval = |header: &mut Header| {
            header.allocation = 3;
            header.offset = 5;
        };
        for (n, name) in [(1, a), (2, b)] {
            let frame = scene.frame(1, Kind::Invalidate, request(n, 1), name, interval);
            scene.inject(1, &frame);
        }
        scene.turns(4);
        let mut acknowledged = Vec::new();
        scene
            .owner
            .cover_pending(&mut client, &mut acknowledged, 0)
            .unwrap();
        assert_eq!(acknowledged.len(), 2, "one page write covers both");
        scene.turns(4);
        let sent = scene.sent_of(1, Kind::Invalidated);
        assert_eq!(sent.len(), 1, "a ring of one carries one INVALIDATED");
        assert_eq!(scene.owner.serve_report().dropped_replies, 1);
        let dropped = if sent[0].key == key(a) { b } else { a };
        let resend = scene.frame(1, Kind::Invalidate, request(3, 1), dropped, interval);
        scene.inject(1, &resend);
        scene.turns(4);
        scene
            .owner
            .cover_pending(&mut client, &mut acknowledged, 0)
            .unwrap();
        scene.turns(4);
        let sent = scene.sent_of(1, Kind::Invalidated);
        assert_eq!(
            sent.iter()
                .map(|header| (header.request, header.key))
                .collect::<Vec<_>>(),
            [(request(3, 1), key(dropped))],
            "the resend is acknowledged under its own request"
        );
    });
}

#[test]
fn a_second_fencing_install_is_refused() {
    use crate::storage::CacheVersion;
    scene(&PRINCIPALS, |mut scene| {
        let store = crate::storage::store_tests::seeded_under(scene.owner.tenure());
        let (fencing, mut client) = fenced_coverage(&store, scene.owner.tenure());
        scene.owner.install_coverage(fencing).unwrap();
        (scene.owner)
            .invalidate_interval(&key(5), versions(3, 5), 4, &mut WorkBudget::new(1 << 12))
            .unwrap();
        let mut acknowledged = Vec::new();
        scene
            .owner
            .cover_pending(&mut client, &mut acknowledged, 0)
            .unwrap();
        assert_eq!(acknowledged, [(key(5), versions(3, 5))]);
        let (spare, _) = fenced_coverage(&store, scene.owner.tenure());
        assert!(
            scene.owner.install_coverage(spare).is_err(),
            "a second install is refused"
        );
        assert!(
            !(scene.owner.coverage_mut().unwrap()).admits(&key(5), CacheVersion(4)),
            "the acknowledged interval stays covered"
        );
    });
}

#[test]
fn an_unfenced_fencing_is_refused() {
    scene(&PRINCIPALS, |mut scene| {
        let tenure = scene.owner.tenure();
        let unfenced = crate::storage::page_coverage::Fencing::new(
            &crate::storage::store_tests::record_under(tenure),
            tenure,
            4,
        )
        .unwrap();
        assert!(unfenced.coverage().is_none());
        assert!(
            scene.owner.install_coverage(unfenced).is_err(),
            "a fencing with an unfenced page is refused"
        );
    });
}

/// `Owner::install_coverage` rejects a fencing after this owner published a wire PUT and leaves the owner unfenced, because the coverage could include a version already resident and served.
#[test]
fn an_install_after_a_published_put_is_refused() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(100, 2);
        let serial = ready_named(&mut scene, request(1, 1), 5, &object);
        assert_eq!(
            finish_named(&mut scene, request(1, 1), serial, 5, &object),
            None
        );
        assert!(scene.visible(5));
        let store = crate::storage::store_tests::seeded_under(scene.owner.tenure());
        let (fencing, _) = fenced_coverage(&store, scene.owner.tenure());
        assert!(
            scene.owner.install_coverage(fencing).is_err(),
            "an install after a published PUT is refused"
        );
        assert!(scene.owner.coverage_mut().is_none());
    });
}

#[test]
fn a_fencing_of_another_tenure_is_refused() {
    use crate::storage::page_coverage::{Fencing, Progress};
    use crate::storage::store_tests::{client, record_under, seeded_under};
    scene(&PRINCIPALS, |mut scene| {
        let other = crate::storage::next_session();
        assert_ne!(other.get(), scene.owner.tenure().get());
        let store = seeded_under(&other);
        let mut client = client(&store);
        let record = record_under(&other);
        let mut fencing = Fencing::new(&record, &other, 4).unwrap();
        for at in 0..record.pages.get() {
            assert!((0..8).any(|_| fencing.fence(&mut client, at) == Ok(Progress::Done)));
        }
        assert!(fencing.coverage().is_some(), "the fencing is complete");
        assert!(
            scene.owner.install_coverage(fencing).is_err(),
            "a fencing of another session of the shard is refused"
        );
        assert!(scene.owner.coverage_mut().is_none());
    });
}

#[test]
fn a_fencing_of_another_shard_is_refused() {
    use crate::net::ownership::Shard;
    use crate::storage::Session;
    use crate::storage::page_coverage::{Fencing, Progress};
    use crate::storage::store_tests::{client, record};
    scene(&PRINCIPALS, |mut scene| {
        let tenure = scene.owner.tenure();
        let other = crate::failover::records::ShardRecord {
            shard: Shard::new(8).unwrap(),
            generation: tenure.generation(),
            attempts: tenure.target().attempts - 1,
            ..record()
        };
        let store = crate::storage::store::sim::Shared::new();
        let mut client = client(&store);
        let read = client.create_shard(other).unwrap();
        let session = Session::activate(client.bump(&read).unwrap()).unwrap();
        assert_eq!(session.get(), tenure.get(), "only the shard differs");
        let mut fencing = Fencing::new(&other, &session, 4).unwrap();
        for at in 0..other.pages.get() {
            assert!((0..8).any(|_| fencing.fence(&mut client, at) == Ok(Progress::Done)));
        }
        assert!(fencing.coverage().is_some(), "the fencing is complete");
        assert!(
            scene.owner.install_coverage(fencing).is_err(),
            "a fencing of shard 8 is refused by a shard 7 owner"
        );
        assert!(scene.owner.coverage_mut().is_none());
    });
}

/// `Owner::install_coverage` rejects a fencing after this owner published a local fill and leaves the owner unfenced, because the coverage could include a version already resident and served.
#[test]
fn an_install_after_a_published_local_fill_is_refused() {
    scene(&PRINCIPALS, |mut scene| {
        let body = payload(100, 6);
        let mut fill = crate::storage::owner_fixture::reserve_at(
            scene.storage,
            &key(5),
            crate::storage::CacheVersion(4),
            0,
            body.len(),
        )
        .unwrap();
        let mut taken = 0;
        while !scene.owner.fill_progress(&fill).is_ready() {
            if taken < body.len() {
                let mut budget = WorkBudget::with_io(0, usize::MAX, usize::MAX);
                taken += scene
                    .owner
                    .receive_fill(&mut fill, &body[taken..], &mut budget)
                    .unwrap_or(0);
            }
            scene.turns(1);
            assert!(scene.turn < 10_000, "the fill finished its writes");
        }
        drop(
            (scene.owner)
                .publish_fill(fill, u64::MAX, 2, &mut WorkBudget::new(1024))
                .unwrap(),
        );
        assert!(scene.visible(5));
        let store = crate::storage::store_tests::seeded_under(scene.owner.tenure());
        let (fencing, _) = fenced_coverage(&store, scene.owner.tenure());
        assert!(
            scene.owner.install_coverage(fencing).is_err(),
            "an install after a published local fill is refused"
        );
        assert!(scene.owner.coverage_mut().is_none());
    });
}

/// The repository client sends an INVALIDATE of k and the owner takes it, removing k at
/// once; the owner sends one INVALIDATED only after the page write that covers the interval is acknowledged, and
/// the client records it. An INVALIDATE whose interval is inverted refuses at parse and changes nothing, and the client
/// refuses to send one. Both clients' sessions activate through their handshakes; client 0 sends, since
/// the test injects client 1's other frames under its own sequence.
#[test]
fn invalidate_frames_reach_the_owner_and_invalidated_reaches_the_client() {
    scene(&PRINCIPALS, |mut scene| {
        let store = crate::storage::store_tests::seeded_under(scene.owner.tenure());
        let (fencing, mut client) = fenced_coverage(&store, scene.owner.tenure());
        scene.owner.install_coverage(fencing).unwrap();
        let object = payload(100, 2);
        let serial = ready_named(&mut scene, request(1, 1), 5, &object);
        assert_eq!(
            finish_named(&mut scene, request(1, 1), serial, 5, &object),
            None
        );
        let inverted = scene.frame(1, Kind::Invalidate, request(2, 1), 5, |header| {
            header.allocation = 0
        });
        scene.inject_edited(1, &inverted, &[], |bytes| {
            bytes[72..80].copy_from_slice(&3u64.to_be_bytes());
            bytes[104..112].copy_from_slice(&2u64.to_be_bytes());
            reseal(bytes);
        });
        scene.turns(4);
        let mut acknowledged = Vec::new();
        scene
            .owner
            .cover_pending(&mut client, &mut acknowledged, 0)
            .unwrap();
        assert!(
            acknowledged.is_empty() && scene.visible(5),
            "an inverted interval changes nothing"
        );
        assert_eq!(
            scene.clients[0].invalidate(key(5), 3, 2),
            Err(super::client::PutRefused::Interval)
        );
        let request = scene.clients[0].invalidate(key(5), 3, 5).unwrap();
        let bytes = scene.nets[0]
            .borrow()
            .peek(1)
            .expect("the INVALIDATE toward the owner");
        let sent = parse(Crc32c::detect(), &bytes, false).unwrap().header();
        assert_eq!(
            (
                sent.kind,
                sent.request,
                sent.key,
                sent.allocation,
                sent.offset
            ),
            (Kind::Invalidate, request, key(5), 3, 5)
        );
        scene.turns(4);
        assert!(!scene.visible(5), "the INVALIDATE removes the key at once");
        let resent = scene.clients[0].invalidate(key(5), 3, 5).unwrap();
        assert_ne!(resent, request, "a resend carries a fresh request field");
        scene.turns(4);
        scene.clients[0].poll(scene.turn * 100);
        assert_eq!(
            scene.clients[0].take_invalidated(),
            None,
            "nothing acknowledges before the write"
        );
        scene
            .owner
            .cover_pending(&mut client, &mut acknowledged, 0)
            .unwrap();
        assert_eq!(
            acknowledged,
            [(key(5), versions(3, 5))],
            "the resend coalesces with the held INVALIDATE"
        );
        scene.turns(4);
        scene.clients[0].poll(scene.turn * 100);
        assert_eq!(
            scene.clients[0].take_invalidated(),
            Some(super::client::Invalidated {
                request: resent,
                key: key(5),
                low: 3,
                high: 5
            })
        );
        assert_eq!(scene.clients[0].take_invalidated(), None);
    });
}

/// For same-session INVALIDATEs of one entry delivered in reverse send order, the owner retains the asker with the higher authenticated sequence and acknowledges that request.
#[test]
fn a_reordered_resend_acknowledges_the_later_sent_request() {
    scene(&PRINCIPALS, |mut scene| {
        let store = crate::storage::store_tests::seeded_under(scene.owner.tenure());
        let (fencing, mut client) = fenced_coverage(&store, scene.owner.tenure());
        scene.owner.install_coverage(fencing).unwrap();
        let interval = |header: &mut Header| {
            header.allocation = 3;
            header.offset = 5;
        };
        let first = scene.frame(1, Kind::Invalidate, request(1, 1), 5, interval);
        let second = scene.frame(1, Kind::Invalidate, request(2, 1), 5, interval);
        assert!(first.sequence < second.sequence);
        scene.inject(1, &second);
        scene.inject(1, &first);
        scene.turns(4);
        let mut acknowledged = Vec::new();
        scene
            .owner
            .cover_pending(&mut client, &mut acknowledged, 0)
            .unwrap();
        assert_eq!(acknowledged, [(key(5), versions(3, 5))]);
        scene.turns(4);
        let sent = scene.sent_of(1, Kind::Invalidated);
        assert_eq!(
            sent.iter().map(|header| header.request).collect::<Vec<_>>(),
            [second.request],
            "the later-sent request is acknowledged"
        );
    });
}

/// Tenure 0 acknowledges INVALIDATE(k, [3, 5]) and crashes, with its INVALIDATED queued and unsent when
/// `emitted` is false, and sent and lost on the link when it is true. The acknowledged INVALIDATE is in the coverage
/// tenure 1 fences, which refuses a FILL of version 4.
fn crash_after_acknowledgment(emitted: bool) {
    use crate::storage::CacheVersion;
    use crate::storage::page_coverage::{Fencing, Progress};
    use crate::storage::store_tests::client;
    scene(&PRINCIPALS, |mut scene| {
        let store = crate::storage::store_tests::seeded_under(scene.owner.tenure());
        let (fencing, mut tenure) = fenced_coverage(&store, scene.owner.tenure());
        scene.owner.install_coverage(fencing).unwrap();
        let header = scene.frame(1, Kind::Invalidate, request(1, 1), 5, |header| {
            header.allocation = 3;
            header.offset = 5;
        });
        scene.inject(1, &header);
        scene.turns(4);
        let mut acknowledged = Vec::new();
        scene
            .owner
            .cover_pending(&mut tenure, &mut acknowledged, 0)
            .unwrap();
        assert_eq!(acknowledged, [(key(5), versions(3, 5))]);
        if emitted {
            scene.turns(4);
            let sent = scene.sent_of(1, Kind::Invalidated);
            assert_eq!(
                sent.iter()
                    .map(|header| (header.allocation, header.offset))
                    .collect::<Vec<_>>(),
                [(3, 5)],
                "emitted, then lost"
            );
        } else {
            assert!(
                scene.sent_of(1, Kind::Invalidated).is_empty(),
                "acknowledged, not emitted"
            );
        }
        let next = crate::storage::next_session();
        let record = crate::storage::store_tests::record_under(&next);
        let mut later = Fencing::new(&record, &next, 4).unwrap();
        let mut successor = client(&store);
        for at in 0..record.pages.get() {
            assert!(
                (0..8).any(|_| later.fence(&mut successor, at) == Ok(Progress::Done)),
                "page {} fences",
                at
            );
        }
        for version in 3..=5 {
            assert!(
                later
                    .coverage()
                    .unwrap()
                    .covers(&key(5), CacheVersion(version))
            );
        }
        assert!(!later.admits(&key(5), CacheVersion(4)));
    });
}

#[test]
fn invalidate_ack_boundary_acknowledged_before_emission() {
    crash_after_acknowledgment(false);
}

#[test]
fn invalidate_ack_boundary_emitted_before_delivery() {
    crash_after_acknowledgment(true);
}

/// `Owner::publish_fill` aborts a version 4 local fill with `Superseded` and leaves it unmapped when the coverage
/// holds `[3, 5]` for its key after its writes finish; coverage of `[5, 9]` allows publication.
#[test]
fn a_covered_local_fill_is_refused_at_its_insert() {
    for ((low, high), covered) in [((3, 5), true), ((5, 9), false)] {
        scene(&PRINCIPALS, |mut scene| {
            let store = crate::storage::store_tests::seeded_under(scene.owner.tenure());
            let (fencing, _) = fenced_coverage(&store, scene.owner.tenure());
            scene.owner.install_coverage(fencing).unwrap();
            let body = payload(100, 6);
            let version = crate::storage::CacheVersion(4);
            let mut fill = crate::storage::owner_fixture::reserve_at(
                scene.storage,
                &key(5),
                version,
                0,
                body.len(),
            )
            .unwrap();
            let mut taken = 0;
            while !scene.owner.fill_progress(&fill).is_ready() {
                if taken < body.len() {
                    let mut budget = WorkBudget::with_io(0, usize::MAX, usize::MAX);
                    taken += scene
                        .owner
                        .receive_fill(&mut fill, &body[taken..], &mut budget)
                        .unwrap_or(0);
                }
                scene.turns(1);
                assert!(scene.turn < 10_000, "the fill finished its writes");
            }
            scene
                .owner
                .coverage_mut()
                .unwrap()
                .hold((key(5), versions(low, high)));
            let published = scene
                .owner
                .publish_fill(fill, u64::MAX, 2, &mut WorkBudget::new(1024));
            assert_eq!(published.is_err(), covered);
            if covered {
                assert_eq!(
                    published.err(),
                    Some(crate::storage::FillPublishError::Superseded)
                );
            }
            assert_eq!(scene.visible(5), !covered);
        });
    }
}

#[test]
fn a_covered_local_fill_takes_no_payload() {
    scene(&PRINCIPALS, |mut scene| {
        let store = crate::storage::store_tests::seeded_under(scene.owner.tenure());
        let (fencing, _) = fenced_coverage(&store, scene.owner.tenure());
        scene.owner.install_coverage(fencing).unwrap();
        let body = payload(100, 6);
        let fill = crate::storage::owner_fixture::reserve_at(
            scene.storage,
            &key(5),
            crate::storage::CacheVersion(4),
            0,
            body.len(),
        );
        let mut fill = fill.unwrap();
        (scene.owner.coverage_mut().unwrap()).hold((key(5), versions(3, 5)));
        let volume = scene.owner.volume_report();
        let mut budget = WorkBudget::with_io(0, usize::MAX, usize::MAX);
        assert_eq!(
            scene.owner.receive_fill(&mut fill, &body, &mut budget),
            Err(crate::storage::ReceiveError::Revoked)
        );
        scene.turns(4);
        assert_eq!(scene.owner.volume_report(), volume);
        assert_eq!(
            (scene.owner)
                .publish_fill(fill, u64::MAX, 2, &mut WorkBudget::new(1024))
                .err(),
            Some(crate::storage::FillPublishError::Superseded)
        );
        assert!(!scene.visible(5));
    });
}

fn fenced_at_detached(scene: &mut Scene<'_, '_>) -> crate::storage::page_coverage::Coverage {
    assert_eq!(scene.owner.readiness(), crate::storage::Readiness::Detached);
    let store = crate::storage::store_tests::seeded_under(scene.owner.tenure());
    let (fencing, _) = fenced_coverage(&store, scene.owner.tenure());
    let coverage = fencing.coverage().expect("every page is fenced").clone();
    scene.owner.install_coverage(fencing).unwrap();
    coverage
}

fn refuses_contended_while_initializing(scene: &mut Scene<'_, '_>) {
    for state in [
        crate::storage::Readiness::Detached,
        crate::storage::Readiness::Loading,
    ] {
        if state == crate::storage::Readiness::Loading {
            let loading = crate::storage::store_tests::start_loading(scene.storage);
            assert_eq!(loading, Ok(state));
        }
        let mut budget = WorkBudget::new(1 << 12);
        assert_eq!(
            (scene.owner)
                .invalidate_interval(&key(5), versions(3, 5), 4, &mut budget)
                .err(),
            Some(crate::storage::InvalidateError::Contended),
            "{state:?}: an INVALIDATE while the owner initializes a warm volume refuses Contended"
        );
        assert_eq!(
            budget.remaining(),
            1 << 12,
            "{state:?}: the refusal precedes the removal's hash pass and gate try"
        );
        assert!(
            (scene.owner.coverage_mut().unwrap()).admits(&key(5), crate::storage::CacheVersion(4)),
            "{state:?}: the refused INVALIDATE adds no coverage"
        );
        assert_eq!(
            scene.owner.held_invalidations(),
            0,
            "{state:?}: no pair queued"
        );
    }
}

#[test]
fn an_invalidate_while_a_warm_bootstrap_loads_refuses_contended_and_holds_nothing() {
    invalidates_while_initializing(true);
}

fn invalidates_while_initializing(warm: bool) {
    scene_unformatted(|mut scene| {
        let coverage = fenced_at_detached(&mut scene);
        if warm {
            let load = crate::storage::SlotLoad::handed(Vec::new());
            scene.owner.assume_warm(load, coverage).unwrap();
        }
        refuses_contended_while_initializing(&mut scene);
    });
}

/// Cold initialization makes the `Contended` assertion fail at `Readiness::Detached`.
#[test]
#[should_panic(expected = "Detached: an INVALIDATE while the owner initializes a warm volume")]
fn negative_control_an_invalidate_on_a_cold_owner_fails_the_contended_refusal() {
    invalidates_while_initializing(false);
}

#[test]
fn an_invalidate_while_a_cold_bootstrap_loads_holds_its_entry_and_queues_its_pair() {
    use crate::storage::Readiness::{Detached, Loading};
    scene_unformatted(|mut scene| {
        assert_eq!(scene.owner.readiness(), Detached);
        let store = crate::storage::store_tests::seeded_under(scene.owner.tenure());
        let (fencing, _) = fenced_coverage(&store, scene.owner.tenure());
        scene.owner.install_coverage(fencing).unwrap();
        for (held, (name, state)) in [(5, Detached), (6, Loading)].into_iter().enumerate() {
            if state == Loading {
                let loading = crate::storage::store_tests::start_loading(scene.storage);
                assert_eq!(loading, Ok(state));
            }
            let mut budget = WorkBudget::new(1 << 12);
            let removal =
                (scene.owner).invalidate_interval(&key(name), versions(3, 5), 4, &mut budget);
            assert!(matches!(removal, Ok(Some(_))), "{state:?}: {removal:?}");
            assert!(
                !(scene.owner.coverage_mut().unwrap())
                    .admits(&key(name), crate::storage::CacheVersion(4)),
                "{state:?}: the coverage holds the entry"
            );
            assert_eq!(
                scene.owner.held_invalidations(),
                held + 1,
                "{state:?}: the pair is queued"
            );
        }
    });
}

/// The write commands upload `serial` has submitted, in device order.
fn written_by(scene: &Scene<'_, '_>, serial: u64) -> Vec<crate::oracle::CommandEvidence> {
    super::adapters::written_commands(scene.owner.volume_bound(), &scene.control.capture(), serial)
}

/// The turn's command bytes fund one full segment and its commands eight.
/// Peer 1's upload, admitted first, has four segments to write and peer 0's
/// upload one. No write ends. In the first turn peer 1's first segment
/// spends the bytes, and peer 0's upload, holding no command of its share of
/// two, has its segment staged and finds the turn's budget spent. The module
/// documentation's write-command rule makes the following turns lend
/// nothing, so peer 0's upload writes before peer 1 takes a command beyond
/// its share.
#[test]
fn a_spent_command_byte_budget_gives_the_next_command_to_the_peer_below_its_share() {
    let at = request(1, 1);
    let ordinals = |scene: &Scene<'_, '_>, serial: u64| -> Vec<u64> {
        super::adapters::written_commands(
            scene.owner.volume_bound(),
            &scene.control.capture(),
            serial,
        )
        .iter()
        .map(|command| command.ordinal)
        .collect()
    };
    let config = OwnerConfig {
        put: PutConfig {
            command_bytes: 16384,
            ..OWNER.put
        },
        ..OWNER
    };
    // Four read records leave the writes four slots, two a peer, and the metadata share one more while no metadata command claims it; three fill records give the scene six receive-write buffers.
    let storage = crate::storage::owner_fixture::storage_filling(4, 3);
    scene_over(storage, config, &PRINCIPALS, |mut scene| {
        let small = payload(FRAGMENT_LEN as usize, 25);
        let large = payload(6 * FRAGMENT_LEN as usize, 26);
        let borrower = ready_upload_from(&mut scene, 1, at, 5, &large);
        let waiter = ready_upload_from(&mut scene, 0, at, 6, &small);
        let (header, body) = scene.fragment_from(0, at, waiter, 6, &small, 0);
        scene.inject_edited(0, &header, &body, |_| {});
        let mut trace = Vec::new();
        for turn in 0..6 {
            for index in 0..6 {
                let (header, body) = scene.fragment_from(1, at, borrower, 5, &large, index);
                scene.inject_edited(1, &header, &body, |_| {});
            }
            let waits = scene.owner.put_report().receive_waits;
            scene.polls(1);
            trace.push((
                ordinals(&scene, borrower).len(),
                ordinals(&scene, waiter).len(),
                scene.owner.put_lends(),
                scene.owner.put_report().receive_waits - waits,
            ));
            if turn == 0 {
                assert_eq!(
                    (trace[0].0, trace[0].1),
                    (1, 0),
                    "premise: peer 1's first segment spent the turn's command bytes before peer 0's upload wrote"
                );
            }
        }
        let (borrowed, waited) = (ordinals(&scene, borrower), ordinals(&scene, waiter));
        assert!(
            borrowed.len() >= 3 && !waited.is_empty(),
            "premise: both uploads wrote: {trace:?}"
        );
        assert!(
            waited[0] < borrowed[2],
            "peer 1 took a command beyond its share of two before peer 0's upload wrote; (peer 1's commands, peer 0's commands, the turn lent, receive waits) by turn: {trace:?}"
        );
    });
}

/// The turn's commands are eight. Peer 1's upload, admitted first, has four
/// segments to write, and its fragments arrive in the first two turns.
/// Peer 0's upload of five fragments copies its first four in the third
/// turn; the fourth fills the upload's second segment, which the volume
/// submits once full, and the receive returns the bytes it took before that
/// submit. With command bytes for many segments peer 0 writes that segment
/// in the third turn. With command bytes for one segment, peer 1 holds its
/// share of two commands before the third turn, the third turn's bytes go to
/// peer 1's third command, and peer 0's submit finds them spent. The module
/// documentation's write-command rule makes the following turns lend
/// nothing, so peer 0's upload writes before peer 1 takes a fourth command.
#[test]
fn a_submit_refused_inside_a_receive_gives_the_next_command_to_the_peer_below_its_share() {
    let at = request(1, 1);
    let ordinals = |scene: &Scene<'_, '_>, serial: u64| -> Vec<u64> {
        super::adapters::written_commands(
            scene.owner.volume_bound(),
            &scene.control.capture(),
            serial,
        )
        .iter()
        .map(|command| command.ordinal)
        .collect()
    };
    for command_bytes in [1 << 20, 16384] {
        let config = OwnerConfig {
            put: PutConfig {
                command_bytes,
                ..OWNER.put
            },
            ..OWNER
        };
        let storage = crate::storage::owner_fixture::storage_filling(4, 3);
        scene_over(storage, config, &PRINCIPALS, |mut scene| {
            let waiting = payload(5 * FRAGMENT_LEN as usize, 27);
            let large = payload(6 * FRAGMENT_LEN as usize, 28);
            let borrower = ready_upload_from(&mut scene, 1, at, 5, &large);
            let waiter = ready_upload_from(&mut scene, 0, at, 6, &waiting);
            let mut trace = Vec::new();
            for turn in 0..8 {
                for index in (0..6).filter(|_| turn < 2) {
                    let (header, body) = scene.fragment_from(1, at, borrower, 5, &large, index);
                    scene.inject_edited(1, &header, &body, |_| {});
                }
                for index in (0..5).filter(|_| turn >= 2) {
                    let (header, body) = scene.fragment_from(0, at, waiter, 6, &waiting, index);
                    scene.inject_edited(0, &header, &body, |_| {});
                }
                let waits = scene.owner.put_report().receive_waits;
                scene.polls(1);
                trace.push((
                    ordinals(&scene, borrower).len(),
                    ordinals(&scene, waiter).len(),
                    scene.owner.put_lends(),
                    scene.owner.put_report().receive_waits - waits,
                ));
            }
            if command_bytes > 16384 {
                assert_eq!(
                    trace[2].1, 1,
                    "premise: with bytes to spare peer 0's second segment submits in the third turn; (peer 1's commands, peer 0's commands, the turn lent, receive waits) by turn: {trace:?}"
                );
                return;
            }
            assert_eq!(
                (trace[1].0, trace[2].0, trace[2].1),
                (2, 3, 0),
                "premise: peer 1 held its share of two before the third turn, whose bytes went to peer 1's third command; (peer 1's commands, peer 0's commands, the turn lent, receive waits) by turn: {trace:?}"
            );
            let (borrowed, waited) = (ordinals(&scene, borrower), ordinals(&scene, waiter));
            assert!(
                borrowed.len() >= 4 && !waited.is_empty(),
                "premise: both uploads wrote: {trace:?}"
            );
            assert!(
                waited[0] < borrowed[3],
                "peer 1 took a fourth command before peer 0's upload wrote; (peer 1's commands, peer 0's commands, the turn lent, receive waits) by turn: {trace:?}"
            );
        });
    }
}

/// The write-command rule of the PUT core's module documentation: a turn in
/// which a PUT with a write to submit, of a peer holding fewer commands than
/// its share, finds no command it may take is followed by a turn that lends
/// nothing. Peer 0 has two uploads and a share of one. Its second upload
/// holds the peer's one command with every unit submitted, peer 1's upload
/// holds the other two commands the volume admits with segments waiting,
/// and peer 0's first upload waits with a write to submit. The second
/// upload's command ends. In the turn that sees the terminal, peer 1's
/// upload, admitted first, takes the freed command, and peer 0's waiting
/// upload finds none while its peer holds no command. The next turn lends
/// nothing, and the waiting upload writes before peer 1 takes a further
/// command, whichever of peer 0's uploads the progress pass visits first.
#[test]
fn a_command_ended_on_a_peers_other_upload_leaves_the_peer_below_its_share_in_that_turn() {
    let commands = |scene: &Scene<'_, '_>, serial: u64| written_by(scene, serial).len();
    let config = OwnerConfig {
        request_slots: 6,
        peer_requests: 3,
        serve: ServeConfig {
            slots: 6,
            ..OWNER.serve
        },
        put: PutConfig {
            puts: 4,
            peer_puts: 2,
            ..OWNER.put
        },
        ..OWNER
    };
    // The progress pass visits uploads in admission order, so the two orders of peer 0's uploads cover the waiting upload visited before and after the upload whose command ended.
    for holder_first in [true, false] {
        // Six read records leave the writes two slots, one a peer, and the metadata share one more while no metadata command claims it.
        let storage = crate::storage::owner_fixture::storage_for_puts(6, 4);
        scene_over(storage, config, &PRINCIPALS, |mut scene| {
            let (at, second) = (request(1, 1), request(2, 1));
            let large = payload(6 * FRAGMENT_LEN as usize, 31);
            let smalls = [32, 33].map(|seed| payload(FRAGMENT_LEN as usize, seed));
            let lender = ready_upload_from(&mut scene, 1, at, 5, &large);
            let (waiter, holder) = if holder_first {
                let holder = ready_upload_from(&mut scene, 0, second, 7, &smalls[1]);
                (ready_upload_from(&mut scene, 0, at, 6, &smalls[0]), holder)
            } else {
                let waiter = ready_upload_from(&mut scene, 0, at, 6, &smalls[0]);
                (
                    waiter,
                    ready_upload_from(&mut scene, 0, second, 7, &smalls[1]),
                )
            };
            let (header, body) = scene.fragment_from(0, second, holder, 7, &smalls[1], 0);
            scene.inject_edited(0, &header, &body, |_| {});
            scene.polls(3);
            let own = written_by(&scene, holder);
            assert_eq!(own.len(), 1, "premise: peer 0 holds its share of one");
            scene
                .control
                .hold(crate::storage::CommandToken::from_raw(own[0].token));
            for batch in [0..2, 2..6] {
                for index in batch {
                    let (header, body) = scene.fragment_from(1, at, lender, 5, &large, index);
                    scene.inject_edited(1, &header, &body, |_| {});
                }
                scene.polls(3);
            }
            let lent = written_by(&scene, lender);
            assert_eq!(
                lent.len(),
                2,
                "premise: peer 1 holds the rest of the write room, with segments waiting"
            );
            for command in &lent {
                scene
                    .control
                    .hold(crate::storage::CommandToken::from_raw(command.token));
            }
            let (header, body) = scene.fragment_from(0, at, waiter, 6, &smalls[0], 0);
            scene.inject_edited(0, &header, &body, |_| {});
            scene.polls(2);
            assert_eq!(commands(&scene, waiter), 0, "premise: no command is free");
            assert!(
                scene.owner.put_lends(),
                "premise: peer 0 holds its share, so its waiting upload stops no lending"
            );
            scene
                .control
                .release(crate::storage::CommandToken::from_raw(own[0].token));
            scene.turns(1);
            assert_eq!(
                (commands(&scene, lender), commands(&scene, waiter)),
                (3, 0),
                "premise: peer 1's upload, admitted first, takes the freed command in a turn that lends"
            );
            let mut trace = Vec::new();
            for _ in 0..4 {
                scene.turns(1);
                trace.push((
                    commands(&scene, lender),
                    commands(&scene, waiter),
                    scene.owner.put_lends(),
                ));
                if commands(&scene, waiter) == 1 {
                    break;
                }
            }
            assert_eq!(
                trace,
                [(3, 1, false)],
                "holder first {holder_first}: the turn after peer 0's upload found no command lends nothing, and that upload writes before peer 1 takes a fourth command"
            );
        });
    }
}

/// An upload of 33 fragments spans two extents, the first carrying the first
/// 31 fragments' payload. Its client sends each fragment the grant admits up
/// to the 31st and then nothing until the 30th turn. The disk completes every
/// write. With command bytes to spare, the upload submits all 16 of the first
/// extent's segments while the client is still sending. With command bytes
/// for one segment a turn, a turn's copy fills more segments than its bytes
/// fund, so a submit is refused and its segment stays staged. The storage
/// contract is that the next receive retries it, with or without bytes. The
/// module documentation's write-command rule bounds the wait of a peer below
/// its share by the terminals of commands held beyond the other peers' shares
/// and the budget earlier admissions take. No other upload holds a command or
/// takes budget, so the upload submits the first extent's last segments
/// before its client sends again.
#[test]
fn a_segment_staged_at_an_extent_end_is_submitted_before_the_client_sends_again() {
    let at = request(1, 1);
    let written = |scene: &Scene<'_, '_>, serial: u64| {
        super::adapters::written_commands(
            scene.owner.volume_bound(),
            &scene.control.capture(),
            serial,
        )
        .len()
    };
    for command_bytes in [1 << 20, 16384] {
        let config = OwnerConfig {
            put: PutConfig {
                command_bytes,
                ..OWNER.put
            },
            ..OWNER
        };
        let storage = crate::storage::owner_fixture::sequence_storage_with_body(
            33 * FRAGMENT_LEN as usize,
            crate::storage::owner_fixture::Shape {
                units: 512,
                slots: 8,
            },
        );
        scene_over(storage, config, &PRINCIPALS, |mut scene| {
            let object = payload(33 * FRAGMENT_LEN as usize, 31);
            let serial = ready_upload_from(&mut scene, 0, at, 6, &object);
            let (mut next, mut grant) = (0, 4);
            // (turn, the upload's written commands, the turn lent, the grant)
            let mut trace = Vec::new();
            for turn in 0..30 {
                for ack in acks(&scene.replies(0)) {
                    grant = grant.max(ack.2);
                }
                while next < grant.min(31) {
                    let (header, body) = scene.fragment_from(0, at, serial, 6, &object, next);
                    scene.inject_edited(0, &header, &body, |_| {});
                    next += 1;
                }
                scene.turns(1);
                trace.push((
                    turn,
                    written(&scene, serial),
                    scene.owner.put_lends(),
                    grant,
                ));
            }
            assert_eq!(
                next, 31,
                "premise: the client sent the first 31 fragments: {trace:?}"
            );
            assert_eq!(
                written(&scene, serial),
                16,
                "the upload submitted every segment of its first extent before its client sent again; command bytes {command_bytes}; (turn, written commands, the turn lent, grant): {trace:?}"
            );
        });
    }
}

/// The upload of the test above, now with another peer's upload admitted
/// first. Command bytes fund one segment a turn. From the turn the first
/// upload's extent ends, the other upload's client sends two fragments a turn,
/// so each turn's bytes go to the earlier admission and the first upload's
/// retries of its staged segments are refused. The module documentation's write-command rule bounds its wait by the budget
/// the earlier admission takes, so once that upload's fragments end, the first
/// upload submits the last segments of its first extent before its client
/// sends again.
#[test]
fn a_staged_segment_whose_retry_is_refused_is_submitted_once_the_budget_frees() {
    let at = request(1, 1);
    let written = |scene: &Scene<'_, '_>, serial: u64| {
        super::adapters::written_commands(
            scene.owner.volume_bound(),
            &scene.control.capture(),
            serial,
        )
        .len()
    };
    let config = OwnerConfig {
        put: PutConfig {
            command_bytes: 16384,
            ..OWNER.put
        },
        ..OWNER
    };
    let storage = crate::storage::owner_fixture::sequence_storage_with_body(
        33 * FRAGMENT_LEN as usize,
        crate::storage::owner_fixture::Shape {
            units: 512,
            slots: 8,
        },
    );
    scene_over(storage, config, &PRINCIPALS, |mut scene| {
        let other = payload(20 * FRAGMENT_LEN as usize, 32);
        let object = payload(33 * FRAGMENT_LEN as usize, 31);
        let earlier = ready_upload_from(&mut scene, 1, at, 5, &other);
        let serial = ready_upload_from(&mut scene, 0, at, 6, &object);
        let (mut next, mut grant) = (0, 4);
        let (mut sent, mut granted) = (0, 4);
        // (turn, the upload's written commands, the earlier upload's written commands)
        let mut trace = Vec::new();
        for turn in 0..40 {
            for ack in acks(&scene.replies(0)) {
                grant = grant.max(ack.2);
            }
            for ack in acks(&scene.replies(1)) {
                granted = granted.max(ack.2);
            }
            while next < grant.min(31) {
                let (header, body) = scene.fragment_from(0, at, serial, 6, &object, next);
                scene.inject_edited(0, &header, &body, |_| {});
                next += 1;
            }
            if next == 31 {
                for _ in 0..2 {
                    if sent < granted.min(20) {
                        let (header, body) = scene.fragment_from(1, at, earlier, 5, &other, sent);
                        scene.inject_edited(1, &header, &body, |_| {});
                        sent += 1;
                    }
                }
            }
            scene.turns(1);
            trace.push((turn, written(&scene, serial), written(&scene, earlier)));
        }
        assert_eq!(
            (next, sent),
            (31, 20),
            "premise: the clients sent the first 31 fragments and the other object: {trace:?}"
        );
        assert_eq!(
            written(&scene, serial),
            16,
            "the upload submitted every segment of its first extent before its client sent again; (turn, written commands, the earlier upload's written commands): {trace:?}"
        );
    });
}

/// The write-command rule of the PUT core's module documentation: a turn in
/// which a PUT with a write to submit, of a peer holding fewer commands than
/// its share, finds no command it may take, because the turn's budget is
/// spent, is followed by a turn that lends nothing. Here the PUT finds none
/// inside a receive: the turn's command bytes cover one segment, peer 1's
/// upload, admitted first, takes them, and peer 0's upload fills a segment
/// whose submit the budget refuses. Peer 0 has a share of one and a second
/// upload that holds one command. When that command ended before the turn,
/// peer 0 holds none, so the next turn lends nothing and peer 0's segment
/// is written before peer 1 takes a second command, whichever of peer 0's
/// uploads the progress pass visits first. In the sibling runs the command
/// has not ended, peer 0 holds its share, and the next turn lends.
#[test]
fn a_submit_refused_inside_a_receive_after_a_command_ended_on_the_peers_other_upload_stops_the_lending()
 {
    let commands = |scene: &Scene<'_, '_>, serial: u64| written_by(scene, serial).len();
    let config = OwnerConfig {
        request_slots: 6,
        peer_requests: 3,
        serve: ServeConfig {
            slots: 6,
            ..OWNER.serve
        },
        put: PutConfig {
            puts: 4,
            peer_puts: 2,
            command_bytes: 16384,
            ..OWNER.put
        },
        ..OWNER
    };
    // The progress pass visits uploads in admission order, so the two orders of peer 0's uploads cover the upload whose submit is refused visited before and after the upload whose command ended.
    for (holder_first, ended) in [(true, false), (false, false), (true, true), (false, true)] {
        // Six read records leave the writes two slots, one a peer, and the metadata share one more while no metadata command claims it.
        let storage = crate::storage::owner_fixture::storage_for_puts(6, 4);
        scene_over(storage, config, &PRINCIPALS, |mut scene| {
            let (at, second) = (request(1, 1), request(2, 1));
            let large = payload(6 * FRAGMENT_LEN as usize, 31);
            let waiting = payload(5 * FRAGMENT_LEN as usize, 32);
            let small = payload(FRAGMENT_LEN as usize, 33);
            let lender = ready_upload_from(&mut scene, 1, at, 5, &large);
            let (waiter, holder) = if holder_first {
                let holder = ready_upload_from(&mut scene, 0, second, 7, &small);
                (ready_upload_from(&mut scene, 0, at, 6, &waiting), holder)
            } else {
                let waiter = ready_upload_from(&mut scene, 0, at, 6, &waiting);
                (waiter, ready_upload_from(&mut scene, 0, second, 7, &small))
            };
            let (header, body) = scene.fragment_from(0, second, holder, 7, &small, 0);
            scene.inject_edited(0, &header, &body, |_| {});
            scene.polls(3);
            let own = written_by(&scene, holder);
            assert_eq!(own.len(), 1, "premise: peer 0 holds its share of one");
            let own = crate::storage::CommandToken::from_raw(own[0].token);
            scene.control.hold(own);
            for index in 0..6 {
                let (header, body) = scene.fragment_from(1, at, lender, 5, &large, index);
                scene.inject_edited(1, &header, &body, |_| {});
            }
            for index in 0..4 {
                let (header, body) = scene.fragment_from(0, at, waiter, 6, &waiting, index);
                scene.inject_edited(0, &header, &body, |_| {});
            }
            if ended {
                scene.control.release(own);
            }
            let waits = scene.owner.put_report().command_waits;
            scene.turns(1);
            for command in written_by(&scene, lender) {
                scene
                    .control
                    .hold(crate::storage::CommandToken::from_raw(command.token));
            }
            assert_eq!(
                (
                    commands(&scene, lender),
                    commands(&scene, waiter),
                    scene.owner.put_report().command_waits - waits,
                    scene.owner.put_lends(),
                ),
                (1, 0, 0, true),
                "premise, holder first {holder_first}, ended {ended}: in a turn that lends, peer 1's upload takes the turn's command bytes and peer 0's upload writes nothing, with no fragment left held for a command"
            );
            scene.turns(1);
            let next = (
                commands(&scene, lender),
                commands(&scene, waiter),
                scene.owner.put_lends(),
            );
            if ended {
                assert_eq!(
                    next,
                    (1, 1, false),
                    "holder first {holder_first}: peer 0 held no command when its upload's submit was refused, so the next turn lends nothing and that upload writes before peer 1 takes a second command"
                );
            } else {
                assert_eq!(
                    next,
                    (2, 0, true),
                    "premise, holder first {holder_first}: peer 0 holds its share, so its refused submit stops no lending"
                );
            }
        });
    }
}

/// The write-command rule of the PUT core's module documentation: in a turn
/// that lends nothing a PUT takes a command while its peer holds fewer than
/// its share, and such a peer waits for at most the terminals of the commands
/// held beyond the other peers' shares and for the budget earlier admissions
/// take. The volume admits three write commands and each peer's share is
/// one. Peer 0's holder upload, its every unit submitted, holds all three,
/// so peer 1's upload, holding none, finds none and the next turn lends
/// nothing. The holder's commands end. In the turn that sees the terminals
/// peer 0 holds no command and three are free, so peer 0's waiting upload
/// takes one, whichever of peer 0's uploads the progress pass visits first.
#[test]
fn a_turn_that_lends_nothing_gives_a_command_to_a_peer_whose_other_uploads_commands_ended() {
    let commands = |scene: &Scene<'_, '_>, serial: u64| written_by(scene, serial).len();
    let config = OwnerConfig {
        request_slots: 6,
        peer_requests: 3,
        serve: ServeConfig {
            slots: 6,
            ..OWNER.serve
        },
        put: PutConfig {
            puts: 4,
            peer_puts: 2,
            ..OWNER.put
        },
        ..OWNER
    };
    // The progress pass visits uploads in admission order, so the two orders of peer 0's uploads cover the waiting upload visited before and after the upload whose commands ended.
    for holder_first in [true, false] {
        // Six read records leave the writes two slots, one a peer, and the metadata share one more while no metadata command claims it.
        let storage = crate::storage::owner_fixture::storage_for_puts(6, 4);
        scene_over(storage, config, &PRINCIPALS, |mut scene| {
            let (at, second) = (request(1, 1), request(2, 1));
            let large = payload(5 * FRAGMENT_LEN as usize, 41);
            let smalls = [42, 43].map(|seed| payload(FRAGMENT_LEN as usize, seed));
            let (waiter, holder) = if holder_first {
                let holder = ready_upload_from(&mut scene, 0, second, 7, &large);
                (ready_upload_from(&mut scene, 0, at, 6, &smalls[0]), holder)
            } else {
                let waiter = ready_upload_from(&mut scene, 0, at, 6, &smalls[0]);
                (waiter, ready_upload_from(&mut scene, 0, second, 7, &large))
            };
            let other = ready_upload_from(&mut scene, 1, at, 5, &smalls[1]);
            for index in 0..5 {
                let (header, body) = scene.fragment_from(0, second, holder, 7, &large, index);
                scene.inject_edited(0, &header, &body, |_| {});
            }
            scene.polls(3);
            let own = written_by(&scene, holder);
            assert_eq!(
                own.len(),
                3,
                "premise: peer 0's holder upload holds every write command the volume admits"
            );
            for command in &own {
                scene
                    .control
                    .hold(crate::storage::CommandToken::from_raw(command.token));
            }
            let (header, body) = scene.fragment_from(0, at, waiter, 6, &smalls[0], 0);
            scene.inject_edited(0, &header, &body, |_| {});
            let (header, body) = scene.fragment_from(1, at, other, 5, &smalls[1], 0);
            scene.inject_edited(1, &header, &body, |_| {});
            scene.polls(2);
            assert_eq!(
                (commands(&scene, waiter), commands(&scene, other)),
                (0, 0),
                "premise: no command is free"
            );
            for command in &own {
                scene
                    .control
                    .release(crate::storage::CommandToken::from_raw(command.token));
            }
            scene.turns(1);
            assert_eq!(
                (
                    scene.owner.put_lends(),
                    commands(&scene, holder),
                    commands(&scene, other)
                ),
                (false, 3, 1),
                "premise: the turn that sees the terminals lends nothing, the holder asks for no command, and peer 1 takes its share"
            );
            let taken = commands(&scene, waiter);
            scene.turns(1);
            let after = (commands(&scene, waiter), scene.owner.put_lends());
            assert_eq!(
                taken, 1,
                "holder first {holder_first}: peer 0 holds no command in a turn that lends nothing and leaves commands free, so its waiting upload takes one; one turn later its commands and whether that turn lent: {after:?}"
            );
        });
    }
}

/// Two peers share four write commands, two each, and the volume admits one
/// more while no metadata command claims its slot. Peer 1's upload, admitted
/// first, holds commands beyond its share on a disk that completes nothing,
/// and its client keeps two fragments a turn arriving. Peer 0's upload of two
/// extents holds none and has consumed all but the last fragment of its first
/// extent.
///
/// In the held arm peer 1 holds all five commands when peer 0's fragment
/// arrives, so the fragment stays held and its upload finds no command. In
/// the staged arm peer 1 holds four, so the fragment is consumed with one
/// command: the extent's last segment is submitted, the submit of its header
/// segment is refused for the receive's one command and stays staged, and in
/// the next turn the upload, holding one command of its share of two, finds
/// the volume admits none.
///
/// The module documentation's write-command rule makes the turn after such a
/// turn lend nothing. The disk then completes one command of peer 1, which
/// still holds more than its share, so the freed command goes to peer 0's
/// upload in both arms.
#[test]
fn a_staged_segment_that_finds_no_command_makes_the_next_turn_lend_nothing() {
    let at = request(1, 1);
    // (written commands, commands outstanding)
    let commands = |scene: &Scene<'_, '_>, serial: u64| {
        let written = super::adapters::written_commands(
            scene.owner.volume_bound(),
            &scene.control.capture(),
            serial,
        );
        let outstanding = (written.iter())
            .filter(|command| command.delivered.is_none())
            .count();
        (written.len(), outstanding)
    };
    for staged in [false, true] {
        // Five fill records give the scene ten receive-write buffers, so peer 1's upload holds five commands beside both uploads' staged buffers.
        let storage = crate::storage::owner_fixture::sequence_storage_filling(
            33 * FRAGMENT_LEN as usize,
            crate::storage::owner_fixture::Shape {
                units: 512,
                slots: 8,
            },
            5,
        );
        scene_over(storage, OWNER, &PRINCIPALS, |mut scene| {
            let other = payload(31 * FRAGMENT_LEN as usize, 32);
            let object = payload(33 * FRAGMENT_LEN as usize, 31);
            let earlier = ready_upload_from(&mut scene, 1, at, 5, &other);
            let serial = ready_upload_from(&mut scene, 0, at, 6, &object);
            let (mut next, mut grant) = (0, 4);
            for _ in 0..30 {
                for ack in acks(&scene.replies(0)) {
                    grant = grant.max(ack.2);
                }
                while next < grant.min(30) {
                    let (header, body) = scene.fragment_from(0, at, serial, 6, &object, next);
                    scene.inject_edited(0, &header, &body, |_| {});
                    next += 1;
                }
                scene.turns(1);
            }
            assert_eq!(
                (next, commands(&scene, serial)),
                (30, (14, 0)),
                "premise: peer 0's upload wrote the fourteen segments its first thirty fragments fill, and the disk completed them"
            );
            // (peer 0's written and outstanding commands, peer 1's, the turn lent)
            let mut trace = Vec::new();
            let (mut sent, mut granted) = (0, 4);
            let mut feed = |scene: &mut Scene<'_, '_>, limit: u32| {
                for ack in acks(&scene.replies(1)) {
                    granted = granted.max(ack.2);
                }
                for _ in 0..2 {
                    if sent < granted.min(limit) {
                        let (header, body) = scene.fragment_from(1, at, earlier, 5, &other, sent);
                        scene.inject_edited(1, &header, &body, |_| {});
                        sent += 1;
                    }
                }
            };
            let mut poll = |scene: &mut Scene<'_, '_>| {
                scene.polls(1);
                trace.push((
                    commands(scene, serial),
                    commands(scene, earlier),
                    scene.owner.put_lends(),
                ));
            };
            let borrowed = if staged { 4 } else { 5 };
            for _ in 0..12 {
                feed(&mut scene, 2 + 2 * borrowed);
                poll(&mut scene);
            }
            assert_eq!(
                commands(&scene, earlier),
                (borrowed as usize, borrowed as usize),
                "premise: peer 1's upload holds {borrowed} commands, beyond its share of two: {trace:?}"
            );
            let (header, body) = scene.fragment_from(0, at, serial, 6, &object, 30);
            scene.inject_edited(0, &header, &body, |_| {});
            poll(&mut scene);
            if staged {
                assert_eq!(
                    commands(&scene, serial),
                    (15, 1),
                    "premise: peer 0's upload submitted its extent's last segment with the one command the volume admitted: {trace:?}"
                );
                feed(&mut scene, 31);
                poll(&mut scene);
            }
            let before = (commands(&scene, serial), commands(&scene, earlier));
            assert_eq!(
                (before.0.1 < 2, before.0.1 + before.1.1),
                (true, 5),
                "premise: peer 0's upload, below its share of two, ended the turn with a segment to submit and no command, because the volume admits none: {trace:?}"
            );
            scene.control.tick(1);
            feed(&mut scene, 31);
            poll(&mut scene);
            let after = (commands(&scene, serial), commands(&scene, earlier));
            assert_eq!(
                (after.0.0 - before.0.0, after.1.0 - before.1.0),
                (1, 0),
                "the command the disk freed goes to peer 0's upload, below its share, and not to peer 1's, beyond its own; staged {staged}; (peer 0's written and outstanding commands, peer 1's, the turn lent) by poll: {trace:?}"
            );
        });
    }
}

/// An upload of 33 fragments spans two extents, the first carrying the first
/// 31 fragments' payload. Its client sends the first 31 fragments and then
/// nothing. No other upload holds a command or takes budget, and the turn's
/// command bytes fund every segment. In the refused arm the device refuses
/// one submit `QueueFull` in the turn that consumes the 31st fragment, so a
/// segment of the first extent stays staged inside a receive that returns
/// `Ok`; the disk has room again from the next submit on.
///
/// The storage contract is that "the next `receive`, with or without new
/// bytes, retries" a staged segment first. `PutCore::idle` settles an upload
/// only with "no segment staged by a refused submit", and the retry in
/// `PutCore::consume` exists "so the PUT does not wait on its client for a
/// write it holds". So the upload submits all 16 segments of its first
/// extent in the turns after the refusal, before its client sends again, as
/// it does in the arm with no refusal.
#[test]
fn a_segment_a_device_refusal_staged_at_an_extent_end_is_submitted_before_the_client_sends_again() {
    let at = request(1, 1);
    let written = |scene: &Scene<'_, '_>, serial: u64| {
        super::adapters::written_commands(
            scene.owner.volume_bound(),
            &scene.control.capture(),
            serial,
        )
        .len()
    };
    for refused in [false, true] {
        let storage = crate::storage::owner_fixture::sequence_storage_with_body(
            33 * FRAGMENT_LEN as usize,
            crate::storage::owner_fixture::Shape {
                units: 512,
                slots: 8,
            },
        );
        scene_over(storage, OWNER, &PRINCIPALS, |mut scene| {
            let object = payload(33 * FRAGMENT_LEN as usize, 31);
            let serial = ready_upload_from(&mut scene, 0, at, 6, &object);
            let (mut next, mut grant) = (0, 4);
            for _ in 0..30 {
                for ack in acks(&scene.replies(0)) {
                    grant = grant.max(ack.2);
                }
                while next < grant.min(30) {
                    let (header, body) = scene.fragment_from(0, at, serial, 6, &object, next);
                    scene.inject_edited(0, &header, &body, |_| {});
                    next += 1;
                }
                scene.turns(1);
            }
            assert_eq!(
                (next, written(&scene, serial)),
                (30, 14),
                "premise: the upload wrote the fourteen segments its first thirty fragments fill"
            );
            let device_refusals = scene
                .control
                .refused(crate::storage::device::sim::Origin::Script);
            if refused {
                scene.control.refuse_next(SubmitRefusal {
                    reason: RefusalReason::QueueFull,
                    code: None,
                });
            }
            let (header, body) = scene.fragment_from(0, at, serial, 6, &object, 30);
            scene.inject_edited(0, &header, &body, |_| {});
            // (the upload's written commands, the turn lent)
            let mut trace = Vec::new();
            scene.turns(1);
            trace.push((written(&scene, serial), scene.owner.put_lends()));
            assert_eq!(
                scene
                    .control
                    .refused(crate::storage::device::sim::Origin::Script)
                    - device_refusals,
                usize::from(refused),
                "premise: the device refused one submit of the turn that consumed the extent's last fragment, exactly in the refused arm: {trace:?}"
            );
            for _ in 0..20 {
                scene.turns(1);
                trace.push((written(&scene, serial), scene.owner.put_lends()));
            }
            let waited = written(&scene, serial);
            let (header, body) = scene.fragment_from(0, at, serial, 6, &object, 31);
            scene.inject_edited(0, &header, &body, |_| {});
            scene.turns(2);
            let resumed = written(&scene, serial);
            assert_eq!(
                waited, 16,
                "the upload submitted every segment of its first extent before its client sent again; refused {refused}; written commands two turns after the client's next fragment: {resumed}; (written commands, the turn lent) by turn: {trace:?}"
            );
        });
    }
}

/// What a three-extent upload showed once every fragment was sent: the
/// replies other than ACKs before its deadline and after it, and the
/// owner's and the storage's counts at each point.
#[derive(Debug)]
struct BoundaryUpload {
    /// Replies other than ACKs up to ten turns before the deadline.
    early: Vec<(Kind, Option<Status>)>,
    /// Live PUTs ten turns before the deadline.
    live_early: u32,
    /// Receive waits counted up to ten turns before the deadline.
    waits_early: u64,
    /// Replies other than ACKs from then to thirty turns past the deadline.
    late: Vec<(Kind, Option<Status>)>,
    live: u32,
    /// `published` and `failed_timed_out` of the PUT report at the end.
    tallies: (u64, u64),
    /// Lease credits reserved at the end, less those reserved before the BEGIN.
    credits: i64,
    visible: bool,
}

/// Uploads a three-extent object whose BEGIN allows 100 ms, which is 1000
/// turns. With `poisoned`, the pool gate is poisoned after READY, when the
/// first extent's locator is already read, so the fill's lookup of the
/// second extent's locator is its first to meet the poison.
fn boundary_upload(poisoned: bool) -> BoundaryUpload {
    const DEADLINE_TURNS: u64 = 1_000;
    let (storage, _, _) = three_extent_storage();
    let mut shown = None;
    scene_over(storage, OWNER, &PRINCIPALS, |mut scene| {
        let (metadata_len, body_len) = THREE_EXTENT_LENGTHS;
        let total = u64::from(metadata_len + body_len);
        let count = FragmentGeometry::fragments(total) as u32;
        let object = payload(total as usize, 77);
        let credits = scene.storage.lease_report().unwrap().reserved as i64;
        let at = request(1, 1);
        let begun = scene.turn;
        let begin = scene.frame(1, Kind::PutBegin, at, 10, |header| {
            header.remaining_ms = 100
        });
        let serial = scene.one(1, &begin).allocation;
        let header = scene.frame(1, Kind::PutPrepare, at, 10, three_extents(serial));
        scene.inject(1, &header);
        scene.turns(8);
        let kinds: Vec<_> = scene.replies(1).iter().map(|reply| reply.kind).collect();
        assert_eq!(kinds, [Kind::PutReady], "premise: the PREPARE is ready");
        if poisoned {
            crate::storage::owner_fixture::poison_pool(scene.storage);
        }
        let mut early = Vec::new();
        let collect = |scene: &mut Scene<'_, '_>, into: &mut Vec<_>| {
            let replies = scene.replies(1);
            into.extend(
                (replies.iter())
                    .filter(|reply| reply.kind != Kind::PutAck)
                    .map(|reply| (reply.kind, error(reply))),
            );
        };
        for index in 0..count {
            let start = index as usize * FRAGMENT_LEN as usize;
            let end = (start + FRAGMENT_LEN as usize).min(object.len());
            let data = scene.frame(1, Kind::PutData, at, 10, |header| {
                header.allocation = serial;
                header.metadata_len = metadata_len;
                header.body_len = body_len;
                header.total = total;
                header.count = count;
                header.index = index;
                header.offset = start as u64;
                header.datagram_len = (end - start) as u32;
            });
            scene.inject_edited(1, &data, &object[start..end], |_| {});
            scene.turns(3);
            collect(&mut scene, &mut early);
        }
        assert!(
            scene.owner.volume_report().writes_submitted > 0,
            "premise: the first extent's writes were submitted"
        );
        let near = begun + DEADLINE_TURNS - 10;
        assert!(scene.turn < near, "premise: every fragment was sent early");
        scene.turns(near - scene.turn);
        collect(&mut scene, &mut early);
        let (live_early, waits_early) = (scene.live(), scene.owner.put_report().receive_waits);
        scene.turns(40);
        let mut late = Vec::new();
        collect(&mut scene, &mut late);
        let report = scene.owner.put_report();
        shown = Some(BoundaryUpload {
            early,
            live_early,
            waits_early,
            late,
            live: scene.live(),
            tallies: (report.published, report.failed_timed_out),
            credits: scene.storage.lease_report().unwrap().reserved as i64 - credits,
            visible: scene.visible(10),
        });
    });
    shown.expect("the scene ran")
}

/// The judgment of an upload held at an extent boundary by a poisoned pool
/// gate: it waits unanswered and live until its deadline, then ends with one
/// `TimedOut` error, publishes nothing, and returns its credits.
fn held_until_its_deadline(upload: &BoundaryUpload) -> Result<(), String> {
    let waited = upload.early.is_empty() && upload.live_early == 1 && upload.waits_early > 0;
    let ended = upload.late == [(Kind::PutError, Some(Status::TimedOut))]
        && upload.live == 0
        && upload.tallies == (0, 1)
        && upload.credits == 0
        && !upload.visible;
    if waited && ended {
        Ok(())
    } else {
        Err(format!(
            "the upload did not wait until its deadline and end there: {upload:?}"
        ))
    }
}

/// A fill whose pool gate is poisoned at an extent boundary waits as on
/// `TableFull` until its deadline. A three-extent network upload whose pool
/// gate is poisoned after READY draws no reply but ACKs and stays live until
/// ten turns before its deadline, counting receive waits; within thirty
/// turns after the deadline it has ended with one `TimedOut` error, nothing
/// published, the key unmapped and both fill credits returned. The sibling,
/// the same upload at a sound gate, ends before the deadline with its RESULT.
#[test]
fn an_upload_at_a_poisoned_pool_gate_waits_until_its_deadline_and_times_out() {
    let poisoned = boundary_upload(true);
    assert_eq!(held_until_its_deadline(&poisoned), Ok(()));
    let sound = boundary_upload(false);
    assert_eq!(
        (&sound.early[..], &sound.late[..], sound.live_early),
        (&[(Kind::PutResult, None)][..], &[][..], 0),
        "the sibling published before the deadline: {sound:?}"
    );
    assert_eq!((sound.tallies, sound.credits), ((1, 0), 0), "{sound:?}");
}

/// The control of
/// `an_upload_at_a_poisoned_pool_gate_waits_until_its_deadline_and_times_out`:
/// an upload that passes the extent boundary, here at a sound gate, fails
/// the judgment.
#[test]
fn negative_control_an_upload_that_passes_the_boundary_fails_the_deadline_judgment() {
    let refusal = held_until_its_deadline(&boundary_upload(false)).unwrap_err();
    assert!(
        refusal.starts_with("the upload did not wait until its deadline and end there"),
        "{refusal}"
    );
}

/// An upload whose every write the device accepted before another upload's
/// refused submit lost the volume: its writes then end in success, and the
/// lost owner publishes nothing, so the upload ends without a RESULT and its
/// key stays missing.
#[test]
fn an_owner_loss_before_the_last_write_terminal_publishes_nothing() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(2 * FRAGMENT_LEN as usize, 45);
        let (at, serial) = ready_upload(&mut scene, &object);
        let accepted = send_all(&mut scene, at, serial, &object, 0..2);
        assert_eq!(
            accepted.len(),
            2,
            "one payload write, then the header write"
        );
        for &token in &accepted {
            scene.control.hold(token);
        }
        let other = payload(FRAGMENT_LEN as usize, 46);
        let later = request(1, 1);
        let second = ready_upload_from(&mut scene, 0, later, 6, &other);
        scene.control.refuse_next(SubmitRefusal {
            reason: RefusalReason::DeviceGone,
            code: None,
        });
        let (header, body) = scene.fragment_from(0, later, second, 6, &other, 0);
        scene.inject_edited(0, &header, &body, |_| {});
        scene.polls(8);
        let errors: Vec<_> = scene.replies(0).iter().filter_map(error).collect();
        assert_eq!(
            errors,
            [Status::OwnerUnavailable],
            "the other upload's refused submit lost the volume"
        );
        assert!(
            scene.replies(1).iter().all(|r| r.kind != Kind::PutResult),
            "premise: nothing published while the writes are held"
        );
        for &token in &accepted {
            scene.control.release(token);
        }
        scene.turns(20);
        let replies = scene.replies(1);
        assert!(
            replies.iter().all(|reply| reply.kind != Kind::PutResult),
            "a lost owner sent a RESULT: {replies:?}"
        );
        let errors: Vec<_> = replies.iter().filter_map(error).collect();
        assert_eq!(
            errors,
            [Status::OwnerUnavailable],
            "the upload ends as the lost owner's other uploads do"
        );
        assert!(!scene.visible(5), "a lost owner published the key");
    });
}
