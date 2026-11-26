//! Owner and client over the ENA poll-mode driver on the approved host pair,
//! each on its dataplane ENI bound by `kestrike-bind`: multi-frame GETs
//! with held leases, low-latency placement, allowance counters, the proven
//! port stop and the teardown order, and in-place recovery.
//!
//! The hardware tests are ignored by default and require
//! `KESTRIKE_MAPPINGS` to name the mappings file.
//! Each host has hugepages reserved, its ENI bound with the approved
//! write-combining modules, and runs as root, alone. The owner host serves
//! for `KESTRIKE_SERVE_SECONDS` (300 by default) while the client host
//! fetches; `KESTRIKE_PEER` names the other host's ENI address:
//!
//! ```text
//! sudo KESTRIKE_MAPPINGS=/run/kestrike/mappings KESTRIKE_PEER=10.0.1.9 \
//!     target/debug/deps/kestrike-<hash> --ignored net::ena_hardware_tests::the_owner_serves --nocapture
//! sudo KESTRIKE_MAPPINGS=/run/kestrike/mappings KESTRIKE_PEER=10.0.1.5 \
//!     target/debug/deps/kestrike-<hash> --ignored net::ena_hardware_tests::the_client_fetches --nocapture
//! ```
//!
//! The single-host tests prove the port's stop and the teardown order: one
//! from an idle port, one with accepted source-backed PUT DATA and the
//! receive ring posted at the stop, which records the stop certificate and
//! the custody it ends. The recovery test resets the device and runs only
//! with `KESTRIKE_ALLOW_RESET=1`, under separate approval.

use std::cell::RefCell;
use std::net::Ipv4Addr;
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use super::client::{Client, ClientMemory, SessionState};
use super::client_namespace::ClientRequests;
use super::datagram::{Datagrams, HEADER_LEN, Outgoing, Payload, PeerId};
use super::fetch::{FragmentLease, Outcome, Releases};
use super::frame::{Header, encode_with_body_crc};
use super::geometry::FRAGMENT_LEN;
use super::link::{Faults, LinkEnd, Net, network};
use super::owner::{Bundle, Keys, Owner};
use super::owner_tests::{
    OWNER, PRINCIPALS, TestOwner, client, client_config, drive, entries, key, payload,
    pool as owner_pool, start,
};
use super::packet::PacketPool;
use super::requests::{RequestId, RequestTable};
use super::serving::Serving;
use super::upload::{UploadCore, UploadOutcome};
use super::upload_tests::ready_core;
use crate::bind::{Host, Mappings, OwnerLock};
use crate::native::mock::{self, Forged, MockPort, iova};
use crate::native::registration_tests::Recorder;
use crate::native::{
    ArenaRegistration, BUS_MASTER, Burst, CAUSE_TURNS, DeviceStopped, DmaPolicy, EnaPort,
    EnvConfig, Environment, Link, PacketMempool, Port, RecoveryStage, RecoveryWatch, Role,
    StartupReport, Station, StopFailure, Supervisor, Unregistered, Watchdog, Wire, allowed_devices,
    attach_port, start_port, stations, stop_port, stop_port_watched,
};
use crate::storage::owner_fixture::{
    Device, SimControl, TestPlatform, arena_on, heap_storage_on, publish,
};
use crate::storage::{
    BufferArena, BufferConfig, Crc32c, EngineBudget, HugepageSize, NodeMask, PoolKind, PoolSpec,
};

pub(super) const OWNER_PORT: u16 = 7000;
pub(super) const CLIENT_PORT: u16 = 9000;
pub(super) const RECEIVE: u32 = 1024;
pub(super) const RESERVE: u32 = 600;
pub(super) const BATCH: usize = 8;
pub(super) const PATIENCE: Duration = Duration::from_secs(60);
/// The body sizes of the served objects, each keyed `key(n)` for its position `n` from 1, with 48 bytes of metadata.
const BODIES: [usize; 3] = [8_192, 15_743, 241_011];
const METADATA: usize = 48;
/// Rounds of the three GETs: enough data frames that the receive buffers recycle many times over.
const ROUNDS: usize = 25;

/// The recovery watch a burst over the device arms each episode with: the
/// role's `KESTRIKE_RECOVERY_DEADLINE_MS`, which every reset case's
/// manifest entry declares, else 30 seconds for a case that runs no
/// deliberate reset, over a supervisor that panics on containment, so the
/// interrupted recovery loses the link and the test's link assertions fail.
pub(super) fn recovery_watch() -> RecoveryWatch {
    let deadline =
        std::env::var("KESTRIKE_RECOVERY_DEADLINE_MS").map_or(Duration::from_secs(30), |text| {
            Duration::from_millis(
                text.parse()
                    .expect("the recovery deadline is a whole number of milliseconds"),
            )
        });
    RecoveryWatch::new(deadline, Arc::new(Unexpected))
}

/// Containment the tests never expect: a request fails the run.
pub(super) struct Unexpected;

impl Supervisor for Unexpected {
    fn contain(&self) {
        panic!("containment requested");
    }
}

/// The read, receive-write and maintenance buffers the volume needs, and the packet kinds, on 2 MiB pages.
pub(super) const POOLS: [PoolSpec; 6] = [
    PoolSpec {
        kind: PoolKind::ReadResponse,
        count: 64,
        buffer_len: 16 << 10,
    },
    PoolSpec {
        kind: PoolKind::ReceiveWrite,
        count: 8,
        buffer_len: 16 << 10,
    },
    PoolSpec {
        kind: PoolKind::Maintenance,
        count: 1,
        buffer_len: 16 << 10,
    },
    PoolSpec {
        kind: PoolKind::PacketReceive,
        count: RECEIVE,
        buffer_len: 16 << 10,
    },
    PoolSpec {
        kind: PoolKind::Reservation,
        count: 2,
        buffer_len: 4096,
    },
    PoolSpec {
        kind: PoolKind::PacketHeader,
        count: 512,
        buffer_len: 4 << 10,
    },
];

fn object(n: usize) -> Vec<u8> {
    payload(METADATA + BODIES[n], 0x4b50 + n as u64)
}

pub(super) fn mappings() -> (Mappings, OwnerLock) {
    let path =
        std::env::var("KESTRIKE_MAPPINGS").expect("set KESTRIKE_MAPPINGS; see the module docs");
    let path = Path::new(&path);
    let lock = OwnerLock::acquire(path.parent().unwrap()).unwrap();
    (Mappings::read(path).unwrap(), lock)
}

pub(super) fn peer() -> Ipv4Addr {
    std::env::var("KESTRIKE_PEER")
        .expect("set KESTRIKE_PEER; see the module docs")
        .parse()
        .unwrap()
}

pub(super) fn now_us(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_micros()).unwrap()
}

/// The environment on this thread's core, allowed to attach the inventory's devices.
pub(super) fn environment(mappings: &Mappings) -> Environment {
    // SAFETY: reads this thread's CPU.
    let core = u32::try_from(unsafe { libc::sched_getcpu() }).unwrap();
    Environment::initialize(&EnvConfig {
        core,
        hugepage_dir: Path::new("/dev/hugepages"),
        allowed: &allowed_devices(mappings),
    })
    .unwrap()
}

pub(super) fn arena() -> BufferArena<TestPlatform> {
    let config = BufferConfig {
        hugepage: HugepageSize::TwoMiB,
        nodes: NodeMask::from_nodes(&[0]).unwrap(),
        pools: &POOLS,
    };
    BufferArena::initialize(
        &config.validate().unwrap(),
        TestPlatform::linux(),
        &mut EngineBudget::unlimited(),
    )
    .unwrap()
}

/// The started port's checks every role makes: low-latency placement with a
/// nonzero push prefix, the qualified MTU and segments, the receive ring
/// within the receive reserve, and every DMA page verified.
pub(super) fn check_report(report: &StartupReport) {
    eprintln!("startup report:\n{report}");
    let port = &report.port;
    assert!(port.llq.push > 0, "low-latency placement pushes a prefix");
    assert_eq!((port.mtu, port.segments), (9001, 3));
    assert!(u32::from(port.rx_ring) + BATCH as u32 <= RESERVE);
    assert_eq!(
        report.dma.verified_pages,
        report.dma.extent / report.dma.page_size
    );
}

/// Stops `port` with its proof, releases the mempools with it after
/// checking every buffer the device held came back through their ops,
/// retires the lease, undoes the registration and closes the port, in that
/// order, then checks the packet kinds hold only what the application still
/// leases. It returns the undo's proof, which another device's detach requires, and
/// [`finish`] then ends the environment.
pub(super) fn teardown<'a>(
    mut port: EnaPort<'_>,
    pools: [PacketMempool<'_>; 3],
    registration: ArenaRegistration<'a>,
    arena: &BufferArena<TestPlatform>,
) -> Unregistered<'a> {
    let stopped = stop_port(&mut port).expect("the port's DMA stop is proven");
    release_stopped(port, stopped, pools, registration, arena)
}

/// [`teardown`] from the stop proof `stopped` of `port`, whose stop the caller made.
fn release_stopped<'a>(
    port: EnaPort<'_>,
    stopped: DeviceStopped,
    pools: [PacketMempool<'_>; 3],
    mut registration: ArenaRegistration<'a>,
    arena: &BufferArena<TestPlatform>,
) -> Unregistered<'a> {
    for pool in &pools {
        let report = pool.report();
        assert_eq!((report.stray, report.refused), (0, 0), "{report:?}");
    }
    let [header, payload, receive] = pools;
    let released = |pool: PacketMempool<'_>, stopped| {
        pool.release(stopped)
            .map_err(|(pool, _)| pool.report())
            .expect("the pool's objects are all back")
    };
    let stopped = released(payload, released(header, released(receive, stopped)));
    registration
        .device_stopped(stopped)
        .expect("the stop proof is this registration's");
    let watchdog = Watchdog::arm(Duration::from_secs(60), Arc::new(Unexpected)).unwrap();
    let undone = registration
        .unregister(&watchdog)
        .expect("registration undone");
    port.close(&undone).map_err(|_| "closed").unwrap();
    for kind in [PoolKind::PacketReceive, PoolKind::PacketHeader] {
        let report = arena.report(kind);
        assert_eq!(
            (report.posted, report.nic_held),
            (0, 0),
            "{kind:?} {report:?}"
        );
    }
    undone
}

/// Finishes the environment once every registration and port it served ended.
pub(super) fn finish(env: Environment) {
    let watchdog = Watchdog::arm(Duration::from_secs(60), Arc::new(Unexpected)).unwrap();
    env.finish(&watchdog).unwrap();
}

/// One host's dataplane up to a started port: the registration verified
/// after every device attached, the mempools, the write-combining mapping,
/// the startup report and the page-edge check. The form with
/// `disk = name, lock` also attaches the owner's volume controller before
/// the port and runs its canary once the registration verified.
macro_rules! dataplane {
    ($mappings:expr, $env:ident, $arena:ident, $registration:ident, $view:ident, $pools:ident, $port:ident) => {
        dataplane!(@up $mappings, $env, $arena, $registration, $view, $pools, $port, Arc::new(Unexpected), {}, {});
    };
    ($mappings:expr, $env:ident, $arena:ident, $registration:ident, $view:ident, $pools:ident, $port:ident, supervisor = $supervisor:expr) => {
        dataplane!(@up $mappings, $env, $arena, $registration, $view, $pools, $port, $supervisor, {}, {});
    };
    ($mappings:expr, $env:ident, $arena:ident, $registration:ident, $view:ident, $pools:ident, $port:ident, disk = $disk:ident, $lock:expr) => {
        dataplane!(@up $mappings, $env, $arena, $registration, $view, $pools, $port, Arc::new(Unexpected), {
            let mut $disk = $crate::storage::SpdkDisk::<$crate::storage::device::Spdk>::attach_qualification(&$crate::bind::Host::system(), &$lock, &mut $registration, SPDK, $crate::failover::evidence::Pair { exhid: $crate::failover::identity::Exhid::new([1; 16]).unwrap(), key: $crate::failover::identity::Key::decode((1 << 32) | 1).unwrap() }, reservations()).unwrap();
        }, {
            let canary = $arena.acquire($crate::storage::PoolKind::ReadResponse).unwrap();
            $disk.enable_reservations(&$registration).unwrap();
            drop($disk.canary(&$registration, canary, Duration::from_secs(5)).unwrap());
            eprintln!("volume geometry {:?}", crate::storage::Disk::geometry(&$disk));
        });
    };
    (@up $mappings:expr, $env:ident, $arena:ident, $registration:ident, $view:ident, $pools:ident, $port:ident, $supervisor:expr, {$($attach:tt)*}, {$($verified:tt)*}) => {
        let $env = environment(&$mappings);
        let $arena = arena();
        let mut $registration = ArenaRegistration::register(
            &$env,
            &$arena,
            DmaPolicy {
                allow_no_iommu: true,
            },
        )
        .unwrap();
        $($attach)*
        let host = Host::system();
        let mut $port = attach_port(
            &$env,
            &mut $registration,
            &host,
            &$mappings,
            RECEIVE,
            $supervisor,
        )
        .unwrap();
        $registration.map().unwrap();
        $registration.verify().unwrap();
        $($verified)*
        check_page_edges(&$registration, &$arena);
        let $view = PacketPool::new(&$arena, $crate::storage::PoolKind::PacketReceive, RESERVE).unwrap();
        let $pools = {
            let nic = $crate::native::Port::device_lease(&$port).expect("an attached port holds its lease");
            [
                PacketMempool::header(&$arena, &$registration, nic, c"ks-hw-hdr", &mut EngineBudget::unlimited()).unwrap(),
                PacketMempool::payload(&$arena, &$registration, nic, c"ks-hw-pay", 256, &mut EngineBudget::unlimited()).unwrap(),
                PacketMempool::receive(&$view, &$registration, nic, c"ks-hw-rx", &mut EngineBudget::unlimited()).unwrap(),
            ]
        };
        let report = start_port(&mut $port, &$pools[2], &$registration, &host, &$mappings).unwrap();
        check_report(&report);
    };
}
pub(super) use dataplane;

/// The SPDK driver's configuration on the owner's volume.
pub(super) const SPDK: crate::storage::SpdkConfig = crate::storage::SpdkConfig {
    queue_depth: 10,
    timeout_io_us: 30_000_000,
    timeout_admin_us: 30_000_000,
};

/// The owner's reservation limits on its volume.
pub(super) fn reservations() -> crate::storage::ReservationLimits {
    crate::storage::ReservationLimits::new(2, 2, 10, 10).unwrap()
}

/// Device-facing addresses at a backing page's edges: the registration
/// translates a range ending at a page's last byte to that page's address
/// plus the offset, translates the next page from its page-aligned start,
/// and refuses a range crossing between them.
pub(super) fn check_page_edges(
    registration: &ArenaRegistration<'_>,
    arena: &BufferArena<TestPlatform>,
) {
    let page = registration.report().page_size;
    let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    let base = buffer.bytes().as_ptr().addr();
    let edge = (base / page + 1) * page;
    drop(buffer);
    let start = registration
        .iova(edge - page, 1)
        .expect("the page's start translates");
    assert_eq!(
        start % page as u64,
        0,
        "a page's device address is page-aligned"
    );
    assert_eq!(
        registration.iova(edge - 16, 16),
        Some(start + page as u64 - 16),
        "a range ending at the page edge translates within its page"
    );
    if let Some(next) = registration.iova(edge, 16) {
        assert_eq!(next % page as u64, 0, "the next page starts page-aligned");
    }
    assert!(
        registration.iova(edge - 8, 16).is_none(),
        "a range crossing the page edge refuses"
    );
    eprintln!(
        "native {}, page {page} bytes, edge at {edge:#x}",
        spdk_sys::PINS
    );
}

/// Without traffic, the started port's stop clears and reads back bus
/// mastering, its proof releases the mempools and retires the lease, and
/// the registration, the port and the environment then end in order.
#[test]
#[ignore = "needs a dataplane ENI bound by kestrike-bind, named by KESTRIKE_MAPPINGS"]
fn the_port_stops_with_proof_and_tears_down_in_order() {
    let (mappings, _lock) = mappings();
    dataplane!(mappings, env, arena, registration, view, pools, port);
    eprintln!("allowances {:?}", port.allowances());
    for _ in 0..1_000 {
        assert_eq!(port.service(), crate::native::Health::Running);
    }
    let _undone = teardown(port, pools, registration, &arena);
    finish(env);
    drop(view);
}

/// A client upload core in Ready over two registered source slots of `arena`,
/// its two-fragment object supplied, with the owner's AUTHORITY and READY
/// taken as given, so the DATA path alone is under test.
fn staged_upload<'a>(
    arena: &'a BufferArena<TestPlatform>,
    releases: &'a Releases,
    budget: &mut EngineBudget,
    seed: u64,
) -> (ClientRequests<'a>, UploadCore<'a>, RequestId) {
    let mut requests = ClientRequests::new(RequestTable::new(4, 1, 4), releases, budget).unwrap();
    let object = payload(2 * FRAGMENT_LEN as usize, seed);
    let slots = super::memory::sources(arena, 2, budget).unwrap();
    let (mut core, id) = ready_core(slots, &mut requests, budget, object.len() as u32);
    for (index, fragment) in object.chunks(FRAGMENT_LEN as usize).enumerate() {
        core.supply(&mut requests, id, index as u32, fragment)
            .unwrap();
    }
    (requests, core, id)
}

/// The source-backed DATA frames of one upload, staged through the client's
/// upload core and handed to `burst` as datagrams whose payloads the device
/// reads in place from the registered source slots: the staged slots, in
/// send order, and how many datagrams the transport took. The sources' arena
/// outlives the burst logic's pools, so the upload core's lifetime outlives
/// the transport's.
fn send_data<'a: 'b, 'b, P: Port>(
    core: &mut UploadCore<'a>,
    requests: &mut ClientRequests<'a>,
    burst: &mut Burst<'b, P>,
) -> (Vec<u16>, usize) {
    let crc = Crc32c::detect();
    let mut frames = vec![[0u8; HEADER_LEN]; BATCH];
    let mut staged = Vec::new();
    core.data(requests, BATCH, |epoch, ask, slot, source| {
        // The session fields a live client fills; the owner's part of the handshake is given.
        let header = Header {
            principal: 1,
            key_epoch: 1,
            owner_nonce: [0x0a; 16],
            client_nonce: [0x0c; 16],
            sequence: staged.len() as u64 + 1,
            epoch,
            ..ask
        };
        let frame = &mut frames[staged.len()];
        encode_with_body_crc(crc, &header, [source.bytes(), &[]], source.crc(), frame).unwrap();
        staged.push(slot);
        true
    });
    let slots = core.slots();
    let datagrams: Vec<Outgoing<'_, 'b>> = staged
        .iter()
        .zip(&frames)
        .map(|(&slot, frame)| Outgoing {
            peer: PeerId(0),
            header: frame,
            payload: [
                Payload::Retained(slots[usize::from(slot)].piece().expect("a held slot")),
                Payload::EMPTY,
            ],
        })
        .collect();
    let taken = burst
        .send(&datagrams)
        .expect("the transport takes the batch");
    (staged, taken)
}

/// The census the outstanding witness reads before the first stop call.
#[derive(Debug)]
struct Outstanding {
    /// Header buffers whose device references stand: the sent frames' headers, until a reclaim returns them.
    nic_held: u32,
    /// Receive buffers posted to the ring.
    posted: u32,
    /// The ring's descriptor count.
    rx_ring: u32,
    /// Recoveries the burst logic ran.
    recoveries: u64,
    /// Staged source slots a device reference holds.
    sources_held: usize,
    /// Staged source slots that hand out writable bytes.
    writable: usize,
}

fn outstanding<P: Port>(
    burst: &Burst<'_, P>,
    arena: &BufferArena<TestPlatform>,
    core: &mut UploadCore<'_>,
    staged: &[u16],
) -> Outstanding {
    let (sources_held, writable) = sources(core, staged);
    Outstanding {
        nic_held: arena.report(PoolKind::PacketHeader).nic_held,
        posted: arena.report(PoolKind::PacketReceive).posted,
        rx_ring: burst.rx_ring(),
        recoveries: burst.report().recoveries,
        sources_held,
        writable,
    }
}

/// How many of the `staged` source slots a device reference holds, and how many hand out writable bytes.
fn sources(core: &mut UploadCore<'_>, staged: &[u16]) -> (usize, usize) {
    let slots = core.slots_mut();
    let held = staged
        .iter()
        .filter(|&&slot| slots[usize::from(slot)].device_held())
        .count();
    let writable = staged
        .iter()
        .filter(|&&slot| slots[usize::from(slot)].writable().is_some())
        .count();
    (held, writable)
}

/// The source slots after the device's access ended: every staged slot is
/// free of device references and stays unwritable while its upload holds it;
/// ending the session decides the upload Unknown after its sends and, with
/// the device's references gone, frees its slots, so the bytes become
/// writable; abandon and close then retire the request.
fn check_source_release(
    core: &mut UploadCore<'_>,
    requests: &mut ClientRequests<'_>,
    id: RequestId,
    staged: &[u16],
) {
    assert_eq!(
        sources(core, staged),
        (0, 0),
        "the stop ended the device references and the live upload keeps its source bytes"
    );
    core.end_session(requests, 1);
    assert_eq!(core.outcome(requests, id), Some(UploadOutcome::Unknown));
    assert_eq!(
        sources(core, staged),
        (0, staged.len()),
        "the ended upload's sources are writable once the device's access ended"
    );
    assert!(core.abandon(requests, id));
    assert!(core.close(requests, id), "the abandoned upload retires");
}

/// With accepted source-backed PUT DATA and the receive ring posted, the
/// started port's stop is proven and recorded: before the first stop call
/// the device's references on the sent frames' headers and on the registered
/// source bytes stand, as no reclaim ran since the send, the sources hand
/// out no writable view, the receive ring is fully posted at the driver's
/// `ring - 1` and no recovery ran; the watchdog is armed before the stop;
/// the stop result and the command register's bus-master read-back are
/// recorded; an unproven stop keeps the lease and the source references,
/// whose census the failure records; after the proof every reference is
/// back and the sources free only once their upload ended, and the
/// mempools, lease, registration, port and environment then end in order.
/// The owner's AUTHORITY and READY are taken as given, so the run claims the
/// native access end alone.
#[test]
#[ignore = "needs a dataplane ENI bound by kestrike-bind, named by KESTRIKE_MAPPINGS, and KESTRIKE_PEER"]
fn the_port_stops_with_source_backed_put_data_and_active_rx_outstanding() {
    let (mappings, _lock) = mappings();
    let contained = Arc::new(Recorder::new());
    dataplane!(
        mappings,
        env,
        arena,
        registration,
        view,
        pools,
        port,
        supervisor = contained.clone()
    );
    let (local, peers) = stations(&mappings, CLIENT_PORT, &[(peer(), OWNER_PORT)]).unwrap();
    let wire = Wire::new(local, &peers, &mut EngineBudget::unlimited()).unwrap();
    let mut burst = Burst::over(
        port,
        wire,
        [&pools[0], &pools[1], &pools[2]],
        &registration,
        recovery_watch(),
        BATCH,
        &mut EngineBudget::unlimited(),
    )
    .unwrap();
    let mut budget = EngineBudget::new(1 << 24);
    let releases = Releases::new(4, &mut budget).unwrap();
    let (mut requests, mut core, id) = staged_upload(&arena, &releases, &mut budget, 0x5500);
    let (staged, taken) = send_data(&mut core, &mut requests, &mut burst);
    assert_eq!(
        (staged.len(), taken),
        (2, 2),
        "the device accepted both DATA frames"
    );
    // The outstanding witness, before the first stop call: no reclaim ran, so the device's references stand.
    let before = outstanding(&burst, &arena, &mut core, &staged);
    eprintln!("outstanding before stop: {before:?}");
    assert!(
        before.nic_held > 0,
        "the sent frames' headers are device-held"
    );
    // The driver populates `ring - 1` descriptors at queue start and keeps one open, so head and tail differ while the ring is full.
    assert_eq!(
        before.posted + 1,
        before.rx_ring,
        "the receive ring is fully posted"
    );
    assert_eq!(before.recoveries, 0);
    assert_eq!(
        (before.sources_held, before.writable),
        (staged.len(), 0),
        "the registered source bytes are device-held and hand out no writable view"
    );
    assert_eq!(contained.requests(), 0, "no containment before the stop");
    let watchdog = Watchdog::arm(Duration::from_secs(60), contained.clone()).unwrap();
    let mut port = burst.into_port();
    let stopped = match stop_port_watched(&mut port, &watchdog) {
        Ok(stopped) => stopped,
        Err(failure) => {
            let held: Vec<_> = pools.iter().map(PacketMempool::report).collect();
            let census = (
                arena.report(PoolKind::PacketHeader).nic_held,
                arena.report(PoolKind::PacketReceive).posted,
                sources(&mut core, &staged),
            );
            eprintln!(
                "stop failed ({failure:?}): pool reports {held:?}, header nic_held, receive posted, sources (held, writable) {census:?}"
            );
            drop(watchdog);
            assert!(
                contained.requests() > 0,
                "the failed stop asked for containment"
            );
            if failure == StopFailure::Unproven {
                assert!(
                    port.device_lease().is_some(),
                    "an unproven stop keeps the lease"
                );
                assert_eq!(
                    census.2,
                    (staged.len(), 0),
                    "an unproven stop keeps the source references"
                );
            }
            panic!("the stop failed ({failure:?}); the memory the device may reach stays held");
        }
    };
    let command = port.command().expect("the command register reads back");
    eprintln!("stop proven; command register read-back {command:#06x}");
    assert_eq!(
        command & BUS_MASTER,
        0,
        "the stop certificate reads bus mastering clear"
    );
    drop(watchdog);
    assert_eq!(
        contained.requests(),
        0,
        "the joined watchdog and the port asked for no containment through the stop and its certificate read"
    );
    let after = (
        arena.report(PoolKind::PacketHeader).nic_held,
        arena.report(PoolKind::PacketReceive).posted,
    );
    eprintln!(
        "returns after stop: header nic_held {}, receive posted {}",
        after.0, after.1
    );
    assert_eq!(
        after,
        (0, 0),
        "the stop returned every header and receive buffer"
    );
    check_source_release(&mut core, &mut requests, id, &staged);
    let _undone = release_stopped(port, stopped, pools, registration, &arena);
    finish(env);
    drop(view);
}

/// The outstanding-stop schedule over the mock port, which posts `ring - 1`
/// receive buffers at its restart and holds every accepted chain until its
/// stop: the sent headers and the source bytes are device-held and
/// unwritable before the stop with the ring fully posted, the proven stop
/// returns every header and receive buffer, and the sources free only once
/// the upload ended.
#[test]
fn the_outstanding_stop_schedule_holds_sources_over_the_mock_port() {
    let arena = mock::arena();
    let header = mock::arena_pool(arena, PoolKind::PacketHeader, Role::Header);
    let payload_pool = mock::payload_pool(arena, mock::COUNT);
    let receive = mock::arena_pool(arena, PoolKind::PacketReceive, Role::Receive);
    let mut port = MockPort {
        receive: Some(receive.state),
        ..MockPort::open()
    };
    port.start().expect("the mock posts its receive ring");
    let local = Station {
        port: CLIENT_PORT,
        ports: 1,
        ..super::composed_tests::LOCAL
    };
    let peer = Station {
        port: OWNER_PORT,
        ..super::composed_tests::PEER
    };
    let wire = Wire::new(
        local,
        std::slice::from_ref(&peer),
        &mut EngineBudget::unlimited(),
    )
    .unwrap();
    let translation = Box::leak(Box::new(Forged(iova, || true)));
    let mut burst = Burst::new(
        port,
        wire,
        [header.state, payload_pool.state, receive.state],
        translation,
        recovery_watch(),
        BATCH,
        &mut EngineBudget::unlimited(),
    )
    .unwrap();
    let mut budget = EngineBudget::new(1 << 24);
    let releases = Releases::new(4, &mut budget).unwrap();
    let (mut requests, mut core, id) = staged_upload(arena, &releases, &mut budget, 0x5501);
    let (staged, taken) = send_data(&mut core, &mut requests, &mut burst);
    assert_eq!((staged.len(), taken), (2, 2));
    let before = outstanding(&burst, arena, &mut core, &staged);
    assert!(before.nic_held > 0, "{before:?}");
    assert_eq!(before.posted + 1, before.rx_ring, "{before:?}");
    assert_eq!(
        (before.recoveries, before.sources_held, before.writable),
        (0, 2, 0),
        "{before:?}"
    );
    burst.port_mut().stop().expect("the mock proves its stop");
    assert_eq!(
        (
            arena.report(PoolKind::PacketHeader).nic_held,
            arena.report(PoolKind::PacketReceive).posted
        ),
        (0, 0)
    );
    check_source_release(&mut core, &mut requests, id, &staged);
}

/// The owner serves three bodies, one of them many frames, to the client over
/// its ENA port until the serving time passes, completing every GET with no
/// failed frame or unsendable datagram, each datagram from the source port
/// its request slot selects, then closes, drains, shuts down and tears down
/// in order. A SIGTERM ends the serving early: the test then proves the
/// close, the drain and the teardown, skips the GET count, and prints a line
/// that starts `close requested by SIGTERM`, which the hardware lane reads as
/// a cut-short run that earns no credit.
#[test]
#[ignore = "needs the host pair's dataplane ENIs bound by kestrike-bind, named by KESTRIKE_MAPPINGS"]
fn the_owner_serves() {
    let (mappings, _lock) = mappings();
    let seconds: u64 =
        std::env::var("KESTRIKE_SERVE_SECONDS").map_or(300, |text| text.parse().unwrap());
    dataplane!(mappings, env, arena, registration, view, pools, port);
    let (local, peers) = stations(&mappings, OWNER_PORT, &[(peer(), CLIENT_PORT)]).unwrap();
    let wire = Wire::new(local, &peers, &mut EngineBudget::unlimited()).unwrap();
    let storage = heap_storage_on(3 << 20, 512 << 10);
    let mut device = Device::new(&storage, &arena);
    for n in 0..BODIES.len() {
        publish(
            &storage,
            &mut device,
            &key(n as u8 + 1),
            METADATA,
            &object(n),
        );
    }
    let Device { volume, control } = device;
    let cache = storage.issue_cache().unwrap();
    let cache_registration = cache.register().unwrap();
    let allowances = port.allowances();
    let burst = Burst::over(
        port,
        wire,
        [&pools[0], &pools[1], &pools[2]],
        &registration,
        recovery_watch(),
        BATCH,
        &mut EngineBudget::unlimited(),
    )
    .unwrap();
    let mut owner = Owner::start(
        OWNER,
        Bundle {
            cache,
            registration: cache_registration,
            volume,
        },
        Keys {
            principals: &PRINCIPALS[..1],
            entries: &entries()[..1],
            epoch: 1,
            put: &[],
        },
        burst,
        &view,
        &mut EngineBudget::new(1 << 26),
    )
    .map_err(|refused| refused.error)
    .unwrap();
    let start = Instant::now();
    let mut serving = Serving::start(Duration::from_secs(seconds));
    while serving.keep() {
        control.tick(64);
        owner.poll(now_us(start));
    }
    // A SIGTERM closes the owner at once, before the clients' rounds finished. The loop's end returns the
    // inherited SIGTERM action, so a signal during the drain or the teardown takes its ordinary course.
    let signalled = serving.signalled();
    drop(serving);
    let closing = Instant::now();
    let _ = owner.close(now_us(start));
    while owner.blockers().is_some() {
        assert!(closing.elapsed() < PATIENCE, "the owner drained");
        control.tick(64);
        owner.poll(now_us(start));
    }
    let (served, report) = (owner.serve_report(), owner.report());
    eprintln!("owner report {report:?} serve report {served:?}");
    assert!(
        signalled || served.completed >= (ROUNDS * BODIES.len()) as u64,
        "every GET completed"
    );
    assert_eq!((report.failed, report.defects), (0, 0));
    let burst = owner.shutdown().map_err(|_| "shut down").unwrap().transport;
    let sent = burst.report();
    eprintln!("burst report {sent:?}");
    assert_eq!(burst.link(), Link::Up);
    assert_eq!(
        (sent.unsendable, sent.quarantined, sent.prepare_refused),
        (0, 0, 0)
    );
    assert!(
        sent.sources.iter().sum::<u64>() >= sent.sent,
        "every datagram left from the source port its request slot selects"
    );
    let port = burst.into_port();
    eprintln!(
        "allowances before {allowances:?} after {:?}",
        port.allowances()
    );
    let _undone = teardown(port, pools, registration, &arena);
    finish(env);
}

/// One GET a round completed: its request, the `turn` time after the poll
/// that completed it and the SHA-256 of the bytes it returned.
struct Fetched {
    id: RequestId,
    done_us: u64,
    sha256: [u8; 32],
}

/// `turn` must poll the client once and return monotonic time in
/// microseconds taken after that poll.
fn fetch_round<'m, D: Datagrams<'m>>(
    client: &mut Client<'m, D>,
    round: usize,
    held: &mut Vec<FragmentLease<'m>>,
    turn: &mut impl FnMut(&mut Client<'m, D>) -> u64,
) -> Vec<Fetched> {
    let patience = u64::try_from(PATIENCE.as_micros()).unwrap();
    let mut fetched = Vec::with_capacity(BODIES.len());
    for n in 0..BODIES.len() {
        let begun = turn(client);
        let id = client
            .get(key(n as u8 + 1), 64, 1 << 20, begun, 30_000_000)
            .unwrap();
        let mut bytes = Vec::new();
        loop {
            let now = turn(client);
            assert!(now - begun < patience, "round {round} body {n} finished");
            while let Some(fragment) = client.take(id) {
                assert_eq!(fragment.offset(), bytes.len() as u64, "in order");
                bytes.extend_from_slice(fragment.bytes());
                if round == 0 && fragment.offset() == 0 {
                    held.push(fragment);
                }
            }
            if let Some(outcome) = client.outcome(id) {
                assert_eq!(outcome, Outcome::Complete, "round {round} body {n}");
                fetched.push(Fetched {
                    id,
                    done_us: now,
                    sha256: Sha256::digest(&bytes).into(),
                });
                break;
            }
        }
        assert_eq!(bytes, object(n), "round {round} body {n} is exact");
        while !client.retire(id) {
            turn(client);
        }
    }
    fetched
}

/// The lowercase hex of `bytes`.
pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn poll_since<'m, D: Datagrams<'m>>(start: Instant) -> impl FnMut(&mut Client<'m, D>) -> u64 {
    move |client| {
        client.poll(now_us(start));
        now_us(start)
    }
}

/// A transport that delays each receive by at least two milliseconds, so a
/// time sampled before a poll and one sampled after it differ.
struct Slow;

impl Datagrams<'_> for Slow {
    fn receive<'p>(
        &mut self,
        _: &'p PacketPool<'p>,
        _: &mut [Option<super::packet::PacketLease<'p>>],
        _: &mut [super::datagram::Received],
    ) -> Result<usize, super::datagram::DatagramError> {
        std::thread::sleep(Duration::from_millis(2));
        Ok(0)
    }

    fn rx_ring(&self) -> u32 {
        0
    }

    fn reclaim(&mut self) {}

    fn send(
        &mut self,
        batch: &[Outgoing<'_, '_>],
    ) -> Result<usize, super::datagram::DatagramError> {
        Ok(batch.len())
    }
}

/// The closure [`poll_since`] returns timestamps each turn after polling, so
/// a completion the poll reveals is dated once it was observable.
#[test]
fn a_turn_is_timed_after_its_poll() {
    let pool = super::packet::test_pool(40, 8).unwrap();
    let mut budget = EngineBudget::new(1 << 24);
    let releases = Releases::new(4, &mut budget).unwrap();
    let memory = ClientMemory {
        receive: &pool,
        releases: &releases,
        requests: RequestTable::new(4, 1, 4),
        sources: Box::default(),
        routes: super::client_tests::routes(),
    };
    let keys = [entries()[0]];
    let mut client =
        Client::initialize(client_config(0), memory, Slow, &keys, 1, &mut budget).unwrap();
    let start = Instant::now();
    let mut turn = poll_since(start);
    let before = now_us(start);
    let at = turn(&mut client);
    assert!(
        at >= before + 2_000,
        "the turn time {at} us follows the two millisecond poll begun at or after {before} us"
    );
}

/// Each call is one [`drive`] turn of 100 µs from turn 0.
fn simulated<'m>(
    owner: &mut TestOwner<'_, '_, '_>,
    control: &SimControl,
    nets: &[Rc<RefCell<Net<'_>>>],
) -> impl FnMut(&mut Client<'m, LinkEnd<'m>>) -> u64 {
    let mut at = 0;
    move |client| {
        let now = at * 100;
        at = drive(&mut [client], &mut *owner, control, nets, at, 1, |_| false);
        now
    }
}

fn check_held(held: &[FragmentLease<'_>]) {
    assert_eq!(
        held.len(),
        BODIES.len(),
        "round 0 held each body's first fragment"
    );
    for (n, lease) in held.iter().enumerate() {
        let body = object(n);
        assert_eq!(
            lease.bytes(),
            &body[..lease.bytes().len()],
            "a held first-round lease is unchanged"
        );
    }
}

/// Resets the client's port, requires an in-place recovery with the link up,
/// the low-latency placement unchanged and a recorded pause, then runs
/// `round` and requires its first GET to complete with exact bytes within
/// `bound` of the end of the reset turns, printing the reset and that GET as the reset
/// profile's conjunction reads them.
fn reset_then_fetch<'m, 'e>(
    client: &mut Client<'m, Burst<'m, EnaPort<'e>>>,
    round: usize,
    held: &mut Vec<FragmentLease<'m>>,
    turn: &mut impl FnMut(&mut Client<'m, Burst<'m, EnaPort<'e>>>) -> u64,
    bound: Duration,
) {
    let llq = client.transport().port().report().llq;
    // Service reads the flag on one of these `CAUSE_TURNS` turns.
    client.transport().port().request_reset();
    let mut recovered_us = 0;
    for _ in 0..CAUSE_TURNS {
        recovered_us = turn(client);
    }
    let report = client.transport().report();
    assert_eq!(
        (client.transport().link(), report.resets, report.recoveries),
        (Link::Up, 1, 1),
        "the reset recovered in place"
    );
    assert_eq!(client.transport().port().report().llq, llq);
    assert!(report.pause_us > 0, "the recovery recorded its pause");
    eprintln!(
        "observe: reset {} recovered link up llq unchanged pause {} us",
        report.resets, report.pause_us
    );
    let first = fetch_round(client, round, held, turn).remove(0);
    let after_us = first.done_us - recovered_us;
    assert!(
        u128::from(after_us) <= bound.as_micros(),
        "the post-reset GET completed in {after_us} us, past its {bound:?} bound"
    );
    eprintln!(
        "observe: post-reset-get after reset {} sha256 {} outcome complete within {} ms request {:?} after {after_us} us",
        report.resets,
        hex(&first.sha256),
        bound.as_millis(),
        first.id
    );
}

/// The client fetches every body for its rounds, holding each body's first
/// fragment from round 0. Under `KESTRIKE_ALLOW_RESET=1` it resets its
/// port halfway: the reset must recover in place with the link up and the
/// low-latency placement unchanged, printing `observe: reset N recovered`
/// with the pause, and the round's first GET must then return exact bytes
/// within the `KESTRIKE_POST_RESET_GET_MS` bound, printing `observe:
/// post-reset-get after reset N` with its request, bytes digest and outcome,
/// so the reset profile's conjunction binds the reset and the GET to one
/// episode.
#[test]
#[ignore = "needs the host pair's dataplane ENIs bound by kestrike-bind, named by KESTRIKE_MAPPINGS"]
fn the_client_fetches() {
    let reset_round = std::env::var("KESTRIKE_ALLOW_RESET").as_deref() == Ok("1");
    let post_reset_bound = reset_round.then(|| {
        Duration::from_millis(
            std::env::var("KESTRIKE_POST_RESET_GET_MS")
                .expect("a reset round needs KESTRIKE_POST_RESET_GET_MS, the post-reset GET bound")
                .parse()
                .expect("the post-reset GET bound is a whole number of milliseconds"),
        )
    });
    let (mappings, _lock) = mappings();
    dataplane!(mappings, env, arena, registration, view, pools, port);
    let (local, peers) = stations(&mappings, CLIENT_PORT, &[(peer(), OWNER_PORT)]).unwrap();
    let wire = Wire::new(local, &peers, &mut EngineBudget::unlimited()).unwrap();
    let allowances = port.allowances();
    let burst = Burst::over(
        port,
        wire,
        [&pools[0], &pools[1], &pools[2]],
        &registration,
        recovery_watch(),
        BATCH,
        &mut EngineBudget::unlimited(),
    )
    .unwrap();
    let mut budget = EngineBudget::new(1 << 24);
    let releases = Releases::new(4, &mut budget).unwrap();
    let memory = ClientMemory {
        receive: &view,
        releases: &releases,
        requests: RequestTable::new(4, 1, 4),
        sources: Box::default(),
        routes: super::client_tests::routes(),
    };
    let keys = [entries()[0]];
    let mut client =
        Client::initialize(client_config(0), memory, burst, &keys, 1, &mut budget).unwrap();
    let start = Instant::now();
    client.session(now_us(start));
    while client.state() != SessionState::Active {
        assert!(start.elapsed() < PATIENCE, "the session opened");
        client.poll(now_us(start));
    }
    let mut turn = poll_since(start);
    let mut held = Vec::new();
    for round in 0..ROUNDS {
        if round == ROUNDS / 2
            && let Some(bound) = post_reset_bound
        {
            reset_then_fetch(&mut client, round, &mut held, &mut turn, bound);
        } else {
            fetch_round(&mut client, round, &mut held, &mut turn);
        }
    }
    check_held(&held);
    drop((held, turn));
    let (report, burst) = client.close(now_us(start));
    assert!(!report.blocked);
    let sent = burst.report();
    eprintln!("burst report {sent:?}");
    assert_eq!(burst.link(), Link::Up);
    assert!(
        sent.sources.iter().sum::<u64>() >= sent.sent,
        "every datagram left from the source port its request slot selects"
    );
    assert_eq!(sent.recoveries, u64::from(post_reset_bound.is_some()));
    let port = burst.into_port();
    eprintln!(
        "allowances before {allowances:?} after {:?}",
        port.allowances()
    );
    let _undone = teardown(port, pools, registration, &arena);
    finish(env);
}

/// The reset profile's conjunction names the digest of the bytes the
/// post-reset GET must return, the first body's object, so the judge holds
/// the GET to those exact bytes after reset 1 within the declared bound.
#[test]
fn the_reset_profile_names_the_digest_of_the_first_body() {
    let manifest = include_str!("../../../../scripts/hardware-profiles.json");
    let entry = format!(
        "\"client:post-reset-get after reset 1 sha256 {} outcome complete within {{KESTRIKE_POST_RESET_GET_MS}} ms request \"",
        hex(&Sha256::digest(object(0)))
    );
    assert!(manifest.contains(&entry), "the reset profile names {entry}");
}

#[test]
fn the_client_rounds_complete_against_an_in_memory_owner() {
    let storage = heap_storage_on(3 << 20, 512 << 10);
    let buffers = arena_on(TestPlatform::heap(4096), 8, 5);
    let receive = owner_pool();
    let client_pool = owner_pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 1, [Faults::default(); 2]);
    let objects: Vec<Vec<u8>> = (0..BODIES.len()).map(object).collect();
    let published: Vec<([u8; 32], usize, &[u8])> = objects
        .iter()
        .enumerate()
        .map(|(n, body)| (key(n as u8 + 1), METADATA, body.as_slice()))
        .collect();
    let (mut owner, control) = start(&storage, &buffers, &receive, &published, vec![owner_end]);
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let mut turn = simulated(&mut owner, &control, &nets);
    client.session(0);
    while client.state() != SessionState::Active {
        assert!(turn(&mut client) < 1_000_000, "the session opened");
    }
    let mut held = Vec::new();
    for round in 0..ROUNDS {
        fetch_round(&mut client, round, &mut held, &mut turn);
    }
    check_held(&held);
}

/// In-place recovery on the device through the burst logic: a reset event
/// stops admission, the stop is proven, the registration rechecked, the
/// function reset, the driver re-initialized with the same low-latency
/// placement, and the port restarted, with its pause recorded; service then
/// stays running and the ordered teardown follows. It resets the device, so
/// it runs only under `KESTRIKE_ALLOW_RESET=1`; the client test's reset
/// round proves frames flow after recovery.
#[test]
#[ignore = "resets the dataplane ENI; needs KESTRIKE_ALLOW_RESET=1, KESTRIKE_MAPPINGS and KESTRIKE_PEER"]
fn the_port_recovers_in_place() {
    assert_eq!(
        std::env::var("KESTRIKE_ALLOW_RESET").as_deref(),
        Ok("1"),
        "a device reset needs separate approval"
    );
    let (mappings, _lock) = mappings();
    dataplane!(mappings, env, arena, registration, view, pools, port);
    let before = port.report();
    let (local, peers) = stations(&mappings, CLIENT_PORT, &[(peer(), OWNER_PORT)]).unwrap();
    let wire = Wire::new(local, &peers, &mut EngineBudget::unlimited()).unwrap();
    let mut burst = Burst::over(
        port,
        wire,
        [&pools[0], &pools[1], &pools[2]],
        &registration,
        recovery_watch(),
        BATCH,
        &mut EngineBudget::unlimited(),
    )
    .unwrap();
    burst.port().request_reset();
    crate::net::Datagrams::reclaim(&mut burst);
    let report = burst.report();
    eprintln!("recovery pause {} us", report.pause_us);
    assert_eq!(
        (burst.link(), report.resets, report.recoveries),
        (Link::Up, 1, 1)
    );
    assert_eq!(
        (
            report.episode.reached,
            report.episode.expired_at,
            report.episode.containment_requested
        ),
        (Some(RecoveryStage::Restart), None, false),
        "every stage ran under the watchdog, which the episode disarmed"
    );
    // The restart re-probes and requires the attach-time placement; a recovery counts only when it matched.
    assert_eq!(burst.port().report().llq, before.llq);
    for _ in 0..1_000 {
        crate::net::Datagrams::reclaim(&mut burst);
    }
    assert_eq!(
        burst.report().resets,
        1,
        "service stays running after the restart"
    );
    let port = burst.into_port();
    let _undone = teardown(port, pools, registration, &arena);
    finish(env);
    drop(view);
}
