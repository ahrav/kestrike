//! The complete bypass stack on the approved host pair: an owner serves
//! records read from its EBS volume through the SPDK driver over its ENA
//! port, and the client fetches them through its own, each over the one
//! shared registration of its arena.
//!
//! The host-pair tests are ignored by default and require
//! `KESTRIKE_MAPPINGS` to name the mappings file `kestrike-bind` wrote.
//! The owner's volume attach takes its session from the soak store in that
//! state directory, as the soak and the SPDK volume tests do, so the owner's
//! state directory is a persistent 0700 directory of the running user under
//! ancestors only root or that user can write, outside `/run` and
//! `/var/run`, such as `/var/lib/kestrike/owner-1`. Each owner process binds its volume and ENI into its
//! own state directory, and each client process its ENI; each process runs
//! as root, pinned to its own core with `taskset`, with hugepages reserved.
//! At a client, `KESTRIKE_PEER` names the owner's ENI address and
//! `KESTRIKE_CLIENT` the client's index among the owner's peers (0 by
//! default); at an owner, `KESTRIKE_PEER` lists its clients' ENI
//! addresses, comma-separated, in index order. Start the owner, which serves
//! for `KESTRIKE_SERVE_SECONDS` (600 by default), then the client:
//!
//! ```text
//! sudo KESTRIKE_MAPPINGS=/var/lib/kestrike/owner-1/mappings KESTRIKE_PEER=<client ENI IPv4> \
//!     taskset -c 2 target/debug/deps/kestrike-<hash> --ignored net::host_pair_tests::the_owner_serves_the_volume --nocapture
//! sudo KESTRIKE_MAPPINGS=/run/kestrike/mappings KESTRIKE_PEER=<owner ENI IPv4> \
//!     taskset -c 2 target/debug/deps/kestrike-<hash> --ignored net::host_pair_tests::the_client_fetches_the_volume --nocapture
//! ```
//!
//! For the PUT run, the owner lists both client addresses in
//! `KESTRIKE_PEER` and grants each PUT. On the client host two processes
//! run, each with its own ENI bound into its own state directory, its own
//! `KESTRIKE_MAPPINGS` and its own core:
//! `net::host_pair_tests::the_client_puts_an_object_onto_the_volume` with
//! `KESTRIKE_CLIENT=0`, and, once it logged the PUT `Published`,
//! `net::host_pair_tests::an_independent_client_reads_the_put_back` with
//! `KESTRIKE_CLIENT=1`, within the owner's serve time. The owner writes
//! the PUT to its volume; the reader compares it against bytes it generates
//! itself.
//!
//! For the two-owner runs, each owner binds into its own state directory
//! with `kestrike-bind --state-dir <own> --other-state-dir <other>
//! --volume <id> --eni <id> --peer <client 0> --peer <client 1>`, and each
//! client its ENI with `--peer` for both owners. Start the two owners from
//! their own cores, each listing both client addresses, record
//! `HugePages_Free` from `/proc/meminfo` with both running, then two client processes
//! on the client host, each on its own ENI and core, running
//! `net::host_pair_tests::the_client_fetches_from_two_owners` with
//! `KESTRIKE_CLIENT` 0 and 1 and `KESTRIKE_PEERS` naming the two
//! owners in opposite orders, so both owners serve GETs at once. Each
//! client runs for `KESTRIKE_CLIENT_SECONDS` (900 by default), longer
//! than the owners serve. `KESTRIKE_STOPPED` names, by its index in the
//! client's `KESTRIKE_PEERS`, the owner that stops first, so the two
//! clients give opposite indices. In the first
//! run that owner has a shorter `KESTRIKE_SERVE_SECONDS` and stops
//! cleanly; in the second it is killed with `SIGKILL` while the clients
//! cycle. While the clients still cycle, `kestrike-bind --release
//! --state-dir` of the stopped owner's directory restores its devices,
//! `readlink /sys/bus/pci/devices/<bdf>/driver` shows the other owner's
//! controller and ENI still on `vfio-pci`, and the other owner keeps
//! serving exact bytes. The owner overwrites its volume's records. Once a
//! host's processes exited, `kestrike-bind --release --state-dir <dir>`
//! for each of its state directories returns its devices to their kernel
//! drivers.

mod hit_gate;

use std::cell::RefCell;
use std::net::Ipv4Addr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::Datagrams;
use super::adapters::{ID, fills_written};
use super::client::{Client, ClientMemory, GetRefused, SessionState};
use super::ena_hardware_tests::{
    BATCH, CLIENT_PORT, OWNER_PORT, PATIENCE, POOLS, RECEIVE, RESERVE, SPDK, Unexpected, arena,
    check_page_edges, check_report, dataplane, environment, finish, mappings, now_us, peer,
    recovery_watch, reservations, teardown,
};
use super::fetch::{FragmentLease, Outcome, Releases};
use super::frame::Status;
use super::geometry::FRAGMENT_LEN;
use super::link::{Faults, LinkEnd, Net, TxRelease, network};
use super::observe::Cuts;
use super::owner::{Bundle, Keys, Owner, Shutdown};
use super::owner_tests::{
    OWNER, PRINCIPALS, TestOwner, client_config, entries, key, payload, pool, start,
};
use super::packet::PacketPool;
use super::requests::{RequestId, RequestTable};
use super::serving::Serving;
use super::upload::{PrepareRefused, SourceSlot, SupplyRefused, UploadOutcome};
use crate::bind::Host;
use crate::native::{
    ArenaRegistration, Burst, DmaPolicy, EnaPort, PacketMempool, Port, Station, Wire, attach_port,
    start_port, stations,
};
use crate::oracle::MAX_KEYS;
use crate::oracle::{
    ActionKind, CommandEvidence, KeyId, Label, Obligation, Outcome as OracleOutcome,
    Owner as OracleOwner, Recorder, Verdict,
};
use crate::sim::round::{Act, Actor, round};
use crate::storage::device::scripted_reserving;
use crate::storage::owner_fixture::{
    SimControl, TestPlatform, arena_on, hardware_storage_on, heap_storage_on,
    heap_storage_with_metadata_on, reserve,
};
use crate::storage::{
    BufferArena, BufferConfig, Disk, EngineBudget, HugepageSize, NodeMask, PoolKind, QuiesceStatus,
    Released, TickConfig, Volume, WorkBudget,
};

/// The body and metadata lengths of the served records, keyed `key(n)` for
/// position `n` from 1: the three body sizes of the suite, the largest of
/// them within one extent, and one record of exactly 8,192 bytes on the
/// device. The final record occupies 8,192 bytes including its 116-byte
/// header: 108 fixed bytes and a two-entry chunk table.
const RECORDS: [(usize, usize); 4] = [(8_192, 48), (15_743, 48), (241_011, 48), (8_192 - 116, 0)];
const ROUNDS: usize = 3;
const TICK: TickConfig = TickConfig {
    submit_burst: 8,
    terminal_burst: 8,
    validate_bytes: 1 << 20,
};
const SESSION: u64 = 0x4b36;
/// Payload bytes of the storage's volume; `test_volume` adds two `IO_UNIT`s of metadata prefix.
const RAW: usize = 64 << 20;
const BODY_CAP: usize = 512 << 10;
/// The client's silence after its first round, during which the owner drains on transmit reclamation alone.
const QUIET: Duration = Duration::from_secs(2);
/// How long the client keeps fetching for the owner's close to meet GETs in flight.
const TAIL: Duration = Duration::from_secs(900);

/// Record `n`'s bytes, the oracle's content for its key and label in the corpus history.
fn record(n: usize) -> Vec<u8> {
    let (body, metadata) = RECORDS[n];
    Recorder::content(key_id(n), label(n), metadata as u32, body as u64)
}

#[test]
fn the_last_record_fills_exactly_8192_bytes() {
    let (body, metadata) = RECORDS[3];
    let layout = crate::storage::RecordConfig { chunk_len: 8192 }
        .validate()
        .unwrap()
        .layout(metadata as u32, body as u32);
    assert_eq!(layout.record_len(), 8192);
}

#[test]
fn the_host_pair_owner_keeps_a_write_command_per_peer() {
    let config = BufferConfig {
        hugepage: HugepageSize::TwoMiB,
        nodes: NodeMask::from_nodes(&[0]).unwrap(),
        pools: &POOLS,
    };
    let arena = BufferArena::initialize(
        &config.validate().unwrap(),
        TestPlatform::heap(4096),
        &mut EngineBudget::unlimited(),
    )
    .unwrap();
    let storage = hardware_storage_on(RAW, BODY_CAP, PUT_METADATA);
    let disk = scripted_reserving(
        "scripted:host-pair-write-share",
        SPDK.queue_depth,
        reservations(),
    );
    let volume = Volume::attach(
        &storage,
        &arena,
        disk,
        crate::storage::portable::scripted::ScriptedClock::trusted(),
        crate::storage::ServingAuthority::fixture_limits(
            crate::storage::ReservationLimits::new(2, 2, 10, 10).unwrap(),
        ),
        u16::try_from(SPDK.queue_depth).unwrap(),
        TICK,
        &mut EngineBudget::new(1 << 24),
    )
    .map_err(|(error, _)| error)
    .unwrap();
    assert!(
        volume.write_share() as usize >= PRINCIPALS.len(),
        "write share {} covers {} peers, the Owner::start put check",
        volume.write_share(),
        PRINCIPALS.len()
    );
}

/// The owner attaches its volume's controller and its ENA port to one
/// registration, verifies it, passes the storage canary and starts the port;
/// it publishes every record through the volume, writes the PUT a granted
/// client sends to the volume, and serves them until its
/// time passes, requiring, when it serves one client, that some request
/// drained while no frame arrived, through transmit reclamation alone. It then closes once a request is
/// live, meeting requests whose reads or device references are in flight,
/// quiesces the controller to its stop, proves the
/// controller's and the port's stops before undoing the registration,
/// detaches the controller, finishes the environment and releases the arena.
/// A SIGTERM ends the serving early: the test then proves the close, the
/// drain and the teardown, and skips the serving checks; it prints a line
/// that starts `close requested by SIGTERM`, which the hardware lane reads
/// as a cut-short run that earns no credit.
#[test]
#[ignore = "needs the host pair's devices bound by kestrike-bind, named by KESTRIKE_MAPPINGS"]
fn the_owner_serves_the_volume() {
    let (mappings, mut lock) = mappings();
    let authority = crate::soak::tenure_authority(&mut lock);
    let seconds: u64 =
        std::env::var("KESTRIKE_SERVE_SECONDS").map_or(600, |text| text.parse().unwrap());
    // SAFETY: reads this thread's CPU.
    let core = unsafe { libc::sched_getcpu() };
    eprintln!(
        "owner on core {core}, state directory {:?}",
        std::env::var("KESTRIKE_MAPPINGS")
    );
    dataplane!(
        mappings,
        env,
        arena,
        registration,
        view,
        pools,
        port,
        disk = disk,
        lock
    );
    let allowances = port.allowances();
    let storage = hardware_storage_on(RAW, BODY_CAP, PUT_METADATA);
    let mut volume = Volume::attach(
        &storage,
        &arena,
        disk,
        crate::storage::portable::scripted::ScriptedClock::trusted(),
        authority,
        u16::try_from(SPDK.queue_depth).unwrap(),
        TICK,
        &mut EngineBudget::new(1 << 24),
    )
    .map_err(|(error, _)| error)
    .unwrap();
    crate::storage::owner_fixture::open_polled(&mut volume, 1 << 20);
    eprintln!("read shape {:?}", volume.read_shape());
    let cache = storage.issue_cache().unwrap();
    let cache_registration = cache.register().unwrap();
    let clients = peers();
    assert!(
        (1..=PRINCIPALS.len()).contains(&clients.len()),
        "one or two clients"
    );
    let addressed: Vec<_> = clients.iter().map(|&ip| (ip, CLIENT_PORT)).collect();
    let burst = over(
        port,
        route(&mappings, OWNER_PORT, &addressed),
        &pools,
        &registration,
    );
    let mut owner = Owner::start(
        OWNER,
        Bundle {
            cache,
            registration: cache_registration,
            volume,
        },
        Keys {
            principals: &PRINCIPALS[..clients.len()],
            entries: &entries()[..clients.len()],
            epoch: 1,
            put: &PRINCIPALS[..clients.len()],
        },
        burst,
        &view,
        &mut EngineBudget::new(1 << 26),
    )
    .map_err(|refused| refused.error)
    .unwrap();
    let start = Instant::now();
    for (n, &(body, metadata)) in RECORDS.iter().enumerate() {
        let bytes = record(n);
        let mut fill = reserve(&storage, &key(n as u8 + 1), metadata, body).expect("a fill");
        let mut taken = 0;
        while !owner.fill_progress(&fill).is_ready() {
            assert!(
                !owner.fill_progress(&fill).failed,
                "every write of record {n} succeeds"
            );
            if taken < bytes.len()
                && let Ok(count) = owner.receive_fill(
                    &mut fill,
                    &bytes[taken..],
                    &mut crate::storage::WorkBudget::with_io(0, usize::MAX, usize::MAX),
                )
            {
                taken += count;
            }
            owner.poll(now_us(start));
            assert!(start.elapsed() < PATIENCE, "record {n}'s writes finished");
        }
        drop(
            owner
                .publish_fill(fill, u64::MAX, 4, &mut WorkBudget::new(1 << 16))
                .unwrap(),
        );
        eprintln!("record {n}: metadata {metadata} body {body}");
    }
    let mut serving = Serving::start(Duration::from_secs(seconds));
    let mut quiet = QuietDrains::default();
    let mut returns = pools[1].report().returned;
    while serving.keep() {
        let before = owner.report().received;
        owner.poll(now_us(start));
        let census = owner.census();
        let returned = pools[1].report().returned;
        if let Some(run_us) = quiet.observe(
            now_us(start),
            owner.report().received != before,
            census.active + census.draining > 0,
            returned != returns,
        ) {
            eprintln!("drained {run_us} us after the last frame arrived");
        }
        returns = returned;
    }
    // A SIGTERM closes the owner at once, against whatever work is in flight. The loop's end returns the
    // inherited SIGTERM action, so a signal during the drain or the teardown takes its ordinary course.
    let signalled = serving.signalled();
    drop(serving);
    // A single client's silence after its first round leaves the owner frameless; two clients keep frames arriving.
    if clients.len() == 1 && !signalled {
        assert!(
            quiet.drains > 0,
            "requests drain with no further incoming frame"
        );
    }
    let closing = Instant::now();
    while owner.census().active == 0 && !signalled {
        assert!(
            closing.elapsed() < PATIENCE,
            "a GET arrived to close against"
        );
        owner.poll(now_us(start));
    }
    let first = owner.close(now_us(start));
    let met = owner.blockers();
    eprintln!("close met {first:?} with {met:?}");
    if !signalled {
        let met = met.expect("the close met work in flight");
        assert!(
            met.census.active + met.census.draining > 0,
            "the close met requests whose reads or device references were in flight"
        );
    }
    while owner.blockers().is_some() {
        assert!(closing.elapsed() < PATIENCE, "the owner drained");
        owner.poll(now_us(start));
    }
    let (served, report) = (owner.serve_report(), owner.report());
    eprintln!(
        "owner {report:?} serve {served:?} volume {:?}",
        owner.volume_report()
    );
    assert!(
        signalled || served.completed >= (ROUNDS * RECORDS.len()) as u64,
        "every GET completed"
    );
    assert_eq!((report.failed, report.defects), (0, 0));
    let Shutdown {
        cache,
        registration: cache_registration,
        mut disk,
        transport: burst,
        ..
    } = owner.shutdown().map_err(|_| "shut down").unwrap();
    drop((cache, cache_registration));
    // A quiesce that found nothing outstanding leaves the controller enabled; its stop proof needs the disable.
    let stopping = Instant::now();
    loop {
        match disk.quiesce() {
            QuiesceStatus::Stopped => break,
            QuiesceStatus::Failed(error) => panic!("the controller's disable failed: {error:?}"),
            QuiesceStatus::Pending => {
                assert!(stopping.elapsed() < PATIENCE, "the controller disabled");
            }
        }
    }
    let sent = burst.report();
    eprintln!("burst {sent:?}");
    let port = burst.into_port();
    eprintln!(
        "allowances before {allowances:?} after {:?}",
        port.allowances()
    );
    registration
        .device_stopped(disk.stop_proof().expect("the controller's stop is proven"))
        .expect("the stop proof is this registration's");
    let undone = teardown(port, pools, registration, &arena);
    assert!(
        disk.detach(&undone),
        "the controller detached after the undo"
    );
    drop((view, disk));
    finish(env);
    assert!(matches!(
        arena.release().map_err(|_| "held"),
        Ok(Released::Complete)
    ));
}

/// This host's station at base port `local` and its `peers`', which every
/// burst over them shares.
fn route(
    mappings: &crate::bind::Mappings,
    local: u16,
    peers: &[(Ipv4Addr, u16)],
) -> (Station, &'static [Station]) {
    let (station, stations) = stations(mappings, local, peers).unwrap();
    (station, Box::leak(stations.into_boxed_slice()))
}

/// The burst logic over `port` along `route`.
fn over<'a, 'e>(
    port: EnaPort<'e>,
    (station, stations): (Station, &'static [Station]),
    pools: &'a [PacketMempool<'_>; 3],
    registration: &'a ArenaRegistration<'_>,
) -> Burst<'a, EnaPort<'e>> {
    let wire = Wire::new(station, stations, &mut EngineBudget::unlimited()).unwrap();
    Burst::over(
        port,
        wire,
        [&pools[0], &pools[1], &pools[2]],
        registration,
        recovery_watch(),
        BATCH,
        &mut EngineBudget::unlimited(),
    )
    .unwrap()
}

/// The comma-separated addresses `KESTRIKE_PEER` names.
fn peers() -> Vec<Ipv4Addr> {
    std::env::var("KESTRIKE_PEER")
        .expect("set KESTRIKE_PEER; see the module docs")
        .split(',')
        .map(|ip| ip.trim().parse().unwrap())
        .collect()
}

/// This client's index among the owner's peers, from `KESTRIKE_CLIENT` (0 by default).
fn client_index() -> usize {
    std::env::var("KESTRIKE_CLIENT").map_or(0, |text| text.parse().unwrap())
}

trait Pump<'m, D: Datagrams<'m>> {
    /// Microseconds since the run started.
    fn now_us(&self) -> u64;
    fn turn(&mut self, client: &mut Client<'m, D>);
    /// Suspends client polling for `quiet_us` microseconds.
    fn idle(&mut self, quiet_us: u64);
    /// Records that record `n`'s GET delivered `bytes` whole.
    fn served(&mut self, _n: usize, _bytes: &[u8]) {}
    /// Ends a history window where no GET is in flight.
    fn cut(&mut self) {}
}

struct Wall {
    start: Instant,
    corpus: Corpus,
}

impl Wall {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            corpus: Corpus::new(),
        }
    }

    fn now_us(&self) -> u64 {
        now_us(self.start)
    }
}

impl<'m, D: Datagrams<'m>> Pump<'m, D> for Wall {
    fn now_us(&self) -> u64 {
        Wall::now_us(self)
    }

    fn turn(&mut self, client: &mut Client<'m, D>) {
        client.poll(Wall::now_us(self));
    }

    fn idle(&mut self, quiet_us: u64) {
        std::thread::sleep(Duration::from_micros(quiet_us));
    }

    fn served(&mut self, n: usize, bytes: &[u8]) {
        self.corpus.served(n, bytes);
    }

    fn cut(&mut self) {
        self.corpus.cut();
    }
}

const PATIENCE_US: u64 = PATIENCE.as_micros() as u64;
const QUIET_US: u64 = QUIET.as_micros() as u64;
const WAIT_US: u64 = 30_000_000;
const SLOTS: u32 = 2;

fn client<'m, D: Datagrams<'m>>(
    index: usize,
    view: &'m PacketPool<'m>,
    releases: &'m Releases,
    sources: Box<[SourceSlot<'m>]>,
    transport: D,
    pump: &mut impl Pump<'m, D>,
) -> Result<Client<'m, D>, Box<D>> {
    let memory = ClientMemory {
        receive: view,
        releases,
        requests: RequestTable::new(SLOTS, 1, SLOTS),
        sources,
        routes: super::client_tests::routes(),
    };
    let keys = [entries()[index]];
    let mut budget = EngineBudget::new(1 << 24);
    let mut client = Client::initialize(
        client_config(index),
        memory,
        transport,
        &keys,
        1,
        &mut budget,
    )
    .unwrap();
    let opening = pump.now_us();
    client.session(opening);
    while client.state() != SessionState::Active {
        if pump.now_us() - opening > PATIENCE_US {
            return Err(Box::new(client.close(pump.now_us()).1));
        }
        pump.turn(&mut client);
    }
    Ok(client)
}

fn get<'m, D: Datagrams<'m>>(
    client: &mut Client<'m, D>,
    n: usize,
    now: u64,
    wait_us: u64,
) -> Result<RequestId, GetRefused> {
    client.get(key(n as u8 + 1), 64, BODY_CAP as u32, now, wait_us)
}

struct Fetched<'m> {
    outcome: Outcome,
    bytes: Vec<u8>,
    first: Option<FragmentLease<'m>>,
}

fn fetch<'m, D: Datagrams<'m>>(
    client: &mut Client<'m, D>,
    id: RequestId,
    pump: &mut impl Pump<'m, D>,
) -> Fetched<'m> {
    let begun = pump.now_us();
    let (mut bytes, mut first) = (Vec::new(), None);
    loop {
        assert!(pump.now_us() - begun < PATIENCE_US, "the GET ended");
        pump.turn(client);
        while let Some(fragment) = client.take(id) {
            assert_eq!(fragment.offset(), bytes.len() as u64, "in order");
            bytes.extend_from_slice(fragment.bytes());
            first.get_or_insert(fragment);
        }
        if let Some(outcome) = client.outcome(id) {
            while !client.retire(id) {
                pump.turn(client);
            }
            return Fetched {
                outcome,
                bytes,
                first,
            };
        }
    }
}

fn rounds<'m, D: Datagrams<'m>>(
    client: &mut Client<'m, D>,
    pump: &mut impl Pump<'m, D>,
    wait_us: u64,
) {
    let mut held: Vec<FragmentLease<'m>> = Vec::new();
    for round in 0..ROUNDS {
        for n in 0..RECORDS.len() {
            let id = get(client, n, pump.now_us(), wait_us).unwrap();
            let fetched = fetch(client, id, pump);
            if fetched.outcome == Outcome::Complete {
                pump.served(n, &fetched.bytes);
            }
            assert_eq!(
                fetched.outcome,
                Outcome::Complete,
                "round {round} record {n}"
            );
            assert_eq!(
                fetched.bytes,
                record(n),
                "round {round} record {n} is exact"
            );
            eprintln!("round {round} record {n}: {} bytes", fetched.bytes.len());
            if round == 0 {
                held.push(fetched.first.expect("a fragment"));
            }
        }
        if round == 0 {
            abandon(client, pump, wait_us);
        }
        pump.cut();
    }
    for (n, lease) in held.iter().enumerate() {
        assert_eq!(
            lease.bytes(),
            &record(n)[..lease.bytes().len()],
            "a held first-round lease is unchanged"
        );
    }
}

fn abandon<'m, D: Datagrams<'m>>(
    client: &mut Client<'m, D>,
    pump: &mut impl Pump<'m, D>,
    wait_us: u64,
) {
    let id = get(client, 2, pump.now_us(), wait_us).unwrap();
    pump.turn(client);
    pump.idle(QUIET_US);
    client.cancel(id);
    let cancelled = fetch(client, id, pump).outcome;
    assert!(
        matches!(
            cancelled,
            Outcome::Failed(Status::Cancelled) | Outcome::Incomplete(Status::Cancelled)
        ),
        "{cancelled:?}"
    );
}

fn pressure<'m, D: Datagrams<'m>>(
    client: &mut Client<'m, D>,
    pump: &mut impl Pump<'m, D>,
    wait_us: u64,
) {
    let ids: Vec<_> = (0..SLOTS)
        .map(|_| get(client, 0, pump.now_us(), wait_us).unwrap())
        .collect();
    assert_eq!(
        get(client, 0, pump.now_us(), wait_us).err(),
        Some(GetRefused::RequestPressure)
    );
    for id in ids {
        assert_eq!(fetch(client, id, pump).outcome, Outcome::Complete);
    }
    let again = get(client, 0, pump.now_us(), wait_us).unwrap();
    assert_eq!(fetch(client, again, pump).outcome, Outcome::Complete);
    let mut hoard = Vec::new();
    let refused = (0..64).find_map(|_| match get(client, 2, pump.now_us(), wait_us) {
        Ok(id) => {
            let fetched = fetch(client, id, pump);
            assert_eq!(
                fetched.outcome,
                Outcome::Complete,
                "a GET either completes or is refused at the bound"
            );
            hoard.extend(fetched.first);
            None
        }
        Err(refusal) => Some(refusal),
    });
    eprintln!(
        "receive pressure {refused:?} with {} leases held",
        hoard.len()
    );
    assert_eq!(refused, Some(GetRefused::ReceivePressure));
    eprintln!("observe: pressure at the request and receive limits with the session active");
    drop(hoard);
    let id = get(client, 2, pump.now_us(), wait_us).unwrap();
    let healed = fetch(client, id, pump);
    assert_eq!(healed.outcome, Outcome::Complete, "recovered");
    assert_eq!(healed.bytes, record(2), "the healed GET is exact");
    eprintln!("observe: healed with an exact GET after the holders released");
}

fn ends<'m, D: Datagrams<'m>>(
    client: &mut Client<'m, D>,
    pump: &mut impl Pump<'m, D>,
    wait_us: u64,
) {
    let id = get(client, 2, pump.now_us(), wait_us).unwrap();
    client.cancel(id);
    let cancelled = fetch(client, id, pump).outcome;
    assert!(
        matches!(
            cancelled,
            Outcome::Failed(Status::Cancelled) | Outcome::Incomplete(Status::Cancelled)
        ),
        "{cancelled:?}"
    );
    let timed = get(client, 2, pump.now_us(), 1).unwrap();
    let ended = fetch(client, timed, pump).outcome;
    assert!(
        matches!(
            ended,
            Outcome::Failed(Status::TimedOut) | Outcome::Incomplete(Status::TimedOut)
        ),
        "{ended:?}"
    );
}

/// Fetches record `n`, getting it again while the owner answers `RequestPressure`: the owner keeps a cancelled or timed-out GET active on its wire slot until its read drains and its terminal is sent, so a GET that reuses the slot sooner meets pressure until then.
fn fetch_admitted<'m, D: Datagrams<'m>>(
    client: &mut Client<'m, D>,
    n: usize,
    pump: &mut impl Pump<'m, D>,
) -> Fetched<'m> {
    let begun = pump.now_us();
    loop {
        let id = get(client, n, pump.now_us(), WAIT_US).unwrap();
        let fetched = fetch(client, id, pump);
        if fetched.outcome != Outcome::Pressure(Status::RequestPressure) {
            return fetched;
        }
        assert!(
            pump.now_us() - begun < PATIENCE_US,
            "the owner kept the wire slot busy"
        );
    }
}

fn ended_by_stop(outcome: Outcome) -> bool {
    matches!(
        outcome,
        Outcome::Failed(Status::OwnerUnavailable | Status::TimedOut)
            | Outcome::Incomplete(Status::OwnerUnavailable | Status::TimedOut)
    )
}

#[test]
#[ignore = "needs the host pair's devices bound by kestrike-bind, named by KESTRIKE_MAPPINGS"]
fn the_client_fetches_the_volume() {
    let (mappings, _lock) = mappings();
    // SAFETY: `sched_getcpu` is safe to call from any thread.
    eprintln!("client on core {}", unsafe { libc::sched_getcpu() });
    dataplane!(mappings, env, arena, registration, view, pools, port);
    let allowances = port.allowances();
    let burst = over(
        port,
        route(&mappings, CLIENT_PORT, &[(peer(), OWNER_PORT)]),
        &pools,
        &registration,
    );
    let mut budget = EngineBudget::new(1 << 24);
    let releases = Releases::new(4, &mut budget).unwrap();
    let mut pump = Wall::new();
    let mut client = client(
        client_index(),
        &view,
        &releases,
        Box::default(),
        burst,
        &mut pump,
    )
    .map_err(|_| "no session")
    .expect("the session opened");
    rounds(&mut client, &mut pump, WAIT_US);
    assert!(pump.corpus.satisfies(&[Obligation::Bytes]));
    eprintln!(
        "observe: history {} windows judged by the oracle",
        pump.corpus.windows
    );
    pressure(&mut client, &mut pump, WAIT_US);
    ends(&mut client, &mut pump, WAIT_US);

    let Fetched { outcome, first, .. } = fetch_admitted(&mut client, 0, &mut pump);
    assert_eq!(outcome, Outcome::Complete);
    let kept = first.expect("a fragment");
    let n = 2;
    until_closed(&mut client, &mut pump, key(n as u8 + 1), 64, &record(n));
    let (report, burst) = client.close(pump.now_us());
    eprintln!("close {report:?}");
    let sent = burst.report();
    eprintln!("burst {sent:?}");
    let mut port = burst.into_port();
    eprintln!(
        "allowances before {allowances:?} after {:?}",
        port.allowances()
    );
    port.stop().expect("the port's DMA stop is proven");
    assert_eq!(
        kept.bytes(),
        &record(0)[..kept.bytes().len()],
        "a lease held across close and the port's stop stays readable"
    );
    drop(kept);
    let _undone = teardown(port, pools, registration, &arena);
    finish(env);
    drop(view);
    release(arena);
}

/// GETs `key` under `metadata_cap` until the owner's close ends one. Every
/// completed GET returns `expected` exactly, and a GET the owner answers
/// `RequestPressure` is retried within the same tail deadline.
fn until_closed<'m, D: Datagrams<'m>>(
    client: &mut Client<'m, D>,
    pump: &mut impl Pump<'m, D>,
    key: [u8; 32],
    metadata_cap: u32,
    expected: &[u8],
) {
    let tail = Instant::now();
    loop {
        assert!(tail.elapsed() < TAIL, "the owner closed");
        let Ok(id) = client.get(key, metadata_cap, BODY_CAP as u32, pump.now_us(), WAIT_US) else {
            pump.turn(client);
            continue;
        };
        let fetched = fetch(client, id, pump);
        if ended_by_stop(fetched.outcome) {
            eprintln!("the owner's close ended a GET: {:?}", fetched.outcome);
            return;
        }
        if fetched.outcome == Outcome::Pressure(Status::RequestPressure) {
            continue;
        }
        assert_eq!(
            fetched.outcome,
            Outcome::Complete,
            "a GET before the owner's close completes"
        );
        assert_eq!(fetched.bytes, expected);
    }
}

/// The PUT's key, metadata and body lengths: the metadata spans two
/// fragments, and the record takes more than one write command.
const PUT_KEY: u8 = 9;
const PUT_METADATA: usize = 9_000;
const PUT_BODY: usize = 30_000;
const PUT_TTL_MS: u32 = 3_600_000;
/// Source slots the PUT client takes from its registered read-response pool, one per fragment of the owner's window.
const SOURCES: u32 = 4;

/// The PUT's bytes, metadata first, generated the same way in every process.
fn put_object() -> Vec<u8> {
    payload(PUT_METADATA + PUT_BODY, 0x5055)
}

/// Uploads [`put_object`] under `key(PUT_KEY)`: prepares its shape once the
/// owner granted authority, supplies each fragment once a source slot is
/// free, and returns the request once its outcome is known.
fn put_once<'m, D: Datagrams<'m>>(
    client: &mut Client<'m, D>,
    pump: &mut impl Pump<'m, D>,
    wait_us: u64,
) -> RequestId {
    let object = put_object();
    let id = client
        .put(
            key(PUT_KEY),
            crate::storage::CacheVersion(0),
            pump.now_us(),
            wait_us,
        )
        .expect("a PUT slot");
    let begun = pump.now_us();
    loop {
        match client.prepare(id, PUT_METADATA as u32, PUT_BODY as u32, PUT_TTL_MS) {
            Err(PrepareRefused::Phase) if client.put_outcome(id).is_none() => {
                assert!(
                    pump.now_us() - begun < PATIENCE_US,
                    "the owner granted authority"
                );
                pump.turn(client);
            }
            prepared => {
                assert_eq!(prepared, Ok(()), "{:?}", client.put_outcome(id));
                break;
            }
        }
    }
    let count = object.len().div_ceil(FRAGMENT_LEN as usize) as u32;
    let mut next = 0;
    while client.put_outcome(id).is_none() {
        assert!(pump.now_us() - begun < PATIENCE_US, "the PUT ended");
        while next < count {
            let start = next as usize * FRAGMENT_LEN as usize;
            let piece = &object[start..object.len().min(start + FRAGMENT_LEN as usize)];
            match client.supply(id, next, piece) {
                Ok(_) => next += 1,
                Err(SupplyRefused::Slots | SupplyRefused::NotReady) => break,
                Err(refused) => panic!("fragment {next}: {refused:?}"),
            }
        }
        pump.turn(client);
    }
    assert_eq!(
        next,
        count,
        "every fragment was supplied before {:?}",
        client.put_outcome(id)
    );
    eprintln!(
        "put key {PUT_KEY}: metadata {PUT_METADATA} body {PUT_BODY} fragments {count}, {:?}",
        client.put_outcome(id)
    );
    id
}

/// Retires PUT `id`, which waits until the device returned every source slot it held, and returns the turns that took.
fn retire_put<'m, D: Datagrams<'m>>(
    client: &mut Client<'m, D>,
    id: RequestId,
    pump: &mut impl Pump<'m, D>,
) -> u64 {
    retire_put_with(client, id, pump, Client::retire)
}

/// [`retire_put`] with the client's retire passed in, so a negative control can run a broken one.
fn retire_put_with<'m, D: Datagrams<'m>>(
    client: &mut Client<'m, D>,
    id: RequestId,
    pump: &mut impl Pump<'m, D>,
    retire: fn(&mut Client<'m, D>, RequestId) -> bool,
) -> u64 {
    let (begun, mut turns) = (pump.now_us(), 0);
    while !retire(client, id) {
        assert!(
            pump.now_us() - begun < PATIENCE_US,
            "the device returned the sources"
        );
        pump.turn(client);
        turns += 1;
    }
    turns
}

/// A GET of `key(PUT_KEY)` with metadata capped at `cap`, retried until a request slot frees.
fn get_put<'m, D: Datagrams<'m>>(
    client: &mut Client<'m, D>,
    pump: &mut impl Pump<'m, D>,
    cap: usize,
    wait_us: u64,
) -> Fetched<'m> {
    let begun = pump.now_us();
    loop {
        assert!(pump.now_us() - begun < PATIENCE_US, "a GET slot freed");
        match client.get(
            key(PUT_KEY),
            cap as u32,
            BODY_CAP as u32,
            pump.now_us(),
            wait_us,
        ) {
            Ok(id) => return fetch(client, id, pump),
            Err(_) => pump.turn(client),
        }
    }
}

/// Reads `key(PUT_KEY)` back: a GET capped at the PUT's metadata length
/// returns its exact bytes under a manifest naming its metadata and body
/// lengths, and a GET capped one byte below it ends `TooLarge`.
fn read_put_back<'m, D: Datagrams<'m>>(
    client: &mut Client<'m, D>,
    pump: &mut impl Pump<'m, D>,
    wait_us: u64,
) {
    let fetched = get_put(client, pump, PUT_METADATA, wait_us);
    assert_eq!(fetched.outcome, Outcome::Complete);
    let manifest = fetched.first.as_ref().expect("a fragment").manifest();
    assert_eq!(
        (manifest.metadata_len as usize, manifest.body_len as usize),
        (PUT_METADATA, PUT_BODY)
    );
    assert!(fetched.bytes == put_object(), "the read back is byte-exact");
    eprintln!(
        "read back key {PUT_KEY}: {manifest:?}, {} bytes exact",
        fetched.bytes.len()
    );
    drop(fetched);
    let capped = get_put(client, pump, PUT_METADATA - 1, wait_us);
    assert_eq!(capped.outcome, Outcome::Failed(Status::TooLarge));
    assert!(capped.bytes.is_empty(), "a TooLarge GET delivers no bytes");
}

/// The client at `KESTRIKE_CLIENT` uploads [`put_object`] from source
/// slots of its registered arena: nine thousand bytes of metadata across two
/// fragments and a thirty-thousand-byte body, five fragments in all that
/// the owner writes to its EBS volume. Once the PUT is `Published`, its retire
/// waits until the port returned every source slot, the client closes, the
/// port's stop is proven, and only then does the registration undo and the
/// arena release. Run it with the owner serving, before
/// `an_independent_client_reads_the_put_back`.
#[test]
#[ignore = "needs the host pair's devices bound by kestrike-bind, named by KESTRIKE_MAPPINGS"]
fn the_client_puts_an_object_onto_the_volume() {
    let (mappings, _lock) = mappings();
    // SAFETY: `sched_getcpu` is safe to call from any thread.
    eprintln!("PUT client {} on core {}", client_index(), unsafe {
        libc::sched_getcpu()
    });
    dataplane!(mappings, env, arena, registration, view, pools, port);
    let burst = over(
        port,
        route(&mappings, CLIENT_PORT, &[(peer(), OWNER_PORT)]),
        &pools,
        &registration,
    );
    let mut budget = EngineBudget::new(1 << 24);
    let releases = Releases::new(4, &mut budget).unwrap();
    let sources = super::memory::sources(&arena, SOURCES, &mut budget).unwrap();
    let mut pump = Wall::new();
    let mut client = client(client_index(), &view, &releases, sources, burst, &mut pump)
        .map_err(|_| "no session")
        .expect("the session opened");
    let id = put_once(&mut client, &mut pump, WAIT_US);
    assert_eq!(client.put_outcome(id), Some(UploadOutcome::Published));
    let held = arena.report(PoolKind::ReadResponse);
    let turns = retire_put(&mut client, id, &mut pump);
    eprintln!("sources at publication {held:?}; retired after {turns} turns");
    assert_eq!(
        arena.report(PoolKind::ReadResponse).nic_held,
        0,
        "no source reference remains after the retire"
    );
    let (report, burst) = client.close(pump.now_us());
    eprintln!("close {report:?} burst {:?}", burst.report());
    let mut port = burst.into_port();
    port.stop().expect("the port's DMA stop is proven");
    let after = arena.report(PoolKind::ReadResponse);
    assert_eq!(
        after.nic_held, 0,
        "no source reference remains after the stop"
    );
    let _undone = teardown(port, pools, registration, &arena);
    finish(env);
    drop(view);
    release(arena);
}

/// A second client, at a different `KESTRIKE_CLIENT` than the PUT
/// client, runs the GET rounds the owner counts, then reads the PUT back by
/// its key: exact bytes, metadata and body lengths from the manifest, and
/// `TooLarge` one metadata byte below; it then GETs the PUT until the
/// owner's close ends one.
#[test]
#[ignore = "needs the host pair's devices bound by kestrike-bind, named by KESTRIKE_MAPPINGS"]
fn an_independent_client_reads_the_put_back() {
    let (mappings, _lock) = mappings();
    // SAFETY: `sched_getcpu` is safe to call from any thread.
    eprintln!("reading client {} on core {}", client_index(), unsafe {
        libc::sched_getcpu()
    });
    dataplane!(mappings, env, arena, registration, view, pools, port);
    let burst = over(
        port,
        route(&mappings, CLIENT_PORT, &[(peer(), OWNER_PORT)]),
        &pools,
        &registration,
    );
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 24)).unwrap();
    let mut pump = Wall::new();
    let mut client = client(
        client_index(),
        &view,
        &releases,
        Box::default(),
        burst,
        &mut pump,
    )
    .map_err(|_| "no session")
    .expect("the session opened");
    rounds(&mut client, &mut pump, WAIT_US);
    read_put_back(&mut client, &mut pump, WAIT_US);
    until_closed(
        &mut client,
        &mut pump,
        key(PUT_KEY),
        PUT_METADATA as u32,
        &put_object(),
    );
    let (report, burst) = client.close(pump.now_us());
    eprintln!("close {report:?}");
    let mut port = burst.into_port();
    port.stop().expect("the port's DMA stop is proven");
    let _undone = teardown(port, pools, registration, &arena);
    finish(env);
    drop(view);
    release(arena);
}

fn release(arena: BufferArena<TestPlatform>) {
    assert!(matches!(
        arena.release().map_err(|_| "held"),
        Ok(Released::Complete)
    ));
}

#[test]
#[ignore = "needs two owners and the client's ENI bound by kestrike-bind, KESTRIKE_MAPPINGS, KESTRIKE_PEERS and KESTRIKE_STOPPED"]
fn the_client_fetches_from_two_owners() {
    let (mappings, _lock) = mappings();
    let owners: Vec<Ipv4Addr> = std::env::var("KESTRIKE_PEERS")
        .expect("set KESTRIKE_PEERS; see the module docs")
        .split(',')
        .map(|ip| ip.trim().parse().unwrap())
        .collect();
    assert_eq!(owners.len(), 2, "two owners");
    let expected: usize = std::env::var("KESTRIKE_STOPPED")
        .expect("set KESTRIKE_STOPPED to the index of the owner that stops")
        .parse()
        .unwrap();
    let seconds: u64 =
        std::env::var("KESTRIKE_CLIENT_SECONDS").map_or(900, |text| text.parse().unwrap());
    dataplane!(mappings, env, arena, registration, view, pools, port);
    let routes: Vec<_> = owners
        .iter()
        .map(|&owner| route(&mappings, CLIENT_PORT, &[(owner, OWNER_PORT)]))
        .collect();
    let index = client_index();
    let mut pump = Wall::new();
    let mut port = Some(port);
    let (mut served, mut survived, mut gone) = ([0u32; 2], [0u32; 2], [false; 2]);
    let mut first = None;
    let mut cycle = 0;
    while pump.start.elapsed() < Duration::from_secs(seconds) && gone.contains(&false) {
        for (at, &route) in routes.iter().enumerate() {
            if gone[at] {
                continue;
            }
            let releases = Releases::new(4, &mut EngineBudget::new(1 << 16)).unwrap();
            let burst = over(port.take().unwrap(), route, &pools, &registration);
            let mut session =
                match client(index, &view, &releases, Box::default(), burst, &mut pump) {
                    Ok(session) => session,
                    Err(mut burst) => {
                        burst.reclaim();
                        port = Some(burst.into_port());
                        stopped(&mut gone, &served, at, cycle, "its session did not open");
                        first.get_or_insert(at);
                        continue;
                    }
                };
            let mut whole = true;
            for n in 0..RECORDS.len() {
                let id = match get(&mut session, n, pump.now_us(), WAIT_US) {
                    Ok(id) => id,
                    Err(GetRefused::NoSession) => {
                        whole = false;
                        break;
                    }
                    Err(refused) => panic!("cycle {cycle} owner {at} record {n}: {refused:?}"),
                };
                let fetched = fetch(&mut session, id, &mut pump);
                if ended_by_stop(fetched.outcome) {
                    whole = false;
                    break;
                }
                assert_eq!(
                    fetched.outcome,
                    Outcome::Complete,
                    "cycle {cycle} owner {at} record {n}"
                );
                assert_eq!(
                    fetched.bytes,
                    record(n),
                    "cycle {cycle} owner {at} record {n} is exact"
                );
            }
            let (_, mut burst) = session.close(pump.now_us());
            // The next cycle reuses the port.
            burst.reclaim();
            port = Some(burst.into_port());
            if whole {
                served[at] += 1;
                if gone[1 - at] && survived[at] == 0 {
                    eprintln!(
                        "observe: healthy owner {at} served exact bytes after owner {} stopped",
                        1 - at
                    );
                }
                survived[at] += u32::from(gone[1 - at]);
            } else {
                stopped(&mut gone, &served, at, cycle, "a GET ended short");
                first.get_or_insert(at);
            }
        }
        cycle += 1;
    }
    eprintln!("served {served:?}, after the other stopped {survived:?}, stopped {gone:?}");
    assert_eq!(first, Some(expected), "the named owner stopped first");
    assert!(
        survived[1 - expected] > 0,
        "the other owner served exact bytes after the first stopped"
    );
    let port = port.expect("the port came back from the last cycle");
    let _undone = teardown(port, pools, registration, &arena);
    finish(env);
    drop(view);
    release(arena);
}

fn stopped(gone: &mut [bool; 2], served: &[u32; 2], at: usize, cycle: usize, why: &str) {
    assert!(
        served.iter().all(|&n| n > 0),
        "both owners served before owner {at} stopped in cycle {cycle}: {why}"
    );
    eprintln!("cycle {cycle}: owner {at} stopped; {why}");
    eprintln!("observe: failure owner {at} in cycle {cycle}");
    gone[at] = true;
}

/// Counts the owner's quiet drains: runs of polls that begin at a poll that
/// received a frame and left requests live, receive no frame after, see a
/// device return at one of their frameless polls, and end at the first poll
/// that leaves no request live.
#[derive(Default)]
struct QuietDrains {
    /// When the current run began, and whether a device returned a reference at one of its frameless polls.
    run: Option<(u64, bool)>,
    drains: u32,
}

impl QuietDrains {
    fn observe(&mut self, now_us: u64, received: bool, live: bool, returned: bool) -> Option<u64> {
        if received {
            self.run = live.then_some((now_us, false));
            return None;
        }
        if live {
            let (_, any) = self.run.get_or_insert((now_us, false));
            *any |= returned;
            return None;
        }
        let (since, any) = self.run.take()?;
        (any || returned).then(|| {
            self.drains += 1;
            now_us - since
        })
    }
}

const TURN_US: u64 = 100;
const SIM_WAIT_US: u64 = 2_000_000;
const SIM_PAYLOAD: usize =
    (4 << 20) - crate::storage::TEST_METADATA_UNITS as usize * crate::storage::IO_UNIT;
const CLIENT_SIDE: usize = 0;

struct Simulated<'o, 's, 'a, 'r, 'n> {
    owner: &'o mut TestOwner<'s, 'a, 'r>,
    control: &'o SimControl,
    net: Rc<RefCell<Net<'n>>>,
    held: usize,
    turn: u64,
    quiet: QuietDrains,
    corpus: Corpus,
}

/// The oracle histories of the corpus's GETs: record `n` published once
/// under key `n % 2` and label `n + 1` in history `n / 2`, since one history admits
/// two keys, and each complete GET a hit and its delivery, every history judged
/// window by window through the continuation's cuts.
struct Corpus {
    histories: Vec<(Recorder, Cuts)>,
    windows: u32,
}

fn label(n: usize) -> Label {
    Label(n as u64 + 1)
}

fn key_id(n: usize) -> KeyId {
    KeyId((n % MAX_KEYS) as u8)
}

impl Corpus {
    /// The corpus for records whose writes lie outside the device observation boundary.
    fn new() -> Self {
        Self::published(|_| None)
    }

    /// The corpus for records the simulated owner's device wrote; `fills[n]` contains record `n`'s write commands and
    /// their delivered terminals.
    ///
    /// # Panics
    ///
    /// When `fills` holds other than one entry per record.
    fn written(fills: Vec<Vec<CommandEvidence>>) -> Self {
        assert_eq!(fills.len(), RECORDS.len(), "one fill per record");
        let mut fills = fills.into_iter();
        Self::published(|_| fills.next())
    }

    fn published(mut written: impl FnMut(usize) -> Option<Vec<CommandEvidence>>) -> Self {
        let mut histories: Vec<_> = (0..RECORDS.len().div_ceil(MAX_KEYS))
            .map(|_| (Recorder::new(1), Cuts::new(OracleOwner(0))))
            .collect();
        for (n, &(_, metadata)) in RECORDS.iter().enumerate() {
            let (key, rec) = Self::of(&mut histories, n);
            rec.published_written(key, label(n), metadata as u32, &record(n), ID, written(n));
        }
        Self {
            histories,
            windows: 0,
        }
    }

    fn of(histories: &mut [(Recorder, Cuts)], n: usize) -> (KeyId, &mut Recorder) {
        (key_id(n), &mut histories[n / MAX_KEYS].0)
    }

    fn served(&mut self, n: usize, bytes: &[u8]) {
        let (body, metadata) = RECORDS[n];
        let (key, rec) = Self::of(&mut self.histories, n);
        let read = rec.lookup(key, OracleOutcome::Hit, Some(label(n)));
        rec.delivered(
            read,
            (key, label(n)),
            (metadata as u32, body as u64),
            ID,
            OracleOutcome::Complete,
            bytes.to_vec(),
        );
    }

    fn cut(&mut self) {
        for (rec, cuts) in &mut self.histories {
            let verdict = cuts.cut(rec.rows(), &[]).expect("the rows only grow");
            assert!(
                matches!(verdict, Verdict::Pass(_)),
                "window {}: {verdict:?}",
                self.windows
            );
        }
        self.windows += 1;
    }

    fn satisfies(&self, obligations: &[Obligation]) -> bool {
        self.histories
            .iter()
            .all(|(_, cuts)| cuts.finish().satisfies(obligations))
    }
}

impl Simulated<'_, '_, '_, '_, '_> {
    /// One turn as one controller round: the link advances, `side` runs as
    /// `actor`, the device ticks and the owner polls, its action observing the
    /// device returns and receives of that poll for the quiet-drain check.
    /// The legacy schedule keeps that order; a generated one runs the link
    /// advance first and then the order it picks.
    fn owner_turn(&mut self, actor: Actor, mut side: impl FnMut()) {
        let turn = self.turn;
        let now = turn * TURN_US;
        let net = &self.net;
        let control = self.control;
        let (owner, held, quiet) = (&mut *self.owner, &mut self.held, &mut self.quiet);
        round(&mut [
            Act::new(Actor::Link(0), &mut || net.borrow_mut().advance(turn)),
            Act::new(actor, &mut side),
            Act::new(Actor::Disk(0), &mut || control.tick(64)),
            Act::new(Actor::Owner(0), &mut || {
                let returned = net.borrow().nic_held() < *held;
                let before = owner.report().received;
                owner.poll(now);
                *held = net.borrow().nic_held();
                let census = owner.census();
                quiet.observe(
                    now,
                    owner.report().received != before,
                    census.active + census.draining > 0,
                    returned,
                );
            }),
        ]);
        self.turn += 1;
    }
}

impl<'m> Pump<'m, LinkEnd<'m>> for Simulated<'_, '_, '_, '_, '_> {
    fn now_us(&self) -> u64 {
        self.turn * TURN_US
    }

    fn turn(&mut self, client: &mut Client<'m, LinkEnd<'m>>) {
        let now = self.turn * TURN_US;
        self.owner_turn(Actor::Client(0), || {
            let _ = client.poll(now);
        });
    }

    fn served(&mut self, n: usize, bytes: &[u8]) {
        self.corpus.served(n, bytes);
    }

    fn cut(&mut self) {
        self.corpus.cut();
    }

    fn idle(&mut self, quiet_us: u64) {
        for _ in 0..quiet_us / TURN_US {
            let net = Rc::clone(&self.net);
            self.owner_turn(Actor::Harness(0), || net.borrow_mut().clear(CLIENT_SIDE));
        }
    }
}

#[test]
fn the_client_scenario_passes_over_the_simulated_owner() {
    let storage = heap_storage_on(SIM_PAYLOAD, BODY_CAP);
    let buffers = arena_on(TestPlatform::heap(4096), 16, 8);
    let (receive, client_pool) = (pool(), pool());
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let records: Vec<_> = (0..RECORDS.len()).map(record).collect();
    let published: Vec<_> = records
        .iter()
        .enumerate()
        .map(|(n, bytes)| (key(n as u8 + 1), RECORDS[n].1, bytes.as_slice()))
        .collect();
    let (client_end, owner_end, net) = network(64, 8384, SESSION, [Faults::default(); 2]);
    let (mut owner, control) = start(&storage, &buffers, &receive, &published, vec![owner_end]);
    let corpus = Corpus::written(fills_written(&owner, &control));
    let mut pump = Simulated {
        owner: &mut owner,
        control: &control,
        net,
        held: 0,
        turn: 0,
        quiet: QuietDrains::default(),
        corpus,
    };
    assert!(
        pump.corpus
            .histories
            .iter()
            .flat_map(|(rec, _)| rec.rows())
            .filter(|row| row.kind == ActionKind::WriteCompleted)
            .all(|row| row.commands.as_ref().is_some_and(|c| !c.is_empty())),
        "every preload's write completion carries the device's write evidence"
    );
    let mut client = client(
        0,
        &client_pool,
        &releases,
        Box::default(),
        client_end,
        &mut pump,
    )
    .map_err(|_| "no session")
    .expect("the session opened");
    rounds(&mut client, &mut pump, SIM_WAIT_US);
    assert!(pump.corpus.satisfies(&[Obligation::Bytes]));
    assert_eq!(pump.corpus.windows, ROUNDS as u32, "one window per round");
    pressure(&mut client, &mut pump, SIM_WAIT_US);
    ends(&mut client, &mut pump, SIM_WAIT_US);
    assert!(
        pump.quiet.drains > 0,
        "the owner drained a request on device returns while no frame arrived"
    );
    let _ = pump.owner.close(pump.turn * TURN_US);
    let id = get(&mut client, 2, pump.turn * TURN_US, SIM_WAIT_US).unwrap();
    let closed = fetch(&mut client, id, &mut pump).outcome;
    assert!(ended_by_stop(closed), "{closed:?}");
}

/// The PUT and read-back schedule over the simulated owner: the client on
/// the link holding PUT permission uploads from heap source slots and its
/// retire waits for the link's late device returns, then a client on the other
/// link reads the PUT back exactly, with its lengths, and one metadata byte
/// short ends `TooLarge`.
#[test]
fn the_put_scenario_passes_over_the_simulated_owner() {
    put_scenario_over_the_simulated_owner(|client, id| client.retire(id));
}

/// Record `put-then-independent-get-native-schedule` excludes a PUT retire
/// that frees its request before the link returned the source slots it holds.
/// [`Client::retire_once_known`] is that retire, and the record test's own
/// check refuses it: the retire ends in the first turn, while the link still
/// holds device references.
#[test]
#[should_panic(expected = "the retire waited for late device returns")]
fn negative_control_a_retire_that_skips_the_late_device_returns_fails_the_put_scenario() {
    put_scenario_over_the_simulated_owner(|client, id| client.retire_once_known(id));
}

/// The body of [`the_put_scenario_passes_over_the_simulated_owner`], with the
/// writing client's PUT retire passed in.
fn put_scenario_over_the_simulated_owner(
    retire: for<'m> fn(&mut Client<'m, LinkEnd<'m>>, RequestId) -> bool,
) {
    let storage = heap_storage_with_metadata_on(SIM_PAYLOAD, BODY_CAP, PUT_METADATA);
    let buffers = arena_on(TestPlatform::heap(4096), 16, 8);
    let sourced = arena_on(TestPlatform::heap(4096), SOURCES, 1);
    let (receive, reader_pool, writer_pool) = (pool(), pool(), pool());
    let mut budget = EngineBudget::new(1 << 20);
    let releases = [
        Releases::new(4, &mut budget).unwrap(),
        Releases::new(4, &mut budget).unwrap(),
    ];
    let faults = [Faults::default(); 2];
    let (reader_end, reader_owner, reader_net) = network(64, 8384, SESSION, faults);
    let (writer_end, writer_owner, writer_net) = network(64, 8384, SESSION + 1, faults);
    // The second link's peer holds PUT permission.
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[],
        vec![reader_owner, writer_owner],
    );
    let sources = super::memory::sources(&sourced, SOURCES, &mut budget).unwrap();
    // Device references return late, so the PUT's retire has to wait for them.
    writer_net
        .borrow_mut()
        .set_tx_release(TxRelease::Delayed(40));
    let mut pump = Simulated {
        owner: &mut owner,
        control: &control,
        net: writer_net,
        held: 0,
        turn: 0,
        quiet: QuietDrains::default(),
        corpus: Corpus::new(),
    };
    let mut writer = client(
        1,
        &writer_pool,
        &releases[1],
        sources,
        writer_end,
        &mut pump,
    )
    .map_err(|_| "no session")
    .expect("the PUT client's session opened");
    let id = put_once(&mut writer, &mut pump, SIM_WAIT_US);
    assert_eq!(writer.put_outcome(id), Some(UploadOutcome::Published));
    assert!(
        retire_put_with(&mut writer, id, &mut pump, retire) > 0,
        "the retire waited for late device returns"
    );
    assert_eq!(pump.net.borrow().nic_held(), 0);
    drop(writer.close(pump.now_us()));
    let mut pump = Simulated {
        net: reader_net,
        ..pump
    };
    let mut reader = client(
        0,
        &reader_pool,
        &releases[0],
        Box::default(),
        reader_end,
        &mut pump,
    )
    .map_err(|_| "no session")
    .expect("the reading client's session opened");
    read_put_back(&mut reader, &mut pump, SIM_WAIT_US);
    drop(reader.close(pump.now_us()));
    let returned = sourced.report(PoolKind::ReadResponse);
    assert_eq!(
        (returned.free, returned.nic_held),
        (SOURCES, 0),
        "every source slot returned"
    );
}

#[test]
fn a_quiet_drain_needs_a_device_return_without_a_frame() {
    let mut quiet = QuietDrains::default();
    assert_eq!(quiet.observe(0, true, true, false), None);
    assert_eq!(
        quiet.observe(1, false, false, false),
        None,
        "nothing returned after the last frame"
    );
    assert_eq!(quiet.observe(2, true, true, false), None);
    assert_eq!(quiet.observe(3, false, true, true), None);
    assert_eq!(quiet.observe(4, false, true, false), None);
    assert_eq!(quiet.observe(5, false, false, false), Some(3));
    assert_eq!(quiet.observe(6, true, true, true), None);
    assert_eq!(
        quiet.observe(7, false, false, false),
        None,
        "the return at 6 came with a frame"
    );
    assert_eq!(quiet.drains, 1);
}

#[test]
fn only_a_stopped_owners_outcomes_count_as_its_stop() {
    for outcome in [
        Outcome::Failed(Status::OwnerUnavailable),
        Outcome::Incomplete(Status::OwnerUnavailable),
        Outcome::Failed(Status::TimedOut),
        Outcome::Incomplete(Status::TimedOut),
    ] {
        assert!(ended_by_stop(outcome), "{outcome:?}");
    }
    for outcome in [
        Outcome::Complete,
        Outcome::Missing,
        Outcome::Pressure(Status::RequestPressure),
        Outcome::Failed(Status::IntegrityError),
        Outcome::Incomplete(Status::IntegrityError),
        Outcome::Incomplete(Status::DeviceError),
        Outcome::Failed(Status::Cancelled),
        Outcome::Failed(Status::SessionMismatch),
    ] {
        assert!(!ended_by_stop(outcome), "{outcome:?}");
    }
}

/// The corpus's history refuses a GET that delivered bytes other than its record.
#[test]
fn a_corpus_delivery_other_than_its_record_fails_the_window() {
    let mut corpus = Corpus::new();
    let mut bytes = record(1);
    bytes[0] ^= 1;
    corpus.served(1, &bytes);
    let (rec, cuts) = &mut corpus.histories[0];
    let verdict = cuts.cut(rec.rows(), &[]).unwrap();
    assert_eq!(
        verdict.violated(),
        Some((
            Obligation::Bytes,
            "a complete read returned bytes other than the label's content"
        ))
    );
}

crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
    the_put_scenario_passes_over_the_simulated_owner,
);
