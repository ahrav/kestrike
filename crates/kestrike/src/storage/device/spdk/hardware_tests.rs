//! The SPDK driver on a disposable EBS volume bound by `kestrike-bind`:
//! the shared `Disk` contract, every outcome-table row, the startup canary,
//! the proven stop and the teardown order, then a volume round trip and a
//! cold start.
//!
//! The volume tests are ignored by default and fail without
//! `KESTRIKE_MAPPINGS` naming the mappings file, so a run without the
//! volume never reports a pass. Each attach of the volume takes its session
//! from the soak store in the mappings file's state directory, creating it
//! on first use and bumping it on every run, so tests and soaks on one bound
//! volume share that store and keep its sessions rising. The store requires
//! a persistent state directory: a 0700 directory of the running user under
//! ancestors only root or that user can write, outside `/run` and
//! `/var/run`, such as one bound with
//! `kestrike-bind --state-dir /var/lib/kestrike`. The host has hugepages reserved, the volume
//! bound with `kestrike-bind --volume`, and each volume test runs as root,
//! alone in its process, since the environment initializes once per process:
//!
//! ```text
//! sudo KESTRIKE_MAPPINGS=/var/lib/kestrike/mappings \
//!     target/debug/deps/kestrike-<hash> --ignored --exact \
//!     storage::device::spdk::hardware_tests::the_spdk_driver_passes_every_outcome_row_on_the_volume \
//!     --test-threads=1 --nocapture
//! ```
//!
//! and likewise for `the_spdk_driver_meets_the_disk_contract`, which writes
//! the volume's first 16 KiB and also needs `KESTRIKE_IDLE_OBSERVATION_MS`,
//! the milliseconds each idle-buffer observation in the contract lasts.
//!
//! The outcome-row test overwrites the volume's first 512 KiB. After the driver-level
//! rows it attaches a volume over a fresh driver, publishes a record and
//! reads it back byte for byte, then cold starts a third driver with a new
//! session, which trusts nothing the first wrote. Each driver is stopped,
//! its registration undone and its controller detached, in that order.
//!
//! `the_spdk_driver_stops_with_dispatched_reads_and_writes_outstanding`
//! stops the controller while dispatched reads and writes are outstanding,
//! which the host judges by observed completions, and overwrites the
//! volume's second 64 KiB. Its schedule runs by default over the scripted
//! driver, with its failed-stop and early-drain controls.

mod warm_cycle;

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use spdk_sys as sys;

use super::super::profile::{PersistenceProfile, UnitSource, completion_is_durable};
use super::super::torn_write::TornWriteFields;
use super::disk::{SpdkConfig, SpdkDisk, StopReport};
use super::disk_tests::{SCRIPT, Scripted, limits};
use super::native::{Native, Spdk};
use crate::bind::{Host, Mappings, OwnerLock};
use crate::native::{
    ArenaRegistration, DmaPolicy, EnvConfig, Environment, PciAddress, RegistrationStep, Supervisor,
    Watchdog, registration_tests,
};
use crate::storage::owner_fixture::{TestPlatform, hardware_storage_on, heap_storage_on};
use crate::storage::record::HeaderMismatch;
use crate::storage::volume::{RawRead, ReadOp};
use crate::storage::volume_fixture::{close_and_release, open_polled};
use crate::storage::writable_tests::bytes;
use crate::storage::{
    BufferArena, Classification, CommandTable, CommandToken, Completion, CompletionSink, Decision,
    DeviceRange, DeviceStatus, Disk, EngineBudget, ExtentLease, Operation, PoolKind,
    QuiesceProgress, QuiesceStatus, Quiesced, ReadEvent, ReadStatus, RefusalReason, Storage,
    Terminal, TickConfig, Volume, WorkBudget,
};

struct Unreachable;

impl Supervisor for Unreachable {
    fn contain(&self) {
        panic!("teardown stalled");
    }
}

const CONFIG: SpdkConfig = SpdkConfig {
    queue_depth: 10,
    timeout_io_us: 30_000_000,
    timeout_admin_us: 30_000_000,
};
const RAW: usize = 512 << 10;
const TICK: TickConfig = TickConfig {
    submit_burst: 8,
    terminal_burst: 8,
    validate_bytes: 1 << 20,
};
const PATIENCE: Duration = Duration::from_secs(10);
/// The smallest FIS test timeout whose half still holds an EBS read at normal latency.
const MIN_FIS_TIMEOUT_US: u64 = 200_000;

type SpdkVolume<'s, 'a, 'l, N = Spdk> = Volume<'s, 'a, TestPlatform, SpdkDisk<'l, N>>;

fn pick_one(disk: &mut SpdkDisk<'_>) -> Completion {
    let (start, mut out) = (Instant::now(), Vec::with_capacity(1));
    while out.is_empty() {
        assert!(start.elapsed() < PATIENCE, "a completion arrived");
        disk.pick_completions(&mut CompletionSink::new(&mut out, 1));
    }
    out[0]
}

fn pick_each<N: Native>(disk: &mut SpdkDisk<'_, N>, count: usize) -> Vec<Completion> {
    let (start, mut out) = (Instant::now(), Vec::with_capacity(count));
    while out.len() < count {
        assert!(start.elapsed() < PATIENCE, "every command completed");
        let before = out.len();
        disk.pick_completions(&mut CompletionSink::new(&mut out, 1));
        assert!(out.len() - before <= 1);
    }
    out
}

/// Quiesces `disk` until it proves the controller disabled.
fn stop<N: Native>(disk: &mut SpdkDisk<'_, N>) {
    let start = Instant::now();
    while disk.quiesce() != QuiesceStatus::Stopped {
        assert!(start.elapsed() < PATIENCE, "the controller disabled");
    }
}

/// Undoes `registration` after `disk` stopped, then detaches the controller.
fn teardown<N: Native>(mut registration: ArenaRegistration<'_>, disk: &mut SpdkDisk<'_, N>) {
    registration
        .device_stopped(disk.stop_proof().unwrap())
        .unwrap();
    let watchdog = Watchdog::arm(Duration::from_secs(30), Arc::new(Unreachable)).unwrap();
    let undone = registration.unregister(&watchdog).unwrap();
    assert!(disk.detach(&undone));
}

fn start<'a, 'l>(
    lock: &'l OwnerLock,
    env: &'a Environment,
    arena: &'a BufferArena<TestPlatform>,
) -> (ArenaRegistration<'a>, SpdkDisk<'l>) {
    start_with(lock, env, arena, CONFIG)
}

/// Registers the arena, attaches a driver under `config`, maps and verifies, and passes the canary.
fn start_with<'a, 'l>(
    lock: &'l OwnerLock,
    env: &'a Environment,
    arena: &'a BufferArena<TestPlatform>,
    config: SpdkConfig,
) -> (ArenaRegistration<'a>, SpdkDisk<'l>) {
    start_under(
        lock,
        env,
        arena,
        config,
        DmaPolicy {
            allow_no_iommu: true,
        },
    )
}

fn start_under<'a, 'l>(
    lock: &'l OwnerLock,
    env: &'a Environment,
    arena: &'a BufferArena<TestPlatform>,
    config: SpdkConfig,
    policy: DmaPolicy,
) -> (ArenaRegistration<'a>, SpdkDisk<'l>) {
    let mut registration = ArenaRegistration::register(env, arena, policy).unwrap();
    let mut disk = SpdkDisk::attach_qualification(
        &crate::bind::Host::system(),
        lock,
        &mut registration,
        config,
        crate::failover::evidence::Pair {
            exhid: crate::failover::identity::Exhid::new([1; 16]).unwrap(),
            key: crate::failover::identity::Key::decode((1 << 32) | 1).unwrap(),
        },
        crate::storage::ReservationLimits::new(2, 2, 10, 10).unwrap(),
    )
    .unwrap();
    let facts = disk.attach_facts().unwrap();
    eprintln!(
        "identify: {:?} {:?}, completion-without-volatile-cache {:?}",
        facts.identify.decoded(),
        facts.identify.transfer(),
        completion_is_durable(facts.identify.raw().record(), &facts.identity)
    );
    registration.map().unwrap();
    eprintln!(
        "startup: {:?} {disk:?} {:?}",
        registration.verify().unwrap(),
        disk.geometry()
    );
    disk.enable_reservations(&registration).unwrap();
    let canary = arena.acquire(PoolKind::ReadResponse).unwrap();
    drop(
        disk.canary(&registration, canary, Duration::from_secs(5))
            .unwrap(),
    );
    (registration, disk)
}

fn publish<'s>(
    storage: &'s Storage<TestPlatform>,
    volume: &mut SpdkVolume<'s, '_, '_>,
    key: &[u8; 32],
    metadata: usize,
    payload: &[u8],
) -> ExtentLease<'s, TestPlatform> {
    let mut budget = WorkBudget::new(1 << 16);
    let body = payload.len() - metadata;
    let attempt = storage
        .begin_fill(key, crate::storage::CacheVersion(0), 4, &mut budget)
        .expect("an attempt");
    let Decision::Admit(admit) = storage.decide_admission(Some(metadata), Some(body)) else {
        panic!("an open storage admits the fill");
    };
    let mut fill = attempt
        .reserve_storage(admit, Some(metadata), Some(body), 4, &mut budget)
        .expect("a reservation");
    let (start, mut taken, mut out) = (Instant::now(), 0, Vec::with_capacity(8));
    let mut last_refusal = None;
    loop {
        let progress = fill.progress(volume);
        assert!(!progress.failed, "every write succeeds");
        if progress.is_ready() {
            break;
        }
        // A submit the volume refused leaves its segment staged; a receive of no bytes retries it.
        match fill.receive(
            volume,
            &payload[taken..],
            &mut crate::storage::WorkBudget::with_io(0, usize::MAX, usize::MAX),
        ) {
            Ok(count) => taken += count,
            Err(refusal) => last_refusal = Some(refusal),
        }
        volume.poll_storage(0, &mut out);
        assert!(
            start.elapsed() < PATIENCE,
            "the fill's writes finished: {taken} of {} bytes taken, {progress:?}, last receive refusal {last_refusal:?}, readiness {:?}, {:?}",
            payload.len(),
            volume.readiness(),
            volume.authority_report()
        );
    }
    fill.publish(volume, u64::MAX, 4, &mut budget)
        .expect("published")
}

fn finish(volume: &mut SpdkVolume<'_, '_, '_>, op: ReadOp) -> (Vec<u8>, ReadStatus) {
    finish_by(volume, op, Instant::now() + PATIENCE)
}

fn finish_by(
    volume: &mut SpdkVolume<'_, '_, '_>,
    op: ReadOp,
    deadline: Instant,
) -> (Vec<u8>, ReadStatus) {
    let (mut bytes, mut out) = (Vec::new(), Vec::with_capacity(8));
    loop {
        assert!(Instant::now() < deadline, "the read ended");
        volume.poll_storage(0, &mut out);
        for event in out.drain(..) {
            match event {
                ReadEvent::Chunk { chunk, .. } => {
                    bytes.extend_from_slice(chunk.bytes());
                    let _ = volume.grant_read(op);
                }
                ReadEvent::Done { status, .. } => return (bytes, status),
            }
        }
    }
}

/// Publishes a record and reads it back byte for byte, returning what a cold start reads it by.
fn round_trip<'s>(
    storage: &'s Storage<TestPlatform>,
    volume: &mut SpdkVolume<'s, '_, '_>,
    seed: u64,
) -> RawRead {
    let (key, metadata) = ([seed as u8; 32], 40);
    let payload = bytes(metadata + 2 * 16384 + 5, seed);
    let lease = publish(storage, volume, &key, metadata, &payload);
    let id = lease.id();
    let locator = storage.live_pool().unwrap().records()[id.slot_index()].locator();
    let op = volume.read(lease, u64::MAX).expect("a read");
    let (read, status) = finish(volume, op);
    assert_eq!(status, ReadStatus::Complete);
    assert!(read == payload, "the read back is byte-exact");
    RawRead {
        locator,
        key,
        allocation: id.record_tag(),
        session: volume.session(),
        version: 0,
    }
}

/// Closes `volume` until it quiesced, releases it for its driver, stops the driver, undoes the registration, then detaches.
fn shut(volume: SpdkVolume<'_, '_, '_>, registration: ArenaRegistration<'_>) {
    let (start, mut out) = (Instant::now(), Vec::with_capacity(8));
    let (_, mut disk) = close_and_release(
        volume,
        |_| start.elapsed() < PATIENCE,
        |volume| {
            let _ = volume.poll_storage(0, &mut out);
            out.clear();
        },
    );
    stop(&mut disk);
    teardown(registration, &mut disk);
}

fn address(bdf: &str) -> PciAddress {
    let hex = |range: std::ops::Range<usize>| u32::from_str_radix(&bdf[range], 16).unwrap();
    PciAddress {
        domain: hex(0..4),
        bus: hex(5..7) as u8,
        device: hex(8..10) as u8,
        function: hex(11..12) as u8,
    }
}

/// The owner lock over the volume `KESTRIKE_MAPPINGS` names and an environment allowing only its controller.
fn bound() -> (OwnerLock, Environment) {
    let path =
        std::env::var("KESTRIKE_MAPPINGS").expect("set KESTRIKE_MAPPINGS; see the module docs");
    let path = Path::new(&path);
    let mappings = Mappings::read(path).unwrap();
    let (instance, boot) = Host::system().instance_and_boot().unwrap();
    mappings.check_current(&instance, &boot).unwrap();
    let lock = OwnerLock::acquire(path.parent().unwrap()).unwrap();
    // SAFETY: reads this thread's CPU.
    let core = u32::try_from(unsafe { libc::sched_getcpu() }).unwrap();
    let allowed = [address(
        &mappings
            .nvme
            .as_ref()
            .expect("the mappings record a volume")
            .bdf,
    )];
    let env = Environment::initialize(&EnvConfig {
        core,
        hugepage_dir: Path::new("/dev/hugepages"),
        allowed: &allowed,
    })
    .unwrap();
    (lock, env)
}

/// Aborts the process when dropped during an unwind, so a failed check never
/// returns buffers the controller may still write.
struct AbortOnUnwind;

impl Drop for AbortOnUnwind {
    fn drop(&mut self) {
        if std::thread::panicking() {
            std::process::abort();
        }
    }
}

/// The SPDK driver meets the contract every `Disk` implementation meets, the
/// simulated device's leg of which runs in every lane, with the drained
/// buffers observed for the `KESTRIKE_IDLE_OBSERVATION_MS` interval the
/// platform owner declares for the volume. The contract ends with the
/// controller stopped.
#[test]
#[ignore = "needs a disposable EBS volume bound by kestrike-bind, named by KESTRIKE_MAPPINGS"]
fn the_spdk_driver_meets_the_disk_contract() {
    let observe = Duration::from_millis(
        std::env::var("KESTRIKE_IDLE_OBSERVATION_MS")
            .expect("KESTRIKE_IDLE_OBSERVATION_MS names the idle buffers' observation interval")
            .parse()
            .expect("the observation interval is a whole number of milliseconds"),
    );
    assert!(
        observe > Duration::ZERO,
        "the volume's observation interval is positive"
    );
    let (lock, env) = bound();
    let arena = arena_on(TestPlatform::linux(), 16, 5);
    let (registration, mut disk) = start(&lock, &env, &arena);
    let guard = AbortOnUnwind;
    // SAFETY: `guard` aborts the process on an unwind out of the contract, before the arena unmaps or any buffer the controller may write is reacquired.
    unsafe {
        super::super::disk_contract::meets_the_disk_contract(&mut disk, &arena, observe, || {
            std::thread::sleep(Duration::from_micros(10));
        });
    }
    drop(guard);
    stop(&mut disk);
    teardown(registration, &mut disk);
}

/// The attached volume derives a persistence profile from the facts the SPDK
/// driver returned, and a unit-sized, unit-aligned range qualifies. Each
/// `observe:` line prints after the assertion it follows passed.
#[test]
#[ignore = "needs a disposable EBS volume bound by kestrike-bind, named by KESTRIKE_MAPPINGS"]
fn the_attached_volume_derives_a_persistence_profile() {
    let (lock, env) = bound();
    let arena = arena_on(TestPlatform::linux(), 16, 5);
    let (registration, mut disk) = start(&lock, &env, &arena);
    let facts = disk.attach_facts().unwrap().clone();
    let profile = PersistenceProfile::derive(&facts).unwrap();
    assert_ne!(
        profile.unit_source(),
        UnitSource::OneBlock,
        "the EBS volume reports a unit above one block"
    );
    assert_eq!(
        profile.unit_source(),
        UnitSource::Both,
        "both sources report"
    );
    eprintln!("observe: profile {}", profile.kind().name());
    let sector = u64::from(profile.sector_size());
    let unit = u32::try_from(profile.unit() * sector).unwrap();
    assert_eq!(unit, 16_384, "(NAWUPF 31 + 1) blocks of 512 bytes");
    let qualifying = (0..64u64)
        .map(|k| DeviceRange::new(k * u64::from(unit), unit).unwrap())
        .filter(|range| profile.qualifies(*range))
        .count();
    assert!(qualifying > 0, "a unit-sized range qualifies");
    eprintln!(
        "observe: unit-source {:?} unit {} granularity {} standard {:?} vendor {:?} qualifying {qualifying} of 64",
        profile.unit_source(),
        unit,
        profile.granularity() * sector,
        profile.standard_boundary(),
        profile.vendor_boundary()
    );
    let raw = facts.identify.raw();
    let decoded = facts.identify.decoded().unwrap();
    eprintln!("observe: vwc 0x{:02x}", raw.controller()[525]);
    eprintln!(
        "observe: atomics {:?} awupf {} atomicity-mode {}",
        decoded.atomics,
        decoded.awupf,
        profile.atomicity_mode()
    );
    eprintln!(
        "observe: vendor-fields {:?}",
        TornWriteFields::decode(raw, decoded)
    );
    eprintln!("observe: transfer {:?}", profile.limits());
    let digest = |page: &[u8]| {
        Sha256::digest(page)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    eprintln!(
        "observe: identify-sha256 controller {} namespace {}",
        digest(raw.controller()),
        digest(raw.namespace())
    );
    stop(&mut disk);
    teardown(registration, &mut disk);
}

/// The persistence contract holds on the volume across a host-side
/// controller disable, a detach and a fresh attach in this process.
/// `KESTRIKE_IDLE_OBSERVATION_MS` is the window, in milliseconds, a write
/// fetched before the disable and not yet complete is given to land between
/// the contract's two readbacks. NVMe permits a late landing inside it; the
/// case fails one with `qualified-late-landing`, and a pass means none was
/// observed within the window. The contract writes six units of the derived
/// profile's size, 16 KiB on EBS: one pair near the volume's start, one near
/// half its capacity and one near its end. The case fails as inconclusive
/// when the one completion pick before the disable observed every
/// outstanding write's completion; a completion that pick missed leaves
/// its write outstanding in the contract's bookkeeping, so a pass shows the
/// landing checks ran, with the in-flight status of each write at the
/// disable known only to the device.
/// Each `observe:` line prints after the assertion it follows passed.
#[test]
#[ignore = "needs a disposable EBS volume bound by kestrike-bind, named by KESTRIKE_MAPPINGS"]
fn the_volume_meets_the_persistence_contract_across_a_controller_disable() {
    let window = Duration::from_millis(
        std::env::var("KESTRIKE_IDLE_OBSERVATION_MS")
            .expect("KESTRIKE_IDLE_OBSERVATION_MS names the late-landing window")
            .parse()
            .expect("the window is a whole number of milliseconds"),
    );
    assert!(
        window > Duration::ZERO,
        "the late-landing window is positive"
    );
    let (lock, env) = bound();
    let arena = arena_on(TestPlatform::linux(), 16, 5);
    let (registration, mut disk) = start(&lock, &env, &arena);
    let guard = AbortOnUnwind;
    let pause = || std::thread::sleep(Duration::from_micros(10));
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    // SAFETY: `guard` aborts the process on an unwind out of the contract, before the arena unmaps or any buffer the controller may write is reacquired.
    let expectation =
        unsafe { super::super::persistence_contract::before_stop(&mut disk, &arena, nonce, pause) }
            .unwrap();
    let report = disk.witness().stop.expect("the disable read the registers");
    assert!(
        report.proven && report.cc & 1 == 0 && report.csts & 1 == 0,
        "CC.EN and CSTS.RDY read zero: {report:?}"
    );
    teardown(registration, &mut disk);
    let (registration, mut disk) = start(&lock, &env, &arena);
    // SAFETY: as for the first half.
    let landed = unsafe {
        super::super::persistence_contract::after_reattach(
            &mut disk,
            &arena,
            &expectation,
            window,
            pause,
        )
    };
    drop(guard);
    let landed = landed.unwrap_or_else(|violation| panic!("{}: {violation:?}", violation.label()));
    assert!(
        super::super::persistence_contract::sometimes_outstanding(&[expectation.outstanding()]),
        "inconclusive: every outstanding write's completion was observed before the disable"
    );
    let landings: Vec<String> = landed
        .landings
        .iter()
        .map(|landing| {
            format!(
                "{} old {} new {} other {}",
                landing.token.raw(),
                landing.old,
                landing.new,
                landing.other
            )
        })
        .collect();
    eprintln!("observe: landing {}", landings.join(", "));
    eprintln!(
        "observe: completed-before-stop exact {} outstanding {} nonce {nonce:#x}",
        landed.completed,
        landed.landings.len()
    );
    eprintln!("observe: late-landing none within {}", window.as_millis());
    stop(&mut disk);
    teardown(registration, &mut disk);
}

#[test]
#[ignore = "needs a disposable EBS volume bound by kestrike-bind, named by KESTRIKE_MAPPINGS"]
fn the_spdk_driver_passes_every_outcome_row_on_the_volume() {
    let (mut lock, env) = bound();
    let (first_authority, second_authority) = (
        crate::soak::tenure_authority(&mut lock),
        crate::soak::tenure_authority(&mut lock),
    );
    let arena = arena_on(TestPlatform::linux(), 16, 5);
    let (registration, mut disk) = start(&lock, &env, &arena);
    let geometry = disk.geometry();

    // Refused: past the capacity, and at the admission depth.
    let mut buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    let past = DeviceRange::new(geometry.capacity, 4096).unwrap();
    // SAFETY: each buffer is exclusive to its command until its completion is picked; a refusal ends the obligation.
    let refused =
        unsafe { disk.submit_read(CommandToken::from_raw(1), past, buffer.range(4096).unwrap()) };
    assert_eq!(refused.unwrap_err().reason, RefusalReason::InvalidRange);
    let held: Vec<_> = (0..geometry.queue_depth)
        .map(|_| arena.acquire(PoolKind::ReadResponse).unwrap())
        .collect();
    let first = DeviceRange::new(0, 4096).unwrap();
    for (n, slot) in held.iter().enumerate() {
        // SAFETY: as above.
        unsafe {
            disk.submit_read(
                CommandToken::from_raw(10 + n as u64),
                first,
                slot.range(4096).unwrap(),
            )
        }
        .unwrap();
    }
    // SAFETY: as above.
    let full = unsafe {
        disk.submit_read(
            CommandToken::from_raw(99),
            first,
            buffer.range(4096).unwrap(),
        )
    };
    assert_eq!(full.unwrap_err().reason, RefusalReason::QueueFull);
    // A full sink makes no native call and takes nothing.
    let mut none = Vec::new();
    disk.pick_completions(&mut CompletionSink::new(&mut none, 0));
    assert!(none.is_empty());
    let out = pick_each(&mut disk, geometry.queue_depth as usize);
    for done in &out {
        eprintln!("read status {:?}", done.status);
        assert_eq!(done.status.classify(4096), Classification::Success);
    }

    // Accepted and succeeded: a write and the read that returns its bytes.
    let pattern: Vec<u8> = (0..4096u32).map(|n| (n % 251) as u8).collect();
    buffer.bytes_mut()[..4096].copy_from_slice(&pattern);
    let block = DeviceRange::new(4096, 4096).unwrap();
    // SAFETY: as above.
    unsafe {
        disk.submit_write(
            CommandToken::from_raw(2),
            block,
            buffer.range(4096).unwrap(),
        )
    }
    .unwrap();
    let written = pick_one(&mut disk);
    assert_eq!(
        (written.token, written.status.classify(4096)),
        (CommandToken::from_raw(2), Classification::Success)
    );
    buffer.bytes_mut().fill(0);
    // SAFETY: as above.
    unsafe {
        disk.submit_read(
            CommandToken::from_raw(3),
            block,
            buffer.range(4096).unwrap(),
        )
    }
    .unwrap();
    assert_eq!(
        pick_one(&mut disk).status.classify(4096),
        Classification::Success
    );
    assert_eq!(&buffer.bytes()[..4096], &pattern[..]);

    // Failed: the device refuses a range past the namespace, and its raw status passes through.
    disk.widen_capacity(4096);
    // SAFETY: as above.
    unsafe { disk.submit_read(CommandToken::from_raw(4), past, buffer.range(4096).unwrap()) }
        .unwrap();
    let failed = pick_one(&mut disk);
    eprintln!("past-capacity status {:?}", failed.status);
    assert_eq!(failed.status.classify(4096), Classification::Failed);

    // Quiesced: proven controller disable, then permanent refusal and silence.
    stop(&mut disk);
    // SAFETY: as above.
    let gone = unsafe {
        disk.submit_read(
            CommandToken::from_raw(5),
            block,
            buffer.range(4096).unwrap(),
        )
    };
    assert_eq!(gone.unwrap_err().reason, RefusalReason::DeviceGone);
    let mut out = Vec::with_capacity(4);
    disk.pick_completions(&mut CompletionSink::new(&mut out, 4));
    assert!(out.is_empty(), "Stopped produces no later terminal");
    teardown(registration, &mut disk);
    drop((buffer, held));

    // A volume over a fresh driver round-trips a record.
    let storage = hardware_storage_on(RAW, 3 * 16384, 64);
    let (registration, disk) = start(&lock, &env, &arena);
    let mut volume = Volume::attach(
        &storage,
        &arena,
        disk,
        crate::storage::portable::scripted::ScriptedClock::trusted(),
        first_authority,
        8,
        TICK,
        &mut EngineBudget::new(1 << 24),
    )
    .map_err(|(error, _)| error)
    .unwrap();
    open_polled(&mut volume, 1 << 20);
    let first = volume.session();
    let old = round_trip(&storage, &mut volume, 9);
    shut(volume, registration);

    // A cold start under the next, higher session trusts nothing the first one wrote.
    let storage = hardware_storage_on(RAW, 3 * 16384, 64);
    let (registration, disk) = start(&lock, &env, &arena);
    let mut volume = Volume::attach(
        &storage,
        &arena,
        disk,
        crate::storage::portable::scripted::ScriptedClock::trusted(),
        second_authority,
        8,
        TICK,
        &mut EngineBudget::new(1 << 24),
    )
    .map_err(|(error, _)| error)
    .unwrap();
    open_polled(&mut volume, 1 << 20);
    let stale = RawRead {
        session: volume.session(),
        ..old
    };
    let op = volume.read_raw(&stale, u64::MAX).expect("a raw read");
    let (exposed, status) = finish(&mut volume, op);
    assert!(exposed.is_empty(), "a stale record exposes nothing");
    let second = volume.session();
    assert!(second > first, "the second attach writes a higher session");
    assert_eq!(
        status,
        ReadStatus::HeaderMismatch(HeaderMismatch::Session {
            expected: second,
            found: first
        })
    );
    round_trip(&storage, &mut volume, 6);
    shut(volume, registration);

    let watchdog = Watchdog::arm(Duration::from_secs(30), Arc::new(Unreachable)).unwrap();
    env.finish(&watchdog).unwrap();
    assert!(matches!(
        arena.release(),
        Ok(crate::storage::Released::Complete)
    ));
}

/// Reads, then writes, the outstanding-stop schedule hands the driver, one
/// per `SPAN`-byte block from the volume's start; the writes cover the
/// volume's second 64 KiB.
const READS: u64 = 4;
const WRITES: u64 = 4;
const SPAN: u32 = 16384;

type SpdkTable<'a, 'l, N> = CommandTable<'a, SpdkDisk<'l, N>>;

/// Why the outstanding-stop schedule earned no stop credit.
#[derive(Debug, PartialEq, Eq)]
enum StopFailure {
    /// The witness pick delivered a terminal or left no command at the device.
    Drained {
        accepted: usize,
        staged: usize,
        delivered: usize,
    },
    /// The first stop call found every command returned, or SPDK refused to
    /// start the disable with every command still held.
    NotDraining(QuiesceProgress),
    /// The stop ended neither proven nor delivered, with the last registers read and the census then.
    Unproven {
        progress: QuiesceProgress,
        report: Option<StopReport>,
        census: (u32, u32, u32),
    },
}

/// What a proven outstanding stop observed: the register words each stop
/// call after the first read, the last of them the certificate, the
/// commands the first call found outstanding, the terminals the proving
/// call left to later calls, and each command's one terminal.
#[derive(Debug)]
struct Stopped {
    reports: Vec<StopReport>,
    first_outstanding: u32,
    left_to_delivery: u32,
    /// Commands that completed before the proof, by their terminal's token.
    completed: Vec<CommandToken>,
    quiesced_reads: Vec<CommandToken>,
    /// Writes the stop ended; the device may or may not have written them.
    unknown_writes: Vec<CommandToken>,
}

/// The CC.EN and CSTS.RDY masks.
fn masks() -> (u32, u32) {
    // SAFETY: the mask accessors read native constants.
    unsafe {
        (
            sys::spdk_sys_nvme_cc_en_mask(),
            sys::spdk_sys_nvme_csts_rdy_mask(),
        )
    }
}

/// The table's pending commands and the read and write pools' buffers in storage custody.
fn census<N: Native>(
    table: &SpdkTable<'_, '_, N>,
    arena: &BufferArena<TestPlatform>,
) -> (u32, u32, u32) {
    (
        table.report().pending,
        arena.report(PoolKind::ReadResponse).storage,
        arena.report(PoolKind::ReceiveWrite).storage,
    )
}

/// Submits `reads` reads from block 0, then `writes` writes of a per-block
/// pattern from block [`READS`], in submission order; `reads` is at most
/// [`READS`], so the two ranges stay apart.
fn dispatch_of<'a, N: Native>(
    table: &mut SpdkTable<'a, '_, N>,
    arena: &'a BufferArena<TestPlatform>,
    reads: u64,
    writes: u64,
) -> Vec<CommandToken> {
    assert!(reads <= READS && writes <= WRITES);
    let range = |block: u64| DeviceRange::new(block * u64::from(SPAN), SPAN).unwrap();
    let mut tokens: Vec<CommandToken> = (0..reads)
        .map(|block| {
            table
                .submit_read(arena.acquire(PoolKind::ReadResponse).unwrap(), range(block))
                .unwrap()
        })
        .collect();
    tokens.extend((READS..READS + writes).map(|block| {
        let mut buffer = arena.acquire(PoolKind::ReceiveWrite).unwrap();
        buffer.bytes_mut()[..SPAN as usize].fill(block as u8);
        table.submit_write(buffer, range(block)).unwrap()
    }));
    tokens
}

/// One pick, whose completion poll rings the submission doorbell, so the
/// device holds every accepted command without a staged terminal. Credits
/// the witness only when that count is nonzero and the pick delivered
/// nothing; a submit alone proves host custody, since the doorbell rings
/// only in a poll.
fn witness<'a, N: Native>(
    table: &mut SpdkTable<'a, '_, N>,
    out: &mut Vec<Terminal<'a>>,
) -> Result<usize, StopFailure> {
    let delivered = table.poll(out).delivered;
    let super::DriverWitness {
        accepted, staged, ..
    } = table.driver_witness();
    eprintln!(
        "outstanding before stop: accepted {accepted}, staged {staged}, delivered {delivered}"
    );
    if delivered == 0 && accepted > staged {
        Ok(accepted - staged)
    } else {
        Err(StopFailure::Drained {
            accepted,
            staged,
            delivered,
        })
    }
}

/// Quiesces the table until the driver proves the stop or `patient` says
/// stop waiting; `out` has room for every command. The first call must
/// report `Draining` with a command outstanding. Until the proof, every
/// call keeps the driver's lease and keeps each outstanding command's
/// buffer in storage custody; the proof then ends every outstanding command
/// as `Quiesced`. The first call only starts the disable; each later call
/// reads the registers once, so each later call's report is a fresh read.
fn stop_outstanding<'a, N: Native>(
    table: &mut SpdkTable<'a, '_, N>,
    arena: &BufferArena<TestPlatform>,
    out: &mut Vec<Terminal<'a>>,
    mut patient: impl FnMut() -> bool,
) -> Result<Stopped, StopFailure> {
    let mut reports = Vec::new();
    let leased = table.driver_witness().leased;
    let mut progress = table.quiesce(out);
    eprintln!("first stop call: {progress:?}");
    let first_outstanding = match progress {
        QuiesceProgress::Draining { outstanding } if outstanding > 0 => outstanding,
        _ => return Err(StopFailure::NotDraining(progress)),
    };
    loop {
        let report = table.driver_witness().stop;
        if let Some(report) = report {
            eprintln!(
                "registers: CC {:#010x} CSTS {:#010x} proven {}",
                report.cc, report.csts, report.proven
            );
            reports.push(report);
        }
        match progress {
            QuiesceProgress::Quiesced(Quiesced::DeviceStopped)
            | QuiesceProgress::Delivering { .. } => break,
            QuiesceProgress::Draining { .. } if patient() => {
                let (pending, reads, writes) = census(table, arena);
                assert_eq!(
                    reads + writes,
                    pending,
                    "each outstanding buffer stays held"
                );
                assert_eq!(table.driver_witness().leased, leased, "the lease stays");
            }
            _ => {
                return Err(StopFailure::Unproven {
                    progress,
                    report,
                    census: census(table, arena),
                });
            }
        }
        progress = table.quiesce(out);
    }
    let left_to_delivery = match progress {
        QuiesceProgress::Delivering { remaining } => remaining,
        _ => 0,
    };
    while let QuiesceProgress::Delivering { remaining } = progress {
        eprintln!("delivering after the proof: {remaining} remaining");
        progress = table.quiesce(out);
    }
    assert_eq!(progress, QuiesceProgress::Quiesced(Quiesced::DeviceStopped));
    Ok(Stopped::sorted(
        reports,
        first_outstanding,
        left_to_delivery,
        out,
    ))
}

impl Stopped {
    /// Sorts the terminals in `out` by how they ended.
    fn sorted(
        reports: Vec<StopReport>,
        first_outstanding: u32,
        left_to_delivery: u32,
        out: &[Terminal<'_>],
    ) -> Self {
        let mut stopped = Self {
            reports,
            first_outstanding,
            left_to_delivery,
            completed: Vec::new(),
            quiesced_reads: Vec::new(),
            unknown_writes: Vec::new(),
        };
        for terminal in out {
            match terminal {
                Terminal::Quiesced {
                    token,
                    op: Operation::Read,
                    ..
                } => stopped.quiesced_reads.push(*token),
                Terminal::Quiesced {
                    token,
                    op: Operation::Write,
                    ..
                } => stopped.unknown_writes.push(*token),
                other => stopped.completed.push(other.token()),
            }
        }
        eprintln!(
            "returns after stop: completed {:?}, quiesced reads {:?}, writes of unknown outcome {:?}",
            stopped.completed, stopped.quiesced_reads, stopped.unknown_writes
        );
        stopped
    }
}

/// The proven stop's checks: the last read is the certificate, with CC.EN
/// and CSTS.RDY clear in the raw words (an all-ones failed read has both
/// set), the commands the first stop call found outstanding are exactly
/// the ones the proof ended, since a stopping driver polls no completion,
/// and every dispatched command returned one terminal.
fn check_stopped(stopped: &Stopped, tokens: &[CommandToken]) {
    let (en, rdy) = masks();
    let certificate = *stopped.reports.last().expect("a register read");
    assert!(certificate.proven, "{certificate:?}");
    assert_eq!((certificate.cc & en, certificate.csts & rdy), (0, 0));
    assert!(
        stopped.reports[..stopped.reports.len() - 1]
            .iter()
            .all(|report| !report.proven),
        "one proving read"
    );
    let mut seen = [
        &stopped.completed[..],
        &stopped.quiesced_reads,
        &stopped.unknown_writes,
    ]
    .concat();
    let mut dispatched = tokens.to_vec();
    seen.sort_unstable_by_key(|token| token.raw());
    dispatched.sort_unstable_by_key(|token| token.raw());
    assert_eq!(seen, dispatched, "each command ends once");
    assert_eq!(
        stopped.quiesced_reads.len() + stopped.unknown_writes.len(),
        stopped.first_outstanding as usize,
        "the proof ends exactly the commands outstanding at the first stop call"
    );
}

/// The CPU this thread runs on, the first `model name` in `/proc/cpuinfo`
/// (empty on AArch64, whose kernels print none), the kernel release, and the
/// native build.
fn pins() -> String {
    let read = |path: &str| std::fs::read_to_string(path).unwrap_or_default();
    let cpuinfo = read("/proc/cpuinfo");
    let model = cpuinfo
        .lines()
        .find_map(|line| line.strip_prefix("model name"))
        .map_or("", |rest| rest.trim_start_matches([' ', '\t', ':']));
    // SAFETY: reads this thread's CPU.
    let core = unsafe { libc::sched_getcpu() };
    format!(
        "core {core} ({model}), kernel {}, native {}",
        read("/proc/sys/kernel/osrelease").trim(),
        sys::PINS
    )
}

/// The controller stops while dispatched reads and writes are outstanding,
/// which the host judges by observed completions:
/// one pick rings the doorbell and delivers nothing, the first stop call
/// finds the commands outstanding, register reads certify the disable with
/// every buffer and the lease held until then, and the proof ends each
/// outstanding command once, its write's outcome unknown. A failed stop
/// keeps every buffer by aborting the process.
#[test]
#[ignore = "needs a disposable EBS volume bound by kestrike-bind, named by KESTRIKE_MAPPINGS"]
fn the_spdk_driver_stops_with_dispatched_reads_and_writes_outstanding() {
    stop_with(READS, WRITES);
}

/// Stops the controller with `reads` reads and `writes` writes outstanding,
/// recording each command's evidence before the stop and checking that the
/// proof ends exactly those commands, once each.
fn stop_with(reads: u64, writes: u64) {
    let (lock, env) = bound();
    eprintln!("pins: {}", pins());
    let arena = arena_on(TestPlatform::linux(), 16, 5);
    let (registration, disk) = start(&lock, &env, &arena);
    let depth = u16::try_from(CONFIG.queue_depth).unwrap();
    let mut table = CommandTable::new(disk, &arena, depth, &mut EngineBudget::new(usize::MAX))
        .map_err(|(error, _)| error)
        .unwrap();
    // Declared after the table, so an unwind aborts before the table returns a buffer the controller may still access.
    let guard = AbortOnUnwind;
    let tokens = dispatch_of(&mut table, &arena, reads, writes);
    let mut out = Vec::with_capacity(tokens.len());
    for (i, token) in tokens.iter().enumerate() {
        let evidence = table
            .evidence(*token)
            .expect("evidence for a dispatched command");
        eprintln!("evidence before stop: {token:?} {evidence:?}");
        let (operation, kind) = if (i as u64) < reads {
            (Operation::Read, PoolKind::ReadResponse)
        } else {
            (Operation::Write, PoolKind::ReceiveWrite)
        };
        assert_eq!(
            (evidence.operation, evidence.accepted, evidence.buffer.0),
            (operation, true, kind)
        );
    }
    witness(&mut table, &mut out).expect("an outstanding witness");
    assert!(table.driver_witness().leased, "the driver holds its lease");
    eprintln!("census before stop: {:?}", census(&table, &arena));
    let start_at = Instant::now();
    let stopped = match stop_outstanding(&mut table, &arena, &mut out, || {
        start_at.elapsed() < PATIENCE
    }) {
        Ok(stopped) => stopped,
        Err(failure) => {
            eprintln!("failed stop, memory retained: {failure:?}");
            panic!("the stop stayed unproven");
        }
    };
    check_stopped(&stopped, &tokens);
    assert!(tokens.iter().all(|token| table.evidence(*token).is_none()));
    drop(out);
    eprintln!("final census: {:?}", census(&table, &arena));
    assert_eq!(census(&table, &arena), (0, 0, 0));
    let Ok(mut disk) = table.release_idle() else {
        panic!("a quiesced table holds no pending or abandoned record");
    };
    teardown(registration, &mut disk);
    drop(guard);
    let watchdog = Watchdog::arm(Duration::from_secs(30), Arc::new(Unreachable)).unwrap();
    env.finish(&watchdog).unwrap();
    assert!(matches!(
        arena.release(),
        Ok(crate::storage::Released::Complete)
    ));
}

/// The controller stops with reads alone outstanding.
#[test]
#[ignore = "needs a disposable EBS volume bound by kestrike-bind, named by KESTRIKE_MAPPINGS"]
fn the_spdk_driver_stops_with_a_read_outstanding() {
    stop_with(READS, 0);
}

/// The controller stops with writes alone outstanding; each write's outcome stays unknown.
#[test]
#[ignore = "needs a disposable EBS volume bound by kestrike-bind, named by KESTRIKE_MAPPINGS"]
fn the_spdk_driver_stops_with_a_write_outstanding() {
    stop_with(0, WRITES);
}

/// The NVMe read opcode, and the generic internal-error status code an injection writes.
const OPC_READ: u8 = 0x02;
const INTERNAL_ERROR: (u8, u8) = (0, 0x06);

/// What an injected read's run observed: whether an application deadline
/// detached it first, and its terminal's variant, operation and status.
#[derive(Debug)]
struct InjectedEnd {
    expired: bool,
    variant: &'static str,
    op: Operation,
    status: Option<DeviceStatus>,
}

/// Arms an error injection for one read, submits the read through a table
/// over `disk`, and polls until its terminal arrives, cancelling it once
/// `expire` passes to model an application deadline; then removes the
/// injection. The expired read must keep its slot and buffer incarnation.
fn injected_read<'a>(
    arena: &'a BufferArena<TestPlatform>,
    disk: SpdkDisk<'a>,
    do_not_submit: bool,
    mut expire: Option<Duration>,
) -> (SpdkTable<'a, 'a, super::native::Spdk>, InjectedEnd) {
    let mut table = CommandTable::new(disk, arena, 4, &mut EngineBudget::new(usize::MAX))
        .map_err(|(error, _)| error)
        .unwrap();
    let rc = table
        .driver()
        .inject(OPC_READ, do_not_submit, 2_000_000, 1, INTERNAL_ERROR);
    assert_eq!(rc, 0, "SPDK installs the injection");
    // Held while the read is at the device, so an unwind aborts before its buffer returns.
    let guard = AbortOnUnwind;
    let token = dispatch_of(&mut table, arena, 1, 0)[0];
    let evidence = table.evidence(token).unwrap();
    eprintln!(
        "injection scope: qpair read opcode, count 1, do_not_submit {do_not_submit}; evidence {evidence:?}"
    );
    let (start, mut out, mut expired) = (Instant::now(), Vec::with_capacity(1), false);
    while out.is_empty() {
        assert!(start.elapsed() < PATIENCE, "the injected read ends");
        if expire.is_some_and(|after| start.elapsed() > after) {
            expire = None;
            expired = true;
            table.cancel(token).unwrap();
            assert_eq!(
                table.evidence(token).map(|e| (e.accepted, e.buffer)),
                Some((false, evidence.buffer)),
                "the expired read keeps its slot and buffer incarnation"
            );
            eprintln!("application expiry after {:?}", start.elapsed());
        }
        table.poll(&mut out);
    }
    eprintln!("terminal after {:?}: {:?}", start.elapsed(), out[0]);
    let end = match &out[0] {
        Terminal::Abandoned { op, status, .. } => ("Abandoned", *op, *status),
        Terminal::Failed { op, status, .. } => ("Failed", *op, Some(*status)),
        Terminal::Read { status, .. } => ("Read", Operation::Read, Some(*status)),
        other => panic!("an injected read ends otherwise: {other:?}"),
    };
    drop(out);
    drop(guard);
    table.driver().clear_injection(OPC_READ);
    eprintln!("injection removed");
    let (variant, op, status) = end;
    (
        table,
        InjectedEnd {
            expired,
            variant,
            op,
            status,
        },
    )
}

/// Whether `status` is exactly the status an injection of [`INTERNAL_ERROR`]
/// writes: its status code type and code, with the CRD, M and DNR bits clear;
/// a submitted command keeps its device phase bit, the one bit left out.
fn injected(status: Option<DeviceStatus>) -> bool {
    let code = u16::from(INTERNAL_ERROR.1) << 1 | u16::from(INTERNAL_ERROR.0) << 9;
    matches!(status, Some(DeviceStatus::Nvme(raw)) if raw & 0xFFFE == code)
}

/// SPDK holds a `do_not_submit` read off the device and synthesizes its
/// completion after the injection's timeout. An application deadline that
/// passes first leaves the read detached on its buffer until that
/// synthetic terminal, which ends it with the injected status and no read
/// view. The row is adapter evidence: no device saw the command.
#[test]
#[ignore = "needs a disposable EBS volume bound by kestrike-bind, named by KESTRIKE_MAPPINGS"]
fn an_expired_read_held_by_a_synthetic_delay_ends_at_its_late_terminal() {
    let (lock, env) = bound();
    let arena = arena_on(TestPlatform::linux(), 16, 5);
    let (registration, disk) = start(&lock, &env, &arena);
    let (table, end) = injected_read(&arena, disk, true, Some(Duration::from_millis(200)));
    eprintln!("adapter-only evidence (synthetic, do_not_submit): {end:?}");
    assert!(end.expired);
    assert_eq!((end.variant, end.op), ("Abandoned", Operation::Read));
    assert!(injected(end.status), "{:?}", end.status);
    let mut disk = shut_table(table, &arena);
    teardown(registration, &mut disk);
    drop(disk);
    let watchdog = Watchdog::arm(Duration::from_secs(30), Arc::new(Unreachable)).unwrap();
    env.finish(&watchdog).unwrap();
    assert!(matches!(
        arena.release(),
        Ok(crate::storage::Released::Complete)
    ));
}

/// A submitted read whose completion SPDK rewrites to the injected status
/// reaches the table as `Failed` with that raw status.
#[test]
#[ignore = "needs a disposable EBS volume bound by kestrike-bind, named by KESTRIKE_MAPPINGS"]
fn a_submitted_read_with_a_rewritten_status_fails_with_that_raw_status() {
    let (lock, env) = bound();
    let arena = arena_on(TestPlatform::linux(), 16, 5);
    let (registration, disk) = start(&lock, &env, &arena);
    let (table, end) = injected_read(&arena, disk, false, None);
    eprintln!("submitted status rewrite (do_not_submit false): {end:?}");
    assert_eq!(
        (end.expired, end.variant, end.op),
        (false, "Failed", Operation::Read)
    );
    assert!(injected(end.status), "{:?}", end.status);
    let mut disk = shut_table(table, &arena);
    teardown(registration, &mut disk);
    drop(disk);
    let watchdog = Watchdog::arm(Duration::from_secs(30), Arc::new(Unreachable)).unwrap();
    env.finish(&watchdog).unwrap();
    assert!(matches!(
        arena.release(),
        Ok(crate::storage::Released::Complete)
    ));
}

fn shut_table<'l, N: Native>(
    mut table: SpdkTable<'_, 'l, N>,
    arena: &BufferArena<TestPlatform>,
) -> SpdkDisk<'l, N> {
    let mut none = Vec::new();
    let start_at = Instant::now();
    while !matches!(table.quiesce(&mut none), QuiesceProgress::Quiesced(_)) {
        assert!(start_at.elapsed() < PATIENCE, "the table quiesced");
    }
    assert_eq!(census(&table, arena), (0, 0, 0));
    let Ok(mut disk) = table.release_idle() else {
        panic!("a quiesced table holds no pending or abandoned record");
    };
    stop(&mut disk);
    disk
}

/// A watchdog that expires while the stop of outstanding reads and writes
/// stalls before its proof asks the external controller, over the FIFOs
/// `KESTRIKE_CONTROLLER_REQUESTS` and `KESTRIKE_CONTROLLER_ACKS` name,
/// to fence the endpoint and contain the device and host. The registration
/// stays retained with the backing mapped, and the watchdog's drop waits
/// for the controller's acknowledgement.
#[test]
#[ignore = "needs a disposable EBS volume bound by kestrike-bind, named by KESTRIKE_MAPPINGS, and the containment controller's FIFOs"]
fn a_watchdog_expiry_during_a_pre_proof_stall_escalates_to_the_controller() {
    // The lane holds both FIFOs open read-write, so neither open waits for the other end.
    let requests = std::fs::OpenOptions::new()
        .write(true)
        .open(std::env::var("KESTRIKE_CONTROLLER_REQUESTS").unwrap())
        .unwrap();
    let acks = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(std::env::var("KESTRIKE_CONTROLLER_ACKS").unwrap())
        .unwrap();
    let supervisor = Arc::new(
        crate::native::ControllerSupervisor::new(
            std::env::var("KESTRIKE_MAPPINGS").unwrap(),
            requests,
            std::io::BufReader::new(acks),
        )
        .unwrap(),
    );
    let (lock, env) = bound();
    let arena = arena_on(TestPlatform::linux(), 16, 5);
    let (mut registration, disk) = start(&lock, &env, &arena);
    let depth = u16::try_from(CONFIG.queue_depth).unwrap();
    let mut table = CommandTable::new(disk, &arena, depth, &mut EngineBudget::new(usize::MAX))
        .map_err(|(error, _)| error)
        .unwrap();
    // Declared after the table, so an unwind aborts before the table returns a buffer the controller may still access.
    let guard = AbortOnUnwind;
    let tokens = dispatch_of(&mut table, &arena, READS, WRITES);
    let mut out = Vec::with_capacity(tokens.len());
    witness(&mut table, &mut out).expect("an outstanding witness");
    eprintln!("census before stall: {:?}", census(&table, &arena));
    let watchdog = Watchdog::arm(Duration::from_millis(100), supervisor.clone()).unwrap();
    let waited = supervisor.clone();
    let stalled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stalling = stalled.clone();
    table.driver().stall_before_proof(move || {
        let unrequested_at_entry = !waited.requested();
        let start = Instant::now();
        while !waited.requested() && start.elapsed() < PATIENCE {
            std::thread::sleep(Duration::from_millis(5));
        }
        stalling.store(
            unrequested_at_entry && waited.requested(),
            std::sync::atomic::Ordering::Release,
        );
    });
    let start_at = Instant::now();
    let stopped = stop_outstanding(&mut table, &arena, &mut out, || {
        start_at.elapsed() < PATIENCE
    })
    .expect("the disable proves the stop after the stall");
    check_stopped(&stopped, &tokens);
    assert!(watchdog.expired());
    // Asserted after the proof, so a stall the request did not land inside fails the case with the device stopped.
    assert!(
        stalled.load(std::sync::atomic::Ordering::Acquire),
        "the request reached the controller inside the stall, after it began and before the proof"
    );
    eprintln!("stalled until the request");
    eprintln!("containment requests {}", supervisor.calls());
    drop(out);
    let Ok(mut disk) = table.release_idle() else {
        panic!("a quiesced table holds no pending or abandoned record");
    };
    registration
        .device_stopped(disk.stop_proof().unwrap())
        .unwrap();
    let retained = registration.unregister(&watchdog).unwrap_err();
    eprintln!("retained after expiry: {:?}", retained.error);
    assert_eq!(retained.error.step, RegistrationStep::Watchdog);
    drop(retained);
    drop(disk);
    let blocked = arena
        .release()
        .expect_err("the retained registration blocks the release");
    assert_eq!(blocked.registrations, 1);
    drop(watchdog);
    eprintln!("controller acknowledged {}", supervisor.acknowledged());
    assert!(supervisor.acknowledged());
    drop(guard);
}

/// A scripted table holding the dispatched schedule, its driver leased
/// from `registration`; its polls complete
/// every command unless the script queues poll results.
fn scripted<'a>(
    arena: &'a BufferArena<TestPlatform>,
    registration: &mut ArenaRegistration<'_>,
    address: &str,
) -> (SpdkTable<'a, 'a, Scripted>, Vec<CommandToken>) {
    SCRIPT.take();
    let mut disk =
        SpdkDisk::<Scripted>::scripted_leased(address, limits(CONFIG.queue_depth), registration);
    disk.set_reservation_limits(crate::storage::ReservationLimits::new(2, 2, 10, 10).unwrap());
    let probe = arena.acquire(PoolKind::ReadResponse).unwrap();
    disk.mark_verified(probe.range(SPAN).unwrap());
    drop(probe);
    let depth = u16::try_from(CONFIG.queue_depth).unwrap();
    let mut table = CommandTable::new(disk, arena, depth, &mut EngineBudget::new(usize::MAX))
        .map_err(|(error, _)| error)
        .unwrap();
    let tokens = dispatch_of(&mut table, arena, READS, WRITES);
    (table, tokens)
}

/// Two completion polls without completions, one for the witness pick and
/// one for the first stop call's pick, then a disable that reads CC.EN
/// still set `unproven` times before the proving read.
fn script_disable(unproven: usize) {
    let (en, _) = masks();
    SCRIPT.with_borrow_mut(|script| {
        script.poll.extend([(0, false), (0, false)]);
        script
            .registers
            .extend(std::iter::repeat_n((en, 0), unproven));
    });
}

/// The outstanding-stop schedule over the scripted driver: the witness
/// holds after the pick, the first stop call drains with all eight
/// outstanding, the unproven read keeps every buffer, and the proving read
/// ends all eight as `Quiesced` with the writes' outcome unknown.
#[test]
fn the_outstanding_stop_schedule_certifies_the_disable_over_scripted_spdk() {
    let (env, arena) = (
        Environment::detached(),
        arena_on(TestPlatform::heap(4096), 16, 5),
    );
    let mut registration = registration_tests::ready(&env, &arena);
    let (mut table, tokens) = scripted(&arena, &mut registration, "scripted:outstanding-stop");
    assert!(table.driver_witness().leased);
    script_disable(1);
    let mut out = Vec::with_capacity(tokens.len());
    assert_eq!(witness(&mut table, &mut out), Ok(8));
    assert_eq!(census(&table, &arena), (8, 4, 4));
    let stopped = stop_outstanding(&mut table, &arena, &mut out, || true).unwrap();
    check_stopped(&stopped, &tokens);
    assert_eq!(
        (stopped.first_outstanding, stopped.left_to_delivery),
        (8, 0)
    );
    let (en, _) = masks();
    assert_eq!(
        stopped.reports,
        [
            StopReport {
                cc: en,
                csts: 0,
                proven: false
            },
            StopReport {
                cc: 0,
                csts: 0,
                proven: true
            }
        ]
    );
    assert_eq!(
        (
            stopped.completed.len(),
            stopped.quiesced_reads.len(),
            stopped.unknown_writes.len()
        ),
        (0, 4, 4)
    );
    drop(out);
    assert_eq!(census(&table, &arena), (0, 0, 0));
    // A stopped driver answers later quiesces without a read and keeps its certificate.
    let Ok(mut disk) = table.release_idle() else {
        panic!("a quiesced table holds no pending or abandoned record");
    };
    SCRIPT.with_borrow_mut(|script| script.registers.push_back((u32::MAX, u32::MAX)));
    assert_eq!(disk.quiesce(), QuiesceStatus::Stopped);
    assert_eq!(disk.witness().stop, stopped.reports.last().copied());
}

#[test]
fn a_read_the_first_stop_call_completes_still_certifies_the_disable() {
    let (env, arena) = (
        Environment::detached(),
        arena_on(TestPlatform::heap(4096), 16, 5),
    );
    let mut registration = registration_tests::ready(&env, &arena);
    let (mut table, tokens) = scripted(
        &arena,
        &mut registration,
        "scripted:partly-completed-outstanding-stop",
    );
    let (en, _) = masks();
    SCRIPT.with_borrow_mut(|script| {
        script.poll.push_back((0, false));
        script.finished.push_back(1);
        script.registers.push_back((en, 0));
    });
    let mut out = Vec::with_capacity(tokens.len());
    assert_eq!(witness(&mut table, &mut out), Ok(8));
    let stopped = stop_outstanding(&mut table, &arena, &mut out, || true).unwrap();
    check_stopped(&stopped, &tokens);
    assert_eq!(stopped.first_outstanding, 7);
    assert_eq!(
        stopped.left_to_delivery, 0,
        "the completed read's empty slot spends none of the proving call's room"
    );
    assert_eq!(stopped.completed, [tokens[0]]);
    assert_eq!(
        (stopped.quiesced_reads.len(), stopped.unknown_writes.len()),
        (3, 4)
    );
    assert_eq!(
        stopped.reports,
        [
            StopReport {
                cc: en,
                csts: 0,
                proven: false
            },
            StopReport {
                cc: 0,
                csts: 0,
                proven: true
            }
        ]
    );
    drop(out);
    assert_eq!(census(&table, &arena), (0, 0, 0));
}

/// A stop that stays unproven past its patience fails with every buffer
/// still held, and only a later proving read returns them.
#[test]
fn an_unproven_outstanding_stop_fails_with_every_buffer_held() {
    let (env, arena) = (
        Environment::detached(),
        arena_on(TestPlatform::heap(4096), 16, 5),
    );
    let mut registration = registration_tests::ready(&env, &arena);
    let (mut table, tokens) = scripted(
        &arena,
        &mut registration,
        "scripted:unproven-outstanding-stop",
    );
    assert!(table.driver_witness().leased);
    script_disable(4);
    let mut out = Vec::with_capacity(tokens.len());
    witness(&mut table, &mut out).unwrap();
    let mut calls = 0;
    let failure = stop_outstanding(&mut table, &arena, &mut out, || {
        calls += 1;
        calls <= 2
    })
    .unwrap_err();
    let StopFailure::Unproven {
        progress,
        census: held,
        report: Some(report),
        ..
    } = failure
    else {
        panic!("{failure:?}")
    };
    assert_eq!(progress, QuiesceProgress::Draining { outstanding: 8 });
    assert!(!report.proven);
    assert_eq!(held, (8, 4, 4));
    assert!(out.is_empty(), "an unproven stop returns nothing");
    SCRIPT.with_borrow_mut(|script| script.registers.clear());
    assert_eq!(
        table.quiesce(&mut out),
        QuiesceProgress::Quiesced(Quiesced::DeviceStopped)
    );
    assert_eq!(
        table.driver_witness().stop.map(|report| report.proven),
        Some(true)
    );
    assert_eq!(out.len(), tokens.len());
    drop(out);
    assert_eq!(census(&table, &arena), (0, 0, 0));
}

/// Commands the pick completes earn no witness, and a stop with nothing
/// outstanding earns no stop credit: the first stop call reports every
/// command already returned.
#[test]
fn an_early_drain_fails_the_outstanding_witness() {
    let (env, arena) = (
        Environment::detached(),
        arena_on(TestPlatform::heap(4096), 16, 5),
    );
    let mut registration = registration_tests::ready(&env, &arena);
    let (mut table, tokens) = scripted(
        &arena,
        &mut registration,
        "scripted:drained-outstanding-stop",
    );
    assert!(table.driver_witness().leased);
    let mut out = Vec::with_capacity(tokens.len());
    assert_eq!(
        witness(&mut table, &mut out),
        Err(StopFailure::Drained {
            accepted: 0,
            staged: 0,
            delivered: 8
        })
    );
    assert_eq!(
        stop_outstanding(&mut table, &arena, &mut out, || true).unwrap_err(),
        StopFailure::NotDraining(QuiesceProgress::Quiesced(Quiesced::AllReturned))
    );
    drop(out);
    assert_eq!(census(&table, &arena), (0, 0, 0));
}

#[test]
fn the_outcome_collection_takes_every_read_at_the_configured_depth() {
    SCRIPT.take();
    let arena = arena_on(TestPlatform::heap(4096), 16, 5);
    let depth = CONFIG.queue_depth;
    let mut disk = SpdkDisk::<Scripted>::scripted("scripted:outcome-depth", limits(depth));
    let held: Vec<_> = (0..depth)
        .map(|_| arena.acquire(PoolKind::ReadResponse).unwrap())
        .collect();
    disk.mark_verified(held[0].range(4096).unwrap());
    let first = DeviceRange::new(0, 4096).unwrap();
    for (n, buffer) in held.iter().enumerate() {
        // SAFETY: `held` keeps every submitted buffer alive and exclusive until `pick_each` collects all completions.
        unsafe {
            disk.submit_read(
                CommandToken::from_raw(10 + n as u64),
                first,
                buffer.range(4096).unwrap(),
            )
        }
        .unwrap();
    }
    let tokens: Vec<_> = pick_each(&mut disk, depth as usize)
        .iter()
        .map(|done| done.token.raw())
        .collect();
    assert_eq!(tokens, (10..10 + u64::from(depth)).collect::<Vec<_>>());
}

/// What a fault row does while the controller's injected fault is in effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    Read,
    Write,
    Stop,
}

/// The driver's timeout-callback count and the command ID of its last
/// report, when that report was on an I/O queue; `(0, None)` when the driver
/// reported no timeout or its last report was on the admin queue.
fn io_timeouts<N: Native>(volume: &mut SpdkVolume<'_, '_, '_, N>) -> (u64, Option<u16>) {
    match volume.table_mut().driver().timeouts() {
        (count, Some((qpair, cid))) if qpair != 0 => (count, Some(cid)),
        (_, _) => (0, None),
    }
}

/// A record on the volume while the controller injects a fault: the row
/// announces readiness, then issues reads, or fills, until the driver
/// reports an I/O timeout below the injected delay, and prints it. A read
/// or write row then waits for the late terminal, checks its bytes exact,
/// and, once the controller marks the fault ended, checks a read or a fill
/// exact at normal latency. A stop row closes the volume with the read
/// outstanding; a stop it cannot prove keeps every hold and parks.
fn under_fault(fault: Fault) {
    let (mut lock, env) = bound();
    let arena = arena_on(TestPlatform::linux(), 16, 5);
    faulted(fault, &mut lock, &env, &arena);
    let watchdog = Watchdog::arm(Duration::from_secs(30), Arc::new(Unreachable)).unwrap();
    env.finish(&watchdog).unwrap();
    assert!(matches!(
        arena.release(),
        Ok(crate::storage::Released::Complete)
    ));
}

fn faulted(
    fault: Fault,
    lock: &mut OwnerLock,
    env: &Environment,
    arena: &BufferArena<TestPlatform>,
) {
    let timeout_io_us: u64 = std::env::var("KESTRIKE_FIS_TIMEOUT_US")
        .expect("set KESTRIKE_FIS_TIMEOUT_US below the injected delay")
        .parse()
        .unwrap();
    // The rows read restoration as an I/O that ends within half the timeout, so the timeout must leave a read at
    // the volume's normal latency room under that half.
    assert!(
        timeout_io_us >= MIN_FIS_TIMEOUT_US,
        "KESTRIKE_FIS_TIMEOUT_US is at least {MIN_FIS_TIMEOUT_US} us, so a read at normal latency fits half of it"
    );
    let started = std::env::var("KESTRIKE_FIS_STARTED").expect("the controller's fault-start path");
    let ended = std::env::var("KESTRIKE_FIS_ENDED").expect("the controller's fault-end path");
    let abandoned = std::env::var("KESTRIKE_FIS_ABANDONED").expect("the controller's abandon path");
    let patience: u64 = std::env::var("KESTRIKE_FIS_DEADLINE_SECONDS")
        .expect("the controller's case deadline")
        .parse()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(patience);
    let config = SpdkConfig {
        timeout_io_us,
        ..CONFIG
    };
    let authority = crate::soak::tenure_authority(lock);
    let (registration, disk) = start_with(lock, env, arena, config);
    let storage = hardware_storage_on(RAW, 3 * 16384, 64);
    let mut volume = Volume::attach(
        &storage,
        arena,
        disk,
        crate::storage::portable::scripted::ScriptedClock::trusted(),
        authority,
        8,
        TICK,
        &mut EngineBudget::new(1 << 24),
    )
    .map_err(|(error, _)| error)
    .unwrap();
    open_polled(&mut volume, 1 << 20);
    let guard = AbortOnUnwind;
    let (key, payload) = ([7u8; 32], bytes(40 + 2 * 16384 + 5, 7));
    drop(publish(&storage, &mut volume, &key, 40, &payload));
    eprintln!("fis: ready for the fault, timeout_io_us {timeout_io_us}");
    if !wait_for(&started, &abandoned, deadline) {
        return settle(volume, registration, guard);
    }
    let mut reader = storage.register().unwrap();
    let mut out = Vec::with_capacity(8);
    let pace = Duration::from_micros(timeout_io_us / 2);
    if fault == Fault::Write {
        let write = [8u8; 32];
        for generation in 8u64.. {
            assert!(
                Instant::now() < deadline,
                "the fault produced a timeout callback"
            );
            if Path::new(&abandoned).exists() {
                break;
            }
            let late = bytes(40 + 16384, generation);
            let (lease, timed, _) =
                fill_under_fault(&storage, &mut volume, &write, &late, deadline);
            // The fault may still delay this read, so it follows the case's deadline rather than PATIENCE.
            let op = volume.read(lease, u64::MAX).expect("a read");
            let (read, status) = finish_by(&mut volume, op, deadline);
            assert!(
                status == ReadStatus::Complete && read == late,
                "every write reads back exact"
            );
            if timed {
                if wait_for(&ended, &abandoned, deadline) {
                    restored_write(
                        &storage,
                        &mut volume,
                        &write,
                        timeout_io_us,
                        &abandoned,
                        deadline,
                    );
                }
                break;
            }
            std::thread::sleep(pace);
        }
        return settle(volume, registration, guard);
    }
    loop {
        assert!(
            Instant::now() < deadline,
            "the fault produced a timeout callback"
        );
        if Path::new(&abandoned).exists() {
            break;
        }
        let lease = reader
            .lookup(&key, 4, &mut WorkBudget::new(1 << 16))
            .unwrap();
        let (before, _) = io_timeouts(&mut volume);
        let op = volume.read(lease, u64::MAX).expect("a read");
        let (issued, mut read, mut timed) = (Instant::now(), Vec::new(), false);
        let status = 'read: loop {
            assert!(Instant::now() < deadline, "the read reached its terminal");
            volume.poll_storage(0, &mut out);
            for event in out.drain(..) {
                match event {
                    ReadEvent::Chunk { chunk, .. } => {
                        read.extend_from_slice(chunk.bytes());
                        let _ = volume.grant_read(op);
                    }
                    ReadEvent::Done { status, .. } => break 'read status,
                }
            }
            if let (count, Some(cid)) = io_timeouts(&mut volume)
                && !timed
                && count > before
            {
                timed = true;
                let report = volume.report();
                let held = arena.report(PoolKind::ReadResponse);
                eprintln!(
                    "observe: timeout of command {cid} after {} us with reads submitted {} done {}, {} read buffers held",
                    issued.elapsed().as_micros(),
                    report.reads_submitted,
                    report.reads_done,
                    held.count - held.free - held.retired
                );
                if fault == Fault::Stop {
                    stop_under_fault(volume, registration, guard);
                    return;
                }
            }
        };
        // Every read under the fault ends exact, the ones the fault delayed short of the timeout included; the
        // timed read is the one that also prints the witness.
        assert!(
            status == ReadStatus::Complete && read == payload,
            "every read under the fault ends exact"
        );
        if timed {
            eprintln!(
                "observe: late terminal exact after {} us",
                issued.elapsed().as_micros()
            );
            if wait_for(&ended, &abandoned, deadline) {
                restored_read(
                    &mut volume,
                    &mut reader,
                    &key,
                    &payload,
                    timeout_io_us,
                    &abandoned,
                    deadline,
                );
            }
            break;
        }
        std::thread::sleep(pace);
    }
    settle(volume, registration, guard);
}

/// Waits until the controller's mark file at `mark` exists, or returns
/// `false` once the abandon mark appears first.
fn wait_for(mark: &str, abandoned: &str, deadline: Instant) -> bool {
    while !Path::new(mark).exists() {
        if Path::new(abandoned).exists() {
            return false;
        }
        assert!(Instant::now() < deadline, "the controller wrote {mark}");
        std::thread::sleep(Duration::from_millis(200));
    }
    true
}

fn settle(
    volume: SpdkVolume<'_, '_, '_>,
    registration: ArenaRegistration<'_>,
    guard: AbortOnUnwind,
) {
    shut(volume, registration);
    drop(guard);
}

/// Replaces `key` with `payload`, polling until its writes finish, and
/// returns the lease, whether an I/O timeout arrived during the writes, and
/// how long they took.
fn fill_under_fault<'s, N: Native>(
    storage: &'s Storage<TestPlatform>,
    volume: &mut SpdkVolume<'s, '_, '_, N>,
    key: &[u8; 32],
    payload: &[u8],
    deadline: Instant,
) -> (ExtentLease<'s, TestPlatform>, bool, Duration) {
    let mut budget = WorkBudget::new(1 << 16);
    let _ = storage.invalidate(key, 4, &mut budget);
    let _ = storage.maintain(&mut WorkBudget::new(1 << 16));
    let attempt = storage
        .begin_fill(key, crate::storage::CacheVersion(0), 4, &mut budget)
        .expect("an attempt");
    let Decision::Admit(admit) = storage.decide_admission(Some(40), Some(payload.len() - 40))
    else {
        panic!("an open storage admits the fill");
    };
    let mut fill = attempt
        .reserve_storage(admit, Some(40), Some(payload.len() - 40), 4, &mut budget)
        .expect("a reservation");
    let (begun, mut taken, mut timed) = (Instant::now(), 0, false);
    let mut out = Vec::with_capacity(8);
    let (before, _) = io_timeouts(volume);
    while !fill.progress(volume).is_ready() {
        assert!(!fill.progress(volume).failed, "every write succeeds late");
        assert!(Instant::now() < deadline, "the fill's writes finished");
        // A submit the volume refused leaves its segment staged; a receive of no bytes retries it.
        if let Ok(count) = fill.receive(
            volume,
            &payload[taken..],
            &mut WorkBudget::with_io(0, usize::MAX, usize::MAX),
        ) {
            taken += count;
        }
        volume.poll_storage(0, &mut out);
        if let (count, Some(cid)) = io_timeouts(volume)
            && !timed
            && count > before
        {
            timed = true;
            eprintln!(
                "observe: timeout of command {cid} after {} us with a write outstanding",
                begun.elapsed().as_micros()
            );
        }
    }
    let lease = fill
        .publish(volume, u64::MAX, 4, &mut budget)
        .expect("published");
    (lease, timed, begun.elapsed())
}

/// Reads `key` until one read completes exact within half the timeout.
fn restored_read<'s>(
    volume: &mut SpdkVolume<'s, '_, '_>,
    reader: &mut crate::storage::Registration<'s, TestPlatform>,
    key: &[u8; 32],
    payload: &[u8],
    timeout_io_us: u64,
    abandoned: &str,
    deadline: Instant,
) {
    loop {
        assert!(
            Instant::now() < deadline,
            "the volume's reads were restored"
        );
        if Path::new(abandoned).exists() {
            return;
        }
        let lease = reader
            .lookup(key, 4, &mut WorkBudget::new(1 << 16))
            .unwrap();
        let issued = Instant::now();
        let op = volume.read(lease, u64::MAX).expect("a read");
        let (read, status) = finish_by(volume, op, deadline);
        assert!(
            status == ReadStatus::Complete && read == payload,
            "every read is exact"
        );
        if issued.elapsed().as_micros() < u128::from(timeout_io_us / 2) {
            eprintln!("observe: restored exact bytes at normal read latency");
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Replaces `key` until one fill's writes finish within half the timeout
/// with no I/O timeout, then reads it back exact.
fn restored_write<'s>(
    storage: &'s Storage<TestPlatform>,
    volume: &mut SpdkVolume<'s, '_, '_>,
    key: &[u8; 32],
    timeout_io_us: u64,
    abandoned: &str,
    deadline: Instant,
) {
    for generation in 1_000u64.. {
        assert!(
            Instant::now() < deadline,
            "the volume's writes were restored"
        );
        if Path::new(abandoned).exists() {
            return;
        }
        let payload = bytes(40 + 16384, generation);
        let (lease, timed, took) = fill_under_fault(storage, volume, key, &payload, deadline);
        let op = volume.read(lease, u64::MAX).expect("a read");
        let (read, status) = finish_by(volume, op, deadline);
        assert!(
            status == ReadStatus::Complete && read == payload,
            "every write reads back exact"
        );
        if !timed && took.as_micros() < u128::from(timeout_io_us / 2) {
            eprintln!("observe: restored exact bytes at normal write latency");
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Closes the volume while the read stays outstanding under the fault: a
/// proven stop releases the driver and tears down; an unproven one keeps
/// every hold and parks until the host is contained.
fn stop_under_fault(
    mut volume: SpdkVolume<'_, '_, '_>,
    registration: ArenaRegistration<'_>,
    guard: AbortOnUnwind,
) {
    // The witness needs the read outstanding when the disable began: the first call must find it pending, `Draining`
    // as `stop_outstanding` requires, or `Unproven`, which this row also accepts so a refused disable parks below.
    // The proof must be the device stopped. A quiesce whose poll returned the read first proves no stop under the
    // fault, so the row fails rather than earn the witness.
    let (begun, mut out) = (Instant::now(), Vec::with_capacity(8));
    let first = volume.close();
    assert!(
        !matches!(first, QuiesceProgress::Quiesced(_)),
        "the stop found the read outstanding: {first:?}"
    );
    let proof = loop {
        match volume.close() {
            QuiesceProgress::Quiesced(proof) => break proof,
            _ if begun.elapsed() > Duration::from_secs(600) => {
                eprintln!("observe: retained the stop stayed unproven under the fault");
                loop {
                    std::thread::park();
                }
            }
            _ => {
                volume.poll_storage(0, &mut out);
                out.clear();
            }
        }
    };
    assert_eq!(
        proof,
        Quiesced::DeviceStopped,
        "the stop ended with the device stopped, the read outstanding"
    );
    eprintln!(
        "observe: stop proven after {} us with the read outstanding",
        begun.elapsed().as_micros()
    );
    let (_proof, mut disk) = volume
        .release_driver()
        .map_err(|_| "proven")
        .expect("released");
    stop(&mut disk);
    teardown(registration, &mut disk);
    drop(guard);
}

/// A read under injected latency or paused I/O reports its timeout and the
/// buffers it holds, ends exact at its late terminal, and reads exact at
/// normal latency once the fault ends.
#[test]
#[ignore = "needs a disposable EBS volume bound by kestrike-bind, named by KESTRIKE_MAPPINGS, under the FIS controller's fault"]
fn a_read_under_an_injected_fault_reports_its_timeout_and_ends_exact_at_its_late_terminal() {
    under_fault(Fault::Read);
}

/// A write under injected latency reports its timeout, reads back exact once
/// it lands, and lands at normal latency once the fault ends.
#[test]
#[ignore = "needs a disposable EBS volume bound by kestrike-bind, named by KESTRIKE_MAPPINGS, under the FIS controller's fault"]
fn a_write_under_an_injected_fault_reports_its_timeout_and_reads_back_exact() {
    under_fault(Fault::Write);
}

/// A stop under paused I/O with a read outstanding is proven or keeps custody.
#[test]
#[ignore = "needs a disposable EBS volume bound by kestrike-bind, named by KESTRIKE_MAPPINGS, under the FIS controller's fault"]
fn a_stop_under_an_injected_fault_with_a_read_outstanding_is_proven_or_holds_custody() {
    under_fault(Fault::Stop);
}

fn scripted_volume<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    arena: &'a BufferArena<TestPlatform>,
    registration: &mut ArenaRegistration<'_>,
    address: &str,
    configure: impl FnOnce(&mut SpdkDisk<'a, Scripted>),
) -> SpdkVolume<'s, 'a, 'a, Scripted> {
    SCRIPT.take();
    let mut disk = SpdkDisk::<Scripted>::scripted_leased(address, limits(8), registration);
    let probe = arena.acquire(PoolKind::ReadResponse).unwrap();
    disk.mark_verified(probe.range(SPAN).unwrap());
    drop(probe);
    configure(&mut disk);
    let geometry = disk.geometry();
    disk.set_facts(crate::storage::volume_fixture::facts_for(
        geometry.capacity,
        geometry.max_transfer,
    ));
    let mut volume = Volume::attach(
        storage,
        arena,
        disk,
        crate::storage::portable::scripted::ScriptedClock::trusted(),
        crate::storage::ServingAuthority::fixture_limits(
            crate::storage::ReservationLimits::new(2, 2, 10, 10).unwrap(),
        ),
        8,
        TICK,
        &mut EngineBudget::new(1 << 24),
    )
    .map_err(|(error, _)| error)
    .unwrap();
    open_polled(&mut volume, 64);
    volume
}

#[test]
fn a_timeout_the_driver_reported_reaches_the_fault_rows_while_the_volume_serves() {
    let (env, arena) = (
        Environment::detached(),
        arena_on(TestPlatform::heap(4096), 16, 5),
    );
    let mut registration = registration_tests::ready(&env, &arena);
    let storage = heap_storage_on(RAW, 3 * 16384);
    let mut volume = scripted_volume(
        &storage,
        &arena,
        &mut registration,
        "scripted:fis-timeout",
        |disk| disk.report_timeout(7),
    );
    assert_eq!(io_timeouts(&mut volume), (1, Some(7)));
}

#[test]
fn refilling_one_key_past_its_fill_records_and_raw_capacity_publishes_every_fill() {
    let (env, arena) = (
        Environment::detached(),
        arena_on(TestPlatform::heap(4096), 16, 5),
    );
    let mut registration = registration_tests::ready(&env, &arena);
    let storage = heap_storage_on(RAW, 3 * 16384);
    let mut volume = scripted_volume(
        &storage,
        &arena,
        &mut registration,
        "scripted:fis-refill",
        |_| {},
    );
    let deadline = Instant::now() + PATIENCE;
    let fills = 2 * RAW / 16384;
    for generation in 0..fills as u64 {
        let payload = bytes(40 + 16384, generation);
        let (lease, timed, _) =
            fill_under_fault(&storage, &mut volume, &[8; 32], &payload, deadline);
        assert!(!timed, "the scripted driver reports no timeout");
        drop(lease);
    }
}

/// A table whose commands have ended quiesces as `AllReturned` while its
/// driver still runs; teardown requires the returned driver's stop proof.
#[test]
fn a_drained_table_shuts_to_a_driver_that_proves_its_stop_for_teardown() {
    let (env, arena) = (
        Environment::detached(),
        arena_on(TestPlatform::heap(4096), 16, 5),
    );
    let mut registration = registration_tests::ready(&env, &arena);
    let (mut table, tokens) = scripted(&arena, &mut registration, "scripted:drained-teardown");
    let mut out = Vec::with_capacity(tokens.len());
    assert_eq!(table.poll(&mut out).delivered, 8);
    drop(out);
    let mut none = Vec::new();
    assert_eq!(
        table.quiesce(&mut none),
        QuiesceProgress::Quiesced(Quiesced::AllReturned)
    );
    assert!(
        table.driver().stop_proof().is_none(),
        "the running driver proves no stop"
    );
    let mut disk = shut_table(table, &arena);
    teardown(registration, &mut disk);
}

fn arena_on<P: crate::storage::Platform>(platform: P, read: u32, receive: u32) -> BufferArena<P> {
    let pools = [
        crate::storage::PoolSpec {
            kind: PoolKind::ReadResponse,
            count: read,
            buffer_len: 16384,
        },
        crate::storage::PoolSpec {
            kind: PoolKind::ReceiveWrite,
            count: receive,
            buffer_len: 16384,
        },
        crate::storage::PoolSpec {
            kind: PoolKind::Maintenance,
            count: 1,
            buffer_len: 16384,
        },
        crate::storage::PoolSpec {
            kind: PoolKind::Reservation,
            count: 2,
            buffer_len: 4096,
        },
    ];
    let config = crate::storage::BufferConfig {
        hugepage: crate::storage::HugepageSize::TwoMiB,
        nodes: crate::storage::NodeMask::from_nodes(&[0]).unwrap(),
        pools: &pools,
    }
    .validate()
    .unwrap();
    BufferArena::initialize(&config, platform, &mut EngineBudget::new(usize::MAX)).unwrap()
}

/// A production attach reaches Live and round-trips a record on the bound volume: the state directory holds a host
/// key, a signed assignment naming this instance, volume and zone, and the local record the fresh path writes;
/// `SpdkDisk::attach` admits them and closes the medium gate; a read before the volume's gate refuses
/// `NotVerified`; the volume's gate passes on the device's own Register, Acquire and Report, opens the driver's
/// medium gate, formats and replays to Live. Serving comes from the test's fixture authority over the recorded
/// pair, the stand-in for the restart sequence's authority. The volume must be Multi-Attach io2, which carries NVMe
/// reservations and the extended host identifier, bound as a disposable test binding under a state directory
/// outside `/run`: the test writes the host key and assignment there when absent. The attach sets the recorded
/// host identifier on the controller, which keeps it across reconnects, so no qualification profile attaches the
/// same attachment in the same boot.
#[test]
#[ignore = "needs a disposable Multi-Attach io2 volume bound by kestrike-bind under /var/lib, named by KESTRIKE_MAPPINGS, that no qualification profile attaches in the same boot"]
fn a_production_attach_reaches_live_and_serving_on_the_volume() {
    use crate::bind::Metadata;
    use crate::failover::assignment::{Assignment, Content};
    use crate::failover::identity::Incarnation;
    use crate::storage::ReservationLimits;
    use std::fs;
    use std::os::unix::fs::OpenOptionsExt;
    let (mut lock, env) = bound();
    let host = Host::system();
    let (instance, _) = host.instance_and_boot().unwrap();
    let volume = lock.mappings().unwrap().nvme.unwrap().volume;
    let az = crate::bind::Imds::connect(60)
        .unwrap()
        .get("placement/availability-zone")
        .unwrap()
        .trim()
        .to_owned();
    let owner = lock
        .check_authority_directory()
        .expect("a 0700 state directory of this user outside /run");
    let state = lock.state_dir().to_path_buf();
    let private = |name: &str, bytes: &[u8]| {
        let path = state.join(name);
        if path.exists() {
            return;
        }
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut file, bytes).unwrap();
        file.sync_all().unwrap();
    };
    let mut fresh = [0u8; 32];
    let (low, high) = fresh.split_at_mut(16);
    crate::entropy::os_entropy(low.try_into().unwrap()).unwrap();
    crate::entropy::os_entropy(high.try_into().unwrap()).unwrap();
    private("host.key", &fresh);
    let key: [u8; 32] = crate::bind::private_read(&state.join("host.key"), 32, owner)
        .expect("a private host key of this user")
        .try_into()
        .expect("a 32-byte host key");
    let assignment = Assignment {
        instance: instance.clone(),
        volume: volume.clone(),
        az,
        attachment: volume.clone(),
        incarnation: Incarnation::new(1).unwrap(),
        content: Content::Format,
        delete_on_termination: Some(false),
        ..crate::failover::assignment_tests::sample()
    };
    private("assignment", &assignment.sign(&key).unwrap());
    if !state.join("authority").exists() {
        lock.prepare_fresh(
            &host,
            0,
            crate::failover::records::attachment_key(0).unwrap(),
            || Ok::<(), ()>(()),
        )
        .unwrap();
    }
    let authority = crate::soak::recorded_tenure_authority(&mut lock, &host);
    let limits = ReservationLimits::new(2, 2, 10, 10).unwrap();
    let storage = hardware_storage_on(RAW, 3 * 16384, 64);
    let arena = arena_on(TestPlatform::linux(), 16, 5);
    let mut registration = ArenaRegistration::register(
        &env,
        &arena,
        DmaPolicy {
            allow_no_iommu: true,
        },
    )
    .unwrap();
    let mut disk = SpdkDisk::<Spdk>::attach(
        &host,
        &lock,
        &crate::bind::Imds::connect(60).unwrap(),
        &mut registration,
        CONFIG,
        limits,
    )
    .unwrap();
    assert!(disk.medium_withheld(), "the attach closes the medium gate");
    registration.map().unwrap();
    registration.verify().unwrap();
    disk.enable_reservations(&registration).unwrap();
    let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    // SAFETY: a refused read keeps the exclusive buffer with the caller.
    let refused = unsafe {
        disk.submit_read(
            CommandToken::from_raw(1),
            DeviceRange::new(0, 4096).unwrap(),
            buffer.range(4096).unwrap(),
        )
    };
    assert_eq!(
        refused.unwrap_err().reason,
        RefusalReason::NotVerified,
        "no read before the volume's gate"
    );
    drop(buffer);
    let mut volume = Volume::attach(
        &storage,
        &arena,
        disk,
        crate::storage::portable::scripted::ScriptedClock::trusted(),
        authority,
        8,
        TICK,
        &mut EngineBudget::new(1 << 24),
    )
    .map_err(|(error, _)| error)
    .unwrap();
    open_polled(&mut volume, 1 << 20);
    let (start, mut out) = (Instant::now(), Vec::with_capacity(8));
    while volume.authority_state() != crate::failover::serving::State::Serving {
        assert!(
            start.elapsed() < PATIENCE,
            "Serving after Live: {:?}",
            volume.authority_report()
        );
        volume.poll_storage(0, &mut out);
        out.clear();
    }
    drop(out);
    eprintln!(
        "production attach, serving under the fixture authority of the recorded pair: {:?}",
        volume.authority_report()
    );
    round_trip(&storage, &mut volume, 11);
    shut(volume, registration);
    let watchdog = Watchdog::arm(Duration::from_secs(30), Arc::new(Unreachable)).unwrap();
    env.finish(&watchdog).unwrap();
    assert!(matches!(
        arena.release(),
        Ok(crate::storage::Released::Complete)
    ));
}

/// The same-host restart reaches the fencing boundary through the host fencer and `connect_restart` on the bound
/// volume, after `a_production_attach_reaches_live_and_serving_on_the_volume` on the same binding, and its driver or
/// outstanding table ends through the shared proven stop.
#[test]
#[ignore = "needs a disposable Multi-Attach io2 volume bound by kestrike-bind under /var/lib, named by KESTRIKE_MAPPINGS, whose own pair holds the reservation"]
fn the_restart_reaches_the_fencing_boundary_through_the_fencer_on_the_volume() {
    use crate::failover::attachments::InstanceId;
    use crate::failover::poll::Holder;
    use crate::failover::records::{ShardRecord, VolumeId, VolumeRecord};
    use crate::failover::restart::LocalSource;
    use crate::failover::restart::tests::{self as restart_tests, store};
    use crate::host::fencer::{Fencer, Release};
    use crate::host::inputs::{Inputs, restart};
    use crate::storage::ReservationLimits;
    use crate::storage::store_tests::{client, shard};
    let (lock, env) = bound();
    let host = Host::system();
    let record = lock
        .local()
        .expect("the local record a production attach wrote");
    let own = record.pair();
    let volume = VolumeId::new(&record.binding().volume).unwrap();
    let holder = Holder {
        volume,
        host: restart_tests::host(),
        instance: InstanceId::new(&record.binding().instance).unwrap(),
    };
    let limits = ReservationLimits::new(2, 2, 1_000_000, 1_000_000).unwrap();
    let bounds = crate::storage::gate_fixture::bounds_of(limits);
    let enrolled = VolumeRecord {
        volume,
        pairs: Vec::new(),
        ..restart_tests::volume_record()
    }
    .enroll(holder.host, own, &bounds)
    .unwrap()
    .expect("the own pair enrolls for this host's attach");
    let records = store(
        ShardRecord {
            active: volume,
            ..restart_tests::shard_record(1)
        },
        enrolled,
    );
    let arena = arena_on(TestPlatform::linux(), 16, 5);
    let mut registration = ArenaRegistration::register(
        &env,
        &arena,
        DmaPolicy {
            allow_no_iommu: true,
        },
    )
    .unwrap();
    let clock = crate::storage::BootClock::default();
    let (restarted, released) = {
        let (lock, host, registration) = (&lock, &host, &mut registration);
        let mut fencer = Fencer::new(
            &crate::host::HostGate::qualified(),
            move || {
                super::connect::connect_restart::<Spdk>(
                    host,
                    lock,
                    registration,
                    CONFIG,
                    record,
                    limits,
                )
            },
            limits,
            &arena,
            &clock,
        );
        let inputs = Inputs::new(shard(), holder, bounds, limits, 4)
            .expect("the bounds repeat the limits' registrants and Report deadline");
        let restarted = restart(&inputs, &[]).run(&mut client(&records), lock, &mut fencer);
        (restarted, fencer.release())
    };
    let patience = Duration::from_secs(30);
    let stopped = |released| match released {
        Release::Driver(disk) => super::connect::stop(disk, registration, patience),
        Release::Outstanding(table) => super::connect::stop_table(table, registration, patience),
        Release::Unconnected => panic!("the restart never attached: {restarted:?}"),
    };
    let watchdog = stopped(released).unwrap();
    env.finish(&watchdog).unwrap();
    let attempts = restarted
        .expect("the restart reaches the fencing boundary")
        .session()
        .target()
        .attempts;
    assert!(matches!(
        arena.release(),
        Ok(crate::storage::Released::Complete)
    ));
    assert_eq!(attempts, 2);
}
