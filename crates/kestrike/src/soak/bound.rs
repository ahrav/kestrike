use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

use super::{Closed, Soak, SoakConfig, SoakFailure};
use crate::bind::{Host, OwnerLock};
use crate::failover::bounds::{Bounds, BoundsError, Parameter};
use crate::index::{IndexConfig, Ratio, ShardLimits};
use crate::native::{ArenaRegistration, DmaPolicy, EnvConfig, Environment, Watchdog, pci_address};
use crate::net::serving::Serving;
use crate::storage::device::ReservationLimits;
use crate::storage::device::connect::{self, Unready, hold, stop};
use crate::storage::portable::{DEFAULT_MARKER, DEFAULT_SEGMENT};
use crate::storage::{
    BufferArena, BufferConfig, Cleanup, ClockContract, ClockScale, CpuSet, EngineBudget,
    FeedContract, Finalization, HugepageSize, IO_UNIT, LinuxPlatform, Native, NodeMask,
    PlacementConfig, Platform, PoolKind, PoolSpec, RecordConfig, Released, SegmentV2,
    ServingAuthority, Session, SpdkConfig, SpdkDisk, Storage, StorageConfig, TickConfig,
    ValidatedConfig, Volume, VolumeConfig, VolumeWatermarks, WorkBudget,
};

pub const SMOKE_BOUND: BoundConfig = BoundConfig {
    raw_bytes: 64 << 20,
    metadata_units: 40,
    slots: 64,
    run: Duration::from_secs(120),
    allow_no_iommu: false,
};

#[derive(Debug, Clone, Copy)]
pub struct BoundConfig {
    /// Bytes of the volume the storage occupies, from its start.
    pub raw_bytes: usize,
    pub metadata_units: u64,
    pub slots: usize,
    /// How long the soak runs before it closes on its own.
    pub run: Duration,
    /// Whether this host is on the no-IOMMU allowlist.
    pub allow_no_iommu: bool,
}

/// The operator supplies every reservation-command and serving bound before
/// the owner lock.
#[derive(Debug, PartialEq, Eq)]
enum OperatorInputError {
    Missing(&'static str),
    Invalid(&'static str),
}
impl std::fmt::Display for OperatorInputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(name) => write!(f, "missing {name}"),
            Self::Invalid(name) => write!(f, "invalid {name}"),
        }
    }
}

/// The Extended Report must fit one arena hugepage, which bounds
/// `KESTRIKE_N_REG`.
const HUGEPAGE: HugepageSize = HugepageSize::TwoMiB;

type Read<'r> = &'r dyn Fn(&'static str) -> Result<String, OperatorInputError>;

fn number(read: Read<'_>, name: &'static str) -> Result<u64, OperatorInputError> {
    read(name)?
        .parse::<u64>()
        .map_err(|_| OperatorInputError::Invalid(name))
}

fn count(read: Read<'_>, name: &'static str) -> Result<u32, OperatorInputError> {
    u32::try_from(number(read, name)?).map_err(|_| OperatorInputError::Invalid(name))
}

fn operator_reservations(
    read: impl Fn(&'static str) -> Result<String, OperatorInputError>,
) -> Result<ReservationLimits, OperatorInputError> {
    let read: Read<'_> = &read;
    let limits = ReservationLimits::new(
        count(read, "KESTRIKE_N_REG")?,
        count(read, "KESTRIKE_N_RESV")?,
        number(read, "KESTRIKE_T_REPORT")?,
        number(read, "KESTRIKE_T_PA")?,
    )
    .map_err(|error| {
        OperatorInputError::Invalid(match error {
            crate::storage::ReservationLimitsError::Registrants => "KESTRIKE_N_REG",
            crate::storage::ReservationLimitsError::Commands => "KESTRIKE_N_RESV",
            crate::storage::ReservationLimitsError::Deadline => {
                "KESTRIKE_T_REPORT or KESTRIKE_T_PA"
            }
        })
    })?;
    if limits.commands() != 2 {
        return Err(OperatorInputError::Invalid("KESTRIKE_N_RESV"));
    }
    if limits.report_bytes() as usize > HUGEPAGE.bytes() {
        return Err(OperatorInputError::Invalid("KESTRIKE_N_REG"));
    }
    Ok(limits)
}

/// The serving bounds, in microseconds of the serving clock. They repeat
/// `KESTRIKE_N_REG` and `KESTRIKE_T_REPORT`, the values attach requires
/// the reservation limits and the serving bounds to share.
fn operator_serving(
    read: impl Fn(&'static str) -> Result<String, OperatorInputError>,
) -> Result<Bounds, OperatorInputError> {
    let read: Read<'_> = &read;
    let registrants = count(read, "KESTRIKE_N_REG")?;
    let retry = count(read, "KESTRIKE_N_RETRY")?;
    Bounds::new(
        registrants,
        retry,
        number(read, "KESTRIKE_SERVING_WINDOW_US")?,
        number(read, "KESTRIKE_T_REPORT")?,
        number(read, "KESTRIKE_REPORT_PERIOD_US")?,
        number(read, "KESTRIKE_CLOCK_ERROR_US")?,
    )
    .map_err(|error| {
        OperatorInputError::Invalid(match error {
            BoundsError::Zero(Parameter::RegistrantMax) => "KESTRIKE_N_REG",
            BoundsError::Zero(Parameter::RetryMax) => "KESTRIKE_N_RETRY",
            BoundsError::Zero(Parameter::Window) | BoundsError::WindowTooShort { .. } => {
                "KESTRIKE_SERVING_WINDOW_US"
            }
            BoundsError::Zero(Parameter::ReportDeadline) => "KESTRIKE_T_REPORT",
            BoundsError::Zero(Parameter::ReportPeriod) => "KESTRIKE_REPORT_PERIOD_US",
            BoundsError::Overflow => {
                "KESTRIKE_REPORT_PERIOD_US, KESTRIKE_T_REPORT or KESTRIKE_CLOCK_ERROR_US"
            }
        })
    })
}

const SPDK: SpdkConfig = SpdkConfig {
    queue_depth: 8,
    timeout_io_us: 30_000_000,
    timeout_admin_us: 30_000_000,
};
pub(super) fn recovery(core: u32) -> Result<crate::storage::RecoveryLimits, String> {
    let mut cpus = CpuSet::current().map_err(|error| format!("recovery CPUs: {error}"))?;
    cpus.remove(core as usize);
    if cpus.is_empty() {
        return Err(format!(
            "recovery CPUs: none apart from the owner's CPU {core}"
        ));
    }
    Ok(crate::storage::RecoveryLimits {
        cpus,
        helpers: 2,
        jobs: 8,
        input_bytes: 8 * 4096,
        output_bytes: 8 * 4096 * 24,
        adopt: 8,
        io: crate::storage::HostShare {
            bytes: 64 << 20,
            interval: 1_000_000,
            owners: 1,
        },
    })
}

const TICK: TickConfig = TickConfig {
    submit_burst: 8,
    terminal_burst: 8,
    validate_bytes: 1 << 20,
};
/// The bounded-clock contract the soak's volume records: smeared UTC, readings up to 10 ms wide and a 200 ppm writer rate-error bound.
const CLOCK: ClockContract = ClockContract {
    scale: ClockScale::UtcSmeared,
    max_uncertainty_ns: 10_000_000,
    rate_error_ppb: 200_000,
    provenance: 1,
};
/// The soak's own feed: the stand-in coverage action advances its positions.
const FEED: FeedContract = FeedContract {
    authority: *b"kestrike-soak-v1",
    contract: 1,
};
/// Attempts one bounded-clock reading makes before it re-evaluates its cached snapshot.
const CLOCK_READ_ATTEMPTS: u32 = 4;
/// The widest suspend bracket a bounded-clock reading admits.
const CLOCK_BRACKET_NS: u64 = 1_000_000;
const BUFFER: u32 = 16384;
const METADATA_CAP: usize = 64;
const DRAIN_PASSES: usize = 64;
const READ_OPS: u32 = 4;
const OBJECT_RIGHTS: usize = 8;

/// Refuses a configuration no run can carry out: a zero run closes before
/// its first step, a zero patience parks the stop at the first quiesce that
/// reports the controller still stopping, a pressure at or past the ledger
/// capacity holds leases the ledger refuses and loops that long over keys
/// it cannot acquire, and a ledger capacity above the leases every slot's
/// rights and every read operation can hold at once is never reached and
/// would size the ledger past what the address space allocates.
///
/// # Errors
///
/// The refused field.
pub(super) fn admit(config: &SoakConfig, bound: &BoundConfig) -> Result<(), String> {
    if bound.run.is_zero() {
        return Err("run: zero seconds".to_owned());
    }
    if config.patience.is_zero() {
        return Err("patience: zero seconds".to_owned());
    }
    if config.pressure >= config.capacity {
        return Err(format!(
            "pressure: {} at or past the ledger capacity {}",
            config.pressure, config.capacity
        ));
    }
    let reachable = bound
        .slots
        .checked_mul(OBJECT_RIGHTS)
        .and_then(|leases| leases.checked_add(READ_OPS as usize))
        .ok_or("slots: past the address space")?;
    if config.capacity > reachable {
        return Err(format!(
            "capacity: {} past the {reachable} leases and reads the volume can hold",
            config.capacity
        ));
    }
    Ok(())
}

/// How a run ended: the failure it recorded, if any, or the error that
/// stopped it before it ran.
type Outcome = Result<Option<SoakFailure>, String>;

/// Writes one `soak: ` line to standard error and ignores a failed write. A
/// run may close after its notice, so a standard error that refuses the line
/// must not unwind past the close, as `eprintln!` would; a park writes its own
/// line through [`hold`].
fn notice(line: std::fmt::Arguments<'_>) {
    let _ = writeln!(std::io::stderr().lock(), "soak: {line}");
}

fn current_cpu() -> Option<u32> {
    let stat = std::fs::read_to_string("/proc/thread-self/stat").ok()?;
    let (_, after_name) = stat.rsplit_once(')')?;
    after_name.split_whitespace().nth(36)?.parse().ok()
}

pub(super) fn arena<P: Platform>(
    platform: P,
    budget: &mut EngineBudget,
    reservations: ReservationLimits,
) -> Result<BufferArena<P>, String> {
    let pools = [
        PoolSpec {
            kind: PoolKind::ReadResponse,
            count: 16,
            buffer_len: BUFFER,
        },
        PoolSpec {
            kind: PoolKind::ReceiveWrite,
            count: 8,
            buffer_len: BUFFER,
        },
        PoolSpec {
            kind: PoolKind::Maintenance,
            count: 1,
            buffer_len: 16384,
        },
        PoolSpec {
            kind: PoolKind::Reservation,
            count: reservations.commands(),
            buffer_len: reservations.report_bytes().max(4096).next_power_of_two(),
        },
    ];
    let nodes = NodeMask::from_nodes(&[0]).ok_or("node 0")?;
    let validated = BufferConfig {
        hugepage: HUGEPAGE,
        nodes,
        pools: &pools,
    }
    .validate()
    .map_err(|error| format!("arena config: {error:?}"))?;
    BufferArena::initialize(&validated, platform, budget).map_err(|failure| {
        match failure.retained {
            Some(mapping) => format!(
                "arena: {:?}; arena rollback retained {mapping:?}",
                failure.error
            ),
            None => format!("arena: {:?}", failure.error),
        }
    })
}

pub(super) fn storage(
    config: &SoakConfig,
    bound: &BoundConfig,
    core: u32,
) -> Result<Storage<LinuxPlatform>, String> {
    admit(config, bound)?;
    let validated = storage_config(config, bound, recovery(core)?)?;
    storage_indexed(&validated, bound)
}

pub(super) fn storage_config(
    config: &SoakConfig,
    bound: &BoundConfig,
    recovery: crate::storage::RecoveryLimits,
) -> Result<ValidatedConfig, String> {
    let units = ((bound.raw_bytes / IO_UNIT) as u64)
        .checked_sub(bound.metadata_units)
        .ok_or("metadata units: past the volume")?;
    let record_bytes = config
        .body_cap
        .checked_add(METADATA_CAP)
        .ok_or("body cap: past the address space")?;
    let record_units = (record_bytes / IO_UNIT) as u64 + 2;
    let nodes = NodeMask::from_nodes(&[0]).ok_or("node 0")?;
    let volume = VolumeConfig {
        raw_bytes: bound.raw_bytes,
        metadata_units: bound.metadata_units,
        slot_count: bound.slots,
        alloc_search_words: crate::storage::work_bound(units, bound.slots, record_units),
        read_ops: READ_OPS,
        read_commands: 4,
        read_ahead: 0,
        metadata_commands: 1,
        metadata_retries: 4,
        clock: CLOCK,
        feed: FEED,
        block_roots: 0,
        reserve_units: 1,
        record: RecordConfig { chunk_len: 8192 },
        nodes,
        recovery,
        maintenance: None,
    };
    let mut storage_config = StorageConfig {
        page_size: 4096,
        engine_budget: 1 << 24,
        body_cap: config.body_cap,
        metadata_cap: Some(METADATA_CAP),
        lease_limit: config
            .capacity
            .checked_mul(2)
            .ok_or("capacity: past half the address space")?,
        object_rights: OBJECT_RIGHTS,
        reader_limit: 2,
        volume,
    };
    let validate = |config: &StorageConfig| {
        config
            .validate()
            .map_err(|error| format!("storage config: {error:?}"))
    };
    // The soak holds one fill open at a time, so its watermark is the
    // structural floor of one promise under an allowance of the largest
    // object's charge.
    let unwatched = validate(&storage_config)?;
    let marks = VolumeWatermarks {
        low_units: unwatched.placeable_ceiling(),
        min_free_slots: 1,
        retired_units: unwatched.largest_geometry().total_units(),
    };
    storage_config.volume.maintenance = Some(marks);
    let marks = VolumeWatermarks {
        low_units: validate(&storage_config)?
            .structural_floor(1)
            .map_err(|error| format!("storage config: {error:?}"))?,
        ..marks
    };
    storage_config.volume.maintenance = Some(marks);
    validate(&storage_config)
}

fn storage_indexed(
    validated: &ValidatedConfig,
    bound: &BoundConfig,
) -> Result<Storage<LinuxPlatform>, String> {
    let fills = [4];
    let limits = [bound.slots];
    let index = IndexConfig {
        shards: ShardLimits::Explicit(&limits),
        load: Ratio {
            numerator: 1,
            denominator: 2,
        },
        overflow: Ratio {
            numerator: 1,
            denominator: 1,
        },
        depth: 1,
        batch_max: 4,
        fills: &fills,
    }
    .validate(validated)
    .map_err(|error| format!("index config: {error:?}"))?;
    Storage::initialize_indexed(
        validated,
        index,
        &PlacementConfig { control_home: 0 },
        LinuxPlatform,
    )
    .map_err(|failure| match failure.cleanup {
        Cleanup::Complete => format!("storage: {:?}", failure.error),
        Cleanup::Incomplete(retained) => format!(
            "storage: {:?}; storage rollback retained {:?}",
            failure.error,
            retained.iter().collect::<Vec<_>>()
        ),
    })
}

/// The operator supplies KESTRIKE_N_RESV as 2. The Extended Report for KESTRIKE_N_REG registrants must fit one arena hugepage.
/// KESTRIKE_T_REPORT and KESTRIKE_T_PA are positive, in the owner's clock unit.
/// KESTRIKE_N_RETRY must be positive. The run validates every reservation and serving input, including KESTRIKE_SERVING_WINDOW_US, KESTRIKE_REPORT_PERIOD_US and KESTRIKE_CLOCK_ERROR_US, before it takes the owner lock.
/// The depth-8 soak reserves four read slots, one metadata slot and two reservation slots, leaving one fill-write slot.
///
/// `receipt` opens the receipt once this run holds the owner lock and its
/// state directory passed the state-directory rule, given the locked state
/// directory, so a run the lock refuses touches no file the running soak
/// writes. Each run past the mappings check then bumps the shard
/// record's attempt counter in the state directory's soak store, creating the
/// store on a first run, so a run refused later still consumes one attempt.
///
/// The run opens its instance metadata session after the arena registration
/// and before the attach, so an unreachable metadata service refuses the run
/// ahead of the attach's own local checks.
///
/// A storage initialization failure reports any mapping its rollback
/// retained. Once the storage initialized, an arena-creation or
/// environment-initialization failure finalizes it through `early_exit`,
/// releasing an acquired arena first; the retained mapping of an arena
/// rollback is part of the initiating error, ahead of the storage's cleanup
/// report. Once the controller attached, `drive` drains the storage once its
/// stop succeeded. A registration, instance-metadata or attach refusal, and a
/// stop that failed at the device-stopped record, the watchdog, unregistration
/// or detach, return their error directly and drop the storage unfinalized, so
/// the storage's mappings stay mapped until the process exits.
pub fn soak_bound<W: Write>(
    mappings: &Path,
    config: SoakConfig,
    bound: BoundConfig,
    receipt: impl FnOnce(&Path) -> Result<W, String>,
) -> Result<Option<SoakFailure>, String> {
    let reservations = operator_reservations(|name| {
        std::env::var(name).map_err(|_| OperatorInputError::Missing(name))
    })
    .map_err(|error| format!("reservation inputs: {error}"))?;
    let serving =
        operator_serving(|name| std::env::var(name).map_err(|_| OperatorInputError::Missing(name)))
            .map_err(|error| format!("serving inputs: {error}"))?;
    let state = mappings.parent().ok_or("a state directory")?;
    let mut lock = OwnerLock::acquire(state).map_err(|error| format!("owner lock: {error}"))?;
    // The receipt's alias checks read the state directory, so its chain must be one only root or its owner changes.
    lock.check_authority_directory().map_err(|error| {
        format!(
            "state directory: a 0700 directory of this user under ancestors only root or this user can write, outside /run and /var/run: {error:?}"
        )
    })?;
    let receipt = receipt(lock.state_dir())?;
    let recorded = lock
        .mappings()
        .map_err(|error| format!("mappings: {error:?}"))?;
    let (instance, boot) = Host::system()
        .instance_and_boot()
        .ok_or("instance and boot")?;
    recorded
        .check_current(&instance, &boot)
        .map_err(|error| format!("mappings: {error:?}"))?;
    let nvme = recorded
        .nvme
        .as_ref()
        .ok_or("the mappings record no volume")?;
    let session = super::store::session(&mut lock, &nvme.volume)?;
    let allowed = [pci_address(&nvme.bdf).ok_or("the volume's PCI address")?];
    let core = current_cpu().ok_or("the current CPU")?;
    // The storage and the arena come before the native environment, so a
    // configuration they refuse leaves the environment uninitialized.
    let mut storage = storage(&config, &bound, core)?;
    let arena = match arena(
        LinuxPlatform,
        &mut EngineBudget::new(usize::MAX),
        reservations,
    ) {
        Ok(arena) => arena,
        Err(error) => return Err(early_exit(error, &mut storage, None)),
    };
    let env = match Environment::initialize(&EnvConfig {
        core,
        hugepage_dir: Path::new("/dev/hugepages"),
        allowed: &allowed,
    }) {
        Ok(env) => env,
        Err(error) => {
            return Err(early_exit(
                format!("environment: {error:?}"),
                &mut storage,
                Some(arena),
            ));
        }
    };
    let policy = DmaPolicy {
        allow_no_iommu: bound.allow_no_iommu,
    };
    // SIGTERM asks the run to close while the arena is registered or the
    // controller attached; the default disposition would end the process
    // with both live, and in no-IOMMU mode that proves nothing about DMA.
    let _serving = Serving::start(bound.run);
    let mut registration = ArenaRegistration::register(&env, &arena, policy)
        .map_err(|error| format!("registration: {error:?}"))?;
    let metadata =
        crate::bind::Imds::connect(60).map_err(|error| format!("instance metadata: {error}"))?;
    // A refusal after the connect detaches the controller; one whose
    // detach SPDK refused leaves it attached with the arena registered
    // and no handle to stop it, so the process keeps custody.
    let disk = connect::attach_or_hold(&mut registration, |registration| {
        SpdkDisk::<crate::storage::device::Spdk>::attach(
            &Host::system(),
            &lock,
            &metadata,
            registration,
            SPDK,
            reservations,
        )
    })
    .map_err(|error| format!("attach: {error:?}"))?;
    let (outcome, watchdog) = drive(
        &mut storage,
        &arena,
        registration,
        disk,
        config,
        (serving, session),
        &bound,
        receipt,
    )?;
    let finished = env
        .finish(&watchdog)
        .map_err(|error| format!("environment finish: {error:?}"))
        .and_then(|()| release(arena));
    conclude(outcome, finished)
}

/// Cleans up a startup that failed with `error` after the storage
/// initialized and before arena registration, and returns the run's error
/// message.
///
/// Releases `arena` when one was acquired, then finalizes `storage` through
/// [`drain`], which unmaps every storage mapping once, in reverse order of
/// acquisition. A storage dropped without finalizing abandons its mappings,
/// so this path finalizes it explicitly. The storage drains even when the
/// arena release fails.
///
/// The message starts with `error`. Each cleanup failure follows it after
/// `"; "`, the arena's ahead of the storage's: an arena release that kept
/// the backing mapped or stayed blocked, then a storage that stopped short
/// of drained.
pub(super) fn early_exit<P: Platform>(
    error: String,
    storage: &mut Storage<P>,
    arena: Option<BufferArena<P>>,
) -> String {
    let released = arena.map_or(Ok(()), release);
    [released, drain(storage)]
        .into_iter()
        .filter_map(Result::err)
        .fold(error, |message, failure| format!("{message}; {failure}"))
}

/// A backing the kernel kept mapped is an incomplete teardown, reported
/// like a release the registrations blocked.
fn release<P: Platform>(arena: BufferArena<P>) -> Result<(), String> {
    match arena.release() {
        Ok(Released::Complete) => Ok(()),
        Ok(Released::Retained(mapping)) => Err(format!("arena release retained {mapping:?}")),
        Err(blocked) => Err(format!(
            "the arena stayed held: registrations {}, buffers {:?}",
            blocked.registrations, blocked.held
        )),
    }
}

/// Every failure after the controller attached, a mapping, verification or
/// reservation-enable failure included, ends the run only after [`stop`] proved the
/// controller disabled, because a read the volume issued and timed out may still write
/// its buffer. The storage then drains to [`Finalization::Drained`], so an
/// obligation the soak left behind fails the run. The run's outcome comes
/// back inside `Ok` with the watchdog whenever the stop was proved, so the
/// caller finishes the environment after a failed run too; `Err` is a stop,
/// unregistration or detach that failed. The watchdog's deadline also covers
/// the environment's finish.
#[expect(
    clippy::too_many_arguments,
    reason = "the run takes the operator's serving bounds with its device, storage and configurations"
)]
pub(super) fn drive<N: Native, P: Platform, W: Write>(
    storage: &mut Storage<P>,
    arena: &BufferArena<P>,
    mut registration: ArenaRegistration<'_>,
    mut disk: SpdkDisk<'_, N>,
    config: SoakConfig,
    (serving, session): (Bounds, Session),
    bound: &BoundConfig,
    receipt: W,
) -> Result<(Outcome, Watchdog), String> {
    let machine = crate::failover::serving::Machine::gated(serving, &session, disk.own());
    let authority = ServingAuthority::new(
        serving,
        machine,
        Box::new(crate::storage::BootClock::default()),
        session,
    );
    let (outcome, disk) = match ready(&mut registration, &mut disk) {
        Ok(()) => run(storage, arena, disk, config, authority, bound.run, receipt),
        Err(error) => (Err(error), disk),
    };
    let watchdog = stop(disk, registration, config.patience)?;
    let drained = drain(storage);
    Ok((conclude(outcome, drained), watchdog))
}

/// A failure the soak recorded is the run's result; a later teardown
/// error then goes to standard error, since the failure that blocked the
/// teardown is the one the receipt names.
pub(super) fn conclude(outcome: Outcome, drained: Result<(), String>) -> Outcome {
    match (outcome?, drained) {
        (Some(failure), Err(error)) => {
            notice(format_args!("{error}"));
            Ok(Some(failure))
        }
        (failure, drained) => drained.map(|()| failure),
    }
}

fn ready<N: Native>(
    registration: &mut ArenaRegistration<'_>,
    disk: &mut SpdkDisk<'_, N>,
) -> Result<(), String> {
    connect::ready(registration, disk).map_err(|unready| match unready {
        Unready::Map(error) => format!("map: {error:?}"),
        Unready::Verify(error) => format!("verify: {error:?}"),
        Unready::Reservations(error) => format!("reservation DMA: {error:?}"),
    })
}

/// On a reader-registration or volume-attach failure the driver comes back,
/// so the caller can stop the controller.
fn run<'l, N: Native, P: Platform, W: Write>(
    storage: &Storage<P>,
    arena: &BufferArena<P>,
    disk: SpdkDisk<'l, N>,
    config: SoakConfig,
    authority: ServingAuthority,
    run: Duration,
    receipt: W,
) -> (Outcome, SpdkDisk<'l, N>) {
    let reader = match storage.register() {
        Ok(reader) => reader,
        Err(error) => return (Err(format!("reader: {error:?}")), disk),
    };
    let clock = match SegmentV2::open(
        Path::new(DEFAULT_SEGMENT),
        Path::new(DEFAULT_MARKER),
        CLOCK.scale,
        CLOCK_READ_ATTEMPTS,
        CLOCK_BRACKET_NS,
    ) {
        Ok(clock) => clock,
        Err(error) => return (Err(format!("clock: {error:?}")), disk),
    };
    let volume = match Volume::attach(
        storage,
        arena,
        disk,
        Box::new(clock),
        authority,
        SPDK.queue_depth as u16,
        TICK,
        &mut EngineBudget::new(1 << 24),
    ) {
        Ok(volume) => volume,
        Err((error, disk)) => return (Err(format!("volume: {error:?}")), disk),
    };
    let mut soak = Soak::new(storage, volume, reader, config, receipt);
    // The first step runs before the deadline is read, so every accepted
    // run exercises the workload; the signal is read once per step, inside
    // the loop, so one that lands after the deadline ended the run leaves
    // the timed completion standing.
    let started = Instant::now();
    loop {
        let _ = soak.step();
        if soak.failure().is_some() {
            break;
        }
        if Serving::requested() {
            notice(format_args!(
                "close requested by SIGTERM after {:?}",
                started.elapsed()
            ));
            soak.interrupt();
            break;
        }
        if started.elapsed() >= run {
            break;
        }
    }
    let ended = soak.close();
    let Closed::Drained(volume) = ended.closed else {
        hold("the volume's stop stayed unproven")
    };
    let disk = match volume.release_driver() {
        Ok((_proof, disk)) => disk,
        Err(kept) => {
            let _kept = kept;
            hold("the quiesced volume kept its driver")
        }
    };
    (Ok(ended.failure), disk)
}

pub(super) fn drain<P: Platform>(storage: &mut Storage<P>) -> Result<(), String> {
    storage.close();
    let mut last = None;
    for _ in 0..DRAIN_PASSES {
        let report = storage
            .close_service(&mut WorkBudget::new(1 << 20))
            .map_err(|error| format!("close service: {error:?}"))?;
        if report.complete && report.blockers == Default::default() {
            last = None;
            break;
        }
        last = Some(report.blockers);
    }
    if let Some(blockers) = last {
        return Err(format!("close service: {blockers:?}"));
    }
    loop {
        match storage.finalize(&mut WorkBudget::new(1 << 20)) {
            Ok(Finalization::Drained) => return Ok(()),
            Ok(Finalization::Closing(progress)) if progress.retained == 0 => {}
            Ok(outcome) => return Err(format!("finalize: {outcome:?}")),
            Err(error) => return Err(format!("finalize: {error:?}")),
        }
    }
}

#[cfg(test)]
mod operator_input_tests {
    use super::{OperatorInputError, operator_reservations, operator_serving};

    fn fixture(name: &'static str) -> Result<String, OperatorInputError> {
        Ok(match name {
            "KESTRIKE_N_REG" => "3",
            "KESTRIKE_N_RESV" => "2",
            "KESTRIKE_T_REPORT" => "10",
            "KESTRIKE_T_PA" => "20",
            "KESTRIKE_N_RETRY" => "1",
            "KESTRIKE_SERVING_WINDOW_US" => "1000",
            "KESTRIKE_REPORT_PERIOD_US" => "100",
            "KESTRIKE_CLOCK_ERROR_US" => "0",
            _ => panic!("unknown fixture input"),
        }
        .to_owned())
    }

    #[test]
    fn every_serving_bound_is_an_explicit_validated_input() {
        let bounds = operator_serving(fixture).unwrap();
        assert_eq!(
            (
                bounds.registrant_max(),
                bounds.retry_max(),
                bounds.window(),
                bounds.report_deadline(),
                bounds.report_period()
            ),
            (3, 1, 1000, 10, 100)
        );
        for missing in [
            "KESTRIKE_N_REG",
            "KESTRIKE_N_RETRY",
            "KESTRIKE_SERVING_WINDOW_US",
            "KESTRIKE_T_REPORT",
            "KESTRIKE_REPORT_PERIOD_US",
            "KESTRIKE_CLOCK_ERROR_US",
        ] {
            assert_eq!(
                operator_serving(|name| if name == missing {
                    Err(OperatorInputError::Missing(name))
                } else {
                    fixture(name)
                }),
                Err(OperatorInputError::Missing(missing))
            );
        }
        // A window at `P_report + T_report + tau` (100 + 10 + 0) leaves no
        // belief past the next Report's deadline.
        for (name, value) in [
            ("KESTRIKE_N_RETRY", "0"),
            ("KESTRIKE_SERVING_WINDOW_US", "0"),
            ("KESTRIKE_SERVING_WINDOW_US", "110"),
            ("KESTRIKE_REPORT_PERIOD_US", "0"),
            ("KESTRIKE_CLOCK_ERROR_US", "-1"),
        ] {
            assert_eq!(
                operator_serving(|field| if field == name {
                    Ok(value.to_owned())
                } else {
                    fixture(field)
                }),
                Err(OperatorInputError::Invalid(name)),
                "{name}={value}"
            );
        }
    }

    #[test]
    fn every_device_bound_is_an_explicit_validated_input() {
        let limits = operator_reservations(fixture).unwrap();
        assert_eq!(
            (
                limits.registrants(),
                limits.commands(),
                limits.report_timeout(),
                limits.preempt_timeout()
            ),
            (3, 2, 10, 20)
        );
        for missing in [
            "KESTRIKE_N_REG",
            "KESTRIKE_N_RESV",
            "KESTRIKE_T_REPORT",
            "KESTRIKE_T_PA",
        ] {
            assert_eq!(
                operator_reservations(|name| if name == missing {
                    Err(OperatorInputError::Missing(name))
                } else {
                    fixture(name)
                }),
                Err(OperatorInputError::Missing(missing))
            );
        }
        for (name, value) in [
            ("KESTRIKE_N_REG", "0"),
            ("KESTRIKE_N_REG", "32768"),
            ("KESTRIKE_N_REG", "65536"),
            ("KESTRIKE_N_RESV", "1"),
            ("KESTRIKE_N_RESV", "3"),
            ("KESTRIKE_N_RESV", "4294967295"),
            ("KESTRIKE_T_REPORT", "0"),
            ("KESTRIKE_T_PA", "0"),
        ] {
            assert_eq!(
                operator_reservations(|field| if field == name {
                    Ok(value.to_owned())
                } else {
                    fixture(field)
                }),
                Err(OperatorInputError::Invalid(
                    if name.starts_with("KESTRIKE_T_") {
                        "KESTRIKE_T_REPORT or KESTRIKE_T_PA"
                    } else {
                        name
                    }
                ))
            );
        }
    }
}
