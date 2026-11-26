use std::cell::Cell;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::bound::{
    BoundConfig, SMOKE_BOUND, admit, arena, conclude, drain, drive, early_exit, recovery, storage,
    storage_config,
};
use super::{Closed, SMOKE, Soak, SoakConfig, SoakFailure};
use crate::failover::bounds::Bounds;
use crate::native::{ArenaRegistration, Environment, registration_tests};
use crate::storage::Phase;
use crate::storage::device::{
    ReservationLimits, scripted_attached, scripted_silent, scripted_silent_at,
};
use crate::storage::owner_fixture::{
    Device, TestPlatform, arena_on, heap_storage_on, storage_over,
};
use crate::storage::test_platform::{Fail, Log, Op};
use crate::storage::{
    BufferArena, CpuSet, EngineBudget, InitError, InitPhase, Native, OsCode, Region,
    RetainedMapping, SpdkDisk, Storage,
};

const PATIENT: SoakConfig = SoakConfig {
    patience: Duration::from_secs(5),
    ..SMOKE
};

/// Valid serving bounds for runs that end before the volume attaches.
fn serving() -> Bounds {
    Bounds::new(3, 1, 1000, 10, 100, 0).unwrap()
}

#[test]
fn a_run_whose_gate_never_completes_submits_register_and_ends_never_serving() {
    crate::exact_child::run(
        "soak::bound_tests::a_run_whose_gate_never_completes_submits_register_and_ends_never_serving",
        Duration::from_secs(120),
        never_serving_run,
    );
}

fn never_serving_run() {
    assert_eq!(
        silent_gate_outcome(PATIENT),
        Ok(Some(SoakFailure::NeverServing))
    );
}

/// A SIGTERM closes the run even when its notice cannot be written: with
/// the signal pending before the first step and standard error refusing
/// every write, the run still ends `Interrupted` with the controller stopped
/// and detached and the storage drained. A notice printed with `eprintln!`
/// panics there, before the close.
#[test]
fn a_sigterm_ends_the_run_interrupted_when_standard_error_refuses_the_notice() {
    crate::exact_child::run(
        "soak::bound_tests::a_sigterm_ends_the_run_interrupted_when_standard_error_refuses_the_notice",
        Duration::from_secs(120),
        || {
            let _serving = crate::net::serving::Serving::start(Duration::from_secs(600));
            refuse_standard_error();
            // SAFETY: raises SIGTERM on this thread, whose handler `Serving::start` installed.
            assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
            assert_eq!(
                silent_gate_outcome(PATIENT),
                Ok(Some(SoakFailure::Interrupted))
            );
        },
    );
}

const GATE_ADDRESS: &str = "scripted:soak-authority";

/// Drives a 50 ms run under `config` whose device never answers the gate
/// and returns its outcome, having checked the controller stopped and
/// detached and the storage drained.
fn silent_gate_outcome(config: SoakConfig) -> Result<Option<SoakFailure>, String> {
    use crate::storage::device::scripted_device_commanded;
    const ADDRESS: &str = GATE_ADDRESS;
    let env = Environment::detached();
    let arena = serving_arena();
    let mut storage = heap_storage_on(512 << 10, 64 << 10);
    let mut registration = registration_tests::registered(&env, &arena);
    let mut disk = scripted_silent_at(ADDRESS, &mut registration, 1 << 22, 8);
    disk.set_authority(crate::bind::authority_tests::prepared());
    serve(&mut disk);
    let bound = BoundConfig {
        run: Duration::from_millis(50),
        ..SMOKE_BOUND
    };
    let (outcome, _watchdog) = drive(
        &mut storage,
        &arena,
        registration,
        disk,
        config,
        (serving(), crate::storage::next_session()),
        &bound,
        Vec::new(),
    )
    .expect("the controller stopped, so the run hands its outcome and watchdog back");
    assert!(
        scripted_device_commanded(),
        "the gate's Register reached the device"
    );
    assert!(!scripted_attached(ADDRESS));
    assert_eq!(storage.phase(), Phase::Drained);
    outcome
}

/// A patience no stop can meet: the first quiesce only starts the disable,
/// so the stop is unproven when the patience has passed.
const IMPATIENT: SoakConfig = SoakConfig {
    patience: Duration::from_nanos(1),
    ..SMOKE
};

/// How long after the run began the child reads whether it returned.
const PARKED_FOR: Duration = Duration::from_secs(3);

/// Points this process's standard error at `/dev/full`, where every write
/// fails with `ENOSPC`.
fn refuse_standard_error() {
    use std::os::fd::AsRawFd;
    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    // SAFETY: both descriptors are open, and `dup2` only repoints descriptor 2.
    assert_eq!(unsafe { libc::dup2(full.as_raw_fd(), 2) }, 2);
}

/// A stop that stays unproven parks the run with the controller attached
/// even when the hold notice cannot be written: the child's standard error
/// refuses every write, its run's volume close stays unproven within the
/// patience, and [`PARKED_FOR`] later the run has not ended and its
/// controller is still attached. A notice printed with `eprintln!` panics
/// there, and the run unwinds instead of parking.
#[test]
fn a_stop_that_stays_unproven_parks_the_run_when_standard_error_cannot_be_written() {
    crate::exact_child::run(
        "soak::bound_tests::a_stop_that_stays_unproven_parks_the_run_when_standard_error_cannot_be_written",
        Duration::from_secs(120),
        || {
            refuse_standard_error();
            let run = std::thread::spawn(|| silent_gate_outcome(IMPATIENT));
            std::thread::sleep(PARKED_FOR);
            assert!(!run.is_finished(), "the run ended instead of parking");
            assert!(
                scripted_attached(GATE_ADDRESS),
                "the parked run keeps its controller attached"
            );
        },
    );
}

#[test]
fn a_drained_soak_s_storage_drains_to_finalized() {
    let mut storage = heap_storage_on(512 << 10, 64 << 10);
    let arena = arena_on(TestPlatform::heap(4096), 16, 8);
    {
        let Device { volume, control } = Device::new(&storage, &arena);
        let reader = storage.register().unwrap();
        let config = SoakConfig {
            body_cap: 40_000,
            capacity: 8,
            pressure: 2,
            cut_every: 8,
            ..PATIENT
        };
        let mut soak = Soak::new(&storage, volume, reader, config, Vec::new());
        soak.device = Some(control);
        for _ in 0..500 {
            let _ = soak.step();
        }
        assert_eq!(soak.failure(), None);
        let ended = soak.close();
        assert!(matches!(ended.closed, Closed::Drained(_)));
    }
    assert_eq!(drain(&mut storage), Ok(()));
    assert_eq!(storage.phase(), Phase::Drained);
}

/// A heap platform and its log, with `fail` armed on it when given.
fn logged_platform(fail: Option<Fail>) -> (TestPlatform, Log) {
    let platform = TestPlatform::heap(4096);
    let log = platform.log();
    if let Some(fail) = fail {
        platform.fail_at(fail);
    }
    (platform, log)
}

/// A storage over a logged heap platform, with `fail` armed before
/// initialization when given.
fn logged_storage(fail: Option<Fail>) -> (Storage<TestPlatform>, Log) {
    let (platform, log) = logged_platform(fail);
    let storage = storage_over(platform, 512 << 10, 64 << 10);
    assert_eq!(
        storage.phase(),
        Phase::Live,
        "premise: the storage initialized"
    );
    assert!(
        !log.mapped().is_empty() && log.calls(Op::Unmap).is_empty(),
        "premise: the storage holds every mapping it made: {:?}",
        log.all()
    );
    (storage, log)
}

/// An arena over a logged heap platform, with `fail` armed when given.
fn logged_arena(fail: Option<Fail>) -> (BufferArena<TestPlatform>, Log) {
    let (platform, log) = logged_platform(fail);
    let arena = arena_on(platform, 16, 8);
    assert!(
        !log.mapped().is_empty() && log.calls(Op::Unmap).is_empty(),
        "premise: the arena holds every mapping it made: {:?}",
        log.all()
    );
    (arena, log)
}

/// The first unmap of a platform, refused with `EBUSY`.
const REFUSED_UNMAP: Fail = Fail {
    op: Op::Unmap,
    ordinal: 1,
    code: OsCode(libc::EBUSY),
    region: None,
};

/// Asserts that `log` holds at least one mapping and records one unmap
/// attempt per mapping its platform made, at its original base and extent,
/// in reverse order of acquisition.
fn assert_unmapped_in_reverse(log: &Log) {
    let mut expected = log.mapped();
    expected.reverse();
    assert!(!expected.is_empty(), "{:?}", log.all());
    assert_eq!(log.ranges(Op::Unmap), expected);
}

/// The parts of a cleanup message, the initiating error first.
fn parts(message: &str) -> Vec<&str> {
    message.split("; ").collect()
}

/// An arena-creation failure after the storage initialized finalizes the
/// storage: every storage mapping unmaps once at its original extent in
/// reverse order, the storage drains, and the message is the arena failure.
#[test]
fn an_arena_failure_after_storage_initialized_finalizes_the_storage() {
    let (mut storage, log) = logged_storage(None);
    let message = early_exit("arena: refused".to_owned(), &mut storage, None);
    assert_eq!(message, "arena: refused");
    assert_unmapped_in_reverse(&log);
    assert_eq!(storage.phase(), Phase::Drained);
}

/// An environment failure releases the acquired arena once and finalizes the
/// storage: both platforms unmap every mapping once, in reverse order, and
/// the message is the environment failure.
#[test]
fn an_environment_failure_releases_the_arena_and_finalizes_the_storage() {
    let (mut storage, storage_log) = logged_storage(None);
    let (arena, arena_log) = logged_arena(None);
    let message = early_exit("environment: refused".to_owned(), &mut storage, Some(arena));
    assert_eq!(message, "environment: refused");
    assert_unmapped_in_reverse(&arena_log);
    assert_unmapped_in_reverse(&storage_log);
    assert_eq!(storage.phase(), Phase::Drained);
}

/// A storage unmap the platform refuses stays retained: finalization still
/// attempts every unmap at its original extent in reverse order, the storage
/// stops short of `Drained`, and the message names the initiating failure
/// first and the retained report after it.
#[test]
fn a_refused_storage_unmap_keeps_the_initiating_error_first_and_reports_it_retained() {
    let (mut storage, log) = logged_storage(Some(REFUSED_UNMAP));
    let message = early_exit("arena: refused".to_owned(), &mut storage, None);
    let parts = parts(&message);
    assert_eq!(parts.len(), 2, "{message}");
    assert_eq!(parts[0], "arena: refused");
    assert!(parts[1].starts_with("finalize: "), "{message}");
    assert!(parts[1].contains("retained: 1"), "{message}");
    assert_ne!(storage.phase(), Phase::Drained);
    assert_unmapped_in_reverse(&log);
}

/// An arena release that keeps its backing mapped is reported after the
/// initiating failure, and the storage still drains.
#[test]
fn a_retained_arena_release_is_reported_and_the_storage_still_drains() {
    let (mut storage, storage_log) = logged_storage(None);
    let (arena, arena_log) = logged_arena(Some(REFUSED_UNMAP));
    let message = early_exit("environment: refused".to_owned(), &mut storage, Some(arena));
    let parts = parts(&message);
    assert_eq!(parts.len(), 2, "{message}");
    assert_eq!(parts[0], "environment: refused");
    assert!(parts[1].starts_with("arena release retained "), "{message}");
    assert_eq!(arena_log.calls(Op::Unmap).len(), 1);
    assert_unmapped_in_reverse(&storage_log);
    assert_eq!(storage.phase(), Phase::Drained);
}

/// With both cleanups failing, the message holds the initiating failure,
/// then the arena's retained report, then the storage's.
#[test]
fn both_cleanup_failures_follow_the_initiating_error_arena_first() {
    let (mut storage, storage_log) = logged_storage(Some(REFUSED_UNMAP));
    let (arena, _) = logged_arena(Some(REFUSED_UNMAP));
    let message = early_exit("environment: refused".to_owned(), &mut storage, Some(arena));
    let parts = parts(&message);
    assert_eq!(parts.len(), 3, "{message}");
    assert_eq!(parts[0], "environment: refused");
    assert!(parts[1].starts_with("arena release retained "), "{message}");
    assert!(parts[2].starts_with("finalize: "), "{message}");
    assert!(parts[2].contains("retained: 1"), "{message}");
    assert_unmapped_in_reverse(&storage_log);
    assert_ne!(storage.phase(), Phase::Drained);
}

/// `early_exit` completes all arena unmap attempts before the first storage
/// unmap, even when the platform refuses an arena unmap.
#[test]
fn an_environment_failure_releases_the_arena_before_the_storage_s_first_unmap() {
    for fail in [None, Some(REFUSED_UNMAP)] {
        let (arena, arena_log) = logged_arena(fail);
        let (platform, storage_log) = logged_platform(None);
        let seen = Arc::new(Mutex::new(Vec::new()));
        platform.before_unmap({
            let (arena_log, seen) = (arena_log.clone(), Arc::clone(&seen));
            move || seen.lock().unwrap().push(arena_log.calls(Op::Unmap).len())
        });
        let mut storage = storage_over(platform, 512 << 10, 64 << 10);
        early_exit("environment: refused".to_owned(), &mut storage, Some(arena));
        assert_unmapped_in_reverse(&storage_log);
        let attempts = arena_log.calls(Op::Unmap).len();
        assert!(attempts > 0, "the arena's release attempted an unmap");
        assert_eq!(
            *seen.lock().unwrap(),
            vec![attempts; storage_log.mapped().len()],
            "the arena unmap attempts each storage unmap found already made"
        );
    }
}

/// If `Op::Populate` fails and the platform refuses the rollback unmap, the
/// arena error identifies the retained mapping. `early_exit` reports that
/// error before the storage finalization error.
#[test]
fn a_retained_arena_rollback_is_in_the_initiating_error_ahead_of_the_storage_report() {
    let (mut storage, storage_log) = logged_storage(Some(REFUSED_UNMAP));
    let refused = InitError::Os {
        phase: InitPhase::Populate,
        region: Region::Buffers,
        code: OsCode(libc::EIO),
    };
    let (platform, arena_log) = logged_platform(Some(Fail {
        op: Op::Populate,
        ordinal: 1,
        code: OsCode(libc::EIO),
        region: None,
    }));
    platform.fail_at(REFUSED_UNMAP);
    let error = arena(
        platform,
        &mut EngineBudget::new(usize::MAX),
        reservation_limits(),
    )
    .expect_err("the platform refuses the arena's populate");
    let [(base, len)] = arena_log.mapped()[..] else {
        panic!("premise: the arena made one mapping: {:?}", arena_log.all());
    };
    assert_eq!(arena_log.ranges(Op::Unmap), [(base, len)]);
    let retained = RetainedMapping {
        region: Region::Buffers,
        base,
        len,
        code: REFUSED_UNMAP.code,
    };
    assert_eq!(
        error,
        format!("arena: {refused:?}; arena rollback retained {retained:?}")
    );
    let message = early_exit(error.clone(), &mut storage, None);
    let report = message
        .strip_prefix(error.as_str())
        .and_then(|rest| rest.strip_prefix("; "));
    assert!(
        report.is_some_and(
            |report| report.starts_with("finalize: ") && report.contains("retained: 1")
        ),
        "{message}"
    );
    assert_unmapped_in_reverse(&storage_log);
    assert_ne!(storage.phase(), Phase::Drained);
}

#[test]
fn a_recorded_soak_failure_outranks_a_drain_error() {
    let failure = Some(SoakFailure::Inconclusive);
    let blocked = "finalize: Blocked".to_owned();
    assert_eq!(
        conclude(Ok(failure), Err(blocked.clone())),
        Ok(failure),
        "the recorded failure is the result"
    );
    assert_eq!(
        conclude(Ok(None), Err(blocked.clone())),
        Err(blocked.clone()),
        "a clean soak reports the drain error"
    );
    assert_eq!(conclude(Ok(None), Ok(())), Ok(None));
    assert_eq!(
        conclude(Err("verify: Unmapped".to_owned()), Err(blocked)),
        Err("verify: Unmapped".to_owned()),
        "the earlier error is the result"
    );
}

#[test]
fn a_body_cap_near_the_address_space_is_a_configuration_error() {
    let config = SoakConfig {
        body_cap: usize::MAX,
        ..SMOKE
    };
    let error = storage(&config, &SMOKE_BOUND, 0)
        .err()
        .expect("the storage refuses the cap");
    assert!(error.contains("body cap"), "{error}");
}

#[test]
fn a_capacity_past_half_the_address_space_is_a_configuration_error() {
    // Enough slots for `admit` to accept the capacity, so the doubling is
    // what refuses it.
    let bound = BoundConfig {
        slots: usize::MAX / 8,
        ..SMOKE_BOUND
    };
    let config = SoakConfig {
        capacity: usize::MAX / 2 + 1,
        ..SMOKE
    };
    assert_eq!(admit(&config, &bound), Ok(()));
    let error = storage_config(&config, &bound, crate::storage::test_recovery())
        .expect_err("the storage refuses the capacity");
    assert!(error.contains("past half the address space"), "{error}");
}

#[test]
fn the_smoke_soak_s_watermark_is_the_structural_floor_of_one_promise() {
    let validated = storage_config(&SMOKE, &SMOKE_BOUND, crate::storage::test_recovery())
        .expect("the smoke configuration");
    let marks = validated.volume().maintenance.expect("watermarks");
    assert_eq!(validated.largest_geometry().total_units(), 49);
    assert_eq!((marks.retired_units, marks.low_units), (49, 99));
    assert_eq!(validated.structural_floor(1), Ok(99));
}

#[test]
fn a_capacity_the_volume_can_never_fill_is_a_configuration_error() {
    let config = SoakConfig {
        capacity: usize::MAX / 2,
        ..SMOKE
    };
    let error = storage(&config, &SMOKE_BOUND, 0)
        .err()
        .expect("the storage refuses the capacity");
    assert!(error.contains("capacity"), "{error}");
}

#[test]
fn a_zero_run_is_a_configuration_error_before_native_setup() {
    let bound = BoundConfig {
        run: Duration::ZERO,
        ..SMOKE_BOUND
    };
    let error = admit(&SMOKE, &bound).expect_err("a zero run is refused");
    assert!(error.contains("run"), "{error}");
    assert_eq!(admit(&SMOKE, &SMOKE_BOUND), Ok(()));
}

#[test]
fn a_zero_patience_is_a_configuration_error_before_native_setup() {
    let config = SoakConfig {
        patience: Duration::ZERO,
        ..SMOKE
    };
    let error = admit(&config, &SMOKE_BOUND).expect_err("a zero patience is refused");
    assert!(error.contains("patience"), "{error}");
}

#[test]
fn a_pressure_at_or_past_the_capacity_is_a_configuration_error() {
    let config = SoakConfig {
        pressure: SMOKE.capacity,
        ..SMOKE
    };
    let error = admit(&config, &SMOKE_BOUND).expect_err("a pressure at the capacity is refused");
    assert!(error.contains("pressure"), "{error}");
}

#[test]
fn the_soak_s_recovery_helpers_run_on_every_allowed_cpu_but_the_owner_core() {
    let allowed = CpuSet::current().unwrap();
    let core = allowed.cpus().next().expect("an allowed CPU");
    let limits = recovery(core as u32).unwrap();
    let mut expected = allowed;
    expected.remove(core);
    assert_eq!(limits.cpus, expected);
}

/// What the scripted driver's quiesce saw just before it read the registers
/// that prove its stop: the count of the storage's `Unmap` calls so far, and
/// whether the controller was attached.
type Seen = Rc<Cell<Option<(usize, bool)>>>;

/// Arms `disk`, the scripted driver at `address`, so that its quiesce stores
/// in the returned cell the count of `Unmap` calls in `log` and whether the
/// controller is attached, just before it reads the registers that prove the
/// stop.
fn watch<N: Native>(disk: &mut SpdkDisk<'_, N>, address: &'static str, log: &Log) -> Seen {
    let seen = Seen::default();
    let (log, cell) = (log.clone(), Rc::clone(&seen));
    disk.stall_before_proof(move || {
        cell.set(Some((
            log.calls(Op::Unmap).len(),
            scripted_attached(address),
        )));
    });
    seen
}

/// Runs `drive` over `storage` under [`PATIENT`] and [`SMOKE_BOUND`], and
/// returns the run's outcome, concluded with the drain's result, when the
/// stop succeeded, the stop's error otherwise.
fn driven<N: Native>(
    storage: &mut Storage<TestPlatform>,
    arena: &BufferArena<TestPlatform>,
    registration: ArenaRegistration<'_>,
    disk: SpdkDisk<'_, N>,
) -> Result<Result<Option<SoakFailure>, String>, String> {
    drive(
        storage,
        arena,
        registration,
        disk,
        PATIENT,
        (serving(), crate::storage::next_session()),
        &SMOKE_BOUND,
        Vec::new(),
    )
    .map(|(outcome, _watchdog)| outcome)
}

/// Asserts that a run whose stop succeeded drained its storage after the
/// controller proved its stop: the quiesce that proved the stop saw the
/// controller attached and every storage mapping still mapped, and after
/// the run the controller is detached, every storage mapping is unmapped
/// once in reverse order of acquisition, and the storage is `Drained`.
fn assert_drained_after_the_proven_stop(
    address: &str,
    seen: &Seen,
    storage: &Storage<TestPlatform>,
    log: &Log,
) {
    assert_eq!(
        seen.get(),
        Some((0, true)),
        "no storage mapping is unmapped before the attached controller proved its stop"
    );
    assert!(
        !scripted_attached(address),
        "the controller detached before the run ended"
    );
    assert_unmapped_in_reverse(log);
    assert_eq!(storage.phase(), Phase::Drained);
}

/// Asserts that a run whose stop failed left the storage unfinalized: the
/// quiesce that proved the stop saw the controller attached and every
/// storage mapping still mapped, and after the error every storage mapping
/// is still mapped and the storage is short of `Drained`.
fn assert_undrained_after_the_failed_stop(seen: &Seen, storage: &Storage<TestPlatform>, log: &Log) {
    assert_eq!(seen.get(), Some((0, true)));
    assert!(
        log.calls(Op::Unmap).is_empty(),
        "a failed stop leaves every storage mapping mapped: {:?}",
        log.calls(Op::Unmap)
    );
    assert_ne!(storage.phase(), Phase::Drained);
}

/// A run that fails verification drains its storage only after the
/// controller proved its stop. The driver's quiesce counts the storage's
/// `Unmap` calls just before it reads the registers that prove the stop, so
/// a drain that ran ahead of the stop shows as a nonzero count there. After
/// the run the controller is detached and every storage mapping is unmapped
/// once, in reverse order of acquisition.
#[test]
fn a_verify_failure_unmaps_the_storage_only_after_the_controller_proved_its_stop() {
    const ADDRESS: &str = "scripted:soak-order-verify";
    let (env, arena) = (
        Environment::detached(),
        arena_on(TestPlatform::heap(4096), 16, 8),
    );
    let (mut storage, log) = logged_storage(None);
    let mut registration = registration_tests::mistranslated(&env, &arena);
    let mut disk = scripted_silent(ADDRESS, &mut registration, 1 << 22);
    let seen = watch(&mut disk, ADDRESS, &log);
    let outcome = driven(&mut storage, &arena, registration, disk)
        .expect("the controller stopped, so the run hands its outcome back");
    let error = outcome.expect_err("the verify failed the run");
    assert!(error.starts_with("verify: "), "{error}");
    assert_drained_after_the_proven_stop(ADDRESS, &seen, &storage, &log);
}

/// An arena over a heap platform with the pools a volume and its two
/// reservation commands attach over: sixteen read-response buffers, eight
/// receive-write buffers, one maintenance buffer and two reservation
/// buffers.
fn serving_arena() -> BufferArena<TestPlatform> {
    use crate::storage::volume_fixture::{BUFFER, pools_with};
    pools_with(
        TestPlatform::heap(4096),
        (16, BUFFER),
        (8, BUFFER),
        crate::storage::owner_fixture::HARDWARE_UNIT,
        2,
    )
}

fn reservation_limits() -> ReservationLimits {
    ReservationLimits::new(3, 2, 10, 100).unwrap()
}

/// Installs on the scripted driver the reservation limits and the attach
/// facts the volume attach reads: a device of 1 GiB that takes commands of
/// up to 128 KiB.
fn serve<N: Native>(disk: &mut SpdkDisk<'_, N>) {
    disk.set_reservation_limits(reservation_limits());
    disk.set_facts(crate::storage::volume_fixture::facts_for(
        1 << 30,
        128 << 10,
    ));
}

/// A run past verification ends with the controller detached and every
/// storage mapping unmapped once, in reverse order of acquisition: the
/// registration verifies, the volume attaches, the soak steps its seeded
/// workload until a fill fails and closes `NeverServing`, and the storage
/// ends `Drained`. The silent device leaves every command pending, so the
/// volume closes with a command outstanding and its own close takes the
/// quiesce hook: the hook shows the workload ended with the controller
/// attached and every storage mapping still mapped.
/// `a_stop_refused_at_unregistration_after_a_run_returns_its_error_with_the_storage_mapped`
/// shows that the drain waits for the stop's unregistration on this path.
/// The run reads the process-wide close request and parks its thread when a
/// stop stays unproven, so the test runs in a child process of its own,
/// which a parked run fails at the child's deadline.
#[test]
fn a_run_past_verification_ends_with_the_controller_detached_and_every_storage_mapping_unmapped_in_reverse()
 {
    crate::exact_child::run(
        "soak::bound_tests::a_run_past_verification_ends_with_the_controller_detached_and_every_storage_mapping_unmapped_in_reverse",
        Duration::from_secs(120),
        || {
            const ADDRESS: &str = "scripted:soak-order-run";
            let (env, arena) = (Environment::detached(), serving_arena());
            let (mut storage, log) = logged_storage(None);
            let mut registration = registration_tests::registered(&env, &arena);
            let mut disk = scripted_silent_at(ADDRESS, &mut registration, 1 << 22, 8);
            serve(&mut disk);
            let seen = watch(&mut disk, ADDRESS, &log);
            let outcome = driven(&mut storage, &arena, registration, disk)
                .expect("the controller stopped, so the run hands its outcome back");
            assert_eq!(
                outcome,
                Ok(Some(SoakFailure::NeverServing)),
                "the soak ran its workload and closed its volume"
            );
            assert_drained_after_the_proven_stop(ADDRESS, &seen, &storage, &log);
        },
    );
}

/// A stop refused at unregistration after a run past verification returns
/// its error with every storage mapping still mapped. A second device lease
/// of the registration stays outstanding: the controller proves its stop and
/// the registration records it, the unregistration refuses, and the
/// controller stays attached. The run reads the process-wide close request
/// and parks its thread when a stop stays unproven, so the test runs in a
/// child process of its own, which a parked run fails at the child's
/// deadline.
#[test]
fn a_stop_refused_at_unregistration_after_a_run_returns_its_error_with_the_storage_mapped() {
    crate::exact_child::run(
        "soak::bound_tests::a_stop_refused_at_unregistration_after_a_run_returns_its_error_with_the_storage_mapped",
        Duration::from_secs(120),
        || {
            const ADDRESS: &str = "scripted:soak-order-run-unregister";
            let (env, arena) = (Environment::detached(), serving_arena());
            let (mut storage, log) = logged_storage(None);
            let mut registration = registration_tests::registered(&env, &arena);
            let mut disk = scripted_silent_at(ADDRESS, &mut registration, 1 << 22, 8);
            serve(&mut disk);
            let _live = registration.device_attached();
            let seen = watch(&mut disk, ADDRESS, &log);
            let error = driven(&mut storage, &arena, registration, disk)
                .expect_err("the registration keeps a device that proved no stop");
            assert!(error.starts_with("unregister: "), "{error}");
            assert!(scripted_attached(ADDRESS));
            assert_undrained_after_the_failed_stop(&seen, &storage, &log);
        },
    );
}

type Register = for<'a> fn(&'a Environment, &'a BufferArena<TestPlatform>) -> ArenaRegistration<'a>;

/// A driver leased from another registration supplies the mismatched stop
/// proof that triggers the refusal.
fn assert_a_stop_refused_at_the_record_leaves_the_storage_mapped(
    address: &'static str,
    register: Register,
) {
    let (env, arena, other) = (
        Environment::detached(),
        arena_on(TestPlatform::heap(4096), 16, 8),
        arena_on(TestPlatform::heap(4096), 16, 8),
    );
    let (mut storage, log) = logged_storage(None);
    let registration = register(&env, &arena);
    let mut leasing = registration_tests::registered(&env, &other);
    let mut disk = scripted_silent(address, &mut leasing, 1 << 22);
    let seen = watch(&mut disk, address, &log);
    let error = driven(&mut storage, &arena, registration, disk)
        .expect_err("the registration refuses another registration's stop proof");
    assert!(error.starts_with("device stopped: "), "{error}");
    assert_undrained_after_the_failed_stop(&seen, &storage, &log);
}

/// A stop refused at the device-stopped record returns its error with every
/// storage mapping still mapped: the registration refuses a stop proof that
/// another registration's lease produced, before any unregistration.
#[test]
fn a_stop_refused_at_the_device_stopped_record_returns_its_error_with_the_storage_mapped() {
    assert_a_stop_refused_at_the_record_leaves_the_storage_mapped(
        "scripted:soak-order-record",
        registration_tests::registered,
    );
}

#[test]
fn a_stop_refused_at_the_device_stopped_record_after_a_verify_failure_returns_its_error_with_the_storage_mapped()
 {
    assert_a_stop_refused_at_the_record_leaves_the_storage_mapped(
        "scripted:soak-order-record-verify",
        registration_tests::mistranslated,
    );
}

/// A stop refused at unregistration after a verification failure returns its
/// error with every storage mapping still mapped, and the stopped controller
/// stays attached under the registration the refused unregistration left in
/// place.
#[test]
fn a_stop_refused_at_unregistration_after_a_verify_failure_returns_its_error_with_the_storage_mapped()
 {
    const ADDRESS: &str = "scripted:soak-order-unregister";
    let (env, arena) = (
        Environment::detached(),
        arena_on(TestPlatform::heap(4096), 16, 8),
    );
    let (mut storage, log) = logged_storage(None);
    let mut registration = registration_tests::mistranslated(&env, &arena);
    let mut disk = scripted_silent(ADDRESS, &mut registration, 1 << 22);
    // A second device lease of the registration stays outstanding, so the
    // unregistration refuses.
    let _live = registration.device_attached();
    let seen = watch(&mut disk, ADDRESS, &log);
    let error = driven(&mut storage, &arena, registration, disk)
        .expect_err("the registration keeps a device that proved no stop");
    assert!(error.starts_with("unregister: "), "{error}");
    assert!(
        scripted_attached(ADDRESS),
        "the stopped controller stays attached under the kept registration"
    );
    assert_undrained_after_the_failed_stop(&seen, &storage, &log);
}

/// Whether `env` counts exactly `live` registrations. The count is a private
/// field; the environment's `Debug` form shows it through a shared
/// reference, so the read works while a registration borrows the
/// environment.
fn counts_registrations(env: &Environment, live: u32) -> bool {
    format!("{env:?}").contains(&format!("registrations: Cell {{ value: {live} }}"))
}

/// Within the stop, the controller proves its stop before the registration
/// is undone. When the driver's quiesce is about to read the registers that
/// prove the stop, the environment still counts the run's registration and
/// the controller is attached; once the run returned, the environment counts
/// no registration, the controller is detached and the storage is `Drained`.
#[test]
fn the_registration_is_still_held_when_the_controller_proves_its_stop() {
    const ADDRESS: &str = "scripted:soak-order-registration-held";
    // The quiesce hook is `'static`, so the environment it reads is leaked
    // and lives for the process.
    let env: &'static Environment = Box::leak(Box::new(Environment::detached()));
    let arena = arena_on(TestPlatform::heap(4096), 16, 8);
    let (mut storage, _) = logged_storage(None);
    assert!(counts_registrations(env, 0), "{env:?}");
    let mut registration = registration_tests::mistranslated(env, &arena);
    assert!(counts_registrations(env, 1), "{env:?}");
    let mut disk = scripted_silent(ADDRESS, &mut registration, 1 << 22);
    let held = Rc::new(Cell::new(None));
    let cell = Rc::clone(&held);
    disk.stall_before_proof(move || {
        cell.set(Some((
            counts_registrations(env, 1),
            scripted_attached(ADDRESS),
        )));
    });
    let outcome = driven(&mut storage, &arena, registration, disk)
        .expect("the controller stopped, so the run hands its outcome back");
    outcome.expect_err("the verify failed the run");
    assert_eq!(
        held.get(),
        Some((true, true)),
        "the registration is held and the controller attached when the stop is proved"
    );
    assert!(
        counts_registrations(env, 0),
        "the stop unregistered once the controller proved it: {env:?}"
    );
    assert!(!scripted_attached(ADDRESS));
    assert_eq!(storage.phase(), Phase::Drained);
}
