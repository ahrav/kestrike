use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use super::super::identify_tests::SERIAL;
use super::attach_tests::{CONFIG, bind_driver, script_controller};
use super::connect::{ConnectError, Unready, connect_fresh, connect_restart, stop, stop_table};
use super::disk::{SpdkAttachError, SpdkConfig};
use super::disk_tests::{Call, SCRIPT, Scripted, ready_masks};
use crate::bind::authority_tests::{Placement, Setup, owner_records, owner_setup};
use crate::bind::{Mappings, Metadata};
use crate::exact_child::{self, ExactChild};
use crate::failover::admission::AdmissionError;
use crate::failover::evidence::{Pair, Registrant};
use crate::failover::fresh::Refusals;
use crate::failover::fresh::tests::{
    fresh_of, holder, local_record, plane, shard_record, store, volume_record,
};
use crate::failover::restart::LocalSource;
use crate::failover::restart::tests::shard_now;
use crate::host::HostGate;
use crate::host::fencer::{Fencer, Release};
use crate::native::{Environment, registration_tests};
use crate::storage::IO_UNIT;
use crate::storage::gate_fixture::{Ticking, encode_report, limits};
use crate::storage::store_tests::{client, shard};

/// The park case fails when a connect has not attached its address after this long.
const ATTACHED_WITHIN: Duration = Duration::from_secs(60);

/// The park case waits `PARKED_FOR` after attachment before checking whether the connects returned.
const PARKED_FOR: Duration = Duration::from_secs(1);

/// Each child has at most this long to finish.
const DEADLINE: Duration = Duration::from_secs(120);

/// The supervising test owns this directory and removes it on drop. It holds the child's fixtures, which a parked
/// thread or a child killed at its deadline leaves on disk.
struct Scratch(PathBuf);

impl Scratch {
    /// The directory sits under the home directory, since an authority directory refuses an ancestor that another
    /// user can write. `prepare_state_dir` creates it, and each missing parent, with mode `0o700` under any umask
    /// that keeps the owner bits.
    fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let root = std::env::var_os("HOME")
            .map_or_else(|| std::env::current_dir().unwrap(), PathBuf::from)
            .join(".tmp/kestrike-connect-tests")
            .join(format!(
                "{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        let _ = std::fs::remove_dir_all(&root);
        let owner = std::fs::metadata("/proc/self").unwrap().uid();
        crate::bind::prepare_state_dir(&root, owner).unwrap();
        Self(root)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Runs `body` as the case `name` of this module in a child process of its own. A connect whose refused attach keeps
/// its controller, and a stop that stays unproven, park their thread for good, so a parked case fails at its child's
/// deadline while the other cases of the run report their results.
///
/// The child's `HOME` and `TMPDIR` name the parent's [`Scratch`], so the child creates its fixture trees and
/// authority directories there.
fn in_child(name: &str, body: fn()) {
    let id = format!("storage::device::spdk::connect_tests::{name}");
    if exact_child::is_child(&id) {
        return exact_child::run(&id, DEADLINE, body);
    }
    let scratch = Scratch::new();
    let root = scratch.0.to_str().expect("the scratch path is UTF-8");
    let outcome = ExactChild::spawn(&id, &[("HOME", root), ("TMPDIR", root)])
        .unwrap_or_else(|error| panic!("spawn {id}: {error}"))
        .finish(Instant::now() + DEADLINE);
    assert!(
        exact_child::credited(&id, &outcome),
        "{id} in a fresh child: {outcome:?}"
    );
}

/// Under umask `0o002`, [`Scratch`] keeps its group and other write bits clear, so `prepare_state_dir` accepts a
/// state directory beneath it.
#[test]
fn a_scratch_made_under_a_group_writable_umask_admits_a_state_directory_beneath_it() {
    exact_child::run(
        "storage::device::spdk::connect_tests::a_scratch_made_under_a_group_writable_umask_admits_a_state_directory_beneath_it",
        DEADLINE,
        || {
            // SAFETY: A dedicated child process isolates the process-wide `umask` change from other tests.
            unsafe { libc::umask(0o002) };
            let scratch = Scratch::new();
            let meta = std::fs::metadata(&scratch.0).unwrap();
            let state = scratch.0.join(".tmp/kestrike-authority-tests/case");
            let prepared = crate::bind::prepare_state_dir(&state, meta.uid());
            assert!(prepared.is_ok(), "{prepared:?}");
            assert_eq!(
                meta.mode() & 0o022,
                0,
                "the scratch mode is {:o}",
                meta.mode() & 0o777
            );
        },
    );
}

/// The fresh path connects only after its acknowledged bump, over the record it persisted under the shared lock.
#[test]
fn a_fresh_acquisition_connects_after_its_bump_over_one_shared_owner_lock() {
    in_child(
        "a_fresh_acquisition_connects_after_its_bump_over_one_shared_owner_lock",
        fresh_acquisition,
    );
}

fn fresh_acquisition() {
    let bdf = "0000:ab:1c.0";
    let setup = bound(bdf);
    let authority = setup.state.join("authority");
    std::fs::remove_file(&authority).unwrap();
    let host = setup.host().clone();
    let store = store(shard_record(0), volume_record());
    let (env, arena) = (
        Environment::detached(),
        crate::storage::gate_fixture::arena(),
    );
    let mut registration = registration_tests::registered(&env, &arena);
    let clock = Ticking::default();
    let mut records = owner_records(&setup);
    let observed = store.clone();
    let (lock, connect_host, registration_ref) = (&setup.lock, &host, &mut registration);
    let persisted = std::cell::Cell::new(None);
    let mut fencer = Fencer::new(
        &HostGate::qualified(),
        || {
            assert_eq!(
                shard_now(&observed).attempts,
                1,
                "the connect follows the acknowledged bump"
            );
            assert!(
                authority.exists(),
                "the fresh path persisted the local record before the connect"
            );
            let own = lock.local().unwrap().pair();
            script_holder(own);
            persisted.set(Some(own));
            let connected = connect_fresh::<Scripted>(
                connect_host,
                lock,
                &Placement,
                registration_ref,
                CONFIG,
                limits(),
            );
            assert!(
                connected
                    .as_ref()
                    .is_ok_and(|(disk, _)| disk.medium_withheld()),
                "the fresh attach withholds medium commands until a gate pass"
            );
            connected
        },
        limits(),
        &arena,
        &clock,
    );
    let activated = fresh_of(shard(), holder())
        .run(
            &mut client(&store),
            &mut plane(),
            &mut records,
            &mut fencer,
            &mut Refusals::default(),
        )
        .unwrap();
    assert_eq!(activated.session().target().attempts, 1);
    assert_eq!(shard_now(&store).attempts, 1);
    assert!(activated.fencing().coverage().is_some());
    let own = persisted.get().expect("the connect ran");
    assert_eq!(own.key, local_record().pair().key);
    SCRIPT.with_borrow(|script| {
        assert_eq!(
            script.connected,
            Some((own.exhid.bytes(), bdf.to_owned())),
            "the connect names the persisted host ID and the recorded address"
        );
        let sectors = u64::try_from(IO_UNIT / 512).unwrap();
        assert_eq!(
            script.media.keys().copied().collect::<Vec<_>>(),
            (0..sectors).collect::<Vec<_>>(),
            "the activation record's write covers unit 0 and nothing else"
        );
    });
    assert_eq!(
        reservation_calls(),
        [(Call::Register, 0), (Call::Acquire, 0), (Call::Report, 0)]
    );
    let Release::Driver(disk) = fencer.release() else {
        panic!("the activated sequence left nothing outstanding");
    };
    assert!(
        !disk.medium_withheld(),
        "the fresh fencer's gate pass admitted the unit-0 commands"
    );
    assert!(stop(disk, registration, Duration::from_secs(5)).is_ok());
    assert!(!super::disk::attached().contains(bdf));
}

/// The scripted controller's next register read reports CC.EN and CSTS.RDY set, so a connect over the setup
/// observes a ready controller.
fn bound(bdf: &str) -> Setup {
    SCRIPT.take();
    let setup = owner_setup();
    let mut mappings = setup.lock.mappings().unwrap();
    let nvme = mappings.nvme.as_mut().unwrap();
    (nvme.bdf, nvme.sector_size, nvme.capacity) = (bdf.into(), 512, 1 << 30);
    mappings.write(&setup.state.join("mappings")).unwrap();
    bind_driver(setup.host(), bdf, crate::bind::VFIO);
    script_controller(SERIAL, 9);
    script_holder(local_record().pair());
    SCRIPT.with_borrow_mut(|script| {
        script.medium = true;
        script.registers.push_back(ready_masks());
    });
    setup
}

fn script_disabled_controller() {
    SCRIPT.with_borrow_mut(|script| script.registers.clear());
}

fn script_holder(own: Pair) {
    SCRIPT.with_borrow_mut(|script| {
        script.feature_host_id = own.exhid.bytes();
        script.report_bytes = encode_report(
            2,
            &[Registrant {
                cntlid: 1,
                holder: true,
                pair: own,
            }],
        );
    });
}

fn reservation_calls() -> Vec<(Call, u32)> {
    SCRIPT.with_borrow(|script| {
        script
            .reservation_calls
            .iter()
            .map(|&(call, action, ..)| (call, action))
            .collect()
    })
}

/// A readiness failure after the attach hands the attached driver back for the proven stop.
#[test]
fn a_readiness_failure_returns_the_attached_driver_for_its_stop() {
    in_child(
        "a_readiness_failure_returns_the_attached_driver_for_its_stop",
        || {
            for (bdf, disabled) in [("0000:ab:1d.0", false), ("0000:ab:11.0", true)] {
                readiness_failure(bdf, disabled);
            }
        },
    );
}

fn readiness_failure(bdf: &str, disabled: bool) {
    let setup = bound(bdf);
    let host = setup.host().clone();
    let store = store(shard_record(0), volume_record());
    let (env, arena) = (
        Environment::detached(),
        crate::storage::gate_fixture::arena(),
    );
    let mut registration = if disabled {
        script_disabled_controller();
        registration_tests::registered(&env, &arena)
    } else {
        registration_tests::ready(&env, &arena)
    };
    let clock = Ticking::default();
    let mut records = owner_records(&setup);
    let (lock, connect_host, registration_ref) = (&setup.lock, &host, &mut registration);
    let mut fencer = Fencer::new(
        &HostGate::qualified(),
        move || {
            let connected = connect_fresh::<Scripted>(
                connect_host,
                lock,
                &Placement,
                registration_ref,
                CONFIG,
                limits(),
            );
            assert!(
                match &connected {
                    Err(ConnectError::Controller(_)) => disabled,
                    Err(ConnectError::Unready(_, Unready::Map(_))) => !disabled,
                    _ => false,
                },
                "{connected:?}"
            );
            connected
        },
        limits(),
        &arena,
        &clock,
    );
    let refused = fresh_of(shard(), holder())
        .run(
            &mut client(&store),
            &mut plane(),
            &mut records,
            &mut fencer,
            &mut Refusals::default(),
        )
        .unwrap_err();
    assert_eq!(
        refused.check,
        crate::failover::fresh::Check::HostId(crate::failover::restart::Failed(None)),
        "{bdf}"
    );
    assert!(refused.flip.is_some(), "{bdf}");
    assert!(reservation_calls().is_empty(), "{bdf}");
    let Release::Driver(disk) = fencer.release() else {
        panic!("{bdf}: an unready connect hands its driver back");
    };
    assert!(stop(disk, registration, Duration::from_secs(5)).is_ok());
    assert!(!super::disk::attached().contains(bdf));
}

/// A restart through `connect_restart` reaches the fencing boundary, and a readiness failure holds with no flip.
#[test]
fn a_restart_connects_through_connect_restart_and_reaches_the_fencing_boundary() {
    in_child(
        "a_restart_connects_through_connect_restart_and_reaches_the_fencing_boundary",
        restart_connect,
    );
}

fn restart_connect() {
    use crate::failover::attachments::InstanceId;
    use crate::failover::poll::Holder;
    use crate::failover::records::{ShardRecord, VolumeId, VolumeRecord};
    use crate::failover::restart::tests as restart_tests;
    use crate::failover::restart::{Check, Failed};
    use crate::host::inputs::{Inputs, restart};
    for (bdf, mapped, disabled) in [
        ("0000:ab:1a.0", false, false),
        ("0000:ab:1e.0", true, false),
        ("0000:ab:12.0", false, true),
    ] {
        let unready = mapped || disabled;
        let setup = bound(bdf);
        if disabled {
            script_disabled_controller();
        }
        let host = setup.host().clone();
        let local = setup.lock.local().unwrap();
        let own = local.pair();
        let volume = VolumeId::new(&local.binding().volume).unwrap();
        let holder = Holder {
            volume,
            host: restart_tests::host(),
            instance: InstanceId::new(&local.binding().instance).unwrap(),
        };
        let bounds = crate::storage::gate_fixture::bounds_of(limits());
        let enrolled = VolumeRecord {
            volume,
            pairs: Vec::new(),
            ..restart_tests::volume_record()
        }
        .enroll(holder.host, own, &bounds)
        .unwrap()
        .expect("the own pair enrolls for this host's attach");
        let records = restart_tests::store(
            ShardRecord {
                active: volume,
                ..restart_tests::shard_record(1)
            },
            enrolled,
        );
        let (env, arena) = (
            Environment::detached(),
            crate::storage::gate_fixture::arena(),
        );
        let mut registration = if mapped {
            registration_tests::ready(&env, &arena)
        } else {
            registration_tests::registered(&env, &arena)
        };
        let clock = Ticking::default();
        let (lock, connect_host, registration_ref) = (&setup.lock, &host, &mut registration);
        let mut fencer = Fencer::new(
            &HostGate::qualified(),
            move || {
                let connected = connect_restart::<Scripted>(
                    connect_host,
                    lock,
                    registration_ref,
                    CONFIG,
                    local,
                    limits(),
                );
                let disk = match &connected {
                    Ok((disk, _)) => disk,
                    Err(ConnectError::Controller(disk)) => {
                        assert!(
                            disabled,
                            "{bdf}: a ready controller refused its observation"
                        );
                        &**disk
                    }
                    Err(ConnectError::Unready(disk, Unready::Map(_))) if mapped => &**disk,
                    Err(error) => panic!("{bdf}: the restart connect: {error:?}"),
                };
                assert!(
                    disk.medium_withheld(),
                    "the restart attach withholds medium commands until a gate pass"
                );
                connected
            },
            limits(),
            &arena,
            &clock,
        );
        let inputs = Inputs::new(shard(), holder, bounds, limits(), 4).unwrap();
        let restarted = restart(&inputs, &[]).run(&mut client(&records), &setup.lock, &mut fencer);
        if unready {
            let refused = restarted.unwrap_err();
            assert_eq!(
                (refused.check, refused.flip),
                (Check::Ready(Failed(None)), None),
                "{bdf}"
            );
            assert!(reservation_calls().is_empty(), "{bdf}");
            assert_eq!(restart_tests::shard_now(&records).attempts, 1);
        } else {
            assert_eq!(restarted.unwrap().session().target().attempts, 2);
            assert_eq!(
                reservation_calls(),
                [(Call::Report, 0), (Call::Acquire, 2), (Call::Report, 0)]
            );
        }
        let Release::Driver(disk) = fencer.release() else {
            panic!("the restart left nothing outstanding");
        };
        assert!(
            disk.medium_withheld(),
            "the restart passes no gate value, so the medium stays withheld for the volume's gate"
        );
        assert!(stop(disk, registration, Duration::from_secs(5)).is_ok());
        assert!(!super::disk::attached().contains(bdf));
    }
}

/// A table left holding a command ends through `stop_table`, which detaches the driver.
#[test]
fn a_table_with_a_command_outstanding_ends_through_the_table_stop() {
    in_child(
        "a_table_with_a_command_outstanding_ends_through_the_table_stop",
        || {
            for (bdf, withheld) in [("0000:ab:1b.0", false), ("0000:ab:19.0", true)] {
                table_stop(bdf, withheld);
            }
        },
    );
}

fn table_stop(bdf: &str, withheld: bool) {
    let setup = bound(bdf);
    let host = setup.host().clone();
    let store = store(shard_record(0), volume_record());
    let (env, arena) = (
        Environment::detached(),
        crate::storage::gate_fixture::arena(),
    );
    let mut registration = registration_tests::registered(&env, &arena);
    let clock = Ticking::default();
    let mut records = owner_records(&setup);
    let (lock, connect_host, registration_ref) = (&setup.lock, &host, &mut registration);
    let mut fencer = Fencer::new(
        &HostGate::qualified(),
        move || {
            let connected = connect_fresh::<Scripted>(
                connect_host,
                lock,
                &Placement,
                registration_ref,
                CONFIG,
                limits(),
            );
            SCRIPT.with_borrow_mut(|script| script.finished.extend([0; 1 << 12]));
            connected
        },
        limits(),
        &arena,
        &clock,
    );
    let refused = fresh_of(shard(), holder())
        .run(
            &mut client(&store),
            &mut plane(),
            &mut records,
            &mut fencer,
            &mut Refusals::default(),
        )
        .unwrap_err();
    assert_eq!(
        refused.check,
        crate::failover::fresh::Check::Register(crate::failover::restart::Failed(None))
    );
    assert_eq!(reservation_calls(), [(Call::Register, 0)]);
    let Release::Outstanding(table) = fencer.release() else {
        panic!("a Register that never completes keeps its table");
    };
    if !withheld {
        SCRIPT.with_borrow_mut(|script| script.finished.clear());
    }
    assert!(stop_table(table, registration, Duration::from_secs(5)).is_ok());
    assert!(!super::disk::attached().contains(bdf));
    if withheld {
        SCRIPT.with_borrow(|script| {
            let register = script
                .submits
                .iter()
                .position(|submit| submit.rc == 0)
                .expect("the Register was accepted");
            let origin = script
                .origins
                .iter()
                .find(|origin| origin.submission == Some(register))
                .expect("the Register's callback ran");
            assert_eq!(
                origin.inside,
                Call::Free,
                "the qpair free ended the Register"
            );
        });
    }
    assert!(matches!(
        arena.release(),
        Ok(crate::storage::Released::Complete)
    ));
}

/// A native connect that returns no controller refuses `ConnectError::Attach(Connect)` with the address released,
/// and the fresh path refuses at its host-ID step with no reservation command and no driver to release.
#[test]
fn a_failed_native_connect_refuses_with_the_address_released() {
    in_child(
        "a_failed_native_connect_refuses_with_the_address_released",
        failed_native_connect,
    );
}

fn failed_native_connect() {
    let bdf = "0000:ab:18.0";
    let setup = bound(bdf);
    SCRIPT.with_borrow_mut(|script| script.controller = None);
    let host = setup.host().clone();
    let store = store(shard_record(0), volume_record());
    let (env, arena) = (
        Environment::detached(),
        crate::storage::gate_fixture::arena(),
    );
    let mut registration = registration_tests::registered(&env, &arena);
    let clock = Ticking::default();
    let mut records = owner_records(&setup);
    let (lock, connect_host, registration_ref) = (&setup.lock, &host, &mut registration);
    let mut fencer = Fencer::new(
        &HostGate::qualified(),
        move || {
            let connected = connect_fresh::<Scripted>(
                connect_host,
                lock,
                &Placement,
                registration_ref,
                CONFIG,
                limits(),
            );
            assert!(
                matches!(
                    connected,
                    Err(ConnectError::Attach(SpdkAttachError::Connect))
                ),
                "{connected:?}"
            );
            connected
        },
        limits(),
        &arena,
        &clock,
    );
    let refused = fresh_of(shard(), holder())
        .run(
            &mut client(&store),
            &mut plane(),
            &mut records,
            &mut fencer,
            &mut Refusals::default(),
        )
        .unwrap_err();
    assert_eq!(
        refused.check,
        crate::failover::fresh::Check::HostId(crate::failover::restart::Failed(None))
    );
    assert!(reservation_calls().is_empty());
    assert!(SCRIPT.with_borrow(|script| script.connected.is_some()));
    assert!(!super::disk::attached().contains(bdf));
    assert!(matches!(fencer.release(), Release::Unconnected));
}

/// A stop whose detach SPDK refuses returns its error after the proven disable and the unregistration, with the
/// address still attached.
#[test]
fn a_stop_whose_detach_is_refused_reports_the_controller_attached() {
    in_child(
        "a_stop_whose_detach_is_refused_reports_the_controller_attached",
        || {
            let bdf = "0000:ab:17.0";
            let setup = bound(bdf);
            let (env, arena) = (
                Environment::detached(),
                crate::storage::gate_fixture::arena(),
            );
            let mut registration = registration_tests::registered(&env, &arena);
            let (disk, _) = connect_fresh::<Scripted>(
                setup.host(),
                &setup.lock,
                &Placement,
                &mut registration,
                CONFIG,
                limits(),
            )
            .expect("the connect reaches a ready driver");
            SCRIPT.with_borrow_mut(|script| script.detach.push_back(-libc::ENOMEM));
            assert_eq!(
                stop(disk, registration, Duration::from_secs(5))
                    .err()
                    .as_deref(),
                Some("the controller stayed attached")
            );
            assert!(super::disk::attached().contains(bdf));
        },
    );
}

/// A connect refused while a live driver of this process holds the recorded address returns its refusal, since that
/// attach acquired nothing: an invalid configuration refuses `Config` through either connect, and a valid one
/// `AlreadyAttached`. The live driver then ends through its stop.
///
/// During the zone check, a connect using a second state directory records the live driver's address under a
/// different volume in that directory's mappings file. The second connect returns its `Binding` refusal.
#[test]
fn a_connect_refused_beside_a_live_driver_of_the_address_returns() {
    in_child(
        "a_connect_refused_beside_a_live_driver_of_the_address_returns",
        || {
            let bdf = "0000:ab:14.0";
            let setup = bound(bdf);
            let (env, arena) = (
                Environment::detached(),
                crate::storage::gate_fixture::arena(),
            );
            let mut registration = registration_tests::registered(&env, &arena);
            let (disk, _) = connect_fresh::<Scripted>(
                setup.host(),
                &setup.lock,
                &Placement,
                &mut registration,
                CONFIG,
                limits(),
            )
            .expect("the first connect reaches a ready driver");
            let invalid = SpdkConfig {
                queue_depth: 0,
                ..CONFIG
            };
            for (config, refusal) in [
                (invalid, SpdkAttachError::Config),
                (CONFIG, SpdkAttachError::AlreadyAttached),
            ] {
                let again = connect_fresh::<Scripted>(
                    setup.host(),
                    &setup.lock,
                    &Placement,
                    &mut registration,
                    config,
                    limits(),
                );
                assert!(
                    matches!(&again, Err(ConnectError::Attach(error)) if *error == refusal),
                    "{again:?}"
                );
            }
            let again = connect_restart::<Scripted>(
                setup.host(),
                &setup.lock,
                &mut registration,
                invalid,
                setup.lock.local().unwrap(),
                limits(),
            );
            assert!(
                matches!(again, Err(ConnectError::Attach(SpdkAttachError::Config))),
                "{again:?}"
            );
            let elsewhere = Setup::new();
            let mut rewritten = elsewhere.lock.mappings().unwrap();
            let nvme = rewritten.nvme.as_mut().unwrap();
            assert_ne!(nvme.bdf, bdf);
            (nvme.bdf, nvme.volume) = (bdf.to_owned(), "vol-0fedcba9876543210".to_owned());
            let racing = Remapping {
                path: elsewhere.state.join("mappings"),
                other: rewritten,
            };
            let again = connect_fresh::<Scripted>(
                elsewhere.host(),
                &elsewhere.lock,
                &racing,
                &mut registration,
                CONFIG,
                limits(),
            );
            assert_eq!(
                elsewhere.lock.mappings().unwrap().nvme.unwrap().bdf,
                bdf,
                "the admission's zone request rewrote the mappings file to the live driver's address"
            );
            assert!(
                matches!(
                    again,
                    Err(ConnectError::Attach(SpdkAttachError::Authority(
                        AdmissionError::Binding
                    )))
                ),
                "{again:?}"
            );
            assert!(stop(disk, registration, Duration::from_secs(5)).is_ok());
            assert!(!super::disk::attached().contains(bdf));
        },
    );
}

/// An attach refusal that leaves the recorded address attached parks the connect, the fresh one and the restart's
/// alike: the namespace capture fails after the native connect and SPDK refuses the rollback detach, and
/// [`PARKED_FOR`] later neither connect has returned and both addresses are still attached.
#[test]
fn an_attach_refusal_that_keeps_its_controller_parks_the_connect() {
    in_child(
        "an_attach_refusal_that_keeps_its_controller_parks_the_connect",
        || {
            const FRESH: &str = "0000:ab:16.0";
            const RESTART: &str = "0000:ab:13.0";
            let connects = [FRESH, RESTART].map(|bdf| {
                std::thread::spawn(move || {
                    let setup = bound(bdf);
                    let mappings = setup.state.join("mappings");
                    SCRIPT.with_borrow_mut(|script| {
                        script.namespace_data = None;
                        script.detach.push_back(-libc::ENOMEM);
                        script.detaching = Some(Box::new(move || {
                            std::fs::remove_file(&mappings).unwrap();
                        }));
                    });
                    let (env, arena) = (
                        Environment::detached(),
                        crate::storage::gate_fixture::arena(),
                    );
                    let mut registration = registration_tests::registered(&env, &arena);
                    if bdf == FRESH {
                        drop(connect_fresh::<Scripted>(
                            setup.host(),
                            &setup.lock,
                            &Placement,
                            &mut registration,
                            CONFIG,
                            limits(),
                        ));
                    } else {
                        drop(connect_restart::<Scripted>(
                            setup.host(),
                            &setup.lock,
                            &mut registration,
                            CONFIG,
                            setup.lock.local().unwrap(),
                            limits(),
                        ));
                    }
                })
            });
            let attaching = Instant::now();
            for (connect, bdf) in connects.iter().zip([FRESH, RESTART]) {
                while !super::disk::attached().contains(bdf) {
                    assert!(
                        !connect.is_finished(),
                        "{bdf}: the connect ended before it attached"
                    );
                    assert!(
                        attaching.elapsed() < ATTACHED_WITHIN,
                        "{bdf}: the connect attached nothing"
                    );
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            std::thread::sleep(PARKED_FOR);
            for (connect, bdf) in connects.iter().zip([FRESH, RESTART]) {
                assert!(
                    !connect.is_finished(),
                    "{bdf}: the connect returned with its controller attached"
                );
                assert!(super::disk::attached().contains(bdf), "{bdf}");
            }
        },
    );
}

/// Instance metadata that rewrites the mappings file to `other` when asked for the availability zone, which the
/// admission reads after it took the mapped volume from the file.
struct Remapping {
    path: PathBuf,
    other: Mappings,
}

impl Metadata for Remapping {
    fn get(&self, path: &str) -> std::io::Result<String> {
        if path == "placement/availability-zone" {
            self.other.write(&self.path)?;
        }
        Placement.get(path)
    }
}

/// A mappings file that names another volume once the admission has checked the first refuses `Binding` before the
/// native connect, so the fresh connect attaches only the volume its authority admitted.
#[test]
fn a_mappings_file_rewritten_after_the_admission_refuses_binding_before_the_connect() {
    in_child(
        "a_mappings_file_rewritten_after_the_admission_refuses_binding_before_the_connect",
        || {
            let bdf = "0000:ab:15.0";
            let setup = bound(bdf);
            let renamed = "vol-0fedcba9876543210";
            let mut other = setup.lock.mappings().unwrap();
            other.nvme.as_mut().unwrap().volume = renamed.to_owned();
            let racing = Remapping {
                path: setup.state.join("mappings"),
                other,
            };
            let (env, arena) = (
                Environment::detached(),
                crate::storage::gate_fixture::arena(),
            );
            let mut registration = registration_tests::registered(&env, &arena);
            let connected = connect_fresh::<Scripted>(
                setup.host(),
                &setup.lock,
                &racing,
                &mut registration,
                CONFIG,
                limits(),
            );
            assert_eq!(
                setup.lock.mappings().unwrap().nvme.unwrap().volume,
                renamed,
                "the admission's zone request rewrote the mappings file"
            );
            assert!(
                matches!(
                    connected,
                    Err(ConnectError::Attach(SpdkAttachError::Authority(
                        AdmissionError::Binding
                    )))
                ),
                "{connected:?}"
            );
            assert!(
                SCRIPT.with_borrow(|script| script.connected.is_none()),
                "the refusal precedes the native connect"
            );
            assert!(!super::disk::attached().contains(bdf));
        },
    );
}
