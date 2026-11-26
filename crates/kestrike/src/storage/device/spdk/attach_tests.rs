use std::path::Path;
use std::ptr::NonNull;
use std::sync::Arc;
use std::time::Duration;

use super::super::disk::{Disk, QuiesceStatus};
use super::super::identify::IdentifyRaw;
use super::super::identify_tests::{SERIAL, controller, namespace};
use super::super::profile::completion_is_durable;
use super::disk::{SpdkAttachError, SpdkConfig, SpdkDisk, attached};
use super::disk_tests::{Call, SCRIPT, Scripted, calls, facts};
use super::limits::NamespaceFacts;
use crate::bind::{DEVICE_LOCKS, DeviceLock, NvmeBinding};
use crate::native::{ArenaRegistration, Environment, Watchdog, registration_tests};

pub(super) const CONFIG: SpdkConfig = SpdkConfig {
    queue_depth: 8,
    timeout_io_us: 1_000_000,
    timeout_admin_us: 1_000_000,
};

fn binding(bdf: &str) -> NvmeBinding {
    NvmeBinding {
        volume: "vol-0123456789abcdef0".to_owned(),
        bdf: bdf.to_owned(),
        nsid: 1,
        sector_size: 512,
        capacity: 1 << 30,
        original_driver: "nvme".to_owned(),
        original_override: None,
    }
}

pub(super) fn script(bdf: &str, serial: &str, lbads: u32) {
    script_controller(serial, lbads);
    assert!(attached().insert(bdf.to_owned()));
}

/// Scripts an EDS-capable controller of `serial` with a namespace of `2^lbads`-byte sectors, whose Get Features
/// reads back the host ID [`own`] carries.
pub(super) fn script_controller(serial: &str, lbads: u32) {
    SCRIPT.with_borrow_mut(|script| {
        let mut data = controller(serial);
        data.ctratt = sys_ctratt();
        script.controller = Some(data);
        script.namespace_data = Some(namespace(1 << (30 - lbads), lbads));
        script.pci = Some((0x1d0f, 0x8061));
        script.facts = Some(facts());
        script.feature_host_id = *b"persisted-exhid!";
    });
}

pub(super) fn configure<'l>(
    bdf: &str,
    registration: &mut ArenaRegistration<'_>,
) -> Result<SpdkDisk<'l, Scripted>, SpdkAttachError> {
    configure_with(
        bdf,
        registration,
        CONFIG,
        crate::storage::ReservationLimits::new(2, 2, 10, 10).unwrap(),
    )
}

/// The persisted pair the scripted controller is connected with.
pub(super) fn own() -> crate::failover::evidence::Pair {
    crate::failover::evidence::Pair {
        exhid: crate::failover::identity::Exhid::new(*b"persisted-exhid!").unwrap(),
        key: crate::failover::identity::Key::decode((5 << 32) | 5).unwrap(),
    }
}

pub(super) fn configure_with<'l>(
    bdf: &str,
    registration: &mut ArenaRegistration<'_>,
    config: SpdkConfig,
    limits: crate::storage::ReservationLimits,
) -> Result<SpdkDisk<'l, Scripted>, SpdkAttachError> {
    // SAFETY: the scripted controller holds no qpair or callback, and `bdf` is marked attached.
    unsafe {
        SpdkDisk::<Scripted>::configured(
            NonNull::dangling(),
            &binding(bdf),
            SERIAL,
            config,
            limits,
            own(),
            registration,
        )
    }
}

#[test]
fn attach_owns_the_identify_data_after_the_native_data_is_gone_and_after_detach() {
    let bdf = "scripted:identify";
    script(bdf, SERIAL, 9);
    SCRIPT.with_borrow_mut(|script| {
        script.facts = Some(NamespaceFacts {
            max_transfer: 512 << 10,
            boundary: 256,
            ..facts()
        });
    });
    let (env, arena) = (Environment::detached(), registration_tests::new_arena());
    let mut registration = registration_tests::ready(&env, &arena);
    let mut disk = configure(bdf, &mut registration).unwrap();
    let (c, n) = SCRIPT.with_borrow_mut(|script| {
        (
            script.controller.take().unwrap(),
            script.namespace_data.take().unwrap(),
        )
    });
    // SAFETY: both fixtures are readable structures.
    let expected = unsafe { IdentifyRaw::capture(&c, &*n, 1) }.unwrap();
    drop((c, n));
    let before = disk.attach_facts().cloned().unwrap();
    assert_eq!(before.identify.raw(), &expected);
    assert_eq!(
        before.identify.decoded().map(|facts| facts.sector_size),
        Ok(512)
    );
    assert_eq!(before.identity.serial, SERIAL);
    assert_eq!(before.identity.capacity, 1 << 30);
    let transfer = before.identify.transfer();
    assert_eq!(
        (transfer.namespace_max, transfer.boundary, transfer.command),
        (512 << 10, 256, 256 << 10)
    );
    assert_eq!(
        completion_is_durable(before.identify.raw().record(), &before.identity),
        Ok(())
    );
    let order = calls();
    let at = |call| order.iter().position(|&c| c == call).unwrap();
    assert!(at(Call::NamespaceData) < at(Call::NamespaceFacts));
    assert!(at(Call::NamespaceFacts) < at(Call::GetFeature));
    assert!(at(Call::GetFeature) < at(Call::AllocQpair));
    assert_eq!(disk.quiesce(), QuiesceStatus::Pending);
    assert_eq!(disk.quiesce(), QuiesceStatus::Stopped);
    registration
        .device_stopped(disk.stop_proof().unwrap())
        .unwrap();
    assert!(disk.detach(&registration_tests::undone(registration)));
    assert_eq!(disk.attach_facts(), Some(&before));
}

#[test]
fn each_attach_refusal_detaches_the_controller_and_frees_its_address() {
    let (env, arena) = (Environment::detached(), registration_tests::new_arena());
    let mut registration = registration_tests::ready(&env, &arena);
    type Case = (&'static str, &'static str, u32, fn(), SpdkAttachError);
    let cases: [Case; 5] = [
        (
            "scripted:namespace",
            SERIAL,
            9,
            || SCRIPT.with_borrow_mut(|script| script.no_namespace = true),
            SpdkAttachError::Identity,
        ),
        (
            "scripted:serial",
            "vol0fedcba9876543210",
            9,
            || {},
            SpdkAttachError::Identity,
        ),
        (
            "scripted:geometry",
            SERIAL,
            12,
            || {
                SCRIPT.with_borrow_mut(|script| {
                    script.facts = Some(NamespaceFacts {
                        sector_size: 4096,
                        sectors: 1 << 18,
                        ..facts()
                    });
                });
            },
            SpdkAttachError::Geometry,
        ),
        (
            "scripted:capture",
            SERIAL,
            9,
            || SCRIPT.with_borrow_mut(|script| script.namespace_data = None),
            SpdkAttachError::Capture,
        ),
        (
            "scripted:qpair",
            SERIAL,
            9,
            || SCRIPT.with_borrow_mut(|script| script.no_qpair = true),
            SpdkAttachError::Qpair,
        ),
    ];
    for (bdf, serial, lbads, adjust, error) in cases {
        SCRIPT.with_borrow_mut(|script| *script = Default::default());
        script(bdf, serial, lbads);
        adjust();
        assert_eq!(configure(bdf, &mut registration).unwrap_err(), error);
        let order = calls();
        assert_eq!(order.last(), Some(&Call::Detach), "{bdf}: {order:?}");
        assert!(!order.contains(&Call::RegisterTimeout), "{bdf}: {order:?}");
        if error != SpdkAttachError::Qpair {
            assert!(!order.contains(&Call::AllocQpair), "{bdf}: {order:?}");
            assert!(!order.contains(&Call::GetFeature), "{bdf}: {order:?}");
        }
        assert!(!attached().contains(bdf), "{bdf}");
        if error == SpdkAttachError::Capture {
            assert!(!order.contains(&Call::NamespaceFacts), "{order:?}");
        }
    }
}

#[test]
fn a_refused_detach_after_a_capture_failure_keeps_the_address_reserved() {
    let bdf = "scripted:capture-detach";
    script(bdf, SERIAL, 9);
    SCRIPT.with_borrow_mut(|script| {
        script.namespace_data = None;
        script.detach.push_back(-libc::ENOMEM);
    });
    let (env, arena) = (Environment::detached(), registration_tests::new_arena());
    let mut registration = registration_tests::ready(&env, &arena);
    assert_eq!(
        configure(bdf, &mut registration).unwrap_err(),
        SpdkAttachError::Capture
    );
    assert!(attached().contains(bdf));
    assert!(!calls().contains(&Call::AllocQpair));
}

fn sys_ctratt() -> spdk_sys::spdk_nvme_cdata_ctratt {
    spdk_sys::spdk_nvme_cdata_ctratt { raw: 1 }
}

#[test]
fn a_controller_without_eds_detaches_before_qpair_or_reservation_commands() {
    let bdf = "scripted:no-eds";
    script(bdf, SERIAL, 9);
    SCRIPT.with_borrow_mut(|s| {
        s.controller.as_mut().unwrap().ctratt = spdk_sys::spdk_nvme_cdata_ctratt { raw: 0 }
    });
    let (env, arena) = (Environment::detached(), registration_tests::new_arena());
    let mut registration = registration_tests::ready(&env, &arena);
    assert_eq!(
        configure(bdf, &mut registration).unwrap_err(),
        SpdkAttachError::ExtendedReportUnsupported
    );
    assert_eq!(calls().last(), Some(&Call::Detach));
    for call in [
        Call::Register,
        Call::Report,
        Call::Acquire,
        Call::AllocQpair,
        Call::GetFeature,
    ] {
        assert!(!calls().contains(&call));
    }
    assert!(!attached().contains(bdf));
}

#[test]
fn attach_refuses_reservation_depth_and_report_transfer_limits_before_allocating_a_qpair() {
    let (env, arena) = (Environment::detached(), registration_tests::new_arena());
    let mut registration = registration_tests::ready(&env, &arena);
    for (name, limits) in [
        (
            "depth",
            crate::storage::ReservationLimits::new(2, 8, 10, 10).unwrap(),
        ),
        (
            "transfer",
            crate::storage::ReservationLimits::new(2048, 2, 10, 10).unwrap(),
        ),
    ] {
        SCRIPT.take();
        let bdf = format!("scripted:attach-reservation-{name}");
        script(&bdf, SERIAL, 9);
        assert_eq!(
            configure_with(&bdf, &mut registration, CONFIG, limits).unwrap_err(),
            SpdkAttachError::ReservationLimits
        );
        assert_eq!(calls().last(), Some(&Call::Detach));
        assert!(!calls().contains(&Call::AllocQpair));
        assert!(!calls().contains(&Call::GetFeature));
        assert!(!attached().contains(&bdf));
    }
}

#[test]
fn configured_reports_count_records_by_the_confirmed_host_id_at_every_controller_id() {
    let bdf = "scripted:configured-exhid-report";
    script(bdf, SERIAL, 9);
    let (env, arena) = (Environment::detached(), registration_tests::new_arena());
    let mut registration = registration_tests::ready(&env, &arena);
    let mut disk = configure(bdf, &mut registration).unwrap();
    let order = calls();
    let at = |call| order.iter().position(|&c| c == call).unwrap();
    assert!(
        at(Call::GetFeature) < at(Call::Admin),
        "the confirmation polls its Get Features"
    );
    // Every row reads controller ID 65535; only the host ID identifies the own record.
    let mut bytes = [0; 192];
    bytes[5] = 2;
    for row in [64, 128] {
        bytes[row..row + 2].copy_from_slice(&0xFFFFu16.to_le_bytes());
        bytes[row + 16..row + 32].fill(7);
    }
    let key = own().key.encode().to_le_bytes();
    bytes[72..80].copy_from_slice(&key);
    bytes[80..96].copy_from_slice(b"persisted-exhid!");
    assert_eq!(disk.check_reservation_report(&bytes), Ok(()));
    bytes[5] = 3;
    assert_eq!(
        disk.check_reservation_report(&bytes),
        Err(crate::storage::ReportError::Inconclusive { regctl: 3 }),
        "a header over the bound with one visible own record"
    );
    bytes[136..144].copy_from_slice(&key);
    bytes[144..160].copy_from_slice(b"persisted-exhid!");
    for regctl in [2, 3] {
        bytes[5] = regctl;
        assert_eq!(
            disk.check_reservation_report(&bytes),
            Err(crate::storage::ReportError::DuplicateOwnHostId { records: 2 }),
            "a visible duplicate refuses with its own cause under REGCTL {regctl}"
        );
    }
    bytes[5] = 0;
    assert_eq!(disk.check_reservation_report(&bytes[..64]), Ok(()));
    assert_eq!(disk.quiesce(), QuiesceStatus::Pending);
    assert_eq!(disk.quiesce(), QuiesceStatus::Stopped);
    registration
        .device_stopped(disk.stop_proof().unwrap())
        .unwrap();
    assert!(disk.detach(&registration_tests::undone(registration)));
}

#[test]
fn duplicate_production_attach_preserves_the_live_pair_before_authentication() {
    use crate::failover::assignment_tests::record;
    let setup = crate::bind::authority_tests::Setup::new();
    let mut mappings = setup.lock.mappings().unwrap();
    let bdf = "0000:ab:1f.0";
    mappings.nvme.as_mut().unwrap().bdf = bdf.into();
    mappings.write(&setup.state.join("mappings")).unwrap();
    let before = std::fs::read(setup.state.join("authority")).unwrap();
    std::fs::remove_file(setup.state.join("host.key")).unwrap();
    assert!(attached().insert(bdf.to_owned()));
    let (env, arena) = (Environment::detached(), registration_tests::new_arena());
    let mut registration = registration_tests::ready(&env, &arena);
    let host = setup.host().clone();
    SCRIPT.take();
    let refused = SpdkDisk::<Scripted>::attach(
        &host,
        &setup.lock,
        &crate::bind::authority_tests::Placement,
        &mut registration,
        CONFIG,
        crate::storage::ReservationLimits::new(3, 2, 10, 20).unwrap(),
    );
    assert!(matches!(refused, Err(SpdkAttachError::AlreadyAttached)));
    assert!(calls().is_empty());
    assert_eq!(
        std::fs::read(setup.state.join("authority")).unwrap(),
        before
    );
    assert_eq!(
        crate::failover::record::LocalRecord::decode(&before).unwrap(),
        record()
    );
    assert!(attached().remove(bdf));
}

#[test]
fn the_running_driver_holds_its_address_s_device_lock_until_detach() {
    let setup = crate::bind::authority_tests::Setup::new();
    let locks = setup.host().under_root(Path::new(DEVICE_LOCKS));
    let bdf = "scripted:writer";
    script(bdf, SERIAL, 9);
    let (env, arena) = (Environment::detached(), registration_tests::new_arena());
    let mut registration = registration_tests::ready(&env, &arena);
    let mut disk = configure(bdf, &mut registration).unwrap();
    disk.hold(DeviceLock::acquire(&locks, bdf).unwrap());
    assert_eq!(
        DeviceLock::acquire(&locks, bdf)
            .map(drop)
            .map_err(|error| error.kind()),
        Err(std::io::ErrorKind::WouldBlock),
        "the running driver holds its address's lock"
    );
    assert_eq!(disk.quiesce(), QuiesceStatus::Pending);
    assert_eq!(disk.quiesce(), QuiesceStatus::Stopped);
    registration
        .device_stopped(disk.stop_proof().unwrap())
        .unwrap();
    assert!(disk.detach(&registration_tests::undone(registration)));
    DeviceLock::acquire(&locks, bdf).expect("detach released the lock");
}

/// The fixture mirrors the kernel's bind-time `driver` symlink of `bdf`.
pub(super) fn bind_driver(host: &crate::bind::Host, bdf: &str, driver: &str) {
    let pci = host.pci(bdf);
    std::fs::create_dir_all(&pci).unwrap();
    let target = host.sys.join("bus/pci/drivers").join(driver);
    std::fs::create_dir_all(&target).unwrap();
    std::os::unix::fs::symlink(target, pci.join("driver")).unwrap();
}

#[test]
fn attach_refuses_a_held_device_lock_before_connecting() {
    let setup = crate::bind::authority_tests::Setup::new();
    let bdf = "0000:ab:1f.1";
    let mut mappings = setup.lock.mappings().unwrap();
    mappings.nvme.as_mut().unwrap().bdf = bdf.into();
    mappings.write(&setup.state.join("mappings")).unwrap();
    let host = setup.host().clone();
    bind_driver(&host, bdf, crate::bind::VFIO);
    let held = DeviceLock::acquire(&host.under_root(Path::new(DEVICE_LOCKS)), bdf).unwrap();
    let (env, arena) = (Environment::detached(), registration_tests::new_arena());
    let mut registration = registration_tests::ready(&env, &arena);
    SCRIPT.take();
    let refused = SpdkDisk::<Scripted>::attach_qualification(
        &host,
        &setup.lock,
        &mut registration,
        CONFIG,
        own(),
        crate::storage::ReservationLimits::new(3, 2, 10, 20).unwrap(),
    );
    let Err(error) = refused else {
        panic!("a held device lock refuses the attach");
    };
    assert_eq!(
        error,
        SpdkAttachError::DeviceLock(std::io::ErrorKind::WouldBlock)
    );
    assert_eq!(
        crate::failover::restart::Driver::of_attach(&error),
        Some(crate::failover::restart::Driver::LiveQueues),
        "a held device lock is the restart's live-queue refusal"
    );
    assert!(!attached().contains(bdf));
    assert!(calls().is_empty(), "no native call");
    drop(held);
}

#[test]
fn attach_restart_refuses_an_attached_address_and_a_record_of_another_volume_before_connecting() {
    use crate::failover::record::{Binding, LocalRecord};
    let setup = crate::bind::authority_tests::Setup::new();
    let bdf = "0000:ab:1f.4";
    let mut mappings = setup.lock.mappings().unwrap();
    mappings.nvme.as_mut().unwrap().bdf = bdf.into();
    mappings.write(&setup.state.join("mappings")).unwrap();
    let host = setup.host().clone();
    let (env, arena) = (Environment::detached(), registration_tests::new_arena());
    let mut registration = registration_tests::ready(&env, &arena);
    let limits = crate::storage::ReservationLimits::new(3, 2, 10, 20).unwrap();
    let sample = crate::failover::assignment_tests::record();
    let rebound = |binding: Binding| {
        let pair = sample.pair();
        LocalRecord::fresh(binding, pair.key, || Some(pair.exhid.bytes())).unwrap()
    };
    for (name, record) in [
        (
            "another volume",
            rebound(Binding {
                volume: "vol-0fffffffffffffff0".into(),
                ..sample.binding().clone()
            }),
        ),
        (
            "another instance",
            rebound(Binding {
                instance: "i-0fffffffffffffff0".into(),
                ..sample.binding().clone()
            }),
        ),
    ] {
        SCRIPT.take();
        let refused = SpdkDisk::<Scripted>::attach_restart(
            &host,
            &setup.lock,
            &mut registration,
            CONFIG,
            record,
            limits,
        );
        assert!(calls().is_empty(), "{name}: no native call");
        assert!(
            matches!(
                refused,
                Err(SpdkAttachError::Authority(
                    crate::failover::admission::AdmissionError::Binding
                ))
            ),
            "{name}"
        );
    }
    assert!(attached().insert(bdf.into()));
    SCRIPT.take();
    let refused = SpdkDisk::<Scripted>::attach_restart(
        &host,
        &setup.lock,
        &mut registration,
        CONFIG,
        sample.clone(),
        limits,
    );
    assert!(attached().remove(bdf));
    assert!(matches!(refused, Err(SpdkAttachError::AlreadyAttached)));
    assert!(calls().is_empty(), "no native call");
}

#[test]
fn attach_refuses_a_kernel_bound_controller_before_locking_or_connecting() {
    for (bdf, driver) in [("0000:ab:1f.2", Some("nvme")), ("0000:ab:1f.3", None)] {
        let setup = crate::bind::authority_tests::Setup::new();
        std::fs::remove_file(setup.state.join("assignment")).unwrap();
        std::fs::remove_file(setup.state.join("host.key")).unwrap();
        let mut mappings = setup.lock.mappings().unwrap();
        mappings.nvme.as_mut().unwrap().bdf = bdf.into();
        mappings.write(&setup.state.join("mappings")).unwrap();
        let host = setup.host().clone();
        std::fs::create_dir_all(host.pci(bdf)).unwrap();
        if let Some(driver) = driver {
            bind_driver(&host, bdf, driver);
        }
        let (env, arena) = (Environment::detached(), registration_tests::new_arena());
        let mut registration = registration_tests::ready(&env, &arena);
        SCRIPT.take();
        let refused = SpdkDisk::<Scripted>::attach_restart(
            &host,
            &setup.lock,
            &mut registration,
            CONFIG,
            crate::failover::assignment_tests::record(),
            crate::storage::ReservationLimits::new(3, 2, 10, 20).unwrap(),
        );
        let Err(error) = refused else {
            panic!("{driver:?}: the binding refuses the attach");
        };
        assert_eq!(error, SpdkAttachError::KernelBinding, "{driver:?}");
        assert_eq!(
            crate::failover::restart::Driver::of_attach(&error),
            Some(crate::failover::restart::Driver::KernelBinding)
        );
        assert!(!attached().contains(bdf));
        assert!(calls().is_empty(), "{driver:?}: no native call");
        drop(DeviceLock::acquire(&host.under_root(Path::new(DEVICE_LOCKS)), bdf).unwrap());
    }
    use crate::failover::restart::Driver;
    for (error, driver) in [
        (SpdkAttachError::AlreadyAttached, Some(Driver::LiveQueues)),
        (
            SpdkAttachError::DeviceLock(std::io::ErrorKind::PermissionDenied),
            None,
        ),
        (SpdkAttachError::Config, None),
    ] {
        assert_eq!(Driver::of_attach(&error), driver, "{error:?}");
    }
}

/// What the teardown after an attach whose configure refused `Capture`
/// showed: whether the registration undid, how many finalizers the
/// environment's finish ran, and whether the address stayed marked attached.
/// With `refuse_detach` the scripted detach of the refused attach fails, so
/// the controller stays attached.
fn teardown_after_a_refused_attach(bdf: &str, refuse_detach: bool) -> (bool, usize, bool) {
    script(bdf, SERIAL, 9);
    SCRIPT.with_borrow_mut(|script| {
        script.namespace_data = None;
        if refuse_detach {
            script.detach.push_back(-libc::ENOMEM);
        }
    });
    let (env, arena) = (Environment::detached(), registration_tests::new_arena());
    let mut registration = registration_tests::ready(&env, &arena);
    assert_eq!(
        configure(bdf, &mut registration).unwrap_err(),
        SpdkAttachError::Capture
    );
    let watchdog = Watchdog::arm(
        Duration::from_secs(60),
        Arc::new(registration_tests::Recorder::new()),
    )
    .unwrap();
    let undone = registration.unregister(&watchdog).is_ok();
    let mut finalized = 0;
    drop(env.finish_with(|| false, |_| finalized += 1));
    (undone, finalized, attached().contains(bdf))
}

/// A refused attach whose controller detached leaves no native user: the
/// registration undoes and the finish runs both finalizers.
#[test]
fn the_environment_finishes_after_a_refused_attach_that_detached() {
    assert_eq!(
        teardown_after_a_refused_attach("scripted:refused-attach-detached", false),
        (true, 2, false)
    );
}

/// The environment's finalizers require that no DPDK memory user is live. A
/// refused attach whose detach SPDK refused leaves the controller attached
/// with no driver to stop it, so the registration it attached through never
/// undoes and the finish runs no finalizer.
#[test]
fn the_environment_runs_no_finalizer_under_a_controller_a_refused_attach_left() {
    assert_eq!(
        teardown_after_a_refused_attach("scripted:refused-attach-kept", true),
        (false, 0, true),
        "the registration undid or the finish finalized under the controller the refused attach left attached"
    );
}
