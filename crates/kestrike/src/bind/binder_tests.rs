//! Bind and release over a fixture host tree and a fake PCI core: every
//! step forced to fail, refused postures and groups, unreadable host state,
//! the owner lock, and release restoring exactly the recorded state.

use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::time::Duration;

use super::binder::{
    BindError, BindRequest, Binder, DeviceState, EniRequest, VfioPosture, held_elsewhere,
    mappings_path, prepare_state_dir, private_state_dir, sole_member,
};
use super::eni::EniError;
use super::fixture::{
    BDF, BOOT, CONFIG, ENI, ENI_BDF, ENI_MAC, ENS6_ADDRESS, FakeKernel, FakeMetadata, Fixture,
    INSTANCE, RELEASE, SRCVERSION, VOLUME, group_of, neighbor_entry,
};
use super::group::{CONTAINER_SET, VIABLE};
use super::host::{Host, Kernel};
use super::identity::{ControllerIdentity, IdentityError};
use super::lock::{DeviceLock, OwnerLock};
use super::mappings::{MAPPINGS_BYTES, Mappings, MappingsError};
use super::record_step::{RecordStep, SCRIPT, Script};
use super::wc::WcError;

pub(super) const ALLOWLISTED: VfioPosture = VfioPosture {
    allow_no_iommu: true,
};

pub(super) fn new_binder(fixture: &Fixture) -> Binder<FakeKernel> {
    Binder {
        host: fixture.host.clone(),
        kernel: FakeKernel::new(&fixture.host),
        state_dir: fixture.state_dir(),
    }
}

/// Binds `volume` alone under the fixture's approved write-combining module.
fn bind_volume(
    binder: &Binder<FakeKernel>,
    volume: &str,
    posture: VfioPosture,
) -> Result<Mappings, BindError> {
    let manifest = Fixture::manifest_of(&binder.host);
    let request = BindRequest {
        volume: Some(volume),
        eni: None,
        posture,
        wc: &manifest,
        others: &[],
    };
    binder.bind(&request)
}

/// A bind takes the device's driver, IDs and IOMMU group, the host's IOMMU
/// class and the instance and boot it stamps its record with from sysfs and
/// procfs. Each is the kernel's own only where no mount covers it: under a
/// mount the driver link can name a driver the device is not bound to, and
/// a write to the driver's files reaches the mount. A bind under a mount
/// over one of them refuses before any driver write. The same bind under
/// the mounts a stock distribution lists goes through.
#[test]
fn a_bind_reads_no_device_or_host_entry_under_a_mount() {
    const STOCK: &str = "/dev/nvme0n1p1 / xfs rw 0 0\n\
        proc /proc proc rw 0 0\n\
        sysfs /sys sysfs rw 0 0\n\
        cgroup2 /sys/fs/cgroup cgroup2 rw 0 0\n\
        binfmt_misc /proc/sys/fs/binfmt_misc binfmt_misc rw 0 0\n\
        debugfs /sys/kernel/debug debugfs rw 0 0\n\
        configfs /sys/kernel/config configfs rw 0 0\n";
    let bound = |cover: Option<&str>| {
        let fixture = Fixture::new(4096);
        let tail = cover.map_or(String::new(), |at| format!("tmpfs {at} tmpfs rw 0 0\n"));
        fixture.file("proc/self/mounts", &format!("{STOCK}{tail}"));
        let binder = new_binder(&fixture);
        let bound = bind_volume(&binder, VOLUME, ALLOWLISTED).map(drop);
        (bound.is_ok(), untouched(&binder))
    };
    assert_eq!(bound(None), (true, false), "premise: a stock table");
    // A link is read in its directory, so the mount that covers the
    // function's driver or IOMMU group link is one over the function.
    let function = format!("/sys/bus/pci/devices/{BDF}");
    let entries = ["driver_override", "vendor"];
    let covers = entries
        .iter()
        .map(|entry| format!("{function}/{entry}"))
        .chain(
            [
                function.as_str(),
                "/sys/class/nvme",
                "/sys/class/nvme/nvme1/serial",
                "/sys/class/iommu",
                "/sys/bus/pci/drivers/vfio-pci",
                "/sys/devices/virtual/dmi/id/board_asset_tag",
                "/proc/sys/kernel/random/boot_id",
            ]
            .map(str::to_owned),
        );
    let mut read = Vec::new();
    for cover in covers {
        if bound(Some(&cover)) != (false, true) {
            read.push(cover);
        }
    }
    assert_eq!(read, [] as [String; 0], "entries a bind read under a mount");
}

pub(super) fn observed(fixture: &Fixture, bdf: &str) -> (Option<String>, Option<String>) {
    (
        fixture.host.driver(bdf),
        fixture.host.driver_override(bdf).flatten(),
    )
}

pub(super) fn untouched(binder: &Binder<FakeKernel>) -> bool {
    binder.kernel.writes.borrow().is_empty()
}

#[test]
fn bind_moves_only_the_volume_s_controller_and_records_it() {
    let fixture = Fixture::new(4096);
    // An unrelated, unbound device with the full EBS PCI identity is never touched.
    fixture.file("sys/bus/pci/devices/0000:00:1d.0/vendor", "0x1d0f\n");
    fixture.file("sys/bus/pci/devices/0000:00:1d.0/device", "0x8061\n");
    fixture.file(
        "sys/bus/pci/devices/0000:00:1d.0/driver_override",
        "(null)\n",
    );
    let binder = new_binder(&fixture);
    let mappings = bind_volume(&binder, "vol0123456789abcdef0", ALLOWLISTED).unwrap();
    assert_eq!(
        observed(&fixture, BDF),
        (Some("vfio-pci".into()), Some("vfio-pci".into()))
    );
    assert_eq!(
        observed(&fixture, "0000:00:04.0"),
        (Some("nvme".into()), None),
        "the boot volume stays on nvme"
    );
    assert_eq!(observed(&fixture, "0000:00:1d.0"), (None, None));
    assert!(
        binder
            .kernel
            .writes
            .borrow()
            .iter()
            .all(|(path, value)| path.contains(BDF) || value == BDF)
    );
    assert!(
        !binder
            .kernel
            .writes
            .borrow()
            .iter()
            .any(|(path, _)| path.ends_with("new_id"))
    );
    assert_eq!(
        (mappings.instance.as_str(), mappings.boot.as_str()),
        (INSTANCE, BOOT)
    );
    assert_eq!(
        (
            mappings.nvme.as_ref().unwrap().volume.as_str(),
            mappings.nvme.as_ref().unwrap().bdf.as_str(),
            mappings.nvme.as_ref().unwrap().nsid
        ),
        (VOLUME, BDF, 1)
    );
    assert_eq!(
        (
            mappings.nvme.as_ref().unwrap().sector_size,
            mappings.nvme.as_ref().unwrap().capacity
        ),
        (4096, 64 << 30)
    );
    assert_eq!(
        (
            mappings.nvme.as_ref().unwrap().original_driver.as_str(),
            mappings.nvme.as_ref().unwrap().original_override.as_deref()
        ),
        ("nvme", None)
    );
    assert_eq!(
        Mappings::read(&mappings_path(&fixture.state_dir())).unwrap(),
        mappings
    );
    // A second bind refuses while the first is recorded.
    assert!(matches!(
        bind_volume(&binder, VOLUME, ALLOWLISTED),
        Err(BindError::AlreadyBound)
    ));
}

#[test]
fn an_iommu_host_binds_without_the_allowlist() {
    let fixture = Fixture::new(4096);
    fs::create_dir(fixture.host.sys.join("class/iommu/dmar0")).unwrap();
    fixture.file(
        "sys/module/vfio/parameters/enable_unsafe_noiommu_mode",
        "N\n",
    );
    bind_volume(
        &new_binder(&fixture),
        VOLUME,
        VfioPosture {
            allow_no_iommu: false,
        },
    )
    .unwrap();
    assert_eq!(observed(&fixture, BDF).0.as_deref(), Some("vfio-pci"));
}

#[test]
fn every_failed_bind_step_restores_the_kernel_driver_and_reports_the_state() {
    for step in ["driver_override", "nvme/unbind", "vfio-pci/bind"] {
        let fixture = Fixture::new(4096);
        let binder = new_binder(&fixture);
        binder.kernel.fail.replace(Some(step));
        let Err(BindError::Step {
            state:
                DeviceState {
                    driver,
                    driver_override,
                    ..
                },
            ..
        }) = bind_volume(&binder, VOLUME, ALLOWLISTED)
        else {
            panic!("{step} must fail the bind");
        };
        assert_eq!(
            (driver.as_deref(), driver_override),
            (Some("nvme"), None),
            "{step}"
        );
        assert!(
            !mappings_path(&fixture.state_dir()).exists(),
            "{step} leaves no record once restored"
        );
    }
    // A bind the kernel accepted without acting on fails verification and restores.
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    binder.kernel.ignore.replace(Some("vfio-pci/bind"));
    assert!(matches!(
        bind_volume(&binder, VOLUME, ALLOWLISTED),
        Err(BindError::Step { step: "bind", .. })
    ));
    assert_eq!(observed(&fixture, BDF), (Some("nvme".into()), None));
    // A record that cannot be written stops the bind before any driver write.
    let fixture = Fixture::new(4096);
    fs::create_dir_all(fixture.state_dir().join("mappings.tmp/blocker")).unwrap();
    let binder = new_binder(&fixture);
    assert!(matches!(
        bind_volume(&binder, VOLUME, ALLOWLISTED),
        Err(BindError::Step {
            step: "mappings",
            ..
        })
    ));
    assert!(untouched(&binder));
}

#[test]
fn a_refusal_by_the_second_check_makes_no_driver_write() {
    let fixture = Fixture::new(4096);
    // Writing the record first removes `mappings.tmp`, so a swap table
    // linked there reads for the first check and is gone for the second.
    let staged = fixture.state_dir().join("mappings.tmp");
    fs::copy(fixture.host.proc.join("swaps"), &staged).unwrap();
    fs::remove_file(fixture.host.proc.join("swaps")).unwrap();
    symlink(&staged, fixture.host.proc.join("swaps")).unwrap();
    let binder = new_binder(&fixture);
    let refused = bind_volume(&binder, VOLUME, ALLOWLISTED);
    assert!(
        matches!(
            refused,
            Err(BindError::Identity(IdentityError::Unverifiable("swaps")))
        ),
        "{refused:?}"
    );
    assert!(untouched(&binder), "{:?}", binder.kernel.writes.borrow());
    assert_eq!(observed(&fixture, BDF), (Some("nvme".into()), None));
    assert!(!mappings_path(&fixture.state_dir()).exists());
}

#[test]
fn an_original_override_naming_another_driver_is_restored_with_the_kernel_driver() {
    // The kernel leaves a device on its driver when its override later names another.
    let original = || {
        let fixture = Fixture::new(4096);
        fixture.file(
            &format!("sys/bus/pci/devices/{BDF}/driver_override"),
            "vfio-pci\n",
        );
        fixture
    };
    let fixture = original();
    let binder = new_binder(&fixture);
    let mappings = bind_volume(&binder, VOLUME, ALLOWLISTED).unwrap();
    assert_eq!(
        mappings.nvme.as_ref().unwrap().original_override.as_deref(),
        Some("vfio-pci")
    );
    binder.release(&[]).unwrap();
    assert_eq!(
        observed(&fixture, BDF),
        (Some("nvme".into()), Some("vfio-pci".into()))
    );
    let fixture = original();
    let binder = new_binder(&fixture);
    binder.kernel.fail.replace(Some("vfio-pci/bind"));
    let failed = bind_volume(&binder, VOLUME, ALLOWLISTED);
    assert!(
        matches!(failed, Err(BindError::Step { step: "bind", .. })),
        "{failed:?}"
    );
    assert_eq!(
        observed(&fixture, BDF),
        (Some("nvme".into()), Some("vfio-pci".into()))
    );
    assert!(!mappings_path(&fixture.state_dir()).exists());
}

#[test]
fn a_bind_that_dies_midway_leaves_a_record_release_restores() {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    // A restore the kernel ignores keeps the record, as a bind killed after its unbind would.
    binder.kernel.fail.replace(Some("vfio-pci/bind"));
    binder.kernel.ignore.replace(Some("nvme/bind"));
    let Err(BindError::Unrestored(both)) = bind_volume(&binder, VOLUME, ALLOWLISTED) else {
        panic!("a bind whose restore fails reports both errors");
    };
    assert!(matches!(both.0, BindError::Step { step: "bind", .. }));
    assert!(matches!(
        both.1,
        BindError::Step {
            step: "restore",
            ..
        }
    ));
    assert_eq!(observed(&fixture, BDF), (None, None));
    assert!(mappings_path(&fixture.state_dir()).exists());
    binder.kernel.ignore.replace(None);
    binder.release(&[]).unwrap();
    assert_eq!(observed(&fixture, BDF), (Some("nvme".into()), None));
}

#[test]
fn contradictory_postures_groups_used_devices_and_unreadable_state_refuse_before_any_write() {
    type Case = (fn(&Fixture), VfioPosture);
    let postures: [Case; 5] = [
        (
            |_| {},
            VfioPosture {
                allow_no_iommu: false,
            },
        ),
        (
            // An unreadable no-IOMMU parameter establishes neither posture:
            // a guest IOMMU is visible, and the parameter's value is unknown.
            |f| {
                fs::create_dir(f.host.sys.join("class/iommu/dmar0")).unwrap();
                let parameter = f
                    .host
                    .sys
                    .join("module/vfio/parameters/enable_unsafe_noiommu_mode");
                fs::remove_file(&parameter).unwrap();
                fs::create_dir(&parameter).unwrap();
            },
            VfioPosture {
                allow_no_iommu: false,
            },
        ),
        (
            |f| fs::remove_dir(f.host.sys.join("bus/pci/drivers/vfio-pci")).unwrap(),
            ALLOWLISTED,
        ),
        (
            |f| fs::create_dir(f.host.sys.join("class/iommu/dmar0")).unwrap(),
            ALLOWLISTED,
        ),
        (
            |f| {
                f.file(
                    "sys/module/vfio/parameters/enable_unsafe_noiommu_mode",
                    "N\n",
                )
            },
            ALLOWLISTED,
        ),
    ];
    for (edit, posture) in postures {
        let fixture = Fixture::new(4096);
        edit(&fixture);
        let binder = new_binder(&fixture);
        assert!(matches!(
            bind_volume(&binder, VOLUME, posture),
            Err(BindError::Posture)
        ));
        assert!(untouched(&binder));
    }
    // An unreadable IOMMU class establishes neither posture nor the VFIO
    // backend the kernel configuration must build, and the kernel check
    // refuses first.
    let fixture = Fixture::new(4096);
    let class = fixture.host.sys.join("class/iommu");
    fs::remove_dir(&class).unwrap();
    fs::write(&class, "").unwrap();
    let binder = new_binder(&fixture);
    assert!(matches!(
        bind_volume(&binder, VOLUME, ALLOWLISTED),
        Err(BindError::Wc(WcError::Interface("iommu")))
    ));
    assert!(untouched(&binder));
    let groups: [fn(&Fixture); 2] = [
        |f| fs::write(f.host.pci(BDF).join("iommu_group/devices/0000:00:1e.0"), "").unwrap(),
        |f| {
            fs::remove_dir_all(f.host.pci(BDF).join("iommu_group")).unwrap();
            fs::create_dir(f.host.sys.join("class/iommu/dmar0")).unwrap();
            f.file(
                "sys/module/vfio/parameters/enable_unsafe_noiommu_mode",
                "N\n",
            );
        },
    ];
    for edit in groups {
        let fixture = Fixture::new(4096);
        edit(&fixture);
        let binder = new_binder(&fixture);
        assert!(matches!(
            bind_volume(&binder, VOLUME, ALLOWLISTED),
            Err(BindError::Group)
        ));
        assert!(untouched(&binder));
    }
    type Refusal = (fn(&Fixture), fn(&BindError) -> bool);
    let refusals: [Refusal; 7] = [
        (
            |f| f.file("sys/class/block/nvme1n1/dev", "259:99\n"),
            |e| matches!(e, BindError::Identity(IdentityError::Substituted(n)) if n == "nvme1n1"),
        ),
        (
            |f| f.file("proc/self/mounts", "/dev/nvme1n1 /data xfs rw 0 0\n"),
            |e| matches!(e, BindError::Identity(IdentityError::InUse(_))),
        ),
        (
            // Held only in a thread's own table, beside a leader table of equal size.
            |f| {
                f.open(70, &f.host.dev.join("other0"));
                f.open_on_thread(70, 71, &f.host.dev.join("nvme1n1"));
            },
            |e| matches!(e, BindError::Identity(IdentityError::InUse(_))),
        ),
        (
            // Without a mount table the kernel's release is no evidence,
            // and the write-combining check outranks the in-use check.
            |f| fs::remove_file(f.host.proc.join("self/mounts")).unwrap(),
            |e| matches!(e, BindError::Wc(WcError::Kernel)),
        ),
        (
            |f| fs::remove_file(f.host.proc.join("swaps")).unwrap(),
            |e| matches!(e, BindError::Identity(IdentityError::Unverifiable("swaps"))),
        ),
        (
            |f| fs::remove_file(f.host.proc.join("sys/kernel/random/boot_id")).unwrap(),
            |e| matches!(e, BindError::Host),
        ),
        (
            |f| fs::remove_file(f.host.pci(BDF).join("driver")).unwrap(),
            |e| matches!(e, BindError::Changed),
        ),
    ];
    for (edit, expected) in refusals {
        let fixture = Fixture::new(4096);
        edit(&fixture);
        let binder = new_binder(&fixture);
        let refused = bind_volume(&binder, VOLUME, ALLOWLISTED).unwrap_err();
        assert!(expected(&refused), "{refused:?}");
        assert!(untouched(&binder));
    }
    let fixture = Fixture::new(4096);
    fs::remove_file(fixture.host.proc.join("self/mounts")).unwrap();
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("mounts")),
        "the in-use check without a mount table"
    );
}

#[test]
fn the_root_volume_s_id_is_refused_by_its_mounted_partition() {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    assert!(matches!(
        bind_volume(&binder, "vol-0aaaaaaaaaaaaaaaaa", ALLOWLISTED),
        Err(BindError::Identity(IdentityError::InUse(device))) if device == "nvme0n1p1"
    ));
    assert!(untouched(&binder));
}

#[test]
fn the_owner_lock_serializes_bind_release_and_the_owner() {
    let fixture = Fixture::new(4096);
    let owner = OwnerLock::acquire(&fixture.state_dir()).unwrap();
    let binder = new_binder(&fixture);
    let locked = |result: Result<(), BindError>| matches!(result, Err(BindError::Lock(e)) if e.kind() == std::io::ErrorKind::WouldBlock);
    assert!(locked(bind_volume(&binder, VOLUME, ALLOWLISTED).map(drop)));
    drop(owner);
    bind_volume(&binder, VOLUME, ALLOWLISTED).unwrap();
    let owner = OwnerLock::acquire(&fixture.state_dir()).unwrap();
    assert!(
        locked(binder.release(&[])),
        "release waits for the application to stop"
    );
    drop(owner);
}

#[test]
fn release_restores_exactly_the_recorded_driver_and_override() {
    let fixture = Fixture::new(4096);
    fixture.file(
        &format!("sys/bus/pci/devices/{BDF}/driver_override"),
        "nvme\n",
    );
    let binder = new_binder(&fixture);
    let mappings = bind_volume(&binder, VOLUME, ALLOWLISTED).unwrap();
    assert_eq!(
        mappings.nvme.as_ref().unwrap().original_override.as_deref(),
        Some("nvme")
    );
    binder.kernel.fail.replace(Some("nvme/bind"));
    let Err(BindError::Step { state, .. }) = binder.release(&[]) else {
        panic!("a failed release step must report")
    };
    assert_eq!(
        (state.driver, state.driver_override.as_deref()),
        (None, Some("nvme")),
        "the actual state after the failure"
    );
    binder.kernel.group_opens.borrow_mut().clear();
    binder.release(&[]).unwrap();
    assert!(
        binder.kernel.group_opens.borrow().is_empty(),
        "an unbound device has no group to guard"
    );
    assert_eq!(
        observed(&fixture, BDF),
        (Some("nvme".into()), Some("nvme".into()))
    );
    assert!(!mappings_path(&fixture.state_dir()).exists());
    assert!(
        matches!(
            binder.release(&[]),
            Err(BindError::Mappings(MappingsError::Io(_)))
        ),
        "nothing left to release"
    );
}

#[test]
fn release_refuses_a_stale_record_or_a_device_it_did_not_bind() {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    bind_volume(&binder, VOLUME, ALLOWLISTED).unwrap();
    fixture.file("proc/sys/kernel/random/boot_id", "another-boot\n");
    assert!(matches!(
        binder.release(&[]),
        Err(BindError::Mappings(MappingsError::Boot))
    ));
    fixture.file("proc/sys/kernel/random/boot_id", &format!("{BOOT}\n"));
    // The recorded address now holds another device on another driver.
    fixture.file(&format!("sys/bus/pci/devices/{BDF}/device"), "0xec20\n");
    let writes = binder.kernel.writes.borrow().len();
    assert!(matches!(
        binder.release(&[]),
        Err(BindError::NotRecorded(_))
    ));
    assert_eq!(binder.kernel.writes.borrow().len(), writes);
    fixture.file(&format!("sys/bus/pci/devices/{BDF}/device"), "0x8061\n");
    let mut stale = Mappings::read(&mappings_path(&fixture.state_dir())).unwrap();
    stale.instance = "i-0fffffffffffffff0".into();
    fs::remove_file(mappings_path(&fixture.state_dir())).unwrap();
    stale.write(&mappings_path(&fixture.state_dir())).unwrap();
    assert!(matches!(
        binder.release(&[]),
        Err(BindError::Mappings(MappingsError::Instance))
    ));
}

pub(super) const PEERS: [Ipv4Addr; 2] = [Ipv4Addr::new(10, 0, 1, 9), Ipv4Addr::new(10, 0, 2, 7)];
pub(super) const SECONDARY_BDF: &str = "0000:00:07.0";

/// Binds the fixture's ENI, with the volume when `volume` is set.
pub(super) fn bind_eni(
    binder: &Binder<FakeKernel>,
    volume: Option<&str>,
    metadata: &FakeMetadata,
) -> Result<Mappings, BindError> {
    let manifest = Fixture::manifest_of(&binder.host);
    let request = BindRequest {
        volume,
        eni: Some(EniRequest {
            id: ENI,
            peers: &PEERS,
            metadata,
        }),
        posture: ALLOWLISTED,
        wc: &manifest,
        others: &[],
    };
    binder.bind(&request)
}

/// A fixture with a second, unrelated dataplane ENI, which no bind may touch.
pub(super) fn with_secondary() -> (Fixture, FakeMetadata) {
    let fixture = Fixture::new(4096);
    fixture.netdev("ens7", SECONDARY_BDF, "0a:77:77:77:77:77", 0x1003);
    let metadata = FakeMetadata::new();
    let base = "network/interfaces/macs/";
    let mut paths = metadata.0.lock().unwrap();
    let listing = paths.get(base).unwrap().clone();
    paths.insert(base.into(), format!("{listing}0a:77:77:77:77:77/\n"));
    for (field, value) in [
        ("interface-id", "eni-0bbbbbbbbbbbbbbbb"),
        ("device-number", "2"),
        ("network-card", "0"),
        ("local-ipv4s", "10.0.1.7"),
        ("subnet-id", "subnet-0123"),
        ("subnet-ipv4-cidr-block", "10.0.1.0/24"),
    ] {
        paths.insert(format!("{base}0a:77:77:77:77:77/{field}"), value.into());
    }
    drop(paths);
    (fixture, metadata)
}

/// An owner binds its controller and its ENI, a client its ENI alone: each writes only its own devices' files and binds only their addresses, records the ENI's identity, network state, next hops and the checked modules, and leaves the primary and an unrelated ENI on `ena`.
#[test]
fn owner_and_client_bind_the_eni_and_record_it() {
    for volume in [Some(VOLUME), None] {
        let (fixture, metadata) = with_secondary();
        let binder = new_binder(&fixture);
        let mappings = bind_eni(&binder, volume, &metadata).unwrap();
        assert_eq!(
            Mappings::read(&mappings_path(&fixture.state_dir())).unwrap(),
            mappings
        );
        let binding = mappings.eni.as_ref().unwrap();
        let eni = &binding.eni;
        assert_eq!(
            (eni.id.as_str(), eni.bdf.as_str(), eni.netdev.as_str()),
            (ENI, ENI_BDF, "ens6")
        );
        assert_eq!(
            (
                binding.original_driver.as_str(),
                binding.original_override.as_deref()
            ),
            ("ena", None)
        );
        assert_eq!(
            binding.net.addresses,
            ["10.0.1.5/24 brd 10.0.1.255 metric 1003"]
        );
        assert_eq!(
            binding.next_hops,
            [
                (PEERS[0], [0x0a, 0, 0, 0, 1, 9]),
                (PEERS[1], [0x0a, 0, 0, 0, 1, 1])
            ]
        );
        assert_eq!(mappings.wc.modules[0].srcversion, SRCVERSION);
        assert_eq!(mappings.nvme.is_some(), volume.is_some());
        assert_eq!(
            observed(&fixture, ENI_BDF),
            (Some("vfio-pci".into()), Some("vfio-pci".into()))
        );
        let nvme_driver = if volume.is_some() { "vfio-pci" } else { "nvme" };
        assert_eq!(observed(&fixture, BDF).0.as_deref(), Some(nvme_driver));
        for untouched_eni in ["0000:00:05.0", SECONDARY_BDF] {
            assert_eq!(
                observed(&fixture, untouched_eni),
                (Some("ena".into()), None)
            );
        }
        for (path, value) in binder.kernel.writes.borrow().iter() {
            let names_in_value = path.ends_with("vfio-pci/bind")
                || path.ends_with("nvme/unbind")
                || path.ends_with("ena/unbind");
            assert!(
                path.contains(ENI_BDF) || path.contains(BDF) || names_in_value,
                "{path}"
            );
            if names_in_value {
                assert!(
                    value == ENI_BDF || value == BDF,
                    "binds and unbinds only its own devices: {value}"
                );
            }
        }
    }
}

/// Requests without a device or an ENI without peers, unapproved modules,
/// a refused ENI identity and an unresolved next hop all refuse before any
/// driver write and leave no record; the controller stays on `nvme`.
#[test]
fn refusals_before_the_record_touch_nothing() {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    stale_gateway(&fixture);
    let manifest = Fixture::manifest_of(&fixture.host);
    let metadata = FakeMetadata::new();
    let eni = |peers: &'static [Ipv4Addr]| EniRequest {
        id: ENI,
        peers,
        metadata: &metadata,
    };
    let request = |volume, eni| BindRequest {
        volume,
        eni,
        posture: ALLOWLISTED,
        wc: &manifest,
        others: &[],
    };
    for refused in [request(None, None), request(None, Some(eni(&[])))] {
        assert!(matches!(binder.bind(&refused), Err(BindError::Request)));
    }
    let crowded: Vec<Ipv4Addr> = (0..=u16::MAX as u32)
        .map(|at| Ipv4Addr::from(0x0a00_0000 + at))
        .collect();
    let refused = BindRequest {
        volume: None,
        eni: Some(EniRequest {
            id: ENI,
            peers: &crowded,
            metadata: &metadata,
        }),
        posture: ALLOWLISTED,
        wc: &manifest,
        others: &[],
    };
    assert!(
        matches!(binder.bind(&refused), Err(BindError::Request)),
        "a peer list of {} is one more than the key ring counts",
        crowded.len()
    );
    let mut unapproved = manifest.clone();
    unapproved.modules[0].sha256 = "00".repeat(32);
    let refused = BindRequest {
        wc: &unapproved,
        others: &[],
        ..request(Some(VOLUME), Some(eni(&PEERS)))
    };
    assert!(matches!(
        binder.bind(&refused),
        Err(BindError::Wc(WcError::Module(_)))
    ));
    let primary = FakeMetadata::new();
    primary.0.lock().unwrap().insert(
        "network/interfaces/macs/0a:11:22:33:44:55/device-number".into(),
        "0".into(),
    );
    assert!(matches!(
        bind_eni(&binder, Some(VOLUME), &primary),
        Err(BindError::Eni(EniError::Primary))
    ));
    assert!(
        neighbors_untouched(&binder),
        "refusals before the next hops change no neighbor entry"
    );
    fs::write(
        fixture.root.join("neigh/ens6"),
        neighbor_entry("10.0.1.9", Some("0a:00:00:00:01:09"), "REACHABLE"),
    )
    .unwrap();
    assert!(matches!(
        bind_eni(&binder, Some(VOLUME), &metadata),
        Err(BindError::Eni(EniError::NextHop(_)))
    ));
    assert!(untouched(&binder));
    assert!(!mappings_path(&fixture.state_dir()).exists());
    assert_eq!(observed(&fixture, BDF).0.as_deref(), Some("nvme"));
    assert_eq!(observed(&fixture, ENI_BDF).0.as_deref(), Some("ena"));
}

/// Every ENI step forced to fail, for an owner and a client, and a bind the
/// kernel accepts without acting on, restores each moved device to its
/// recorded driver and override and removes the record; a device that
/// changed between the checks, or a module reloaded between them, also
/// refuses with nothing left moved.
#[test]
fn every_failed_eni_step_restores_the_moved_devices() {
    let cases: [(Option<&str>, Option<&'static str>, Option<&'static str>); 6] = [
        (Some(VOLUME), Some("0000:00:06.0/driver_override"), None),
        (Some(VOLUME), Some("ena/unbind=0000:00:06.0"), None),
        (None, Some("0000:00:06.0/driver_override"), None),
        (None, Some("ena/unbind=0000:00:06.0"), None),
        (None, Some("vfio-pci/bind"), None),
        (None, None, Some("vfio-pci/bind")),
    ];
    for (volume, fail, ignore) in cases {
        let fixture = Fixture::new(4096);
        let binder = new_binder(&fixture);
        binder.kernel.fail.replace(fail);
        binder.kernel.ignore.replace(ignore);
        let Err(BindError::Step { state, .. }) = bind_eni(&binder, volume, &FakeMetadata::new())
        else {
            panic!("{fail:?} {ignore:?} must fail the bind");
        };
        assert_eq!(state.bdf, ENI_BDF, "{fail:?}");
        assert_eq!(observed(&fixture, BDF), (Some("nvme".into()), None));
        assert_eq!(observed(&fixture, ENI_BDF), (Some("ena".into()), None));
        assert!(!mappings_path(&fixture.state_dir()).exists(), "{fail:?}");
    }
    // The ENI's metadata changes between the two checks.
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    let metadata = FakeMetadata::new();
    let manifest = Fixture::manifest_of(&fixture.host);
    struct Shifting<'m>(&'m FakeMetadata, std::sync::atomic::AtomicU32);
    impl super::metadata::Metadata for Shifting<'_> {
        fn get(&self, path: &str) -> std::io::Result<String> {
            let order = std::sync::atomic::Ordering::Relaxed;
            if path.ends_with("subnet-id") && self.1.fetch_add(1, order) > 0 {
                return Ok("subnet-0999".into());
            }
            self.0.get(path)
        }
    }
    let shifting = Shifting(&metadata, std::sync::atomic::AtomicU32::new(0));
    let request = BindRequest {
        volume: Some(VOLUME),
        eni: Some(EniRequest {
            id: ENI,
            peers: &PEERS,
            metadata: &shifting,
        }),
        posture: ALLOWLISTED,
        wc: &manifest,
        others: &[],
    };
    assert!(
        matches!(binder.bind(&request), Err(BindError::Changed)),
        "a changed ENI refuses"
    );
    assert_eq!(
        observed(&fixture, BDF),
        (Some("nvme".into()), None),
        "the moved controller is restored"
    );
    assert_eq!(observed(&fixture, ENI_BDF), (Some("ena".into()), None));
    assert!(!mappings_path(&fixture.state_dir()).exists());
    // A module reloaded between the checks refuses the move.
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    let reloading = FakeMetadata::new();
    let root = fixture.root.clone();
    struct Reload<'m>(&'m FakeMetadata, std::path::PathBuf);
    impl super::metadata::Metadata for Reload<'_> {
        fn get(&self, path: &str) -> std::io::Result<String> {
            if path.ends_with("subnet-ipv4-cidr-block") {
                fs::write(self.1.join("sys/module/vfio_pci/srcversion"), "RELOADED\n").unwrap();
            }
            self.0.get(path)
        }
    }
    let reload = Reload(&reloading, root);
    let manifest = Fixture::manifest_of(&fixture.host);
    let request = BindRequest {
        volume: None,
        eni: Some(EniRequest {
            id: ENI,
            peers: &PEERS,
            metadata: &reload,
        }),
        posture: ALLOWLISTED,
        wc: &manifest,
        others: &[],
    };
    assert!(matches!(
        binder.bind(&request),
        Err(BindError::Wc(WcError::Loaded(_)))
    ));
    assert_eq!(observed(&fixture, ENI_BDF), (Some("ena".into()), None));
}

/// A bind that dies after the ENI's unbind leaves a record release restores, network state included.
#[test]
fn an_eni_bind_that_dies_midway_leaves_a_record_release_restores() {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    binder.kernel.fail.replace(Some("vfio-pci/bind"));
    binder.kernel.ignore.replace(Some("ena/bind"));
    assert!(matches!(
        bind_eni(&binder, None, &FakeMetadata::new()),
        Err(BindError::Unrestored(_))
    ));
    assert_eq!(observed(&fixture, ENI_BDF), (None, None));
    assert!(mappings_path(&fixture.state_dir()).exists());
    binder.kernel.ignore.replace(None);
    binder.release(&[]).unwrap();
    assert_eq!(observed(&fixture, ENI_BDF), (Some("ena".into()), None));
    assert!(!mappings_path(&fixture.state_dir()).exists());
}

/// Release refuses while the ENI's VFIO group file does not open, then returns the
/// ENI to `ena` with its recorded override, finds its device again by MAC,
/// and restores its link, addresses and routes; it refuses an address whose
/// PCI identity is no longer an ENA's, and keeps the record when the ENI's
/// device never returns.
#[test]
fn release_restores_the_eni_and_its_network_state() {
    let fixture = Fixture::new(4096);
    fixture.file(
        &format!("sys/bus/pci/devices/{ENI_BDF}/driver_override"),
        "ena\n",
    );
    let binder = new_binder(&fixture);
    let mappings = bind_eni(&binder, Some(VOLUME), &FakeMetadata::new()).unwrap();
    assert_eq!(
        mappings.eni.unwrap().original_override.as_deref(),
        Some("ena")
    );
    let (writes, runs) = (
        binder.kernel.writes.borrow().len(),
        binder.kernel.runs.borrow().len(),
    );
    let group_file = fixture
        .host
        .dev
        .join(format!("vfio/noiommu-{}", group_of(ENI_BDF)));
    fixture.hold(&group_file);
    assert!(matches!(binder.release(&[]), Err(BindError::VfioInUse)));
    assert_eq!(binder.kernel.writes.borrow().len(), writes);
    assert_eq!(binder.kernel.runs.borrow().len(), runs);
    fixture.unhold(&group_file);
    fixture.file(&format!("sys/bus/pci/devices/{ENI_BDF}/device"), "0x8061\n");
    assert!(matches!(
        binder.release(&[]),
        Err(BindError::NotRecorded(_))
    ));
    fixture.file(&format!("sys/bus/pci/devices/{ENI_BDF}/device"), "0xec21\n");
    binder.kernel.runs.borrow_mut().clear();
    binder.release(&[]).unwrap();
    assert_eq!(
        observed(&fixture, ENI_BDF),
        (Some("ena".into()), Some("ena".into()))
    );
    assert_eq!(observed(&fixture, BDF), (Some("nvme".into()), None));
    assert_eq!(
        *binder.kernel.runs.borrow(),
        [
            "ip -o link show",
            "ip link set dev if6 mtu 9001",
            "ip link set dev if6 up",
            "ip addr replace 10.0.1.5/24 brd 10.0.1.255 metric 1003 dev if6",
            "ip route replace 10.0.1.0/24 proto kernel scope link src 10.0.1.5 metric 1003 dev if6",
        ]
    );
    assert!(!mappings_path(&fixture.state_dir()).exists());

    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    bind_eni(&binder, None, &FakeMetadata::new()).unwrap();
    assert!(matches!(
        bind_eni(&binder, None, &FakeMetadata::new()),
        Err(BindError::AlreadyBound)
    ));
    fs::remove_dir_all(fixture.root.join("sys/class/net/ens6")).unwrap();
    binder.kernel.runs.borrow_mut().clear();
    assert!(matches!(binder.release(&[]), Err(BindError::Network(_))));
    assert!(
        binder.kernel.runs.borrow().is_empty(),
        "no network change without the device"
    );
    assert!(mappings_path(&fixture.state_dir()).exists());
}

/// A client binds its ENI while another state directory's controller already sits on `vfio-pci`, with no module loaded or unloaded.
#[test]
fn a_client_binds_beside_a_bound_controller() {
    let fixture = Fixture::new(4096);
    bind_volume(&new_binder(&fixture), VOLUME, ALLOWLISTED).unwrap();
    let client = Binder {
        state_dir: fixture.root.join("client"),
        ..new_binder(&fixture)
    };
    fs::create_dir_all(&client.state_dir).unwrap();
    bind_eni(&client, None, &FakeMetadata::new()).unwrap();
    assert_eq!(observed(&fixture, BDF).0.as_deref(), Some("vfio-pci"));
    assert_eq!(observed(&fixture, ENI_BDF).0.as_deref(), Some("vfio-pci"));
    assert!(
        !client
            .kernel
            .runs
            .borrow()
            .iter()
            .any(|run| run.contains("modprobe") || run.contains("rmmod"))
    );
}

/// An unapproved module refuses before any driver write or record, and an
/// approved one is recorded with the binding; no write touches a module or
/// a driver's ID table.
#[test]
fn the_write_combining_check_gates_the_bind() {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    let manifest = Fixture::manifest_of(&fixture.host);
    let mut unapproved = manifest.clone();
    unapproved.modules[0].sha256 = "00".repeat(32);
    assert!(matches!(
        binder.bind(&BindRequest {
            volume: Some(VOLUME),
            eni: None,
            posture: ALLOWLISTED,
            wc: &unapproved,
            others: &[],
        }),
        Err(BindError::Wc(WcError::Module(_)))
    ));
    assert!(untouched(&binder));
    assert!(!mappings_path(&fixture.state_dir()).exists());
    // An approved configuration that also builds iommufd refuses too.
    let iommufd = Fixture::new(4096);
    iommufd.file(
        &format!("boot/config-{RELEASE}"),
        &CONFIG.replace("# CONFIG_IOMMUFD is not set", "CONFIG_IOMMUFD=y"),
    );
    let iommufd_binder = new_binder(&iommufd);
    assert!(matches!(
        bind_volume(&iommufd_binder, VOLUME, ALLOWLISTED),
        Err(BindError::Wc(WcError::Interface("CONFIG_IOMMUFD")))
    ));
    assert!(untouched(&iommufd_binder));
    let mappings = bind_volume(&binder, VOLUME, ALLOWLISTED).unwrap();
    assert_eq!(mappings.wc, manifest);
    for (path, _) in binder.kernel.writes.borrow().iter() {
        assert!(
            !path.starts_with("module/")
                && !path.ends_with("new_id")
                && !path.ends_with("remove_id"),
            "no module or driver-table write: {path}"
        );
    }
}

/// A failed network step during release keeps the record while the controller's restore still runs, and a retry completes once the step succeeds.
#[test]
fn a_failed_network_step_keeps_the_record_for_a_retry() {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    bind_eni(&binder, Some(VOLUME), &FakeMetadata::new()).unwrap();
    let step = "ip addr replace 10.0.1.5/24 brd 10.0.1.255 metric 1003 dev if6".to_owned();
    binder
        .kernel
        .outputs
        .borrow_mut()
        .insert(step.clone(), None);
    assert!(matches!(
        binder.release(&[]),
        Err(BindError::Step {
            step: "network",
            ..
        })
    ));
    assert!(mappings_path(&fixture.state_dir()).exists());
    assert_eq!(
        observed(&fixture, BDF),
        (Some("nvme".into()), None),
        "the controller restored"
    );
    binder.kernel.outputs.borrow_mut().remove(&step);
    binder.kernel.group_opens.borrow_mut().clear();
    binder.release(&[]).unwrap();
    assert!(!mappings_path(&fixture.state_dir()).exists());
    assert!(
        binder.kernel.group_opens.borrow().is_empty(),
        "release opens a group guard only for devices on vfio-pci"
    );
}

/// Release waits through settling intervals for the ENI's device to return under its MAC before restoring its network state.
#[test]
fn release_waits_for_the_eni_device_to_return() {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    bind_eni(&binder, None, &FakeMetadata::new()).unwrap();
    let net = fixture.root.join("sys/class/net/ens6");
    let saved = fixture.root.join("ens6-away");
    fs::rename(&net, &saved).unwrap();
    let (back, from) = (net.clone(), saved.clone());
    binder.kernel.on_settle.borrow_mut().extend([
        Box::new(|| {}) as Box<dyn FnOnce()>,
        Box::new(move || fs::rename(&from, &back).unwrap()),
    ]);
    binder.kernel.runs.borrow_mut().clear();
    binder.release(&[]).unwrap();
    assert!(
        binder.kernel.on_settle.borrow().is_empty(),
        "two intervals passed"
    );
    assert_eq!(binder.kernel.runs.borrow()[2], "ip link set dev if6 up");
}

/// A udev rename during the network batch moves no command: a batch whose
/// first command is refused as the rename lands is rerun at once, since the
/// name changed, and both runs name the device by its index.
#[test]
fn release_reruns_the_network_batch_right_after_a_rename() {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    bind_eni(&binder, None, &FakeMetadata::new()).unwrap();
    let named = fixture.root.join("sys/class/net/ens6");
    let enumerated = fixture.root.join("sys/class/net/eth0");
    fs::rename(&named, &enumerated).unwrap();
    let failing = "ip link set dev if6 mtu 9001".to_owned();
    binder
        .kernel
        .queued
        .borrow_mut()
        .insert(failing.clone(), [None].into());
    let (from, to) = (enumerated.clone(), named.clone());
    binder.kernel.during_run.replace(Some((
        failing.clone(),
        Box::new(move || fs::rename(&from, &to).unwrap()),
    )));
    binder.kernel.runs.borrow_mut().clear();
    let started = binder.kernel.now();
    binder.release(&[]).unwrap();
    assert_eq!(binder.kernel.now(), started, "no interval passed");
    let runs = binder.kernel.runs.borrow();
    assert_eq!(
        runs.iter().filter(|run| **run == failing).count(),
        2,
        "the batch ran again after the rename"
    );
    assert!(runs.iter().any(|run| run == "ip link set dev if6 up"));
}

/// A network batch that fails while udev's rename is still pending makes release look the device up again one interval later and rerun the batch.
#[test]
fn release_reruns_the_network_batch_after_a_pending_rename() {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    bind_eni(&binder, None, &FakeMetadata::new()).unwrap();
    let named = fixture.root.join("sys/class/net/ens6");
    let enumerated = fixture.root.join("sys/class/net/eth0");
    fs::rename(&named, &enumerated).unwrap();
    let failing = "ip link set dev if6 mtu 9001".to_owned();
    binder
        .kernel
        .queued
        .borrow_mut()
        .insert(failing.clone(), [None].into());
    let (from, to) = (enumerated.clone(), named.clone());
    binder
        .kernel
        .on_settle
        .borrow_mut()
        .push(Box::new(move || fs::rename(&from, &to).unwrap()));
    binder.kernel.runs.borrow_mut().clear();
    let started = binder.kernel.now();
    binder.release(&[]).unwrap();
    assert!(
        binder.kernel.on_settle.borrow().is_empty() && binder.kernel.now() > started,
        "one interval passed"
    );
    let runs = binder.kernel.runs.borrow();
    assert_eq!(
        runs.iter().filter(|run| **run == failing).count(),
        2,
        "the batch ran again after the rename"
    );
    assert!(runs.iter().any(|run| run == "ip link set dev if6 up"));
}

/// A network batch that fails under a device name that stays the same through one interval fails release's network step with that batch's error.
#[test]
fn release_fails_a_network_batch_whose_device_keeps_its_name() {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    bind_eni(&binder, None, &FakeMetadata::new()).unwrap();
    binder
        .kernel
        .queued
        .borrow_mut()
        .insert("ip link set dev if6 mtu 9001".into(), [None].into());
    binder.kernel.runs.borrow_mut().clear();
    let started = binder.kernel.now();
    let failed = binder.release(&[]);
    assert!(
        matches!(
            failed,
            Err(BindError::Step {
                step: "network",
                ..
            })
        ),
        "{failed:?}"
    );
    assert_eq!(
        binder.kernel.now() - started,
        Duration::from_millis(100),
        "exactly one interval passed between the failure and the error"
    );
    let runs = binder.kernel.runs.borrow();
    assert_eq!(
        runs.iter()
            .filter(|run| run.as_str() == "ip link set dev if6 mtu 9001")
            .count(),
        1,
        "no rerun under an unchanged name"
    );
}

/// Release waits for the recorded PCI function's network device to return even when another interface carries the ENI's MAC.
#[test]
fn release_restores_only_the_recorded_function_s_device() {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    bind_eni(&binder, None, &FakeMetadata::new()).unwrap();
    let net = fixture.root.join("sys/class/net/ens6");
    let saved = fixture.root.join("ens6-away");
    fs::rename(&net, &saved).unwrap();
    fixture.netdev("bond0", "0000:00:09.0", ENI_MAC, 0x1003);
    let (back, from) = (net.clone(), saved.clone());
    binder
        .kernel
        .on_settle
        .borrow_mut()
        .push(Box::new(move || fs::rename(&from, &back).unwrap()));
    binder.kernel.runs.borrow_mut().clear();
    binder.release(&[]).unwrap();
    // The link listing before the batch names no device and writes none.
    let runs = binder.kernel.runs.borrow();
    let runs: Vec<&String> = runs
        .iter()
        .filter(|run| *run != "ip -o link show")
        .collect();
    assert!(
        !runs.is_empty() && runs.iter().all(|run| run.contains(" dev if6")),
        "{runs:?}"
    );
}

/// Moves the fixture ENI's device away and queues `waits` settles, the last
/// of which moves it back, so the device returns at lookup probe `waits + 1`.
fn returning_after(fixture: &Fixture, binder: &Binder<FakeKernel>, waits: usize) {
    let net = fixture.root.join("sys/class/net/ens6");
    let saved = fixture.root.join("ens6-away");
    fs::rename(&net, &saved).unwrap();
    let mut settles = binder.kernel.on_settle.borrow_mut();
    settles.extend((1..waits).map(|_| Box::new(|| {}) as Box<dyn FnOnce()>));
    settles.push(Box::new(move || fs::rename(&saved, &net).unwrap()));
}

/// Whether the binder's command log is empty since it was last cleared.
fn ran_nothing(binder: &Binder<FakeKernel>) -> bool {
    binder.kernel.runs.borrow().is_empty()
}

/// One lookup makes at most 50 probes and 49 waits: a device that returns
/// at the 49th wait is found by the 50th probe and restored, and one that
/// would return at the 50th wait stays unseen, so release fails with
/// `Network` after exactly 49 waits, with an empty command log and the record
/// kept.
#[test]
fn a_lookup_makes_at_most_fifty_probes_and_forty_nine_waits() {
    for (waits, found) in [(49, true), (50, false)] {
        let fixture = Fixture::new(4096);
        let binder = new_binder(&fixture);
        bind_eni(&binder, None, &FakeMetadata::new()).unwrap();
        returning_after(&fixture, &binder, waits);
        binder.kernel.runs.borrow_mut().clear();
        let started = binder.kernel.now();
        let released = binder.release(&[]);
        let waited = binder.kernel.now() - started;
        assert_eq!(waited, Duration::from_millis(100) * 49, "{waits}");
        if found {
            assert!(released.is_ok(), "{released:?}");
            assert!(binder.kernel.on_settle.borrow().is_empty());
        } else {
            assert!(
                matches!(released, Err(BindError::Network(_))),
                "{released:?}"
            );
            assert_eq!(binder.kernel.on_settle.borrow().len(), 1, "49 waits");
            assert!(ran_nothing(&binder));
            assert!(mappings_path(&fixture.state_dir()).exists());
        }
    }
}

/// One restore runs at most 51 batches: each failed batch whose device a
/// later interval renames reruns for the device under its new name, and the
/// 51st failure returns its error after the 50th rename with the record
/// kept. Every batch names the device by its interface index, which the
/// renames keep, after its own link listing.
#[test]
fn a_restore_runs_at_most_fifty_one_batches_across_renames() {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    bind_eni(&binder, None, &FakeMetadata::new()).unwrap();
    let names = ["ens6", "eth0"];
    binder
        .kernel
        .outputs
        .borrow_mut()
        .insert("ip link set dev if6 mtu 9001".into(), None);
    let net = fixture.root.join("sys/class/net");
    let renames = (0..60).map(|turn| {
        let (from, to) = (net.join(names[turn % 2]), net.join(names[(turn + 1) % 2]));
        Box::new(move || fs::rename(&from, &to).unwrap()) as Box<dyn FnOnce()>
    });
    binder.kernel.on_settle.borrow_mut().extend(renames);
    binder.kernel.runs.borrow_mut().clear();
    let failed = binder.release(&[]);
    assert!(
        matches!(
            failed,
            Err(BindError::Step {
                step: "network",
                ..
            })
        ),
        "{failed:?}"
    );
    let runs = binder.kernel.runs.borrow();
    assert_eq!(runs.iter().filter(|run| run.contains(" mtu ")).count(), 51);
    assert!(
        runs.chunks(2)
            .all(|batch| batch == ["ip -o link show", "ip link set dev if6 mtu 9001"]),
        "each batch lists the links and stops at its first command: {runs:?}"
    );
    assert_eq!(
        binder.kernel.on_settle.borrow().len(),
        60 - 51,
        "one wait, and so one rename, per batch"
    );
    assert!(mappings_path(&fixture.state_dir()).exists());
}

/// A lookup targets only the one device carrying the recorded MAC on the
/// recorded function: a second device on that function with the same MAC
/// makes the match ambiguous, and a same-MAC device on another function lies
/// outside the match, so either release fails with `Network` after 49 waits
/// with an empty command log.
#[test]
fn a_duplicate_or_other_function_candidate_is_never_targeted() {
    for duplicate in [true, false] {
        let fixture = Fixture::new(4096);
        let binder = new_binder(&fixture);
        bind_eni(&binder, None, &FakeMetadata::new()).unwrap();
        if duplicate {
            fixture.file("sys/class/net/eth9/address", &format!("{ENI_MAC}\n"));
            fixture.file("sys/class/net/eth9/flags", "0x1003\n");
            fixture.file("sys/class/net/eth9/mtu", "9001\n");
            symlink(
                fixture.host.pci(ENI_BDF),
                fixture.root.join("sys/class/net/eth9/device"),
            )
            .unwrap();
        } else {
            fs::rename(
                fixture.root.join("sys/class/net/ens6"),
                fixture.root.join("ens6-away"),
            )
            .unwrap();
            fixture.netdev("bond0", "0000:00:09.0", ENI_MAC, 0x1003);
        }
        binder.kernel.runs.borrow_mut().clear();
        let started = binder.kernel.now();
        let released = binder.release(&[]);
        assert!(
            matches!(released, Err(BindError::Network(_))),
            "{released:?}"
        );
        assert_eq!(
            binder.kernel.now() - started,
            Duration::from_millis(100) * 49
        );
        assert!(ran_nothing(&binder), "{duplicate}");
    }
}

/// Each restore batch sets the MTU, then the link state, then every
/// recorded address in the recorded order, then every recorded route, with
/// host-scope routes first, then link-scope routes and every other route
/// with no gateway, then the rest, in
/// the recorded order within each group, each on the device's interface
/// index, after the link listing that guards it.
#[test]
fn each_restore_batch_orders_the_mtu_link_addresses_and_routes() {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    let mut outputs = binder.kernel.outputs.borrow_mut();
    outputs.insert(
        "ip -4 -o addr show dev ens6".into(),
        Some(format!(
            "{ENS6_ADDRESS}3: ens6    inet 10.0.1.6/24 brd 10.0.1.255 scope global secondary noprefixroute ens6\n"
        )),
    );
    outputs.insert(
        "ip -4 -o route show table all dev ens6".into(),
        Some(
            "10.0.1.0/24 proto kernel scope link src 10.0.1.5 metric 1003\n10.9.0.0/16 via 10.0.1.1 metric 50\n\
             local 10.0.1.5 table local proto kernel scope host src 10.0.1.5\n"
                .into(),
        ),
    );
    drop(outputs);
    bind_eni(&binder, None, &FakeMetadata::new()).unwrap();
    binder.kernel.runs.borrow_mut().clear();
    binder.release(&[]).unwrap();
    assert_eq!(
        *binder.kernel.runs.borrow(),
        [
            "ip -o link show",
            "ip link set dev if6 mtu 9001",
            "ip link set dev if6 up",
            "ip addr replace 10.0.1.5/24 brd 10.0.1.255 metric 1003 dev if6",
            "ip addr replace 10.0.1.6/24 brd 10.0.1.255 noprefixroute dev if6",
            "ip route replace 10.0.1.0/24 proto kernel scope link src 10.0.1.5 metric 1003 dev if6",
            "ip route replace 10.9.0.0/16 via 10.0.1.1 metric 50 dev if6",
        ]
    );
}

#[test]
fn release_restores_a_recorded_down_link() {
    let fixture = Fixture::new(4096);
    fixture.file("sys/class/net/ens6/flags", "0x1002\n");
    let binder = new_binder(&fixture);
    bind_eni(&binder, None, &FakeMetadata::new()).unwrap();
    binder.kernel.runs.borrow_mut().clear();
    binder.release(&[]).unwrap();
    assert_eq!(binder.kernel.runs.borrow()[2], "ip link set dev if6 down");
}

/// An ENI enslaved to a bond, bridge or VRF refuses before any write, since release replays no master membership.
#[test]
fn an_enslaved_eni_refuses() {
    let fixture = Fixture::new(4096);
    std::os::unix::fs::symlink(
        fixture.root.join("sys/class/net/ens5"),
        fixture.root.join("sys/class/net/ens6/master"),
    )
    .unwrap();
    let binder = new_binder(&fixture);
    assert!(matches!(
        bind_eni(&binder, None, &FakeMetadata::new()),
        Err(BindError::Eni(EniError::Unverifiable("master")))
    ));
    assert!(untouched(&binder));
    assert!(!mappings_path(&fixture.state_dir()).exists());
}

/// Two state directories naming the same ENI bind it once: the second bind finds it off `ena` and writes nothing, and an address that no longer holds an ENA refuses release with nothing restored.
#[test]
fn a_second_directory_cannot_take_a_bound_eni() {
    let fixture = Fixture::new(4096);
    let first = new_binder(&fixture);
    bind_eni(&first, None, &FakeMetadata::new()).unwrap();
    let second = Binder {
        state_dir: fixture.root.join("second"),
        ..new_binder(&fixture)
    };
    fs::create_dir_all(&second.state_dir).unwrap();
    assert!(matches!(
        bind_eni(&second, None, &FakeMetadata::new()),
        Err(BindError::Eni(EniError::NotFound | EniError::NotEna))
    ));
    assert!(untouched(&second));
    fixture.file(&format!("sys/bus/pci/devices/{ENI_BDF}/device"), "0x8061\n");
    let (writes, runs) = (
        first.kernel.writes.borrow().len(),
        first.kernel.runs.borrow().len(),
    );
    assert!(matches!(first.release(&[]), Err(BindError::NotRecorded(_))));
    assert_eq!(first.kernel.writes.borrow().len(), writes);
    assert_eq!(first.kernel.runs.borrow().len(), runs);
}

/// Two owners on one host bind through their own state directories while the
/// first owner runs, holding its lock and its devices' VFIO groups: each
/// binds its own volume and ENI under its own lock, and releasing one owner
/// restores only its devices and leaves the other's bound and in use. A
/// controller or ENI already on `vfio-pci` refuses, and the first owner's
/// release waits for its own groups to close.
#[test]
fn two_owner_directories_bind_and_release_independently() {
    let (fixture, metadata) = with_secondary();
    fixture.controller("nvme2", "0000:00:1e.0", "vol0bbbbbbbbbbbbbbbbb", 4096);
    let first = new_binder(&fixture);
    bind_eni(&first, Some(VOLUME), &metadata).unwrap();
    let running = OwnerLock::acquire(&fixture.state_dir()).unwrap();
    let vfio = |bdf| {
        fixture
            .host
            .dev
            .join(format!("vfio/noiommu-{}", group_of(bdf)))
    };
    fixture.hold(&vfio(BDF));
    fixture.hold(&vfio(ENI_BDF));
    let second = Binder {
        state_dir: fixture.root.join("owner-2"),
        ..new_binder(&fixture)
    };
    fs::create_dir_all(&second.state_dir).unwrap();
    fixture.neighbor(
        "ens7",
        &neighbor_entry("10.0.1.9", Some("0a:00:00:00:01:09"), "REACHABLE"),
    );
    fixture.neighbor(
        "ens7",
        &neighbor_entry("10.0.1.1", Some("0a:00:00:00:01:01"), "REACHABLE"),
    );
    let manifest = Fixture::manifest_of(&fixture.host);
    let peers = [PEERS[0]];
    let request = |volume| BindRequest {
        volume: Some(volume),
        eni: Some(EniRequest {
            id: "eni-0bbbbbbbbbbbbbbbb",
            peers: &peers,
            metadata: &metadata,
        }),
        posture: ALLOWLISTED,
        wc: &manifest,
        others: &[],
    };
    assert!(
        matches!(second.bind(&request(VOLUME)), Err(BindError::Changed)),
        "the first owner's controller is already on vfio-pci"
    );
    second.bind(&request("vol-0bbbbbbbbbbbbbbbbb")).unwrap();
    for bdf in [BDF, ENI_BDF, "0000:00:1e.0", SECONDARY_BDF] {
        assert_eq!(
            observed(&fixture, bdf).0.as_deref(),
            Some("vfio-pci"),
            "{bdf}"
        );
    }
    assert!(
        matches!(first.release(&[]), Err(BindError::Lock(_))),
        "the running owner's lock holds its directory"
    );
    second.kernel.group_opens.borrow_mut().clear();
    second.release(&[]).unwrap();
    let opened: Vec<_> = second
        .kernel
        .group_opens
        .borrow()
        .iter()
        .map(|(path, _)| path.clone())
        .collect();
    assert_eq!(
        opened,
        [vfio("0000:00:1e.0"), vfio(SECONDARY_BDF)],
        "the second owner guards only its own groups"
    );
    for bdf in ["0000:00:1e.0", SECONDARY_BDF] {
        assert_eq!(
            observed(&fixture, bdf).0.as_deref(),
            Some(if bdf == SECONDARY_BDF { "ena" } else { "nvme" })
        );
    }
    for bdf in [BDF, ENI_BDF] {
        assert_eq!(
            observed(&fixture, bdf).0.as_deref(),
            Some("vfio-pci"),
            "the first owner stays bound"
        );
    }
    drop(running);
    assert!(matches!(first.release(&[]), Err(BindError::VfioInUse)));
    for bdf in [BDF, ENI_BDF] {
        fixture.unhold(&vfio(bdf));
    }
    first.release(&[]).unwrap();
    assert_eq!(observed(&fixture, BDF).0.as_deref(), Some("nvme"));
}

/// Next-hop resolution rechecks the ENI under its lock, before any neighbor
/// entry changes: an ENI that left `ena` and one whose network device no
/// longer names its function each refuse with no driver write and no
/// record. Each change happens while the bind's ownership check, under the
/// ENI's lock, reads another owner's state directory, whose mappings path
/// is a FIFO the change precedes.
#[test]
fn next_hops_recheck_the_eni_under_its_lock() {
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;
    let records = Fixture::new(4096);
    let binder = new_binder(&records);
    let manifest = Fixture::manifest_of(&records.host);
    let metadata = FakeMetadata::new();
    let record = |volume, eni| {
        let request = BindRequest {
            volume,
            eni,
            posture: ALLOWLISTED,
            wc: &manifest,
            others: &[],
        };
        binder.bind(&request).unwrap();
        let text = fs::read_to_string(mappings_path(&records.state_dir())).unwrap();
        binder.release(&[]).unwrap();
        text
    };
    let eni = || EniRequest {
        id: ENI,
        peers: &PEERS,
        metadata: &metadata,
    };
    let controller = record(Some(VOLUME), None);
    type Change = fn(&Host);
    type Expected = fn(&BindError) -> bool;
    let cases: [(Change, Expected); 2] = [
        (
            |host| fs::remove_file(host.pci(ENI_BDF).join("driver")).unwrap(),
            |e| matches!(e, BindError::Changed),
        ),
        (
            |host| {
                let net = host.sys.join("class/net");
                fs::rename(net.join("ens6"), net.join("ens9")).unwrap();
            },
            |e| matches!(e, BindError::Changed),
        ),
    ];
    for (change, expected) in cases {
        let fixture = Fixture::new(4096);
        let binder = new_binder(&fixture);
        stale_gateway(&fixture);
        let other = fixture.root.join("owner-2");
        fs::create_dir_all(&other).unwrap();
        let fifo = mappings_path(&other);
        let path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: `path` is a NUL-terminated string that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let (host, pipe, first) = (fixture.host.clone(), fifo.clone(), controller.clone());
        let locks = fixture.device_locks();
        let writer = std::thread::spawn(move || {
            let mut sink = fs::OpenOptions::new().write(true).open(&pipe).unwrap();
            let held = DeviceLock::acquire(&locks, ENI_BDF).map(drop);
            change(&host);
            let _sent = sink.write_all(first.as_bytes());
            held
        });
        let manifest = Fixture::manifest_of(&fixture.host);
        let refused = binder.bind(&BindRequest {
            volume: None,
            eni: Some(eni()),
            posture: ALLOWLISTED,
            wc: &manifest,
            others: &[other],
        });
        // A bind that never opened the FIFO releases the writer here.
        let _reader = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo);
        let held = writer.join().unwrap();
        assert_eq!(
            held.unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "the ownership check reads the other directory under the ENI's lock"
        );
        let refused = refused.unwrap_err();
        assert!(expected(&refused), "{refused:?}");
        assert!(neighbors_untouched(&binder), "{refused:?}");
        assert!(untouched(&binder), "{refused:?}");
        assert!(!mappings_path(&fixture.state_dir()).exists());
    }
}

/// A controller or ENI another owner's state directory records refuses
/// before this bind writes anything, and so does a given directory that is
/// missing, is not a directory, or holds an unreadable record.
#[test]
fn a_device_another_owner_records_refuses() {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    let metadata = FakeMetadata::new();
    bind_eni(&binder, Some(VOLUME), &metadata).unwrap();
    let other = fixture.root.join("owner-2");
    fs::create_dir_all(&other).unwrap();
    fs::copy(mappings_path(&fixture.state_dir()), mappings_path(&other)).unwrap();
    binder.release(&[]).unwrap();
    let eni_owner = fixture.root.join("owner-5");
    fs::create_dir_all(&eni_owner).unwrap();
    bind_eni(&binder, None, &metadata).unwrap();
    fs::copy(
        mappings_path(&fixture.state_dir()),
        mappings_path(&eni_owner),
    )
    .unwrap();
    binder.release(&[]).unwrap();
    let garbled = fixture.root.join("owner-3");
    fs::create_dir_all(&garbled).unwrap();
    fs::write(mappings_path(&garbled), "not a record\n").unwrap();
    let oversized = fixture.root.join("owner-6");
    fs::create_dir_all(&oversized).unwrap();
    {
        use std::io::Write;
        let mut file = fs::File::create(mappings_path(&oversized)).unwrap();
        file.write_all(b"format=3\n").unwrap();
        let line = format!("nvme.bdf={BDF}\n");
        let lines = usize::try_from(MAPPINGS_BYTES).unwrap() / line.len() + 1;
        for _ in 0..lines {
            file.write_all(line.as_bytes()).unwrap();
        }
    }
    let manifest = Fixture::manifest_of(&fixture.host);
    let writes = binder.kernel.writes.borrow().len();
    stale_gateway(&fixture);
    binder.kernel.solicits.borrow_mut().clear();
    binder.kernel.runs.borrow_mut().clear();
    let eni = EniRequest {
        id: ENI,
        peers: &PEERS,
        metadata: &metadata,
    };
    let cases = [
        (Some(VOLUME), None, vec![other.clone()], Some(BDF)),
        (None, Some(eni), vec![other.clone()], Some(ENI_BDF)),
        (Some(VOLUME), Some(eni), vec![eni_owner], Some(ENI_BDF)),
        (Some(VOLUME), None, vec![fixture.root.join("owner-4")], None),
        (Some(VOLUME), None, vec![garbled], None),
        (Some(VOLUME), None, vec![mappings_path(&other)], None),
    ];
    for (volume, eni, others, recorded) in cases {
        let refused = binder.bind(&BindRequest {
            volume,
            eni,
            posture: ALLOWLISTED,
            wc: &manifest,
            others: &others,
        });
        match (refused, recorded) {
            (Err(BindError::OtherOwner { bdf, state_dir }), Some(expected)) => {
                assert_eq!((bdf.as_str(), &state_dir), (expected, &others[0]));
            }
            (Err(BindError::Mappings(_)), None) => {}
            (unexpected, _) => panic!("{unexpected:?}"),
        }
        assert!(!mappings_path(&fixture.state_dir()).exists());
    }
    let refused = binder.bind(&BindRequest {
        volume: Some(VOLUME),
        eni: None,
        posture: ALLOWLISTED,
        wc: &manifest,
        others: &[oversized],
    });
    assert!(
        matches!(
            refused,
            Err(BindError::Mappings(MappingsError::Io(ref error)))
                if error.kind() == std::io::ErrorKind::InvalidData
        ),
        "a record over the byte bound refuses before its parse: {refused:?}"
    );
    assert!(!mappings_path(&fixture.state_dir()).exists());
    assert_eq!(binder.kernel.writes.borrow().len(), writes, "nothing moved");
    assert!(
        neighbors_untouched(&binder),
        "no neighbor of another owner's ENI is refreshed"
    );
    assert_eq!(observed(&fixture, BDF).0.as_deref(), Some("nvme"));
    assert_eq!(observed(&fixture, ENI_BDF).0.as_deref(), Some("ena"));
}

/// A bind that finds a requested device's lock held by another bind moves
/// nothing and writes no record, and a release refuses with `Lock` while a
/// recorded device's lock is held. A lock held before the bind refuses
/// before the next hops change any neighbor entry; once the controller
/// moved, the bind still holds both devices' locks, so another holder takes
/// neither before the ENI moves.
#[test]
fn a_locked_device_refuses_the_bind_and_a_bind_holds_its_locks_through_the_moves() {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    stale_gateway(&fixture);
    let held = fixture.lock_device(ENI_BDF);
    let refused = bind_eni(&binder, Some(VOLUME), &FakeMetadata::new());
    assert!(matches!(refused, Err(BindError::Lock(_))), "{refused:?}");
    assert!(neighbors_untouched(&binder));
    assert!(untouched(&binder));
    assert!(!mappings_path(&fixture.state_dir()).exists());
    drop(held);

    binder
        .kernel
        .answers
        .borrow_mut()
        .insert(Ipv4Addr::new(10, 0, 1, 1), "0a:00:00:00:01:01");
    let locks = fixture.device_locks();
    let taken = std::rc::Rc::new(std::cell::RefCell::new(None));
    let keep = taken.clone();
    binder.kernel.after_write.replace(Some((
        "vfio-pci/bind",
        Box::new(move || {
            *keep.borrow_mut() = Some([BDF, ENI_BDF].map(|bdf| {
                DeviceLock::acquire(&locks, bdf)
                    .map(drop)
                    .map_err(|error| error.kind())
            }));
        }),
    )));
    bind_eni(&binder, Some(VOLUME), &FakeMetadata::new()).unwrap();
    let taken = taken
        .borrow_mut()
        .take()
        .expect("the hook ran after the controller moved");
    assert_eq!(
        taken,
        [Err(std::io::ErrorKind::WouldBlock); 2],
        "the bind holds both devices' locks from its ownership check through its moves"
    );
    assert_eq!(observed(&fixture, ENI_BDF).0.as_deref(), Some("vfio-pci"));
    let held = fixture.lock_device(BDF);
    let writes = binder.kernel.writes.borrow().len();
    assert!(
        matches!(binder.release(&[]), Err(BindError::Lock(_))),
        "release holds every recorded device's lock before it checks or restores one"
    );
    assert_eq!(
        binder.kernel.writes.borrow().len(),
        writes,
        "nothing restored"
    );
    assert_eq!(observed(&fixture, BDF).0.as_deref(), Some("vfio-pci"));
    assert_eq!(observed(&fixture, ENI_BDF).0.as_deref(), Some("vfio-pci"));
    assert!(
        mappings_path(&fixture.state_dir()).exists(),
        "the record stays"
    );
    drop(held);
    binder.release(&[]).unwrap();
    assert_eq!(observed(&fixture, BDF).0.as_deref(), Some("nvme"));
}

/// Whether the binder's kernel saw no driver write and no neighbor change, and
/// its state directory holds no record.
fn without_effects(binder: &Binder<FakeKernel>) -> bool {
    untouched(binder) && neighbors_untouched(binder) && !mappings_path(&binder.state_dir).exists()
}

/// A request for the fixture's controller when `volume` is set and its ENI
/// when `eni` is, under the fixture's approved module and the allowlisted
/// posture, refusing devices `others` records.
fn request<'r>(
    volume: bool,
    eni: bool,
    metadata: &'r FakeMetadata,
    wc: &'r super::wc::WcManifest,
    others: &'r [std::path::PathBuf],
) -> BindRequest<'r> {
    BindRequest {
        volume: volume.then_some(VOLUME),
        eni: eni.then_some(EniRequest {
            id: ENI,
            peers: &PEERS,
            metadata,
        }),
        posture: ALLOWLISTED,
        wc,
        others,
    }
}

/// Replaces `bdf`'s IOMMU group member listing with a regular file, so opening
/// it fails with an error other than `NotFound` whatever the caller's
/// privileges.
fn unreadable_group(fixture: &Fixture, bdf: &str) {
    let members = fixture.host.pci(bdf).join("iommu_group/devices");
    fs::remove_dir_all(&members).unwrap();
    fs::write(&members, "").unwrap();
}

/// Only a member listing that is absent represents a missing IOMMU group. In
/// the allowlisted no-IOMMU posture, an unreadable listing of the controller's
/// or the ENI's group refuses with `Group` before any driver write, neighbor
/// change or record, while a missing group still binds; an unreadable listing
/// refuses on an IOMMU host too. The group classifier also refuses a listing
/// whose iteration fails, which the fixture's filesystem cannot produce, so
/// that case calls the classifier directly.
#[test]
fn an_unreadable_iommu_group_listing_refuses_binding() {
    let metadata = FakeMetadata::new();
    for (bdf, volume) in [(BDF, true), (ENI_BDF, false)] {
        for missing in [false, true] {
            let fixture = Fixture::new(4096);
            let binder = new_binder(&fixture);
            if missing {
                fs::remove_file(fixture.host.pci(bdf).join("iommu_group")).unwrap();
            } else {
                stale_gateway(&fixture);
                unreadable_group(&fixture, bdf);
            }
            let manifest = Fixture::manifest_of(&fixture.host);
            let outcome = binder.bind(&request(volume, !volume, &metadata, &manifest, &[]));
            if missing {
                assert!(
                    outcome.is_ok(),
                    "{bdf}: a missing group binds without an IOMMU: {outcome:?}"
                );
            } else {
                assert!(
                    matches!(outcome, Err(BindError::Group)),
                    "{bdf}: {outcome:?}"
                );
                assert!(without_effects(&binder), "{bdf}");
            }
        }
    }
    let fixture = Fixture::new(4096);
    let posture = iommu_mode(&fixture);
    unreadable_group(&fixture, BDF);
    let binder = new_binder(&fixture);
    assert!(matches!(
        bind_volume(&binder, VOLUME, posture),
        Err(BindError::Group)
    ));
    assert!(without_effects(&binder));
    let failing = || {
        Ok::<_, std::io::Error>(
            [Ok(BDF.into()), Err(std::io::Error::other("iteration"))].into_iter(),
        )
    };
    for guest_iommu in [false, true] {
        assert!(matches!(
            sole_member(failing(), BDF, guest_iommu),
            Err(BindError::Group)
        ));
    }
}

/// Owner A holds a device's lock across its ownership check, its record's
/// publication and its driver move; at each boundary owner B's bind of the
/// same device, given A's directory, refuses with `Lock`, writes no driver
/// attribute, changes no neighbor entry and publishes no record. Once A
/// releases the lock after its publication or its move, B's bind refuses on
/// A's record. The publication and move boundaries hold A's record on disk,
/// the move boundary also A's override write, so B reaches the device lock
/// before it could read that record.
#[test]
fn a_contending_owner_cannot_publish_a_device_another_owner_s_bind_holds() {
    let (template, metadata) = (Fixture::new(4096), FakeMetadata::new());
    let recorder = new_binder(&template);
    let records = [true, false].map(|volume| {
        let manifest = Fixture::manifest_of(&template.host);
        recorder
            .bind(&request(volume, !volume, &metadata, &manifest, &[]))
            .unwrap();
        let text = fs::read_to_string(mappings_path(&template.state_dir())).unwrap();
        recorder.release(&[]).unwrap();
        text
    });
    type Boundary = fn(&Fixture, &Path, &str, &str);
    let boundaries: [(&str, bool, Boundary); 3] = [
        ("ownership check", false, |_, _, _, _| {}),
        ("publication", true, |_, a, _, record| {
            fs::write(mappings_path(a), record).unwrap()
        }),
        ("move", true, |f, a, bdf, record| {
            fs::write(mappings_path(a), record).unwrap();
            f.file(
                &format!("sys/bus/pci/devices/{bdf}/driver_override"),
                "vfio-pci\n",
            );
        }),
    ];
    for ((bdf, volume), record) in [(BDF, true), (ENI_BDF, false)].into_iter().zip(&records) {
        for (name, recorded, boundary) in boundaries {
            let fixture = Fixture::new(4096);
            stale_gateway(&fixture);
            let owner_a = fixture.root.join("owner-a");
            fs::create_dir_all(&owner_a).unwrap();
            let held = fixture.lock_device(bdf);
            boundary(&fixture, &owner_a, bdf, record);
            let owner_b = new_binder(&fixture);
            let manifest = Fixture::manifest_of(&fixture.host);
            let others = [owner_a.clone()];
            let request = request(volume, !volume, &metadata, &manifest, &others);
            let refused = owner_b.bind(&request);
            assert!(
                matches!(refused, Err(BindError::Lock(_))),
                "{bdf} at A's {name}: {refused:?}"
            );
            assert!(without_effects(&owner_b), "{bdf} at A's {name}");
            drop(held);
            if !recorded {
                continue;
            }
            let refused = owner_b.bind(&request);
            assert!(
                matches!(&refused, Err(BindError::OtherOwner { bdf: found, state_dir }) if found == bdf && *state_dir == owner_a),
                "{bdf} after A's {name}: {refused:?}"
            );
            assert!(without_effects(&owner_b), "{bdf} after A's {name}");
        }
    }
}

/// The bytes of every file under `dir`, by path, so a test can compare a
/// state tree before and after an operation.
fn snapshot(dir: &Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let mut files = Vec::new();
    let mut pending = vec![dir.to_owned()];
    while let Some(at) = pending.pop() {
        for entry in fs::read_dir(&at).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push((path.clone(), fs::read(&path).unwrap()));
            }
        }
    }
    files.sort();
    files
}

/// Owner A publishes its record and dies before its driver moves; owner B,
/// configured without A's directory, then binds the devices. A's stale
/// release, given B's directory, refuses with `OtherOwner` before any
/// restore or group guard: B's record, the devices' drivers and overrides,
/// and the ENI's neighbor and network state are byte-identical afterwards,
/// and A's record stays. The schedule runs for the controller, the ENI and
/// both, and for an A that recorded both devices while B binds the ENI
/// alone.
#[test]
fn a_stale_release_leaves_another_owner_s_binding_intact() {
    let metadata = FakeMetadata::new();
    let schedules = [
        ((true, false), (true, false)),
        ((false, true), (false, true)),
        ((true, true), (true, true)),
        ((true, true), (false, true)),
    ];
    for ((a_volume, a_eni), (b_volume, b_eni)) in schedules {
        let case = (a_volume, a_eni, b_volume, b_eni);
        let fixture = Fixture::new(4096);
        let owner_a = new_binder(&fixture);
        let manifest = Fixture::manifest_of(&fixture.host);
        owner_a
            .bind(&request(a_volume, a_eni, &metadata, &manifest, &[]))
            .unwrap();
        let published = fs::read(mappings_path(&owner_a.state_dir)).unwrap();
        owner_a.release(&[]).unwrap();
        fs::write(mappings_path(&owner_a.state_dir), &published).unwrap();
        let owner_b = Binder {
            state_dir: fixture.root.join("owner-b"),
            ..new_binder(&fixture)
        };
        fs::create_dir_all(&owner_b.state_dir).unwrap();
        owner_b
            .bind(&request(b_volume, b_eni, &metadata, &manifest, &[]))
            .unwrap();
        let state = || {
            (
                snapshot(&owner_b.state_dir),
                [BDF, ENI_BDF].map(|bdf| observed(&fixture, bdf)),
                snapshot(&fixture.root.join("neigh")),
                snapshot(&fixture.host.sys.join("class/net")),
            )
        };
        let effects = || {
            let kernel = &owner_a.kernel;
            (
                kernel.writes.borrow().len(),
                kernel.runs.borrow().len(),
                kernel.solicits.borrow().len(),
                kernel.group_opens.borrow().len(),
            )
        };
        let (before, logged) = (state(), effects());
        let refused = owner_a.release(std::slice::from_ref(&owner_b.state_dir));
        assert!(
            matches!(&refused, Err(BindError::OtherOwner { state_dir, .. }) if *state_dir == owner_b.state_dir),
            "{case:?}: {refused:?}"
        );
        assert_eq!(state(), before, "{case:?}");
        assert_eq!(
            effects(),
            logged,
            "{case:?}: the stale release writes, runs and opens nothing"
        );
        assert_eq!(
            fs::read(mappings_path(&owner_a.state_dir)).unwrap(),
            published
        );
        owner_b.release(&[]).unwrap();
        if b_volume {
            assert_eq!(observed(&fixture, BDF).0.as_deref(), Some("nvme"));
        }
        if b_eni {
            assert_eq!(observed(&fixture, ENI_BDF).0.as_deref(), Some("ena"));
        }
    }
}

/// An owner whose own state directory appears among the other owners'
/// directories, as one shared list of every owner gives it, binds and
/// releases as though that entry were absent; the release, which finds the
/// owner's own record there, shows the skip.
#[test]
fn an_owner_s_own_directory_among_the_others_is_skipped() {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    let (metadata, manifest) = (FakeMetadata::new(), Fixture::manifest_of(&fixture.host));
    let others = [fixture.root.join("owner-2"), fixture.state_dir()];
    fs::create_dir_all(&others[0]).unwrap();
    binder
        .bind(&request(true, true, &metadata, &manifest, &others))
        .unwrap();
    binder.release(&others).unwrap();
    assert_eq!(observed(&fixture, BDF).0.as_deref(), Some("nvme"));
    assert_eq!(observed(&fixture, ENI_BDF).0.as_deref(), Some("ena"));
}

#[test]
fn a_flock_on_a_device_s_sysfs_directory_gates_nothing() {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    let held = [BDF, ENI_BDF].map(|bdf| {
        let directory = fs::File::open(fixture.host.pci(bdf)).unwrap();
        directory.try_lock().unwrap();
        directory
    });
    bind_eni(&binder, Some(VOLUME), &FakeMetadata::new()).unwrap();
    assert_eq!(observed(&fixture, BDF).0.as_deref(), Some("vfio-pci"));
    assert_eq!(observed(&fixture, ENI_BDF).0.as_deref(), Some("vfio-pci"));
    binder.release(&[]).unwrap();
    assert_eq!(observed(&fixture, BDF).0.as_deref(), Some("nvme"));
    assert_eq!(observed(&fixture, ENI_BDF).0.as_deref(), Some("ena"));
    drop(held);
}

#[test]
fn a_device_lock_directory_open_to_others_or_a_linked_lock_refuses() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    let locks = fixture.device_locks();
    let refused = |binder: &Binder<FakeKernel>| {
        let result = bind_volume(binder, VOLUME, ALLOWLISTED);
        assert!(matches!(result, Err(BindError::Lock(_))), "{result:?}");
        assert!(untouched(binder), "no driver write");
        assert!(!mappings_path(&fixture.state_dir()).exists());
    };
    fs::create_dir_all(&locks).unwrap();
    for mode in [0o755, 0o710, 0o701] {
        fs::set_permissions(&locks, fs::Permissions::from_mode(mode)).unwrap();
        refused(&binder);
    }
    fs::set_permissions(&locks, fs::Permissions::from_mode(0o700)).unwrap();
    symlink(
        fixture.root.join("elsewhere"),
        locks.join(format!("{BDF}.lock")),
    )
    .unwrap();
    refused(&binder);
    assert!(
        !fixture.root.join("elsewhere").exists(),
        "the link is not followed"
    );
    fs::remove_file(locks.join(format!("{BDF}.lock"))).unwrap();
    let real = fixture.root.join("real-locks");
    fs::rename(&locks, &real).unwrap();
    symlink(&real, &locks).unwrap();
    refused(&binder);
    fs::remove_file(&locks).unwrap();
    bind_volume(&binder, VOLUME, ALLOWLISTED).unwrap();
    assert_eq!(
        fs::metadata(&locks).unwrap().permissions().mode() & 0o777,
        0o700,
        "a missing directory is created private"
    );
}

#[test]
fn a_fifo_at_a_lock_path_refuses_without_waiting() {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
    let fixture = Fixture::new(4096);
    let locks = fixture.device_locks();
    drop(DeviceLock::acquire(&locks, "0000:00:1e.0").unwrap());
    let state = fixture.root.join("fifo-owner");
    fs::create_dir_all(&state).unwrap();
    let fifos = [locks.join(format!("{BDF}.lock")), state.join("bind.lock")];
    for fifo in &fifos {
        let path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: `path` is a NUL-terminated string that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    }
    let acquire = || {
        [
            DeviceLock::acquire(&locks, BDF).map(drop),
            OwnerLock::acquire(&state).map(drop),
        ]
    };
    for result in acquire() {
        assert_eq!(
            result.map_err(|error| error.raw_os_error()),
            Err(Some(libc::ENXIO)),
            "a write-only open of a FIFO without a reader fails at once"
        );
    }
    let readers = fifos.each_ref().map(|fifo| {
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(fifo)
            .unwrap()
    });
    for result in acquire() {
        assert_eq!(
            result.map_err(|error| error.kind()),
            Err(io::ErrorKind::PermissionDenied),
            "an opened FIFO is refused as a non-regular lock entry"
        );
    }
    drop(readers);
    for fifo in &fifos {
        assert!(fs::symlink_metadata(fifo).unwrap().file_type().is_fifo());
    }
}

/// A regular file where the device lock directory belongs fails the lock
/// with the directory creation's `AlreadyExists`, before any driver write
/// or record.
#[test]
fn a_file_in_place_of_the_device_lock_directory_fails_with_its_creation_error() {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    let locks = fixture.device_locks();
    fs::create_dir_all(locks.parent().unwrap()).unwrap();
    fs::write(&locks, "").unwrap();
    let result = bind_volume(&binder, VOLUME, ALLOWLISTED);
    assert!(
        matches!(&result, Err(BindError::Lock(error)) if error.kind() == io::ErrorKind::AlreadyExists),
        "{result:?}"
    );
    assert!(untouched(&binder), "no driver write");
    assert!(!mappings_path(&fixture.state_dir()).exists());
}

#[test]
fn a_state_dir_under_a_shared_directory_is_refused_at_that_directory() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new(4096);
    let shared = fixture.root.join("shared");
    let state_dir = shared.join("run");
    fs::create_dir_all(&state_dir).unwrap();
    let shared = fs::canonicalize(&shared).unwrap();
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
    // SAFETY: reads the effective user ID.
    let owner = unsafe { libc::geteuid() };
    assert_eq!(private_state_dir(&state_dir, owner), Err(shared));
}

#[test]
fn a_state_dir_reached_through_a_link_in_a_shared_directory_is_refused_there() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new(4096);
    let private = fixture.root.join("private").join("run");
    fs::create_dir_all(&private).unwrap();
    let shared = fixture.root.join("shared");
    fs::create_dir(&shared).unwrap();
    symlink(&private, shared.join("run")).unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
    // SAFETY: reads the effective user ID.
    let owner = unsafe { libc::geteuid() };
    assert_eq!(
        private_state_dir(&shared.join("run"), owner),
        Err(fs::canonicalize(&shared).unwrap())
    );
}

/// A link on the way to the state directory that sits in a directory other
/// users can write is refused there, also when the path reaches it through
/// an earlier link (`private_state_dir`: only root or the owner can "retarget
/// a link on the way to it"). The given path is a link in a private
/// directory to `shared/hop`, itself a link to the private state directory.
/// The check refuses a shared temporary directory, so the fixture goes under
/// a private directory below the home directory, and the only directory on
/// either path that other users can write is `shared`.
#[test]
fn a_state_dir_reached_through_a_second_link_in_a_shared_directory_is_refused_there() {
    use std::os::unix::fs::PermissionsExt;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = std::env::var_os("HOME")
        .map_or_else(
            || std::env::current_dir().unwrap(),
            std::path::PathBuf::from,
        )
        .join(".tmp/kestrike-binder-tests");
    // SAFETY: reads the effective user ID.
    let owner = unsafe { libc::geteuid() };
    let root = base.join(format!("second-link-{}-{nanos}", std::process::id()));
    prepare_state_dir(&root, owner).unwrap();
    let private = root.join("private");
    let run = private.join("run");
    fs::create_dir_all(&run).unwrap();
    let shared = root.join("shared");
    fs::create_dir(&shared).unwrap();
    symlink(&run, shared.join("hop")).unwrap();
    let entry = private.join("entry");
    symlink(shared.join("hop"), &entry).unwrap();
    // Premise: with `shared` still private, both chains and the link pass.
    let premise = private_state_dir(&entry, owner);
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
    let checked = private_state_dir(&entry, owner);
    let refused = fs::canonicalize(&shared).unwrap();
    fs::remove_dir_all(&root).unwrap();
    assert_eq!(premise, Ok(()), "premise: the private fixture passes");
    assert_eq!(checked, Err(refused));
}

#[test]
fn release_fails_when_the_restored_override_cannot_be_read_back() {
    use std::os::unix::fs::PermissionsExt;
    // The readback failure below is a mode bit, which root reads through.
    // SAFETY: reads the effective user ID.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    bind_volume(&binder, VOLUME, ALLOWLISTED).unwrap();
    // The kernel accepts the override write; its readback fails.
    let override_file = fixture.host.pci(BDF).join("driver_override");
    fs::set_permissions(&override_file, fs::Permissions::from_mode(0o200)).unwrap();
    assert!(matches!(
        binder.release(&[]),
        Err(BindError::Step {
            step: "restore",
            ..
        })
    ));
    assert!(mappings_path(&fixture.state_dir()).exists());
    fs::set_permissions(&override_file, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn preparing_a_state_dir_creates_nothing_through_a_shared_directory() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new(4096);
    let private = fixture.root.join("private");
    fs::create_dir(&private).unwrap();
    let shared = fixture.root.join("shared");
    fs::create_dir(&shared).unwrap();
    // Another user plants a link where the operator's path has a missing component.
    symlink(&private, shared.join("state")).unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
    // SAFETY: reads the effective user ID.
    let owner = unsafe { libc::geteuid() };
    let error = prepare_state_dir(&shared.join("state").join("run"), owner).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(
        !private.join("run").exists(),
        "nothing is created where the link points"
    );
}

#[test]
fn bind_refuses_before_any_write_when_the_original_override_cannot_be_read() {
    use std::os::unix::fs::PermissionsExt;
    // The read failure below is a mode bit, which root reads through.
    // SAFETY: reads the effective user ID.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let fixture = Fixture::new(4096);
    let override_file = fixture.host.pci(BDF).join("driver_override");
    fs::set_permissions(&override_file, fs::Permissions::from_mode(0o200)).unwrap();
    let binder = new_binder(&fixture);
    assert!(matches!(
        bind_volume(&binder, VOLUME, ALLOWLISTED),
        Err(BindError::Identity(IdentityError::Attribute(
            "driver_override"
        )))
    ));
    assert!(untouched(&binder));
    assert!(!mappings_path(&fixture.state_dir()).exists());
    fs::set_permissions(&override_file, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn a_relative_state_dir_is_checked_through_the_current_directory() {
    // SAFETY: reads the effective user ID.
    let owner = unsafe { libc::geteuid() };
    // The empty path that ends a relative path's ancestors is the current
    // directory, never a component to refuse.
    assert_ne!(
        private_state_dir(std::path::Path::new("."), owner),
        Err(std::path::PathBuf::new())
    );
}

#[test]
fn a_pid_namespace_other_than_the_initial_one_is_recognized() {
    let fixture = Fixture::new(4096);
    // A fixture file has an ordinary inode, not the initial namespace's.
    fixture.file("proc/self/ns/pid", "");
    assert_eq!(
        fixture
            .host
            .in_initial_pid_namespace()
            .map_err(|e| e.kind()),
        Ok(false)
    );
    // The answer for the real host depends on where the tests run; the probe itself must work.
    assert!(Host::system().in_initial_pid_namespace().is_ok());
}

/// The fixture's IOMMU mode: a guest IOMMU unit, VFIO's no-IOMMU mode off,
/// and a posture without the allowlist.
fn iommu_mode(fixture: &Fixture) -> VfioPosture {
    fs::create_dir(fixture.host.sys.join("class/iommu/dmar0")).unwrap();
    fixture.file(
        "sys/module/vfio/parameters/enable_unsafe_noiommu_mode",
        "N\n",
    );
    VfioPosture {
        allow_no_iommu: false,
    }
}

/// Release refuses with no driver write while a process holds the
/// controller's VFIO group, in no-IOMMU and in IOMMU mode. Once the group
/// is free, release opens the guard before its first write on the group's
/// node, `noiommu-<group>` or `<group>`, and the guard is still open there
/// when the device leaves `vfio-pci`.
#[test]
fn a_held_group_refuses_release_in_either_vfio_mode() {
    for iommu in [false, true] {
        let fixture = Fixture::new(4096);
        let posture = if iommu {
            iommu_mode(&fixture)
        } else {
            ALLOWLISTED
        };
        let binder = new_binder(&fixture);
        bind_volume(&binder, VOLUME, posture).unwrap();
        let name = if iommu {
            group_of(BDF).to_string()
        } else {
            format!("noiommu-{}", group_of(BDF))
        };
        let node = fixture.host.dev.join("vfio").join(name);
        let writes = binder.kernel.writes.borrow().len();
        fixture.hold(&node);
        assert!(matches!(binder.release(&[]), Err(BindError::VfioInUse)));
        assert_eq!(binder.kernel.writes.borrow().len(), writes, "no write");
        assert_eq!(observed(&fixture, BDF).0.as_deref(), Some("vfio-pci"));
        fixture.unhold(&node);
        binder.kernel.group_opens.borrow_mut().clear();
        binder.release(&[]).unwrap();
        assert_eq!(
            *binder.kernel.group_opens.borrow(),
            [(node, writes)],
            "the guard opens before release's first write"
        );
        assert_eq!(
            *binder.kernel.guarded_unbinds.borrow(),
            [true],
            "the guard is open on its node at the unbind"
        );
        assert_eq!(observed(&fixture, BDF).0.as_deref(), Some("nvme"));
    }
}

/// A guard that cannot be verified refuses release with no driver write:
/// an unreadable or non-numeric IOMMU group; sysfs naming neither or both
/// group devices, or a malformed or unreadable device number; a missing
/// node, a regular file, or another character device in its place; a
/// failed status request; and a group not viable or already in a
/// container. Release succeeds once the group checks out.
#[test]
fn an_unverifiable_group_guard_refuses_release() {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    bind_volume(&binder, VOLUME, ALLOWLISTED).unwrap();
    let group = group_of(BDF);
    let class = fixture.host.sys.join("class/vfio");
    let node = fixture.host.dev.join(format!("vfio/noiommu-{group}"));
    let link = fixture.host.pci(BDF).join("iommu_group");
    let target = fs::read_link(&link).unwrap();
    let writes = binder.kernel.writes.borrow().len();
    let refuses = |step: &str| {
        let refused = binder.release(&[]);
        assert!(
            matches!(&refused, Err(BindError::VfioGroup(at)) if *at == step),
            "{step}: {refused:?}"
        );
        assert_eq!(binder.kernel.writes.borrow().len(), writes, "{step}");
    };
    fs::remove_file(&link).unwrap();
    refuses("group");
    symlink("../iommu_groups/abc", &link).unwrap();
    refuses("group");
    fs::remove_file(&link).unwrap();
    symlink(&target, &link).unwrap();

    let named = class.join(format!("noiommu-{group}"));
    fs::rename(&named, class.join("absent")).unwrap();
    refuses("node");
    fs::rename(class.join("absent"), &named).unwrap();
    fixture.file(&format!("sys/class/vfio/{group}/dev"), "1:3\n");
    refuses("node");
    fs::remove_dir_all(class.join(group.to_string())).unwrap();
    fs::write(named.join("dev"), "one:three\n").unwrap();
    refuses("node");
    fs::remove_file(named.join("dev")).unwrap();
    fs::create_dir(named.join("dev")).unwrap();
    refuses("node");
    fs::remove_dir(named.join("dev")).unwrap();
    fs::write(named.join("dev"), "1:3\n").unwrap();

    fs::remove_file(&node).unwrap();
    refuses("node");
    fs::write(&node, "").unwrap();
    refuses("node");
    fs::remove_file(&node).unwrap();
    symlink("/dev/zero", &node).unwrap();
    refuses("node");
    fs::remove_file(&node).unwrap();
    symlink("/dev/null", &node).unwrap();

    for flags in [None, Some(0), Some(VIABLE | CONTAINER_SET)] {
        binder.kernel.group_status.replace(flags);
        refuses("status");
    }
    binder.kernel.group_status.replace(Some(VIABLE));
    binder.release(&[]).unwrap();
    assert_eq!(observed(&fixture, BDF).0.as_deref(), Some("nvme"));
}

/// Release checks the running kernel and the loaded VFIO modules against
/// the recorded manifest before any driver write: a missing configuration,
/// an IOMMU class that cannot select the VFIO backend, another release, a
/// configuration whose digest differs, and an approved module loaded with
/// another `srcversion` refuse.
#[test]
fn release_refuses_a_running_kernel_the_record_does_not_approve() {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    bind_volume(&binder, VOLUME, ALLOWLISTED).unwrap();
    let writes = binder.kernel.writes.borrow().len();
    let config = fixture.root.join(format!("boot/config-{RELEASE}"));
    let approved = fs::read_to_string(&config).unwrap();
    type Edit = (fn(&Fixture), fn(&Fixture), WcError);
    let edits: [Edit; 5] = [
        (
            |f| fs::remove_file(f.root.join(format!("boot/config-{RELEASE}"))).unwrap(),
            |_| {},
            WcError::Kernel,
        ),
        (
            |f| {
                let class = f.host.sys.join("class/iommu");
                fs::remove_dir(&class).unwrap();
                fs::write(&class, "").unwrap();
            },
            |f| {
                let class = f.host.sys.join("class/iommu");
                fs::remove_file(&class).unwrap();
                fs::create_dir(&class).unwrap();
            },
            WcError::Interface("iommu"),
        ),
        (
            |f| f.file("proc/sys/kernel/osrelease", "6.1.0-other\n"),
            |f| f.file("proc/sys/kernel/osrelease", &format!("{RELEASE}\n")),
            WcError::Kernel,
        ),
        (
            |f| f.file(&format!("boot/config-{RELEASE}"), "CONFIG_IOMMUFD=y\n"),
            |_| {},
            WcError::Kernel,
        ),
        (
            |f| f.file("sys/module/vfio_pci/srcversion", "0000\n"),
            |f| f.file("sys/module/vfio_pci/srcversion", &format!("{SRCVERSION}\n")),
            WcError::Loaded("vfio_pci".into()),
        ),
    ];
    for (edit, undo, expected) in edits {
        edit(&fixture);
        let refused = binder.release(&[]);
        assert!(
            matches!(&refused, Err(BindError::Wc(error)) if *error == expected),
            "{refused:?}"
        );
        assert_eq!(binder.kernel.writes.borrow().len(), writes);
        undo(&fixture);
        fs::write(&config, &approved).unwrap();
    }
    binder.release(&[]).unwrap();
}

/// A recorded device release found unbound, and so did not guard, that
/// another actor binds to `vfio-pci` before its restore is refused with
/// `Changed` and no write for it: release unbinds from `vfio-pci` only the
/// devices whose group it holds. The record stays for a retry.
#[test]
fn release_unbinds_from_vfio_pci_only_a_device_it_guards() {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    bind_eni(&binder, Some(VOLUME), &FakeMetadata::new()).unwrap();
    let pci = fixture.host.pci(ENI_BDF);
    binder
        .kernel
        .write(&pci.join("driver/unbind"), ENI_BDF)
        .unwrap();
    assert_eq!(observed(&fixture, ENI_BDF).0, None);
    let host = fixture.host.clone();
    binder.kernel.after_write.replace(Some((
        "nvme/bind",
        Box::new(move || {
            let probe = FakeKernel::new(&host);
            probe.write(&host.bind_file("vfio-pci"), ENI_BDF).unwrap();
        }),
    )));
    let writes = binder.kernel.writes.borrow().len();
    assert!(matches!(binder.release(&[]), Err(BindError::Changed)));
    assert!(
        binder.kernel.writes.borrow()[writes..]
            .iter()
            .all(|(path, value)| !path.contains(ENI_BDF) && value != ENI_BDF),
        "no write for the unguarded device"
    );
    assert_eq!(observed(&fixture, ENI_BDF).0.as_deref(), Some("vfio-pci"));
    assert_eq!(observed(&fixture, BDF).0.as_deref(), Some("nvme"));
    assert!(mappings_path(&fixture.state_dir()).exists());
    binder.release(&[]).unwrap();
    assert_eq!(observed(&fixture, ENI_BDF).0.as_deref(), Some("ena"));
}

/// Release reads a recorded device's driver from the name its `driver` link
/// ends in. A link whose name is outside UTF-8 names a driver release cannot
/// read, which is neither `vfio-pci`, the original driver nor none, so
/// release refuses before any write and keeps the record, as it does for the
/// same device on a third driver it can name. The control releases the
/// binding left on `vfio-pci`.
#[test]
fn release_refuses_a_recorded_device_whose_driver_name_it_cannot_read() {
    use std::os::unix::ffi::OsStrExt;
    let unreadable = std::ffi::OsStr::from_bytes(b"stub\xff");
    for third in [
        Some(std::ffi::OsStr::new("pci-stub")),
        Some(unreadable),
        None,
    ] {
        let fixture = Fixture::new(4096);
        bind_volume(&new_binder(&fixture), VOLUME, ALLOWLISTED).unwrap();
        let link = fixture.host.pci(BDF).join("driver");
        if let Some(third) = third {
            let driver = fixture.host.sys.join("bus/pci/drivers").join(third);
            fs::create_dir_all(&driver).unwrap();
            fs::remove_file(&link).unwrap();
            std::os::unix::fs::symlink(&driver, &link).unwrap();
        }
        let binder = new_binder(&fixture);
        let released = binder.release(&[]);
        let Some(third) = third else {
            released.unwrap();
            assert_eq!(observed(&fixture, BDF).0.as_deref(), Some("nvme"));
            continue;
        };
        assert!(
            untouched(&binder),
            "{third:?}: release wrote {:?} and returned {released:?}",
            binder.kernel.writes.borrow()
        );
        assert!(released.is_err(), "{third:?}");
        assert_eq!(fs::read_link(&link).unwrap().file_name(), Some(third));
        assert!(mappings_path(&fixture.state_dir()).exists(), "{third:?}");
    }
}

/// The sibling for a `driver` entry release cannot read as a link: a read
/// error other than absence leaves the driver unknown, so release refuses
/// `NotRecorded` before any write and keeps the record. The premise is that
/// the entry exists and fails `read_link` with another error than
/// `NotFound`.
#[test]
fn release_refuses_a_recorded_device_whose_driver_link_it_cannot_read() {
    let fixture = Fixture::new(4096);
    bind_volume(&new_binder(&fixture), VOLUME, ALLOWLISTED).unwrap();
    let link = fixture.host.pci(BDF).join("driver");
    fs::remove_file(&link).unwrap();
    fs::write(&link, "vfio-pci\n").unwrap();
    let error = fs::read_link(&link).unwrap_err();
    assert_ne!(error.kind(), io::ErrorKind::NotFound, "{error}");
    let binder = new_binder(&fixture);
    let released = binder.release(&[]);
    assert!(
        untouched(&binder),
        "release wrote {:?} and returned {released:?}",
        binder.kernel.writes.borrow()
    );
    assert!(
        matches!(released, Err(BindError::NotRecorded(_))),
        "{released:?}"
    );
    assert!(mappings_path(&fixture.state_dir()).exists());
}

/// A missing or zero MTU and a `brd` without a valid address
/// refuse the ENI's bind before any driver write or record.
#[test]
fn an_unrecordable_mtu_or_broadcast_address_refuses_before_any_write() {
    type Edit = (fn(&Fixture, &FakeKernel), EniError);
    let edits: [Edit; 3] = [
        (
            |f, _| fs::remove_file(f.host.sys.join("class/net/ens6/mtu")).unwrap(),
            EniError::Unverifiable("mtu"),
        ),
        (
            |f, _| f.file("sys/class/net/ens6/mtu", "0\n"),
            EniError::Unverifiable("mtu"),
        ),
        (
            |_, kernel| {
                kernel.outputs.borrow_mut().insert(
                    "ip -4 -o addr show dev ens6".into(),
                    Some("3: ens6    inet 10.0.1.5/24 brd 10.0.1 scope global ens6\n".into()),
                );
            },
            EniError::Unverifiable("addresses"),
        ),
    ];
    for (edit, expected) in edits {
        let fixture = Fixture::new(4096);
        let binder = new_binder(&fixture);
        edit(&fixture, &binder.kernel);
        let refused = bind_eni(&binder, Some(VOLUME), &FakeMetadata::new());
        assert!(
            matches!(&refused, Err(BindError::Eni(error)) if *error == expected),
            "{refused:?}"
        );
        assert!(untouched(&binder));
        assert!(!mappings_path(&fixture.state_dir()).exists());
    }
}

#[test]
fn an_eni_amazon_ec2_net_utils_policy_routes_refuses_before_any_write() {
    let main = "10.0.1.0/24 proto kernel scope link src 10.0.1.5 metric 1003\n";
    let table = "default via 10.0.1.1 table 10001 proto dhcp metric 513\n\
                 10.0.1.0/24 table 10001 proto static scope link\n";
    let defaults = "0:\tfrom all lookup local\n32766:\tfrom all lookup main\n32767:\tfrom all lookup default\n";
    let rule = "10001:\tfrom 10.0.1.5 lookup 10001 proto static\n";
    for (routes, rules, expected) in [
        (
            format!("{main}{table}"),
            format!("{defaults}{rule}"),
            "routes",
        ),
        (main.to_owned(), format!("{defaults}{rule}"), "rules"),
    ] {
        let fixture = Fixture::new(4096);
        let binder = new_binder(&fixture);
        let mut outputs = binder.kernel.outputs.borrow_mut();
        outputs.insert(
            "ip -4 -o route show table all dev ens6".into(),
            Some(routes),
        );
        outputs.insert("ip -4 -o rule show".into(), Some(rules));
        drop(outputs);
        let refused = bind_eni(&binder, Some(VOLUME), &FakeMetadata::new());
        assert!(
            matches!(&refused, Err(BindError::Eni(EniError::Unverifiable(detail))) if *detail == expected),
            "{refused:?}"
        );
        assert!(untouched(&binder));
        assert!(!mappings_path(&fixture.state_dir()).exists());
    }
}

#[test]
fn an_eni_network_state_changed_between_the_checks_refuses_the_move() {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    let mtu = fixture.host.sys.join("class/net/ens6/mtu");
    binder.kernel.after_write.replace(Some((
        "vfio-pci/bind",
        Box::new(move || fs::write(&mtu, "1500\n").unwrap()),
    )));
    let refused = bind_eni(&binder, Some(VOLUME), &FakeMetadata::new());
    assert!(matches!(refused, Err(BindError::Changed)), "{refused:?}");
    assert_eq!(
        observed(&fixture, BDF),
        (Some("nvme".into()), None),
        "the moved controller is restored"
    );
    assert_eq!(observed(&fixture, ENI_BDF), (Some("ena".into()), None));
    assert!(!mappings_path(&fixture.state_dir()).exists());
}

/// Release sets the recorded MTU, here 1500, before the link state and the
/// addresses; a failed MTU restore keeps the record with the controller
/// restored, and the retry completes.
#[test]
fn release_restores_the_recorded_mtu_first_and_keeps_the_record_on_failure() {
    let fixture = Fixture::new(4096);
    fixture.file("sys/class/net/ens6/mtu", "1500\n");
    let binder = new_binder(&fixture);
    let mappings = bind_eni(&binder, Some(VOLUME), &FakeMetadata::new()).unwrap();
    assert_eq!(mappings.eni.as_ref().unwrap().net.mtu.get(), 1500);
    let step = "ip link set dev if6 mtu 1500".to_owned();
    binder
        .kernel
        .outputs
        .borrow_mut()
        .insert(step.clone(), None);
    binder.kernel.runs.borrow_mut().clear();
    assert!(matches!(
        binder.release(&[]),
        Err(BindError::Step {
            step: "network",
            ..
        })
    ));
    assert_eq!(
        binder.kernel.runs.borrow().last(),
        Some(&step),
        "the network replay stops at the MTU"
    );
    assert!(mappings_path(&fixture.state_dir()).exists());
    assert_eq!(observed(&fixture, BDF).0.as_deref(), Some("nvme"));
    binder.kernel.outputs.borrow_mut().remove(&step);
    binder.kernel.runs.borrow_mut().clear();
    binder.release(&[]).unwrap();
    assert_eq!(
        binder.kernel.runs.borrow()[1..4],
        [
            step,
            "ip link set dev if6 up".to_owned(),
            "ip addr replace 10.0.1.5/24 brd 10.0.1.255 metric 1003 dev if6".to_owned(),
        ]
    );
    assert!(!mappings_path(&fixture.state_dir()).exists());
}

/// A host with IPv6 disabled, whose `ip` fails every IPv6 route and rule
/// read, binds the ENI: the capture reads the link line alone.
#[test]
fn a_bind_on_a_host_without_ipv6_admits_the_eni() {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    assert!(!fixture.root.join("proc/net/if_inet6").exists());
    let mut outputs = binder.kernel.outputs.borrow_mut();
    outputs.insert("ip -6 -o route show table all dev ens6".into(), None);
    outputs.insert("ip -6 -o rule show".into(), None);
    drop(outputs);
    let bound = bind_eni(&binder, Some(VOLUME), &FakeMetadata::new());
    assert!(bound.is_ok(), "{bound:?}");
}

/// Replaces the fixture ENI's neighbor entries with a reachable peer and a
/// stale gateway, so a bind that reached its next hops would remove the
/// gateway's entry and solicit it.
pub(super) fn stale_gateway(fixture: &Fixture) {
    fixture.file(
        "neigh/ens6",
        &(neighbor_entry("10.0.1.9", Some("0a:00:00:00:01:09"), "REACHABLE")
            + &neighbor_entry("10.0.1.1", Some("0a:00:00:00:01:01"), "STALE")),
    );
}

/// Whether the binder's kernel saw no neighbor removal and no solicitation.
pub(super) fn neighbors_untouched(binder: &Binder<FakeKernel>) -> bool {
    binder.kernel.solicits.borrow().is_empty()
        && !binder
            .kernel
            .runs
            .borrow()
            .iter()
            .any(|run| run.contains("neigh flush"))
}

/// Runs `edit` between the ENI's two checks, on the binder's thread: the
/// fixture's neighbor file holds no gateway entry, so the bind's next-hop
/// resolution, which runs between the checks, solicits the gateway and
/// settles, and `edit` runs at that settle, after the first check read the
/// device's network state and before the second check reads it again.
pub(super) fn between_checks(
    fixture: &Fixture,
    binder: &Binder<FakeKernel>,
    edit: impl FnOnce() + 'static,
) {
    fixture.file(
        "neigh/ens6",
        &neighbor_entry("10.0.1.9", Some("0a:00:00:00:01:09"), "REACHABLE"),
    );
    binder
        .kernel
        .answers
        .borrow_mut()
        .insert(Ipv4Addr::new(10, 0, 1, 1), "0a:00:00:00:01:01");
    binder.kernel.on_settle.borrow_mut().push(Box::new(edit));
}

/// Binds the fixture's ENI alone through `metadata`.
fn bind_eni_through(
    binder: &Binder<FakeKernel>,
    metadata: &dyn super::metadata::Metadata,
) -> Result<Mappings, BindError> {
    let manifest = Fixture::manifest_of(&binder.host);
    binder.bind(&BindRequest {
        volume: None,
        eni: Some(EniRequest {
            id: ENI,
            peers: &PEERS,
            metadata,
        }),
        posture: ALLOWLISTED,
        wc: &manifest,
        others: &[],
    })
}

const SHOW_ADDR: &str = "ip -4 -o addr show dev ens6";
const SHOW_ROUTE: &str = "ip -4 -o route show table all dev ens6";

/// The ENI's second check refuses with `Changed`, writing no driver
/// attribute and leaving no record, when its addresses, broadcast address,
/// routes, link state or MTU changed after the first; reordered addresses
/// and routes, a lease countdown that moved, a route the kernel marks
/// `linkdown` and a carrier flag that changed still bind.
#[test]
fn the_eni_s_second_check_refuses_a_changed_network_state() {
    let two = format!("{ENS6_ADDRESS}3: ens6    inet 10.0.1.6/24 scope global secondary ens6\n");
    let two_reordered = format!(
        "3: ens6    inet 10.0.1.6/24 scope global secondary ens6\n{}",
        ENS6_ADDRESS.replace("3000sec", "2990sec")
    );
    let routes =
        "10.0.1.0/24 proto kernel scope link src 10.0.1.5 metric 1003\n10.9.0.0/16 via 10.0.1.1\n";
    let routes_reordered = "10.9.0.0/16 via 10.0.1.1 linkdown\n10.0.1.0/24 proto kernel scope link src 10.0.1.5 metric 1003\n";
    let bind_seeing = |addresses: [String; 2], second_routes: &str| {
        let fixture = Fixture::new(4096);
        let binder = new_binder(&fixture);
        let mut queued = binder.kernel.queued.borrow_mut();
        queued.insert(SHOW_ADDR.into(), addresses.map(Some).into());
        queued.insert(
            SHOW_ROUTE.into(),
            [Some(routes.to_owned()), Some(second_routes.to_owned())].into(),
        );
        drop(queued);
        let bound = bind_eni_through(&binder, &FakeMetadata::new());
        (fixture, binder, bound)
    };
    let (_, _, bound) = bind_seeing([two.clone(), two_reordered], routes_reordered);
    assert!(bound.is_ok(), "{bound:?}");
    let removed = routes.lines().next().unwrap().to_owned() + "\n";
    let ip_cases = [
        ("an added address", [ENS6_ADDRESS.into(), two], routes),
        (
            "a changed broadcast address",
            [
                ENS6_ADDRESS.into(),
                ENS6_ADDRESS.replace("brd 10.0.1.255", "brd 10.0.1.254"),
            ],
            routes,
        ),
        (
            "a removed route",
            [ENS6_ADDRESS.into(), ENS6_ADDRESS.into()],
            removed.as_str(),
        ),
        (
            "the metadata's address replaced",
            [
                ENS6_ADDRESS.into(),
                "3: ens6    inet 10.0.1.6/24 scope global ens6\n".into(),
            ],
            routes,
        ),
    ];
    for (case, addresses, second_routes) in ip_cases {
        let (fixture, binder, bound) = bind_seeing(addresses, second_routes);
        assert!(
            matches!(bound, Err(BindError::Changed)),
            "{case}: {bound:?}"
        );
        assert!(untouched(&binder), "{case}");
        assert!(!mappings_path(&fixture.state_dir()).exists(), "{case}");
    }
    type Edit = fn(&Path);
    let file_cases: [(&str, Edit); 2] = [
        ("the link set down", |sys| {
            fs::write(sys.join("class/net/ens6/flags"), "0x1002\n").unwrap();
        }),
        ("another MTU", |sys| {
            fs::write(sys.join("class/net/ens6/mtu"), "1500\n").unwrap();
        }),
    ];
    for (case, edit) in file_cases {
        let fixture = Fixture::new(4096);
        let binder = new_binder(&fixture);
        let sys = fixture.host.sys.clone();
        between_checks(&fixture, &binder, move || edit(&sys));
        let bound = bind_eni_through(&binder, &FakeMetadata::new());
        assert!(
            matches!(bound, Err(BindError::Changed)),
            "{case}: {bound:?}"
        );
        assert!(untouched(&binder), "{case}");
        assert!(!mappings_path(&fixture.state_dir()).exists(), "{case}");
    }
    // `IFF_RUNNING` follows the carrier; the link stays administratively up.
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    let flags = fixture.host.sys.join("class/net/ens6/flags");
    between_checks(&fixture, &binder, move || {
        fs::write(flags, "0x1043\n").unwrap()
    });
    let bound = bind_eni_through(&binder, &FakeMetadata::new());
    assert!(bound.is_ok(), "a carrier flag: {bound:?}");
}

/// The second check repeats the first's refusals: a global IPv6 address, a
/// default route or a master added after the first check, or a network
/// state the second read cannot get, refuses with its own error and no
/// driver write.
#[test]
fn the_eni_s_second_check_repeats_its_refusals() {
    type Edit = fn(&Host);
    type Expected = fn(&BindError) -> bool;
    let cases: [(Edit, Expected); 4] = [
        (
            |host| {
                fs::write(
                    host.proc.join("net/if_inet6"),
                    "20010db8000000000000000000000005 03 40 00 80 ens6\n",
                )
                .unwrap()
            },
            |e| matches!(e, BindError::Eni(EniError::Unverifiable("ipv6"))),
        ),
        (
            |host| {
                let path = host.proc.join("net/route");
                let route = fs::read_to_string(&path).unwrap();
                fs::write(
                    path,
                    format!("{route}ens6\t00000000\t0101000A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"),
                )
                .unwrap();
            },
            |e| matches!(e, BindError::Eni(EniError::Management)),
        ),
        (
            |host| {
                symlink(
                    host.sys.join("class/net/ens5"),
                    host.sys.join("class/net/ens6/master"),
                )
                .unwrap()
            },
            |e| matches!(e, BindError::Eni(EniError::Unverifiable("master"))),
        ),
        (
            |host| fs::write(host.sys.join("class/net/ens6/flags"), "flags\n").unwrap(),
            |e| matches!(e, BindError::Eni(EniError::Unverifiable("flags"))),
        ),
    ];
    for (edit, expected) in cases {
        let fixture = Fixture::new(4096);
        let binder = new_binder(&fixture);
        let host = fixture.host.clone();
        between_checks(&fixture, &binder, move || edit(&host));
        let refused = bind_eni_through(&binder, &FakeMetadata::new()).unwrap_err();
        assert!(expected(&refused), "{refused:?}");
        assert!(untouched(&binder));
        assert!(!mappings_path(&fixture.state_dir()).exists());
    }
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    binder
        .kernel
        .queued
        .borrow_mut()
        .insert(SHOW_ADDR.into(), [Some(ENS6_ADDRESS.into()), None].into());
    let refused = bind_eni_through(&binder, &FakeMetadata::new()).unwrap_err();
    assert!(
        matches!(refused, BindError::Eni(EniError::Unverifiable("ip"))),
        "{refused:?}"
    );
    assert!(untouched(&binder));
    assert!(!mappings_path(&fixture.state_dir()).exists());
}

/// The metadata must list exactly one valid IPv4 address for the ENI, inside
/// its subnet and on its device: none, two, a malformed one, one outside the
/// subnet and one the device lacks each refuse at the first check, before
/// any driver write and any record, the controller's too in a combined bind.
#[test]
fn the_eni_s_sole_metadata_address_must_be_on_its_device_and_subnet() {
    let path = "network/interfaces/macs/0a:11:22:33:44:55/local-ipv4s";
    let eni_only = [
        "",
        "10.0.1.5\n10.0.1.6\n",
        "10.0.1.x",
        "10.0.2.5",
        "10.0.1.8",
    ]
    .map(|a| (a, None));
    let combined = ["10.0.1.x", "10.0.1.8"].map(|a| (a, Some(VOLUME)));
    for (addresses, volume) in eni_only.into_iter().chain(combined) {
        let fixture = Fixture::new(4096);
        let binder = new_binder(&fixture);
        // The device carries the second listed address and the
        // out-of-subnet one too, so only the count and the subnet checks
        // refuse them.
        binder.kernel.outputs.borrow_mut().insert(
            SHOW_ADDR.into(),
            Some(format!(
                "{ENS6_ADDRESS}3: ens6    inet 10.0.1.6/24 scope global ens6\n3: ens6    inet 10.0.2.5/24 scope global ens6\n"
            )),
        );
        let metadata = FakeMetadata::new();
        metadata
            .0
            .lock()
            .unwrap()
            .insert(path.into(), addresses.into());
        let manifest = Fixture::manifest_of(&binder.host);
        let refused = binder
            .bind(&BindRequest {
                volume,
                eni: Some(EniRequest {
                    id: ENI,
                    peers: &PEERS,
                    metadata: &metadata,
                }),
                posture: ALLOWLISTED,
                wc: &manifest,
                others: &[],
            })
            .unwrap_err();
        assert!(
            matches!(refused, BindError::Eni(EniError::Attribute("local-ipv4s"))),
            "{addresses:?}: {refused:?}"
        );
        assert!(untouched(&binder), "{addresses:?} {volume:?}");
        assert!(!mappings_path(&fixture.state_dir()).exists());
    }
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    let metadata = FakeMetadata::new();
    metadata
        .0
        .lock()
        .unwrap()
        .insert(path.into(), "10.0.1.5\n".into());
    assert!(
        bind_eni_through(&binder, &metadata).is_ok(),
        "a trailing newline"
    );
}

/// In a combined bind the controller moves before the ENI's second check; a
/// changed ENI refuses with no ENI driver write, the controller is restored
/// under the lock the bind holds and the record removed, and a restore that
/// fails keeps the record and reports `Unrestored`.
#[test]
fn a_combined_bind_refused_by_the_eni_restores_the_controller() {
    for restore_fails in [false, true] {
        let fixture = Fixture::new(4096);
        let binder = new_binder(&fixture);
        let sys = fixture.host.sys.clone();
        between_checks(&fixture, &binder, move || {
            fs::write(sys.join("class/net/ens6/mtu"), "1500\n").unwrap()
        });
        let metadata = FakeMetadata::new();
        let probe = std::rc::Rc::new(std::cell::RefCell::new(None));
        if restore_fails {
            binder.kernel.fail.replace(Some("nvme/bind"));
        } else {
            let (locks, keep) = (fixture.device_locks(), probe.clone());
            binder.kernel.after_write.replace(Some((
                "nvme/bind",
                Box::new(move || {
                    *keep.borrow_mut() =
                        Some(DeviceLock::acquire(&locks, BDF).map_err(|error| error.kind()));
                }),
            )));
        }
        let manifest = Fixture::manifest_of(&binder.host);
        let refused = binder.bind(&BindRequest {
            volume: Some(VOLUME),
            eni: Some(EniRequest {
                id: ENI,
                peers: &PEERS,
                metadata: &metadata,
            }),
            posture: ALLOWLISTED,
            wc: &manifest,
            others: &[],
        });
        assert!(
            binder
                .kernel
                .writes
                .borrow()
                .iter()
                .all(|(path, _)| !path.contains(ENI_BDF)),
            "no ENI driver write"
        );
        assert_eq!(observed(&fixture, ENI_BDF).0.as_deref(), Some("ena"));
        if restore_fails {
            let Err(BindError::Unrestored(errors)) = refused else {
                panic!("a failed restore: {refused:?}");
            };
            assert!(matches!(errors.0, BindError::Changed));
            assert!(mappings_path(&fixture.state_dir()).exists());
        } else {
            assert!(matches!(refused, Err(BindError::Changed)), "{refused:?}");
            assert_eq!(observed(&fixture, BDF).0.as_deref(), Some("nvme"));
            assert!(!mappings_path(&fixture.state_dir()).exists());
            assert!(
                matches!(
                    probe.borrow_mut().take(),
                    Some(Err(std::io::ErrorKind::WouldBlock))
                ),
                "the rollback restores the controller under the lock the bind holds"
            );
        }
    }
}

/// A guest's emulated controller: QEMU's NVMe model and PCI identity.
const GUEST: ControllerIdentity = ControllerIdentity {
    model: "QEMU NVMe Ctrl",
    pci: (0x1b36, 0x0010),
};

/// The fixture with its volume's controller retyped as [`GUEST`].
fn guest_fixture() -> Fixture {
    let fixture = Fixture::new(4096);
    fixture.file(
        "sys/class/nvme/nvme1/model",
        &format!("{:<40}\n", GUEST.model),
    );
    fixture.file(&format!("sys/bus/pci/devices/{BDF}/vendor"), "0x1b36\n");
    fixture.file(&format!("sys/bus/pci/devices/{BDF}/device"), "0x0010\n");
    fixture
}

fn guest_binder(fixture: &Fixture, controller: ControllerIdentity) -> Binder<FakeKernel> {
    Binder {
        host: fixture.host.clone().expecting(controller),
        ..new_binder(fixture)
    }
}

/// The one identity a test host expects governs both resolution and
/// release: under [`GUEST`] the guest's controller binds and releases
/// through the production binder, and the default EBS identity refuses
/// it before any driver write.
#[test]
fn a_test_identity_binds_and_releases_the_controller_the_default_identity_refuses() {
    let fixture = guest_fixture();
    assert_eq!(fixture.host.resolve(VOLUME), Err(IdentityError::NotEbs));
    let default = new_binder(&fixture);
    assert!(matches!(
        bind_volume(&default, VOLUME, ALLOWLISTED),
        Err(BindError::Identity(IdentityError::NotEbs))
    ));
    assert!(untouched(&default));

    let binder = guest_binder(&fixture, GUEST);
    let mappings = bind_volume(&binder, VOLUME, ALLOWLISTED).unwrap();
    assert_eq!(mappings.nvme.as_ref().unwrap().bdf, BDF);
    assert_eq!(observed(&fixture, BDF).0.as_deref(), Some("vfio-pci"));
    binder.release(&[]).unwrap();
    assert_eq!(observed(&fixture, BDF).0.as_deref(), Some("nvme"));
    assert!(!mappings_path(&fixture.state_dir()).exists());
}

/// Release authorizes each recorded address from the host's current
/// expected identity and the controller's current PCI identity: a host
/// expecting another identity, or a guest controller whose PCI identity
/// changed before release, refuses with `NotRecorded`, keeps the record and
/// leaves every driver unwritten.
#[test]
fn release_requires_the_current_controller_to_match_the_expected_identity() {
    for change in [
        |fixture: &Fixture| guest_binder(fixture, ControllerIdentity::EBS),
        |fixture: &Fixture| {
            fixture.file(&format!("sys/bus/pci/devices/{BDF}/device"), "0x0011\n");
            guest_binder(fixture, GUEST)
        },
    ] {
        let fixture = guest_fixture();
        bind_volume(&guest_binder(&fixture, GUEST), VOLUME, ALLOWLISTED).unwrap();
        let binder = change(&fixture);
        assert!(matches!(
            binder.release(&[]),
            Err(BindError::NotRecorded(_))
        ));
        assert!(untouched(&binder));
        assert!(mappings_path(&fixture.state_dir()).exists());
        assert_eq!(observed(&fixture, BDF).0.as_deref(), Some("vfio-pci"));
    }
}

/// Under the test identity, a controller of another model or PCI identity,
/// or a volume ID matching no controller's serial, resolves to the same
/// refusals the EBS identity gives, and an EBS volume's controller is
/// refused too.
#[test]
fn the_test_identity_refuses_a_wrong_model_pci_identity_or_serial() {
    let host = |fixture: &Fixture| fixture.host.clone().expecting(GUEST);
    let model = guest_fixture();
    model.file("sys/class/nvme/nvme1/model", "QEMU NVMe Ctrl 2\n");
    assert_eq!(host(&model).resolve(VOLUME), Err(IdentityError::NotEbs));
    let vendor = guest_fixture();
    vendor.file(&format!("sys/bus/pci/devices/{BDF}/vendor"), "0x1d0f\n");
    assert_eq!(host(&vendor).resolve(VOLUME), Err(IdentityError::NotEbs));
    let serial = guest_fixture();
    assert_eq!(
        host(&serial).resolve("vol-0123456789abcdef1"),
        Err(IdentityError::NotFound)
    );
    assert!(host(&serial).resolve(VOLUME).is_ok());
    let ebs = Fixture::new(4096);
    assert_eq!(
        host(&ebs).resolve(VOLUME),
        Err(IdentityError::NotEbs),
        "the test identity replaces the EBS identity"
    );
}

/// A record a successful bind writes is one release reads: the bind either
/// refuses a controller at an address outside the mappings reader's
/// canonical spelling before any write, or records it so release restores
/// it. Linux prints a PCI domain above `0xffff` in five hexadecimal digits.
#[test]
fn a_bind_records_only_a_device_address_release_reads_back() {
    const WIDE: &str = "10000:00:1e.0";
    const WIDE_VOLUME: &str = "vol0bbbbbbbbbbbbbbbbb";
    let fixture = Fixture::new(4096);
    fixture.controller("nvme2", WIDE, WIDE_VOLUME, 4096);
    let binder = new_binder(&fixture);
    let path = mappings_path(&fixture.state_dir());
    match bind_volume(&binder, WIDE_VOLUME, ALLOWLISTED) {
        Err(_) => {
            assert!(untouched(&binder), "a refused bind writes no attribute");
            assert!(!path.exists(), "a refused bind leaves no record");
        }
        Ok(mappings) => {
            let read = Mappings::read(&path);
            let released = binder.release(&[]);
            assert!(
                matches!(&read, Ok(found) if *found == mappings) && released.is_ok(),
                "the record the bind wrote reads as {read:?}, release returns {released:?}, \
                 and the controller stays on {:?}",
                observed(&fixture, WIDE)
            );
            assert_eq!(observed(&fixture, WIDE), (Some("nvme".into()), None));
        }
    }
}

/// A process that holds the volume's namespace open moves its descriptor, in
/// each of the bind's two in-use checks, to a partition it adds after that
/// check listed the partitions: in the first, from the namespace to `p2`; in
/// the second, from `p2` through the namespace to `p3`. The namespace is in
/// use at every instant of the bind. Each handoff happens while that check's
/// walk reads the uptime, a FIFO here, before it reads any descriptor table.
#[test]
fn a_volume_handed_to_a_new_partition_during_each_check_is_refused() {
    use std::ffi::CString;
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;
    let fixture = Fixture::new(4096);
    let (dev, block) = (
        fixture.host.dev.clone(),
        fixture.host.sys.join("block/nvme1n1"),
    );
    let table = fixture.host.proc.join("4242/fd");
    fixture.open(4242, &dev.join("nvme1n1"));
    assert_eq!(
        fs::read_link(table.join("3")).unwrap(),
        dev.join("nvme1n1"),
        "premise"
    );
    let uptime = fixture.host.proc.join("uptime");
    let fifo = |path: &Path| {
        let _ = fs::remove_file(path);
        let text = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `text` is a NUL-terminated string that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(text.as_ptr(), 0o600) }, 0);
    };
    fifo(&uptime);
    let writer = {
        let uptime = uptime.clone();
        std::thread::spawn(move || {
            let add = |partition: &str| {
                fs::create_dir_all(block.join(partition).join("holders")).unwrap();
                fs::write(dev.join(partition), "").unwrap();
            };
            let first = fs::OpenOptions::new().write(true).open(&uptime);
            add("nvme1n1p2");
            symlink(dev.join("nvme1n1p2"), table.join("4")).unwrap();
            fs::remove_file(table.join("3")).unwrap();
            fifo(&uptime);
            drop(first.map(|mut sink| sink.write_all(b"100.00 400.00\n")));
            let second = fs::OpenOptions::new().write(true).open(&uptime);
            symlink(dev.join("nvme1n1"), table.join("5")).unwrap();
            fs::remove_file(table.join("4")).unwrap();
            add("nvme1n1p3");
            symlink(dev.join("nvme1n1p3"), table.join("6")).unwrap();
            fs::remove_file(table.join("5")).unwrap();
            drop(second.map(|mut sink| sink.write_all(b"100.00 400.00\n")));
        })
    };
    let binder = new_binder(&fixture);
    let bound = bind_volume(&binder, VOLUME, ALLOWLISTED).map(drop);
    // A bind that stopped before a walk releases the writer here. The
    // writer replaces the FIFO once, so a reader of each one stays open
    // until the writer ends.
    let mut readers = Vec::new();
    while !writer.is_finished() {
        readers.push(
            fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&uptime),
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
        readers.truncate(64);
    }
    writer.join().unwrap();
    drop(readers);
    fs::remove_file(&uptime).unwrap();
    fs::write(&uptime, "100.00 400.00\n").unwrap();
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1p3".into())),
        "premise: after the handoffs the newest partition alone is found"
    );
    assert!(
        matches!(
            bound,
            Err(BindError::Identity(IdentityError::Unverifiable(
                "partitions"
            )))
        ),
        "a volume in use at every instant of the bind was bound: {bound:?}, driver {:?}",
        observed(&fixture, BDF)
    );
}

/// Release unbinds only a guarded device from `vfio-pci`, and a device on
/// any third driver gets no write. Here another actor moves the
/// guarded ENI onto a third driver after `restore` read it on `vfio-pci`
/// and before its unbind write, which reaches the device's driver at the
/// time of the write. Release must leave the device on the third driver and
/// keep the record. The sibling moves it there and back at the same point,
/// and release restores it.
#[test]
fn release_does_not_unbind_a_guarded_device_moved_onto_a_third_driver_before_its_unbind() {
    assert_eq!(ENI_BDF, "0000:00:06.0");
    let release_with = |back: bool| {
        let fixture = Fixture::new(4096);
        let binder = new_binder(&fixture);
        bind_eni(&binder, Some(VOLUME), &FakeMetadata::new()).unwrap();
        let host = fixture.host.clone();
        binder.kernel.before_write.replace(Some((
            "/unbind=0000:00:06.0",
            Box::new(move || {
                rebind(&host, ENI_BDF, "pci-stub");
                if back {
                    rebind(&host, ENI_BDF, "vfio-pci");
                }
            }),
        )));
        let released = binder.release(&[]);
        let driver = observed(&fixture, ENI_BDF).0;
        let kept = mappings_path(&fixture.state_dir()).exists();
        (released, driver, kept)
    };
    let (released, driver, kept) = release_with(true);
    assert!(released.is_ok(), "{released:?}");
    assert_eq!((driver.as_deref(), kept), (Some("ena"), false));
    let (released, driver, kept) = release_with(false);
    assert!(released.is_err(), "{released:?}");
    assert_eq!(
        (driver.as_deref(), kept),
        (Some("pci-stub"), true),
        "the device another actor bound to a third driver stays there"
    );
}

/// A bind writes the unbind file of the kernel driver its second check
/// confirmed, and its rollback that of `vfio-pci`, so a device that sits
/// on a third driver when either write arrives gets no unbind. Here
/// another actor moves the controller
/// onto a third driver after the second check and before the bind's unbind
/// write. The bind fails at that write, its rollback refuses the device,
/// and the device stays on the third driver with the record kept.
#[test]
fn bind_does_not_unbind_a_device_moved_onto_a_third_driver_before_its_unbind() {
    assert_eq!(BDF, "0000:00:1f.0");
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    let host = fixture.host.clone();
    binder.kernel.before_write.replace(Some((
        "/unbind=0000:00:1f.0",
        Box::new(move || rebind(&host, BDF, "pci-stub")),
    )));
    let bound = bind_volume(&binder, VOLUME, ALLOWLISTED);
    let Err(BindError::Unrestored(causes)) = bound else {
        panic!("a bind that cannot restore the device is unrestored: {bound:?}");
    };
    assert!(
        matches!(
            *causes,
            (BindError::Step { step: "unbind", .. }, BindError::Changed)
        ),
        "{causes:?}"
    );
    assert_eq!(
        observed(&fixture, BDF),
        (Some("pci-stub".into()), Some("pci-stub".into())),
        "the device another actor bound to a third driver stays there"
    );
    assert!(
        mappings_path(&fixture.state_dir()).exists(),
        "an unrestored bind keeps its record"
    );

    // Moved before the bind's override write, the device carries the
    // override the bind wrote over the other actor's. The rollback takes
    // that override back and leaves the device on the third driver.
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    let host = fixture.host.clone();
    binder.kernel.before_write.replace(Some((
        "0000:00:1f.0/driver_override",
        Box::new(move || rebind(&host, BDF, "pci-stub")),
    )));
    let bound = bind_volume(&binder, VOLUME, ALLOWLISTED);
    assert!(matches!(bound, Err(BindError::Unrestored(_))), "{bound:?}");
    assert_eq!(
        observed(&fixture, BDF),
        (Some("pci-stub".into()), None),
        "the override the bind wrote stayed on a device it did not move"
    );
}

/// Moves `bdf` onto `driver` as another actor would, through a kernel of its
/// own: an unbind from its current driver, an override naming `driver`, and
/// a bind.
fn rebind(host: &Host, bdf: &str, driver: &str) {
    let probe = FakeKernel::new(host);
    fs::create_dir_all(host.sys.join("bus/pci/drivers").join(driver)).unwrap();
    if host.driver(bdf).is_some() {
        probe
            .write(&host.pci(bdf).join("driver/unbind"), bdf)
            .unwrap();
    }
    probe
        .write(&host.pci(bdf).join("driver_override"), driver)
        .unwrap();
    probe.write(&host.bind_file(driver), bdf).unwrap();
}

/// A private root and a shared directory, mode `0o777`, that the root
/// reaches through the link `n1`, for a detour that steps out of the root
/// after a missing level. Both sit in a fresh directory below the home
/// directory, since the preparation refuses a shared temporary directory
/// above them.
fn detour_tree(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = std::env::var_os("HOME")
        .map_or_else(
            || std::env::current_dir().unwrap(),
            std::path::PathBuf::from,
        )
        .join(".tmp/kestrike-binder-tests");
    // SAFETY: reads the effective user ID.
    prepare_state_dir(&base, unsafe { libc::geteuid() }).unwrap();
    let scratch = base.join(format!("{tag}-{}-{nanos}", std::process::id()));
    fs::create_dir(&scratch).unwrap();
    let scratch = fs::canonicalize(scratch).unwrap();
    let shared = scratch.join("shared");
    fs::create_dir(&shared).unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
    let root = scratch.join("root");
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    symlink(&shared, root.join("n1")).unwrap();
    (root, shared)
}

/// `root/new/../n1/new/deeper`, whose nearest existing ancestor is the
/// private root, leads its creation through the link into
/// the shared directory. The preparation refuses the shared directory before
/// it creates anything in it, as it does for the plain `root/n1/new/deeper`.
#[test]
fn a_detour_into_a_shared_directory_refuses_before_creating_there() {
    // SAFETY: reads the effective user ID.
    let own = unsafe { libc::geteuid() };
    let (root, shared) = detour_tree("detour");
    for spelling in ["n1/new/deeper", "new/../n1/new/deeper"] {
        let path = std::path::PathBuf::from(format!("{}/{spelling}", root.display()));
        let refused = prepare_state_dir(&path, own).unwrap_err();
        assert_eq!(
            refused.kind(),
            io::ErrorKind::PermissionDenied,
            "{spelling}"
        );
        assert!(
            refused.to_string().contains("shared"),
            "{spelling}: {refused}"
        );
        assert!(
            !shared.join("new").exists(),
            "{spelling}: created inside the shared directory before refusing it"
        );
    }
    fs::remove_dir_all(root.parent().unwrap()).unwrap();
}

/// A link any user may place at `shared/new` would steer a detour's next
/// level into a directory of that user's choosing; the
/// preparation refuses before it reaches the link.
#[test]
fn a_link_in_a_shared_directory_cannot_steer_a_detours_creation() {
    use std::os::unix::fs::DirBuilderExt;
    // SAFETY: reads the effective user ID.
    let own = unsafe { libc::geteuid() };
    let (root, shared) = detour_tree("steer");
    let chosen = root.parent().unwrap().join("chosen");
    fs::DirBuilder::new().mode(0o700).create(&chosen).unwrap();
    symlink(&chosen, shared.join("new")).unwrap();
    let path = std::path::PathBuf::from(format!("{}/new/../n1/new/deeper", root.display()));
    let outcome = prepare_state_dir(&path, own);
    assert!(
        !chosen.join("deeper").exists(),
        "created {} through the shared directory's link, then returned {outcome:?}",
        chosen.join("deeper").display()
    );
    let refused = outcome.unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied, "{refused}");
    assert!(refused.to_string().contains("shared"), "{refused}");
    fs::remove_dir_all(root.parent().unwrap()).unwrap();
}

/// Replaces `path` with a pipe whose reads return `first`, then `vfio-pci` on every later read. Each read is one
/// open of the pipe; the feeder waits for the reader's close before it serves the next, so no read sees two answers.
fn answer_reads(path: &std::path::Path, first: &'static [u8]) {
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    fs::remove_file(path).unwrap();
    // SAFETY: `name` is a NUL-terminated path; the calls keep no pointer.
    let watch = unsafe {
        assert_eq!(libc::mkfifo(name.as_ptr(), 0o600), 0);
        let watch = libc::inotify_init1(libc::IN_CLOEXEC);
        assert!(libc::inotify_add_watch(watch, name.as_ptr(), libc::IN_CLOSE_NOWRITE) >= 0);
        watch
    };
    let path = path.to_owned();
    std::thread::spawn(move || {
        for answer in std::iter::once(first).chain(std::iter::repeat(&b"vfio-pci\n"[..])) {
            // Blocks until a reader opens the pipe; the fixture's removal ends the feeder.
            let Ok(mut pipe) = fs::File::options().write(true).open(&path) else {
                return;
            };
            pipe.write_all(answer).unwrap();
            drop(pipe);
            let mut event = [0u8; 64];
            // SAFETY: reads one close event into a live buffer of the length given.
            assert!(unsafe { libc::read(watch, event.as_mut_ptr().cast(), event.len()) } > 0);
        }
    });
}

/// A release whose restored override cannot be read once and then reads `vfio-pci` fails as the `restore` step and
/// keeps the record: an unreadable override does not establish that a change is safe, so the
/// verification judges the read that failed, not a later one. With every read answering `vfio-pci` the same release
/// fails the same way.
#[test]
fn release_does_not_verify_an_override_it_could_not_read() {
    for first in [&b"\xff\n"[..], &b"vfio-pci\n"[..]] {
        let fixture = Fixture::new(4096);
        let binder = new_binder(&fixture);
        bind_eni(&binder, None, &FakeMetadata::new()).unwrap();
        let override_file = fixture.host.pci(ENI_BDF).join("driver_override");
        binder.kernel.after_write.replace(Some((
            "0000:00:06.0/driver_override=\n",
            Box::new(move || answer_reads(&override_file, first)),
        )));
        let refused = binder.release(&[]);
        assert!(
            matches!(
                refused,
                Err(BindError::Step {
                    step: "restore",
                    error: None,
                    ..
                })
            ),
            "{first:?}: {refused:?}"
        );
        assert!(mappings_path(&fixture.state_dir()).exists(), "{first:?}");
    }
}

/// Bind records the original driver and override, and release restores and verifies them. The kernel keeps
/// a `driver_override` byte for byte up to its first newline, so an override that begins or ends with a space names
/// no driver and the record's trimmed text would name another. Bind refuses such a controller before any write and
/// leaves the override's bytes and no record. The same override without the space binds, and release writes it back.
#[test]
fn bind_refuses_an_override_with_edge_whitespace_before_any_write() {
    let file = format!("sys/bus/pci/devices/{BDF}/driver_override");
    for text in [" nvme\n", "nvme \n", " \n"] {
        let fixture = Fixture::new(4096);
        fixture.file(&file, text);
        let binder = new_binder(&fixture);
        let refused = bind_volume(&binder, VOLUME, ALLOWLISTED);
        assert!(
            matches!(
                refused,
                Err(BindError::Identity(IdentityError::Attribute(
                    "driver_override"
                )))
            ),
            "{text:?}: {refused:?}"
        );
        assert!(untouched(&binder), "{text:?}");
        assert!(!mappings_path(&fixture.state_dir()).exists(), "{text:?}");
        assert_eq!(fs::read_to_string(fixture.root.join(&file)).unwrap(), text);
    }
    let fixture = Fixture::new(4096);
    fixture.file(&file, "nvme\n");
    let binder = new_binder(&fixture);
    let mappings = bind_volume(&binder, VOLUME, ALLOWLISTED).unwrap();
    assert_eq!(
        mappings.nvme.unwrap().original_override.as_deref(),
        Some("nvme")
    );
    binder.release(&[]).unwrap();
    assert_eq!(
        fs::read_to_string(fixture.root.join(&file)).unwrap(),
        "nvme\n"
    );
}

/// `ip -o link show` from iproute2 6.10 on Linux 6.12.115, captured under
/// `unshare -rn`: `d0` at index 2, a VLAN on it, and
/// `d1` at index 3 holding no name of the form `if<N>`.
const LISTING_NONE: &str = "\
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN mode DEFAULT group default qlen 1000\\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: d0: <BROADCAST,NOARP> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000\\    link/ether 1a:11:dc:da:69:8c brd ff:ff:ff:ff:ff:ff
3: d1: <BROADCAST,NOARP> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000\\    link/ether 1e:bb:98:b2:34:31 brd ff:ff:ff:ff:ff:ff
4: d0.5@d0: <BROADCAST,NOARP,M-DOWN> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000\\    link/ether 1a:11:dc:da:69:8c brd ff:ff:ff:ff:ff:ff
";

/// As [`LISTING_NONE`], with `d1` renamed `if2`.
const LISTING_NAMED: &str = "\
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN mode DEFAULT group default qlen 1000\\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: d0: <BROADCAST,NOARP> mtu 1400 qdisc noop state DOWN mode DEFAULT group default qlen 1000\\    link/ether 1a:11:dc:da:69:8c brd ff:ff:ff:ff:ff:ff
3: if2: <BROADCAST,NOARP> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000\\    link/ether 1e:bb:98:b2:34:31 brd ff:ff:ff:ff:ff:ff
4: d0.5@d0: <BROADCAST,NOARP,M-DOWN> mtu 1400 qdisc noop state DOWN mode DEFAULT group default qlen 1000\\    link/ether 1a:11:dc:da:69:8c brd ff:ff:ff:ff:ff:ff
";

/// As [`LISTING_NONE`], with `d1` holding the altnames `x9` and `if2`.
const LISTING_ALTNAMED: &str = "\
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN mode DEFAULT group default qlen 1000\\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: d0: <BROADCAST,NOARP> mtu 1400 qdisc noop state DOWN mode DEFAULT group default qlen 1000\\    link/ether 1a:11:dc:da:69:8c brd ff:ff:ff:ff:ff:ff
3: d1: <BROADCAST,NOARP> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000\\    link/ether 1e:bb:98:b2:34:31 brd ff:ff:ff:ff:ff:ff\\    altname x9\\    altname if2
4: d0.5@d0: <BROADCAST,NOARP,M-DOWN> mtu 1400 qdisc noop state DOWN mode DEFAULT group default qlen 1000\\    link/ether 1a:11:dc:da:69:8c brd ff:ff:ff:ff:ff:ff
";

/// On real `ip` listings, the index word `if2` of `d0` counts as held only
/// when another device holds it as its name or an altname. With no holder,
/// the case the batch resolves by index, the check passes; a device's own
/// name, a VLAN's lower device and a word another device does not hold
/// pass as well.
#[test]
fn an_index_word_counts_as_held_only_by_another_devices_name_or_altname() {
    assert!(!held_elsewhere(LISTING_NONE, "if2", 2));
    assert!(held_elsewhere(LISTING_NAMED, "if2", 2));
    assert!(held_elsewhere(LISTING_ALTNAMED, "if2", 2));
    assert!(!held_elsewhere(LISTING_ALTNAMED, "if2", 3));
    assert!(!held_elsewhere(LISTING_NONE, "d0", 2));
    assert!(held_elsewhere(LISTING_NONE, "d0.5", 2));
    assert!(held_elsewhere(LISTING_ALTNAMED, "x9", 2));
    assert!(held_elsewhere("garbage\n", "if2", 2));
}

/// The VFIO no-IOMMU parameter is read at the fixed sysfs path
/// `module/vfio/parameters/enable_unsafe_noiommu_mode`, and a missing entry
/// is read as a kernel without the parameter, the unsafe mode off. A tmpfs
/// the mount table lists at `/sys/module/vfio/parameters` covers the entry
/// on a host with a guest IOMMU and the unsafe mode on, a contradictory
/// posture, so the parameter's value is unknown and neither posture is
/// established. Without the cover the bind refuses `Posture`.
#[test]
fn a_no_iommu_parameter_under_a_covered_parameter_directory_establishes_no_posture() {
    let bound = |cover: bool| {
        let fixture = Fixture::new(4096);
        fs::create_dir(fixture.host.sys.join("class/iommu/dmar0")).unwrap();
        fixture.file(
            "sys/module/vfio/parameters/enable_unsafe_noiommu_mode",
            "Y\n",
        );
        let mut mounts = String::from("/dev/nvme0n1p1 / xfs rw 0 0\nsysfs /sys sysfs rw 0 0\n");
        if cover {
            let covered = fixture.root.join("sys/module/vfio/parameters");
            fs::remove_dir_all(&covered).unwrap();
            fs::create_dir_all(&covered).unwrap();
            mounts.push_str("tmpfs /sys/module/vfio/parameters tmpfs rw 0 0\n");
        }
        fixture.file("proc/self/mounts", &mounts);
        let binder = new_binder(&fixture);
        let bound = bind_volume(&binder, VOLUME, ALLOWLISTED).map(drop);
        (bound, untouched(&binder))
    };
    assert!(
        matches!(bound(false), (Err(BindError::Posture), true)),
        "premise"
    );
    let (covered, untouched) = bound(true);
    assert!(
        matches!(covered, Err(BindError::Posture)) && untouched,
        "a covered no-IOMMU parameter read as the unsafe mode off: {covered:?}, untouched {untouched}"
    );
}

/// A mount of another type beside the VFIO parameter directory, here a tmpfs
/// at `/sys/module/other`, covers nothing the posture check reads, so a host
/// with a guest IOMMU and the unsafe mode off still binds.
#[test]
fn a_mount_beside_the_no_iommu_parameter_leaves_the_posture_established() {
    let fixture = Fixture::new(4096);
    fs::create_dir(fixture.host.sys.join("class/iommu/dmar0")).unwrap();
    fixture.file(
        "sys/module/vfio/parameters/enable_unsafe_noiommu_mode",
        "N\n",
    );
    fs::create_dir_all(fixture.root.join("sys/module/other")).unwrap();
    fixture.file(
        "proc/self/mounts",
        "/dev/nvme0n1p1 / xfs rw 0 0\nsysfs /sys sysfs rw 0 0\ntmpfs /sys/module/other tmpfs rw 0 0\n",
    );
    let binder = new_binder(&fixture);
    let bound = bind_volume(&binder, VOLUME, ALLOWLISTED).map(drop);
    assert!(
        bound.is_ok() && !untouched(&binder),
        "a mount beside the parameter directory refused the bind: {bound:?}"
    );
}

/// Every driver write of a bind follows a record its reader admits, from
/// which a release restores the device. The controller sits at a PCI
/// address whose domain takes five hexadecimal digits, the form sysfs
/// prints for a domain above `ffff` and the record's reader refuses. The
/// bind either refuses with no driver write, no record and the controller
/// on `nvme`, or leaves a record that reads back and that a release
/// restores from.
#[test]
fn a_bind_moves_a_device_only_under_a_record_its_reader_admits() {
    const WIDE: &str = "10000:00:1e.0";
    let fixture = Fixture::new(4096);
    fixture.controller("nvme2", WIDE, "vol0fedcba9876543210", 4096);
    let binder = new_binder(&fixture);
    let bound = bind_volume(&binder, "vol0fedcba9876543210", ALLOWLISTED);
    if untouched(&binder) {
        assert!(bound.is_err(), "a bind that moves nothing refuses");
        assert_eq!(observed(&fixture, WIDE), (Some("nvme".into()), None));
        assert!(
            !mappings_path(&fixture.state_dir()).exists(),
            "a bind that moves nothing leaves no record"
        );
        return;
    }
    let record = Mappings::read(&mappings_path(&fixture.state_dir()));
    assert!(
        record.is_ok(),
        "a driver write followed a record its reader refuses: {record:?}, writes {:?}",
        binder.kernel.writes.borrow()
    );
    binder.release(&[]).unwrap();
    assert_eq!(observed(&fixture, WIDE), (Some("nvme".into()), None));
}

/// Binds the fixture's ENI over `routes` as its IPv4 route listing and a
/// second address, `10.0.3.5/24`, then releases, and returns the commands
/// each `ip` process of the release read, processes and commands in order.
fn released_processes(routes: &str) -> Vec<Vec<String>> {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    let mut outputs = binder.kernel.outputs.borrow_mut();
    outputs.insert(
        SHOW_ADDR.into(),
        Some(format!(
            "{ENS6_ADDRESS}3: ens6    inet 10.0.3.5/24 brd 10.0.3.255 scope global ens6\\       valid_lft forever preferred_lft forever\n"
        )),
    );
    outputs.insert(SHOW_ROUTE.into(), Some(routes.to_owned()));
    drop(outputs);
    bind_eni(&binder, None, &FakeMetadata::new()).expect("the bind");
    binder.kernel.runs.borrow_mut().clear();
    binder.kernel.processes.borrow_mut().clear();
    binder.release(&[]).expect("the release");
    let runs = binder.kernel.runs.borrow();
    let starts = binder.kernel.processes.borrow();
    let ends = starts.iter().skip(1).copied().chain([runs.len()]);
    starts
        .iter()
        .zip(ends)
        .map(|(start, end)| runs[*start..end].to_vec())
        .collect()
}

/// The first route command, among the commands each `ip` process read, whose
/// protocol, scope, realm or type of service `ip` writes as another value
/// than the word names.
///
/// One `ip` process keeps, for each of those four attributes, the last name
/// it resolved and one result slot. A name equal to the kept name returns
/// the slot without a lookup, and a number is parsed into the same slot
/// while the kept name stays. So after a name, then a number, the same name
/// again returns the number, until another name of that attribute is
/// resolved. The state lasts for the process: every command of one
/// `ip -batch` shares it. `ip` reads a word as a number when it is decimal,
/// or hexadecimal after `0x`.
fn first_misread_name(processes: &[Vec<String>]) -> Option<&String> {
    let numbered = |word: &str| {
        word.strip_prefix("0x").map_or_else(
            || word.parse::<u32>().is_ok(),
            |digits| u32::from_str_radix(digits, 16).is_ok(),
        )
    };
    processes.iter().find_map(|commands| {
        // Per attribute: the kept name, and whether a number was read since it was resolved.
        let mut kept: [Option<(&str, bool)>; 4] = [None; 4];
        commands.iter().find(|command| {
            let words: Vec<&str> = command.split(' ').collect();
            let ["ip", "route", "replace", _, rest @ ..] = &words[..] else {
                return false;
            };
            let mut misread = false;
            for (slot, names) in [
                ["proto", "protocol"],
                ["scope", "scope"],
                ["realm", "realms"],
                ["tos", "dsfield"],
            ]
            .iter()
            .enumerate()
            {
                let Some(text) = rest
                    .windows(2)
                    .find(|pair| names.contains(&pair[0]))
                    .map(|pair| pair[1])
                else {
                    continue;
                };
                // A realm word may hold a source and a destination realm, each resolved in turn.
                for word in text.split('/') {
                    match &mut kept[slot] {
                        Some((_, stale)) if numbered(word) => *stale = true,
                        Some((name, stale)) if *name == word => misread |= *stale,
                        _ if numbered(word) => {}
                        entry => *entry = Some((word, false)),
                    }
                }
            }
            misread
        })
    })
}

const TWO_PREFIX_ROUTES: [&str; 2] = [
    "10.0.1.0/24 proto kernel scope link src 10.0.1.5 metric 1003",
    "10.0.3.0/24 proto kernel scope link src 10.0.3.5",
];

/// A device with two subnets holds each one's kernel prefix route, which
/// `ip` lists as `proto kernel`, and between them a link route a routing
/// agent added under a protocol number the host's protocol file does not
/// name, listed as `proto 250`. Replayed by one `ip` process in listing
/// order, the second `proto kernel` returns the number the process parsed
/// just before it, and the second prefix route comes back at protocol 250
/// with the batch reporting success. Release restores each recorded route
/// at the protocol, scope, realm and type of service its words name.
#[test]
fn a_named_protocol_replayed_after_a_numbered_one_keeps_its_own_number() {
    let [first, second] = TWO_PREFIX_ROUTES;
    let processes = released_processes(&format!(
        "{first}\n10.0.2.0/24 proto 250 scope link\n{second}\n"
    ));
    let replayed: Vec<&String> = processes
        .iter()
        .flatten()
        .filter(|command| command.starts_with("ip route replace "))
        .collect();
    assert_eq!(
        replayed,
        [
            "ip route replace 10.0.1.0/24 proto kernel scope link src 10.0.1.5 metric 1003 dev if6",
            "ip route replace 10.0.2.0/24 proto 250 scope link dev if6",
            "ip route replace 10.0.3.0/24 proto kernel scope link src 10.0.3.5 dev if6",
        ],
        "release replays the three recorded routes"
    );
    let misread = first_misread_name(&processes);
    assert!(
        misread.is_none(),
        "ip writes {misread:?} at the number its process read before it\n{processes:#?}"
    );
}

/// The same hazard through the scope: a link route at a scope number the
/// host does not name, listed between two `scope link` routes, makes one
/// `ip` process write the later prefix route at that number. The kernel then
/// finds no link-scope route to a gateway in that prefix and refuses the
/// gateway route, so the batch fails with the routes after it unrestored.
#[test]
fn a_named_scope_replayed_after_a_numbered_one_keeps_its_own_number() {
    let [first, second] = TWO_PREFIX_ROUTES;
    let processes = released_processes(&format!(
        "{first}\n10.0.2.0/24 scope 100\n{second}\n10.9.0.0/16 via 10.0.3.1\n"
    ));
    let misread = first_misread_name(&processes);
    assert!(
        misread.is_none(),
        "ip writes {misread:?} at the number its process read before it\n{processes:#?}"
    );
}

/// A state in which no name follows a number of its attribute replays
/// through one batch after the link listing: names alone, and numbers
/// listed after every name.
#[test]
fn routes_without_a_name_after_a_number_replay_through_one_batch() {
    let [first, second] = TWO_PREFIX_ROUTES;
    for routes in [
        format!("{first}\n10.0.2.0/24 proto static scope link\n{second}\n"),
        format!(
            "{first}\n{second}\n10.0.2.0/24 proto 250 scope 100\n10.0.4.0/24 proto 7 scope 253\n"
        ),
    ] {
        let processes = released_processes(&routes);
        assert_eq!(first_misread_name(&processes), None, "{processes:#?}");
        let [listing, replay] = &processes[..] else {
            panic!("the link listing and one batch: {processes:#?}");
        };
        assert_eq!(listing[..], ["ip -o link show"]);
        assert_eq!(
            replay
                .iter()
                .filter(|command| command.starts_with("ip route replace "))
                .count(),
            routes.lines().count()
        );
    }
}

/// The name judge follows `ip`: a name read again after a number in one
/// process is misread, whichever of the four attributes it belongs to; a
/// number alone, another name resolved in between, or a process of its own
/// for the later command leaves every word at its value.
#[test]
fn the_name_judge_flags_a_name_read_again_after_a_number_in_one_process() {
    let run = |text: &str| text.to_owned();
    let kernel = run("ip route replace 10.0.1.0/24 proto kernel scope link dev if6");
    let numbered_protocol = run("ip route replace 10.0.2.0/24 proto 250 scope link dev if6");
    let again = run("ip route replace 10.0.3.0/24 proto kernel scope link dev if6");
    let one_process = [vec![
        kernel.clone(),
        numbered_protocol.clone(),
        again.clone(),
    ]];
    assert_eq!(first_misread_name(&one_process), Some(&one_process[0][2]));
    let apart = [
        vec![kernel.clone()],
        vec![numbered_protocol.clone()],
        vec![again.clone()],
    ];
    assert_eq!(first_misread_name(&apart), None);
    let fresh_for_the_last = [vec![kernel.clone(), numbered_protocol.clone()], vec![again]];
    assert_eq!(first_misread_name(&fresh_for_the_last), None);
    let another_name_between = [vec![
        kernel,
        numbered_protocol,
        run("ip route replace 10.0.4.0/24 proto static scope link dev if6"),
        run("ip route replace 10.0.5.0/24 proto kernel scope link dev if6"),
    ]];
    assert_eq!(first_misread_name(&another_name_between), None);
    let numbers_alone = [vec![
        run("ip route replace 10.0.2.0/24 proto 250 scope 253 dev if6"),
        run("ip route replace 10.0.6.0/24 proto 7 scope 100 tos 0x10 realm 5/6 dev if6"),
        run("ip route replace 10.0.7.0/24 proto 250 scope 253 dev if6"),
    ]];
    assert_eq!(first_misread_name(&numbers_alone), None);
    for (first, between) in [
        ("scope link", "scope 100"),
        ("tos AF11 scope link", "tos 0x10 scope link"),
        ("dsfield AF11 scope link", "tos 0x10 scope link"),
        ("scope link realm red", "scope link realm 9"),
    ] {
        let named = format!("ip route replace 10.0.1.0/24 {first} dev if6");
        let one_process = [vec![
            named.clone(),
            format!("ip route replace 10.0.2.0/24 {between} dev if6"),
            named,
        ]];
        assert_eq!(
            first_misread_name(&one_process),
            Some(&one_process[0][2]),
            "{first} after {between}"
        );
    }
    // A realm pair resolves its source realm, then its destination realm, through the one slot.
    let pairs = [vec![
        run("ip route replace 10.0.1.0/24 scope link realms red/blue dev if6"),
        run("ip route replace 10.0.2.0/24 scope link realms 9/7 dev if6"),
        run("ip route replace 10.0.3.0/24 scope link realms blue/red dev if6"),
    ]];
    assert_eq!(first_misread_name(&pairs), Some(&pairs[0][2]));
}

/// Binds the fixture's volume alone, running `change` once as the record's
/// rename is reached: after the first check and before the second. Returns
/// the bind's result and whether the kernel's write log is empty. `change`
/// may write the fixture's device attributes; a record write or removal
/// inside it reaches a step while the script is borrowed and panics.
fn bind_changing_between_checks(
    fixture: &Fixture,
    change: impl FnOnce() + 'static,
) -> (Result<(), BindError>, bool) {
    let binder = new_binder(fixture);
    let mut change = Some(change);
    SCRIPT.set(Some(Script {
        outcomes: Vec::new(),
        reached: Vec::new(),
        observe: Box::new(move |step| {
            if step == RecordStep::Rename
                && let Some(change) = change.take()
            {
                change();
            }
        }),
    }));
    let bound = bind_volume(&binder, VOLUME, ALLOWLISTED);
    let script = SCRIPT.take().unwrap();
    assert!(
        script
            .reached
            .iter()
            .any(|(step, _)| *step == RecordStep::Rename),
        "the change ran between the checks"
    );
    (bound.map(drop), untouched(&binder))
}

/// A `driver_override` another actor writes between a bind's two checks
/// leaves the controller on `nvme` with every attribute readable, so the
/// second check resolves it, in a state other than the recorded one: the
/// bind refuses with `Changed` before any driver write, leaves the
/// controller on `nvme` under that override and removes its record.
#[test]
fn an_override_changed_between_the_checks_refuses_before_any_driver_write() {
    let fixture = Fixture::new(4096);
    let attribute = fixture.host.pci(BDF).join("driver_override");
    let (refused, untouched) = bind_changing_between_checks(&fixture, move || {
        fs::write(&attribute, "nvme\n").unwrap();
    });
    assert!(matches!(refused, Err(BindError::Changed)), "{refused:?}");
    assert!(untouched, "no driver write");
    assert_eq!(
        observed(&fixture, BDF),
        (Some("nvme".into()), Some("nvme".into())),
        "the controller stays on its kernel driver with the override the other actor wrote"
    );
    assert!(!mappings_path(&fixture.state_dir()).exists());
}

/// A namespace size or logical block size that changes between a bind's two
/// checks leaves the controller resolvable, with a geometry other than the
/// one the first check recorded: the bind refuses with `Changed` before any
/// driver write, leaves the controller on `nvme` and removes its record.
#[test]
fn a_geometry_changed_between_the_checks_refuses_before_any_driver_write() {
    type Change = (&'static str, String);
    let changes: [Change; 2] = [
        ("size", format!("{}\n", (32u64 << 30) / 512)),
        ("queue/logical_block_size", "512\n".to_owned()),
    ];
    for (attribute, value) in changes {
        let fixture = Fixture::new(4096);
        let path = fixture
            .host
            .sys
            .join("class/nvme/nvme1/nvme1n1")
            .join(attribute);
        let (refused, untouched) = bind_changing_between_checks(&fixture, move || {
            fs::write(&path, value).unwrap();
        });
        assert!(
            matches!(refused, Err(BindError::Changed)),
            "{attribute}: {refused:?}"
        );
        assert!(untouched, "{attribute}: no driver write");
        assert_eq!(observed(&fixture, BDF), (Some("nvme".into()), None));
        assert!(!mappings_path(&fixture.state_dir()).exists());
    }
}

/// With an empty change at the record's rename, the second check finds the
/// controller as the first check recorded it and the bind moves it to
/// `vfio-pci`, so the refusals of binds run through the same hook come from
/// the changes they make.
#[test]
fn a_controller_unchanged_between_the_checks_is_moved() {
    let fixture = Fixture::new(4096);
    let (bound, untouched) = bind_changing_between_checks(&fixture, || {});
    assert!(bound.is_ok(), "{bound:?}");
    assert!(!untouched, "the driver writes follow the second check");
    assert_eq!(observed(&fixture, BDF).0.as_deref(), Some("vfio-pci"));
}

/// A third driver, beside the ENI's original `ena` and `vfio-pci`.
const THIRD: &str = "uio_pci_generic";

/// Release unbinds a device only from `vfio-pci`, even one whose group guard
/// it holds. The controller and the ENI are bound, and release opens the ENI's
/// group guard before its first write. Right after the controller's restore
/// binds it to `nvme`, the ENI is moved from `vfio-pci` onto a third driver,
/// so the ENI's restore reads that driver: release returns `Changed`, writes
/// for the controller alone, leaves the ENI on the third driver and keeps
/// the record.
#[test]
fn release_refuses_a_guarded_eni_its_restore_finds_on_a_third_driver() {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    bind_eni(&binder, Some(VOLUME), &FakeMetadata::new()).unwrap();
    assert_eq!(observed(&fixture, ENI_BDF).0.as_deref(), Some("vfio-pci"));
    assert_eq!(observed(&fixture, BDF).0.as_deref(), Some("vfio-pci"));

    let third = fixture.host.sys.join("bus/pci/drivers").join(THIRD);
    fs::create_dir_all(&third).unwrap();
    let link = fixture.host.pci(ENI_BDF).join("driver");
    binder.kernel.after_write.replace(Some((
        "nvme/bind",
        Box::new(move || {
            fs::remove_file(&link).unwrap();
            symlink(&third, &link).unwrap();
        }),
    )));
    binder.kernel.group_opens.borrow_mut().clear();
    let writes = binder.kernel.writes.borrow().len();

    let released = binder.release(&[]);

    let guard = fixture
        .host
        .dev
        .join("vfio")
        .join(format!("noiommu-{}", group_of(ENI_BDF)));
    assert!(
        binder
            .kernel
            .group_opens
            .borrow()
            .iter()
            .any(|(node, at)| *node == guard && *at == writes),
        "release opened the ENI's group guard before its first write"
    );
    assert_eq!(
        observed(&fixture, BDF).0.as_deref(),
        Some("nvme"),
        "the controller's restore ran, and the move with it"
    );
    assert!(
        matches!(released, Err(BindError::Changed)),
        "a guarded device found on a third driver refuses the restore: {released:?}"
    );
    let after = &binder.kernel.writes.borrow()[writes..];
    assert!(
        after
            .iter()
            .all(|(path, value)| !path.contains(ENI_BDF) && value != ENI_BDF),
        "no write for the device found on a third driver: {after:?}"
    );
    assert_eq!(
        observed(&fixture, ENI_BDF).0.as_deref(),
        Some(THIRD),
        "the device stays on the driver the restore found"
    );
    assert!(
        mappings_path(&fixture.state_dir()).exists(),
        "the record stays for a retry"
    );
}
