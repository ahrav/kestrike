//! The binder over the real sysfs kernel inside a disposable QEMU guest,
//! whose emulated NVMe controller sits behind the guest's IOMMU.
//!
//! `scripts/guest-binder.py` starts the guest and supplies the case's
//! `KESTRIKE_GUEST_*` inputs; run the case by exact ID among the ignored
//! cases:
//!
//! ```text
//! kestrike-<hash> --ignored --exact \
//!     bind::guest_tests::the_binder_binds_and_releases_the_guest_s_controller \
//!     --test-threads=1 --nocapture
//! ```
//!
//! The harness records each `guest-binder:` line the case prints and
//! requires, in order, its default refusal, the refusals of a substituted
//! regular file, a different block node and a partition open in a process, the
//! namespace's claim, and the bind and release reports.

use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use super::binder::{
    BindError, BindRequest, Binder, VfioPosture, mappings_path, prepare_state_dir,
};
use super::host::{Host, SysfsKernel, device_number};
use super::identity::{ControllerIdentity, IdentityError};
use super::wc::WcManifest;

fn input(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name}; see scripts/guest-binder.py"))
}

fn report(line: &str) {
    println!("guest-binder: {line}");
}

/// The kernel's partition rescan request, `_IO(0x12, 95)`.
const BLKRRPART: libc::c_ulong = 0x125f;

/// Writes `table` as the namespace's first 512 bytes and asks the kernel to
/// rescan its partitions, then waits up to five seconds until the first
/// partition's sysfs entry exists when `present`, or is gone otherwise.
fn repartition(namespace: &str, table: &[u8; 512], present: bool) {
    let mut disk = OpenOptions::new()
        .read(true)
        .write(true)
        .open(Path::new("/dev").join(namespace))
        .unwrap();
    disk.seek(SeekFrom::Start(0)).unwrap();
    disk.write_all(table).unwrap();
    disk.sync_all().unwrap();
    // SAFETY: `disk` is an open block device descriptor; the request takes no argument.
    assert_eq!(unsafe { libc::ioctl(disk.as_raw_fd(), BLKRRPART as _) }, 0);
    drop(disk);
    // A guest that runs udev settles its probes of the new partitions, which
    // open them, before the case's use checks; a guest without it has none.
    let _ = std::process::Command::new("udevadm").arg("settle").status();
    let entry = Path::new("/sys/class/block").join(format!("{namespace}p1"));
    for _ in 0..50 {
        if entry.exists() == present {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("{} did not reach present={present}", entry.display());
}

/// The MBR's first partition entry, whose type byte sits 4 bytes in and whose
/// first block and block count, little-endian, sit 8 and 12 bytes in.
const ENTRY: usize = 446;

/// An MBR with one Linux partition of 8,192 blocks at block 2,048.
fn one_partition() -> [u8; 512] {
    let mut table = [0u8; 512];
    table[ENTRY + 4] = 0x83;
    table[ENTRY + 8..ENTRY + 12].copy_from_slice(&2048u32.to_le_bytes());
    table[ENTRY + 12..ENTRY + 16].copy_from_slice(&8192u32.to_le_bytes());
    table[510..].copy_from_slice(&[0x55, 0xaa]);
    table
}

/// The device number sysfs names for block device `name`.
fn number(name: &str) -> (u32, u32) {
    let text = fs::read_to_string(Path::new("/sys/class/block").join(name).join("dev")).unwrap();
    device_number(&text).unwrap()
}

/// Creates a block device node at `path` for device `(major, minor)`.
fn block_node(path: &Path, (major, minor): (u32, u32)) {
    let _ = fs::remove_file(path);
    let name = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: `name` is NUL-terminated and outlives the call.
    let made = unsafe {
        libc::mknod(
            name.as_ptr(),
            libc::S_IFBLK | 0o600,
            libc::makedev(major, minor),
        )
    };
    assert_eq!(made, 0, "mknod {}", path.display());
}

/// `vendor:device` in hexadecimal, as `lspci -n` prints a PCI identity.
fn pci_identity(text: &str) -> (u16, u16) {
    let (vendor, device) = text.split_once(':').expect("a vendor:device PCI identity");
    let hex = |part: &str| u16::from_str_radix(part, 16).expect("a hexadecimal PCI ID");
    (hex(vendor), hex(device))
}

#[test]
#[ignore = "needs the disposable QEMU guest scripts/guest-binder.py starts, with its KESTRIKE_GUEST_* inputs"]
fn the_binder_binds_and_releases_the_guest_s_controller() {
    let volume = input("KESTRIKE_GUEST_VOLUME");
    let controller = ControllerIdentity {
        model: Box::leak(
            input("KESTRIKE_GUEST_MODEL")
                .trim_matches('"')
                .to_owned()
                .into_boxed_str(),
        ),
        pci: pci_identity(&input("KESTRIKE_GUEST_PCI")),
    };
    let state_dir = PathBuf::from(input("KESTRIKE_GUEST_STATE_DIR"));
    prepare_state_dir(&state_dir, 0).unwrap();
    let wc = WcManifest::read(Path::new(&input("KESTRIKE_GUEST_WC_MANIFEST"))).unwrap();

    let request = BindRequest {
        volume: Some(&volume),
        eni: None,
        posture: VfioPosture {
            allow_no_iommu: false,
        },
        wc: &wc,
        others: &[],
    };
    let default = Binder {
        host: Host::system(),
        kernel: SysfsKernel,
        state_dir: state_dir.clone(),
    };
    assert!(
        matches!(
            default.bind(&request),
            Err(BindError::Identity(IdentityError::NotEbs))
        ),
        "the EBS identity refuses the guest's controller"
    );
    report("default refused");
    let host = Host::system().expecting(controller);
    let resolved = host.resolve(&volume).unwrap();
    let bdf = resolved.bdf.clone();
    assert_eq!(host.driver(&bdf).as_deref(), Some("nvme"));
    let group = std::fs::read_link(host.pci(&bdf).join("iommu_group")).unwrap();
    let group = group.file_name().unwrap().to_str().unwrap().to_owned();
    report(&format!(
        "controller {bdf} model {:?} pci {:04x}:{:04x} namespace {} group {group}",
        controller.model, controller.pci.0, controller.pci.1, resolved.namespace
    ));
    let namespace = resolved.namespace.clone();
    // A bind whose host reads device nodes from `dev` refuses with `refusal`
    // before any driver write, the controller still on `nvme` and no record
    // written.
    let refuses = |dev: &Path, refusal: IdentityError| {
        let binder = Binder {
            host: Host {
                dev: dev.to_owned(),
                ..host.clone()
            },
            kernel: SysfsKernel,
            state_dir: state_dir.clone(),
        };
        let refused = binder.bind(&request);
        assert!(
            matches!(&refused, Err(BindError::Identity(found)) if *found == refusal),
            "{refused:?}"
        );
        assert_eq!(binder.host.driver(&bdf).as_deref(), Some("nvme"));
        assert!(!mappings_path(&state_dir).exists());
    };
    // A regular file at the namespace's node path opens as a regular file,
    // which the claim refuses as a substitution.
    let nodes = state_dir.join("nodes");
    fs::create_dir_all(&nodes).unwrap();
    fs::write(nodes.join(&namespace), "").unwrap();
    refuses(&nodes, IdentityError::Substituted(namespace.clone()));
    report("substituted file refused");
    // The partition gives a second block device number. A block node for it
    // at the namespace's path opens a device whose number differs from the
    // namespace's sysfs entry; the partition's own node lets the in-use check
    // resolve the partition.
    // The namespace is unused before the case writes its partition table.
    drop(host.check_unused(&namespace).unwrap());
    repartition(&namespace, &one_partition(), true);
    let partition = format!("{namespace}p1");
    let other = number(&partition);
    assert_ne!(other, number(&namespace));
    fs::remove_file(nodes.join(&namespace)).unwrap();
    block_node(&nodes.join(&namespace), other);
    block_node(&nodes.join(&partition), other);
    refuses(&nodes, IdentityError::Substituted(namespace.clone()));
    report("other block node refused");
    // An open descriptor on the partition is a use the process walk finds.
    let partition_node = Path::new("/dev").join(&partition);
    if !partition_node.exists() {
        block_node(&partition_node, other);
    }
    let holder = File::open(&partition_node).unwrap();
    refuses(&host.dev, IdentityError::InUse(partition.clone()));
    drop(holder);
    report("holder refused");
    // With the partition table cleared, the namespace is the only device and
    // the real `/dev` node yields the claim and the bind.
    fs::remove_dir_all(&nodes).unwrap();
    repartition(&namespace, &[0; 512], false);
    let _ = fs::remove_file(&partition_node);
    let claim = host.check_unused(&namespace).unwrap();
    let opened = claim.metadata().unwrap();
    assert_eq!(
        (libc::major(opened.rdev()), libc::minor(opened.rdev())),
        number(&namespace),
        "the claim holds the namespace sysfs names"
    );
    drop(claim);
    report("claimed");
    let binder = Binder {
        host,
        kernel: SysfsKernel,
        state_dir,
    };
    let mappings = binder.bind(&request).unwrap();
    assert_eq!(
        mappings.nvme.as_ref().map(|n| n.bdf.as_str()),
        Some(bdf.as_str())
    );
    assert_eq!(binder.host.driver(&bdf).as_deref(), Some("vfio-pci"));
    assert!(
        Path::new(&format!("/dev/vfio/{group}")).exists(),
        "the guest IOMMU names the group's VFIO node"
    );
    report("bound");
    binder.release(&[]).unwrap();
    assert_eq!(binder.host.driver(&bdf).as_deref(), Some("nvme"));
    assert!(!mappings_path(&binder.state_dir).exists());
    report("released");
    drop(binder);
    drop(default);
    super::network_tests::guest_namespace_campaign();
}
