//! Controller resolution and the in-use checks over a fixture host tree.

use std::fs::{self, OpenOptions};
use std::io;
use std::os::unix::fs::{OpenOptionsExt, symlink};
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use super::fixture::{
    BDF, Fixture, TRACER, VOLUME, hold_readers, hold_ring, make_fifo, release, ring_info,
};
use super::host::Host;
use super::identity::{Controller, ControllerIdentity, IdentityError};
use super::walk::Node;
use crate::exact_child;

#[test]
fn the_process_walk_returns_every_matching_descriptor_target() {
    let fixture = Fixture::new(4096);
    // 400 processes span several batches at `BATCH = 128` and several
    // `LISTING` reads of the process table; process `pid` holds `pid % 7`
    // descriptors, so some tables are empty.
    let mut targets: Vec<Node> = (1..=400)
        .flat_map(|pid| (0..pid % 7).map(move |fd| (pid, fd)))
        .map(|(pid, fd)| {
            let target = fixture.host.dev.join(format!("file{pid}-{fd}"));
            fixture.open(pid, &target);
            Host::node(&target).unwrap()
        })
        .collect();
    fixture.process(401);
    fixture.open(402, &fixture.host.dev.join("nvme1n1"));
    // A directory that holds a descriptor table under a name that is no
    // process ID, with the status the capability check reads there.
    fs::remove_file(fixture.host.proc.join("thread-self")).unwrap();
    fs::rename(
        fixture.host.proc.join("402"),
        fixture.host.proc.join("thread-self"),
    )
    .unwrap();
    fixture.file("proc/thread-self/status", TRACER);
    let found = fixture.host.opened(|_| true).expect("proc lists");
    targets.sort();
    assert_eq!(found, targets, "sorted, each node once");
    let one = Host::node(&fixture.host.dev.join("file10-2")).unwrap();
    assert_eq!(fixture.host.opened(|node| node == one), Some(vec![one]));
    let unlistable = Host {
        proc: fixture.host.proc.join("missing"),
        ..fixture.host.clone()
    };
    assert_eq!(unlistable.opened(|_| true), None);
}

#[test]
fn a_large_descriptor_table_is_read_completely() {
    let fixture = Fixture::new(4096);
    fixture.process(4242);
    let table = fixture.root.join("proc/4242/fd");
    fs::create_dir_all(&table).unwrap();
    // 1000 entries exceed one `getdents64` read of the table and span
    // several shares at `SHARE = 128`.
    let mut targets: Vec<Node> = (0..1000)
        .map(|fd| {
            let target = fixture.host.dev.join(format!("file{fd}"));
            fs::write(&target, "").unwrap();
            std::os::unix::fs::symlink(&target, table.join(fd.to_string())).unwrap();
            Host::node(&target).unwrap()
        })
        .collect();
    fixture.open(7, &fixture.host.dev.join("nvme1n1"));
    let found = fixture.host.opened(|_| true).expect("proc lists");
    targets.push(Host::node(&fixture.host.dev.join("nvme1n1")).unwrap());
    targets.sort();
    assert_eq!(found, targets);
}

#[test]
fn a_table_queuing_more_shares_than_walkers_is_read_completely() {
    // 4,500 descriptors queue 35 shares of `SHARE = 128`, more than the 32
    // walkers of `WALKERS`, so the walker listing the table reads the shares
    // past one per walker that others have not taken. Every descriptor is
    // still found, and a failing one still fails the walk.
    let fixture = Fixture::new(4096);
    let target = fixture.host.dev.join("held");
    fs::write(&target, "").unwrap();
    fixture.process(4243);
    let table = fixture.root.join("proc/4243/fd");
    fs::create_dir_all(&table).unwrap();
    for fd in 0..4500 {
        symlink(&target, table.join(fd.to_string())).unwrap();
    }
    let node = Host::node(&target).unwrap();
    assert_eq!(fixture.host.opened(|_| true), Some(vec![node]));
    // A link to itself fails its `statx` with `ELOOP`.
    symlink("4500", table.join("4500")).unwrap();
    assert_eq!(fixture.host.opened(|_| true), None);
}

#[test]
fn the_volume_resolves_to_its_controller_with_or_without_the_hyphen() {
    for sector in [512, 4096] {
        let fixture = Fixture::new(sector);
        let expected = Controller {
            bdf: BDF.into(),
            namespace: "nvme1n1".into(),
            nsid: 1,
            sector_size: sector,
            capacity: 64 << 30,
        };
        assert_eq!(fixture.host.resolve(VOLUME), Ok(expected.clone()));
        assert_eq!(fixture.host.resolve("vol0123456789abcdef0"), Ok(expected));
    }
}

#[test]
fn ambiguous_foreign_and_malformed_identities_refuse() {
    let fixture = Fixture::new(4096);
    for bad in ["", "vol-", "vol-xyz", "VOL-0123"] {
        assert_eq!(
            fixture.host.resolve(bad),
            Err(IdentityError::VolumeId),
            "{bad:?}"
        );
    }
    assert_eq!(
        fixture.host.resolve("vol-0123456789abcdef1"),
        Err(IdentityError::NotFound)
    );
    // A second controller reporting the same serial.
    fixture.controller("nvme2", "0000:00:1e.0", "vol0123456789abcdef0", 4096);
    assert_eq!(fixture.host.resolve(VOLUME), Err(IdentityError::Duplicate));

    let wrong_model = Fixture::new(4096);
    wrong_model.file(
        "sys/class/nvme/nvme1/model",
        "Amazon EC2 NVMe Instance Storage\n",
    );
    assert_eq!(wrong_model.host.resolve(VOLUME), Err(IdentityError::NotEbs));
    let wrong_device = Fixture::new(4096);
    wrong_device.file(&format!("sys/bus/pci/devices/{BDF}/device"), "0xcd00\n");
    assert_eq!(
        wrong_device.host.resolve(VOLUME),
        Err(IdentityError::NotEbs)
    );

    let two = Fixture::new(4096);
    fs::create_dir_all(two.host.sys.join("class/nvme/nvme1/nvme1n2")).unwrap();
    assert_eq!(two.host.resolve(VOLUME), Err(IdentityError::Namespaces(2)));
    let none = Fixture::new(4096);
    fs::remove_dir_all(none.host.sys.join("class/nvme/nvme1/nvme1n1")).unwrap();
    assert_eq!(none.host.resolve(VOLUME), Err(IdentityError::Namespaces(0)));
}

#[test]
fn an_unreadable_serial_on_any_controller_refuses_resolution() {
    let fixture = Fixture::new(4096);
    // The boot volume's serial cannot be read, so the volume's controller
    // cannot be shown unique.
    let serial = fixture.host.sys.join("class/nvme/nvme0/serial");
    fs::remove_file(&serial).unwrap();
    fs::create_dir(&serial).unwrap();
    assert_eq!(
        fixture.host.resolve(VOLUME),
        Err(IdentityError::Attribute("serial"))
    );
}

#[test]
fn a_mounted_swapped_held_or_open_device_is_in_use() {
    let fixture = Fixture::new(4096);
    assert!(fixture.host.check_unused("nvme1n1").is_ok());
    assert_eq!(
        fixture.host.check_unused("nvme0n1").map(drop),
        Err(IdentityError::InUse("nvme0n1p1".into())),
        "the root device"
    );

    let swapped = Fixture::new(4096);
    swapped.file(
        "proc/swaps",
        "Filename Type\n/dev/nvme1n1 partition 0 0 -2\n",
    );
    assert_eq!(
        swapped.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into()))
    );

    let held = Fixture::new(4096);
    held.partition("nvme1n1", "nvme1n1p2");
    fs::write(
        held.host.sys.join("block/nvme1n1/nvme1n1p2/holders/dm-0"),
        "",
    )
    .unwrap();
    assert_eq!(
        held.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1p2".into()))
    );

    let open = Fixture::new(4096);
    open.open(4242, &open.host.dev.join("nvme1n1"));
    assert_eq!(
        open.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into()))
    );

    let open_partition = Fixture::new(4096);
    open_partition.partition("nvme1n1", "nvme1n1p2");
    open_partition.open(4242, &open_partition.host.dev.join("nvme1n1p2"));
    assert_eq!(
        open_partition.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1p2".into()))
    );
}

/// A namespace that backs a loop device, or has a partition that does, is in
/// use. The loop driver keeps the backing file open inside the kernel: the
/// process that configured it has closed its descriptor, the namespace gains
/// no holder, and the loop device is what a mount or swap table names. The
/// kernel names the backing file in `sys/block/loop<n>/loop/backing_file`.
/// A loop device that is not configured, or backs another file, leaves the
/// namespace unused, and a backing file entry that cannot be read refuses.
#[test]
fn a_namespace_backing_a_loop_device_is_in_use() {
    let fixture = Fixture::new(4096);
    fs::create_dir_all(fixture.host.sys.join("block/loop1")).unwrap();
    fixture.file("var/disk.img", "");
    fixture.loop_device("loop2", "/var/disk.img");
    fixture.file("dev/nvme1n10", "");
    fixture.loop_device("loop3", "/dev/nvme1n10");
    assert!(fixture.host.check_unused("nvme1n1").is_ok());
    fixture.loop_device("loop0", "/dev/nvme1n1");
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "a loop device over the namespace"
    );

    let partition = Fixture::new(4096);
    partition.partition("nvme1n1", "nvme1n1p2");
    partition.loop_device("loop0", "/dev/nvme1n1p2");
    assert_eq!(
        partition.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1p2".into())),
        "a loop device over a partition"
    );

    let unreadable = Fixture::new(4096);
    fs::create_dir_all(unreadable.host.sys.join("block/loop0/loop/backing_file")).unwrap();
    assert_eq!(
        unreadable.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("loops")),
        "a backing file entry that cannot be read"
    );
}

/// A namespace is not shown unused while the pNFS block layout client is
/// in use. `blocklayoutdriver` opens the block devices its servers' layouts
/// name inside the kernel with no holder, so such a device gains no holder
/// link, no exclusive claim and no descriptor in any process, and the mount
/// table names the NFS export. The kernel lists those devices nowhere; the
/// module's use count, `sys/module/blocklayoutdriver/refcnt`, is above zero
/// while an NFS mount uses the driver. A host without the module, or with
/// it loaded and unused, leaves the namespace unused.
#[test]
fn a_namespace_beside_an_active_pnfs_block_layout_client_is_not_shown_unused() {
    let fixture = Fixture::new(4096);
    assert!(fixture.host.check_unused("nvme1n1").is_ok());
    fixture.file("sys/module/blocklayoutdriver/refcnt", "0\n");
    assert!(fixture.host.check_unused("nvme1n1").is_ok());
    fixture.file("sys/module/blocklayoutdriver/refcnt", "1\n");
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("layouts")),
        "an NFS mount uses the block layout driver"
    );
}

/// A block layout driver built into the kernel has no entry under
/// `sys/module`: the kernel makes one for a built-in only when it declares a
/// parameter or a version, and `blocklayoutdriver` declares neither. Its
/// mounts hold the namespace open as a loaded module's do, and no use count
/// tells whether one does. The kernel's symbol table lists the driver's
/// `bl_alloc_deviceid_node` with no module name, so the check refuses
/// whenever the driver is built in, and when no symbol table is readable. A
/// host whose symbol table lacks the driver, or names another module's
/// symbol of that name, leaves the namespace unused.
#[test]
fn a_namespace_beside_a_built_in_pnfs_block_layout_client_is_not_shown_unused() {
    const OTHER: &str = "ffffffffa1b2c3d0 T blk_mq_alloc_request\n";
    let fixture = Fixture::new(4096);
    fixture.file("proc/kallsyms", OTHER);
    assert!(fixture.host.check_unused("nvme1n1").is_ok());
    fixture.file(
        "proc/kallsyms",
        &format!("{OTHER}ffffffffc0a01230 t bl_alloc_deviceid_node\t[lookalike]\n"),
    );
    assert!(fixture.host.check_unused("nvme1n1").is_ok());
    fixture.file(
        "proc/kallsyms",
        &format!("{OTHER}ffffffff8145e2a0 T bl_alloc_deviceid_node\n"),
    );
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("layouts")),
        "the kernel holds the block layout driver built in"
    );
    fs::remove_file(fixture.host.proc.join("kallsyms")).unwrap();
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("layouts")),
        "no symbol table tells whether the driver is built in"
    );
}

/// A kernel with configfs keeps every target, gadget and heartbeat entry
/// whether or not configfs is mounted, so on such a kernel a mount table
/// with no configfs mount shows none of them: `sys/kernel/config` is an
/// empty directory while an enabled NVMe target namespace exports the
/// namespace. `proc/filesystems` lists configfs on that kernel, and the
/// check has no answer. A kernel without configfs has no such entry, and the
/// same table admits the namespace; so does a kernel with configfs mounted.
#[test]
fn a_kernel_with_configfs_and_no_configfs_mount_does_not_show_its_entries_absent() {
    let checked = |filesystems: Option<&str>, mounted: bool| {
        let fixture = Fixture::new(4096);
        fs::create_dir_all(fixture.host.sys.join("kernel/config")).unwrap();
        match filesystems {
            Some(text) => fixture.file("proc/filesystems", text),
            None => fs::remove_file(fixture.host.proc.join("filesystems")).unwrap(),
        }
        if mounted {
            fixture.file(
                "proc/self/mounts",
                "/dev/nvme0n1p1 / xfs rw 0 0\nconfigfs /sys/kernel/config configfs rw 0 0\n",
            );
        }
        fixture.host.check_unused("nvme1n1").map(drop)
    };
    let with = "nodev\tsysfs\nnodev\tproc\nnodev\tconfigfs\n\text4\n";
    let without = "nodev\tsysfs\nnodev\tproc\n\text4\n";
    let unverifiable = Err(IdentityError::Unverifiable("configfs"));
    assert_eq!(
        checked(Some(without), false),
        Ok(()),
        "a kernel without configfs"
    );
    assert_eq!(checked(Some(with), true), Ok(()), "configfs mounted");
    assert_eq!(
        checked(Some(with), false),
        unverifiable,
        "a kernel with configfs and no mount of it admitted"
    );
    assert_eq!(
        checked(None, false),
        unverifiable,
        "no list of the kernel's file systems"
    );
}

/// The kernel's symbol table is read at `proc/kallsyms`. A mount the mount
/// table lists at that path shows its own text there, here a table without
/// the driver's symbol, so a kernel that holds the block layout driver built
/// in reads as one without it. The check has no answer under the cover; the
/// same table with no mount over it leaves the namespace unused, and a mount
/// beside the table leaves it read.
#[test]
fn a_symbol_table_a_mount_covers_does_not_show_the_layout_driver_absent() {
    let checked = |tail: &str| {
        let fixture = Fixture::new(4096);
        fixture.file("proc/kallsyms", "ffffffffa1b2c3d0 T blk_mq_alloc_request\n");
        fixture.file(
            "proc/self/mounts",
            &format!("/dev/nvme0n1p1 / xfs rw 0 0\nproc /proc proc rw 0 0\n{tail}"),
        );
        fixture.host.check_unused("nvme1n1").map(drop)
    };
    assert_eq!(
        checked(""),
        Ok(()),
        "premise: the table as the kernel shows it"
    );
    assert_eq!(
        checked("binfmt_misc /proc/sys/fs/binfmt_misc binfmt_misc rw 0 0\n"),
        Ok(()),
        "a mount beside the table"
    );
    assert_eq!(
        checked("tmpfs /proc/kallsyms tmpfs rw 0 0\n"),
        Err(IdentityError::Unverifiable("layouts")),
        "a covered symbol table admitted"
    );
}

/// A loop device whose backing file is another node of the namespace, not
/// its `/dev` node, still holds the namespace in use. The kernel names the
/// backing file by the path the loop device was configured with, so a loop
/// device over a bind mount of the namespace's node, as a container runtime
/// holds for a raw block volume, names the mount point, and one over a node
/// made with `mknod` names that node. Each such path is the namespace's node
/// under the host root.
#[test]
fn a_loop_device_over_another_node_of_the_namespace_is_in_use() {
    const PUBLISHED: &str =
        "var/lib/kubelet/plugins/kubernetes.io/csi/volumeDevices/publish/pvc-1/pod-1";
    let fixture = Fixture::new(4096);
    let node = fixture.host.dev.join("nvme1n1");
    let alias = fixture.root.join(PUBLISHED);
    fs::create_dir_all(alias.parent().unwrap()).unwrap();
    fs::hard_link(&node, &alias).unwrap();
    assert_eq!(Host::node(&alias), Host::node(&node), "premise: one node");
    fixture.loop_device("loop0", &format!("/{PUBLISHED}"));
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "a loop device over a bind mount of the namespace's node"
    );

    let made = Fixture::new(4096);
    fs::create_dir_all(made.root.join("tmp")).unwrap();
    fs::hard_link(made.host.dev.join("nvme1n1"), made.root.join("tmp/disk")).unwrap();
    made.loop_device("loop0", "/tmp/disk");
    assert_eq!(
        made.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "a loop device over a second node of the namespace"
    );
}

/// A loop device over a second node of the namespace keeps the namespace in
/// use after that node is unlinked. `mknod /run/volume b <major> <minor>`,
/// `losetup /dev/loop0 /run/volume`, `rm /run/volume` leaves the loop device
/// configured, and the kernel then names an unlinked backing file with a
/// ` (deleted)` suffix, a path that resolves to no node. While the node
/// exists the check refuses by node; once it is unlinked the check cannot
/// tell which device the loop device serves and refuses as unverifiable.
#[test]
fn a_loop_device_over_an_unlinked_node_of_the_namespace_is_not_admitted() {
    let fixture = Fixture::new(4096);
    let second = fixture.root.join("run/volume");
    fs::create_dir_all(second.parent().unwrap()).unwrap();
    fs::hard_link(fixture.host.dev.join("nvme1n1"), &second).unwrap();
    fixture.loop_device("loop0", "/run/volume");
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: the loop device over the linked node refuses"
    );

    fs::remove_file(&second).unwrap();
    fixture.file(
        "sys/block/loop0/loop/backing_file",
        "/run/volume (deleted)\n",
    );
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("loops")),
        "a loop device whose backing file resolves to no node"
    );
}

/// Whether the check refuses the volume's namespace as in use on a host
/// where process 4242 holds the character node `node` open, after granting
/// the claim with the node present and closed. `sysfs` is the node's device
/// number entry.
fn refuses_open_character_node(node: &str, sysfs: &str) {
    let fixture = Fixture::new(4096);
    let path = fixture.host.dev.join(node);
    fs::write(&path, "").unwrap();
    fixture.file(sysfs, "241:1\n");
    assert!(
        fixture.host.check_unused("nvme1n1").is_ok(),
        "{node} present and closed"
    );
    fixture.open(4242, &path);
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "{node} open in process 4242"
    );
}

/// A process that holds the namespace's generic node `ng<c>n<n>` open is a
/// use of the namespace: the node carries I/O commands to it. The open takes
/// no claim on the block device, so only the process walk can show it.
#[test]
fn a_namespace_open_through_its_generic_node_is_in_use() {
    refuses_open_character_node("ng1n1", "sys/class/nvme/nvme1/ng1n1/dev");
}

/// A process that holds the controller's node `nvme<c>` open is a use of the
/// namespace: the node carries I/O commands to a namespace by its ID.
#[test]
fn a_namespace_open_through_its_controller_node_is_in_use() {
    refuses_open_character_node("nvme1", "sys/class/nvme/nvme1/dev");
}

/// A namespace's character devices are the ones sysfs numbers in
/// `class/nvme/<controller>/dev` and `class/nvme/<controller>/ng<c>n<n>/dev`,
/// whatever file sits at their `/dev` paths. A process that holds one of
/// those devices open through any node is a use of the namespace. Here the
/// host's device nodes are real ones: sysfs gives the device the number of
/// the system's null device, a process holds `/dev/null` open, and the
/// fixture's `dev/nvme1` is a regular file, as a node put in the device's
/// place would be. Without the descriptor the check reaches its claim,
/// which a regular file refuses.
#[test]
fn a_character_device_open_through_another_node_is_in_use_whatever_its_dev_path_names() {
    use std::os::unix::fs::MetadataExt;
    let null = fs::metadata("/dev/null").unwrap().rdev();
    for attribute in ["sys/class/nvme/nvme1/dev", "sys/class/nvme/nvme1/ng1n1/dev"] {
        let fixture = Fixture::new(4096);
        fixture.file(
            attribute,
            &format!("{}:{}\n", libc::major(null), libc::minor(null)),
        );
        let host = Host {
            file_nodes: false,
            ..fixture.host.clone()
        };
        assert_eq!(
            host.check_unused("nvme1n1").map(drop),
            Err(IdentityError::Substituted("nvme1n1".into())),
            "premise: no process holds the device {attribute} numbers"
        );
        fixture.open(4242, Path::new("/dev/null"));
        assert_eq!(
            host.check_unused("nvme1n1").map(drop),
            Err(IdentityError::InUse("nvme1n1".into())),
            "the device {attribute} numbers, open through another node, admitted to the claim"
        );
    }
}

/// A character node the check cannot identify refuses with
/// `Unverifiable("devices")`: the controller's, or the generic node of a
/// generic device the kernel registers. A host whose kernel registers no
/// generic device grants the claim without that node.
#[test]
fn an_unidentified_character_node_is_unverifiable() {
    let fixture = Fixture::new(4096);
    assert!(
        fixture.host.check_unused("nvme1n1").is_ok(),
        "no generic device"
    );
    fixture.file("sys/class/nvme/nvme1/ng1n1/dev", "241:1\n");
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("devices")),
        "a registered generic device without a node"
    );

    let fixture = Fixture::new(4096);
    fs::remove_file(fixture.host.dev.join("nvme1")).unwrap();
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("devices")),
        "no controller node"
    );
}

/// A loop device is backed by a regular file or a block device and by
/// nothing else, so a backing path that resolves to a directory is not the
/// file the loop device serves. The kernel names a backing file on a mount
/// this process cannot reach by its path from that mount's root: a bind
/// mount of the namespace's node made inside another mount namespace reads
/// as `/`, and a node under a directory mounted there reads as a path that
/// may name a directory here. The check then cannot tell which device the
/// loop device serves and refuses as unverifiable. A loop device over a
/// regular file that is not the namespace's node admits the namespace.
#[test]
fn a_loop_device_whose_backing_path_names_a_directory_is_not_admitted() {
    let image = Fixture::new(4096);
    image.file("var/disk.img", "");
    image.loop_device("loop0", "/var/disk.img");
    assert!(
        image.host.check_unused("nvme1n1").is_ok(),
        "premise: a loop device over another regular file admits the namespace"
    );

    for path in ["/", "/run/volumes"] {
        let fixture = Fixture::new(4096);
        fs::create_dir_all(fixture.root.join("run/volumes")).unwrap();
        fixture.file("sys/block/loop0/loop/backing_file", &format!("{path}\n"));
        assert_eq!(
            fixture.host.check_unused("nvme1n1").map(drop),
            Err(IdentityError::Unverifiable("loops")),
            "a loop device whose backing path {path} names a directory"
        );
    }
}

/// A loop device over a second node of the namespace whose name ends with a
/// newline keeps the namespace in use. The kernel prints the backing file's
/// path and one newline after it, so the entry of a node `/run/volume\n`
/// ends with two newlines and names that node, not `/run/volume`. A regular
/// file at `/run/volume` is no loop device's backing file and does not
/// change which device the loop device serves.
#[test]
fn a_loop_device_over_a_node_whose_name_ends_with_a_newline_is_in_use() {
    let fixture = Fixture::new(4096);
    let second = fixture.root.join("run/volume\n");
    fs::hard_link(fixture.host.dev.join("nvme1n1"), &second).unwrap();
    assert_eq!(
        Host::node(&second),
        Host::node(&fixture.host.dev.join("nvme1n1")),
        "premise: one node"
    );
    fixture.file("run/volume", "");
    fixture.loop_device("loop0", "/run/volume");
    assert!(
        fixture.host.check_unused("nvme1n1").is_ok(),
        "premise: a loop device over the regular file admits the namespace"
    );

    fs::remove_file(fixture.host.dev.join("loop0")).unwrap();
    fixture.loop_device("loop0", "/run/volume\n");
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "a loop device over the node the kernel names"
    );
}

/// A loop device whose backing path resolves to no node under the host root
/// is not admitted. A backing file on a mount this process cannot reach, as
/// in another mount namespace, prints a path that names nothing here, so the
/// path does not tell which device the loop device serves. The same path
/// over a regular file is the control: the loop device serves that file and
/// the namespace is unused.
#[test]
fn a_loop_device_whose_backing_path_resolves_to_no_node_is_not_admitted() {
    let fixture = Fixture::new(4096);
    fixture.file("sys/block/loop0/loop/backing_file", "/mnt/other/disk.img\n");
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("loops")),
        "a backing path that names no node under the host root"
    );

    fixture.file("mnt/other/disk.img", "");
    fixture.loop_device("loop0", "/mnt/other/disk.img");
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Ok(()),
        "control: the same path over a regular file"
    );
}

/// A loop device over an unlinked second node of the namespace is not
/// admitted when another file holds the name the kernel prints for it. The
/// kernel names an unlinked backing file `/run/volume` as
/// `/run/volume (deleted)`, the same text it prints for a linked file of
/// that name, so the text does not tell which of the two the loop device
/// serves, and the regular file found at that path says nothing about the
/// unlinked node.
#[test]
fn a_loop_device_over_an_unlinked_node_is_not_admitted_by_a_file_named_as_deleted() {
    let fixture = Fixture::new(4096);
    fixture.file(
        "sys/block/loop0/loop/backing_file",
        "/run/volume (deleted)\n",
    );
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("loops")),
        "premise: with no file of that name the loop device already refuses"
    );

    fixture.file("run/volume (deleted)", "");
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("loops")),
        "a file at the path the kernel prints for the unlinked node"
    );
}

/// A loop device configured inside another mount namespace keeps the
/// namespace in use even when its backing path names a different file here.
/// The kernel names a backing file by its path within the mount namespace
/// that holds it, so a container whose private `/dev` holds the namespace's
/// node as `/dev/xvda` and runs `losetup /dev/loop0 /dev/xvda` leaves
/// `backing_file` reading `/dev/xvda`. On the host that path is another
/// device's node, the root volume's on a Nitro instance. The path then names
/// a block device, yet not the one the loop device serves. Here
/// `dev/loop0` is a hard link of the namespace's node: it stands in for the
/// kernel's own record of the backing file, which `LOOP_GET_STATUS64`
/// returns as `lo_rdevice`, `lo_device` and `lo_inode`.
#[test]
fn a_loop_device_whose_backing_path_names_another_device_here_is_not_admitted() {
    let fixture = Fixture::new(4096);
    let root = fixture.host.dev.join("nvme0n1");
    let named = fixture.host.dev.join("xvda");
    fs::hard_link(&root, &named).unwrap();
    fs::hard_link(
        fixture.host.dev.join("nvme1n1"),
        fixture.host.dev.join("loop0"),
    )
    .unwrap();
    assert_eq!(
        Host::node(&named),
        Host::node(&root),
        "premise: the path names nvme0n1"
    );
    assert_ne!(
        Host::node(&named),
        Host::node(&fixture.host.dev.join("nvme1n1")),
        "premise: the path does not name the namespace"
    );
    fixture.file("sys/block/loop0/loop/backing_file", "/dev/xvda\n");
    assert!(
        fixture.host.check_unused("nvme1n1").is_err(),
        "a loop device over the namespace whose backing path names nvme0n1 here"
    );
}

/// A namespace node swapped after resolution for another file, which the
/// exclusive open then returns, refuses with `Substituted`: the claim counts
/// only the descriptor the open returned. The swap happens while the check
/// reads the swap table, a FIFO here, after it resolved the namespace's node.
#[test]
fn a_node_swapped_after_resolution_refuses_the_claim() {
    use std::io::Write;

    let fixture = Fixture::new(4096);
    let swaps = fixture.host.proc.join("swaps");
    fs::remove_file(&swaps).unwrap();
    make_fifo(&swaps);
    let node = fixture.host.dev.join("nvme1n1");
    let writer = {
        let (swaps, node) = (swaps.clone(), node.clone());
        thread::spawn(move || {
            let mut sink = fs::OpenOptions::new().write(true).open(&swaps).unwrap();
            let staged = node.with_extension("staged");
            fs::write(&staged, "").unwrap();
            fs::rename(&staged, &node).unwrap();
            let _sent = sink.write_all(b"Filename Type Size Used Priority\n");
        })
    };
    let refused = fixture.host.check_unused("nvme1n1").map(drop);
    // A check that returned before it read the swap table releases the
    // writer here, so a wrong refusal fails the assertion below.
    let _reader = release(&swaps);
    assert_eq!(refused, Err(IdentityError::Substituted("nvme1n1".into())));
    writer.join().unwrap();
}

/// A FIFO at the namespace's node path opens at once, since the claim opens
/// nonblocking, and refuses with `Substituted`. The check runs on its own
/// thread; one that blocks in the open is released by a writer and fails the
/// test after five seconds.
#[test]
fn a_fifo_at_the_node_path_refuses_without_blocking_the_claim() {
    let fixture = Fixture::new(4096);
    let node = fixture.host.dev.join("nvme1n1");
    make_fifo(&node);
    let host = fixture.host.clone();
    let (done, outcome) = mpsc::channel();
    let check = thread::spawn(move || done.send(host.check_unused("nvme1n1").map(drop)).unwrap());
    let refused = outcome.recv_timeout(Duration::from_secs(5));
    if refused.is_err() {
        let _writer = fs::OpenOptions::new().write(true).open(&node);
    }
    check.join().unwrap();
    assert_eq!(
        refused,
        Ok(Err(IdentityError::Substituted("nvme1n1".into()))),
        "the claim's open returns at once on a FIFO"
    );
}

/// A namespace whose sysfs device number names another device than its node
/// refuses with `Substituted` once the open returns, and one whose sysfs
/// device number is missing or malformed is `Unverifiable("dev")` before the
/// open.
#[test]
fn a_sysfs_device_number_that_differs_or_is_unreadable_refuses_the_claim() {
    let dev = |fixture: &Fixture| fixture.host.sys.join("class/block/nvme1n1/dev");
    let other = Fixture::new(4096);
    let planted = fs::read_to_string(dev(&other)).unwrap();
    let (major, minor) = planted.trim().split_once(':').unwrap();
    let minor: u32 = minor.parse().unwrap();
    fs::write(dev(&other), format!("{major}:{}\n", minor + 1)).unwrap();
    assert_eq!(
        other.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Substituted("nvme1n1".into()))
    );
    for edit in [
        |path: &Path| fs::remove_file(path).unwrap(),
        |path: &Path| fs::write(path, "259\n").unwrap(),
        |path: &Path| fs::write(path, "major:minor\n").unwrap(),
    ] {
        let fixture = Fixture::new(4096);
        edit(&dev(&fixture));
        assert_eq!(
            fixture.host.check_unused("nvme1n1").map(drop),
            Err(IdentityError::Unverifiable("dev"))
        );
    }
}

/// With the fixture accommodation clear, a host whose device nodes are
/// regular files refuses the claim with
/// `Substituted`, while the fixture host with the accommodation claims the
/// same node.
#[test]
fn a_regular_file_node_refuses_the_claim_without_the_fixture_accommodation() {
    let fixture = Fixture::new(4096);
    let host = Host {
        file_nodes: false,
        ..fixture.host.clone()
    };
    assert_eq!(
        host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Substituted("nvme1n1".into()))
    );
    assert!(fixture.host.check_unused("nvme1n1").is_ok());
}

#[test]
fn an_unlistable_partition_table_is_unverifiable() {
    let fixture = Fixture::new(4096);
    fixture.partition("nvme1n1", "nvme1n1p2");
    fixture.open(4242, &fixture.host.dev.join("nvme1n1p2"));
    fs::remove_dir_all(fixture.host.sys.join("block/nvme1n1")).unwrap();
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("partitions"))
    );
}

#[test]
fn another_node_for_the_same_device_is_in_use() {
    let fixture = Fixture::new(4096);
    // Fixture device nodes are regular files, so a hard link stands for a
    // second node with the same device number.
    let alias = fixture.host.dev.join("xvdf");
    fs::hard_link(fixture.host.dev.join("nvme1n1"), &alias).unwrap();
    fixture.open(4242, &alias);
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into()))
    );
}

/// A procfs mounted with `hidepid` lists no process this one may not trace,
/// so the walk of a process without `CAP_SYS_PTRACE` proves no namespace
/// unused.
#[test]
fn a_walk_without_the_ptrace_capability_is_unverifiable() {
    let fixture = Fixture::new(4096);
    // Every capability of Linux 6.12 but bit 19, `CAP_SYS_PTRACE`.
    fixture.file(
        "proc/self/status",
        "Name:\ttest\nCapEff:\t000001fffff7ffff\n",
    );
    assert_eq!(fixture.host.opened(|_| true), None);
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("processes"))
    );
    fixture.file(
        "proc/self/status",
        "Name:\ttest\nCapEff:\t000001ffffffffff\n",
    );
    assert_eq!(fixture.host.opened(|_| true), Some(Vec::new()));
    assert_eq!(fixture.host.check_unused("nvme1n1").map(drop), Ok(()));
}

/// `CapEff` counts only in the reader's own user namespace, and a procfs
/// mounted with `hidepid` hides from a reader in a child user namespace
/// every process of an ancestor namespace that holds capabilities there,
/// so the walk of a process outside the initial user namespace proves no
/// namespace unused whatever its effective set.
#[test]
fn a_walk_outside_the_initial_user_namespace_is_unverifiable() {
    let fixture = Fixture::new(4096);
    let user = fixture.host.proc.join("self/ns/user");
    assert_eq!(fixture.host.opened(|_| true), Some(Vec::new()));
    // An ordinary inode, as every user namespace but the initial one has.
    fs::remove_file(&user).unwrap();
    fs::write(&user, "").unwrap();
    assert_eq!(fixture.host.opened(|_| true), None);
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("processes"))
    );
    fs::remove_file(&user).unwrap();
    assert_eq!(fixture.host.opened(|_| true), None);
}

#[test]
fn a_table_or_descriptor_that_cannot_be_read_fails_the_walk() {
    let table = Fixture::new(4096);
    table.process(55);
    assert_eq!(
        table.host.opened(|_| true),
        Some(Vec::new()),
        "premise: the walk answers for the process"
    );
    table.file("proc/55/fd", "");
    assert_eq!(table.host.opened(|_| true), None);
    assert_eq!(
        table.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("processes"))
    );
    let descriptor = Fixture::new(4096);
    descriptor.process(56);
    let fd = descriptor.host.proc.join("56/fd");
    fs::create_dir_all(&fd).unwrap();
    assert_eq!(
        descriptor.host.opened(|_| true),
        Some(Vec::new()),
        "premise: the walk answers for the empty table"
    );
    std::os::unix::fs::symlink("3", fd.join("3")).unwrap();
    assert_eq!(descriptor.host.opened(|_| true), None);
}

#[test]
fn a_thread_s_table_is_read_when_the_process_leader_s_is_empty() {
    let fixture = Fixture::new(4096);
    // procfs reads a process's `fd` directory through its leader thread,
    // which releases its descriptor table when it exits. The leader's
    // `stat` entry then shows state `Z` and the tick it started in.
    let leader = format!("60 (leader) Z{} 0\n", " 0".repeat(18));
    fixture.file("proc/60/task/60/stat", &leader);
    fs::create_dir_all(fixture.host.proc.join("60/fd")).unwrap();
    fs::create_dir_all(fixture.host.proc.join("60/task/60/fd")).unwrap();
    let thread = fixture.host.proc.join("60/task/61/fd");
    fs::create_dir_all(&thread).unwrap();
    std::os::unix::fs::symlink(fixture.host.dev.join("nvme1n1"), thread.join("3")).unwrap();
    fixture.thread_started(60, 61, 0);
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into()))
    );
}

/// A process whose leader shows no start tick in two listings may be two
/// processes under one ID, of which the walk read the first alone. The
/// walk then has no answer and the check cannot show the namespace unused,
/// whether the process table shows a start tick for other processes or for
/// none.
#[test]
fn a_process_no_listing_reads_a_start_tick_for_leaves_the_walk_without_an_answer() {
    for others in [0, 3] {
        let fixture = Fixture::new(4096);
        for pid in 0..others {
            fixture.open(100 + pid, &fixture.host.dev.join("log"));
        }
        assert_eq!(
            fixture.host.check_unused("nvme1n1").map(drop),
            Ok(()),
            "premise: beside {others} processes with a start tick the namespace is unused"
        );
        fs::create_dir_all(fixture.host.proc.join("77/fd")).unwrap();
        assert_eq!(fixture.host.opened(|_| true), None, "{others} others");
        assert_eq!(
            fixture.host.check_unused("nvme1n1").map(drop),
            Err(IdentityError::Unverifiable("processes")),
            "{others} others"
        );
    }
}

/// A thread under a command name outside UTF-8, as the kernel leaves a name
/// it cut inside a multibyte character, shows the walk the tick it started
/// in as any other thread does, so the walk reads its table and reports the
/// device it holds.
#[test]
fn a_device_open_in_a_thread_under_a_name_outside_utf8_is_in_use() {
    let fixture = Fixture::new(4096);
    fixture.open(70, &fixture.host.dev.join("other0"));
    fixture.open_on_thread(70, 71, &fixture.host.dev.join("nvme1n1"));
    let in_use = Err(IdentityError::InUse("nvme1n1".into()));
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        in_use,
        "premise: the thread under a name that is text"
    );
    // Fifteen bytes: one letter, four characters of three bytes, and the
    // first two bytes of a fifth.
    let mut stat = b"71 (a".to_vec();
    stat.extend_from_slice(&"\u{8a9e}".repeat(5).as_bytes()[..14]);
    stat.extend_from_slice(format!(") S{} 0\n", " 0".repeat(18)).as_bytes());
    assert!(std::str::from_utf8(&stat).is_err());
    fs::write(fixture.host.proc.join("70/task/71/stat"), stat).unwrap();
    assert_eq!(fixture.host.check_unused("nvme1n1").map(drop), in_use);
}

#[test]
fn a_device_open_only_in_a_thread_s_own_table_is_in_use() {
    // Each leader's table is nonempty. In the first two cases it matches the
    // thread's table in size, and in the third it is larger. The thread's
    // table is read whatever the leader's table holds.
    let fixture = Fixture::new(4096);
    fixture.open(70, &fixture.host.dev.join("other0"));
    fixture.open_on_thread(70, 71, &fixture.host.dev.join("nvme1n1"));
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into()))
    );

    let partition = Fixture::new(4096);
    partition.partition("nvme1n1", "nvme1n1p2");
    // A second name under `/dev` for the partition's device.
    let alias = partition.host.dev.join("xvdf2");
    fs::hard_link(partition.host.dev.join("nvme1n1p2"), &alias).unwrap();
    partition.open(72, &partition.host.dev.join("other1"));
    partition.open_on_thread(72, 74, &alias);
    assert_eq!(
        partition.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1p2".into()))
    );

    let busy = Fixture::new(4096);
    for n in 0..3 {
        busy.open(75, &busy.host.dev.join(format!("other{n}")));
    }
    busy.open_on_thread(75, 76, &busy.host.dev.join("other0"));
    busy.open_on_thread(75, 77, &busy.host.dev.join("nvme1n1"));
    assert_eq!(
        busy.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into()))
    );
}

#[test]
fn threads_that_share_one_table_report_each_device_once() {
    // procfs shows one shared table under the leader and every thread.
    let fixture = Fixture::new(4096);
    let volume = fixture.host.dev.join("nvme1n1");
    fixture.open(80, &volume);
    for tid in 81..=83 {
        fixture.open_on_thread(80, tid, &volume);
    }
    // The leader's own `task` entry mirrors its table, which the walk reads
    // once, through `<pid>/fd`; a file there fails any read of that entry.
    let leader_entry = fixture.host.proc.join("80/task/80/fd");
    fs::remove_dir(&leader_entry).unwrap();
    fs::write(&leader_entry, "").unwrap();
    let node = Host::node(&volume).unwrap();
    assert_eq!(fixture.host.opened(|_| true), Some(vec![node]));
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into()))
    );
}

/// Gives the calling thread its own copy of the process's descriptor
/// table. In the case's fresh child the copy holds only the child's own
/// descriptors, so no lock file of a concurrent test stays locked through
/// it.
fn unshare_files() -> bool {
    // SAFETY: `unshare` takes no memory arguments.
    unsafe { libc::unshare(libc::CLONE_FILES) == 0 }
}

/// Bounds each descriptor case's fresh child, which runs two threads and a
/// few fixture walks.
const CHILD_DEADLINE: Duration = Duration::from_secs(60);

// Each descriptor case runs in a fresh child of the test executable that
// runs only that case, so `kcmp` compares this case's own threads and no
// concurrent test's threads or descriptor tables take part.
#[test]
fn a_thread_kcmp_reports_sharing_its_leader_s_table_is_read_through_the_leader() {
    exact_child::run(
        "bind::identity_tests::a_thread_kcmp_reports_sharing_its_leader_s_table_is_read_through_the_leader",
        CHILD_DEADLINE,
        a_thread_sharing_the_leader_s_table_is_read_through_the_leader,
    );
}

fn a_thread_sharing_the_leader_s_table_is_read_through_the_leader() {
    // The fixture's process is this test process, so `kcmp` compares its
    // real threads: one shares the leader's table and one holds its own
    // after `unshare(CLONE_FILES)`. procfs shows a shared table identically
    // under the leader and each sharing thread, so a file only in the
    // sharing thread's fixture table is found exactly when that table is
    // read. Linux assigns thread IDs below `PID_MAX_LIMIT`, which is
    // 4,194,304 on 64-bit hosts, so `kcmp` fails for thread ID 4,194,304
    // and the walk reads its table.
    let pid = std::process::id();
    let found = thread::scope(|scope| {
        let (sender, reported) = mpsc::channel();
        let mut releases = Vec::new();
        for private in [false, true] {
            let (release, released) = mpsc::channel::<()>();
            releases.push(release);
            let sender = sender.clone();
            scope.spawn(move || {
                let own = private && unshare_files();
                // SAFETY: `gettid` takes no arguments.
                sender.send((own, unsafe { libc::gettid() })).unwrap();
                // The thread keeps its table until its release drops.
                let _ = released.recv();
            });
        }
        let threads: Vec<(bool, i32)> = reported.iter().take(2).collect();
        assert!(
            threads.iter().any(|(own, _)| *own),
            "a thread unshared its table"
        );
        let walk = |status: &str| {
            let fixture = Fixture::new(4096);
            fixture.file("proc/self/status", status);
            let dev = &fixture.host.dev;
            fixture.open(pid, &dev.join("leader"));
            for (own, tid) in &threads {
                let held = dev.join(if *own { "own" } else { "shared" });
                fixture.open_on_thread(pid, u32::try_from(*tid).unwrap(), &held);
            }
            fixture.open_on_thread(pid, 4_194_304, &dev.join("uncompared"));
            let found = fixture.host.opened(|_| true)?;
            Some(
                ["leader", "own", "shared", "uncompared"]
                    .into_iter()
                    .filter(|name| found.contains(&Host::node(&dev.join(name)).unwrap()))
                    .collect::<Vec<_>>(),
            )
        };
        // One `NStgid` entry names this process's namespace. Two name a
        // procfs of an ancestor namespace, and none an older kernel's, so
        // `opened` reads every thread's fixture table.
        [
            walk(&format!("Name:\ttest\nNStgid:\t{pid}\n{TRACER}")),
            walk(&format!("Name:\ttest\nNStgid:\t7\t{pid}\n{TRACER}")),
            walk(&format!("Name:\ttest\n{TRACER}")),
        ]
    });
    let every = Some(vec!["leader", "own", "shared", "uncompared"]);
    assert_eq!(
        found,
        [
            Some(vec!["leader", "own", "uncompared"]),
            every.clone(),
            every
        ]
    );
}

#[test]
fn a_share_read_through_a_thread_is_kept_only_while_that_thread_uses_the_leader_s_table() {
    exact_child::run(
        "bind::identity_tests::a_share_read_through_a_thread_is_kept_only_while_that_thread_uses_the_leader_s_table",
        CHILD_DEADLINE,
        a_share_is_kept_only_while_the_thread_uses_the_leader_s_table,
    );
}

fn a_share_is_kept_only_while_the_thread_uses_the_leader_s_table() {
    let pid = std::process::id();
    let found = thread::scope(|scope| {
        let (sender, reported) = mpsc::channel();
        let mut releases = Vec::new();
        for private in [false, true] {
            let (release, released) = mpsc::channel::<()>();
            releases.push(release);
            let sender = sender.clone();
            scope.spawn(move || {
                let own = private && unshare_files();
                // SAFETY: `gettid` takes no arguments.
                sender.send((own, unsafe { libc::gettid() })).unwrap();
                let _ = released.recv();
            });
        }
        let threads: Vec<(bool, i32)> = reported.iter().take(2).collect();
        let walk = |own: bool| {
            let (_, tid) = threads.iter().find(|(private, _)| *private == own)?;
            let tid = u32::try_from(*tid).unwrap();
            let fixture = Fixture::new(4096);
            fixture.file(
                "proc/self/status",
                &format!("Name:\ttest\nNStgid:\t{pid}\n{TRACER}"),
            );
            fs::create_dir_all(fixture.host.proc.join("self/fd")).unwrap();
            let dev = &fixture.host.dev;
            for fd in 0..300 {
                fixture.open(pid, &dev.join(format!("leader{fd}")));
                fixture.open_on_thread(pid, tid, &dev.join(format!("thread{fd}")));
            }
            let found = fixture.host.opened(|_| true)?;
            let count = |name: &str| {
                (0..300)
                    .filter(|fd| {
                        found.contains(&Host::node(&dev.join(format!("{name}{fd}"))).unwrap())
                    })
                    .count()
            };
            Some((count("leader"), count("thread")))
        };
        [walk(false), walk(true)]
    });
    // The leader's table is read a second time through the leader's own
    // directory, so every leader descriptor is found; the 172 found through
    // the thread show its shares were kept only while it shared the table.
    assert_eq!(found, [Some((300, 172)), Some((300, 300))]);
}

#[test]
fn a_thread_that_shares_the_leader_s_table_after_an_exec_is_read() {
    // A non-leader thread that execs takes over its process's ID with its
    // own table, every other thread exits, and a thread the new program
    // starts shares the replacement table, which `kcmp` then reports as the
    // leader's. The three threads here share the test process's real table.
    // The fixture uses the first thread's ID as its process ID to exercise
    // the walk's handling of another process. Until the exec releases the
    // old leader, the exec'ing thread's former ID lists that leader, dead
    // and in state `X`.
    let found = thread::scope(|scope| {
        let (sender, reported) = mpsc::channel();
        let mut releases = Vec::new();
        for _ in 0..3 {
            let (release, released) = mpsc::channel::<()>();
            releases.push(release);
            let sender = sender.clone();
            scope.spawn(move || {
                sender
                    .send(fs::read_link("/proc/thread-self").unwrap())
                    .unwrap();
                let _ = released.recv();
            });
        }
        let tids: Vec<u32> = reported
            .iter()
            .take(3)
            .map(|link| link.file_name().unwrap().to_str().unwrap().parse().unwrap())
            .collect();
        let (pid, early, late) = (tids[0], tids[1], tids[2]);
        let walk = |exec: Option<&str>| {
            let fixture = Fixture::new(4096);
            fixture.file(
                "proc/self/status",
                &format!("Name:\ttest\nNStgid:\t{}\n{TRACER}", std::process::id()),
            );
            let dev = &fixture.host.dev;
            fixture.open(pid, &dev.join("leader"));
            fixture.open_on_thread(pid, early, &dev.join("early"));
            fs::write(dev.join("late"), "").unwrap();
            // The last task ID the host gave, which the late thread's start changes.
            fixture.file("proc/loadavg", &format!("0.00 0.00 0.00 1/3 {early}\n"));
            let changed = std::sync::Once::new();
            let found = fixture.host.opened(|_| {
                if let Some(state) = exec {
                    changed.call_once(|| {
                        let task = fixture.host.proc.join(format!("{pid}/task/{early}"));
                        if state == "gone" {
                            fs::remove_dir_all(task).unwrap();
                        } else {
                            let fields = " 0".repeat(18);
                            fs::write(
                                task.join("stat"),
                                format!("{early} (t) {state}{fields} 0\n"),
                            )
                            .unwrap();
                        }
                        fixture.open_on_thread(pid, late, &dev.join("late"));
                        fixture.thread_started(pid, late, u64::MAX);
                        fixture.file("proc/loadavg", &format!("0.00 0.00 0.00 1/3 {late}\n"));
                    });
                }
                true
            })?;
            Some(
                ["leader", "early", "late"]
                    .into_iter()
                    .filter(|name| found.contains(&Host::node(&dev.join(name)).unwrap()))
                    .collect::<Vec<_>>(),
            )
        };
        [walk(None), walk(Some("gone")), walk(Some("X"))]
    });
    assert_eq!(
        found,
        [
            Some(vec!["leader"]),
            Some(vec!["leader", "late"]),
            Some(vec!["leader", "early", "late"]),
        ]
    );
}

#[test]
fn the_leader_s_table_is_read_again_when_an_exec_leaves_no_earlier_thread() {
    // A thread holding its own table execs once every other thread exits
    // and takes over the process's ID with that table, which the new
    // program's descriptors inherit. The walk read the old leader's table,
    // so it reads the process's table again when no thread that started
    // before the walk remains to prove the leader unchanged. Linux assigns
    // task IDs below 4,194,304, so the fixture's process ID lies outside
    // the live task-ID range.
    let (pid, early) = (4_194_304, 4_194_303);
    let fixture = Fixture::new(4096);
    fixture.file(
        "proc/self/status",
        &format!("Name:\ttest\nNStgid:\t{}\n{TRACER}", std::process::id()),
    );
    let dev = &fixture.host.dev;
    fixture.open(pid, &dev.join("leader"));
    fixture.open_on_thread(pid, early, &dev.join("early"));
    fs::write(dev.join("inherited"), "").unwrap();
    let changed = std::sync::Once::new();
    let found = fixture
        .host
        .opened(|_| {
            changed.call_once(|| {
                let task = fixture.host.proc.join(format!("{pid}/task/{early}"));
                fs::remove_dir_all(task).unwrap();
                fixture.open(pid, &dev.join("inherited"));
            });
            true
        })
        .unwrap();
    let names: Vec<&str> = ["leader", "early", "inherited"]
        .into_iter()
        .filter(|name| found.contains(&Host::node(&dev.join(name)).unwrap()))
        .collect();
    assert_eq!(names, ["leader", "inherited"]);
}

#[test]
fn the_leader_s_table_is_read_again_when_the_earlier_thread_dies_after_the_comparisons() {
    // A thread that started before the walk and survives the comparisons
    // proves the leader unchanged then. A thread holding its own table can
    // exec afterward: the earlier thread exits, the exec'ing thread takes
    // over the process's ID with that table, and its former ID vanishes
    // before the walk reads the table there. The walk checks the earlier
    // thread again once every queued table is read, and reads the table
    // under the process's ID when that thread is gone.
    let (pid, early, private) = (4_194_304, 4_194_303, 4_194_302);
    let fixture = Fixture::new(4096);
    fixture.file(
        "proc/self/status",
        &format!("Name:\ttest\nNStgid:\t{}\n{TRACER}", std::process::id()),
    );
    let dev = &fixture.host.dev;
    fixture.open(pid, &dev.join("leader"));
    fixture.open_on_thread(pid, early, &dev.join("early"));
    fixture.open_on_thread(pid, private, &dev.join("private"));
    fs::write(dev.join("inherited"), "").unwrap();
    let leader = Host::node(&dev.join("leader")).unwrap();
    let changed = std::sync::Once::new();
    let found = fixture
        .host
        .opened(|node| {
            if node != leader {
                changed.call_once(|| {
                    for tid in [early, private] {
                        let task = fixture.host.proc.join(format!("{pid}/task/{tid}"));
                        fs::remove_dir_all(task).unwrap();
                    }
                    fixture.open(pid, &dev.join("inherited"));
                });
            }
            true
        })
        .unwrap();
    assert!(found.contains(&leader));
    assert!(found.contains(&Host::node(&dev.join("inherited")).unwrap()));
}

#[test]
fn a_walker_that_panics_fails_the_walk() {
    let fixture = Fixture::new(4096);
    fixture.open(7, &fixture.host.dev.join("nvme1n1"));
    assert_eq!(fixture.host.opened(|_| panic!("the matcher panics")), None);
}

#[test]
fn a_vanished_thread_is_skipped_and_an_unreadable_thread_table_fails_the_walk() {
    let vanished = Fixture::new(4096);
    vanished.open(90, &vanished.host.dev.join("other0"));
    vanished.open_on_thread(90, 91, &vanished.host.dev.join("other1"));
    // A listed thread with a missing `fd` directory models a thread exiting
    // during the walk.
    fs::remove_dir_all(vanished.host.proc.join("90/task/91/fd")).unwrap();
    fs::create_dir_all(vanished.host.proc.join("90/task/92")).unwrap();
    vanished.thread_started(90, 92, 0);
    assert!(vanished.host.check_unused("nvme1n1").is_ok());
    // The walk still reads every other thread's table.
    vanished.open_on_thread(90, 95, &vanished.host.dev.join("nvme1n1"));
    assert_eq!(
        vanished.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into()))
    );

    let unreadable = Fixture::new(4096);
    unreadable.open(93, &unreadable.host.dev.join("other0"));
    unreadable.open_on_thread(93, 94, &unreadable.host.dev.join("other1"));
    fs::remove_dir_all(unreadable.host.proc.join("93/task/94/fd")).unwrap();
    // A file in place of the thread's table fails its open with `ENOTDIR`.
    unreadable.file("proc/93/task/94/fd", "");
    assert_eq!(unreadable.host.opened(|_| true), None);
    assert_eq!(
        unreadable.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("processes"))
    );
}

/// A namespace that a Xen block backend exports to a guest, or whose
/// partition one exports, is in use. The backend opens the device by number
/// inside the kernel without an exclusive claim, and the guest reads and
/// writes it: the device gains no holder, no mount or swap line and no
/// descriptor in any process. Sysfs prints the device's number in
/// hexadecimal in `bus/xen-backend/devices/vbd-<domain>-<handle>/physical_device`,
/// `0:0` until the backend is given a device. A backend over another
/// device, an unconfigured backend and a backend of another kind leave the
/// namespace unused; a backend number that does not parse, or a partition
/// whose sysfs number is unreadable while a backend exports something,
/// cannot be checked.
#[test]
fn a_namespace_exported_by_a_xen_block_backend_is_in_use() {
    /// One backend: its `physical_device` text from the namespace's number,
    /// the shift of the partition's sysfs minor from the namespace's, if it
    /// has one, and the check's answer.
    struct Case {
        name: &'static str,
        backend: fn(u32, u32) -> String,
        partition: Option<u32>,
        expected: Result<(), IdentityError>,
    }
    const DEVICES: &str = "sys/bus/xen-backend/devices";
    let exported = |backend: fn(u32, u32) -> String, partition: Option<u32>| {
        let fixture = Fixture::new(4096);
        let number = fs::read_to_string(fixture.host.sys.join("class/block/nvme1n1/dev")).unwrap();
        let (major, minor) = number.trim().split_once(':').unwrap();
        let (major, minor): (u32, u32) = (major.parse().unwrap(), minor.parse().unwrap());
        fixture.partition("nvme1n1", "nvme1n1p2");
        if let Some(shift) = partition {
            fixture.file(
                "sys/class/block/nvme1n1p2/dev",
                &format!("{major}:{}\n", minor + shift),
            );
        }
        fixture.file(&format!("{DEVICES}/vif-3-0/state"), "4\n");
        fixture.file(
            &format!("{DEVICES}/vbd-3-51728/physical_device"),
            &backend(major, minor),
        );
        fixture
    };
    let checked = |fixture: &Fixture| fixture.host.check_unused("nvme1n1").map(drop);

    let cases = [
        Case {
            name: "a backend over another device",
            backend: |major, minor| format!("{major:x}:{:x}\n", minor + 1),
            partition: Some(2),
            expected: Ok(()),
        },
        Case {
            name: "an unconfigured backend",
            backend: |_, _| "0:0\n".to_owned(),
            partition: None,
            expected: Ok(()),
        },
        Case {
            name: "a backend over the namespace",
            backend: |major, minor| format!("{major:x}:{minor:x}\n"),
            partition: Some(2),
            expected: Err(IdentityError::InUse("nvme1n1".into())),
        },
        Case {
            name: "a backend over a partition",
            backend: |major, minor| format!("{major:x}:{:x}\n", minor + 2),
            partition: Some(2),
            expected: Err(IdentityError::InUse("nvme1n1p2".into())),
        },
        Case {
            name: "a backend number that does not parse",
            backend: |_, _| "zz:1\n".to_owned(),
            partition: Some(2),
            expected: Err(IdentityError::Unverifiable("xen-backends")),
        },
        Case {
            name: "a partition with no sysfs number beside a backend",
            backend: |major, minor| format!("{major:x}:{:x}\n", minor + 1),
            partition: None,
            expected: Err(IdentityError::Unverifiable("dev")),
        },
    ];
    for case in cases {
        assert_eq!(
            checked(&exported(case.backend, case.partition)),
            case.expected,
            "{}",
            case.name
        );
    }
}

/// A namespace that an OCFS2 disk heartbeat region writes, or has a
/// partition that one does, is in use. The cluster tools hand the region a
/// descriptor of the device and close it; the kernel opens the device by
/// number without an exclusive claim, and its heartbeat thread reads and
/// writes the region's blocks every heartbeat interval, whether or not this
/// node mounts a volume there: the device gains no holder, no mount or swap
/// line and no descriptor in any process. Configfs prints the device's name
/// in `cluster/<cluster>/heartbeat/<region>/dev`. A region with no device,
/// or over another device, leaves the namespace unused, and a region whose
/// device entry cannot be read refuses.
#[test]
fn a_namespace_under_an_ocfs2_heartbeat_region_is_in_use() {
    const REGION: &str = "sys/kernel/config/cluster/c1/heartbeat/0123ABCD/dev";
    let configured = |device: &str| {
        let fixture = Fixture::new(4096);
        fixture.partition("nvme1n1", "nvme1n1p2");
        fixture.file(REGION, device);
        fixture
    };
    let checked = |fixture: &Fixture| fixture.host.check_unused("nvme1n1").map(drop);
    let in_use = |device: &str| Err(IdentityError::InUse(device.into()));

    for device in ["", "nvme0n1\n", "nvme1n10\n"] {
        assert_eq!(
            checked(&configured(device)),
            Ok(()),
            "a region over {device:?}"
        );
    }
    assert_eq!(
        checked(&configured("nvme1n1\n")),
        in_use("nvme1n1"),
        "a region over the namespace"
    );
    assert_eq!(
        checked(&configured("nvme1n1p2\n")),
        in_use("nvme1n1p2"),
        "a region over a partition"
    );
    let other = Fixture::new(4096);
    other.file("sys/kernel/config/cluster/c1/heartbeat/mode", "global\n");
    other.file("sys/kernel/config/cluster/c1/node/n1/num", "1\n");
    assert_eq!(checked(&other), Ok(()), "a cluster with no region");

    let unreadable = configured("nvme0n1\n");
    let entry = unreadable.root.join(REGION);
    fs::remove_file(&entry).unwrap();
    fs::create_dir(&entry).unwrap();
    assert_eq!(
        checked(&unreadable),
        Err(IdentityError::Unverifiable("heartbeats")),
        "a region whose device entry cannot be read"
    );
}

/// A namespace under an OCFS2 disk heartbeat region is in use whichever
/// directory configfs is mounted at; the mount table names that directory.
/// The same region listed under the conventional directory refuses, which
/// shows the listing is well formed, and a host with configfs mounted at the
/// other directory and no region stays unused.
#[test]
fn a_heartbeat_region_under_another_configfs_mount_is_in_use() {
    const MOUNTS: &str = "/dev/nvme0n1p1 / xfs rw 0 0\nconfigfs /config configfs rw,relatime 0 0\n";
    let region = |fixture: &Fixture, configfs: &str| {
        fixture.file(
            &format!("{configfs}/cluster/c1/heartbeat/0123ABCD/dev"),
            "nvme1n1\n",
        );
    };
    let conventional = Fixture::new(4096);
    region(&conventional, "sys/kernel/config");
    assert_eq!(
        conventional.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: the region refuses under the conventional mount"
    );
    let idle = Fixture::new(4096);
    idle.file("config/cluster/c1/heartbeat/mode", "global\n");
    idle.file("proc/self/mounts", MOUNTS);
    assert_eq!(
        idle.host.check_unused("nvme1n1").map(drop),
        Ok(()),
        "premise: another configfs mount with no region leaves the namespace unused"
    );

    let elsewhere = Fixture::new(4096);
    region(&elsewhere, "config");
    elsewhere.file("proc/self/mounts", MOUNTS);
    assert_eq!(
        elsewhere.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "the same region with configfs mounted at /config"
    );
}

/// A namespace the RNBD server exports, or one with an exported partition,
/// is in use. The server opens the device inside the kernel without an
/// exclusive claim, and its remote clients read and write it: the namespace
/// gains no holder, no mount or swap line and no descriptor in any process.
/// Sysfs lists each exported device by its block device name under
/// `class/rnbd-server/ctl/devices`. An export of another device leaves the
/// namespace unused, and a listing that cannot be read refuses.
#[test]
fn a_namespace_the_rnbd_server_exports_is_in_use() {
    const DEVICES: &str = "sys/class/rnbd-server/ctl/devices";
    let exported = |device: &str| {
        let fixture = Fixture::new(4096);
        fixture.partition("nvme1n1", "nvme1n1p2");
        fixture.file(
            &format!("{DEVICES}/{device}/sessions/client1/mapping_path"),
            "volume\n",
        );
        fixture
    };
    let checked = |fixture: &Fixture| fixture.host.check_unused("nvme1n1").map(drop);
    let in_use = |device: &str| Err(IdentityError::InUse(device.into()));

    assert_eq!(
        checked(&exported("nvme1n1")),
        in_use("nvme1n1"),
        "an export of the namespace"
    );
    assert_eq!(
        checked(&exported("nvme1n1p2")),
        in_use("nvme1n1p2"),
        "an export of a partition"
    );

    for device in ["nvme0n1", "nvme1n10", "nvme1n1p20"] {
        assert_eq!(checked(&exported(device)), Ok(()), "an export of {device}");
    }
    let idle = Fixture::new(4096);
    fs::create_dir_all(idle.root.join(DEVICES)).unwrap();
    assert_eq!(checked(&idle), Ok(()), "a server that exports nothing");

    let unreadable = Fixture::new(4096);
    unreadable.file(DEVICES, "");
    assert_eq!(
        checked(&unreadable),
        Err(IdentityError::Unverifiable("rnbd")),
        "an export listing that cannot be read"
    );
}

/// A namespace moved from one loop device to another during the check, as
/// `losetup` on a free device and then `losetup -d` on the old one leave it,
/// backs a loop device at every instant, so it is in use. One reading of
/// the loop devices lists the block devices and then reads each backing
/// file: here the device listed first is free when it is read, the
/// namespace moves while the check reads the next device's backing file, a
/// FIFO for that one read, and the device listed last no longer backs it
/// when it is read. A reading after the move finds the device listed first.
#[test]
fn a_namespace_moved_between_loop_devices_during_the_check_is_in_use() {
    use std::io::Write;

    let fixture = Fixture::new(4096);
    fixture.file("var/disk.img", "");
    let block = fixture.host.sys.join("block");
    for name in ["loop0", "loop1", "loop2"] {
        fs::create_dir_all(block.join(name)).unwrap();
    }
    // The roles follow the order the listing yields, which the check sees too.
    let listed: Vec<_> = fs::read_dir(&block)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.starts_with("loop"))
        .collect();
    let [free, pause, bound] = <[String; 3]>::try_from(listed).unwrap();
    let backing = |name: &str| block.join(name).join("loop/backing_file");
    fixture.loop_device(&bound, "/dev/nvme1n1");
    fixture.loop_device(&pause, "/var/disk.img");
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: the loop device listed last is found"
    );
    let fifo = backing(&pause);
    make_fifo(&fifo);
    let writer = {
        let (fifo, to, from) = (fifo.clone(), backing(&free), backing(&bound));
        let dev = &fixture.host.dev;
        let (node, to_node, from_node) = (dev.join("nvme1n1"), dev.join(&free), dev.join(&bound));
        thread::spawn(move || {
            let mut sink = fs::OpenOptions::new().write(true).open(&fifo).unwrap();
            fs::create_dir_all(to.parent().unwrap()).unwrap();
            fs::hard_link(&node, &to_node).unwrap();
            fs::write(&to, "/dev/nvme1n1\n").unwrap();
            fs::remove_dir_all(from.parent().unwrap()).unwrap();
            fs::remove_file(&from_node).unwrap();
            // A later reading of this device finds a file again, as the first premise did.
            fs::remove_file(&fifo).unwrap();
            fs::write(&fifo, "/var/disk.img\n").unwrap();
            let _sent = sink.write_all(b"/var/disk.img\n");
        })
    };
    let checked = fixture.host.check_unused("nvme1n1").map(drop);
    // A check that never read the FIFO releases the writer here.
    let _reader = release(&fifo);
    writer.join().unwrap();
    assert!(!backing(&bound).exists(), "premise: the move ran");
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: after the move the loop device listed first is found"
    );
    assert_eq!(
        checked,
        Err(IdentityError::InUse("nvme1n1".into())),
        "a namespace backing a loop device at every instant of the check was admitted"
    );
}

/// A namespace that backs a LUN of a USB gadget mass-storage function, or
/// has a partition that does, is in use. The function opens the LUN's
/// backing file inside the kernel without an exclusive claim, and the USB
/// host on the other side reads and writes it: the namespace gains no
/// holder, no mount or swap line and no descriptor in any process. Configfs
/// prints the open file's path in
/// `usb_gadget/<gadget>/functions/mass_storage.<name>/lun.<n>/file`, which
/// can be a second node of the device. A LUN with no file leaves the
/// namespace unused. A LUN over another file or device may have opened its
/// path in another mount namespace, where it can name the namespace, so the
/// use is unknown, and a LUN whose file names no node under the host root,
/// or whose entry cannot be read, refuses too.
#[test]
fn a_namespace_backing_a_usb_gadget_mass_storage_lun_is_in_use() {
    const LUN: &str = "sys/kernel/config/usb_gadget/g1/functions/mass_storage.usb0/lun.0/file";
    let configured = |file: &str| {
        let fixture = Fixture::new(4096);
        fixture.partition("nvme1n1", "nvme1n1p2");
        fixture.file("var/disk.img", "an image");
        fixture.file(LUN, file);
        fixture
    };
    let checked = |fixture: &Fixture| fixture.host.check_unused("nvme1n1").map(drop);
    let in_use = |device: &str| Err(IdentityError::InUse(device.into()));

    assert_eq!(
        checked(&configured("/dev/nvme1n1\n")),
        in_use("nvme1n1"),
        "a LUN over the namespace"
    );
    assert_eq!(
        checked(&configured("/dev/nvme1n1p2\n")),
        in_use("nvme1n1p2"),
        "a LUN over a partition"
    );
    let aliased = configured("/run/disk\n");
    fs::hard_link(
        aliased.host.dev.join("nvme1n1"),
        aliased.root.join("run/disk"),
    )
    .unwrap();
    assert_eq!(
        checked(&aliased),
        in_use("nvme1n1"),
        "a LUN over a second node of the namespace"
    );

    assert_eq!(checked(&configured("\n")), Ok(()), "a LUN with no file");
    let other = Fixture::new(4096);
    other.file(
        "sys/kernel/config/usb_gadget/g1/functions/ecm.usb0/dev_addr",
        "02:00:00:00:00:01\n",
    );
    assert_eq!(checked(&other), Ok(()), "a gadget with no mass storage");

    let unverifiable = Err(IdentityError::Unverifiable("gadgets"));
    for file in ["/var/disk.img\n", "/dev/nvme0n1\n"] {
        assert_eq!(
            checked(&configured(file)),
            unverifiable,
            "a LUN over {file:?}"
        );
    }
    assert_eq!(
        checked(&configured("/dev/nvme1n1 (deleted)\n")),
        unverifiable,
        "a LUN whose file names no node"
    );
    let unreadable = configured("/var/disk.img\n");
    let entry = unreadable.root.join(LUN);
    fs::remove_file(&entry).unwrap();
    fs::create_dir(&entry).unwrap();
    assert_eq!(
        checked(&unreadable),
        unverifiable,
        "a LUN whose file entry cannot be read"
    );
}

/// A mass-storage LUN prints its backing file's path and one newline, so a
/// newline before the last belongs to the path. A LUN over a second node of
/// the namespace whose name ends with a newline is in use, whatever file the
/// name without it names; a LUN over that other file leaves the namespace's
/// use unknown.
#[test]
fn a_gadget_lun_over_a_node_whose_name_ends_with_a_newline_is_in_use() {
    const LUN: &str = "sys/kernel/config/usb_gadget/g1/functions/mass_storage.usb0/lun.0/file";
    let fixture = Fixture::new(4096);
    fs::create_dir_all(fixture.root.join("run")).unwrap();
    fixture.file("run/volume", "another file");
    let checked = |fixture: &Fixture| fixture.host.check_unused("nvme1n1").map(drop);

    fixture.file(LUN, "/run/volume\n");
    assert_eq!(
        checked(&fixture),
        Err(IdentityError::Unverifiable("gadgets")),
        "a LUN over the other file"
    );

    fs::hard_link(
        fixture.host.dev.join("nvme1n1"),
        fixture.root.join("run/volume\n"),
    )
    .unwrap();
    fixture.file(LUN, "/run/volume\n\n");
    assert_eq!(
        checked(&fixture),
        Err(IdentityError::InUse("nvme1n1".to_owned())),
        "a LUN over a node of the namespace whose name ends with a newline"
    );
}

/// A gadget LUN over an unlinked second node of the namespace is not
/// admitted when another file holds the name the kernel prints for it. A
/// LUN's `file` prints the open file's path, and the kernel prints an
/// unlinked file `/run/volume` as `/run/volume (deleted)`, the same text
/// it prints for a linked file of that name. The text does not tell which
/// of the two the LUN serves, so the regular file found at that path says
/// nothing about the unlinked node, as for a loop device's backing file.
#[test]
fn a_gadget_lun_over_an_unlinked_node_is_not_admitted_by_a_file_named_as_deleted() {
    const LUN: &str = "sys/kernel/config/usb_gadget/g1/functions/mass_storage.usb0/lun.0/file";
    let fixture = Fixture::new(4096);
    fixture.file(LUN, "/run/volume (deleted)\n");
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("gadgets")),
        "premise: with no file of that name the LUN already refuses"
    );

    fixture.file("run/volume (deleted)", "");
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("gadgets")),
        "a file at the path the kernel prints for the unlinked node"
    );
}

/// A namespace that backs a LUN of a legacy mass-storage gadget module, or
/// has a partition that does, is in use. A legacy module (`g_mass_storage`
/// and the composite modules that carry the function) has no configfs
/// entry: it registers each LUN as a device under the gadget device of its
/// USB device controller, `class/udc/<controller>/device/gadget.<n>/lun<n>`
/// in sysfs, named `gadget` on kernels before 5.19 and `lun` for a
/// single LUN on older ones, and prints the open file's path in its `file`
/// as configfs does. A LUN with no file leaves the namespace unused, a LUN
/// over another file or device leaves its use unknown, and a LUN whose
/// entry cannot be read refuses.
#[test]
fn a_namespace_backing_a_legacy_gadget_module_lun_is_in_use() {
    const LUN: &str = "sys/class/udc/dummy_udc.0/device/gadget.0/lun0/file";
    let configured = |entry: &str, file: &str| {
        let fixture = Fixture::new(4096);
        fixture.partition("nvme1n1", "nvme1n1p2");
        fixture.file("var/disk.img", "an image");
        fixture.file(entry, file);
        fixture
    };
    let checked = |fixture: &Fixture| fixture.host.check_unused("nvme1n1").map(drop);
    let in_use = |device: &str| Err(IdentityError::InUse(device.into()));

    assert_eq!(
        checked(&configured(LUN, "\n")),
        Ok(()),
        "a LUN with no file"
    );
    for file in ["/var/disk.img\n", "/dev/nvme0n1\n"] {
        assert_eq!(
            checked(&configured(LUN, file)),
            Err(IdentityError::Unverifiable("gadgets")),
            "a LUN over {file:?}"
        );
    }
    let other = configured("sys/class/udc/dummy_udc.0/device/gadget.0/suspended", "0\n");
    assert_eq!(checked(&other), Ok(()), "a gadget with no mass storage");

    assert_eq!(
        checked(&configured(LUN, "/dev/nvme1n1\n")),
        in_use("nvme1n1"),
        "a LUN over the namespace"
    );
    assert_eq!(
        checked(&configured(LUN, "/dev/nvme1n1p2\n")),
        in_use("nvme1n1p2"),
        "a LUN over a partition"
    );
    assert_eq!(
        checked(&configured(
            "sys/class/udc/dummy_udc.0/device/gadget/lun/file",
            "/dev/nvme1n1\n"
        )),
        in_use("nvme1n1"),
        "a LUN under the gadget device's earlier names"
    );

    let unverifiable = Err(IdentityError::Unverifiable("gadgets"));
    assert_eq!(
        checked(&configured(LUN, "/dev/nvme1n1 (deleted)\n")),
        unverifiable,
        "a LUN whose file names no node"
    );
    let unreadable = configured(LUN, "/var/disk.img\n");
    let entry = unreadable.root.join(LUN);
    fs::remove_file(&entry).unwrap();
    fs::create_dir(&entry).unwrap();
    assert_eq!(
        checked(&unreadable),
        unverifiable,
        "a LUN whose file entry cannot be read"
    );
}

/// A process that holds the namespace open and, during the check, adds a
/// partition, opens it and closes its descriptor on the namespace keeps the
/// namespace in use at every instant: open in a process, then a partition of
/// it open in that process. The handoff happens while the walk reads the
/// uptime, a FIFO here, after the check listed the namespace's partitions and
/// before the walk reads any descriptor table.
#[test]
fn a_namespace_handed_to_a_partition_added_during_the_check_is_in_use() {
    use std::io::Write;

    let fixture = Fixture::new(4096);
    let node = fixture.host.dev.join("nvme1n1");
    fixture.open(4242, &node);
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: the descriptor alone is found"
    );
    let uptime = fixture.host.proc.join("uptime");
    make_fifo(&uptime);
    let (partition, node_of_partition, table) = (
        fixture.host.sys.join("block/nvme1n1/nvme1n1p2/holders"),
        fixture.host.dev.join("nvme1n1p2"),
        fixture.host.proc.join("4242/fd"),
    );
    assert_eq!(fs::read_link(table.join("3")).unwrap(), node, "premise");
    let writer = {
        let (uptime, partition, node_of_partition, table) = (
            uptime.clone(),
            partition.clone(),
            node_of_partition.clone(),
            table.clone(),
        );
        thread::spawn(move || {
            let mut sink = fs::OpenOptions::new().write(true).open(&uptime).unwrap();
            fs::create_dir_all(&partition).unwrap();
            fs::write(&node_of_partition, "").unwrap();
            std::os::unix::fs::symlink(&node_of_partition, table.join("4")).unwrap();
            fs::remove_file(table.join("3")).unwrap();
            let _sent = sink.write_all(b"100.00 400.00\n");
        })
    };
    let checked = fixture.host.check_unused("nvme1n1").map(drop);
    // A check that never read the uptime releases the writer here.
    let _reader = release(&uptime);
    writer.join().unwrap();
    fs::remove_file(&uptime).unwrap();
    fs::write(&uptime, "100.00 400.00\n").unwrap();
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1p2".into())),
        "premise: after the handoff the partition alone is found"
    );
    assert_eq!(
        checked,
        Err(IdentityError::Unverifiable("partitions")),
        "a namespace in use at every instant of the check was admitted"
    );
}

/// A partition deleted and added again during the check keeps its name and
/// is another device, with another node. A process that holds the namespace
/// open, replaces a listed partition so, opens the new partition and closes
/// its descriptor on the namespace keeps the namespace in use at every
/// instant, and the walk matches its descriptor against the node the
/// partition had before. The handoff happens while the walk reads the
/// uptime, a FIFO here, after the check resolved the partition's node and
/// before the walk reads any descriptor table.
#[test]
fn a_namespace_handed_to_a_listed_partition_added_again_during_the_check_is_in_use() {
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;
    let fixture = Fixture::new(4096);
    let node = fixture.host.dev.join("nvme1n1");
    let node_of_partition = fixture.host.dev.join("nvme1n1p2");
    fs::create_dir_all(fixture.host.sys.join("block/nvme1n1/nvme1n1p2/holders")).unwrap();
    fs::write(&node_of_partition, "").unwrap();
    let listed = fs::metadata(&node_of_partition).unwrap().ino();
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Ok(()),
        "premise: the namespace and its listed partition are unused"
    );
    fixture.open(4242, &node);
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: the descriptor alone is found"
    );
    let uptime = fixture.host.proc.join("uptime");
    make_fifo(&uptime);
    let table = fixture.host.proc.join("4242/fd");
    assert_eq!(fs::read_link(table.join("3")).unwrap(), node, "premise");
    let writer = {
        let (uptime, node_of_partition, table) =
            (uptime.clone(), node_of_partition.clone(), table.clone());
        let added = fixture.host.dev.join("nvme1n1p2.added");
        thread::spawn(move || {
            let mut sink = fs::OpenOptions::new().write(true).open(&uptime).unwrap();
            // The new node exists beside the old one, so it is another file.
            fs::write(&added, "").unwrap();
            fs::rename(&added, &node_of_partition).unwrap();
            std::os::unix::fs::symlink(&node_of_partition, table.join("4")).unwrap();
            fs::remove_file(table.join("3")).unwrap();
            let _sent = sink.write_all(b"100.00 400.00\n");
        })
    };
    let checked = fixture.host.check_unused("nvme1n1").map(drop);
    // A check that never read the uptime releases the writer here.
    let _reader = release(&uptime);
    writer.join().unwrap();
    fs::remove_file(&uptime).unwrap();
    fs::write(&uptime, "100.00 400.00\n").unwrap();
    assert_ne!(
        fs::metadata(&node_of_partition).unwrap().ino(),
        listed,
        "premise: the partition added again has another node"
    );
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1p2".into())),
        "premise: after the handoff the partition alone is found"
    );
    assert_eq!(
        checked,
        Err(IdentityError::Unverifiable("partitions")),
        "a namespace in use at every instant of the check was admitted"
    );
}

/// A namespace that backs an enabled SCSI target file backstore is in use:
/// the target serves initiators from it. The file backstore opens its
/// backing path as a file inside the kernel, so no descriptor table,
/// `holders` entry, exclusive claim, mount or swap line shows the use;
/// configfs names the path under `target/core/fileio_<n>/<name>`, in
/// `udev_path` and in the `File:` field of `info`.
#[test]
fn a_namespace_backing_a_scsi_target_file_backstore_is_in_use() {
    let fixture = Fixture::new(4096);
    assert!(fixture.host.check_unused("nvme1n1").is_ok());
    let backstore = "sys/kernel/config/target/core/fileio_0/disk0";
    fixture.file(&format!("{backstore}/udev_path"), "/dev/nvme1n1\n");
    fixture.file(&format!("{backstore}/enable"), "1\n");
    fixture.file(
        &format!("{backstore}/info"),
        "Status: ACTIVATED  Max Queue Depth: 0  SectorSize: 512  HwMaxSectors: 16384\n        \
         TCM FILEIO ID: 0        File: /dev/nvme1n1  Size: 4096  Mode: O_DSYNC Async: 0\n",
    );
    let refused = fixture.host.check_unused("nvme1n1").map(drop);
    assert!(
        matches!(refused, Err(IdentityError::InUse(_))),
        "a file backstore over the namespace: {refused:?}"
    );
    // The path the kernel opens decides alone, and names a partition as it names the namespace.
    let partition = Fixture::new(4096);
    partition.partition("nvme1n1", "nvme1n1p2");
    partition.file(
        "sys/kernel/config/target/core/fileio_3/lun/info",
        "Status: DEACTIVATED  Max Queue Depth: 0  SectorSize: 512  HwMaxSectors: 16384\n        \
         TCM FILEIO ID: 3        File: /dev/nvme1n1p2  Size: 0  Mode: Buffered-WCE Async: 0\n",
    );
    assert_eq!(
        partition.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1p2".to_owned())),
        "a file backstore over a partition"
    );
    // A backstore of another kind and a host with no backstore leave the namespace unused.
    let other = Fixture::new(4096);
    other.file(
        "sys/kernel/config/target/core/fileio_0/hba_info",
        "HBA Index: 1 plugin: fileio\n",
    );
    other.file(
        "sys/kernel/config/target/core/iblock_0/disk0/udev_path",
        "/dev/nvme1n1\n",
    );
    other.file(
        "sys/kernel/config/target/core/alua/default_lu_gp/lu_gp_id",
        "0\n",
    );
    assert!(
        other.host.check_unused("nvme1n1").is_ok(),
        "other backstores"
    );
    // A file backstore over another file or device may have opened its path in another mount
    // namespace, where it can name the namespace, so the use is unknown.
    other.file("var/disk.img", "");
    other.file("dev/nvme1n10", "");
    other.file(
        "sys/kernel/config/target/core/fileio_0/image/udev_path",
        "/var/disk.img\n",
    );
    other.file(
        "sys/kernel/config/target/core/fileio_0/image/info",
        "File: /dev/nvme1n10  Size: 1\n",
    );
    assert_eq!(
        other.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("targets")),
        "a file backstore over another file or device"
    );
    // An entry that cannot be read leaves the use unknown.
    let unreadable = Fixture::new(4096);
    fs::create_dir_all(
        unreadable
            .host
            .sys
            .join("kernel/config/target/core/fileio_0/disk0/udev_path"),
    )
    .unwrap();
    assert_eq!(
        unreadable.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("targets")),
    );
}

/// A namespace the kernel's NVMe target exports, or whose partition it
/// exports, is in use: an enabled target namespace whose `device_path` names
/// it serves remote hosts from it. The target opens the device without a
/// holder, so no descriptor table, `holders` entry, mount or swap line shows
/// the use; configfs lists it under `nvmet/subsystems/<nqn>/namespaces/<nsid>`.
/// Mount namespaces can resolve `device_path` differently, so an enabled
/// target namespace backed by another device makes the check unverifiable.
#[test]
fn a_namespace_an_nvme_target_exports_is_in_use() {
    let fixture = Fixture::new(4096);
    let subsystem = "sys/kernel/config/nvmet/subsystems/nqn.2026-11.test:export";
    fixture.file(
        &format!("{subsystem}/namespaces/2/device_path"),
        "/dev/nvme1n1\n",
    );
    fixture.file(&format!("{subsystem}/namespaces/2/enable"), "0\n");
    assert!(fixture.host.check_unused("nvme1n1").is_ok());
    fixture.file(
        &format!("{subsystem}/namespaces/3/device_path"),
        "/dev/nvme1n10\n",
    );
    fixture.file(&format!("{subsystem}/namespaces/3/enable"), "1\n");
    fixture.file("dev/nvme1n10", "");
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("targets")),
        "a target namespace backed by another device"
    );
    let exported = format!("{subsystem}/namespaces/1");
    fixture.file(&format!("{exported}/device_path"), "/dev/nvme1n1\n");
    fixture.file(&format!("{exported}/enable"), "1\n");
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "a target namespace backed by the namespace"
    );

    let partition = Fixture::new(4096);
    partition.partition("nvme1n1", "nvme1n1p2");
    partition.file(&format!("{exported}/device_path"), "/dev/nvme1n1p2\n");
    partition.file(&format!("{exported}/enable"), "1\n");
    assert_eq!(
        partition.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1p2".into())),
        "a target namespace backed by a partition"
    );

    let unreadable = Fixture::new(4096);
    fs::create_dir_all(unreadable.root.join(format!("{exported}/enable"))).unwrap();
    assert_eq!(
        unreadable.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("targets")),
        "a target namespace whose enable flag cannot be read"
    );

    let unlisted = Fixture::new(4096);
    unlisted.file(&format!("{subsystem}/namespaces"), "");
    assert_eq!(
        unlisted.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("targets")),
        "a subsystem whose namespace listing cannot be read"
    );
}

/// A file backstore names its backing path as its creator wrote it, and the
/// kernel opens that path, following links. A backstore created over a
/// `/dev/disk/by-id` link to the namespace serves initiators from the
/// namespace as one created over `/dev/nvme1n1` does, so the namespace is in
/// use; one over a link to another device leaves its use unknown.
#[test]
fn a_file_backstore_over_a_link_to_the_namespace_is_in_use() {
    let link = "dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_vol0123456789abcdef0";
    let linked = |target: &str| {
        let fixture = Fixture::new(4096);
        fixture.file("dev/nvme2n1", "");
        fs::create_dir_all(fixture.root.join("dev/disk/by-id")).unwrap();
        symlink(target, fixture.root.join(link)).unwrap();
        let backstore = "sys/kernel/config/target/core/fileio_0/disk0";
        fixture.file(&format!("{backstore}/udev_path"), &format!("/{link}\n"));
        fixture.file(&format!("{backstore}/enable"), "1\n");
        fixture.file(
            &format!("{backstore}/info"),
            &format!(
                "Status: ACTIVATED  Max Queue Depth: 0  SectorSize: 512  HwMaxSectors: 16384\n        \
                 TCM FILEIO ID: 0        File: /{link}  Size: 4096  Mode: O_DSYNC Async: 0\n"
            ),
        );
        fixture
    };
    let namespace = linked("../../nvme1n1");
    let refused = namespace.host.check_unused("nvme1n1").map(drop);
    assert!(
        matches!(refused, Err(IdentityError::InUse(_))),
        "a file backstore over a link to the namespace: {refused:?}"
    );
    let other = linked("../../nvme2n1");
    assert_eq!(
        other.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("targets")),
        "a file backstore over a link to another device"
    );
}

/// Bounds the ring-pass case's fresh child, which runs 2000 passes over its
/// own process table beside threads that start and exit.
const RING_PASS_DEADLINE: Duration = Duration::from_secs(300);

/// On the running kernel, [`Host::registered`] completes while threads of
/// the process it reads start and exit: procfs answers `EACCES` or `ESRCH`
/// for a thread released between two reads of the pass, and the pass
/// skips that thread as vanished. The process table read is the test
/// process's own, under its own process ID, where its leader's start tick
/// reads, and holds no ring, so each pass must complete.
///
/// The case runs in a fresh child of the test executable that runs only
/// this case, so the table holds this case's threads and descriptors and no
/// concurrent test's. Another test's descriptors, opened and closed at new
/// numbers through every pass, read as moved rings and fail the pass.
#[test]
fn a_thread_that_exits_during_the_ring_pass_is_skipped() {
    exact_child::run(
        "bind::identity_tests::a_thread_that_exits_during_the_ring_pass_is_skipped",
        RING_PASS_DEADLINE,
        a_ring_pass_beside_exiting_threads_completes,
    );
}

fn a_ring_pass_beside_exiting_threads_completes() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let fixture = Fixture::new(4096);
    let own = fixture.root.join(format!("proc/{}", std::process::id()));
    symlink("/proc/self", own).unwrap();
    let stop = AtomicBool::new(false);
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                while !stop.load(Ordering::Relaxed) {
                    std::thread::scope(|short| {
                        for _ in 0..8 {
                            short.spawn(|| drop(fs::File::open("/proc/self/stat")));
                        }
                    });
                }
            });
        }
        let complete = (0..2000).all(|_| fixture.host.registered(|_| true).is_some());
        stop.store(true, Ordering::Relaxed);
        assert!(complete, "a pass beside exiting threads completes");
    });
}

/// A namespace or partition a process registered with an io_uring instance
/// is open in that process after it closes the descriptor: the ring reads
/// and writes the device through its registered-file table. The process's
/// descriptor table then holds the ring alone, in the leader's table or in
/// a thread's private one, and the ring's `fdinfo` lists the device under
/// `UserFiles`. The check refuses the device the ring names. A ring that
/// holds other files, or an empty table, leaves the namespace unused.
#[test]
fn a_namespace_registered_with_an_io_uring_and_closed_is_in_use() {
    let in_use = |task: &str, files: &[&str]| {
        let fixture = Fixture::new(4096);
        fixture.partition("nvme1n1", "nvme1n1p1");
        assert!(fixture.host.check_unused("nvme1n1").is_ok());
        hold_ring(&fixture, task, 5, &ring_info(files));
        fixture.host.check_unused("nvme1n1").map(drop)
    };
    for task in ["4242", "4242/task/4243"] {
        for (files, device) in [
            (&["nvme1n1"][..], "nvme1n1"),
            (&["<none>", "log", "nvme1n1p1"][..], "nvme1n1p1"),
        ] {
            assert_eq!(
                in_use(task, files),
                Err(IdentityError::InUse(device.to_owned())),
                "a ring of {task} holding {files:?}"
            );
        }
        for files in [&[][..], &["<none>", "nvme0n1", "nvme1n10", "nvme1n"][..]] {
            assert_eq!(
                in_use(task, files),
                Ok(()),
                "a ring of {task} holding {files:?}"
            );
        }
    }
}

/// A ring's registered-file table the check cannot read whole leaves the
/// namespace unverifiable, not unused: a kernel that cannot take the ring's
/// lock prints the table's count and no slot, so a count with no slot line
/// after it, or a ring with no count, may hide the namespace. A ring that
/// vanished with its `fdinfo` holds nothing.
#[test]
fn a_ring_whose_table_is_not_listed_whole_is_unverifiable() {
    use super::rings::registered_files;

    let whole = ring_info(&["a", "dir/nvme1n1", "<none>"]);
    assert_eq!(
        registered_files(&whole, false),
        Some(vec!["a", "nvme1n1", "<none>"])
    );
    let unlisted = ring_info(&["a", "b"]).replace("    0: a\n    1: b\n", "");
    let uncounted = ring_info(&[]).replace("UserFiles:\t0\n", "");
    for info in [&unlisted, &uncounted] {
        assert_eq!(registered_files(info, false), None, "{info}");
        let fixture = Fixture::new(4096);
        hold_ring(&fixture, "4242", 5, info);
        assert_eq!(
            fixture.host.check_unused("nvme1n1").map(drop),
            Err(IdentityError::Unverifiable("processes")),
            "{info}"
        );
    }
    let fixture = Fixture::new(4096);
    hold_ring(&fixture, "4242", 5, &whole);
    fs::remove_file(fixture.root.join("proc/4242/fdinfo/5")).unwrap();
    assert!(fixture.host.check_unused("nvme1n1").is_ok());
}

/// Linux 6.12 prints a registered file's name as it is, a line break
/// included, so a table whose earlier names hold line breaks reads as more
/// lines than it has slots. The text below is what that kernel printed for
/// a ring holding three files: one named `"x\n    1: y"`, one named
/// `"q\nstop"`, and the namespace in the last slot. The same table under
/// plain names is the sibling, which the check refuses as in use. Under
/// the names with line breaks the table still holds the namespace, so the
/// check must not answer unused.
#[test]
fn a_registered_name_with_a_line_break_hides_no_later_slot() {
    const PRINTED: &str = "pos:\t0\nflags:\t02000002\nmnt_id:\t17\nino:\t18561241\nSqThread:\t-1\nSqThreadCpu:\t-1\nUserFiles:\t3\n    0: x\n    1: y\n    1: q\nstop\n    2: nvme1n1\nUserBufs:\t0\nPollList:\nCqOverflowList:\nNAPI:\tdisabled\n";
    let checked = |info: &str| {
        let fixture = Fixture::new(4096);
        assert!(fixture.host.check_unused("nvme1n1").is_ok());
        hold_ring(&fixture, "4242", 5, info);
        fixture.host.check_unused("nvme1n1").map(drop)
    };
    assert_eq!(
        checked(&ring_info(&["x", "q", "nvme1n1"])),
        Err(IdentityError::InUse("nvme1n1".to_owned())),
        "the same table under names without a line break"
    );
    let hidden = checked(PRINTED);
    assert!(
        hidden.is_err(),
        "a ring holding the namespace in its last slot left it unused: {hidden:?}"
    );
}

/// No line ends the read of a ring's table, since a registered name can
/// hold any line. The text is what Linux 6.12.115 prints for a ring holding
/// a file named `"x\n    1: y\nUserBufs:\t0"`, one named `q`, the namespace
/// and one registered buffer: the slots after the forged `UserBufs` line
/// are read, and the buffer's slot-shaped line adds its length as a name.
#[test]
fn a_registered_name_that_forges_the_end_of_the_table_hides_no_later_slot() {
    use super::rings::registered_files;

    const PRINTED: &str = "pos:\t0\nflags:\t02000002\nSqThreadCpu:\t-1\nSqTotalTime:\t0\nSqWorkTime:\t0\nUserFiles:\t3\n    0: x\n    1: y\nUserBufs:\t0\n    1: q\n    2: nvme1n1\nUserBufs:\t1\n    0: 0x7fd6777bd000/4096\nPollList:\nCqOverflowList:\nNAPI:\tdisabled\n";
    assert_eq!(
        registered_files(PRINTED, false),
        Some(vec!["x", "y", "q", "nvme1n1", "4096"])
    );
    let fixture = Fixture::new(4096);
    hold_ring(&fixture, "4242", 5, PRINTED);
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".to_owned()))
    );
}

/// A descriptor table the ring pass cannot list while its task is present
/// leaves the namespace unverifiable: only a failure whose task is gone
/// reads as a vanished task.
#[test]
fn a_descriptor_table_unreadable_beside_its_task_is_unverifiable() {
    for task in ["4242", "4242/task/4243"] {
        let fixture = Fixture::new(4096);
        fixture.process(4242);
        fixture.file("proc/4242/fdinfo/5", &ring_info(&[]));
        assert_eq!(fixture.host.registered(|_| true), Some(Vec::new()));
        fixture.file(&format!("proc/{task}/fd"), "");
        assert_eq!(
            fixture.host.registered(|_| true),
            None,
            "a file in place of the table of {task}"
        );
    }
}

/// The fixture of the two tests below: the volume's namespace with its
/// generic node present and registered in sysfs, both character nodes
/// closed, and process 4242 holding one ring whose registered-file table
/// lists `file`. Returns what the check answers.
fn checks_beside_a_ring_holding(file: &str) -> Result<(), IdentityError> {
    let fixture = Fixture::new(4096);
    fs::write(fixture.host.dev.join("ng1n1"), "").unwrap();
    fixture.file("sys/class/nvme/nvme1/ng1n1/dev", "241:1\n");
    assert!(
        fixture.host.check_unused("nvme1n1").is_ok(),
        "premise: both character nodes present and closed, no ring"
    );
    hold_ring(&fixture, "4242", 5, &ring_info(&[file]));
    fixture.host.check_unused("nvme1n1").map(drop)
}

/// The same ring holding the namespace's block node refuses: the premise
/// that the fixture's ring is read.
#[test]
fn a_ring_holding_the_block_node_beside_closed_character_nodes_is_in_use() {
    assert_eq!(
        checks_beside_a_ring_holding("nvme1n1"),
        Err(IdentityError::InUse("nvme1n1".to_owned()))
    );
}

/// A process that opens the namespace's generic node `ng<c>n<n>` or its
/// controller's node `nvme<c>`, registers it with an io_uring instance and
/// closes the descriptor still sends the namespace commands through the
/// ring's registered-file table, as passthrough with fixed files does. Its
/// descriptor table then holds the ring alone, and the ring's `fdinfo`
/// lists the character node under `UserFiles`. The check refuses a
/// namespace open in any process.
#[test]
fn a_character_node_registered_with_an_io_uring_and_closed_is_in_use() {
    for node in ["ng1n1", "nvme1"] {
        assert_eq!(
            checks_beside_a_ring_holding(node),
            Err(IdentityError::InUse("nvme1n1".to_owned())),
            "a ring holding {node}"
        );
    }
}

/// An NVMe target namespace names its device path as its creator wrote it,
/// and the kernel opens that path, following links. A target namespace
/// enabled over a `/dev/disk/by-id` link to the namespace exports the
/// namespace as one enabled over `/dev/nvme1n1` does, so the namespace is in
/// use.
#[test]
fn an_nvme_target_namespace_over_a_link_to_the_namespace_is_in_use() {
    let link = "dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_vol0123456789abcdef0";
    let linked = |target: &str| {
        let fixture = Fixture::new(4096);
        fixture.file("dev/nvme2n1", "");
        fs::create_dir_all(fixture.root.join("dev/disk/by-id")).unwrap();
        symlink(target, fixture.root.join(link)).unwrap();
        let exported = "sys/kernel/config/nvmet/subsystems/nqn.2026-11.test:export/namespaces/1";
        fixture.file(&format!("{exported}/device_path"), &format!("/{link}\n"));
        fixture.file(&format!("{exported}/enable"), "1\n");
        fixture
    };
    let namespace = linked("../../nvme1n1");
    let refused = namespace.host.check_unused("nvme1n1").map(drop);
    assert!(
        matches!(refused, Err(IdentityError::InUse(_))),
        "a target namespace over a link to the namespace: {refused:?}"
    );
    let other = linked("../../nvme2n1");
    assert_eq!(
        other.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("targets")),
        "a target namespace over a link to another device"
    );
    // A path that resolves to no node does not tell which device the target exports.
    let dangling = linked("../../nvme3n1");
    assert_eq!(
        dangling.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("targets")),
        "a target namespace over a dangling link"
    );
}

/// A file backstore keeps the file it opened while its recorded path names
/// nothing: after `mknod /run/volume`, a backstore created over it, and
/// `rm /run/volume`, `udev_path` and `info` still name `/run/volume` and the
/// backstore serves initiators from the namespace. The path tells no device,
/// so the check refuses, as it does for a backstore whose path names another
/// device.
#[test]
fn a_file_backstore_over_an_unlinked_node_is_not_admitted() {
    let backstore = |path: &str| {
        let fixture = Fixture::new(4096);
        fixture.file("dev/nvme2n1", "");
        let backstore = "sys/kernel/config/target/core/fileio_0/disk0";
        fixture.file(&format!("{backstore}/udev_path"), &format!("{path}\n"));
        fixture.file(&format!("{backstore}/enable"), "1\n");
        fixture.file(
            &format!("{backstore}/info"),
            &format!(
                "Status: ACTIVATED  Max Queue Depth: 0  SectorSize: 512  HwMaxSectors: 16384\n        \
                 TCM FILEIO ID: 0        File: {path}  Size: 4096  Mode: O_DSYNC Async: 0\n"
            ),
        );
        fixture
    };
    let other = backstore("/dev/nvme2n1");
    assert_eq!(
        other.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("targets")),
        "a file backstore over another device"
    );
    let unlinked = backstore("/run/volume");
    let refused = unlinked.host.check_unused("nvme1n1").map(drop);
    assert!(
        matches!(
            refused,
            Err(IdentityError::Unverifiable(_) | IdentityError::InUse(_))
        ),
        "a file backstore whose path names no node: {refused:?}"
    );
}

/// A file backstore created inside another mount namespace keeps the
/// namespace in use even when its recorded path names a different device
/// here. The kernel opens a file backstore's path when it is enabled, in the
/// mount namespace of the process that writes `enable`, and keeps the path
/// text as written: a target run in a container whose private `/dev` holds
/// the namespace's node as `/dev/xvda` leaves `udev_path` and `info` naming
/// `/dev/xvda`. On a Nitro host that path is the udev link to the root
/// volume, `nvme0n1`. The path then names a block device, yet not the one the
/// backstore serves, and nothing in configfs records which device it opened.
#[test]
fn a_file_backstore_whose_path_names_another_device_here_is_not_admitted() {
    let fixture = Fixture::new(4096);
    let named = fixture.host.dev.join("xvda");
    symlink("nvme0n1", &named).unwrap();
    assert_eq!(
        Host::node(&named),
        Host::node(&fixture.host.dev.join("nvme0n1")),
        "premise: the path names nvme0n1 here"
    );
    assert_ne!(
        Host::node(&named),
        Host::node(&fixture.host.dev.join("nvme1n1")),
        "premise: the path does not name the namespace here"
    );
    let backstore = "sys/kernel/config/target/core/fileio_0/disk0";
    fixture.file(&format!("{backstore}/udev_path"), "/dev/xvda\n");
    fixture.file(&format!("{backstore}/enable"), "1\n");
    fixture.file(
        &format!("{backstore}/info"),
        "Status: ACTIVATED  Max Queue Depth: 0  SectorSize: 512  HwMaxSectors: 16384\n        \
         TCM FILEIO ID: 0        File: /dev/xvda  Size: 4096  Mode: O_DSYNC Async: 0\n",
    );
    let admitted = fixture.host.check_unused("nvme1n1").map(drop);
    assert!(
        admitted.is_err(),
        "a file backstore over the namespace whose path names nvme0n1 here: {admitted:?}"
    );
}

/// An enabled NVMe target's `device_path` can name different devices in the
/// container that enabled the target and in the checking process, so a path
/// that resolves in the checking process to a device other than the
/// namespace or a partition leaves the namespace's use unverifiable.
#[test]
fn an_nvme_target_namespace_whose_path_names_another_device_here_is_not_admitted() {
    let fixture = Fixture::new(4096);
    let named = fixture.host.dev.join("xvda");
    symlink("nvme0n1", &named).unwrap();
    assert_eq!(
        Host::node(&named),
        Host::node(&fixture.host.dev.join("nvme0n1")),
        "premise: the path names nvme0n1 here"
    );
    assert_ne!(
        Host::node(&named),
        Host::node(&fixture.host.dev.join("nvme1n1")),
        "premise: the path names a node other than the namespace's here"
    );
    let exported = "sys/kernel/config/nvmet/subsystems/nqn.2026-11.test:export/namespaces/1";
    fixture.file(&format!("{exported}/device_path"), "/dev/xvda\n");
    fixture.file(&format!("{exported}/enable"), "1\n");
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("targets")),
        "a target namespace over the namespace whose path names nvme0n1 here"
    );
}

/// A mass-storage LUN opens its backing file in the mount namespace of the
/// process that wrote `file`, and prints the path it holds there. A path
/// that resolves in the checking process to a device other than the
/// namespace or a partition can name the namespace where the LUN opened it,
/// so it leaves the namespace's use unverifiable, under configfs and under a
/// legacy gadget module alike.
#[test]
fn a_gadget_lun_whose_path_names_another_device_here_is_not_admitted() {
    for lun in [
        "sys/kernel/config/usb_gadget/g1/functions/mass_storage.usb0/lun.0/file",
        "sys/class/udc/dummy_udc.0/device/gadget.0/lun0/file",
    ] {
        let fixture = Fixture::new(4096);
        let named = fixture.host.dev.join("xvda");
        symlink("nvme0n1", &named).unwrap();
        assert_eq!(
            Host::node(&named),
            Host::node(&fixture.host.dev.join("nvme0n1")),
            "premise: the path names nvme0n1 here"
        );
        assert_ne!(
            Host::node(&named),
            Host::node(&fixture.host.dev.join("nvme1n1")),
            "premise: the path names a node other than the namespace's here"
        );
        fixture.file(lun, "/dev/xvda\n");
        assert_eq!(
            fixture.host.check_unused("nvme1n1").map(drop),
            Err(IdentityError::Unverifiable("gadgets")),
            "{lun}: a LUN over the namespace whose path names nvme0n1 here"
        );
    }
}

/// A file backstore's `info` prints the path the kernel opens between
/// `File: ` and the `  Size: ` field that closes it, and that path can hold
/// two spaces or end with a space. A backstore over a second node of the
/// namespace under such a name serves initiators from the namespace, so the
/// namespace is in use, whatever file the name's first part names; a
/// backstore over that other file leaves its use unknown.
#[test]
fn a_file_backstore_over_a_node_whose_name_holds_two_spaces_is_in_use() {
    let backed = |name: &str| {
        let fixture = Fixture::new(4096);
        fs::create_dir_all(fixture.root.join("run")).unwrap();
        fixture.file("run/volume", "another file");
        if name != "volume" {
            let node = fixture.root.join("run").join(name);
            fs::hard_link(fixture.host.dev.join("nvme1n1"), node).unwrap();
        }
        let backstore = "sys/kernel/config/target/core/fileio_0/disk0";
        // A backstore whose creator recorded no path.
        fixture.file(&format!("{backstore}/udev_path"), "\n");
        fixture.file(&format!("{backstore}/enable"), "1\n");
        fixture.file(
            &format!("{backstore}/info"),
            &format!(
                "Status: ACTIVATED  Max Queue Depth: 0  SectorSize: 512  HwMaxSectors: 16384\n        \
                 TCM FILEIO ID: 0        File: /run/{name}  Size: 4096  Mode: O_DSYNC Async: 0\n"
            ),
        );
        fixture
    };
    let checked = |fixture: &Fixture| fixture.host.check_unused("nvme1n1").map(drop);

    assert_eq!(
        checked(&backed("volume")),
        Err(IdentityError::Unverifiable("targets")),
        "a file backstore over the other file"
    );
    for name in ["volume ", "volume  two", "volume  Size: 1  Mode: x"] {
        assert_eq!(
            checked(&backed(name)),
            Err(IdentityError::InUse("nvme1n1".to_owned())),
            "a file backstore over a node of the namespace named {name:?}"
        );
    }
}

/// An NVMe target subsystem in passthrough mode takes the controller its
/// `passthru/device_path` names inside the kernel and forwards every remote
/// host's commands to it, so that controller's namespace is in use while the
/// passthrough is enabled: no holder, mount, swap line or descriptor shows
/// it. The path is the one the passthrough was configured with, which can be
/// a second node of the controller. A passthrough that is not enabled leaves
/// the namespace unused, and an enabled passthrough whose path names no node
/// under the host root, or whose entries cannot be read, refuses.
#[test]
fn a_namespace_under_an_nvme_target_passthrough_controller_is_in_use() {
    const PASSTHRU: &str = "sys/kernel/config/nvmet/subsystems/nqn.2026-11.test:passthru/passthru";
    let configured = |device_path: &str, enable: &str| {
        let fixture = Fixture::new(4096);
        fixture.file("dev/nvme1", "controller 1");
        fixture.file("dev/nvme2", "controller 2");
        fixture.file(&format!("{PASSTHRU}/device_path"), device_path);
        fixture.file(&format!("{PASSTHRU}/enable"), enable);
        fixture
    };
    let checked = |fixture: &Fixture| fixture.host.check_unused("nvme1n1").map(drop);
    let in_use = Err(IdentityError::InUse("nvme1n1".into()));

    assert_eq!(
        checked(&configured("/dev/nvme1\n", "1\n")),
        in_use,
        "a passthrough of the namespace's controller"
    );
    let aliased = configured("/run/nvme-target\n", "1\n");
    fs::hard_link(
        aliased.host.dev.join("nvme1"),
        aliased.root.join("run/nvme-target"),
    )
    .unwrap();
    assert_eq!(
        checked(&aliased),
        in_use,
        "a passthrough of a second node of the namespace's controller"
    );

    for (device_path, enable) in [
        ("/dev/nvme2\n", "0\n"),
        ("/dev/nvme1\n", "0\n"),
        ("(null)\n", "0\n"),
    ] {
        assert_eq!(
            checked(&configured(device_path, enable)),
            Ok(()),
            "a passthrough of {device_path:?} with enable {enable:?}"
        );
    }
    let bare = Fixture::new(4096);
    fs::create_dir_all(
        bare.host
            .sys
            .join("kernel/config/nvmet/subsystems/nqn.bare"),
    )
    .unwrap();
    assert_eq!(checked(&bare), Ok(()), "a subsystem with no passthrough");

    let unverifiable = Err(IdentityError::Unverifiable("targets"));
    assert_eq!(
        checked(&configured("/dev/gone\n", "1\n")),
        unverifiable,
        "an enabled passthrough of a path that names no node"
    );
    let unreadable = configured("/dev/nvme2\n", "1\n");
    let device_path = unreadable.root.join(PASSTHRU).join("device_path");
    fs::remove_file(&device_path).unwrap();
    fs::create_dir(&device_path).unwrap();
    assert_eq!(
        checked(&unreadable),
        unverifiable,
        "an enabled passthrough whose device path cannot be read"
    );
}

/// A process that holds the namespace open and, during the check, makes it
/// the backing file of a loop device and closes its descriptor, as
/// `losetup` does, keeps the namespace in use at every instant: open in a
/// process until the loop device backs it. The handoff happens while the
/// walk reads the uptime, a FIFO here, after the check read the loop
/// devices' backing files and before the walk reads any descriptor table.
#[test]
fn a_namespace_handed_from_a_descriptor_to_a_loop_device_during_the_check_is_in_use() {
    use std::io::Write;

    let fixture = Fixture::new(4096);
    let node = fixture.host.dev.join("nvme1n1");
    fs::create_dir_all(fixture.host.sys.join("block/loop0")).unwrap();
    fixture.open(4242, &node);
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: the descriptor alone is found"
    );
    let uptime = fixture.host.proc.join("uptime");
    make_fifo(&uptime);
    let (backing, descriptor) = (
        fixture.host.sys.join("block/loop0/loop/backing_file"),
        fixture.host.proc.join("4242/fd/3"),
    );
    assert_eq!(fs::read_link(&descriptor).unwrap(), node, "premise");
    let writer = {
        let (uptime, backing, descriptor) = (uptime.clone(), backing.clone(), descriptor.clone());
        let (node, device) = (node.clone(), fixture.host.dev.join("loop0"));
        thread::spawn(move || {
            let mut sink = fs::OpenOptions::new().write(true).open(&uptime).unwrap();
            fs::create_dir_all(backing.parent().unwrap()).unwrap();
            fs::hard_link(&node, &device).unwrap();
            fs::write(&backing, "/dev/nvme1n1\n").unwrap();
            fs::remove_file(&descriptor).unwrap();
            let _sent = sink.write_all(b"100.00 400.00\n");
        })
    };
    let checked = fixture.host.check_unused("nvme1n1").map(drop);
    // A check that never read the uptime releases the writer here.
    let _reader = release(&uptime);
    writer.join().unwrap();
    fs::remove_file(&uptime).unwrap();
    fs::write(&uptime, "100.00 400.00\n").unwrap();
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: after the handoff the loop device alone is found"
    );
    assert_eq!(
        checked,
        Err(IdentityError::InUse("nvme1n1".into())),
        "a namespace in use at every instant of the check was admitted"
    );
}

/// The kernel opens a passthrough's `device_path` where the writer of the
/// configfs entry resolves it and prints the text back unchanged. A writer
/// in another mount namespace can name the namespace's controller by a path
/// that names a different controller under the host root, or a regular file,
/// and configfs keeps no other record of the controller the passthrough
/// holds. So an enabled passthrough whose path is not provably the
/// namespace's controller refuses rather than admitting the namespace; the
/// same paths with the passthrough disabled leave it unused.
#[test]
fn an_enabled_passthrough_whose_path_names_another_controller_here_is_not_admitted() {
    const PASSTHRU: &str = "sys/kernel/config/nvmet/subsystems/nqn.2026-11.test:foreign/passthru";
    let configured = |device_path: &str, enable: &str| {
        let fixture = Fixture::new(4096);
        fixture.file("dev/nvme1", "controller 1");
        fixture.file("dev/nvme2", "controller 2");
        fixture.file("srv/image", "a regular file");
        fixture.file(&format!("{PASSTHRU}/device_path"), device_path);
        fixture.file(&format!("{PASSTHRU}/enable"), enable);
        fixture
    };
    let checked = |fixture: &Fixture| fixture.host.check_unused("nvme1n1").map(drop);

    for device_path in ["/dev/nvme2\n", "/srv/image\n"] {
        assert_eq!(
            checked(&configured(device_path, "1\n")),
            Err(IdentityError::Unverifiable("targets")),
            "an enabled passthrough of {device_path:?}"
        );
        assert_eq!(
            checked(&configured(device_path, "0\n")),
            Ok(()),
            "a disabled passthrough of {device_path:?}"
        );
    }
}

/// Configfs mounts wherever the administrator puts it; `/sys/kernel/config`
/// is a convention. A namespace an enabled NVMe target namespace exports is
/// in use whichever directory shows the target's configuration, and the
/// mount table names that directory. The same export listed under the
/// conventional directory refuses, which shows the listing is well formed.
#[test]
fn an_nvme_target_export_under_another_configfs_mount_is_in_use() {
    let export = |fixture: &Fixture, configfs: &str| {
        let namespace = format!("{configfs}/nvmet/subsystems/nqn.2026-11.test:export/namespaces/1");
        fixture.file(&format!("{namespace}/device_path"), "/dev/nvme1n1\n");
        fixture.file(&format!("{namespace}/enable"), "1\n");
    };
    let conventional = Fixture::new(4096);
    export(&conventional, "sys/kernel/config");
    assert_eq!(
        conventional.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: the export refuses under the conventional mount"
    );

    let elsewhere = Fixture::new(4096);
    export(&elsewhere, "config");
    elsewhere.file(
        "proc/self/mounts",
        "/dev/nvme0n1p1 / xfs rw 0 0\nconfigfs /config configfs rw,relatime 0 0\n",
    );
    assert_eq!(
        elsewhere.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "the same export with configfs mounted at /config"
    );
}

#[test]
fn another_configfs_mount_is_read_as_the_conventional_one() {
    let mounted = |fixture: &Fixture, kind: &str| {
        fixture.file(
            "proc/self/mounts",
            &format!("/dev/nvme0n1p1 / xfs rw 0 0\nnone /config {kind} rw,relatime 0 0\n"),
        );
    };
    let subsystem = "config/nvmet/subsystems/nqn.2026-11.test:export";
    let fixture = Fixture::new(4096);
    mounted(&fixture, "configfs");
    fixture.file(
        &format!("{subsystem}/namespaces/2/device_path"),
        "/dev/nvme1n1\n",
    );
    fixture.file(&format!("{subsystem}/namespaces/2/enable"), "0\n");
    assert!(fixture.host.check_unused("nvme1n1").is_ok());
    fixture.file("dev/nvme1n10", "");
    fixture.file(
        &format!("{subsystem}/namespaces/1/device_path"),
        "/dev/nvme1n10\n",
    );
    fixture.file(&format!("{subsystem}/namespaces/1/enable"), "1\n");
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("targets")),
        "a target namespace over another device"
    );

    let unlisted = Fixture::new(4096);
    mounted(&unlisted, "configfs");
    unlisted.file(&format!("{subsystem}/namespaces"), "");
    assert_eq!(
        unlisted.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("targets")),
        "a namespace listing that cannot be read"
    );

    let other = Fixture::new(4096);
    mounted(&other, "tmpfs");
    other.file(
        &format!("{subsystem}/namespaces/1/device_path"),
        "/dev/nvme1n1\n",
    );
    other.file(&format!("{subsystem}/namespaces/1/enable"), "1\n");
    assert!(other.host.check_unused("nvme1n1").is_ok());
}

/// A SCSI target file backstore over the namespace is in use whichever
/// directory configfs is mounted at; the mount table names that directory.
/// The same backstore listed under the conventional directory refuses, which
/// shows the listing is well formed.
#[test]
fn a_scsi_target_file_backstore_under_another_configfs_mount_is_in_use() {
    let backstore = |fixture: &Fixture, configfs: &str| {
        fixture.file(
            &format!("{configfs}/target/core/fileio_0/disk0/udev_path"),
            "/dev/nvme1n1\n",
        );
    };
    let conventional = Fixture::new(4096);
    backstore(&conventional, "sys/kernel/config");
    assert_eq!(
        conventional.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: the backstore refuses under the conventional mount"
    );

    let elsewhere = Fixture::new(4096);
    backstore(&elsewhere, "config");
    elsewhere.file(
        "proc/self/mounts",
        "/dev/nvme0n1p1 / xfs rw 0 0\nconfigfs /config configfs rw,relatime 0 0\n",
    );
    assert_eq!(
        elsewhere.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "the same backstore with configfs mounted at /config"
    );
}

/// An enabled NVMe target passthrough of the namespace's controller is in use
/// whichever directory configfs is mounted at; the mount table names that
/// directory. The same passthrough listed under the conventional directory
/// refuses, which shows the listing is well formed.
#[test]
fn an_nvme_target_passthrough_under_another_configfs_mount_is_in_use() {
    let passthrough = |fixture: &Fixture, configfs: &str| {
        let passthru = format!("{configfs}/nvmet/subsystems/nqn.2026-11.test:passthru/passthru");
        fixture.file("dev/nvme1", "controller 1");
        fixture.file(&format!("{passthru}/device_path"), "/dev/nvme1\n");
        fixture.file(&format!("{passthru}/enable"), "1\n");
    };
    let conventional = Fixture::new(4096);
    passthrough(&conventional, "sys/kernel/config");
    assert_eq!(
        conventional.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: the passthrough refuses under the conventional mount"
    );

    let elsewhere = Fixture::new(4096);
    passthrough(&elsewhere, "config");
    elsewhere.file(
        "proc/self/mounts",
        "/dev/nvme0n1p1 / xfs rw 0 0\nconfigfs /config configfs rw,relatime 0 0\n",
    );
    assert_eq!(
        elsewhere.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "the same passthrough with configfs mounted at /config"
    );
}

/// Another configfs mount is read as the conventional one is: a subsystem
/// listing there that cannot be read leaves the check unverifiable, and a
/// directory the mount table gives another type is not a target listing.
#[test]
fn a_passthrough_listing_under_another_mount_is_read_as_the_conventional_one() {
    let mounted = |fixture: &Fixture, kind: &str| {
        fixture.file("dev/nvme1", "controller 1");
        fixture.file(
            "proc/self/mounts",
            &format!("/dev/nvme0n1p1 / xfs rw 0 0\nnone /config {kind} rw,relatime 0 0\n"),
        );
    };
    let unlisted = Fixture::new(4096);
    mounted(&unlisted, "configfs");
    unlisted.file("config/nvmet/subsystems", "");
    assert_eq!(
        unlisted.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("targets")),
        "a subsystem listing that cannot be read"
    );

    let other = Fixture::new(4096);
    mounted(&other, "tmpfs");
    let passthru = "config/nvmet/subsystems/nqn.2026-11.test:passthru/passthru";
    other.file(&format!("{passthru}/device_path"), "/dev/nvme1\n");
    other.file(&format!("{passthru}/enable"), "1\n");
    assert!(other.host.check_unused("nvme1n1").is_ok());
}

/// A USB gadget mass-storage LUN over the namespace is in use whichever
/// directory configfs is mounted at; the mount table names that directory.
/// The same LUN listed under the conventional directory refuses, which shows
/// the listing is well formed.
#[test]
fn a_usb_gadget_lun_under_another_configfs_mount_is_in_use() {
    let lun = |fixture: &Fixture, configfs: &str| {
        fixture.file(
            &format!("{configfs}/usb_gadget/g1/functions/mass_storage.usb0/lun.0/file"),
            "/dev/nvme1n1\n",
        );
    };
    let conventional = Fixture::new(4096);
    lun(&conventional, "sys/kernel/config");
    assert_eq!(
        conventional.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: the LUN refuses under the conventional mount"
    );

    let elsewhere = Fixture::new(4096);
    lun(&elsewhere, "config");
    elsewhere.file(
        "proc/self/mounts",
        "/dev/nvme0n1p1 / xfs rw 0 0\nconfigfs /config configfs rw,relatime 0 0\n",
    );
    assert_eq!(
        elsewhere.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "the same LUN with configfs mounted at /config"
    );
}

/// Under a configfs mount the mount table names, a gadget LUN with no
/// backing file leaves the namespace unused, one over another device leaves
/// its use unknown, and a LUN whose `file` cannot be read refuses. A mount
/// of another type at a directory with the same entries is no gadget
/// listing.
#[test]
fn another_configfs_mount_is_read_as_the_conventional_gadget_listing() {
    let mounted = |fixture: &Fixture, kind: &str| {
        fixture.file(
            "proc/self/mounts",
            &format!("/dev/nvme0n1p1 / xfs rw 0 0\nnone /config {kind} rw,relatime 0 0\n"),
        );
    };
    let function = "config/usb_gadget/g1/functions/mass_storage.usb0";
    let fixture = Fixture::new(4096);
    mounted(&fixture, "configfs");
    fixture.file(&format!("{function}/lun.1/file"), "\n");
    assert_eq!(fixture.host.check_unused("nvme1n1").map(drop), Ok(()));
    fixture.file(&format!("{function}/lun.0/file"), "/dev/nvme0n1\n");
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("gadgets")),
        "a LUN over another device"
    );

    let unreadable = Fixture::new(4096);
    mounted(&unreadable, "configfs");
    fs::create_dir_all(unreadable.root.join(function).join("lun.0/file")).unwrap();
    assert_eq!(
        unreadable.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("gadgets")),
        "a LUN whose file cannot be read"
    );

    let other = Fixture::new(4096);
    mounted(&other, "tmpfs");
    other.file(&format!("{function}/lun.0/file"), "/dev/nvme1n1\n");
    assert_eq!(other.host.check_unused("nvme1n1").map(drop), Ok(()));
}

/// A process that holds the namespace open and, during the check, enables a
/// SCSI target file backstore over it and closes its descriptor keeps the
/// namespace in use at every instant: open in a process until the backstore
/// serves it. The file backstore opens its path inside the kernel and takes
/// no exclusive claim, so the final exclusive open does not see it either.
/// The handoff happens while the walk reads the uptime, a FIFO here, after
/// the check read the target's backstores and before the walk reads any
/// descriptor table.
#[test]
fn a_namespace_handed_from_a_descriptor_to_a_file_backstore_during_the_check_is_in_use() {
    use std::io::Write;

    let fixture = Fixture::new(4096);
    let node = fixture.host.dev.join("nvme1n1");
    fs::create_dir_all(fixture.host.sys.join("kernel/config/target/core")).unwrap();
    fixture.open(4242, &node);
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: the descriptor alone is found"
    );
    let uptime = fixture.host.proc.join("uptime");
    make_fifo(&uptime);
    let (backstore, descriptor) = (
        fixture
            .host
            .sys
            .join("kernel/config/target/core/fileio_0/disk0"),
        fixture.host.proc.join("4242/fd/3"),
    );
    assert_eq!(fs::read_link(&descriptor).unwrap(), node, "premise");
    let writer = {
        let (uptime, backstore, descriptor) =
            (uptime.clone(), backstore.clone(), descriptor.clone());
        thread::spawn(move || {
            let mut sink = fs::OpenOptions::new().write(true).open(&uptime).unwrap();
            fs::create_dir_all(&backstore).unwrap();
            fs::write(backstore.join("udev_path"), "/dev/nvme1n1\n").unwrap();
            fs::write(backstore.join("enable"), "1\n").unwrap();
            fs::write(
                backstore.join("info"),
                "Status: ACTIVATED  Max Queue Depth: 0  SectorSize: 512  HwMaxSectors: 16384\n        \
                 TCM FILEIO ID: 0        File: /dev/nvme1n1  Size: 4096  Mode: O_DSYNC Async: 0\n",
            )
            .unwrap();
            fs::remove_file(&descriptor).unwrap();
            let _sent = sink.write_all(b"100.00 400.00\n");
        })
    };
    let checked = fixture.host.check_unused("nvme1n1").map(drop);
    // A check that never read the uptime releases the writer here.
    let _reader = release(&uptime);
    writer.join().unwrap();
    fs::remove_file(&uptime).unwrap();
    fs::write(&uptime, "100.00 400.00\n").unwrap();
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: after the handoff the file backstore alone is found"
    );
    assert_eq!(
        checked,
        Err(IdentityError::InUse("nvme1n1".into())),
        "a namespace in use at every instant of the check was admitted"
    );
}

/// A namespace held by a device-mapper device that, during the check, a
/// process opens and the device-mapper device then releases is in use at
/// every instant: held by another block device until a descriptor holds it.
/// The process's descriptor takes no exclusive claim, so the final exclusive
/// open does not see it. The ring's `fdinfo` and `uptime` are FIFOs here.
/// The handoff happens at the first opening of the `fdinfo` after the walk
/// began by reading `uptime`: inside the ring reading after the walk, once
/// the walk read every descriptor table and before the check reads the
/// namespace's holders again.
#[test]
fn a_namespace_handed_from_a_holder_to_a_descriptor_during_the_check_is_in_use() {
    use std::io::Write;

    use std::sync::atomic::{AtomicBool, Ordering};
    let fixture = Fixture::new(4096);
    let node = fixture.host.dev.join("nvme1n1");
    let holder = fixture.host.sys.join("block/nvme1n1/holders/dm-0");
    fs::write(&holder, "").unwrap();
    hold_ring(&fixture, "5000", 3, &ring_info(&[]));
    fixture.process(4242);
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: the holder alone is found"
    );
    let info = fixture.root.join("proc/5000/fdinfo/3");
    fs::remove_file(&info).unwrap();
    make_fifo(&info);
    let uptime = fixture.host.proc.join("uptime");
    fs::remove_file(&uptime).unwrap();
    make_fifo(&uptime);
    let table = fixture.root.join("proc/4242/fd");
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let walking = std::sync::Arc::new(AtomicBool::new(false));
    // Serves `text` to every opening of `fifo` until `stop`, running
    // `opened` after each opening and before the text is written.
    let serve = |fifo: &Path, text: String, mut opened: Box<dyn FnMut() + Send>| {
        let (fifo, stop) = (fifo.to_owned(), stop.clone());
        thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                let Ok(mut sink) = fs::OpenOptions::new().write(true).open(&fifo) else {
                    break;
                };
                opened();
                let _sent = sink.write_all(text.as_bytes());
            }
        })
    };
    // The walk reads the uptime as it begins, after the ring reading before it.
    let clock = serve(&uptime, "100.00 400.00\n".to_owned(), {
        let walking = walking.clone();
        Box::new(move || walking.store(true, Ordering::SeqCst))
    });
    // The first opening of the ring after the walk began is the ring reading after the walk.
    let ring = serve(&info, ring_info(&[]), {
        let (walking, table, holder, node) =
            (walking.clone(), table.clone(), holder.clone(), node.clone());
        Box::new(move || {
            if walking.load(Ordering::SeqCst) && holder.exists() {
                fs::create_dir_all(&table).unwrap();
                symlink(&node, table.join("3")).unwrap();
                fs::remove_file(&holder).unwrap();
            }
        })
    });
    let checked = fixture.host.check_unused("nvme1n1").map(drop);
    // The check is over, so each writer is released from its next opening.
    stop.store(true, Ordering::SeqCst);
    while !(clock.is_finished() && ring.is_finished()) {
        for fifo in [&info, &uptime] {
            let _reader = release(fifo);
        }
        thread::yield_now();
    }
    clock.join().unwrap();
    ring.join().unwrap();
    for (fifo, text) in [
        (&info, ring_info(&[])),
        (&uptime, "100.00 400.00\n".to_owned()),
    ] {
        fs::remove_file(fifo).unwrap();
        fs::write(fifo, text).unwrap();
    }
    assert!(!holder.exists(), "premise: the handoff ran");
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: after the handoff the descriptor alone is found"
    );
    assert_eq!(
        checked,
        Err(IdentityError::InUse("nvme1n1".into())),
        "a namespace in use at every instant of the check was admitted"
    );
}

/// The mount table lines among `lines`, each paired with the directory its
/// configfs mount shows, under which an enabled NVMe target namespace over
/// the volume is admitted as unused.
fn admitted_exports(lines: &[(&'static str, &'static str)]) -> Vec<&'static str> {
    lines
        .iter()
        .filter_map(|&(directory, line)| {
            let fixture = Fixture::new(4096);
            let namespace =
                format!("{directory}/nvmet/subsystems/nqn.2026-11.test:export/namespaces/1");
            fixture.file(&format!("{namespace}/device_path"), "/dev/nvme1n1\n");
            fixture.file(&format!("{namespace}/enable"), "1\n");
            fixture.file(
                "proc/self/mounts",
                &format!("/dev/nvme0n1p1 / xfs rw 0 0\n{line}\n"),
            );
            let checked = fixture.host.check_unused("nvme1n1").map(drop);
            (checked != Err(IdentityError::InUse("nvme1n1".into()))).then_some(line)
        })
        .collect()
}

/// The kernel prints a mount made with an empty source name as a line that
/// starts with the field separator, so the directory is the line's first
/// word. An enabled NVMe target namespace over the volume is in use under
/// such a configfs mount, as under one whose source has a name.
#[test]
fn an_nvme_target_export_under_a_configfs_mount_with_no_source_name_is_in_use() {
    let admitted = admitted_exports(&[
        ("config", "configfs /config configfs rw,relatime 0 0"),
        ("config", " /config configfs rw,relatime 0 0"),
    ]);
    assert_eq!(
        admitted, [""; 0],
        "mount table lines whose export was admitted"
    );
}

/// A namespace moved between loop devices during each of the first two
/// passes over them backs a loop device at every instant, so it is in use. In
/// each of those passes the device listed first is free when it is read; at
/// the first pause the namespace moves to it from the device listed third,
/// which is then free when it is read; at the second pause, after both were
/// read, it moves back. Each move is a configure and a detach, and each sends
/// a uevent, as the loop driver does, so the host's uevent counter moves
/// across both passes and the check reads the devices again. Each pause is a
/// FIFO for one read of a device that backs another file.
#[test]
fn a_namespace_moved_during_each_reading_of_the_loop_devices_is_in_use() {
    use std::io::Write;

    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let fixture = Fixture::new(4096);
    fixture.file("var/disk.img", "");
    let block = fixture.host.sys.join("block");
    for name in ["loop0", "loop1", "loop2", "loop3"] {
        fs::create_dir_all(block.join(name)).unwrap();
    }
    // The roles follow the order the listing yields, which the check sees too.
    let listed: Vec<_> = fs::read_dir(&block)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.starts_with("loop"))
        .collect();
    let [free, first, bound, second] = <[String; 4]>::try_from(listed).unwrap();
    let backing = |name: &str| block.join(name).join("loop/backing_file");
    fixture.loop_device(&bound, "/dev/nvme1n1");
    for pause in [&first, &second] {
        fixture.loop_device(pause, "/var/disk.img");
    }
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: the loop device listed third is found"
    );
    let fifos = [backing(&first), backing(&second)];
    for fifo in &fifos {
        make_fifo(fifo);
    }
    let counter = fixture.host.sys.join("kernel/uevent_seqnum");
    let dev = fixture.host.dev.clone();
    // Configure `to` over the namespace, then detach `from`; the kernel
    // sends one uevent for each. Each loop device's node stands for its
    // record of the backing node.
    let shift = move |to: &Path, from: &Path| {
        let name = |entry: &Path| {
            entry
                .ancestors()
                .nth(2)
                .unwrap()
                .file_name()
                .unwrap()
                .to_owned()
        };
        fs::create_dir_all(to.parent().unwrap()).unwrap();
        fs::hard_link(dev.join("nvme1n1"), dev.join(name(to))).unwrap();
        fs::write(to, "/dev/nvme1n1\n").unwrap();
        fs::remove_dir_all(from.parent().unwrap()).unwrap();
        fs::remove_file(dev.join(name(from))).unwrap();
        let sent: u64 = fs::read_to_string(&counter)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        fs::write(&counter, format!("{}\n", sent + 2)).unwrap();
    };
    let done = Arc::new(AtomicBool::new(false));
    // Moves the namespace at the four pauses of the first two passes, then
    // answers each later pause without a move, until the check has returned.
    let writer = {
        let (fifos, early, late) = (fifos.clone(), backing(&free), backing(&bound));
        let done = Arc::clone(&done);
        thread::spawn(move || {
            let mut moves = [(&early, &late), (&late, &early)]
                .into_iter()
                .cycle()
                .take(4);
            for fifo in fifos.iter().cycle() {
                let mut sink = fs::OpenOptions::new().write(true).open(fifo).unwrap();
                if done.load(Ordering::SeqCst) {
                    break;
                }
                if let Some((to, from)) = moves.next() {
                    shift(to, from);
                }
                let _sent = sink.write_all(b"/var/disk.img\n");
            }
            moves.count()
        })
    };
    let checked = fixture.host.check_unused("nvme1n1").map(drop);
    done.store(true, Ordering::SeqCst);
    // The writer waits for a reader of one of the FIFOs.
    while !writer.is_finished() {
        for fifo in &fifos {
            let _reader = release(fifo);
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(writer.join().unwrap(), 0, "premise: all four moves ran");
    assert!(!backing(&free).exists(), "premise: the moves ended");
    for fifo in &fifos {
        fs::remove_file(fifo).unwrap();
        fs::write(fifo, "/var/disk.img\n").unwrap();
    }
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: after the moves the loop device listed third is found"
    );
    assert_eq!(
        checked,
        Err(IdentityError::InUse("nvme1n1".into())),
        "a namespace backing a loop device at every instant of the check was admitted"
    );
}

/// The loop devices tell nothing of a host whose uevent counter is absent,
/// is not a number, or moves across every pass over them: a loop device
/// configured or detached during a pass can hide a backing file from it.
#[test]
fn loop_devices_are_unverifiable_without_a_still_uevent_counter() {
    use std::io::Write;

    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let fixture = Fixture::new(4096);
    let counter = fixture.host.sys.join("kernel/uevent_seqnum");
    let refused = Err(IdentityError::Unverifiable("loops"));
    assert!(fixture.host.check_unused("nvme1n1").is_ok(), "premise");
    for text in ["", "many\n", "-1\n"] {
        fs::write(&counter, text).unwrap();
        assert_eq!(fixture.host.check_unused("nvme1n1").map(drop), refused);
    }
    fs::remove_file(&counter).unwrap();
    assert_eq!(fixture.host.check_unused("nvme1n1").map(drop), refused);
    fs::write(&counter, "0\n").unwrap();
    assert!(fixture.host.check_unused("nvme1n1").is_ok());
    // Two loop devices over another file; a uevent is sent before each read
    // of either is answered. Each read is a FIFO, and the two alternate so
    // that the writer's next open waits for the check's next read.
    fixture.file("var/disk.img", "");
    let block = fixture.host.sys.join("block");
    for name in ["loop0", "loop1"] {
        fs::create_dir_all(block.join(name).join("loop")).unwrap();
        // The node stands for the loop device's record of its backing node.
        fs::hard_link(
            fixture.host.under_root(Path::new("/var/disk.img")),
            fixture.host.dev.join(name),
        )
        .unwrap();
    }
    // In the order the listing yields, which the check reads them in.
    let fifos: Vec<_> = fs::read_dir(&block)
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("loop"))
        .map(|entry| entry.path().join("loop/backing_file"))
        .collect();
    for fifo in &fifos {
        make_fifo(fifo);
    }
    let done = Arc::new(AtomicBool::new(false));
    let writer = {
        let (fifos, done) = (fifos.clone(), Arc::clone(&done));
        thread::spawn(move || {
            let mut sent = 0_u64;
            for fifo in fifos.iter().cycle() {
                let mut sink = fs::OpenOptions::new().write(true).open(fifo).unwrap();
                if done.load(Ordering::SeqCst) {
                    break;
                }
                sent += 1;
                fs::write(&counter, format!("{sent}\n")).unwrap();
                let _sent = sink.write_all(b"/var/disk.img\n");
            }
            sent
        })
    };
    let checked = fixture.host.check_unused("nvme1n1").map(drop);
    done.store(true, Ordering::SeqCst);
    while !writer.is_finished() {
        for fifo in &fifos {
            let _reader = release(fifo);
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        writer.join().unwrap(),
        16,
        "two uevents in each of eight passes"
    );
    assert_eq!(checked, refused);
}

/// The mass-storage function takes a LUN directory of any `<name>.<number>`
/// name: `lun.0` exists by default, and `mkdir partition.5` adds LUN 5. A
/// namespace backing a LUN in a directory named otherwise is in use as one
/// in `lun.<n>` is, and such a LUN over another file leaves its use unknown.
#[test]
fn a_gadget_lun_in_a_directory_not_named_lun_is_in_use() {
    const FUNCTION: &str = "sys/kernel/config/usb_gadget/g1/functions/mass_storage.usb0";
    let configured = |lun: &str, file: &str| {
        let fixture = Fixture::new(4096);
        fixture.file("var/disk.img", "an image");
        fixture.file(&format!("{FUNCTION}/stall"), "1\n");
        fixture.file(&format!("{FUNCTION}/lun.0/file"), "");
        fixture.file(&format!("{FUNCTION}/{lun}/file"), file);
        fixture
    };
    let checked = |fixture: &Fixture| fixture.host.check_unused("nvme1n1").map(drop);
    let in_use = Err(IdentityError::InUse("nvme1n1".to_owned()));

    assert_eq!(
        checked(&configured("lun.5", "/dev/nvme1n1\n")),
        in_use,
        "a LUN in lun.5 over the namespace"
    );
    assert_eq!(
        checked(&configured("partition.5", "/var/disk.img\n")),
        Err(IdentityError::Unverifiable("gadgets")),
        "a LUN in partition.5 over another file"
    );
    assert_eq!(
        checked(&configured("partition.5", "/dev/nvme1n1\n")),
        in_use,
        "a LUN in partition.5 over the namespace"
    );
}

/// The kernel prints a space, tab, newline or backslash of a mount's
/// directory in the mount table as a three-digit octal escape. An enabled
/// NVMe target namespace over the volume is in use under a configfs mount
/// at such a directory, as under `/config`.
#[test]
fn an_nvme_target_export_under_a_configfs_mount_at_an_escaped_directory_is_in_use() {
    let admitted = admitted_exports(&[
        ("config", "configfs /config configfs rw,relatime 0 0"),
        (
            "my config",
            "configfs /my\\040config configfs rw,relatime 0 0",
        ),
        (
            "my\tconfig",
            "configfs /my\\011config configfs rw,relatime 0 0",
        ),
        (
            "my\nconfig",
            "configfs /my\\012config configfs rw,relatime 0 0",
        ),
        (
            "my\\config",
            "configfs /my\\134config configfs rw,relatime 0 0",
        ),
    ]);
    assert_eq!(
        admitted, [""; 0],
        "mount table lines whose export was admitted"
    );
}

/// A configfs mount whose directory the mount table spells with a malformed
/// escape names no directory the tool can read, so the configfs listings
/// under it are unverifiable rather than empty, and the first that
/// `check_unused` reads refuses.
#[test]
fn a_configfs_mount_at_a_malformed_escape_leaves_the_listings_unverifiable() {
    let fixture = Fixture::new(4096);
    fixture.file(
        "proc/self/mounts",
        "/dev/nvme0n1p1 / xfs rw 0 0\nconfigfs /my\\04config configfs rw,relatime 0 0\n",
    );
    let checked = fixture.host.check_unused("nvme1n1").map(drop);
    assert!(
        matches!(checked, Err(IdentityError::Unverifiable(_))),
        "{checked:?}"
    );
}

/// A configfs mount the mount table lists is read through its directory, but a
/// later mount at that directory or at one above it covers it, and the
/// directory then shows the covering file system: the target, backstore, gadget
/// and heartbeat listings configfs holds cannot be read there, so a table that
/// lists configfs only at covered directories refuses. The same table without
/// the covering mount leaves the namespace unused, and a configfs mount no
/// later mount covers is still read beside a covered one.
#[test]
fn a_configfs_mount_another_mount_covers_is_not_read_as_an_empty_listing() {
    let host = |table: &str| {
        let fixture = Fixture::new(4096);
        fixture.file(
            "proc/self/mounts",
            &format!("/dev/nvme0n1p1 / xfs rw 0 0\n{table}"),
        );
        fixture
    };
    let checked = |fixture: &Fixture| fixture.host.check_unused("nvme1n1").map(drop);
    for (configfs, covering) in [
        (
            "configfs /config configfs rw,relatime 0 0\n",
            "tmpfs /config tmpfs rw 0 0\n",
        ),
        (
            "configfs /sys/kernel/config configfs rw,relatime 0 0\n",
            "tmpfs /sys/kernel/config tmpfs rw 0 0\n",
        ),
        (
            "configfs /sys/kernel/config configfs rw,relatime 0 0\n",
            "tmpfs /sys/kernel tmpfs rw 0 0\n",
        ),
    ] {
        assert_eq!(
            checked(&host(configfs)),
            Ok(()),
            "premise: {configfs:?} uncovered leaves the namespace unused"
        );
        assert_eq!(
            checked(&host(&format!("{configfs}{covering}"))),
            Err(IdentityError::Unverifiable("configfs")),
            "{configfs:?} covered by {covering:?}"
        );
    }

    let beside = host(
        "configfs /config configfs rw,relatime 0 0\ntmpfs /config tmpfs rw 0 0\n\
         configfs /cfg configfs rw,relatime 0 0\n",
    );
    let namespace = "cfg/nvmet/subsystems/nqn.2026-11.test:export/namespaces/1";
    beside.file(&format!("{namespace}/device_path"), "/dev/nvme1n1\n");
    beside.file(&format!("{namespace}/enable"), "1\n");
    assert_eq!(
        checked(&beside),
        Err(IdentityError::InUse("nvme1n1".into())),
        "an export under the configfs mount no later mount covers"
    );
}

/// A mount listed after a configfs mount at a directory strictly inside the
/// configfs directory hides the configfs entries below that directory. The
/// fixture omits the hidden listing to exercise the case where a missing
/// listing would otherwise be read as no export, and the check answers
/// `Unverifiable("configfs")`.
#[test]
fn an_nvme_target_export_under_a_mount_inside_configfs_is_not_read_as_no_export() {
    let host = |table: &str| {
        let fixture = Fixture::new(4096);
        fixture.file(
            "proc/self/mounts",
            &format!("/dev/nvme0n1p1 / xfs rw 0 0\n{table}"),
        );
        fixture
    };
    let checked = |fixture: &Fixture| fixture.host.check_unused("nvme1n1").map(drop);
    let conventional = "configfs /sys/kernel/config configfs rw,relatime 0 0\n";
    let elsewhere = "configfs /config configfs rw,relatime 0 0\n";
    for (configfs, inside) in [
        (
            conventional,
            "tmpfs /sys/kernel/config/nvmet tmpfs rw 0 0\n",
        ),
        (
            conventional,
            "tmpfs /sys/kernel/config/target/core tmpfs rw 0 0\n",
        ),
        (elsewhere, "tmpfs /config/usb_gadget tmpfs rw 0 0\n"),
        (elsewhere, "tmpfs /config/cluster tmpfs rw 0 0\n"),
    ] {
        assert_eq!(
            checked(&host(configfs)),
            Ok(()),
            "premise: {configfs:?} alone leaves the namespace unused"
        );
        assert_eq!(
            checked(&host(&format!("{configfs}{inside}"))),
            Err(IdentityError::Unverifiable("configfs")),
            "{configfs:?} with {inside:?} inside it"
        );
    }
    assert_eq!(
        checked(&host(&format!(
            "tmpfs /config/nvmet tmpfs rw 0 0\n{elsewhere}"
        ))),
        Ok(()),
        "a mount the configfs mount was made over"
    );
}

/// A process whose ring holds the namespace registered and that, during the
/// check, installs the registered file in its descriptor table
/// (`IORING_OP_FIXED_FD_INSTALL`) and then removes it from the ring keeps
/// the namespace open at every instant: registered with the ring until the
/// descriptor holds it. The handoff happens while the check's first read
/// of the ring's `fdinfo`, a FIFO here, waits; that read and every later
/// one find the ring's table empty.
#[test]
fn a_namespace_handed_from_a_ring_to_a_descriptor_during_the_check_is_in_use() {
    use std::io::Write;

    let fixture = Fixture::new(4096);
    let node = fixture.host.dev.join("nvme1n1");
    hold_ring(&fixture, "4242", 5, &ring_info(&["nvme1n1"]));
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: the ring's registration alone is found"
    );
    let info = fixture.host.proc.join("4242/fdinfo/5");
    make_fifo(&info);
    let descriptor = fixture.host.proc.join("4242/fd/6");
    let writer = {
        let (info, node, descriptor) = (info.clone(), node.clone(), descriptor.clone());
        thread::spawn(move || {
            let mut sink = fs::OpenOptions::new().write(true).open(&info).unwrap();
            symlink(&node, &descriptor).unwrap();
            fs::remove_file(&info).unwrap();
            fs::write(&info, ring_info(&[])).unwrap();
            let _sent = sink.write_all(ring_info(&[]).as_bytes());
        })
    };
    let checked = fixture.host.check_unused("nvme1n1").map(drop);
    // A check that never read the ring's listing releases the writer here.
    let _reader = release(&info);
    writer.join().unwrap();
    assert_eq!(fs::read_link(&descriptor).unwrap(), node, "premise");
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: after the handoff the descriptor alone is found"
    );
    assert_eq!(
        checked,
        Err(IdentityError::InUse("nvme1n1".into())),
        "a namespace in use at every instant of the check was admitted"
    );
}

/// A process that holds the namespace through a descriptor and, during the
/// check, registers it with its ring and closes the descriptor keeps the
/// namespace open at every instant: through the descriptor until the ring
/// holds it. The handoff happens while the check's first read of the ring's
/// `fdinfo`, a FIFO here, waits; that read finds the table empty, as a read
/// begun before the registration does, and every later one lists the
/// namespace.
#[test]
fn a_namespace_handed_from_a_descriptor_to_a_ring_during_the_check_is_in_use() {
    use std::io::Write;

    let fixture = Fixture::new(4096);
    let node = fixture.host.dev.join("nvme1n1");
    hold_ring(&fixture, "4242", 5, &ring_info(&[]));
    let descriptor = fixture.host.proc.join("4242/fd/6");
    symlink(&node, &descriptor).unwrap();
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: the descriptor alone is found"
    );
    let info = fixture.host.proc.join("4242/fdinfo/5");
    make_fifo(&info);
    let writer = {
        let (info, descriptor) = (info.clone(), descriptor.clone());
        thread::spawn(move || {
            let mut sink = fs::OpenOptions::new().write(true).open(&info).unwrap();
            fs::remove_file(&info).unwrap();
            fs::write(&info, ring_info(&["nvme1n1"])).unwrap();
            fs::remove_file(&descriptor).unwrap();
            let _sent = sink.write_all(ring_info(&[]).as_bytes());
        })
    };
    let checked = fixture.host.check_unused("nvme1n1").map(drop);
    // A check that never read the ring's listing releases the writer here.
    let _reader = release(&info);
    writer.join().unwrap();
    assert!(fs::symlink_metadata(&descriptor).is_err(), "premise");
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: after the handoff the ring's registration alone is found"
    );
    assert_eq!(
        checked,
        Err(IdentityError::InUse("nvme1n1".into())),
        "a namespace in use at every instant of the check was admitted"
    );
}

/// What the check answers when process 4242 moves a ring that holds the
/// namespace registered to another descriptor number while the check reads
/// its rings. The table holds a ring with an empty table and the ring
/// holding the namespace, in the order its listing yields them. A move runs
/// while a ring reading has listed the table and reads the empty ring's
/// `fdinfo`, a FIFO for that read. With `onto` unset the ring moves to a
/// number the listing did not return and that lists after the empty ring,
/// as `dup2(ring, n)` and `close(ring)` leave it, so its old number reads
/// `ENOENT`; it moves so during each of the check's two ring readings. With
/// `onto` set it moves once onto the empty ring's number, which the reading
/// has read, and an `open` reuses its old number, so no read fails. The
/// process holds the ring as a descriptor at every instant.
fn checks_beside_a_ring_moved_during_the_pass(onto: bool) -> Result<(), IdentityError> {
    use std::io::Write;

    let fixture = Fixture::new(4096);
    fixture.file("var/log", "");
    let table = fixture.root.join("proc/4242/fd");
    let info = fixture.root.join("proc/4242/fdinfo");
    for fd in [5, 9] {
        hold_ring(&fixture, "4242", fd, &ring_info(&[]));
    }
    // The roles follow the order the listing yields, which the pass sees too.
    let listed = |table: &Path| -> Vec<String> {
        fs::read_dir(table)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.bytes().all(|byte| byte.is_ascii_digit()))
            .collect()
    };
    let [pause, ring] = <[String; 2]>::try_from(listed(&table)).unwrap();
    fs::write(info.join(&ring), ring_info(&["nvme1n1"])).unwrap();
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: the ring listed last is found"
    );
    let fifo = info.join(&pause);
    make_fifo(&fifo);
    let writer = {
        let (fifo, table, info, pause) = (fifo.clone(), table.clone(), info.clone(), pause.clone());
        let log = fixture.root.join("var/log");
        thread::spawn(move || {
            let shift = |from: &str, to: &str| {
                fs::rename(table.join(from), table.join(to)).unwrap();
                fs::rename(info.join(from), info.join(to)).unwrap();
            };
            // The ring moves to an unlisted number the next listing yields
            // after the empty ring, so that listing reaches the FIFO first.
            let away = |from: &str, numbers: std::ops::Range<u32>| {
                for number in numbers {
                    let to = number.to_string();
                    shift(from, &to);
                    if listed(&table) != [pause.clone(), to.clone()] {
                        // A file system that lists the newest name first
                        // lists the empty ring first once its name is the
                        // newer one. The pass waits in the FIFO meanwhile.
                        fs::rename(table.join(&pause), table.join("renamed")).unwrap();
                        fs::rename(table.join("renamed"), table.join(&pause)).unwrap();
                    }
                    if listed(&table) == [pause.clone(), to.clone()] {
                        return to;
                    }
                    shift(&to, from);
                }
                panic!("premise: no number lists after the empty ring");
            };
            let mut sink = fs::OpenOptions::new().write(true).open(&fifo).unwrap();
            let to = if onto {
                shift(&ring, &pause);
                symlink(&log, table.join(&ring)).unwrap();
                pause.clone()
            } else {
                let first = away(&ring, 12..100);
                make_fifo(&fifo);
                let _sent = sink.write_all(ring_info(&[]).as_bytes());
                drop(sink);
                sink = fs::OpenOptions::new().write(true).open(&fifo).unwrap();
                let second = away(&first, 100..200);
                // A later reading of the empty ring finds a file again, as the first premise did.
                fs::remove_file(&fifo).unwrap();
                fs::write(&fifo, ring_info(&[])).unwrap();
                second
            };
            let _sent = sink.write_all(ring_info(&[]).as_bytes());
            to
        })
    };
    let checked = fixture.host.check_unused("nvme1n1").map(drop);
    // A check that read the FIFO fewer times than the writer waits for
    // releases the writer here: the writer makes the FIFO again between its
    // waits, so one read end of each is held until the writer has ended.
    hold_readers(&[&fifo], || writer.is_finished());
    let to = writer.join().unwrap();
    assert_eq!(
        fs::read_to_string(info.join(&to)).unwrap(),
        ring_info(&["nvme1n1"]),
        "premise: the move ran"
    );
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: after the move the ring is found under its new number"
    );
    checked
}

/// A ring a process moves, during each ring reading of the check, to a
/// descriptor number that reading's listing of its table did not return
/// stays a descriptor of that process, and the namespace it holds
/// registered stays in use, though each reading reads `ENOENT` under the
/// ring's old number.
#[test]
fn a_ring_moved_to_an_unlisted_number_during_the_ring_pass_is_in_use() {
    assert_eq!(
        checks_beside_a_ring_moved_during_the_pass(false),
        Err(IdentityError::InUse("nvme1n1".into())),
        "a namespace registered with a ring some task held at every instant of the check was admitted"
    );
}

/// The same when the ring moves onto a number the pass already read and an
/// `open` reuses its old number, so the pass reads no vanished descriptor.
#[test]
fn a_ring_moved_onto_a_read_number_during_the_ring_pass_is_in_use() {
    assert_eq!(
        checks_beside_a_ring_moved_during_the_pass(true),
        Err(IdentityError::InUse("nvme1n1".into())),
        "a namespace registered with a ring some task held at every instant of the check was admitted"
    );
}

/// A ring a child inherits at a fork stays held as a descriptor when the
/// parent exits, and the namespace it holds registered stays in use. Here
/// the holder forks and exits each time the in-use check reads another
/// process's ring, a FIFO for each of its first `READINGS` reads, so each
/// fork runs after a listing of the process table passed the holder's ID.
/// Each child's ID is one no listing returned and lists after the other
/// process, so a pass that lists the table once finds the holder vanished
/// and never lists its child.
#[test]
fn a_ring_inherited_by_a_child_forked_during_the_ring_pass_is_in_use() {
    use std::io::Write;

    /// The check reads the rings on both sides of the descriptor walk and
    /// each process's table twice in each reading.
    const READINGS: u32 = 4;
    let fixture = Fixture::new(4096);
    let proc = fixture.root.join("proc");
    for pid in ["4242", "5000"] {
        hold_ring(&fixture, pid, 5, &ring_info(&[]));
    }
    // The roles follow the order the listing yields, which the pass sees too.
    let listed = |proc: &Path| -> Vec<String> {
        fs::read_dir(proc)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.bytes().all(|byte| byte.is_ascii_digit()))
            .collect()
    };
    let [pause, parent] = <[String; 2]>::try_from(listed(&proc)).unwrap();
    fs::write(proc.join(&parent).join("fdinfo/5"), ring_info(&["nvme1n1"])).unwrap();
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: the parent's ring is found"
    );
    let fifo = proc.join(&pause).join("fdinfo/5");
    make_fifo(&fifo);
    let writer = {
        let (fifo, proc, pause) = (fifo.clone(), proc.clone(), pause.clone());
        thread::spawn(move || {
            // Puts the process `from` under the ID `to`, its leader's
            // entry with it, as procfs shows a process.
            let renumber = |from: &str, to: &str| {
                fs::rename(proc.join(from), proc.join(to)).unwrap();
                let tasks = proc.join(to).join("task");
                fs::rename(tasks.join(from), tasks.join(to)).unwrap();
            };
            // The child holds what its parent held, the parent is gone, and
            // the child's ID lists after the paused process, so the next
            // listing reaches the pause first.
            let fork = |from: &str, ids: std::ops::Range<u32>| {
                for id in ids {
                    let child = id.to_string();
                    renumber(from, &child);
                    if listed(&proc) != [pause.clone(), child.clone()] {
                        // A file system that lists the newest name first
                        // lists the paused process first once its name is
                        // the newer one. The pass waits in the FIFO meanwhile.
                        fs::rename(proc.join(&pause), proc.join("renamed")).unwrap();
                        fs::rename(proc.join("renamed"), proc.join(&pause)).unwrap();
                    }
                    if listed(&proc) == [pause.clone(), child.clone()] {
                        return child;
                    }
                    renumber(&child, from);
                }
                panic!("premise: no child ID lists after the paused process");
            };
            let mut holder = parent;
            for reading in 1..=READINGS {
                let mut sink = fs::OpenOptions::new().write(true).open(&fifo).unwrap();
                holder = fork(&holder, 6000 + 100 * reading..6100 + 100 * reading);
                if reading < READINGS {
                    make_fifo(&fifo);
                } else {
                    // A later reading of this ring finds a file again, as the first premise did.
                    fs::remove_file(&fifo).unwrap();
                    fs::write(&fifo, ring_info(&[])).unwrap();
                }
                let _sent = sink.write_all(ring_info(&[]).as_bytes());
            }
            holder
        })
    };
    let checked = fixture.host.check_unused("nvme1n1").map(drop);
    // A check that read the FIFO fewer than `READINGS` times releases the
    // writer here.
    while !writer.is_finished() {
        let _reader = release(&fifo);
        thread::yield_now();
    }
    let holder = writer.join().unwrap();
    assert!(
        proc.join(&holder).join("fd/5").is_symlink(),
        "premise: every fork ran"
    );
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: after the forks the last child's ring is found"
    );
    assert_eq!(
        checked,
        Err(IdentityError::InUse("nvme1n1".into())),
        "a namespace registered with a ring some task held at every instant of the check was admitted"
    );
}

/// The Xen block backend, RNBD server and pNFS block layout listings are read at fixed sysfs paths, but a mount the
/// mount table lists at one of those directories, or above it, covers it, and the directory then shows the covering
/// file system: the backend, the export or the loaded driver the kernel lists there cannot be read, and the check
/// cannot show the namespace unexported. The same host without the covering mount leaves the namespace unused.
#[test]
fn a_sysfs_listing_another_mount_covers_is_not_read_as_an_empty_listing() {
    let checked = |covering: &str, kallsyms: &str| {
        let fixture = Fixture::new(4096);
        fixture.file(
            "proc/self/mounts",
            &format!("/dev/nvme0n1p1 / xfs rw 0 0\nsysfs /sys sysfs rw 0 0\n{covering}"),
        );
        fixture.file("proc/kallsyms", kallsyms);
        fixture.host.check_unused("nvme1n1").map(drop)
    };
    let plain = "ffffffff81000000 T _stext\n";
    let loaded = "ffffffff81000000 T _stext\nffffffffc0000000 t bl_alloc_deviceid_node\t[blocklayoutdriver]\n";
    let mut admitted = Vec::new();
    for (covering, kallsyms) in [
        ("tmpfs /sys/bus/xen-backend tmpfs rw 0 0\n", plain),
        ("tmpfs /sys/bus tmpfs rw 0 0\n", plain),
        ("tmpfs /sys/class/rnbd-server tmpfs rw 0 0\n", plain),
        ("tmpfs /sys/module/blocklayoutdriver tmpfs rw 0 0\n", loaded),
    ] {
        assert_eq!(
            checked("", kallsyms),
            Ok(()),
            "premise: uncovered, {kallsyms:?} leaves the namespace unused"
        );
        if checked(covering, kallsyms).is_ok() {
            admitted.push(covering);
        }
    }
    assert!(
        admitted.is_empty(),
        "admitted under covering mounts: {admitted:?}"
    );
}

/// `sys/class/rnbd-server/ctl` is a link into
/// `sys/devices/virtual/rnbd-server/ctl`, and the mount table names a mount
/// by the directory a path resolves to. A tmpfs mounted over the resolved
/// `ctl/devices` hides the export listing behind the class link.
#[test]
fn an_rnbd_export_listing_a_mount_hides_behind_the_class_link_is_not_read_as_empty() {
    let host = |mounted: &str| {
        let fixture = Fixture::new(4096);
        fs::create_dir_all(fixture.root.join("sys/devices/virtual/rnbd-server/ctl")).unwrap();
        fs::create_dir_all(fixture.root.join("sys/class/rnbd-server")).unwrap();
        symlink(
            "../../devices/virtual/rnbd-server/ctl",
            fixture.root.join("sys/class/rnbd-server/ctl"),
        )
        .unwrap();
        fixture.file(
            "proc/self/mounts",
            &format!("/dev/nvme0n1p1 / xfs rw 0 0\nsysfs /sys sysfs rw 0 0\n{mounted}"),
        );
        fixture
    };
    let checked = |fixture: &Fixture| fixture.host.check_unused("nvme1n1").map(drop);
    let listed = host("");
    listed.file(
        "sys/devices/virtual/rnbd-server/ctl/devices/nvme1n1/sessions/client1/mapping_path",
        "volume\n",
    );
    assert_eq!(
        checked(&listed),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: the export is read through the class link"
    );
    assert_eq!(
        checked(&host("")),
        Ok(()),
        "premise: with no export and no mount the namespace is unused"
    );
    assert_eq!(
        checked(&host(
            "tmpfs /sys/devices/virtual/rnbd-server/ctl/devices tmpfs rw 0 0\n"
        )),
        Err(IdentityError::Unverifiable("rnbd")),
        "a tmpfs over the listing the class link resolves to"
    );
}

/// The mount table gives a bind mount of a sysfs subtree the type `sysfs`,
/// so a `sysfs` mount at the RNBD class directory can show another
/// subtree's entries in place of the export listing.
#[test]
fn a_sysfs_bind_mount_over_the_rnbd_class_is_not_read_as_no_export() {
    let fixture = Fixture::new(4096);
    fixture.file(
        "proc/self/mounts",
        "/dev/nvme0n1p1 / xfs rw 0 0\nsysfs /sys sysfs rw 0 0\n\
         sysfs /sys/class/rnbd-server sysfs rw 0 0\n",
    );
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("rnbd"))
    );
}

/// A later `sysfs` mount below `sys` can be a bind mount of another sysfs subtree, so it covers a listing as a mount
/// of another type does, while a later `sysfs` mount at `sys` uncovers the listing.
#[test]
fn a_mount_that_does_not_cover_a_sysfs_listing_leaves_the_namespace_unused() {
    let checked = |later: &str| {
        let fixture = Fixture::new(4096);
        fixture.file(
            "proc/self/mounts",
            &format!("/dev/nvme0n1p1 / xfs rw 0 0\nsysfs /sys sysfs rw 0 0\n{later}"),
        );
        fixture.host.check_unused("nvme1n1").map(drop)
    };
    for later in [
        "tmpfs /sys/bus/xen-backend/devices/vbd-1-51712 tmpfs rw 0 0\n",
        "tmpfs /sys/bus/xen-backend-other tmpfs rw 0 0\n",
        "tmpfs /sys/class/rnbd-client tmpfs rw 0 0\n",
        "tmpfs /sys/module/blocklayoutdriver/refcnt/below tmpfs rw 0 0\n",
        "tmpfs /mnt/sys/bus tmpfs rw 0 0\n",
        "tmpfs /sys/bus tmpfs rw 0 0\nsysfs /sys sysfs rw 0 0\n",
        "tmpfs /sys tmpfs rw 0 0\nsysfs /sys sysfs rw 0 0\n",
    ] {
        assert_eq!(checked(later), Ok(()), "not covered by {later:?}");
    }
    for (later, listing) in [
        (
            "tmpfs /sys/bus/xen-backend/devices tmpfs rw 0 0\n",
            "xen-backends",
        ),
        ("tmpfs /sys/class/rnbd-server/ctl tmpfs rw 0 0\n", "rnbd"),
        (
            "tmpfs /sys/module/blocklayoutdriver/refcnt tmpfs rw 0 0\n",
            "layouts",
        ),
        (
            "sysfs /sys/bus sysfs rw 0 0\ntmpfs /sys/bus tmpfs rw 0 0\n",
            "xen-backends",
        ),
        (
            "tmpfs /sys/bus tmpfs rw 0 0\nsysfs /sys/bus sysfs rw 0 0\n",
            "xen-backends",
        ),
        (
            "tmpfs /sys\\040 tmpfs rw 0 0\ntmpfs /sys tmpfs rw 0 0\n",
            "dev",
        ),
    ] {
        assert_eq!(
            checked(later),
            Err(IdentityError::Unverifiable(listing)),
            "covered by {later:?}"
        );
    }
}

/// A process that holds the namespace open while an NFS mount starts to
/// use the pNFS block layout driver, and closes its descriptor once the
/// driver may hold the namespace, leaves no instant at which the check can
/// show the namespace unused: open in a process until the driver's use
/// count is above zero. The handoff happens while the walk reads the
/// uptime, a FIFO here, after the check read the driver's use count and
/// before the walk reads any descriptor table.
#[test]
fn a_namespace_handed_from_a_descriptor_to_a_pnfs_layout_during_the_check_is_not_admitted() {
    use std::io::Write;

    let fixture = Fixture::new(4096);
    let node = fixture.host.dev.join("nvme1n1");
    fixture.file("sys/module/blocklayoutdriver/refcnt", "0\n");
    fixture.open(4242, &node);
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: the descriptor alone is found"
    );
    let uptime = fixture.host.proc.join("uptime");
    make_fifo(&uptime);
    let (count, descriptor) = (
        fixture.host.sys.join("module/blocklayoutdriver/refcnt"),
        fixture.host.proc.join("4242/fd/3"),
    );
    assert_eq!(fs::read_link(&descriptor).unwrap(), node, "premise");
    let writer = {
        let (uptime, count, descriptor) = (uptime.clone(), count.clone(), descriptor.clone());
        thread::spawn(move || {
            let mut sink = fs::OpenOptions::new().write(true).open(&uptime).unwrap();
            fs::write(&count, "1\n").unwrap();
            fs::remove_file(&descriptor).unwrap();
            let _sent = sink.write_all(b"100.00 400.00\n");
        })
    };
    let checked = fixture.host.check_unused("nvme1n1").map(drop);
    // A check that never read the uptime releases the writer here.
    let _reader = release(&uptime);
    writer.join().unwrap();
    fs::remove_file(&uptime).unwrap();
    fs::write(&uptime, "100.00 400.00\n").unwrap();
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::Unverifiable("layouts")),
        "premise: after the handoff the driver's use count alone refuses"
    );
    assert_ne!(
        checked,
        Ok(()),
        "a namespace no reading could show unused at any instant of the check was admitted"
    );
}

/// The events queued on inotify instance `fd`, in queue order, each as its watch descriptor and whether it names the watched directory itself and no entry of it; blocks for the first when `fd` blocks, and returns none when a nonblocking `fd` holds none.
fn queued_watch_events(fd: i32) -> Vec<(i32, bool)> {
    let mut buffer = [0u8; 4096];
    // SAFETY: the kernel writes at most `buffer.len()` bytes into the buffer this call owns.
    let read = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
    let mut events = Vec::new();
    let mut at = 0;
    while read > 0 && at + 16 <= read as usize {
        let word =
            |from: usize| u32::from_ne_bytes(buffer[at + from..at + from + 4].try_into().unwrap());
        events.push((word(0) as i32, word(12) == 0));
        at += 16 + word(12) as usize;
    }
    events
}

/// How one in-use check ended beside a SCSI target file backstore over `nvme1n1`, and whether each change of backstore fell where the check could not read it.
struct BackstoreCheck {
    checked: Result<(), IdentityError>,
    /// The first backstore reading read the early adapter, then the file changed backstores, then the reading read the late adapter; the file changed back while the process walk ran, before the second reading; and the second reading saw the same change as the first. Each of the three changes happened once.
    moved_inside: bool,
}

/// Runs [`Host::check_unused`] on `nvme1n1` once while a file backstore over `/dev/nvme1n1` exists at every instant.
/// `target/core` lists three file adapters in the order the fixture yields them. The middle one holds many backstore directories with no entry, which take a reading long enough for a change. With `moves`, the backstore starts under the last-listed adapter. Once the first reading opens the middle adapter, and again once the second reading first does, a backstore over the same file is created under the first-listed adapter and only then the last-listed one's is removed; once the process walk opens the process table, the backstore under the last-listed adapter is created again and only then the first-listed one's is removed. Without `moves` the backstore stays under the last-listed adapter.
fn check_beside_a_moving_backstore(moves: bool) -> BackstoreCheck {
    const PADDING: u32 = 20_000;
    const PROCESSES: u32 = 2_000;
    let fixture = Fixture::new(4096);
    let core = fixture.host.sys.join("kernel/config/target/core");
    for adapter in 0..3 {
        fs::create_dir_all(core.join(format!("fileio_{adapter}"))).unwrap();
    }
    let order: Vec<_> = fs::read_dir(&core)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    let [early, middle, late] = order.as_slice() else {
        panic!("premise: the fixture lists three adapters, not {order:?}");
    };
    for backstore in 0..PADDING {
        fs::create_dir_all(middle.join(format!("empty{backstore}"))).unwrap();
    }
    // The walk reads these processes, which hold nothing, long enough for the change back.
    for pid in 0..PROCESSES {
        fixture.process(10_000 + pid);
    }
    let create = |adapter: &Path| {
        let backstore = adapter.join("disk0");
        fs::create_dir(&backstore).unwrap();
        fs::write(backstore.join("udev_path"), "/dev/nvme1n1\n").unwrap();
        fs::write(
            backstore.join("info"),
            "Status: ACTIVATED  Max Queue Depth: 0  SectorSize: 512  HwMaxSectors: 16384\n        \
             TCM FILEIO ID: 0        File: /dev/nvme1n1  Size: 4096  Mode: O_DSYNC Async: 0\n",
        )
        .unwrap();
    };
    let remove = |adapter: &Path| fs::remove_dir_all(adapter.join("disk0")).unwrap();
    create(late);
    let marks = fixture.root.join("marks");
    fs::create_dir_all(&marks).unwrap();

    // SAFETY: the call takes no pointer.
    let watch = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
    assert!(watch >= 0);
    let add = |path: &Path, mask: u32| {
        let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `path` is a NUL-terminated string that outlives the call.
        let wd = unsafe { libc::inotify_add_watch(watch, path.as_ptr(), mask) };
        assert!(wd >= 0);
        wd
    };
    let middle_opened = (add(middle, libc::IN_OPEN), true);
    let late_opened = (add(late, libc::IN_OPEN), true);
    let walk_opened = (add(&fixture.host.proc, libc::IN_OPEN), true);
    let moved = (add(&marks, libc::IN_CREATE), false);
    // An entry here ends the mover's wait when the check returned before the event it waits for.
    let ended = fixture.root.join("ended");
    fs::create_dir_all(&ended).unwrap();
    let stopped = (add(&ended, libc::IN_CREATE), false);

    let mut seen = Vec::new();
    let checked = thread::scope(|scope| {
        let mover = scope.spawn(|| {
            let mut seen = Vec::new();
            // Waits for `event`, counted only after `after` when one is given.
            let mut wait = |event: (i32, bool), after: Option<(i32, bool)>| {
                let found = |seen: &[(i32, bool)]| {
                    let from = match after {
                        Some(after) => seen.iter().position(|&found| found == after),
                        None => Some(0),
                    };
                    from.is_some_and(|from| seen[from..].contains(&event))
                };
                while !found(&seen) {
                    if seen.contains(&stopped) {
                        return false;
                    }
                    seen.extend(queued_watch_events(watch));
                }
                true
            };
            // Each change creates the new backstore before it removes the old one. The third waits for the first open of the middle adapter after the walk began, which is the second reading's.
            let steps = [
                (middle_opened, None, early, late),
                (walk_opened, None, late, early),
                (middle_opened, Some(walk_opened), early, late),
            ];
            for (step, (event, after, to, from)) in steps.into_iter().enumerate() {
                if !wait(event, after) {
                    break;
                }
                if moves {
                    create(to);
                    remove(from);
                }
                fs::write(marks.join(step.to_string()), "").unwrap();
            }
            seen
        });
        let checked = fixture.host.check_unused("nvme1n1").map(drop);
        fs::write(ended.join("check"), "").unwrap();
        seen = mover.join().unwrap();
        checked
    });
    // SAFETY: `watch` is an open descriptor this function owns; the calls take no pointer.
    unsafe {
        let flags = libc::fcntl(watch, libc::F_GETFL);
        assert_eq!(
            libc::fcntl(watch, libc::F_SETFL, flags | libc::O_NONBLOCK),
            0
        );
    }
    loop {
        let more = queued_watch_events(watch);
        if more.is_empty() {
            break;
        }
        seen.extend(more);
    }
    // SAFETY: `watch` is open and closed once.
    unsafe { libc::close(watch) };
    // The two readings' adapter opens, the walk's first open of the process table and the three changes, in order.
    let mut walked = false;
    let trace: Vec<&str> = seen
        .iter()
        .filter_map(|&event| {
            if event == middle_opened {
                Some("middle")
            } else if event == late_opened {
                Some("late")
            } else if event == moved {
                Some("moved")
            } else if event == walk_opened && !std::mem::replace(&mut walked, true) {
                Some("walk")
            } else {
                None
            }
        })
        .collect();
    // A reading that reads its adapters again adds opens after each of these runs and no change.
    let (first, second) = match trace.iter().position(|&event| event == "walk") {
        Some(walk) => (&trace[..walk], &trace[walk + 1..]),
        None => (&trace[..], &trace[..0]),
    };
    let changes = |events: &[&str]| events.iter().filter(|&&event| event == "moved").count();
    BackstoreCheck {
        checked,
        moved_inside: first.starts_with(&["middle", "moved", "late"])
            && changes(first) == 1
            && second.starts_with(&["moved", "middle", "moved", "late"])
            && changes(second) == 2,
    }
}

/// [`Host::check_unused`] refuses a namespace that is "the backing file ... of a SCSI target file backstore". A backstore over the namespace that is replaced by another over the same file under another adapter, the new one created before the old one is removed, serves the namespace at every instant, so the check refuses it wherever its two backstore readings fall.
#[test]
fn a_file_backstore_that_changes_adapters_during_each_reading_is_in_use() {
    let check = (0..5)
        .map(|_| check_beside_a_moving_backstore(true))
        .find(|check| check.moved_inside)
        .expect("premise: each change fell where the check could not read it in five tries");
    assert_eq!(
        check.checked,
        Err(IdentityError::InUse("nvme1n1".to_owned())),
        "the check admitted a namespace a file backstore served throughout"
    );
}

/// The sibling without the change: the same tree refuses the namespace when the backstore stays under the last-listed adapter for the whole check.
#[test]
fn a_file_backstore_that_keeps_its_adapter_during_the_check_is_in_use() {
    let check = check_beside_a_moving_backstore(false);
    assert_eq!(
        check.checked,
        Err(IdentityError::InUse("nvme1n1".to_owned()))
    );
}

/// A process that holds the namespace open and, during the check, hands it
/// to a use the kernel holds with no descriptor and closes its own keeps
/// the namespace in use at every instant: open in a process until the
/// kernel serves it. An NVMe target namespace or passthrough, a gadget LUN,
/// an RNBD export, a heartbeat region and a Xen block backend each take the
/// device inside the kernel without an exclusive claim, so the final
/// exclusive open does not see them either. Each handoff happens while the
/// walk reads the uptime, a FIFO here, after the check read the listing of
/// that use and before the walk reads any descriptor table.
#[test]
fn a_namespace_handed_from_a_descriptor_to_a_use_inside_the_kernel_during_the_check_is_in_use() {
    use std::io::Write;

    const SUBSYSTEM: &str = "sys/kernel/config/nvmet/subsystems/nqn.2026-11.test:handed";
    const LUN: &str = "sys/kernel/config/usb_gadget/g1/functions/mass_storage.usb0/lun.0/file";
    /// The entries a use shows, as paths under the root and their text, on
    /// a host whose namespace has the device number given.
    type Entries = fn(&str) -> Vec<(String, String)>;
    let uses: [(&str, Entries); 6] = [
        ("an NVMe target namespace", |_| {
            vec![
                (
                    format!("{SUBSYSTEM}/namespaces/1/device_path"),
                    "/dev/nvme1n1\n".into(),
                ),
                (format!("{SUBSYSTEM}/namespaces/1/enable"), "1\n".into()),
            ]
        }),
        ("an NVMe target passthrough", |_| {
            vec![
                (
                    format!("{SUBSYSTEM}/passthru/device_path"),
                    "/dev/nvme1\n".into(),
                ),
                (format!("{SUBSYSTEM}/passthru/enable"), "1\n".into()),
            ]
        }),
        ("a gadget LUN", |_| {
            vec![(LUN.into(), "/dev/nvme1n1\n".into())]
        }),
        ("an RNBD export", |_| {
            vec![(
                "sys/class/rnbd-server/ctl/devices/nvme1n1/sessions/client1/mapping_path".into(),
                "volume\n".into(),
            )]
        }),
        ("a heartbeat region", |_| {
            vec![(
                "sys/kernel/config/cluster/c1/heartbeat/0123ABCD/dev".into(),
                "nvme1n1\n".into(),
            )]
        }),
        ("a Xen block backend", |number| {
            let (major, minor) = number.trim().split_once(':').unwrap();
            let (major, minor): (u32, u32) = (major.parse().unwrap(), minor.parse().unwrap());
            vec![(
                "sys/bus/xen-backend/devices/vbd-3-51728/physical_device".into(),
                format!("{major:x}:{minor:x}\n"),
            )]
        }),
    ];
    let in_use = Err(IdentityError::InUse("nvme1n1".into()));
    let mut admitted = Vec::new();
    for (name, entries) in uses {
        let fixture = Fixture::new(4096);
        let node = fixture.host.dev.join("nvme1n1");
        let number = fs::read_to_string(fixture.host.sys.join("class/block/nvme1n1/dev")).unwrap();
        fixture.open(4242, &node);
        assert_eq!(
            fixture.host.check_unused("nvme1n1").map(drop),
            in_use,
            "premise: before {name} the descriptor alone is found"
        );
        let uptime = fixture.host.proc.join("uptime");
        make_fifo(&uptime);
        let descriptor = fixture.host.proc.join("4242/fd/3");
        assert_eq!(fs::read_link(&descriptor).unwrap(), node, "premise");
        let writer = {
            let (uptime, root) = (uptime.clone(), fixture.root.clone());
            thread::spawn(move || {
                let mut sink = fs::OpenOptions::new().write(true).open(&uptime).unwrap();
                for (entry, text) in entries(&number) {
                    let entry = root.join(entry);
                    fs::create_dir_all(entry.parent().unwrap()).unwrap();
                    fs::write(entry, text).unwrap();
                }
                fs::remove_file(&descriptor).unwrap();
                let _sent = sink.write_all(b"100.00 400.00\n");
            })
        };
        let checked = fixture.host.check_unused("nvme1n1").map(drop);
        // A check that never read the uptime releases the writer here.
        let _reader = release(&uptime);
        writer.join().unwrap();
        fs::remove_file(&uptime).unwrap();
        fs::write(&uptime, "100.00 400.00\n").unwrap();
        assert_eq!(
            fixture.host.check_unused("nvme1n1").map(drop),
            in_use,
            "premise: after the handoff {name} alone is found"
        );
        if checked != in_use {
            admitted.push((name, checked));
        }
    }
    assert_eq!(
        admitted,
        [],
        "uses a namespace in use at every instant of the check was handed to and admitted"
    );
}

/// The check's answer beside a use inside the kernel that a process holding
/// the namespace hands it to during the walk and, when `back` is given,
/// takes back before the check reads that use the second time. `idle`,
/// `active` and `back` are the use's entries, as paths under the root and
/// their text: the tree starts with the idle ones, the handoff writes the
/// active ones and the handback the ones in `back`. An entry without text
/// stands for a directory the use lacks: its parent's parent exists and its
/// parent does not. The first handoff happens while the walk reads the
/// uptime, a FIFO, after the first reading of the use. The second happens
/// while the second layout reading reads the block layout module's use
/// count, a FIFO for that one read, after the walk and before the second
/// reading of the use. With `handed` clear the tree and the pauses are the
/// same, no process holds the namespace and nothing changes hands.
fn check_beside_a_use_handed_over(
    idle: &[(&str, Option<&str>)],
    active: &[(&str, Option<&str>)],
    handed: bool,
    back: Option<&[(&str, Option<&str>)]>,
) -> Result<(), IdentityError> {
    use std::io::Write;
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new(4096);
    for (entry, text) in idle {
        match text {
            Some(text) => fixture.file(entry, text),
            None => {
                let made = fixture.root.join(entry);
                fs::create_dir_all(made.parent().unwrap().parent().unwrap()).unwrap();
            }
        }
    }
    fixture.file("sys/module/blocklayoutdriver/refcnt", "0\n");
    let count = fixture.host.sys.join("module/blocklayoutdriver/refcnt");
    let node = fixture.host.dev.join("nvme1n1");
    fixture.open(4242, &node);
    let descriptor = fixture.host.proc.join("4242/fd/3");
    assert_eq!(fs::read_link(&descriptor).unwrap(), node, "premise");
    if !handed {
        fs::remove_file(&descriptor).unwrap();
    }
    let uptime = fixture.host.proc.join("uptime");
    fs::remove_file(&uptime).unwrap();
    make_fifo(&uptime);
    let owned = |entries: &[(&str, Option<&str>)]| -> Vec<(std::path::PathBuf, Option<String>)> {
        entries
            .iter()
            .map(|(entry, text)| (fixture.root.join(entry), text.map(str::to_owned)))
            .collect()
    };
    let (active, back) = (owned(active), back.map(owned));
    let writer = {
        let (uptime, count) = (uptime.clone(), count.clone());
        let (node, descriptor) = (node.clone(), descriptor.clone());
        thread::spawn(move || {
            let write = |entries: &[(std::path::PathBuf, Option<String>)]| {
                for (entry, text) in entries {
                    let made = entry.parent().unwrap();
                    match text {
                        Some(text) => {
                            fs::create_dir_all(made).unwrap();
                            fs::write(entry, text).unwrap();
                        }
                        None => fs::remove_dir_all(made).unwrap(),
                    }
                }
            };
            let mut sink = fs::OpenOptions::new().write(true).open(&uptime).unwrap();
            if handed {
                write(&active);
                fs::remove_file(&descriptor).unwrap();
            }
            fs::remove_file(&count).unwrap();
            make_fifo(&count);
            fs::remove_file(&uptime).unwrap();
            fs::write(&uptime, "100.00 400.00\n").unwrap();
            let _sent = sink.write_all(b"100.00 400.00\n");
            drop(sink);
            let mut sink = fs::OpenOptions::new().write(true).open(&count).unwrap();
            if let Some(back) = back.filter(|_| handed) {
                symlink(&node, &descriptor).unwrap();
                write(&back);
            }
            fs::remove_file(&count).unwrap();
            fs::write(&count, "0\n").unwrap();
            let _sent = sink.write_all(b"0\n");
        })
    };
    let checked = fixture.host.check_unused("nvme1n1").map(drop);
    // A check that never read a FIFO releases the writer here.
    hold_readers(&[&uptime, &count], || writer.is_finished());
    writer.join().unwrap();
    checked
}

/// A process that holds the namespace open, hands it to a use inside the
/// kernel while the walk runs and takes it back before the check reads that
/// use the second time, keeps it in use at every instant: open in the
/// process, then served by the kernel, then open again. Neither reading of
/// the use and no descriptor table the walk read holds it. Each such use
/// under configfs changes by a write the kernel reports to a watch on its
/// directory, so the check refuses it. The last three rows start with the
/// use's listing absent, as it is until its module registers it, which the
/// kernel reports to no watch: the listing is there at the second reading,
/// and the check refuses by that. The same tree with the same pauses and no
/// handoff is admitted, and a use that keeps the namespace is found.
#[test]
fn a_namespace_handed_to_a_use_inside_the_kernel_and_back_during_the_check_is_not_admitted() {
    const SUBSYSTEM: &str = "sys/kernel/config/nvmet/subsystems/nqn.2026-11.test:handed";
    const LUN: &str = "sys/kernel/config/usb_gadget/g1/functions/mass_storage.usb0/lun.0/file";
    const REGION: &str = "sys/kernel/config/cluster/c1/heartbeat/0123ABCD/dev";
    const BACKSTORE: &str = "sys/kernel/config/target/core/fileio_0/disk/udev_path";
    let exported = format!("{SUBSYSTEM}/namespaces/1");
    let (path, enable) = (
        format!("{exported}/device_path"),
        format!("{exported}/enable"),
    );
    let (forwarded, passed) = (
        format!("{SUBSYSTEM}/passthru/device_path"),
        format!("{SUBSYSTEM}/passthru/enable"),
    );
    type Entries<'a> = Vec<(&'a str, Option<&'a str>)>;
    // Each use: its name, its label, and its entries idle, active and
    // handed back.
    let uses: [(&str, &'static str, Entries, Entries, Entries); 8] = [
        (
            "a gadget LUN",
            "gadgets",
            vec![(LUN, Some(""))],
            vec![(LUN, Some("/dev/nvme1n1\n"))],
            vec![(LUN, Some(""))],
        ),
        (
            "an NVMe target namespace",
            "targets",
            vec![(&path, Some("/dev/nvme1n1\n")), (&enable, Some("0\n"))],
            vec![(&enable, Some("1\n"))],
            vec![(&enable, Some("0\n"))],
        ),
        (
            "a heartbeat region",
            "heartbeats",
            vec![(REGION, Some(""))],
            vec![(REGION, Some("nvme1n1\n"))],
            vec![(REGION, Some(""))],
        ),
        (
            "an NVMe target passthrough",
            "targets",
            vec![(&forwarded, Some("/dev/nvme1\n")), (&passed, Some("0\n"))],
            vec![(&passed, Some("1\n"))],
            vec![(&passed, Some("0\n"))],
        ),
        (
            "a file backstore",
            "targets",
            vec![(BACKSTORE, None)],
            vec![(BACKSTORE, Some("/dev/nvme1n1\n"))],
            vec![(BACKSTORE, None)],
        ),
        (
            "a gadget LUN under a listing registered during the check",
            "gadgets",
            vec![],
            vec![(LUN, Some("/dev/nvme1n1\n"))],
            vec![(LUN, Some(""))],
        ),
        (
            "an NVMe target namespace under a listing registered during the check",
            "targets",
            vec![],
            vec![(&path, Some("/dev/nvme1n1\n")), (&enable, Some("1\n"))],
            vec![(&enable, Some("0\n"))],
        ),
        (
            "a heartbeat region under a listing registered during the check",
            "heartbeats",
            vec![],
            vec![(REGION, Some("nvme1n1\n"))],
            vec![(REGION, Some(""))],
        ),
    ];
    let mut admitted = Vec::new();
    for (name, label, idle, active, back) in &uses {
        assert_eq!(
            check_beside_a_use_handed_over(idle, active, false, None),
            Ok(()),
            "premise: the tree of {name} and the pauses alone are admitted"
        );
        assert_eq!(
            check_beside_a_use_handed_over(idle, active, true, None),
            Err(IdentityError::InUse("nvme1n1".into())),
            "premise: {name} that keeps the namespace is found"
        );
        let checked = check_beside_a_use_handed_over(idle, active, true, Some(back));
        if checked != Err(IdentityError::Unverifiable(label)) {
            admitted.push((*name, checked));
        }
    }
    assert_eq!(
        admitted,
        [],
        "uses a namespace was handed to and back from during the check, and the answers"
    );
}

/// The host's uevent counter spans every second reading of a use under
/// configfs: the check takes its second sample after the last of them, the
/// passthrough's. A module that registers a configfs listing after a use's
/// first reading and is unloaded before its second leaves the listing
/// absent at both and reports to no watch, and its load and unload each
/// send a uevent. Here a subsystem's `passthru/enable` is a link to a FIFO
/// outside configfs, so a read of it waits and reports to no watch. The
/// first reading is answered at once. The counter moves by two while the
/// second reading waits, and the check refuses. The same pauses with the
/// counter left alone are admitted.
#[test]
fn a_uevent_sent_during_the_last_second_configfs_reading_refuses_the_check() {
    use std::io::Write;
    use std::os::unix::fs::symlink;
    let checked = |sent: bool| {
        let fixture = Fixture::new(4096);
        let passthru = "sys/kernel/config/nvmet/subsystems/nqn.2026-11.test:paused/passthru";
        fixture.file(&format!("{passthru}/device_path"), "/dev/nvme1\n");
        let enable = fixture.root.join("var/enable");
        fixture.file("var/.keep", "");
        make_fifo(&enable);
        symlink(&enable, fixture.root.join(passthru).join("enable")).unwrap();
        let counter = fixture.host.sys.join("kernel/uevent_seqnum");
        let uptime = fixture.host.proc.join("uptime");
        fs::remove_file(&uptime).unwrap();
        make_fifo(&uptime);
        let writer = {
            let (uptime, enable) = (uptime.clone(), enable.clone());
            thread::spawn(move || {
                let answer = |before: &dyn Fn()| {
                    let mut sink = fs::OpenOptions::new().write(true).open(&enable).unwrap();
                    before();
                    let _sent = sink.write_all(b"0\n");
                };
                answer(&|| ());
                // The walk reads the uptime after every first reading has
                // returned, so the second answer goes to the second reading.
                let mut sink = fs::OpenOptions::new().write(true).open(&uptime).unwrap();
                fs::remove_file(&uptime).unwrap();
                fs::write(&uptime, "100.00 400.00\n").unwrap();
                let _sent = sink.write_all(b"100.00 400.00\n");
                drop(sink);
                answer(&|| {
                    if sent {
                        fs::write(&counter, "7067\n").unwrap();
                    }
                });
            })
        };
        let checked = fixture.host.check_unused("nvme1n1").map(drop);
        // A check that never read a FIFO releases the writer here.
        hold_readers(&[&uptime, &enable], || writer.is_finished());
        writer.join().unwrap();
        checked
    };
    assert_eq!(checked(false), Ok(()), "premise: the pauses alone");
    assert_eq!(
        checked(true),
        Err(IdentityError::Unverifiable("loops")),
        "uevents sent during the last second configfs reading went unseen"
    );
}

/// The check's answers before, during and after a namespace's use moves
/// between two LUNs of one mass-storage function, and the passes the check
/// made over the LUNs while it moved. The LUN the listing yields first has
/// no file and the one it yields third backs the namespace. The second
/// LUN's `file` links to a FIFO outside the gadget, so each pass waits there
/// between its reads of the first and the third. During the first wait, and
/// during every later one when `every_pass` is set, the LUN without the
/// namespace is given it and then the other gives it up, so some LUN backs
/// the namespace at every instant.
fn checked_across_lun_moves(every_pass: bool) -> ([Result<(), IdentityError>; 3], u32) {
    use std::io::Write;

    use std::sync::atomic::{AtomicBool, Ordering};
    const FUNCTION: &str = "sys/kernel/config/usb_gadget/g1/functions/mass_storage.usb0";
    const USED: &str = "/dev/nvme1n1\n";
    let fixture = Fixture::new(4096);
    let function = fixture.root.join(FUNCTION);
    for lun in ["lun.0", "lun.1", "lun.2"] {
        fixture.file(&format!("{FUNCTION}/{lun}/file"), "\n");
    }
    // The roles follow the order the listing yields, which the check sees too.
    let order: Vec<_> = fs::read_dir(&function)
        .unwrap()
        .map(|entry| entry.unwrap().path().join("file"))
        .collect();
    let [first, between, third] = <[_; 3]>::try_from(order).unwrap();
    fs::write(&third, USED).unwrap();
    let checked = || fixture.host.check_unused("nvme1n1").map(drop);
    let before = checked();
    let pause = fixture.root.join("pause");
    let fifo = || make_fifo(&pause);
    fifo();
    fs::remove_file(&between).unwrap();
    symlink(&pause, &between).unwrap();
    let done = AtomicBool::new(false);
    let (during, passes) = thread::scope(|scope| {
        // Answers each pass's read of the FIFO as a LUN with no file, after
        // the move that pass is due.
        let writer = scope.spawn(|| {
            let mut passes = 0u32;
            loop {
                let mut sink = fs::OpenOptions::new().write(true).open(&pause).unwrap();
                if done.load(Ordering::SeqCst) {
                    break passes;
                }
                if passes == 0 || every_pass {
                    let (to, from) = if passes.is_multiple_of(2) {
                        (&first, &third)
                    } else {
                        (&third, &first)
                    };
                    fs::write(to, USED).unwrap();
                    fs::write(from, "\n").unwrap();
                }
                passes += 1;
                let _sent = sink.write_all(b"\n");
                // A new FIFO takes the path before this one's read ends, so
                // the next answer waits for the next pass's read.
                fs::remove_file(&pause).unwrap();
                fifo();
                drop(sink);
            }
        });
        let during = checked();
        done.store(true, Ordering::SeqCst);
        // The writer waits for a reader of the FIFO.
        while !writer.is_finished() {
            let _reader = release(&pause);
            thread::sleep(Duration::from_millis(10));
        }
        (during, writer.join().unwrap())
    });
    fs::remove_file(&between).unwrap();
    fs::write(&between, "\n").unwrap();
    ([before, during, checked()], passes)
}

/// A namespace whose use moves from a LUN not yet read to one already read
/// while the check reads the LUNs backs a LUN at every instant, so it is in
/// use (`check_unused`: refuses a namespace that is "the backing file ... of
/// a USB gadget mass-storage LUN"). The write that moves it changes the
/// gadget under the pass, so the check reads the LUNs again and finds it.
#[test]
fn a_namespace_moved_between_gadget_luns_during_the_reading_is_in_use() {
    let in_use = || Err(IdentityError::InUse("nvme1n1".into()));
    let ([before, during, after], passes) = checked_across_lun_moves(false);
    assert_eq!(before, in_use(), "premise: the third LUN is found");
    assert_eq!(after, in_use(), "premise: the first LUN is found");
    assert_eq!(
        during,
        in_use(),
        "a namespace some LUN backed at every instant of the check was admitted"
    );
    assert_eq!(
        passes, 3,
        "the pass the move crossed and one still pass, then the still pass of the reading after the walk"
    );
}

/// A namespace moved between two LUNs once during every pass over them is
/// in no pass the gadget stayed still across, so the check refuses it as
/// unverifiable after its last pass instead of admitting it.
#[test]
fn a_namespace_moved_between_gadget_luns_during_every_pass_is_unverifiable() {
    let in_use = || Err(IdentityError::InUse("nvme1n1".into()));
    let ([before, during, after], passes) = checked_across_lun_moves(true);
    assert_eq!(before, in_use(), "premise: the third LUN is found");
    assert_eq!(
        after,
        in_use(),
        "premise: an even count of moves ends at the third LUN"
    );
    assert_eq!(during, Err(IdentityError::Unverifiable("gadgets")));
    assert_eq!(passes, 8, "every pass the check allows itself");
}

/// The check's answers before, during and after a namespace's export moves
/// between two namespaces of one NVMe target subsystem, and the passes the
/// check made over the target namespaces while it moved. The namespace the
/// listing yields first is disabled and the one it yields third is enabled
/// over the namespace. The second's `enable` links to a FIFO outside the
/// subsystem, so each pass waits there between its reads of the first and
/// the third. During the first wait, and during every later one when
/// `every_pass` is set, the disabled namespace is enabled over the namespace
/// and then the other is disabled, so some enabled target namespace exports
/// it at every instant.
fn checked_across_target_moves(every_pass: bool) -> ([Result<(), IdentityError>; 3], u32) {
    use std::io::Write;

    use std::sync::atomic::{AtomicBool, Ordering};
    const NAMESPACES: &str =
        "sys/kernel/config/nvmet/subsystems/nqn.2026-11.test:export/namespaces";
    const USED: &str = "/dev/nvme1n1\n";
    let fixture = Fixture::new(4096);
    let namespaces = fixture.root.join(NAMESPACES);
    for nsid in ["1", "2", "3"] {
        fixture.file(&format!("{NAMESPACES}/{nsid}/enable"), "0\n");
    }
    // The roles follow the order the listing yields, which the check sees too.
    let order: Vec<_> = fs::read_dir(&namespaces)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    let [first, between, third] = <[_; 3]>::try_from(order).unwrap();
    let enable = |namespace: &Path| {
        fs::write(namespace.join("device_path"), USED).unwrap();
        fs::write(namespace.join("enable"), "1\n").unwrap();
    };
    let disable = |namespace: &Path| fs::write(namespace.join("enable"), "0\n").unwrap();
    enable(&third);
    let checked = || fixture.host.check_unused("nvme1n1").map(drop);
    let before = checked();
    let pause = fixture.root.join("pause");
    let fifo = || make_fifo(&pause);
    fifo();
    let paused = between.join("enable");
    fs::remove_file(&paused).unwrap();
    symlink(&pause, &paused).unwrap();
    let done = AtomicBool::new(false);
    let (during, passes) = thread::scope(|scope| {
        // Answers each pass's read of the FIFO as a disabled namespace,
        // after the move that pass is due.
        let writer = scope.spawn(|| {
            let mut passes = 0u32;
            loop {
                let mut sink = fs::OpenOptions::new().write(true).open(&pause).unwrap();
                if done.load(Ordering::SeqCst) {
                    break passes;
                }
                if passes == 0 || every_pass {
                    let (to, from) = if passes.is_multiple_of(2) {
                        (&first, &third)
                    } else {
                        (&third, &first)
                    };
                    enable(to);
                    disable(from);
                }
                passes += 1;
                let _sent = sink.write_all(b"0\n");
                // A new FIFO takes the path before this one's read ends, so
                // the next answer waits for the next pass's read.
                fs::remove_file(&pause).unwrap();
                fifo();
                drop(sink);
            }
        });
        let during = checked();
        done.store(true, Ordering::SeqCst);
        // The writer waits for a reader of the FIFO.
        while !writer.is_finished() {
            let _reader = release(&pause);
            thread::sleep(Duration::from_millis(10));
        }
        (during, writer.join().unwrap())
    });
    fs::remove_file(&paused).unwrap();
    fs::write(&paused, "0\n").unwrap();
    ([before, during, checked()], passes)
}

/// A namespace whose export moves from a target namespace not yet read to
/// one already read while the check reads the target namespaces is exported
/// at every instant, so it is in use (`check_unused`: refuses a namespace
/// "exported by an enabled NVMe target namespace"). The writes that move it
/// change the subsystem under the pass, so the check reads the target
/// namespaces again and finds it.
#[test]
fn a_namespace_moved_between_nvme_target_namespaces_during_the_reading_is_in_use() {
    let in_use = || Err(IdentityError::InUse("nvme1n1".into()));
    let ([before, during, after], passes) = checked_across_target_moves(false);
    assert_eq!(before, in_use(), "premise: the third namespace is found");
    assert_eq!(after, in_use(), "premise: the first namespace is found");
    assert_eq!(
        during,
        in_use(),
        "a namespace some enabled target namespace exported at every instant of the check was admitted"
    );
    assert_eq!(
        passes, 3,
        "the pass the move crossed and one still pass, then the still pass of the reading after the walk"
    );
}

/// A namespace whose export moves between two target namespaces once during
/// every pass over them is in no pass the target stayed still across, so
/// the check refuses it as unverifiable after its last pass instead of
/// admitting it.
#[test]
fn a_namespace_moved_between_nvme_target_namespaces_during_every_pass_is_unverifiable() {
    let in_use = || Err(IdentityError::InUse("nvme1n1".into()));
    let ([before, during, after], passes) = checked_across_target_moves(true);
    assert_eq!(before, in_use(), "premise: the third namespace is found");
    assert_eq!(
        after,
        in_use(),
        "premise: an even count of moves ends at the third namespace"
    );
    assert_eq!(during, Err(IdentityError::Unverifiable("targets")));
    assert_eq!(passes, 8, "every pass the check allows itself");
}

/// The check's answers before, during and after a namespace's heartbeat
/// moves between two OCFS2 heartbeat regions of one cluster, and the passes
/// the check made over the regions while it moved. The region the listing
/// yields first has no device and the one it yields third names the
/// namespace. The second region's `dev` links to a FIFO outside the
/// cluster, so each pass waits there between its reads of the first and
/// the third. During the first wait, and during every later one when
/// `every_pass` is set, the region without the namespace is given it and
/// then the other gives it up, so some region names the namespace at every
/// instant.
fn checked_across_heartbeat_moves(every_pass: bool) -> ([Result<(), IdentityError>; 3], u32) {
    use std::sync::atomic::{AtomicBool, Ordering};
    const HEARTBEAT: &str = "sys/kernel/config/cluster/c1/heartbeat";
    const USED: &str = "nvme1n1\n";
    let fixture = Fixture::new(4096);
    let heartbeat = fixture.root.join(HEARTBEAT);
    for region in ["0123ABCD", "4567EF01", "89AB2345"] {
        fixture.file(&format!("{HEARTBEAT}/{region}/dev"), "");
    }
    // The roles follow the order the listing yields, which the check sees too.
    let order: Vec<_> = fs::read_dir(&heartbeat)
        .unwrap()
        .map(|entry| entry.unwrap().path().join("dev"))
        .collect();
    let [first, between, third] = <[_; 3]>::try_from(order).unwrap();
    fs::write(&third, USED).unwrap();
    let checked = || fixture.host.check_unused("nvme1n1").map(drop);
    let before = checked();
    let pause = fixture.root.join("pause");
    let fifo = || make_fifo(&pause);
    fifo();
    fs::remove_file(&between).unwrap();
    symlink(&pause, &between).unwrap();
    let done = AtomicBool::new(false);
    let (during, passes) = thread::scope(|scope| {
        // Answers each pass's read of the FIFO as a region with no device,
        // after the move that pass is due.
        let writer = scope.spawn(|| {
            let mut passes = 0u32;
            loop {
                let sink = fs::OpenOptions::new().write(true).open(&pause).unwrap();
                if done.load(Ordering::SeqCst) {
                    break passes;
                }
                if passes == 0 || every_pass {
                    let (to, from) = if passes.is_multiple_of(2) {
                        (&first, &third)
                    } else {
                        (&third, &first)
                    };
                    fs::write(to, USED).unwrap();
                    fs::write(from, "").unwrap();
                }
                passes += 1;
                // A new FIFO takes the path before this one's read ends, so
                // the next answer waits for the next pass's read.
                fs::remove_file(&pause).unwrap();
                fifo();
                drop(sink);
            }
        });
        let during = checked();
        done.store(true, Ordering::SeqCst);
        // The writer waits for a reader of the FIFO.
        while !writer.is_finished() {
            let _reader = release(&pause);
            thread::sleep(Duration::from_millis(10));
        }
        (during, writer.join().unwrap())
    });
    fs::remove_file(&between).unwrap();
    fs::write(&between, "").unwrap();
    ([before, during, checked()], passes)
}

/// A namespace whose heartbeat moves from a region not yet read to one
/// already read while the check reads the regions is a region's device at
/// every instant, so it is in use (`check_unused`: refuses a namespace that
/// is "the device of an OCFS2 disk heartbeat region"). The write that moves
/// it changes the cluster under the pass, so the check reads the regions
/// again and finds it.
#[test]
fn a_namespace_moved_between_heartbeat_regions_during_the_reading_is_in_use() {
    let in_use = || Err(IdentityError::InUse("nvme1n1".into()));
    let ([before, during, after], passes) = checked_across_heartbeat_moves(false);
    assert_eq!(before, in_use(), "premise: the third region is found");
    assert_eq!(after, in_use(), "premise: the first region is found");
    assert_eq!(
        during,
        in_use(),
        "a namespace some region named at every instant of the check was admitted"
    );
    assert_eq!(
        passes, 3,
        "the pass the move crossed and one still pass, then the still pass of the reading after the walk"
    );
}

/// A namespace moved between two heartbeat regions once during every pass
/// over them is in no pass the cluster stayed still across, so the check
/// refuses it as unverifiable after its last pass instead of admitting it.
#[test]
fn a_namespace_moved_between_heartbeat_regions_during_every_pass_is_unverifiable() {
    let in_use = || Err(IdentityError::InUse("nvme1n1".into()));
    let ([before, during, after], passes) = checked_across_heartbeat_moves(true);
    assert_eq!(before, in_use(), "premise: the third region is found");
    assert_eq!(
        after,
        in_use(),
        "premise: an even count of moves ends at the third region"
    );
    assert_eq!(during, Err(IdentityError::Unverifiable("heartbeats")));
    assert_eq!(passes, 8, "every pass the check allows itself");
}

/// A fixture with `count` Xen block backends that export nothing, the
/// backends' `physical_device` entries in the order the listing yields,
/// which the check reads them in, and the text of a backend that exports
/// the namespace.
fn xen_backends(count: usize) -> (Fixture, Vec<std::path::PathBuf>, String) {
    let fixture = Fixture::new(4096);
    let number = fs::read_to_string(fixture.host.sys.join("class/block/nvme1n1/dev")).unwrap();
    let (major, minor) = number.trim().split_once(':').unwrap();
    let (major, minor): (u32, u32) = (major.parse().unwrap(), minor.parse().unwrap());
    let devices = fixture.host.sys.join("bus/xen-backend/devices");
    for handle in 0..count {
        let backend = devices.join(format!("vbd-1-{handle}"));
        fs::create_dir_all(&backend).unwrap();
        fs::write(backend.join("physical_device"), "0:0\n").unwrap();
    }
    let listed = fs::read_dir(&devices)
        .unwrap()
        .map(|entry| entry.unwrap().path().join("physical_device"))
        .collect();
    (fixture, listed, format!("{major:x}:{minor:x}\n"))
}

/// The bytes written to the FIFO behind `sink` that no reader has taken.
fn queued(sink: &fs::File) -> libc::c_int {
    use std::os::fd::AsRawFd;
    let mut bytes: libc::c_int = 0;
    // SAFETY: `FIONREAD` writes one `c_int` through the pointer, which is valid for the call.
    let status = unsafe { libc::ioctl(sink.as_raw_fd(), libc::FIONREAD, &raw mut bytes) };
    assert_eq!(status, 0);
    bytes
}

/// Whether a descriptor of this process is open on the file at `path`.
fn held_open(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let file = fs::metadata(path).unwrap();
    fs::read_dir("/proc/self/fd")
        .unwrap()
        .flatten()
        .any(|entry| {
            fs::metadata(entry.path())
                .is_ok_and(|open| (open.dev(), open.ino()) == (file.dev(), file.ino()))
        })
}

/// The check's answer while every read of the FIFO `pause` is answered `0:0`
/// after `at_read` ran with the number of reads answered before it.
fn checked_with_paused_backend(
    fixture: &Fixture,
    pause: &Path,
    at_read: impl Fn(usize) + Sync,
) -> Result<(), IdentityError> {
    use std::io::Write;

    use std::sync::atomic::{AtomicBool, Ordering};
    let done = AtomicBool::new(false);
    thread::scope(|scope| {
        let writer = scope.spawn(|| {
            for read in 0.. {
                let mut sink = fs::OpenOptions::new().write(true).open(pause).unwrap();
                if done.load(Ordering::SeqCst) {
                    break;
                }
                at_read(read);
                let _sent = sink.write_all(b"0:0\n");
                // The reader holds a descriptor once it has taken the answer.
                while queued(&sink) != 0 {
                    thread::sleep(Duration::from_millis(1));
                }
                drop(sink);
                // The read ends when the reader has closed the FIFO: until
                // then a second open would add its answer to the same read.
                // The next read waits in its open with no descriptor, so
                // this wait does not open the FIFO and end that read empty.
                while held_open(pause) {
                    thread::sleep(Duration::from_millis(1));
                }
            }
        });
        let checked = fixture.host.check_unused("nvme1n1").map(drop);
        done.store(true, Ordering::SeqCst);
        // The writer waits for a reader of the FIFO.
        while !writer.is_finished() {
            let _reader = release(pause);
            thread::sleep(Duration::from_millis(10));
        }
        checked
    })
}

/// Adds `sent` to the fixture's uevent counter.
fn send_uevents(fixture: &Fixture, sent: u64) {
    let counter = fixture.host.sys.join("kernel/uevent_seqnum");
    let before: u64 = fs::read_to_string(&counter)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    fs::write(&counter, format!("{}\n", before + sent)).unwrap();
}

/// A namespace whose export moves between two Xen block backends while the
/// check reads the backends is exported to a guest at every instant, so it
/// is in use (`check_unused`: refuses a namespace exported "to a guest by a
/// Xen block backend"). The backend listed first exports nothing when the
/// check reads it; while the check waits on the second, the first is given
/// the namespace and the backend listed last, which exported it, is
/// removed, so the listing no longer yields it. The kernel sends a uevent
/// when it removes a backend, so the host's uevent counter moves across the
/// pass and the check reads the backends again. The listing is longer than
/// one read of the directory returns, so the removed backend was not yet
/// listed.
#[test]
fn a_namespace_moved_between_xen_block_backends_while_they_are_read_is_in_use() {
    let (fixture, listed, exporting) = xen_backends(3000);
    let (free, pause, bound) = (&listed[0], &listed[1], &listed[listed.len() - 1]);
    let in_use = || Err(IdentityError::InUse("nvme1n1".into()));
    let checked = || fixture.host.check_unused("nvme1n1").map(drop);
    assert_eq!(
        checked(),
        Ok(()),
        "premise: no backend exports the namespace"
    );
    fs::write(bound, &exporting).unwrap();
    assert_eq!(checked(), in_use(), "premise: the last backend is found");
    make_fifo(pause);
    let during = checked_with_paused_backend(&fixture, pause, |read| {
        if read == 0 {
            fs::write(free, &exporting).unwrap();
            fs::remove_dir_all(bound.parent().unwrap()).unwrap();
            send_uevents(&fixture, 1);
        }
    });
    assert!(!bound.exists(), "premise: the move ran");
    fs::remove_file(pause).unwrap();
    fs::write(pause, "0:0\n").unwrap();
    assert_eq!(checked(), in_use(), "premise: the first backend is found");
    assert_eq!(
        during,
        in_use(),
        "a namespace some backend exported at every instant of the check was admitted"
    );
}

/// The Xen block backends tell nothing of a host whose uevent counter moves
/// across every pass over them: a backend removed during a pass can hide an
/// export from it. The sibling whose counter stands still is admitted.
#[test]
fn xen_block_backends_are_unverifiable_without_a_still_uevent_counter() {
    let (fixture, listed, _) = xen_backends(2);
    let pause = &listed[0];
    make_fifo(pause);
    let still = checked_with_paused_backend(&fixture, pause, |_| {});
    assert_eq!(
        still,
        Ok(()),
        "premise: a still counter admits the namespace"
    );
    let moving = checked_with_paused_backend(&fixture, pause, |_| send_uevents(&fixture, 1));
    assert_eq!(moving, Err(IdentityError::Unverifiable("xen-backends")));
}

/// Every kernel file and listing the in-use check takes as evidence is the
/// kernel's own only where no mount covers it. A mount the mount table
/// lists at one of them shows the mount's text or entries there, which can
/// read as an idle host: an empty swap table, a counter that stands still,
/// a backend with no device. Each row lists a mount over one such entry of
/// a host the check otherwise admits, leaves the entry's content as it is,
/// and the check refuses under that reading's label. The same host under
/// the mounts a stock distribution lists below `proc` and `sys` is
/// admitted.
#[test]
fn an_entry_a_mount_covers_is_no_evidence_that_the_namespace_is_unused() {
    const STOCK: &str = "/dev/nvme0n1p1 / xfs rw 0 0\n\
        proc /proc proc rw 0 0\n\
        sysfs /sys sysfs rw 0 0\n\
        securityfs /sys/kernel/security securityfs rw 0 0\n\
        cgroup2 /sys/fs/cgroup cgroup2 rw 0 0\n\
        efivarfs /sys/firmware/efi/efivars efivarfs rw 0 0\n\
        binfmt_misc /proc/sys/fs/binfmt_misc binfmt_misc rw 0 0\n\
        tracefs /sys/kernel/tracing tracefs rw 0 0\n\
        debugfs /sys/kernel/debug debugfs rw 0 0\n\
        configfs /sys/kernel/config configfs rw 0 0\n";
    let host = || {
        let fixture = Fixture::new(4096);
        fixture.file("var/disk.img", "");
        fs::create_dir_all(fixture.host.sys.join("block/loop0")).unwrap();
        fixture.loop_device("loop0", "/var/disk.img");
        fixture.file(
            "sys/bus/xen-backend/devices/vbd-3-51728/physical_device",
            "0:0\n",
        );
        fixture.file("sys/class/rnbd-server/ctl/devices/.keep", "");
        fixture
    };
    let fixture = host();
    fixture.file("proc/self/mounts", STOCK);
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Ok(()),
        "premise: the host under a stock mount table is admitted"
    );
    let rows: [(&str, &'static str); 13] = [
        ("/sys/class/block/nvme1n1/dev", "dev"),
        ("/sys/block/nvme1n1", "partitions"),
        ("/proc/swaps", "swaps"),
        ("/sys/kernel/uevent_seqnum", "loops"),
        ("/sys/block/loop0/loop/backing_file", "loops"),
        ("/sys/block/loop0/dev", "loops"),
        (
            "/sys/bus/xen-backend/devices/vbd-3-51728/physical_device",
            "xen-backends",
        ),
        ("/sys/block/nvme1n1/holders", "holders"),
        ("/sys/class/nvme/nvme1/dev", "devices"),
        ("/proc/loadavg", "processes"),
        ("/proc/uptime", "processes"),
        ("/proc/sys/kernel/osrelease", "processes"),
        ("/proc/sys", "processes"),
    ];
    let mut read = Vec::new();
    for (covered, label) in rows {
        let fixture = host();
        fixture.file(
            "proc/self/mounts",
            &format!("{STOCK}tmpfs {covered} tmpfs rw 0 0\n"),
        );
        let checked = fixture.host.check_unused("nvme1n1").map(drop);
        if checked != Err(IdentityError::Unverifiable(label)) {
            read.push((covered, checked));
        }
    }
    assert_eq!(read, [], "entries read as the kernel's under a mount");
}

/// `check_unused` on a host whose kernel keeps the use `configure` sets up, read through a fixed sysfs path under
/// `covered`, first as written and then with a tmpfs the mount table lists at `covered`, which shows an empty
/// directory there in place of the kernel's entries.
fn checked_with_cover(configure: fn(&Fixture), covered: &str) -> [Result<(), IdentityError>; 2] {
    [false, true].map(|cover| {
        let fixture = Fixture::new(4096);
        configure(&fixture);
        let mut mounts = String::from("/dev/nvme0n1p1 / xfs rw 0 0\nsysfs /sys sysfs rw 0 0\n");
        if cover {
            let directory = fixture.root.join(covered);
            fs::remove_dir_all(&directory).unwrap();
            fs::create_dir_all(&directory).unwrap();
            mounts.push_str(&format!("tmpfs /{covered} tmpfs rw 0 0\n"));
        }
        fixture.file("proc/self/mounts", &mounts);
        fixture.host.check_unused("nvme1n1").map(drop)
    })
}

/// A legacy gadget module's LUN is read at the fixed sysfs path `class/udc/<controller>/device/gadget.<n>/lun<n>`. A
/// mount the mount table lists at `/sys/class/udc` covers it, so a LUN the kernel keeps open over the namespace
/// cannot be read there, and the check cannot show the namespace unused. Without the cover the LUN refuses as in use.
#[test]
fn a_legacy_gadget_lun_under_a_covered_udc_listing_is_not_read_as_no_lun() {
    let [uncovered, covered] = checked_with_cover(
        |fixture| {
            fixture.file(
                "sys/class/udc/dummy_udc.0/device/gadget.0/lun0/file",
                "/dev/nvme1n1\n",
            )
        },
        "sys/class/udc",
    );
    assert_eq!(
        uncovered,
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise"
    );
    assert_ne!(covered, Ok(()), "a LUN under a covered class/udc admitted");
}

/// A mount the mount table lists below `class/udc` covers part of the legacy LUN listing: one at a controller, its
/// device, the gadget device or the LUN shows a directory without the LUN, and one at the LUN's `file` shows another
/// file's text, here an empty one. Each hides a LUN the kernel keeps open over the namespace, so the check cannot
/// show the namespace unused. Without the cover the LUN refuses as in use.
#[test]
fn a_legacy_gadget_lun_under_a_mount_below_class_udc_is_not_read_as_no_lun() {
    const LUN: &str = "sys/class/udc/dummy_udc.0/device/gadget.0/lun0";
    let unverifiable = Err(IdentityError::Unverifiable("gadgets"));
    for covered in [
        "sys/class/udc/dummy_udc.0",
        "sys/class/udc/dummy_udc.0/device",
        "sys/class/udc/dummy_udc.0/device/gadget.0",
        LUN,
    ] {
        let [uncovered, covered_at] = checked_with_cover(
            |fixture| fixture.file(&format!("{LUN}/file"), "/dev/nvme1n1\n"),
            covered,
        );
        assert_eq!(
            uncovered,
            Err(IdentityError::InUse("nvme1n1".into())),
            "premise under {covered}"
        );
        assert_eq!(covered_at, unverifiable, "a LUN under a cover of {covered}");
    }
    let fixture = Fixture::new(4096);
    fixture.file(&format!("{LUN}/file"), "");
    fixture.file(
        "proc/self/mounts",
        &format!(
            "/dev/nvme0n1p1 / xfs rw 0 0\nsysfs /sys sysfs rw 0 0\ntmpfs /{LUN}/file tmpfs rw 0 0\n"
        ),
    );
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        unverifiable,
        "a LUN whose file a mount covers"
    );
}

/// A mount that leaves `class/udc` uncovered leaves the legacy LUN listing readable: a tmpfs beside it covers
/// nothing the listing reads, and a sysfs mounted over a tmpfs at `/sys/class/udc` uncovers it again, so a LUN over
/// the namespace still refuses as in use and a host without one still shows it unused.
#[test]
fn a_mount_that_does_not_cover_class_udc_leaves_the_lun_listing_read() {
    let lun = "sys/class/udc/dummy_udc.0/device/gadget.0/lun0/file";
    for tail in [
        "tmpfs /sys/class/udc_spare tmpfs rw 0 0\n",
        "tmpfs /sys/class/udc tmpfs rw 0 0\nsysfs /sys sysfs rw 0 0\n",
    ] {
        for backing in [true, false] {
            let fixture = Fixture::new(4096);
            fixture.file(lun, if backing { "/dev/nvme1n1\n" } else { "\n" });
            fixture.file(
                "proc/self/mounts",
                &format!("/dev/nvme0n1p1 / xfs rw 0 0\nsysfs /sys sysfs rw 0 0\n{tail}"),
            );
            let expected = if backing {
                Err(IdentityError::InUse("nvme1n1".into()))
            } else {
                Ok(())
            };
            assert_eq!(
                fixture.host.check_unused("nvme1n1").map(drop),
                expected,
                "{tail:?} with a backing LUN: {backing}"
            );
        }
    }
}

/// The process walk and the ring pass read each process's tables at `proc/<pid>/fd` and skip a table that answers
/// `ENOENT` as a process that exited. A mount the mount table lists at `/proc/4242` covers that process's
/// directory, so its tables answer `ENOENT` while the process still holds the namespace open, or holds it
/// registered with a ring, and the check cannot show the namespace unused. A mount at `/proc/4242/fd` shows an
/// empty table instead. Each cover refuses as unverifiable; without it each use refuses as in use.
#[test]
fn a_use_by_a_process_whose_proc_directory_a_mount_covers_is_not_read_as_ended() {
    let checked = |ring: bool, shown: Option<&str>, listed: Option<&str>| {
        let fixture = Fixture::new(4096);
        if ring {
            hold_ring(&fixture, "4242", 5, &ring_info(&["nvme1n1"]));
        } else {
            fixture.open(4242, &fixture.host.dev.join("nvme1n1"));
        }
        let mut mounts = String::from(
            "/dev/nvme0n1p1 / xfs rw 0 0\nproc /proc proc rw 0 0\n\
             binfmt_misc /proc/sys/fs/binfmt_misc binfmt_misc rw 0 0\n",
        );
        match shown {
            Some("/proc/4242") => {
                let directory = fixture.root.join("proc/4242");
                fs::remove_dir_all(&directory).unwrap();
                fs::create_dir_all(&directory).unwrap();
                fixture.process(4242);
            }
            // A cover of the table alone shows an empty table, with no `ENOENT` for the walk to skip.
            Some("/proc/4242/fd") => {
                let table = fixture.root.join("proc/4242/fd");
                fs::remove_dir_all(&table).unwrap();
                fs::create_dir_all(&table).unwrap();
            }
            Some(other) => panic!("no fixture for a cover at {other}"),
            None => {}
        }
        if let Some(at) = listed {
            mounts.push_str(&format!("tmpfs {at} tmpfs rw 0 0\n"));
        }
        fixture.file("proc/self/mounts", &mounts);
        fixture.host.check_unused("nvme1n1").map(drop)
    };
    for ring in [false, true] {
        assert_eq!(
            checked(ring, None, None),
            Err(IdentityError::InUse("nvme1n1".into())),
            "premise, ring {ring}"
        );
    }
    let covers = ["/proc/4242", "/proc/4242/fd"];
    let cases = || {
        [false, true]
            .into_iter()
            .flat_map(|ring| covers.map(|at| (ring, at)))
    };
    for (ring, at) in cases() {
        assert_eq!(
            checked(ring, Some(at), None),
            Ok(()),
            "premise: with no mount listed, the directory a cover at {at} shows admits the namespace, \
             ring {ring}"
        );
    }
    let admitted: Vec<(bool, &str)> = cases()
        .filter(|&(ring, at)| {
            checked(ring, Some(at), Some(at)) != Err(IdentityError::Unverifiable("processes"))
        })
        .collect();
    assert!(
        admitted.is_empty(),
        "a namespace in use by a process under a covered proc directory not refused as unverifiable \
         (ring, cover): {admitted:?}"
    );
}

/// A mount inside `proc` outside every process's directory, such as the `binfmt_misc` mount most hosts carry,
/// covers no descriptor table, so an unused namespace is still admitted under it.
#[test]
fn a_mount_inside_proc_outside_every_process_directory_admits_an_unused_namespace() {
    let fixture = Fixture::new(4096);
    fixture.file(
        "proc/self/mounts",
        "proc /proc proc rw 0 0\nbinfmt_misc /proc/sys/fs/binfmt_misc binfmt_misc rw 0 0\n",
    );
    assert_eq!(fixture.host.check_unused("nvme1n1").map(drop), Ok(()));
}

/// The generic node `ng<c>n<n>` is counted only when its entry under the fixed sysfs path `class/nvme/<controller>`
/// exists, and a missing entry is read as a kernel that registers no generic device. A mount the mount table lists at
/// `/sys/class/nvme/nvme1` covers the entry, so a process holding the generic node open cannot be matched, and the
/// check cannot show the namespace unused. Without the cover the open node refuses as in use.
#[test]
fn a_generic_node_under_a_covered_controller_directory_is_not_read_as_unregistered() {
    let checked = |cover: bool| {
        let fixture = Fixture::new(4096);
        let path = fixture.host.dev.join("ng1n1");
        fs::write(&path, "").unwrap();
        fixture.file("sys/class/nvme/nvme1/ng1n1/dev", "241:1\n");
        fixture.open(4242, &path);
        let mut mounts = String::from("/dev/nvme0n1p1 / xfs rw 0 0\nsysfs /sys sysfs rw 0 0\n");
        if cover {
            let directory = fixture.root.join("sys/class/nvme/nvme1");
            fs::remove_dir_all(&directory).unwrap();
            fs::create_dir_all(&directory).unwrap();
            mounts.push_str("tmpfs /sys/class/nvme/nvme1 tmpfs rw 0 0\n");
        }
        fixture.file("proc/self/mounts", &mounts);
        fixture.host.check_unused("nvme1n1").map(drop)
    };
    assert_eq!(
        checked(false),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise"
    );
    assert_ne!(
        checked(true),
        Ok(()),
        "an open generic node under a covered controller directory admitted"
    );
}

/// On a kernel's sysfs `class/nvme/<controller>` is a link into
/// `sys/devices`, and the mount table names a mount by its resolved
/// directory. A cover of the resolved controller directory, of
/// `sys/devices` above it, which leaves the link leading nowhere, or of
/// `class/nvme` hides the generic entry of an open generic node.
#[test]
fn a_generic_node_hidden_behind_the_class_link_is_not_read_as_unregistered() {
    const SYSFS: &str = "/dev/nvme0n1p1 / xfs rw 0 0\nsysfs /sys sysfs rw 0 0\n";
    let linked = |generic: bool| {
        let fixture = Fixture::new(4096);
        let device = fixture.root.join("sys/devices/pci0/nvme");
        fs::create_dir_all(&device).unwrap();
        let class = fixture.root.join("sys/class/nvme/nvme1");
        fs::rename(&class, device.join("nvme1")).unwrap();
        symlink("../../devices/pci0/nvme/nvme1", &class).unwrap();
        if generic {
            let path = fixture.host.dev.join("ng1n1");
            fs::write(&path, "").unwrap();
            fixture.file("sys/devices/pci0/nvme/nvme1/ng1n1/dev", "241:1\n");
            fixture.open(4242, &path);
        }
        fixture
    };
    let checked = |generic: bool, cover: Option<&str>, mount: &str| {
        let fixture = linked(generic);
        if let Some(cover) = cover {
            let directory = fixture.root.join(cover);
            fs::remove_dir_all(&directory).unwrap();
            fs::create_dir_all(&directory).unwrap();
        }
        fixture.file("proc/self/mounts", &format!("{SYSFS}{mount}"));
        fixture.host.check_unused("nvme1n1").map(drop)
    };
    assert_eq!(
        checked(true, None, ""),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: the open generic node is found through the link"
    );
    assert_eq!(
        checked(false, None, ""),
        Ok(()),
        "premise: no generic device and no cover"
    );
    assert_eq!(
        checked(false, None, "cgroup2 /sys/fs/cgroup cgroup2 rw 0 0\n"),
        Ok(()),
        "premise: no generic device and a mount beside the entry"
    );
    for cover in [
        "sys/devices/pci0/nvme/nvme1",
        "sys/devices",
        "sys/class/nvme",
    ] {
        assert_eq!(
            checked(true, Some(cover), &format!("tmpfs /{cover} tmpfs rw 0 0\n")),
            Err(IdentityError::Unverifiable("devices")),
            "an open generic node under a cover of {cover}"
        );
    }
}

/// What one ring pass reported beside a ring that holds `nvme1n1` registered, and whether the ring's change of process fell inside the pass.
struct RingReading {
    names: Option<Vec<String>>,
    /// The pass read the early process's table, then the ring changed processes, then the pass read the late process's.
    moved_inside: bool,
}

/// Runs [`Host::registered`] once while a ring that holds `nvme1n1` registered is descriptor 5 of some process at every instant.
/// Three processes are listed in the order the fixture's `proc` yields them. With `moves`, the ring starts in the last-listed process; once the pass opens the middle process's many tasks, the first-listed process receives the ring (as over `SCM_RIGHTS` or by `pidfd_getfd`) and only then the last-listed one closes it. Without `moves`, the first-listed process holds the ring throughout when `early_holds`, else the last-listed one.
fn read_beside_a_moving_ring(moves: bool, early_holds: bool) -> RingReading {
    const TASKS: u32 = 20_000;
    let fixture = Fixture::new(4096);
    let proc = fixture.root.join("proc");
    for pid in [4242, 5151, 6060] {
        fixture.process(pid);
        fs::create_dir_all(proc.join(format!("{pid}/fd"))).unwrap();
        fs::create_dir_all(proc.join(format!("{pid}/fdinfo"))).unwrap();
    }
    let order: Vec<String> = fs::read_dir(&proc)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.bytes().all(|byte| byte.is_ascii_digit()))
        .collect();
    let [early, middle, late] = order.as_slice() else {
        panic!("premise: the fixture lists three processes, not {order:?}");
    };
    let holder = if moves || !early_holds { late } else { early };
    hold_ring(&fixture, holder, 5, &ring_info(&["nvme1n1"]));
    // The middle process holds no ring; listing its tasks takes the pass long enough for the change.
    let tasks = proc.join(format!("{middle}/task"));
    for tid in 0..TASKS {
        fs::create_dir_all(tasks.join((100_000 + tid).to_string())).unwrap();
    }
    // The ring's link and `fdinfo` the change renames into the receiver's table, and the directory that marks its end.
    let staged = fixture.root.join("staged");
    let marks = fixture.root.join("marks");
    fs::create_dir_all(&staged).unwrap();
    fs::create_dir_all(&marks).unwrap();
    symlink("anon_inode:[io_uring]", staged.join("ring")).unwrap();
    fs::write(staged.join("info"), ring_info(&["nvme1n1"])).unwrap();

    // SAFETY: the call takes no pointer.
    let watch = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
    assert!(watch >= 0);
    let add = |path: &Path, mask: u32| {
        let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `path` is a NUL-terminated string that outlives the call.
        let wd = unsafe { libc::inotify_add_watch(watch, path.as_ptr(), mask) };
        assert!(wd >= 0);
        wd
    };
    let middle_opened = add(&tasks, libc::IN_OPEN);
    let late_opened = add(&proc.join(format!("{late}/fd")), libc::IN_OPEN);
    let moved = add(&marks, libc::IN_CREATE);

    let mut seen = Vec::new();
    let names = thread::scope(|scope| {
        let mover = scope.spawn(|| {
            let mut seen = Vec::new();
            while !seen.contains(&middle_opened) {
                seen.extend(queued_watch_events(watch).into_iter().map(|(wd, _)| wd));
            }
            if moves {
                // The first-listed process holds the ring before the last-listed one closes it.
                fs::rename(staged.join("info"), proc.join(format!("{early}/fdinfo/5"))).unwrap();
                fs::rename(staged.join("ring"), proc.join(format!("{early}/fd/5"))).unwrap();
                fs::remove_file(proc.join(format!("{late}/fd/5"))).unwrap();
                fs::remove_file(proc.join(format!("{late}/fdinfo/5"))).unwrap();
            }
            fs::write(marks.join("moved"), "").unwrap();
            seen
        });
        let names = fixture.host.registered(|_| true);
        seen = mover.join().unwrap();
        names
    });
    // SAFETY: `watch` is an open descriptor this function owns; the calls take no pointer.
    unsafe {
        let flags = libc::fcntl(watch, libc::F_GETFL);
        assert_eq!(
            libc::fcntl(watch, libc::F_SETFL, flags | libc::O_NONBLOCK),
            0
        );
    }
    loop {
        let more = queued_watch_events(watch);
        if more.is_empty() {
            break;
        }
        seen.extend(more.into_iter().map(|(wd, _)| wd));
    }
    // SAFETY: `watch` is open and closed once.
    unsafe { libc::close(watch) };
    let at = |wd: i32| seen.iter().position(|&event| event == wd);
    RingReading {
        names,
        moved_inside: matches!(
            (at(middle_opened), at(moved), at(late_opened)),
            (Some(opened), Some(moved), Some(late)) if opened < moved && moved < late
        ),
    }
}

/// The ring pass reports "the name of every file a ring some task holds as a descriptor has registered" ([`Host::registered`]). A ring that holds the namespace registered and that changes processes during the pass, the receiver holding it before the sender closes it, is a descriptor of some task at every instant, so the pass reports the namespace.
#[test]
fn a_ring_that_changes_processes_during_the_ring_pass_is_reported() {
    let reading = (0..5)
        .map(|_| read_beside_a_moving_ring(true, false))
        .find(|reading| reading.moved_inside)
        .expect("premise: the ring changed processes inside one pass in five tries");
    assert_eq!(
        reading.names,
        Some(vec!["nvme1n1".to_owned()]),
        "the pass missed a ring a process held throughout"
    );
}

/// The siblings without the change: the same tree reports the namespace whichever of the two processes holds the ring for the whole pass.
#[test]
fn a_ring_either_process_keeps_during_the_ring_pass_is_reported() {
    for early_holds in [true, false] {
        let reading = read_beside_a_moving_ring(false, early_holds);
        assert_eq!(
            reading.names,
            Some(vec!["nvme1n1".to_owned()]),
            "early_holds {early_holds}"
        );
    }
}

/// A process that holds the namespace open, hands it to a loop device while
/// the walk runs and takes it back before the check reads that loop device
/// the second time, keeps it in use at every instant: open in the process,
/// then backing the loop device, then open again. The first handoff happens
/// while the walk reads the uptime, a FIFO, after the first loop reading.
/// The second happens while the second loop reading reads the backing file
/// of the device listed first, a FIFO for that one read, so the device
/// listed last is detached when its turn comes and the pass read again
/// after the detach's uevent finds no loop device over the namespace. The
/// kernel sends a uevent at each handoff, so the counter the second reading
/// settles on is not the one the first reading settled on, and the check
/// refuses.
#[test]
fn a_namespace_handed_to_a_loop_device_and_back_during_the_check_is_in_use() {
    use std::io::Write;
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new(4096);
    fixture.file("var/disk.img", "");
    let node = fixture.host.dev.join("nvme1n1");
    let block = fixture.host.sys.join("block");
    let counter = fixture.host.sys.join("kernel/uevent_seqnum");
    for name in ["loop0", "loop1"] {
        fs::create_dir_all(block.join(name)).unwrap();
    }
    // The roles follow the order the listing yields, which the check sees too.
    let listed: Vec<_> = fs::read_dir(&block)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.starts_with("loop"))
        .collect();
    let [pause, bound] = <[String; 2]>::try_from(listed).unwrap();
    let backing = |name: &str| block.join(name).join("loop/backing_file");
    fixture.loop_device(&pause, "/var/disk.img");
    fixture.open(4242, &node);
    let descriptor = fixture.host.proc.join("4242/fd/3");
    assert_eq!(fs::read_link(&descriptor).unwrap(), node, "premise");
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: the descriptor alone is found"
    );
    let uptime = fixture.host.proc.join("uptime");
    fs::remove_file(&uptime).unwrap();
    make_fifo(&uptime);
    let writer = {
        let (uptime, fifo, to) = (uptime.clone(), backing(&pause), backing(&bound));
        let (node, descriptor, counter) = (node.clone(), descriptor.clone(), counter.clone());
        let device = fixture.host.dev.join(&bound);
        thread::spawn(move || {
            let mut sink = fs::OpenOptions::new().write(true).open(&uptime).unwrap();
            fs::create_dir_all(to.parent().unwrap()).unwrap();
            fs::hard_link(&node, &device).unwrap();
            fs::write(&to, "/dev/nvme1n1\n").unwrap();
            fs::write(&counter, "7066\n").unwrap();
            fs::remove_file(&descriptor).unwrap();
            fs::remove_file(&fifo).unwrap();
            make_fifo(&fifo);
            fs::remove_file(&uptime).unwrap();
            fs::write(&uptime, "100.00 400.00\n").unwrap();
            let _sent = sink.write_all(b"100.00 400.00\n");
            drop(sink);
            let mut sink = fs::OpenOptions::new().write(true).open(&fifo).unwrap();
            symlink(&node, &descriptor).unwrap();
            fs::remove_dir_all(to.parent().unwrap()).unwrap();
            fs::remove_file(&device).unwrap();
            fs::write(&counter, "7067\n").unwrap();
            fs::remove_file(&fifo).unwrap();
            fs::write(&fifo, "/var/disk.img\n").unwrap();
            let _sent = sink.write_all(b"/var/disk.img\n");
        })
    };
    let checked = fixture.host.check_unused("nvme1n1").map(drop);
    // A check that never read a FIFO releases the writer here.
    while !writer.is_finished() {
        for fifo in [&uptime, &backing(&pause)] {
            let _reader = release(fifo);
        }
        thread::sleep(Duration::from_millis(10));
    }
    writer.join().unwrap();
    assert!(!backing(&bound).exists(), "premise: both handoffs ran");
    assert_eq!(
        fs::read_to_string(&counter).unwrap(),
        "7067\n",
        "premise: each handoff sent a uevent"
    );
    assert_eq!(fs::read_link(&descriptor).unwrap(), node, "premise");
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: after both handoffs the descriptor alone is found"
    );
    assert_eq!(
        checked,
        Err(IdentityError::Unverifiable("loops")),
        "a namespace in use at every instant of the check was admitted"
    );
}

/// `check_unused` with `loop0` configured over the namespace, first as written and then with a tmpfs the mount table
/// lists at `covered`, which shows an empty directory there in place of the kernel's entries.
fn checked_with_covered_loop(covered: &str) -> [Result<(), IdentityError>; 2] {
    [false, true].map(|cover| {
        let fixture = Fixture::new(4096);
        fixture.loop_device("loop0", "/dev/nvme1n1");
        let mut mounts = String::from("/dev/nvme0n1p1 / xfs rw 0 0\nsysfs /sys sysfs rw 0 0\n");
        if cover {
            let directory = fixture.root.join(covered);
            fs::remove_dir_all(&directory).unwrap();
            fs::create_dir_all(&directory).unwrap();
            mounts.push_str(&format!("tmpfs /{covered} tmpfs rw 0 0\n"));
        }
        fixture.file("proc/self/mounts", &mounts);
        fixture.host.check_unused("nvme1n1").map(drop)
    })
}

/// A loop device's backing file is read at the fixed sysfs path `block/loop<n>/loop/backing_file`, and a missing
/// entry is read as an unconfigured loop device. A mount the mount table lists over the loop device's sysfs directory
/// covers the entry, so a loop device the kernel keeps configured over the namespace cannot be read, and the check
/// cannot show the namespace unused. Without the cover the loop device refuses as in use.
#[test]
fn a_loop_device_under_a_covered_sysfs_directory_is_not_read_as_unconfigured() {
    for covered in ["sys/block/loop0", "sys/block/loop0/loop"] {
        let [uncovered, covered] = checked_with_covered_loop(covered);
        assert_eq!(
            uncovered,
            Err(IdentityError::InUse("nvme1n1".into())),
            "premise"
        );
        assert_eq!(covered, Err(IdentityError::Unverifiable("loops")));
    }
}

/// The loop devices are found by the `sys/block` listing. A mount the mount table lists at `/sys/block` shows its own
/// entries there, so one that names the namespace and no loop device hides a loop device the kernel keeps configured
/// over the namespace, and the listing cannot show the namespace unused. Without the cover the loop device refuses
/// as in use, and a mount beside the listing leaves it read.
#[test]
fn a_loop_device_a_mount_over_the_block_listing_hides_is_not_read_as_absent() {
    let checked = |cover: Option<&str>| {
        let fixture = Fixture::new(4096);
        fixture.loop_device("loop0", "/dev/nvme1n1");
        let mut mounts = String::from("/dev/nvme0n1p1 / xfs rw 0 0\nsysfs /sys sysfs rw 0 0\n");
        if let Some(cover) = cover {
            if cover == "sys/block" {
                fs::remove_dir_all(fixture.root.join("sys/block/loop0")).unwrap();
            }
            mounts.push_str(&format!("tmpfs /{cover} tmpfs rw 0 0\n"));
        }
        fixture.file("proc/self/mounts", &mounts);
        fixture.host.check_unused("nvme1n1").map(drop)
    };
    let in_use = Err(IdentityError::InUse("nvme1n1".into()));
    assert_eq!(checked(None), in_use, "premise");
    assert_eq!(
        checked(Some("sys/block_spare")),
        in_use,
        "a mount beside the listing"
    );
    assert_eq!(
        checked(Some("sys/block")),
        Err(IdentityError::Unverifiable("partitions")),
        "a loop device under a covered block listing admitted"
    );
}

/// The kernel lists a loop device in `sys/block` as a link into `sys/devices`, and the mount table names a mount over
/// the device's directory, or over a directory above it, by the link's target. The covered entry is judged at that
/// target too, including when the cover hides the target itself and leaves the link dangling.
#[test]
fn a_loop_device_covered_at_or_above_its_link_target_is_not_read_as_unconfigured() {
    for covered in [
        "sys/devices/virtual/block/loop0",
        "sys/devices/virtual/block",
        "sys/devices/virtual",
    ] {
        let fixture = Fixture::new(4096);
        fixture.loop_device("loop0", "/dev/nvme1n1");
        let device = fixture.root.join("sys/devices/virtual/block/loop0");
        fs::create_dir_all(device.parent().unwrap()).unwrap();
        fs::rename(fixture.root.join("sys/block/loop0"), &device).unwrap();
        std::os::unix::fs::symlink(
            "../devices/virtual/block/loop0",
            fixture.root.join("sys/block/loop0"),
        )
        .unwrap();
        let table = "/dev/nvme0n1p1 / xfs rw 0 0\nsysfs /sys sysfs rw 0 0\n";
        fixture.file("proc/self/mounts", table);
        assert_eq!(
            fixture.host.check_unused("nvme1n1").map(drop),
            Err(IdentityError::InUse("nvme1n1".into())),
            "premise under {covered}"
        );
        let directory = fixture.root.join(covered);
        fs::remove_dir_all(&directory).unwrap();
        fs::create_dir_all(&directory).unwrap();
        fixture.file(
            "proc/self/mounts",
            &format!("{table}tmpfs /{covered} tmpfs rw 0 0\n"),
        );
        assert_eq!(
            fixture.host.check_unused("nvme1n1").map(drop),
            Err(IdentityError::Unverifiable("loops")),
            "{covered}"
        );
    }
}

/// The cover refusal is scoped to a mount that can hide the entry: an unconfigured loop device under no other mount,
/// under a tmpfs beside its directory, or under a tmpfs that a later sysfs mount covers in turn, leaves the namespace
/// unused.
#[test]
fn an_unconfigured_loop_device_no_mount_covers_leaves_the_namespace_unused() {
    for extra in [
        "",
        "tmpfs /sys/block/loop1 tmpfs rw 0 0\n",
        "tmpfs /mnt/sys/block/loop0 tmpfs rw 0 0\n",
        "tmpfs /sys/block/loop0 tmpfs rw 0 0\nsysfs /sys sysfs rw 0 0\n",
    ] {
        let fixture = Fixture::new(4096);
        fs::create_dir_all(fixture.root.join("sys/block/loop0/loop")).unwrap();
        fixture.file(
            "proc/self/mounts",
            &format!("/dev/nvme0n1p1 / xfs rw 0 0\nsysfs /sys sysfs rw 0 0\n{extra}"),
        );
        assert_eq!(
            fixture.host.check_unused("nvme1n1").map(drop),
            Ok(()),
            "{extra:?}"
        );
    }
}

/// Judging a loop device's link target is scoped to that target: an unconfigured loop device listed by a link into
/// `sys/devices` leaves the namespace unused under a tmpfs beside its target directory.
#[test]
fn an_unconfigured_linked_loop_device_beside_a_covered_directory_leaves_the_namespace_unused() {
    let fixture = Fixture::new(4096);
    fs::create_dir_all(fixture.root.join("sys/devices/virtual/block/loop0/loop")).unwrap();
    fs::create_dir_all(fixture.root.join("sys/devices/virtual/block/loop1")).unwrap();
    std::os::unix::fs::symlink(
        "../devices/virtual/block/loop0",
        fixture.root.join("sys/block/loop0"),
    )
    .unwrap();
    fixture.file(
        "proc/self/mounts",
        "/dev/nvme0n1p1 / xfs rw 0 0\nsysfs /sys sysfs rw 0 0\ntmpfs /sys/devices/virtual/block/loop1 tmpfs rw 0 0\n",
    );
    assert_eq!(fixture.host.check_unused("nvme1n1").map(drop), Ok(()));
}

/// A ring that lists the namespace is held at every instant of the check
/// while a thread execs with it in each ring reading, and the check finds
/// it. The check reads the rings before and after the descriptor walk and
/// lists the process table twice each time, which makes four readings.
/// Thread 4243 holds the ring in a private table and execs, so the ring
/// comes under the process's ID and the thread's entry goes. The process
/// then starts a thread without `CLONE_FILES`, which gets a copy of the
/// table, and closes the ring in its own table and opens an empty one.
/// That thread execs in the next reading, and so on. Each exec comes after
/// a reading read the table under the process's ID for the last time
/// before it lists the threads, so readings that read that table only
/// before the threads find the ring in none.
///
/// The fixture times the moves by the reads of an empty ring's `fdinfo`, a
/// FIFO per read. A reading reads a table twice, and each exec comes while
/// the second read of the process's ring waits. The start of a thread
/// comes while a read of the ring of process 5000 waits, the first such
/// read after an exec: that is after one reading listed the threads of
/// 4242 and before the next reads its table, in whichever order a reading
/// lists the two processes.
#[test]
fn a_ring_a_thread_execs_with_in_each_ring_reading_is_in_use() {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
    use std::sync::{Arc, Barrier};

    /// The ring readings of one check.
    const READINGS: usize = 4;
    /// The moves of the ring: an exec in each reading and the start of a
    /// thread between two.
    const MOVES: u8 = 7;
    /// The ID of the thread that execs in the first reading; the thread
    /// of each later reading has the next ID.
    const FIRST: usize = 4243;

    let fixture = Fixture::new(4096);
    let root = fixture.root.clone();
    let process = fixture.host.proc.join("4242");
    hold_ring(&fixture, "4242", 5, &ring_info(&[]));
    hold_ring(&fixture, "4242/task/4243", 5, &ring_info(&["nvme1n1"]));
    hold_ring(&fixture, "5000", 5, &ring_info(&[]));
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: the ring in the first thread's table is found"
    );
    let fifo = |name: String| {
        let fifo = root.join(name);
        make_fifo(&fifo);
        fifo
    };
    // The FIFOs the reads of the process's empty ring wait on, two for
    // each reading: the ring the process holds during that reading is
    // read twice before its threads are listed.
    let leader: Vec<_> = (0..2 * READINGS)
        .map(|read| fifo(format!("leader-{read}")))
        .collect();
    // The FIFOs the reads of the other process's ring wait on, more than
    // the readings take at two reads each.
    let other: Vec<_> = (0..8 * READINGS)
        .map(|read| fifo(format!("other-{read}")))
        .collect();
    let info = process.join("fdinfo/5");
    let other_info = fixture.host.proc.join("5000/fdinfo/5");
    // Puts a link to `file` at `at` in one step.
    let place = {
        let staged = root.join("staged");
        move |file: &Path, at: &Path| {
            fs::hard_link(file, &staged).unwrap();
            fs::rename(&staged, at).unwrap();
        }
    };
    let held = root.join("held");
    fs::write(&held, ring_info(&["nvme1n1"])).unwrap();
    let empty = root.join("empty");
    fs::write(&empty, ring_info(&[])).unwrap();
    place(&leader[0], &info);
    place(&other[0], &other_info);
    // The moves made so far: an odd count after an exec, an even one after
    // the start of the next thread.
    let moves = Arc::new(AtomicU8::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let started = Arc::new(Barrier::new(2));
    // Waits for a read of `fifo` and returns the end that answers it, or
    // `None` once the check is over.
    let reader = {
        let stop = Arc::clone(&stop);
        move |fifo: &Path| {
            let sink = fs::OpenOptions::new().write(true).open(fifo).unwrap();
            (!stop.load(Ordering::SeqCst)).then_some(sink)
        }
    };
    let execs = {
        let (leader, info, held, process) =
            (leader.clone(), info.clone(), held.clone(), process.clone());
        let (moves, started, reader, place) = (
            Arc::clone(&moves),
            Arc::clone(&started),
            reader.clone(),
            place.clone(),
        );
        thread::spawn(move || {
            for reading in 0..READINGS {
                let reads = &leader[2 * reading..];
                let Some(mut first) = reader(&reads[0]) else {
                    return;
                };
                place(&reads[1], &info);
                let _sent = first.write_all(ring_info(&[]).as_bytes());
                drop(first);
                let Some(mut second) = reader(&reads[1]) else {
                    return;
                };
                // The exec: the thread's table, with the ring that lists
                // the namespace as descriptor 5, becomes the process's, and
                // the thread's own entry goes.
                place(&held, &info);
                let thread = format!("task/{}", FIRST + reading);
                fs::remove_dir_all(process.join(thread)).unwrap();
                moves.fetch_add(1, Ordering::SeqCst);
                let _sent = second.write_all(ring_info(&[]).as_bytes());
                drop(second);
                if reading + 1 < READINGS {
                    // The next thread has started and the process's ring
                    // is an empty one again once the other thread passes
                    // here.
                    started.wait();
                }
            }
        })
    };
    let starts = {
        let (leader, other, info, other_info, process) = (
            leader.clone(),
            other.clone(),
            info.clone(),
            other_info.clone(),
            process.clone(),
        );
        let (moves, started, held, place) = (
            Arc::clone(&moves),
            Arc::clone(&started),
            held.clone(),
            place.clone(),
        );
        thread::spawn(move || {
            for read in 0..other.len() {
                let Some(mut sink) = reader(&other[read]) else {
                    return;
                };
                if let Some(next) = other.get(read + 1) {
                    place(next, &other_info);
                }
                let made = moves.load(Ordering::SeqCst);
                if !made.is_multiple_of(2) && made < MOVES {
                    // The process starts a thread on a copy of its table,
                    // closes its own descriptor for the ring and opens an
                    // empty ring, which takes the freed number.
                    let reading = usize::from(made).div_ceil(2);
                    let thread = process.join(format!("task/{}", FIRST + reading));
                    fs::create_dir_all(thread.join("fd")).unwrap();
                    // Start tick 0, as the fixture gives the first thread.
                    let stat = format!("{} (thread) S{} 0\n", FIRST + reading, " 0".repeat(18));
                    fs::write(thread.join("stat"), stat).unwrap();
                    fs::create_dir_all(thread.join("fdinfo")).unwrap();
                    fs::hard_link(&held, thread.join("fdinfo/5")).unwrap();
                    // The file the descriptor names, as `hold_ring` gives a
                    // table: an open descriptor always resolves.
                    fs::write(thread.join("fd/anon_inode:[io_uring]"), "").unwrap();
                    symlink("anon_inode:[io_uring]", thread.join("fd/5")).unwrap();
                    place(&leader[2 * reading], &info);
                    moves.store(made + 1, Ordering::SeqCst);
                    started.wait();
                }
                let _sent = sink.write_all(ring_info(&[]).as_bytes());
            }
        })
    };
    let checked = fixture.host.check_unused("nvme1n1").map(drop);
    let moved = moves.load(Ordering::SeqCst);
    // The check is over: every thread that waits for a read, or for the
    // other thread, is released, and the rings read without waiting.
    stop.store(true, Ordering::SeqCst);
    if moved.is_multiple_of(2) {
        place(&empty, &info);
    }
    place(&empty, &other_info);
    let _readers: Vec<_> = leader
        .iter()
        .chain(&other)
        .map(|fifo| {
            fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(fifo)
        })
        .collect();
    if !moved.is_multiple_of(2) && moved < MOVES {
        // An exec was made and no read of the other process's ring
        // followed it.
        started.wait();
    }
    starts.join().unwrap();
    execs.join().unwrap();
    assert_eq!(
        moved, MOVES,
        "premise: every exec and every start of a thread came during the check"
    );
    assert_eq!(
        fixture.host.check_unused("nvme1n1").map(drop),
        Err(IdentityError::InUse("nvme1n1".into())),
        "premise: after the last exec the ring in the process's table is found"
    );
    assert_eq!(
        checked,
        Err(IdentityError::InUse("nvme1n1".into())),
        "a namespace a ring held at every instant of the check was admitted"
    );
}

/// How one in-use check ended beside an RNBD export of `nvme1n1` or its partition `nvme1n1p2`, and where the three changes of export fell among the check's readings of the export listing.
struct ExportCheck {
    checked: Result<(), IdentityError>,
    /// A reading had returned its first entries, then the export changed to the namespace, then the reading returned more; the process walk began, and the export changed back to the partition before the listing was read again; then a reading had returned its first entries, the export changed to the namespace again, and the reading returned more.
    moved_inside: bool,
    /// Where the namespace's export lists after the last change, counted from the first entry.
    namespace_at: Option<usize>,
    /// The partition whose export the check began beside.
    partition: String,
}

/// Runs [`Host::check_unused`] on `nvme1n1` once while the RNBD server exports the namespace or one of its partitions at every instant: `nvme1n1p2`, or on a filesystem that lists entries by name the partition there named to list after the namespace.
/// The listing holds many exports of other devices, which take one reading long enough for a change, and the partition's export lists in its second half. With `moves`, the export changes three times, each new export created before the old one ends. Once the check's first reading has returned its first entries, the namespace's export is created at the front of the listing, and the partition's ends. Once the process walk has opened `proc`, the partition's export is created again, in the second half, and the namespace's ends, while the walk waits at its read of the uptime, a FIFO here. Once the next reading after that has returned its first entries, the export changes to the namespace as the first time. On the kernel the listing is ordered by name hash, so an export created during a reading lists before the reading's position whenever its hash is lower; the front of the listing stands in for that order. Without `moves` the partition's export stays.
/// Where a new entry lists depends on the filesystem that holds the fixture. Where the newest entry lists first, as on tmpfs, a new export is at the front, and the partition's is put in the second half by more entries of other devices made after it. Where entries list by their names alone, as on ext4, which orders by name hash, the partition is the one of sixteen whose name lists last after the namespace's, and only names of other devices that list after the namespace's are kept, until more than half of them list before the partition's. Otherwise the directory keeps one free entry slot, at the front of the listing, which the namespace's export takes and frees again, and the partition's export is made while the slot is taken, so it lists after the other exports.
fn check_beside_a_moving_export(moves: bool) -> ExportCheck {
    use std::io::Write;
    const OTHERS: u32 = 50_000;
    const DEVICES: &str = "sys/class/rnbd-server/ctl/devices";
    let fixture = Fixture::new(4096);
    let devices = fixture.root.join(DEVICES);
    let listed = |directory: &Path| -> Vec<String> {
        fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect()
    };
    let probed = |made: &[u32]| -> Vec<String> {
        let probe = fixture.root.join("probe");
        for entry in made {
            fs::create_dir_all(probe.join(entry.to_string())).unwrap();
        }
        let order = listed(&probe);
        fs::remove_dir_all(&probe).unwrap();
        order
    };
    let ascending: Vec<u32> = (0..8).collect();
    let descending: Vec<u32> = ascending.iter().rev().copied().collect();
    let order = probed(&ascending);
    // Two directories that make the same entries in opposite orders list them alike only where the names alone decide the order.
    let by_name = order == probed(&descending);
    let newest_first = !by_name
        && order
            == descending
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
    fs::create_dir_all(&devices).unwrap();
    let partition = if by_name {
        let candidates: Vec<String> = (1..=16).map(|number| format!("nvme1n1p{number}")).collect();
        for name in candidates.iter().map(String::as_str).chain(["nvme1n1"]) {
            fs::create_dir(devices.join(name)).unwrap();
        }
        let order = listed(&devices);
        for name in &order {
            fs::remove_dir(devices.join(name)).unwrap();
        }
        let last = order.last().unwrap().clone();
        assert_ne!(
            last, "nvme1n1",
            "premise: the export of a partition lists after the namespace's"
        );
        last
    } else {
        "nvme1n1p2".to_owned()
    };
    fixture.partition("nvme1n1", &partition);
    let export = |device: &str| {
        let session = devices.join(device).join("sessions/client1");
        fs::create_dir_all(&session).unwrap();
        fs::write(session.join("mapping_path"), "volume\n").unwrap();
    };
    let others = AtomicU32::new(0);
    let other = || {
        let other = others.fetch_add(1, Ordering::Relaxed);
        fs::create_dir_all(devices.join(format!("nvme0n{other}"))).unwrap();
    };
    // The export of `to` begins before the export of `from` ends. The export of the partition, made `back`, lists in the second half.
    let change = |from: &str, to: &str, back: bool| {
        export(to);
        if back && newest_first {
            (0..OTHERS / 2 + 1).for_each(|_| other());
        }
        fs::remove_dir_all(devices.join(from)).unwrap();
    };
    let first_listed = |devices: &Path| -> Option<String> {
        let entry = fs::read_dir(devices).unwrap().next()?.unwrap();
        Some(entry.file_name().into_string().unwrap())
    };
    if newest_first {
        export(&partition);
        (0..OTHERS).for_each(|_| other());
    } else if by_name {
        // A stand-in for the namespace's export lists where its export will; other devices' exports are made, and those that list before the stand-in removed, until more than half of `OTHERS` list between it and the partition's.
        export(&partition);
        fs::create_dir(devices.join("nvme1n1")).unwrap();
        loop {
            let order = listed(&devices);
            let at = |device: &str| order.iter().position(|name| name == device).unwrap();
            let namespace = at("nvme1n1");
            for name in &order[..namespace] {
                fs::remove_dir(devices.join(name)).unwrap();
            }
            if at(&partition) - namespace > OTHERS as usize / 2 + 1 {
                break;
            }
            assert!(
                others.load(Ordering::Relaxed) < 16 * OTHERS,
                "premise: more than half of {OTHERS} names list between the namespace's and the partition's"
            );
            (0..OTHERS / 2).for_each(|_| other());
        }
        fs::remove_dir(devices.join("nvme1n1")).unwrap();
    } else {
        (0..OTHERS).for_each(|_| other());
        export(&partition);
        // Leave one free entry slot, at the front of the listing, by freeing the first-listed export and then filling every later slot: each filler of the same entry size takes a later free slot first, and the first that lists first took the front one and is removed again.
        let first = first_listed(&devices).unwrap();
        assert!(
            first.starts_with("nvme0n"),
            "premise: the export of another device lists first, not {first}"
        );
        fs::remove_dir(devices.join(first)).unwrap();
        for filler in 0.. {
            assert!(filler < 10_000, "premise: a filler took the front slot");
            let name = format!("nvme2n{filler}");
            fs::create_dir(devices.join(&name)).unwrap();
            if first_listed(&devices).as_ref() == Some(&name) {
                fs::remove_dir(devices.join(&name)).unwrap();
                break;
            }
        }
    }
    let late = |device: &str| {
        listed(&devices).iter().position(|name| name == device) > Some(OTHERS as usize / 2)
    };
    assert!(
        late(&partition),
        "premise: the partition's export lists in the second half"
    );
    // The first two changes, made once before the check, leave the listing as it began: the partition's export in the second half and, where entries take free slots, the front slot free.
    change(&partition, "nvme1n1", false);
    assert_eq!(
        first_listed(&devices).as_deref(),
        Some("nvme1n1"),
        "premise: a new export of the namespace lists first"
    );
    change("nvme1n1", &partition, true);
    assert!(
        late(&partition),
        "premise: the partition's export lists in the second half after it changes back"
    );
    let marks = fixture.root.join("marks");
    fs::create_dir_all(&marks).unwrap();
    let ended = fixture.root.join("ended");
    fs::create_dir_all(&ended).unwrap();
    // The walk reads the uptime once, after it opened `proc` and before it reads any descriptor table; a FIFO here holds the check there until the change back has been made.
    let uptime = fixture.host.proc.join("uptime");
    make_fifo(&uptime);

    // SAFETY: the call takes no pointer.
    let watch = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
    assert!(watch >= 0);
    let add = |path: &Path, mask: u32| {
        let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `path` is a NUL-terminated string that outlives the call.
        let wd = unsafe { libc::inotify_add_watch(watch, path.as_ptr(), mask) };
        assert!(wd >= 0);
        wd
    };
    // Each `getdents` call on the listing queues one access of the directory itself.
    let read_some = (add(&devices, libc::IN_ACCESS), true);
    // The process walk opens `proc` itself; the check reads the export listing once more only after the walk.
    let walked = (add(&fixture.root.join("proc"), libc::IN_OPEN), true);
    let moved = (add(&marks, libc::IN_CREATE), false);
    // An entry here ends the mover's wait when the check returned before the event it waits for.
    let stopped = (add(&ended, libc::IN_CREATE), false);

    let mut seen = Vec::new();
    let checked = thread::scope(|scope| {
        let mover = scope.spawn(|| {
            let mut seen = Vec::new();
            let mut read = 0;
            // For the change `back`, once the awaited event came, the mover opens the uptime, which waits until the walk opens it, and writes it only after the change.
            let steps = [
                (read_some, false, partition.as_str(), "nvme1n1"),
                (walked, true, "nvme1n1", partition.as_str()),
                (read_some, false, partition.as_str(), "nvme1n1"),
            ];
            for (step, (awaited, back, from, to)) in steps.into_iter().enumerate() {
                // Only an event queued after the last step's wait ended counts for this one.
                loop {
                    if let Some(at) = seen[read..].iter().position(|&event| event == awaited) {
                        read += at + 1;
                        break;
                    }
                    if seen[read..].contains(&stopped) {
                        return seen;
                    }
                    read = seen.len();
                    seen.extend(queued_watch_events(watch));
                }
                let held = back.then(|| OpenOptions::new().write(true).open(&uptime).unwrap());
                if moves {
                    change(from, to, back);
                }
                fs::write(marks.join(step.to_string()), "").unwrap();
                if let Some(mut held) = held {
                    let _sent = held.write_all(b"100.00 400.00\n");
                }
            }
            seen
        });
        let checked = fixture.host.check_unused("nvme1n1").map(drop);
        fs::write(ended.join("check"), "").unwrap();
        // A check that never read the uptime releases the mover's wait for it here.
        let _reader = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&uptime)
            .unwrap();
        seen = mover.join().unwrap();
        checked
    });
    // SAFETY: `watch` is an open descriptor this function owns; the calls take no pointer.
    unsafe {
        let flags = libc::fcntl(watch, libc::F_GETFL);
        assert_eq!(
            libc::fcntl(watch, libc::F_SETFL, flags | libc::O_NONBLOCK),
            0
        );
    }
    loop {
        let more = queued_watch_events(watch);
        if more.is_empty() {
            break;
        }
        seen.extend(more);
    }
    // SAFETY: `watch` is open and closed once.
    unsafe { libc::close(watch) };
    let marks: Vec<usize> = (0..seen.len()).filter(|&at| seen[at] == moved).collect();
    let moved_inside = match marks.as_slice() {
        &[first, back, last] => {
            let walk = seen[first..back].iter().position(|&event| event == walked);
            seen[..first].contains(&read_some)
                && walk.is_some_and(|walk| {
                    seen[first..first + walk].contains(&read_some)
                        && !seen[first + walk..back].contains(&read_some)
                })
                && seen[back..last].contains(&read_some)
                && seen[last..].contains(&read_some)
        }
        _ => false,
    };
    ExportCheck {
        checked,
        moved_inside,
        namespace_at: listed(&devices).iter().position(|name| name == "nvme1n1"),
        partition,
    }
}

/// [`Host::check_unused`] refuses a namespace "exported ... by the RNBD server", and a namespace with an exported partition. It reads the export listing before the process walk and after it. An export of the partition that is replaced by an export of the whole namespace during the reading before the walk, replaced by one of the partition during the walk, and replaced by one of the namespace again during the reading after it, each new export created before the old one ends, exports the namespace's blocks at every instant, so the check refuses it wherever its readings of the export listing fall.
#[test]
fn an_rnbd_export_that_moves_from_a_partition_to_the_namespace_during_the_check_is_in_use() {
    let check = (0..5)
        .map(|_| check_beside_a_moving_export(true))
        .find(|check| check.moved_inside && check.namespace_at.is_some_and(|at| at < 100))
        .expect("premise: in five tries each change to the namespace fell inside a reading, the namespace's export before its position, and the change back fell between the walk's start and the next reading");
    assert_eq!(
        check.checked,
        Err(IdentityError::InUse("nvme1n1".to_owned())),
        "the check admitted a namespace the RNBD server exported throughout"
    );
}

/// The sibling of [`an_rnbd_export_that_moves_from_a_partition_to_the_namespace_during_the_check_is_in_use`] with the partition's export left in place: the same listing and the same readings refuse the partition.
#[test]
fn an_rnbd_export_of_a_partition_that_stays_during_the_check_is_in_use() {
    let check = (0..5)
        .map(|_| check_beside_a_moving_export(false))
        .find(|check| check.moved_inside)
        .expect("premise: in five tries the marks fell where the changes fall");
    assert_eq!(check.checked, Err(IdentityError::InUse(check.partition)),);
}

/// A serial is padded with spaces alone, so a serial field that holds a tab
/// or a no-break space beside `vol0123abcd` states another serial, and
/// resolving `vol-0123abcd` answers `NotFound`. Each case first resolves the
/// controller under its well-formed serial, so the serial field alone
/// decides the refusal. Every case is resolved, and the cases that answer
/// anything else are reported together.
#[test]
fn a_serial_that_is_the_volume_id_only_after_a_tab_or_no_break_space_is_removed_is_not_found() {
    // A short volume ID, so its serial and the added character fit within
    // the field's 20 bytes.
    let volume = "vol-0123abcd";
    let resolved: Vec<_> = [
        "\tvol0123abcd        \n",
        "vol0123abcd\t        \n",
        "vol0123abcd\u{a0}      \n",
    ]
    .into_iter()
    .filter_map(|serial| {
        let fixture = Fixture::new(4096);
        fixture.controller("nvme2", "0000:00:1e.0", "vol0123abcd", 4096);
        assert!(fixture.host.resolve(volume).is_ok());
        fixture.file("sys/class/nvme/nvme2/serial", serial);
        let found = fixture.host.resolve(volume).map(|found| found.bdf);
        (found != Err(IdentityError::NotFound)).then_some((serial, found))
    })
    .collect();
    assert_eq!(
        resolved,
        [],
        "no controller's serial is the volume ID, so each resolution answers NotFound"
    );
}

/// A model is padded with spaces alone, so a model field that holds a tab
/// before the EBS model, after it or after its padding, or a no-break space
/// after it, states another model, and resolving the controller's volume
/// answers `NotEbs`. Each case first resolves the controller under the EBS
/// model, so the model field alone decides the refusal. Every case is
/// resolved, and the cases that answer anything else are reported together.
#[test]
fn a_model_that_is_the_ebs_model_only_after_a_tab_or_no_break_space_is_removed_is_not_ebs() {
    let volume = "vol-0123abcd";
    let ebs = ControllerIdentity::EBS.model;
    let mut accepted = Vec::new();
    for model in [
        format!("\t{ebs}             \n"),
        format!("{ebs}\t             \n"),
        format!("{ebs}             \t\n"),
        format!("{ebs}\u{a0}            \n"),
    ] {
        let fixture = Fixture::new(4096);
        fixture.controller("nvme2", "0000:00:1e.0", "vol0123abcd", 4096);
        assert!(fixture.host.resolve(volume).is_ok());
        fixture.file("sys/class/nvme/nvme2/model", &model);
        let answer = fixture.host.resolve(volume).map(|found| found.bdf);
        if answer != Err(IdentityError::NotEbs) {
            accepted.push((model, answer));
        }
    }
    assert_eq!(accepted, [], "models resolved as an EBS volume's");
}

/// The target of the kernel's own class link `sys/class/rnbd-server/ctl`.
const OWN: &str = "../../devices/virtual/rnbd-server/ctl";

/// The target of the link a mount at `sys/class/rnbd-server` shows as `ctl`: the directory of
/// another class, as `mount --bind /sys/class/rnbd-client /sys/class/rnbd-server` shows it.
const OTHER: &str = "../../devices/virtual/rnbd-client/ctl";

/// The target of the link a mount at `sys/devices/virtual/rnbd-server` shows as `ctl`.
const BESIDE: &str = "../rnbd-client/ctl";

/// The path the binder reads the export listing by, and the same listing named by its
/// directory under `sys/devices`.
const BY_CLASS: &str = "class/rnbd-server/ctl/devices";
const BY_DEVICE: &str = "devices/virtual/rnbd-server/ctl/devices";

/// A fixture host with the directory `sys/devices/virtual/rnbd-client/ctl`, which no mount
/// covers, whose `sys/class/rnbd-server/ctl` is the link `class` when one is given, whose
/// `sys/devices/virtual/rnbd-server/ctl` is the link `device` when one is given and else the
/// directory of a server that exports nvme1n1, and whose mount table ends with `mounted`.
fn host(class: Option<&str>, device: Option<&str>, mounted: &str) -> Fixture {
    let fixture = Fixture::new(4096);
    fs::create_dir_all(fixture.root.join("sys/devices/virtual/rnbd-client/ctl")).unwrap();
    fs::create_dir_all(fixture.root.join("sys/devices/virtual/rnbd-server")).unwrap();
    fs::create_dir_all(fixture.root.join("sys/class/rnbd-server")).unwrap();
    match device {
        Some(device) => {
            symlink(
                device,
                fixture.root.join("sys/devices/virtual/rnbd-server/ctl"),
            )
            .unwrap();
        }
        None => fixture.file(
            "sys/devices/virtual/rnbd-server/ctl/devices/nvme1n1/sessions/client1/mapping_path",
            "volume\n",
        ),
    }
    if let Some(class) = class {
        symlink(class, fixture.root.join("sys/class/rnbd-server/ctl")).unwrap();
    }
    fixture.file(
        "proc/self/mounts",
        &format!("/dev/nvme0n1p1 / xfs rw 0 0\nsysfs /sys sysfs rw 0 0\n{mounted}"),
    );
    fixture
}

/// Whether `Host::shown` refuses `listing`, a path below `sys`, as unreadable: with an error of
/// a kind other than `NotFound`.
fn refused(fixture: &Fixture, listing: &str) -> bool {
    let entry = fixture.host.sys.join(listing);
    let mounts = fixture.host.mount_table().unwrap();
    matches!(fixture.host.shown(&mounts, &entry), Err(error) if error.kind() != io::ErrorKind::NotFound)
}

/// A link is an entry of the directory that holds it, so a link inside a
/// mount is the mount's entry, and what it leads to is no evidence about the
/// kernel, also when its target lies in a part of `sys` that no mount
/// covers: `Host::shown` refuses a path that reaches such a link as
/// unreadable. The kernel resolves a path one name at a time and walks a
/// link's target the same way, so a path reaches a mount's link in three
/// ways, and each is scripted with a mount of type `sysfs`, which a bind
/// mount of a sysfs subtree keeps, and of type `tmpfs`:
///
/// - `class`: the mount is at `sys/class/rnbd-server`, and the path names
///   the link `ctl` there;
/// - `named`: the mount is at `sys/devices/virtual/rnbd-server`, and the
///   path names the link `ctl` there by the directory's own name;
/// - `behind`: the same mount, and the path comes to that link through the
///   kernel's own class link `sys/class/rnbd-server/ctl`, whose target
///   passes through the mounted directory.
///
/// Every assertion is on `Host::shown`, which reads the fixture's tree and
/// mount table alone, so the result does not depend on the user namespace
/// or the capabilities of the process that runs the test.
#[test]
fn an_entry_behind_a_link_that_a_mount_shows_is_refused_as_unreadable() {
    assert!(
        !refused(&host(Some(OWN), None, ""), BY_CLASS),
        "premise: with no mount the listing behind the class link is the kernel's own"
    );
    assert!(
        !refused(&host(Some(OWN), Some(BESIDE), ""), BY_CLASS),
        "premise: with no mount a listing behind two links is the kernel's own"
    );
    assert!(
        !refused(
            &host(Some(OWN), None, "tmpfs /sys/fs/cgroup tmpfs rw 0 0\n"),
            BY_CLASS
        ),
        "premise: a mount beside the path covers no name of it"
    );
    let mut accepted = Vec::new();
    for kind in ["sysfs", "tmpfs"] {
        let over_class = format!("{kind} /sys/class/rnbd-server {kind} rw 0 0\n");
        let over_device = format!("{kind} /sys/devices/virtual/rnbd-server {kind} rw 0 0\n");
        assert!(
            refused(&host(None, None, &over_class), BY_CLASS),
            "premise: a mount at the class directory that shows no link is refused: {kind}"
        );
        if !refused(&host(Some(OTHER), None, &over_class), BY_CLASS) {
            accepted.push(("class", kind));
        }
        if !refused(&host(Some(OWN), Some(BESIDE), &over_device), BY_DEVICE) {
            accepted.push(("named", kind));
        }
        if !refused(&host(Some(OWN), Some(BESIDE), &over_device), BY_CLASS) {
            accepted.push(("behind", kind));
        }
    }
    assert!(
        accepted.is_empty(),
        "the listing behind a link that a mount shows was returned as the kernel's own: {accepted:?}"
    );
}

#[test]
fn a_parent_step_keeps_the_cover_of_the_directory_it_leaves() {
    let fixture = Fixture::new(4096);
    fixture.file("sys/example/visited/deep/value", "1\n");
    fixture.file("sys/example/result", "2\n");
    let entry = "example/visited/deep/../../result";
    let cover = "tmpfs /\\163ys/example/visited tmpfs rw 0 0\r\n";
    let own = "sysfs /sys sysfs rw 0 0\n";

    for (table, expected) in [
        (format!("{own}{cover}"), true),
        (format!("{cover}{own}"), false),
    ] {
        fixture.file("proc/self/mounts", &table);
        assert_eq!(refused(&fixture, entry), expected, "{table:?}");
        assert!(!refused(&fixture, "example/result"));
    }
}
