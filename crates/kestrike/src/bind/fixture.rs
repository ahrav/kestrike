//! A scratch host tree shaped like the kernel's sysfs, procfs and device
//! directories, and a [`Kernel`] that acts on it as the PCI core would.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::ffi::CString;
use std::fs::{self, File};
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use super::group::VIABLE;
use super::host::{Fed, Host, Kernel, Started};
use super::lock::{DEVICE_LOCKS, DeviceLock};
use super::metadata::Metadata;
use super::replay_control;
use super::wc::{WcManifest, WcModule, sha256};

pub(super) const VOLUME: &str = "vol-0123456789abcdef0";
pub(super) const BDF: &str = "0000:00:1f.0";
pub(super) const INSTANCE: &str = "i-0123456789abcdef0";
pub(super) const BOOT: &str = "6f2a9a1c-0000-4000-8000-000000000001";
/// The `status` line of a process that holds every capability of Linux
/// 6.12, `CAP_SYS_PTRACE` among them, in its effective set.
pub(super) const TRACER: &str = "CapEff:\t000001ffffffffff\n";
/// The `ns/user` link of a process in the initial user namespace, where the
/// tests run: the running process's own.
pub(super) const INITIAL_USERNS: &str = "/proc/self/ns/user";
pub(super) const ENI: &str = "eni-0123456789abcdef0";
pub(super) const ENI_BDF: &str = "0000:00:06.0";
pub(super) const ENI_MAC: &str = "0a:11:22:33:44:55";
pub(super) const ENI_NETDEV: &str = "ens6";
/// The word a restoring command names the fixture ENI by: `if` and the
/// interface index [`Fixture::netdev`] gives [`ENI_BDF`].
const ENI_IF: &str = "if6";
/// A `proc/net/rt6_stats` the fixture's tables hold still under, in the kernel's format.
pub(super) const RT6_STATS: &str = "0001 0001 0000 0001 0000 0000 0000\n";
/// The two header lines of `proc/net/dev`, in the kernel's format.
pub(super) const NET_DEV_HEADER: &str = "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n";

/// The `proc/net/dev` line of device `name` with every counter zero, in the kernel's format.
pub(super) fn net_dev_line(name: &str) -> String {
    format!("{name:>6}:{}\n", "       0".repeat(16))
}

/// Renames device `from` to `to` in the `proc/net/dev` listing at `listing`, as a rename does in the kernel.
pub(super) fn rename_listed(listing: &Path, from: &str, to: &str) {
    let text = fs::read_to_string(listing).unwrap();
    let renamed = text.replace(&net_dev_line(from), &net_dev_line(to));
    assert_ne!(renamed, text, "premise: the listing names {from}");
    fs::write(listing, renamed).unwrap();
}

pub(super) const RELEASE: &str = "6.1.0-wc";
pub(super) const SRCVERSION: &str = "4C1D2E3F4A5B6C7D8E9F0A1";
const MODULE: &str = "/lib/modules/6.1.0-wc/extra/vfio-pci.ko";
/// The approved kernel configuration's VFIO lines: the classic group and
/// container interface and both backends, with iommufd and the device cdev
/// unset.
pub(super) const CONFIG: &str = "CONFIG_VFIO=y\nCONFIG_VFIO_GROUP=y\nCONFIG_VFIO_CONTAINER=y\nCONFIG_VFIO_IOMMU_TYPE1=m\nCONFIG_VFIO_NOIOMMU=y\n# CONFIG_IOMMUFD is not set\nCONFIG_VFIO_PCI=m\n";
/// The character device every fixture VFIO group node links to, and the
/// device number sysfs reports for it.
const GROUP_NODE: &str = "/dev/null";
const GROUP_DEV: &str = "1:3";

pub(super) struct Fixture {
    pub(super) root: PathBuf,
    pub(super) host: Host,
    live: Option<Live>,
}

/// Fixtures and lock-holding tests alive now. A child process shares the
/// parent's open file descriptions until it executes, so a lock file a test
/// opened stays locked by that child and the test's next lock of the file
/// would refuse; a test spawns a child only through [`spawn_quiet`], which
/// waits until none lives, and holds no fixture or lock while it calls it.
/// A fixture made [`unlisted`](Fixture::unlisted) holds only paths and no
/// open descriptor, and stays outside this count, so its test may spawn
/// while it holds it.
static LIVE: (Mutex<u32>, Condvar) = (Mutex::new(0), Condvar::new());

/// A fixture's or a lock-holding test's membership in [`LIVE`].
pub(super) struct Live;

impl Live {
    pub(super) fn enter() -> Self {
        *LIVE.0.lock().unwrap_or_else(PoisonError::into_inner) += 1;
        Self
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        *LIVE.0.lock().unwrap_or_else(PoisonError::into_inner) -= 1;
        LIVE.1.notify_all();
    }
}

/// Holds off new fixtures, once none lives, for the guard's life.
pub(crate) fn spawn_quiet() -> MutexGuard<'static, u32> {
    let live = LIVE.0.lock().unwrap_or_else(PoisonError::into_inner);
    LIVE.1
        .wait_while(live, |live| *live > 0)
        .unwrap_or_else(PoisonError::into_inner)
}

impl Fixture {
    /// An instance with the volume's controller `nvme1` at [`BDF`] on `nvme`,
    /// one namespace of `sector`-byte sectors, beside the boot volume `nvme0`,
    /// `vfio-pci` loaded and VFIO in no-IOMMU mode.
    pub(super) fn new(sector: u32) -> Self {
        Self::under(&std::env::temp_dir(), sector)
    }

    /// [`new`](Self::new) with the fixture's tree under `base`, for a test
    /// whose premise depends on the filesystem that holds the tree.
    pub(super) fn under(base: &Path, sector: u32) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let root = base.join(format!(
            "bind-fixture-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        let host = host_at(&root);
        let fixture = Self {
            root,
            host,
            live: Some(Live::enter()),
        };
        for dir in [
            "sys/class/iommu",
            "sys/bus/pci/drivers/nvme",
            "sys/bus/pci/drivers/ena",
            "sys/bus/pci/drivers/vfio-pci",
            "dev/vfio",
            "proc/self",
            "run",
            "proc/sys/kernel/random",
        ] {
            fs::create_dir_all(fixture.root.join(dir)).unwrap();
        }
        fixture.file(
            "sys/module/vfio/parameters/enable_unsafe_noiommu_mode",
            "Y\n",
        );
        fixture.file(
            "sys/devices/virtual/dmi/id/board_asset_tag",
            &format!("{INSTANCE}\n"),
        );
        fixture.file("proc/sys/kernel/random/boot_id", &format!("{BOOT}\n"));
        fixture.file("proc/self/mounts", "/dev/nvme0n1p1 / xfs rw 0 0\n");
        fixture.file("proc/filesystems", "nodev\tsysfs\nnodev\tproc\n\txfs\n");
        fs::create_dir_all(fixture.host.proc.join("self/ns")).unwrap();
        symlink(INITIAL_USERNS, fixture.host.proc.join("self/ns/user")).unwrap();
        fixture.file("proc/swaps", "Filename Type Size Used Priority\n");
        fixture.file("proc/uptime", "100.00 400.00\n");
        fixture.file("proc/self/status", &format!("Name:\ttest\n{TRACER}"));
        fixture.file("sys/kernel/uevent_seqnum", "7065\n");
        // procfs links `thread-self` to the calling thread's directory; a
        // fixture process has one thread, whose status is the process's.
        symlink("self", fixture.host.proc.join("thread-self")).unwrap();
        fixture.file("proc/kallsyms", "ffffffff81000000 T _stext\n");
        fixture.file("proc/net/rt6_stats", RT6_STATS);
        fixture.file("proc/sys/net/ipv6/conf/default/disable_ipv6", "0\n");
        fixture.file("proc/net/dev", NET_DEV_HEADER);
        fixture.controller("nvme0", "0000:00:04.0", "vol0aaaaaaaaaaaaaaaaa", sector);
        fixture.partition("nvme0n1", "nvme0n1p1");
        fixture.controller("nvme1", BDF, "vol0123456789abcdef0", sector);
        fixture.file("proc/sys/kernel/osrelease", &format!("{RELEASE}\n"));
        fixture.file(&format!("boot/config-{RELEASE}"), CONFIG);
        fixture.file(
            &MODULE[1..],
            &format!("\x7fELF write-combining vfio-pci\0srcversion={SRCVERSION}\0depends=vfio\0"),
        );
        fixture.file("sys/module/vfio_pci/srcversion", &format!("{SRCVERSION}\n"));
        fixture.file("sys/module/vfio_pci/initstate", "live\n");
        fixture.netdev("ens5", "0000:00:05.0", "0a:00:00:00:00:01", 0x1003);
        fixture.netdev(ENI_NETDEV, ENI_BDF, ENI_MAC, 0x1003);
        fixture.file(
            &format!("neigh/{ENI_NETDEV}"),
            &format!(
                "{}{}",
                neighbor_entry("10.0.1.9", Some("0a:00:00:00:01:09"), "REACHABLE"),
                neighbor_entry("10.0.1.1", Some("0a:00:00:00:01:01"), "REACHABLE")
            ),
        );
        fixture.file(
            "proc/net/route",
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\nens5\t00000000\t0100000A\t0003\t0\t0\t0\t00000000\t0\t0\t0\nens6\t0001000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n",
        );
        fixture
    }

    /// Adds `line` to the neighbor entries of `netdev`, as `ip neigh` prints them.
    pub(super) fn neighbor(&self, netdev: &str, line: &str) {
        let path = self.root.join("neigh").join(netdev);
        let table = fs::read_to_string(&path).unwrap_or_default();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, format!("{table}{line}")).unwrap();
    }

    /// A network device `name` of function `bdf` on `ena` with an ENA PCI
    /// ID, MAC `mac` and interface flags `flags`. Its interface index is the
    /// function's PCI device number, so `0000:00:06.0` is `if6`.
    pub(super) fn netdev(&self, name: &str, bdf: &str, mac: &str, flags: u32) {
        let slot = bdf
            .rsplit(':')
            .next()
            .and_then(|slot| slot.split('.').next());
        let index = u32::from_str_radix(slot.expect("a PCI address"), 16).unwrap();
        self.file(
            &format!("sys/class/net/{name}/ifindex"),
            &format!("{index}\n"),
        );
        let pci = self.host.pci(bdf);
        self.file(&format!("sys/bus/pci/devices/{bdf}/vendor"), "0x1d0f\n");
        self.file(&format!("sys/bus/pci/devices/{bdf}/device"), "0xec20\n");
        self.file(
            &format!("sys/bus/pci/devices/{bdf}/driver_override"),
            "(null)\n",
        );
        self.group(bdf);
        symlink(
            self.host.sys.join("bus/pci/drivers/ena"),
            pci.join("driver"),
        )
        .unwrap();
        let net = format!("sys/class/net/{name}");
        self.file(&format!("{net}/address"), &format!("{mac}\n"));
        self.file(&format!("{net}/flags"), &format!("0x{flags:x}\n"));
        self.file(&format!("{net}/mtu"), "9001\n");
        self.file(&format!("{net}/addr_assign_type"), "0\n");
        symlink(&pci, self.root.join(&net).join("device")).unwrap();
        self.live_netdev(name);
    }

    /// Adds `name` to `proc/net/dev`, the kernel's listing of devices by their current names.
    pub(super) fn live_netdev(&self, name: &str) {
        let path = self.host.proc.join("net/dev");
        let listing = fs::read_to_string(&path).unwrap_or_else(|_| NET_DEV_HEADER.to_owned());
        fs::write(path, format!("{listing}{}", net_dev_line(name))).unwrap();
    }

    /// The manifest approving the kernel and module of the fixture host `host`.
    pub(super) fn manifest_of(host: &Host) -> WcManifest {
        let digest = |relative: &str| sha256(&fs::read(host.root.join(relative)).unwrap());
        WcManifest {
            kernel: RELEASE.to_owned(),
            config_sha256: digest(&format!("boot/config-{RELEASE}")),
            patch: "wc-1".to_owned(),
            modules: vec![WcModule {
                name: "vfio_pci".to_owned(),
                file: MODULE.into(),
                sha256: digest(&MODULE[1..]),
                srcversion: SRCVERSION.to_owned(),
            }],
        }
    }

    /// Places `bdf` alone in IOMMU group [`group_of`]`(bdf)`, linked as sysfs links it.
    pub(super) fn group(&self, bdf: &str) {
        let group = self
            .host
            .sys
            .join(format!("kernel/iommu_groups/{}", group_of(bdf)));
        fs::create_dir_all(group.join("devices")).unwrap();
        fs::write(group.join("devices").join(bdf), "").unwrap();
        symlink(&group, self.host.pci(bdf).join("iommu_group")).unwrap();
    }

    pub(super) fn file(&self, relative: &str, text: &str) {
        let path = self.root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    /// Loop device `name` configured over the file at absolute host path
    /// `backing`: its `backing_file` names `backing`, and its node is a hard
    /// link of that file, which stands in for the kernel's record of the
    /// backing file.
    pub(super) fn loop_device(&self, name: &str, backing: &str) {
        self.file(
            &format!("sys/block/{name}/loop/backing_file"),
            &format!("{backing}\n"),
        );
        fs::hard_link(
            self.host.under_root(Path::new(backing)),
            self.host.dev.join(name),
        )
        .unwrap();
    }

    /// An NVMe controller with its node, one namespace `<name>n1` and its PCI device on `nvme`.
    pub(super) fn controller(&self, name: &str, bdf: &str, serial: &str, sector: u32) {
        let pci = self.host.pci(bdf);
        self.file(&format!("sys/bus/pci/devices/{bdf}/vendor"), "0x1d0f\n");
        self.file(&format!("sys/bus/pci/devices/{bdf}/device"), "0x8061\n");
        self.file(
            &format!("sys/bus/pci/devices/{bdf}/driver_override"),
            "(null)\n",
        );
        self.group(bdf);
        symlink(
            self.host.sys.join("bus/pci/drivers/nvme"),
            pci.join("driver"),
        )
        .unwrap();
        let class = self.host.sys.join("class/nvme").join(name);
        self.file(
            &format!("sys/class/nvme/{name}/serial"),
            &format!("{serial:<20}\n"),
        );
        self.file(
            &format!("sys/class/nvme/{name}/model"),
            "Amazon Elastic Block Store              \n",
        );
        symlink(&pci, class.join("device")).unwrap();
        // The controller's character device number, as sysfs states it.
        self.file(&format!("sys/class/nvme/{name}/dev"), "241:0\n");
        let ns = format!("sys/class/nvme/{name}/{name}n1");
        self.file(&format!("{ns}/nsid"), "1\n");
        self.file(&format!("{ns}/size"), &format!("{}\n", (64u64 << 30) / 512));
        self.file(
            &format!("{ns}/queue/logical_block_size"),
            &format!("{sector}\n"),
        );
        fs::create_dir_all(
            self.host
                .sys
                .join("block")
                .join(format!("{name}n1/holders")),
        )
        .unwrap();
        let node = self.host.dev.join(format!("{name}n1"));
        fs::write(&node, "").unwrap();
        fs::write(self.host.dev.join(name), "").unwrap();
        self.number(&format!("{name}n1"), &node);
    }

    /// Plants the filesystem device of regular file `node` as the sysfs
    /// device number of block device `name`, the identity the fixture host's
    /// claim compares a regular-file node against.
    fn number(&self, name: &str, node: &Path) {
        let device = fs::metadata(node).unwrap().dev();
        self.file(
            &format!("sys/class/block/{name}/dev"),
            &format!("{}:{}\n", libc::major(device), libc::minor(device)),
        );
    }

    pub(super) fn partition(&self, namespace: &str, partition: &str) {
        fs::create_dir_all(
            self.host
                .sys
                .join("block")
                .join(namespace)
                .join(partition)
                .join("holders"),
        )
        .unwrap();
        fs::write(self.host.dev.join(partition), "").unwrap();
    }

    /// A VFIO group file the kernel refuses to open, as it does while a
    /// process holds the group or one of its devices; a directory stands in,
    /// which [`FakeKernel::open_group`] refuses with `EBUSY`.
    pub(super) fn hold(&self, group_file: &Path) {
        let _ = fs::remove_file(group_file);
        fs::create_dir_all(group_file).unwrap();
    }

    /// Ends [`hold`](Self::hold): the group file is the group's character device again.
    pub(super) fn unhold(&self, group_file: &Path) {
        fs::remove_dir(group_file).unwrap();
        symlink(GROUP_NODE, group_file).unwrap();
    }

    /// A process `pid` whose leader shows a start tick, so a listing of the
    /// process table can tell it from another process under its ID. A
    /// leader with no start recorded yet gets start tick 0.
    pub(super) fn process(&self, pid: u32) {
        if fs::symlink_metadata(self.root.join(format!("proc/{pid}/task/{pid}/stat"))).is_err() {
            self.thread_started(pid, pid, 0);
        }
    }

    /// A process `pid` holding a descriptor open on `target`.
    pub(super) fn open(&self, pid: u32, target: &Path) {
        self.process(pid);
        Self::hold_in(&self.root.join(format!("proc/{pid}/fd")), target);
    }

    /// Thread `tid` of process `pid` holding a descriptor open on `target` in
    /// its own table, as after `unshare(CLONE_FILES)`. The process's `task`
    /// directory lists its leader too, as procfs does. A thread with no start
    /// recorded yet gets start tick 0.
    pub(super) fn open_on_thread(&self, pid: u32, tid: u32, target: &Path) {
        self.process(pid);
        fs::create_dir_all(self.root.join(format!("proc/{pid}/task/{pid}/fd"))).unwrap();
        Self::hold_in(&self.root.join(format!("proc/{pid}/task/{tid}/fd")), target);
        if fs::symlink_metadata(self.root.join(format!("proc/{pid}/task/{tid}/stat"))).is_err() {
            self.thread_started(pid, tid, 0);
        }
    }

    /// Records that thread `tid` of process `pid` started `ticks` clock ticks
    /// after boot, in the thread's procfs `stat` entry.
    pub(super) fn thread_started(&self, pid: u32, tid: u32, ticks: u64) {
        let fields = " 0".repeat(18);
        self.file(
            &format!("proc/{pid}/task/{tid}/stat"),
            &format!("{tid} (thread) S{fields} {ticks}\n"),
        );
    }

    /// Adds a descriptor open on `target`, created empty when absent, to the table at `fd`.
    fn hold_in(fd: &Path, target: &Path) {
        if fs::symlink_metadata(target).is_err() {
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::write(target, "").unwrap();
        }
        fs::create_dir_all(fd).unwrap();
        let held = fs::read_dir(fd).unwrap().count();
        symlink(target, fd.join((3 + held).to_string())).unwrap();
    }

    /// Leaves [`LIVE`], so a test that holds this fixture can spawn a child
    /// process: the fixture holds files alone, and the test opens no lock
    /// while it spawns.
    pub(super) fn unlisted(mut self) -> Self {
        self.live = None;
        self
    }

    pub(super) fn state_dir(&self) -> PathBuf {
        self.root.join("run")
    }

    pub(super) fn device_locks(&self) -> PathBuf {
        self.host.under_root(Path::new(DEVICE_LOCKS))
    }

    pub(super) fn lock_device(&self, bdf: &str) -> DeviceLock {
        DeviceLock::acquire(&self.device_locks(), bdf).unwrap()
    }
}

/// The fixture host whose tree lies under `root`, as [`Fixture::new`] lays
/// it out.
pub(super) fn host_at(root: &Path) -> Host {
    Host {
        root: root.to_owned(),
        sys: root.join("sys"),
        proc: root.join("proc"),
        dev: root.join("dev"),
        file_nodes: true,
        ..Host::system()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Clone, Copy)]
pub(super) enum Slots {
    Every,
    Filled,
}

/// The `fdinfo` text Linux 6.12 prints for a ring whose registered-file
/// table holds `files`, one slot each, between the fields that precede and
/// follow the table.
pub(super) fn ring_info(files: &[&str]) -> String {
    ring_info_listing(Slots::Every, files)
}

/// The `fdinfo` text of a ring whose registered-file table holds `files`,
/// one slot each, where `<none>` is an empty slot.
pub(super) fn ring_info_listing(slots: Slots, files: &[&str]) -> String {
    let lines: String = files
        .iter()
        .enumerate()
        .filter(|(_, file)| matches!(slots, Slots::Every) || **file != "<none>")
        .map(|(slot, file)| format!("{slot:5}: {file}\n"))
        .collect();
    format!(
        "pos:\t0\nflags:\t02000002\nmnt_id:\t17\nino:\t1057\nSqThreadCpu:\t-1\nUserFiles:\t{}\n{lines}UserBufs:\t0\nPollList:\n",
        files.len()
    )
}

/// Gives the task whose directory under the fixture's process table is
/// `task` a ring as descriptor `fd`, with `info` as the ring's `fdinfo`.
/// The link reads as a ring's does and leads to a file of that name beside
/// it, so the descriptor answers `statx` as a ring's does on procfs. The
/// task's process is one [`Fixture::process`] makes, and the task, when it
/// is a thread with no start recorded yet, gets start tick 0.
pub(super) fn hold_ring(fixture: &Fixture, task: &str, fd: u32, info: &str) {
    let mut ids = task.split('/').filter_map(|id| id.parse().ok());
    let pid = ids
        .next()
        .expect("a task directory starts with its process ID");
    fixture.process(pid);
    if let Some(tid) = ids.next()
        && fs::symlink_metadata(fixture.root.join(format!("proc/{task}/stat"))).is_err()
    {
        fixture.thread_started(pid, tid, 0);
    }
    let table = fixture.root.join("proc").join(task).join("fd");
    fs::create_dir_all(&table).unwrap();
    fs::write(table.join("anon_inode:[io_uring]"), "").unwrap();
    symlink("anon_inode:[io_uring]", table.join(fd.to_string())).unwrap();
    fixture.file(&format!("proc/{task}/fdinfo/{fd}"), info);
}

/// Replaces the file at `path` with a FIFO. A read of the path then waits
/// until a test's writer opens the FIFO, so the writer changes the fixture
/// at that read.
pub(super) fn make_fifo(path: &Path) {
    let _ = fs::remove_file(path);
    let name = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: `name` is a NUL-terminated string that outlives the call.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
}

/// Opens `fifo` for reading without waiting and returns the open end, or
/// `None` when the path cannot be opened. While the caller holds the end,
/// a writer's open of the FIFO succeeds whenever it starts: one still
/// waiting for a read after the check has ended is released, and one that
/// reaches its open later does not wait.
pub(super) fn release(fifo: &Path) -> Option<File> {
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(fifo)
        .ok()
}

/// Holds one read end of each FIFO that appears at `fifos` until
/// `finished` answers true, so a writer that opens one of them after the
/// check has ended, or makes it again, still opens. A path that names no
/// FIFO is left alone, and a FIFO already held is not opened again.
pub(super) fn hold_readers(fifos: &[&Path], finished: impl Fn() -> bool) {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let mut held: Vec<((u64, u64), File)> = Vec::new();
    while !finished() {
        for fifo in fifos {
            let found = fs::metadata(fifo)
                .ok()
                .filter(|meta| meta.file_type().is_fifo())
                .map(|meta| (meta.dev(), meta.ino()));
            if let Some(id) = found.filter(|id| held.iter().all(|(known, _)| known != id))
                && let Some(reader) = release(fifo)
            {
                held.push((id, reader));
            }
        }
        std::thread::yield_now();
    }
}

/// One neighbor entry as `ip -4 neigh show dev <netdev>` prints it; `ip`
/// prints kernel state zero, `NONE`, as an empty state list.
pub(super) fn neighbor_entry(address: &str, mac: Option<&str>, state: &str) -> String {
    let mut entry = address.to_owned();
    if let Some(mac) = mac {
        entry += &format!(" lladdr {mac}");
    }
    if state != "NONE" {
        entry += &format!(" {state}");
    }
    entry + "\n"
}

/// The fixture ENI's address line as `ip -4 -o addr show dev ens6` prints it.
pub(super) const ENS6_ADDRESS: &str = "3: ens6    inet 10.0.1.5/24 metric 1003 brd 10.0.1.255 scope global dynamic ens6\\       valid_lft 3000sec preferred_lft 3000sec\n";

/// The fixture ENI's link line as `ip -o link show dev ens6` prints it.
pub(super) const ENS6_LINK: &str = "3: ens6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc mq state UP mode DEFAULT group default qlen 1000\\    link/ether 0a:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff\n";

/// A change another actor makes to the fixture host.
pub(super) type Action = Box<dyn FnOnce()>;

/// The PCI core over a fixture: override writes set the attribute, unbind
/// removes the driver link, and bind links the driver the override allows.
/// A device's own `driver/unbind` reaches whichever driver holds it, and a
/// driver's `unbind` refuses with `ENODEV` a device that driver does not
/// hold.
/// `fail` names a control file whose next write fails; `ignore` names one
/// the kernel accepts without acting on. Each names a path suffix, or a
/// suffix of `<path>=<value>` to pick one value's write, such as
/// `vfio-pci/bind=0000:00:06.0`. A solicitation replaces the hop's
/// entry in `neigh/<netdev>`: a hop in `answers` gets a `REACHABLE` entry
/// with its MAC and any other hop an `INCOMPLETE` one, and with
/// `solicit_fails` set the send then reports failure.
pub(super) struct FakeKernel {
    pub(super) host: Host,
    /// Standard output by command line; a command without an entry prints nothing, and one mapped to `None` fails.
    pub(super) outputs: RefCell<HashMap<String, Option<String>>>,
    /// Outputs the next runs of a command line print, one per run in order,
    /// with `None` failing its run, before `outputs` answers it again.
    pub(super) queued: RefCell<HashMap<String, VecDeque<Option<String>>>>,
    pub(super) runs: RefCell<Vec<String>>,
    /// The length of `runs` when each tool process began, in order: the
    /// commands one process read are the `runs` from its entry up to the
    /// next entry.
    pub(super) processes: RefCell<Vec<usize>>,
    /// Each solicitation, as `<hop> dev <netdev>`.
    pub(super) solicits: RefCell<Vec<String>>,
    /// The MAC each hop answers a solicitation with.
    pub(super) answers: RefCell<HashMap<Ipv4Addr, &'static str>>,
    /// Actions run by successive settles, one each, modelling the kernel finishing a change.
    pub(super) on_settle: RefCell<Vec<Box<dyn FnOnce()>>>,
    /// The virtual clock, advanced by each settle's interval and by
    /// `run_cost` for each command line run.
    pub(super) clock: Cell<Instant>,
    pub(super) run_cost: Cell<Duration>,
    pub(super) solicit_fails: Cell<bool>,
    pub(super) fail: RefCell<Option<&'static str>>,
    pub(super) ignore: RefCell<Option<&'static str>>,
    pub(super) writes: RefCell<Vec<(String, String)>>,
    /// What every group status request reports: its flags, or `None` for a failed request.
    pub(super) group_status: RefCell<Option<u32>>,
    /// Every group file open: its path, and how many writes preceded it.
    pub(super) group_opens: RefCell<Vec<(PathBuf, usize)>>,
    /// The descriptor of each group file opened, by path.
    pub(super) group_fds: RefCell<Vec<(PathBuf, RawFd)>>,
    /// For each `vfio-pci` unbind, whether the descriptor last opened on the
    /// device's group node was still open on that node's character device.
    pub(super) guarded_unbinds: RefCell<Vec<bool>>,
    /// An action run once, after the next accepted write whose path or
    /// `<path>=<value>` ends with the pattern, modelling a change another
    /// actor makes between two of the binder's writes.
    pub(super) after_write: RefCell<Option<(&'static str, Action)>>,
    /// An action run once, when the command line next runs and before its
    /// answer, modelling a change another actor makes while the command runs.
    pub(super) during_run: RefCell<Option<(String, Action)>>,
    /// An action run once, before the next write whose path or
    /// `<path>=<value>` ends with the pattern takes effect.
    pub(super) before_write: RefCell<Option<(&'static str, Action)>>,
    /// A file every write and run is appended to as it happens, so a parent
    /// process reads the log of a child it killed: `write <path>=<value>
    /// <record>`, with the value trimmed, logged before the write takes
    /// effect, with the record
    /// file's bytes in hexadecimal at that moment, or `-` when it is absent,
    /// and `run <command line>`.
    pub(super) journal: RefCell<Option<Journal>>,
}

/// Where a [`FakeKernel`] appends its log, and the record file each write
/// entry captures.
pub(super) struct Journal {
    pub(super) log: File,
    pub(super) record: PathBuf,
}

impl Journal {
    fn append(&mut self, entry: &str) {
        use std::io::Write;
        self.log.write_all(format!("{entry}\n").as_bytes()).unwrap();
    }
}

impl FakeKernel {
    /// What `ip -o link show` prints for the devices under `sys/class/net`,
    /// in index order, as iproute2 6.10 prints a device with no altname.
    fn link_listing(&self) -> String {
        let net = self.host.sys.join("class/net");
        let read = |name: &str, file: &str| {
            fs::read_to_string(net.join(name).join(file))
                .map(|text| text.trim().to_owned())
                .ok()
        };
        let mut devices: Vec<(u32, String)> = fs::read_dir(&net)
            .into_iter()
            .flatten()
            .filter_map(|entry| {
                let name = entry.ok()?.file_name().into_string().ok()?;
                Some((read(&name, "ifindex")?.parse().ok()?, name))
            })
            .collect();
        devices.sort();
        devices
            .into_iter()
            .map(|(index, name)| {
                let mac = read(&name, "address").unwrap_or_default();
                format!(
                    "{index}: {name}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc mq state UP mode DEFAULT \
                     group default qlen 1000\\    link/ether {mac} brd ff:ff:ff:ff:ff:ff\n"
                )
            })
            .collect()
    }

    pub(super) fn new(host: &Host) -> Self {
        let outputs = HashMap::from([
            (
                "ip -4 -o addr show dev ens6".to_owned(),
                Some(ENS6_ADDRESS.to_owned()),
            ),
            (
                "ip -4 -o route show table all dev ens6".to_owned(),
                Some("10.0.1.0/24 proto kernel scope link src 10.0.1.5 metric 1003\n".to_owned()),
            ),
            (
                "ip -4 -o link show dev ens6".to_owned(),
                Some(ENS6_LINK.to_owned()),
            ),
            (
                "ip -4 -o link show dev ens7".to_owned(),
                Some(ENS6_LINK.replace("3: ens6", "4: ens7")),
            ),
            (
                "ip -6 -o link show dev ens6".to_owned(),
                Some(ENS6_LINK.to_owned()),
            ),
            (
                "ip -6 -o link show dev ens7".to_owned(),
                Some(ENS6_LINK.replace("3: ens6", "4: ens7")),
            ),
            (
                "ip -4 -o addr show dev ens7".to_owned(),
                Some("4: ens7    inet 10.0.1.7/24 brd 10.0.1.255 scope global ens7\n".to_owned()),
            ),
            // The rules a host holds until one is added or deleted.
            (
                "ip -4 -o rule show".to_owned(),
                Some(
                    "0:\tfrom all lookup local\n32766:\tfrom all lookup main\n32767:\tfrom all lookup default\n"
                        .to_owned(),
                ),
            ),
        ]);
        Self {
            host: host.clone(),
            outputs: RefCell::new(outputs),
            queued: RefCell::new(HashMap::new()),
            runs: RefCell::new(Vec::new()),
            processes: RefCell::new(Vec::new()),
            solicits: RefCell::new(Vec::new()),
            answers: RefCell::new(HashMap::new()),
            on_settle: RefCell::new(Vec::new()),
            clock: Cell::new(Instant::now()),
            run_cost: Cell::new(Duration::ZERO),
            solicit_fails: Cell::new(false),
            fail: RefCell::new(None),
            ignore: RefCell::new(None),
            writes: RefCell::new(Vec::new()),
            group_status: RefCell::new(Some(VIABLE)),
            group_opens: RefCell::new(Vec::new()),
            group_fds: RefCell::new(Vec::new()),
            guarded_unbinds: RefCell::new(Vec::new()),
            after_write: RefCell::new(None),
            during_run: RefCell::new(None),
            before_write: RefCell::new(None),
            journal: RefCell::new(None),
        }
    }
}

impl FakeKernel {
    /// A line in `outputs` or `queued` takes precedence over the fixture's
    /// `neigh/<netdev>` and `proxy/<netdev>` files, so a test can make a
    /// listing fail or print malformed text. As in the kernel, proxy entries
    /// are a table of their own: `proxy/<netdev>` answers only
    /// `neigh show proxy`, and `neigh/<netdev>` only the `nud all` listing.
    fn neighbors(&self, line: &str) -> Option<io::Result<String>> {
        let words: Vec<&str> = line.split_whitespace().collect();
        if self.outputs.borrow().contains_key(line) || self.queued.borrow().contains_key(line) {
            return None;
        }
        match words[..] {
            [
                "ip",
                "-4",
                "-o",
                "neigh",
                "show",
                "dev",
                netdev,
                "nud",
                "all",
            ] => Some(Ok(fs::read_to_string(
                self.host.root.join("neigh").join(netdev),
            )
            .unwrap_or_default())),
            ["ip", "-4", "-o", "neigh", "show", "proxy", "dev", netdev] => Some(Ok(
                fs::read_to_string(self.host.root.join("proxy").join(netdev)).unwrap_or_default(),
            )),
            ["ip", "-4", "neigh", "flush", "to", hop, "dev", netdev] => {
                self.remove_neighbor(netdev, hop.parse().unwrap());
                Some(Ok(String::new()))
            }
            _ => None,
        }
    }

    /// Removes `hop`'s entry from `netdev`'s neighbor file, reporting whether it had one.
    fn remove_neighbor(&self, netdev: &str, hop: Ipv4Addr) -> bool {
        let path = self.host.root.join("neigh").join(netdev);
        let table = fs::read_to_string(&path).unwrap_or_default();
        let address = hop.to_string();
        let kept: String = table
            .lines()
            .filter(|entry| entry.split_whitespace().next() != Some(address.as_str()))
            .map(|entry| format!("{entry}\n"))
            .collect();
        let removed = kept.len() != table.len();
        fs::write(path, kept).unwrap();
        removed
    }

    /// The name of `bdf`'s VFIO group device in the fixture's VFIO mode.
    fn group_name(&self, bdf: &str) -> String {
        let no_iommu = Host::read(
            &self
                .host
                .sys
                .join("module/vfio/parameters/enable_unsafe_noiommu_mode"),
        )
        .as_deref()
            == Some("Y");
        let group = group_of(bdf);
        if no_iommu {
            format!("noiommu-{group}")
        } else {
            group.to_string()
        }
    }

    /// Whether the descriptor last opened on `bdf`'s group node is still
    /// open on the node's character device.
    fn guarded(&self, bdf: &str) -> bool {
        let node = self.host.dev.join("vfio").join(self.group_name(bdf));
        let fds = self.group_fds.borrow();
        let Some(&(_, fd)) = fds.iter().rev().find(|(path, _)| *path == node) else {
            return false;
        };
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `stat` is writable for one record; a closed `fd` fails the call.
        let open = unsafe { libc::fstat(fd, stat.as_mut_ptr()) } == 0;
        // SAFETY: a zero result means the kernel filled the record.
        open && unsafe { stat.assume_init() }.st_rdev == libc::makedev(1, 3)
    }

    /// Adds or removes `bdf`'s VFIO group device as `vfio-pci` does at bind
    /// and unbind: its sysfs class entry and its `/dev/vfio` node, named for
    /// the fixture's VFIO mode.
    fn vfio_group(&self, bdf: &str, present: bool) -> io::Result<()> {
        let name = self.group_name(bdf);
        let class = self.host.sys.join("class/vfio").join(&name);
        let node = self.host.dev.join("vfio").join(&name);
        if present {
            fs::create_dir_all(&class)?;
            fs::write(class.join("dev"), format!("{GROUP_DEV}\n"))?;
            symlink(GROUP_NODE, node)
        } else {
            fs::remove_dir_all(class)?;
            fs::remove_file(node)
        }
    }
}

/// A run `FakeKernel::start` defers to `feed`, so the scripted output and
/// the recorded run belong to the moment the input arrives.
struct Deferred<'k> {
    kernel: &'k FakeKernel,
    program: String,
    args: Vec<String>,
}

impl Started for Deferred<'_> {
    fn feed<'s>(self: Box<Self>, input: &str) -> Box<dyn Fed + 's>
    where
        Self: 's,
    {
        let args: Vec<&str> = self.args.iter().map(String::as_str).collect();
        Box::new(Ran(self.kernel.run(&self.program, &args, input)))
    }
}

/// The result of a scripted run, held from its feed to its finish.
struct Ran(io::Result<String>);

impl Fed for Ran {
    fn finish(self: Box<Self>) -> io::Result<String> {
        self.0
    }
}

impl Kernel for FakeKernel {
    fn start<'k>(&'k self, program: &str, args: &[&str]) -> io::Result<Box<dyn Started + 'k>> {
        Ok(Box::new(Deferred {
            kernel: self,
            program: program.to_owned(),
            args: args.iter().map(|arg| (*arg).to_owned()).collect(),
        }))
    }

    /// A directory at `path` stands for a group file another process holds.
    fn open_group(&self, path: &Path) -> io::Result<File> {
        let writes = self.writes.borrow().len();
        self.group_opens
            .borrow_mut()
            .push((path.to_owned(), writes));
        if path.is_dir() {
            return Err(io::Error::from_raw_os_error(libc::EBUSY));
        }
        let file = File::options().read(true).write(true).open(path)?;
        self.group_fds
            .borrow_mut()
            .push((path.to_owned(), file.as_raw_fd()));
        Ok(file)
    }

    fn group_status(&self, _group: &File) -> io::Result<u32> {
        self.group_status
            .borrow()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOTTY))
    }

    /// A hop in `answers` answers the solicitation's ARP request, so its
    /// entry becomes `REACHABLE` with its MAC.
    fn solicit(&self, netdev: &str, hop: Ipv4Addr) -> io::Result<()> {
        self.solicits
            .borrow_mut()
            .push(format!("{hop} dev {netdev}"));
        let entry = match self.answers.borrow().get(&hop) {
            Some(mac) => neighbor_entry(&hop.to_string(), Some(mac), "REACHABLE"),
            None => neighbor_entry(&hop.to_string(), None, "INCOMPLETE"),
        };
        self.remove_neighbor(netdev, hop);
        let path = self.host.root.join("neigh").join(netdev);
        let table = fs::read_to_string(&path).unwrap_or_default();
        fs::create_dir_all(path.parent().unwrap())?;
        fs::write(path, format!("{table}{entry}"))?;
        if self.solicit_fails.get() {
            return Err(io::Error::other("unsent"));
        }
        Ok(())
    }

    fn now(&self) -> Instant {
        self.clock.get()
    }

    fn settle(&self, interval: Duration) {
        self.clock.set(self.clock.get() + interval);
        let mut pending = self.on_settle.borrow_mut();
        if !pending.is_empty() {
            let action = pending.remove(0);
            drop(pending);
            action();
        }
    }

    /// `-batch -` runs each input line as its own command line, after the
    /// other options, and stops at the first that fails.
    fn run(&self, program: &str, args: &[&str], input: &str) -> io::Result<String> {
        let (options, commands): (&[&str], Vec<&str>) = match args {
            [options @ .., "-batch", "-"] => (options, input.lines().collect()),
            _ => (args, vec![""]),
        };
        let mut stdout = String::new();
        self.processes.borrow_mut().push(self.runs.borrow().len());
        for command in commands {
            let line = std::iter::once(program)
                .chain(options.iter().copied())
                .chain(command.split_whitespace())
                .collect::<Vec<_>>()
                .join(" ");
            let stopped = replay_control::network_phase(&replay_control::mode(), &line);
            if let Some(phase) = stopped {
                replay_control::before(phase, &line);
            }
            self.runs.borrow_mut().push(line.clone());
            if let Some(journal) = self.journal.borrow_mut().as_mut() {
                journal.append(&format!("run {line}"));
            }
            self.clock.set(self.clock.get() + self.run_cost.get());
            let due = self
                .during_run
                .borrow()
                .as_ref()
                .is_some_and(|(during, _)| *during == line);
            if due && let Some((_, action)) = self.during_run.take() {
                action();
            }
            if let Some(answer) = self.neighbors(&line) {
                stdout.push_str(&answer?);
                continue;
            }
            let next = self
                .queued
                .borrow_mut()
                .get_mut(&line)
                .and_then(VecDeque::pop_front);
            let answer = next.or_else(|| self.outputs.borrow().get(&line).cloned());
            match answer.as_ref() {
                Some(Some(text)) => stdout.push_str(text),
                Some(None) => return Err(io::Error::other("refused")),
                None if line == "ip -o link show" => stdout.push_str(&self.link_listing()),
                None => {}
            }
            if let Some(phase) = stopped {
                self.restore_network(&line);
                replay_control::after(phase, &line, true);
            }
        }
        Ok(stdout)
    }

    fn write(&self, path: &Path, value: &str) -> io::Result<()> {
        let file = path.file_name().unwrap().to_str().unwrap();
        // A `driver_override` path names its device in its parent directory;
        // a `bind` or `unbind` write names it in the written value.
        let device = match file {
            "driver_override" => path
                .parent()
                .unwrap()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap(),
            _ => value,
        };
        let stopped = replay_control::driver_before(device, file, value);
        let written = self.apply(path, value);
        if let Some(phase) = stopped {
            replay_control::after(phase, device, written.is_ok());
        }
        written
    }
}

impl FakeKernel {
    /// The kernel's handling of one driver write.
    fn apply(&self, path: &Path, value: &str) -> io::Result<()> {
        let relative = path
            .strip_prefix(&self.host.sys)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        self.writes
            .borrow_mut()
            .push((relative.clone(), value.to_owned()));
        let file = path.file_name().unwrap().to_str().unwrap();
        let names = |pattern: &str| {
            relative.ends_with(pattern) || format!("{relative}={value}").ends_with(pattern)
        };
        if let Some(journal) = self.journal.borrow_mut().as_mut() {
            let record = fs::read(&journal.record).map_or_else(
                |_| "-".to_owned(),
                |bytes| bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
            );
            journal.append(&format!("write {relative}={} {record}", value.trim()));
        }
        let before = self
            .before_write
            .borrow()
            .as_ref()
            .is_some_and(|(pattern, _)| names(pattern));
        if before && let Some((_, action)) = self.before_write.take() {
            action();
        }
        if replay_control::write_refused() {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        if self.fail.borrow().is_some_and(names) {
            self.fail.replace(None);
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        if self.ignore.borrow().is_some_and(names) {
            return Ok(());
        }
        let written = match file {
            "driver_override" => fs::write(
                path,
                if value.trim().is_empty() {
                    "(null)\n".to_owned()
                } else {
                    format!("{value}\n")
                },
            ),
            "unbind" => {
                let dir = path.parent().unwrap();
                let named = dir.parent().unwrap().ends_with("bus/pci/drivers");
                let held = self.host.driver(value);
                if named && held.as_deref() != dir.file_name().unwrap().to_str() {
                    return Err(io::Error::from_raw_os_error(libc::ENODEV));
                }
                if held.as_deref() == Some("vfio-pci") {
                    let guarded = self.guarded(value);
                    self.guarded_unbinds.borrow_mut().push(guarded);
                    self.vfio_group(value, false)?;
                }
                fs::remove_file(self.host.pci(value).join("driver"))
            }
            "bind" => {
                let driver = path.parent().unwrap();
                let device = self.host.pci(value);
                let allowed = self.host.driver_override(value).flatten();
                if allowed.is_some_and(|name| driver.file_name().unwrap() != name.as_str())
                    || device.join("driver").exists()
                {
                    return Err(io::Error::from_raw_os_error(libc::ENODEV));
                }
                if driver.ends_with("vfio-pci") {
                    self.vfio_group(value, true)?;
                }
                symlink(driver, device.join("driver"))
            }
            _ => Err(io::Error::from_raw_os_error(libc::EINVAL)),
        };
        if written.is_ok() {
            if file == "unbind" && value == ENI_BDF && replay_control::connected() {
                self.reset_network();
            }
            let due = self
                .after_write
                .borrow()
                .as_ref()
                .is_some_and(|(pattern, _)| names(pattern));
            if due && let Some((_, action)) = self.after_write.take() {
                action();
            }
        }
        written
    }

    /// Applies a restoring command of a supervised release or rollback to
    /// the ENI's network files, which the supervisor reads as the ENI's
    /// network state: `mtu` and `flags` as sysfs holds them, and the
    /// assigned addresses and routes in `addresses` and `routes`.
    fn restore_network(&self, line: &str) {
        let net = self.host.sys.join("class/net").join(ENI_NETDEV);
        let words: Vec<&str> = line.split_whitespace().collect();
        match words[..] {
            ["ip", "link", "set", "dev", ENI_IF, "mtu", mtu] => {
                fs::write(net.join("mtu"), format!("{mtu}\n")).unwrap();
            }
            ["ip", "link", "set", "dev", ENI_IF, state @ ("up" | "down")] => {
                let flags = fs::read_to_string(net.join("flags")).unwrap();
                let flags = u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16).unwrap();
                let flags = if state == "up" { flags | 1 } else { flags & !1 };
                fs::write(net.join("flags"), format!("0x{flags:x}\n")).unwrap();
            }
            [
                "ip",
                kind @ ("addr" | "route"),
                "replace",
                ref values @ ..,
                "dev",
                ENI_IF,
            ] => {
                let file = if kind == "addr" {
                    "addresses"
                } else {
                    "routes"
                };
                fs::write(net.join(file), values.join(" ")).unwrap();
            }
            _ => panic!("a restore runs {line}"),
        }
    }

    /// Clears the ENI's network files and neighbor entries, as the kernel
    /// drops an interface's state when its device leaves `ena`.
    fn reset_network(&self) {
        let net = self.host.sys.join("class/net").join(ENI_NETDEV);
        fs::write(net.join("mtu"), "1500\n").unwrap();
        fs::write(net.join("flags"), "0x1002\n").unwrap();
        fs::write(net.join("addresses"), "").unwrap();
        fs::write(net.join("routes"), "").unwrap();
        fs::write(self.host.root.join("neigh").join(ENI_NETDEV), "").unwrap();
    }
}

/// Instance metadata for the fixture: the primary interface and the dataplane ENI in subnet 10.0.1.0/24.
pub(super) struct FakeMetadata(pub(super) Mutex<HashMap<String, String>>);

impl FakeMetadata {
    pub(super) fn new() -> Self {
        let base = "network/interfaces/macs/";
        let mut paths =
            HashMap::from([(base.to_owned(), format!("0a:00:00:00:00:01/\n{ENI_MAC}/\n"))]);
        for (mac, id, device, ip) in [
            (
                "0a:00:00:00:00:01",
                "eni-0aaaaaaaaaaaaaaaa",
                "0",
                "10.0.0.5",
            ),
            (ENI_MAC, ENI, "1", "10.0.1.5"),
        ] {
            for (field, value) in [
                ("interface-id", id),
                ("device-number", device),
                ("network-card", "0"),
                ("local-ipv4s", ip),
                ("subnet-id", "subnet-0123"),
                (
                    "subnet-ipv4-cidr-block",
                    if device == "0" {
                        "10.0.0.0/24"
                    } else {
                        "10.0.1.0/24"
                    },
                ),
            ] {
                paths.insert(format!("{base}{mac}/{field}"), value.to_owned());
            }
        }
        Self(Mutex::new(paths))
    }
}

impl Metadata for FakeMetadata {
    fn get(&self, path: &str) -> io::Result<String> {
        self.0
            .lock()
            .unwrap()
            .get(path)
            .cloned()
            .ok_or_else(|| io::ErrorKind::NotFound.into())
    }
}

/// The fixture IOMMU group of `bdf`: its device number.
pub(super) fn group_of(bdf: &str) -> u32 {
    let slot = bdf.rsplit(':').next().unwrap().split('.').next().unwrap();
    u32::from_str_radix(slot, 16).unwrap()
}
