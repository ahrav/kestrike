//! The host's identity and PCI driver state as the kernel reports them, the
//! [`Kernel`] that changes it, and the forms EBS gives a volume ID.

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read};
use std::net::{Ipv4Addr, UdpSocket};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::identity::ControllerIdentity;
use super::tool::Running;

/// The search path of every tool the bind runs, as root.
const TOOL_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
/// The discard service's port. An empty datagram sent to it makes the
/// kernel resolve the next hop.
const DISCARD: u16 = 9;
/// Listings of `class/net` one lookup of a MAC's devices makes while each
/// differs from the listing before it.
const NETDEV_LISTINGS: u32 = 4;
/// What one listing of `class/net` read: each listed name that may be a
/// device, with its `address`, `None` where it has none.
type Listing = Vec<(OsString, Option<String>)>;

/// Writes the kernel's control files, whose success is the kernel's
/// acceptance, runs the host's network tools, solicits neighbors, and opens
/// and queries VFIO group files.
pub trait Kernel {
    /// # Errors
    ///
    /// The kernel's refusal.
    fn write(&self, path: &Path, value: &str) -> io::Result<()>;

    /// Starts `program` with `args`; the program waits on its standard
    /// input until [`Started::feed`] gives it that input.
    ///
    /// # Errors
    ///
    /// The spawn error.
    fn start<'k>(&'k self, program: &str, args: &[&str]) -> io::Result<Box<dyn Started + 'k>>;

    /// Runs `program` with `args` and `input` on its standard input, and
    /// returns its standard output.
    ///
    /// # Errors
    ///
    /// The spawn error, or as [`Fed::finish`].
    fn run(&self, program: &str, args: &[&str], input: &str) -> io::Result<String> {
        self.start(program, args)?.feed(input).finish()
    }

    /// Runs `program` as [`run`](Self::run) does, with `input` reaching it
    /// no earlier than `at`, so a program that acts on its input, such as
    /// `ip -batch -`, acts at or after `at`. The program starts before the
    /// wait, so its startup overlaps the wait.
    ///
    /// # Errors
    ///
    /// As [`run`](Self::run).
    fn run_at(&self, program: &str, args: &[&str], input: &str, at: Instant) -> io::Result<String> {
        let started = self.start(program, args)?;
        let wait = at.saturating_duration_since(self.now());
        if !wait.is_zero() {
            self.settle(wait);
        }
        started.feed(input).finish()
    }

    /// Sends `hop` one empty datagram through `netdev`, so the kernel
    /// resolves `hop`'s neighbor entry on `netdev`.
    ///
    /// # Errors
    ///
    /// `solicit` returns errors from socket creation, binding to `netdev`, or
    /// sending.
    fn solicit(&self, netdev: &str, hop: Ipv4Addr) -> io::Result<()>;

    /// Waits `interval` for the kernel to finish an asynchronous change.
    fn settle(&self, interval: Duration);

    /// The monotonic time the waits and the ENI resolution's deadline are
    /// measured on.
    fn now(&self) -> Instant;

    /// Opens the VFIO group file at `path` for reading and writing, which
    /// the kernel grants one holder at a time.
    ///
    /// # Errors
    ///
    /// The open's error: `EBUSY` while another process holds the group file
    /// or one of the group's devices.
    fn open_group(&self, path: &Path) -> io::Result<File>;

    /// The flags `VFIO_GROUP_GET_STATUS` reports for the open group `group`.
    ///
    /// # Errors
    ///
    /// The ioctl's error.
    fn group_status(&self, group: &File) -> io::Result<u32>;
}

/// A program [`Kernel::start`] started, waiting on its standard input.
pub trait Started {
    /// Gives the program `input` as its whole standard input. The program
    /// acts on the input from this call on, beside whatever the caller does
    /// before it calls [`Fed::finish`].
    fn feed<'s>(self: Box<Self>, input: &str) -> Box<dyn Fed + 's>
    where
        Self: 's;
}

/// A program acting on the input [`Started::feed`] gave it.
pub trait Fed {
    /// Returns the program's standard output once it exits.
    ///
    /// # Errors
    ///
    /// `Other` for a nonzero exit, the error of a write that left the
    /// input short, or the implementation's refusal of a run past its
    /// bounds, after which the program's effect on the host is unknown.
    fn finish(self: Box<Self>) -> io::Result<String>;
}

/// `SysfsKernel` writes control values through sysfs, runs tools with `PATH`
/// as their whole environment, and sends solicitations from a UDP socket
/// bound to the device.
#[derive(Debug, Clone, Copy)]
pub struct SysfsKernel;

impl Started for Running {
    /// Writes the part of `input` the program's input pipe takes at once,
    /// and closes the pipe when that is all of it; [`Fed::finish`] writes
    /// the rest.
    fn feed<'s>(mut self: Box<Self>, input: &str) -> Box<dyn Fed + 's>
    where
        Self: 's,
    {
        Running::feed(&mut self, input);
        self
    }
}

impl Fed for Running {
    /// A refused run stays inside [`LIMITS`](super::tool::LIMITS): 1 MiB
    /// of each output stream, 30 seconds from spawn, and 5 seconds of
    /// reaping after a kill. A run that ends on a `pidfd_open`, `poll`,
    /// `fcntl` or wait error leaves the tool to the drop's kill and blocking
    /// reap. A nonzero exit takes precedence over an error writing the
    /// input.
    ///
    /// # Errors
    ///
    /// As [`Fed::finish`], and `TimedOut` or `FileTooLarge` carrying
    /// the tool's [`Stopped`](super::tool::Stopped) record when it passed
    /// its deadline or an output bound; that tool's effect on the host is
    /// unknown, and the caller reconciles it under the binder's safety
    /// procedure; or a `pidfd_open`, `poll`, `fcntl` or wait error.
    fn finish(mut self: Box<Self>) -> io::Result<String> {
        self.run()
    }
}

impl Kernel for SysfsKernel {
    fn write(&self, path: &Path, value: &str) -> io::Result<()> {
        fs::write(path, value)
    }

    fn start<'k>(&'k self, program: &str, args: &[&str]) -> io::Result<Box<dyn Started + 'k>> {
        let path = TOOL_PATH
            .split(':')
            .map(|directory| Path::new(directory).join(program))
            .find(|path| {
                fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.mode() & 0o111 != 0)
            })
            .ok_or(io::ErrorKind::NotFound)?;
        let child = Command::new(path)
            .args(args)
            .env_clear()
            .env("PATH", TOOL_PATH)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        Ok(Box::new(Running::new(child)))
    }

    fn solicit(&self, netdev: &str, hop: Ipv4Addr) -> io::Result<()> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        let length = libc::socklen_t::try_from(netdev.len()).map_err(io::Error::other)?;
        // SAFETY: the option value is `netdev`'s bytes, valid for `length`
        // bytes for the call's duration, on a descriptor `socket` owns.
        let bound = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                netdev.as_ptr().cast(),
                length,
            )
        };
        if bound != 0 {
            return Err(io::Error::last_os_error());
        }
        socket.send_to(&[], (hop, DISCARD)).map(drop)
    }

    fn settle(&self, interval: Duration) {
        std::thread::sleep(interval);
    }

    fn now(&self) -> Instant {
        Instant::now()
    }

    fn open_group(&self, path: &Path) -> io::Result<File> {
        File::options().read(true).write(true).open(path)
    }

    fn group_status(&self, group: &File) -> io::Result<u32> {
        super::group::status(group)
    }
}

/// The read size of [`Host::stream`]: its stack buffer holds this many bytes
/// of the file at once, whatever the file's size.
pub(crate) const CHUNK: usize = 16 * 1024;

/// Where the host's kernel state is read: the sysfs, procfs and device roots.
#[derive(Debug, Clone)]
pub struct Host {
    /// The filesystem root that absolute host paths, such as `/boot`, resolve under.
    pub root: PathBuf,
    pub sys: PathBuf,
    pub proc: PathBuf,
    pub dev: PathBuf,
    /// The controller identity a test's host accepts in place of an EBS
    /// volume's; one value governs both resolution and release.
    #[cfg(test)]
    pub(crate) controller: ControllerIdentity,
    /// Whether a test's device nodes are regular files. The exclusive claim
    /// then also accepts a regular-file descriptor whose filesystem and inode
    /// match the resolved node and whose filesystem device number is the
    /// namespace's sysfs `dev`.
    #[cfg(test)]
    pub(crate) file_nodes: bool,
}

impl Host {
    /// The running host's roots.
    pub fn system() -> Self {
        Self {
            root: "/".into(),
            sys: "/sys".into(),
            proc: "/proc".into(),
            dev: "/dev".into(),
            #[cfg(test)]
            controller: ControllerIdentity::EBS,
            #[cfg(test)]
            file_nodes: false,
        }
    }

    /// The controller identity resolution accepts, whose PCI vendor and
    /// device release requires at a recorded address: an EBS volume's.
    #[cfg(not(test))]
    pub(crate) fn controller_identity(&self) -> ControllerIdentity {
        ControllerIdentity::EBS
    }

    /// The controller identity resolution accepts, whose PCI vendor and
    /// device release requires at a recorded address: the identity this
    /// test's host names.
    #[cfg(test)]
    pub(crate) fn controller_identity(&self) -> ControllerIdentity {
        self.controller
    }

    /// This host, accepting `controller` in place of an EBS volume's
    /// controller.
    #[cfg(test)]
    pub(crate) fn expecting(self, controller: ControllerIdentity) -> Self {
        Self { controller, ..self }
    }

    /// `stream` reads the file at `path` in one pass, handing `sink` each
    /// piece of at most [`CHUNK`] bytes in file order and retrying a read the
    /// kernel interrupts; `None` when opening or a read fails, after `sink`
    /// has seen every earlier piece.
    pub(crate) fn stream(path: &Path, mut sink: impl FnMut(&[u8])) -> Option<()> {
        let mut file = File::open(path).ok()?;
        let mut buffer = [0u8; CHUNK];
        loop {
            match file.read(&mut buffer) {
                Ok(0) => return Some(()),
                Ok(n) => sink(&buffer[..n]),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return None,
            }
        }
    }

    /// `read` returns the file's trimmed text, or `None` for an unreadable
    /// file or bytes outside UTF-8.
    pub(crate) fn read(path: &Path) -> Option<String> {
        let mut bytes = Vec::new();
        Self::stream(path, |chunk| bytes.extend_from_slice(chunk))?;
        Some(String::from_utf8(bytes).ok()?.trim().to_owned())
    }

    /// Reads the kernel attribute at `path` and removes one final newline,
    /// the one the kernel appends. Every other byte, edge whitespace
    /// included, is part of the value. `None` for an unreadable file or
    /// bytes outside UTF-8.
    pub(super) fn attribute(path: &Path) -> Option<String> {
        let mut bytes = Vec::new();
        Self::stream(path, |chunk| bytes.extend_from_slice(chunk))?;
        let mut text = String::from_utf8(bytes).ok()?;
        if text.ends_with('\n') {
            text.pop();
        }
        Some(text)
    }

    /// The instance ID and boot ID of the running host.
    pub fn instance_and_boot(&self) -> Option<(String, String)> {
        self.instance_and_boot_by(Self::read)
    }

    /// The instance ID and boot ID a bind or a release stamps and compares
    /// its record by: each is the kernel's text only where no mount
    /// [covers](Self::kernel) it.
    pub(crate) fn shown_instance_and_boot(&self) -> Option<(String, String)> {
        self.instance_and_boot_by(|entry| self.kernel_text(entry))
    }

    fn instance_and_boot_by(
        &self,
        read: impl Fn(&Path) -> Option<String>,
    ) -> Option<(String, String)> {
        Some((
            read(&self.sys.join("devices/virtual/dmi/id/board_asset_tag"))?,
            read(&self.proc.join("sys/kernel/random/boot_id"))?,
        ))
    }

    /// The host path of `absolute` under [`root`](Self::root).
    pub(crate) fn under_root(&self, absolute: &Path) -> PathBuf {
        self.root
            .join(absolute.strip_prefix("/").unwrap_or(absolute))
    }

    pub(crate) fn pci(&self, bdf: &str) -> PathBuf {
        self.sys.join("bus/pci/devices").join(bdf)
    }

    /// The `bind` file of PCI driver `driver`.
    pub(crate) fn bind_file(&self, driver: &str) -> PathBuf {
        self.sys.join("bus/pci/drivers").join(driver).join("bind")
    }

    /// The `unbind` file of PCI driver `driver`. The kernel refuses a device
    /// written there with `ENODEV` unless `driver` holds it as the write
    /// arrives. It checks the driver before it takes the device's lock and
    /// then detaches whichever driver holds the device, so a move that
    /// completes while the write waits for that lock is detached too.
    pub(crate) fn unbind_file(&self, driver: &str) -> PathBuf {
        self.sys.join("bus/pci/drivers").join(driver).join("unbind")
    }

    /// The PCI vendor and device IDs of `bdf`; `None` when either is
    /// unreadable, malformed or under a mount that
    /// [covers](Self::kernel) it.
    pub(crate) fn pci_id(&self, bdf: &str) -> Option<(u16, u16)> {
        let hex = |file| {
            u16::from_str_radix(
                self.kernel_text(&self.pci(bdf).join(file))?
                    .strip_prefix("0x")?,
                16,
            )
            .ok()
        };
        Some((hex("vendor")?, hex("device")?))
    }

    /// The network devices whose MAC is `mac`, from a listing of the class
    /// in which every device was read under its listed name. An entry that
    /// is no directory, as the bonding driver's `bonding_masters` file is,
    /// is no device and is left out.
    ///
    /// One listing does not show the class: a device renamed while the
    /// directory is read may be returned under neither name, and a device
    /// renamed after it may leave its listed name to another device or to
    /// none, and either may carry `mac` under a name the listing does not
    /// hold. The class is therefore listed until two successive listings
    /// agree on every name and on what was read beneath it. A listed name
    /// with no `address` beneath it in both is no device and is left out.
    ///
    /// # Errors
    ///
    /// The error of the mount table, of the listing, of an entry of it, or
    /// of reading a device's `address`, a [covered](Self::shown) one
    /// included: a device that cannot be read may carry `mac`, so the list
    /// would not show the match unique. `NotFound` when each of
    /// [`NETDEV_LISTINGS`] listings differed from the listing before.
    /// `InvalidData` for a device that
    /// carries `mac` under a name outside UTF-8: the list cannot hold that
    /// name, and leaving the device out would show another device's match
    /// unique.
    pub(crate) fn netdevs_with_mac(&self, mac: [u8; 6]) -> io::Result<Vec<String>> {
        let mut before = None;
        for _ in 0..NETDEV_LISTINGS {
            let (found, listed) = self.listed_netdevs_with_mac(mac)?;
            if before.as_ref() == Some(&listed) {
                return Ok(found);
            }
            before = Some(listed);
        }
        Err(io::Error::from(io::ErrorKind::NotFound))
    }

    /// One listing of `class/net` with the read of each entry's `address`,
    /// for [`netdevs_with_mac`](Self::netdevs_with_mac): the devices whose
    /// MAC is `mac`, and every listed name that may be a device with its
    /// `address`, `None` where it has none, in sorted order.
    fn listed_netdevs_with_mac(&self, mac: [u8; 6]) -> io::Result<(Vec<String>, Listing)> {
        let (mut found, mut listed) = (Vec::new(), Vec::new());
        let mounts = self.mount_table()?;
        let class = self.sys.join("class/net");
        for entry in self.shown(&mounts, &class).and_then(fs::read_dir)? {
            let entry = entry?;
            let address = entry.path().join("address");
            let address = match self.shown(&mounts, &address).and_then(fs::read_to_string) {
                Ok(address) => address,
                Err(error) if error.kind() == io::ErrorKind::NotADirectory => continue,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    listed.push((entry.file_name(), None));
                    continue;
                }
                Err(error) => return Err(error),
            };
            if super::eni::parse_mac(&address) == Some(mac) {
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
                found.push(name);
            }
            listed.push((entry.file_name(), Some(address)));
        }
        listed.sort_unstable();
        Ok((found, listed))
    }

    /// What `read` reads of `attribute` of the device named `netdev`, when
    /// that device sits on PCI function `bdf`; `None` when it sits on
    /// another function, its directory or function cannot be read, or a
    /// mount [covers](Self::shown) the attribute or the function link.
    ///
    /// A name can pass from one device to another between two reads under
    /// it. The attribute and the function are therefore read through one
    /// open directory of the device, which stays that device's directory
    /// under any name, so both are the same device's. `read` takes the
    /// attribute's path, which the kernel resolves through that open
    /// directory itself.
    fn netdev_on<T>(
        &self,
        netdev: &str,
        bdf: &str,
        attribute: &str,
        read: impl FnOnce(&Path) -> Option<T>,
    ) -> Option<T> {
        // The device's directory is the kernel's own, and so are the two
        // entries read through it, only where no mount covers them.
        let named = self.sys.join("class/net").join(netdev);
        let mounts = self.mount_table().ok()?;
        for entry in [attribute, "device"] {
            self.shown(&mounts, &named.join(entry)).ok()?;
        }
        let device = File::open(named).ok()?;
        let held = PathBuf::from(format!("/proc/self/fd/{}", device.as_raw_fd()));
        let found = read(&held.join(attribute))?;
        let function = fs::read_link(held.join("device")).ok()?;
        (function.file_name()?.to_str()? == bdf).then_some(found)
    }

    /// The interface index of the device named `netdev`, which the kernel
    /// keeps for a device across its renames, when that device sits on PCI
    /// function `bdf`, both read from one device as
    /// [`netdev_on`](Self::netdev_on) reads them; `None` when it sits on
    /// another function or either cannot be read.
    pub(crate) fn netdev_index_on(&self, netdev: &str, bdf: &str) -> Option<u32> {
        self.netdev_on(netdev, bdf, "ifindex", |index| {
            Self::read(index)?.parse().ok()
        })
    }

    /// Whether the device named `netdev` carries `mac` and sits on PCI
    /// function `bdf` now, both read from one device as
    /// [`netdev_on`](Self::netdev_on) reads them. An unreadable or
    /// malformed `address` reads as another MAC.
    pub(crate) fn netdev_carries_on(&self, netdev: &str, mac: [u8; 6], bdf: &str) -> bool {
        self.netdev_on(netdev, bdf, "address", |address| {
            Self::read(address).and_then(|address| super::eni::parse_mac(&address))
        }) == Some(mac)
    }

    /// The PCI function the device named `netdev` sits on; `None` when its
    /// function link cannot be resolved or a mount [covers](Self::kernel)
    /// it.
    pub(crate) fn netdev_function(&self, netdev: &str) -> Option<String> {
        let device = self.sys.join("class/net").join(netdev).join("device");
        let device = (self.kernel(&device).and_then(fs::canonicalize)).ok()?;
        Some(device.file_name()?.to_str()?.to_owned())
    }

    /// Whether this process runs in the initial PID namespace, where its
    /// process table lists every process on the host. The kernel gives the
    /// initial namespace's `ns/pid` file the fixed inode `PROC_PID_INIT_INO`;
    /// every other PID namespace has an ordinary one.
    ///
    /// # Errors
    ///
    /// The error from reading the namespace file's metadata.
    pub fn in_initial_pid_namespace(&self) -> std::io::Result<bool> {
        use std::os::unix::fs::MetadataExt;
        const PROC_PID_INIT_INO: u64 = 0xEFFF_FFFC;
        Ok(fs::metadata(self.proc.join("self/ns/pid"))?.ino() == PROC_PID_INIT_INO)
    }

    /// Whether the kernel's IOMMU class lists a guest IOMMU unit:
    /// `Some(false)` for an empty or absent class, `None` when the class
    /// cannot be read or a mount [covers](Self::kernel) it.
    pub(crate) fn guest_iommu(&self) -> Option<bool> {
        let class = self.sys.join("class/iommu");
        let units = self.kernel(&class).and_then(fs::read_dir);
        match units.map(|mut units| units.next()) {
            Ok(None) => Some(false),
            Ok(Some(Ok(_))) => Some(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Some(false),
            Ok(Some(Err(_))) | Err(_) => None,
        }
    }

    /// The driver `bdf` is bound to, if any; `None` as well when its
    /// `driver` link cannot be read or names a driver outside UTF-8, which
    /// only a comparison against a known driver may treat as absent.
    pub(crate) fn driver(&self, bdf: &str) -> Option<String> {
        self.driver_link(bdf).flatten()
    }

    /// The driver `bdf` is bound to: `Some(None)` for none, when its
    /// `driver` link is absent, and `None` when the link cannot be read, a
    /// mount [covers](Self::kernel) it, or it names a driver outside UTF-8.
    pub(crate) fn driver_link(&self, bdf: &str) -> Option<Option<String>> {
        self.driver_link_in(&self.mount_table().ok()?, bdf)
    }

    /// As [`driver_link`](Self::driver_link), judged by `mounts`, the mount
    /// table the caller's check holds.
    pub(super) fn driver_link_in(&self, mounts: &str, bdf: &str) -> Option<Option<String>> {
        let link = self.pci(bdf).join("driver");
        match self.shown(mounts, &link).and_then(fs::read_link) {
            Ok(link) => Some(Some(link.file_name()?.to_str()?.to_owned())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Some(None),
            Err(_) => None,
        }
    }

    /// The `driver_override` of `bdf`: `Some(None)` for none, which the
    /// kernel writes as `(null)`, and `None` when the attribute is
    /// unreadable, a mount [covers](Self::kernel) it, or its text, up to the one newline the kernel appends, begins or ends
    /// with whitespace. The kernel keeps an override byte for byte and
    /// matches it whole against a driver's name, so the trimmed text would
    /// name another override than the one the device holds.
    pub(crate) fn driver_override(&self, bdf: &str) -> Option<Option<String>> {
        let path = self.pci(bdf).join("driver_override");
        let value = Self::attribute(self.kernel(&path).ok()?)?;
        if value != value.trim() {
            return None;
        }
        Some(Some(value).filter(|value| value != "(null)" && !value.is_empty()))
    }
}

/// The `ip -batch` input that runs each of `commands` on its own line, or
/// `None` when `commands` contains an empty word, a word holding
/// whitespace, `#` (starts a comment) or `\` (can join lines), or a word
/// opening with a quote.
pub(crate) fn batch<'w, C>(commands: impl IntoIterator<Item = C>) -> Option<String>
where
    C: IntoIterator<Item = &'w str>,
{
    let mut input = String::new();
    for command in commands {
        for word in command {
            let special = |c: char| c == '#' || c == '\\' || c.is_whitespace();
            if word.is_empty() || word.contains(special) || word.starts_with(['"', '\'']) {
                return None;
            }
            input.push_str(word);
            input.push(' ');
        }
        input.push('\n');
    }
    Some(input)
}

/// Whether an `ip` process that has read `read`, the commands of its batch
/// so far, would resolve a word of `command` to another value than the word
/// names.
///
/// `ip` resolves a route's protocol, scope, realm and type of service
/// through one name file each, and keeps per file the last name it resolved
/// beside one result slot. A name equal to the kept name returns the slot
/// without a lookup, and a number is parsed into the slot while the kept
/// name stays, so a name read again after a number returns that number. The
/// state lasts for the process.
///
/// The test errs toward `true`. It takes the word after every word spelled
/// as one of a file's keywords as resolved through that file, whether or
/// not `ip` reads that position as the attribute, takes each part of a word
/// holding `/` apart, as `ip` does for a pair of realms, and takes a word
/// that opens with a digit or a sign as a number.
pub(crate) fn rereads_name_after_number(read: &[Vec<&str>], command: &[&str]) -> bool {
    const FILES: [&[&str]; 4] = [
        &["proto", "protocol"],
        &["scope"],
        &["realm", "realms"],
        &["tos", "dsfield", "tc"],
    ];
    fn resolved<'w>(command: &[&'w str], keywords: &[&str]) -> Vec<&'w str> {
        command
            .windows(2)
            .filter(|pair| keywords.contains(&pair[0]))
            .flat_map(|pair| pair[1].split('/'))
            .collect()
    }
    let numbered =
        |word: &str| word.starts_with(|c: char| c.is_ascii_digit() || c == '+' || c == '-');
    FILES.iter().any(|keywords| {
        let mut seen: Vec<&str> = read
            .iter()
            .flat_map(|earlier| resolved(earlier, keywords))
            .collect();
        resolved(command, keywords).into_iter().any(|word| {
            let reread = seen
                .iter()
                .position(|earlier| *earlier == word)
                .is_some_and(|first| {
                    seen[first + 1..]
                        .iter()
                        .any(|between| *between != word && numbered(between))
                });
            seen.push(word);
            reread
        })
    })
}

/// The device number a sysfs `dev` attribute states as `major:minor`, or
/// `None` when either part is missing or not a decimal `u32`.
pub(super) fn device_number(text: &str) -> Option<(u32, u32)> {
    let (major, minor) = text.trim().split_once(':')?;
    Some((major.parse().ok()?, minor.parse().ok()?))
}

/// The serial EBS reports for `volume`: `vol-0123` and `vol0123` both name
/// the controller whose serial reads `vol0123`.
pub(crate) fn serial_of(volume: &str) -> Option<String> {
    let digits = volume
        .strip_prefix("vol-")
        .or_else(|| volume.strip_prefix("vol"))?;
    (!digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| format!("vol{digits}"))
}

/// Whether `text` is a volume ID: `vol-` or `vol` followed by hexadecimal
/// digits, the grammar [`Host::resolve`] requires.
pub fn is_volume_id(text: &str) -> bool {
    serial_of(text).is_some()
}

/// The volume ID's `vol-` form.
pub(crate) fn volume_id_of(volume: &str) -> Option<String> {
    serial_of(volume).map(|serial| format!("vol-{}", &serial["vol".len()..]))
}
