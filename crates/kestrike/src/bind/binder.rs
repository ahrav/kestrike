//! Binding and release of the EBS controller and the dataplane ENI, through
//! the kernel's per-device PCI driver files, under the owner lock of the
//! invoked state directory.
//!
//! Bind checks the write-combining module before either device moves, and
//! records each device's original driver and override, and the ENI's
//! network state and next hops, in the mappings file before its first
//! driver write, so a bind that dies midway leaves a record `--release`
//! restores from.
//!
//! Owners on one host exclude each other per device through the host-wide
//! device locks and identify each other through their mappings files. A bind
//! takes each requested device's lock once, before it checks the other
//! owners' records, and holds it through the record's publication and the
//! driver move. A release takes every recorded device's lock, then refuses
//! when a given other owner's record names one of the devices, before it
//! restores anything.

use std::cell::Cell;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File};
use std::io;
use std::net::Ipv4Addr;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::thread;
use std::time::Duration;

use super::checkpoint;
use super::eni::{ENA_DRIVER, ENA_PCI, Eni, EniError, IpShows, NetState, Sighting, replay_order};
use super::group::GroupError;
use super::host::{Host, Kernel, batch, rereads_name_after_number, volume_id_of};
use super::identity::{Controller, IdentityError, LINKS_FOLLOWED};
use super::lock::{DEVICE_LOCKS, DeviceLock, OwnerLock};
use super::mappings::{EniBinding, Mappings, MappingsError, NvmeBinding};
use super::metadata::Metadata;
use super::wc::{WcError, WcManifest};
use crate::net::MAX_PEERS;

pub(crate) const VFIO: &str = "vfio-pci";
const KERNEL_DRIVER: &str = "nvme";
/// Lookups release makes, `NETDEV_INTERVAL` apart, for the ENI's network
/// device to return under its MAC, and the reruns of its network batch after
/// the device's name changes.
const NETDEV_RETURN: u32 = 50;
const NETDEV_INTERVAL: Duration = Duration::from_millis(100);

/// The dataplane ENI a bind moves, the peers whose next hops it records,
/// and the metadata service that resolves it.
#[derive(Clone, Copy)]
pub struct EniRequest<'r> {
    pub id: &'r str,
    pub peers: &'r [Ipv4Addr],
    pub metadata: &'r dyn Metadata,
}

/// What one bind moves: the volume's controller, the dataplane ENI, or
/// both, under the approved write-combining kernel and modules.
#[derive(Clone, Copy)]
pub struct BindRequest<'r> {
    pub volume: Option<&'r str>,
    pub eni: Option<EniRequest<'r>>,
    pub posture: VfioPosture,
    pub wc: &'r WcManifest,
    /// The state directories of this host's other owners; a device their
    /// mappings files record refuses.
    pub others: &'r [PathBuf],
}

/// Which VFIO postures this host may bind for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VfioPosture {
    /// Whether this host is on the no-IOMMU allowlist.
    pub allow_no_iommu: bool,
}

/// The ENI's first check hands its second the record the bind writes and
/// what the resolution saw.
struct EniChecked {
    binding: EniBinding,
    seen: Sighting,
}

/// A device's driver and override as last observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceState {
    pub bdf: String,
    pub driver: Option<String>,
    pub driver_override: Option<String>,
}

/// Why a bind or release refused or failed.
#[derive(Debug)]
pub enum BindError {
    /// Opening the owner lock file fails; a bind, release, or state-directory owner holds the owner lock (`WouldBlock`); another bind holds a requested device's lock; or the device lock directory is a link or grants group or other users access.
    Lock(io::Error),
    /// Another owner's state directory records the device at this address.
    OtherOwner {
        bdf: String,
        state_dir: PathBuf,
    },
    /// A mappings file already records a bound device; release it first.
    AlreadyBound,
    /// The request names no device, or an ENI with no peers or more than [`MAX_PEERS`].
    Request,
    /// The write-combining kernel or modules failed their check; nothing moved after it.
    Wc(WcError),
    Identity(IdentityError),
    Eni(EniError),
    /// The device is off its kernel driver, or its identity, driver or
    /// override changed between the two checks; or, at a release's restore,
    /// the device sits on a driver release may not unbind it from.
    Changed,
    /// `vfio-pci` is not loaded, or the VFIO mode contradicts the guest IOMMU or the allowlist.
    Posture,
    /// The device's IOMMU group holds anything but the device, its member
    /// listing cannot be read, or it is missing under a guest IOMMU. Only a
    /// listing whose open fails with `NotFound` represents an absent group.
    Group,
    /// The host's instance or boot ID is unreadable.
    Host,
    /// The mappings file is unreadable, malformed, or from another instance
    /// or boot; or another owner's given state directory, or the mappings
    /// file in it, is unreadable or malformed.
    Mappings(MappingsError),
    /// The recorded address no longer has its device's PCI identity, or sits
    /// on a driver other than `vfio-pci`, the recorded original driver, or none.
    NotRecorded(DeviceState),
    /// The ENI's device did not return under its MAC after release, so its network state was not restored.
    Network(DeviceState),
    /// A bind failed with the first error, and restoring the devices it moved failed with the second; the record stays for `--release`.
    Unrestored(Box<(BindError, BindError)>),
    /// The kernel refuses to open a recorded device's VFIO group file with
    /// `EBUSY`, as it does while a process holds that file or one of the
    /// group's devices, so its application still runs.
    VfioInUse,
    /// The VFIO group guard of a recorded device on `vfio-pci` cannot be
    /// verified, at the step named: `group` for its IOMMU group, `node` for
    /// the group device sysfs names and the file opened as it, `status` for
    /// the group's status.
    VfioGroup(&'static str),
    /// A driver step failed; `state` is the device's actual state afterwards.
    Step {
        step: &'static str,
        error: Option<io::Error>,
        state: DeviceState,
    },
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Step {
                step,
                error: Some(error),
                state,
            } => write!(f, "{step} failed: {error}; device now {state:?}"),
            Self::Step {
                step,
                error: None,
                state,
            } => write!(f, "{step} did not take effect; device now {state:?}"),
            other => write!(f, "{other:?}"),
        }
    }
}

impl std::error::Error for BindError {}

impl From<GroupError> for BindError {
    fn from(error: GroupError) -> Self {
        match error {
            GroupError::InUse => Self::VfioInUse,
            GroupError::Unverifiable(step) => Self::VfioGroup(step),
        }
    }
}

/// Which devices a restore may unbind from `vfio-pci`. No restore writes
/// the unbind file of any other driver: only another actor puts a device
/// there.
#[derive(Clone, Copy)]
enum VfioUnbind<'g> {
    /// Any: a failed bind restores the devices it moved itself, under the
    /// device locks it still holds.
    Moved,
    /// The devices whose VFIO group guard release holds.
    Guarded(&'g [&'g String]),
}

impl VfioUnbind<'_> {
    fn allows(self, bdf: &str, driver: &str) -> bool {
        driver == VFIO
            && match self {
                Self::Moved => true,
                Self::Guarded(guarded) => guarded.iter().any(|held| *held == bdf),
            }
    }
}

/// The validation [`Binder::release`] applies before it restores a device;
/// `kestrike-inspect` prints it with every report.
pub const RELEASE_SCOPE: &str = "kestrike-bind release revalidates the recorded BDF, the host's \
instance and boot identity, the module manifest, the PCI vendor and device ID, the driver state and \
the guards, and refuses a device another given owner's state directory records; a controller on \
vfio-pci reports no NVMe serial, so release identifies the volume by those facts alone";

/// Binds and releases the configured controller and dataplane ENI.
pub struct Binder<K: Kernel> {
    pub host: Host,
    pub kernel: K,
    pub state_dir: PathBuf,
}

/// The mappings file under `state_dir`.
pub fn mappings_path(state_dir: &Path) -> PathBuf {
    state_dir.join("mappings")
}

/// Checks that only root or `owner` can write `state_dir` or any directory
/// above it, or retarget a link on the way to it, so no other user can swap
/// in a planted lock or mappings file between this check and the opens
/// beneath the directory. Every component of `state_dir` as given and of its
/// canonical form, and every entry the resolution of `state_dir` reads on
/// the way, a link inside another link's target and the directories above
/// it included, must be owned by root or `owner`, and every directory among
/// them writable by neither group nor others.
///
/// # Errors
///
/// The first path, walking up the ancestors of `state_dir` as given and then
/// those of its canonical form, whose `lstat` fails, such as a missing one,
/// or reports an owner other than root or `owner`, or a non-link with a group
/// or other write bit; `state_dir` itself when its canonical form or, for a
/// relative path, the working directory cannot be resolved; otherwise the
/// first such entry the resolution reads, from the root down, spelled by the
/// link-free path that reaches it. A final component spelled with a trailing
/// `/`, `//` or `/.` makes `lstat` read the entry that a final link names.
pub fn private_state_dir(state_dir: &Path, owner: u32) -> Result<(), PathBuf> {
    private_canonical(state_dir, owner).map(drop)
}

/// Checks `state_dir` as [`private_state_dir`] does and returns its
/// canonical form. When `state_dir` is absolute, spelled exactly as its
/// components with plain names, and the walk reads no link, it is its own
/// canonical form; one walk then checks both chains and the path is returned
/// as given.
pub(crate) fn private_canonical(state_dir: &Path, owner: u32) -> Result<PathBuf, PathBuf> {
    let check = |component: &Path| {
        fs::symlink_metadata(component)
            .ok()
            .filter(|meta| {
                (meta.uid() == 0 || meta.uid() == owner)
                    && (meta.file_type().is_symlink() || meta.mode() & 0o022 == 0)
            })
            .ok_or_else(|| component.to_owned())
    };
    // In such a path every entry it names is one of its ancestors, each
    // spelled without a trailing separator, so each lstat reports the entry
    // itself, whether link, directory or file.
    let plain = state_dir.is_absolute()
        && !state_dir.components().any(|c| c == Component::ParentDir)
        && state_dir.components().collect::<PathBuf>().as_os_str() == state_dir.as_os_str();
    let mut linked = !plain;
    // A relative path's ancestors end with the empty path, the current
    // directory, whose chain the canonical form covers.
    for component in state_dir
        .ancestors()
        .filter(|component| !component.as_os_str().is_empty())
    {
        linked |= check(component)?.file_type().is_symlink();
    }
    if !linked {
        return Ok(state_dir.to_owned());
    }
    let canonical = fs::canonicalize(state_dir).map_err(|_| state_dir.to_owned())?;
    for component in canonical.ancestors() {
        check(component)?;
    }
    // A link's target can pass through further links, which neither chain
    // names; the resolution reads each of them and the directories above it.
    // The components still to resolve, the next one last.
    fn follow(pending: &mut Vec<OsString>, path: &Path) {
        pending.extend(path.components().rev().map(|c| c.as_os_str().to_owned()));
    }
    let mut pending = Vec::new();
    follow(&mut pending, state_dir);
    if state_dir.is_relative() {
        let start = std::env::current_dir().map_err(|_| state_dir.to_owned())?;
        follow(&mut pending, &start);
    }
    let mut resolved = PathBuf::from("/");
    let mut links = 0;
    while let Some(name) = pending.pop() {
        match Path::new(&name).components().next() {
            Some(Component::RootDir) => resolved = PathBuf::from("/"),
            Some(Component::ParentDir) => drop(resolved.pop()),
            Some(Component::Normal(name)) => {
                let entry = resolved.join(name);
                if !check(&entry)?.file_type().is_symlink() {
                    resolved = entry;
                    continue;
                }
                links += 1;
                // The kernel follows at most this many links in one resolution.
                if links > LINKS_FOLLOWED {
                    return Err(entry);
                }
                let target = fs::read_link(&entry).map_err(|_| entry.clone())?;
                follow(&mut pending, &target);
            }
            _ => {}
        }
    }
    Ok(canonical)
}

/// Creates `state_dir` where it is missing and checks that only root or
/// `owner` can reach or write it: the nearest existing ancestor passes
/// [`private_state_dir`] before anything is created beneath it, each missing
/// directory is created with mode `0o700`, top level first, only after the
/// path above it passes [`private_state_dir`], and the whole path passes
/// [`private_state_dir`] afterwards. A `name/../` detour can lead the path
/// above a missing level out of the nearest existing ancestor, so each
/// level's own parent is checked.
///
/// # Errors
///
/// `PermissionDenied` naming the component another user owns or could write;
/// otherwise the creation error.
pub fn prepare_state_dir(state_dir: &Path, owner: u32) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let shared = |component: PathBuf| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} must be a root-owned directory only root can write",
                component.display()
            ),
        )
    };
    let levels: Vec<&Path> = state_dir
        .ancestors()
        .map(|ancestor| {
            if ancestor.as_os_str().is_empty() {
                Path::new(".")
            } else {
                ancestor
            }
        })
        .collect();
    let missing = levels
        .iter()
        .take_while(|level| fs::symlink_metadata(level).is_err())
        .count();
    let existing = levels.get(missing).copied().unwrap_or(Path::new("/"));
    private_state_dir(existing, owner).map_err(shared)?;
    if missing == 0 {
        // Nothing to create: an existing entry that is no directory fails
        // as its creation does.
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(state_dir)?;
    }
    for depth in (0..missing).rev() {
        if depth + 1 < missing {
            private_state_dir(levels[depth + 1], owner).map_err(shared)?;
        }
        match fs::DirBuilder::new().mode(0o700).create(levels[depth]) {
            Ok(()) => {}
            Err(_) if levels[depth].is_dir() => {}
            Err(error) => return Err(error),
        }
    }
    private_state_dir(state_dir, owner).map_err(shared)
}

impl<K: Kernel> Binder<K> {
    fn state(&self, bdf: &str) -> DeviceState {
        DeviceState {
            bdf: bdf.to_owned(),
            driver: self.host.driver(bdf),
            driver_override: self.host.driver_override(bdf).flatten(),
        }
    }

    fn write(
        &self,
        step: &'static str,
        bdf: &str,
        path: PathBuf,
        value: &str,
    ) -> Result<(), BindError> {
        self.kernel
            .write(&path, value)
            .map_err(|error| BindError::Step {
                step,
                error: Some(error),
                state: self.state(bdf),
            })
    }

    fn expect(
        &self,
        step: &'static str,
        bdf: &str,
        driver: &str,
        driver_override: Option<&str>,
    ) -> Result<(), BindError> {
        // An unreadable override attribute verifies nothing, so the read that is judged is the read that is compared.
        let read = self.host.driver_override(bdf);
        let readable = read.is_some();
        let state = DeviceState {
            bdf: bdf.to_owned(),
            driver: self.host.driver(bdf),
            driver_override: read.flatten(),
        };
        if readable
            && state.driver.as_deref() == Some(driver)
            && state.driver_override.as_deref() == driver_override
        {
            Ok(())
        } else {
            Err(BindError::Step {
                step,
                error: None,
                state,
            })
        }
    }

    /// Checks the VFIO posture, and that `bdf` sits alone in its IOMMU group.
    fn vfio_ready(&self, bdf: &str, posture: VfioPosture) -> Result<(), BindError> {
        let sys = &self.host.sys;
        // A class that cannot be read establishes neither posture.
        let guest_iommu = self.host.guest_iommu().ok_or(BindError::Posture)?;
        // A kernel without the parameter has the unsafe mode off; a parameter
        // that cannot be read establishes neither posture, and neither does
        // one a mount of another type covers, whose absence says nothing of
        // the kernel's mode.
        let parameter = sys.join("module/vfio/parameters/enable_unsafe_noiommu_mode");
        let mounts = self.host.mount_table().map_err(|_| BindError::Posture)?;
        let shown = |entry| self.host.shown(&mounts, entry);
        let no_iommu = match shown(&parameter).and_then(fs::read_to_string) {
            Ok(value) => value.trim() == "Y",
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(_) => return Err(BindError::Posture),
        };
        let consistent = if guest_iommu {
            !no_iommu
        } else {
            no_iommu && posture.allow_no_iommu
        };
        let driver = sys.join("bus/pci/drivers").join(VFIO);
        if !shown(&driver).is_ok_and(Path::is_dir) || !consistent {
            return Err(BindError::Posture);
        }
        let members = self.host.pci(bdf).join("iommu_group/devices");
        let listing = shown(&members)
            .and_then(fs::read_dir)
            .map(|members| members.map(|entry| entry.map(|entry| entry.file_name())));
        sole_member(listing, bdf, guest_iommu)
    }

    /// The device's driver and override for the record, which release
    /// restores; an unreadable override records nothing.
    fn original_state(&self, bdf: &str) -> Option<DeviceState> {
        Some(DeviceState {
            bdf: bdf.to_owned(),
            driver: self.host.driver(bdf),
            driver_override: self.host.driver_override(bdf)?,
        })
    }

    /// Every check a bind needs, run once early and again immediately before
    /// the controller leaves its kernel driver; the claim holds the whole
    /// namespace until it drops.
    fn preflight(
        &self,
        volume: &str,
        posture: VfioPosture,
    ) -> Result<(Controller, DeviceState, File), BindError> {
        let controller = self.host.resolve(volume).map_err(BindError::Identity)?;
        let claim = self
            .host
            .check_unused(&controller.namespace)
            .map_err(BindError::Identity)?;
        self.vfio_ready(&controller.bdf, posture)?;
        let original = self
            .original_state(&controller.bdf)
            .ok_or(BindError::Identity(IdentityError::Attribute(
                "driver_override",
            )))?;
        if original.driver.as_deref() != Some(KERNEL_DRIVER) {
            return Err(BindError::Changed);
        }
        Ok((controller, original, claim))
    }

    /// Callers run ENI checks early and repeat them with the first `Sighting`
    /// immediately before the ENI leaves `ena`. The network read finishes
    /// `ip`, the `ip` programs started before; a read without them, or a
    /// repeated read, starts its own.
    fn eni_preflight(
        &self,
        request: &EniRequest<'_>,
        posture: VfioPosture,
        seen: Option<&Sighting>,
        ip: Option<IpShows<'_>>,
    ) -> Result<(Eni, NetState, Sighting), BindError> {
        let ip = Cell::new(ip);
        let (found, net, seen) =
            self.host
                .resolve_eni_while(&self.kernel, request.metadata, request.id, seen, |netdev| {
                    match ip.take() {
                        Some(ip) => self.host.net_state_from(ip, netdev),
                        None => self.host.net_state(&self.kernel, netdev),
                    }
                })
                .map_err(BindError::Eni)?;
        self.vfio_ready(&found.bdf, posture)?;
        Ok((found, net.map_err(BindError::Eni)?, seen))
    }

    /// `start_ip` overlaps the startup of the `ip` programs a network read
    /// finishes with the work before that read. A failed start leaves the
    /// read to start its own pair and report any failure from that attempt.
    fn start_ip(&self) -> Option<IpShows<'_>> {
        IpShows::start(&self.kernel).ok()
    }

    /// Builds the ENI record the bind writes: the resolution, the network
    /// state read beside its metadata requests, and the driver state release
    /// restores, with the peers' next hops left for `bind` to resolve under
    /// the device lock.
    ///
    /// # Errors
    ///
    /// The resolution's, VFIO and network-state refusals,
    /// `Attribute("local-ipv4s")` for a device whose addresses lack the
    /// metadata's address, and `Attribute("driver_override")` for an
    /// unreadable override.
    fn eni_first_check(
        &self,
        eni: &EniRequest<'_>,
        posture: VfioPosture,
    ) -> Result<EniChecked, BindError> {
        let ip = self.start_ip();
        let (found, net, seen) = self.eni_preflight(eni, posture, None, ip)?;
        if !net.holds(found.ipv4) {
            return Err(BindError::Eni(EniError::Attribute("local-ipv4s")));
        }
        let original = self
            .original_state(&found.bdf)
            .ok_or(BindError::Eni(EniError::Attribute("driver_override")))?;
        let binding = EniBinding {
            original_driver: ENA_DRIVER.to_owned(),
            original_override: original.driver_override,
            eni: found,
            net,
            next_hops: Vec::new(),
        };
        Ok(EniChecked { binding, seen })
    }

    /// Repeats the first check's resolution, network-state and VFIO checks
    /// with what that check saw, and refuses with `Changed` when the ENI,
    /// its driver state or its network configuration differs from the
    /// record. The caller holds the ENI's device lock from before this call
    /// through the move it guards.
    fn eni_second_check(
        &self,
        eni: &EniRequest<'_>,
        posture: VfioPosture,
        checked: EniChecked,
    ) -> Result<(), BindError> {
        // The `ip` programs start here, beside this check's metadata round,
        // so their 30-second run deadlines from spawn exclude the bind's
        // work between the two checks.
        let ip = self.start_ip();
        let EniChecked { binding, seen } = checked;
        let found = &binding.eni;
        let original = DeviceState {
            bdf: found.bdf.clone(),
            driver: Some(binding.original_driver.clone()),
            driver_override: binding.original_override.clone(),
        };
        let (again, net, _) = self.eni_preflight(eni, posture, Some(&seen), ip)?;
        if again != *found
            || !net.same_configuration(&binding.net)
            || self.original_state(&found.bdf) != Some(original)
        {
            return Err(BindError::Changed);
        }
        Ok(())
    }

    /// Binds the requested devices to `vfio-pci` and records them: each
    /// device's checks and the ENI's network state, with the write-combining
    /// check beside them, whose refusal comes first; then every requested
    /// device's lock, taken once and held until the bind returns, and one
    /// check of the other owners' records against every requested device;
    /// then the ENI's next hops; then the record, and only then the driver
    /// moves, the controller before the ENI, each after its checks and the
    /// loaded modules' identity repeat.
    ///
    /// # Errors
    ///
    /// `Lock` when another holder has a requested device's lock,
    /// `OtherOwner` when one of `request.others` records a requested device,
    /// and `Mappings` when one of `request.others` is not a readable
    /// directory or holds an unreadable, malformed or other-version file,
    /// all before any neighbor change. A refusal before the record is
    /// written writes no driver attribute;
    /// one in or after the next-hop resolution can leave the ENI's neighbor
    /// entries refreshed. Driver writes
    /// start only after a device's second check resolves it in the state the
    /// first check recorded. A refusal by a second check, or a failed driver
    /// step, restores the devices this bind moved where it can, removes the
    /// record once they are restored, and reports the device's actual state
    /// read after the restore. A device another actor has moved onto a third
    /// driver before the bind's unbind write arrives gets no unbind, from
    /// the move or from the rollback, and the bind answers `Unrestored`. A
    /// move that completes while that write waits for the device's lock is
    /// detached by it ([`Host::unbind_file`]); the bind then fails at its
    /// `bind` step and restores the device. A record that
    /// outlives a refusal before any
    /// driver write blocks every later bind until `release` removes it, so
    /// its removal error outranks the refusal, which the next run
    /// reproduces. `Unrestored` keeps the record for `--release`.
    pub fn bind(&self, request: &BindRequest<'_>) -> Result<Mappings, BindError> {
        let _lock = checkpoint::step("owner", "", || OwnerLock::acquire(&self.state_dir))
            .map_err(BindError::Lock)?;
        let path = mappings_path(&self.state_dir);
        let (controller, mut eni) = checkpoint::step("bindPreflight", "", || {
            if path.exists() {
                return Err(BindError::AlreadyBound);
            }
            if (request.volume.is_none() && request.eni.is_none())
                || request
                    .eni
                    .is_some_and(|eni| eni.peers.is_empty() || eni.peers.len() > MAX_PEERS)
            {
                return Err(BindError::Request);
            }
            let checks = || -> Result<_, BindError> {
                let controller = request
                    .volume
                    .map(|volume| {
                        self.preflight(volume, request.posture).map(
                            |(controller, original, claim)| (volume, controller, original, claim),
                        )
                    })
                    .transpose()?;
                let eni = request.eni.map(|eni| {
                    self.eni_first_check(&eni, request.posture)
                        .map(|checked| (eni, checked))
                });
                Ok((controller, eni.transpose()?))
            };
            // The write-combining check only reads module state, so it runs on
            // its own thread while the devices are checked, or on this thread
            // after them when that thread cannot start.
            let (host, manifest) = (&self.host, request.wc);
            let (wc, checked) = thread::scope(|scope| {
                let wc =
                    thread::Builder::new().spawn_scoped(scope, move || host.check_wc(manifest));
                let checked = checks();
                let wc = match wc {
                    Ok(handle) => handle
                        .join()
                        .unwrap_or_else(|panic| std::panic::resume_unwind(panic)),
                    Err(_) => host.check_wc(manifest),
                };
                (wc, checked)
            });
            wc.map_err(BindError::Wc)?;
            checked
        })?;
        let bdfs: Vec<&str> = controller
            .iter()
            .map(|(_, found, _, _)| found.bdf.as_str())
            .chain(
                eni.iter()
                    .map(|(_, checked)| checked.binding.eni.bdf.as_str()),
            )
            .collect();
        // Each device's lock, taken once, spans its ownership check, the
        // record's publication and its driver move, so no other owner that
        // takes the device lock records or moves the device meanwhile.
        let _devices = bdfs
            .iter()
            .map(|bdf| checkpoint::step("deviceLock", bdf, || self.lock_device(bdf)))
            .collect::<Result<Vec<_>, _>>()?;
        checkpoint::step("consultRecords", "", || {
            self.check_unrecorded(&bdfs, request.others)
        })?;
        // Resolving the next hops can remove and refresh neighbor entries,
        // a change to the ENI's network state, so it runs once the ownership
        // check passed, under the ENI's device lock, while the ENI is still
        // on `ena` and its network device still names its function.
        if let Some((wanted, checked)) = eni.as_mut() {
            let binding = &mut checked.binding;
            let bdf = binding.eni.bdf.as_str();
            if self.host.driver(bdf).as_deref() != Some(ENA_DRIVER)
                || self.host.netdev_function(&binding.eni.netdev).as_deref() != Some(bdf)
            {
                return Err(BindError::Changed);
            }
            binding.next_hops = checkpoint::step("resolveHops", bdf, || {
                self.host
                    .next_hops(&self.kernel, &binding.eni, wanted.peers)
            })
            .map_err(BindError::Eni)?;
        }
        let (instance, boot) = self.host.shown_instance_and_boot().ok_or(BindError::Host)?;
        let nvme = controller
            .as_ref()
            .map(|(volume, controller, original, _)| {
                Ok::<_, BindError>(NvmeBinding {
                    volume: volume_id_of(volume)
                        .ok_or(BindError::Identity(IdentityError::VolumeId))?,
                    bdf: controller.bdf.clone(),
                    nsid: controller.nsid,
                    sector_size: controller.sector_size,
                    capacity: controller.capacity,
                    original_driver: KERNEL_DRIVER.to_owned(),
                    original_override: original.driver_override.clone(),
                })
            })
            .transpose()?;
        let mappings = Mappings {
            instance,
            boot,
            wc: request.wc.clone(),
            nvme,
            eni: eni.as_ref().map(|(_, checked)| checked.binding.clone()),
        };
        checkpoint::step("publish", "", || mappings.write(&path)).map_err(|error| {
            BindError::Step {
                step: "mappings",
                error: Some(error),
                state: self.state(mappings.first_bdf()),
            }
        })?;
        let mut moved = Vec::new();
        if let Err(error) = self.move_recorded(request, controller, eni, &mut moved) {
            let error = match self.restore_moved(&mappings, &moved) {
                Ok(()) => match checkpoint::step("unlink", "", || Mappings::discard(&path)) {
                    Err(discard) if moved.is_empty() => BindError::Step {
                        step: "mappings",
                        error: Some(discard),
                        state: self.state(mappings.first_bdf()),
                    },
                    _ => error,
                },
                Err(restore) => return Err(BindError::Unrestored(Box::new((error, restore)))),
            };
            return Err(match error {
                BindError::Step { step, error, state } => BindError::Step {
                    step,
                    error,
                    state: self.state(&state.bdf),
                },
                other => other,
            });
        }
        Ok(mappings)
    }

    /// Repeats each device's checks and the loaded modules' identity under
    /// the device locks the caller holds, then moves it, the controller
    /// first, noting each device in `moved` before its first driver write.
    /// Every bind holds a device's lock from its ownership check through its
    /// move, so of two binds naming one device, the second finds it locked,
    /// recorded or on `vfio-pci` and moves nothing.
    fn move_recorded(
        &self,
        request: &BindRequest<'_>,
        controller: Option<(&str, Controller, DeviceState, File)>,
        eni: Option<(EniRequest<'_>, EniChecked)>,
        moved: &mut Vec<String>,
    ) -> Result<(), BindError> {
        if let Some((volume, controller, original, first_claim)) = controller {
            drop(first_claim);
            let (again, state, claim) = checkpoint::step("secondCapture", &controller.bdf, || {
                self.preflight(volume, request.posture)
            })?;
            if again != controller || state != original {
                return Err(BindError::Changed);
            }
            self.host
                .check_wc_loaded(request.wc)
                .map_err(BindError::Wc)?;
            moved.push(controller.bdf.clone());
            self.move_to_vfio(&controller.bdf, KERNEL_DRIVER, Some(claim))?;
        }
        if let Some((eni, checked)) = eni {
            let bdf = checked.binding.eni.bdf.clone();
            checkpoint::step("secondCapture", &bdf, || {
                self.eni_second_check(&eni, request.posture, checked)
            })?;
            self.host
                .check_wc_loaded(request.wc)
                .map_err(BindError::Wc)?;
            moved.push(bdf.clone());
            self.move_to_vfio(&bdf, ENA_DRIVER, None)?;
        }
        Ok(())
    }

    fn lock_device(&self, bdf: &str) -> Result<DeviceLock, BindError> {
        DeviceLock::acquire(&self.host.under_root(Path::new(DEVICE_LOCKS)), bdf)
            .map_err(BindError::Lock)
    }

    /// Refuses with `OtherOwner` when a mappings file in one of `others`
    /// records one of `bdfs`, and with `Mappings` when one of `others` is
    /// not a readable directory or holds a mappings file that is
    /// unreadable, malformed or of another format version. It visits
    /// `others` in order, reads each present mappings file once, matches
    /// every address in `bdfs` against it, and returns the first refusal. The
    /// caller holds every device lock of `bdfs`, so each other owner that
    /// takes the device locks keeps its record of those devices unchanged
    /// meanwhile. An entry naming this binder's own state directory, by
    /// device and inode, is skipped, so one list of every owner's directory
    /// serves each owner.
    fn check_unrecorded(&self, bdfs: &[&str], others: &[PathBuf]) -> Result<(), BindError> {
        let own = fs::metadata(&self.state_dir).ok();
        for state_dir in others {
            let directory =
                fs::metadata(state_dir).map_err(|e| BindError::Mappings(MappingsError::Io(e)))?;
            if !directory.is_dir() {
                return Err(BindError::Mappings(MappingsError::Format(
                    "state directory",
                )));
            }
            let identity = |meta: &fs::Metadata| (meta.dev(), meta.ino());
            if own.as_ref().map(identity) == Some(identity(&directory)) {
                continue;
            }
            let mappings = match Mappings::read(&mappings_path(state_dir)) {
                Ok(mappings) => mappings,
                Err(MappingsError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                    continue;
                }
                Err(error) => return Err(BindError::Mappings(error)),
            };
            let mut recorded = mappings
                .nvme
                .iter()
                .map(|n| &n.bdf)
                .chain(mappings.eni.iter().map(|e| &e.eni.bdf));
            if let Some(bdf) = recorded.find(|other| bdfs.contains(&other.as_str())) {
                return Err(BindError::OtherOwner {
                    bdf: bdf.clone(),
                    state_dir: state_dir.clone(),
                });
            }
        }
        Ok(())
    }

    /// Moves `bdf` from `driver`, the kernel driver the second check found
    /// it on, to `vfio-pci` through its own override, releasing `claim`
    /// between the unbind and the bind. The unbind goes through `driver`'s
    /// own [unbind file](Host::unbind_file), which the kernel refuses with
    /// `ENODEV` when another driver holds the device as the write arrives,
    /// so a device moved before then gets no unbind.
    fn move_to_vfio(&self, bdf: &str, driver: &str, claim: Option<File>) -> Result<(), BindError> {
        self.write(
            "override",
            bdf,
            self.host.pci(bdf).join("driver_override"),
            VFIO,
        )?;
        self.write("unbind", bdf, self.host.unbind_file(driver), bdf)?;
        drop(claim);
        self.write("bind", bdf, self.host.bind_file(VFIO), bdf)?;
        self.expect("bind", bdf, VFIO, Some(VFIO))
    }

    /// Restores the recorded devices whose address is in `moved`, under the
    /// device locks the bind holds, the ENI with its network state.
    fn restore_moved(&self, mappings: &Mappings, moved: &[String]) -> Result<(), BindError> {
        let nvme = mappings
            .nvme
            .as_ref()
            .filter(|n| moved.contains(&n.bdf))
            .map_or(Ok(()), |n| {
                let (driver, original) = (&n.original_driver, n.original_override.as_deref());
                self.restore(&n.bdf, driver, original, VfioUnbind::Moved)
            });
        let eni = mappings
            .eni
            .as_ref()
            .filter(|e| moved.contains(&e.eni.bdf))
            .map_or(Ok(()), |e| self.restore_eni(e, VfioUnbind::Moved));
        nvme.and(eni)
    }

    /// Restores every recorded device under the device locks the caller
    /// holds, the ENI with its network state, unbinding from `vfio-pci` only
    /// the devices in `guarded`.
    fn restore_recorded(&self, mappings: &Mappings, guarded: &[&String]) -> Result<(), BindError> {
        let unbind = VfioUnbind::Guarded(guarded);
        let nvme = mappings.nvme.as_ref().map_or(Ok(()), |n| {
            let (driver, original) = (&n.original_driver, n.original_override.as_deref());
            self.restore(&n.bdf, driver, original, unbind)
        });
        let eni = mappings
            .eni
            .as_ref()
            .map_or(Ok(()), |e| self.restore_eni(e, unbind));
        nvme.and(eni)
    }

    fn restore_eni(&self, binding: &EniBinding, unbind: VfioUnbind<'_>) -> Result<(), BindError> {
        self.restore(
            &binding.eni.bdf,
            &binding.original_driver,
            binding.original_override.as_deref(),
            unbind,
        )?;
        self.restore_net(binding)
    }

    /// Finds the ENI's network device again by its MAC once `ena` holds it,
    /// then restores its MTU, link state, addresses and routes, in that
    /// order with host-scope routes first, then link-scope routes and every
    /// other route with no gateway, then the rest, through one or more
    /// `ip -batch` runs (see [`Self::restore_net_at`]) that name the device
    /// by its interface index. Each address is assigned with a forever
    /// lifetime and stays until removed; renewing a DHCP lease or handing
    /// the device back to a network manager is the deployment's step after
    /// release.
    ///
    /// The kernel names a returning device by enumeration, and udev may rename
    /// it at any time. A rename keeps the index, so it fails no command of a
    /// running batch; one that lands before the index is read fails the
    /// replay before its first command. A failed replay looks the device up
    /// again and runs again from its first command, each of which sets or
    /// replaces state, when the device's name changed: at once, or one
    /// interval later for a rename still pending when the replay failed. A
    /// failure under an unchanged name, or after [`NETDEV_RETURN`] reruns,
    /// fails the step with that replay's error; a lookup that finds no
    /// device fails it as `Network`.
    fn restore_net(&self, binding: &EniBinding) -> Result<(), BindError> {
        let mut netdev = self.returned_netdev(binding)?;
        let mut renames = 0;
        loop {
            let error = match self.restore_net_as(binding, &netdev) {
                Ok(()) => return Ok(()),
                Err(error) => error,
            };
            let mut now = self.returned_netdev(binding)?;
            if now == netdev {
                self.kernel.settle(NETDEV_INTERVAL);
                now = self.returned_netdev(binding)?;
            }
            if now == netdev || renames == NETDEV_RETURN {
                return Err(error);
            }
            renames += 1;
            netdev = now;
        }
    }

    /// The ENI's network device under `ena`, found by its MAC and recorded PCI function within [`NETDEV_RETURN`] lookups.
    fn returned_netdev(&self, binding: &EniBinding) -> Result<String, BindError> {
        (0..NETDEV_RETURN)
            .find_map(|attempt| {
                if attempt > 0 {
                    self.kernel.settle(NETDEV_INTERVAL);
                }
                let found: Vec<String> = self
                    .host
                    .netdevs_with_mac(binding.eni.mac)
                    .ok()?
                    .into_iter()
                    .filter(|netdev| {
                        self.host.netdev_function(netdev).as_deref()
                            == Some(binding.eni.bdf.as_str())
                    })
                    .collect();
                <[String; 1]>::try_from(found).ok().map(|[one]| one)
            })
            .ok_or_else(|| BindError::Network(self.state(&binding.eni.bdf)))
    }

    /// Restores the recorded MTU, link state, addresses and routes on the
    /// ENI, found as `netdev`, through one or more `ip -batch` runs (see
    /// [`Self::restore_net_at`]).
    ///
    /// A name can pass to another device: udev renames the ENI, and the
    /// kernel gives the vacated enumerated name to the next device that
    /// reaches a driver. Every command therefore names the device by its
    /// interface index, which the kernel never moves between devices. The
    /// index counts only when the device it was read from sits on the
    /// recorded function ([`Host::netdev_index_on`]);
    /// [`Self::restore_net_at`] then replays the record at that index.
    /// Otherwise the step fails as `NotFound` before any command runs, and
    /// the caller looks the device up again.
    pub(super) fn restore_net_as(
        &self,
        binding: &EniBinding,
        netdev: &str,
    ) -> Result<(), BindError> {
        let index = self
            .host
            .netdev_index_on(netdev, &binding.eni.bdf)
            .ok_or_else(|| BindError::Step {
                step: "network",
                error: Some(io::ErrorKind::NotFound.into()),
                state: self.state(&binding.eni.bdf),
            })?;
        self.restore_net_at(binding, index)
    }

    /// Restores the recorded MTU, link state, addresses and routes on the
    /// device at interface index `index` through one `ip -batch` whose every
    /// command names the device as `if<index>`, or through more, each
    /// continuing where the one before ended, when one `ip` process would
    /// misread a route's words as [`rereads_name_after_number`] tells.
    ///
    /// `ip` reads a device word as a name or altname before it reads `if<N>`
    /// as an index, so the word counts only when `ip -o link show` lists no
    /// other device holding it; a device that takes the word after that
    /// listing and before a command takes the command. A word another device
    /// holds fails the step as `NotFound` before any command runs.
    pub(super) fn restore_net_at(&self, binding: &EniBinding, index: u32) -> Result<(), BindError> {
        let failed = |error| BindError::Step {
            step: "network",
            error: Some(error),
            state: self.state(&binding.eni.bdf),
        };
        let device = format!("if{index}");
        let netdev = device.as_str();
        let listing = self
            .kernel
            .run("ip", &["-o", "link", "show"], "")
            .map_err(failed)?;
        if held_elsewhere(&listing, netdev, index) {
            return Err(failed(io::ErrorKind::NotFound.into()));
        }
        let NetState {
            mtu,
            up,
            addresses,
            routes,
        } = &binding.net;
        let mtu_text = mtu.to_string();
        let set_mtu = vec!["link", "set", "dev", netdev, "mtu", mtu_text.as_str()];
        let link = vec![
            "link",
            "set",
            "dev",
            netdev,
            if *up { "up" } else { "down" },
        ];
        let addresses = addresses.iter().map(|address| {
            let mut words = vec!["addr", "replace"];
            words.extend(address.split_whitespace());
            words.extend(["dev", netdev]);
            words
        });
        // The kernel refuses a route through a gateway that no route of a
        // nearer scope reaches ("Nexthop has invalid gateway"), and the
        // listing may show a gateway route before the route that reaches its
        // gateway. Host-scope routes therefore replay first, then link-scope
        // routes and every other route with no gateway, then the rest, each
        // group in recorded order.
        let mut ordered: Vec<&String> = routes.iter().collect();
        ordered.sort_by_cached_key(|route| replay_order(route));
        let routes = ordered.into_iter().map(|route| {
            let mut words = vec!["route", "replace"];
            words.extend(route.split_whitespace());
            words.extend(["dev", netdev]);
            words
        });
        let commands: Vec<Vec<&str>> = [set_mtu, link]
            .into_iter()
            .chain(addresses)
            .chain(routes)
            .collect();
        let mut processes: Vec<Vec<Vec<&str>>> = Vec::new();
        let mut current: Vec<Vec<&str>> = Vec::new();
        for command in commands {
            if !current.is_empty() && rereads_name_after_number(&current, &command) {
                processes.push(std::mem::take(&mut current));
            }
            current.push(command);
        }
        processes.push(current);
        // Every input is built before the first run, so a word `ip -batch` cannot pass fails the step with nothing replayed.
        let inputs = processes
            .into_iter()
            .map(batch)
            .collect::<Option<Vec<String>>>()
            .ok_or_else(|| failed(io::ErrorKind::InvalidInput.into()))?;
        // `ip -batch` stops at the first command that fails, and the first run that fails ends the replay.
        inputs.iter().try_for_each(|input| {
            self.kernel
                .run("ip", &["-batch", "-"], input)
                .map(drop)
                .map_err(failed)
        })
    }

    /// Returns `bdf` to its recorded driver and override.
    ///
    /// An unbound device binds with its override set to the original
    /// driver's name, since the PCI core matches a device that has an
    /// override against the named driver alone. The recorded override is
    /// written after the bind. A device found on a driver other than its
    /// original one is unbound only as `unbind` allows; otherwise, or when
    /// its driver cannot be read, the restore refuses with `Changed` and
    /// leaves the device where it is. A failed bind's restore first writes
    /// the recorded override back over the `vfio-pci` override the bind
    /// wrote, when the device still carries it; no other refusal writes.
    /// The unbind goes to that driver's own
    /// [unbind file](Host::unbind_file), which the kernel refuses when
    /// another actor has moved the device off it before the write arrives.
    fn restore(
        &self,
        bdf: &str,
        original_driver: &str,
        original_override: Option<&str>,
        unbind: VfioUnbind<'_>,
    ) -> Result<(), BindError> {
        let override_file = self.host.pci(bdf).join("driver_override");
        let found = self.host.driver_link(bdf).ok_or(BindError::Changed)?;
        if let Some(driver) = found.filter(|driver| driver != original_driver) {
            if !unbind.allows(bdf, &driver) {
                // The bind wrote its override before its unbind was refused.
                if matches!(unbind, VfioUnbind::Moved)
                    && self.host.driver_override(bdf).flatten().as_deref() == Some(VFIO)
                {
                    self.write(
                        "override",
                        bdf,
                        override_file,
                        original_override.unwrap_or("\n"),
                    )?;
                }
                return Err(BindError::Changed);
            }
            self.write("unbind", bdf, self.host.unbind_file(&driver), bdf)?;
        }
        if self.host.driver_link(bdf) == Some(None) {
            self.write("override", bdf, override_file.clone(), original_driver)?;
            self.write("bind", bdf, self.host.bind_file(original_driver), bdf)?;
        }
        let recorded = original_override.unwrap_or("\n");
        self.write("override", bdf, override_file, recorded)?;
        self.expect("restore", bdf, original_driver, original_override)
    }

    /// Restores every recorded device once the application stopped, the
    /// ENI with its network state, then removes the mappings file. Its
    /// validation is the one [`RELEASE_SCOPE`] states.
    ///
    /// Before its first write, release checks the running kernel and the
    /// loaded VFIO modules against the recorded manifest, then opens a VFIO
    /// group guard for every recorded device on `vfio-pci`. It holds the
    /// guards and the device locks through every unbind and restore, so no
    /// process opens one of those groups meanwhile. A device already on its
    /// recorded driver, or unbound, goes straight to restore. Once it holds
    /// every recorded device's lock, release refuses with `OtherOwner` when
    /// the mappings file of one of `others`, the state directories of this
    /// host's other owners, records one of those devices, before any device
    /// check, restore or record change. Release protects the bindings of the
    /// owners `others` names; another owner's device on `vfio-pci` is
    /// protected only by its group guard, which refuses while that owner's
    /// application holds the group.
    ///
    /// # Errors
    ///
    /// `Lock` while the owner runs or another holder has a recorded device's
    /// lock, taken for every recorded device before any device's checks and
    /// held through the restores; `OtherOwner` when another owner's directory
    /// records a recorded device, checked once every lock is held and before
    /// any `NotRecorded` check; `Mappings` for an unreadable or malformed
    /// file, a file of another format version, or a file from another
    /// instance or boot, and for one of `others` that is not a readable
    /// directory or holds an unreadable, malformed or other-version file;
    /// `Wc` when the running kernel or VFIO modules differ from the recorded
    /// manifest; `NotRecorded` when an address no longer holds its
    /// recorded device on `vfio-pci`, its original driver or none, or its
    /// driver cannot be read;
    /// `VfioInUse` while the kernel refuses a recorded device's VFIO group
    /// file because a process holds that file or one of the group's devices;
    /// `VfioGroup` when a guard cannot be verified; `Changed` when a device
    /// sits at its restore on a driver release may not unbind it from,
    /// `vfio-pci` without a guard or any third driver, which then writes
    /// nothing for it; `Network` when the ENI's device does not
    /// return; or the failed step with the device's actual state. The
    /// unlink runs only once every recorded device is restored. Every
    /// refusal and failure keeps the file, a failed unlink included, except
    /// a directory open or sync failing after the unlink, which returns its
    /// error as the `mappings` step with the file already removed.
    pub fn release(&self, others: &[PathBuf]) -> Result<(), BindError> {
        let _lock = checkpoint::step("owner", "", || OwnerLock::acquire(&self.state_dir))
            .map_err(BindError::Lock)?;
        let path = mappings_path(&self.state_dir);
        let mappings = checkpoint::step("readRecord", "", || Mappings::read(&path))
            .map_err(BindError::Mappings)?;
        let (instance, boot) = self.host.shown_instance_and_boot().ok_or(BindError::Host)?;
        mappings
            .check_current(&instance, &boot)
            .map_err(BindError::Mappings)?;
        self.host
            .check_wc_running(&mappings.wc)
            .map_err(BindError::Wc)?;
        let controller = [self.host.controller_identity().pci];
        let devices: Vec<_> = mappings
            .nvme
            .iter()
            .map(|n| (&n.bdf, &n.original_driver, &controller[..]))
            .chain(
                mappings
                    .eni
                    .iter()
                    .map(|e| (&e.eni.bdf, &e.original_driver, &ENA_PCI[..])),
            )
            .collect();
        let bdfs: Vec<&str> = devices.iter().map(|(bdf, _, _)| bdf.as_str()).collect();
        let locks = bdfs
            .iter()
            .map(|bdf| checkpoint::step("deviceLock", bdf, || self.lock_device(bdf)))
            .collect::<Result<Vec<_>, _>>()?;
        checkpoint::step("releaseConsult", "", || {
            self.check_unrecorded(&bdfs, others)
        })?;
        let mut on_vfio = Vec::new();
        for (bdf, original, ids) in devices {
            let state = self.state(bdf);
            let driver_ok = self.host.driver_link(bdf).is_some_and(|driver| {
                matches!(driver.as_deref(), None | Some(VFIO)) || driver.as_ref() == Some(original)
            });
            if !self.host.pci_id(bdf).is_some_and(|id| ids.contains(&id)) || !driver_ok {
                return Err(BindError::NotRecorded(state));
            }
            if state.driver.as_deref() == Some(VFIO) {
                on_vfio.push(bdf);
            }
        }
        let guards = on_vfio
            .iter()
            .map(|bdf| checkpoint::guard(bdf, || self.host.guard_group(&self.kernel, bdf)))
            .collect::<Result<Vec<File>, _>>()?;
        self.restore_recorded(&mappings, &on_vfio)?;
        drop(guards);
        // The record goes before the device locks, so a bind that takes a
        // released device's lock finds no stale record of it.
        let discarded =
            checkpoint::step("unlink", "", || Mappings::discard(&path)).map_err(|error| {
                BindError::Step {
                    step: "mappings",
                    error: Some(error),
                    state: self.state(mappings.first_bdf()),
                }
            });
        drop(locks);
        discarded
    }
}

/// Checks that `bdf` sits alone in the IOMMU group whose members `listing`
/// yields. A listing whose open fails with `NotFound` names an absent group,
/// which only a host without a guest IOMMU accepts; every other open or
/// iteration error refuses with `Group`.
pub(super) fn sole_member(
    listing: io::Result<impl Iterator<Item = io::Result<OsString>>>,
    bdf: &str,
    guest_iommu: bool,
) -> Result<(), BindError> {
    match listing {
        Ok(members) => match members.collect::<io::Result<Vec<_>>>() {
            Ok(members) if members.len() == 1 && members[0] == *bdf => Ok(()),
            _ => Err(BindError::Group),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound && !guest_iommu => Ok(()),
        Err(_) => Err(BindError::Group),
    }
}

/// Whether `listing`, the output of `ip -o link show`, shows a device other
/// than the one at interface index `index` holding `word` as its name or an
/// altname. Each device prints on one line, led by its index and its name
/// closed by a colon, with a backslash where each line of its listing ends:
/// `3: d1: <BROADCAST> ...\    altname x9\    altname if2`. A VLAN prints its
/// lower device after its name, as `4: d0.5@d0:`. A line that does not open
/// with an index counts as holding the word, so the check refuses what it
/// cannot read.
pub(super) fn held_elsewhere(listing: &str, word: &str, index: u32) -> bool {
    listing
        .lines()
        .filter(|line| !line.trim().is_empty())
        .any(|line| {
            let mut words = line.split_whitespace();
            let leading = words
                .next()
                .and_then(|first| first.strip_suffix(':'))
                .and_then(|first| first.parse::<u32>().ok());
            let Some(leading) = leading else {
                return true;
            };
            let name = words
                .next()
                .and_then(|second| second.strip_suffix(':'))
                .map(|second| second.split_once('@').map_or(second, |(name, _)| name));
            let mut altnames = Vec::new();
            while let Some(token) = words.next() {
                if token == "altname" {
                    altnames.extend(words.next().map(|name| name.trim_end_matches('\\')));
                }
            }
            leading != index && (name == Some(word) || altnames.contains(&word))
        })
}
