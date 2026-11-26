//! Identity and use of the EBS volume's controller, read from the kernel's
//! device tree while the controller is still on its kernel driver.
//!
//! EBS reports a volume's ID, without its hyphen, as the controller's serial:
//! `vol-0123` is the controller whose serial reads `vol0123`, padded with
//! spaces. Resolution reads only directory listings, attribute files and
//! symbolic links. The in-use check also reads the mount, swap and process
//! tables and the device nodes, failing closed when one is unreadable. The
//! check then opens the namespace's node with `O_EXCL`; this exclusive claim
//! conflicts with a mount, swap area, or holder of the namespace or a
//! partition. The claim counts only once the opened descriptor itself, read
//! with `fstat`, is a block device whose device number is the one the
//! namespace's sysfs block class entry names, so the claim and the later
//! driver writes refer to the kernel object the sysfs resolution named.

use std::borrow::Cow;
use std::cell::{Cell, OnceCell};
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::panic;
use std::path::{Component, Path, PathBuf};
use std::thread::{self, JoinHandle};

use super::changes::{Changes, Pass};
use super::host::{Host, device_number, serial_of};
use super::walk::Node;

/// The EBS controller's PCI vendor and device.
const EBS_PCI: (u16, u16) = (0x1d0f, 0x8061);
const EBS_MODEL: &str = "Amazon Elastic Block Store";

/// The model and PCI vendor and device of the controllers that resolution
/// accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ControllerIdentity {
    pub(crate) model: &'static str,
    pub(crate) pci: (u16, u16),
}

impl ControllerIdentity {
    /// An EBS volume's controller, the only identity production accepts.
    pub(crate) const EBS: Self = Self {
        model: EBS_MODEL,
        pci: EBS_PCI,
    };
}

/// Bytes per sector of a block device's `size` attribute.
const SECTOR: u64 = 512;

/// Passes over the SCSI target's file backstores one reading makes before it
/// refuses: one, and one more for each pass an adapter or a backstore was
/// added under. A host whose backstores are created faster than the passes
/// complete is refused.
const BACKSTORE_PASSES: u32 = 8;

/// Passes over the loop devices, or over the Xen block backends, one reading
/// makes before it refuses: one, and one more for each pass the host's
/// uevent counter moved across. A host that sends uevents faster than the
/// passes complete is refused.
const UEVENT_PASSES: u32 = 8;

/// Passes over the USB gadget LUNs one reading makes before it refuses: one,
/// and one more for each pass a gadget changed under. A host whose gadgets
/// are rewritten faster than the passes complete is refused.
const LUN_PASSES: u32 = 8;

/// Passes over the NVMe target namespaces one reading makes before it
/// refuses: one, and one more for each pass a subsystem changed under. A
/// host whose target namespaces are rewritten faster than the passes
/// complete is refused.
const TARGET_PASSES: u32 = 8;

/// Passes over the OCFS2 heartbeat regions one reading makes before it
/// refuses: one, and one more for each pass a cluster changed under. A host
/// whose regions are rewritten faster than the passes complete is refused.
const HEARTBEAT_PASSES: u32 = 8;

/// Readings of the RNBD export listing one check makes before it refuses:
/// it returns once two readings in a row list the same exports.
const RNBD_PASSES: u32 = 8;

/// `LOOP_GET_STATUS64`.
const LOOP_GET_STATUS64: libc::Ioctl = 0x4c05;

/// `struct loop_info64`. The kernel fills `device`, `inode` and `rdevice`
/// from the backing file's attributes: the device number of its filesystem,
/// its inode, and the device it is the node of, zero for a regular file.
#[repr(C)]
struct LoopInfo {
    device: u64,
    inode: u64,
    rdevice: u64,
    offset: u64,
    sizelimit: u64,
    number: u32,
    encrypt_type: u32,
    encrypt_key_size: u32,
    flags: u32,
    file_name: [u8; 64],
    crypt_name: [u8; 64],
    encrypt_key: [u8; 32],
    init: [u64; 2],
}

// The request number does not encode a size, so the kernel writes its whole
// 232-byte record.
const _: () = assert!(size_of::<LoopInfo>() == 232);

/// The resolved controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Controller {
    pub bdf: String,
    /// The namespace's block device name, `nvme<c>n<n>`.
    pub namespace: String,
    pub nsid: u32,
    pub sector_size: u32,
    pub capacity: u64,
}

/// Why resolution refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// The volume ID is not `vol-` or `vol` followed by hexadecimal digits.
    VolumeId,
    /// No controller's serial is the volume ID.
    NotFound,
    /// More than one controller reports the volume ID.
    Duplicate,
    /// The controller's model or PCI identity is not an EBS volume's.
    NotEbs,
    /// The controller holds no namespace, or more than one.
    Namespaces(usize),
    /// An identity or geometry attribute is missing or malformed.
    Attribute(&'static str),
    /// The namespace or a partition is mounted, swapped on, held, open or under an OCFS2 heartbeat region; the string names it.
    InUse(String),
    /// A partition or holder listing, the mount, swap or process table, a
    /// loop device or SCSI target backstore listing, an OCFS2 cluster or
    /// heartbeat region listing or a heartbeat region's device entry, a
    /// device node, the claimed descriptor's metadata, or the namespace's
    /// sysfs device number is unreadable, or that device number is not
    /// `major:minor`, or the pNFS block layout client is in use, built into
    /// the kernel, or its use count or the kernel's symbol table is
    /// unreadable, so the device's use or identity is unknown.
    Unverifiable(&'static str),
    /// The descriptor the exclusive open returned is not the block device
    /// the namespace's sysfs entry names; the string names the namespace.
    Substituted(String),
}

impl Host {
    /// Finds the one controller whose serial is `volume`, requires the
    /// host's expected controller identity, an EBS volume's in production,
    /// and reads its namespace's identity and geometry.
    ///
    /// # Errors
    ///
    /// In this order: `VolumeId`, `Unverifiable("mounts")` for an
    /// unreadable mount table, `NotFound` for an unreadable controller
    /// listing, `Attribute("serial")` for a controller whose serial is
    /// unreadable, `Duplicate` or `NotFound`,
    /// `Attribute("device")`, `NotEbs`, `Attribute("namespace")`,
    /// `Namespaces`, then `Attribute` for the namespace's geometry. An
    /// entry a mount [covers](Self::shown) is unreadable.
    pub fn resolve(&self, volume: &str) -> Result<Controller, IdentityError> {
        let serial = serial_of(volume).ok_or(IdentityError::VolumeId)?;
        let class = self.sys.join("class/nvme");
        let mounts = self
            .mount_table()
            .map_err(|_| IdentityError::Unverifiable("mounts"))?;
        let shown = |entry: &Path| self.shown(&mounts, entry).ok().and_then(Self::read);
        let identity =
            |entry: &Path| (self.shown(&mounts, entry).ok()).and_then(Self::identity_field);
        let mut matched = None;
        let controllers = (self.shown(&mounts, &class))
            .and_then(fs::read_dir)
            .map_err(|_| IdentityError::NotFound)?;
        for entry in controllers {
            let entry = entry.map_err(|_| IdentityError::NotFound)?;
            // Every controller's serial must be readable to show the match unique.
            let found =
                identity(&entry.path().join("serial")).ok_or(IdentityError::Attribute("serial"))?;
            if found == serial && matched.replace(entry.path()).is_some() {
                return Err(IdentityError::Duplicate);
            }
        }
        let controller = matched.ok_or(IdentityError::NotFound)?;
        let function = controller.join("device");
        let bdf = (self.shown(&mounts, &function))
            .and_then(fs::canonicalize)
            .ok()
            .and_then(|path| path.file_name()?.to_str().map(str::to_owned))
            .ok_or(IdentityError::Attribute("device"))?;
        let expected = self.controller_identity();
        if identity(&controller.join("model")).as_deref() != Some(expected.model)
            || self.pci_id(&bdf) != Some(expected.pci)
        {
            return Err(IdentityError::NotEbs);
        }
        let name = controller
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        let prefix = format!("{name}n");
        let entries: Vec<_> = (self.shown(&mounts, &controller))
            .and_then(fs::read_dir)
            .and_then(|entries| entries.map(|entry| Ok(entry?.file_name())).collect())
            .map_err(|_| IdentityError::Attribute("namespace"))?;
        let namespaces: Vec<String> = entries
            .into_iter()
            .filter_map(|entry| entry.into_string().ok())
            .filter(|entry| {
                entry
                    .strip_prefix(&prefix)
                    .is_some_and(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()))
            })
            .collect();
        let [namespace] = <[String; 1]>::try_from(namespaces)
            .map_err(|found| IdentityError::Namespaces(found.len()))?;
        let attr = |relative: &'static str| -> Result<u64, IdentityError> {
            shown(&controller.join(&namespace).join(relative))
                .and_then(|text| text.parse().ok())
                .ok_or(IdentityError::Attribute(relative))
        };
        let nsid = u32::try_from(attr("nsid")?).map_err(|_| IdentityError::Attribute("nsid"))?;
        let sector_size = u32::try_from(attr("queue/logical_block_size")?)
            .map_err(|_| IdentityError::Attribute("queue/logical_block_size"))?;
        let capacity = attr("size")?
            .checked_mul(SECTOR)
            .ok_or(IdentityError::Attribute("size"))?;
        Ok(Controller {
            bdf,
            namespace,
            nsid,
            sector_size,
            capacity,
        })
    }

    /// The value the `serial` or `model` attribute file at `path` states:
    /// the file's text less the one newline the kernel prints after the
    /// fixed-width field and the trailing spaces that pad a shorter value to
    /// the field's width. Every other character is part of the value that
    /// resolution compares with the volume's serial or the expected model,
    /// leading whitespace and a tab or no-break space before the padding
    /// included. `None` for an unreadable file or bytes outside UTF-8.
    fn identity_field(path: &Path) -> Option<String> {
        let mut field = Self::attribute(path)?;
        field.truncate(field.trim_end_matches(' ').len());
        Some(field)
    }

    /// Refuses a namespace that is the root or boot device or in any use:
    /// it or one of its partitions is mounted, swapped on, held by another
    /// block device, the backing file of a loop device, of a SCSI target
    /// file backstore or of a USB gadget mass-storage LUN, the device of an
    /// OCFS2 disk heartbeat region, exported by an
    /// enabled NVMe target namespace, by the RNBD server or to a guest by a
    /// Xen block backend, or open in any
    /// process, through a descriptor or as a file registered under
    /// the device's name with an io_uring instance some task holds as a
    /// descriptor, or a process holds open, or a ring holds registered, a
    /// character node that carries commands to it, or its controller is the one an enabled NVMe target
    /// passthrough forwards to; and refuses every namespace while the pNFS
    /// block layout client, whose devices the kernel does not list, is in
    /// use. A file backstore's path and an enabled NVMe target namespace's
    /// device path count by the node each resolves to under
    /// [`root`](Self::root), links followed, and a backstore's path by its
    /// text too. Either path may have been opened in another mount
    /// namespace, where the path can name the NVMe namespace, so a path that
    /// resolves here to no node, or to a node other than the namespace's or
    /// a partition's, answers `Unverifiable("targets")`. A mass-storage
    /// LUN's backing file path counts the same way and answers
    /// `Unverifiable("gadgets")`. On success
    /// it returns an
    /// exclusive claim on the whole namespace, which the kernel grants only
    /// while no partition is claimed and which blocks later mounts, swap and
    /// claims of it or any partition; the caller holds it across the unbind.
    /// The returned descriptor is a block device whose device number is the
    /// one `sys/class/block/<namespace>/dev` names, whatever file the node
    /// path names after the check resolved it.
    ///
    /// # Errors
    ///
    /// `Unverifiable("mounts")` when the mount table, read first, is
    /// unreadable. Every entry under `proc` or `sys` named below is
    /// unreadable where a mount of that table [covers](Self::shown) it,
    /// and so are the host's last task ID and uptime, which the walk reads
    /// (`"processes"`).
    /// `Unverifiable` when the namespace's sysfs device number (`"dev"`)
    /// is missing or not `major:minor`, when the partition
    /// listing after the process walk holds a partition the listing before
    /// it lacks, or one whose node is not the node resolved before the walk
    /// (`"partitions"`), or when the namespace's
    /// partition or holder listing, the mount, swap or process table, or a
    /// process's directory under a mount the mount table names
    /// (`"processes"`), the
    /// block device listing or a loop device's backing file (`"loops"`), a
    /// ring's registered-file listing (`"processes"`), the RNBD server's
    /// export listing, or one that changed across every pass (`"rnbd"`), an
    /// OCFS2 cluster or heartbeat region listing or a region's device entry,
    /// or a watch for changes to them, or a cluster changed under every pass
    /// over the regions (`"heartbeats"`), the Xen backend listing
    /// or a block backend's device number, or one not `major:minor`, or the
    /// host's uevent counter moves across every pass over the backends
    /// (`"xen-backends"`), the USB gadget
    /// listing or a mass-storage LUN's backing file, or a watch for changes
    /// to them, or a gadget changed under every pass over the LUNs
    /// (`"gadgets"`), the
    /// SCSI target's backstore listing or a file backstore's entry, or a
    /// watch for entries added to that listing, or an adapter or a backstore
    /// was added under every pass over it, the NVMe
    /// target's namespace listing or an enabled namespace's device path, or
    /// a watch for changes to them, or a subsystem changed under every pass
    /// over its namespaces, an NVMe target passthrough's entries or the
    /// controller an enabled one names (`"targets"`), the use count of a loaded pNFS block layout
    /// driver, or one above zero, or a built-in one, or the kernel's symbol
    /// table on a host without the module (`"layouts"`), the node of the namespace or
    /// a partition, or the claimed descriptor's metadata, is unreadable, or
    /// when the mount table lists configfs only at directories a later mount
    /// covers, so no directory shows its listings, or lists a mount strictly
    /// inside a configfs directory the check reads, or lists no configfs
    /// mount on a kernel whose `proc/filesystems` names configfs or cannot
    /// be read, or the kernel grants no inotify instance to watch the
    /// configfs listings with (`"configfs"`), or
    /// when a mount of another type, or any mount strictly below `sys`,
    /// [covers](Self::shown) the Xen backend listing, the RNBD
    /// server's export listing or the block layout driver's use count under
    /// `sys` (`"xen-backends"`, `"rnbd"`, `"layouts"`), or a mount
    /// [covers](Self::shown) the kernel's symbol table on a host
    /// without the module (`"layouts"`) or the kernel's release
    /// (`"processes"`), or
    /// when a mass-storage LUN's backing file path ends with ` (deleted)` or
    /// resolves to no node or to a node other than the namespace's or a
    /// partition's, or a mount [covers](Self::shown) the legacy
    /// gadget listing or a legacy LUN's `file` (`"gadgets"`), when a mount
    /// covers the block device listing or a loop device's backing file
    /// path ends with ` (deleted)` or
    /// resolves to no node or to one that cannot back a loop device, or the
    /// host's uevent counter is unreadable, moves across every pass over
    /// the loop devices or differs between the two readings of them and no
    /// device is in use, or a mount [covers](Self::shown) the
    /// backing file entry of a loop device that reports an absent backing
    /// file (`"loops"`), or when a file
    /// backstore's path or an enabled NVMe target namespace's device path
    /// resolves to no node or to a node other than the namespace's or a
    /// partition's (`"targets"`), or when, with no device found in use, a
    /// gadget LUN, a heartbeat region (`"heartbeats"`), an NVMe target
    /// namespace or passthrough or a file backstore changed, or its watch
    /// cannot be read, between the first reading of that use and the end of
    /// the second, where a use taken from a descriptor and handed back to
    /// one is in neither reading;
    /// `Unverifiable("dev")` when a block backend exports a device and a
    /// partition's sysfs device number is unreadable;
    /// `Unverifiable("devices")` when the namespace's character nodes
    /// cannot be identified;
    /// `InUse` naming the first device found in use, or the namespace when
    /// a character node is open or its claim is refused; `Substituted`
    /// naming the namespace when the claimed descriptor is not the block
    /// device sysfs names.
    ///
    /// # Panics
    ///
    /// With the panic of a thread that read the ring tables, the listed
    /// processes' start ticks or the kernel's symbol table for the check.
    pub fn check_unused(&self, namespace: &str) -> Result<File, IdentityError> {
        let block = self.sys.join("block").join(namespace);
        let mounts = self
            .mount_table()
            .map_err(|_| IdentityError::Unverifiable("mounts"))?;
        let shown = |entry: &Path| self.shown(&mounts, entry).ok().and_then(Self::read);
        let number = shown(&self.sys.join("class/block").join(namespace).join("dev"))
            .as_deref()
            .and_then(device_number)
            .ok_or(IdentityError::Unverifiable("dev"))?;
        let mut devices = vec![namespace.to_owned()];
        devices.extend(self.partitions(&mounts, &block, namespace)?);
        let nodes: Vec<Node> = devices
            .iter()
            .map(|device| Self::node(&self.dev.join(device)))
            .collect::<Option<_>>()
            .ok_or(IdentityError::Unverifiable("devices"))?;
        self.configfs_reached(&mounts)?;
        let swaps = shown(&self.proc.join("swaps")).ok_or(IdentityError::Unverifiable("swaps"))?;
        // A use handed between a descriptor and a loop device while the walk
        // runs is in one of the two loop readings: a loop device configured
        // before the walk read the descriptor's table is in the second, one
        // detached after a descriptor reopened the device is in the first.
        // One configured after the first reading and detached before the
        // second read it is in neither, and moves the uevent counter between
        // them.
        let (mut backing, settled) = self.loop_backing_files(&mounts)?;
        // The layout client's use count is read on both sides of the walk
        // too: a mount that takes the driver before the walk read a
        // descriptor's table is in the second reading, one that ended after
        // a descriptor reopened the device is in the first. The symbols of
        // the kernel's own image stay as they are while it runs, so the two
        // readings share one read of its symbol table, which the first
        // reading that finds no module starts and which runs beside the
        // readings that follow it.
        let symbols = self.proc.join("kallsyms");
        // A mount over the symbol table shows its own text, which can lack
        // the symbols of a driver the kernel's image holds.
        let uncovered = || match self.shown(&mounts, &symbols) {
            Ok(_) => Ok(()),
            Err(_) => Err(IdentityError::Unverifiable("layouts")),
        };
        let image = ImageSymbols::of(symbols.clone());
        if !self.layout_module_idle(&mounts)? {
            uncovered()?;
            image.begin();
        }
        let checked = (|| -> Result<File, IdentityError> {
            // A gadget LUN, an RNBD export, a heartbeat region, a Xen backend
            // and an NVMe target namespace or passthrough each hold the device
            // inside the kernel with no descriptor and no exclusive claim. A use
            // handed between a descriptor and one of them while the walk runs is
            // in one of the two readings of that use's listing: a use started
            // before the walk read the descriptor's table is in the second, one
            // stopped after a descriptor reopened the device is in the first.
            //
            // A use handed from a descriptor to one of them and back within
            // the check is in neither reading. Where the kernel reports the
            // change, the check refuses: one inotify instance serves every
            // configfs reading, each first reading keeps the watches of the
            // pass it settled on until its second reading has returned, a
            // listing that pass found absent must still be absent then, and
            // a device added to or removed from sysfs moves the uevent
            // counter between the two loop readings. A ring's registered
            // files, an RNBD session and a holder change with no such
            // report, so their two readings are the whole guard.
            let changes = Changes::new().map_err(|_| IdentityError::Unverifiable("configfs"))?;
            let (mut luns, lun_watch) = self.gadget_lun_files(&mounts, &changes)?;
            let mut rnbd = self.rnbd_exports(&mounts)?;
            let (mut heartbeats, heartbeat_watch) = self.heartbeat_devices(&mounts, &changes)?;
            let mut xen = self.xen_block_backends(&mounts)?;
            let (mut exported, export_watch) = self.target_device_paths(&mounts, &changes)?;
            // The file backstore opens its path following links, so a backstore
            // over a link or another node of a device serves that device. A path
            // that resolves to no node, such as an unlinked node the backstore
            // still holds open, does not tell which device it serves; nor does
            // one that resolves to another file, since the backstore opened it
            // in its enabler's mount namespace.
            let backstores = || -> Result<(Vec<String>, Vec<Node>, Pass<'_>), IdentityError> {
                let (targets, watch) = self.target_backing_files(&mounts, &changes)?;
                let served = targets
                    .iter()
                    .map(|path| Self::node(&self.under_root(Path::new(path))))
                    .collect::<Option<_>>()
                    .ok_or(IdentityError::Unverifiable("targets"))?;
                Ok((targets, served, watch))
            };
            // A use handed between a descriptor and a file backstore while the
            // walk runs is in one of the two backstore readings: a backstore
            // enabled before the walk read the descriptor's table is in the
            // second, one removed after a descriptor reopened the device is in
            // the first.
            let (mut targets, mut served, backstore_watch) = backstores()?;
            // A use handed between a descriptor and a holding block device
            // while the walk runs is in one of the two holder readings: a
            // holder that claimed the device before the walk read the
            // descriptor's table is in the second, one that released it after a
            // descriptor opened the device is in the first.
            let holders = || -> Result<Vec<bool>, IdentityError> {
                devices
                    .iter()
                    .map(|device| {
                        let holders = if device == namespace {
                            block.join("holders")
                        } else {
                            block.join(device).join("holders")
                        };
                        let listed = self.shown(&mounts, &holders).and_then(fs::read_dir);
                        match listed.map(|mut entries| entries.next()) {
                            Ok(None) => Ok(false),
                            Ok(Some(Ok(_))) => Ok(true),
                            Ok(Some(Err(_))) | Err(_) => {
                                Err(IdentityError::Unverifiable("holders"))
                            }
                        }
                    })
                    .collect()
            };
            let held_before = holders()?;
            let characters = self.character_nodes(namespace, &mounts)?;
            let (passed_through, passthrough_watch) =
                self.passed_through(namespace, &mounts, &changes)?;
            // The ring pass judges a count without slot lines by the
            // kernel's release, and the walk judges the processes it may
            // have missed by the host's last task ID and uptime, so one of
            // them under a mount is no evidence.
            let walked = ["sys/kernel/osrelease", "loadavg", "uptime"];
            if self.process_covered(&mounts)
                || (walked.iter()).any(|read| self.shown(&mounts, &self.proc.join(read)).is_err())
            {
                return Err(IdentityError::Unverifiable("processes"));
            }
            // A use handed between a descriptor and a ring's registered-file
            // table while the walk runs is in one of the two ring readings: a
            // file registered before the walk read the descriptor's table is in
            // the second, one a ring held until a descriptor was installed on it
            // is in the first.
            let characters_named = character_names(namespace);
            let rings = || {
                self.registered(|name| {
                    devices.iter().any(|device| device == name)
                        || (characters_named.as_ref()).is_some_and(|(controller, generic)| {
                            controller == name || generic == name
                        })
                })
                .ok_or(IdentityError::Unverifiable("processes"))
            };
            let mut registered = rings()?;
            let open = self
                .opened(|node| nodes.contains(&node) || characters.contains(&node))
                .ok_or(IdentityError::Unverifiable("processes"))?;
            registered.extend(rings()?);
            image.settle()?;
            if !self.layout_module_idle(&mounts)? {
                uncovered()?;
                image.lists_no_driver()?;
            }
            let (later, later_served, _) = backstores()?;
            targets.extend(later);
            served.extend(later_served);
            luns.extend(self.gadget_lun_files(&mounts, &changes)?.0);
            rnbd.extend(self.rnbd_exports(&mounts)?);
            heartbeats.extend(self.heartbeat_devices(&mounts, &changes)?.0);
            xen.extend(self.xen_block_backends(&mounts)?);
            exported.extend(self.target_device_paths(&mounts, &changes)?.0);
            let passed_through =
                passed_through || self.passed_through(namespace, &mounts, &changes)?.0;
            // The second loop reading follows every second configfs
            // reading, so the uevent counter spans them all: a module that
            // registered a configfs listing and was unloaded again between
            // a use's two readings sent its uevents inside the span.
            let (later, resettled) = self.loop_backing_files(&mounts)?;
            backing.extend(later);
            let held_after = holders()?;
            let held = held_before.iter().zip(&held_after);
            for ((device, node), (&before, &after)) in devices.iter().zip(&nodes).zip(held) {
                // The kernel names mount and swap sources by their `/dev` path.
                let source = format!("/dev/{device}");
                let named = |line: &str| line.split_whitespace().next() == Some(source.as_str());
                let held = before || after;
                // A backend names its device by number alone, so each device's
                // sysfs number is read only when some backend exports one.
                let xen_exported = !xen.is_empty() && {
                    let own = if device == namespace {
                        Some(number)
                    } else {
                        shown(&self.sys.join("class/block").join(device).join("dev"))
                            .as_deref()
                            .and_then(device_number)
                    };
                    xen.contains(&own.ok_or(IdentityError::Unverifiable("dev"))?)
                };
                if held
                    || xen_exported
                    || open.contains(node)
                    || luns.contains(node)
                    || rnbd.iter().any(|name| *name == **device)
                    || mounts.lines().any(named)
                    || swaps.lines().any(named)
                    || heartbeats.contains(device)
                    || backing
                        .iter()
                        .any(|(path, backed)| *path == source || backed == node)
                    || targets.contains(&source)
                    || exported.contains(node)
                    || served.contains(node)
                    || registered.contains(device)
                {
                    return Err(IdentityError::InUse(device.clone()));
                }
            }
            if served
                .iter()
                .chain(&exported)
                .any(|node| !nodes.contains(node))
            {
                return Err(IdentityError::Unverifiable("targets"));
            }
            // A LUN opened its backing file in the mount namespace of the
            // process that wrote `file`, where the path it prints can name
            // the namespace, so a LUN over any other node here does not tell
            // which device it serves.
            if luns.iter().any(|node| !nodes.contains(node)) {
                return Err(IdentityError::Unverifiable("gadgets"));
            }
            if resettled != settled {
                return Err(IdentityError::Unverifiable("loops"));
            }
            if passed_through {
                return Err(IdentityError::InUse(namespace.to_owned()));
            }
            // An open character node takes no claim on the block device, so the
            // exclusive open below is granted beside it. A ring that holds one
            // registered lists it by the name the kernel gives the node.
            let ringed = characters_named.is_some_and(|(controller, generic)| {
                registered.contains(&controller) || registered.contains(&generic)
            });
            if ringed || characters.iter().any(|node| open.contains(node)) {
                return Err(IdentityError::InUse(namespace.to_owned()));
            }
            // A change a first reading's watch reports was made after that
            // reading and before the second one of the same use returned,
            // where a use taken and given back is in neither.
            let handed = [
                ("targets", &backstore_watch),
                ("gadgets", &lun_watch),
                ("heartbeats", &heartbeat_watch),
                ("targets", &export_watch),
                ("targets", &passthrough_watch),
            ];
            for (use_, watch) in handed {
                if !watch.still().unwrap_or(false) {
                    return Err(IdentityError::Unverifiable(use_));
                }
            }
            // The walk matched only the nodes resolved before it. A process that
            // moved its use to a partition added since then, under a new name or
            // under a listed name after that partition was deleted, held a
            // descriptor the walk could not match. So a partition the first
            // listing lacks, or one whose node is no longer the node resolved
            // then, leaves the check without an answer.
            for partition in self.partitions(&mounts, &block, namespace)? {
                let listed = devices
                    .iter()
                    .position(|device| *device == partition)
                    .map(|at| nodes[at]);
                if listed.is_none() || Self::node(&self.dev.join(&partition)) != listed {
                    return Err(IdentityError::Unverifiable("partitions"));
                }
            }
            // On a block device the kernel refuses an exclusive open of the whole
            // disk while any mount namespace mounts, swaps on or claims it or any
            // of its partitions.
            // `O_NONBLOCK` keeps a FIFO substituted at the node path from
            // blocking the open; the descriptor check below refuses it.
            let claim = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_EXCL | libc::O_NONBLOCK)
                .open(self.dev.join(namespace))
                .map_err(|_| IdentityError::InUse(namespace.to_owned()))?;
            let opened = claim
                .metadata()
                .map_err(|_| IdentityError::Unverifiable("devices"))?;
            // The descriptor alone decides, because the node path can name
            // another file between resolution and the open.
            let claimed = block_device(&opened, number);
            // `devices` starts with the namespace, so `nodes[0]` is its node.
            #[cfg(test)]
            let claimed = claimed || self.fixture_claim(&opened, nodes[0], number);
            if !claimed {
                return Err(IdentityError::Substituted(namespace.to_owned()));
            }
            Ok(claim)
        })();
        // A step between the two layout readings that refused did so after
        // the first reading, so the first reading's refusal comes first.
        image.settle()?;
        checked
    }

    /// The partitions sysfs lists under `block`, the directory of
    /// `namespace`.
    ///
    /// # Errors
    ///
    /// `Unverifiable("partitions")` when the directory is unreadable or a
    /// mount of `mounts` [covers](Self::shown) it.
    fn partitions(
        &self,
        mounts: &str,
        block: &Path,
        namespace: &str,
    ) -> Result<Vec<String>, IdentityError> {
        let entries: Vec<_> = (self.shown(mounts, block))
            .and_then(fs::read_dir)
            .and_then(|entries| entries.map(|entry| Ok(entry?.file_name())).collect())
            .map_err(|_| IdentityError::Unverifiable("partitions"))?;
        Ok(entries
            .into_iter()
            .filter_map(|entry| entry.into_string().ok())
            .filter(|entry| entry.starts_with(namespace) && entry != namespace)
            .collect())
    }

    /// The device number of every Xen block backend that exports one to a
    /// guest. The backend opens its device by number inside the kernel
    /// without an exclusive claim, so the device gains no holder, no mount
    /// or swap line and no descriptor in any process. Sysfs lists each
    /// backend in `bus/xen-backend/devices`, a block backend as
    /// `vbd-<domain>-<handle>`, whose `physical_device` prints the number in
    /// hexadecimal as `major:minor`, `0:0` until the backend is given a
    /// device. A host that is no Xen backend domain has no such listing and
    /// exports nothing.
    ///
    /// The backends are read one after another, so an export moved from a
    /// backend not yet read to one already read is in no single pass. A
    /// backend keeps the device it was given until the kernel removes the
    /// backend, and the kernel sends a uevent when it removes one, so a pass
    /// is returned only when the host's uevent counter reads the same before
    /// and after it ([`still_pass`](Self::still_pass)): every backend that
    /// exported a device when such a pass began was listed and read in it.
    ///
    /// # Errors
    ///
    /// `Unverifiable("xen-backends")` when the uevent counter is unreadable
    /// or not a number or moved across every pass, or as
    /// [`xen_backend_pass`](Self::xen_backend_pass) refuses.
    fn xen_block_backends(&self, mounts: &str) -> Result<Vec<(u32, u32)>, IdentityError> {
        self.still_pass(mounts, "xen-backends", || self.xen_backend_pass(mounts))
            .map(|(exports, _)| exports)
    }

    /// One pass over the Xen block backends: the backend listing read once
    /// and each listed block backend's device number read in listing order.
    ///
    /// # Errors
    ///
    /// `Unverifiable("xen-backends")` when another mount of `mounts`
    /// [covers](Self::shown) the listing or a block backend's
    /// `physical_device`, when the listing exists and is unreadable, or a
    /// block backend's `physical_device` is unreadable or not hexadecimal
    /// `major:minor`.
    fn xen_backend_pass(&self, mounts: &str) -> Result<Vec<(u32, u32)>, IdentityError> {
        let unverifiable = || IdentityError::Unverifiable("xen-backends");
        let listing = self.sys.join("bus/xen-backend/devices");
        let entries = match self.shown(mounts, &listing).and_then(fs::read_dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(unverifiable()),
        };
        let mut exported = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|_| unverifiable())?;
            if !entry.file_name().to_string_lossy().starts_with("vbd-") {
                continue;
            }
            let device = entry.path().join("physical_device");
            let text = (self.shown(mounts, &device).ok())
                .and_then(Self::read)
                .ok_or_else(unverifiable)?;
            let (major, minor) = text.trim().split_once(':').ok_or_else(unverifiable)?;
            let parse = |field: &str| u32::from_str_radix(field, 16).map_err(|_| unverifiable());
            let number = (parse(major)?, parse(minor)?);
            if number != (0, 0) {
                exported.push(number);
            }
        }
        Ok(exported)
    }

    /// The backing file of every configured loop device, by the path the
    /// kernel names and by the node that path resolves to under
    /// [`root`](Self::root). The loop driver keeps its backing file open
    /// inside the kernel, so a backing device gains no holder, no exclusive
    /// claim and no descriptor in any process, and a mount or swap area on
    /// the loop device names the loop device. The kernel names the backing
    /// file in `sys/block/loop<n>/loop/backing_file`, present only while the
    /// loop device is configured, by the path it was configured with, which
    /// can be a bind mount of a device node or a second node of the device.
    /// The entry is that path and one newline, so a newline before the last
    /// belongs to the path.
    /// A path that resolves to no node, such as one in another mount
    /// namespace, does not tell which device the loop device serves, so it
    /// refuses. The kernel names an unlinked backing file by its path with a
    /// ` (deleted)` suffix, the same text it prints for a linked file of that
    /// literal name, so a path with that suffix refuses too: the file found
    /// there may not be the one the loop device serves. So does a path that
    /// resolves to anything but a regular file or a block device, such as the
    /// `/` the kernel names a backing file by when the file is the root of a
    /// mount this process cannot reach: the loop driver takes no other file,
    /// so the path is not the backing file.
    /// A path on a mount in another mount namespace is that namespace's path,
    /// which can name a different file here, so the node it resolves to must
    /// also be the node the kernel records for the loop device, read by
    /// [`loop_record`](Self::loop_record); otherwise it refuses.
    ///
    /// The devices are read one after another, so a backing file moved from
    /// a device not yet read to one already read is in no single pass. The
    /// kernel sends a uevent when it configures or detaches a loop device,
    /// and `sys/kernel/uevent_seqnum` counts every uevent sent on the host,
    /// so a pass is returned only when the counter reads the same before and
    /// after it ([`still_pass`](Self::still_pass)), with the value it read.
    /// Two readings that return the same value span no uevent, so no loop
    /// device was configured or detached between them.
    ///
    /// # Errors
    ///
    /// `Unverifiable("loops")` when the uevent counter is unreadable or not a
    /// number, when it moved across every pass, or as
    /// [`loop_pass`](Self::loop_pass) refuses.
    fn loop_backing_files(
        &self,
        mounts: &str,
    ) -> Result<(Vec<(String, Node)>, u64), IdentityError> {
        self.still_pass(mounts, "loops", || self.loop_pass(mounts))
    }

    /// What `pass` reads while no uevent is sent on the host:
    /// `sys/kernel/uevent_seqnum` counts every uevent sent, and a pass is
    /// returned only when the counter reads the same before and after it,
    /// with the value the counter read. A pass the counter moved across is
    /// read again, at most [`UEVENT_PASSES`] in all.
    ///
    /// # Errors
    ///
    /// `Unverifiable(what)` when the uevent counter is unreadable, under a
    /// mount of `mounts` that [covers](Self::shown) it, not a number or
    /// moved across every pass, or as `pass` refuses.
    fn still_pass<T>(
        &self,
        mounts: &str,
        what: &'static str,
        pass: impl Fn() -> Result<T, IdentityError>,
    ) -> Result<(T, u64), IdentityError> {
        let counter = self.sys.join("kernel/uevent_seqnum");
        let sequence = || {
            (self.shown(mounts, &counter).ok())
                .and_then(Self::read)
                .and_then(|text| text.parse::<u64>().ok())
                .ok_or(IdentityError::Unverifiable(what))
        };
        let mut before = sequence()?;
        for _pass in 0..UEVENT_PASSES {
            let read = pass()?;
            let after = sequence()?;
            if after == before {
                return Ok((read, after));
            }
            before = after;
        }
        Err(IdentityError::Unverifiable(what))
    }

    /// One pass over the loop devices: the block device listing read once
    /// and each listed loop device's backing file read in listing order.
    ///
    /// # Errors
    ///
    /// `Unverifiable("loops")` when another mount of `mounts`
    /// [covers](Self::shown) the block device listing, which then
    /// shows the covering mount's entries in place of the kernel's loop
    /// devices, when the listing is unreadable,
    /// a loop device's backing file entry exists and is unreadable, its path
    /// ends with ` (deleted)` or resolves to no node or to one that cannot
    /// back a loop device, the loop device's record is unreadable or names
    /// another node, or a loop device has no backing file entry and another
    /// mount of `mounts` [covers](Self::shown) where the entry would
    /// be: under a covering mount the entry is absent while the kernel keeps
    /// the loop device configured. The block device listing names a loop
    /// device by a link into `sys/devices`, which
    /// [`sysfs_covered`](Self::sysfs_covered) follows to the directory the
    /// mount table names.
    fn loop_pass(&self, mounts: &str) -> Result<Vec<(String, Node)>, IdentityError> {
        let unverifiable = |_| IdentityError::Unverifiable("loops");
        let listing = self.sys.join("block");
        let mut backing = Vec::new();
        let devices = (self.shown(mounts, &listing))
            .and_then(fs::read_dir)
            .map_err(unverifiable)?;
        for entry in devices {
            let entry = entry.map_err(unverifiable)?;
            if !entry.file_name().to_string_lossy().starts_with("loop") {
                continue;
            }
            let file = entry.path().join("loop/backing_file");
            // A cover is no absence: under one the entry can be missing
            // while the kernel keeps the loop device configured.
            match self.shown(mounts, &file).and_then(fs::read_to_string) {
                Ok(path) => {
                    // Only the last newline is the kernel's; one before it is the path's.
                    let path = path.strip_suffix('\n').unwrap_or(&path).to_owned();
                    if path.ends_with(" (deleted)") {
                        return Err(IdentityError::Unverifiable("loops"));
                    }
                    let resolved = self.under_root(Path::new(&path));
                    // The loop driver takes a regular file or a block device and nothing else.
                    let backs = fs::metadata(&resolved).is_ok_and(|found| {
                        found.file_type().is_file() || found.file_type().is_block_device()
                    });
                    let node = Self::node(&resolved)
                        .filter(|_| backs)
                        .ok_or(IdentityError::Unverifiable("loops"))?;
                    if self.loop_record(mounts, &entry.file_name()) != Some(node) {
                        return Err(IdentityError::Unverifiable("loops"));
                    }
                    backing.push((path, node));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(unverifiable(error)),
            }
        }
        Ok(backing)
    }

    /// The backing path of every SCSI target file backstore. The file
    /// backstore opens its backing path as a file inside the kernel, so a
    /// backing device gains no holder, no exclusive claim and no descriptor in
    /// any process. Configfs lists each backstore as
    /// `target/core/fileio_<n>/<name>` under each directory
    /// [`configfs_dirs`](Self::configfs_dirs) names for `mounts`, whose
    /// `udev_path` holds the path its creator recorded and whose `info` holds
    /// the path the kernel opens, between `File: ` and the last `  Size: ` on
    /// its line, so a path that holds spaces is read whole. Both are
    /// returned, for a backstore not yet enabled too. A directory without the
    /// target's listing has no backstore.
    ///
    /// The adapters are read one after another, so a file whose backstore is
    /// replaced by one made under an adapter already read is in no single
    /// pass. An adapter or a backstore appears only by an entry made in its
    /// parent, so each pass watches `target/core` and every file adapter for
    /// such an entry, from before it lists them, and a pass is returned only
    /// when it ends with none reported. A pass an entry was reported in is
    /// read again, at most [`BACKSTORE_PASSES`] in all. The paths come with
    /// the pass they were read in, which answers for entries made after it.
    ///
    /// # Errors
    ///
    /// `Unverifiable("targets")` when the reports of `changes` cannot be read, when
    /// an
    /// entry was reported in every pass, or as
    /// [`target_backing_pass`](Self::target_backing_pass) refuses.
    fn target_backing_files<'a>(
        &self,
        mounts: &str,
        changes: &'a Changes,
    ) -> Result<(Vec<String>, Pass<'a>), IdentityError> {
        let unverifiable = |_| IdentityError::Unverifiable("targets");
        for _pass in 0..BACKSTORE_PASSES {
            let pass = changes.pass().map_err(unverifiable)?;
            let backing = self.target_backing_pass(mounts, &pass)?;
            if pass.still().map_err(unverifiable)? {
                return Ok((backing, pass));
            }
        }
        Err(IdentityError::Unverifiable("targets"))
    }

    /// One pass over the file backstores: each `target/core` listing read
    /// once and its file adapters in listing order, each listing after
    /// `changes` began to watch its directory.
    ///
    /// # Errors
    ///
    /// `Unverifiable("targets")` when a `configfs` mount's directory is a
    /// malformed escape or lies outside UTF-8, a listing is unreadable or
    /// cannot be watched, or a file backstore's `udev_path` or `info` exists
    /// and is unreadable.
    fn target_backing_pass(
        &self,
        mounts: &str,
        changes: &Pass<'_>,
    ) -> Result<Vec<String>, IdentityError> {
        let unverifiable = |_| IdentityError::Unverifiable("targets");
        let mut backing = Vec::new();
        let dirs = self
            .configfs_dirs(mounts)
            .ok_or(IdentityError::Unverifiable("targets"))?;
        for configfs in dirs {
            let core = configfs.join("target/core");
            let adapters = match changes.watch(&core).and_then(|()| fs::read_dir(&core)) {
                Ok(adapters) => adapters,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(unverifiable(error)),
            };
            backing.extend(Self::file_backstores(adapters, changes)?);
        }
        Ok(backing)
    }

    /// The `udev_path` and `info` paths of every file backstore in one
    /// `target/core` listing, as [`target_backing_files`](Self::target_backing_files)
    /// describes, each file adapter listed after `changes` began to watch it.
    ///
    /// # Errors
    ///
    /// `Unverifiable("targets")` as for
    /// [`target_backing_pass`](Self::target_backing_pass).
    fn file_backstores(
        adapters: fs::ReadDir,
        changes: &Pass<'_>,
    ) -> Result<Vec<String>, IdentityError> {
        let unverifiable = |_| IdentityError::Unverifiable("targets");
        let mut backing = Vec::new();
        for adapter in adapters {
            let adapter = adapter.map_err(unverifiable)?;
            let file_adapter = adapter.file_name().to_string_lossy().starts_with("fileio_");
            if !file_adapter || !adapter.file_type().map_err(unverifiable)?.is_dir() {
                continue;
            }
            changes.watch(&adapter.path()).map_err(unverifiable)?;
            for backstore in fs::read_dir(adapter.path()).map_err(unverifiable)? {
                let backstore = backstore.map_err(unverifiable)?;
                if !backstore.file_type().map_err(unverifiable)?.is_dir() {
                    continue;
                }
                for attribute in ["udev_path", "info"] {
                    let text = match fs::read_to_string(backstore.path().join(attribute)) {
                        Ok(text) => text,
                        Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                        Err(error) => return Err(unverifiable(error)),
                    };
                    let path = if attribute == "info" {
                        // The path can hold spaces and no newline, and nothing the kernel prints after
                        // it on the line holds the field's opening words, so their last occurrence ends it.
                        text.split_once("File: ").map(|(_, rest)| {
                            let line = rest.lines().next().unwrap_or(rest);
                            line.rsplit_once("  Size: ").map_or(line, |(path, _)| path)
                        })
                    } else {
                        Some(text.as_str())
                    };
                    backing.extend(path.map(|path| path.trim_end_matches('\n').to_owned()));
                }
            }
        }
        Ok(backing)
    }

    /// The node of the backing file of every USB gadget mass-storage LUN
    /// that has one. The function opens a LUN's backing file inside the
    /// kernel without an exclusive claim, for the USB host to read and
    /// write, so a backing device gains no holder, no mount or swap line and
    /// no descriptor in any process. Configfs lists each LUN under
    /// `kernel/config/usb_gadget/<gadget>/functions/mass_storage.<name>/<lun>`
    /// in sysfs, where `<lun>` is `lun.0` or any directory the administrator
    /// made, which the function takes under any `<name>.<number>` name. A
    /// legacy gadget module has no configfs entry and registers
    /// each LUN as a device under the gadget device of its USB device
    /// controller, `class/udc/<controller>/device/gadget.<n>/lun<n>`, with
    /// the gadget device named `gadget` on kernels before 5.19. In both
    /// listings a LUN's `file` is empty while the LUN has no backing file and
    /// otherwise prints the open file's path and one newline. The path can
    /// be any node of the device and is resolved under [`root`](Self::root).
    /// The kernel prints an unlinked backing file by its path with a
    /// ` (deleted)` suffix, the same text it prints for a linked file of that
    /// literal name, so a path with that suffix refuses: the file found
    /// there may not be the one the LUN serves.
    /// Configfs mounts at any directory, so the configfs listing is read
    /// under each directory [`configfs_dirs`](Self::configfs_dirs) names for
    /// `mounts`, the mount table. A host with no gadget support has neither
    /// listing and backs nothing.
    ///
    /// The LUNs are read one after another, so a backing file moved from a
    /// LUN not yet read to one already read is in no single pass. A LUN
    /// gains a backing file only by a write to its `file`, and a LUN, a
    /// function or a gadget appears only by an entry made in its parent, so
    /// each pass watches every directory it lists and every LUN it reads for
    /// such a change, from before it reads them, and a pass is returned only
    /// when it ends with none reported. A pass a change was reported in is
    /// read again, at most [`LUN_PASSES`] in all. The nodes come with the
    /// pass they were read in, which answers for changes made after it.
    ///
    /// # Errors
    ///
    /// `Unverifiable("gadgets")` when the reports of `changes` cannot be read, when
    /// a
    /// change was reported in every pass, or as
    /// [`gadget_lun_pass`](Self::gadget_lun_pass) refuses.
    fn gadget_lun_files<'a>(
        &self,
        mounts: &str,
        changes: &'a Changes,
    ) -> Result<(Vec<Node>, Pass<'a>), IdentityError> {
        let unverifiable = |_| IdentityError::Unverifiable("gadgets");
        for _pass in 0..LUN_PASSES {
            let pass = changes.pass().map_err(unverifiable)?;
            let backing = self.gadget_lun_pass(mounts, &pass)?;
            if pass.still().map_err(unverifiable)? {
                return Ok((backing, pass));
            }
        }
        Err(IdentityError::Unverifiable("gadgets"))
    }

    /// One pass over the USB gadget LUNs: each listing read once and each
    /// LUN's `file` read in listing order, each after `changes` began to
    /// watch its directory.
    ///
    /// # Errors
    ///
    /// `Unverifiable("gadgets")` when a `configfs` mount's directory is a
    /// malformed escape or lies outside UTF-8, when another mount of
    /// `mounts` [covers](Self::shown) `class/udc`, a controller's
    /// device, a gadget device under it or a legacy LUN's `file`, which
    /// then shows the covering mount's entries or text in place of the
    /// kernel's, when a gadget,
    /// function, controller or LUN listing that exists or a LUN's `file` is
    /// unreadable or cannot be watched, or when a LUN's backing file path
    /// ends with ` (deleted)` or resolves to no node, so the device it backs
    /// is unknown.
    fn gadget_lun_pass(
        &self,
        mounts: &str,
        changes: &Pass<'_>,
    ) -> Result<Vec<Node>, IdentityError> {
        let unverifiable = || IdentityError::Unverifiable("gadgets");
        let listing = |path: PathBuf| {
            let entries = changes.watch(&path).and_then(|()| fs::read_dir(path));
            match entries {
                Ok(entries) => entries
                    .map(|entry| Ok(entry?.path()))
                    .collect::<io::Result<Vec<_>>>()
                    .map_err(|_| unverifiable()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
                Err(_) => Err(unverifiable()),
            }
        };
        let named = |path: &Path, prefix: &str| {
            (path.file_name()).is_some_and(|name| name.to_string_lossy().starts_with(prefix))
        };
        let mut luns = Vec::new();
        let dirs = self
            .configfs_dirs(mounts)
            .ok_or(IdentityError::Unverifiable("gadgets"))?;
        for configfs in dirs {
            for gadget in listing(configfs.join("usb_gadget"))? {
                let functions = listing(gadget.join("functions"))?;
                for function in functions.iter().filter(|path| named(path, "mass_storage.")) {
                    // The function makes a LUN for any directory named `<name>.<number>`, so
                    // every directory is one; its other entries are attribute files.
                    for lun in listing(function.clone())? {
                        if fs::metadata(&lun).map_err(|_| unverifiable())?.is_dir() {
                            luns.push(lun);
                        }
                    }
                }
            }
        }
        // A mount at or above a directory shows its own entries there, and
        // one at a LUN's `file` its own text, so each legacy listing and
        // each legacy LUN's `file` is read only where no mount covers it.
        let uncovered = |path: PathBuf| match self.shown(mounts, &path) {
            Ok(_) => Ok(path),
            Err(_) => Err(unverifiable()),
        };
        for controller in listing(uncovered(self.sys.join("class/udc"))?)? {
            let devices = listing(uncovered(controller.join("device"))?)?;
            for gadget in devices.iter().filter(|path| named(path, "gadget")) {
                for lun in listing(uncovered(gadget.clone())?)? {
                    if named(&lun, "lun") {
                        uncovered(lun.join("file"))?;
                        luns.push(lun);
                    }
                }
            }
        }
        let mut backing = Vec::new();
        for lun in luns {
            changes.watch(&lun).map_err(|_| unverifiable())?;
            let file = fs::read_to_string(lun.join("file")).map_err(|_| unverifiable())?;
            // Only the last newline is the kernel's; one before it is the path's.
            let file = file.strip_suffix('\n').unwrap_or(&file);
            if file.is_empty() {
                continue;
            }
            if file.ends_with(" (deleted)") {
                return Err(unverifiable());
            }
            let node = Self::node(&self.under_root(Path::new(file)));
            backing.push(node.ok_or_else(unverifiable)?);
        }
        Ok(backing)
    }

    /// The node of every enabled namespace of the kernel's NVMe target, which
    /// its `device_path` resolves to under [`root`](Self::root).
    /// The target opens an enabled namespace's device inside the kernel with
    /// no holder and no exclusive claim, so the device gains no holder entry,
    /// no descriptor in any process and no mount or swap line. Configfs lists
    /// each namespace under `kernel/config/nvmet/subsystems/<nqn>/namespaces/<nsid>`
    /// in sysfs, with its `enable` flag and `device_path`. The listing is read
    /// under each directory [`configfs_dirs`](Self::configfs_dirs) names for
    /// `mounts`. The kernel opens the path its creator wrote, following
    /// links, so the path can be a `/dev/disk/by-id` link or another node of
    /// the device. [`check_unused`](Self::check_unused) refuses as
    /// unverifiable any returned node other than the namespace's or a
    /// partition's, since the writer may have resolved the path in another
    /// mount namespace. A
    /// directory with no such listing exports nothing.
    ///
    /// The namespaces are read one after another, so an export moved from a
    /// namespace not yet read to one already read is in no single pass. A
    /// namespace exports a device only after writes to its `enable` and
    /// `device_path`, and a namespace or a subsystem appears only by an entry
    /// made in its parent, so each pass watches every directory it lists and
    /// every namespace it reads for such a change, from before it reads them,
    /// and a pass is returned only when it ends with none reported. A pass a
    /// change was reported in is read again, at most [`TARGET_PASSES`] in
    /// all. The nodes come with the pass they were read in, which answers
    /// for changes made after it.
    ///
    /// # Errors
    ///
    /// `Unverifiable("targets")` when the reports of `changes` cannot be read, when
    /// a
    /// change was reported in every pass, or as
    /// [`target_pass`](Self::target_pass) refuses.
    fn target_device_paths<'a>(
        &self,
        mounts: &str,
        changes: &'a Changes,
    ) -> Result<(Vec<Node>, Pass<'a>), IdentityError> {
        let unverifiable = |_| IdentityError::Unverifiable("targets");
        for _pass in 0..TARGET_PASSES {
            let pass = changes.pass().map_err(unverifiable)?;
            let exported = self.target_pass(mounts, &pass)?;
            if pass.still().map_err(unverifiable)? {
                return Ok((exported, pass));
            }
        }
        Err(IdentityError::Unverifiable("targets"))
    }

    /// One pass over the NVMe target namespaces: each listing read once and
    /// each namespace's `enable`, and an enabled one's `device_path`, read in
    /// listing order, each after `changes` began to watch its directory.
    ///
    /// # Errors
    ///
    /// `Unverifiable("targets")` when a `configfs` mount's directory is a
    /// malformed escape or lies outside UTF-8, a subsystem or namespace
    /// listing that exists is unreadable or cannot be watched, an existing
    /// namespace cannot be watched or its `enable` or an enabled namespace's
    /// `device_path` is unreadable, or an enabled namespace's `device_path`
    /// resolves to no node.
    fn target_pass(&self, mounts: &str, changes: &Pass<'_>) -> Result<Vec<Node>, IdentityError> {
        let unverifiable = |_| IdentityError::Unverifiable("targets");
        let listing = |path: &Path| match changes.watch(path).and_then(|()| fs::read_dir(path)) {
            Ok(entries) => entries
                .map(|entry| Ok(entry?.path()))
                .collect::<io::Result<Vec<_>>>()
                .map_err(unverifiable),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(error) => Err(unverifiable(error)),
        };
        let field = |path: PathBuf| match fs::read_to_string(path) {
            Ok(text) => Ok(Some(text.trim_end_matches('\n').to_owned())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(unverifiable(error)),
        };
        let mut exported = Vec::new();
        let dirs = self
            .configfs_dirs(mounts)
            .ok_or(IdentityError::Unverifiable("targets"))?;
        for configfs in dirs {
            for subsystem in listing(&configfs.join("nvmet/subsystems"))? {
                for namespace in listing(&subsystem.join("namespaces"))? {
                    match changes.watch(&namespace) {
                        Ok(()) => {}
                        // A namespace removed since the listing exports nothing.
                        Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                        Err(error) => return Err(unverifiable(error)),
                    }
                    if field(namespace.join("enable"))?.as_deref() != Some("1") {
                        continue;
                    }
                    if let Some(path) = field(namespace.join("device_path"))? {
                        let node = Self::node(&self.under_root(Path::new(&path)))
                            .ok_or(IdentityError::Unverifiable("targets"))?;
                        exported.push(node);
                    }
                }
            }
        }
        Ok(exported)
    }

    /// Whether `mounts`, the mount table, names a mount at a process's
    /// directory `proc/<pid>` or inside it. Under such a mount the process's
    /// descriptor tables are absent or are another directory's entries while
    /// the process table still lists the process, so the walk and the ring
    /// pass, which skip a missing table as a process that exited, would pass
    /// over a live process. The kernel removes a mount inside a process's
    /// directory when the process exits, so a listed one covers a process
    /// that may hold the namespace. Each directory is decoded and taken under
    /// [`root`](Self::root) as [`configfs_dirs`](Self::configfs_dirs) does. A
    /// directory that is a malformed escape covers nothing: every name
    /// inside a process's directory is printed without an escape.
    fn process_covered(&self, mounts: &str) -> bool {
        mounts.lines().any(|line| {
            let directory = line.split(' ').nth(1).and_then(unescaped);
            directory.is_some_and(|at| {
                let at = self.under_root(Path::new(&*at));
                let process = at
                    .strip_prefix(&self.proc)
                    .ok()
                    .and_then(|inside| inside.components().next());
                process.is_some_and(|pid| {
                    let pid = pid.as_os_str().as_encoded_bytes();
                    pid.iter().all(u8::is_ascii_digit)
                })
            })
        })
    }

    /// Every directory a configfs listing may sit under: `sys/kernel/config`,
    /// where configfs is conventionally mounted, and every directory `mounts`,
    /// the mount table, names as a `configfs` mount and no later mount
    /// covers, each with its octal escapes decoded and taken under
    /// [`root`](Self::root). Configfs mounts at any directory, and the target
    /// listings appear under each of its mounts that no later mount covers.
    /// The kernel prints a space, tab, newline or backslash of the directory
    /// as `\040`, `\011`, `\012` or `\134`. `None` when an uncovered
    /// `configfs` mount's directory is a malformed escape or lies outside
    /// UTF-8.
    fn configfs_dirs(&self, mounts: &str) -> Option<Vec<PathBuf>> {
        let mut dirs = vec![self.sys.join("kernel/config")];
        for (_, at, covered) in configfs_mounts(mounts) {
            if !covered {
                dirs.push(self.under_root(Path::new(&*unescaped(at)?)));
            }
        }
        Some(dirs)
    }

    /// Refuses a mount table that lists configfs only at directories later
    /// mounts cover, obscuring the listings at those directories, and one
    /// that lists a mount strictly inside a directory
    /// [`configfs_dirs`](Self::configfs_dirs) names: after the uncovered
    /// configfs mount at that directory, or on any line for
    /// `sys/kernel/config`, which the readers read whatever the table lists.
    /// Such a mount can hide a target, backstore, gadget or heartbeat
    /// listing. The refusal reports `configfs` because a hidden directory
    /// can contain any reader's listing.
    ///
    /// A table that lists no configfs mount shows a host with no configfs
    /// entry only on a kernel without configfs: a kernel that has it keeps
    /// every configured entry while no mount shows them. The kernel lists
    /// its file systems in `proc/filesystems`, so such a table refuses when
    /// that list names configfs, cannot be read, or sits under a mount that
    /// [covers](Self::shown) it.
    fn configfs_reached(&self, mounts: &str) -> Result<(), IdentityError> {
        let mut listed = configfs_mounts(mounts).peekable();
        let shown = match listed.peek() {
            Some(_) => listed.any(|(_, _, covered)| !covered),
            None => {
                let filesystems = self.proc.join("filesystems");
                let kernel = (self.shown(mounts, &filesystems).ok())
                    .and_then(Self::read)
                    .ok_or(IdentityError::Unverifiable("configfs"))?;
                // Each line is a file system's name after `nodev` or an empty field.
                !kernel
                    .lines()
                    .any(|line| line.split('\t').nth(1) == Some("configfs"))
            }
        };
        // `inside` is a directory relative to the root, as the mount table names it.
        let mounted_inside = |from: usize, inside: &Path| {
            mounts
                .lines()
                .skip(from)
                .filter_map(|line| line.split(' ').nth(1).and_then(unescaped))
                .any(|later| {
                    let later = Path::new(&*later);
                    let later = later.strip_prefix("/").unwrap_or(later);
                    later.starts_with(inside) && later != inside
                })
        };
        let conventional = self.sys.join("kernel/config");
        let hidden = conventional
            .strip_prefix(&self.root)
            .is_ok_and(|inside| mounted_inside(0, inside))
            || configfs_mounts(mounts)
                .filter(|&(_, _, covered)| !covered)
                .any(|(line, at, _)| {
                    unescaped(at).is_some_and(|at| {
                        let at = Path::new(&*at);
                        mounted_inside(line + 1, at.strip_prefix("/").unwrap_or(at))
                    })
                });
        if shown && !hidden {
            Ok(())
        } else {
            Err(IdentityError::Unverifiable("configfs"))
        }
    }

    /// Detects mount coverage that makes a missing `entry`, a path under
    /// [`sys`](Self::sys), inconclusive evidence of disuse. Sysfs class links
    /// lead into `sys/devices` and the mount table names a mount by its
    /// resolved directory, so `entry` is matched by its nearest existing
    /// ancestor with links followed and the absent names below it. The last
    /// line of `mounts` whose mount point is at or below `sys` and at or above
    /// the resolved entry path, or at or above a place where a name is
    /// looked up on the way to it, decides coverage. Bind mounts of sysfs
    /// subtrees retain the `sysfs` type, so a mount strictly below `sys`
    /// counts as coverage regardless of type, and a mount at `sys` counts
    /// unless its type is `sysfs`. Resolution failures and paths outside
    /// `sys` also count as coverage.
    fn sysfs_covered(&self, mounts: &str, entry: &Path) -> bool {
        self.covered(mounts, &self.sys, "sysfs", entry)
    }

    /// As [`sysfs_covered`](Self::sysfs_covered), for `entry`, a path under
    /// [`proc`](Self::proc): a mount at or above the entry and at or below
    /// `proc` shows its own entries or text in place of the kernel's. A
    /// mount at `proc` counts unless its type is `proc`.
    fn procfs_covered(&self, mounts: &str, entry: &Path) -> bool {
        self.covered(mounts, &self.proc, "proc", entry)
    }

    /// The mount table of this process, the one text every cover is judged
    /// by. A table that is itself another file system's text is outside
    /// what the binder guards: placing one takes the privilege to unbind
    /// the device directly.
    ///
    /// # Errors
    ///
    /// An error when the table cannot be read.
    pub(super) fn mount_table(&self) -> io::Result<String> {
        Self::read(&self.proc.join("self/mounts"))
            .ok_or_else(|| io::Error::other("the mount table is unreadable"))
    }

    /// `entry`, a file or directory under [`proc`](Self::proc) or
    /// [`sys`](Self::sys), when it is the kernel's own: no mount of
    /// `mounts` covers it. Every read of kernel state the binder takes as
    /// evidence resolves its path here first, so the text or the entries
    /// of a mount over the path are never read as the kernel's state. An
    /// entry under `proc` is judged as
    /// [`procfs_covered`](Self::procfs_covered) does and one under `sys` as
    /// [`sysfs_covered`](Self::sysfs_covered) does. Debugfs is a mount of
    /// its own at `sys/kernel/debug`, so an entry inside it is judged
    /// against that mount, and against a mount over `sys/kernel`, which
    /// hides it. An entry that is absent is the kernel's own absence only
    /// when this returns it.
    ///
    /// The configfs listings and a process's own directory are judged once
    /// for a whole check, by [`configfs_reached`](Self::configfs_reached)
    /// and [`process_covered`](Self::process_covered).
    ///
    /// # Errors
    ///
    /// An error of a kind other than `NotFound` when a mount covers
    /// `entry`, so a caller that reads `NotFound` as absence does not read
    /// a cover as one.
    pub(super) fn shown<'a>(&self, mounts: &str, entry: &'a Path) -> io::Result<&'a Path> {
        let debug = self.sys.join("kernel/debug");
        let covered = if entry.starts_with(&self.proc) {
            self.procfs_covered(mounts, entry)
        } else if entry.starts_with(&debug) {
            self.covered(mounts, &debug, "debugfs", entry)
                || self.sysfs_covered(mounts, &self.sys.join("kernel"))
        } else {
            self.sysfs_covered(mounts, entry)
        };
        if covered {
            Err(io::Error::other("a mount covers the entry"))
        } else {
            Ok(entry)
        }
    }

    /// As [`shown`](Self::shown), by the mount table read now, for a read
    /// outside a check that holds one.
    ///
    /// # Errors
    ///
    /// As [`shown`](Self::shown), and when the mount table cannot be read.
    pub(super) fn kernel<'a>(&self, entry: &'a Path) -> io::Result<&'a Path> {
        self.shown(&self.mount_table()?, entry)
    }

    /// The trimmed text of `entry` when it is the kernel's own by the mount
    /// table read now; `None` when a mount covers it or it cannot be read.
    pub(super) fn kernel_text(&self, entry: &Path) -> Option<String> {
        Self::read(self.kernel(entry).ok()?)
    }

    /// Whether the last line of `mounts` whose mount point is at or below
    /// `base` and at or above `entry`, a path under `base`, covers the
    /// entry: any mount strictly below `base`, and a mount at `base` of a
    /// type other than `own`, the type of the file system the kernel mounts
    /// there. Resolution failures and entries outside `base` count as
    /// covered. A mount can show a link that leads to a part of `base` no
    /// mount covers, so a mount point is above the entry when it is at or
    /// above the entry's resolved path or one of its [`lookups`]: a name
    /// looked up inside a mount is the mount's entry, wherever it leads.
    fn covered(&self, mounts: &str, base: &Path, own: &str, entry: &Path) -> bool {
        let resolved = entry.ancestors().find_map(|above| {
            let below = entry.strip_prefix(above).ok()?;
            match fs::symlink_metadata(above) {
                Ok(_) => Some(fs::canonicalize(above).ok().map(|real| real.join(below))),
                // A name below a file is absent as a name below nothing is.
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                    ) =>
                {
                    None
                }
                Err(_) => Some(None),
            }
        });
        let (Some(Some(resolved)), Ok(real)) = (resolved, fs::canonicalize(base)) else {
            return true;
        };
        let Ok(inside) = resolved.strip_prefix(&real) else {
            return true;
        };
        let Some(lookups) = entry
            .strip_prefix(base)
            .ok()
            .and_then(|below| lookups(&real, below))
        else {
            return true;
        };
        // The mount table names `base` by this path, relative to the root.
        let Ok(named) = base.strip_prefix(&self.root) else {
            return false;
        };
        let initial = named.as_os_str().as_encoded_bytes().first().copied();
        for line in mounts.lines().rev() {
            let mut fields = line.split(' ').skip(1);
            let (Some(at), Some(kind)) = (fields.next(), fields.next()) else {
                continue;
            };
            // A literal initial byte survives mount-table decoding and path
            // normalization. Dot components and escapes need the full check.
            if let (Some(first), Some(&byte)) =
                (initial, at.trim_start_matches('/').as_bytes().first())
                && !matches!(first, b'.' | b'/')
                && !matches!(byte, b'.' | b'\\')
                && first != byte
            {
                continue;
            }
            let Some(at) = unescaped(at) else {
                continue;
            };
            let at = Path::new(&*at);
            if let Ok(below) = at.strip_prefix("/").unwrap_or(at).strip_prefix(named)
                && (inside.starts_with(below)
                    || lookups.iter().any(|lookup| lookup.starts_with(below)))
            {
                return kind != own || !below.as_os_str().is_empty();
            }
        }
        false
    }

    /// The character devices that carry commands to `namespace`: its
    /// controller's `nvme<c>`, which takes I/O commands for a namespace by
    /// its ID, and the namespace's generic device `ng<c>n<n>` on a kernel
    /// that registers one under the controller. Each is identified by the
    /// number its sysfs `dev` attribute states, so every node of the device
    /// is the one the walk matches, whatever file sits at its `/dev` path.
    ///
    /// # Errors
    ///
    /// `Unverifiable("devices")` when `namespace` is not `nvme<c>n<n>`, the
    /// generic device's sysfs entry cannot be read, or is absent where a
    /// mount of `mounts` [may hide](Self::shown) it, or the `dev`
    /// attribute of the controller, or of a registered generic device, is
    /// unreadable or not `major:minor`.
    fn character_nodes(&self, namespace: &str, mounts: &str) -> Result<Vec<Node>, IdentityError> {
        const UNVERIFIABLE: IdentityError = IdentityError::Unverifiable("devices");
        let (controller, generic) = character_names(namespace).ok_or(UNVERIFIABLE)?;
        let controller = self.sys.join("class/nvme").join(controller);
        let registered = controller.join(generic);
        let mut entries = vec![controller];
        match self
            .shown(mounts, &registered)
            .and_then(fs::symlink_metadata)
        {
            Ok(_) => entries.push(registered),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(UNVERIFIABLE),
        }
        let identified = |entry: &PathBuf| -> Option<Node> {
            let number = entry.join("dev");
            let number = self.shown(mounts, &number).ok()?;
            // A fixture's devices are regular files, identified at the
            // path under `dev` that carries the sysfs entry's name.
            #[cfg(test)]
            if self.file_nodes {
                return Self::node(&self.dev.join(entry.file_name()?));
            }
            let (major, minor) = Self::read(number).as_deref().and_then(device_number)?;
            Some(Node::Device {
                block: false,
                major,
                minor,
            })
        };
        entries
            .iter()
            .map(identified)
            .collect::<Option<_>>()
            .ok_or(UNVERIFIABLE)
    }

    /// Whether an enabled passthrough subsystem of the kernel's NVMe target
    /// forwards to `namespace`'s controller. A passthrough takes the
    /// controller inside the kernel and sends it every remote host's
    /// commands, so the namespace gains no holder, no exclusive claim, no
    /// mount or swap line and no descriptor in any process. Configfs lists
    /// each subsystem under `kernel/config/nvmet/subsystems/<nqn>` in sysfs,
    /// with `passthru/enable` and, in `passthru/device_path`, the path the
    /// passthrough was configured with, which can be any node of the
    /// controller's character device. The kernel opens that path where the
    /// writer resolves it, in the writer's mount namespace and root, and
    /// keeps no other record of the controller it took, so the path read
    /// here can name a different node, or none, while the passthrough holds
    /// the namespace's controller. Configfs mounts at any directory, so the
    /// listing is read under each directory
    /// [`configfs_dirs`](Self::configfs_dirs) names for `mounts`, the mount
    /// table. The controller of a namespace
    /// [`resolve`](Self::resolve) accepts is the one whose name precedes the
    /// namespace's `n<id>`. A directory with no such listing passes nothing
    /// through.
    ///
    /// A passthrough takes a controller only after writes to its `enable`
    /// and `device_path`, and a subsystem appears only by an entry made in
    /// the listing, so the pass watches the listing and each subsystem's
    /// `passthru` directory from before it reads them. The answer comes
    /// with that pass, which answers for every such change made since.
    ///
    /// # Errors
    ///
    /// `Unverifiable("targets")` when a `configfs` mount's directory is a
    /// malformed escape or lies outside UTF-8, a subsystem listing that exists,
    /// an existing `enable` or an enabled passthrough's `device_path` is
    /// unreadable, or an existing `passthru` directory cannot be watched,
    /// or when an enabled passthrough's path is neither the
    /// controller's `/dev` path nor a node of the controller here, so the
    /// controller it forwards to is unknown.
    fn passed_through<'a>(
        &self,
        namespace: &str,
        mounts: &str,
        changes: &'a Changes,
    ) -> Result<(bool, Pass<'a>), IdentityError> {
        let unverifiable = || IdentityError::Unverifiable("targets");
        let changes = changes.pass().map_err(|_| unverifiable())?;
        let field = |path: PathBuf| match fs::read_to_string(path) {
            Ok(text) => Ok(Some(text.trim_end_matches('\n').to_owned())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(unverifiable()),
        };
        let controller = namespace
            .rsplit_once('n')
            .filter(|(controller, id)| {
                !controller.is_empty() && !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit())
            })
            .map(|(controller, _)| controller);
        let dirs = self
            .configfs_dirs(mounts)
            .ok_or(IdentityError::Unverifiable("targets"))?;
        for configfs in dirs {
            let listing = configfs.join("nvmet/subsystems");
            let subsystems = match changes.watch(&listing).and_then(|()| fs::read_dir(listing)) {
                Ok(subsystems) => subsystems,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(_) => return Err(unverifiable()),
            };
            for subsystem in subsystems {
                let passthru = subsystem
                    .map_err(|_| unverifiable())?
                    .path()
                    .join("passthru");
                match changes.watch(&passthru) {
                    Ok(()) => {}
                    // A kernel built without passthrough gives a subsystem no such directory.
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(_) => return Err(unverifiable()),
                }
                if field(passthru.join("enable"))?.as_deref() != Some("1") {
                    continue;
                }
                let path = field(passthru.join("device_path"))?.ok_or_else(unverifiable)?;
                let controller = controller.ok_or_else(unverifiable)?;
                // The kernel prints the path as configured; `/dev/<controller>`
                // names the controller whether or not this process can see it.
                if path == format!("/dev/{controller}") {
                    return Ok((true, changes));
                }
                let forwarded = Self::node(&self.under_root(Path::new(&path)));
                let own = Self::node(&self.dev.join(controller));
                // The kernel opened the path where its writer resolved it, so
                // a different node here does not show another controller.
                if forwarded.is_none() || forwarded != own {
                    return Err(unverifiable());
                }
                return Ok((true, changes));
            }
        }
        Ok((false, changes))
    }

    /// The node the kernel records as the backing file of loop device
    /// `name`, from `LOOP_GET_STATUS64` on its node in [`dev`](Self::dev):
    /// the block device the file is the node of, or else the file by its
    /// filesystem and inode. The kernel takes these from the open backing
    /// file, whatever path names it. The node opened must be the block
    /// device `sys/block/<name>/dev` names. On a host with `file_nodes`
    /// set, the loop device's node is a hard link of its backing file and
    /// stands in for the record.
    ///
    /// `None` when the node cannot be opened or is not that block device,
    /// the device number is unreadable, or the request fails, as it does
    /// once the loop device is no longer configured.
    fn loop_record(&self, mounts: &str, name: &OsStr) -> Option<Node> {
        let path = self.dev.join(name);
        let number = self.sys.join("block").join(name).join("dev");
        let number = self.shown(mounts, &number).ok()?;
        #[cfg(test)]
        if self.file_nodes {
            return Self::node(&path);
        }
        let number = Self::read(number).as_deref().and_then(device_number)?;
        // `O_NONBLOCK` keeps a FIFO substituted at the node path from blocking the open.
        let device = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&path)
            .ok()?;
        if !block_device(&device.metadata().ok()?, number) {
            return None;
        }
        let mut info = MaybeUninit::<LoopInfo>::uninit();
        // SAFETY: `info` is writable for one `loop_info64` record, for the
        // call's duration, on a descriptor `device` owns.
        let result =
            unsafe { libc::ioctl(device.as_raw_fd(), LOOP_GET_STATUS64, info.as_mut_ptr()) };
        if result != 0 {
            return None;
        }
        // SAFETY: a zero result means the kernel filled the whole record.
        let info = unsafe { info.assume_init() };
        Some(if info.rdevice == 0 {
            Node::File {
                major: libc::major(info.device),
                minor: libc::minor(info.device),
                inode: info.inode,
            }
        } else {
            Node::Device {
                block: true,
                major: libc::major(info.rdevice),
                minor: libc::minor(info.rdevice),
            }
        })
    }

    /// Refuses while the pNFS block layout client's module is in use, and
    /// reports whether the module is present.
    /// `blocklayoutdriver` opens the block devices its servers' layouts name
    /// inside the kernel with no holder, so such a device gains no holder
    /// link, no exclusive claim and no descriptor in any process, and the
    /// mount table names the NFS export. The kernel lists those devices
    /// nowhere, so no namespace is shown unused while an NFS mount uses the
    /// driver. Each such mount holds a reference on the module, which
    /// `sys/module/blocklayoutdriver/refcnt` counts. A driver built into
    /// the kernel has no entry under `sys/module`, since it declares no
    /// parameter and no version, and no count of its mounts; the kernel's
    /// symbol table lists its symbols with no module name. So `Ok(false)`,
    /// for a host without the module, leaves the answer to
    /// [`ImageSymbols`]: a host with neither the module nor the built-in
    /// driver has no such mount.
    ///
    /// # Errors
    ///
    /// `Unverifiable("layouts")` when another mount of `mounts`
    /// [covers](Self::shown) the module's count, when the count is
    /// above zero, or when the module is present and its count is
    /// unreadable or not a decimal.
    fn layout_module_idle(&self, mounts: &str) -> Result<bool, IdentityError> {
        let module = self.sys.join("module/blocklayoutdriver");
        let count = module.join("refcnt");
        let count =
            (self.shown(mounts, &count)).map_err(|_| IdentityError::Unverifiable("layouts"))?;
        if matches!(fs::symlink_metadata(&module), Err(error) if error.kind() == io::ErrorKind::NotFound)
        {
            return Ok(false);
        }
        // The kernel prints the count of a module being unloaded as -1.
        Self::read(count)
            .and_then(|count| count.parse::<i64>().ok())
            .filter(|&count| count <= 0)
            .map(|_| true)
            .ok_or(IdentityError::Unverifiable("layouts"))
    }

    /// The name of every block device the RNBD server exports. The server
    /// opens an exported device inside the kernel without an exclusive
    /// claim, for its remote clients to read and write, so the device gains
    /// no holder, no mount or swap line and no descriptor in any process.
    /// Sysfs lists each exported device by its block device name under
    /// `class/rnbd-server/ctl/devices` while a client session maps it. A
    /// host without the server module has no such listing and exports
    /// nothing.
    ///
    /// The listing is not read at one instant: sysfs returns it in name-hash
    /// order and resumes after the last name it returned, so an export
    /// created during a reading lists behind the reading whenever its hash is
    /// lower, and an export moved from a device not yet listed to one already
    /// listed is in no single reading. The server sends no uevent when it
    /// adds or removes an export, so no counter brackets a reading. The
    /// listing is read until two readings in a row name the same exports, at
    /// most [`RNBD_PASSES`] times, and every export any reading names is
    /// returned. A reading that missed a moved export lacks the export the
    /// next reading lists, unless the export moves again during that reading
    /// too, so a reading that missed one is read again.
    ///
    /// # Errors
    ///
    /// `Unverifiable("rnbd")` when another mount of `mounts`
    /// [covers](Self::shown) the listing, when the listing exists
    /// and is unreadable, or when no two readings in a row named the same
    /// exports.
    fn rnbd_exports(&self, mounts: &str) -> Result<Vec<OsString>, IdentityError> {
        let unverifiable = |_| IdentityError::Unverifiable("rnbd");
        let listing = self.sys.join("class/rnbd-server/ctl/devices");
        let listing =
            (self.shown(mounts, &listing)).map_err(|_| IdentityError::Unverifiable("rnbd"))?;
        let reading = || -> Result<BTreeSet<OsString>, IdentityError> {
            match fs::read_dir(listing) {
                Ok(entries) => entries
                    .map(|entry| Ok(entry?.file_name()))
                    .collect::<io::Result<_>>()
                    .map_err(unverifiable),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(BTreeSet::new()),
                Err(error) => Err(unverifiable(error)),
            }
        };
        let mut previous = reading()?;
        let mut exports = previous.clone();
        for _pass in 1..RNBD_PASSES {
            let next = reading()?;
            if next == previous {
                return Ok(exports.into_iter().collect());
            }
            exports.extend(next.iter().cloned());
            previous = next;
        }
        Err(IdentityError::Unverifiable("rnbd"))
    }

    /// The device of each OCFS2 disk heartbeat region, by the name configfs
    /// prints in `cluster/<cluster>/heartbeat/<region>/dev`. The region opens
    /// its device inside the kernel without an exclusive claim, after which
    /// the tool that started it closes its descriptor, and its heartbeat
    /// thread reads and writes the device whether or not a volume is mounted
    /// from it. A region with no device prints nothing. The listing is read
    /// under each directory [`configfs_dirs`](Self::configfs_dirs) names for
    /// `mounts`. A directory with no cluster listing has no region.
    ///
    /// The regions are read one after another, so a device moved from a
    /// region not yet read to one already read is in no single pass. A
    /// region gains a device only by a write to its `dev`, and a region or a
    /// cluster appears only by an entry made in its parent, so each pass
    /// watches every directory it lists and every region it reads for such
    /// a change, from before it reads them, and a pass is returned only when
    /// it ends with none reported. A pass a change was reported in is read
    /// again, at most [`HEARTBEAT_PASSES`] in all. The devices come with the
    /// pass they were read in, which answers for changes made after it.
    ///
    /// # Errors
    ///
    /// `Unverifiable("heartbeats")` when a `configfs` mount's directory is a
    /// malformed escape or lies outside UTF-8, when the reports of
    /// `changes` cannot be read, when a change was reported in every pass,
    /// or as
    /// [`heartbeat_devices_under`](Self::heartbeat_devices_under) refuses.
    fn heartbeat_devices<'a>(
        &self,
        mounts: &str,
        changes: &'a Changes,
    ) -> Result<(Vec<String>, Pass<'a>), IdentityError> {
        let unverifiable = |_| IdentityError::Unverifiable("heartbeats");
        let dirs = self
            .configfs_dirs(mounts)
            .ok_or(IdentityError::Unverifiable("heartbeats"))?;
        for _pass in 0..HEARTBEAT_PASSES {
            let pass = changes.pass().map_err(unverifiable)?;
            let mut devices = Vec::new();
            for configfs in &dirs {
                Self::heartbeat_devices_under(configfs, &pass, &mut devices)?;
            }
            if pass.still().map_err(unverifiable)? {
                return Ok((devices, pass));
            }
        }
        Err(IdentityError::Unverifiable("heartbeats"))
    }

    /// Appends to `devices` the device of each heartbeat region listed under
    /// `configfs`, one configfs mount, each listing and each region's `dev`
    /// read after `changes` began to watch its directory.
    ///
    /// # Errors
    ///
    /// `Unverifiable("heartbeats")` when a cluster listing exists and it,
    /// a cluster's region listing or a region's device entry is unreadable,
    /// or one of their directories cannot be watched.
    fn heartbeat_devices_under(
        configfs: &Path,
        changes: &Pass<'_>,
        devices: &mut Vec<String>,
    ) -> Result<(), IdentityError> {
        let unverifiable = |_| IdentityError::Unverifiable("heartbeats");
        let absent = |error: &io::Error| error.kind() == io::ErrorKind::NotFound;
        let listing = configfs.join("cluster");
        let clusters = match changes.watch(&listing).and_then(|()| fs::read_dir(listing)) {
            Ok(clusters) => clusters,
            Err(error) if absent(&error) => return Ok(()),
            Err(error) => return Err(unverifiable(error)),
        };
        for cluster in clusters {
            let regions = cluster.map_err(unverifiable)?.path().join("heartbeat");
            changes.watch(&regions).map_err(unverifiable)?;
            for region in fs::read_dir(regions).map_err(unverifiable)? {
                let region = region.map_err(unverifiable)?.path();
                // The heartbeat directory holds the cluster's heartbeat settings as files beside its regions.
                match changes
                    .watch(&region)
                    .and_then(|()| fs::read_to_string(region.join("dev")))
                {
                    Ok(device) => {
                        let device = device.strip_suffix('\n').unwrap_or(&device);
                        if !device.is_empty() {
                            devices.push(device.to_owned());
                        }
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                        ) => {}
                    Err(error) => return Err(unverifiable(error)),
                }
            }
        }
        Ok(())
    }

    /// Whether a host with `file_nodes` set claims `opened`: a regular file
    /// with the filesystem and inode of `resolved`, on the filesystem whose
    /// device number is `number`.
    #[cfg(test)]
    fn fixture_claim(&self, opened: &fs::Metadata, resolved: Node, number: (u32, u32)) -> bool {
        let filesystem = (libc::major(opened.dev()), libc::minor(opened.dev()));
        let node = Node::File {
            major: filesystem.0,
            minor: filesystem.1,
            inode: opened.ino(),
        };
        self.file_nodes && opened.file_type().is_file() && node == resolved && filesystem == number
    }
}

/// One check's read of the kernel's symbol table for the pNFS block layout
/// driver built into the kernel's own image. The image lists the same
/// symbols for as long as the kernel runs, so one check reads the table at
/// most once, for the first layout reading that finds no module, and every
/// later reading takes that answer. The read is megabytes of text, so
/// [`begin`](Self::begin) starts it on a thread of its own, where it runs
/// beside the check's other readings until one needs its answer.
struct ImageSymbols {
    /// The symbol table's path, `proc/kallsyms`.
    table: PathBuf,
    /// The read [`begin`](Self::begin) started, until its answer is taken.
    ahead: Cell<Option<JoinHandle<Option<bool>>>>,
    /// Whether a layout reading called [`begin`](Self::begin).
    begun: Cell<bool>,
    /// Whether the image lists the driver; `None` inside for a table that
    /// is unreadable or holds bytes outside UTF-8.
    built_in: OnceCell<Option<bool>>,
}

impl ImageSymbols {
    fn of(table: PathBuf) -> Self {
        Self {
            table,
            ahead: Cell::new(None),
            begun: Cell::new(false),
            built_in: OnceCell::new(),
        }
    }

    /// Starts the read for a layout reading on a host without the module.
    /// When the thread fails to start, the first call that needs the answer
    /// reads the table.
    fn begin(&self) {
        self.begun.set(true);
        let table = self.table.clone();
        let read = thread::Builder::new().spawn(move || built_in_layout_driver(&table));
        self.ahead.set(read.ok());
    }

    /// Refuses a kernel whose image holds the driver, waiting for the read
    /// [`begin`](Self::begin) started or reading the table now.
    ///
    /// # Errors
    ///
    /// `Unverifiable("layouts")` when the symbol table lists the built-in
    /// driver or is unreadable.
    ///
    /// # Panics
    ///
    /// With the panic of the thread that read the table.
    fn lists_no_driver(&self) -> Result<(), IdentityError> {
        let built_in = self.built_in.get_or_init(|| match self.ahead.take() {
            Some(ahead) => ahead
                .join()
                .unwrap_or_else(|panic| panic::resume_unwind(panic)),
            None => built_in_layout_driver(&self.table),
        });
        built_in
            .filter(|built_in| !built_in)
            .map(drop)
            .ok_or(IdentityError::Unverifiable("layouts"))
    }

    /// The verdict of the layout reading that called
    /// [`begin`](Self::begin); `Ok` before any reading has called it.
    ///
    /// # Errors
    ///
    /// As [`lists_no_driver`](Self::lists_no_driver).
    ///
    /// # Panics
    ///
    /// As [`lists_no_driver`](Self::lists_no_driver).
    fn settle(&self) -> Result<(), IdentityError> {
        if self.begun.get() {
            self.lists_no_driver()
        } else {
            Ok(())
        }
    }
}

/// Whether the kernel's symbol table at `table` lists the pNFS block layout
/// driver's `bl_alloc_deviceid_node` as a symbol of the kernel's own image,
/// or `None` when the table is unreadable or holds bytes outside UTF-8. A
/// symbol of a loaded module carries the module's name as a fourth field; a
/// built-in driver's has three. The table holds a line for each symbol the
/// kernel records, so only the lines that hold the symbol's name are split
/// into fields.
fn built_in_layout_driver(table: &Path) -> Option<bool> {
    const SYMBOL: &str = "bl_alloc_deviceid_node";
    let mut symbols = Vec::new();
    Host::stream(table, |chunk| symbols.extend_from_slice(chunk))?;
    let symbols = std::str::from_utf8(&symbols).ok()?.trim();
    Some(
        memchr::memmem::find_iter(symbols.as_bytes(), SYMBOL).any(|at| {
            let start = symbols[..at].rfind('\n').map_or(0, |end| end + 1);
            let line = symbols[start..].split('\n').next().unwrap_or_default();
            let mut fields = line.split_ascii_whitespace().skip(2);
            fields.next() == Some(SYMBOL) && fields.next().is_none()
        }),
    )
}

/// The controller `nvme<c>` and the generic device `ng<c>n<n>` of the
/// namespace `nvme<c>n<n>`, or `None` for another name. The kernel names all
/// three from the same two numbers.
fn character_names(namespace: &str) -> Option<(String, String)> {
    let numbers = namespace.strip_prefix("nvme")?;
    let (controller, id) = numbers.split_once('n')?;
    let decimal = |text: &str| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit());
    (decimal(controller) && decimal(id))
        .then(|| (format!("nvme{controller}"), format!("ng{numbers}")))
}

/// The directory of each `configfs` line of `mounts`, the mount table, and
/// whether a later line's directory, the same one or one above it, covers it.
/// A mount table line holds its source, directory and type between single
/// spaces, and the kernel escapes a space inside a field, so the directory is
/// the second field of a line whose source is empty too. The kernel lists a
/// mount namespace's mounts in the order they were made, so a mount listed
/// later at the directory or above it was made over the configfs mount, and a
/// path through the directory reaches that mount instead.
fn configfs_mounts(mounts: &str) -> impl Iterator<Item = (usize, &str, bool)> {
    mounts.lines().enumerate().filter_map(move |(at, line)| {
        let mut fields = line.split(' ').skip(1);
        let dir = fields.next()?;
        (fields.next()? == "configfs").then(|| {
            let covered = mounts
                .lines()
                .skip(at + 1)
                .filter_map(|later| later.split(' ').nth(1))
                .any(|later| Path::new(dir).starts_with(later));
            (at, dir, covered)
        })
    })
}

/// Whether `opened` is a block device whose device number is `number`.
fn block_device(opened: &fs::Metadata, number: (u32, u32)) -> bool {
    opened.file_type().is_block_device()
        && (libc::major(opened.rdev()), libc::minor(opened.rdev())) == number
}

/// The kernel follows at most this many symbolic links while it resolves one
/// path and returns `ELOOP` at the next one.
pub(super) const LINKS_FOLLOWED: u32 = 40;

/// The walk returns `None` if reading a name or a link fails or if it follows
/// more than [`LINKS_FOLLOWED`] links.
fn lookups(real: &Path, below: &Path) -> Option<Vec<PathBuf>> {
    let mut places = Vec::new();
    let mut at = real.to_path_buf();
    let mut links = 0;
    walk_names(below, &mut at, &mut links, &mut |place| {
        if let Ok(inside) = place.strip_prefix(real) {
            places.push(inside.to_path_buf());
        }
    })?;
    Some(places)
}

/// The deepest lookup represents each uninterrupted descent: every earlier
/// name in that descent is a prefix. An absent name ends the whole walk,
/// including the pending suffix of a path that led through a link.
fn walk_names(
    path: &Path,
    at: &mut PathBuf,
    links: &mut u32,
    record: &mut impl FnMut(&Path),
) -> Option<bool> {
    let mut descending = false;
    for component in path.components() {
        match component {
            Component::RootDir => *at = PathBuf::from("/"),
            Component::ParentDir => {
                if descending {
                    record(at);
                    descending = false;
                }
                at.pop();
            }
            Component::Normal(name) => {
                at.push(name);
                match fs::symlink_metadata(&*at) {
                    Ok(found) if found.is_symlink() => {
                        record(at);
                        *links += 1;
                        if *links > LINKS_FOLLOWED {
                            return None;
                        }
                        let target = fs::read_link(&*at).ok()?;
                        at.pop();
                        if !walk_names(&target, at, links, record)? {
                            return Some(false);
                        }
                        descending = false;
                    }
                    Ok(_) => descending = true,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                        ) =>
                    {
                        record(at);
                        return Some(false);
                    }
                    Err(_) => return None,
                }
            }
            Component::CurDir | Component::Prefix(_) => {}
        }
    }
    if descending {
        record(at);
    }
    Some(true)
}

/// A mount table path with its `\ooo` octal escapes, which stand for a space,
/// tab, newline or backslash, replaced by the bytes they name. `None` for a
/// malformed escape or a path outside UTF-8.
fn unescaped(path: &str) -> Option<Cow<'_, str>> {
    if !path.contains('\\') {
        return Some(Cow::Borrowed(path));
    }
    let mut bytes = Vec::with_capacity(path.len());
    let mut rest = path.as_bytes();
    while let [first, tail @ ..] = rest {
        if *first == b'\\' {
            let (digits, tail) = tail.split_at_checked(3)?;
            if !digits.iter().all(|digit| (b'0'..=b'7').contains(digit)) {
                return None;
            }
            bytes.push(u8::from_str_radix(std::str::from_utf8(digits).ok()?, 8).ok()?);
            rest = tail;
        } else {
            bytes.push(*first);
            rest = tail;
        }
    }
    String::from_utf8(bytes).ok().map(Cow::Owned)
}
