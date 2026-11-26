//! The filesystem contract of a state directory: it lies on a read-write
//! journaled ext4 mount in ordered or journal data mode, or on a read-write
//! xfs mount, with write barriers enabled; it is a directory the running
//! user owns with mode 0700; and the process umask clears no owner
//! permission bit, so the store's creates get their exact modes. File and
//! directory `fsync` on such a mount survive a process crash, and survive
//! a VM reset when the disk completes a flush only after prior writes are
//! stable, which this check cannot observe; power-loss durability is
//! unproven. The filesystem type alone
//! does not establish this, since ext2, ext3 and ext4 share one magic and
//! mount options are invisible to it, so the check reads the mount record
//! of the directory's own mount. The mount record prints an ext4 data mode
//! only when it differs from the superblock's default, and prints none
//! without a journal, so for ext4 the check also reads the kernel's full
//! option list for the device, `/proc/fs/ext4/DEVICE/options`, and requires
//! ordered or journal data mode there.

use std::fs::{File, Metadata};
use std::os::unix::fs::MetadataExt;

use super::{Refusal, read};
use crate::step::{self, Step};
use crate::sys;

/// The most bytes of any one kernel table the check reads.
const TABLE_BOUND: u64 = 4 << 20;

/// The fields of one `/proc/self/mountinfo` record the contract reads.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Mount<'a> {
    /// The mount's `major:minor` device number, as `/sys/dev/block` names
    /// it.
    pub(super) device: &'a str,
    pub(super) fstype: &'a str,
    pub(super) mount_options: &'a str,
    pub(super) super_options: &'a str,
}

/// Checks that `dir`, whose status is `status`, meets the filesystem
/// contract.
pub(super) fn check(dir: &File, status: &Metadata) -> Result<(), super::Error> {
    writable(dir)?;
    owned(status.uid(), status.mode(), sys::euid())?;
    // The calling thread's status reports the umask its creates use.
    umask(&table("/proc/thread-self/status")?)?;
    Ok(())
}

pub(super) fn writable(dir: &File) -> Result<(), super::Error> {
    let mounts = table("/proc/self/mountinfo")?;
    let mount = mounted(dir, &mounts)?;
    supported(&mount)?;
    if mount.fstype == "ext4" {
        let uevent = table(&format!("/sys/dev/block/{}/uevent", mount.device))?;
        let device = devname(&uevent)
            .ok_or_else(|| Refusal::Mount(format!("device {} has no name", mount.device)))?;
        journaled(&table(&format!("/proc/fs/ext4/{device}/options"))?)?;
    }
    Ok(())
}

/// Checks that `dir`, whose status is `status`, may be read as a
/// published directory without the store's lock: it lies on an ext4 or xfs
/// mount, whose status-change times the identity cache relies on, and it
/// is a directory the running user owns with mode 0700. The writer-only
/// rules, a read-write journaled mount and the umask, are left to
/// [`check`].
pub(super) fn viewable(dir: &File, status: &Metadata) -> Result<(), super::Error> {
    let mounts = table("/proc/self/mountinfo")?;
    filesystem(&mounted(dir, &mounts)?)?;
    owned(status.uid(), status.mode(), sys::euid())?;
    Ok(())
}

/// The record, in the mount table `mounts`, of the mount `dir` lies on.
fn mounted<'a>(dir: &File, mounts: &'a str) -> Result<Mount<'a>, super::Error> {
    let id = step::call(Step::Stat, || sys::mount_id(dir))?;
    let mount = record(mounts, id)
        .ok_or_else(|| Refusal::Mount(format!("mount {id} has no mount record")))?;
    Ok(mount)
}

/// Whether `mount` is ext4 or xfs.
fn filesystem(mount: &Mount<'_>) -> Result<(), Refusal> {
    if matches!(mount.fstype, "ext4" | "xfs") {
        Ok(())
    } else {
        Err(Refusal::Filesystem(mount.fstype.to_owned()))
    }
}

/// The text of the kernel table at `path`, read up to its bound.
fn table(path: &str) -> Result<String, super::Error> {
    let file = step::call(Step::Open, || File::open(path))?;
    let text = read::capped(&file, TABLE_BOUND, 0)?
        .ok_or_else(|| Refusal::Mount(format!("{path} exceeds its read bound")))?;
    Ok(String::from_utf8_lossy(&text).into_owned())
}

/// The device name a block device's `uevent` text gives. A name holding
/// `/` is refused, since it must be one component of the
/// `/proc/fs/ext4/DEVICE` path.
pub(super) fn devname(uevent: &str) -> Option<&str> {
    uevent
        .lines()
        .find_map(|line| line.strip_prefix("DEVNAME="))
        .filter(|name| !name.is_empty() && !name.contains('/'))
}

/// Whether an ext4 device's full option list, one option per line, names
/// ordered or journal data mode and leaves barriers enabled. A filesystem
/// without a journal lists no data mode.
pub(super) fn journaled(options: &str) -> Result<(), Refusal> {
    let mut options = options.split_whitespace();
    if options.clone().any(|option| option == "nobarrier") {
        return Err(Refusal::Mount("nobarrier".into()));
    }
    match options.find(|option| option.starts_with("data=")) {
        Some("data=ordered" | "data=journal") => Ok(()),
        Some(mode) => Err(Refusal::Mount(mode.to_owned())),
        None => Err(Refusal::Mount("no journal data mode".into())),
    }
}

/// The record of mount `id` in the text of `/proc/self/mountinfo`.
pub(super) fn record(text: &str, id: u64) -> Option<Mount<'_>> {
    text.lines().find_map(|line| {
        // Fields: mount ID, parent ID, major:minor, root, mount point,
        // per-mount options, zero or more optional fields, `-`, filesystem
        // type, source, superblock options.
        let mut fields = line.split(' ');
        if fields.next()?.parse::<u64>().ok()? != id {
            return None;
        }
        let device = fields.nth(1)?;
        let mount_options = fields.nth(2)?;
        let mut rest = fields.skip_while(|&field| field != "-").skip(1);
        let fstype = rest.next()?;
        let super_options = rest.nth(1)?;
        Some(Mount {
            device,
            fstype,
            mount_options,
            super_options,
        })
    })
}

/// Whether `mount`'s record meets the filesystem contract: ext4 or xfs,
/// mounted read-write. The ext4 data mode and barriers are checked on the
/// device's full option list. The mount ID comes from statx's
/// `STATX_MNT_ID`, which kernels report from 5.8, and xfs has had no
/// option that disables cache flushes since 4.19, so every xfs mount this
/// check reaches flushes.
pub(super) fn supported(mount: &Mount<'_>) -> Result<(), Refusal> {
    filesystem(mount)?;
    let mut options = mount
        .mount_options
        .split(',')
        .chain(mount.super_options.split(','));
    if options.any(|option| option == "ro") {
        return Err(Refusal::Mount("ro".into()));
    }
    Ok(())
}

/// Whether the umask a process status text reports leaves every owner
/// permission bit, so each create's 0600 or 0700 mode is exact.
pub(super) fn umask(status: &str) -> Result<(), Refusal> {
    let mask = status
        .lines()
        .find_map(|line| line.strip_prefix("Umask:"))
        .and_then(|mask| u32::from_str_radix(mask.trim(), 8).ok());
    match mask {
        Some(mask) if mask & 0o700 == 0 => Ok(()),
        mask => Err(Refusal::Umask(mask)),
    }
}

/// Whether a directory owned by `uid` with `mode` is one the user `euid`
/// may keep state in: owned by `euid`, with permission bits exactly 0700.
pub(super) fn owned(uid: u32, mode: u32, euid: u32) -> Result<(), Refusal> {
    if uid != euid {
        return Err(Refusal::Owner(uid));
    }
    if mode & 0o7777 != 0o700 {
        return Err(Refusal::Mode(mode & 0o7777));
    }
    Ok(())
}
