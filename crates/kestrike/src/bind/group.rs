//! The VFIO group guard release holds over each recorded device still on
//! `vfio-pci`, from before its first restore write through every restore.
//!
//! The approved kernel exposes VFIO through the classic group and container
//! interface alone, so every user of a device holds its group's file: a
//! container's device descriptor keeps a reference to the group file after
//! the user closes its group and container descriptors. The kernel opens a
//! group file for one holder at a time, so a guard that opens it proves no
//! other holder exists and keeps every later one out while it stays open.
//! The guard holds only the group file, detached from any container. A
//! group file pins the group alone, so the device's unbind completes while
//! the guard is open.
//!
//! A guard accepts only the group character device sysfs names for the
//! device's IOMMU group, `/dev/vfio/<group>` in IOMMU mode or
//! `/dev/vfio/noiommu-<group>` in no-IOMMU mode, checked by the device
//! number of the file it opened, and only a group the kernel reports viable
//! with no container set.

use std::fs::{self, File};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt};

use super::host::{Host, Kernel, device_number};

/// The VFIO request number `n`: `_IO(VFIO_TYPE, VFIO_BASE + n)`, with
/// `VFIO_TYPE` the character `;` and `VFIO_BASE` 100.
pub(crate) const fn vfio_request(n: libc::Ioctl) -> libc::Ioctl {
    (0x3b << 8) | (100 + n)
}
/// `VFIO_GROUP_GET_STATUS`.
const GET_STATUS: libc::Ioctl = vfio_request(3);
/// `VFIO_GROUP_FLAGS_VIABLE`: no driver or user claims DMA ownership of the
/// group, or a container holds it, which sets `CONTAINER_SET` too.
pub(crate) const VIABLE: u32 = 1 << 0;
/// `VFIO_GROUP_FLAGS_CONTAINER_SET`: a container holds the group.
pub(crate) const CONTAINER_SET: u32 = 1 << 1;

/// `struct vfio_group_status`.
#[repr(C)]
struct GroupStatus {
    argsz: u32,
    flags: u32,
}

/// Why a device's group guard was refused.
#[derive(Debug)]
pub(crate) enum GroupError {
    /// The kernel refuses the open with `EBUSY`: another process holds the
    /// group file or one of the group's devices.
    InUse,
    /// The guard cannot be verified, at the step named:
    ///
    /// - `group`: the device's `iommu_group` link is unreadable, names
    ///   something other than a decimal group number, or names another group
    ///   once the guard is open.
    /// - `node`: sysfs names neither or both group devices, a `dev` file is
    ///   unreadable or malformed, the open fails with an error other than
    ///   `EBUSY`, or the opened file is a file other than that character
    ///   device.
    /// - `status`: the status request fails, or the group is unviable or
    ///   already in a container.
    Unverifiable(&'static str),
}

/// The flags `VFIO_GROUP_GET_STATUS` reports for the open group `group`.
///
/// # Errors
///
/// The ioctl's error.
pub(crate) fn status(group: &File) -> io::Result<u32> {
    let mut status = GroupStatus {
        argsz: size_of::<GroupStatus>() as u32,
        flags: 0,
    };
    // SAFETY: `status` is a writable `vfio_group_status` whose `argsz` names
    // its size, for the call's duration, on a descriptor `group` owns.
    let result = unsafe { libc::ioctl(group.as_raw_fd(), GET_STATUS, &raw mut status) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(status.flags)
}

impl Host {
    /// Opens and checks the VFIO group file of `bdf`, which sits on
    /// `vfio-pci`, and returns it as the guard; dropping it closes the group.
    ///
    /// # Errors
    ///
    /// [`GroupError`] at the first failed step, in this order: the IOMMU
    /// group, the group device sysfs names, the open (`InUse` for `EBUSY`),
    /// the opened file's device number, the status, then the IOMMU group
    /// again, which must still be the one the guard holds.
    pub(crate) fn guard_group(&self, kernel: &impl Kernel, bdf: &str) -> Result<File, GroupError> {
        let unverifiable = GroupError::Unverifiable;
        let group = self.iommu_group(bdf).ok_or(unverifiable("group"))?;
        let mut named = Vec::new();
        for name in [group.clone(), format!("noiommu-{group}")] {
            let number = self.sys.join("class/vfio").join(&name).join("dev");
            match self.kernel(&number).and_then(fs::read_to_string) {
                Ok(text) => named.push((name, device_number(&text).ok_or(unverifiable("node"))?)),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(_) => return Err(unverifiable("node")),
            }
        }
        let [(name, (major, minor))] =
            <[_; 1]>::try_from(named).map_err(|_| unverifiable("node"))?;
        let guard = kernel
            .open_group(&self.dev.join("vfio").join(name))
            .map_err(|error| {
                if error.raw_os_error() == Some(libc::EBUSY) {
                    GroupError::InUse
                } else {
                    unverifiable("node")
                }
            })?;
        let opened = guard.metadata().map_err(|_| unverifiable("node"))?;
        if !opened.file_type().is_char_device() || opened.rdev() != libc::makedev(major, minor) {
            return Err(unverifiable("node"));
        }
        let flags = kernel
            .group_status(&guard)
            .map_err(|_| unverifiable("status"))?;
        if flags & VIABLE == 0 || flags & CONTAINER_SET != 0 {
            return Err(unverifiable("status"));
        }
        // The device is still in the group the guard holds.
        if self.iommu_group(bdf).as_ref() != Some(&group) {
            return Err(unverifiable("group"));
        }
        Ok(guard)
    }

    /// The decimal IOMMU group number sysfs links `bdf` to; `None` when a
    /// mount [covers](Self::kernel) the link.
    fn iommu_group(&self, bdf: &str) -> Option<String> {
        let link = self.pci(bdf).join("iommu_group");
        (self.kernel(&link).and_then(fs::read_link))
            .ok()
            .and_then(|target| Some(target.file_name()?.to_str()?.to_owned()))
            .filter(|group| !group.is_empty() && group.bytes().all(|b| b.is_ascii_digit()))
    }
}

#[cfg(test)]
#[path = "group_tests.rs"]
mod tests;
