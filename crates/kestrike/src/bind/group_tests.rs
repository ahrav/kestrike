//! The last step of a VFIO group guard, over a fixture host tree: once the
//! group file is open and its status read, the guard is accepted only while
//! the device's `iommu_group` link still names the group the guard holds. A
//! link retargeted to another group, removed or made non-numeric during the
//! status request refuses the guard at the step `group`, with the group
//! device named `<group>` or `noiommu-<group>`.

use std::cell::Cell;
use std::fs::{self, File};
use std::io;
use std::net::Ipv4Addr;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::super::fixture::{BDF, Fixture, group_of};
use super::super::host::{Kernel, Started};
use super::{GroupError, VIABLE};

/// What happens to the device's `iommu_group` link while the status request runs.
#[derive(Clone, Copy, Debug)]
enum Change {
    Unchanged,
    /// The link is replaced by one that reaches the same group directory
    /// through another path.
    SameGroup,
    /// The link is replaced by one whose target names another group number.
    Retargeted,
    Removed,
    /// The link is replaced by one whose target is a non-numeric name.
    NotANumber,
}

/// A kernel that opens the group file it is given and reports the group
/// viable with no container. Its first status request, which the guard
/// makes with the group file open, applies `change` to `link` before it
/// answers.
struct ChangingKernel {
    link: PathBuf,
    change: Change,
    /// Whether a status request ran, and so applied the change.
    applied: Cell<bool>,
}

impl Kernel for ChangingKernel {
    fn write(&self, _: &Path, _: &str) -> io::Result<()> {
        unreachable!("a guard writes nothing")
    }

    fn start<'k>(&'k self, _: &str, _: &[&str]) -> io::Result<Box<dyn Started + 'k>> {
        unreachable!("a guard runs no command")
    }

    fn solicit(&self, _: &str, _: Ipv4Addr) -> io::Result<()> {
        unreachable!("a guard solicits nothing")
    }

    fn settle(&self, _: Duration) {
        unreachable!("a guard waits for nothing")
    }

    fn now(&self) -> Instant {
        unreachable!("a guard reads no clock")
    }

    fn open_group(&self, path: &Path) -> io::Result<File> {
        File::options().read(true).write(true).open(path)
    }

    fn group_status(&self, _: &File) -> io::Result<u32> {
        if self.applied.replace(true) {
            return Ok(VIABLE);
        }
        // The fixture links a group by its path under `Host::sys`; this
        // reaches the same group directories from the device's directory.
        let groups = self
            .link
            .parent()
            .unwrap()
            .join("../../../../kernel/iommu_groups");
        let relink = |target: PathBuf| {
            fs::remove_file(&self.link).unwrap();
            symlink(target, &self.link).unwrap();
        };
        let held = group_of(BDF);
        match self.change {
            Change::Unchanged => {}
            Change::SameGroup => relink(groups.join(held.to_string())),
            Change::Retargeted => relink(groups.join((held + 1).to_string())),
            Change::Removed => fs::remove_file(&self.link).unwrap(),
            Change::NotANumber => relink(groups.join("abc")),
        }
        Ok(VIABLE)
    }
}

/// The guard's outcome for the fixture volume's controller, put on
/// `vfio-pci` with its group device named `<prefix><group>`: `Ok` when
/// accepted, otherwise the step it was refused at, or `in use` for a busy
/// group file. `change` happens during the first status request.
fn guard_after(change: Change, prefix: &str) -> Result<(), &'static str> {
    let fixture = Fixture::new(4096);
    let pci = fixture.host.pci(BDF);
    fs::remove_file(pci.join("driver")).unwrap();
    symlink(
        fixture.host.sys.join("bus/pci/drivers/vfio-pci"),
        pci.join("driver"),
    )
    .unwrap();
    assert_eq!(
        fixture.host.driver(BDF).as_deref(),
        Some("vfio-pci"),
        "the guard is taken for a device on vfio-pci"
    );
    let link = pci.join("iommu_group");
    let started = fs::read_link(&link).unwrap();
    let group = group_of(BDF);
    assert_eq!(
        fixture.host.iommu_group(BDF),
        Some(group.to_string()),
        "the device starts in its fixture group"
    );
    // A dangling link reads as one a mount covers, so the directories a
    // retargeted or non-numeric link names exist: each replaced link
    // resolves, and the guard reads the name of its target.
    for other in [(group + 1).to_string(), "abc".to_owned()] {
        fs::create_dir_all(fixture.host.sys.join("kernel/iommu_groups").join(other)).unwrap();
    }
    let name = format!("{prefix}{group}");
    fixture.file(&format!("sys/class/vfio/{name}/dev"), "1:3\n");
    symlink("/dev/null", fixture.host.dev.join("vfio").join(&name)).unwrap();
    let kernel = ChangingKernel {
        link,
        change,
        applied: Cell::new(false),
    };
    let outcome = fixture.host.guard_group(&kernel, BDF);
    assert!(
        kernel.applied.get(),
        "{change:?}: the group file was open and its status requested, which changed the link"
    );
    if let Change::SameGroup = change {
        assert_ne!(
            fs::read_link(&kernel.link).unwrap(),
            started,
            "the link was replaced"
        );
        assert_eq!(
            fs::canonicalize(&kernel.link).unwrap(),
            fs::canonicalize(&started).unwrap(),
            "the replaced link reaches the group directory the device started in"
        );
    }
    if let Change::Retargeted | Change::NotANumber = change {
        assert!(
            fs::canonicalize(&kernel.link).is_ok(),
            "{change:?}: the replaced link resolves"
        );
    }
    match outcome {
        Ok(_guard) => Ok(()),
        Err(GroupError::Unverifiable(step)) => Err(step),
        Err(GroupError::InUse) => Err("in use"),
    }
}

/// A guard is accepted when the device's `iommu_group` link, read again
/// after the status request, names the group the guard holds: the link
/// untouched, or replaced by one that reaches the same group directory
/// through another path, with the group device named `<group>` or
/// `noiommu-<group>`.
#[test]
fn a_guard_whose_device_still_names_its_group_is_accepted() {
    for prefix in ["", "noiommu-"] {
        for change in [Change::Unchanged, Change::SameGroup] {
            assert_eq!(
                guard_after(change, prefix),
                Ok(()),
                "{change:?}, group device {prefix}<group>"
            );
        }
    }
}

/// A device whose `iommu_group` link names another group, is gone or names
/// a non-numeric target once the status request returns has left the group
/// the guard holds, so the guard is refused at the step `group`, with the
/// group device named `<group>` or `noiommu-<group>`.
#[test]
fn a_guard_whose_device_left_its_group_during_the_status_request_is_refused() {
    for prefix in ["", "noiommu-"] {
        for change in [Change::Retargeted, Change::Removed, Change::NotANumber] {
            assert_eq!(
                guard_after(change, prefix),
                Err("group"),
                "{change:?}, group device {prefix}<group>: the link no longer names the group the guard holds"
            );
        }
    }
}
