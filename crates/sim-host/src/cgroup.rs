//! The runner's cgroup-v2 layout under the unit's delegated group: the
//! runner in `runner/`, the sweep under `campaign/`, and one confirmation
//! root per root nonce under `confirm/`. A group that enables domain
//! controllers holds no process itself, so the runner moves to `runner/`
//! before it enables them. The checks here read the unit's controllers,
//! its writable files and the CPU and memory limits of the unit and its
//! ancestors.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const CONTROLLERS: [&str; 3] = ["cpu", "memory", "pids"];

#[derive(Clone, Debug)]
pub struct Layout {
    pub runner: PathBuf,
    pub campaign: PathBuf,
    pub confirm: PathBuf,
}

impl Layout {
    pub fn of(unit: &Path) -> Self {
        Self {
            runner: unit.join("runner"),
            campaign: unit.join("campaign"),
            confirm: unit.join("confirm"),
        }
    }

    pub fn sweep(&self) -> PathBuf {
        self.campaign.join("sweep")
    }

    pub fn confirm_root(&self, nonce: &str) -> PathBuf {
        self.confirm.join(nonce)
    }
}

pub fn own() -> io::Result<PathBuf> {
    let text = fs::read_to_string("/proc/self/cgroup")?;
    let path = text
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| io::Error::other("/proc/self/cgroup names no cgroup-v2 group"))?;
    Ok(Path::new("/sys/fs/cgroup").join(path.trim_start_matches('/')))
}

fn make(group: &Path) -> io::Result<()> {
    match fs::create_dir(group) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists && group.is_dir() => Ok(()),
        Err(error) => Err(io::Error::new(
            error.kind(),
            format!("{}: {error}", group.display()),
        )),
    }
}

/// Makes the layout under `unit`, moves this process to `runner/` and
/// enables the controllers under `unit` and `confirm/`. Enabling domain
/// controllers requires a cgroup that holds no process, so the runner moves
/// before it enables them, and `confirm/` holds only the confirmation
/// roots.
pub fn delegate(unit: &Path) -> io::Result<Layout> {
    let layout = Layout::of(unit);
    for group in [&layout.runner, &layout.campaign, &layout.confirm] {
        make(group)?;
    }
    write(
        &layout.runner.join("cgroup.procs"),
        std::process::id().to_string().as_bytes(),
    )?;
    let enable = CONTROLLERS.map(|name| format!("+{name}")).join(" ");
    write(&unit.join("cgroup.subtree_control"), enable.as_bytes())?;
    write(
        &layout.confirm.join("cgroup.subtree_control"),
        enable.as_bytes(),
    )?;
    Ok(layout)
}

pub fn make_confirm_root(layout: &Layout, nonce: &str) -> io::Result<PathBuf> {
    let group = layout.confirm_root(nonce);
    make(&group)?;
    Ok(group)
}

fn write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    fs::OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|mut file| file.write_all(bytes))
        .map_err(|error| io::Error::new(error.kind(), format!("{}: {error}", path.display())))
}

pub fn usage_usec(group: &Path) -> io::Result<Option<u64>> {
    let text = match fs::read_to_string(group.join("cpu.stat")) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    text.lines()
        .find_map(|line| line.strip_prefix("usage_usec "))
        .and_then(|value| value.trim().parse().ok())
        .map(Some)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} holds no usage_usec", group.join("cpu.stat").display()),
            )
        })
}

pub fn missing_controllers(unit: &Path) -> io::Result<Vec<&'static str>> {
    let path = unit.join("cgroup.controllers");
    let listed = fs::read_to_string(&path)
        .map_err(|error| io::Error::new(error.kind(), format!("{}: {error}", path.display())))?;
    Ok(CONTROLLERS
        .into_iter()
        .filter(|name| !listed.split_whitespace().any(|listed| listed == *name))
        .collect())
}

fn writable(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    let Ok(name) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `name` is a NUL-terminated path for the length of the call.
    unsafe { libc::faccessat(libc::AT_FDCWD, name.as_ptr(), libc::W_OK, libc::AT_EACCESS) == 0 }
}

pub fn unwritable(unit: &Path) -> Vec<PathBuf> {
    [
        unit.to_owned(),
        unit.join("cgroup.procs"),
        unit.join("cgroup.subtree_control"),
    ]
    .into_iter()
    .filter(|path| !writable(path))
    .collect()
}

/// Whether `path` is absolute and has no `..` component. A path that also
/// passes through no symlink, which [`real`] checks, has its lexical
/// parents as its real ancestors, as `campaign` requires of a cgroup root.
pub fn is_plain_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| component != std::path::Component::ParentDir)
}

/// Checks that `unit` is absolute, holds no `..` and resolves to itself,
/// so it passes through no symlink. This is a check at the time of the
/// call; a later replacement of a component is not seen.
///
/// # Errors
///
/// A path that fails one of these rules, or one that cannot be resolved.
pub fn real(unit: &Path) -> io::Result<()> {
    if !is_plain_absolute(unit) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not an absolute path without `..`", unit.display()),
        ));
    }
    if fs::canonicalize(unit)? != unit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} passes through a symlink", unit.display()),
        ));
    }
    Ok(())
}

/// The CPU and memory limits that `unit` and its ancestors set. The walk
/// ends at the first directory without `cgroup.controllers`, the parent of
/// the cgroup-v2 mount.
///
/// # Errors
///
/// A path that [`real`] refuses, whose lexical parents are not its
/// ancestors, or a limit file that cannot be read.
pub fn limits(unit: &Path) -> io::Result<Vec<String>> {
    real(unit)?;
    let mut found = Vec::new();
    let mut group = Some(unit);
    while let Some(dir) = group {
        if !dir.join("cgroup.controllers").exists() {
            break;
        }
        for (name, unlimited) in [("cpu.max", "max"), ("memory.max", "max")] {
            match fs::read_to_string(dir.join(name)) {
                Ok(value) => {
                    let value = value.trim();
                    if value.split_whitespace().next() != Some(unlimited) {
                        found.push(format!("{} sets {name} {value}", dir.display()));
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        group = dir.parent();
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::file::scratch;

    #[test]
    fn a_limit_on_any_ancestor_is_listed_and_the_walk_stops_at_the_mount() {
        let base = scratch("cgroup");
        let unit = base.join("fs/slice/unit");
        fs::create_dir_all(&unit).expect("the groups");
        for dir in [base.join("fs"), base.join("fs/slice"), unit.clone()] {
            fs::write(dir.join("cgroup.controllers"), "cpu memory pids").expect("controllers");
        }
        fs::write(base.join("cpu.max"), "1 100000").expect("a limit outside the mount");
        fs::write(unit.join("cpu.max"), "max 100000").expect("no limit");
        fs::write(unit.join("memory.max"), "max").expect("no limit");
        assert!(super::limits(&unit).expect("the walk").is_empty());
        fs::write(base.join("fs/slice/memory.max"), "1073741824").expect("a limit");
        let found = super::limits(&unit).expect("the walk");
        assert_eq!(found.len(), 1);
        assert!(found[0].contains("memory.max 1073741824"), "{found:?}");
        // The link's lexical parent is `base`, which skips the limited
        // `fs/slice` that the path really passes through.
        let link = base.join("link");
        std::os::unix::fs::symlink(base.join("fs/slice"), &link).expect("a link");
        for refused in [
            std::path::Path::new("fs/slice/unit"),
            &base.join("fs/slice/../slice/unit"),
            &link.join("unit"),
        ] {
            let error = super::limits(refused).expect_err("a path whose parents are not ancestors");
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::InvalidInput,
                "{refused:?}"
            );
        }
        fs::remove_dir_all(&base).expect("cleanup");
    }

    #[test]
    fn delegation_moves_the_runner_and_enables_controllers_for_both_parents() {
        let unit = scratch("delegate");
        fs::create_dir_all(&unit).expect("the unit");
        assert!(
            super::delegate(&unit).is_err(),
            "a tree without control files"
        );
        assert!(!unit.join("runner/cgroup.procs").exists());
        for dir in ["runner", "confirm"] {
            fs::create_dir_all(unit.join(dir)).expect("a group");
        }
        for file in [
            "cgroup.subtree_control",
            "runner/cgroup.procs",
            "confirm/cgroup.subtree_control",
        ] {
            fs::write(unit.join(file), "").expect("a control file");
        }
        let layout = super::delegate(&unit).expect("the delegation");
        assert_eq!(
            fs::read_to_string(layout.runner.join("cgroup.procs")).expect("procs"),
            std::process::id().to_string()
        );
        for parent in [&unit, &layout.confirm] {
            assert_eq!(
                fs::read_to_string(parent.join("cgroup.subtree_control")).expect("control"),
                "+cpu +memory +pids"
            );
        }
        assert_eq!(layout.campaign, unit.join("campaign"));
        assert_eq!(layout.sweep(), unit.join("campaign/sweep"));
        let root = super::make_confirm_root(&layout, "ab").expect("a confirmation root");
        assert_eq!(root, unit.join("confirm/ab"));
        assert!(root.is_dir());
        fs::remove_dir_all(&unit).expect("cleanup");
    }

    #[test]
    fn a_counter_without_usage_is_an_error_and_an_absent_group_is_none() {
        let group = scratch("usage");
        fs::create_dir_all(&group).expect("the group");
        assert_eq!(super::usage_usec(&group).expect("absent"), None);
        fs::write(group.join("cpu.stat"), "usage_usec 42\nuser_usec 1\n").expect("a counter");
        assert_eq!(super::usage_usec(&group).expect("a counter"), Some(42));
        fs::write(group.join("cpu.stat"), "user_usec 1\n").expect("a counter");
        assert!(super::usage_usec(&group).is_err());
        fs::remove_dir_all(&group).expect("cleanup");
    }
}
