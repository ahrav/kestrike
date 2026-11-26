//! Directory handles confine attempt cgroup operations beneath the delegated root.
//! `Root::limits_fit` reads `cpu.max`, `memory.max` and `pids.max` from each cgroup-v2 ancestor.
//! A root reserves the child names `controller`, which holds the process that opened
//! the root, and `sweep`, which `Root::sweep` opens and `Root::children` skips.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fs::{File, TryLockError};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::Name;
use crate::step::{self, Step};
use crate::sys;

pub(crate) const CPU_PERIOD_US: u64 = 100_000;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counters {
    pub cpu: BTreeMap<String, u64>,
    pub memory: BTreeMap<String, u64>,
    pub pids: BTreeMap<String, u64>,
}

#[derive(Debug)]
pub(crate) enum FitError {
    Limit {
        resource: &'static str,
        ancestor: PathBuf,
    },
    Io(io::Error),
}
impl From<io::Error> for FitError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub(crate) struct Root {
    directory: File,
    path: PathBuf,
}

pub(crate) struct Group {
    parent: File,
    name: CString,
    directory: File,
    events: File,
}

const SWEEP: &CStr = c"sweep";

fn attempt_name(name: &Name) -> io::Result<&CStr> {
    if name.as_str() == "controller" || name.as_c_str() == SWEEP {
        return Err(refused("cgroup name is reserved"));
    }
    Ok(name.as_c_str())
}

fn refused(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}

fn ceiling(value: &str) -> io::Result<Option<u64>> {
    if value == "max" {
        return Ok(None);
    }
    value
        .parse::<u64>()
        .map(Some)
        .map_err(|_| refused("invalid ancestor resource limit"))
}

fn open(directory: &File, name: &CStr, flags: i32) -> io::Result<File> {
    step::call(Step::Open, || sys::open_beneath(directory, name, flags, 0))
}

fn write(directory: &File, name: &CStr, bytes: &[u8]) -> io::Result<()> {
    let mut file = open(directory, name, libc::O_WRONLY)?;
    let count = step::write(bytes.len(), |length| file.write(&bytes[..length]))?;
    if count != bytes.len() {
        return Err(io::ErrorKind::WriteZero.into());
    }
    step::last(Step::Close, || sys::close(file))
}

fn read_file(file: &File) -> io::Result<String> {
    use std::os::unix::fs::FileExt;
    let mut bytes = [0; 4097];
    let length = step::call(Step::Read, || file.read_at(&mut bytes, 0))?;
    if length == bytes.len() {
        return Err(refused("cgroup file exceeds bound"));
    }
    String::from_utf8(bytes[..length].to_vec()).map_err(|_| refused("cgroup file is not UTF-8"))
}

fn read(directory: &File, name: &CStr) -> io::Result<String> {
    read_file(&open(directory, name, libc::O_RDONLY)?)
}

impl Root {
    /// Initialization moves this process into the controller child.
    /// The caller supplies its systemd delegation.
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        let directory = super::host::cgroup_directory(path)?;
        if step::call(Step::Stat, || directory.metadata())?.uid() != sys::euid() {
            return Err(refused("root must be a user-owned cgroup-v2 delegation"));
        }
        let controllers = read(&directory, c"cgroup.controllers")?;
        for needed in ["cpu", "memory", "pids"] {
            if !controllers.split_whitespace().any(|name| name == needed) {
                return Err(refused("delegation lacks cpu, memory or pids"));
            }
        }
        match step::call(Step::Mkdir, || sys::mkdir(&directory, c"controller", 0o700)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let controller = open(
            &directory,
            c"controller",
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
        write(
            &controller,
            c"cgroup.procs",
            std::process::id().to_string().as_bytes(),
        )?;
        write(&directory, c"cgroup.subtree_control", b"+cpu +memory +pids")?;
        let kill = open(&directory, c"cgroup.kill", libc::O_WRONLY)?;
        step::last(Step::Close, || sys::close(kill))?;
        for name in [
            c"cpu.max",
            c"memory.max",
            c"memory.swap.max",
            c"memory.oom.group",
            c"pids.max",
        ] {
            let limit = open(&controller, name, libc::O_WRONLY)?;
            step::last(Step::Close, || sys::close(limit))?;
        }
        Ok(Self {
            directory,
            path: path.to_owned(),
        })
    }

    pub(crate) fn sweep(&self) -> io::Result<Self> {
        match step::call(Step::Mkdir, || sys::mkdir(&self.directory, SWEEP, 0o700)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        Self::open(
            &self
                .path
                .join(std::ffi::OsStr::from_bytes(SWEEP.to_bytes())),
        )
    }

    /// `false` means another open file description holds a conflicting
    /// lock on the root directory. The kernel releases the lock when the
    /// last handle referring to the locked open file description closes.
    pub(crate) fn try_lock(&self) -> io::Result<bool> {
        step::call(Step::Lock, || match self.directory.try_lock() {
            Ok(()) => Ok(true),
            Err(TryLockError::WouldBlock) => Ok(false),
            Err(TryLockError::Error(error)) => Err(error),
        })
    }

    pub(crate) fn limits_fit(
        &self,
        cpu: u64,
        memory: u64,
        pids: u64,
        shares: u128,
    ) -> Result<(), FitError> {
        for path in self.path.ancestors() {
            let name = CString::new(path.as_os_str().as_bytes())
                .map_err(|_| refused("invalid ancestor path"))?;
            let directory = step::call(Step::Open, || sys::open_dir_nofollow(&name))?;
            if !step::call(Step::Stat, || sys::cgroup_v2(&directory))? {
                break;
            }
            let limits = [
                read(&directory, c"cpu.max"),
                read(&directory, c"memory.max"),
                read(&directory, c"pids.max"),
            ];
            if limits.iter().all(|value| {
                value
                    .as_ref()
                    .err()
                    .is_some_and(|error| error.kind() == io::ErrorKind::NotFound)
            }) {
                continue;
            }
            let [cpu_limit, memory_limit, pids_limit] = limits;
            let cpu_limit = cpu_limit?;
            let words: Vec<_> = cpu_limit.split_whitespace().collect();
            let [quota, period] = words.as_slice() else {
                return Err(refused("invalid ancestor cpu.max").into());
            };
            let period = period
                .parse::<u64>()
                .ok()
                .filter(|value| *value > 0)
                .ok_or_else(|| refused("invalid ancestor cpu period"))?;
            let quota = ceiling(quota)?;
            for (resource, fits) in [
                (
                    "aggregate cpu",
                    quota.is_none_or(|quota| {
                        shares
                            .checked_mul(u128::from(cpu))
                            .and_then(|sum| sum.checked_mul(u128::from(period)))
                            .is_some_and(|sum| sum < u128::from(quota) * u128::from(CPU_PERIOD_US))
                    }),
                ),
                (
                    "aggregate memory",
                    ceiling(memory_limit?.trim())?
                        .is_none_or(|limit| shares * u128::from(memory) < u128::from(limit)),
                ),
                (
                    "aggregate pids",
                    ceiling(pids_limit?.trim())?
                        .is_none_or(|limit| shares * u128::from(pids) + 1 < u128::from(limit)),
                ),
            ] {
                if !fits {
                    return Err(FitError::Limit {
                        resource,
                        ancestor: path.to_owned(),
                    });
                }
            }
        }
        Ok(())
    }

    pub(crate) fn contains(&self, path: &Path) -> bool {
        path.parent() == Some(self.path.as_path())
    }

    pub(crate) fn path(&self, name: &Name) -> io::Result<PathBuf> {
        let component = attempt_name(name)?;
        match open(&self.directory, component, libc::O_PATH | libc::O_NOFOLLOW) {
            Ok(file) => {
                if !step::call(Step::Stat, || file.metadata())?.is_dir() {
                    return Err(refused("attempt name is a cgroup control file"));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        Ok(self.path.join(name.as_str()))
    }

    pub(crate) fn create(
        &self,
        name: &Name,
        cpu: u64,
        memory: u64,
        pids: u64,
    ) -> io::Result<Group> {
        let name = attempt_name(name)?;
        step::call(Step::Mkdir, || sys::mkdir(&self.directory, name, 0o700))?;
        let group = self.group(name)?;
        write(
            &group.directory,
            c"cpu.max",
            format!("{cpu} {CPU_PERIOD_US}").as_bytes(),
        )?;
        write(
            &group.directory,
            c"memory.max",
            memory.to_string().as_bytes(),
        )?;
        write(&group.directory, c"memory.swap.max", b"0")?;
        write(&group.directory, c"memory.oom.group", b"1")?;
        write(&group.directory, c"pids.max", pids.to_string().as_bytes())?;
        Ok(group)
    }

    /// Recorded paths resolve as immediate attempt children.
    pub(crate) fn recorded(&self, path: &Path) -> io::Result<Option<Group>> {
        if !self.contains(path) {
            return Err(refused("recorded cgroup is outside delegated root"));
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| refused("cgroup name is not ASCII"))?;
        let name = Name::new(name).ok_or_else(|| refused("invalid recorded cgroup name"))?;
        match self.group(attempt_name(&name)?) {
            Ok(group) => Ok(Some(group)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn group(&self, name: &CStr) -> io::Result<Group> {
        let directory = open(&self.directory, name, libc::O_RDONLY | libc::O_DIRECTORY)?;
        let events = open(&directory, c"cgroup.events", libc::O_RDONLY)?;
        let parent = step::call(Step::Open, || self.directory.try_clone())?;
        Ok(Group {
            parent,
            name: name.to_owned(),
            directory,
            events,
        })
    }

    pub(crate) fn children(&self, bound: usize) -> io::Result<Vec<PathBuf>> {
        let directory = open(&self.directory, c".", libc::O_RDONLY | libc::O_DIRECTORY)?;
        let mut children = Vec::new();
        let mut bytes = [0; 8192];
        loop {
            let count = step::call(Step::List, || sys::entries(&directory, &mut bytes))?;
            if count == 0 {
                return Ok(children);
            }
            for name in sys::names(&bytes[..count]) {
                if matches!(name, b"." | b".." | b"controller") || name == SWEEP.to_bytes() {
                    continue;
                }
                let name = CString::new(name).map_err(|_| refused("entry contains NUL"))?;
                match open(&directory, &name, libc::O_RDONLY | libc::O_DIRECTORY) {
                    Ok(_) => {
                        if children.len() >= bound {
                            return Err(refused("cgroup scan exceeds bound"));
                        }
                        children.push(self.path.join(std::ffi::OsStr::from_bytes(name.to_bytes())))
                    }
                    Err(error) if error.raw_os_error() == Some(libc::ENOTDIR) => {}
                    Err(error) => return Err(error),
                }
            }
        }
    }
}

impl Group {
    pub(crate) fn inode(&self) -> io::Result<u64> {
        step::call(Step::Stat, || self.directory.metadata()).map(|status| status.ino())
    }

    pub(crate) fn move_gate(&self, child: &std::process::Child) -> io::Result<()> {
        write(
            &self.directory,
            c"cgroup.procs",
            child.id().to_string().as_bytes(),
        )
    }

    pub(crate) fn kill(&self) -> io::Result<()> {
        write(&self.directory, c"cgroup.kill", b"1")
    }

    pub(crate) fn populated(&self) -> io::Result<bool> {
        match counters(&read_file(&self.events)?)?.get("populated") {
            Some(0) => Ok(false),
            Some(1) => Ok(true),
            _ => Err(refused("cgroup events lacks populated state")),
        }
    }

    pub(crate) fn acknowledge_events(&self) -> io::Result<()> {
        self.populated().map(|_| ())
    }

    pub(crate) fn cpu_usage(&self) -> io::Result<u64> {
        counters(&read(&self.directory, c"cpu.stat")?)?
            .get("usage_usec")
            .copied()
            .ok_or_else(|| refused("CPU stat lacks usage"))
    }

    pub(crate) fn snapshot(&self) -> io::Result<Counters> {
        let mut memory = counters(&read(&self.directory, c"memory.events")?)?;
        let mut pids = counters(&read(&self.directory, c"pids.events")?)?;
        for (name, values) in [(c"memory.peak", &mut memory), (c"pids.peak", &mut pids)] {
            match read(&self.directory, name) {
                Ok(value) => {
                    let peak = value
                        .trim()
                        .parse::<u64>()
                        .map_err(|_| refused("invalid cgroup peak"))?;
                    values.insert("peak".into(), peak);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        Ok(Counters {
            cpu: counters(&read(&self.directory, c"cpu.stat")?)?,
            memory,
            pids,
        })
    }

    pub(crate) fn poll(&self, signals: &sys::Signals, timeout: Duration) -> io::Result<()> {
        let mut descriptors = sys::PollSet::new(signals);
        descriptors.add(None, &self.events);
        match step::last(Step::Poll, || descriptors.poll(timeout)) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(()),
            result => result,
        }
    }

    pub(crate) fn watch<'a>(
        &'a self,
        process: Option<&'a sys::Process>,
        descriptors: &mut sys::PollSet<'a>,
    ) {
        descriptors.add(process, &self.events);
    }

    pub(crate) fn remove(self) -> io::Result<()> {
        step::call(Step::Unlink, || sys::rmdir(&self.parent, &self.name))
    }
}

fn counters(text: &str) -> io::Result<BTreeMap<String, u64>> {
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let name = fields.next().ok_or_else(|| refused("empty counter"))?;
        let value = fields
            .next()
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| refused("invalid counter"))?;
        if fields.next().is_some() || values.insert(name.to_owned(), value).is_some() {
            return Err(refused("invalid counter fields"));
        }
    }
    Ok(values)
}

/// The boot identity binds paths to the current kernel lifetime.
pub(crate) fn boot() -> io::Result<String> {
    let mut bytes = String::new();
    step::call(Step::Read, || {
        File::open("/proc/sys/kernel/random/boot_id")?
            .take(128)
            .read_to_string(&mut bytes)
    })?;
    Ok(bytes.trim().to_owned())
}

/// The cgroup-v2 directory this process runs in: `/sys/fs/cgroup` joined
/// with the path of the process's `0::` membership line.
///
/// # Errors
///
/// A failed read of `/proc/self/cgroup`; `InvalidData` when it holds no
/// cgroup-v2 membership line.
pub(crate) fn own() -> io::Result<PathBuf> {
    let text = std::fs::read_to_string("/proc/self/cgroup")?;
    text.lines()
        .find_map(|line| line.strip_prefix("0::/"))
        .map(|path| Path::new("/sys/fs/cgroup").join(path))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the process has no cgroup-v2 membership",
            )
        })
}
