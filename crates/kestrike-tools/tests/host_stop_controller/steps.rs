//! The file steps of the system, each passed first through the plants a case set: a plant sees the
//! step and the plane's state, may change the state or deliver a signal, and may fail the step with
//! a system error.

use std::cell::{Cell, RefCell};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant};

use kestrike_tools::gameday::ReadError;
use kestrike_tools::host_stop::{Disk, Files, Links};
use kestrike_tools::text::Text;

use super::plane::{Shared, State};

/// One file step and what it acts on.
#[derive(Debug)]
pub(crate) enum Step<'p> {
    OpenDirectory,
    OpenUnnamed(&'p Path),
    Write,
    /// The sync of the file open on this descriptor.
    Fsync(i32),
    /// The sync of the directory at this path.
    FsyncDirectory(PathBuf),
    /// A read of the file at this path, before its open.
    Read(PathBuf),
    Link(&'p OsStr),
    Unlink(&'p OsStr),
    TryLock,
    Lstat(&'p Path),
    Exists(&'p Path),
    Mkdir(&'p Path),
    Rmdir,
}

pub(crate) type Plant = Box<dyn FnMut(&mut State, &Step<'_>) -> Option<io::Error>>;
pub(crate) type Plants = Rc<RefCell<Vec<Plant>>>;

/// The file steps of one case. `cap` bounds the bytes one write takes, and `stall` makes each write
/// take none.
pub(crate) struct Steps {
    pub(crate) state: Shared,
    pub(crate) plants: Plants,
    pub(crate) cap: Rc<Cell<Option<usize>>>,
    pub(crate) stall: Rc<Cell<bool>>,
    /// Set by a case that holds the lock on purpose, so a taken lock is refused at once.
    pub(crate) contended: Rc<Cell<bool>>,
}

impl Steps {
    fn enter(&self, step: &Step<'_>) -> io::Result<()> {
        let mut state = self.state.borrow_mut();
        for plant in self.plants.borrow_mut().iter_mut() {
            if let Some(error) = plant(&mut state, step) {
                return Err(error);
            }
        }
        Ok(())
    }
}

fn named(file: &File) -> PathBuf {
    named_fd(file.as_raw_fd())
}

/// The path the descriptor `fd` of this process names, or an empty path once it is closed.
pub(crate) fn named_fd(fd: i32) -> PathBuf {
    fs::read_link(format!("/proc/self/fd/{fd}")).unwrap_or_default()
}

impl Files for Steps {
    fn open_directory(&self, path: &Path, links: Links) -> io::Result<File> {
        self.enter(&Step::OpenDirectory)?;
        Disk.open_directory(path, links)
    }

    fn open_unnamed(&self, directory: &Path) -> io::Result<File> {
        self.enter(&Step::OpenUnnamed(directory))?;
        Disk.open_unnamed(directory)
    }

    fn write(&self, file: &File, bytes: &[u8]) -> io::Result<usize> {
        self.enter(&Step::Write)?;
        if self.stall.get() {
            return Ok(0);
        }
        let taken = self
            .cap
            .get()
            .map_or(bytes.len(), |cap| cap.min(bytes.len()));
        Disk.write(file, &bytes[..taken])
    }

    fn fsync(&self, file: &File) -> io::Result<()> {
        self.enter(&Step::Fsync(file.as_raw_fd()))?;
        Disk.fsync(file)
    }

    fn fsync_directory(&self, directory: &File) -> io::Result<()> {
        self.enter(&Step::FsyncDirectory(named(directory)))?;
        Disk.fsync_directory(directory)
    }

    fn link(&self, file: &File, directory: &File, name: &OsStr) -> io::Result<()> {
        self.enter(&Step::Link(name))?;
        Disk.link(file, directory, name)
    }

    fn unlink(&self, directory: &File, name: &OsStr) -> io::Result<()> {
        self.enter(&Step::Unlink(name))?;
        Disk.unlink(directory, name)
    }

    /// A lock that another process of the test run holds through a descriptor it inherited
    /// between its fork and its exec is taken again for up to [`LOCK_WAIT`], unless the case
    /// holds the lock on purpose.
    fn try_lock(&self, directory: &File) -> io::Result<()> {
        self.enter(&Step::TryLock)?;
        let until = Instant::now() + LOCK_WAIT;
        loop {
            match Disk.try_lock(directory) {
                Err(error)
                    if error.raw_os_error() == Some(libc::EWOULDBLOCK)
                        && !self.contended.get()
                        && Instant::now() < until =>
                {
                    std::thread::sleep(Duration::from_millis(5));
                }
                other => return other,
            }
        }
    }

    fn lstat(&self, path: &Path) -> io::Result<fs::Metadata> {
        self.enter(&Step::Lstat(path))?;
        Disk.lstat(path)
    }

    fn exists(&self, path: &Path) -> bool {
        self.enter(&Step::Exists(path)).is_ok() && Disk.exists(path)
    }

    fn mkdir(&self, path: &Path) -> io::Result<()> {
        self.enter(&Step::Mkdir(path))?;
        Disk.mkdir(path)
    }

    fn rmdir(&self, path: &Path) -> io::Result<()> {
        self.enter(&Step::Rmdir)?;
        Disk.rmdir(path)
    }

    fn read_synced(
        &self,
        name: &Path,
        directory: &File,
        what: &Text,
        limit: u64,
    ) -> Result<Vec<u8>, ReadError> {
        if let Err(error) = self.enter(&Step::Read(named(directory).join(name))) {
            panic!("a plant failed the read of {}: {error}", name.display());
        }
        Reader(self).read_synced(name, directory, what, limit)
    }
}

/// The seal's read over [`Files`]'s own reader, its sync passed through the case's file steps.
struct Reader<'s>(&'s Steps);

impl Files for Reader<'_> {
    fn fsync(&self, file: &File) -> io::Result<()> {
        self.0.fsync(file)
    }
}

/// How long a lock that no case holds on purpose is taken again before its refusal stands.
pub(crate) const LOCK_WAIT: Duration = Duration::from_secs(2);

/// The system error `code`.
pub(crate) fn errno(code: i32) -> io::Error {
    io::Error::from_raw_os_error(code)
}

/// Whether a link names the mark `name`.
pub(crate) fn links(step: &Step<'_>, name: &str) -> bool {
    matches!(step, Step::Link(linked) if *linked == OsString::from(name).as_os_str())
}

/// Whether the step syncs a file or a directory, as `fsync(2)` counts both.
pub(crate) fn syncs(step: &Step<'_>) -> bool {
    matches!(step, Step::Fsync(_) | Step::FsyncDirectory(_))
}
