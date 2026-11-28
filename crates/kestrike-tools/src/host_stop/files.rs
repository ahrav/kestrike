//! The file steps under a mark's write, the evidence lock, the probe and the lookup, each a method of
//! [`Files`] whose default makes the step's system call. A test implements [`Files`] to fail or observe
//! one step and keeps the defaults for the rest; [`Disk`] keeps every default. Every descriptor opens
//! with `O_CLOEXEC`.

use std::ffi::{CString, OsStr};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// Whether [`Files::open_directory`] follows a link at the path's last component.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Links {
    Follow,
    Refuse,
}

/// The file steps, one method each, every argument the one the system call takes.
pub trait Files {
    /// `open(path, O_RDONLY | O_DIRECTORY)`, with `O_NOFOLLOW` under [`Links::Refuse`].
    fn open_directory(&self, path: &Path, links: Links) -> io::Result<File> {
        let flags = match links {
            Links::Follow => libc::O_DIRECTORY,
            Links::Refuse => libc::O_DIRECTORY | libc::O_NOFOLLOW,
        };
        OpenOptions::new().read(true).custom_flags(flags).open(path)
    }

    /// `open(directory, O_TMPFILE | O_WRONLY, 0644)`: a file in the directory that has no name.
    fn open_unnamed(&self, directory: &Path) -> io::Result<File> {
        OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_TMPFILE)
            .mode(0o644)
            .open(directory)
    }

    /// One `write(2)`, which may take fewer bytes than it is given. A write that reaches
    /// `RLIMIT_FSIZE` can return a short count. An attempt to extend the file from that limit raises
    /// SIGXFSZ, whose default action terminates the process.
    fn write(&self, file: &File, bytes: &[u8]) -> io::Result<usize> {
        let mut file = file;
        file.write(bytes)
    }

    /// `fsync(2)` of a file.
    fn fsync(&self, file: &File) -> io::Result<()> {
        file.sync_all()
    }

    /// `fsync(2)` of an open directory, which makes its entries durable on storage that honors it.
    fn fsync_directory(&self, directory: &File) -> io::Result<()> {
        directory.sync_all()
    }

    /// `linkat` of `/proc/self/fd/<file>` to `name` in `directory` with `AT_SYMLINK_FOLLOW`, which
    /// names the open file. `linkat` resolves a relative `name` from `directory` and an absolute
    /// `name` from the root.
    fn link(&self, file: &File, directory: &File, name: &OsStr) -> io::Result<()> {
        linkat(file, directory, name)
    }

    /// `unlink(2)` of `/proc/self/fd/<directory>/<name>`, the name in the directory the descriptor
    /// holds. `Path::join` puts an absolute `name` in place of the directory's path.
    fn unlink(&self, directory: &File, name: &OsStr) -> io::Result<()> {
        fs::remove_file(proc_path(directory).join(name))
    }

    /// `flock(LOCK_EX | LOCK_NB)`. A lock held through another open file description is the system's
    /// `EWOULDBLOCK`, returned at once.
    fn try_lock(&self, directory: &File) -> io::Result<()> {
        directory.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => io::Error::from_raw_os_error(libc::EWOULDBLOCK),
            TryLockError::Error(error) => error,
        })
    }

    /// When the final component of `path` is a symlink, `lstat` returns the symlink's metadata.
    fn lstat(&self, path: &Path) -> io::Result<fs::Metadata> {
        fs::symlink_metadata(path)
    }

    /// `exists` follows symlinks and returns `true` only if it can read metadata for the resolved
    /// `path`.
    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    /// `mkdir(path, 0777)`.
    fn mkdir(&self, path: &Path) -> io::Result<()> {
        fs::create_dir(path)
    }

    /// `rmdir(2)`.
    fn rmdir(&self, path: &Path) -> io::Result<()> {
        fs::remove_dir(path)
    }
}

/// The file steps of the system.
#[derive(Clone, Copy, Debug, Default)]
pub struct Disk;

impl Files for Disk {}

/// `/proc/self/fd/<descriptor>`, which resolves to the file open on that descriptor.
pub(super) fn proc_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

fn linkat(file: &File, directory: &File, name: &OsStr) -> io::Result<()> {
    let source = CString::new(proc_path(file).into_os_string().into_vec())?;
    let name = CString::new(name.as_bytes())?;
    // SAFETY: both paths are NUL-terminated strings that outlive the call, and both descriptors are
    // open for its whole length because `file` and `directory` are borrowed across it.
    let status = unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            source.as_ptr(),
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::AT_SYMLINK_FOLLOW,
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
