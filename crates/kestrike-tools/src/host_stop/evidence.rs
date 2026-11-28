//! The evidence directory's lock, the probe for files with no name, and the lookup of an entry.

use std::fs::File;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use super::files::{Files, Links, proc_path};

/// The exclusive `flock` of a directory, held until the value drops.
#[derive(Debug)]
#[must_use = "the lock frees when the value drops"]
pub struct Lock {
    held: File,
}

impl Lock {
    /// Whether `path` names the locked directory: an `lstat` of `path` finds the device and inode
    /// numbers of the directory the lock holds open. The open directory keeps its inode number in
    /// use, so a directory removed and made again at `path` reads as another one. The `lstat` is a
    /// step of `files`; the `fstat` reads the lock's own descriptor and is no step of `files`.
    ///
    /// # Errors
    ///
    /// The error of the open directory's `fstat` or of the `lstat` of `path`, `ENOENT` for a name
    /// with no entry.
    pub fn stands_at(&self, files: &impl Files, path: &Path) -> io::Result<bool> {
        let held = self.held.metadata()?;
        let found = files.lstat(path)?;
        Ok((held.dev(), held.ino()) == (found.dev(), found.ino()))
    }
}

/// `Open` carries the directory-open error; `Taken` carries the nonblocking `flock` error, whose
/// `EWOULDBLOCK` means another holder has the lock.
#[derive(Debug)]
pub enum LockError {
    Open(io::Error),
    Taken(io::Error),
}

/// `lock` rejects a symlink at `directory` and attempts a nonblocking exclusive `flock` on the opened
/// directory. Runs, restores and seals for the same evidence directory exclude each other by locking
/// the directory itself. A `flock` that a signal interrupts runs again.
///
/// # Errors
///
/// [`LockError::Open`] when the open fails, [`LockError::Taken`] with the error of the `flock`,
/// `EWOULDBLOCK` when the lock is held elsewhere.
pub fn lock(files: &impl Files, directory: &Path) -> Result<Lock, LockError> {
    let held = files
        .open_directory(directory, Links::Refuse)
        .map_err(LockError::Open)?;
    loop {
        match files.try_lock(&held) {
            Ok(()) => return Ok(Lock { held }),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(LockError::Taken(error)),
        }
    }
}

/// Why `root` cannot hold a mark: it takes no file without a name, or the `/proc/self/fd` path of
/// such a file does not resolve, so the file cannot be linked to a name.
#[derive(Debug)]
pub enum ProbeError {
    Unnamed(io::Error),
    Unresolved(PathBuf),
}

/// Opens a file with no name in `root` by path and checks that its `/proc/self/fd` path resolves. The
/// file is gone once the probe returns.
///
/// # Errors
///
/// [`ProbeError`] names the check that failed.
pub fn probe(files: &impl Files, root: &Path) -> Result<(), ProbeError> {
    let unnamed = files.open_unnamed(root).map_err(ProbeError::Unnamed)?;
    let resolved = proc_path(&unnamed);
    if files.exists(&resolved) {
        Ok(())
    } else {
        Err(ProbeError::Unresolved(resolved))
    }
}

/// Whether an entry stands at `path`, by a lookup of the path itself, which reads a link as an entry.
///
/// # Errors
///
/// A lookup that fails other than with `ENOENT`, so the answer is unknown.
pub fn stands(files: &impl Files, path: &Path) -> io::Result<bool> {
    match files.lstat(path) {
        Ok(_) => Ok(true),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(false),
        Err(error) => Err(error),
    }
}
