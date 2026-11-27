//! The evidence directory's lock, the probe for files with no name, and the lookup of an entry.

use std::fmt;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use super::files::{Files, Links, proc_path};
use super::mark::strerror;

/// The exclusive `flock` of a directory, held until the value drops.
#[derive(Debug)]
#[must_use = "the lock frees when the value drops"]
pub struct Lock {
    _held: File,
}

/// Why [`lock`] holds no lock: the directory's open failed, or another holder has the lock.
#[derive(Debug)]
pub enum LockError {
    Open(io::Error),
    Taken(io::Error),
}

impl fmt::Display for LockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open(error) => write!(f, "the open failed: {}", strerror(error)),
            Self::Taken(error) => write!(f, "the lock is held: {}", strerror(error)),
        }
    }
}

impl std::error::Error for LockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Open(error) | Self::Taken(error) => Some(error),
        }
    }
}

/// Opens `directory` without following a link and takes its exclusive lock at once, so two runs,
/// restores or seals of one evidence directory exclude each other. The lock adds no file.
///
/// # Errors
///
/// [`LockError::Open`] when the open fails, [`LockError::Taken`] with the system's error when the lock
/// is held elsewhere.
pub fn lock(files: &impl Files, directory: &Path) -> Result<Lock, LockError> {
    let held = files
        .open_directory(directory, Links::Refuse)
        .map_err(LockError::Open)?;
    files.try_lock(&held).map_err(LockError::Taken)?;
    Ok(Lock { _held: held })
}

/// Why `root` cannot hold a mark: it takes no file without a name, or the `/proc/self/fd` path of
/// such a file does not resolve, so the file cannot be linked to a name.
#[derive(Debug)]
pub enum ProbeError {
    Unnamed(io::Error),
    Unresolved(PathBuf),
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unnamed(error) => write!(f, "no unnamed file opens: {}", strerror(error)),
            Self::Unresolved(path) => write!(f, "{} does not resolve", path.display()),
        }
    }
}

impl std::error::Error for ProbeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unnamed(error) => Some(error),
            Self::Unresolved(_) => None,
        }
    }
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
