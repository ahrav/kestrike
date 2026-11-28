//! The judge's read of one regular file: opened with no link at its last component and without blocking,
//! refused by type and size before its bytes are read, and refused when it reads longer than its size.

use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use super::refusal::{Refusal, said};
use crate::fixtures::close;
use crate::plants::files::strerror;
use crate::text::Text;

/// A read that [`read_file`] does not finish.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadError {
    /// The path holds a NUL byte, which no system call takes; the caller words the refusal.
    Nul,
    /// The read is refused with the sentence the refusal holds, which names the file.
    Refused(Refusal),
    /// The close of the opened file failed, with the system's text; the caller words it. A failed close
    /// stands in place of every outcome after the open, a refusal included.
    Closed(String),
}

impl From<Refusal> for ReadError {
    fn from(refusal: Refusal) -> Self {
        Self::Refused(refusal)
    }
}

/// `dir` anchors relative names. An empty `name` refers to `dir` itself; an absolute `name` retains its
/// own root.
pub(super) fn in_dir(dir: BorrowedFd<'_>, name: &Path) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd())).join(name)
}

/// When `dir` is present, it anchors each nonempty relative `path`. An absolute or empty `path` stands
/// for itself.
///
/// # Errors
///
/// [`ReadError::Nul`] for a path with a NUL byte.
pub(super) fn opened(path: &Path, dir: Option<BorrowedFd<'_>>) -> Result<PathBuf, ReadError> {
    if path.as_os_str().as_bytes().contains(&0) {
        return Err(ReadError::Nul);
    }
    Ok(match dir {
        Some(dir) if !path.as_os_str().is_empty() => in_dir(dir, path),
        _ => path.to_path_buf(),
    })
}

/// `read_file` returns the bytes of the regular file at `path`, at most `limit` of them. With `dir`, a
/// relative `path` names an entry of that open directory, reached as `/proc/self/fd/<descriptor>/<path>`;
/// an absolute `path` stands for itself, and an empty `path` names no file. The file opens with
/// `O_RDONLY | O_NOFOLLOW | O_NONBLOCK`: a link at the last component fails the open, which is refused as
/// `<what> cannot be read: <reason>`, and a named pipe opens without waiting for a writer and is refused as
/// no regular file. With `sync`, the file is synced once it is read. The opened file is closed once on
/// every path. Every refusal names `what`.
///
/// # Errors
///
/// In order: [`ReadError::Nul`] for a path with a NUL byte; `<what> cannot be read: <reason>` when the
/// open or the status fails, the reason being the system's text; `<what> is no regular file`;
/// `<what> holds more than <limit> bytes` when the size passes `limit`; `<what> grew while it was read`
/// when the read returns more bytes than the size; and `<what> cannot be read: <reason>`, or
/// `<what> cannot be read and synced: <reason>` with `sync`, when the read or the sync fails. A read that
/// is interrupted is retried; a read that would block is refused as a failed read. After a successful
/// open, [`ReadError::Closed`] for a failed close replaces each of these.
pub fn read_file(
    path: &Path,
    dir: Option<BorrowedFd<'_>>,
    what: &Text,
    limit: u64,
    sync: bool,
) -> Result<Vec<u8>, ReadError> {
    let all = |file: &File| file.sync_all();
    read_file_with(path, dir, what, limit, sync.then_some(&all))
}

/// The function a file read by [`read_file_with`] is synced through, once its bytes are read.
pub(crate) type Syncer<'s> = &'s dyn Fn(&File) -> io::Result<()>;

/// `read_file_with` reads as [`read_file`] does, and with `sync` it syncs the opened file through
/// that function in place of `fsync(2)`; the failures and their sentences are [`read_file`]'s, a
/// failure of `sync` worded as a failed sync.
///
/// # Errors
///
/// Each failure [`read_file`] names, in its order.
pub(crate) fn read_file_with(
    path: &Path,
    dir: Option<BorrowedFd<'_>>,
    what: &Text,
    limit: u64,
    sync: Option<Syncer<'_>>,
) -> Result<Vec<u8>, ReadError> {
    let at = opened(path, dir)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&at)
        .map_err(|error| unread(what, &error))?;
    let outcome = read_open(&file, what, limit, sync);
    closed(outcome, close(file))
}

fn unread(what: &Text, error: &io::Error) -> Refusal {
    Refusal::new(said!(what, " cannot be read: ", strerror(error)))
}

/// The read's outcome once the file is closed: a failed close stands in place of `outcome`.
fn closed(outcome: Result<Vec<u8>, Refusal>, close: io::Result<()>) -> Result<Vec<u8>, ReadError> {
    match close {
        Ok(()) => outcome.map_err(ReadError::Refused),
        Err(error) => Err(ReadError::Closed(strerror(&error))),
    }
}

/// The bytes of the open file when it is a regular file of at most `limit` bytes, with one byte past its
/// size asked for, which tells a file that grew while it was read.
fn read_open(
    file: &File,
    what: &Text,
    limit: u64,
    sync: Option<Syncer<'_>>,
) -> Result<Vec<u8>, Refusal> {
    let info = file.metadata().map_err(|error| unread(what, &error))?;
    if !info.file_type().is_file() {
        return Err(Refusal::new(said!(what, " is no regular file")));
    }
    let size = info.len();
    if size > limit {
        return Err(Refusal::new(said!(
            what,
            " holds more than ",
            limit.to_string(),
            " bytes"
        )));
    }
    read_sized(file, size, what, sync)
}

/// The bytes of the open regular file of `size` bytes, refused when the read returns more than `size`,
/// then synced through `sync`.
fn read_sized(
    file: &File,
    size: u64,
    what: &Text,
    sync: Option<Syncer<'_>>,
) -> Result<Vec<u8>, Refusal> {
    let failed = |error: &io::Error| {
        let and = if sync.is_some() { " and synced" } else { "" };
        Refusal::new(said!(what, " cannot be read", and, ": ", strerror(error)))
    };
    let mut data = Vec::new();
    file.take(size.saturating_add(1))
        .read_to_end(&mut data)
        .map_err(|error| failed(&error))?;
    let read = u64::try_from(data.len()).expect("a length fits a u64");
    if read > size {
        return Err(Refusal::new(said!(what, " grew while it was read")));
    }
    if let Some(sync) = sync {
        sync(file).map_err(|error| failed(&error))?;
    }
    Ok(data)
}

#[cfg(test)]
#[path = "read_tests.rs"]
mod tests;
