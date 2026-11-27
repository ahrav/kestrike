//! The judge's read of one regular file: opened with no link at its last component and without blocking,
//! refused by type and size before its bytes are read, and refused when it reads longer than its size.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use super::refusal::{Refusal, said};
use crate::plants::files::strerror;
use crate::text::Text;

/// A read that [`read_file`] does not finish.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadError {
    /// The path holds a NUL byte, which no system call takes; the caller words the refusal.
    Nul,
    Refused(Refusal),
}

impl From<Refusal> for ReadError {
    fn from(refusal: Refusal) -> Self {
        Self::Refused(refusal)
    }
}

/// `read_file` returns the bytes of the regular file at `path`, at most `limit` of them. With `dir`, a
/// relative `path` names an entry of that open directory, reached as `/proc/self/fd/<descriptor>/<path>`;
/// an absolute `path` stands for itself, and an empty `path` names no file. The file opens with `O_RDONLY | O_NOFOLLOW | O_NONBLOCK`, so a
/// link at the last component and a named pipe with no writer do not hold the read. With `sync`, the file
/// is synced once it is read. Every refusal names `what`.
///
/// # Errors
///
/// In order: [`ReadError::Nul`] for a path with a NUL byte; `<what> cannot be read: <reason>` when the
/// open or the status fails, the reason being the system's text; `<what> is no regular file`;
/// `<what> holds more than <limit> bytes` when the size passes `limit`; `<what> grew while it was read`
/// when the read returns more bytes than the size or than `limit`; and `<what> cannot be read: <reason>`,
/// or `<what> cannot be read and synced: <reason>` with `sync`, when the read or the sync fails.
pub fn read_file(
    path: &Path,
    dir: Option<BorrowedFd<'_>>,
    what: &Text,
    limit: u64,
    sync: bool,
) -> Result<Vec<u8>, ReadError> {
    if path.as_os_str().as_bytes().contains(&0) {
        return Err(ReadError::Nul);
    }
    let at = match dir {
        Some(dir) if !path.as_os_str().is_empty() => {
            PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd())).join(path)
        }
        _ => path.to_path_buf(),
    };
    let unread =
        |error: &std::io::Error| Refusal::new(said!(what, " cannot be read: ", strerror(error)));
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&at)
        .map_err(|error| unread(&error))?;
    let info = file.metadata().map_err(|error| unread(&error))?;
    if !info.file_type().is_file() {
        return Err(Refusal::new(said!(what, " is no regular file")).into());
    }
    let size = info.len();
    if size > limit {
        return Err(Refusal::new(said!(
            what,
            " holds more than ",
            limit.to_string(),
            " bytes"
        ))
        .into());
    }
    Ok(read_open(file, size, what, limit, sync)?)
}

/// The bytes of the open regular file of `size` bytes, with one byte past `size` asked for, which tells
/// a file that grew while it was read.
fn read_open(
    file: File,
    size: u64,
    what: &Text,
    limit: u64,
    sync: bool,
) -> Result<Vec<u8>, Refusal> {
    let failed = |error: &std::io::Error| {
        let and = if sync { " and synced" } else { "" };
        Refusal::new(said!(what, " cannot be read", and, ": ", strerror(error)))
    };
    let mut data = Vec::new();
    (&file)
        .take(size + 1)
        .read_to_end(&mut data)
        .map_err(|error| failed(&error))?;
    let read = u64::try_from(data.len()).expect("a length fits a u64");
    if read > size || read > limit {
        return Err(Refusal::new(said!(what, " grew while it was read")));
    }
    if sync {
        file.sync_all().map_err(|error| failed(&error))?;
    }
    Ok(data)
}

#[cfg(test)]
#[path = "read_tests.rs"]
mod tests;
