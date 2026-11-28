//! The run's writes of a scoped file and of its two JSON files, and the digests it compares.

use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::json::{self, Value};
use crate::ownership::PathError;
use crate::plants::{Creation, Staging, THREAD_STATUS, publish_staged, umask};
use crate::python::hexdigest;

/// The suffix of each staging file's name.
const SUFFIX: &str = ".weaken";

/// `nanoseconds` is a status's modification time in nanoseconds after the epoch.
fn nanoseconds(status: &Metadata) -> i128 {
    i128::from(status.mtime()) * 1_000_000_000 + i128::from(status.mtime_nsec())
}

/// `fresh_write` replaces `path` with a new regular file holding `text`, created exclusively beside it,
/// with the permission bits of `previous`, `path`'s own status with links followed unless given, and a
/// modification time later than that status's: the wall clock's, or that time plus one nanosecond where
/// the clock reads no later. A link at `path` is replaced and its target stays.
///
/// # Errors
///
/// `path`'s status cannot be read, or the staged write fails.
pub(super) fn fresh_write(path: &Path, text: &str, previous: Option<&Metadata>) -> io::Result<()> {
    let own;
    let previous = match previous {
        Some(previous) => previous,
        None => {
            own = fs::metadata(path)?;
            &own
        }
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos().try_into().unwrap_or(i128::MAX));
    let later = now.max(nanoseconds(previous).saturating_add(1));
    let staging = Staging::new(Creation::Exact(previous.mode() & 0o7777))
        .suffix(SUFFIX)
        .modified(later);
    publish_staged(path, text.as_bytes(), staging).map_err(PathError::into_error)
}

/// `regular_digest` is the SHA-256 of `path` when it names a regular file, no symbolic link, that can be
/// opened and read, else `None`. The file is opened once without following a link, and its type and bytes
/// are read through that descriptor.
pub(super) fn regular_digest(path: &Path) -> Option<String> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    read_all(file).ok().map(|bytes| hexdigest(&bytes))
}

fn read_all(mut file: File) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// `sha256` is the SHA-256 of the bytes `path` names, links followed.
///
/// # Errors
///
/// The file cannot be read.
pub(super) fn sha256(path: &Path) -> io::Result<String> {
    fs::read(path).map(|bytes| hexdigest(&bytes))
}

/// `save` writes `data` to `path` as JSON indented by two spaces in document order with a final newline,
/// as a new file renamed over `path`, with mode 0666 less the thread's umask.
///
/// # Errors
///
/// The staged write fails.
pub(super) fn save(path: &Path, data: &Value) -> io::Result<()> {
    save_unless(path, data, &|| Ok(()))
}

/// `save_unless` is [`save`] whose rename waits for `commit`, called once the staging file is written and
/// closed; an error of `commit` removes the staging file, leaves `path` as it stood and is returned.
///
/// # Errors
///
/// The thread's umask cannot be read, `commit` fails, or the staged write fails.
pub(super) fn save_unless(
    path: &Path,
    data: &Value,
    commit: &dyn Fn() -> io::Result<()>,
) -> io::Result<()> {
    let mut written = json::indented_in_order(data);
    written.push('\n');
    let mask =
        umask().map_err(|error| PathError::new(Path::new(THREAD_STATUS), error).into_error())?;
    let staging = Staging::new(Creation::Masked(mask))
        .suffix(SUFFIX)
        .commit(commit);
    publish_staged(path, written.as_bytes(), staging).map_err(PathError::into_error)
}

#[cfg(test)]
#[path = "files_tests.rs"]
mod tests;
