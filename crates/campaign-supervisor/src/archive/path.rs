//! Archive paths: entry names, and the rule that an archive's path is one
//! literal entry of the loader's library search path. The loader splits
//! that path on `:` and `;` and expands `$` tokens, so an archive path
//! holding any of them, or a byte outside printable ASCII, is refused.
//! The pre-build check rejects a new archive's path if the loaded archive
//! view would reject an ancestor path.

use std::io;
use std::path::{Path, PathBuf};

use super::Invalid;
use crate::store::{
    self, Name, Opened, Unreadable, ancestors, given_ancestors, new_path, open_host,
};

pub(super) const RECORD: &str = "build";
pub(super) const WORKER: &str = "worker";
pub(super) const LOCK: &str = "Cargo.lock";
pub(super) const LIBRARIES: &str = "lib";

/// The most libraries an archive holds.
pub(super) const LIBRARY_BOUND: usize = 256;

/// `entry`, one of the constants above, as a name.
pub(super) fn name(entry: &str) -> Name {
    Name::new(entry).expect("an archive entry's name is valid")
}

/// Opens the regular file at host path `path`.
pub(super) fn host(path: &Path) -> Result<Opened, Invalid> {
    open_host(path).map_err(|why| Invalid::Unreadable(path.display().to_string(), why))
}

/// Returns `output` as a new absolute path the loader's search path can
/// carry. The ancestors are checked twice: as given, before the parent is
/// resolved, so a symlink in the given prefix is refused rather than
/// resolved away; and on the resolved path, which the archive later uses.
///
/// # Errors
///
/// [`Invalid::Exists`] when an entry has the path; [`Invalid::Path`] for a
/// path the search path splits or expands; [`Invalid::Refused`] holding
/// [`Refusal::Ancestor`](crate::store::Refusal::Ancestor) for a component
/// of the given path or an ancestor of the resolved path that another user
/// owns, that is group- or world-writable without the sticky bit, or that
/// is a symlink; [`Invalid::Unreadable`] when a component's status or the
/// parent's resolution fails, which [`Unreadable::faulted`] classes as a
/// refused input or a host fault.
pub(super) fn vacant(output: &Path) -> Result<PathBuf, Invalid> {
    given_ancestors(output).map_err(|error| match error {
        store::Error::Io(error) => {
            Invalid::Unreadable(output.display().to_string(), Unreadable::Io(error))
        }
        error => Invalid::store(error),
    })?;
    let path = match new_path(output) {
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Err(Invalid::Exists),
        path => path.map_err(|error| {
            Invalid::Unreadable(output.display().to_string(), Unreadable::Io(error))
        }),
    }?;
    searchable(&path)?;
    ancestors(&path).map_err(Invalid::store)?;
    Ok(path)
}

/// Refuses a path holding `:`, `;`, `$` or a byte outside printable ASCII.
pub(super) fn searchable(path: &Path) -> Result<(), Invalid> {
    let text = path.as_os_str().as_encoded_bytes();
    if text
        .iter()
        .all(|byte| (0x20..=0x7e).contains(byte) && !b":;$".contains(byte))
    {
        Ok(())
    } else {
        Err(Invalid::Path(path.display().to_string()))
    }
}
