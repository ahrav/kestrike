//! [`open_dir`] refuses a symbolic link named by the last component of its path, and [`entries`] refuses
//! links, special files, and directories whose relative paths fall outside `LAYOUT_DIRS`.
//!
//! For an entry name, `/proc/self/fd/<descriptor>` anchors the lookup at the open directory. The
//! listing opens the directory again through that path, so it needs `/proc` and read permission on
//! the directory when it runs.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use super::constants::LAYOUT_DIRS;
use super::read::{ReadError, in_dir, opened};
use super::refusal::{Refusal, need, said};
use crate::plants::files::strerror;
use crate::text::Text;

/// `open_dir` rejects a symbolic link named by the final component of `path`. A `path` that ends in
/// `/` or `/.` puts the link before the final component, so the kernel follows it and requires its
/// target to be a directory. When `dir` is present, `open_dir` resolves relative paths from `dir`.
/// `open_dir` rejects an empty `path` regardless of `dir`.
///
/// # Errors
///
/// [`ReadError::Nul`] if `path` contains a NUL byte; otherwise `<what> is no directory: <reason>`, the
/// reason being the system's text.
pub fn open_dir(
    path: &Path,
    dir: Option<BorrowedFd<'_>>,
    what: &Text,
) -> Result<OwnedFd, ReadError> {
    let at = opened(path, dir)?;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(&at)
        .map(OwnedFd::from)
        .map_err(|error| Refusal::new(said!(what, " is no directory: ", strerror(&error))).into())
}

/// `entries` maps each prefixed name to `true` for a directory or `false` for a regular file. It checks
/// the names in [`Text`] order, reports the first refusal in that order, and classifies each entry by
/// an `lstat` of its name in the open directory, taken in that order once the listing ends.
///
/// # Errors
///
/// `<prefix> cannot be listed: <reason>`, or `the evidence directory cannot be listed: <reason>` for an
/// empty prefix, when the listing fails; then, for the first refused entry in order,
/// `<rel> cannot be read: <reason>` when its type cannot be read, `<rel> is a link or a special file`,
/// or `<rel> is no directory of the layout` when a directory's relative path falls outside
/// `LAYOUT_DIRS`.
pub fn entries(dir: BorrowedFd<'_>, prefix: &Text) -> Result<BTreeMap<Text, bool>, Refusal> {
    let listing = |error: &std::io::Error| {
        let whom = if prefix.is_empty() {
            Text::from("the evidence directory")
        } else {
            prefix.clone()
        };
        Refusal::new(said!(whom, " cannot be listed: ", strerror(error)))
    };
    let mut names = Vec::new();
    for entry in std::fs::read_dir(in_dir(dir, Path::new(""))).map_err(|error| listing(&error))? {
        names.push(entry.map_err(|error| listing(&error))?.file_name());
    }
    names.sort_by_cached_key(|name| Text::from_os(name));
    let mut found = BTreeMap::new();
    for name in names {
        let rel = said!(prefix, Text::from_os(&name));
        let kind = std::fs::symlink_metadata(in_dir(dir, Path::new(&name)))
            .map_err(|error| Refusal::new(said!(rel, " cannot be read: ", strerror(&error))))?
            .file_type();
        need(kind.is_dir() || kind.is_file(), || {
            said!(rel, " is a link or a special file")
        })?;
        need(
            kind.is_file() || LAYOUT_DIRS.iter().any(|layout| rel == *layout),
            || said!(rel, " is no directory of the layout"),
        )?;
        found.insert(rel, kind.is_dir());
    }
    Ok(found)
}
