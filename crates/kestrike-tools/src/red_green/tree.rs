//! The entries a commit names, read from the records of `git ls-tree -z --full-tree`, and the comparison
//! of a worktree with them. [`named_entries`] and [`carried_blob`] each name the listing they read.
//!
//! A record is `MODE TYPE ID`, a tab, the path and a NUL. The caller runs Git, checks its exit status and
//! passes its standard output as written; each path is relative to the repository root. The caller lists
//! the commit and checks out the worktree with replace objects disabled, as [`crate::git`] starts Git,
//! and lists a carried path with inherited pathspec modes cleared, so the records and the checkout name
//! the commit's own objects and the path as written.
//!
//! The comparison treats symbolic links as leaf entries. It counts every nondirectory entry, including
//! FIFOs and links to directories, and each directory that holds no entry or cannot be listed. The
//! worktree's own `.git` at the top and each path the commit names with mode 160000 stand outside the
//! comparison, a directory at such a path that cannot be listed included. Paths compare in code point
//! order of the names as [`Text`] decodes them, and the first that differs is the result: a path on one
//! side alone, a named mode other than 100644, 100755 and 120000, a kind or an executable bit that differs
//! from the mode, or bytes whose Git blob ID differs from the named ID. A file's bytes and a link's target
//! hash as a blob, with SHA-1 for an ID of 40 digits and SHA-256 for any other.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::hook;
use crate::ownership::PathError;
use crate::paths;
use crate::python;
use crate::text::{Text, text};

pub const FILE: &str = "100644";
pub const EXECUTABLE: &str = "100755";
pub const LINK: &str = "120000";
pub const SUBMODULE: &str = "160000";

/// The modes whose entries the comparison reads; any other named mode differs.
const COMPARED: [&str; 3] = [FILE, EXECUTABLE, LINK];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub mode: Text,
    pub id: Text,
}

pub type Entries = BTreeMap<Text, Entry>;

/// The bytes of a rejected record. A record holds a tab after exactly three metadata fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Malformed(pub Vec<u8>);

fn decoded(bytes: &[u8]) -> Text {
    Text::from_os(OsStr::from_bytes(bytes))
}

/// The mode, type and ID of a record with the bytes after its first tab, or `None` for a record that
/// holds no tab or another count of fields before it.
fn fields(record: &[u8]) -> Option<([Text; 3], &[u8])> {
    let tab = record.iter().position(|&byte| byte == b'\t')?;
    let meta = decoded(&record[..tab]).split().try_into().ok()?;
    Some((meta, &record[tab + 1..]))
}

/// The entries in the output of `git ls-tree -r -z --full-tree COMMIT`. The recursive listing names each
/// file, link and submodule and no directory.
///
/// # Errors
///
/// `named_entries` returns [`Malformed`] for the first nonempty record that fails the tab or field-count
/// check. For duplicate decoded paths, the last record wins.
pub fn named_entries(stdout: &[u8]) -> Result<Entries, Malformed> {
    let mut entries = Entries::new();
    for record in stdout
        .split(|&byte| byte == 0)
        .filter(|record| !record.is_empty())
    {
        let Some(([mode, _, id], path)) = fields(record) else {
            return Err(Malformed(record.to_vec()));
        };
        entries.insert(decoded(path), Entry { mode, id });
    }
    Ok(entries)
}

/// The blob ID of `path` from the output of `git --literal-pathspecs ls-tree -z --full-tree HEAD -- PATH`,
/// with `head` as the revision and `path` as one literal name relative to the repository root. The ID is
/// the record's third field as written.
///
/// # Errors
///
/// `carried_blob` requires three metadata fields, mode 100644 or 100755, and a decoded name equal to
/// `path` followed by NUL. On mismatch, the error names the first 12 characters of `head`, the full
/// commit ID of the listing, and `path`.
pub fn carried_blob(head: &str, path: &Text, stdout: &[u8]) -> Result<Text, Text> {
    match fields(stdout) {
        Some(([mode, _, id], name))
            if (mode == FILE || mode == EXECUTABLE) && decoded(name) == text!(path, "\0") =>
        {
            Ok(id)
        }
        _ => Err(text!(
            "the head ",
            hook::short(&Text::from(head)),
            " holds no regular file ",
            path.repr()
        )),
    }
}

/// `overlaid` matches a carried path and its slash-delimited ancestors and descendants.
pub fn overlaid<'a>(path: &Text, carry: impl IntoIterator<Item = &'a Text>) -> bool {
    let below = |inner: &Text, outer: &Text| inner.starts_with(&text!(outer, "/"));
    carry
        .into_iter()
        .any(|other| path == other || below(path, other) || below(other, path))
}

/// The base leg's entries: the base's, less each path the overlay of `carry` decides, with each carried
/// path at the head's mode and ID.
///
/// # Errors
///
/// A carried path that `head` lacks.
pub fn base_entries(base: &Entries, head: &Entries, carry: &[Text]) -> Result<Entries, Text> {
    let mut carried = Entries::new();
    for path in carry {
        let entry = head.get(path).ok_or_else(|| path.clone())?;
        carried.insert(path.clone(), entry.clone());
    }
    let mut entries: Entries = base
        .iter()
        .filter(|(path, _)| !overlaid(path, carried.keys()))
        .map(|(path, entry)| (path.clone(), entry.clone()))
        .collect();
    entries.extend(carried);
    Ok(entries)
}

/// The hexadecimal digest of `blob LEN`, a NUL and `data`, `LEN` being the count of bytes of `data`.
pub fn blob_id<D: Digest>(data: &[u8]) -> String {
    let mut digest = D::new();
    digest.update(format!("blob {}\0", data.len()).as_bytes());
    digest.update(data);
    python::hex(&digest.finalize())
}

/// A top directory that cannot be listed is the path `.`.
fn present(tree: &Path) -> BTreeSet<Text> {
    let mut present = BTreeSet::new();
    let mut pending = vec![Vec::new()];
    while let Some(relative) = pending.pop() {
        let Ok(entries) = fs::read_dir(tree.join(OsStr::from_bytes(&relative)))
            .and_then(|listing| listing.collect::<io::Result<Vec<_>>>())
        else {
            let shown: &[u8] = if relative.is_empty() { b"." } else { &relative };
            present.insert(decoded(shown));
            continue;
        };
        if entries.is_empty() && !relative.is_empty() {
            present.insert(decoded(&relative));
        }
        for entry in entries {
            let path = paths::join(&relative, entry.file_name().as_bytes());
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => pending.push(path),
                _ => {
                    present.insert(decoded(&path));
                }
            }
        }
    }
    present
}

/// `named_bytes` returns the bytes to hash: the link target or the regular file contents, read through the
/// descriptor whose type and owner execute bit it checks against the mode. `None` means the kind or the
/// execute bit differs. The first open does not wait, so a FIFO is never waited on; where it fails with
/// `EWOULDBLOCK` on an entry whose status shows the named kind, as under another process's write lease,
/// a second open waits for the lease to break.
fn named_bytes(full: &Path, entry: &Entry) -> io::Result<Option<Vec<u8>>> {
    if entry.mode == LINK {
        return match fs::read_link(full) {
            Ok(target) => Ok(Some(target.into_os_string().into_vec())),
            Err(error) if error.raw_os_error() == Some(libc::EINVAL) => Ok(None),
            Err(error) => Err(error),
        };
    }
    let named = entry.mode == EXECUTABLE;
    let differs = |status: &fs::Metadata| {
        !status.file_type().is_file() || (status.permissions().mode() & 0o100 != 0) != named
    };
    let open = |flags| {
        OpenOptions::new()
            .read(true)
            .custom_flags(flags | libc::O_NOFOLLOW | libc::O_NOCTTY)
            .open(full)
    };
    let mut file = match open(libc::O_NONBLOCK) {
        Ok(file) => file,
        Err(error) => match fs::symlink_metadata(full) {
            Ok(status) if differs(&status) => return Ok(None),
            Ok(_) if error.raw_os_error() == Some(libc::EWOULDBLOCK) => open(0)?,
            _ => return Err(error),
        },
    };
    if differs(&file.metadata()?) {
        return Ok(None);
    }
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(Some(data))
}

/// The first path at which the worktree at `tree` differs from `named`, or `None`. The caller trusts
/// `tree` and the entries in it. The comparison holds the set of paths and one whole regular file at a
/// time in memory.
///
/// # Errors
///
/// `PathError` carries the full worktree path for propagated I/O errors.
pub fn tree_difference(tree: &Path, named: &Entries) -> Result<Option<Text>, PathError> {
    let outside = |path: &Text| named.get(path).is_some_and(|entry| entry.mode == SUBMODULE);
    let present: BTreeSet<Text> = present(tree)
        .into_iter()
        .filter(|path| *path != ".git" && !outside(path))
        .collect();
    let mut paths = present.clone();
    paths.extend(named.keys().filter(|path| !outside(path)).cloned());
    for path in paths {
        let Some(entry) = named.get(&path).filter(|_| present.contains(&path)) else {
            return Ok(Some(path));
        };
        if !COMPARED.iter().any(|mode| entry.mode == *mode) {
            return Ok(Some(path));
        }
        let relative = path
            .to_os()
            .expect("a path the walk listed decodes from the bytes of its name");
        let full = tree.join(relative);
        let Some(data) = named_bytes(&full, entry).map_err(|error| PathError::new(&full, error))?
        else {
            return Ok(Some(path));
        };
        let id = if entry.id.len() == 40 {
            blob_id::<Sha1>(&data)
        } else {
            blob_id::<Sha256>(&data)
        };
        if entry.id != id.as_str() {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

#[cfg(test)]
#[path = "tree_tests.rs"]
mod tests;
