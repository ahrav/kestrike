//! The entries a commit names, read from the records of `git ls-tree -z`, and the comparison of a
//! worktree with them.
//!
//! A record is `MODE TYPE ID`, a tab, the path and a NUL. The comparison treats symbolic links as leaf
//! entries. It counts every nondirectory entry, including FIFOs and links to directories, and each
//! directory that holds no entry or cannot be listed. The worktree's own `.git` at the top and each path
//! the commit names with mode 160000 stand outside the comparison. Paths compare in code point order of
//! the names as [`Text`] decodes them, and the first that differs is the result: a path on one side alone,
//! a named mode other than 100644, 100755 and 120000, a kind or an executable bit that differs from the
//! mode, or bytes whose Git blob ID differs from the named ID. A file's bytes and a link's target hash as
//! a blob, with SHA-1 for an ID of 40 digits and SHA-256 for any other.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::ownership::PathError;
use crate::text::{Text, text};

pub const FILE: &str = "100644";
pub const EXECUTABLE: &str = "100755";
pub const LINK: &str = "120000";
pub const SUBMODULE: &str = "160000";

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

fn fields(record: &[u8]) -> Option<(Vec<Text>, &[u8])> {
    let tab = record.iter().position(|&byte| byte == b'\t')?;
    Some((decoded(&record[..tab]).split(), &record[tab + 1..]))
}

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
        let Some((meta, path)) = fields(record) else {
            return Err(Malformed(record.to_vec()));
        };
        let [mode, _, id] = <[Text; 3]>::try_from(meta).map_err(|_| Malformed(record.to_vec()))?;
        entries.insert(decoded(path), Entry { mode, id });
    }
    Ok(entries)
}

/// The blob ID of `path` from the output of `git ls-tree -z HEAD -- PATH`.
///
/// # Errors
///
/// `carried_blob` requires three metadata fields, mode 100644 or 100755, and a decoded name equal to
/// `path` followed by NUL. On mismatch, the error identifies `head` and `path`.
pub fn carried_blob(head: &str, path: &Text, stdout: &[u8]) -> Result<Text, Text> {
    let (meta, name) = fields(stdout).unwrap_or_else(|| (decoded(stdout).split(), &[][..]));
    let regular = matches!(meta.first(), Some(mode) if *mode == FILE || *mode == EXECUTABLE);
    if meta.len() != 3 || !regular || decoded(name) != text!(path, "\0") {
        return Err(text!(
            "the head ",
            super::short(head),
            " holds no regular file ",
            path.repr()
        ));
    }
    Ok(meta[2].clone())
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
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn joined(directory: &[u8], name: &[u8]) -> Vec<u8> {
    if directory.is_empty() {
        return name.to_vec();
    }
    [directory, b"/", name].concat()
}

/// A top directory that cannot be listed is the path `.`.
fn present(tree: &Path) -> BTreeSet<Text> {
    let mut present = BTreeSet::new();
    let mut pending = vec![Vec::new()];
    while let Some(relative) = pending.pop() {
        let shown = if relative.is_empty() {
            b".".to_vec()
        } else {
            relative.clone()
        };
        let Ok(listing) = fs::read_dir(tree.join(OsStr::from_bytes(&relative))) else {
            present.insert(decoded(&shown));
            continue;
        };
        let (mut directories, mut others) = (Vec::new(), Vec::new());
        let mut complete = true;
        for entry in listing {
            let Ok(entry) = entry else {
                complete = false;
                break;
            };
            let path = joined(&relative, entry.file_name().as_bytes());
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => directories.push(path),
                _ => others.push(path),
            }
        }
        if !complete {
            present.insert(decoded(&shown));
            continue;
        }
        if directories.is_empty() && others.is_empty() && !relative.is_empty() {
            present.insert(decoded(&relative));
        }
        present.extend(others.iter().map(|path| decoded(path)));
        pending.extend(directories);
    }
    present
}

enum Found {
    Other,
    Regular { executable: bool, file: fs::File },
}

/// For `Found::Regular`, `open_regular` checks the file type and owner execute bit on the same handle that
/// `tree_difference` reads.
fn open_regular(path: &Path) -> io::Result<Found> {
    let flags = libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY;
    let file = match OpenOptions::new().read(true).custom_flags(flags).open(path) {
        Ok(file) => file,
        Err(error) => {
            return match fs::symlink_metadata(path) {
                Ok(status) if !status.file_type().is_file() => Ok(Found::Other),
                _ => Err(error),
            };
        }
    };
    let status = file.metadata()?;
    if !status.file_type().is_file() {
        return Ok(Found::Other);
    }
    let executable = status.permissions().mode() & 0o100 != 0;
    Ok(Found::Regular { executable, file })
}

/// The first path at which the worktree at `tree` differs from `named`, or `None`.
///
/// # Errors
///
/// `PathError` carries the full worktree path for propagated I/O errors. A failed `to_os()` conversion
/// carries `tree` instead.
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
        if ![FILE, EXECUTABLE, LINK]
            .iter()
            .any(|mode| entry.mode == *mode)
        {
            return Ok(Some(path));
        }
        let Some(relative) = path.to_os() else {
            let error = io::Error::new(io::ErrorKind::InvalidInput, "a path with no bytes");
            return Err(PathError::new(tree, error));
        };
        let full = tree.join(relative);
        let failed = |error| PathError::new(&full, error);
        let data = if entry.mode == LINK {
            let status = fs::symlink_metadata(&full).map_err(failed)?;
            if !status.file_type().is_symlink() {
                return Ok(Some(path));
            }
            fs::read_link(&full)
                .map_err(failed)?
                .into_os_string()
                .into_vec()
        } else {
            let Found::Regular {
                executable,
                mut file,
            } = open_regular(&full).map_err(failed)?
            else {
                return Ok(Some(path));
            };
            if executable != (entry.mode == EXECUTABLE) {
                return Ok(Some(path));
            }
            let mut data = Vec::new();
            file.read_to_end(&mut data).map_err(failed)?;
            data
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
