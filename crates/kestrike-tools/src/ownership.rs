//! The module flags path entries by ownership and write-permission bits.
//!
//! Ownership checks use the process's real user id, called this user below. A path's lineage is the path
//! and then each lexical parent, as Python's `pathlib` gives them: repeated slashes and `.` components drop,
//! `..` stays, exactly two leading slashes stay `//` while three or more become `/`, and a relative path ends
//! at `.`.

use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

use crate::text::Text;

/// `TOOLCHAIN_FILES` names candidate Cargo configuration and rustup toolchain entries relative to a
/// lineage member.
pub const TOOLCHAIN_FILES: [&str; 5] = [
    ".cargo",
    ".cargo/config.toml",
    ".cargo/config",
    "rust-toolchain",
    "rust-toolchain.toml",
];

/// `SHARED` selects the group-write and other-write permission bits.
pub const SHARED: u32 = 0o020 | 0o002;

const MAX_LINKS: usize = 40;

fn real_uid() -> u32 {
    // SAFETY: `getuid` takes no argument, touches no memory of the caller and always succeeds.
    unsafe { libc::getuid() }
}

fn path(bytes: &[u8]) -> PathBuf {
    PathBuf::from(OsStr::from_bytes(bytes))
}

fn lineage(path: &Path) -> Vec<PathBuf> {
    let bytes = path.as_os_str().as_bytes();
    let root: &[u8] = match bytes.iter().take_while(|&&byte| byte == b'/').count() {
        0 => b"",
        2 => b"//",
        _ => b"/",
    };
    let names: Vec<&[u8]> = bytes
        .split(|&byte| byte == b'/')
        .filter(|name| !name.is_empty() && *name != b".")
        .collect();
    (0..=names.len())
        .rev()
        .map(|count| {
            let mut joined = root.to_vec();
            joined.extend_from_slice(&names[..count].join(&b'/'));
            if joined.is_empty() {
                joined.push(b'.');
            }
            self::path(&joined)
        })
        .collect()
}

fn join(directory: &Path, name: &str) -> PathBuf {
    match directory.as_os_str().as_bytes() {
        b"." => PathBuf::from(name),
        bytes if bytes.ends_with(b"/") => path(&[bytes, name.as_bytes()].concat()),
        bytes => path(&[bytes, b"/", name.as_bytes()].concat()),
    }
}

fn absent(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR))
}

/// `shared_directories` returns, in lineage order, each existing member that a user other than this user
/// and root owns or that has a [`SHARED`] bit. `stat` judges a link by its target.
///
/// # Errors
///
/// A `stat` fails with an error other than `ENOENT` and `ENOTDIR`.
pub fn shared_directories(path: &Path) -> io::Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    for directory in lineage(path) {
        let status = match fs::metadata(&directory) {
            Ok(status) => status,
            Err(error) if absent(&error) => continue,
            Err(error) => return Err(error),
        };
        if ![real_uid(), 0].contains(&status.uid()) || status.mode() & SHARED != 0 {
            found.push(directory);
        }
    }
    Ok(found)
}

fn dirname(path: &[u8]) -> Vec<u8> {
    let head = &path[..path
        .iter()
        .rposition(|&byte| byte == b'/')
        .map_or(0, |at| at + 1)];
    if head.iter().all(|&byte| byte == b'/') {
        return head.to_vec();
    }
    let end = head
        .iter()
        .rposition(|&byte| byte != b'/')
        .map_or(0, |at| at + 1);
    head[..end].to_vec()
}

/// `traversed` returns each directory in which resolving `path` looks a name up, in order. It walks the
/// names after the first component of `path` from `/`, takes `..` as the lexical parent, and replaces each
/// of the first [`MAX_LINKS`] links it meets by its target's names, from `/` for an absolute target.
///
/// # Errors
///
/// Reading a link fails.
pub fn traversed(path: &Path) -> io::Result<Vec<PathBuf>> {
    let lineage = lineage(path);
    let full = lineage[0].as_os_str().as_bytes();
    let mut pending: std::collections::VecDeque<Vec<u8>> = full
        .split(|&byte| byte == b'/')
        .filter(|name| !name.is_empty())
        .map(<[u8]>::to_vec)
        .skip(usize::from(!full.starts_with(b"/")))
        .collect();
    let mut current = b"/".to_vec();
    let mut passed = Vec::new();
    let mut links = 0;
    while let Some(part) = pending.pop_front() {
        if part == b".." {
            current = dirname(&current);
            continue;
        }
        passed.push(self::path(&current));
        let mut step = current.clone();
        if !step.ends_with(b"/") {
            step.push(b'/');
        }
        step.extend_from_slice(&part);
        let is_link =
            fs::symlink_metadata(self::path(&step)).is_ok_and(|status| status.is_symlink());
        if is_link && links < MAX_LINKS {
            links += 1;
            let target = fs::read_link(self::path(&step))?;
            let target = target.as_os_str().as_bytes();
            if target.starts_with(b"/") {
                current = b"/".to_vec();
            }
            let names = target
                .split(|&byte| byte == b'/')
                .filter(|name| !name.is_empty() && *name != b".");
            for name in names.rev() {
                pending.push_front(name.to_vec());
            }
        } else {
            current = step;
        }
    }
    Ok(passed)
}

#[derive(Debug)]
pub enum PrivateError {
    Io(io::Error),
    /// The members of the lineage that [`shared_directories`] returns once the directories exist.
    Shared(Vec<PathBuf>),
}

impl fmt::Display for PrivateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(f),
            Self::Shared(paths) => {
                let shown: Vec<String> = paths
                    .iter()
                    .map(|path| Text::from_os(path.as_os_str()).to_string())
                    .collect();
                write!(f, "another user owns or can write {}", shown.join(", "))
            }
        }
    }
}

impl std::error::Error for PrivateError {}

impl From<io::Error> for PrivateError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// `ignored` holds for the `stat` errors that make Python's `Path.exists` and `Path.is_dir` false.
fn ignored(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ENOENT | libc::ENOTDIR | libc::EBADF | libc::ELOOP)
    )
}

fn exists(path: &Path) -> io::Result<bool> {
    match fs::metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if ignored(&error) => Ok(false),
        Err(error) => Err(error),
    }
}

fn is_dir(path: &Path) -> io::Result<bool> {
    match fs::metadata(path) {
        Ok(status) => Ok(status.is_dir()),
        Err(error) if ignored(&error) => Ok(false),
        Err(error) => Err(error),
    }
}

/// `make_private` creates each member of `path`'s lineage for which `exists` returns `Ok(false)`,
/// outermost first, as a directory of mode 0700 under the umask, then refuses with
/// [`PrivateError::Shared`] when [`shared_directories`] returns a member. Existing directories retain their
/// modes and owners.
///
/// # Errors
///
/// `make_private` returns an error when `stat` reports an error outside `ignored`, when `mkdir` fails
/// (except for `EEXIST` followed by `is_dir` returning `Ok(true)`), or when a member is shared.
pub fn make_private(path: &Path) -> Result<(), PrivateError> {
    let mut missing = Vec::new();
    for step in lineage(path) {
        if !exists(&step)? {
            missing.push(step);
        }
    }
    for directory in missing.iter().rev() {
        match DirBuilder::new().mode(0o700).create(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                if !is_dir(directory)? {
                    return Err(error.into());
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    let shared = shared_directories(path)?;
    if shared.is_empty() {
        Ok(())
    } else {
        Err(PrivateError::Shared(shared))
    }
}

/// `foreign_toolchain_paths` returns flagged Cargo and rustup configuration paths under `root`: first what
/// [`shared_directories`] returns for `root`, then, for each member of the lineage and each name of
/// [`TOOLCHAIN_FILES`], the entry when its `lstat` succeeds and its `stat` fails, or when the entry or its
/// target has an owner other than this user, root included, the target has a [`SHARED`] bit, or a
/// directory [`traversed`] returns for the entry is itself shared.
///
/// # Errors
///
/// [`shared_directories`] or [`traversed`] fails.
pub fn foreign_toolchain_paths(root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut found = shared_directories(root)?;
    for directory in lineage(root) {
        for name in TOOLCHAIN_FILES {
            let entry = join(&directory, name);
            let Ok(link) = fs::symlink_metadata(&entry) else {
                continue;
            };
            let Ok(target) = fs::metadata(&entry) else {
                found.push(entry);
                continue;
            };
            let me = real_uid();
            if link.uid() != me
                || target.uid() != me
                || target.mode() & SHARED != 0
                || passes_shared(&entry)?
            {
                found.push(entry);
            }
        }
    }
    Ok(found)
}

fn passes_shared(entry: &Path) -> io::Result<bool> {
    for passed in traversed(entry)? {
        let shared = shared_directories(&passed)?;
        if shared.first().map(|first| first.as_os_str()) == Some(passed.as_os_str()) {
            return Ok(true);
        }
    }
    Ok(false)
}
