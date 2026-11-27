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

pub(crate) fn real_uid() -> u32 {
    // SAFETY: `getuid` takes no argument, touches no memory of the caller and always succeeds.
    unsafe { libc::getuid() }
}

fn path_of(bytes: &[u8]) -> PathBuf {
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
            path_of(&joined)
        })
        .collect()
}

fn join(directory: &[u8], name: &[u8]) -> Vec<u8> {
    match directory {
        b"." => name.to_vec(),
        bytes if bytes.ends_with(b"/") => [bytes, name].concat(),
        bytes => [bytes, b"/", name].concat(),
    }
}

fn absent(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR))
}

/// `shared_directories` returns, in lineage order, each existing member that a user other than this user
/// and root owns or that has a [`SHARED`] bit. `stat` judges a link by its target.
///
/// The lineage is `path` and its lexical parents, spelled as given, with `..` and links left unresolved: it
/// ends at `/` (or `//`) for an absolute path and at `.` for a relative one, and a link member is judged by
/// its target alone, not by the target's parents. The result covers the directories the kernel traverses
/// for `path` only when `path` is absolute with its links resolved; [`make_private`] and
/// [`foreign_toolchain_paths`] judge the same lineage.
///
/// # Errors
///
/// A `stat` fails with an error other than `ENOENT` and `ENOTDIR`.
pub fn shared_directories(path: &Path) -> Result<Vec<PathBuf>, PathError> {
    let mut found = Vec::new();
    for directory in lineage(path) {
        let status = match fs::metadata(&directory) {
            Ok(status) => status,
            Err(error) if absent(&error) => continue,
            Err(error) => return Err(PathError::new(&directory, error)),
        };
        if ![real_uid(), 0].contains(&status.uid()) || status.mode() & SHARED != 0 {
            found.push(directory);
        }
    }
    Ok(found)
}

/// `traversed` returns each directory in which resolving an absolute `path` looks a name up, from the root
/// down. It takes `..` as the lexical parent and replaces each of the first [`MAX_LINKS`] links it meets by
/// its target's names, from `/` for an absolute target. For a path with no root it drops the first name and
/// walks the rest from `/`.
///
/// # Errors
///
/// Reading a link fails.
pub fn traversed(path: &Path) -> Result<Vec<PathBuf>, PathError> {
    let bytes = path.as_os_str().as_bytes();
    let mut pending: std::collections::VecDeque<Vec<u8>> = bytes
        .split(|&byte| byte == b'/')
        .filter(|name| !name.is_empty() && *name != b".")
        .map(<[u8]>::to_vec)
        .skip(usize::from(!bytes.starts_with(b"/")))
        .collect();
    let mut current = b"/".to_vec();
    let mut passed = Vec::new();
    let mut links = 0;
    while let Some(part) = pending.pop_front() {
        if part == b".." {
            // `current` is absolute with single slashes and no trailing slash past the root, so its parent
            // ends before its last slash, and the parent of `/` and of `/name` is `/`.
            let last = current.iter().rposition(|&byte| byte == b'/').unwrap_or(0);
            current.truncate(last.max(1));
            continue;
        }
        passed.push(path_of(&current));
        let step = join(&current, &part);
        let is_link = fs::symlink_metadata(path_of(&step)).is_ok_and(|status| status.is_symlink());
        if is_link && links < MAX_LINKS {
            links += 1;
            let target = fs::read_link(path_of(&step))
                .map_err(|error| PathError::new(&path_of(&step), error))?;
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
    Io(PathError),
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

/// The `Display` text of `Io` is its [`PathError`]'s, which holds the I/O error's text, so the error reports
/// no `source`.
impl std::error::Error for PrivateError {}

impl From<PathError> for PrivateError {
    fn from(error: PathError) -> Self {
        Self::Io(error)
    }
}

/// `ignored` holds for the `stat` errors that make Python's `Path.exists` and `Path.is_dir` false.
pub(crate) fn ignored(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ENOENT | libc::ENOTDIR | libc::EBADF | libc::ELOOP)
    )
}

/// `status` returns the `stat` of `path`, or `None` for a path absent by [`ignored`], the errors that make
/// Python's `Path.exists` and `Path.is_file` false, and for a path that holds a NUL byte, which names no
/// file.
///
/// # Errors
///
/// `stat` fails with another error.
pub fn status(path: &Path) -> Result<Option<fs::Metadata>, PathError> {
    if path.as_os_str().as_bytes().contains(&0) {
        return Ok(None);
    }
    match fs::metadata(path) {
        Ok(status) => Ok(Some(status)),
        Err(error) if ignored(&error) => Ok(None),
        Err(error) => Err(PathError::new(path, error)),
    }
}

/// `make_private` creates each member of `path`'s lineage for which `status` returns `Ok(None)`,
/// outermost first, as a directory of mode 0700 under the umask, then refuses with
/// [`PrivateError::Shared`] when [`shared_directories`] returns a member. An existing member, a file or
/// another non-directory included, keeps its type, mode and owner, so `Ok(())` shows that no member is
/// shared and does not show that `path` is a directory.
///
/// # Errors
///
/// `make_private` returns an error when `stat` reports an error outside `ignored`, when `mkdir` fails
/// (except for `EEXIST` when `status` returns `Ok(Some(metadata))` and `metadata.is_dir()` is true), or
/// when a member is shared.
pub fn make_private(path: &Path) -> Result<(), PrivateError> {
    let mut missing = Vec::new();
    for step in lineage(path) {
        if status(&step)?.is_none() {
            missing.push(step);
        }
    }
    for directory in missing.iter().rev() {
        match DirBuilder::new().mode(0o700).create(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                if !status(directory)?.is_some_and(|status| status.is_dir()) {
                    return Err(PathError::new(directory, error).into());
                }
            }
            Err(error) => return Err(PathError::new(directory, error).into()),
        }
    }
    let shared = shared_directories(path)?;
    if shared.is_empty() {
        Ok(())
    } else {
        Err(PrivateError::Shared(shared))
    }
}

/// `foreign_toolchain_paths` returns the flagged Cargo and rustup configuration entries of `root` and of
/// each of its lexical parents: first what [`shared_directories`] returns for `root`, then, for each member
/// of the lineage from `root` outward and each name of [`TOOLCHAIN_FILES`] in order, the entry when its
/// `lstat` succeeds and its `stat` fails, or when the entry or its target has an owner other than the
/// process's real uid (a root-owned entry or target is flagged), the target has a [`SHARED`] bit, or a
/// directory [`traversed`] returns for the entry is itself shared.
///
/// # Errors
///
/// [`shared_directories`] or [`traversed`] fails.
pub fn foreign_toolchain_paths(root: &Path) -> Result<Vec<PathBuf>, PathError> {
    let mut found = shared_directories(root)?;
    for directory in lineage(root) {
        for name in TOOLCHAIN_FILES {
            let entry = path_of(&join(directory.as_os_str().as_bytes(), name.as_bytes()));
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

fn passes_shared(entry: &Path) -> Result<bool, PathError> {
    for passed in traversed(entry)? {
        let shared = shared_directories(&passed)?;
        if shared.first().map(|first| first.as_os_str()) == Some(passed.as_os_str()) {
            return Ok(true);
        }
    }
    Ok(false)
}

#[derive(Debug)]
pub struct PathError {
    path: PathBuf,
    error: io::Error,
}

impl PathError {
    pub(crate) fn new(path: &Path, error: io::Error) -> Self {
        Self {
            path: path.to_path_buf(),
            error,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn error(&self) -> &io::Error {
        &self.error
    }
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {}",
            Text::from_os(self.path.as_os_str()),
            self.error
        )
    }
}

/// The `Display` text holds the path and the I/O error's text, so the error reports no `source`;
/// [`PathError::error`] gives the I/O error itself.
impl std::error::Error for PathError {}
