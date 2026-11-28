//! The write of a file whole or not at all, and the making of its directory.
//!
//! [`write_file`] takes a path and a text, and its steps run in this order:
//!
//! 1. [`make_directory`] makes the parent directory with each missing ancestor and syncs the parent
//!    of each directory it made;
//! 2. a link at the path's name is the error `ELOOP`, and no later step runs;
//! 3. `<name>.partial` beside it is removed where one stands;
//! 4. `<name>.partial` is created with `O_CREAT | O_EXCL | O_NOFOLLOW` and mode 0644;
//! 5. the text is written and the file synced;
//! 6. the file is renamed over the name;
//! 7. on a failure of steps 3 to 6, `<name>.partial` is removed, a failed removal passed over, and the
//!    failure returned, so the previous version stands at the name;
//! 8. the parent directory is synced; a failure here returns with the new file at the name.
//!
//! A reader of the name therefore sees the previous version or the new one whole. Every path is taken
//! in Python's pure form: empty and `.` components dropped, `..` kept. The file and directory syncs, the
//! directory's opens, `mkdir`, `lstat` and `exists` go through [`Files`]; the remove, the create and the
//! rename are calls of the system by the path's name. The module trusts the directories its caller
//! names and checks no owner.

use std::cell::Cell;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use super::failure::SystemError;
use crate::host_stop::{Files, Links, sync_directory};
use crate::paths;

/// Writes `text` to `path` whole or not at all, with [`create_partial`] as step 4.
///
/// # Errors
///
/// The system error of the step that failed, worded as Python words it with the file it named.
pub fn write_file(files: &impl Files, path: &Path, text: &str) -> Result<(), SystemError> {
    write_file_by(files, create_partial, path, text)
}

/// Step 4 of [`write_file`]: `open(partial, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
/// 0644)`.
///
/// # Errors
///
/// The error of the open.
pub fn create_partial(partial: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW)
        .open(partial)
}

/// [`write_file`] with `create` as its step 4, which a test passes to fail that step.
///
/// # Errors
///
/// The system error of the step that failed. A path whose pure form has no final name, as `/` and `.`
/// have none, is an `EINVAL` error after step 2.
pub fn write_file_by(
    files: &impl Files,
    create: impl FnOnce(&Path) -> io::Result<File>,
    path: &Path,
    text: &str,
) -> Result<(), SystemError> {
    let path = pure(path);
    let parent = parent(&path);
    make_directory(files, &parent)?;
    if is_symlink(files, &path)? {
        let error = io::Error::from_raw_os_error(libc::ELOOP);
        return Err(SystemError::of(&error, &[&path]));
    }
    let Some(partial) = partial(&path) else {
        return Err(SystemError::worded(
            Some(libc::EINVAL),
            "the path names no file",
            &[&path],
        ));
    };
    if let Err(error) = replace(files, create, &partial, &path, text) {
        let _ = fs::remove_file(&partial);
        return Err(error);
    }
    sync(files, &parent)
}

/// Steps 3 to 6.
fn replace(
    files: &impl Files,
    create: impl FnOnce(&Path) -> io::Result<File>,
    partial: &Path,
    path: &Path,
    text: &str,
) -> Result<(), SystemError> {
    match fs::remove_file(partial) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => {
            return Err(SystemError::of(&error, &[partial]));
        }
        _ => {}
    }
    let file = create(partial).map_err(|error| SystemError::of(&error, &[partial]))?;
    let mut rest = text.as_bytes();
    while !rest.is_empty() {
        match files.write(&file, rest) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(SystemError::of(&error, &[])),
            Ok(0) => {
                let error = io::Error::from(io::ErrorKind::WriteZero);
                return Err(SystemError::of(&error, &[]));
            }
            Ok(written) => rest = rest.get(written..).unwrap_or_default(),
        }
    }
    files
        .fsync(&file)
        .map_err(|error| SystemError::of(&error, &[]))?;
    drop(file);
    fs::rename(partial, path).map_err(|error| SystemError::of(&error, &[partial, path]))
}

/// Makes `directory` with each missing ancestor: from the directory up, each path that does not
/// exist is missing, until one exists or repeats; then, from the highest, each is made and its parent
/// synced. A `mkdir` that fails passes when a directory stands at the path, as another maker's may.
///
/// # Errors
///
/// The system error of a check that is no plain absence, of a `mkdir` with no directory at its path,
/// or of a sync.
pub fn make_directory(files: &impl Files, directory: &Path) -> Result<(), SystemError> {
    let mut directory = pure(directory);
    let mut missing: Vec<PathBuf> = Vec::new();
    while !exists(files, &directory)? && !missing.contains(&directory) {
        let above = parent(&directory);
        missing.push(directory);
        directory = above;
    }
    for made in missing.iter().rev() {
        if let Err(error) = files.mkdir(made)
            && (error.kind() == io::ErrorKind::NotFound || !is_dir(made)?)
        {
            return Err(SystemError::of(&error, &[made]));
        }
        sync(files, &parent(made))?;
    }
    Ok(())
}

/// Syncs `directory`'s entries through [`sync_directory`]; a failed open names the directory and a
/// failed sync names none.
pub(super) fn sync(files: &impl Files, directory: &Path) -> Result<(), SystemError> {
    let watched = Watched {
        files,
        opened: Cell::new(false),
    };
    sync_directory(&watched, directory).map_err(|error| {
        let names: &[&Path] = if watched.opened.get() {
            &[]
        } else {
            &[directory]
        };
        SystemError::of(&error, names)
    })
}

/// The two steps of [`sync_directory`] passed to `files`, with whether the open succeeded. Only those
/// two methods reach `files`; [`sync`] calls nothing else on this value.
struct Watched<'a, F> {
    files: &'a F,
    opened: Cell<bool>,
}

impl<F: Files> Files for Watched<'_, F> {
    fn open_directory(&self, path: &Path, links: Links) -> io::Result<File> {
        let opened = self.files.open_directory(path, links);
        self.opened.set(opened.is_ok());
        opened
    }

    fn fsync_directory(&self, directory: &File) -> io::Result<()> {
        self.files.fsync_directory(directory)
    }
}

/// The errors a check of a path's existence reads as no entry: `ENOENT`, `ENOTDIR`, `EBADF` and
/// `ELOOP`.
pub(super) fn absent(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ENOENT | libc::ENOTDIR | libc::EBADF | libc::ELOOP)
    )
}

/// Whether `path` exists once links are followed. Where [`Files::exists`] reads no entry, the
/// `lstat` of the path decides: an error of another kind than [`absent`] names is returned.
pub(super) fn exists(files: &impl Files, path: &Path) -> Result<bool, SystemError> {
    if files.exists(path) {
        return Ok(true);
    }
    match files.lstat(path) {
        Err(error) if !absent(&error) => Err(SystemError::of(&error, &[path])),
        _ => Ok(false),
    }
}

/// Whether a link stands at `path`'s name, by its `lstat`; an [`absent`] error reads as none.
pub(super) fn is_symlink(files: &impl Files, path: &Path) -> Result<bool, SystemError> {
    match files.lstat(path) {
        Ok(metadata) => Ok(metadata.file_type().is_symlink()),
        Err(error) if absent(&error) => Ok(false),
        Err(error) => Err(SystemError::of(&error, &[path])),
    }
}

fn is_dir(path: &Path) -> Result<bool, SystemError> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.is_dir()),
        Err(error) if absent(&error) => Ok(false),
        Err(error) => Err(SystemError::of(&error, &[path])),
    }
}

/// `path` in Python's pure form.
pub(super) fn pure(path: &Path) -> PathBuf {
    PathBuf::from(OsStr::from_bytes(&paths::pure_bytes(
        path.as_os_str().as_bytes(),
    )))
}

/// The parent of a pure path as Python gives it: the path less its last component, `.` for a
/// relative path of one component, and the root for the root.
pub(super) fn parent(path: &Path) -> PathBuf {
    let bytes = path.as_os_str().as_bytes();
    let root: &[u8] = if bytes.starts_with(b"//") && !bytes.starts_with(b"///") {
        b"//"
    } else if bytes.starts_with(b"/") {
        b"/"
    } else {
        b""
    };
    let names = &bytes[root.len()..];
    let above = match names.iter().rposition(|&byte| byte == b'/') {
        Some(at) => &names[..at],
        None => &names[..0],
    };
    let mut parent = root.to_vec();
    parent.extend_from_slice(above);
    if parent.is_empty() {
        parent.push(b'.');
    }
    PathBuf::from(OsStr::from_bytes(&parent))
}

/// `<name>.partial` beside a pure path, or none when the path has no final name.
fn partial(path: &Path) -> Option<PathBuf> {
    let bytes = path.as_os_str().as_bytes();
    let name = bytes
        .rsplit(|&byte| byte == b'/')
        .next()
        .unwrap_or_default();
    if name.is_empty() || name == b"." {
        return None;
    }
    let mut partial = bytes.to_vec();
    partial.extend_from_slice(b".partial");
    Some(PathBuf::from(OsStr::from_bytes(&partial)))
}
