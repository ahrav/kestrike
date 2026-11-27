//! File tests that read the errors `stat` and `lstat` report as Python's `pathlib` reads them: a path
//! that is absent by [`crate::ownership::status`] is no file, no directory and no link, and any other
//! error is the caller's to report.

use std::fs;
use std::io;
use std::path::Path;

use crate::ownership::{PathError, status};

/// `is_link` holds when `lstat` names a symbolic link.
///
/// # Errors
///
/// `lstat` fails with an error that does not make the path absent.
pub(crate) fn is_link(path: &Path) -> Result<bool, PathError> {
    match fs::symlink_metadata(path) {
        Ok(found) => Ok(found.file_type().is_symlink()),
        Err(error) if absent(&error) => Ok(false),
        Err(error) => Err(PathError::new(path, error)),
    }
}

/// `is_file` holds when `stat` names a regular file.
///
/// # Errors
///
/// `stat` fails with an error that does not make the path absent.
pub(crate) fn is_file(path: &Path) -> Result<bool, PathError> {
    Ok(status(path)?.is_some_and(|found| found.is_file()))
}

/// `is_dir` holds when `stat` names a directory.
///
/// # Errors
///
/// `stat` fails with an error that does not make the path absent.
pub(crate) fn is_dir(path: &Path) -> Result<bool, PathError> {
    Ok(status(path)?.is_some_and(|found| found.is_dir()))
}

fn absent(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ENOENT | libc::ENOTDIR | libc::EBADF | libc::ELOOP)
    )
}

/// `strerror` is the operating system's text for `error`, without the code the standard library adds.
pub(crate) fn strerror(error: &io::Error) -> String {
    let shown = error.to_string();
    match error.raw_os_error() {
        Some(code) => shown
            .strip_suffix(&format!(" (os error {code})"))
            .map_or_else(|| shown.clone(), str::to_owned),
        None => shown,
    }
}
