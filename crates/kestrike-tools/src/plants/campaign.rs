//! The `campaign` binary of a run, found, resolved and hashed.
//!
//! A `--campaign` value with a `/` is that path, from the invoking directory. Any other value is looked up
//! in each entry of `PATH` in order, an empty entry naming the invoking directory; with `PATH` unset or
//! empty no binary is found. A hit is a path that exists, is no directory, and that the real user may
//! execute.

use std::ffi::{CString, OsStr};
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::stop::Stop;
use crate::ownership::PathError;
use crate::paths;
use crate::python;
use crate::text::Text;

/// `executable` holds for a path that exists, is no directory, and that the real user may execute.
fn executable(path: &Path) -> bool {
    let Ok(status) = fs::metadata(path) else {
        return false;
    };
    let Ok(name) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `access` reads the NUL-terminated name, which `name` owns for the call, and a mode.
    let allowed = unsafe { libc::access(name.as_ptr(), libc::X_OK) } == 0;
    allowed && !status.is_dir()
}

/// `which` returns the path that names the binary `value`, as given or joined to a `PATH` entry.
fn which(value: &OsStr, path: Option<&OsStr>, here: &Path) -> Option<PathBuf> {
    let from_here = |found: &Path| here.join(found);
    if value.as_bytes().contains(&b'/') {
        let given = PathBuf::from(value);
        return executable(&from_here(&given)).then_some(given);
    }
    let path = path.filter(|path| !path.is_empty())?;
    std::env::split_paths(path)
        .map(|entry| entry.join(value))
        .find(|candidate| executable(&from_here(candidate)))
}

/// `campaign` finds the binary `value` names, resolves its links and returns the path with the
/// SHA-256 of the file read now.
///
/// # Errors
///
/// No binary is found, or its file cannot be read, which refuses the run; resolving the path fails,
/// which is a failure.
pub(super) fn campaign(
    value: &OsStr,
    path: Option<&OsStr>,
    here: &Path,
) -> Result<(PathBuf, String), Stop> {
    let Some(found) = which(value, path, here) else {
        let mut reason = Text::from("no campaign binary at ");
        reason.push_text(&Text::from_os(value));
        return Err(Stop::rejected(reason));
    };
    let resolved = paths::resolve(&here.join(found))
        .map_err(|error| Stop::failed(format!("the campaign binary: {error}")))?;
    let unreadable = |error| {
        let error = PathError::new(&resolved, error);
        Stop::rejected(format!("the campaign binary cannot be read: {error}"))
    };
    let mut file = File::open(&resolved).map_err(unreadable)?;
    let mut digest = Sha256::new();
    let mut block = vec![0; 1 << 20];
    loop {
        match file.read(&mut block) {
            Ok(0) => break,
            Ok(read) => digest.update(&block[..read]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(unreadable(error)),
        }
    }
    Ok((resolved, python::hex(&digest.finalize())))
}
