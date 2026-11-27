//! The run's two inputs outside the store: the checkout's `Cargo.lock`, read once, and the `campaign`
//! binary, found, resolved and hashed.
//!
//! A `--campaign` value with a `/` is that path, from the invoking directory. Any other value is looked up
//! in each entry of `PATH` in order, an empty entry naming the invoking directory; with `PATH` unset or
//! empty no binary is found. A hit is a path that exists, is no directory, and that the real user may
//! execute.

use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::files::{is_file, is_link, strerror};
use super::prepare::Stop;
use crate::ownership::PathError;
use crate::paths;
use crate::text::Text;

/// `lock` returns the bytes of `top/Cargo.lock`, which must be a regular file and no link.
///
/// # Errors
///
/// The file is missing, a link or no regular file (`no regular file`), or cannot be read (the operating
/// system's text).
pub(super) fn lock(top: &Path) -> Result<Vec<u8>, Stop> {
    let path = top.join("Cargo.lock");
    let read = || -> Result<Vec<u8>, String> {
        let failed = |error: PathError| strerror(error.error());
        if is_link(&path).map_err(failed)? || !is_file(&path).map_err(failed)? {
            return Err("no regular file".to_owned());
        }
        fs::read(&path).map_err(|error| strerror(&error))
    };
    read().map_err(|why| {
        Stop::Rejected(Text::from(format!(
            "the checkout holds no readable Cargo.lock ({why}); build it once to resolve the \
             dependencies every archive of the run shares"
        )))
    })
}

/// `join` joins `name` to `directory` as a path: an empty directory leaves `name` alone.
fn join(directory: &[u8], name: &[u8]) -> PathBuf {
    let mut joined = directory.to_vec();
    if !joined.is_empty() && !joined.ends_with(b"/") {
        joined.push(b'/');
    }
    joined.extend_from_slice(name);
    PathBuf::from(OsString::from_vec(joined))
}

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
    path.as_bytes()
        .split(|&byte| byte == b':')
        .map(|entry| join(entry, value.as_bytes()))
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
        return Err(Stop::Rejected(reason));
    };
    let resolved = paths::resolve(&here.join(found))
        .map_err(|error| Stop::Failed(Text::from(format!("the campaign binary: {error}"))))?;
    let unreadable = |error| {
        let error = PathError::new(&resolved, error);
        Stop::Rejected(Text::from(format!(
            "the campaign binary cannot be read: {error}"
        )))
    };
    let mut file = File::open(&resolved).map_err(unreadable)?;
    let mut digest = Sha256::new();
    let mut block = vec![0; 1 << 20];
    loop {
        let read = file.read(&mut block).map_err(unreadable)?;
        if read == 0 {
            break;
        }
        digest.update(&block[..read]);
    }
    let hex = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok((resolved, hex))
}
