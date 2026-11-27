//! `resolve` follows symbolic links and returns an absolute path even when components are missing.
//!
//! `resolve` starts a relative path at the process's working directory. It reads components left to right: it
//! skips `.` and empty components, drops the last resolved component at `..`, and appends each other component.
//! `resolve` interprets relative link targets from the link's directory and absolute targets from `/`, and keeps
//! the component on any `read_link` error. `resolve` returns a loop error if it encounters a link again while
//! resolving that link's target.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

/// # Errors
///
/// Reading the working directory fails for a relative `path`, or a link's target leads back to that link.
pub fn resolve(path: &Path) -> io::Result<PathBuf> {
    let base = if path.is_absolute() {
        Vec::new()
    } else {
        std::env::current_dir()?.into_os_string().into_vec()
    };
    let resolved = walk(base, path.as_os_str().as_bytes(), &mut HashMap::new())?;
    Ok(PathBuf::from(OsStr::from_bytes(if resolved.is_empty() {
        b"/"
    } else {
        &resolved
    })))
}

/// `seen` maps each link met so far to its resolved path, or to `None` while that link is being resolved.
fn walk(
    mut path: Vec<u8>,
    rest: &[u8],
    seen: &mut HashMap<Vec<u8>, Option<Vec<u8>>>,
) -> io::Result<Vec<u8>> {
    if rest.starts_with(b"/") {
        path.clear();
    }
    for name in rest.split(|&byte| byte == b'/') {
        if name.is_empty() || name == b"." {
            continue;
        }
        if name == b".." {
            let end = path.iter().rposition(|&byte| byte == b'/').unwrap_or(0);
            path.truncate(end);
            continue;
        }
        let mut next = path.clone();
        if !next.ends_with(b"/") {
            next.push(b'/');
        }
        next.extend_from_slice(name);
        match seen.get(&next) {
            Some(Some(target)) => {
                path = target.clone();
                continue;
            }
            Some(None) => {
                let shown = String::from_utf8_lossy(&next).into_owned();
                return Err(io::Error::other(format!("symlink loop from {shown}")));
            }
            None => {}
        }
        match std::fs::read_link(OsStr::from_bytes(&next)) {
            Ok(target) => {
                seen.insert(next.clone(), None);
                path = walk(path, target.as_os_str().as_bytes(), seen)?;
                seen.insert(next, Some(path.clone()));
            }
            Err(_) => path = next,
        }
    }
    Ok(path)
}
