//! `resolve` follows symbolic links and returns an absolute path even when components are missing.
//!
//! `resolve` reads components left to right, a relative path from the working directory. It skips `.` and
//! empty components and drops the last resolved component at `..`. It follows each link it meets, a
//! relative target from the link's directory and an absolute one from `/`, and keeps every other component
//! as written. When a link's target leads back to a link still being resolved, `resolve` keeps that link
//! and everything after it unresolved, and the final path is normalized lexically. `resolve` refuses a
//! final path whose own lookup fails with a loop error, and links that nest more than [`DEPTH`] deep.
//!
//! `joined`, `parent`, `name` and `pure` read a path's text alone, as a pure POSIX path: a root of
//! `//` stays, empty and `.` components drop, and `..` stays.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

/// The deepest chain of links whose targets `resolve` follows, one link inside the target of the next.
pub const DEPTH: usize = 993;

/// # Errors
///
/// `resolve` returns an error when reading the working directory fails for a relative `path`, when a link
/// that `lstat` reports cannot be read, when links nest more than [`DEPTH`] deep, and when the lookup of
/// the final path meets a link loop.
pub fn resolve(path: &Path) -> io::Result<PathBuf> {
    let raw = path.as_os_str().as_bytes();
    let mut parsed: Vec<u8> = if raw.starts_with(b"/") {
        b"/".to_vec()
    } else {
        Vec::new()
    };
    for name in raw
        .split(|&byte| byte == b'/')
        .filter(|name| !name.is_empty() && *name != b".")
    {
        if !parsed.is_empty() && !parsed.ends_with(b"/") {
            parsed.push(b'/');
        }
        parsed.extend_from_slice(name);
    }
    let (joined, _) = walk(Vec::new(), &parsed, &mut HashMap::new(), 0)?;
    let absolute = if joined.starts_with(b"/") {
        joined
    } else {
        let mut base = std::env::current_dir()?.into_os_string().into_vec();
        base = join(&base, &joined);
        base
    };
    let resolved = PathBuf::from(OsStr::from_bytes(&normalize(&absolute)));
    match std::fs::metadata(&resolved) {
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => Err(io::Error::other(format!(
            "symlink loop from {}",
            resolved.display()
        ))),
        _ => Ok(resolved),
    }
}

/// `join` appends `name` to `path` with one `/` between them; an absolute `name` replaces `path`.
pub(crate) fn join(path: &[u8], name: &[u8]) -> Vec<u8> {
    if name.starts_with(b"/") || path.is_empty() {
        return name.to_vec();
    }
    let mut joined = path.to_vec();
    if !joined.ends_with(b"/") {
        joined.push(b'/');
    }
    joined.extend_from_slice(name);
    joined
}

/// `walk` resolves `rest` from `path` and returns the result with `true`, or, after meeting a link that is
/// still being resolved, the path with that link and the unread components appended and `false`. `seen`
/// maps each link met so far to its resolved path, or to `None` while that link is being resolved.
fn walk(
    mut path: Vec<u8>,
    mut rest: &[u8],
    seen: &mut HashMap<Vec<u8>, Option<Vec<u8>>>,
    depth: usize,
) -> io::Result<(Vec<u8>, bool)> {
    if let Some(stripped) = rest.strip_prefix(b"/") {
        rest = stripped;
        path = b"/".to_vec();
    }
    while !rest.is_empty() {
        let (name, tail) = match rest.iter().position(|&byte| byte == b'/') {
            Some(at) => (&rest[..at], &rest[at + 1..]),
            None => (rest, &rest[rest.len()..]),
        };
        rest = tail;
        if name.is_empty() || name == b"." {
            continue;
        }
        if name == b".." {
            if path.is_empty() {
                path = b"..".to_vec();
            } else {
                let (head, last) = split(&path);
                path = if last == b".." {
                    join(&join(&head, b".."), b"..")
                } else {
                    head
                };
            }
            continue;
        }
        let next = join(&path, name);
        let link = std::fs::symlink_metadata(OsStr::from_bytes(&next))
            .is_ok_and(|metadata| metadata.file_type().is_symlink());
        if !link {
            path = next;
            continue;
        }
        match seen.get(&next) {
            Some(Some(target)) => {
                path = target.clone();
                continue;
            }
            Some(None) => return Ok((join(&next, rest), false)),
            None => {}
        }
        if depth >= DEPTH {
            return Err(io::Error::other(format!(
                "links nest more than {DEPTH} deep at {}",
                String::from_utf8_lossy(&next)
            )));
        }
        let target = std::fs::read_link(OsStr::from_bytes(&next))?;
        seen.insert(next.clone(), None);
        let (resolved, complete) = walk(path, target.as_os_str().as_bytes(), seen, depth + 1)?;
        if !complete {
            return Ok((join(&resolved, rest), false));
        }
        path = resolved;
        seen.insert(next, Some(path.clone()));
    }
    Ok((path, true))
}

/// `split` returns the part of `path` before its last `/`, without trailing slashes unless it is all
/// slashes, and the part after it.
pub(crate) fn split(path: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let at = path
        .iter()
        .rposition(|&byte| byte == b'/')
        .map_or(0, |at| at + 1);
    let (mut head, tail) = (path[..at].to_vec(), path[at..].to_vec());
    if head.iter().any(|&byte| byte != b'/') {
        while head.ends_with(b"/") {
            head.pop();
        }
    }
    (head, tail)
}

/// `normalize` removes empty and `.` components and each `..` with the component before it, keeps a
/// leading `//` and folds three or more leading slashes into one.
pub(crate) fn normalize(path: &[u8]) -> Vec<u8> {
    let slashes = if path.starts_with(b"//") && !path.starts_with(b"///") {
        2
    } else {
        usize::from(path.starts_with(b"/"))
    };
    let mut names: Vec<&[u8]> = Vec::new();
    for name in path.split(|&byte| byte == b'/') {
        if name.is_empty() || name == b"." {
            continue;
        }
        if name != b".." || (slashes == 0 && names.is_empty()) || names.last() == Some(&&b".."[..])
        {
            names.push(name);
        } else {
            names.pop();
        }
    }
    let mut normalized = vec![b'/'; slashes];
    normalized.extend_from_slice(&names.join(&b'/'));
    if normalized.is_empty() {
        normalized.push(b'.');
    }
    normalized
}

/// The root of `path`: `//` when exactly two slashes lead it, `/` for one or three or more, else none.
pub(crate) fn root(path: &str) -> &'static str {
    if path.starts_with("//") && !path.starts_with("///") {
        "//"
    } else if path.starts_with('/') {
        "/"
    } else {
        ""
    }
}

/// The root of a repository path's text and its other components, with empty and `.` components
/// dropped.
pub(crate) fn parts(path: &str) -> (&str, Vec<&str>) {
    let root = root(path);
    let names = path
        .split('/')
        .filter(|name| !name.is_empty() && *name != ".")
        .collect();
    (root, names)
}

pub(crate) fn assembled(root: &str, names: &[&str]) -> String {
    if names.is_empty() && root.is_empty() {
        ".".to_owned()
    } else {
        format!("{root}{}", names.join("/"))
    }
}

/// The text of `path` with empty and `.` components dropped, `..` kept.
pub(crate) fn pure(path: &str) -> String {
    String::from_utf8(pure_bytes(path.as_bytes()))
        .expect("UTF-8 split at `/` and joined again stays UTF-8")
}

/// `pure_bytes` applies the component rules of [`pure`] to a path's bytes and keeps each remaining
/// component byte for byte.
pub(crate) fn pure_bytes(path: &[u8]) -> Vec<u8> {
    let root: &[u8] = if path.starts_with(b"//") && !path.starts_with(b"///") {
        b"//"
    } else if path.starts_with(b"/") {
        b"/"
    } else {
        b""
    };
    let names: Vec<&[u8]> = path
        .split(|&byte| byte == b'/')
        .filter(|name| !name.is_empty() && *name != b".")
        .collect();
    if names.is_empty() && root.is_empty() {
        return b".".to_vec();
    }
    let mut pure = root.to_vec();
    pure.extend_from_slice(&names.join(&b'/'));
    pure
}

/// `name` joined to `base`; an absolute `name` replaces `base`.
pub(crate) fn joined(base: &str, name: &str) -> String {
    if name.starts_with('/') {
        return pure(name);
    }
    let (root, mut names) = parts(base);
    names.extend(parts(name).1);
    assembled(root, &names)
}

pub(crate) fn parent(path: &str) -> String {
    let (root, mut names) = parts(path);
    names.pop();
    assembled(root, &names)
}

pub(crate) fn name(path: &str) -> &str {
    parts(path).1.last().copied().unwrap_or("")
}

#[cfg(test)]
#[path = "paths_tests.rs"]
pub(crate) mod tests;
