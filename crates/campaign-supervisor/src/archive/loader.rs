//! The program interpreter's library resolution. The interpreter's
//! `--list` mode maps an executable's libraries and prints where it found
//! each one without running the executable. It runs with every `LD_*`
//! variable and `GLIBC_TUNABLES` removed from the environment and with
//! the library path the caller names. Every listing refuses active system
//! preload entries, whose load order a name-to-path map cannot represent.
//! Diagnostics on standard error refuse the listing too.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use super::run::{Failure, Stderr};
use super::{Invalid, LIBRARY_BOUND};

/// The longest a listing may run; one maps a few libraries in
/// milliseconds.
const DEADLINE: Duration = Duration::from_secs(60);

/// The libraries `loader` resolves for `executable`, by name, each with the
/// path the loader found it at. `library_path` is the loader's library
/// search path, `LD_LIBRARY_PATH`; `None` lists under no search path of
/// the caller's.
///
/// # Errors
///
/// [`Invalid::Io`] when the loader cannot run or its listing passes its
/// deadline, [`Invalid::Unreadable`] when `/etc/ld.so.preload` cannot be
/// read, and [`Invalid::Resolution`] for an active system preload, a
/// listing that exits nonzero, writes to standard error or passes its
/// output bound, or one [`libraries`] refuses.
pub(super) fn resolve(
    loader: &str,
    executable: &Path,
    library_path: Option<&OsStr>,
) -> Result<BTreeMap<String, String>, Invalid> {
    resolve_before(loader, executable, library_path, DEADLINE)
}

pub(super) fn resolve_before(
    loader: &str,
    executable: &Path,
    library_path: Option<&OsStr>,
    deadline: Duration,
) -> Result<BTreeMap<String, String>, Invalid> {
    resolve_scoped(loader, executable, library_path, deadline, None)
}

pub(super) fn resolve_publishing(
    loader: &str,
    executable: &Path,
    library_path: Option<&OsStr>,
    context: Option<&super::command::Context>,
) -> Result<BTreeMap<String, String>, Invalid> {
    resolve_scoped(loader, executable, library_path, DEADLINE, context)
}

fn resolve_scoped(
    loader: &str,
    executable: &Path,
    library_path: Option<&OsStr>,
    deadline: Duration,
    context: Option<&super::command::Context>,
) -> Result<BTreeMap<String, String>, Invalid> {
    let preload = crate::store::read_host(Path::new("/etc/ld.so.preload"), 1 << 20)
        .map_err(|why| Invalid::Unreadable("/etc/ld.so.preload".to_owned(), why))?;
    system_preload(preload.as_deref().unwrap_or_default())?;
    let mut command = command(Path::new(loader), library_path, std::env::vars_os());
    command.arg("--list").arg(executable);
    let result = super::run::execute(&mut command, Stderr::Capture, Some(deadline), context);
    let listed = match result {
        Ok(listed) => listed,
        Err(Failure::Deadline) => {
            return Err(Invalid::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the listing exceeded its deadline",
            )));
        }
        Err(Failure::Io(error)) => return Err(Invalid::Io(error)),
        Err(failure) => {
            return Err(Invalid::Resolution(format!(
                "the listing failed: {failure}"
            )));
        }
    };
    if !listed.status.success() || !listed.stderr.is_empty() {
        let why = String::from_utf8_lossy(&listed.stderr);
        return Err(Invalid::Resolution(format!(
            "the listing exited {}: {why}",
            listed.status
        )));
    }
    libraries(&String::from_utf8_lossy(&listed.stdout), loader)
}

/// A command running `program` with the environment `vars` minus every
/// `LD_*` variable and `GLIBC_TUNABLES`, `library_path` as its whole
/// `LD_LIBRARY_PATH` when given, and the null device as its standard
/// input.
pub(super) fn command(
    program: &Path,
    library_path: Option<&OsStr>,
    vars: impl Iterator<Item = (OsString, OsString)>,
) -> Command {
    let mut command = Command::new(program);
    command
        .env_clear()
        .envs(vars.filter(|(name, _)| {
            let name = name.as_encoded_bytes();
            !(name.starts_with(b"LD_") || name == b"GLIBC_TUNABLES")
        }))
        .stdin(Stdio::null());
    if let Some(path) = library_path {
        command.env("LD_LIBRARY_PATH", path);
    }
    command
}

/// Whether a name the listing prints with no path is the vDSO, which maps
/// no file: `linux-vdso.so.1` on 64-bit machines, `linux-gate.so.1` on
/// 32-bit x86.
fn vdso(name: &str) -> bool {
    matches!(name, "linux-vdso.so.1" | "linux-gate.so.1")
}

/// The libraries a `--list` output `listing` resolves by name, each with
/// its path. The vDSO maps no file and `loader`, the interpreter, is
/// pinned by its own digest, so both are left out.
///
/// # Errors
///
/// [`Invalid::Resolution`] for a library the loader maps by its path, as
/// a preload named by path is, finds nowhere, or lists twice, for any other line, and
/// for more than [`LIBRARY_BOUND`] libraries: an archive holds only
/// libraries the loader resolves by name.
pub(super) fn libraries(listing: &str, loader: &str) -> Result<BTreeMap<String, String>, Invalid> {
    let mut found = BTreeMap::new();
    for line in listing.lines() {
        let line = line.trim();
        if line == "statically linked" {
            return Err(Invalid::Resolution(
                "the executable names an interpreter and needs no library".to_owned(),
            ));
        }
        let Some((name, rest)) = line.split_once(" => ") else {
            let mapped = line.rsplit_once(" (").map_or(line, |(mapped, _)| mapped);
            if line.is_empty() || mapped == loader || vdso(mapped) {
                continue;
            }
            let why = if mapped.contains('/') {
                "is mapped by its path"
            } else {
                "is listed at no path"
            };
            return Err(Invalid::Resolution(format!("{mapped} {why}")));
        };
        let path = rest.rsplit_once(" (").map_or(rest, |(path, _)| path).trim();
        if path.is_empty() && vdso(name) {
            continue;
        }
        if !path.starts_with('/') {
            return Err(Invalid::Resolution(format!("{name} is found nowhere")));
        }
        if found.insert(name.to_owned(), path.to_owned()).is_some() {
            return Err(Invalid::Resolution(format!("{name} is listed twice")));
        }
        if found.len() > LIBRARY_BOUND {
            return Err(Invalid::Resolution(format!(
                "more than {LIBRARY_BOUND} libraries"
            )));
        }
    }
    Ok(found)
}

pub(super) fn system_preload(bytes: &[u8]) -> Result<(), Invalid> {
    let active = bytes.split(|&byte| byte == b'\n').any(|line| {
        line.iter()
            .take_while(|&&byte| byte != b'#')
            .any(|byte| !byte.is_ascii_whitespace())
    });
    if active {
        return Err(Invalid::Resolution(
            "the host names a system preload".to_owned(),
        ));
    }
    Ok(())
}
