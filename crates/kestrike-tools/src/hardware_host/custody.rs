//! The custody markers of a host, each a JSON file `<directory>/<name>.json` that quarantines the host
//! while the process group it names still holds memory, and the boot identity that dates a marker.

use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::json::{self, Integer, Object, Value};
use crate::paths;
use crate::python::{self, isdigit};
use crate::text::{Text, text};

/// Where the kernel gives its boot identity.
pub const BOOT_ID: &str = "/proc/sys/kernel/random/boot_id";

/// Why [`held_custody`] gave no judgment.
#[derive(Debug)]
pub enum CustodyError {
    /// Listing the custody directory failed other than by a refused permission.
    Listing(io::Error),
    /// Listing the process table failed.
    Processes(io::Error),
    /// A process's `stat` record is no UTF-8.
    Undecodable(PathBuf),
    /// An entry name of the process table, or a field of a `stat` record, holds digits that read as no
    /// integer.
    Number(Text),
}

impl fmt::Display for CustodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Listing(error) => write!(f, "the custody directory cannot be listed: {error}"),
            Self::Processes(error) => write!(f, "the process table cannot be listed: {error}"),
            Self::Undecodable(path) => write!(f, "{} is no UTF-8", path.display()),
            Self::Number(text) => write!(f, "{} reads as no integer", text.repr()),
        }
    }
}

impl std::error::Error for CustodyError {}

/// The boot identity at `path`: its text, decoded with each undecodable byte replaced and stripped of
/// Python's whitespace, when that text is a lower-case UUID as the kernel prints it; none for an
/// unreadable file or another shape.
pub fn boot_id(path: &Path) -> Option<Text> {
    let bytes = fs::read(path).ok()?;
    let identity = Text::from(String::from_utf8_lossy(&bytes).into_owned()).strip();
    is_identity(&identity).then_some(identity)
}

/// Whether `text` is eight, four, four, four and twelve lower-case hexadecimal digits joined by `-`.
fn is_identity(text: &Text) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(at, &byte)| match at {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => matches!(byte, b'0'..=b'9' | b'a'..=b'f'),
        })
}

/// The texts of the markers under `directory` that hold the host, with the markers that hold nothing
/// removed. `proc` is the process table and `boot` the path of the boot identity.
///
/// Every entry whose name ends in `.json` is judged, in the order of the names, and the first state
/// that fits decides: a marker that cannot be read, is no JSON, is no object or lacks `pgid` holds; a
/// truthy `durable` holds; with no current boot identity, or a recorded `boot` of another shape, it
/// holds; a marker of another boot is removed; a `pgid` of null holds, as does a `pgid` that is no
/// positive integer and `members` that are no map from a pid's digits to a positive start time; a group
/// that still holds memory holds; every other marker is removed. A removal that fails is passed over.
/// An absent directory, and one whose listing is refused for permission, give none.
///
/// # Errors
///
/// A listing of `directory` that fails otherwise, and the errors of reading the process table.
pub fn held_custody(directory: &Path, proc: &Path, boot: &Path) -> Result<Vec<Text>, CustodyError> {
    let mut held = Vec::new();
    let current = boot_id(boot);
    for (marker, text) in markers(directory)? {
        let record = fs::read(&marker).ok().and_then(|bytes| {
            let text = String::from_utf8(bytes).ok()?;
            match json::parse(&text).ok()? {
                Value::Object(record) if record.get("pgid").is_some() => Some(record),
                _ => None,
            }
        });
        let Some(record) = record else {
            held.push(text!(&text, " (unreadable)"));
            continue;
        };
        let field = |name: &str| {
            record
                .get(name)
                .map_or_else(|| Text::from("None"), python::str_of)
        };
        let place = text!(
            &field("profile"),
            "/",
            &field("role"),
            " (episode ",
            &field("episode"),
            "): ",
            &field("custody")
        );
        let pgid = record.get("pgid").expect("a readable marker holds pgid");
        let recorded_boot = match record.get("boot") {
            Some(Value::String(recorded)) if is_identity(recorded) => Some(recorded),
            _ => None,
        };
        if record.get("durable").is_some_and(python::truthy) {
            held.push(text!(
                &place,
                "; remove ",
                &text,
                " once the hazard is confirmed over"
            ));
        } else if current.is_none() || recorded_boot.is_none() {
            held.push(text!(
                &text,
                " (the boot identity at ",
                boot,
                " or the one the marker records is unreadable, so the marker is judged held)"
            ));
        } else if recorded_boot != current.as_ref() {
            let _ = fs::remove_file(&marker);
        } else if *pgid == Value::Null {
            held.push(text!(
                "an unknown group of ",
                &place,
                "; remove ",
                &text,
                " once its case is contained"
            ));
        } else if !matches!(pgid, Value::Integer(pgid) if *pgid > Integer::from(0u64)) {
            held.push(text!(
                &text,
                " (unreadable process group ",
                python::repr(pgid).as_str(),
                ")"
            ));
        } else if let Some(members) = members(&record) {
            let Value::Integer(pgid) = pgid else {
                unreachable!("the branch above holds a positive integer pgid")
            };
            let members = members
                .into_iter()
                .map(|(pid, started)| {
                    Integer::from_digits(false, pid)
                        .map(|pid| (pid, started.clone()))
                        .ok_or_else(|| CustodyError::Number(Text::from(pid)))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if still_held(proc, pgid, &members)? {
                let mut line = text!("process group ", pgid, " of ", &place);
                if members.is_empty() {
                    line.push_text(&text!(
                        "; ",
                        &text,
                        " records no member, so identify the group before containing it"
                    ));
                }
                held.push(line);
            } else {
                let _ = fs::remove_file(&marker);
            }
        } else {
            held.push(text!(&text, " (unreadable members)"));
        }
    }
    Ok(held)
}

/// Each entry of `directory` whose name ends in `.json`, in the order of the names, with its path and
/// that path's text with empty and `.` components dropped.
fn markers(directory: &Path) -> Result<Vec<(PathBuf, Text)>, CustodyError> {
    if !directory.is_dir() {
        return Ok(Vec::new());
    }
    let refused = |error: &io::Error| error.kind() == io::ErrorKind::PermissionDenied;
    let listing = match fs::read_dir(directory) {
        Ok(listing) => listing,
        Err(error) if refused(&error) => return Ok(Vec::new()),
        Err(error) => return Err(CustodyError::Listing(error)),
    };
    let mut names = Vec::new();
    for entry in listing {
        match entry {
            Ok(entry) => names.push(entry.file_name()),
            Err(error) if refused(&error) => return Ok(Vec::new()),
            Err(error) => return Err(CustodyError::Listing(error)),
        }
    }
    names.retain(|name| name.as_bytes().ends_with(b".json"));
    names.sort_by_cached_key(|name| Text::from_os(name));
    Ok(names
        .into_iter()
        .map(|name| {
            let joined = paths::join(directory.as_os_str().as_bytes(), name.as_bytes());
            let text = Text::from_os(OsStr::from_bytes(&paths::pure_bytes(&joined)));
            (directory.join(name), text)
        })
        .collect())
}

/// The recorded members of a marker, each a pid's digits and its start time, or none when `members` is
/// no object whose keys are ASCII digits without a leading zero and whose values are positive integers.
fn members(record: &Object) -> Option<Vec<(&str, &Integer)>> {
    let Some(Value::Object(members)) = record.get("members") else {
        return None;
    };
    let zero = Integer::from(0u64);
    members
        .iter()
        .map(|(pid, started)| {
            let digits = pid.to_str().filter(|digits| {
                !digits.is_empty()
                    && digits.bytes().all(|byte| byte.is_ascii_digit())
                    && !digits.starts_with('0')
            })?;
            match started {
                Value::Integer(started) if *started > zero => Some((digits, started)),
                _ => None,
            }
        })
        .collect()
}

/// Whether the group `pgid`, whose members at marking time were `recorded`, still holds memory: a
/// recorded member lives, or the group has a live member while the process `pgid` is absent or is the
/// recorded one. Linux keeps a pid number while a task uses it as a pid, a process group or a session,
/// so a group whose leader ended lives on in its descendants; a process `pgid` with another start time
/// reused the number. With no recorded member, any live member holds the group.
fn still_held(
    proc: &Path,
    pgid: &Integer,
    recorded: &[(Integer, Integer)],
) -> Result<bool, CustodyError> {
    for (pid, started) in recorded {
        if let Some(fields) = stat_fields(&proc.join(pid.to_string()).join("stat"))?
            && fields.len() >= 20
            && !ended(&fields[0])
            && number(&fields[19])? == *started
        {
            return Ok(true);
        }
    }
    let current = group_members(proc, pgid)?;
    if current.is_empty() {
        return Ok(false);
    }
    if recorded.is_empty() {
        return Ok(true);
    }
    let leader = lookup(&current, pgid);
    Ok(leader.is_none() || leader == lookup(recorded, pgid))
}

/// Each process of the group `pgid` that is no zombie, with the start time of its `stat` record, field
/// 22, which names one process for the life of the host. A later entry of the same pid takes the place
/// of an earlier one. A process that ends between the listing and its read is no member.
fn group_members(proc: &Path, pgid: &Integer) -> Result<Vec<(Integer, Integer)>, CustodyError> {
    let mut members: Vec<(Integer, Integer)> = Vec::new();
    for entry in fs::read_dir(proc).map_err(CustodyError::Processes)? {
        let name = entry.map_err(CustodyError::Processes)?.file_name();
        let text = Text::from_os(&name);
        if !isdigit(text.code_points()) {
            continue;
        }
        let Some(fields) = stat_fields(&proc.join(&name).join("stat"))? else {
            continue;
        };
        if fields.len() >= 20 && number(&fields[2])? == *pgid && !ended(&fields[0]) {
            let pid = text
                .to_str()
                .and_then(|digits| python::decimal(digits).ok())
                .ok_or_else(|| CustodyError::Number(text.clone()))?;
            let started = number(&fields[19])?;
            match members.iter_mut().find(|(seen, _)| *seen == pid) {
                Some((_, slot)) => *slot = started,
                None => members.push((pid, started)),
            }
        }
    }
    Ok(members)
}

fn lookup<'a>(members: &'a [(Integer, Integer)], pid: &Integer) -> Option<&'a Integer> {
    members
        .iter()
        .find(|(seen, _)| seen == pid)
        .map(|(_, started)| started)
}

/// The fields after the command of a `stat` record, split at Python's whitespace, or none when the
/// record cannot be read.
///
/// # Errors
///
/// A record that is no UTF-8.
fn stat_fields(path: &Path) -> Result<Option<Vec<Text>>, CustodyError> {
    let Ok(bytes) = fs::read(path) else {
        return Ok(None);
    };
    let text = String::from_utf8(bytes).map_err(|_| CustodyError::Undecodable(path.to_owned()))?;
    Ok(Some(Text::from(text).rpartition(b')').1.split()))
}

/// Whether a state field is a substring of `ZX`: a zombie or a dead task, which holds no memory.
fn ended(state: &Text) -> bool {
    state.to_str().is_some_and(|state| "ZX".contains(state))
}

fn number(field: &Text) -> Result<Integer, CustodyError> {
    python::int(&Value::String(field.clone())).map_err(|_| CustodyError::Number(field.clone()))
}

#[cfg(test)]
#[path = "custody_tests.rs"]
mod tests;
