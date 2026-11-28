//! The custody markers of a host, each a JSON file `<directory>/<name>.json` that quarantines the host
//! while the process group it names still holds memory, and the boot identity that dates a marker.

use std::ffi::{OsStr, OsString};
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
    /// A member key of a marker holds more digits than an integer holds, or an entry name of the process
    /// table or a field of a `stat` record holds digits that read as no integer.
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

/// The boot identity at `path`, opened in the form of [`paths::pure_bytes`]: its text, decoded with each
/// undecodable byte replaced and stripped of Python's whitespace, when that text is a lower-case UUID as
/// the kernel prints it; none for an unreadable file or another shape.
pub fn boot_id(path: &Path) -> Option<Text> {
    let bytes = fs::read(pure(path)).ok()?;
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
/// A `directory` that is no directory or whose status cannot be read, and one whose listing is refused
/// for permission, give none.
///
/// The judgment admits work only under the host reservation: a caller takes [`reserve_host`] before
/// this read and holds it, itself or through a child, while the cases it admits run, and reads an empty
/// result as a free host only once it has checked that the directory can be listed and written.
/// Removal is by name, so a marker written under the same name between its read and its removal is
/// removed on the earlier marker's judgment; the judgment holds while every writer of markers on the
/// host holds the reservation.
///
/// [`reserve_host`]: super::reserve_host
///
/// # Errors
///
/// A listing of `directory` that fails otherwise, a member key of more digits than an integer holds,
/// and the errors of reading the process table.
pub fn held_custody(directory: &Path, proc: &Path, boot: &Path) -> Result<Vec<Text>, CustodyError> {
    let mut held = Vec::new();
    let current = boot_id(boot);
    for (marker, text) in markers(directory)? {
        match judged(&marker, &text, current.as_ref(), proc, boot)? {
            Some(holding) => held.push(holding),
            None => {
                let _ = fs::remove_file(&marker);
            }
        }
    }
    Ok(held)
}

/// The text by which one marker holds the host, or none for a marker of another boot or of a group that
/// holds no memory, which is removed.
fn judged(
    marker: &Path,
    text: &Text,
    current: Option<&Text>,
    proc: &Path,
    boot: &Path,
) -> Result<Option<Text>, CustodyError> {
    let read = fs::read(marker).ok().and_then(|bytes| {
        let text = String::from_utf8(bytes).ok()?;
        let Value::Object(record) = json::parse(&text).ok()? else {
            return None;
        };
        let pgid = record.get("pgid")?.clone();
        Some((record, pgid))
    });
    let Some((record, pgid)) = read else {
        return Ok(Some(text!(text, " (unreadable)")));
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
    if record.get("durable").is_some_and(python::truthy) {
        return Ok(Some(text!(
            &place,
            "; remove ",
            text,
            " once the hazard is confirmed over"
        )));
    }
    let recorded_boot = match record.get("boot") {
        Some(Value::String(recorded)) if is_identity(recorded) => Some(recorded),
        _ => None,
    };
    let (Some(current), Some(recorded_boot)) = (current, recorded_boot) else {
        return Ok(Some(text!(
            text,
            " (the boot identity at ",
            boot,
            " or the one the marker records is unreadable, so the marker is judged held)"
        )));
    };
    if recorded_boot != current {
        return Ok(None);
    }
    let pgid = match pgid {
        Value::Null => {
            return Ok(Some(text!(
                "an unknown group of ",
                &place,
                "; remove ",
                text,
                " once its case is contained"
            )));
        }
        Value::Integer(pgid) if pgid > Integer::from(0u64) => pgid,
        other => {
            return Ok(Some(text!(
                text,
                " (unreadable process group ",
                python::repr(&other).as_str(),
                ")"
            )));
        }
    };
    let Some(members) = members(&record)? else {
        return Ok(Some(text!(text, " (unreadable members)")));
    };
    if !still_held(proc, &pgid, &members)? {
        return Ok(None);
    }
    let mut line = text!("process group ", &pgid, " of ", &place);
    if members.is_empty() {
        line.push_text(&text!(
            "; ",
            text,
            " records no member, so identify the group before containing it"
        ));
    }
    Ok(Some(line))
}

/// `path` in the form of [`paths::pure_bytes`], the spelling by which an entry is opened.
fn pure(path: &Path) -> PathBuf {
    PathBuf::from(OsStr::from_bytes(&paths::pure_bytes(
        path.as_os_str().as_bytes(),
    )))
}

/// Each entry of `directory` whose name ends in `.json`, in the order of the names, with its path in
/// the form of [`paths::pure_bytes`] and that path's text.
fn markers(directory: &Path) -> Result<Vec<(PathBuf, Text)>, CustodyError> {
    if !directory.is_dir() {
        return Ok(Vec::new());
    }
    let listed: io::Result<Vec<OsString>> = fs::read_dir(pure(directory)).and_then(|listing| {
        listing
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect()
    });
    let mut names = match listed {
        Ok(names) => names,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return Ok(Vec::new()),
        Err(error) => return Err(CustodyError::Listing(error)),
    };
    names.retain(|name| name.as_bytes().ends_with(b".json"));
    names.sort_by_cached_key(|name| Text::from_os(name));
    Ok(names
        .into_iter()
        .map(|name| {
            let joined = paths::join(directory.as_os_str().as_bytes(), name.as_bytes());
            let path = PathBuf::from(OsStr::from_bytes(&paths::pure_bytes(&joined)));
            let text = Text::from_os(path.as_os_str());
            (path, text)
        })
        .collect())
}

/// The recorded members of a marker, each a pid and its start time, or none when `members` is no object
/// whose keys are ASCII digits without a leading zero and whose values are positive integers. Every key
/// is checked before the first is read as a number.
///
/// # Errors
///
/// A key of more digits than an integer holds.
fn members(record: &Object) -> Result<Option<Vec<(Integer, Integer)>>, CustodyError> {
    let Some(Value::Object(members)) = record.get("members") else {
        return Ok(None);
    };
    let zero = Integer::from(0u64);
    let checked: Option<Vec<(&str, &Integer)>> = members
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
        .collect();
    let Some(checked) = checked else {
        return Ok(None);
    };
    checked
        .into_iter()
        .map(|(pid, started)| {
            Integer::from_digits(false, pid)
                .map(|pid| (pid, started.clone()))
                .ok_or_else(|| CustodyError::Number(Text::from(pid)))
        })
        .collect::<Result<_, _>>()
        .map(Some)
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
    let Some(leader) = group_members(proc, pgid)? else {
        return Ok(false);
    };
    if recorded.is_empty() {
        return Ok(true);
    }
    let recorded_leader = recorded
        .iter()
        .find(|(pid, _)| pid == pgid)
        .map(|(_, started)| started);
    Ok(leader.is_none() || leader.as_ref() == recorded_leader)
}

/// The digits that Unicode assigned after 13.0, the version of Python 3.9's `str.isdigit()`, which the
/// crate's Unicode 16.0 tables hold among their digits.
const LATER_DIGITS: [(u32, u32); 10] = [
    (0x10d40, 0x10d49),
    (0x116d0, 0x116e3),
    (0x11bf0, 0x11bf9),
    (0x11f50, 0x11f59),
    (0x16130, 0x16139),
    (0x16ac0, 0x16ac9),
    (0x16d70, 0x16d79),
    (0x1ccf0, 0x1ccf9),
    (0x1e4f0, 0x1e4f9),
    (0x1e5f1, 0x1e5fa),
];

/// Whether an entry name of the process table is one or more digits of Unicode 13.0.
fn is_pid_name(name: &Text) -> bool {
    isdigit(name.code_points())
        && name.code_points().all(|code| {
            !LATER_DIGITS
                .iter()
                .any(|&(low, high)| (low..=high).contains(&code))
        })
}

/// Over the processes of the group `pgid` that are no zombie, none when there is none, and else the
/// start time of the process `pgid` among them, field 22 of its `stat` record, which names one process
/// for the life of the host; a later entry of the same pid takes the place of an earlier one. A process
/// that ends between the listing and its read is no member.
fn group_members(proc: &Path, pgid: &Integer) -> Result<Option<Option<Integer>>, CustodyError> {
    let mut live = false;
    let mut leader = None;
    for entry in fs::read_dir(proc).map_err(CustodyError::Processes)? {
        let name = entry.map_err(CustodyError::Processes)?.file_name();
        let text = Text::from_os(&name);
        if !is_pid_name(&text) {
            continue;
        }
        let Some(fields) = stat_fields(&proc.join(&name).join("stat"))? else {
            continue;
        };
        if fields.len() >= 20 && number(&fields[2])? == *pgid && !ended(&fields[0]) {
            let started = number(&fields[19])?;
            let pid = text
                .to_str()
                .and_then(|digits| python::decimal(digits).ok())
                .ok_or_else(|| CustodyError::Number(text.clone()))?;
            live = true;
            if pid == *pgid {
                leader = Some(started);
            }
        }
    }
    Ok(live.then_some(leader))
}

/// The fields after the command of a `stat` record, split at Python's whitespace, or none when the
/// record cannot be read for any reason, an absent process and an error of another kind alike.
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

/// Whether a state field is a substring of `ZX`: a zombie or a dead task, read as holding no memory. The
/// leader of a thread group whose other threads still run reads `Z` too, and counts as ended.
fn ended(state: &Text) -> bool {
    state.to_str().is_some_and(|state| "ZX".contains(state))
}

fn number(field: &Text) -> Result<Integer, CustodyError> {
    python::int(&Value::String(field.clone())).map_err(|_| CustodyError::Number(field.clone()))
}

#[cfg(test)]
#[path = "custody_tests.rs"]
mod tests;
