//! A leg's evidence: the `artifact.json` the runner announced and the attempt outputs beside it.
//!
//! `evidence` reads the artifact at the path returned by `paths::realpath`. The artifact counts only as
//! `artifact.json` in a directory directly under the receipt directory. That directory's name must match
//! [`runner::leg_directory`], optionally followed by `.` and one or more Unicode decimal digits, with the
//! receipt directory's name as the run. An attempt output counts where `attempt-1.stdout` or
//! `attempt-1.stderr` beside the artifact is a regular file once links are followed; the kind comes from
//! the file opened for the read, so an output that is a link is read at its target. An announcement that
//! holds a NUL names no artifact.

use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use super::runner;
use crate::classes;
use crate::ownership::{PathError, ignored};
use crate::paths;
use crate::text::{Text, text};

/// The attempt output streams, in the order a leg's readings and its record list them.
pub const STREAMS: [&str; 2] = ["stdout", "stderr"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Readings {
    pub artifact: PathBuf,
    pub data: Vec<u8>,
    pub outputs: Vec<(&'static str, Vec<u8>)>,
}

impl Readings {
    /// Whether `outputs` holds one reading of each of [`STREAMS`] and nothing else, in any order.
    pub fn complete(&self) -> bool {
        let read = |stream: &str| self.outputs.iter().any(|(name, _)| *name == stream);
        self.outputs.len() == STREAMS.len() && STREAMS.into_iter().all(read)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Evidence {
    /// `evidence` returns `Absent` for a missing announcement or a resolved path outside the leg's
    /// accepted `artifact.json` paths.
    Absent,
    /// A read of the artifact or an attempt output failed, with the error's text.
    Unreadable(Text),
    Read(Readings),
}

impl Evidence {
    pub fn readings(&self) -> Option<&Readings> {
        match self {
            Self::Read(readings) => Some(readings),
            Self::Absent | Self::Unreadable(_) => None,
        }
    }
}

fn own(receipt: &Path, attempt: &Text, leg: &str, name: &OsStr) -> bool {
    let run = Text::from_os(receipt.file_name().unwrap_or_default());
    let prefix = runner::leg_directory(&run, attempt, leg);
    let name = Text::from_os(name);
    let Some(rest) = name.as_bytes().strip_prefix(prefix.as_bytes()) else {
        return false;
    };
    let suffix = rest
        .strip_prefix(b".")
        .and_then(|digits| std::str::from_utf8(digits).ok());
    rest.is_empty()
        || suffix.is_some_and(|digits| !digits.is_empty() && digits.chars().all(classes::is_digit))
}

fn unreadable(path: &Path, error: io::Error) -> Evidence {
    Evidence::Unreadable(text!(PathError::new(path, error).to_string()))
}

/// `None` means `path` names no regular file once links are followed, or its status fails with `ENOENT`,
/// `ENOTDIR`, `EBADF` or `ELOOP`. A failed open is a failed read only where the status of `path` shows a
/// regular file or fails with another error.
fn output(path: &Path) -> io::Result<Option<Vec<u8>>> {
    let flags = libc::O_NONBLOCK | libc::O_NOCTTY;
    let mut file = match OpenOptions::new().read(true).custom_flags(flags).open(path) {
        Ok(file) => file,
        Err(error) => {
            return match fs::metadata(path) {
                Ok(status) if status.is_file() => Err(error),
                Ok(_) => Ok(None),
                Err(status) if ignored(&status) => Ok(None),
                Err(status) => Err(status),
            };
        }
    };
    if !file.metadata()?.is_file() {
        return Ok(None);
    }
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(Some(data))
}

/// The caller must pass the canonical path to the run's receipt directory as `receipt`, and trusts that
/// directory and its entries. `attempt` is the workflow run attempt of [`runner::leg_directory`]. The
/// returned readings hold the whole artifact and each present attempt output in memory together.
///
/// # Errors
///
/// `evidence` propagates the errors of [`paths::realpath`]. A failed read of the artifact or of an
/// attempt output is `Ok(Evidence::Unreadable)`.
pub fn evidence(
    receipt: &Path,
    attempt: &Text,
    leg: &str,
    announced: Option<&Text>,
) -> io::Result<Evidence> {
    let named = announced.filter(|path| !path.as_bytes().contains(&0));
    let Some(announced) = named.and_then(Text::to_os) else {
        return Ok(Evidence::Absent);
    };
    let artifact = paths::realpath(Path::new(&announced))?;
    let directory = artifact.parent().unwrap_or(Path::new("/"));
    let name = directory.file_name().unwrap_or_default();
    if artifact.file_name() != Some(OsStr::new("artifact.json"))
        || directory.parent().unwrap_or(Path::new("/")) != receipt
        || !own(receipt, attempt, leg, name)
    {
        return Ok(Evidence::Absent);
    }
    let mut data = Vec::new();
    if let Err(error) = File::open(&artifact).and_then(|mut file| file.read_to_end(&mut data)) {
        return Ok(unreadable(&artifact, error));
    }
    let mut outputs = Vec::new();
    for stream in STREAMS {
        let path = artifact.with_file_name(format!("attempt-1.{stream}"));
        match output(&path) {
            Ok(Some(bytes)) => outputs.push((stream, bytes)),
            Ok(None) => {}
            Err(error) => return Ok(unreadable(&path, error)),
        }
    }
    Ok(Evidence::Read(Readings {
        artifact,
        data,
        outputs,
    }))
}

#[cfg(test)]
#[path = "evidence_tests.rs"]
mod tests;
