//! A leg's evidence: the `artifact.json` the runner announced and the attempt outputs beside it.
//!
//! `evidence` reads the artifact at the path returned by `paths::realpath`. The artifact counts only as
//! `artifact.json` in a directory directly under the receipt directory. That directory's name must match
//! [`runner::leg_directory`], optionally followed by `.` and one or more Unicode decimal digits, with the
//! receipt directory's name as the run. An attempt output counts where `attempt-1.stdout` or
//! `attempt-1.stderr` beside the artifact is a regular file once links are followed; the kind comes from
//! the file opened for the read.

use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use regex::bytes::Regex;

use super::STREAMS;
use super::runner;
use crate::classes;
use crate::ownership::PathError;
use crate::paths;
use crate::text::{Text, text};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Readings {
    pub artifact: PathBuf,
    pub data: Vec<u8>,
    pub outputs: Vec<(&'static str, Vec<u8>)>,
}

impl Readings {
    pub fn complete(&self) -> bool {
        self.outputs.len() == STREAMS.len()
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

fn literal(text: &[u8]) -> String {
    text.iter().map(|byte| format!(r"\x{byte:02x}")).collect()
}

fn own(receipt: &Path, attempt: &Text, leg: &str) -> Regex {
    let run = Text::from_os(receipt.file_name().unwrap_or_default());
    let name = runner::leg_directory(&run, attempt, leg);
    let name = name.to_os().unwrap_or_default();
    classes::compiled_bytes(&format!(
        r"(?-u)^{}(?:\.(?u:\d)+)?$",
        literal(name.as_bytes())
    ))
}

fn unreadable(path: &Path, error: io::Error) -> Evidence {
    Evidence::Unreadable(text!(PathError::new(path, error).to_string()))
}

enum Output {
    Absent,
    Read(Vec<u8>),
}

/// A failed open is a failed read only where the status of `path` shows a regular file or fails with an
/// error other than `ENOENT`, `ENOTDIR`, `EBADF` and `ELOOP`.
fn output(path: &Path) -> io::Result<Output> {
    let flags = libc::O_NONBLOCK | libc::O_NOCTTY;
    let mut file = match OpenOptions::new().read(true).custom_flags(flags).open(path) {
        Ok(file) => file,
        Err(error) => {
            return match fs::metadata(path) {
                Ok(status) if status.is_file() => Err(error),
                Ok(_) => Ok(Output::Absent),
                Err(status) if ignored(&status) => Ok(Output::Absent),
                Err(status) => Err(status),
            };
        }
    };
    if !file.metadata()?.is_file() {
        return Ok(Output::Absent);
    }
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(Output::Read(data))
}

fn ignored(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ENOENT | libc::ENOTDIR | libc::EBADF | libc::ELOOP)
    )
}

/// # Errors
///
/// `evidence` propagates errors from `paths::realpath`.
pub fn evidence(
    receipt: &Path,
    attempt: &Text,
    leg: &str,
    announced: Option<&Text>,
) -> io::Result<Evidence> {
    let Some(announced) = announced else {
        return Ok(Evidence::Absent);
    };
    let announced = announced.to_os().unwrap_or_default();
    let artifact = paths::realpath(Path::new(&announced))?;
    let directory = artifact.parent().unwrap_or(Path::new("/"));
    let name = directory.file_name().unwrap_or_default();
    if artifact.file_name() != Some(OsStr::new("artifact.json"))
        || directory.parent().unwrap_or(Path::new("/")) != receipt
        || !own(receipt, attempt, leg).is_match(name.as_bytes())
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
            Ok(Output::Read(bytes)) => outputs.push((stream, bytes)),
            Ok(Output::Absent) => {}
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
