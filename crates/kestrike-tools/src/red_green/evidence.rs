//! A leg's evidence: the `artifact.json` the runner announced and the attempt outputs beside it.
//!
//! `evidence` reads the artifact at the path returned by `paths::realpath`. The artifact counts only as
//! `artifact.json` in a directory directly under the receipt directory, the parent compared as the bytes
//! of the canonical receipt path, so a resolved path whose root is `//` lies outside a receipt under `/`.
//! That directory's name must match [`runner::leg_directory`], optionally followed by `.` and one or more
//! Unicode decimal digits, with the receipt directory's name as the run. An attempt output counts where
//! `attempt-1.stdout` or `attempt-1.stderr` beside the artifact is a regular file once links are
//! followed; the kind comes from the file opened for the read, so an output that is a link is read at its
//! target. An announcement that holds a NUL names no artifact.

use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use super::runner;
use crate::classes;
use crate::ownership::{PathError, ignored};
use crate::paths;
use crate::text::{Text, text};

/// The attempt output streams. [`Readings::outputs`] holds one slot for each, at its index here, and
/// [`Readings::read`] and a base leg's `expect_streams` list them in this order. The record writes
/// `attempt_sha256` with its keys sorted.
pub const STREAMS: [&str; 2] = ["stdout", "stderr"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Readings {
    /// The resolved path of `artifact.json`.
    pub artifact: PathBuf,
    /// The bytes of `artifact.json`.
    pub data: Vec<u8>,
    /// The bytes of each attempt output at the index of its stream in [`STREAMS`], or `None` for an
    /// output that counts as absent. A present output may hold no bytes.
    pub outputs: [Option<Vec<u8>>; 2],
}

impl Readings {
    /// Whether both attempt outputs were read.
    pub fn complete(&self) -> bool {
        self.outputs.iter().all(Option::is_some)
    }

    /// Each attempt output read, with its stream's name, in the order of [`STREAMS`].
    pub fn read(&self) -> impl Iterator<Item = (&'static str, &[u8])> {
        STREAMS
            .into_iter()
            .zip(&self.outputs)
            .filter_map(|(stream, data)| data.as_deref().map(|data| (stream, data)))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Evidence {
    /// `evidence` returns `Absent` for a missing announcement, an announcement that holds a NUL or a
    /// surrogate that [`Text::to_os`] refuses, and a resolved path outside the leg's accepted
    /// `artifact.json` paths.
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
/// `ENOTDIR`, `EBADF` or `ELOOP`. The first open does not wait, so a FIFO with no writer is passed over.
/// Where it fails with `EWOULDBLOCK` and the status of `path` shows a regular file, as under another
/// process's write lease, a second open waits for the lease to break. Any other failed open is a failed
/// read where the status of `path` shows a regular file or fails with another error.
fn output(path: &Path) -> io::Result<Option<Vec<u8>>> {
    let open = |flags| {
        OpenOptions::new()
            .read(true)
            .custom_flags(flags | libc::O_NOCTTY)
            .open(path)
    };
    let mut file = match open(libc::O_NONBLOCK) {
        Ok(file) => file,
        Err(error) => match fs::metadata(path) {
            Ok(status) if status.is_file() && error.raw_os_error() == Some(libc::EWOULDBLOCK) => {
                open(0)?
            }
            Ok(status) if status.is_file() => return Err(error),
            Ok(_) => return Ok(None),
            Err(status) if ignored(&status) => return Ok(None),
            Err(status) => return Err(status),
        },
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
/// artifact is opened by its resolved name with no check of its kind, so an `artifact.json` that is a
/// FIFO makes the call wait until a writer opens it and closes it. The returned readings hold the whole
/// artifact and each present attempt output in memory together.
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
    let (directory, file) = paths::split(artifact.as_os_str().as_bytes());
    let (parent, name) = paths::split(&directory);
    if file != b"artifact.json"
        || parent != receipt.as_os_str().as_bytes()
        || !own(receipt, attempt, leg, OsStr::from_bytes(&name))
    {
        return Ok(Evidence::Absent);
    }
    let mut data = Vec::new();
    if let Err(error) = File::open(&artifact).and_then(|mut file| file.read_to_end(&mut data)) {
        return Ok(unreadable(&artifact, error));
    }
    let mut outputs = [None, None];
    for (stream, slot) in STREAMS.into_iter().zip(&mut outputs) {
        let path = artifact.with_file_name(format!("attempt-1.{stream}"));
        match output(&path) {
            Ok(bytes) => *slot = bytes,
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
pub(crate) mod tests;
