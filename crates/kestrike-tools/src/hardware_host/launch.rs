//! A launch's identity: the checkout's revision and the facts of the mappings file a case binds.

use std::ffi::OsStr;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::environ::{self, Environ};
use crate::json::{Object, Value};
use crate::paths;
use crate::python::{self, hexdigest};
use crate::text::{Text, newlines, strip_str};

/// Why [`git_revision`] gave no revision.
#[derive(Debug)]
pub enum RevisionError {
    /// `git` could not be started or waited on.
    Start(io::Error),
    /// `git` exited with `code`, the signal's number negated for a signal, and `stderr`, stripped.
    Exited { code: i32, stderr: String },
    /// A stream of `git` is no UTF-8.
    Undecodable,
}

impl fmt::Display for RevisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start(error) => write!(f, "git rev-parse HEAD cannot start: {error}"),
            Self::Exited { code, stderr } => {
                write!(f, "git rev-parse HEAD exited {code}: {stderr}")
            }
            Self::Undecodable => f.write_str("git rev-parse HEAD wrote output that is no UTF-8"),
        }
    }
}

impl std::error::Error for RevisionError {}

/// The revision of the checkout at `top`: `git -C <top>/scripts rev-parse HEAD` started with exactly
/// the variables of `environ`, the program found on the `PATH` it holds, standard input inherited, both
/// streams captured and the exit awaited with no limit. Each stream reads `\r\n` and `\r` as `\n`, and
/// the revision is the standard output stripped of Python's whitespace.
///
/// # Errors
///
/// A start or a wait that fails, an exit other than 0, and a stream that is no UTF-8.
pub fn git_revision(top: &Path, environ: &Environ) -> Result<String, RevisionError> {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(top.join("scripts"))
        .args(["rev-parse", "HEAD"])
        .env_clear()
        .stdin(Stdio::inherit());
    environ::give(&mut command, environ);
    let done = command.output().map_err(RevisionError::Start)?;
    let decoded = |bytes: Vec<u8>| {
        String::from_utf8(bytes)
            .map(newlines)
            .map_err(|_| RevisionError::Undecodable)
    };
    let (stdout, stderr) = (decoded(done.stdout)?, decoded(done.stderr)?);
    let code = python::returncode(done.status);
    if code != 0 {
        return Err(RevisionError::Exited {
            code,
            stderr: strip_str(&stderr).to_owned(),
        });
    }
    Ok(strip_str(&stdout).to_owned())
}

/// The facts of the mappings file at `path` from one read of its bytes: `path`, the `sha256` of the
/// bytes, the `format` after the first line that starts with `format=`, the sorted `functions` of the
/// lines keyed `nvme.bdf` or `eni.bdf`, and the first `volume` keyed `nvme.volume` and `address` keyed
/// `eni.ipv4`, each null when no line names it. The bytes decode with each undecodable sequence
/// replaced and split at Python's line boundaries, and a line's key is the text before its first `=`.
///
/// The file opens once, by the path in the form of [`paths::pure_bytes`], without blocking and without
/// taking a terminal as the controlling one, and the checks and the read go through that descriptor. An
/// empty path, a path that does not open for any reason, one that is no regular file once links are
/// followed, and a failed read give none, so a FIFO at the path gives none without waiting for a
/// writer. The recorded `path` is the caller's spelling, each byte outside UTF-8 held as the surrogate
/// U+DC00 plus the byte, the text Python reads under a UTF-8 filesystem encoding.
pub fn mappings_facts(path: &OsStr) -> Option<Object> {
    if path.is_empty() {
        return None;
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(OsStr::from_bytes(&paths::pure_bytes(path.as_bytes())))
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut data = Vec::new();
    file.read_to_end(&mut data).ok()?;
    let lines = Text::from(String::from_utf8_lossy(&data).into_owned()).splitlines();
    let lines: Vec<&str> = lines
        .iter()
        .map(|line| line.to_str().expect("a lossy decoding holds no surrogate"))
        .collect();
    let version = lines
        .iter()
        .find_map(|line| line.strip_prefix("format="))
        .map(Text::from);
    let pairs: Vec<(&str, &str)> = lines
        .iter()
        .map(|line| line.split_once('=').unwrap_or((line, "")))
        .collect();
    let mut functions: Vec<Text> = pairs
        .iter()
        .filter(|(key, _)| ["nvme.bdf", "eni.bdf"].contains(key))
        .map(|(_, value)| Text::from(*value))
        .collect();
    functions.sort();
    let first = |name: &str| {
        pairs
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| Text::from(*value))
    };
    let or_null = |value: Option<Text>| value.map_or(Value::Null, Value::String);
    let mut facts = Object::new();
    facts.insert("path", Value::String(Text::from_os(path)));
    facts.insert("sha256", Value::String(Text::from(hexdigest(&data))));
    facts.insert("format", or_null(version));
    facts.insert(
        "functions",
        Value::Array(functions.into_iter().map(Value::String).collect()),
    );
    facts.insert("volume", or_null(first("nvme.volume")));
    facts.insert("address", or_null(first("eni.ipv4")));
    Some(facts)
}

#[cfg(test)]
#[path = "launch_tests.rs"]
mod tests;
