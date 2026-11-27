//! The Git call of the plant run: `git` with five fixed options and `-C DIR`, in an environment given as a
//! value, with both streams captured and the exit code returned.
//!
//! The options turn off hooks (`core.hooksPath=/dev/null`) and optional locks, so a read such as `status`
//! leaves the index as it was; fix the commit encoding to UTF-8, so a commit carries no `encoding` header;
//! and make `git apply` take a patch's whitespace as it stands. A call without input reads the caller's
//! standard input and returns text: strict UTF-8 with `\r\n` and `\r` read as `\n`. A call with input
//! bytes writes them to Git's standard input and returns bytes.
//!
//! Git is found through the `PATH` of the given environment, resolved from this process's working
//! directory. The child is given the first variable of each name, the one [`crate::environ::get`] reads,
//! and a name holding `=` after its first byte stops the call before Git starts. Git inherits every
//! descriptor of this process that is open without close-on-exec, beside the three streams.

use std::ffi::OsStr;
use std::fmt;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};

use crate::environ::Environ;
use crate::git::fed;
use crate::text::Text;

/// The options every call passes before `-C DIR`.
pub const FIXED: [&str; 9] = [
    "--no-optional-locks",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "i18n.commitEncoding=UTF-8",
    "-c",
    "apply.whitespace=nowarn",
    "-c",
    "apply.ignoreWhitespace=no",
];

/// One finished call: its subcommand, the first argument after `-C DIR` or the empty text, its exit code,
/// the negated signal number for a call a signal ended, and both streams.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use = "a call that exited nonzero still returns its Done"]
pub struct Done<T> {
    pub step: Text,
    pub code: i32,
    pub stdout: T,
    pub stderr: T,
}

/// Why a call returned no [`Done`], or why a checked one failed.
#[derive(Debug)]
pub enum CallError {
    /// Git could not be started, or the environment names a variable whose name holds `=` after its
    /// first byte (an error of kind [`io::ErrorKind::InvalidInput`]).
    Start(io::Error),
    /// Git started, and writing its input or waiting for it failed.
    Io { step: Text, error: io::Error },
    /// A text call whose standard output or error is no UTF-8.
    NotUtf8 { step: Text },
    /// A checked call that exited with a code other than 0; `stderr` is its error output.
    Failed { step: Text, code: i32, stderr: Text },
}

impl fmt::Display for CallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start(error) => write!(f, "git cannot be started: {error}"),
            Self::Io { step, error } => write!(f, "`git {step}`: {error}"),
            Self::NotUtf8 { step } => write!(f, "`git {step}` wrote output that is no UTF-8"),
            Self::Failed { step, code, .. } => write!(f, "`git {step}` exited {code}"),
        }
    }
}

/// The `Display` text holds the I/O error's text, so the error reports no `source`.
impl std::error::Error for CallError {}

impl Done<String> {
    /// `checked` returns the call when it exited 0 and [`CallError::Failed`] otherwise.
    ///
    /// # Errors
    ///
    /// The call exited with another code than 0.
    pub fn checked(self) -> Result<Self, CallError> {
        if self.code == 0 {
            return Ok(self);
        }
        Err(CallError::Failed {
            step: self.step,
            code: self.code,
            stderr: Text::from(self.stderr),
        })
    }
}

/// `command` builds `git FIXED -C dir ARGS` with exactly the first variable of each name of `env`.
///
/// # Errors
///
/// A variable's name holds `=` after its first byte, which no environment entry can carry.
fn command(env: &Environ, dir: &Path, args: &[&OsStr]) -> Result<Command, CallError> {
    let mut command = Command::new("git");
    command
        .args(FIXED)
        .arg("-C")
        .arg(dir)
        .args(args)
        .env_clear()
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut given: Vec<&OsStr> = Vec::with_capacity(env.len());
    for (name, value) in env {
        if name.as_bytes().iter().skip(1).any(|&byte| byte == b'=') {
            return Err(CallError::Start(io::Error::new(
                io::ErrorKind::InvalidInput,
                "illegal environment variable name",
            )));
        }
        if !given.contains(&name.as_os_str()) {
            given.push(name);
            command.env(name, value);
        }
    }
    Ok(command)
}

fn step(args: &[&OsStr]) -> Text {
    args.first()
        .map_or_else(Text::new, |first| Text::from_os(first))
}

/// `code` is the exit code, or the negated number of the signal that ended the call.
fn code(status: ExitStatus) -> i32 {
    match (status.code(), status.signal()) {
        (Some(code), _) => code,
        (None, Some(signal)) => -signal,
        (None, None) => unreachable!("a waited child exited or a signal ended it"),
    }
}

/// `newlines` reads `\r\n` and `\r` as `\n`.
fn newlines(text: String) -> String {
    if text.contains('\r') {
        text.replace("\r\n", "\n").replace('\r', "\n")
    } else {
        text
    }
}

/// `text` runs `git FIXED -C dir ARGS` in `env` with the caller's standard input and returns its exit
/// code and both streams as text.
///
/// # Errors
///
/// Git cannot be started or waited for, or a stream is no UTF-8.
pub fn text(env: &Environ, dir: &Path, args: &[&OsStr]) -> Result<Done<String>, CallError> {
    let child = command(env, dir, args)?
        .stdin(Stdio::inherit())
        .spawn()
        .map_err(CallError::Start)?;
    let step = step(args);
    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(error) => return Err(CallError::Io { step, error }),
    };
    let decode = |bytes: Vec<u8>| String::from_utf8(bytes).map(newlines);
    let (Ok(stdout), Ok(stderr)) = (decode(output.stdout), decode(output.stderr)) else {
        return Err(CallError::NotUtf8 { step });
    };
    Ok(Done {
        step,
        code: code(output.status),
        stdout,
        stderr,
    })
}

/// `bytes` runs `git FIXED -C dir ARGS` in `env`, writes `input` to its standard input and returns its
/// exit code and both streams as bytes. Git closing its input before reading all of it ends the write
/// without an error.
///
/// # Errors
///
/// Git cannot be started or waited for, or the write fails otherwise.
pub fn bytes(
    env: &Environ,
    dir: &Path,
    args: &[&OsStr],
    input: &[u8],
) -> Result<Done<Vec<u8>>, CallError> {
    let child = command(env, dir, args)?
        .stdin(Stdio::piped())
        .spawn()
        .map_err(CallError::Start)?;
    let step = step(args);
    let output = match fed(child, input) {
        Ok(output) => output,
        Err(error) => return Err(CallError::Io { step, error }),
    };
    Ok(Done {
        step,
        code: code(output.status),
        stdout: output.stdout,
        stderr: output.stderr,
    })
}
