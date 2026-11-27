//! The one `aws` child of a call, cut at a deadline on the monotonic clock.
//!
//! [`launch`] finds `aws` as the first executable regular file named so in a directory of the given
//! `PATH` (an empty entry is the working directory) and starts it with the call's arguments, then
//! `--no-paginate --output json --cli-read-timeout N --cli-connect-timeout N`, N the cut in whole
//! seconds rounded up and at least 1. The child runs under the given environment alone, plus
//! `AWS_PAGER` empty, `AWS_CLI_AUTO_PROMPT=off`, `AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true` and, for a
//! call without retries, `AWS_MAX_ATTEMPTS=1` and `AWS_RETRY_MODE=standard`. Its standard input is
//! `/dev/null`, and it stays in the tool's process group. A thread reads each of its two outputs.
//!
//! The cut counts from the return of the spawn. The wait reads the child, both outputs and the
//! [`Record`] at least once a [`SLICE`], and ends when the child has exited and both outputs have
//! closed. At the cut, or at a read of the record that raises, the child alone gets SIGKILL and is
//! reaped, with no bound on the reap, and the readers stop keeping the bytes they read. The wait
//! reads the record once more after it sees the child's end, and the call reads it again after both
//! outputs are decoded, so a signal that may raise before the call returns raises in place of the
//! answer. After an early end a reader thread ends at its next read
//! or at its pipe's close, so it outlives the call while a process the child left holds the pipe.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::record::{Interrupted, Record, SLICE, left};
use crate::text::strip_str;

/// The program a call starts, found on the given `PATH`.
pub const AWS: &str = "aws";

/// The characters of a failed child's standard error that its failed call keeps.
const TAIL: usize = 400;

/// One call: the arguments after `aws`, whether the CLI's own retries apply, the cut, and the
/// environment the child runs under, a later entry of one name replacing an earlier one.
#[derive(Clone, Copy, Debug)]
pub struct Call<'a> {
    pub argv: &'a [&'a str],
    pub retry: bool,
    pub cut: Duration,
    pub env: &'a [(OsString, OsString)],
}

/// A call whose outcome is unknown. `what` is the call's first two arguments joined by a space; its
/// sentence is `<what> gave no answer: <reason>` or `<what> exited <code>: <tail>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallFailed {
    what: String,
    failure: Failure,
}

/// How a call failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The call gave no answer, for the reason given: no `aws` on the `PATH`, a start, a read or a
    /// wait that failed, output other than UTF-8, or the cut.
    NoAnswer(String),
    /// The child exited other than 0. `code` is negative for a child a signal ended, and `tail` is the
    /// last 400 characters of its standard error, stripped of Python's whitespace.
    Exited { code: i32, tail: String },
}

impl CallFailed {
    /// A call of `argv` that gave no answer for `reason`.
    pub fn no_answer(argv: &[&str], reason: impl fmt::Display) -> Self {
        Self {
            what: what(argv),
            failure: Failure::NoAnswer(reason.to_string()),
        }
    }

    /// A call of `argv` whose child exited with `code` and wrote `stderr`.
    pub fn exited(argv: &[&str], code: i32, stderr: &str) -> Self {
        Self {
            what: what(argv),
            failure: Failure::Exited {
                code,
                tail: tail(strip_str(stderr)).to_owned(),
            },
        }
    }

    pub fn what(&self) -> &str {
        &self.what
    }

    pub fn failure(&self) -> &Failure {
        &self.failure
    }
}

impl fmt::Display for CallFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.failure {
            Failure::NoAnswer(reason) => write!(f, "{} gave no answer: {reason}", self.what),
            Failure::Exited { code, tail } => write!(f, "{} exited {code}: {tail}", self.what),
        }
    }
}

impl std::error::Error for CallFailed {}

/// Why a call returned no output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ended {
    Failed(CallFailed),
    Interrupted(Interrupted),
}

/// The first two arguments of a call, joined by a space.
fn what(argv: &[&str]) -> String {
    argv[..argv.len().min(2)].join(" ")
}

type Reader = JoinHandle<io::Result<Vec<u8>>>;

/// Runs the call's `aws` child as the module states and returns its standard output, read as UTF-8
/// with `\r\n` and `\r` as `\n`. A read of the record that raises before the child would start ends
/// the call with no process started.
///
/// # Errors
///
/// [`Ended::Interrupted`] for a signal the record raised; [`Ended::Failed`] for no `aws` on the
/// `PATH`, a start, a reader thread, a wait or a read that fails, output other than UTF-8, the cut,
/// or an exit other than 0.
pub fn launch(record: &mut Record<'_>, call: &Call<'_>) -> Result<String, Ended> {
    let no_answer =
        |reason: &dyn fmt::Display| Ended::Failed(CallFailed::no_answer(call.argv, reason));
    record.read().map_err(Ended::Interrupted)?;
    let Some(program) = find(call.env) else {
        return Err(no_answer(&"no directory of PATH holds an executable aws"));
    };
    let mut child = command(program, call)
        .spawn()
        .map_err(|error| no_answer(&error))?;
    let started = Instant::now();
    let abandoned = Arc::new(AtomicBool::new(false));
    let readers = read_all(child.stdout.take(), Arc::clone(&abandoned))
        .and_then(|out| Ok((out, read_all(child.stderr.take(), Arc::clone(&abandoned))?)));
    let (out, err) = match readers {
        Ok(readers) => readers,
        Err(error) => {
            stop(&mut child, None, &abandoned);
            return Err(no_answer(&error));
        }
    };
    let ended = Ending {
        child: &mut child,
        abandoned: &abandoned,
    };
    let status = wait(record, ended, [&out, &err], started, call.cut).map_err(|end| match end {
        Waited::Raised(raised) => Ended::Interrupted(raised),
        Waited::Cut => no_answer(&format_args!("timed out after {:?}", call.cut)),
        Waited::Failed(error) => no_answer(&error),
    })?;
    let stdout = joined(out).map_err(|error| no_answer(&error))?;
    let stderr = joined(err).map_err(|error| no_answer(&error))?;
    record.read().map_err(Ended::Interrupted)?;
    let code = exit_code(status);
    if code != 0 {
        return Err(Ended::Failed(CallFailed::exited(call.argv, code, &stderr)));
    }
    Ok(stdout)
}

/// The `aws` command of `call`: the program found on the `PATH`, started as `aws`, with the
/// arguments, the environment and the standard streams the module states.
fn command(program: PathBuf, call: &Call<'_>) -> Command {
    let cut = whole_seconds(call.cut).to_string();
    let mut command = Command::new(program);
    command
        .arg0(AWS)
        .args(call.argv)
        .args([
            "--no-paginate",
            "--output",
            "json",
            "--cli-read-timeout",
            &cut,
            "--cli-connect-timeout",
            &cut,
        ])
        .env_clear()
        .envs(call.env.iter().map(|(name, value)| (name, value)))
        .env("AWS_PAGER", "")
        .env("AWS_CLI_AUTO_PROMPT", "off")
        .env("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "true");
    if !call.retry {
        command
            .env("AWS_MAX_ATTEMPTS", "1")
            .env("AWS_RETRY_MODE", "standard");
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// The last [`TAIL`] characters of `text`, counted in Unicode scalar values.
fn tail(text: &str) -> &str {
    let start = text
        .char_indices()
        .rev()
        .nth(TAIL - 1)
        .map_or(0, |(at, _)| at);
    &text[start..]
}

enum Waited {
    Raised(Interrupted),
    Cut,
    Failed(io::Error),
}

/// The child of a call and the flag its readers watch, which every early end of the wait stops
/// together.
struct Ending<'a> {
    child: &'a mut Child,
    abandoned: &'a AtomicBool,
}

fn wait(
    record: &mut Record<'_>,
    ending: Ending<'_>,
    readers: [&Reader; 2],
    started: Instant,
    cut: Duration,
) -> Result<ExitStatus, Waited> {
    let Ending { child, abandoned } = ending;
    let end = started.checked_add(cut);
    let mut status = None;
    loop {
        if status.is_none() {
            match child.try_wait() {
                Ok(exited) => status = exited,
                Err(error) => {
                    stop(child, status, abandoned);
                    return Err(Waited::Failed(error));
                }
            }
        }
        let done = status.is_some() && readers.iter().all(|reader| reader.is_finished());
        if let Err(raised) = record.read() {
            stop(child, status, abandoned);
            return Err(Waited::Raised(raised));
        }
        if let (true, Some(status)) = (done, status) {
            return Ok(status);
        }
        let left = left(end);
        if left.is_zero() {
            stop(child, status, abandoned);
            return Err(Waited::Cut);
        }
        thread::sleep(left.min(SLICE));
    }
}

/// Kills a child that has not been reaped with SIGKILL and reaps it, then makes the readers drop
/// what they read from here on.
fn stop(child: &mut Child, status: Option<ExitStatus>, abandoned: &AtomicBool) {
    if status.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    abandoned.store(true, Ordering::SeqCst);
}

/// A thread that reads `stream` to its end; once `abandoned` holds, the thread returns at its next
/// read and drops the bytes.
fn read_all(
    stream: Option<impl Read + Send + 'static>,
    abandoned: Arc<AtomicBool>,
) -> io::Result<Reader> {
    thread::Builder::new().spawn(move || {
        let mut bytes = Vec::new();
        let Some(mut stream) = stream else {
            return Ok(bytes);
        };
        let mut buffer = [0; 8192];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => return Ok(bytes),
                Ok(read) if !abandoned.load(Ordering::SeqCst) => {
                    bytes.extend_from_slice(&buffer[..read]);
                }
                Ok(_) => return Ok(Vec::new()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    })
}

fn joined(reader: Reader) -> io::Result<String> {
    let bytes = reader
        .join()
        .map_err(|_| io::Error::other("a reader of the child's output panicked"))??;
    let text = String::from_utf8(bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(text.replace("\r\n", "\n").replace('\r', "\n"))
}

fn find(env: &[(OsString, OsString)]) -> Option<PathBuf> {
    let (_, path) = env.iter().rev().find(|(name, _)| name == "PATH")?;
    path.as_bytes()
        .split(|&byte| byte == b':')
        .map(|directory| match directory {
            b"" => PathBuf::from("."),
            directory => PathBuf::from(OsStr::from_bytes(directory)),
        })
        .map(|directory| directory.join(AWS))
        .find(|candidate| {
            fs::metadata(candidate)
                .is_ok_and(|found| found.is_file() && found.permissions().mode() & 0o111 != 0)
        })
}

fn whole_seconds(cut: Duration) -> u64 {
    cut.as_secs()
        .saturating_add(u64::from(cut.subsec_nanos() > 0))
        .max(1)
}

fn exit_code(status: ExitStatus) -> i32 {
    status
        .code()
        .or_else(|| status.signal().map(|signal| -signal))
        .expect("a reaped child has an exit code or a signal")
}

#[cfg(test)]
#[path = "launch_tests.rs"]
mod tests;
