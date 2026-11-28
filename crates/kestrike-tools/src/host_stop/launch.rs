//! The one `aws` child of a call, cut at a deadline on the monotonic clock.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::record::{Interrupted, Record, SLICE, left};
use crate::environ;
use crate::python::returncode;
use crate::text::{newlines, strip_str};

/// The program a call starts, found on the given `PATH`.
pub const AWS: &str = "aws";

/// The characters of a failed child's standard error that its failed call keeps.
const TAIL: usize = 400;

/// The wait's first pause between two reads of the child.
const FIRST_PAUSE: Duration = Duration::from_millis(1);

/// `argv` follows `aws` on the command line; `retry` controls whether the AWS CLI applies its own
/// retries.
#[derive(Clone, Copy)]
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

/// Runs the call's `aws` child and returns its standard output, read as UTF-8 with `\r\n` and `\r`
/// as `\n`. The child can start only after both record reads around `find` succeed, and `finish`
/// reads the record once more whatever `run` returned.
///
/// # Errors
///
/// [`Ended::Interrupted`] for a signal the record raised; [`Ended::Failed`] for no `aws` on the
/// `PATH`, a start, a reader thread, a wait or a read that fails, output other than UTF-8, the cut,
/// or an exit other than 0.
pub fn launch(record: &mut Record<'_>, call: &Call<'_>) -> Result<String, Ended> {
    let ended = run(record, call, find);
    finish(record, ended)
}

/// If the final `record.read()` returns an error, `Ended::Interrupted` takes precedence over `ended`.
fn finish(record: &mut Record<'_>, ended: Result<String, Ended>) -> Result<String, Ended> {
    record.read().map_err(Ended::Interrupted)?;
    ended
}

fn run(
    record: &mut Record<'_>,
    call: &Call<'_>,
    find: impl FnOnce(&[(OsString, OsString)]) -> Option<PathBuf>,
) -> Result<String, Ended> {
    let no_answer =
        |reason: &dyn fmt::Display| Ended::Failed(CallFailed::no_answer(call.argv, reason));
    record.read().map_err(Ended::Interrupted)?;
    environ::check(call.env).map_err(|error| no_answer(&error))?;
    let command = find(call.env).map(|program| command(program, call));
    record.read().map_err(Ended::Interrupted)?;
    let Some(mut command) = command else {
        return Err(no_answer(&"no directory of PATH holds an executable aws"));
    };
    let mut child = command.spawn().map_err(|error| no_answer(&error))?;
    let started = Instant::now();
    let abandoned = Arc::new(AtomicBool::new(false));
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        let stopped = stop(&mut child, &abandoned);
        return Err(no_answer(&unstopped(
            "a pipe of the child is missing",
            stopped,
        )));
    };
    let readers = read_all(stdout, Arc::clone(&abandoned))
        .and_then(|out| Ok((out, read_all(stderr, Arc::clone(&abandoned))?)));
    let (out, err) = match readers {
        Ok(readers) => readers,
        Err(error) => {
            let stopped = stop(&mut child, &abandoned);
            return Err(no_answer(&unstopped(error, stopped)));
        }
    };
    let status = wait(
        record,
        &mut child,
        &abandoned,
        [&out, &err],
        started,
        call.cut,
    )
    .map_err(|end| match end {
        Waited::Raised(raised) => Ended::Interrupted(raised),
        Waited::Cut(stopped) => no_answer(&unstopped(
            format_args!("timed out after {:?}", call.cut),
            stopped,
        )),
        Waited::Failed(error) => no_answer(&error),
    })?;
    let stdout = joined(out).map_err(|error| no_answer(&error))?;
    let stderr = joined(err).map_err(|error| no_answer(&error))?;
    let code = returncode(status);
    if code != 0 {
        return Err(Ended::Failed(CallFailed::exited(call.argv, code, &stderr)));
    }
    Ok(stdout)
}

fn unstopped(reason: impl fmt::Display, stopped: io::Result<()>) -> String {
    match stopped {
        Ok(()) => reason.to_string(),
        Err(error) => format!("{reason}, and the child was not stopped: {error}"),
    }
}

/// `program` selects the executable; the child receives `aws` as `argv[0]`. `command` uses the first
/// value for each name in `call.env`.
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
        .env_clear();
    environ::give(&mut command, call.env);
    command
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
    Cut(io::Result<()>),
    Failed(io::Error),
}

/// A `record.read()` error takes precedence over success even after the child exits and both readers
/// finish.
fn wait(
    record: &mut Record<'_>,
    child: &mut Child,
    abandoned: &AtomicBool,
    readers: [&Reader; 2],
    started: Instant,
    cut: Duration,
) -> Result<ExitStatus, Waited> {
    let end = started.checked_add(cut);
    let mut pause = FIRST_PAUSE;
    loop {
        let status = match child.try_wait() {
            Ok(status) => status,
            Err(error) => {
                abandoned.store(true, Ordering::SeqCst);
                return Err(Waited::Failed(error));
            }
        };
        if let Err(raised) = record.read() {
            let _ = stop(child, abandoned);
            return Err(Waited::Raised(raised));
        }
        let left = left(end);
        if left.is_zero() {
            return Err(Waited::Cut(stop(child, abandoned)));
        }
        if let Some(status) = status
            && readers.iter().all(|reader| reader.is_finished())
        {
            return Ok(status);
        }
        thread::sleep(left.min(pause));
        pause = pause.saturating_mul(2).min(SLICE);
    }
}

/// `stop` attempts to send SIGKILL to an unreaped child. Readers discard output once they observe
/// `abandoned`. `child.wait()` can block indefinitely.
fn stop(child: &mut Child, abandoned: &AtomicBool) -> io::Result<()> {
    let killed = child.kill();
    abandoned.store(true, Ordering::SeqCst);
    let reaped = child.wait();
    killed.and(reaped.map(drop))
}

/// A thread that reads `stream` to its end; once `abandoned` holds, the thread returns at its next
/// read and drops the bytes.
fn read_all(
    mut stream: impl Read + Send + 'static,
    abandoned: Arc<AtomicBool>,
) -> io::Result<Reader> {
    thread::Builder::new().spawn(move || {
        let mut bytes = Vec::new();
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
    Ok(newlines(text))
}

fn find(env: &[(OsString, OsString)]) -> Option<PathBuf> {
    let (_, path) = env.iter().find(|(name, _)| name == "PATH")?;
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

fn whole_seconds(cut: Duration) -> u128 {
    (u128::from(cut.as_secs()) + u128::from(cut.subsec_nanos() > 0)).max(1)
}

#[cfg(test)]
#[path = "launch_tests.rs"]
mod tests;
