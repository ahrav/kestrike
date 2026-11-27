//! [`run`] starts one `quint run` with the standard library's `Command` and waits for it under a time limit.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const POLL: Duration = Duration::from_millis(50);

#[derive(Debug)]
pub enum Failure {
    Start(io::Error),
    Wait(io::Error),
    Exit(ExitStatus),
    /// The limit passed and the child was sent SIGKILL. `status` records the status the reap returned,
    /// including a natural exit between the last poll and the signal.
    Limit {
        limit: Duration,
        status: Option<ExitStatus>,
    },
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start(error) => write!(f, "Quint did not start: {error}"),
            Self::Wait(error) => write!(f, "waiting for Quint failed: {error}"),
            Self::Exit(status) => write!(f, "Quint ended with {status}"),
            Self::Limit { limit, .. } => write!(
                f,
                "Quint ran past {} seconds and was sent SIGKILL",
                limit.as_secs_f64()
            ),
        }
    }
}

/// `run` gives the child `stdout` as its standard output; the child inherits standard input, standard error and
/// the environment. The timer starts once `spawn` returns. A failed status read returns at once and sends the
/// child no signal, since the child may already be reaped.
pub fn run(
    program: &OsStr,
    args: &[OsString],
    directory: &Path,
    stdout: Stdio,
    limit: Duration,
) -> Result<(), Failure> {
    let mut child = Command::new(program)
        .args(args)
        .current_dir(directory)
        .stdout(stdout)
        .spawn()
        .map_err(Failure::Start)?;
    let start = Instant::now();
    let mut pause = Duration::from_micros(500);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => return Err(Failure::Exit(status)),
            Ok(None) => {}
            Err(error) => return Err(Failure::Wait(error)),
        }
        let elapsed = start.elapsed();
        if elapsed >= limit {
            let _ = child.kill();
            let status = child.wait().ok();
            return Err(Failure::Limit { limit, status });
        }
        pause = (pause * 2).min(limit - elapsed).min(POLL);
        thread::sleep(pause);
    }
}
