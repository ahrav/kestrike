use std::io::{self, Read};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::sys;

/// The most bytes read from one captured stream of one child.
pub(super) const OUTPUT_BOUND: u64 = 16 << 20;

const FIRST_POLL: Duration = Duration::from_millis(1);
const LAST_POLL: Duration = Duration::from_millis(50);

/// Where a child's standard error goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Stderr {
    /// Read, bounded, into [`Ran::stderr`].
    Capture,
    /// To this process's standard error; [`Ran::stderr`] is empty.
    Inherit,
}

/// A child's exit status and the bytes of its captured streams.
#[derive(Debug)]
pub(super) struct Ran {
    pub(super) status: ExitStatus,
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
}

/// Why a child produced no [`Ran`].
#[derive(Debug)]
pub(super) enum Failure {
    Interrupted,
    /// The child could not start, or its exit or a stream could not be read.
    Io(io::Error),
    /// A captured stream passed [`OUTPUT_BOUND`].
    Oversize,
    /// The child's exit or a captured stream outlived the deadline.
    Deadline,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Interrupted => f.write_str("archive interrupted"),
            Self::Io(error) => write!(f, "it cannot run: {error}"),
            Self::Oversize => write!(f, "its output passes {OUTPUT_BOUND} bytes"),
            Self::Deadline => f.write_str("it outlived its deadline"),
        }
    }
}

/// Runs `command` with null stdin, captured stdout and the selected stderr.
/// `deadline` bounds the wall time until the child and both streams end.
/// Before the spawn it sets the process's SIGCHLD disposition to its
/// default, process-wide, so the child's exit stays waitable.
///
/// # Errors
///
/// After a successful spawn, failure closes the readers, kills the direct
/// child and waits up to 10 s for its exit; a child that outlives that
/// wait is left unreaped.
#[cfg(test)]
pub(super) fn run(
    command: &mut Command,
    stderr: Stderr,
    deadline: Option<Duration>,
) -> Result<Ran, Failure> {
    execute(command, stderr, deadline, None)
}

#[derive(Debug)]
pub(crate) enum Unsuccessful {
    /// Holds the display text of the [`Failure`] returned by [`execute`].
    Failed(String),
    /// Holds the child's status when [`ExitStatus::success`] returns `false`.
    Ended(ExitStatus),
}

impl std::fmt::Display for Unsuccessful {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed(failure) => f.write_str(failure),
            Self::Ended(status) => write!(f, "it ended with {status}"),
        }
    }
}

/// Runs `command` as [`execute`] does, as the leader of its own process
/// group, with its standard error read and dropped, and returns the bytes
/// of its standard output when it exits with success. `deadline` bounds
/// the wall time until the child and both streams end; a child that
/// outlives it is killed with every process in its group. The kernel
/// kills the child, and no other process of its group, when the calling
/// thread exits. The call returns once the child has ended, so that kill
/// reaches a child only when the process dies during the call.
///
/// # Errors
///
/// [`Unsuccessful::Failed`] for a [`Failure`], or [`Unsuccessful::Ended`]
/// when [`ExitStatus::success`] returns `false`, regardless of captured
/// stdout.
pub(crate) fn output(command: &mut Command, deadline: Duration) -> Result<Vec<u8>, Unsuccessful> {
    sys::lead(command);
    let ran = execute(command, Stderr::Capture, Some(deadline), None)
        .map_err(|failure| Unsuccessful::Failed(failure.to_string()))?;
    if ran.status.success() {
        Ok(ran.stdout)
    } else {
        Err(Unsuccessful::Ended(ran.status))
    }
}

fn check(context: Option<&super::command::Context>) -> Result<(), Failure> {
    if let Some(context) = context {
        context.check().map_err(|error| match error {
            super::Error::Interrupted(_) => Failure::Interrupted,
            error => Failure::Io(io::Error::other(error.to_string())),
        })?;
    }
    Ok(())
}

pub(super) fn execute(
    command: &mut Command,
    stderr: Stderr,
    deadline: Option<Duration>,
    context: Option<&super::command::Context>,
) -> Result<Ran, Failure> {
    check(context)?;
    if context.is_some() {
        sys::contain(command, std::path::Path::new(".")).map_err(Failure::Io)?;
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(match stderr {
            Stderr::Capture => Stdio::piped(),
            Stderr::Inherit => Stdio::inherit(),
        });
    sys::child_exits().map_err(Failure::Io)?;
    let mut child = command.spawn().map_err(Failure::Io)?;
    let deadline = deadline.map(|duration| Instant::now() + duration);
    let result = capture(&mut child, deadline, context);
    if result.is_err() {
        if context.is_some() {
            stop_archiving(&mut child);
        } else {
            stop(&mut child);
        }
    }
    result
}

fn capture(
    child: &mut Child,
    deadline: Option<Instant>,
    context: Option<&super::command::Context>,
) -> Result<Ran, Failure> {
    let mut out = child.stdout.take();
    let mut err = child.stderr.take();
    if let Some(out) = &out {
        sys::nonblocking(out).map_err(Failure::Io)?;
    }
    if let Some(err) = &err {
        sys::nonblocking(err).map_err(Failure::Io)?;
    }
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut status = None;
    let mut pause = FIRST_POLL;
    loop {
        check(context)?;
        let progress = drain(&mut out, &mut stdout)? | drain(&mut err, &mut stderr)?;
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(Failure::Deadline);
        }
        // The child is reaped once both streams have ended, so until then
        // its ID names it, and the group it may lead, for a kill.
        if status.is_none()
            && out.is_none()
            && err.is_none()
            && sys::exited(child.id()).map_err(Failure::Io)?
        {
            status = Some(child.wait().map_err(Failure::Io)?);
        }
        if let Some(status) = status
            && out.is_none()
            && err.is_none()
        {
            return Ok(Ran {
                status,
                stdout,
                stderr,
            });
        }
        if progress {
            pause = FIRST_POLL;
        } else {
            let remaining =
                deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
            thread::sleep(remaining.map_or(pause, |remaining| pause.min(remaining)));
            pause = (pause * 2).min(LAST_POLL);
        }
    }
}

fn drain(stream: &mut Option<impl Read>, bytes: &mut Vec<u8>) -> Result<bool, Failure> {
    let Some(reader) = stream.as_mut() else {
        return Ok(false);
    };
    let mut buffer = [0; 64 << 10];
    let count = buffer.len().min(OUTPUT_BOUND as usize + 1 - bytes.len());
    match reader.read(&mut buffer[..count]) {
        Ok(0) => {
            *stream = None;
            Ok(true)
        }
        Ok(count) => {
            bytes.extend_from_slice(&buffer[..count]);
            if bytes.len() as u64 > OUTPUT_BOUND {
                return Err(Failure::Oversize);
            }
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(true),
        Err(error) => Err(Failure::Io(error)),
    }
}

/// Kills `child`, with every process in its group when it leads one, and
/// waits up to 10 s for its exit.
fn stop(child: &mut Child) {
    // The caller has not reaped `child`, so its ID is its own. A child
    // that leads no group has no group of that ID, and the signal reaches
    // no process.
    let _ = sys::kill_group(child.id());
    let _ = child.kill();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return,
        }
        if Instant::now() >= deadline {
            return;
        }
        thread::sleep(FIRST_POLL);
    }
}

fn stop_archiving(child: &mut Child) {
    let _ = sys::terminate_child(child);
    let deadline = Instant::now() + Duration::from_secs(1);
    while sys::exited(child.id()).is_ok_and(|exited| !exited) && Instant::now() < deadline {
        thread::sleep(FIRST_POLL);
    }
    let _ = sys::kill_group(child.id());
    stop(child);
}
