//! The launch contract: one worker process run to its end with bounded
//! output, under a watchdog and the command's interruption signals.
//!
//! The worker starts in a new process group of its own, receives SIGKILL
//! when the launcher dies, reads the null device as its standard input,
//! and writes its standard output and error into nonblocking pipes owned
//! by the calling thread. Each stream retains up to [`OUTPUT`] bytes.
//! The launcher is the subreaper of its descendants.
//!
//! The launcher kills the group while the unreaped worker reserves its ID.
//! It waits for the worker and adopted group members for up to [`DRAIN`].
//! It then collects both pipes for up to another [`DRAIN`].
//! Standalone custody covers members of the worker's original group.
//! Descendants that call `setsid` or `setpgid` can leave that group.
//! An escaped writer that keeps a pipe open past the collection deadline
//! makes the output incomplete; bytes already read remain in evidence.

use std::io::{self, Read};
use std::process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use crate::sys;

/// The most bytes kept of each of a worker's standard output and error.
pub(crate) const OUTPUT: usize = 1 << 20;

/// Each group-drain or pipe-collection wait lasts at most this duration.
const DRAIN: Duration = Duration::from_secs(10);

/// How often the launcher checks exit, output and watchdog while waiting.
const TICK: Duration = Duration::from_millis(10);

/// SIGINT and SIGTERM stay blocked; `wait` latches the first observed signal.
#[derive(Debug)]
pub(crate) struct Interruptions {
    taken: Option<i32>,
}

impl Interruptions {
    /// Blocks interruptions, resets SIGCHLD to its default disposition and
    /// makes the process its descendants' subreaper. These settings persist.
    /// The process's first thread calls this before it starts another, so
    /// every thread inherits the blocked interruptions.
    ///
    /// # Errors
    ///
    /// A failed signal setup or `prctl`.
    pub(crate) fn block() -> io::Result<Self> {
        sys::block_interruptions()?;
        sys::child_subreaper()?;
        Ok(Self { taken: None })
    }

    fn wait(&mut self, timeout: Duration) -> Option<i32> {
        if self.taken.is_none() {
            self.taken = sys::interruption(timeout).ok().flatten();
        }
        self.taken
    }

    /// The first interruption signal observed, checking pending signals now.
    pub(crate) fn pending(&mut self) -> Option<i32> {
        self.wait(Duration::ZERO)
    }
}

/// How a worker process ended.
#[derive(Debug)]
pub(crate) enum End {
    /// It exited with this code.
    Exited(i32),
    /// This signal killed it.
    Signaled(i32),
    /// It outlived the watchdog, and the launcher killed its group.
    Watchdog,
    /// This interruption reached the launcher, which killed the group.
    Interrupted(i32),
    /// It wrote past [`OUTPUT`] bytes to a stream.
    Oversized,
    /// Its group or pipes outlived [`DRAIN`].
    Escaped,
    /// The launch, wait or a pipe read failed.
    Failed(io::Error),
}

impl End {
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::Exited(_) => "exited",
            Self::Signaled(_) => "signaled",
            Self::Watchdog => "watchdog",
            Self::Interrupted(_) => "interrupted",
            Self::Oversized => "oversized",
            Self::Escaped => "escaped",
            Self::Failed(_) => "failed",
        }
    }
}

/// A worker's end, retained streams and observed cleanup results.
#[derive(Debug)]
pub(crate) struct Launched {
    pub(crate) end: End,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) status: Option<ExitStatus>,
    pub(crate) drained: bool,
    pub(crate) closed: bool,
}

/// Runs `command` under the launch contract until it ends, `watchdog`
/// passes or an interruption arrives.
pub(crate) fn launch(
    mut command: Command,
    directory: &std::path::Path,
    watchdog: Duration,
    interruptions: &mut Interruptions,
) -> Launched {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let spawned = sys::contain(&mut command, directory).and_then(|()| command.spawn());
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            return Launched {
                end: End::Failed(error),
                stdout: Vec::new(),
                stderr: Vec::new(),
                status: None,
                drained: true,
                closed: true,
            };
        }
    };
    // Both pipes were requested above and belong to this child.
    let stdout = child.stdout.take().expect("stdout was piped");
    let stderr = child.stderr.take().expect("stderr was piped");
    let setup = sys::nonblocking(&stdout).and_then(|()| sys::nonblocking(&stderr));
    let mut streams = Streams {
        out: Stream::new(stdout),
        err: Stream::new(stderr),
    };
    if let Err(error) = setup {
        streams.out.error = Some(error);
        streams.out.pipe = None;
        streams.err.pipe = None;
    }
    let stopped = watch(&child, watchdog, &mut streams, interruptions);
    let group = child.id();
    let (status, drained) = drain(&mut child, group, &mut streams);
    let deadline = Instant::now() + DRAIN;
    while !streams.closed() && Instant::now() < deadline {
        streams.read();
        if !streams.closed() {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    let closed = streams.closed();
    let end = match (stopped, &status) {
        (Some(stopped), _) => stopped,
        (None, _) if streams.over() => End::Oversized,
        (None, _) if streams.error().is_some() => {
            End::Failed(streams.error().expect("a read failed"))
        }
        (None, Err(error)) => End::Failed(io::Error::new(error.kind(), error.to_string())),
        (None, Ok(_)) if !(drained && closed) => End::Escaped,
        (None, Ok(status)) => ended(*status),
    };
    Launched {
        end,
        stdout: streams.out.bytes,
        stderr: streams.err.bytes,
        status: status.ok(),
        drained,
        closed,
    }
}

fn watch(
    child: &Child,
    watchdog: Duration,
    streams: &mut Streams,
    interruptions: &mut Interruptions,
) -> Option<End> {
    let Some(deadline) = Instant::now().checked_add(watchdog) else {
        return Some(End::Failed(io::Error::new(
            io::ErrorKind::InvalidInput,
            "watchdog overflow",
        )));
    };
    loop {
        let progress = streams.read();
        if streams.over() {
            return Some(End::Oversized);
        }
        if let Some(error) = streams.error() {
            return Some(End::Failed(error));
        }
        match sys::exited(child.id()) {
            Ok(true) => return None,
            Ok(false) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Some(End::Failed(error)),
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Some(End::Watchdog);
        }
        let pause = if progress {
            Duration::ZERO
        } else {
            left.min(TICK)
        };
        if let Some(signal) = interruptions.wait(pause) {
            return Some(End::Interrupted(signal));
        }
    }
}

/// Signals the reserved group once, waits for the leader's waitable exit,
/// then reaps adopted group members within the same deadline.
fn drain(child: &mut Child, group: u32, streams: &mut Streams) -> (io::Result<ExitStatus>, bool) {
    let deadline = Instant::now() + DRAIN;
    let killed = sys::kill_group(group);
    // The unreaped worker reserves its PID even if it left the group.
    let _ = child.kill();
    let status = loop {
        streams.read();
        match sys::exited(child.id()) {
            Ok(true) => break child.wait(),
            Ok(false) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return (Err(error), false),
        }
        if Instant::now() >= deadline {
            return (
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "worker reap deadline",
                )),
                false,
            );
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    if killed.is_err() {
        return (status, false);
    }
    loop {
        loop {
            match sys::reap_group(group) {
                Ok(true) => {}
                Ok(false) => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return (status, false),
            }
            if Instant::now() >= deadline {
                return (status, false);
            }
        }
        match sys::group_alive(group) {
            Ok(false) => return (status, true),
            Ok(true) if Instant::now() < deadline => {
                streams.read();
                std::thread::sleep(Duration::from_millis(1));
            }
            _ => return (status, false),
        }
    }
}

fn ended(status: ExitStatus) -> End {
    use std::os::unix::process::ExitStatusExt;
    match (status.code(), status.signal()) {
        (Some(code), _) => End::Exited(code),
        (None, Some(signal)) => End::Signaled(signal),
        (None, None) => End::Failed(io::Error::other(format!("the worker ended as {status}"))),
    }
}

/// The calling thread owns both stream buffers through collection.
struct Streams {
    out: Stream<ChildStdout>,
    err: Stream<ChildStderr>,
}

impl Streams {
    fn read(&mut self) -> bool {
        self.out.read() | self.err.read()
    }
    fn closed(&self) -> bool {
        self.out.pipe.is_none() && self.err.pipe.is_none()
    }
    fn over(&self) -> bool {
        self.out.over || self.err.over
    }
    fn error(&self) -> Option<io::Error> {
        self.out
            .error
            .as_ref()
            .or(self.err.error.as_ref())
            .map(|error| io::Error::new(error.kind(), error.to_string()))
    }
}

/// A nonblocking stream with bounded retained bytes and its first error.
struct Stream<R> {
    pipe: Option<R>,
    bytes: Vec<u8>,
    over: bool,
    error: Option<io::Error>,
}

impl<R: Read> Stream<R> {
    fn new(pipe: R) -> Self {
        Self {
            pipe: Some(pipe),
            bytes: Vec::new(),
            over: false,
            error: None,
        }
    }

    fn read(&mut self) -> bool {
        let Some(pipe) = &mut self.pipe else {
            return false;
        };
        let mut buffer = [0; 64 << 10];
        match pipe.read(&mut buffer) {
            Ok(0) => {
                self.pipe = None;
                true
            }
            Ok(count) => {
                let keep = count.min(OUTPUT - self.bytes.len());
                self.bytes.extend_from_slice(&buffer[..keep]);
                self.over |= keep < count;
                true
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                false
            }
            Err(error) => {
                self.error = Some(error);
                self.pipe = None;
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pipe_error_preserves_partial_bytes() {
        struct Broken(bool);
        impl Read for Broken {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                if std::mem::replace(&mut self.0, true) {
                    Err(io::Error::other("broken pipe"))
                } else {
                    bytes[..3].copy_from_slice(b"abc");
                    Ok(3)
                }
            }
        }
        let mut stream = Stream {
            pipe: Some(Broken(false)),
            bytes: Vec::new(),
            over: false,
            error: None,
        };
        stream.read();
        stream.read();
        assert_eq!(stream.bytes, b"abc");
        assert!(stream.error.is_some());
        assert!(stream.pipe.is_none());
    }

    #[test]
    fn a_spawn_failure_has_a_failed_end() {
        let _processes = crate::store::fixture::processes();
        let mut interruptions = Interruptions { taken: None };
        let launched = launch(
            Command::new("/absent-campaign-worker"),
            std::path::Path::new("/"),
            Duration::from_secs(1),
            &mut interruptions,
        );
        assert!(matches!(launched.end, End::Failed(_)));
        assert!(launched.stdout.is_empty());
        assert!(launched.status.is_none());
    }
}
